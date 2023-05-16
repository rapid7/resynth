use std::net::SocketAddrV4;

use pkt::eth::eth_hdr;
use pkt::ipv4::{ip_hdr, proto, tcp_hdr};
use pkt::{Packet, Hdr};

#[derive(Debug, PartialEq, Eq)]
struct TcpState {
    snd_nxt: u32,
    rcv_nxt: u32,
}

/// Helper for creating TCP segments
pub struct TcpSeg {
    pkt: Packet,
    ip: Hdr<ip_hdr>,
    tcp: Hdr<tcp_hdr>,
    st: TcpState,
    seq: u32,
}

impl TcpSeg {
    const RAW_OVERHEAD: usize =
        std::mem::size_of::<ip_hdr>()
        + std::mem::size_of::<tcp_hdr>();

    const OVERHEAD: usize =
        std::mem::size_of::<eth_hdr>()
        + Self::RAW_OVERHEAD;

    fn new(src: SocketAddrV4,
           dst: SocketAddrV4,
           st: TcpState,
           raw: bool,
           ) -> Self {

        let mut pkt = if raw {
            Packet::with_capacity(Self::RAW_OVERHEAD)
        } else {
            let mut pkt = Packet::with_capacity(Self::OVERHEAD);

            let eth: Hdr<eth_hdr> = pkt.push_hdr();
            pkt.get_mut_hdr(eth)
                .dst_from_ip(*dst.ip())
                .src_from_ip(*src.ip())
                .proto(0x0800);

            pkt
        };

        let ip: Hdr<ip_hdr> = pkt.push_hdr();
        pkt.get_mut_hdr(ip)
            .init()
            .protocol(proto::TCP)
            .tot_len(Self::RAW_OVERHEAD as u16)
            .saddr(*src.ip())
            .daddr(*dst.ip())
            .calc_csum();

        let tcp: Hdr<tcp_hdr> = pkt.push_hdr();
        pkt.get_mut_hdr(tcp)
            .init()
            .seq(st.snd_nxt)
            .sport(src.port())
            .dport(dst.port());

        Self {
            pkt,
            ip,
            tcp,
            st,
            seq: 0,
        }
    }

    fn syn(mut self) -> Self {
        self.pkt.get_mut_hdr(self.tcp)
            .syn();
        self.seq += 1;
        self
    }

    fn syn_ack(mut self) -> Self {
        self.pkt.get_mut_hdr(self.tcp)
            .syn()
            .ack(self.st.rcv_nxt);
        self.seq += 1;
        self
    }

    fn ack(mut self) -> Self {
        self.pkt.get_mut_hdr(self.tcp)
            .ack(self.st.rcv_nxt);
        self
    }

    fn push(mut self) -> Self {
        self.pkt.get_mut_hdr(self.tcp)
            .push();
        self.ack()
    }

    fn append_data(mut self, bytes: &[u8]) -> Self {
        self.pkt.push_bytes(bytes);
        self.seq += bytes.len() as u32;
        self.update_tot_len(bytes.len() as u16)
    }

    fn push_bytes(self, bytes: &[u8]) -> Self {
        self.push().append_data(bytes)
    }

    fn fin(mut self) -> Self {
        self.pkt.get_mut_hdr(self.tcp)
            .fin();
        self.seq += 1;
        self
    }

    fn fin_ack(mut self) -> Self {
        self = self.fin();
        self = self.ack();
        self
    }

    fn frag_off(mut self, frag_off: u16) -> Self {
        self.pkt.get_mut_hdr(self.ip).frag_off(frag_off).calc_csum();
        self
    }

    fn update_tot_len(mut self, more: u16) -> Self {
        self.pkt.get_mut_hdr(self.ip)
            .add_tot_len(more)
            .calc_csum();
        self
    }

    fn seq_consumed(&self) -> u32 {
        self.seq
    }

    fn tcp_hdr_bytes(&self) -> &[u8] {
        self.pkt.get_hdr_bytes(self.tcp)
    }
}

impl From<TcpSeg> for Packet {
    fn from(seg: TcpSeg) -> Self{
        seg.pkt
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct TcpFlow {
    cl: SocketAddrV4,
    sv: SocketAddrV4,
    cl_seq: u32,
    sv_seq: u32,
    raw: bool,
    pkts: Vec<Packet>,
}

impl TcpFlow {
    pub fn new(cl: SocketAddrV4,
               sv: SocketAddrV4,
               cl_seq: u32,
               sv_seq: u32,
               raw: bool,
               ) -> Self {
        Self {
            cl,
            sv,
            cl_seq,
            sv_seq,
            raw,
            pkts: Vec::new(),
        }
    }

    fn cl_state(&self) -> TcpState {
        TcpState {
            snd_nxt: self.cl_seq,
            rcv_nxt: self.sv_seq,
        }
    }

    fn sv_state(&self) -> TcpState {
        TcpState {
            snd_nxt: self.sv_seq,
            rcv_nxt: self.cl_seq,
        }
    }

    fn cl(&self) -> TcpSeg {
        TcpSeg::new(self.cl, self.sv, self.cl_state(), self.raw)
    }

    fn sv(&self) -> TcpSeg {
        TcpSeg::new(self.sv, self.cl, self.sv_state(), self.raw)
    }
    
    fn cl_tx(&mut self, seg: TcpSeg) {
        self.cl_seq += seg.seq_consumed();
        self.pkts.push(seg.into());
    }
    
    fn sv_tx(&mut self, seg: TcpSeg) {
        self.sv_seq += seg.seq_consumed();
        self.pkts.push(seg.into());
    }

    pub fn open(&mut self) -> Vec<Packet> {
        self.cl_tx(self.cl().syn());
        self.sv_tx(self.sv().syn_ack());
        self.cl_tx(self.cl().ack());

        std::mem::take(&mut self.pkts)
    }

    pub fn client_close(&mut self) -> Vec<Packet> {
        self.cl_tx(self.cl().fin_ack());
        self.sv_tx(self.sv().fin_ack());
        self.cl_tx(self.cl().ack());

        std::mem::take(&mut self.pkts)
    }

    pub fn server_close(&mut self) -> Vec<Packet> {
        self.sv_tx(self.sv().fin_ack());
        self.cl_tx(self.cl().fin_ack());
        self.sv_tx(self.sv().ack());

        std::mem::take(&mut self.pkts)
    }

    // Advance client seq by `bytes` bytes in order to simulate a hole
    pub fn client_hole(&mut self, bytes: u32) {
        self.cl_seq += bytes;
    }

    // Advance server seq by `bytes` bytes in order to simulate a hole
    pub fn server_hole(&mut self, bytes: u32) {
        self.sv_seq += bytes;
    }

    pub fn push_state(&mut self,
                      cl_seq: Option<u32>,
                      sv_seq: Option<u32>,
                      ) -> (Option<u32>, Option<u32>) {
        let ret = (cl_seq.and(Some(self.cl_seq)), sv_seq.and(Some(self.sv_seq)));
        self.cl_seq = cl_seq.unwrap_or(self.cl_seq);
        self.sv_seq = sv_seq.unwrap_or(self.sv_seq);
        ret
    }

    pub fn pop_state(&mut self, st: (Option<u32>, Option<u32>)) {
        let (cl_seq, sv_seq) = st;

        self.cl_seq = cl_seq.unwrap_or(self.cl_seq);
        self.sv_seq = sv_seq.unwrap_or(self.sv_seq);
    }

    pub fn client_message(&mut self,
                          bytes: &[u8],
                          send_ack: bool,
                          frag_off: u16,
                          ) -> Vec<Packet> {
        self.cl_tx(self.cl().frag_off(frag_off).push_bytes(bytes));
        if send_ack {
            self.sv_tx(self.sv().ack());
        }

        std::mem::take(&mut self.pkts)
    }

    pub fn server_message(&mut self,
                          bytes: &[u8],
                          send_ack: bool,
                          frag_off: u16,
                          ) -> Vec<Packet> {
        self.sv_tx(self.sv().frag_off(frag_off).push_bytes(bytes));
        if send_ack {
            self.cl_tx(self.cl().ack());
        }

        std::mem::take(&mut self.pkts)
    }

    pub fn client_hdr(&mut self,
                          dlen: u32,
                          ) -> Vec<u8> {
        let seg = self.cl().push();
        let hdr = seg.tcp_hdr_bytes();

        self.cl_seq += seg.seq_consumed() + dlen;

        Vec::from(hdr)
    }

    pub fn server_hdr(&mut self,
                          dlen: u32,
                          ) -> Vec<u8> {
        let seg = self.sv().push();
        let hdr = seg.tcp_hdr_bytes();

        self.sv_seq += seg.seq_consumed() + dlen;

        Vec::from(hdr)
    }
}
