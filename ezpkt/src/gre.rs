use std::net::Ipv4Addr;

use pkt::eth::eth_hdr;
use pkt::ipv4::{ip_hdr, proto};
use pkt::gre::{GreFlags, gre_hdr, gre_hdr_seq};
use pkt::{Packet, Hdr};

/// Helper for creating GRE frames
pub struct GreFrame {
    pub pkt: Packet,
    ip: Hdr<ip_hdr>,
    seq: Option<Hdr<gre_hdr_seq>>,
}

impl GreFrame {
    const RAW_OVERHEAD: usize =
        std::mem::size_of::<ip_hdr>()
        + std::mem::size_of::<gre_hdr>();

    const OVERHEAD: usize =
        std::mem::size_of::<eth_hdr>()
        + Self::RAW_OVERHEAD;

    pub fn new(src: Ipv4Addr,
               dst: Ipv4Addr,
               proto: u16,
               raw: bool,
               extra: usize,
               ) -> Self {

        let mut pkt = if raw {
            Packet::with_capacity(Self::RAW_OVERHEAD + extra)
        } else {
            let mut pkt = Packet::with_capacity(Self::OVERHEAD + extra);

            let eth: Hdr<eth_hdr> = pkt.push_hdr();
            pkt.get_mut_hdr(eth)
                .dst_from_ip(dst)
                .src_from_ip(src)
                .proto(0x0800);

            pkt
        };

        let mut ip_len = Self::RAW_OVERHEAD;

        let ip: Hdr<ip_hdr> = pkt.push_hdr();

        let gre: Hdr<gre_hdr> = pkt.push_hdr();
        pkt.get_mut_hdr(gre)
            .init()
            .flags(GreFlags::default().seq(true))
            .proto(proto);

        let seq = if pkt.get_hdr(gre).get_seq() {
            let seq: Hdr<gre_hdr_seq> = pkt.push_hdr();
            ip_len += seq.len();
            Some(seq)
        } else {
            None
        };

        pkt.get_mut_hdr(ip)
            .init()
            .protocol(proto::GRE)
            .tot_len(ip_len as u16)
            .saddr(src)
            .daddr(dst)
            .calc_csum();

        Self {
            pkt,
            ip,
            seq,
        }
    }

    fn update_tot_len(&mut self, more: u16) {
        self.pkt.get_mut_hdr(self.ip)
            .add_tot_len(more)
            .calc_csum();
    }

    pub fn push_hdr<T>(&mut self) -> Hdr<T> {
        let ret: Hdr<T> = self.pkt.push_hdr();
        self.update_tot_len(ret.len() as u16);
        ret
    }

    pub fn push<T: AsRef<[u8]>>(mut self, bytes: T) -> Self {
        let b = bytes.as_ref();

        self.pkt.push_bytes(b);
        self.update_tot_len(b.len() as u16);

        self
    }

    pub fn seq(self, seq: u32) -> Self {
        if let Some(shdr) = self.seq {
            self.pkt.get_hdr(shdr)
                .seq(seq);
        };
        self
    }

}

impl From<GreFrame> for Packet {
    fn from(seg: GreFrame) -> Self{
        seg.pkt
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct GreFlow {
    cl: Ipv4Addr,
    sv: Ipv4Addr,
    ethertype: u16,
    raw: bool,
    seq: u32,
}

impl GreFlow {
    pub fn new(cl: Ipv4Addr,
               sv: Ipv4Addr,
               ethertype: u16,
               raw: bool,
               ) -> Self {
        //println!("trace: vxlan:flow({:?}, {:?}, {:#x})", cl, sv, ethertype);
        Self {
            cl,
            sv,
            ethertype,
            raw,
            seq: 0,
        }
    }

    fn next_seq(&mut self) -> u32 {
        let ret = self.seq;

        self.seq += 1;

        ret
    }

    fn dgram(&mut self, extra: usize) -> GreFrame {
        GreFrame::new(self.cl, self.sv, self.ethertype, self.raw, extra)
            .seq(self.next_seq())
    }

    pub fn encap(&mut self, bytes: &[u8]) -> Packet {
        //println!("trace: vxlan:encap({} bytes)", bytes.len());
        self.dgram(bytes.len()).push(bytes).into()
    }
}
