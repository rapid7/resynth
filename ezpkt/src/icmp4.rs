use std::net::Ipv4Addr;

use pkt::eth::eth_hdr;
use pkt::ipv4::{ip_hdr, icmp_hdr, icmp_echo_hdr, ip_csum, proto, ICMP_ECHOREPLY, ICMP_ECHO};
use pkt::{Packet, Hdr};

#[derive(Debug, PartialEq, Eq)]
pub struct IcmpFlow {
    cl: Ipv4Addr,
    sv: Ipv4Addr,
    raw: bool,
    id: u16,
    ping_seq: u16,
    pong_seq: u16,
}

/// Helper for creating ICMP datagrams
pub struct IcmpDgram {
    pkt: Packet,
    ip: Hdr<ip_hdr>,
    icmp: Hdr<icmp_hdr>,
    echo: Hdr<icmp_echo_hdr>,
}

impl IcmpDgram {
    const RAW_OVERHEAD: usize =
        std::mem::size_of::<ip_hdr>()
        + std::mem::size_of::<icmp_echo_hdr>()
        + std::mem::size_of::<icmp_hdr>();

    const OVERHEAD: usize =
        std::mem::size_of::<eth_hdr>()
        + Self::RAW_OVERHEAD;

    fn new(src: Ipv4Addr, dst: Ipv4Addr, raw: bool) -> Self {
        let mut pkt = if raw {
            Packet::with_capacity(Self::RAW_OVERHEAD)
        } else {
            let mut pkt = Packet::with_capacity(Self::OVERHEAD);

            let eth: Hdr<eth_hdr> = pkt.push_hdr();
            pkt.get_mut_hdr(eth)
                .dst_from_ip(dst)
                .src_from_ip(src)
                .proto(0x0800);

            pkt
        };

        let ip: Hdr<ip_hdr> = pkt.push_hdr();
        pkt.get_mut_hdr(ip)
            .init()
            .protocol(proto::ICMP)
            .tot_len(Self::RAW_OVERHEAD as u16)
            .saddr(src)
            .daddr(dst)
            .calc_csum();

        let icmp: Hdr<icmp_hdr> = pkt.push_hdr();

        let echo: Hdr<icmp_echo_hdr> = pkt.push_hdr();

        Self {
            pkt,
            ip,
            icmp,
            echo,
        }
    }

    fn push(mut self, bytes: &[u8]) -> Self {
        self.pkt.push_bytes(bytes);
        self.update_tot_len(bytes.len() as u16)
    }

    fn update_tot_len(mut self, more: u16) -> Self {
        self.pkt.get_mut_hdr(self.ip)
            .add_tot_len(more)
            .calc_csum();
        self
    }

    fn ping(mut self, id: u16, seq: u16, bytes: &[u8]) -> Self {
        self = self.push(bytes);
        self.pkt.get_mut_hdr(self.icmp)
            .typ(ICMP_ECHO);
        self.pkt.get_mut_hdr(self.echo)
            .id(id)
            .seq(seq);

        let bytes = self.pkt.bytes_from(self.icmp, self.pkt.len_from(self.icmp));
        let csum = ip_csum(bytes);
        self.pkt.get_mut_hdr(self.icmp).csum(csum);

        self
    }

    fn pong(mut self, id: u16, seq: u16, bytes: &[u8]) -> Self {
        self = self.push(bytes);
        self.pkt.get_mut_hdr(self.icmp)
            .typ(ICMP_ECHOREPLY);
        self.pkt.get_mut_hdr(self.echo)
            .id(id)
            .seq(seq);

        let bytes = self.pkt.bytes_from(self.icmp, self.pkt.len_from(self.icmp));
        let csum = ip_csum(bytes);
        self.pkt.get_mut_hdr(self.icmp).csum(csum);

        self
    }
}

impl From<IcmpDgram> for Packet {
    fn from(seg: IcmpDgram) -> Self{
        seg.pkt
    }
}

impl IcmpFlow {
    pub fn new(cl: Ipv4Addr, sv: Ipv4Addr, raw: bool) -> Self {
        //println!("trace: icmp:flow({:?}, {:?})", cl, sv);
        Self {
            cl,
            sv,
            raw,
            id: 0x1234,
            ping_seq: 0,
            pong_seq: 0,
        }
    }

    fn clnt(&self) -> IcmpDgram {
        IcmpDgram::new(self.cl, self.sv, self.raw)
    }

    fn srvr(&self) -> IcmpDgram {
        IcmpDgram::new(self.sv, self.cl, self.raw)
    }

    pub fn echo(&mut self, bytes: &[u8]) -> Packet {
        //println!("trace: icmp:ping({} bytes)", bytes.len());
        let ret = self.clnt().ping(self.id, self.ping_seq, bytes).into();
        self.ping_seq += 1;
        ret
    }

    pub fn echo_reply(&mut self, bytes: &[u8]) -> Packet {
        //println!("trace: icmp:pong({} bytes)", bytes.len());
        let ret = self.srvr().pong(self.id, self.pong_seq, bytes).into();
        self.pong_seq += 1;
        ret
    }
}
