use std::net::Ipv4Addr;

use pkt::eth::eth_hdr;
use pkt::ipv4::{ip_hdr, proto};
use pkt::gre::gre_hdr;
use pkt::{Packet, Hdr};

/// Helper for creating GRE frames
pub struct GreFrame {
    pkt: Packet,
    ip: Hdr<ip_hdr>,
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

        let ip: Hdr<ip_hdr> = pkt.push_hdr();
        pkt.get_mut_hdr(ip)
            .init()
            .protocol(proto::GRE)
            .tot_len(Self::RAW_OVERHEAD as u16)
            .saddr(src)
            .daddr(dst);

        let gre: Hdr<gre_hdr> = pkt.push_hdr();
        *pkt.get_mut_hdr(gre) = gre_hdr::new(proto);

        Self {
            pkt,
            ip,
        }
    }

    fn update_tot_len(mut self, more: u16) -> Self {
        self.pkt.get_mut_hdr(self.ip)
            .add_tot_len(more)
            .calc_csum();
        self
    }

    pub fn push<T: AsRef<[u8]>>(mut self, bytes: T) -> Self {
        let b = bytes.as_ref();

        self.pkt.push_bytes(b);
        self.update_tot_len(b.len() as u16)
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
        }
    }

    fn dgram(&self, extra: usize) -> GreFrame {
        GreFrame::new(self.cl, self.sv, self.ethertype, self.raw, extra)
    }

    pub fn encap(&mut self, bytes: &[u8]) -> Packet {
        //println!("trace: vxlan:encap({} bytes)", bytes.len());
        self.dgram(bytes.len()).push(bytes).into()
    }
}
