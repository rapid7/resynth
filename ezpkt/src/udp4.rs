use std::net::{SocketAddrV4, Ipv4Addr};

use pkt::eth::eth_hdr;
use pkt::ipv4::{ip_hdr, udp_hdr, proto};
use pkt::{Packet, Hdr};

#[derive(Debug, PartialEq, Eq)]
pub struct UdpFlow {
    cl: SocketAddrV4,
    sv: SocketAddrV4,
    raw: bool,
}

const UDP_RAW_DGRAM_OVERHEAD: usize =
    std::mem::size_of::<ip_hdr>()
    + std::mem::size_of::<udp_hdr>();

const UDP_DGRAM_OVERHEAD: usize =
    std::mem::size_of::<eth_hdr>()
    + UDP_RAW_DGRAM_OVERHEAD;

/// Helper for creating UDP datagrams
pub struct UdpDgram {
    pkt: Packet,
    eth: Option<Hdr<eth_hdr>>,
    ip: Hdr<ip_hdr>,
    udp: Hdr<udp_hdr>,
    tot_len: usize,
    dgram_len: usize,
}

impl UdpDgram {
    #[must_use]
    pub fn with_capacity(payload_sz: usize, raw: bool) -> Self {
        let mut pkt = if raw {
            Packet::with_capacity(UDP_RAW_DGRAM_OVERHEAD + payload_sz)
        } else {
            Packet::with_capacity(UDP_DGRAM_OVERHEAD + payload_sz)
        };

        let eth = if raw {
            None
        } else {
            let eth: Hdr<eth_hdr> = pkt.push_hdr();
            pkt.get_mut_hdr(eth).proto(0x0800);
            Some(eth)
        };

        let ip: Hdr<ip_hdr> = pkt.push_hdr();
        pkt.get_mut_hdr(ip)
            .init()
            .protocol(proto::UDP);

        let udp: Hdr<udp_hdr> = pkt.push_hdr();

        let tot_len = ip.len() + udp.len();

        let ret = Self {
            pkt,
            eth,
            ip,
            udp,
            tot_len,
            dgram_len: ::std::mem::size_of::<udp_hdr>(),
        };

        ret.update_tot_len().update_dgram_len()
    }

    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(0, false)
    }

    pub fn raw() -> Self {
        Self::with_capacity(0, true)
    }

    pub fn of_type(raw: bool) -> Self {
        Self::with_capacity(0, raw)
    }

    #[must_use]
    pub fn srcip(mut self, src: Ipv4Addr) -> Self {
        self.pkt.get_mut_hdr(self.ip).saddr(src);
        self
    }

    #[must_use]
    pub fn frag_off(mut self, frag_off: u16) -> Self {
        self.pkt.get_mut_hdr(self.ip).frag_off(frag_off);
        self
    }

    #[must_use]
    pub fn src(mut self, src: SocketAddrV4) -> Self {
        if let Some(eth) = self.eth {
            self.pkt.get_mut_hdr(eth).src_from_ip(*src.ip());
        }
        self.pkt.get_mut_hdr(self.ip).saddr(*src.ip());
        self.pkt.get_mut_hdr(self.udp).sport(src.port());
        self
    }

    #[must_use]
    pub fn dst(mut self, dst: SocketAddrV4) -> Self {
        if let Some(eth) = self.eth {
            self.pkt.get_mut_hdr(eth).dst_from_ip(*dst.ip());
        }
        self.pkt.get_mut_hdr(self.ip).daddr(*dst.ip());
        self.pkt.get_mut_hdr(self.udp).dport(dst.port());
        self
    }

    #[must_use]
    pub fn broadcast(mut self) -> Self {
        if let Some(eth) = self.eth {
            self.pkt.get_mut_hdr(eth).broadcast();
        }
        self
    }

    #[must_use]
    pub fn push<T: AsRef<[u8]>>(mut self, bytes: T) -> Self {
        let buf = bytes.as_ref();
        self.pkt.push_bytes(buf);
        self.tot_len += buf.len();
        self.dgram_len += buf.len();
        self.update_tot_len().update_dgram_len()
    }

    #[must_use]
    fn update_tot_len(mut self) -> Self {
        self.pkt.get_mut_hdr(self.ip)
            .tot_len(self.tot_len as u16)
            .calc_csum();
        self
    }

    #[must_use]
    fn update_dgram_len(mut self) -> Self {
        self.pkt.get_mut_hdr(self.udp)
            .len(self.dgram_len as u16);
        self
    }
}

impl Default for UdpDgram {
    fn default() -> Self {
        Self::new()
    }
}

impl From<UdpDgram> for Packet {
    fn from(seg: UdpDgram) -> Self {
        seg.pkt
    }
}

impl UdpFlow {
    pub fn new(cl: SocketAddrV4, sv: SocketAddrV4, raw: bool) -> Self {
        //println!("trace: udp:flow({:?}, {:?})", cl, sv);
        Self {
            cl,
            sv,
            raw,
        }
    }

    fn clnt(&self) -> UdpDgram {
        UdpDgram::of_type(self.raw).src(self.cl).dst(self.sv)
    }

    fn srvr(&self) -> UdpDgram {
        UdpDgram::of_type(self.raw).src(self.sv).dst(self.cl)
    }

    pub fn client_dgram(&mut self, bytes: &[u8]) -> Packet {
        //println!("trace: udp:client({} bytes)", bytes.len());
        self.clnt().push(bytes).into()
    }

    pub fn server_dgram(&mut self, bytes: &[u8]) -> Packet {
        //println!("trace: udp:server({} bytes)", bytes.len());
        self.srvr().push(bytes).into()
    }

    pub fn client_dgram_with_frag_off(&mut self,
                                      bytes: &[u8],
                                      frag_off: u16,
                                      ) -> Packet {
        //println!("trace: udp:client({} bytes)", bytes.len());
        self.clnt().push(bytes).frag_off(frag_off).into()
    }

    pub fn server_dgram_with_frag_off(&mut self,
                                      bytes: &[u8],
                                      frag_off: u16,
                                      ) -> Packet {
        //println!("trace: udp:server({} bytes)", bytes.len());
        self.srvr().push(bytes).frag_off(frag_off).into()
    }
}
