use std::cmp::min;

use pkt::eth::eth_hdr;
use pkt::ipv4::ip_hdr;
use pkt::{Packet, Hdr};

const IPH_LEN: usize = std::mem::size_of::<ip_hdr>();
const IP_DGRAM_OVERHEAD: usize = std::mem::size_of::<eth_hdr>() + IPH_LEN;

/// Helper for creating IP datagrams
pub struct IpDgram{
    pkt: Packet,
    ip: Hdr<ip_hdr>,
}

impl IpDgram {
    #[must_use]
    pub fn new(iph: ip_hdr, payload: &[u8]) -> Self {
        let mut pkt = Packet::with_capacity(IP_DGRAM_OVERHEAD + payload.len());

        let eth: Hdr<eth_hdr> = pkt.push_hdr();
        pkt.get_mut_hdr(eth)
            .src_from_ip(iph.get_saddr().into())
            .dst_from_ip(iph.get_saddr().into())
            .proto(0x0800);

        let ip: Hdr<ip_hdr> = pkt.push_hdr_from(&iph);

        pkt.get_mut_hdr(ip).tot_len(payload.len() as u16 + IPH_LEN as u16);
        pkt.push_bytes(payload);

        Self {
            pkt,
            ip,
        }
    }

    #[must_use]
    pub fn frag(mut self, frag_off: u16, mf: bool) -> Self {
        self.pkt.get_mut_hdr(self.ip)
            .frag_off(frag_off)
            .mf(mf)
            .calc_csum();
        self
    }
}

impl From<IpDgram> for Packet {
    fn from(seg: IpDgram) -> Self {
        seg.pkt
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct IpFrag {
    hdr: ip_hdr,
    payload: Vec<u8>,
}

impl IpFrag {
    pub fn new(hdr: ip_hdr, payload: Vec<u8>) -> Self {
        //println!("trace: udp:flow({:?}, {:?})", cl, sv);
        Self {
            hdr,
            payload,
        }
    }

    /// Offset is in 8-byte blocks, len is in bytes
    pub fn fragment(&self, off: u16, len: u16) -> Packet {
        let byte_off = (off as usize) << 3;
        let byte_len = (len as usize) << 3;
        let byte_end = byte_off + byte_len;
        let end = min(byte_end, self.payload.len());
        let content = &self.payload[byte_off..end];

        IpDgram::new(self.hdr, content).frag(off, end != self.payload.len()).into()
    }

    /// Offset is in 8-byte blocks, include all bytes until the end
    pub fn tail(&self, off: u16) -> Packet {
        self.fragment(off, self.payload.len() as u16)
    }

    /// The whole payload in one unfragmented datagram
    pub fn datagram(&self) -> Packet { 
        IpDgram::new(self.hdr, &self.payload[..]).frag(0, false).into()
    }
}
