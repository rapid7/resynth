use std::net::Ipv4Addr;

use crate::Serialize;
use crate::util::AsBytes;

pub mod proto {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const GRE: u8 = 47;
}

pub mod flags {
    pub const EVIL: u16 = 0x8000;
    pub const DF: u16 = 0x4000;
    pub const MF: u16 = 0x2000;
}

#[repr(C, packed(1))]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ip_hdr {
    pub ihl_version: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub csum: u16,
    pub saddr: u32,
    pub daddr: u32,
}

impl Serialize for ip_hdr {}

impl Default for ip_hdr {
    fn default() -> Self {
        Self {
            ihl_version: 0x45,
            tos: 0,
            tot_len: (std::mem::size_of::<Self>() as u16).to_be(),
            id: 0,
            frag_off: 0,
            ttl: 64,
            protocol: 0,
            csum: 0,
            saddr: 0,
            daddr: 0,
        }
    }
}

impl ip_hdr {
    pub fn init(&mut self) -> &mut Self {
        self.ihl_version = 0x45;
        self.tot_len = (std::mem::size_of::<Self>() as u16).to_be();
        self.ttl = 64;
        self
    }

    pub fn get_saddr(&self) -> u32 {
        u32::from_be(self.saddr)
    }

    pub fn get_daddr(&self) -> u32 {
        u32::from_be(self.daddr)
    }

    pub fn tot_len(&mut self, tot_len: u16) -> &mut Self {
        self.tot_len = tot_len.to_be();
        self
    }

    pub fn id(&mut self, id: u16) -> &mut Self {
        self.id = id.to_be();
        self
    }

    /// Set fragment offset, in units of 8 bytes
    pub fn frag_off(&mut self, frag_off: u16) -> &mut Self {
        let flags: u16 = u16::from_be(self.frag_off) & 0xe000;
        self.frag_off = (frag_off | flags).to_be();
        self
    }

    pub fn ttl(&mut self, ttl: u8) -> &mut Self {
        self.ttl = ttl;
        self
    }

    pub fn protocol(&mut self, protocol: u8) -> &mut Self {
        self.protocol = protocol;
        self
    }

    pub fn saddr(&mut self, addr: Ipv4Addr) -> &mut Self {
        let ip: u32 = addr.into();
        self.saddr = ip.to_be();
        self
    }

    pub fn daddr(&mut self, addr: Ipv4Addr) -> &mut Self {
        let ip: u32 = addr.into();
        self.daddr = ip.to_be();
        self
    }

    pub fn mf(&mut self, mf: bool) -> &mut Self {
        let mut frag_off: u16 = u16::from_be(self.frag_off);

        if mf {
            frag_off |= flags::MF;
        } else {
            frag_off &= !flags::MF;
        }

        self.frag_off = frag_off.to_be();

        self
    }

    pub fn df(&mut self, df: bool) -> &mut Self {
        let mut frag_off: u16 = u16::from_be(self.frag_off);

        if df {
            frag_off |= flags::DF;
        } else {
            frag_off &= !flags::DF;
        }

        self.frag_off = frag_off.to_be();

        self
    }

    pub fn evil(&mut self, evil: bool) -> &mut Self {
        let mut frag_off: u16 = u16::from_be(self.frag_off);

        if evil {
            frag_off |= flags::EVIL;
        } else {
            frag_off &= !flags::EVIL;
        }

        self.frag_off = frag_off.to_be();

        self
    }

    pub fn csum(&mut self, csum: u16) -> &mut Self {
        self.csum = csum.to_be();
        self
    }

    pub fn calc_csum(&mut self) -> &mut Self {
        self.csum = 0;
        self.csum(ip_csum(self.as_bytes()))
    }
}

#[repr(C, packed(1))]
#[derive(Debug, Copy, Clone)]
pub struct udp_hdr {
    pub sport: u16,
    pub dport: u16,
    pub len: u16,
    pub csum: u16,
}

#[repr(C, packed(1))]
#[derive(Debug, Copy, Clone)]
pub struct tcp_hdr {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub doff: u8,
    pub flags: u8,
    pub win: u16,
    pub csum: u16,
    pub urp: u16,
}

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;
pub const TCP_ECE: u8 = 0x40;
pub const TCP_CWR: u8 = 0x80;

impl tcp_hdr {
    pub fn init(&mut self) -> &mut Self {
        let sz = std::mem::size_of::<Self>() as u8;
        self.doff = (sz >> 2) << 4;
        self.win = u16::MAX.to_be();
        self
    }

    pub fn sport(&mut self, sport: u16) -> &mut Self {
        self.sport = sport.to_be();
        self
    }

    pub fn dport(&mut self, dport: u16) -> &mut Self {
        self.dport = dport.to_be();
        self
    }

    pub fn seq(&mut self, seq: u32) -> &mut Self {
        self.seq = seq.to_be();
        self
    }

    pub fn syn(&mut self) -> &mut Self {
        self.flags |= TCP_SYN;
        self
    }

    pub fn push(&mut self) -> &mut Self {
        self.flags |= TCP_PSH;
        self
    }

    pub fn fin(&mut self) -> &mut Self {
        self.flags |= TCP_FIN;
        self
    }

    pub fn rst(&mut self) -> &mut Self {
        self.flags |= TCP_RST;
        self
    }

    pub fn ack(&mut self, ack: u32) -> &mut Self {
        self.ack = ack.to_be();
        self.flags |= TCP_ACK;
        self
    }
}

impl udp_hdr {
    pub fn sport(&mut self, sport: u16) -> &mut Self {
        self.sport = sport.to_be();
        self
    }

    pub fn dport(&mut self, dport: u16) -> &mut Self {
        self.dport = dport.to_be();
        self
    }

    pub fn len(&mut self, len: u16) -> &mut Self {
        self.len = len.to_be();
        self
    }
}

pub const ICMP_ECHOREPLY: u8 = 0;       /* Echo Reply */
pub const ICMP_DEST_UNREACH: u8 = 3;    /* Destination Unreachable */
pub const ICMP_SOURCE_QUENCH: u8 = 4;   /* Source Quench */
pub const ICMP_REDIRECT: u8 = 5;        /* Redirect (change route) */
pub const ICMP_ECHO: u8 = 8;            /* Echo Request */
pub const ICMP_TIME_EXCEEDED: u8 = 11;  /* Time Exceeded */
pub const ICMP_PARAMETERPROB: u8 = 12;  /* Parameter Problem */
pub const ICMP_TIMESTAMP: u8 = 13;      /* Timestamp Request */
pub const ICMP_TIMESTAMPREPLY: u8 = 14; /* Timestamp Reply */
pub const ICMP_INFO_REQUEST: u8 = 15;   /* Information Request */
pub const ICMP_INFO_REPLY: u8 = 16;     /* Information Reply */
pub const ICMP_ADDRESS: u8 = 17;        /* Address Mask Request */
pub const ICMP_ADDRESSREPLY: u8 = 18;   /* Address Mask Reply */

/* For ICMP_DEST_UNREACH */
pub const ICMP_NET_UNREACH: u8 = 0;
pub const ICMP_HOST_UNREACH: u8 = 1;
pub const ICMP_PROT_UNREACH: u8 = 2;
pub const ICMP_PORT_UNREACH: u8 = 3;
pub const ICMP_FRAG_NEEDED: u8 = 4;
pub const ICMP_SR_FAILED: u8 = 5;
pub const ICMP_NET_UNKNOWN: u8 = 7;
pub const ICMP_HOST_UNKNOWN: u8 = 8;
pub const ICMP_NET_ANO: u8 = 9;
pub const ICMP_HOST_ANO: u8 = 10;
pub const ICMP_NET_UNR_TOS: u8 = 11;
pub const ICMP_HOST_UNR_TOS: u8 = 12;
pub const ICMP_PKT_FILTERED: u8 = 13;
pub const ICMP_PREC_VIOLATION: u8 = 14;
pub const ICMP_PREC_CUTOFF: u8 = 15;

#[repr(C, packed(1))]
#[derive(Debug, Copy, Clone)]
pub struct icmp_hdr {
    pub typ: u8,
    pub code: u8,
    pub csum: u16,
}

impl icmp_hdr {
    pub fn typ(&mut self, typ: u8) -> &mut Self {
        self.typ = typ;
        self
    }

    pub fn code(&mut self, code: u8) -> &mut Self {
        self.code = code;
        self
    }

    pub fn csum(&mut self, csum: u16) -> &mut Self {
        self.csum = csum.to_be();
        self
    }
}

#[repr(C, packed(1))]
#[derive(Debug, Copy, Clone)]
pub struct icmp_echo_hdr {
    pub id: u16,
    pub seq: u16,
}

impl icmp_echo_hdr {
    pub fn id(&mut self, id: u16) -> &mut Self {
        self.id = id.to_be();
        self
    }

    pub fn seq(&mut self, seq: u16) -> &mut Self {
        self.seq = seq.to_be();
        self
    }
}

pub fn ip_csum(buf: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    let it = buf.chunks_exact(2);
    let remainder = it.remainder();

    for chunk in it {
        /* hopefully this temporary bounce and bounds-check is optimized out? But I guess it
         * depends on if the compiler can figure out that chunks_exact iterator results must be of
         * size 2 which probably depends on whether it gets inlined or not?
         */
        let mut tmp: [u8; 2] = Default::default();
        tmp.copy_from_slice(chunk);

        let val = u16::from_be_bytes(tmp);
        sum += val as u32;
    }

    if !remainder.is_empty() {
        sum += (remainder[0] as u32) << 8;
    }

    sum = (sum & 0xffffu32) + (sum >> 16);
    sum = (sum & 0xffffu32) + (sum >> 16);
    sum = !sum & 0xffffu32;

    sum as u16
}
