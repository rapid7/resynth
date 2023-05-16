use std::net::Ipv4Addr;

pub mod ethertype {
    pub const VLAN: u16 = 0x8100;
    pub const FABRICPATH: u16 = 0x8903;

    pub const IPV4: u16 = 0x0800;
    pub const IPV6: u16 = 0x86dd;

    pub const PPTP: u16 = 0x880b;
    pub const GRETAP: u16 = 0x6558;
    pub const ERSPAN_1_2: u16 = 0x88be;
    pub const ERSPAN_3: u16 = 0x22eb;
}

#[repr(C, packed(1))]
#[derive(Debug, Copy, Clone)]
pub struct eth_addr {
    octets: [u8; 6],
}

#[repr(C, packed(1))]
#[derive(Debug, Copy, Clone)]
pub struct eth_hdr {
    pub dst: eth_addr,
    pub src: eth_addr,
    pub proto: u16,
}

pub const BROADCAST: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

impl eth_hdr {
    pub fn dst_from_ip(&mut self, addr: Ipv4Addr) -> &mut Self {
        let ip = addr.octets();
        self.dst.octets = [0x00, 0x02, ip[0], ip[1], ip[2], ip[3]];
        self
    }

    pub fn src_from_ip(&mut self, addr: Ipv4Addr) -> &mut Self {
        let ip = addr.octets();
        self.src.octets = [0x00, 0x02, ip[0], ip[1], ip[2], ip[3]];
        self
    }

    pub fn proto(&mut self, proto: u16) -> &mut Self {
        self.proto = proto.to_be();
        self
    }

    pub fn broadcast(&mut self) -> &mut Self {
        self.dst.octets = BROADCAST;
        self
    }
}
