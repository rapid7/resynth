use pkt::{Packet, Hdr, AsBytes};
use pkt::dhcp::{dhcp_hdr, dhcp_opt, MAGIC};


const MIN_CAPACITY: usize = std::mem::size_of::<dhcp_hdr>();
const DEFAULT_CAPACITY: usize = 3 + 3 + 6;

pub struct Dhcp {
    pkt: Packet,
    dhcp: Hdr<dhcp_hdr>,
}

impl Default for Dhcp {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }
}

impl Dhcp {
    pub fn with_capacity(capacity: usize) -> Self {
        let pkt = Packet::with_capacity(MIN_CAPACITY + capacity);
        let dhcp: Hdr<dhcp_hdr> = pkt.push_hdr();

       dhcp.get_mut(&pkt).magic = MAGIC.to_be();

        Self {
            pkt,
            dhcp,
        }
    }

    pub fn min_capacity() -> Self {
        Self::with_capacity(0)
    }

    #[must_use]
    pub fn op(self, op: u8) -> Self {
        self.dhcp.get_mut(&self.pkt).op = op;
        self
    }

    #[must_use]
    pub fn htype(self, htype: u8) -> Self {
        self.dhcp.get_mut(&self.pkt).htype = htype;
        self
    }

    #[must_use]
    pub fn hlen(self, hlen: u8) -> Self {
        self.dhcp.get_mut(&self.pkt).hlen = hlen;
        self
    }

    #[must_use]
    pub fn hops(self, hops: u8) -> Self {
        self.dhcp.get_mut(&self.pkt).hops = hops;
        self
    }

    #[must_use]
    pub fn xid(self, xid: u32) -> Self {
        self.dhcp.get_mut(&self.pkt).xid = xid.to_be();
        self
    }

    #[must_use]
    pub fn secs(self, secs: u16) -> Self {
        self.dhcp.get_mut(&self.pkt).secs = secs.to_be();
        self
    }

    #[must_use]
    pub fn flags(self, flags: u16) -> Self {
        self.dhcp.get_mut(&self.pkt).flags = flags.to_be();
        self
    }

    #[must_use]
    pub fn ciaddr(self, ciaddr: u32) -> Self {
        self.dhcp.get_mut(&self.pkt).ciaddr = ciaddr.to_be();
        self
    }

    #[must_use]
    pub fn yiaddr(self, yiaddr: u32) -> Self {
        self.dhcp.get_mut(&self.pkt).yiaddr = yiaddr.to_be();
        self
    }

    #[must_use]
    pub fn siaddr(self, siaddr: u32) -> Self {
        self.dhcp.get_mut(&self.pkt).siaddr = siaddr.to_be();
        self
    }

    #[must_use]
    pub fn giaddr(self, giaddr: u32) -> Self {
        self.dhcp.get_mut(&self.pkt).giaddr = giaddr.to_be();
        self
    }

    #[must_use]
    pub fn chaddr<T: AsRef<[u8]>>(self, chaddr: T) -> Self {
        {
            let mut dhcp = self.dhcp.get_mut(&self.pkt);
            let buf = chaddr.as_ref();
            let cplen = std::cmp::min(buf.len(), dhcp.chaddr.len());
            dhcp.chaddr[..cplen].copy_from_slice(&buf[..cplen]);
        }
        self
    }

    #[must_use]
    pub fn sname<T: AsRef<[u8]>>(self, sname: T) -> Self {
        {
            let mut dhcp = self.dhcp.get_mut(&self.pkt);
            let buf = sname.as_ref();
            let cplen = std::cmp::min(buf.len(), dhcp.sname.len());
            dhcp.sname[..cplen].copy_from_slice(&buf[..cplen]);
        }
        self
    }

    #[must_use]
    pub fn file<T: AsRef<[u8]>>(self, file: T) -> Self {
        {
            let mut dhcp = self.dhcp.get_mut(&self.pkt);
            let buf = file.as_ref();
            let cplen = std::cmp::min(buf.len(), dhcp.file.len());
            dhcp.file[..cplen].copy_from_slice(&buf[..cplen]);
        }
        self
    }

    #[must_use]
    pub fn magic(self, magic: u32) -> Self {
        self.dhcp.get_mut(&self.pkt).magic = magic.to_be();
        self
    }

    #[must_use]
    pub fn opt<T: AsRef<[u8]>>(self, opt: u8, buf: T) -> Self {
        self.pkt.push_bytes(dhcp_opt::from_buf(opt, &buf).as_bytes());
        self.pkt.push_bytes(buf);
        self
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.pkt.into()
    }
}
