pub mod ns {
    pub mod opcode {
        pub const QUERY: u8 = 0;
        pub const REGISTRATION: u8 = 5;
        pub const RELEASE: u8 = 6;
        pub const WACK: u8 = 7;
        pub const REFRESH: u8 = 8;
        pub const REFRESH_ALT: u8 = 9;
        pub const MH_REGISTRATION: u8 = 15;
    }

    pub mod rrtype {
        /// NULL resource recourd (see: WACK)
        pub const NULL: u16 = 0x0a;

        /// NetBIOS general name service resource record
        pub const NB: u16 = 0x20;

        /// NetBIOS node status resource
        pub const NBSTAT: u16 = 0x21;
    }

    pub mod flags {
        /// Broadcast flag
        pub const B: u16 = 0x0010;
    }

    /// RFC-1002: 4.2.6
    pub mod rcode {
        /// Active error: name owned by another node
        pub const ACT_ERR: u8 = 6;

        /// Conflict error: UNIQUE name owned by more than one node
        pub const CFT_ERR: u8 = 7;
    }
}

pub mod name {
    use std::default::Default;

    pub fn raw_encode(name: [u8; 0x10]) -> [u8; 0x20] {
        let mut buf: [u8; 0x20] = Default::default();

        for i in 0..0x10 {
            let cur = name[i];
            let hi = (cur >> 4) + b'A';
            let lo = (cur & 0xf) + b'A';

            buf[i * 2] = hi;
            buf[i * 2 + 1] = lo;
        }

        buf
    }

    /// Pad a name with spaces to 15 chars and add a suffix byte for a total of 16 chars
    pub fn pad(name: &[u8], suffix: u8) -> Option<[u8; 0x10]> {
        let mut buf = [b' '; 0x10];

        if name.len() + 1 > buf.len() {
            return None;
        }

        buf[..name.len()].copy_from_slice(name);
        buf[0x0f] = suffix;

        Some(buf)
    }

    pub fn encode(name: &[u8], suffix: u8) -> Option<[u8; 0x20]> {
        Some(raw_encode(pad(name, suffix)?))
    }
}
