use pkt::dns::{DnsFlags, rcode};
use pkt::netbios::{name, ns};

use crate::err::Error::RuntimeError;
use crate::libapi::{FuncDef, Module};
use crate::str::Buf;
use crate::sym::Symbol;
use crate::val::{Val, ValDef};

const OPCODE: Module = module! {
    /// # NetBIOS Name Service Opcodes
    resynth mod opcode {
        QUERY => Symbol::u8(ns::opcode::QUERY),
        REGISTRATION => Symbol::u8(ns::opcode::REGISTRATION),
        RELEASE => Symbol::u8(ns::opcode::RELEASE),
        WACK => Symbol::u8(ns::opcode::WACK),
        REFRESH => Symbol::u8(ns::opcode::REFRESH),
        REFRESH_ALT => Symbol::u8(ns::opcode::REFRESH_ALT),
        MH_REGISTRATION => Symbol::u8(ns::opcode::MH_REGISTRATION),
    }
};

const RRTYPE: Module = module! {
    /// # NetBIOS Name Service RR types
    resynth mod rrtype {
        NULL => Symbol::u16(ns::rrtype::NULL),
        NB => Symbol::u16(ns::rrtype::NB),
        NBSTAT => Symbol::u16(ns::rrtype::NBSTAT),
    }
};

const RCODE: Module = module! {
    /// # NetBIOS Name Service Response codes
    resynth mod rcode {
        ACT_ERR => Symbol::u8(ns::rcode::ACT_ERR),
        CFT_ERR => Symbol::u8(ns::rcode::CFT_ERR),
    }
};

const NBNS_FLAGS: FuncDef = func!(
    /// Returns netbios-ns flags
    resynth fn flags(
        /// NetBIOS name service opcode
        opcode: U8,
        =>
        /// If true, this is a response; if false, a query
        response: Bool = false,
        /// Authoritative Answer flag
        aa: Bool = false,
        /// Truncation flag
        tc: Bool = false,
        /// Recursion Desired flag
        rd: Bool = false,
        /// Recursion Available flag
        ra: Bool = false,
        /// Reserved (Z) bit
        z: Bool = false,
        /// Must be zero (maps to DNS AD bit)
        ad: Bool = false, // must be zero
        /// Broadcast/multicast flag
        b: Bool = false,
        /// Response code
        rcode: U8 = rcode::NOERROR,
        =>
        Void
    ) -> U16
    |mut args| {
        let opcode: u8 = args.next().into();

        let response: bool = args.next().into();
        let aa: bool = args.next().into();
        let tc: bool = args.next().into();
        let rd: bool = args.next().into();
        let ra: bool = args.next().into();
        let z: bool = args.next().into();
        let ad: bool = args.next().into();
        let b: bool = args.next().into();
        let rcode: u8 = args.next().into();

        Ok(Val::U16(DnsFlags::default()
            .response(response)
            .opcode(opcode)
            .aa(aa)
            .tc(tc)
            .rd(rd)
            .ra(ra)
            .z(z)
            .ad(ad)
            .cd(b) // CD is called B in NBNS
            .rcode(rcode)
            .build())
        )
    }
);

pub const NS: Module = module! {
    /// # NetBIOS Name Service
    resynth mod ns {
        opcode => Symbol::Module(&OPCODE),
        rrtype => Symbol::Module(&RRTYPE),
        rcode => Symbol::Module(&RCODE),
        flags => Symbol::Func(&NBNS_FLAGS),
    }
};

const NAME_ENCODE: FuncDef = func! (
    /// First-level encode a NetBIOS name, including padding and the one-byte suffix field.
    ///
    /// Returns the raw 32 encoded bytes only — no DNS label length prefix or
    /// terminating null byte. To produce a complete DNS-format name label
    /// suitable for use in an NBNS packet, wrap the result with `dns::name()`:
    ///
    /// ```resynth
    /// dns::name(netbios::name::encode("BILLG"))
    /// ```
    resynth fn encode(
        =>
        /// One-byte suffix identifying the NetBIOS name type
        suffix: U8 = 0,
        =>
        Str
    ) -> Str
    |mut args| {
        let suffix: u8 = args.next().into();
        let data: Buf = args.join_extra(b"").into();
        let res = name::encode(data.as_ref(), suffix).ok_or(RuntimeError)?;

        Ok(Val::Str(res.as_ref().into()))
    }
);

pub const NAME: Module = module! {
    /// # NetBIOS names
    resynth mod name {
        encode => Symbol::Func(&NAME_ENCODE),
    }
};

pub const NETBIOS: Module = module! {
    /// # Microsoft NetBIOS
    ///
    /// NetBIOS over TCP/IP — name encoding, name-service queries, and protocol constants.
    ///
    /// ## Wire format
    ///
    /// NetBIOS Name Service (NBNS, UDP port 137) uses the DNS wire format: the same
    /// 12-byte header, question, and resource record structures. Use the `dns` module
    /// helpers (`dns::hdr`, `dns::flags`, `dns::name`, `dns::answer`) to build the
    /// packet framing, and the `netbios` helpers for name encoding and NBNS-specific
    /// constants.
    ///
    /// ### Example: positive Name Query Response for "BILLG" (workstation)
    ///
    /// ```resynth
    /// import ipv4;
    /// import dns;
    /// import netbios;
    ///
    /// ipv4::udp::unicast(
    ///     192.168.1.100/137,
    ///     192.168.1.1/137,
    ///     dns::hdr(
    ///         0x1234,
    ///         netbios::ns::flags(netbios::ns::opcode::QUERY, response: true, aa: true, ra: true),
    ///         ancount: 1,
    ///     ),
    ///     dns::answer(
    ///         dns::name(netbios::name::encode("BILLG")),
    ///         atype: netbios::ns::rrtype::NB,
    ///         ttl: 300,
    ///         std::be16(0x0000),       # NB_FLAGS: B-node, unique
    ///         192.168.1.100,           # NB_ADDRESS
    ///     ),
    /// );
    /// ```
    resynth mod netbios {
        ns => Symbol::Module(&NS),
        name => Symbol::Module(&NAME),
    }
};
