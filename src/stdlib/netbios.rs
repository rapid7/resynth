use pkt::dns::{rcode, DnsFlags};
use pkt::netbios::{name, ns};

use crate::err::Error::RuntimeError;
use crate::func;
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
        opcode: U8,
        =>
        response: Bool = false,
        aa: Bool = false,
        tc: Bool = false,
        rd: Bool = false,
        ra: Bool = false,
        z: Bool = false,
        ad: Bool = false, // must be zero
        b: Bool = false,
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
    /// Encode a netbios name, including the one-byte suffix field
    resynth fn encode(
        =>
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
    resynth mod netbios {
        ns => Symbol::Module(&NS),
        name => Symbol::Module(&NAME),
    }
};
