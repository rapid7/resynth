use phf::{phf_map, phf_ordered_map};

use pkt::dns::{DnsFlags, rcode};
use pkt::netbios::{ns, name};

use crate::val::{ValType, Val, ValDef};
use crate::libapi::{FuncDef, ArgDecl};
use crate::err::Error::RuntimeError;
use crate::sym::Symbol;
use crate::str::Buf;
use crate::func_def;

const OPCODE: phf::Map<&'static str, Symbol> = phf_map! {
    "QUERY" => Symbol::u8(ns::opcode::QUERY),
    "REGISTRATION" => Symbol::u8(ns::opcode::REGISTRATION),
    "RELEASE" => Symbol::u8(ns::opcode::RELEASE),
    "WACK" => Symbol::u8(ns::opcode::WACK),
    "REFRESH" => Symbol::u8(ns::opcode::REFRESH),
    "REFRESH_ALT" => Symbol::u8(ns::opcode::REFRESH_ALT),
    "MH_REGISTRATION" => Symbol::u8(ns::opcode::MH_REGISTRATION),
};

const RRTYPE: phf::Map<&'static str, Symbol> = phf_map! {
    "NULL" => Symbol::u16(ns::rrtype::NULL),
    "NB" => Symbol::u16(ns::rrtype::NB),
    "NBSTAT" => Symbol::u16(ns::rrtype::NBSTAT),
};

const RCODE: phf::Map<&'static str, Symbol> = phf_map! {
    "ACT_ERR" => Symbol::u8(ns::rcode::ACT_ERR),
    "CFT_ERR" => Symbol::u8(ns::rcode::CFT_ERR),
};

const NBNS_FLAGS: FuncDef = func_def!(
    "netbios::ns::flags";
    ValType::U16;

    "opcode" => ValType::U8,
    =>
    "response" => ValDef::Bool(false),
    "aa" => ValDef::Bool(false),
    "tc" => ValDef::Bool(false),
    "rd" => ValDef::Bool(false),
    "ra" => ValDef::Bool(false),
    "z" => ValDef::Bool(false),
    "ad" => ValDef::Bool(false), // must be zero
    "b" => ValDef::Bool(false),
    "rcode" => ValDef::U8(rcode::NOERROR),
    =>
    ValType::Void;

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

pub const NS: phf::Map<&'static str, Symbol> = phf_map! {
    "opcode" => Symbol::Module(&OPCODE),
    "rrtype" => Symbol::Module(&RRTYPE),
    "rcode" => Symbol::Module(&RCODE),
    "flags" => Symbol::Func(&NBNS_FLAGS),
};

const NAME_ENCODE: FuncDef = func_def! (
    "netbios::name";
    ValType::Str;

    =>
    "suffix" => ValDef::U8(0),
    =>
    ValType::Str;

    |mut args| {
        let suffix: u8 = args.next().into();
        let data: Buf = args.join_extra(b"").into();
        let res = name::encode(data.as_ref(), suffix).ok_or(RuntimeError)?;

        Ok(Val::Str(res.as_ref().into()))
    }
);

pub const NAME: phf::Map<&'static str, Symbol> = phf_map! {
    "encode" => Symbol::Func(&NAME_ENCODE),
};

pub const NETBIOS: phf::Map<&'static str, Symbol> = phf_map! {
    "ns" => Symbol::Module(&NS),
    "name" => Symbol::Module(&NAME),
};
