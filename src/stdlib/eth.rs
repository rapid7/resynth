use phf::phf_map;

use pkt::eth::{BROADCAST, ethertype};

use crate::val::ValDef;
use crate::sym::Symbol;

const TYPE: phf::Map<&'static str, Symbol> = phf_map! {
    "VLAN" => Symbol::u16(ethertype::VLAN),
    "FABRICPATH" => Symbol::u16(ethertype::FABRICPATH),

    "IPV4" => Symbol::u16(ethertype::IPV4),
    "IPV6" => Symbol::u16(ethertype::IPV6),

    "PPTP" => Symbol::u16(ethertype::PPTP),
    "GRETAP" => Symbol::u16(ethertype::GRETAP),
    "ERSPAN_1_2" => Symbol::u16(ethertype::ERSPAN_1_2),
    "ERSPAN_3" => Symbol::u16(ethertype::ERSPAN_3),
};


pub const MODULE: phf::Map<&'static str, Symbol> = phf_map! {
    "type" => Symbol::Module(&TYPE),
    "BROADCAST" => Symbol::Val(ValDef::Str(&BROADCAST)),
};
