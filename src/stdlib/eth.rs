use pkt::eth::{ethertype, BROADCAST};

use crate::libapi::Module;
use crate::sym::Symbol;
use crate::val::ValDef;

const TYPE: Module = module! {
    /// # Ethernet Ethertypes
    resynth mod ethertype {
        VLAN => Symbol::u16(ethertype::VLAN),
        FABRICPATH => Symbol::u16(ethertype::FABRICPATH),

        IPV4 => Symbol::u16(ethertype::IPV4),
        IPV6 => Symbol::u16(ethertype::IPV6),

        PPTP => Symbol::u16(ethertype::PPTP),
        GRETAP => Symbol::u16(ethertype::GRETAP),
        ERSPAN_1_2 => Symbol::u16(ethertype::ERSPAN_1_2),
        ERSPAN_3 => Symbol::u16(ethertype::ERSPAN_3),
    }
};

pub const MODULE: Module = module! {
    /// # Ethernet
    resynth mod eth {
        ethertype => Symbol::Module(&TYPE),
        BROADCAST => Symbol::Val(ValDef::Str(&BROADCAST)),
    }
};
