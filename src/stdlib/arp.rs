use pkt::arp::hrd;

use crate::{libapi::Module, sym::Symbol};

const HRD: Module = module!(
    /// # ARP Hardware types
    resynth mod hrd {
        ETHER => Symbol::int_val(hrd::ETHER as u64),
    }
);

pub const MODULE: Module = module!(
    /// # Address Resolution Protocol
    resynth mod arp {
        hrd => Symbol::Module(&HRD),
    }
);
