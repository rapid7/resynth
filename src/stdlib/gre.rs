use std::rc::Rc;

use phf::phf_map;

use pkt::gre::GreFlags;
use pkt::Packet;

use crate::func_def;
use crate::libapi::{Class, FuncDef, Module};
use crate::sym::Symbol;
use crate::val::{Val, ValDef};
use ezpkt::GreFlow;

const ENCAP: FuncDef = func_def!(
    /// Encapsulate packets in GRETAP
    resynth fn encap(
        gen: PktGen
        =>
        =>
        Void
    ) -> PktGen
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut GreFlow = r.as_mut_any().downcast_mut().unwrap();
        let gen: Rc<Vec<Packet>> = args.next().into();

        let mut ret: Vec<Packet> = Vec::with_capacity(gen.len());

        for pkt in gen.iter() {
            ret.push(this.encap(&pkt.as_slice().get(pkt)));
        }

        Ok(ret.into())
    }
);

impl Class for GreFlow {
    fn symbols(&self) -> phf::Map<&'static str, Symbol> {
        phf_map! {
            "encap" => Symbol::Func(&ENCAP),
        }
    }

    fn class_name(&self) -> &'static str {
        "gre.session"
    }
}

const SESSION: FuncDef = func_def!(
    /// Create a GRETAP session
    resynth fn session(
        cl: Ip4,
        sv: Ip4,
        ethertype: U16,
        =>
        raw: ValDef::Bool(false),
        =>
        Void
    ) -> Obj
    |mut args| {
        let cl = args.next();
        let sv = args.next();
        let flags = GreFlags::default();
        let ethertype: u16= args.next().into();
        let raw: bool = args.next().into();

        Ok(Val::from(GreFlow::new(cl.into(), sv.into(), flags, ethertype, raw)))
    }
);

pub const MODULE: Module = module! {
    /// Genneric Routing Encapsulation (GRE)
    resynth mod gre {
        session => Symbol::Func(&SESSION),
    }
};
