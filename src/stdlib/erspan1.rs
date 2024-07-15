use std::rc::Rc;

use phf::phf_map;

use pkt::Packet;

use crate::func_def;
use crate::libapi::{Class, FuncDef, Module};
use crate::sym::Symbol;
use crate::val::{Val, ValDef};
use ezpkt::Erspan1Flow;

const ENCAP: FuncDef = func_def!(
    /// Encapsulate a sequence of packets
    resynth fn encap(
        gen: PktGen
        =>
        =>
        Void
    ) -> PktGen
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut Erspan1Flow = r.as_mut_any().downcast_mut().unwrap();
        let gen: Rc<Vec<Packet>> = args.next().into();

        let mut ret: Vec<Packet> = Vec::with_capacity(gen.len());

        for pkt in gen.iter() {
            ret.push(this.encap(&pkt.as_slice().get(pkt)));
        }

        Ok(ret.into())
    }
);

impl Class for Erspan1Flow {
    fn symbols(&self) -> phf::Map<&'static str, Symbol> {
        phf_map! {
            "encap" => Symbol::Func(&ENCAP),
        }
    }

    fn class_name(&self) -> &'static str {
        "erspan1.session"
    }
}

const SESSION: FuncDef = func_def!(
    /// Create an ERSPAN session
    resynth fn session(
        cl: Ip4,
        sv: Ip4,
        =>
        raw: ValDef::Bool(false),
        =>
        Void
    ) -> Obj
    |mut args| {
        let cl = args.next();
        let sv = args.next();
        let raw: bool = args.next().into();
        Ok(Val::from(Erspan1Flow::new(cl.into(), sv.into(), raw)))
    }
);

pub const MODULE: Module = module! {
    /// ERSPAN Version 1
    resynth mod erspan1 {
        session => Symbol::Func(&SESSION),
    }
};
