use std::rc::Rc;

use phf::phf_map;

use pkt::Packet;

use crate::func_def;
use crate::libapi::{ArgDecl, ArgDesc, Class, FuncDef};
use crate::sym::Symbol;
use crate::val::{Val, ValDef, ValType};
use ezpkt::Erspan2Flow;

const ENCAP: FuncDef = func_def!(
    /// Encapsulate packets in ERSPAN2
    resynth encap(
        gen: PktGen
        =>
        port_index: ValDef::U32(0),
        =>
        Void
    ) -> PktGen
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut Erspan2Flow = r.as_mut_any().downcast_mut().unwrap();
        let gen: Rc<Vec<Packet>> = args.next().into();
        let port_index: u32 = args.next().into();

        let mut ret: Vec<Packet> = Vec::with_capacity(gen.len());

        for pkt in gen.iter() {
            ret.push(this.encap(&pkt.as_slice().get(pkt), port_index));
        }

        Ok(ret.into())
    }
);

impl Class for Erspan2Flow {
    fn symbols(&self) -> phf::Map<&'static str, Symbol> {
        phf_map! {
            "encap" => Symbol::Func(&ENCAP),
        }
    }

    fn class_name(&self) -> &'static str {
        "erspan2.session"
    }
}

const SESSION: FuncDef = func_def!(
    /// Create an erspan2 session
    resynth session(
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
        Ok(Val::from(Erspan2Flow::new(cl.into(), sv.into(), raw)))
    }
);

pub const MODULE: phf::Map<&'static str, Symbol> = phf_map! {
    "session" => Symbol::Func(&SESSION),
};
