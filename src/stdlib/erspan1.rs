use std::rc::Rc;

use phf::{phf_map, phf_ordered_map};

use pkt::Packet;

use crate::val::{Val, ValDef, ValType};
use crate::libapi::{FuncDef, ArgDecl, Class};
use crate::sym::Symbol;
use ezpkt::Erspan1Flow;
use crate::func_def;

const ENCAP: FuncDef = func_def!(
    "erspan1::session.encap";
    ValType::PktGen;

    "gen" => ValType::PktGen
    =>
    =>
    ValType::Void;

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
    "session";
    ValType::Obj;

    "cl" => ValType::Ip4,
    "sv" => ValType::Ip4,
    =>
    "raw" => ValDef::Bool(false),
    =>
    ValType::Void;

    |mut args| {
        let cl = args.next();
        let sv = args.next();
        let raw: bool = args.next().into();
        Ok(Val::from(Erspan1Flow::new(cl.into(), sv.into(), raw)))
    }
);

pub const MODULE: phf::Map<&'static str, Symbol> = phf_map! {
    "session" => Symbol::Func(&SESSION),
};
