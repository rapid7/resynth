use std::rc::Rc;

use phf::{phf_map, phf_ordered_map};

use pkt::{vxlan, Packet};

use crate::func_def;
use crate::libapi::{ArgDecl, Class, FuncDef};
use crate::sym::Symbol;
use crate::val::{Val, ValDef, ValType};
use ezpkt::VxlanFlow;

const ENCAP: FuncDef = func_def!(
    /// Encapsulate a series of packets
    "vxlan::flow.encap";
    ValType::PktGen;

    "gen" => ValType::PktGen
    =>
    =>
    ValType::Void;

    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut VxlanFlow = r.as_mut_any().downcast_mut().unwrap();
        let gen: Rc<Vec<Packet>> = args.next().into();

        let mut ret: Vec<Packet> = Vec::with_capacity(gen.len());

        for pkt in gen.iter() {
            ret.push(this.encap(&pkt.as_slice().get(pkt)));
        }

        Ok(ret.into())
    }
);

const DGRAM: FuncDef = func_def!(
    /// Encapsulate a single packet
    "vxlan::flow.dgram";
    ValType::Pkt;

    "pkt" => ValType::Pkt
    =>
    =>
    ValType::Void;

    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut VxlanFlow = r.as_mut_any().downcast_mut().unwrap();
        let pkt: Rc<Packet> = args.next().into();
        let ret = Ok(this.encap(&pkt.as_slice().get(&pkt)).into());
        ret
    }
);

impl Class for VxlanFlow {
    fn symbols(&self) -> phf::Map<&'static str, Symbol> {
        phf_map! {
            "dgram" => Symbol::Func(&DGRAM),
            "encap" => Symbol::Func(&ENCAP),
        }
    }

    fn class_name(&self) -> &'static str {
        "vxlan.flow"
    }
}

const SESSION: FuncDef = func_def!(
    /// Create a VXLAN session
    "vxlan::session";
    ValType::Obj;

    "cl" => ValType::Sock4,
    "sv" => ValType::Sock4,
    =>
    "sessionid" => ValDef::U32(0), // TODO: Make it optional
    "raw" => ValDef::Bool(false),
    =>
    ValType::Void;

    |mut args| {
        let cl = args.next();
        let sv = args.next();
        let vni: u32 = args.next().into();
        let raw: bool = args.next().into();
        Ok(Val::from(VxlanFlow::new(cl.into(), sv.into(), vni, raw)))
    }
);

pub const MODULE: phf::Map<&'static str, Symbol> = phf_map! {
    "session" => Symbol::Func(&SESSION),
    "DEFAULT_PORT" => Symbol::u16(vxlan::DEFAULT_PORT),
};
