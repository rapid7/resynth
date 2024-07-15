use std::rc::Rc;

use phf::phf_map;

use pkt::{vxlan, Packet};

use crate::func_def;
use crate::libapi::{Class, FuncDef, Module};
use crate::sym::Symbol;
use crate::val::{Val, ValDef};
use ezpkt::VxlanFlow;

const ENCAP: FuncDef = func_def!(
    /// Encapsulate a series of packets
    resynth fn encap(
        gen: PktGen
        =>
        =>
        Void
    ) -> PktGen
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
    resynth fn dgram(
        pkt: Pkt
        =>
        =>
        Void
    ) -> Pkt
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
    resynth fn session(
        cl: Sock4,
        sv: Sock4,
        =>
        sessionid: ValDef::U32(0), // TODO: Make it optional
        raw: ValDef::Bool(false),
        =>
        Void
    ) -> Obj
    |mut args| {
        let cl = args.next();
        let sv = args.next();
        let vni: u32 = args.next().into();
        let raw: bool = args.next().into();
        Ok(Val::from(VxlanFlow::new(cl.into(), sv.into(), vni, raw)))
    }
);

pub const MODULE: Module = module! {
    /// VXLAN Encapsulation
    ///
    /// Encapsulates ethernet frames in UDP datagrams.
    resynth mod vxlan {
        session => Symbol::Func(&SESSION),
        DEFAULT_PORT => Symbol::u16(vxlan::DEFAULT_PORT),
    }
};
