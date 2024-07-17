use std::rc::Rc;

use pkt::Packet;

use crate::func;
use crate::libapi::{Class, ClassDef, FuncDef, Module};
use crate::sym::Symbol;
use crate::val::{Val, ValDef};
use ezpkt::Erspan1Flow;

const ENCAP: FuncDef = func!(
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

const ERSPAN1: ClassDef = class!(
    /// ERSPAN1 Session
    resynth class Erspan1 {
        encap => Symbol::Func(&ENCAP),
    }
);

impl Class for Erspan1Flow {
    fn def(&self) -> &'static ClassDef {
        &ERSPAN1
    }
}

const SESSION: FuncDef = func!(
    /// Create an ERSPAN session
    resynth fn session(
        cl: Ip4,
        sv: Ip4,
        =>
        raw: Bool = false,
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
        Erspan1 => Symbol::Class(&ERSPAN1),
        session => Symbol::Func(&SESSION),
    }
};
