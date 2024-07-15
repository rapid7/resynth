use std::rc::Rc;

use pkt::gre::GreFlags;
use pkt::Packet;

use crate::func_def;
use crate::libapi::{Class, ClassDef, FuncDef, Module};
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

const GRE: ClassDef = class!(
    /// GRE Session
    resynth class Gre {
        encap => Symbol::Func(&ENCAP),
    }
);

impl Class for GreFlow {
    fn def(&self) -> &'static ClassDef {
        &GRE
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
        Gre => Symbol::Class(&GRE),
        session => Symbol::Func(&SESSION),
    }
};
