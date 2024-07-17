use std::rc::Rc;

use pkt::{vxlan, Packet};

use crate::func;
use crate::libapi::{Class, ClassDef, FuncDef, Module};
use crate::sym::Symbol;
use crate::val::{Val, ValDef};
use ezpkt::VxlanFlow;

const ENCAP: FuncDef = func!(
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

const DGRAM: FuncDef = func!(
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

const VXLAN: ClassDef = class!(
    /// VXLAN Session
    resynth class Vxlan {
        dgram => Symbol::Func(&DGRAM),
        encap => Symbol::Func(&ENCAP),
    }
);

impl Class for VxlanFlow {
    fn def(&self) -> &'static ClassDef {
        &VXLAN
    }
}

const SESSION: FuncDef = func!(
    /// Create a VXLAN session
    resynth fn session(
        cl: Sock4,
        sv: Sock4,
        =>
        sessionid: U32 = 0, // TODO: Make it optional
        raw: Bool = false,
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
        Vxlan => Symbol::Class(&VXLAN),
        session => Symbol::Func(&SESSION),
        DEFAULT_PORT => Symbol::u16(vxlan::DEFAULT_PORT),
    }
};
