use std::rc::Rc;

use pkt::Packet;

use crate::libapi::{Class, ClassDef, FuncDef, Module};
use crate::sym::Symbol;
use crate::val::{Val, ValDef};
use ezpkt::Erspan3Flow;

const ENCAP: FuncDef = func!(
    /// Encapsulate packets in ERSPAN3
    resynth fn encap(
        it: PktGen
        =>
        timestamp: U32 = 0,
        =>
        Void
    ) -> PktGen
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut Erspan3Flow = r.as_mut_any().downcast_mut().unwrap();
        let it: Rc<Box<[Packet]>> = args.next().into();
        let timestamp: u32 = args.next().into();

        let ret: Vec<Packet> = it
            .iter()
            .map(|pkt| this.encap(&pkt.as_slice().get(pkt), timestamp))
            .collect();

        Ok(ret.into())
    }
);

const ERSPAN3: ClassDef = class!(
    /// # ERSPAN3 Session
    resynth class Erspan3 {
        encap => Symbol::Func(&ENCAP),
    }
);

impl Class for Erspan3Flow {
    fn def(&self) -> &'static ClassDef {
        &ERSPAN3
    }
}

const SESSION: FuncDef = func!(
    /// Create an erspan3 session
    resynth fn session(
        cl: Ip4,
        sv: Ip4,
        =>
        raw: Bool = false,
        hwid: U32 = 0,
        sgt: U32 = 0,
        granularity: U32 = 0,
        direction: U32 = 0,
        =>
        Void
    ) -> Class(&ERSPAN3)
    |mut args| {
        let cl = args.next();
        let sv = args.next();
        let raw: bool = args.next().into();
        let hwid: u32 = args.next().into();
        let sgt: u32 = args.next().into();
        let gra: u32 = args.next().into();
        let d: u32 = args.next().into();
        let mut flow = Erspan3Flow::new(cl.into(), sv.into(), raw);
        flow.hwid = hwid as u8;
        flow.sgt = sgt as u16;
        flow.gra = gra as u8;
        flow.d = d != 0;
        Ok(Val::from(flow))
    }
);

pub const MODULE: Module = module! {
    /// # ERSPAN version 3
    resynth mod erspan3 {
        Erspan3 => Symbol::Class(&ERSPAN3),
        session => Symbol::Func(&SESSION),
    }
};
