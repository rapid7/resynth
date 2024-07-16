use crate::func_def;
use crate::libapi::{Class, ClassDef, FuncDef, Module};
use crate::str::Buf;
use crate::sym::Symbol;
use crate::val::{Val, ValDef};
use ezpkt::IcmpFlow;

const ICMP_ECHO: FuncDef = func_def!(
    /// ICMP Ping
    resynth fn echo(
        payload: Str,
        =>
        =>
        Void
    ) -> Pkt
    | mut args | {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut IcmpFlow = r.as_mut_any().downcast_mut().unwrap();
        let bytes: Buf = args.next().into();
        Ok(this.echo(bytes.as_ref()).into())
    }
);

const ICMP_ECHO_REPLY: FuncDef = func_def!(
    /// ICMP Ping reply
    resynth fn echo_reply(
        payload: Str,
        =>
        =>
        Void
    ) -> Pkt
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut IcmpFlow = r.as_mut_any().downcast_mut().unwrap();
        let bytes: Buf = args.next().into();
        Ok(this.echo_reply(bytes.as_ref()).into())
    }
);

const ICMP: ClassDef = class!(
    /// ICMP Session
    resynth class Icmp {
        echo => Symbol::Func(&ICMP_ECHO),
        echo_reply => Symbol::Func(&ICMP_ECHO_REPLY),
    }
);

impl Class for IcmpFlow {
    fn def(&self) -> &'static ClassDef {
        &ICMP
    }
}

const ICMP_FLOW: FuncDef = func_def!(
    /// Create an ICMP flow
    resynth fn flow(
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
        let raw = args.next();
        Ok(Val::from(IcmpFlow::new(cl.into(), sv.into(), raw.into())))
    }
);

pub const ICMP4: Module = module! {
    /// ICMP
    resynth mod icmp {
        Icmp => Symbol::Class(&ICMP),
        flow => Symbol::Func(&ICMP_FLOW),
    }
};
