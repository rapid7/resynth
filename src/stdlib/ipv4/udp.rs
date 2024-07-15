use phf::phf_map;

use std::net::Ipv4Addr;

use ezpkt::{UdpDgram, UdpFlow};
use pkt::{ipv4::udp_hdr, AsBytes, Packet};

use crate::func_def;
use crate::libapi::{Class, FuncDef, Module};
use crate::str::Buf;
use crate::sym::Symbol;
use crate::val::{Val, ValDef};

const BROADCAST: FuncDef = func_def!(
    /// Send a broadcast datagram
    resynth broadcast(
        src: Sock4,
        dst: Sock4,
        =>
        srcip: ValDef::Type(ValType::Ip4),
        raw: ValDef::Bool(false),
        =>
        Str
    ) -> Pkt
    |mut args| {
        let src = args.next();
        let dst = args.next();
        let srcip: Option<Ipv4Addr> = args.next().into();
        let raw: bool = args.next().into();
        let buf: Buf = args.join_extra(b"").into();

        let mut dgram = UdpDgram::with_capacity(buf.len(), raw)
            .src(src.into())
            .dst(dst.into())
            .broadcast()
            .push(buf);

        if let Some(src) = srcip {
            dgram = dgram.srcip(src);
        }

        let pkt: Packet = dgram.into();
        Ok(pkt.into())
    }
);

const UNICAST: FuncDef = func_def!(
    /// Send a unicast datagram
    resynth unicast(
        src: Sock4,
        dst: Sock4,
        =>
        raw: ValDef::Bool(false),
        =>
        Str
    ) -> Pkt
    |mut args| {
        let src = args.next();
        let dst = args.next();
        let raw: bool = args.next().into();
        let buf: Buf = args.join_extra(b"").into();
        let dgram: Packet = UdpDgram::with_capacity(buf.len(), raw)
            .src(src.into())
            .dst(dst.into())
            .push(buf)
            .into();
        Ok(dgram.into())
    }
);

const HDR: FuncDef = func_def!(
    /// Returns a UDP header (with no IP header)
    resynth hdr(
        src: U16,
        dst: U16,
        =>
        len: ValDef::U16(0),
        csum: ValDef::U16(0),
        =>
        Void
    ) -> Str
    |mut args| {
        let src: u16 = args.next().into();
        let dst: u16 = args.next().into();
        let len: u16 = args.next().into();
        let csum: u16 = args.next().into();

        let hdr = udp_hdr {
            sport: src.to_be(),
            dport: dst.to_be(),
            len: (len + std::mem::size_of::<udp_hdr>() as u16).to_be(),
            csum: csum.to_be(),
        };

        Ok(Val::Str(Buf::from(hdr.as_bytes())))
    }
);

const CL_DGRAM: FuncDef = func_def!(
    /// Send a datagram from client to server
    resynth client_dgram(
        =>
        frag_off: ValDef::U16(0),
        csum: ValDef::Bool(true),
        =>
        Str
    ) -> Pkt
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut UdpFlow = r.as_mut_any().downcast_mut().unwrap();
        let frag_off: u16 = args.next().into();
        let csum: bool = args.next().into();

        let bytes: Buf = args.join_extra(b"").into();

        let mut dgram = this.client_dgram(bytes.as_ref()).frag_off(frag_off);

        if csum {
            dgram = dgram.csum();
        }

        Ok(Val::Pkt(dgram.into()))
    }
);

const SV_DGRAM: FuncDef = func_def!(
    /// Send a datagram from server to client
    resynth server_dgram(
        =>
        frag_off: ValDef::U16(0),
        csum: ValDef::Bool(true),
        =>
        Str
    ) -> Pkt
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut UdpFlow = r.as_mut_any().downcast_mut().unwrap();
        let frag_off: u16 = args.next().into();
        let csum: bool = args.next().into();

        let bytes: Buf = args.join_extra(b"").into();

        let mut dgram = this.server_dgram(bytes.as_ref()).frag_off(frag_off);

        if csum {
            dgram = dgram.csum();
        }

        Ok(Val::Pkt(dgram.into()))
    }
);

const CL_RAW_DGRAM: FuncDef = func_def!(
    /// Return a datagram from client to server (minus IP header)
    resynth client_raw_dgram(
        =>
        csum: ValDef::Bool(true),
        =>
        Str
    ) -> Str
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut UdpFlow = r.as_mut_any().downcast_mut().unwrap();
        let csum: bool = args.next().into();

        let bytes: Buf = args.join_extra(b"").into();

        let mut dgram = this.client_dgram(bytes.as_ref());

        if csum {
            dgram = dgram.csum();
        }

        Ok(Val::str(dgram.into_udp_dgram()))
    }
);

const SV_RAW_DGRAM: FuncDef = func_def!(
    /// Return a datagram from server to client (minus IP header)
    resynth server_raw_dgram(
        =>
        csum: ValDef::Bool(true),
        =>
        Str
    ) -> Str
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut UdpFlow = r.as_mut_any().downcast_mut().unwrap();
        let csum: bool = args.next().into();

        let bytes: Buf = args.join_extra(b"").into();

        let mut dgram = this.server_dgram(bytes.as_ref());

        if csum {
            dgram = dgram.csum();
        }

        Ok(Val::str(dgram.into_udp_dgram()))
    }
);

impl Class for UdpFlow {
    fn symbols(&self) -> phf::Map<&'static str, Symbol> {
        phf_map! {
            "client_dgram" => Symbol::Func(&CL_DGRAM),
            "server_dgram" => Symbol::Func(&SV_DGRAM),
            "client_raw_dgram" => Symbol::Func(&CL_RAW_DGRAM),
            "server_raw_dgram" => Symbol::Func(&SV_RAW_DGRAM),
        }
    }

    fn class_name(&self) -> &'static str {
        "ipv4::udp.flow"
    }
}

const FLOW: FuncDef = func_def!(
    /// Create a UDP flow context, from which other packets can be created
    resynth flow(
        cl: Sock4,
        sv: Sock4,
        =>
        raw: ValDef::Bool(false),
        =>
        Void
    ) -> Obj
    |mut args| {
        let cl = args.next();
        let sv = args.next();
        let raw = args.next();
        Ok(Val::from(UdpFlow::new(cl.into(), sv.into(), raw.into())))
    }
);

pub const UDP4: Module = module! {
    /// User Datagram Protocol
    module udp {
        flow => Symbol::Func(&FLOW),
        broadcast => Symbol::Func(&BROADCAST),
        unicast => Symbol::Func(&UNICAST),
        hdr => Symbol::Func(&HDR),
    }
};
