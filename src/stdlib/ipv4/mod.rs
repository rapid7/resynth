use phf::{phf_map, phf_ordered_map};
use std::net::Ipv4Addr;

use pkt::eth::{eth_hdr, ethertype};
use pkt::ipv4::{ip_hdr, proto};
use pkt::Packet;

use ezpkt::IpFrag;

use crate::func_def;
use crate::libapi::{ArgDecl, Class, FuncDef};
use crate::str::Buf;
use crate::sym::Symbol;
use crate::val::{Val, ValDef, ValType};

mod icmp;
mod tcp;
mod udp;

use icmp::ICMP4;
use tcp::TCP4;
use udp::UDP4;

const PROTO: phf::Map<&'static str, Symbol> = phf_map! {
    "ICMP" => Symbol::u8(proto::ICMP),
    "TCP" => Symbol::u8(proto::TCP),
    "UDP" => Symbol::u8(proto::UDP),
    "GRE" => Symbol::u8(proto::GRE),
};

const IPV4_DGRAM_OVERHEAD: usize = std::mem::size_of::<eth_hdr>() + std::mem::size_of::<ip_hdr>();

const DGRAM: FuncDef = func_def!(
    /// Create a raw IPv4 header or datagram
    "ipv4::datagram";
    ValType::Pkt;

    "src" => ValType::Ip4,
    "dst" => ValType::Ip4,
    =>
    "id" => ValDef::U16(0),
    "evil" => ValDef::Bool(false),
    "df" => ValDef::Bool(false),
    "mf" => ValDef::Bool(false),
    "ttl" => ValDef::U8(64),
    "frag_off" => ValDef::U16(0),
    "proto" => ValDef::U8(proto::UDP),
    =>
    ValType::Str;

    |mut args| {
        let src: Ipv4Addr = args.next().into();
        let dst: Ipv4Addr = args.next().into();

        let id: u16 = args.next().into();
        let evil: bool = args.next().into();
        let df: bool = args.next().into();
        let mf: bool = args.next().into();
        let ttl: u8= args.next().into();
        let frag_off: u16 = args.next().into();
        let proto: u8 = args.next().into();

        let data: Buf = args.join_extra(b"").into();

        let payload_size: u16 = data.len() as u16;
        let tot_len: u16 = std::mem::size_of::<ip_hdr>() as u16 + payload_size;

        let eth = eth_hdr::new(
            src.into(),
            dst.into(),
            ethertype::IPV4,
        );

        let mut iph = ip_hdr::default();
        iph.set_tot_len(tot_len)
            .set_id(id)
            .set_evil(evil)
            .set_df(df)
            .set_mf(mf)
            .set_frag_off(frag_off)
            .set_ttl(ttl)
            .set_protocol(proto)
            .set_saddr(src)
            .set_daddr(dst)
            .calc_csum();

        let pkt = Packet::with_capacity(IPV4_DGRAM_OVERHEAD + payload_size as usize);
        pkt.push(eth);
        pkt.push(iph);
        pkt.push_bytes(data);

        Ok(Val::from(pkt))
    }
);

const FRAG_FRAGMENT: FuncDef = func_def!(
    /// Returns an IPv4 packet fragment
    ///
    /// # Arguments
    /// * `frag_off` Offset in 8-byte blocks
    /// * `len` Length in bytes
    "ipv4::frag.fragment";
    ValType::Pkt;

    "frag_off" => ValType::U16,
    "len" => ValType::U16,
    =>
    =>
    ValType::Str;

    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut IpFrag = r.as_mut_any().downcast_mut().unwrap();

        let frag_off: u16 = args.next().into();
        let len: u16 = args.next().into();

        Ok(this.fragment(frag_off, len).into())
    }
);

const FRAG_TAIL: FuncDef = func_def!(
    /// Returns an IPv4 tail-fragment, ie. with MF (more-fragments) bit set to zero.
    /// This is just a convenience function which omits the len parameter.
    ///
    /// # Arguments
    /// * `frag_off` Offset in 8-byte blocks
    "ipv4::frag.tail";
    ValType::Pkt;

    "frag_off" => ValType::U16,
    =>
    =>
    ValType::Str;

    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut IpFrag = r.as_mut_any().downcast_mut().unwrap();

        let frag_off: u16 = args.next().into();

        Ok(this.tail(frag_off).into())
    }
);

const FRAG_DATAGRAM: FuncDef = func_def!(
    /// Return the entire datagram without fragmenting it
    "ipv4::frag.datagram";
    ValType::Pkt;

    =>
    =>
    ValType::Str;

    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut IpFrag = r.as_mut_any().downcast_mut().unwrap();

        Ok(this.datagram().into())
    }
);

impl Class for IpFrag {
    fn symbols(&self) -> phf::Map<&'static str, Symbol> {
        phf_map! {
            "fragment" => Symbol::Func(&FRAG_FRAGMENT),
            "tail" => Symbol::Func(&FRAG_TAIL),
            "datagram" => Symbol::Func(&FRAG_DATAGRAM),
        }
    }

    fn class_name(&self) -> &'static str {
        "ipv4::frag"
    }
}

const FRAG: FuncDef = func_def!(
    /// Create a context for a packet which can be arbitrarily fragmented
    "ipv4::frag";
    ValType::Obj;

    "src" => ValType::Ip4,
    "dst" => ValType::Ip4,
    =>
    "id" => ValDef::U16(0),
    "evil" => ValDef::Bool(false),
    "df" => ValDef::Bool(false),
    "ttl" => ValDef::U8(64),
    "proto" => ValDef::U8(proto::UDP),
    =>
    ValType::Str;

    |mut args| {
        let src: Ipv4Addr = args.next().into();
        let dst: Ipv4Addr = args.next().into();

        let id: u16 = args.next().into();
        let evil: bool = args.next().into();
        let df: bool = args.next().into();
        let ttl: u8= args.next().into();
        let proto: u8 = args.next().into();

        let payload: Buf = args.join_extra(b"").into();

        let mut iph: ip_hdr = Default::default();
        iph
            .set_id(id)
            .set_evil(evil)
            .set_df(df)
            .set_ttl(ttl)
            .set_protocol(proto)
            .set_saddr(src)
            .set_daddr(dst);

        Ok(Val::from(IpFrag::new(iph, payload.cow_buffer())))
    }
);

pub const IPV4: phf::Map<&'static str, Symbol> = phf_map! {
    "tcp" => Symbol::Module(&TCP4),
    "udp" => Symbol::Module(&UDP4),
    "icmp" => Symbol::Module(&ICMP4),
    "datagram" => Symbol::Func(&DGRAM),
    "frag" => Symbol::Func(&FRAG),
    "proto" => Symbol::Module(&PROTO),
};
