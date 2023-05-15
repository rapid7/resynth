use phf::{phf_map, phf_ordered_map};
use std::net::Ipv4Addr;

use pkt::{Packet, Hdr};
use pkt::eth::eth_hdr;
use pkt::ipv4::{ip_hdr, proto};

use ezpkt::IpFrag;

use crate::val::{ValType, Val, ValDef};
use crate::libapi::{FuncDef, ArgDecl, Class};
use crate::sym::Symbol;
use crate::str::Buf;
use crate::func_def;

mod tcp;
mod udp;
mod icmp;

use tcp::TCP4;
use udp::UDP4;
use icmp::ICMP4;

const PROTO: phf::Map<&'static str, Symbol> = phf_map! {
    "ICMP" => Symbol::u8(proto::ICMP),
    "TCP" => Symbol::u8(proto::TCP),
    "UDP" => Symbol::u8(proto::UDP),
    "GRE" => Symbol::u8(proto::GRE),
};

const IPV4_DGRAM_OVERHEAD: usize =
    std::mem::size_of::<eth_hdr>()
    + std::mem::size_of::<ip_hdr>();

const DGRAM: FuncDef = func_def!(
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

        let mut pkt = Packet::with_capacity(IPV4_DGRAM_OVERHEAD + payload_size as usize);

        let eth: Hdr<eth_hdr> = pkt.push_hdr();
        pkt.get_mut_hdr(eth)
            .src_from_ip(src)
            .dst_from_ip(dst)
            .proto(0x0800);

        let ip: Hdr<ip_hdr> = pkt.push_hdr();
        pkt.get_mut_hdr(ip)
            .init()
            .tot_len(tot_len)
            .id(id)
            .evil(evil)
            .df(df)
            .mf(mf)
            .frag_off(frag_off)
            .ttl(ttl)
            .protocol(proto)
            .saddr(src)
            .daddr(dst)
            .calc_csum();

        pkt.push_bytes(data);

        Ok(Val::from(pkt))
    }
);

const FRAG_FRAGMENT: FuncDef = func_def!(
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
            .id(id)
            .evil(evil)
            .df(df)
            .ttl(ttl)
            .protocol(proto)
            .saddr(src)
            .daddr(dst);

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
