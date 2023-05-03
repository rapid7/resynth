use phf::{phf_map, phf_ordered_map};
use std::net::Ipv4Addr;

use pkt::{Packet, Hdr};
use pkt::eth::eth_hdr;
use pkt::ipv4::ip_hdr;

use crate::val::{ValType, Val, ValDef};
use crate::libapi::{FuncDef, ArgDecl};
use crate::sym::Symbol;
use crate::str::Buf;
use crate::func_def;

mod tcp;
mod udp;
mod icmp;

use tcp::TCP4;
use udp::UDP4;
use icmp::ICMP4;

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
    "proto" => ValDef::U8(17),
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

pub const IPV4: phf::Map<&'static str, Symbol> = phf_map! {
    "tcp" => Symbol::Module(&TCP4),
    "udp" => Symbol::Module(&UDP4),
    "icmp" => Symbol::Module(&ICMP4),
    "datagram" => Symbol::Func(&DGRAM),
};
