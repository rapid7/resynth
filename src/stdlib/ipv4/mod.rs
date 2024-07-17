use std::net::Ipv4Addr;

use pkt::eth::{eth_hdr, ethertype};
use pkt::ipv4::{ip_hdr, proto};
use pkt::Packet;

use ezpkt::IpFrag;

use crate::func;
use crate::libapi::{Class, ClassDef, FuncDef, Module};
use crate::str::Buf;
use crate::sym::Symbol;
use crate::val::{Val, ValDef};

mod icmp;
mod tcp;
mod udp;

use icmp::ICMP4;
use tcp::TCP4;
use udp::UDP4;

const PROTO: Module = module! {
    /// IP Protocols
    resynth mod proto {
        ICMP => Symbol::u8(proto::ICMP),
        TCP => Symbol::u8(proto::TCP),
        UDP => Symbol::u8(proto::UDP),
        GRE => Symbol::u8(proto::GRE),
    }
};

const IPV4_DGRAM_OVERHEAD: usize = std::mem::size_of::<eth_hdr>() + std::mem::size_of::<ip_hdr>();

const DGRAM: FuncDef = func!(
    /// Create a raw IPv4 header or datagram
    resynth fn datagram(
        src: Ip4,
        dst: Ip4,
        =>
        id: U16 = 0,
        evil: Bool = false,
        df: Bool = false,
        mf: Bool = false,
        ttl: U8 = 64,
        frag_off: U16 = 0,
        proto: U8 = proto::UDP,
        =>
        Str
    ) -> Pkt
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

const FRAG_FRAGMENT: FuncDef = func!(
    /// Returns an IPv4 packet fragment
    ///
    /// # Arguments
    /// * `frag_off` Offset in 8-byte blocks
    /// * `len` Length in bytes
    resynth fn fragment(
        frag_off: U16,
        len: U16,
        =>
        =>
        Str
    ) -> Pkt
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut IpFrag = r.as_mut_any().downcast_mut().unwrap();

        let frag_off: u16 = args.next().into();
        let len: u16 = args.next().into();

        Ok(this.fragment(frag_off, len).into())
    }
);

const FRAG_TAIL: FuncDef = func!(
    /// Returns an IPv4 tail-fragment, ie. with MF (more-fragments) bit set to zero.
    /// This is just a convenience function which omits the len parameter.
    ///
    /// # Arguments
    /// * `frag_off` Offset in 8-byte blocks
    resynth fn tail(
        frag_off: U16,
        =>
        =>
        Str
    ) -> Pkt
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut IpFrag = r.as_mut_any().downcast_mut().unwrap();

        let frag_off: u16 = args.next().into();

        Ok(this.tail(frag_off).into())
    }
);

const FRAG_DATAGRAM: FuncDef = func!(
    /// Return the entire datagram without fragmenting it
    resynth fn datagram(
        =>
        =>
        Str
    ) -> Pkt
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut IpFrag = r.as_mut_any().downcast_mut().unwrap();

        Ok(this.datagram().into())
    }
);

const IPFRAG: ClassDef = class!(
    /// IP Packet Fragment Builder
    resynth class IpFrag {
        fragment => Symbol::Func(&FRAG_FRAGMENT),
        tail => Symbol::Func(&FRAG_TAIL),
        datagram => Symbol::Func(&FRAG_DATAGRAM),
    }
);

impl Class for IpFrag {
    fn def(&self) -> &'static ClassDef {
        &IPFRAG
    }
}

const FRAG: FuncDef = func!(
    /// Create a context for a packet which can be arbitrarily fragmented
    resynth fn frag(
        src: Ip4,
        dst: Ip4,
        =>
        id: U16 = 0,
        evil: Bool = false,
        df: Bool = false,
        ttl: U8 = 64,
        proto: U8 = proto::UDP,
        =>
        Str
    ) -> Obj
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

pub const IPV4: Module = module! {
    /// Internet Protocol Version 4
    resynth mod ipv4 {
        IpFrag => Symbol::Class(&IPFRAG),
        tcp => Symbol::Module(&TCP4),
        udp => Symbol::Module(&UDP4),
        icmp => Symbol::Module(&ICMP4),
        datagram => Symbol::Func(&DGRAM),
        frag => Symbol::Func(&FRAG),
        proto => Symbol::Module(&PROTO),
    }
};
