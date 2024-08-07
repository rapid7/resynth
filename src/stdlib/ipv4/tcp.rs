use crate::func;
use crate::libapi::{Class, ClassDef, FuncDef, Module};
use crate::str::Buf;
use crate::sym::Symbol;
use crate::val::{Val, ValDef};

use ezpkt::TcpFlow;
use pkt::Packet;

const TCP_OPEN: FuncDef = func!(
    /// Performs a TCP 3-way handshake
    resynth fn open(
        =>
        =>
        Void
    ) -> PktGen
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        Ok(this.open().into())
        }
);

const TCP_CL_MSG: FuncDef = func!(
    /// Sends a message from client to server, may also send an ACK in response
    resynth fn client_message(
        =>
        send_ack: Bool = true,
        seq: Type = ValType::U32,
        ack: Type = ValType::U32,
        frag_off: U16 = 0,
        =>
        Str
    ) -> PktGen
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let send_ack: bool = args.next().into();
        let seq: Option<u32> = args.next().into();
        let ack: Option<u32> = args.next().into();
        let frag_off: u16 = args.next().into();

        let bytes: Buf = args.join_extra(b"").into();

        let saved = this.push_state(seq, ack);
        let pkt = this.client_message(bytes.as_ref(), send_ack, frag_off);
        this.pop_state(saved);

        Ok(pkt.into())
    }
);

const TCP_SV_MSG: FuncDef = func!(
    /// Sends a message from server to client, may also send an ACK in response
    resynth fn server_message(
        =>
        send_ack: Bool = true,
        seq: Type = ValType::U32,
        ack: Type = ValType::U32,
        frag_off: U16 = 0,
        =>
        Str
    ) -> PktGen
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let send_ack: bool = args.next().into();
        let seq: Option<u32> = args.next().into();
        let ack: Option<u32> = args.next().into();
        let frag_off: u16 = args.next().into();

        let bytes: Buf = args.join_extra(b"").into();

        let saved = this.push_state(seq, ack);
        let pkt = this.server_message(bytes.as_ref(), send_ack, frag_off);
        this.pop_state(saved);

        Ok(pkt.into())
    }
);

const TCP_CL_SEG: FuncDef = func!(
    /// Returns a single segment from client to server
    resynth fn client_segment(
        =>
        seq: Type = ValType::U32,
        ack: Type = ValType::U32,
        =>
        Str
    ) -> Pkt
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let seq: Option<u32> = args.next().into();
        let ack: Option<u32> = args.next().into();

        let bytes: Buf = args.join_extra(b"").into();

        let saved = this.push_state(seq, ack);
        let pkt: Packet = this.client_data_segment(bytes.as_ref()).into();
        this.pop_state(saved);

        Ok(pkt.into())
    }
);

const TCP_SV_SEG: FuncDef = func!(
    /// Returns a single segment from server to client
    resynth fn server_segment(
        =>
        seq: Type = ValType::U32,
        ack: Type = ValType::U32,
        =>
        Str
    ) -> Pkt
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let seq: Option<u32> = args.next().into();
        let ack: Option<u32> = args.next().into();

        let bytes: Buf = args.join_extra(b"").into();

        let saved = this.push_state(seq, ack);
        let pkt: Packet = this.server_data_segment(bytes.as_ref()).into();
        this.pop_state(saved);

        Ok(pkt.into())
    }
);

const TCP_CL_RAW_SEG: FuncDef = func!(
    /// Returns a single segment, minus the IP header, from client to server
    resynth fn client_raw_segment(
        =>
        seq: Type = ValType::U32,
        ack: Type = ValType::U32,
        =>
        Str
    ) -> Str
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let seq: Option<u32> = args.next().into();
        let ack: Option<u32> = args.next().into();

        let bytes: Buf = args.join_extra(b"").into();

        let saved = this.push_state(seq, ack);
        let pkt = this.client_data_segment(bytes.as_ref());
        this.pop_state(saved);

        Ok(Val::str(pkt.into_tcpseg()))
    }
);

const TCP_SV_RAW_SEG: FuncDef = func!(
    /// Returns a single segment, minus the IP header, from server to client
    resynth fn server_raw_segment(
        =>
        seq: Type = ValType::U32,
        ack: Type = ValType::U32,
        =>
        Str
    ) -> Str
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let seq: Option<u32> = args.next().into();
        let ack: Option<u32> = args.next().into();

        let bytes: Buf = args.join_extra(b"").into();

        let saved = this.push_state(seq, ack);
        let pkt = this.server_data_segment(bytes.as_ref());
        this.pop_state(saved);

        Ok(Val::str(pkt.into_tcpseg()))
    }
);

const TCP_CL_HDR: FuncDef = func!(
    /// Returns only the TCP header, from client to server
    resynth fn client_hdr(
        =>
        bytes: U32 = 0,
        =>
        Void
    ) -> Str
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let bytes: u32 = args.next().into();

        Ok(Val::Str(Buf::from(this.client_hdr(bytes))))
    }
);

const TCP_SV_HDR: FuncDef = func!(
    /// Returns only the TCP header, from server to client
    resynth fn server_hdr(
        =>
        bytes: U32 = 0,
        =>
        Void
    ) -> Str
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let bytes: u32 = args.next().into();

        Ok(Val::Str(Buf::from(this.server_hdr(bytes))))
    }
);

const TCP_CL_ACK: FuncDef = func!(
    /// Sends an ACK from the client
    resynth fn client_ack(
        =>
        seq: Type = ValType::U32,
        ack: Type = ValType::U32,
        =>
        Void
    ) -> Pkt
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let seq: Option<u32> = args.next().into();
        let ack: Option<u32> = args.next().into();

        let saved = this.push_state(seq, ack);
        let pkt: Packet = this.client_ack().into();
        this.pop_state(saved);

        Ok(pkt.into())
    }
);

const TCP_SV_ACK: FuncDef = func!(
    /// Sends an ACK from the server
    resynth fn server_ack(
        =>
        seq: Type = ValType::U32,
        ack: Type = ValType::U32,
        =>
        Void
    ) -> Pkt
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let seq: Option<u32> = args.next().into();
        let ack: Option<u32> = args.next().into();

        let saved = this.push_state(seq, ack);
        let pkt: Packet = this.server_ack().into();
        this.pop_state(saved);

        Ok(pkt.into())
    }
);

const TCP_CL_HOLE: FuncDef = func!(
    /// Creates a hole in the sever's Tx sequence space, making it look like we missed a packet
    /// from the client
    resynth fn client_hole(
        bytes: U32,
        =>
        =>
        Void
    ) -> Void
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let bytes: u32 = args.next().into();

        this.client_hole(bytes);
        Ok(Val::Nil)
    }
);

const TCP_SV_HOLE: FuncDef = func!(
    /// Creates a hole in the sever's Tx sequence space, making it look like we missed a packet
    /// from the server
    resynth fn server_hole(
        bytes: U32,
        =>
        =>
        Void
    ) -> Void
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let bytes: u32 = args.next().into();

        this.server_hole(bytes);
        Ok(Val::Nil)
    }
);

const TCP_CL_CLOSE: FuncDef = func!(
    /// Shutdown both sides of the TCP connection, with the client sending the first FIN
    resynth fn client_close(
        =>
        =>
        Void
    ) -> PktGen
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        Ok(this.client_close().into())
    }
);

const TCP_SV_CLOSE: FuncDef = func!(
    /// Shutdown both sides of the TCP connection, with the server sending the first FIN
    resynth fn server_close(
        =>
        =>
        Void
    ) -> PktGen
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        Ok(this.server_close().into())
    }
);

const TCP_CL_RESET: FuncDef = func!(
    /// Send a RST packet from the client
    resynth fn client_reset(
        =>
        =>
        Void
    ) -> Pkt
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        Ok(this.client_reset().into())
    }
);

const TCP_SV_RESET: FuncDef = func!(
    /// Send a RST packet from the server
    resynth fn server_reset(
        =>
        =>
        Void
    ) -> Pkt
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        Ok(this.server_reset().into())
    }
);

const TCP_FLOW: ClassDef = class!(
    /// # TCP Connection
    resynth class TcpFlow {
        open => Symbol::Func(&TCP_OPEN),
        client_message => Symbol::Func(&TCP_CL_MSG),
        server_message => Symbol::Func(&TCP_SV_MSG),
        client_segment => Symbol::Func(&TCP_CL_SEG),
        server_segment => Symbol::Func(&TCP_SV_SEG),
        client_raw_segment => Symbol::Func(&TCP_CL_RAW_SEG),
        server_raw_segment => Symbol::Func(&TCP_SV_RAW_SEG),
        client_hdr => Symbol::Func(&TCP_CL_HDR),
        server_hdr => Symbol::Func(&TCP_SV_HDR),
        client_ack => Symbol::Func(&TCP_CL_ACK),
        server_ack => Symbol::Func(&TCP_SV_ACK),
        client_hole => Symbol::Func(&TCP_CL_HOLE),
        server_hole => Symbol::Func(&TCP_SV_HOLE),
        client_close => Symbol::Func(&TCP_CL_CLOSE),
        server_close => Symbol::Func(&TCP_SV_CLOSE),
        client_reset => Symbol::Func(&TCP_CL_RESET),
        server_reset => Symbol::Func(&TCP_SV_RESET),
    }
);

impl Class for TcpFlow {
    fn def(&self) -> &'static ClassDef {
        &TCP_FLOW
    }
}

const FLOW: FuncDef = func!(
    /// Create a [TCP flow context](TcpFlow.md), from which packets can be created
    resynth fn flow(
        cl: Sock4,
        sv: Sock4,
        =>
        cl_seq: U32 = 1,
        sv_seq: U32 = 1,
        raw: Bool = false,
        =>
        Void
    ) -> Obj
    |mut args| {
        let cl = args.next();
        let sv = args.next();
        let cl_seq: u32 = args.next().into();
        let sv_seq: u32 = args.next().into();
        let raw: bool = args.next().into();
        Ok(Val::from(TcpFlow::new(cl.into(), sv.into(), cl_seq, sv_seq, raw)))
    }
);

pub const TCP4: Module = module! {
    /// # Transmission Control Protocol (TCP)
    resynth mod tcp {
        TcpFlow => Symbol::Class(&TCP_FLOW),
        flow => Symbol::Func(&FLOW),
    }
};
