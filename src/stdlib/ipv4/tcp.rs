use phf::phf_map;

use crate::func_def;
use crate::libapi::{ArgDecl, ArgDesc, Class, FuncDef};
use crate::str::Buf;
use crate::sym::Symbol;
use crate::val::{Val, ValDef, ValType};

use ezpkt::TcpFlow;
use pkt::Packet;

const TCP_OPEN: FuncDef = func_def!(
    /// Performs a TCP 3-way handshake
    resynth open(
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

const TCP_CL_MSG: FuncDef = func_def!(
    /// Sends a message from client to server, may also send an ACK in response
    resynth client_message(
        =>
        send_ack: ValDef::Bool(true),
        seq: ValDef::Type(ValType::U32),
        ack: ValDef::Type(ValType::U32),
        frag_off: ValDef::U16(0),
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

const TCP_SV_MSG: FuncDef = func_def!(
    /// Sends a message from server to client, may also send an ACK in response
    resynth server_message(
        =>
        send_ack: ValDef::Bool(true),
        seq: ValDef::Type(ValType::U32),
        ack: ValDef::Type(ValType::U32),
        frag_off: ValDef::U16(0),
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

const TCP_CL_SEG: FuncDef = func_def!(
    /// Returns a single segment from client to server
    resynth client_segment(
        =>
        seq: ValDef::Type(ValType::U32),
        ack: ValDef::Type(ValType::U32),
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

const TCP_SV_SEG: FuncDef = func_def!(
    /// Returns a single segment from server to client
    resynth server_segment(
        =>
        seq: ValDef::Type(ValType::U32),
        ack: ValDef::Type(ValType::U32),
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

const TCP_CL_RAW_SEG: FuncDef = func_def!(
    /// Returns a single segment, minus the IP header, from client to server
    resynth client_raw_segment(
        =>
        seq: ValDef::Type(ValType::U32),
        ack: ValDef::Type(ValType::U32),
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

const TCP_SV_RAW_SEG: FuncDef = func_def!(
    /// Returns a single segment, minus the IP header, from server to client
    resynth server_raw_segment(
        =>
        seq: ValDef::Type(ValType::U32),
        ack: ValDef::Type(ValType::U32),
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

const TCP_CL_HDR: FuncDef = func_def!(
    /// Returns only the TCP header, from client to server
    resynth client_hdr(
        =>
        bytes: ValDef::U32(0),
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

const TCP_SV_HDR: FuncDef = func_def!(
    /// Returns only the TCP header, from server to client
    resynth server_hdr(
        =>
        bytes: ValDef::U32(0),
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

const TCP_CL_ACK: FuncDef = func_def!(
    /// Sends an ACK from the client
    resynth client_ack(
        =>
        seq: ValDef::Type(ValType::U32),
        ack: ValDef::Type(ValType::U32),
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

const TCP_SV_ACK: FuncDef = func_def!(
    /// Sends an ACK from the server
    resynth server_ack(
        =>
        seq: ValDef::Type(ValType::U32),
        ack: ValDef::Type(ValType::U32),
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

const TCP_CL_HOLE: FuncDef = func_def!(
    /// Creates a hole in the sever's Tx sequence space, making it look like we missed a packet
    /// from the client
    resynth client_hole(
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

const TCP_SV_HOLE: FuncDef = func_def!(
    /// Creates a hole in the sever's Tx sequence space, making it look like we missed a packet
    /// from the server
    resynth server_hole(
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

const TCP_CL_CLOSE: FuncDef = func_def!(
    /// Shutdown both sides of the TCP connection, with the client sending the first FIN
    resynth client_close(
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

const TCP_SV_CLOSE: FuncDef = func_def!(
    /// Shutdown both sides of the TCP connection, with the server sending the first FIN
    resynth server_close(
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

const TCP_CL_RESET: FuncDef = func_def!(
    /// Send a RST packet from the client
    resynth client_reset(
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

const TCP_SV_RESET: FuncDef = func_def!(
    /// Send a RST packet from the server
    resynth server_reset(
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

impl Class for TcpFlow {
    fn symbols(&self) -> phf::Map<&'static str, Symbol> {
        phf_map! {
            "open" => Symbol::Func(&TCP_OPEN),
            "client_message" => Symbol::Func(&TCP_CL_MSG),
            "server_message" => Symbol::Func(&TCP_SV_MSG),
            "client_segment" => Symbol::Func(&TCP_CL_SEG),
            "server_segment" => Symbol::Func(&TCP_SV_SEG),
            "client_raw_segment" => Symbol::Func(&TCP_CL_RAW_SEG),
            "server_raw_segment" => Symbol::Func(&TCP_SV_RAW_SEG),
            "client_hdr" => Symbol::Func(&TCP_CL_HDR),
            "server_hdr" => Symbol::Func(&TCP_SV_HDR),
            "client_ack" => Symbol::Func(&TCP_CL_ACK),
            "server_ack" => Symbol::Func(&TCP_SV_ACK),
            "client_hole" => Symbol::Func(&TCP_CL_HOLE),
            "server_hole" => Symbol::Func(&TCP_SV_HOLE),
            "client_close" => Symbol::Func(&TCP_CL_CLOSE),
            "server_close" => Symbol::Func(&TCP_SV_CLOSE),
            "client_reset" => Symbol::Func(&TCP_CL_RESET),
            "server_reset" => Symbol::Func(&TCP_SV_RESET),
        }
    }

    fn class_name(&self) -> &'static str {
        "ipv4::tcp4.flow"
    }
}

const TCP_FLOW: FuncDef = func_def!(
    /// Create a TCP flow context, from which packets can be created
    resynth flow(
        cl: Sock4,
        sv: Sock4,
        =>
        cl_seq: ValDef::U32(1),
        sv_seq: ValDef::U32(1),
        raw: ValDef::Bool(false),
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

pub const TCP4: phf::Map<&'static str, Symbol> = phf_map! {
    "flow" => Symbol::Func(&TCP_FLOW),
};
