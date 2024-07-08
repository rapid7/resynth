use phf::{phf_map, phf_ordered_map};

use crate::func_def;
use crate::libapi::{ArgDecl, Class, FuncDef};
use crate::str::Buf;
use crate::sym::Symbol;
use crate::val::{Val, ValDef, ValType};

use ezpkt::TcpFlow;
use pkt::Packet;

const TCP_OPEN: FuncDef = func_def!(
    "ipv4::tcp::flow.open";
    ValType::PktGen;

    =>
    =>
    ValType::Void;

    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        Ok(this.open().into())
    }
);

const TCP_CL_MSG: FuncDef = func_def!(
    "ipv4::tcp::flow.client_message";
    ValType::PktGen;

    =>
    "send_ack" => ValDef::Bool(true),
    "seq" => ValDef::Type(ValType::U32),
    "ack" => ValDef::Type(ValType::U32),
    "frag_off" => ValDef::U16(0),
    =>
    ValType::Str;

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
    "ipv4::tcp::flow.server_message";
    ValType::PktGen;

    =>
    "send_ack" => ValDef::Bool(true),
    "seq" => ValDef::Type(ValType::U32),
    "ack" => ValDef::Type(ValType::U32),
    "frag_off" => ValDef::U16(0),
    =>
    ValType::Str;

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
    "ipv4::tcp::flow.client_segment";
    ValType::Pkt;

    =>
    "seq" => ValDef::Type(ValType::U32),
    "ack" => ValDef::Type(ValType::U32),
    =>
    ValType::Str;

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
    "ipv4::tcp::flow.server_segment";
    ValType::Pkt;

    =>
    "seq" => ValDef::Type(ValType::U32),
    "ack" => ValDef::Type(ValType::U32),
    =>
    ValType::Str;

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
    "ipv4::tcp::flow.client_raw_segment";
    ValType::Str;

    =>
    "seq" => ValDef::Type(ValType::U32),
    "ack" => ValDef::Type(ValType::U32),
    =>
    ValType::Str;

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
    "ipv4::tcp::flow.server_raw_segment";
    ValType::Str;

    =>
    "seq" => ValDef::Type(ValType::U32),
    "ack" => ValDef::Type(ValType::U32),
    =>
    ValType::Str;

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
    "ipv4::tcp::flow.client_hdr";
    ValType::Str;

    =>
    "bytes" => ValDef::U32(0),
    =>
    ValType::Void;

    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let bytes: u32 = args.next().into();

        Ok(Val::Str(Buf::from(this.client_hdr(bytes))))
    }
);

const TCP_SV_HDR: FuncDef = func_def!(
    "ipv4::tcp::flow.server_hdr";
    ValType::Str;

    =>
    "bytes" => ValDef::U32(0),
    =>
    ValType::Void;

    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        let bytes: u32 = args.next().into();

        Ok(Val::Str(Buf::from(this.server_hdr(bytes))))
    }
);

const TCP_CL_ACK: FuncDef = func_def!(
    "ipv4::tcp::flow.client_ack";
    ValType::Pkt;

    =>
    "seq" => ValDef::Type(ValType::U32),
    "ack" => ValDef::Type(ValType::U32),
    =>
    ValType::Void;

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
    "ipv4::tcp::flow.server_ack";
    ValType::Pkt;

    =>
    "seq" => ValDef::Type(ValType::U32),
    "ack" => ValDef::Type(ValType::U32),
    =>
    ValType::Void;

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
    "ipv4::tcp::flow.client_hole";
    ValType::Void;

    "bytes" => ValType::U32,
    =>
    =>
    ValType::Void;

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
    "ipv4::tcp::flow.server_hole";
    ValType::Void;

    "bytes" => ValType::U32,
    =>
    =>
    ValType::Void;

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
    "ipv4::tcp::flow.client_close";
    ValType::PktGen;

    =>
    =>
    ValType::Void;

    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        Ok(this.client_close().into())
    }
);

const TCP_SV_CLOSE: FuncDef = func_def!(
    "ipv4::tcp::flow.server_close";
    ValType::PktGen;

    =>
    =>
    ValType::Void;

    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        Ok(this.server_close().into())
    }
);

const TCP_CL_RESET: FuncDef = func_def!(
    "ipv4::tcp::flow.client_reset";
    ValType::Pkt;

    =>
    =>
    ValType::Void;

    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut TcpFlow = r.as_mut_any().downcast_mut().unwrap();
        Ok(this.client_reset().into())
    }
);

const TCP_SV_RESET: FuncDef = func_def!(
    "ipv4::tcp::flow.server_reset";
    ValType::Pkt;

    =>
    =>
    ValType::Void;

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
    "flow";
    ValType::Obj;

    "cl" => ValType::Sock4,
    "sv" => ValType::Sock4,
    =>
    "cl_seq" => ValDef::U32(1),
    "sv_seq" => ValDef::U32(1),
    "raw" => ValDef::Bool(false),
    =>
    ValType::Void;

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
