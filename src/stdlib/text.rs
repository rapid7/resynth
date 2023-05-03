use phf::{phf_map, phf_ordered_map};

use crate::val::{Val, ValType, ValDef};
use crate::str::Buf;
use crate::libapi::FuncDef;
use crate::sym::Symbol;
use crate::func_def;

const CONCAT: FuncDef = func_def!(
    "text::concat";
    ValType::Str;

    =>
    =>
    ValType::Str;

    |mut args| {
        Ok(args.join_extra(b""))
    }
);

const CRLFLINES: FuncDef = func_def!(
    "text::crlflines";
    ValType::Str;

    =>
    =>
    ValType::Str;

    |mut args| {
        Ok(args.join_extra(b"\r\n"))
    }
);

const LEN: FuncDef = func_def!(
    "text::len";
    ValType::U64;

    =>
    =>
    ValType::Str;

    |mut args| {
        let buf: Buf = args.join_extra(b"").into();
        Ok(Val::U64(buf.len() as u64))
    }
);

pub const MODULE: phf::Map<&'static str, Symbol> = phf_map! {
    "concat" => Symbol::Func(&CONCAT),
    "crlflines" => Symbol::Func(&CRLFLINES),
    "len" => Symbol::Func(&LEN),
    "CRLF" => Symbol::Val(ValDef::Str(b"\r\n")),
};
