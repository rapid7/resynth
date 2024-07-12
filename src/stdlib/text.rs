use phf::phf_map;

use crate::func_def;
use crate::libapi::FuncDef;
use crate::str::Buf;
use crate::sym::Symbol;
use crate::val::{Val, ValDef, ValType};

const CONCAT: FuncDef = func_def!(
    /// Concatenate strings
    resynth concat(
        =>
        =>
        Str
    ) -> Str
    |mut args| {
        Ok(args.join_extra(b""))
    }
);

const CRLFLINES: FuncDef = func_def!(
    /// join strings with CRLF line-endings
    resynth crlflines(
        =>
        =>
        Str
    ) -> Str
    |mut args| {
        Ok(args.join_extra(b"\r\n"))
    }
);

const LEN: FuncDef = func_def!(
    /// Return the length of a string (or strings)
    resynth len(
        =>
        =>
        Str
    ) -> U64
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
