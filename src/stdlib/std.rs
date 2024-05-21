use phf::{phf_map, phf_ordered_map};

use crate::func_def;
use crate::libapi::{ArgDecl, FuncDef};
use crate::sym::Symbol;
use crate::val::{Val, ValType};

const BE16: FuncDef = func_def!(
    "std::be16";
    ValType::Str;

    "val" => ValType::U64,
    =>
    =>
    ValType::Void;

    |mut args| {
        let val: u16 = args.next().into();
        Ok(Val::str(&val.to_be_bytes()))
    }
);

const BE32: FuncDef = func_def!(
    "std::be32";
    ValType::Str;

    "val" => ValType::U64,
    =>
    =>
    ValType::Void;

    |mut args| {
        let val: u32 = args.next().into();
        Ok(Val::str(&val.to_be_bytes()))
    }
);

const BE64: FuncDef = func_def!(
    "std::be64";
    ValType::Str;

    "val" => ValType::U64,
    =>
    =>
    ValType::Void;

    |mut args| {
        let val: u64 = args.next().into();
        Ok(Val::str(&val.to_be_bytes()))
    }
);

const LE16: FuncDef = func_def!(
    "std::le16";
    ValType::Str;

    "val" => ValType::U64,
    =>
    =>
    ValType::Void;

    |mut args| {
        let val: u16 = args.next().into();
        Ok(Val::str(&val.to_le_bytes()))
    }
);

const LE32: FuncDef = func_def!(
    "std::le32";
    ValType::Str;

    "val" => ValType::U64,
    =>
    =>
    ValType::Void;

    |mut args| {
        let val: u32 = args.next().into();
        Ok(Val::str(&val.to_le_bytes()))
    }
);

const LE64: FuncDef = func_def!(
    "std::le64";
    ValType::Str;

    "val" => ValType::U64,
    =>
    =>
    ValType::Void;

    |mut args| {
        let val: u64 = args.next().into();
        Ok(Val::str(&val.to_le_bytes()))
    }
);

pub const MODULE: phf::Map<&'static str, Symbol> = phf_map! {
    "be16" => Symbol::Func(&BE16),
    "be32" => Symbol::Func(&BE32),
    "be64" => Symbol::Func(&BE64),
    "le16" => Symbol::Func(&LE16),
    "le32" => Symbol::Func(&LE32),
    "le64" => Symbol::Func(&LE64),
};
