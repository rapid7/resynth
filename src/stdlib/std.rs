use crate::func_def;
use crate::libapi::{FuncDef, Module};
use crate::str::Buf;
use crate::sym::Symbol;
use crate::val::Val;

const BE16: FuncDef = func_def!(
    /// Encode a 16bit integer into 2 big-endian bytes
    resynth fn be16(
        val: U64,
        =>
        =>
        Void
    ) -> Str
    |mut args| {
        let val: u16 = args.next().into();
        Ok(Val::str(&val.to_be_bytes()))
    }
);

const BE32: FuncDef = func_def!(
    /// Encode a 32bit integer into 4 big-endian bytes
    resynth fn be32(
        val: U64,
        =>
        =>
        Void
    ) -> Str
    |mut args| {
        let val: u32 = args.next().into();
        Ok(Val::str(&val.to_be_bytes()))
    }
);

const BE64: FuncDef = func_def!(
    /// Encode a 64bit integer into 8 big-endian bytes
    resynth fn be64(
        val: U64,
        =>
        =>
        Void
    ) -> Str
    |mut args| {
        let val: u64 = args.next().into();
        Ok(Val::str(&val.to_be_bytes()))
    }
);

const LE16: FuncDef = func_def!(
    /// Encode a 16bit integer into 2 little-endian bytes
    resynth fn le16(
        val: U64,
        =>
        =>
        Void
    ) -> Str
    |mut args| {
        let val: u16 = args.next().into();
        Ok(Val::str(&val.to_le_bytes()))
    }
);

const LE32: FuncDef = func_def!(
    /// Encode a 32bit integer into 4 little-endian bytes
    resynth fn le32(
        val: U64,
        =>
        =>
        Void
    ) -> Str
    |mut args| {
        let val: u32 = args.next().into();
        Ok(Val::str(&val.to_le_bytes()))
    }
);

const LE64: FuncDef = func_def!(
    /// Encode a 64bit integer into 8 little-endian bytes
    resynth fn le64(
        val: U64,
        =>
        =>
        Void
    ) -> Str
    |mut args| {
        let val: u64 = args.next().into();
        Ok(Val::str(&val.to_le_bytes()))
    }
);

const U8: FuncDef = func_def!(
    /// Convert an integer into a one-byte string
    resynth fn u8(
        val: U8,
        =>
        =>
        Void
    ) -> Str
    |mut args| {
        let val: u8 = args.next().into();
        Ok(Val::str(&val.to_le_bytes()))
    }
);

const LEN_BE64: FuncDef = func_def! (
    /// Prefix a buffer with a 64-bit big-endian length field
    resynth fn len_be64(
        =>
        =>
        Str
    ) -> Str
    |mut args| {
        let bytes: Buf = args.join_extra(b"").into();
        let mut msg: Vec<u8> = Vec::with_capacity(bytes.len() + 5);

        msg.extend((bytes.len() as u64).to_be_bytes());

        msg.extend(bytes.as_ref());

        Ok(Val::str(msg))
    }
);

const LEN_BE32: FuncDef = func_def! (
    /// Prefix a buffer with a 32-bit big-endian length field
    resynth fn len_be32(
        =>
        =>
        Str
    ) -> Str
    |mut args| {
        let bytes: Buf = args.join_extra(b"").into();
        let mut msg: Vec<u8> = Vec::with_capacity(bytes.len() + 5);

        msg.extend((bytes.len() as u32).to_be_bytes());

        msg.extend(bytes.as_ref());

        Ok(Val::str(msg))
    }
);

const LEN_BE16: FuncDef = func_def! (
    /// Prefix a buffer with a 16-bit big-endian length field
    resynth fn len_be16(
        =>
        =>
        Str
    ) -> Str
    |mut args| {
        let bytes: Buf = args.join_extra(b"").into();
        let mut msg: Vec<u8> = Vec::with_capacity(bytes.len() + 5);

        msg.extend((bytes.len() as u16).to_be_bytes());

        msg.extend(bytes.as_ref());

        Ok(Val::str(msg))
    }
);

const LEN_U8: FuncDef = func_def! (
    /// Prefix a buffer with a 8-bit byte length field
    resynth fn len_u8(
        =>
        =>
        Str
    ) -> Str
    |mut args| {
        let bytes: Buf = args.join_extra(b"").into();
        let mut msg: Vec<u8> = Vec::with_capacity(bytes.len() + 5);

        msg.push(bytes.len() as u8);

        msg.extend(bytes.as_ref());

        Ok(Val::str(msg))
    }
);

pub const MODULE: Module = module! {
    /// Standard types
    resynth mod std {
        be16 => Symbol::Func(&BE16),
        be32 => Symbol::Func(&BE32),
        be64 => Symbol::Func(&BE64),
        le16 => Symbol::Func(&LE16),
        le32 => Symbol::Func(&LE32),
        le64 => Symbol::Func(&LE64),
        u8 => Symbol::Func(&U8),

        len_be64 => Symbol::Func(&LEN_BE64),
        len_be32 => Symbol::Func(&LEN_BE32),
        len_be16 => Symbol::Func(&LEN_BE16),
        len_u8 => Symbol::Func(&LEN_U8),
    }
};
