use phf::{phf_map, phf_ordered_map};

use crate::func_def;
use crate::libapi::{ArgDecl, FuncDef};
use crate::sym::Symbol;
use crate::val::{Val, ValType};

const HZ: u64 = 1_000_000_000;
const KHZ: u64 = HZ / 1000;
const MHZ: u64 = KHZ / 1000;

const JUMP_SECS: FuncDef = func_def!(
    /// Advance the pcap timestamp clock by some number of seconds
    "time::jump_seconds";
    ValType::TimeJump;

    "seconds" => ValType::U32,
    =>
    =>
    ValType::Void;

    |mut args| {
        let secs: u32 = args.next().into();

        Ok(Val::TimeJump((secs as u64) * HZ))
    }
);

const JUMP_MILLIS: FuncDef = func_def!(
    /// Advance the pcap timestamp clock by some number of milliseconds
    "time::jump_millis";
    ValType::TimeJump;

    "ms" => ValType::U64,
    =>
    =>
    ValType::Void;

    |mut args| {
        let ms: u64 = args.next().into();

        Ok(Val::TimeJump(ms * KHZ))
    }
);

const JUMP_MICROS: FuncDef = func_def!(
    /// Advance the pcap timestamp clock by some number of microseconds
    "time::jump_micros";
    ValType::TimeJump;

    "us" => ValType::U64,
    =>
    =>
    ValType::Void;

    |mut args| {
        let us: u64 = args.next().into();

        Ok(Val::TimeJump(us * MHZ))
    }
);

const JUMP_NANOS: FuncDef = func_def!(
    /// Advance the pcap timestamp clock by some number of nanoseconds
    "time::jump_nanos";
    ValType::TimeJump;

    "ns" => ValType::U64,
    =>
    =>
    ValType::Void;

    |mut args| {
        let ns: u64 = args.next().into();

        Ok(Val::TimeJump(ns))
    }
);

pub const MODULE: phf::Map<&'static str, Symbol> = phf_map! {
    "jump_seconds" => Symbol::Func(&JUMP_SECS),
    "jump_millis" => Symbol::Func(&JUMP_MILLIS),
    "jump_micros" => Symbol::Func(&JUMP_MICROS),
    "jump_nanos" => Symbol::Func(&JUMP_NANOS),
};
