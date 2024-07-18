use crate::func;
use crate::libapi::{FuncDef, Module};
use crate::sym::Symbol;
use crate::val::Val;

const HZ: u64 = 1_000_000_000;
const KHZ: u64 = HZ / 1000;
const MHZ: u64 = KHZ / 1000;

const JUMP_SECS: FuncDef = func!(
    /// Advance the pcap timestamp clock by some number of seconds
    resynth fn jump_seconds(
        seconds: U32,
        =>
        =>
        Void
    ) -> TimeJump
    |mut args| {
        let secs: u32 = args.next().into();

        Ok(Val::TimeJump((secs as u64) * HZ))
    }
);

const JUMP_MILLIS: FuncDef = func!(
    /// Advance the pcap timestamp clock by some number of milliseconds
    resynth fn jump_millis(
        ms: U64,
        =>
        =>
        Void
    ) -> TimeJump
    |mut args| {
        let ms: u64 = args.next().into();

        Ok(Val::TimeJump(ms * KHZ))
    }
);

const JUMP_MICROS: FuncDef = func!(
    /// Advance the pcap timestamp clock by some number of microseconds
    resynth fn jump_micros(
        us: U64,
        =>
        =>
        Void
    ) -> TimeJump
    |mut args| {
        let us: u64 = args.next().into();

        Ok(Val::TimeJump(us * MHZ))
    }
);

const JUMP_NANOS: FuncDef = func!(
    /// Advance the pcap timestamp clock by some number of nanoseconds
    resynth fn jump_nanos(
        ns: U64,
        =>
        =>
        Void
    ) -> TimeJump
    |mut args| {
        let ns: u64 = args.next().into();

        Ok(Val::TimeJump(ns))
    }
);

pub const MODULE: Module = module! {
    /// # Time Manipulation
    resynth mod time {
        jump_seconds => Symbol::Func(&JUMP_SECS),
        jump_millis => Symbol::Func(&JUMP_MILLIS),
        jump_micros => Symbol::Func(&JUMP_MICROS),
        jump_nanos => Symbol::Func(&JUMP_NANOS),
    }
};
