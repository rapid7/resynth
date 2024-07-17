use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::func;
use crate::libapi::{Class, ClassDef, FuncDef, Module};
use crate::str::Buf;
use crate::sym::Symbol;
use crate::val::Val;

const IO_FILE: FuncDef = func!(
    /// Load the contents of a file into a string
    resynth fn file(
        filename: Str,
        =>
        =>
        Str
    ) -> Str
    |mut args| {
        let arg: Buf = args.next().into();
        let path = Path::new(OsStr::from_bytes(arg.as_ref()));
        let mut f = File::open(path)?;

        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;

        Ok(Val::str(buf))
    }
);

#[derive(Debug, PartialEq, Eq, Default)]
struct BufIo {
    buf: Vec<u8>,
    taken: usize,
}

impl BufIo {
    pub fn read(&mut self, bytes: usize) -> &[u8] {
        let remaining = self.buf.len() - self.taken;
        let take = std::cmp::min(remaining, bytes);

        let ret = &self.buf[self.taken..self.taken + take];
        self.taken += take;

        ret
    }

    pub fn read_all(&mut self) -> &[u8] {
        let remaining = self.buf.len() - self.taken;

        let ret = &self.buf[self.taken..self.taken + remaining];
        self.taken += remaining;

        ret
    }
}

impl<T> From<T> for BufIo
where
    T: AsRef<[u8]>,
{
    fn from(s: T) -> Self {
        Self {
            buf: Vec::from(s.as_ref()),
            taken: 0,
        }
    }
}

const BUFIO_READ: FuncDef = func!(
    /// Read some bytes out of a buffer
    resynth fn read(
        bytes: U64,
        =>
        =>
        Void
    ) -> Str
    |mut args| {
        let bytes: u64 = args.next().into();
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut BufIo = r.as_mut_any().downcast_mut().unwrap();
        Ok(Val::Str(this.read(bytes as usize).into()))
    }
);

const BUFIO_READ_ALL: FuncDef = func!(
    /// Read all remaining bytes out of a buffer
    resynth fn read_all(
        =>
        =>
        Void
    ) -> Str
    |mut args| {
        let obj = args.take_this();
        let mut r = obj.borrow_mut();
        let this: &mut BufIo = r.as_mut_any().downcast_mut().unwrap();
        Ok(Val::Str(this.read_all().into()))
    }
);

const BUFIO_CLASS: ClassDef = class!(
    /// Buffered I/O
    resynth class BufIO {
        read => Symbol::Func(&BUFIO_READ),
        read_all => Symbol::Func(&BUFIO_READ_ALL),
    }
);

impl Class for BufIo {
    fn def(&self) -> &'static ClassDef {
        &BUFIO_CLASS
    }
}

const BUFIO: FuncDef = func!(
    /// Create a buffer from a string, from which you can read parts in sequence
    resynth fn bufio(
        =>
        =>
        Str
    ) -> Obj
    |mut args| {
        let bytes: Buf = args.join_extra(b"").into();
        Ok(Val::from(BufIo::from(bytes.as_ref())))
    }
);

pub const MODULE: Module = module!(
    /// Buffers and File I/O
    resynth mod io {
        BufIO => Symbol::Class(&BUFIO_CLASS),
        file => Symbol::Func(&IO_FILE),
        bufio => Symbol::Func(&BUFIO),
    }
);
