use std::io;

use derive_more::{Display, Error, From};

/// Error code for resynth program. Think of it as base exception type for the resynth language.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Display, Error, From)]
pub enum Error {
    #[display("{}", _0)]
    #[from]
    IoError(io::Error),

    #[display("Lex Error")]
    LexError,

    #[display("Parse Error")]
    ParseError,

    #[display("Memory Error")]
    MemoryError,

    #[display("Import Error: Unknown Module {:?}", _0)]
    #[error(ignore)]
    ImportError(Box<str>),

    #[display("Name Error")]
    NameError,

    #[display("Type Error")]
    TypeError,

    #[display("Runtime Error")]
    RuntimeError,

    #[display("Variable {:?} reassigned", _0)]
    #[error(ignore)]
    MultipleAssignError(Box<str>),
}

impl Eq for Error {}
impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        use Error::*;
        match (self, other) {
            (IoError(a), IoError(b)) => a.kind() == b.kind(),
            (LexError, LexError) => true,
            (ParseError, ParseError) => true,
            (MemoryError, MemoryError) => true,
            (ImportError(a), ImportError(b)) => a == b,
            (NameError, NameError) => true,
            (TypeError, TypeError) => true,
            (RuntimeError, RuntimeError) => true,
            (MultipleAssignError(a), MultipleAssignError(b)) => a == b,
            _ => false,
        }
    }
}
