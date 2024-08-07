use crate::args::{ArgSpec, ArgVec, Args};
use crate::err::Error;
use crate::err::Error::TypeError;
use crate::object::ObjRef;
use crate::sym::Symbol;
use crate::val::{Typed, Val, ValDef, ValType};

use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::io::Write;

/// Argument declarator
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgDecl {
    Positional(ValType),
    Optional(ValDef),
}

impl Display for ArgDecl {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::Positional(typ) => write!(f, "{}", typ),
            Self::Optional(dfl) => {
                write!(f, "{} = {}", dfl.val_type(), dfl)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArgDesc {
    pub name: &'static str,
    pub typ: ArgDecl,
}

impl Display for ArgDesc {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}: {}", self.name, self.typ)
    }
}

/// Defines a function or method for the resynth stdlib
#[derive(Debug)]
pub struct FuncDef {
    pub name: &'static str,
    pub return_type: ValType,
    /// Invariant: All Positionals must come first, then all Optional
    pub args: &'static [ArgDesc],
    pub arg_pos: fn(name: &str) -> Option<usize>,
    /// minimum number of args: ie. number of positionals
    pub min_args: usize,
    pub collect_type: ValType,
    pub exec: fn(args: Args) -> Result<Val, Error>,
    pub doc: &'static str,
}

impl Eq for FuncDef {}
impl PartialEq for FuncDef {
    fn eq(&self, other: &FuncDef) -> bool {
        std::ptr::eq(self as *const FuncDef, other as *const FuncDef)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymDesc {
    pub name: &'static str,
    pub sym: Symbol,
}

/// Applies to anything with a symbol table which is documented into a documentation page
/// ie. classes and modules
pub trait Documented {
    fn symtab(&self) -> &'static [SymDesc];
    fn front_matter(&self) -> &'static str;

    fn symbol_set<F>(&self, flt: F) -> Vec<SymDesc>
    where
        F: FnMut(&SymDesc) -> bool,
    {
        let mut ret: Vec<SymDesc> = self.symtab().iter().cloned().filter(flt).collect();
        ret.sort();
        ret.shrink_to_fit();
        ret
    }

    fn modules(&self) -> Vec<SymDesc> {
        self.symbol_set(|&x| matches!(x.sym, Symbol::Module(_)))
    }

    fn functions(&self) -> Vec<SymDesc> {
        self.symbol_set(|&x| matches!(x.sym, Symbol::Func(_)))
    }

    fn classes(&self) -> Vec<SymDesc> {
        self.symbol_set(|&x| matches!(x.sym, Symbol::Class(_)))
    }

    fn constants(&self) -> Vec<SymDesc> {
        self.symbol_set(|&x| matches!(x.sym, Symbol::Val(_)))
    }

    fn write_docs<W: Write>(&self, wr: &mut W) -> Result<(), std::io::Error> {
        wr.write_all(self.front_matter().as_bytes())?;

        let submods = self.modules();
        let funcs = self.functions();
        let classes = self.classes();
        let consts = self.constants();

        wr.write_all(b"\n## Index\n\n")?;

        if !submods.is_empty() {
            wr.write_all(b"\n### Modules\n\n")?;
            for SymDesc { name, sym: _ } in &submods {
                wr.write_all(format!("- [{}]({}/README.md)\n", name, name,).as_bytes())?;
            }
        }

        if !classes.is_empty() {
            wr.write_all(b"\n### Classes\n\n")?;
            for SymDesc { name, sym: _ } in &classes {
                wr.write_all(format!("- [{}]({}.md)\n", name, name,).as_bytes())?;
            }
        }

        if !funcs.is_empty() {
            wr.write_all(b"\n### Functions\n\n")?;
            for SymDesc { name, sym: _ } in &funcs {
                wr.write_all(format!("- [{}](#{})\n", name, name,).as_bytes())?;
            }
        }

        if !consts.is_empty() {
            wr.write_all(b"\n### Constants\n\n")?;
            wr.write_all(b"| Name | Value |\n")?;
            wr.write_all(b"| ---- | ----- |\n")?;
            for SymDesc { name, sym } in &consts {
                if let Symbol::Val(val) = sym {
                    wr.write_all(
                        format!("| {} | `({}){}` |\n", name, val.val_type(), val,).as_bytes(),
                    )?;
                }
            }
        }

        if !funcs.is_empty() {
            wr.write_all(b"\n\n")?;
            for SymDesc { name, sym } in &funcs {
                if let Symbol::Func(func) = sym {
                    assert_eq!(*name, func.name);
                    func.write_docs(wr)?;
                }
            }
        }

        Ok(())
    }
}

impl PartialOrd for SymDesc {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SymDesc {
    fn cmp(&self, other: &Self) -> Ordering {
        self.name.cmp(other.name)
    }
}

/// Defines a module for the resynth stdlib
#[derive(Debug)]
pub struct Module {
    pub name: &'static str,
    pub symtab: &'static [SymDesc],
    pub lookup: fn(name: &str) -> Option<usize>,
    pub doc: &'static str,
}

impl Documented for Module {
    fn symtab(&self) -> &'static [SymDesc] {
        self.symtab
    }

    fn front_matter(&self) -> &'static str {
        self.doc
    }
}

impl Module {
    pub fn get(&self, name: &str) -> Option<&'static Symbol> {
        match (self.lookup)(name) {
            Some(idx) => Some(&self.symtab[idx].sym),
            None => None,
        }
    }
}

/// Defines a module for the resynth stdlib
#[derive(Debug)]
pub struct ClassDef {
    pub name: &'static str,
    pub symtab: &'static [SymDesc],
    pub lookup: fn(name: &str) -> Option<usize>,
    pub doc: &'static str,
}

impl Documented for ClassDef {
    fn symtab(&self) -> &'static [SymDesc] {
        self.symtab
    }

    fn front_matter(&self) -> &'static str {
        self.doc
    }
}

impl ClassDef {
    pub fn get(&self, name: &str) -> Option<&'static Symbol> {
        match (self.lookup)(name) {
            Some(idx) => Some(&self.symtab[idx].sym),
            None => None,
        }
    }
}

pub trait Class {
    fn def(&self) -> &'static ClassDef;

    fn get(&self, name: &str) -> Option<&'static Symbol> {
        self.def().get(name)
    }

    fn symbols(&self) -> &'static [SymDesc] {
        self.def().symtab
    }

    fn class_name(&self) -> &'static str {
        self.def().name
    }

    fn doc(&self) -> &'static str {
        self.def().doc
    }
}

struct ArgPrep {
    positional: Vec<Val>,
    named: HashMap<String, Val>,
    extra: Vec<Val>,
}

/// Invariant: No argument may be supplied with a value more than once
/// Invariant: No argument can be ambiguous as to where it belongs
///
/// Rules:
///  P-FIRST Positonal args must be supplied first
///  P-NAME-OPTIONAL Positionals may be named or not
///  ANON-FIRST If one positional is named, all subsequent positionals + optionals must be named
///  COLLECT-NAME-OPTS if func has collect args, optionals MUST be named
///  NOCOLLECT-ANON-OPTS if func doesn't have collect args, optionals MAY be anonymous
///  COLLECT-AFTER-NAMED collect args must come after the last named arg
impl FuncDef {
    pub fn is_collect(&self) -> bool {
        self.collect_type != ValType::Void
    }

    fn split_args(&self, args: Vec<ArgSpec>) -> Result<ArgPrep, Error> {
        enum State {
            Anon,
            Optional,
            CollectOnly,
        }
        let mut positional: Vec<Val> = Vec::new();
        let mut named: HashMap<String, Val> = HashMap::new();
        let mut extra: Vec<Val> = Vec::new();
        let mut state = State::Anon;

        for arg in args {
            loop {
                match state {
                    State::Anon => {
                        if !arg.is_anon() {
                            state = State::Optional;
                            continue;
                        } else if self.is_collect() && positional.len() >= self.min_args {
                            // If we have collect args, then any optionals must be named
                            state = State::CollectOnly;
                            continue;
                        } else if positional.len() >= self.args.len() {
                            if self.is_collect() {
                                state = State::CollectOnly;
                                continue;
                            }
                            println!(
                                "ERR: {}: Too many arguments: {} > {}",
                                self.name,
                                positional.len(),
                                self.args.len()
                            );
                            return Err(TypeError);
                        } else {
                            positional.push(arg.val);
                            break;
                        }
                    }
                    State::Optional => {
                        if arg.is_anon() {
                            state = State::CollectOnly;
                            continue;
                        }

                        let name = arg.name.unwrap();

                        let arg_pos = (self.arg_pos)(&name);

                        if arg_pos.is_none() {
                            println!("ERR: {}: No such argument: \"{}\"", self.name, &name);
                            return Err(TypeError);
                        }

                        let arg_index = arg_pos.unwrap();

                        // Invariant: No argument may be supplied with a value more than once

                        // a) If the index of the arg is one of the positionals we've already got,
                        // then a positional has been specified by position, and is now attempting
                        // to be specified by name. So nope.
                        if arg_index < positional.len() {
                            println!(
                                "ERR: {}: Positional argument \"{}\" multiply specified",
                                self.name, &name
                            );
                            return Err(TypeError);
                        }

                        // b) if we've named the same arg twice then that's also not allowed.
                        if named.contains_key(&name) {
                            println!(
                                "ERR: {}: Optional argument \"{}\" multiply specified",
                                self.name, &name
                            );
                            return Err(TypeError);
                        }

                        named.insert(name, arg.val);
                        break;
                    }
                    State::CollectOnly => {
                        if !self.is_collect() {
                            println!("ERR: {}: Unexpected collect-arguments", self.name);
                            return Err(TypeError);
                        }
                        if arg.is_named() {
                            println!(
                                "ERR: {}: Unexpected named argument: \"{}\"",
                                self.name,
                                arg.name.unwrap()
                            );
                            return Err(TypeError);
                        }
                        extra.push(arg.val);
                        break;
                    }
                }
            }
        }

        positional.shrink_to_fit();
        named.shrink_to_fit();
        extra.shrink_to_fit();

        Ok(ArgPrep {
            positional,
            named,
            extra,
        })
    }

    pub fn argvec(&self, this: Option<ObjRef>, args: Vec<ArgSpec>) -> Result<ArgVec, Error> {
        let ArgPrep {
            positional,
            mut named,
            extra,
        } = self.split_args(args)?;
        let nr_positional = positional.len();
        let nr_named = named.len();
        let nr_specified = nr_positional + nr_named;

        // Now do some basic sanity checks to stup us shooting ourselves in the foot later
        if nr_specified < self.min_args {
            println!(
                "ERR: {}: Not enough specified args: {} ({} + {}) < {}",
                self.name, nr_specified, nr_positional, nr_named, self.min_args
            );
            return Err(TypeError);
        }

        let mut args: Vec<Val> = Vec::with_capacity(self.args.len());

        // 1. push anon vals to start with
        for a in positional {
            args.push(a);
        }

        // either all positional and optional args are supplied and then everything else is in
        // extra OR some positional/optional have been named, in which case all the collect args
        // are in extra assert!(args.len() <= self.args.len());

        // 2. Take named positionals and optionals
        for ArgDesc { name, typ } in self.args.iter().skip(nr_positional) {
            if let Some(val) = named.remove(*name) {
                // positional or optional specified by name, push it
                args.push(val);
            } else if let ArgDecl::Optional(dfl) = typ {
                // not specified, but we're optional, so take the default
                args.push((*dfl).into());
            } else {
                // not specified, and we're mandatory, barf
                println!(
                    "ERR: {}: Positional argument \"{}\" not specified",
                    self.name, name
                );
                return Err(TypeError);
            }
        }

        assert!(named.is_empty());

        // 3. Final type-check of all positional args
        for (ArgDesc { name, typ }, arg) in self.args.iter().zip(args.iter()) {
            if !match typ {
                ArgDecl::Positional(typ) => typ.compatible_with(arg),
                ArgDecl::Optional(dfl) => dfl.arg_compatible(arg),
            } {
                println!(
                    "ERR: {}: Argument type-check failed for {:?}",
                    self.name, name
                );
                return Err(TypeError);
            }
        }

        // 4. Type-check the collect-args
        if extra.iter().any(|x| !self.collect_type.compatible_with(x)) {
            println!("ERR: {}: Collect argument of wrong type", self.name);
            return Err(TypeError);
        }

        Ok(ArgVec::new(this, args, extra))
    }

    pub fn args(&self, this: Option<ObjRef>, args: Vec<ArgSpec>) -> Result<Args, Error> {
        Ok(self.argvec(this, args)?.into())
    }

    pub fn write_docs<W: Write>(&self, wr: &mut W) -> Result<(), std::io::Error> {
        wr.write_all(format!("\n## {}\n", self.name).as_bytes())?;
        wr.write_all(b"```resynth\n")?;
        wr.write_all(format!("{}\n", self).as_bytes())?;
        wr.write_all(b"```\n")?;
        wr.write_all(self.doc.as_bytes())?;
        wr.write_all(b"\n")?;
        Ok(())
    }
}

impl Display for FuncDef {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        writeln!(f, "resynth fn {} (", self.name)?;

        for arg in self.args.iter() {
            writeln!(f, "    {},", arg)?;
        }

        if !self.collect_type.is_nil() {
            writeln!(f, "    =>\n    *collect_args: {},", self.collect_type)?;
        }

        write!(f, ") -> {};", self.return_type)
    }
}
