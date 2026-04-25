// Required to allow DSL symbols to be all uppercase
#![allow(clippy::upper_case_acronyms)]

use crate::args::Args;
use crate::err::Error;
use crate::err::Error::RuntimeError;
use crate::libapi::{ClassMap, Documented, Module, SymDesc};
use crate::sym::Symbol;
use crate::val::Val;

use ::std::fs::{File, create_dir_all};
use ::std::io::BufWriter;
use ::std::path::{Path, PathBuf};

pub fn unimplemented(mut args: Args) -> Result<Val, Error> {
    println!("Unimplemented stdlib call");
    args.void();
    Err(RuntimeError)
}

mod arp;
mod dhcp;
mod dns;
mod erspan1;
mod erspan2;
mod erspan3;
mod eth;
mod gre;
mod io;
mod ipv4;
mod netbios;
mod std;
mod text;
mod time;
mod tls;
mod vxlan;

const STDLIB: Module = module! {
    /// # Resynth Standard Library
    ///
    /// These are all the basic functions included in resynth
    resynth mod stdlib {
        std => Symbol::Module(&std::MODULE),
        text => Symbol::Module(&text::MODULE),
        io => Symbol::Module(&io::MODULE),
        ipv4 => Symbol::Module(&ipv4::IPV4),
        dns => Symbol::Module(&dns::DNS),
        netbios => Symbol::Module(&netbios::NETBIOS),
        dhcp => Symbol::Module(&dhcp::MODULE),
        arp => Symbol::Module(&arp::MODULE),
        tls => Symbol::Module(&tls::TLS),
        vxlan => Symbol::Module(&vxlan::MODULE),
        gre => Symbol::Module(&gre::MODULE),
        eth => Symbol::Module(&eth::MODULE),
        erspan1 => Symbol::Module(&erspan1::MODULE),
        erspan2 => Symbol::Module(&erspan2::MODULE),
        erspan3 => Symbol::Module(&erspan3::MODULE),
        time => Symbol::Module(&time::MODULE),
    }
};

pub fn toplevel_module(name: &str) -> Option<&'static Module> {
    match STDLIB.get(name) {
        None => None,
        Some(Symbol::Module(module)) => Some(module),
        Some(Symbol::Func(_)) | Some(Symbol::Class(_)) | Some(Symbol::Val(_)) => {
            /* There shouldn't be any top level function or variable */
            unreachable!();
        }
    }
}

/// First pass: walk the module tree and collect all class → doc-root-relative path entries.
fn collect_classes(stk: &mut Vec<&'static str>, m: &'static Module, map: &mut ClassMap) {
    for SymDesc { name, sym } in m.symtab.iter() {
        stk.push(name);
        match sym {
            Symbol::Module(child) => collect_classes(stk, child, map),
            Symbol::Class(cls) => {
                let path = format!("{}/{}.md", stk[..stk.len() - 1].join("/"), name);
                map.insert(cls, path);
            }
            _ => {}
        }
        stk.pop();
    }
}

/// Compute the relative prefix needed to reach the docs root from a module at depth `depth`.
/// e.g. depth 1 → `"../"`, depth 2 → `"../../"`.
fn doc_root_prefix(depth: usize) -> String {
    "../".repeat(depth)
}

/// Generate documentation for a module.
pub fn recurse(
    out_dir: &Path,
    stk: &mut Vec<&'static str>,
    m: &'static Module,
    class_map: &ClassMap,
) {
    let mut mod_path = PathBuf::from(out_dir);

    for item in stk.iter() {
        mod_path.push(item);
    }

    create_dir_all(&mod_path).expect("mkdir");
    mod_path.push("README.md");

    println!("module -> {}", mod_path.display());

    let f = File::create(mod_path.clone()).expect("Unable to create file");
    let mut wr = BufWriter::new(f);

    mod_path.pop();

    let doc_root = doc_root_prefix(stk.len());
    m.write_docs(&mut wr, class_map, &doc_root)
        .expect("Write module docs");

    for SymDesc { name, sym } in m.symtab.iter() {
        stk.push(name);
        match sym {
            Symbol::Module(child) => recurse(out_dir, stk, child, class_map),
            Symbol::Class(cls) => {
                mod_path.push(format!("{}.md", name));
                println!("class -> {}", mod_path.display());

                let f = File::create(mod_path.clone()).expect("Unable to create file");
                let mut wr = BufWriter::new(f);

                let doc_root = doc_root_prefix(stk.len());
                cls.write_docs(&mut wr, class_map, &doc_root)
                    .expect("class doc");
            }
            _ => {}
        }
        stk.pop();
    }
}

pub fn write_docs(out_dir: &Path) {
    create_dir_all(out_dir).expect("mkdir");

    let mut stk: Vec<&'static str> = Vec::new();
    let mut class_map = ClassMap::new();
    collect_classes(&mut stk, &STDLIB, &mut class_map);

    recurse(out_dir, &mut stk, &STDLIB, &class_map)
}

#[cfg(test)]
mod test;
