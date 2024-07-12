use phf::phf_map;

use crate::args::Args;
use crate::err::Error;
use crate::err::Error::RuntimeError;
use crate::libapi::Module;
use crate::sym::Symbol;
use crate::val::Val;

use ::std::fs::{create_dir_all, File};
use ::std::io::{BufWriter, Write};
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

const STDLIB: phf::Map<&'static str, Symbol> = phf_map! {
    "std" => Symbol::Module(&std::MODULE),
    "text" => Symbol::Module(&text::MODULE),
    "io" => Symbol::Module(&io::MODULE),
    "ipv4" => Symbol::Module(&ipv4::IPV4),
    "dns" => Symbol::Module(&dns::DNS),
    "netbios" => Symbol::Module(&netbios::NETBIOS),
    "dhcp" => Symbol::Module(&dhcp::MODULE),
    "arp" => Symbol::Module(&arp::MODULE),
    "tls" => Symbol::Module(&tls::TLS),
    "vxlan" => Symbol::Module(&vxlan::MODULE),
    "gre" => Symbol::Module(&gre::MODULE),
    "eth" => Symbol::Module(&eth::MODULE),
    "erspan1" => Symbol::Module(&erspan1::MODULE),
    "erspan2" => Symbol::Module(&erspan2::MODULE),
    "time" => Symbol::Module(&time::MODULE),
};

pub fn toplevel_module(name: &str) -> Option<&'static Module> {
    match STDLIB.get(name) {
        None => None,
        Some(Symbol::Module(module)) => Some(module),
        Some(Symbol::Func(_)) | Some(Symbol::Val(_)) => {
            /* There shouldn't be any top level function or variable */
            unreachable!();
        }
    }
}

/// Generate documentation for a module.. This needs a lot of work.
pub fn recurse(out_dir: &Path, stk: &mut Vec<&'static str>, m: &phf::Map<&'static str, Symbol>) {
    let mut mod_path = PathBuf::from(out_dir);

    if stk.is_empty() {
        mod_path.push("README.md");
    } else {
        for item in &stk[..stk.len() - 1] {
            mod_path.push(item);
        }
        create_dir_all(&mod_path).expect("mkdir");
        mod_path.push(format!("{}.md", &stk[stk.len() - 1]));
    }

    println!("mod path: {}", mod_path.display());

    let f = File::create(mod_path).expect("Unable to create file");
    let mut wr = BufWriter::new(f);

    for (name, sym) in m.entries() {
        stk.push(name);
        match sym {
            Symbol::Module(child) => {
                recurse(out_dir, stk, child);
            }
            Symbol::Func(func) => {
                // let qname = stk.join("::");

                wr.write_all(format!("# {}\n", func.name).as_bytes())
                    .expect("write func name");
                wr.write_all(func.doc.as_bytes()).expect("write body");
                wr.write_all(b"\n\n").expect("write LF");
            }
            _ => (),
        }
        stk.pop();
    }
}

pub fn write_docs(out_dir: &Path) {
    println!("Write docs to {}", out_dir.display());
    create_dir_all(out_dir).expect("mkdir");

    let mut stk: Vec<&'static str> = Vec::new();

    recurse(out_dir, &mut stk, &STDLIB)
}

#[cfg(test)]
mod test;
