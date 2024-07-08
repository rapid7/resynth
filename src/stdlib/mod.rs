use phf::phf_map;

use crate::args::Args;
use crate::err::Error;
use crate::err::Error::RuntimeError;
use crate::libapi::Module;
use crate::sym::Symbol;
use crate::val::Val;

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

#[cfg(test)]
mod test;
