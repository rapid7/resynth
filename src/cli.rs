use pkt::PcapWriter;

use resynth::{error, ok, warn};
use resynth::{Error, Lexer, Loc, Parser, Program, EOF};

use std::borrow::Cow;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::{fs, io};

use clap::{error::ErrorKind, value_parser, Arg, ArgAction, Command};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

/// A [source code location](Loc) and an [error code](Error)
#[derive(Debug)]
pub struct ErrorLoc {
    pub loc: Loc,
    pub err: Error,
}

impl ErrorLoc {
    pub fn new(loc: Loc, err: Error) -> Self {
        Self { loc, err }
    }
}

impl From<Error> for ErrorLoc {
    fn from(e: Error) -> Self {
        Self::new(Loc::nil(), e)
    }
}

impl From<io::Error> for ErrorLoc {
    fn from(e: io::Error) -> Self {
        Self::new(Loc::nil(), e.into())
    }
}

pub fn process_file(
    stdout: &mut StandardStream,
    inp: &Path,
    out: &Path,
    verbose: bool,
) -> Result<(), ErrorLoc> {
    let file = fs::File::open(inp)?;
    let rd = io::BufReader::new(file);
    let wr = {
        let wr = PcapWriter::create(out)?;
        if verbose {
            wr.debug()
        } else {
            wr
        }
    };
    let mut prog = Program::with_pcap_writer(wr)?;
    let mut parse = Parser::default();
    let mut lex = Lexer::default();

    let mut warning = |loc: Loc, warn: &str| {
        if loc.is_nil() {
            print!("{}: ", inp.display());
        } else {
            print!("{}:{}:{}: ", inp.display(), loc.line(), loc.col());
        }
        warn!(stdout, "warning");
        println!(": {}", warn);
    };
    prog.set_warning(&mut warning);

    for (lno, res) in rd.lines().enumerate() {
        let line = res?;

        let toks = match lex.line(lno + 1, &line) {
            Ok(toks) => toks,
            Err(err) => return Err(ErrorLoc::new(lex.loc(), err)),
        };

        for tok in toks {
            if let Err(err) = parse.feed(&tok) {
                return Err(ErrorLoc::new(tok.loc(), err));
            }
        }

        if let Err(err) = prog.add_stmts(parse.get_results()) {
            return Err(ErrorLoc::new(prog.loc(), err));
        }
    }

    if let Err(err) = parse.feed(&EOF) {
        return Err(ErrorLoc::new(lex.loc(), err));
    }

    if let Err(err) = prog.add_stmts(parse.get_results()) {
        return Err(ErrorLoc::new(prog.loc(), err));
    }

    Ok(())
}

fn resynth() -> Result<(), ()> {
    let mut ret = Ok(());

    let mut cmd = Command::new("resynth")
        .version("0.1")
        .author("Gianni Teesco <gianni@scaramanga.co.uk>")
        .about("Packet synthesis language")
        .arg(
            Arg::new("color")
                .long("color")
                .value_parser(["always", "ansi", "auto", "never"])
                .default_value("auto")
                .help("always|ansi|auto|never"),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue)
                .help("Print packets"),
        )
        .arg(
            Arg::new("keep")
                .short('k')
                .long("keep")
                .action(ArgAction::SetTrue)
                .help("Keep pcap files on error"),
        )
        .arg(
            Arg::new("out")
                .short('o')
                .long("output")
                .value_name("FILE")
                .required(false)
                .value_parser(value_parser!(PathBuf))
                .action(ArgAction::Append)
                .help("Filenames for pcap output"),
        )
        .arg(
            Arg::new("outdir")
                .long("out-dir")
                .value_name("DIR")
                .default_value(".")
                .conflicts_with("out")
                .value_parser(value_parser!(PathBuf))
                .help("Directory to write pcap files to"),
        )
        .arg(
            Arg::new("in")
                .help("Sets the input file to use")
                .value_name("FILE")
                .required(true)
                .action(ArgAction::Append)
                .index(1),
        );

    let argv = cmd.clone().get_matches();

    let verbose = argv.get_one::<bool>("verbose").copied().unwrap();
    let keep = argv.get_one::<bool>("keep").copied().unwrap();

    let preference: &String = argv.get_one("color").expect("default");
    let color = match preference.as_str() {
        "always" => ColorChoice::Always,
        "ansi" => ColorChoice::AlwaysAnsi,
        "auto" => {
            if atty::is(atty::Stream::Stdout) {
                ColorChoice::Auto
            } else {
                ColorChoice::Never
            }
        }
        _ => ColorChoice::Never,
    };
    let mut stdout = StandardStream::stdout(color);

    let use_filenames = argv.contains_id("out");

    let in_args = argv.get_many::<String>("in").unwrap();

    let out_args = argv
        .get_many::<PathBuf>("out")
        .unwrap_or_default()
        .collect::<Vec<_>>();
    let out_dir = argv.get_one::<PathBuf>("outdir");

    if use_filenames && out_args.len() != in_args.len() {
        cmd.error(
            ErrorKind::WrongNumberOfValues,
            format!(
                "Received {} output(s), expected: {}",
                out_args.len(),
                in_args.len(),
            ),
        )
        .exit();
    }

    for (i, input) in in_args.enumerate() {
        let p = Path::new(input);
        let out = if use_filenames {
            Cow::Borrowed(out_args[i])
        } else {
            let mut out = match out_dir {
                Some(p) => p.clone(),
                None => PathBuf::new(),
            };
            out.push(p.file_stem().unwrap());
            out.set_extension("pcap");
            Cow::Owned(out)
        };

        let result = process_file(&mut stdout, p, &out, verbose);

        if let Err(error) = result {
            let ErrorLoc { loc, err } = error;

            if loc.is_nil() {
                print!("{}: ", p.display());
            } else {
                print!("{}:{}:{}: ", p.display(), loc.line(), loc.col());
            }
            error!(stdout, "error");
            println!(": process_file: {}", err);

            if !keep {
                if let Err(rm_err) = fs::remove_file(out.as_ref()) {
                    print!("{}: ", p.display());
                    error!(stdout, "error");
                    println!(": delete: {}", rm_err);
                }
            }

            ret = Err(());
        } else {
            print!("{} -> {} ", p.display(), out.display());
            ok!(stdout, "ok");
            println!();
        }
    }

    ret
}

fn main() {
    if resynth().is_err() {
        std::process::exit(1);
    }
}
