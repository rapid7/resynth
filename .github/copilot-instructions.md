# Copilot Instructions for resynth

## What This Project Is

Resynth is a **packet synthesis language** — a compiler/interpreter that takes `.rsyn` source files and produces `.pcap` output files. It is a Rust workspace with three crates:

- **`pkt/`** — Low-level packet structs, protocol headers, and constants. No high-level abstractions.
- **`ezpkt/`** — Higher-level flow abstractions (TCP flows, UDP flows, IP fragmentation, etc.) built on top of `pkt`.
- **`src/`** (root crate) — The language itself: lexer, parser, interpreter/program, and the standard library (`src/stdlib/`).

## Build, Test, and Lint

```sh
# Build
cargo build

# Run all tests
cargo test --all

# Run a single test (by name filter)
cargo test <test_name>

# Lint (must be warning-free)
cargo clippy -- -D warnings

# Format
cargo fmt

# Format check only
cargo fmt --check

# Generate stdlib docs (writes to docs/)
cargo run -- --output-docs docs
```

The pre-commit hook (`pre-commit.sh`) runs fmt check, clippy (warnings as errors), tests, doc generation, and stages the updated `docs/` directory.

### Stdlib API reference

```sh
# If resynth is already built:
./target/debug/resynth --output-docs docs

# Or via cargo:
cargo run -- --output-docs docs
```

This regenerates `docs/` from the doc comments embedded in the `func!`/`module!`/`class!` macros. The `docs/` tree is the canonical human-readable API reference for the resynth standard library — consult it when working with or adding stdlib modules. **Always regenerate and `git add docs/` after changing any stdlib doc comments or adding/removing symbols.**

## Architecture: How the Language Works

The pipeline for evaluating a `.rsyn` file is:

1. **`Lexer`** (`src/lex.rs`) — Regex-based tokenizer; processes line by line.
2. **`Parser`** (`src/parse.rs`) — Hand-written LR parser; produces a `Vec<Stmt>` of statements.
3. **`Program`** (`src/program.rs`) — Interpreter/execution state; takes one `Stmt` at a time, maintains a symbol table, and writes generated packets to a `pkt::PcapWriter`.

## Standard Library Pattern

Every stdlib module (in `src/stdlib/`) follows the same DSL-macro pattern:

- **`func!`** macro declares a `FuncDef` with typed positional/optional/collect args, a return type, doc comments, and an exec closure.
- **`module!`** macro declares a `Module` (static symbol table of `SymDesc` entries).
- **`class!`** macro declares a `ClassDef` for object types that have methods.

The `Symbol` enum can hold a `Module`, `Func`, `Class`, or `Val`. The stdlib registry in `src/stdlib/mod.rs` maps top-level import names to modules.

### Adding a new stdlib function

```rust
const MY_FUNC: FuncDef = func! {
    /// Doc comment becomes stdlib docs
    resynth fn my_func(
        src: Ip4,           // positional args
        =>
        ttl: U8 = 64,       // optional args with defaults
        =>
        Void                // collect-args type (Void = none)
    ) -> Pkt
    |mut args| {
        let src: Ipv4Addr = args.next().into();
        let ttl: u8 = args.next().into();
        // ... build and return a packet
        Ok(val)
    }
};
```

Then register it in the relevant `module!` or `class!` block.

### `func!` macro argument sections

The three `=>` sections in `func!` are:
1. Positional (required) args
2. Optional args with defaults (`ValDef` expressions)
3. Collect-args type (variadic; `Void` means none)

## Value System

`Val` is the runtime value type; `ValDef` is its compile-time/const counterpart used for default argument values. Both implement the `Typed` trait. Integral types (`U8`, `U16`, `U32`, `U64`, `Bool`) are mutually compatible; `Str` accepts any `is_string_coercible()` type; `PktGen` accepts `Pkt`.

## Resynth Language Grammar

Derived from `src/parse.rs`. There are exactly **three statement forms**:

```
import <identifier> ;
let <identifier> = <expr> ;
<expr> ;
```

An `<expr>` is one of:
- A **literal**: string, boolean, decimal integer, hex integer (`0x…`), IPv4 address
- A **socket address**: `<ipv4> : <port>` (e.g., `192.168.0.1:80`) — reduced directly to `Sock4`
- A **binary slash**: `<expr> / <expr>` (e.g., `192.168.0.1/80`) — the only binary operator; also produces a socket address when used with IP and port
- An **object reference**: one or more `::` -separated module components followed by zero or more `.`-separated object components (e.g., `ipv4::tcp::flow`, `conn.open`)
- A **call**: `<object-ref> ( <args> )` where args are comma-separated and each arg is either anonymous (`<expr>`) or named (`<identifier> : <expr>`)

String literals support inline hex escapes: `"text|0d 0a|more"` — bytes within `|…|` are hex pairs.

Comments: `#` or `//` to end of line. Shebang (`#!`) on the first line is also treated as a comment.

An expression statement that evaluates to a `Pkt` or `PktGen` value emits packets. Deferring evaluation via `let` and emitting later controls packet ordering (see `examples/http-reorder.rsyn`).

## Key Conventions

- **`#![allow(clippy::upper_case_acronyms)]`** is set in `src/stdlib/mod.rs` — protocol constants like `TCP`, `UDP`, `DNS` are intentionally all-caps.
- Protocol header structs in `pkt/` are plain `bytemuck`-compatible POD types.
- Stdlib functions receive args via `Args` (an iterator wrapper); call `args.next().into()` in declaration order to extract them with type coercion.
- Doc comments on `func!`/`module!`/`class!` invocations feed directly into the generated `docs/` API reference. Keep them accurate and regenerate docs after any stdlib changes.
- Tests for the interpreter/compiler internals live in `src/test/`; stdlib-specific tests live in `src/stdlib/test/`.
