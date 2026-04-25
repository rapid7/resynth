#!/bin/sh

set -euo pipefail

exec 1>&2

cargo fmt --check
cargo clippy -- -D warnings
cargo test --all
cargo doc
cargo run -- --output-docs docs
git add docs
