#!/bin/sh

set -euo pipefail

exec 1>&2

cargo clippy
cargo test --all
cargo doc
