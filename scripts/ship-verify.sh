#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
if ! command -v cargo-audit >/dev/null 2>&1; then
  cargo install cargo-audit --locked
fi
cargo audit
cargo test --workspace
