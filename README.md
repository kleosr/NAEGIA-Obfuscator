<div align="center">
  <img src="https://img.shields.io/badge/rust-1.82+-orange?logo=rust&style=flat-square" />
  <img src="https://img.shields.io/badge/target-x86_64--windows--msvc-blue?style=flat-square" />
  <img src="https://img.shields.io/github/v/tag/your-org/NAEGIA-Obfuscator?style=flat-square" />
  <img src="https://img.shields.io/badge/license-MIT-brightgreen?style=flat-square" />
</div>

<br />

<div align="center">
  <h1>NAEGIA-Obfuscator</h1>
  <p><strong>PE32+ (AMD64) metadata-level obfuscation — Rust</strong></p>
  <p>Rewrite header metadata, append noise entropy, fix checksums.<br />No .text modification. Deterministic. Loader-safe.</p>
</div>

<br />

---

## Install

```bash
# From source (requires Rust 1.82+)
cargo install --git https://github.com/your-org/NAEGIA-Obfuscator

# Or build from the workspace
git clone https://github.com/your-org/NAEGIA-Obfuscator.git
cd NAEGIA-Obfuscator
cargo build --workspace --release
# Binary at target/release/naegia.exe
```

## Usage

```bash
# Default obfuscation: DOS stub, section names, static fingerprint, entropy tail, checksum
naegia protect app.exe -o app_obfuscated.exe

# Same transforms, no file-size increase (Authenticode-friendly)
naegia protect app.exe -o app_obfuscated.exe --no-overlay

# Byte-exact copy (validation only, no obfuscation)
naegia protect app.exe -o app_copy.exe --identity

# Validate input only — output path is accepted but not created
naegia protect app.exe -o /dev/null --dry-run

# Strip debug directory, then run default obfuscation
naegia protect app.exe -o app_obfuscated.exe --strip-debug

# Strip debug pointer only, skip all obfuscation
naegia protect app.exe -o app_obfuscated.exe --identity --strip-debug
```

## Configuration

| Flag | What it does |
|------|-------------|
| `-o <path>` | Output file path (required) |
| `--identity` | Copy input verbatim or strip debug only — skip all obfuscation |
| `--dry-run` | Validate PE64 and exit (no output written) |
| `--strip-debug` | Zero the Debug data directory entry |
| `--no-overlay` | Skip entropy tail append (keeps file size unchanged) |
| `--decoy-metadata` | Use packer-style section names + preset COFF timestamps |
| `--patterned-overlay` | Entropy tail alternates random / ASCII / NOP-like blocks |
| `--nuclear-metadata` | Max cosmetic linker version + image version fields |
| `--xor-rdata-zero-runs` | XOR section-end padding in read-only initialized data |
| `--redirect-entry` | Entry point jumps through a code cave (jmp to original EP) |
| `--anti-debug-entry` | Spin if PEB.BeingDebugged (requires `--redirect-entry`) |

Aggressive flags (`--decoy-metadata`, `--nuclear-metadata`, `--redirect-entry`, `--anti-debug-entry`, `--xor-rdata-zero-runs`, `--patterned-overlay`) stack on the default path. Combine with `--no-overlay` when preserving file size or signatures matters.

## How It Works

1. **Parse and validate** — PE32+ AMD64 check via goblin
2. **Scrub DOS stub** (`--identity` skips this) — deterministic pattern between `MZ` and `e_lfanew`; `e_lfanew` and bytes before 0x40 stay intact
3. **Rename section headers** — 8-byte generated names; indirect names starting with `/` are left alone
4. **Static fingerprint pass** — XOR-mix COFF timestamp, linker/image version words, zero bound-import directory and COFF symbol table fields
5. **XOR .rdata section-end padding** (if `--xor-rdata-zero-runs`) — XOR the file-alignment gap between `VirtualSize` and `SizeOfRawData` only. Internal zero runs (CRT tables, directory gaps) are never touched — changing sentinel zeros can crash the CRT cleanup path
6. **Redirect entry** (if `--redirect-entry`) — find a code cave in an executable section, write `jmp rel32` to original EP; optionally prepend PEB.BeingDebugged test
7. **Append entropy overlay** (default, unless `--no-overlay`) — pseudorandom or patterned tail for whole-file entropy
8. **Recompute PE checksum** — word-sum over the image

The loader sees the same RVAs. `.text` and data sections keep their on-disk layout. For well-formed inputs that already ran, output behaves the same.

### What changes

| Field | How |
|-------|-----|
| DOS stub (0x40 to e_lfanew) | Overwritten with deterministic pattern |
| Section names | Replaced with 8-char generated names |
| COFF TimeDateStamp | XOR-mixed with content-derived seed |
| MajorLinkerVersion / MinorLinkerVersion | XOR-mixed |
| MajorImageVersion / MinorImageVersion | XOR-mixed (or maxed in nuclear mode) |
| Bound import directory | Zeroed (forces full IAT resolution) |
| COFF PointerToSymbolTable / NumberOfSymbols | Zeroed |
| .rdata section-end padding | XOR'd (on request) |
| Entry point | jmp rel32 through code cave (on request) |
| File end | Entropy tail appended (default) |

## Architecture

```
NAEGIA-Obfuscator/
├── Cargo.toml                  # workspace root (resolver v2)
├── rust-toolchain.toml         # stable toolchain pin
├── crates/
│   ├── naegia/                 # binary entry: clap CLI, dispatch
│   └── naegia-pe/              # PE parse, validate, all transforms
│       ├── anti_analysis/      # fingerprint hardening, entropy overlay
│       ├── config.rs           # ProtectConfig struct + validation
│       ├── layout.rs           # PE32+ layout constants
│       ├── obfuscate.rs        # FNV-1a seed, DOS stub, section name gen
│       ├── raw.rs              # Raw byte-offset arithmetic (e_lfanew, PE sig)
│       ├── strings_pad.rs      # XOR section-end padding in .rdata
│       ├── trampoline.rs       # Code cave search + entry jmp stub
│       ├── transform.rs        # protect_with_config pipeline
│       └── validate.rs         # goblin-based PE64 validation
├── fixtures/
│   └── hello-windows/          # tiny EXE for integration tests
└── .github/workflows/          # CI + release
```

~2,400 lines of Rust, zero `unsafe` blocks. Deterministic transforms: same input + same flags = identical output.

## Development

```bash
git clone https://github.com/your-org/NAEGIA-Obfuscator.git
cd NAEGIA-Obfuscator

# Check
cargo fmt --check
cargo clippy -D warnings

# Test (Windows required for integration tests)
cargo test --workspace

# Test with release binary
cargo test --workspace --release
```

Integration tests live in `crates/naegia/tests/`. They use `CARGO_BIN_EXE_naegia` to locate the binary built for the same profile. Windows-only (`x86_64-pc-windows-msvc`).

### Test suite breakdown

| Suite | Count | What |
|-------|-------|------|
| Unit (naegia-pe lib) | 8 | Config validation, entropy, obfuscate, raw offset, padding XOR |
| Fuzz (naegia-pe) | 19 | Panic-free parsing on adversarial inputs |
| Integration (naegia) | 16 | CLI correctness, all flag combinations, identity, dry-run, regression |

## CI/CD

Push a `v*` tag — GitHub Actions (`windows-latest`):
1. `cargo fmt --check`
2. `cargo clippy -D warnings`
3. `cargo test --workspace` (debug)
4. `cargo build --release`
5. `cargo test --workspace --release` (integration on release binary)
6. Attach `naegia.exe` to a GitHub Release

## Why Rust?

PE manipulation is high-risk systems programming. One wrong byte offset and the loader crashes, the binary is rejected, or (worst case) it appears to work but behaves differently. Rust's safety guarantees eliminate entire classes of bugs:
- **No buffer overflows** — all slice accesses are bounds-checked
- **No use-after-free** — the borrow checker catches lifetime violations
- **No unsafe** — `#![deny(unsafe_code)]` at the crate root
- **Deterministic** — no GC, no non-deterministic runtime behavior
- **Single static binary** — ~600 KB release build with no dependencies to ship

## License

MIT. See [LICENSE](LICENSE).
