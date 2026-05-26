<div align="center">
  <img src="https://img.shields.io/badge/rust-1.82+-orange?logo=rust&style=flat-square" />
  <img src="https://img.shields.io/badge/target-x86_64--windows--msvc-blue?style=flat-square" />
  <img src="https://img.shields.io/github/v/tag/kleosr/NAEGIA-Obfuscator?style=flat-square" />
  <img src="https://img.shields.io/badge/license-MIT-brightgreen?style=flat-square" />
</div>

<br />

<div align="center">
  <h1>NAEGIA-Obfuscator</h1>
  <p><strong>PE32+ (AMD64) metadata-level obfuscation — Rust</strong></p>
  <p>Rewrite header metadata, append noise entropy, fix checksums.<br />Entry stubs use padding caves only. Deterministic by default. Loader-safe.</p>
</div>

<br />

---

## Install

```bash
# From source (requires Rust 1.82+)
cargo install --git https://github.com/kleosr/NAEGIA-Obfuscator

# Or build from the workspace
git clone https://github.com/kleosr/NAEGIA-Obfuscator.git
cd NAEGIA-Obfuscator
cargo build --workspace --release
# Binary at target/release/naegia.exe
```

## Usage

```bash
# Inspect before you protect (sections, imports, debug, Authenticode hint)
naegia inspect app.exe

# Recommended shipping path (strip debug, scrub PDB strings, metadata obfuscation, no overlay)
naegia protect app.exe -o app_out.exe --preset release

# Lab / scanner noise (deterministic metadata + 1536-byte entropy tail)
naegia protect app.exe -o app_out.exe --preset lab

# Signed-binary hygiene only (debug + PDB scrub, no section rename / fingerprint)
naegia protect app.exe -o app_out.exe --preset signed

# Maximum metadata layers (still no .text encryption)
naegia protect app.exe -o app_out.exe --preset aggressive --no-overlay

# Manual path (same as legacy default: lab + optional flags)
naegia protect app.exe -o app_obfuscated.exe

# Reproducible “random” builds in CI
naegia protect app.exe -o app_out.exe --preset release --seed 0xDEADBEEFCAFEBABE

# Custom overlay size (bytes, max 16384)
naegia protect app.exe -o app_out.exe --overlay-len 4096
```

**Limits:** input files must be ≤ 256 MiB. Overlay append is refused when Authenticode is detected (`naegia inspect` shows `authenticode: likely`). See [SECURITY.md](SECURITY.md).

### Presets

| Preset | Behavior |
|--------|----------|
| `lab` | Metadata obfuscation + entropy overlay (deterministic) |
| `release` | Strip debug, scrub PDB paths, metadata obfuscation, random seed, **no overlay** |
| `signed` | Strip debug + PDB scrub only (Authenticode-safe metadata) |
| `aggressive` | Release-like + decoy names, entry redirect, `.rdata` padding XOR, overlay |

Extra flags **OR-on** atop a preset (e.g. `--preset release --redirect-entry`).

## Configuration

| Flag | What it does |
|------|-------------|
| `-o <path>` | Output file path (required) |
| `--preset <lab\|release\|signed\|aggressive>` | Built-in flag bundle |
| `--identity` | Byte-identical copy (optional debug/PDB scrub via `--strip-debug` / `--scrub-pdb`) |
| `--dry-run` | Validate PE64 and exit (no output written) |
| `--strip-debug` | Clear debug directory and wipe debug payloads |
| `--scrub-pdb` | Zero PDB/CodeView path strings in read-only data |
| `--no-overlay` | Skip entropy tail |
| `--overlay-len <n>` | Entropy tail size in bytes (default 1536, max 16384) |
| `--random-seed` | OS randomness for seed + COFF timestamp |
| `--seed <u64>` | Fixed seed (implies `--random-seed`, reproducible) |
| `--verify` / `--no-verify` | Re-validate output on disk after write (default: verify on) |
| `--decoy-metadata` | Neutral section names + seed-derived timestamp |
| `--patterned-overlay` | Alternating random / high-byte / NOP overlay blocks |
| `--nuclear-metadata` | Max cosmetic linker/image version fields |
| `--xor-rdata-zero-runs` | XOR section-end padding in read-only data |
| `--redirect-entry` | Two-hop entry through padding caves when possible |
| `--anti-debug-entry` | PEB.BeingDebugged spin (requires `--redirect-entry`) |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | I/O error |
| 2 | Invalid PE / transform error |
| 3 | Invalid CLI / config |
| 4 | Post-write verification failed |

## How It Works

1. **Parse and validate** — PE32+ AMD64 check via goblin
2. **Scrub DOS stub** (`--identity` skips this) — deterministic pattern between `MZ` and `e_lfanew`; `e_lfanew` and bytes before 0x40 stay intact
3. **Rename section headers** — 8-byte generated names; COFF string-table names for `/offset` sections are scrubbed too
4. **Static fingerprint pass** — XOR-mix COFF timestamp, linker/image version words, zero bound-import directory and COFF symbol table fields
5. **XOR .rdata section-end padding** (if `--xor-rdata-zero-runs`) — XOR the file-alignment gap between `VirtualSize` and `SizeOfRawData` only. Internal zero runs (CRT tables, directory gaps) are never touched — changing sentinel zeros can crash the CRT cleanup path
6. **Redirect entry** (if `--redirect-entry`) — prefer two-hop `jmp rel32` chain through disjoint padding caves; optional PEB.BeingDebugged preamble
7. **Append entropy overlay** (default, unless `--no-overlay`) — pseudorandom or patterned tail for whole-file entropy
8. **Recompute PE checksum** — word-sum over the image

The loader sees the same RVAs. Compiled code is unchanged except optional jmp stubs written into **padding** (0x00 / 0xCC) inside executable sections. For well-formed inputs that already ran, output behaves the same.

**Scope:** NAEGIA hardens the **PE envelope** (headers, debug/PDB leakage, fingerprints, optional entry stub). It does **not** encrypt `.text` or implement source/MIR obfuscation. For IP in machine code, combine with `strip = true`, LTO, and a binary packer if you need more than metadata friction.

### Recommended release pipeline

```toml
# Cargo.toml
[profile.release]
strip = true
panic = "abort"
```

```bash
cargo build --release
naegia inspect target/release/app.exe
naegia protect target/release/app.exe -o dist/app.exe --preset release
```

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
| Entry point | Two-hop jmp chain through padding caves (on request) |
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
│       ├── obfuscate/          # FNV-1a seed, DOS stub, section name gen
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
git clone https://github.com/kleosr/NAEGIA-Obfuscator.git
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
| Unit (naegia-pe lib) | 13 | Config validation, entropy, obfuscate, raw offset, padding XOR |
| Fuzz (naegia-pe) | 20 | Panic-free parsing on adversarial inputs |
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
