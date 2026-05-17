# PROJECT KNOWLEDGE BASE

**Generated:** 2026-05-17
**Branch:** *(unknown)*
**Commit:** *(unknown)*

## OVERVIEW

PE32+ (AMD64) post-processor that rewrites header-level metadata, appends entropy noise, and fixes checksums. Rust workspace with a CLI binary (`naegia`) and a PE-manipulation library (`naegia-pe`).

## STRUCTURE

```
NAEGIA-Obfuscator/
├── crates/
│   ├── naegia/          # CLI binary (clap), dispatch
│   └── naegia-pe/       # PE parse, validate, transforms
├── fixtures/
│   └── hello-windows/   # tiny exe for integration tests
└── .github/workflows/   # CI + release
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| CLI args / entry point | `crates/naegia/src/main.rs` | `run_protect` dispatch |
| PE transforms | `crates/naegia-pe/src/transform.rs` | `protect_with_config` pipeline |
| Section/name obfuscation | `crates/naegia-pe/src/obfuscate.rs` | FNV-1a seed, DOS stub, section renames |
| Static fingerprint | `crates/naegia-pe/src/anti_analysis/fingerprint.rs` | COFF timestamp, linker versions, bound IAT |
| Entropy tail | `crates/naegia-pe/src/anti_analysis/entropy.rs` | `DEFAULT_ENTROPY_OVERLAY_LEN` |
| Code cave / entry redirect | `crates/naegia-pe/src/trampoline.rs` | `redirect_entry_plain`, `redirect_entry_with_anti_debug` |
| PE validation | `crates/naegia-pe/src/validate.rs` | goblin-based parse |
| Config / layers | `crates/naegia-pe/src/config.rs` | `ProtectConfig` defaults |
| Integration tests | `crates/naegia/tests/` | Windows-only, use `CARGO_BIN_EXE_naegia` |
| CI pipeline | `.github/workflows/ci.yml` | fmt + clippy + test (debug + release) |
| Release workflow | `.github/workflows/release.yml` | tag v* triggers |

## CONVENTIONS

- **Rust edition 2021**, stable toolchain (rust-toolchain.toml pins stable).
- Workspace resolver v2.
- `thiserror` for error types, `goblin` for PE parsing.
- `ProtectConfig::validate()` rejects unimplemented features at runtime with `NaegiaPeError::Unsupported`.
- Integration tests use `CARGO_BIN_EXE_naegia` env var to locate the binary built for the same profile.
- `anti_debug_entry` requires `redirect_entry` (enforced by config validator).

## ANTI-PATTERNS (THIS PROJECT)

- Unimplemented features (`--scramble-imports`, `--flatten-cfg`, `--junk-imports`, `--opaque-predicates`) return `Unsupported` error — do not add silent no-ops.
- Identity mode skips ALL obfuscation (stub, names, fingerprint, overlay) — do not accidentally apply transforms in identity path.
- Entropy overlay invalidates Authenticode — `--no-overlay` MUST be used for signed binaries.
- DOS stub scrubbing preserves `e_lfanew` — never overwrite bytes before 0x40.

## UNIQUE STYLES

- FNV-1a hash over first 4096 bytes + file length used as deterministic seed for transforms.
- Section names use alphanumeric charset with leading `.` — indirect names starting with `/` are skipped.
- Decoy section names cycle through UPX/ VMP/ themida/ ASPack presets.

## COMMANDS

```bash
cargo build --workspace --release
cargo test --workspace
cargo clippy -D warnings
cargo fmt --check
naegia protect <input> -o <output>
```

## NOTES

- Windows-only (`x86_64-pc-windows-msvc`). PE32+ (64-bit) only.
- `.text` section content is never modified — this is metadata-level obfuscation only.
- Any legitimate PE64 should pass validation; odd linkers may fail.
