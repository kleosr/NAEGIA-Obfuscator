# CRATE: naegia - CLI binary

**See parent AGENTS.md for workspace-wide conventions, anti-patterns, and project overview.**

## OVERVIEW

Binary entry point. clap-derive CLI parses args, `resolve_protect_mode()` picks `DryRun` / `Identity { strip_debug }` / `Obfuscate(ProtectConfig)`, then `run_protect()` dispatches to `naegia-pe`. Windows-only integration tests use `CARGO_BIN_EXE_naegia`.

## WHERE TO LOOK

| Task | File | Notes |
|------|------|-------|
| CLI struct, subcommands | `src/main.rs` | `Cli` derive, `Command::Protect` with all 11 flags |
| Mode resolution | `src/main.rs:138` | `resolve_protect_mode()` priority: dry_run, identity, obfuscate |
| Dispatch logic | `src/main.rs:150` | `run_protect()`: read bytes, match mode, write output |
| Error types | `src/main.rs:71` | `RunError`: `Io(std::io::Error)` / `Pe(NaegiaPeError)` |
| Baseline tests | `tests/protect_windows.rs` | identity, default obfuscate, deterministic, strip-debug, no-overlay, dry-run |
| Aggressive + unsupported | `tests/protect_layers_windows.rs` | redirect-entry, anti-debug, decoy, nuclear, xor-rdata; reject unimplemented flags |
| Regression | `tests/protect_regression_windows.rs` | identity-wins, dry-run no output, invalid PE, double protect, full stack, no partial output |
| Test helpers | `tests/common/mod.rs` | `naegia()`, `fixture_exe()`, `assert_runs_hello()`, `workspace_target_dir()` |

## CONVENTIONS

- All test files gated with `#![cfg(windows)]` + `mod common;`.
- `common::naegia()` returns `std::process::Command` built from `env!("CARGO_BIN_EXE_naegia")` (Rust built-in for per-profile binary).
- `fixture_exe()` builds `fixtures/hello-windows` on first call (cached via `OnceLock`).
- Test output files land in `workspace_root()/target/{debug,release}/` (same profile as test binary).
- `ProtectMode` enum has 3 variants, never 4. No "identity + dry-run" hybrid.
- CLI flags mirror `ProtectConfig` fields directly (no extra parsing layer).

## ANTI-PATTERNS

- `--identity` with aggressive flags (`--redirect-entry`, `--decoy-metadata`, etc.) must produce a byte-identical copy, not a partial obfuscation. `resolve_protect_mode()` short-circuits before config is used.
- `--anti-debug-entry` without `--redirect-entry` must fail (enforced by `ProtectConfig::validate()`).
- `--dry-run` must never write the `-o` path, even if other flags are present.
- A failed run must not leave a partial output file on disk.
- Never add new `ProtectMode` variants without updating `resolve_protect_mode()` priority chain.
