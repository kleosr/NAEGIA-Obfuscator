# NAEGIA-PE — CRATE KNOWLEDGE BASE

## OVERVIEW

PE32+ (AMD64) validation and transforms library. ~14 source files, most project complexity lives here.

## WHERE TO LOOK

| File | What | Notes |
|------|------|-------|
| `transform.rs` | `protect_with_config` pipeline, `protect_identity`, `strip_debug_data_directory` | Orchestrates all transforms in order |
| `obfuscate.rs` | FNV-1a seed calc, DOS stub scrub, section name gen | `obfuscation_seed()` over first 4096B + file len |
| `config.rs` | `ProtectConfig` struct + `validate()` | All layer flags; rejects unsupported at runtime |
| `validate.rs` | `parse_and_validate_pe64` | goblin-based parse, checks AMD64 + PE32+ magic + alignment |
| `checksum.rs` | `write_pe_checksum`, `compute_pe_checksum` | Word-sum over image, skipping checksum field |
| `error.rs` | `NaegiaPeError` enum | 4 variants: InvalidPe, Parse, Io, Unsupported |
| `layout.rs` | PE32+ constants | Magic (0x20B), directory entry indices, field offsets |
| `raw.rs` | `pe_optional_header_raw_offset`, `debug_data_directory_entry` | Byte arithmetic: DOS e_lfanew to PE offset |
| `iat_hash.rs` | `hash_name_ror13_upper` | ROR13 uppercase hash; wired API-only, no consumer |
| `imports.rs` | `import_dll_names` | Sorted unique DLL names from goblin parse |
| `strings_pad.rs` | `xor_zero_runs_in_rdata` | XORs zero-padding runs in .rdata on disk |
| `trampoline.rs` | `redirect_entry_plain`, `redirect_entry_with_anti_debug` | Code cave search (0x00/0xCC), writes jmp rel32 stub |
| `anti_analysis/fingerprint.rs` | COFF timestamp, linker/img versions, bound IAT, symbol table | Static hardening pass + decoy/nuclear modes |
| `anti_analysis/entropy.rs` | `push_entropy_overlay`, `push_patterned_entropy_overlay` | `DEFAULT_ENTROPY_OVERLAY_LEN` = 1536 |
| `anti_analysis/mod.rs` | Re-exports all public anti_analysis functions | |

## CONVENTIONS

- **goblin** for PE parse + section table; raw byte offsets for writes (goblin is read-only)
- **`thiserror`** for `NaegiaPeError`; `#[from]` on goblin/io errors
- Deterministic transforms: same input = same output (FNV-1a seed)
- No .text section content modification — metadata + padding only
- DOS stub preserves `e_lfanew` (0x3C); never writes before offset 0x40
- Section names starting with `/` (string-table indirect) skipped
- All transforms in `protect_with_config` gated behind a `ProtectConfig` flag

## ANTI-PATTERNS

- `--scramble-imports`, `--flatten-cfg`, `--junk-imports`, `--opaque-predicates` return `Unsupported` — do not add silent no-ops
- Identity path (`protect_identity`) must skip ALL obfuscation (stub, names, fingerprint, overlay)
- Entropy overlay invalidates Authenticode — `append_entropy_overlay: false` for signed binaries
- Adding a transform to `protect_with_config` requires a new flag in `ProtectConfig`; never run unconditional
