# Security

## Threat model

NAEGIA is a **local CLI** that reads PE32+ (AMD64) files and writes modified PEs. There is no network service, authentication, or multi-tenant boundary. Risks are:

- **Malicious PE input** — parser/resource exhaustion, unexpected transforms.
- **Path handling** — symlinked `-o` paths or parent directories redirecting writes.
- **Operator misuse** — breaking Authenticode, enabling anti-debug on production builds.

The tool is **dual-use** (defensive hardening vs. evasion). Use only on software you are authorized to modify.

## Limits

| Limit | Value |
|-------|--------|
| Max input file size | 256 MiB (`MAX_INPUT_BYTES`) |
| Max entropy overlay | 16 KiB (`MAX_OVERLAY_LEN`) |
| Max sections parsed for renames | 100 |

Oversize inputs are rejected before parsing. The CLI also checks `metadata.len()` before reading.

## Safe usage

1. Run **`naegia inspect`** first; if `authenticode: likely`, use `--no-overlay` or `--preset signed`.
2. Do not point **`-o`** at symlinks or directories you do not trust (writes are blocked when the output path or its parent is a symlink).
3. Prefer **`--preset release`** or **`signed`** for shipping binaries; reserve **`aggressive`** / **`--redirect-entry`** for lab builds.
4. Treat output EXEs as **modified binaries** — scan and test before distribution.

## Reporting vulnerabilities

Open a **private** security advisory on GitHub (or email the maintainer listed in the repository) with:

- Steps to reproduce
- Impact (confidentiality / integrity / availability)
- Affected version / commit

Please do not file public issues for exploitable memory-safety or path-traversal bugs until coordinated disclosure is complete.

## Hardening in code

- `#![deny(unsafe_code)]` in `naegia` and `naegia-pe`
- Checked arithmetic on PE layout; proptest fuzz tests on parse paths
- Atomic write via temp file + `rename`; post-write `--verify` (default)
- Entropy overlay refused when the certificate directory is present
