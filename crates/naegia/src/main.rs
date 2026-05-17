// The CLI binary delegates all unsafe-eligible work (PE parsing, byte manipulation)
// to `naegia-pe`, which carries `#![deny(unsafe_code)]`.  This crate itself should
// never introduce `unsafe` either.
#![deny(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use naegia_pe::{NaegiaPeError, ProtectConfig};
use thiserror::Error;

#[derive(Parser)]
#[command(name = "naegia", version, about = "NAEGIA Windows PE protection CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate and write a protected PE image.
    Protect {
        /// Input PE/EXE path
        input: PathBuf,
        /// Output path
        #[arg(short = 'o', long)]
        output: PathBuf,
        /// Only validate the input PE (no output file written)
        #[arg(long)]
        dry_run: bool,
        /// Clear the Debug data directory and refresh the PE checksum
        #[arg(long)]
        strip_debug: bool,
        /// Byte-identical copy (no metadata obfuscation). May combine with `--strip-debug` for
        /// debug-directory removal only.
        #[arg(long)]
        identity: bool,
        /// Skip the entropy tail appended after the PE image (use when you rely on Authenticode
        /// or need a stable on-disk size).
        #[arg(long)]
        no_overlay: bool,
        /// Packer-style section names + decoy COFF timestamps.
        #[arg(long)]
        decoy_metadata: bool,
        /// Max linker / image version fields (cosmetic).
        #[arg(long)]
        nuclear_metadata: bool,
        /// Alternate high/low/NOP blocks in the entropy tail.
        #[arg(long)]
        patterned_overlay: bool,
        /// Jump through a code cave before the original entry point.
        #[arg(long)]
        redirect_entry: bool,
        /// With `--redirect-entry`, spin if `PEB.BeingDebugged` is set.
        #[arg(long)]
        anti_debug_entry: bool,
        /// XOR long runs of 0x00 padding inside `.rdata` on disk.
        #[arg(long)]
        xor_rdata_zero_runs: bool,
    },
}

#[derive(Debug, Error)]
enum RunError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Pe(#[from] NaegiaPeError),
}

enum ProtectMode {
    DryRun,
    Identity { strip_debug: bool },
    Obfuscate(ProtectConfig),
}

fn main() -> std::process::ExitCode {
    if let Err(e) = run() {
        eprintln!("naegia: {e}");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

fn run() -> Result<(), RunError> {
    let cli = Cli::parse();
    match cli.command {
        Command::Protect {
            input,
            output,
            dry_run,
            strip_debug,
            identity,
            no_overlay,
            decoy_metadata,
            nuclear_metadata,
            patterned_overlay,
            redirect_entry,
            anti_debug_entry,
            xor_rdata_zero_runs,
        } => {
            let cfg = ProtectConfig {
                strip_debug,
                append_entropy_overlay: !no_overlay,
                patterned_entropy_overlay: patterned_overlay,
                decoy_metadata,
                nuclear_metadata,
                redirect_entry,
                anti_debug_entry,
                xor_rdata_zero_runs,
            };
            run_protect(
                &input,
                &output,
                resolve_protect_mode(dry_run, identity, cfg),
            )?;
        }
    }
    Ok(())
}

fn resolve_protect_mode(dry_run: bool, identity: bool, config: ProtectConfig) -> ProtectMode {
    if dry_run {
        ProtectMode::DryRun
    } else if identity {
        ProtectMode::Identity {
            strip_debug: config.strip_debug,
        }
    } else {
        ProtectMode::Obfuscate(config)
    }
}

fn run_protect(input: &Path, output: &Path, mode: ProtectMode) -> Result<(), RunError> {
    let bytes = fs::read(input)?;
    match mode {
        ProtectMode::DryRun => {
            naegia_pe::parse_and_validate_pe64(&bytes)?;
        }
        ProtectMode::Identity { strip_debug } => {
            let out = if strip_debug {
                naegia_pe::protect_strip_debug_and_checksum(&bytes)?
            } else {
                naegia_pe::protect_identity(&bytes)?
            };
            write_output(output, &out)?;
        }
        ProtectMode::Obfuscate(cfg) => {
            let out = naegia_pe::protect_with_config(&bytes, &cfg)?;
            write_output(output, &out)?;
        }
    }
    Ok(())
}

fn write_output(path: &Path, data: &[u8]) -> Result<(), RunError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, data)?;
    Ok(())
}
