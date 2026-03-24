use std::fs;
use std::path::PathBuf;

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
        /// Not implemented yet (import directory rebuild + resolver stub).
        #[arg(long)]
        scramble_imports: bool,
        /// Not implemented (needs LLVM / IR).
        #[arg(long)]
        flatten_cfg: bool,
        /// Not implemented (synthetic import descriptors).
        #[arg(long, default_value_t = 0)]
        junk_imports: u32,
        /// Not implemented (requires .text rewriting).
        #[arg(long)]
        opaque_predicates: bool,
    },
}

#[derive(Debug, Error)]
enum RunError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Pe(#[from] NaegiaPeError),
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
            scramble_imports,
            flatten_cfg,
            junk_imports,
            opaque_predicates,
        } => {
            let bytes = fs::read(&input)?;
            if dry_run {
                naegia_pe::parse_and_validate_pe64(&bytes)?;
                return Ok(());
            }
            let out = if identity {
                if strip_debug {
                    naegia_pe::protect_strip_debug_and_checksum(&bytes)?
                } else {
                    naegia_pe::protect_identity(&bytes)?
                }
            } else {
                let cfg = ProtectConfig {
                    strip_debug,
                    append_entropy_overlay: !no_overlay,
                    patterned_entropy_overlay: patterned_overlay,
                    decoy_metadata,
                    nuclear_metadata,
                    redirect_entry,
                    anti_debug_entry,
                    xor_rdata_zero_runs,
                    scramble_imports,
                    flatten_cfg,
                    junk_imports,
                    opaque_predicates,
                };
                naegia_pe::protect_with_config(&bytes, &cfg)?
            };
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&output, out)?;
        }
    }
    Ok(())
}
