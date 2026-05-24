#![deny(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use clap::{Parser, Subcommand, ValueEnum};
use naegia_pe::{
    NaegiaPeError, PeInspectReport, Preset, ProtectConfig, DEFAULT_ENTROPY_OVERLAY_LEN,
    MAX_INPUT_BYTES, MAX_OVERLAY_LEN,
};
use thiserror::Error;

/// Exit code: success.
pub const EXIT_OK: i32 = 0;
/// Exit code: I/O failure.
pub const EXIT_IO: i32 = 1;
/// Exit code: invalid PE or transform failure.
pub const EXIT_INVALID_PE: i32 = 2;
/// Exit code: invalid CLI / config combination.
pub const EXIT_CONFIG: i32 = 3;
/// Exit code: post-write verification failed.
pub const EXIT_VERIFY: i32 = 4;

#[derive(Parser)]
#[command(
    name = "naegia",
    version,
    about = "NAEGIA Windows PE metadata protection CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum CliPreset {
    Lab,
    Release,
    Signed,
    Aggressive,
}

impl From<CliPreset> for Preset {
    fn from(p: CliPreset) -> Self {
        match p {
            CliPreset::Lab => Preset::Lab,
            CliPreset::Release => Preset::Release,
            CliPreset::Signed => Preset::Signed,
            CliPreset::Aggressive => Preset::Aggressive,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Validate and write a protected PE image.
    Protect {
        input: PathBuf,
        #[arg(short = 'o', long)]
        output: PathBuf,
        #[arg(long, value_enum)]
        preset: Option<CliPreset>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        strip_debug: bool,
        #[arg(long)]
        identity: bool,
        #[arg(long)]
        no_overlay: bool,
        #[arg(long, value_name = "BYTES")]
        overlay_len: Option<usize>,
        #[arg(long)]
        decoy_metadata: bool,
        #[arg(long)]
        nuclear_metadata: bool,
        #[arg(long)]
        patterned_overlay: bool,
        #[arg(long)]
        redirect_entry: bool,
        #[arg(long)]
        anti_debug_entry: bool,
        #[arg(long)]
        xor_rdata_zero_runs: bool,
        #[arg(long)]
        random_seed: bool,
        #[arg(long, value_name = "U64")]
        seed: Option<u64>,
        #[arg(long)]
        scrub_pdb: bool,
        #[arg(long, default_value_t = true)]
        verify: bool,
    },
    /// Print PE layout summary (no writes).
    Inspect { input: PathBuf },
}

#[derive(Debug, Error)]
enum RunError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Pe(#[from] NaegiaPeError),
    #[error("{0}")]
    Config(&'static str),
    #[error("post-write verification failed")]
    Verify,
}

impl RunError {
    fn exit_code(&self) -> i32 {
        match self {
            RunError::Io(_) => EXIT_IO,
            RunError::Pe(_) => EXIT_INVALID_PE,
            RunError::Config(_) => EXIT_CONFIG,
            RunError::Verify => EXIT_VERIFY,
        }
    }
}

enum ProtectMode {
    DryRun,
    Identity { strip_debug: bool, scrub_pdb: bool },
    Obfuscate(ProtectConfig),
}

fn main() -> process::ExitCode {
    match run() {
        Ok(()) => process::ExitCode::from(EXIT_OK as u8),
        Err(e) => {
            eprintln!("naegia: {e}");
            process::ExitCode::from(e.exit_code() as u8)
        }
    }
}

fn run() -> Result<(), RunError> {
    let cli = Cli::parse();
    match cli.command {
        Command::Inspect { input } => {
            let bytes = read_input_capped(&input)?;
            let report = PeInspectReport::from_image(&bytes)?;
            print!("{}", report.to_text());
        }
        Command::Protect {
            input,
            output,
            preset,
            dry_run,
            strip_debug,
            identity,
            no_overlay,
            overlay_len,
            decoy_metadata,
            nuclear_metadata,
            patterned_overlay,
            redirect_entry,
            anti_debug_entry,
            xor_rdata_zero_runs,
            random_seed,
            seed,
            scrub_pdb,
            verify,
        } => {
            let cfg = build_protect_config(
                preset.map(Preset::from),
                strip_debug,
                no_overlay,
                overlay_len,
                decoy_metadata,
                nuclear_metadata,
                patterned_overlay,
                redirect_entry,
                anti_debug_entry,
                xor_rdata_zero_runs,
                random_seed,
                seed,
                scrub_pdb,
            )?;
            cfg.validate()
                .map_err(|_| RunError::Config("invalid protect config"))?;
            run_protect(
                &input,
                &output,
                resolve_protect_mode(dry_run, identity, cfg),
                verify,
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_protect_config(
    preset: Option<Preset>,
    strip_debug: bool,
    no_overlay: bool,
    overlay_len: Option<usize>,
    decoy_metadata: bool,
    nuclear_metadata: bool,
    patterned_overlay: bool,
    redirect_entry: bool,
    anti_debug_entry: bool,
    xor_rdata_zero_runs: bool,
    random_seed: bool,
    fixed_seed: Option<u64>,
    scrub_pdb: bool,
) -> Result<ProtectConfig, RunError> {
    let mut cfg = if let Some(p) = preset {
        ProtectConfig::from_preset(p)
    } else {
        ProtectConfig {
            append_entropy_overlay: !no_overlay,
            overlay_len: overlay_len.unwrap_or(DEFAULT_ENTROPY_OVERLAY_LEN),
            strip_debug,
            ..ProtectConfig::lab()
        }
    };

    if preset.is_none() {
        cfg.strip_debug |= strip_debug;
    } else if strip_debug {
        cfg.strip_debug = true;
    }

    if no_overlay {
        cfg.append_entropy_overlay = false;
    }
    if let Some(len) = overlay_len {
        cfg.overlay_len = len;
        if len > 0 {
            cfg.append_entropy_overlay = true;
        }
    }
    if overlay_len.is_some() && overlay_len == Some(0) && !no_overlay {
        return Err(RunError::Config("overlay_len 0 requires --no-overlay"));
    }
    if cfg.overlay_len > MAX_OVERLAY_LEN {
        return Err(RunError::Config("overlay_len exceeds 16384"));
    }

    cfg.decoy_metadata |= decoy_metadata;
    cfg.nuclear_metadata |= nuclear_metadata;
    cfg.patterned_entropy_overlay |= patterned_overlay;
    cfg.redirect_entry |= redirect_entry;
    cfg.anti_debug_entry |= anti_debug_entry;
    cfg.xor_rdata_zero_runs |= xor_rdata_zero_runs;
    cfg.random_seed |= random_seed;
    cfg.scrub_pdb_paths |= scrub_pdb;
    if let Some(s) = fixed_seed {
        cfg.fixed_seed = Some(s);
        cfg.random_seed = true;
    }

    Ok(cfg)
}

fn resolve_protect_mode(dry_run: bool, identity: bool, config: ProtectConfig) -> ProtectMode {
    if dry_run {
        ProtectMode::DryRun
    } else if identity {
        ProtectMode::Identity {
            strip_debug: config.strip_debug,
            scrub_pdb: config.scrub_pdb_paths,
        }
    } else {
        ProtectMode::Obfuscate(config)
    }
}

fn read_input_capped(path: &Path) -> Result<Vec<u8>, RunError> {
    let meta = fs::metadata(path)?;
    if meta.len() > MAX_INPUT_BYTES as u64 {
        return Err(RunError::Pe(NaegiaPeError::InvalidPe(
            "image exceeds maximum size (256 MiB)",
        )));
    }
    fs::read(path).map_err(RunError::from)
}

fn path_is_symlink(path: &Path) -> Result<bool, RunError> {
    if !path.exists() {
        return Ok(false);
    }
    Ok(path
        .symlink_metadata()
        .map_err(RunError::from)?
        .file_type()
        .is_symlink())
}

fn run_protect(
    input: &Path,
    output: &Path,
    mode: ProtectMode,
    verify: bool,
) -> Result<(), RunError> {
    let bytes = read_input_capped(input)?;
    match mode {
        ProtectMode::DryRun => {
            naegia_pe::parse_and_validate_pe64(&bytes)?;
        }
        ProtectMode::Identity {
            strip_debug,
            scrub_pdb,
        } => {
            let out = if strip_debug || scrub_pdb {
                let mut cfg = ProtectConfig::signed();
                cfg.strip_debug = strip_debug;
                cfg.scrub_pdb_paths = scrub_pdb;
                cfg.obfuscate_metadata = false;
                naegia_pe::protect_with_config(&bytes, &cfg)?
            } else {
                naegia_pe::protect_identity(&bytes)?
            };
            write_output(output, &out, verify)?;
        }
        ProtectMode::Obfuscate(cfg) => {
            let out = naegia_pe::protect_with_config(&bytes, &cfg)?;
            write_output(output, &out, verify)?;
        }
    }
    Ok(())
}

fn write_output(path: &Path, data: &[u8], verify: bool) -> Result<(), RunError> {
    if path_is_symlink(path)? {
        return Err(RunError::Config("output path must not be a symlink"));
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if path_is_symlink(parent)? {
        return Err(RunError::Config(
            "output parent directory must not be a symlink",
        ));
    }
    fs::create_dir_all(parent)?;
    let staging_path = parent.join(format!(
        ".naegia-{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("out")
    ));
    fs::write(&staging_path, data)?;
    if let Err(e) = fs::rename(&staging_path, path) {
        let _ = fs::remove_file(&staging_path);
        return Err(e.into());
    }
    if verify {
        naegia_pe::verify_written_image(path).map_err(|_| RunError::Verify)?;
    }
    Ok(())
}
