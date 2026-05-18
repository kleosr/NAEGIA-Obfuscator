//! Named protection profiles for common release / lab / signed workflows.

use crate::anti_analysis::DEFAULT_ENTROPY_OVERLAY_LEN;
use crate::config::ProtectConfig;

/// Built-in flag bundles. Use explicit CLI flags to add layers on top (OR-on).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    /// Default metadata obfuscation + entropy tail (reproducible).
    Lab,
    /// Shipping build: strip debug, scrub PDB strings, no overlay, random seed.
    Release,
    /// Minimal change for Authenticode: debug wipe + PDB scrub only, no metadata noise.
    Signed,
    /// Maximum metadata friction (still loader-safe).
    Aggressive,
}

impl Preset {
    /// All preset variants for CLI enumeration.
    pub const ALL: &[Preset] = &[
        Preset::Lab,
        Preset::Release,
        Preset::Signed,
        Preset::Aggressive,
    ];
}

impl ProtectConfig {
    /// Conservative metadata + overlay (deterministic).
    pub fn lab() -> Self {
        Self {
            append_entropy_overlay: true,
            overlay_len: DEFAULT_ENTROPY_OVERLAY_LEN,
            obfuscate_metadata: true,
            ..Default::default()
        }
    }

    /// Recommended for release binaries (pair with `strip = true` at compile time).
    pub fn release() -> Self {
        Self {
            strip_debug: true,
            scrub_pdb_paths: true,
            append_entropy_overlay: false,
            random_seed: true,
            overlay_len: 0,
            obfuscate_metadata: true,
            ..Default::default()
        }
    }

    /// Authenticode-friendly hygiene only (no section/fingerprint obfuscation).
    pub fn signed() -> Self {
        Self {
            strip_debug: true,
            scrub_pdb_paths: true,
            append_entropy_overlay: false,
            overlay_len: 0,
            obfuscate_metadata: false,
            ..Default::default()
        }
    }

    /// Strongest metadata path (no .text encryption).
    pub fn aggressive() -> Self {
        Self {
            strip_debug: true,
            scrub_pdb_paths: true,
            decoy_metadata: true,
            redirect_entry: true,
            xor_rdata_zero_runs: true,
            append_entropy_overlay: true,
            random_seed: true,
            overlay_len: DEFAULT_ENTROPY_OVERLAY_LEN,
            obfuscate_metadata: true,
            ..Default::default()
        }
    }

    /// Map a [`Preset`] to a [`ProtectConfig`].
    pub fn from_preset(preset: Preset) -> Self {
        match preset {
            Preset::Lab => Self::lab(),
            Preset::Release => Self::release(),
            Preset::Signed => Self::signed(),
            Preset::Aggressive => Self::aggressive(),
        }
    }
}
