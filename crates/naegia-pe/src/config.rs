//! Aggressive protection layers (opt-in). Defaults keep the original metadata-only path.

use crate::anti_analysis::DEFAULT_ENTROPY_OVERLAY_LEN;
use crate::error::{NaegiaPeError, Result};

/// Maximum entropy tail size (16 KiB).
pub const MAX_OVERLAY_LEN: usize = 16 * 1024;

/// Maximum PE image size accepted for parse/protect (256 MiB).
pub const MAX_INPUT_BYTES: usize = 256 * 1024 * 1024;

/// All optional transforms. Fields use `Default` (all `false`) for the conservative path.
/// Construct with [`metadata_only`](Self::metadata_only), [`lab`](crate::preset::ProtectConfig::lab),
/// or [`from_preset`](crate::preset::ProtectConfig::from_preset).
#[derive(Debug, Clone)]
pub struct ProtectConfig {
    /// Zero debug directory and wipe debug payloads (see `debug_strip`).
    pub strip_debug: bool,
    /// Append a pseudorandom tail after the PE image to raise file entropy.
    pub append_entropy_overlay: bool,
    /// Byte length of entropy tail when `append_entropy_overlay` is true.
    pub overlay_len: usize,
    /// Alternating high/low entropy blocks in the tail (vs uniform PRNG).
    pub patterned_entropy_overlay: bool,
    /// Neutral high-entropy section names + seed-derived COFF timestamp.
    pub decoy_metadata: bool,
    /// Extra-hard linker / image version values (still loader-ignored).
    pub nuclear_metadata: bool,
    /// Redirect `AddressOfEntryPoint` through padding caves to the original EP.
    pub redirect_entry: bool,
    /// When `redirect_entry` is set, spin if `PEB.BeingDebugged` is set.
    pub anti_debug_entry: bool,
    /// XOR section-end padding in read-only initialized data sections.
    pub xor_rdata_zero_runs: bool,
    /// Mix OS CSPRNG into protect seed and COFF timestamp.
    pub random_seed: bool,
    /// When set, used instead of OS randomness for `random_seed` (reproducible CI builds).
    pub fixed_seed: Option<u64>,
    /// Zero PDB / CodeView path strings in read-only data sections.
    pub scrub_pdb_paths: bool,
    /// DOS stub, section names, and static fingerprint passes.
    pub obfuscate_metadata: bool,
}

impl Default for ProtectConfig {
    fn default() -> Self {
        Self {
            strip_debug: false,
            append_entropy_overlay: false,
            overlay_len: DEFAULT_ENTROPY_OVERLAY_LEN,
            patterned_entropy_overlay: false,
            decoy_metadata: false,
            nuclear_metadata: false,
            redirect_entry: false,
            anti_debug_entry: false,
            xor_rdata_zero_runs: false,
            random_seed: false,
            fixed_seed: None,
            scrub_pdb_paths: false,
            obfuscate_metadata: true,
        }
    }
}

impl ProtectConfig {
    /// Shorthand for the conservative path: optional debug-strip + entropy tail.
    pub fn metadata_only(strip_debug: bool, append_entropy_overlay: bool) -> Self {
        Self {
            strip_debug,
            append_entropy_overlay,
            overlay_len: DEFAULT_ENTROPY_OVERLAY_LEN,
            ..Default::default()
        }
    }

    /// Reject contradictory flag combinations and invalid numeric bounds.
    pub fn validate(&self) -> Result<()> {
        if self.anti_debug_entry && !self.redirect_entry {
            return Err(NaegiaPeError::InvalidPe(
                "anti_debug_entry requires redirect_entry",
            ));
        }
        if self.append_entropy_overlay && self.overlay_len == 0 {
            return Err(NaegiaPeError::InvalidPe(
                "overlay_len must be > 0 when append_entropy_overlay is set",
            ));
        }
        if self.overlay_len > MAX_OVERLAY_LEN {
            return Err(NaegiaPeError::InvalidPe(
                "overlay_len exceeds maximum (16384 bytes)",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_anti_debug_without_redirect() {
        let c = ProtectConfig {
            anti_debug_entry: true,
            redirect_entry: false,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_accepts_default() {
        assert!(ProtectConfig::default().validate().is_ok());
    }

    #[test]
    fn validate_rejects_zero_overlay_with_append() {
        let c = ProtectConfig {
            append_entropy_overlay: true,
            overlay_len: 0,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }
}
