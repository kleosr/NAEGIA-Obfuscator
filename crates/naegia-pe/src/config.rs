//! Aggressive protection layers (opt-in). Defaults keep the original metadata-only path.

use crate::error::{NaegiaPeError, Result};

/// All optional transforms. Fields use `Default` (all `false`) for the conservative path.
/// Construct with [`metadata_only`](Self::metadata_only) or `..Default::default()`.
#[derive(Debug, Clone, Default)]
pub struct ProtectConfig {
    /// Zero the `IMAGE_DIRECTORY_ENTRY_DEBUG` data directory entry.
    pub strip_debug: bool,
    /// Append a pseudorandom tail after the PE image to raise file entropy.
    pub append_entropy_overlay: bool,
    /// Alternating high/low entropy blocks in the tail (vs uniform PRNG).
    pub patterned_entropy_overlay: bool,
    /// Packer-style section names + decoy COFF timestamp presets.
    pub decoy_metadata: bool,
    /// Extra-hard linker / image version values (still loader-ignored).
    pub nuclear_metadata: bool,
    /// Redirect `AddressOfEntryPoint` through a code cave ending in `jmp` to the original EP.
    pub redirect_entry: bool,
    /// When `redirect_entry` is set, prepend a short `BeingDebugged` check (infinite spin if set).
    pub anti_debug_entry: bool,
    /// XOR long runs of zero padding inside `.rdata` disk image (does not touch non-zero bytes).
    pub xor_rdata_zero_runs: bool,
}

impl ProtectConfig {
    /// Shorthand for the conservative path: optional debug-strip + entropy tail,
    /// no decoy/nuclear/redirect layers.
    pub fn metadata_only(strip_debug: bool, append_entropy_overlay: bool) -> Self {
        Self {
            strip_debug,
            append_entropy_overlay,
            ..Default::default()
        }
    }

    /// Reject logically contradictory flag combinations
    /// (e.g. `anti_debug_entry` without `redirect_entry`).
    pub fn validate(&self) -> Result<()> {
        if self.anti_debug_entry && !self.redirect_entry {
            return Err(NaegiaPeError::InvalidPe(
                "anti_debug_entry requires redirect_entry",
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
}
