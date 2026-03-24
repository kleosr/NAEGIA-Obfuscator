//! Aggressive protection layers (opt-in). Defaults keep the original metadata-only path.

use crate::error::{NaegiaPeError, Result};

/// All optional “v2” transforms. Anything that cannot be done safely in-process returns
/// [`NaegiaPeError::Unsupported`].
#[derive(Debug, Clone, Default)]
pub struct ProtectConfig {
    pub strip_debug: bool,
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
    /// Placeholder: needs PE import rebuild + x64 resolver stub (not shipped yet).
    pub scramble_imports: bool,
    /// Placeholder: needs LLVM / IR pipeline.
    pub flatten_cfg: bool,
    /// Placeholder: needs synthetic import descriptors.
    pub junk_imports: u32,
    /// Placeholder: needs basic-block instrumentation.
    pub opaque_predicates: bool,
}

impl ProtectConfig {
    pub fn metadata_only(strip_debug: bool, append_entropy_overlay: bool) -> Self {
        Self {
            strip_debug,
            append_entropy_overlay,
            ..Default::default()
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.scramble_imports {
            return Err(NaegiaPeError::Unsupported(
                "import hashing + IAT rebuild + in-process resolver is not implemented yet (see iat_hash module / roadmap)",
            ));
        }
        if self.flatten_cfg {
            return Err(NaegiaPeError::Unsupported(
                "CFG flattening needs an IR-level pipeline (e.g. LLVM), not PE-only edits",
            ));
        }
        if self.junk_imports > 0 {
            return Err(NaegiaPeError::Unsupported(
                "synthetic junk imports require a new import directory layout (not implemented)",
            ));
        }
        if self.opaque_predicates {
            return Err(NaegiaPeError::Unsupported(
                "opaque predicates require rewriting .text (not implemented)",
            ));
        }
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

    #[test]
    fn validate_rejects_scramble() {
        let c = ProtectConfig {
            scramble_imports: true,
            ..Default::default()
        };
        assert!(matches!(c.validate(), Err(NaegiaPeError::Unsupported(_))));
    }
}
