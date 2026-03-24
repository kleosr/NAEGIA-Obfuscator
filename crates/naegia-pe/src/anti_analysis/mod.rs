//! Static fingerprint noise: timestamps, optional-header cosmetic fields, data-directory
//! cleanup, file tail. This raises the cost of quick static triage (YARA, “what linker”, bound
//! IAT hints). It is not a substitute for code-level hardening: packing, import encryption, and
//! control-flow obfuscation live in another league.
//!
//! Nothing here changes section bodies, the import table, or the entry RVA.

mod entropy;
mod fingerprint;

pub use entropy::{
    push_entropy_overlay, push_patterned_entropy_overlay, DEFAULT_ENTROPY_OVERLAY_LEN,
};
pub use fingerprint::{
    apply_decoy_coff_timestamp, apply_nuclear_optional_versions,
    apply_static_fingerprint_hardening, clear_bound_import_directory_entry,
    obfuscate_coff_timestamp, obfuscate_optional_image_versions,
    obfuscate_optional_linker_versions, zero_coff_linked_symbol_table_fields,
};
