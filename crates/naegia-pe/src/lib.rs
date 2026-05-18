//! PE32+ (AMD64) helpers for NAEGIA: validation and safe transforms.
//!
//! Layout assumptions follow the Microsoft PE specification:
//! <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format>
//!
//! This crate contains **zero `unsafe` blocks** — all memory manipulation is done
//! through safe slice methods and checked arithmetic.  The lint below prevents
//! accidental introduction of `unsafe` during maintenance.

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod anti_analysis;
mod checksum;
mod config;
mod debug_strip;
mod error;
mod imports;
mod inspect;
mod layout;
mod obfuscate;
mod pdb_scrub;
mod preset;
mod raw;
mod rva;
mod seed;
mod strings_pad;
mod trampoline;
mod transform;
mod validate;

pub use anti_analysis::DEFAULT_ENTROPY_OVERLAY_LEN;
pub use config::{ProtectConfig, MAX_OVERLAY_LEN};
pub use error::{NaegiaPeError, Result};
pub use imports::import_dll_names;
pub use inspect::PeInspectReport;
pub use preset::Preset;
pub use raw::debug_data_directory_entry;
pub use transform::{
    protect_identity, protect_obfuscate_metadata, protect_strip_debug_and_checksum,
    protect_with_config, strip_debug_data_directory, verify_written_image,
};
pub use validate::parse_and_validate_pe64;
