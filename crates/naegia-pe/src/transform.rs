use goblin::pe::section_table::SectionTable;

use crate::anti_analysis::{
    apply_decoy_coff_timestamp, apply_nuclear_optional_versions,
    apply_static_fingerprint_hardening, clear_bound_import_directory_entry,
    obfuscate_coff_timestamp, obfuscate_optional_image_versions,
    obfuscate_optional_linker_versions, push_entropy_overlay, push_patterned_entropy_overlay,
    zero_coff_linked_symbol_table_fields, DEFAULT_ENTROPY_OVERLAY_LEN,
};
use crate::checksum::write_pe_checksum;
use crate::config::ProtectConfig;
use crate::error::{NaegiaPeError, Result};
use crate::layout::{
    IMAGE_DIRECTORY_ENTRY_DEBUG, PE32_PLUS_DATA_DIRECTORIES_OFFSET, PE32_PLUS_MAGIC,
};
use crate::obfuscate::{apply_metadata_obfuscation, obfuscation_seed};
use crate::raw::pe_optional_header_raw_offset;
use crate::strings_pad;
use crate::trampoline;
use crate::validate::parse_and_validate_pe64;

/// Validates PE64 and returns an owned copy (identity / pass-through baseline).
pub fn protect_identity(image: &[u8]) -> Result<Vec<u8>> {
    let _ = parse_and_validate_pe64(image)?;
    Ok(image.to_vec())
}

/// Zeros the Debug data directory entry (VirtualAddress + Size) for PE32+ images.
///
/// This **only** detaches the loader-visible debug directory pointer per
/// [`IMAGE_DIRECTORY_ENTRY_DEBUG`](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
/// The actual debug section content (`.debug$S`, `.debug$T`, etc.) remains in the file
/// and can still be recovered by section-scanning tools.
/// For full debug removal, compile the original binary with `strip = true` in `Cargo.toml`.
pub fn strip_debug_data_directory(image: &mut [u8]) -> Result<bool> {
    parse_and_validate_pe64(image)?;
    let opt = pe_optional_header_raw_offset(image)?;
    if opt + PE32_PLUS_DATA_DIRECTORIES_OFFSET + 8 > image.len() {
        return Err(NaegiaPeError::InvalidPe("data directories out of bounds"));
    }
    let magic = u16::from_le_bytes([image[opt], image[opt + 1]]);
    if magic != PE32_PLUS_MAGIC {
        return Err(NaegiaPeError::InvalidPe("optional header magic mismatch"));
    }
    let dir_off = opt + PE32_PLUS_DATA_DIRECTORIES_OFFSET + IMAGE_DIRECTORY_ENTRY_DEBUG * 8;
    if dir_off + 8 > image.len() {
        return Err(NaegiaPeError::InvalidPe(
            "debug data directory out of bounds",
        ));
    }
    let was_set = image[dir_off..dir_off + 8] != [0u8; 8];
    image[dir_off..dir_off + 8].fill(0);
    Ok(was_set)
}

/// Identity copy, then strip debug directory (if present), then recompute PE checksum.
pub fn protect_strip_debug_and_checksum(image: &[u8]) -> Result<Vec<u8>> {
    let mut out = protect_identity(image)?;
    let _ = strip_debug_data_directory(&mut out)?;
    write_pe_checksum(&mut out)?;
    Ok(out)
}

/// Full pipeline with optional aggressive layers (entry trampoline, decoy metadata, etc.).
///
/// Parses the PE exactly once at the start and caches the section table for all
/// downstream transforms that need section-level layout information.  A final
/// re-validation is still performed on the mutated output to guarantee the result
/// is still a well-formed PE32+ image.
pub fn protect_with_config(image: &[u8], config: &ProtectConfig) -> Result<Vec<u8>> {
    config.validate()?;
    let pe = parse_and_validate_pe64(image)?;
    // Clone section tables once: they own their data and are safe to use after
    // the output buffer has been mutated (goblin's PE borrow is tied to `image`).
    let sections: Vec<SectionTable> = pe.sections.clone();
    let seed = obfuscation_seed(image);
    let mut out = image.to_vec();
    if config.strip_debug {
        let _ = strip_debug_data_directory(&mut out)?;
    }
    apply_metadata_obfuscation(&mut out, seed, config.decoy_metadata)?;
    apply_fingerprint_pass(&mut out, seed, config)?;
    if config.xor_rdata_zero_runs {
        strings_pad::xor_zero_runs_in_rdata(&mut out, &sections, seed)?;
    }
    apply_entry_redirect_if_configured(&mut out, &sections, config, seed)?;
    push_configured_entropy_overlay(&mut out, seed, config);
    write_pe_checksum(&mut out)?;
    // Final structural validation: re-parse with goblin to catch accidental
    // PE-header corruption.  When `--xor-rdata-zero-runs` has modified section
    // content (zero padding inside `.rdata`), goblin may fail to parse import
    // strings etc.  These are content-level parse errors, not structural PE
    // corruption, so we only propagate non-parse errors.
    match parse_and_validate_pe64(&out) {
        Ok(_) => {}
        Err(NaegiaPeError::Parse(_)) => {
            // Goblin parse failure after legitimate section-content
            // modification is expected and benign.
        }
        Err(e) => return Err(e),
    }
    Ok(out)
}

/// Default protection: metadata + static fingerprint + optional entropy tail (see [`ProtectConfig`]).
pub fn protect_obfuscate_metadata(
    image: &[u8],
    strip_debug: bool,
    append_entropy_overlay: bool,
) -> Result<Vec<u8>> {
    let cfg = ProtectConfig::metadata_only(strip_debug, append_entropy_overlay);
    protect_with_config(image, &cfg)
}

fn apply_fingerprint_pass(image: &mut [u8], seed: u64, config: &ProtectConfig) -> Result<()> {
    if !config.decoy_metadata && !config.nuclear_metadata {
        apply_static_fingerprint_hardening(image, seed)?;
    } else {
        apply_coff_timestamp_for_mode(image, seed, config)?;
        apply_version_fields_for_mode(image, seed, config)?;
        clear_bound_import_directory_entry(image)?;
        zero_coff_linked_symbol_table_fields(image)?;
    }
    Ok(())
}

fn apply_coff_timestamp_for_mode(
    image: &mut [u8],
    seed: u64,
    config: &ProtectConfig,
) -> Result<()> {
    if config.decoy_metadata {
        apply_decoy_coff_timestamp(image, seed)
    } else {
        obfuscate_coff_timestamp(image, seed)
    }
}

fn apply_version_fields_for_mode(
    image: &mut [u8],
    seed: u64,
    config: &ProtectConfig,
) -> Result<()> {
    if config.nuclear_metadata {
        apply_nuclear_optional_versions(image)
    } else {
        obfuscate_optional_linker_versions(image, seed)?;
        obfuscate_optional_image_versions(image, seed)
    }
}

fn apply_entry_redirect_if_configured(
    image: &mut [u8],
    sections: &[SectionTable],
    config: &ProtectConfig,
    seed: u64,
) -> Result<()> {
    if !config.redirect_entry {
        return Ok(());
    }
    if config.anti_debug_entry {
        trampoline::redirect_entry_with_anti_debug(image, sections, seed)?;
    } else {
        trampoline::redirect_entry_plain(image, sections)?;
    }
    Ok(())
}

fn push_configured_entropy_overlay(image: &mut Vec<u8>, seed: u64, config: &ProtectConfig) {
    if !config.append_entropy_overlay {
        return;
    }
    if config.patterned_entropy_overlay {
        push_patterned_entropy_overlay(image, seed, DEFAULT_ENTROPY_OVERLAY_LEN);
    } else {
        push_entropy_overlay(image, seed, DEFAULT_ENTROPY_OVERLAY_LEN);
    }
}
