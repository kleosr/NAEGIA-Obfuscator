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
/// This does not remove debug raw data from sections; it only detaches the loader-visible
/// debug directory pointer per [`IMAGE_DIRECTORY_ENTRY_DEBUG`](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
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
pub fn protect_with_config(image: &[u8], config: &ProtectConfig) -> Result<Vec<u8>> {
    config.validate()?;
    parse_and_validate_pe64(image)?;
    let seed = obfuscation_seed(image);
    let mut out = image.to_vec();
    if config.strip_debug {
        let _ = strip_debug_data_directory(&mut out)?;
    }
    apply_metadata_obfuscation(&mut out, seed, config.decoy_metadata)?;

    if !config.decoy_metadata && !config.nuclear_metadata {
        apply_static_fingerprint_hardening(&mut out, seed)?;
    } else {
        if config.decoy_metadata {
            apply_decoy_coff_timestamp(&mut out, seed)?;
        } else {
            obfuscate_coff_timestamp(&mut out, seed)?;
        }
        if config.nuclear_metadata {
            apply_nuclear_optional_versions(&mut out)?;
        } else {
            obfuscate_optional_linker_versions(&mut out, seed)?;
            obfuscate_optional_image_versions(&mut out, seed)?;
        }
        clear_bound_import_directory_entry(&mut out)?;
        zero_coff_linked_symbol_table_fields(&mut out)?;
    }

    if config.xor_rdata_zero_runs {
        let sections = parse_and_validate_pe64(&out)?.sections.clone();
        strings_pad::xor_zero_runs_in_rdata(&mut out, &sections, seed)?;
    }

    if config.redirect_entry {
        let sections = parse_and_validate_pe64(&out)?.sections.clone();
        trampoline::redirect_entry_through_cave(&mut out, &sections, config.anti_debug_entry)?;
    }

    if config.append_entropy_overlay {
        if config.patterned_entropy_overlay {
            push_patterned_entropy_overlay(&mut out, seed, DEFAULT_ENTROPY_OVERLAY_LEN);
        } else {
            push_entropy_overlay(&mut out, seed, DEFAULT_ENTROPY_OVERLAY_LEN);
        }
    }
    write_pe_checksum(&mut out)?;
    let _ = parse_and_validate_pe64(&out)?;
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
