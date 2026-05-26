use goblin::pe::section_table::SectionTable;

use crate::anti_analysis::{
    apply_decoy_coff_timestamp, apply_nuclear_optional_versions, apply_random_coff_timestamp,
    apply_static_fingerprint_hardening, clear_bound_import_directory_entry,
    obfuscate_coff_timestamp, obfuscate_optional_image_versions,
    obfuscate_optional_linker_versions, push_entropy_overlay, push_patterned_entropy_overlay,
    zero_coff_linked_symbol_table_fields,
};
use crate::checksum::write_pe_checksum;
use crate::config::ProtectConfig;
use crate::debug_strip::wipe_debug_info;
use crate::error::{NaegiaPeError, Result};
use crate::inspect::authenticode_likely;
use crate::layout::{
    IMAGE_DIRECTORY_ENTRY_DEBUG, PE32_PLUS_DATA_DIRECTORIES_OFFSET, PE32_PLUS_MAGIC,
};
use crate::obfuscate::apply_metadata_obfuscation;
use crate::pdb_scrub::scrub_pdb_path_strings;
use crate::raw::pe_optional_header_raw_offset;
use crate::seed::{os_random_u64, protect_seed};
use crate::strings_pad;
use crate::trampoline;
use crate::validate::{parse_and_validate_pe64, validate_pe64_after_transform};

/// Validates PE64 and returns an owned copy (identity / pass-through baseline).
pub fn protect_identity(image: &[u8]) -> Result<Vec<u8>> {
    let _ = parse_and_validate_pe64(image)?;
    Ok(image.to_vec())
}

/// Zeros the Debug data directory entry (VirtualAddress + Size) for PE32+ images.
///
/// Prefer [`protect_with_config`] with `strip_debug: true`, which also wipes debug
/// directory bytes and common `.debug*` section payloads.
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

/// Identity copy, then full debug wipe, then recompute PE checksum.
pub fn protect_strip_debug_and_checksum(image: &[u8]) -> Result<Vec<u8>> {
    let pe = parse_and_validate_pe64(image)?;
    let sections = pe.sections.clone();
    let mut out = protect_identity(image)?;
    let _ = wipe_debug_info(&mut out, &sections)?;
    write_pe_checksum(&mut out)?;
    validate_pe64_after_transform(&out)?;
    Ok(out)
}

/// Full pipeline with optional aggressive layers (entry trampoline, decoy metadata, etc.).
pub fn protect_with_config(image: &[u8], config: &ProtectConfig) -> Result<Vec<u8>> {
    config.validate()?;
    reject_overlay_for_signed_image(image, config)?;
    let pe = parse_and_validate_pe64(image)?;
    let sections: Vec<SectionTable> = pe.sections.clone();

    let (random_entropy, random_ts) = resolve_random_material(config)?;
    let seed = protect_seed(image, random_entropy);

    let mut out = image.to_vec();
    apply_debug_scrub_passes(&mut out, &sections, config)?;
    apply_metadata_pass_if_configured(&mut out, seed, config, random_ts)?;
    apply_rdata_padding_if_configured(&mut out, &sections, config, seed)?;
    apply_entry_redirect_if_configured(&mut out, &sections, config, seed)?;
    push_configured_entropy_overlay(&mut out, seed, config);
    write_pe_checksum(&mut out)?;
    validate_pe64_after_transform(&out)?;
    Ok(out)
}

fn reject_overlay_for_signed_image(image: &[u8], config: &ProtectConfig) -> Result<()> {
    if config.append_entropy_overlay && authenticode_likely(image) {
        return Err(NaegiaPeError::InvalidPe(
            "authenticode certificate directory present; use --no-overlay or --preset signed",
        ));
    }
    Ok(())
}

fn apply_debug_scrub_passes(
    image: &mut [u8],
    sections: &[SectionTable],
    config: &ProtectConfig,
) -> Result<()> {
    if config.strip_debug {
        let _ = wipe_debug_info(image, sections)?;
    }
    if config.scrub_pdb_paths {
        let _ = scrub_pdb_path_strings(image, sections)?;
    }
    Ok(())
}

fn apply_metadata_pass_if_configured(
    image: &mut [u8],
    seed: u64,
    config: &ProtectConfig,
    random_ts: Option<u32>,
) -> Result<()> {
    if !config.obfuscate_metadata {
        return Ok(());
    }
    apply_metadata_obfuscation(image, seed, config.decoy_metadata)?;
    apply_fingerprint_pass(image, seed, config, random_ts)
}

fn apply_rdata_padding_if_configured(
    image: &mut [u8],
    sections: &[SectionTable],
    config: &ProtectConfig,
    seed: u64,
) -> Result<()> {
    if config.xor_rdata_zero_runs {
        strings_pad::xor_zero_runs_in_rdata(image, sections, seed)?;
    }
    Ok(())
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

fn apply_fingerprint_pass(
    image: &mut [u8],
    seed: u64,
    config: &ProtectConfig,
    random_ts: Option<u32>,
) -> Result<()> {
    if !config.decoy_metadata && !config.nuclear_metadata {
        apply_static_fingerprint_hardening(image, seed)?;
        if let Some(ts) = random_ts {
            apply_random_coff_timestamp(image, ts)?;
        }
    } else {
        apply_coff_timestamp_for_mode(image, seed, config, random_ts)?;
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
    random_ts: Option<u32>,
) -> Result<()> {
    if let Some(ts) = random_ts {
        apply_random_coff_timestamp(image, ts)
    } else if config.decoy_metadata {
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

fn resolve_random_material(config: &ProtectConfig) -> Result<(Option<u64>, Option<u32>)> {
    if !config.random_seed {
        return Ok((None, None));
    }
    if let Some(fixed) = config.fixed_seed {
        let ts = ((fixed >> 32) as u32) ^ (fixed as u32);
        return Ok((Some(fixed), Some(ts)));
    }
    Ok((
        Some(os_random_u64()?),
        Some((os_random_u64()? & 0xFFFF_FFFF) as u32),
    ))
}

fn push_configured_entropy_overlay(image: &mut Vec<u8>, seed: u64, config: &ProtectConfig) {
    if !config.append_entropy_overlay {
        return;
    }
    let len = config.overlay_len;
    if config.patterned_entropy_overlay {
        push_patterned_entropy_overlay(image, seed, len);
    } else {
        push_entropy_overlay(image, seed, len);
    }
}

/// Re-read `path` and run post-transform validation (for CI / `--verify`).
pub fn verify_written_image(path: &std::path::Path) -> Result<()> {
    let bytes = std::fs::read(path).map_err(NaegiaPeError::Io)?;
    validate_pe64_after_transform(&bytes)
}
