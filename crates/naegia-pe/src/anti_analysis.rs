//! Static fingerprint noise: timestamps, optional-header cosmetic fields, data-directory
//! cleanup, file tail. This raises the cost of quick static triage (YARA, “what linker”, bound
//! IAT hints). It is not a substitute for code-level hardening: packing, import encryption, and
//! control-flow obfuscation live in another league.
//!
//! Nothing here changes section bodies, the import table, or the entry RVA.

use crate::error::{NaegiaPeError, Result};
use crate::layout::{
    IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, PE32_PLUS_DATA_DIRECTORIES_OFFSET, PE32_PLUS_MAGIC,
    PE32_PLUS_NUMBER_OF_RVA_AND_SIZES_OFFSET,
};
use crate::obfuscate::pe_signature_offset;
use crate::raw::pe_optional_header_raw_offset;

/// Pseudorandom tail appended after the mapped PE image (loader ignores it for normal exes).
pub const DEFAULT_ENTROPY_OVERLAY_LEN: usize = 1536;

fn optional_header_bounds(image: &[u8]) -> Result<(usize, usize)> {
    let pe_off = pe_signature_offset(image)?;
    let opt = pe_optional_header_raw_offset(image)?;
    if pe_off + 22 > image.len() {
        return Err(NaegiaPeError::InvalidPe("COFF header truncated"));
    }
    let sz = u16::from_le_bytes([image[pe_off + 20], image[pe_off + 21]]) as usize;
    let end = opt
        .checked_add(sz)
        .filter(|&e| e <= image.len())
        .ok_or(NaegiaPeError::InvalidPe(
            "optional header extends past image",
        ))?;
    Ok((opt, end))
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

/// XOR-mix COFF `TimeDateStamp` with the obfuscation seed (deterministic per input).
pub fn obfuscate_coff_timestamp(image: &mut [u8], seed: u64) -> Result<()> {
    let pe_off = pe_signature_offset(image)?;
    let ts_off = pe_off + 8;
    if ts_off + 4 > image.len() {
        return Err(NaegiaPeError::InvalidPe("TimeDateStamp out of bounds"));
    }
    let orig = u32::from_le_bytes(image[ts_off..ts_off + 4].try_into().unwrap());
    let mix = (seed as u32) ^ ((seed >> 32) as u32) ^ 0xA5A5_5A5A;
    let new_ts = orig ^ mix;
    image[ts_off..ts_off + 4].copy_from_slice(&new_ts.to_le_bytes());
    Ok(())
}

/// Append high-entropy bytes after the image (raises file entropy; breaks Authenticode if present).
pub fn push_entropy_overlay(image: &mut Vec<u8>, seed: u64, len: usize) {
    if len == 0 {
        return;
    }
    let mut st = seed ^ 0xCAFE_F00D_D15C_A5ED;
    let old_len = image.len();
    image.reserve(len);
    let mut written = 0usize;
    while written < len {
        let w = splitmix64(&mut st);
        let chunk = w.to_le_bytes();
        let take = (len - written).min(8);
        image.extend_from_slice(&chunk[..take]);
        written += take;
    }
    debug_assert_eq!(image.len(), old_len + len);
}

/// XOR `MajorLinkerVersion` / `MinorLinkerVersion` in the PE32+ optional header (offset +2/+3).
/// The Windows loader does not consult these; YARA rules and “what linker” heuristics often do.
pub fn obfuscate_optional_linker_versions(image: &mut [u8], seed: u64) -> Result<()> {
    let (opt, end) = optional_header_bounds(image)?;
    if opt + 4 > end {
        return Err(NaegiaPeError::InvalidPe("optional header truncated"));
    }
    let magic = u16::from_le_bytes([image[opt], image[opt + 1]]);
    if magic != PE32_PLUS_MAGIC {
        return Err(NaegiaPeError::InvalidPe("optional header magic mismatch"));
    }
    // `| 1` guarantees at least one bit flips so the field always diverges from the original.
    image[opt + 2] ^= ((seed >> 16) as u8) | 1;
    image[opt + 3] ^= ((seed >> 24) as u8) | 1;
    Ok(())
}

/// XOR `MajorImageVersion` / `MinorImageVersion` (WORDs at optional +44 / +46). Usually zero or
/// cosmetic; the loader does not need them to run a normal EXE.
pub fn obfuscate_optional_image_versions(image: &mut [u8], seed: u64) -> Result<()> {
    let (opt, end) = optional_header_bounds(image)?;
    if opt + 48 > end {
        return Err(NaegiaPeError::InvalidPe(
            "optional header missing image version fields",
        ));
    }
    let magic = u16::from_le_bytes([image[opt], image[opt + 1]]);
    if magic != PE32_PLUS_MAGIC {
        return Err(NaegiaPeError::InvalidPe("optional header magic mismatch"));
    }
    let maj = u16::from_le_bytes([image[opt + 44], image[opt + 45]]);
    let min = u16::from_le_bytes([image[opt + 46], image[opt + 47]]);
    let mix0 = ((seed >> 32) as u16) | 1;
    let mix1 = ((seed >> 48) as u16) | 1;
    image[opt + 44..opt + 46].copy_from_slice(&(maj ^ mix0).to_le_bytes());
    image[opt + 46..opt + 48].copy_from_slice(&(min ^ mix1).to_le_bytes());
    Ok(())
}

/// Zeros the bound-import data directory entry so the loader always resolves the full IAT.
/// Peels one more static hint without touching the import descriptors themselves.
pub fn clear_bound_import_directory_entry(image: &mut [u8]) -> Result<()> {
    let (opt, end) = optional_header_bounds(image)?;
    if opt + PE32_PLUS_NUMBER_OF_RVA_AND_SIZES_OFFSET + 4 > end {
        return Err(NaegiaPeError::InvalidPe(
            "optional header missing NumberOfRvaAndSizes",
        ));
    }
    let magic = u16::from_le_bytes([image[opt], image[opt + 1]]);
    if magic != PE32_PLUS_MAGIC {
        return Err(NaegiaPeError::InvalidPe("optional header magic mismatch"));
    }
    let num_dirs = u32::from_le_bytes(
        image[opt + PE32_PLUS_NUMBER_OF_RVA_AND_SIZES_OFFSET
            ..opt + PE32_PLUS_DATA_DIRECTORIES_OFFSET]
            .try_into()
            .map_err(|_| NaegiaPeError::InvalidPe("NumberOfRvaAndSizes read"))?,
    ) as usize;
    if num_dirs <= IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT {
        return Ok(());
    }
    let dir_off = opt + PE32_PLUS_DATA_DIRECTORIES_OFFSET + IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT * 8;
    if dir_off + 8 > end {
        return Err(NaegiaPeError::InvalidPe(
            "bound import directory out of optional header",
        ));
    }
    image[dir_off..dir_off + 8].fill(0);
    Ok(())
}

/// Zeros COFF `PointerToSymbolTable` and `NumberOfSymbols`. Final linked MSVC EXEs already use
/// zeros; when present, this removes a static handle for symbol-based tooling.
pub fn zero_coff_linked_symbol_table_fields(image: &mut [u8]) -> Result<()> {
    let pe_off = pe_signature_offset(image)?;
    let ptr_off = pe_off + 4 + 8;
    let num_off = pe_off + 4 + 12;
    if num_off + 4 > image.len() {
        return Err(NaegiaPeError::InvalidPe("COFF header truncated"));
    }
    image[ptr_off..ptr_off + 4].fill(0);
    image[num_off..num_off + 4].fill(0);
    Ok(())
}

/// Runs the full static-hardening pass (order matters only for checksum, applied later).
pub fn apply_static_fingerprint_hardening(image: &mut [u8], seed: u64) -> Result<()> {
    obfuscate_coff_timestamp(image, seed)?;
    obfuscate_optional_linker_versions(image, seed)?;
    obfuscate_optional_image_versions(image, seed)?;
    clear_bound_import_directory_entry(image)?;
    zero_coff_linked_symbol_table_fields(image)?;
    Ok(())
}

/// Preset COFF timestamps seen in public packer samples (decoy only).
pub static DECOY_COFF_TIMESTAMPS: &[u32] = &[0x5B90_9732, 0x55E7_C184, 0x5D40_9A1Eu32];

/// Overwrite `TimeDateStamp` with a cyclic decoy value.
pub fn apply_decoy_coff_timestamp(image: &mut [u8], seed: u64) -> Result<()> {
    let pe_off = pe_signature_offset(image)?;
    let ts_off = pe_off + 8;
    if ts_off + 4 > image.len() {
        return Err(NaegiaPeError::InvalidPe("TimeDateStamp out of bounds"));
    }
    let idx = (seed as usize) % DECOY_COFF_TIMESTAMPS.len();
    image[ts_off..ts_off + 4].copy_from_slice(&DECOY_COFF_TIMESTAMPS[idx].to_le_bytes());
    Ok(())
}

/// Max out linker and image version words (still unused by the loader for execution).
pub fn apply_nuclear_optional_versions(image: &mut [u8]) -> Result<()> {
    let (opt, end) = optional_header_bounds(image)?;
    if opt + 48 > end {
        return Err(NaegiaPeError::InvalidPe("optional header too small"));
    }
    let magic = u16::from_le_bytes([image[opt], image[opt + 1]]);
    if magic != PE32_PLUS_MAGIC {
        return Err(NaegiaPeError::InvalidPe("optional header magic mismatch"));
    }
    image[opt + 2] = 0xFF;
    image[opt + 3] = 0xFF;
    image[opt + 44..opt + 48].fill(0xFF);
    Ok(())
}

/// High / low / NOP-like blocks to skew naive entropy plots (file tail only).
pub fn push_patterned_entropy_overlay(image: &mut Vec<u8>, seed: u64, total_len: usize) {
    if total_len == 0 {
        return;
    }
    let target_len = image.len().saturating_add(total_len);
    let mut st = seed ^ 0xBADC0FFEEBAD0000;
    let pattern = b"Copyright (C) NAEGIA. All rights reserved.\x00";
    let mut phase: u64 = 0;
    while image.len() < target_len {
        let remain = target_len - image.len();
        let take = remain.min(256);
        match phase % 3 {
            0 => {
                for _ in 0..take {
                    let w = splitmix64(&mut st);
                    image.push(w as u8);
                }
            }
            1 => {
                for i in 0..take {
                    image.push(pattern[i % pattern.len()]);
                }
            }
            _ => {
                image.extend(std::iter::repeat_n(0x90u8, take));
            }
        }
        phase = phase.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_entropy_overlay_exact_len() {
        let mut v = vec![1u8, 2, 3];
        push_entropy_overlay(&mut v, 0x1234, 100);
        assert_eq!(v.len(), 103);
    }

    #[test]
    fn patterned_overlay_matches_length() {
        let mut v = vec![0u8; 10];
        push_patterned_entropy_overlay(&mut v, 0xABCD, 512);
        assert_eq!(v.len(), 522);
    }
}
