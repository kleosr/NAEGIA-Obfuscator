//! COFF / optional header cosmetic edits and data-directory cleanup.

use crate::error::{NaegiaPeError, Result};
use crate::layout::{
    IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, PE32_PLUS_DATA_DIRECTORIES_OFFSET, PE32_PLUS_MAGIC,
    PE32_PLUS_NUMBER_OF_RVA_AND_SIZES_OFFSET,
};
use crate::obfuscate::pe_signature_offset;
use crate::raw::pe_optional_header_raw_offset;

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
