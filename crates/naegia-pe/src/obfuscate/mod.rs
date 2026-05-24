//! Loader-safe metadata obfuscation (DOS stub, section names, COFF string table).

use crate::error::{NaegiaPeError, Result};
use crate::raw;

const MAX_SECTIONS: usize = 100;

/// PE `IMAGE_SECTION_HEADER.Name` charset (8 bytes, no leading `/` indirection in output).
const SECTION_CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._";

fn section_name_raw_offsets(image: &[u8]) -> Result<Vec<usize>> {
    let pe_off = raw::pe_signature_offset(image)?;
    let num_sections = u16::from_le_bytes([image[pe_off + 6], image[pe_off + 7]]) as usize;
    if num_sections > MAX_SECTIONS {
        return Err(NaegiaPeError::InvalidPe(
            "excessive section count (max 100)",
        ));
    }
    let size_opt = u16::from_le_bytes([image[pe_off + 20], image[pe_off + 21]]) as usize;
    let table_off = pe_off
        .checked_add(24)
        .and_then(|o| o.checked_add(size_opt))
        .ok_or(NaegiaPeError::InvalidPe("section table offset overflow"))?;
    let end = table_off
        .checked_add(
            num_sections
                .checked_mul(40)
                .ok_or(NaegiaPeError::InvalidPe("section count overflow"))?,
        )
        .ok_or(NaegiaPeError::InvalidPe("section table end overflow"))?;
    if end > image.len() {
        return Err(NaegiaPeError::InvalidPe("section headers out of bounds"));
    }
    Ok((0..num_sections).map(|i| table_off + i * 40).collect())
}

fn coff_string_table_offset(image: &[u8]) -> Result<usize> {
    let pe_off = raw::pe_signature_offset(image)?;
    let num_sections = u16::from_le_bytes([image[pe_off + 6], image[pe_off + 7]]) as usize;
    let size_opt = u16::from_le_bytes([image[pe_off + 20], image[pe_off + 21]]) as usize;
    pe_off
        .checked_add(24)
        .and_then(|o| o.checked_add(size_opt))
        .and_then(|o| o.checked_add(num_sections.checked_mul(40)?))
        .ok_or(NaegiaPeError::InvalidPe("string table offset overflow"))
}

fn obfuscated_section_name(index: usize, seed: u64) -> [u8; 8] {
    let mut x = seed ^ (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let mut out = [0u8; 8];
    for slot in &mut out {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
        *slot = SECTION_CHARSET[(x as usize) % SECTION_CHARSET.len()];
    }
    out
}

/// Neutral high-entropy names (no packer impersonation) for `--decoy-metadata`.
fn neutral_section_name(index: usize, seed: u64) -> [u8; 8] {
    obfuscated_section_name(index, seed.wrapping_add(0xDEC0_C0DE_A5A5_0000))
}

fn obfuscate_coff_string_entry(
    image: &mut [u8],
    table_base: usize,
    str_off: usize,
    seed: u64,
) -> Result<()> {
    let start = table_base
        .checked_add(str_off)
        .ok_or(NaegiaPeError::InvalidPe(
            "COFF string table offset overflow",
        ))?;
    if start >= image.len() {
        return Err(NaegiaPeError::InvalidPe("COFF string table out of bounds"));
    }
    let end = image[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| start + p)
        .unwrap_or(image.len());
    if end == start {
        return Ok(());
    }
    let mut x = seed ^ (str_off as u64).wrapping_mul(0x517c_c1b7_2722_0a95);
    for b in &mut image[start..end] {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
        *b = SECTION_CHARSET[(x as usize) % SECTION_CHARSET.len()];
    }
    Ok(())
}

fn apply_section_name_pass(
    image: &mut [u8],
    seed: u64,
    name_for_index: impl Fn(usize, u64) -> [u8; 8],
    coff_entry_seed: impl Fn(u64) -> u64,
) -> Result<usize> {
    let offs = section_name_raw_offsets(image)?;
    let table_base = coff_string_table_offset(image)?;
    let mut n = 0usize;
    for (i, off) in offs.iter().enumerate() {
        if *off + 8 > image.len() {
            return Err(NaegiaPeError::InvalidPe("section name out of bounds"));
        }
        let mut name = [0u8; 8];
        name.copy_from_slice(&image[*off..*off + 8]);
        if name[0] == b'/' {
            if let Some(str_off) = parse_coff_name_offset(&name) {
                obfuscate_coff_string_entry(image, table_base, str_off, coff_entry_seed(seed))?;
                n += 1;
            }
            continue;
        }
        let generated = name_for_index(i, seed);
        image[*off..*off + 8].copy_from_slice(&generated);
        n += 1;
    }
    Ok(n)
}

#[allow(clippy::question_mark)] // `?` in the loop; placing this fn after `impl` helpers avoids lizard span bleed.
fn parse_coff_name_offset(name: &[u8; 8]) -> Option<usize> {
    if name[0] != b'/' {
        return None;
    }
    let mut off = 0usize;
    for &b in &name[1..] {
        if b == 0 {
            break;
        }
        if !b.is_ascii_digit() {
            return None;
        }
        off = off.checked_mul(10)?.checked_add((b - b'0') as usize)?;
    }
    Some(off)
}

/// Overwrites the DOS program stub (`[0x40 .. e_lfanew)`). Preserves `e_lfanew` at `0x3C`.
pub fn obfuscate_dos_stub(image: &mut [u8], seed: u64) -> Result<bool> {
    let pe_off = raw::pe_signature_offset(image)?;
    if pe_off <= 0x40 {
        return Ok(false);
    }
    for (i, b) in image[0x40..pe_off].iter_mut().enumerate() {
        let mix = ((seed >> ((i % 56) as u32)) as u8).wrapping_add(i as u8);
        *b = mix;
    }
    Ok(true)
}

/// Renames section headers and COFF string-table names referenced via `/offset`.
pub fn obfuscate_section_names(image: &mut [u8], seed: u64) -> Result<usize> {
    apply_section_name_pass(image, seed, obfuscated_section_name, |s| s)
}

/// Seed-derived neutral section names (`--decoy-metadata`).
pub fn obfuscate_section_names_decoy(image: &mut [u8], seed: u64) -> Result<usize> {
    apply_section_name_pass(image, seed, neutral_section_name, |s| {
        s.wrapping_add(0xA5A5)
    })
}

/// Apply DOS stub + section name obfuscation using a precomputed seed.
pub fn apply_metadata_obfuscation(
    image: &mut [u8],
    seed: u64,
    decoy_section_names: bool,
) -> Result<()> {
    obfuscate_dos_stub(image, seed)?;
    if decoy_section_names {
        obfuscate_section_names_decoy(image, seed)?;
    } else {
        obfuscate_section_names(image, seed)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
