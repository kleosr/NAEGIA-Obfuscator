//! Deterministic, loader-safe metadata obfuscation (DOS stub + section names).

use crate::error::{NaegiaPeError, Result};

const FNV_OFFSET: u64 = 14695981039346656037;
const FNV_PRIME: u64 = 1099511628211;

/// FNV-1a over a bounded prefix of the image for stable transforms.
pub(crate) fn obfuscation_seed(image: &[u8]) -> u64 {
    let mut h = FNV_OFFSET;
    let take = image.len().min(4096);
    for &b in &image[..take] {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h ^ ((image.len() as u64) << 1)
}

pub(crate) fn pe_signature_offset(image: &[u8]) -> Result<usize> {
    if image.len() < 0x40 {
        return Err(NaegiaPeError::InvalidPe("image too small for DOS header"));
    }
    let pe_off = u32::from_le_bytes(image[0x3c..0x40].try_into().unwrap()) as usize;
    if pe_off + 24 > image.len() {
        return Err(NaegiaPeError::InvalidPe("invalid e_lfanew"));
    }
    Ok(pe_off)
}

/// File offsets of each `IMAGE_SECTION_HEADER.Name` (8 bytes).
fn section_name_raw_offsets(image: &[u8]) -> Result<Vec<usize>> {
    let pe_off = pe_signature_offset(image)?;
    let num_sections = u16::from_le_bytes([image[pe_off + 6], image[pe_off + 7]]) as usize;
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

/// Fake packer-style names (8 bytes, PE `IMAGE_SECTION_HEADER` width).
static DECOY_SECTION_NAMES: [[u8; 8]; 5] = [
    *b"UPX0____",
    *b"UPX1____",
    *b".vmp0___",
    *b".themida",
    *b"ASPack__",
];

fn decoy_section_name(index: usize) -> [u8; 8] {
    DECOY_SECTION_NAMES[index % DECOY_SECTION_NAMES.len()]
}

fn obfuscated_section_name(index: usize, seed: u64) -> [u8; 8] {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut x = seed ^ (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let mut out = [b'.'; 8];
    for slot in out.iter_mut().skip(1) {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
        *slot = CHARSET[(x as usize) % CHARSET.len()];
    }
    out
}

/// Overwrites the DOS program stub (`[0x40 .. e_lfanew)`). Preserves `e_lfanew` at `0x3C`.
pub fn obfuscate_dos_stub(image: &mut [u8], seed: u64) -> Result<bool> {
    let pe_off = pe_signature_offset(image)?;
    if pe_off <= 0x40 {
        return Ok(false);
    }
    for (i, b) in image[0x40..pe_off].iter_mut().enumerate() {
        let mix = ((seed >> ((i % 56) as u32)) as u8).wrapping_add(i as u8);
        *b = mix;
    }
    Ok(true)
}

/// Renames PE section headers in-place (8-byte names). Skips string-table indirection (`/`).
pub fn obfuscate_section_names(image: &mut [u8], seed: u64) -> Result<usize> {
    let offs = section_name_raw_offsets(image)?;
    let mut n = 0usize;
    for (i, off) in offs.iter().enumerate() {
        if *off + 8 > image.len() {
            return Err(NaegiaPeError::InvalidPe("section name out of bounds"));
        }
        if image[*off] == b'/' {
            continue;
        }
        let name = obfuscated_section_name(i, seed);
        image[*off..*off + 8].copy_from_slice(&name);
        n += 1;
    }
    Ok(n)
}

/// Same as [`obfuscate_section_names`] but uses packer-style decoy names.
pub fn obfuscate_section_names_decoy(image: &mut [u8]) -> Result<usize> {
    let offs = section_name_raw_offsets(image)?;
    let mut n = 0usize;
    for (i, off) in offs.iter().enumerate() {
        if *off + 8 > image.len() {
            return Err(NaegiaPeError::InvalidPe("section name out of bounds"));
        }
        if image[*off] == b'/' {
            continue;
        }
        let name = decoy_section_name(i);
        image[*off..*off + 8].copy_from_slice(&name);
        n += 1;
    }
    Ok(n)
}

/// Apply DOS stub + section name obfuscation using a precomputed seed.
pub fn apply_metadata_obfuscation(
    image: &mut [u8],
    seed: u64,
    decoy_section_names: bool,
) -> Result<()> {
    obfuscate_dos_stub(image, seed)?;
    if decoy_section_names {
        obfuscate_section_names_decoy(image)?;
    } else {
        obfuscate_section_names(image, seed)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_table_offsets_sane_on_minimal_header() {
        // MZ + e_lfanew=0x80 + padding to 0x80, minimal COFF + optional + 0 sections
        let mut buf = vec![0u8; 0x200];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let pe = 0x80usize;
        buf[pe..pe + 4].copy_from_slice(b"PE\0\0");
        // COFF: machine amd64, 0 sections, time 0, sym 0, num sym 0, opt size 240 (fake), chars
        buf[pe + 4..pe + 6].copy_from_slice(&0x8664u16.to_le_bytes());
        buf[pe + 6..pe + 8].copy_from_slice(&0u16.to_le_bytes());
        buf[pe + 20..pe + 22].copy_from_slice(&240u16.to_le_bytes());
        let offs = section_name_raw_offsets(&buf).unwrap();
        assert!(offs.is_empty());
    }
}
