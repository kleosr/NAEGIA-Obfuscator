//! Deterministic, loader-safe metadata obfuscation (DOS stub + section names).

use crate::error::{NaegiaPeError, Result};
use crate::raw;

const FNV_OFFSET: u64 = 14695981039346656037;
const FNV_PRIME: u64 = 1099511628211;

/// Maximum number of sections we will process.
///
/// Real PE files rarely exceed 20 sections; 100 is a generous upper bound
/// that still prevents pathological iteration over crafted or malicious
/// headers without imposing an arbitrary per-allocation limit.
const MAX_SECTIONS: usize = 100;

/// Deterministic seed derived from the full image for stable transforms.
///
/// Samples both the beginning (first 4 KiB) and the end (last 4 KiB) of the file,
/// then mixes in the total length.  This makes the seed depend on content from
/// both headers and code/data body, not just the PE prefix.
///
/// The 8192-byte threshold ensures we only pay for the second FNV pass when the
/// file is large enough that the prefix alone is not representative of the whole.
/// Files ≤8 KiB are dominated by headers; the single-pass prefix hash is sufficient.
pub(crate) fn obfuscation_seed(image: &[u8]) -> u64 {
    let mut h = fnv1a_prefix(image, image.len().min(4096));
    if image.len() > 8192 {
        let tail = fnv1a_suffix(image, 4096);
        h ^= tail.rotate_left(32);
    }
    h ^ ((image.len() as u64) << 1)
}

/// FNV-1a over the first `take` bytes of `buf`.
fn fnv1a_prefix(buf: &[u8], take: usize) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in &buf[..take] {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// FNV-1a over the last `take` bytes of `buf`.
fn fnv1a_suffix(buf: &[u8], take: usize) -> u64 {
    let start = buf.len().saturating_sub(take);
    fnv1a_prefix(&buf[start..], take.min(buf.len() - start))
}

/// File offsets of each `IMAGE_SECTION_HEADER.Name` (8 bytes).
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

/// Fake packer-style names (8 bytes, PE `IMAGE_SECTION_HEADER` width).
static DECOY_SECTION_NAMES: [[u8; 8]; 16] = [
    *b"UPX0____",
    *b"UPX1____",
    *b".vmp0___",
    *b".themida",
    *b"ASPack__",
    *b".enigma_",
    *b"telock__",
    *b"pex____.",
    *b"petite__",
    *b".mew____",
    *b"kkrunchy",
    *b"nspack__",
    *b"fsg_____",
    *b"mpress__",
    *b"armadill",
    *b"obsidium",
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
        let offs = section_name_raw_offsets(&buf)
            .expect("section_name_raw_offsets should succeed on minimal valid PE header");
        assert!(offs.is_empty());
    }
}
