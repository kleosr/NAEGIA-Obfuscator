//! Remove loader-visible debug directory entries and wipe on-disk debug payloads.

use goblin::pe::section_table::SectionTable;

use crate::error::{NaegiaPeError, Result};
use crate::layout::IMAGE_DIRECTORY_ENTRY_DEBUG;
use crate::raw::{debug_data_directory_entry, pe_optional_header_raw_offset};
use crate::rva::rva_range_file_bounds;

/// Zero debug directory pointer, debug directory blob, and common debug section bodies.
pub fn wipe_debug_info(image: &mut [u8], sections: &[SectionTable]) -> Result<bool> {
    let (debug_rva, debug_size) = debug_data_directory_entry(image).unwrap_or((0, 0));
    let mut changed = clear_debug_directory_entry(image)?;

    if debug_rva != 0 && debug_size != 0 {
        if let Some((start, len)) = rva_range_file_bounds(sections, debug_rva, debug_size) {
            if start + len <= image.len() {
                image[start..start + len].fill(0);
                changed = true;
            }
        }
    }

    for sec in sections {
        if !section_looks_like_debug(&sec.name) {
            continue;
        }
        let raw = sec.pointer_to_raw_data as usize;
        let sz = sec.size_of_raw_data as usize;
        if raw.saturating_add(sz) > image.len() || sz == 0 {
            continue;
        }
        image[raw..raw + sz].fill(0);
        changed = true;
    }

    Ok(changed)
}

fn clear_debug_directory_entry(image: &mut [u8]) -> Result<bool> {
    let opt = pe_optional_header_raw_offset(image)?;
    let dir_off =
        opt + crate::layout::PE32_PLUS_DATA_DIRECTORIES_OFFSET + IMAGE_DIRECTORY_ENTRY_DEBUG * 8;
    if dir_off + 8 > image.len() {
        return Err(NaegiaPeError::InvalidPe(
            "debug data directory out of bounds",
        ));
    }
    let was_set = image[dir_off..dir_off + 8] != [0u8; 8];
    image[dir_off..dir_off + 8].fill(0);
    Ok(was_set)
}

fn section_looks_like_debug(name: &[u8; 8]) -> bool {
    let n = name.split(|&b| b == 0).next().unwrap_or(name);
    if n.is_empty() {
        return false;
    }
    let lower: Vec<u8> = n.iter().map(|b| b.to_ascii_lowercase()).collect();
    lower.starts_with(b".debug") || lower.starts_with(b"debug") || lower.starts_with(b"/debug")
}
