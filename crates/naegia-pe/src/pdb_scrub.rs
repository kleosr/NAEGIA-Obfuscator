//! Zero obvious CodeView / PDB path strings in read-only initialized data sections.

use goblin::pe::section_table::SectionTable;

use crate::error::Result;
use crate::layout::{IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_WRITE};

const MAX_PATH_SCRUB: usize = 520;

fn is_readonly_data(ch: u32) -> bool {
    (ch & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0 && (ch & IMAGE_SCN_MEM_WRITE) == 0
}

fn scrub_pattern_in_slice(data: &mut [u8], pattern: &[u8]) -> usize {
    if pattern.is_empty() || data.len() < pattern.len() {
        return 0;
    }
    let mut changed = 0usize;
    let mut i = 0usize;
    while i + pattern.len() <= data.len() {
        if data[i..i + pattern.len()]
            .iter()
            .zip(pattern.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
        {
            let end = (i + MAX_PATH_SCRUB).min(data.len());
            data[i..end].fill(0);
            changed += end - i;
            i = end;
        } else {
            i += 1;
        }
    }
    changed
}

fn scrub_utf16_pdb(data: &mut [u8]) -> usize {
    let needle: [u8; 8] = [b'.', 0, b'p', 0, b'd', 0, b'b', 0];
    let mut changed = 0usize;
    let mut i = 0usize;
    while i + needle.len() <= data.len() {
        if data[i..i + needle.len()] == needle {
            let start = i.saturating_sub(260 * 2);
            let end = (i + MAX_PATH_SCRUB * 2).min(data.len());
            let run = &mut data[start..end];
            let zeroed = run.len();
            run.fill(0);
            changed += zeroed;
            i = end;
        } else {
            i += 2;
        }
    }
    changed
}

/// Scan read-only data sections for PDB/CodeView path markers and zero bounded runs.
pub fn scrub_pdb_path_strings(image: &mut [u8], sections: &[SectionTable]) -> Result<usize> {
    let patterns: &[&[u8]] = &[b"RSDS", b".pdb", b".PDB", b"\\DEBUG\\", b"/DEBUG/"];
    let mut total = 0usize;
    for sec in sections {
        if !is_readonly_data(sec.characteristics) {
            continue;
        }
        let raw = sec.pointer_to_raw_data as usize;
        let sz = sec.size_of_raw_data as usize;
        if raw.saturating_add(sz) > image.len() || sz == 0 {
            continue;
        }
        let data = &mut image[raw..raw + sz];
        for pat in patterns {
            total += scrub_pattern_in_slice(data, pat);
        }
        total += scrub_utf16_pdb(data);
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubs_ascii_pdb_suffix() {
        let mut buf = b"prefix C:\\path\\file.pdb suffix".to_vec();
        let sec = goblin::pe::section_table::SectionTable {
            name: *b".rdata  ",
            real_name: None,
            virtual_size: buf.len() as u32,
            virtual_address: 0x1000,
            size_of_raw_data: buf.len() as u32,
            pointer_to_raw_data: 0,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: 0x4000_0040,
        };
        let n = scrub_pdb_path_strings(&mut buf, &[sec]).unwrap();
        assert!(n > 0);
        assert!(!buf.windows(4).any(|w| w.eq_ignore_ascii_case(b".pdb")));
    }
}
