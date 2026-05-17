//! XOR section-end padding in read-only initialized data sections.
//!
//! To avoid corrupting PE data structures or CRT runtime metadata, XOR is
//! limited to the **true alignment padding** between `VirtualSize` and
//! `SizeOfRawData` for each section. Per the PE spec, these bytes are
//! guaranteed to be zero (file-alignment padding), unreferenced by the
//! loader and all runtime code.
//!
//! This is conservative: internal zero runs (e.g., CRT initializer table
//! gaps) are left alone because changing them can turn sentinel-zero entries
//! into fake function pointers, crashing the CRT's init/cleanup path.

use goblin::pe::section_table::SectionTable;

use crate::error::Result;
use crate::layout::{IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_WRITE};

fn is_initialized_readonly_data(ch: u32) -> bool {
    (ch & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0 && (ch & IMAGE_SCN_MEM_WRITE) == 0
}

/// XOR every byte in the section-end padding region of each read-only
/// initialized data section.
///
/// The "padding region" is the gap between `VirtualSize` and
/// `SizeOfRawData`. The PE spec guarantees these bytes are zero in the file
/// and unreferenced at runtime, making them safe to XOR regardless of what
/// PE data structures or CRT tables the section contains.
///
/// Returns the number of bytes modified.
pub fn xor_zero_runs_in_rdata(
    image: &mut [u8],
    sections: &[SectionTable],
    seed: u64,
) -> Result<usize> {
    let mut changed = 0usize;
    for sec in sections {
        if !is_initialized_readonly_data(sec.characteristics) {
            continue;
        }
        let raw_start = sec.pointer_to_raw_data as usize;
        let raw_size = sec.size_of_raw_data as usize;
        let virt_size = sec.virtual_size as usize;

        // No section-end padding when virtual size equals or exceeds raw size.
        if virt_size >= raw_size {
            continue;
        }
        if raw_start.saturating_add(raw_size) > image.len() {
            continue;
        }
        let pad_start = raw_start + virt_size;
        let pad_end = raw_start + raw_size;
        for (i, b) in image[pad_start..pad_end].iter_mut().enumerate() {
            let k = pad_start + i;
            let k0 = k as u64;
            *b ^= ((seed >> (k0 % 56)) as u8).wrapping_add(k as u8);
            changed += 1;
        }
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use goblin::pe::section_table::SectionTable;

    #[allow(dead_code)]
    fn make_section(virtual_size: u32, raw_size: u32) -> SectionTable {
        SectionTable {
            name: [0u8; 8],
            real_name: None,
            virtual_size,
            virtual_address: 0x1000,
            size_of_raw_data: raw_size,
            pointer_to_raw_data: 0x200,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: 0x4000_0040,
        }
    }

    #[test]
    fn xor_padding_region_changes_only_padding_bytes() {
        let mut image = vec![0u8; 0x220];
        image[0x100] = 0x41;

        let sec = SectionTable {
            name: [0u8; 8],
            real_name: None,
            virtual_size: 0x200,
            virtual_address: 0x1000,
            size_of_raw_data: 0x220,
            pointer_to_raw_data: 0x000,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: 0x4000_0040,
        };

        let n = xor_zero_runs_in_rdata(&mut image, &[sec], 0xABC).unwrap();
        assert!(n > 0, "should XOR padding bytes");
        assert_eq!(
            image[0x100], 0x41,
            "section data (within VirtualSize) unchanged"
        );
        assert_ne!(image[0x200], 0x00, "first padding byte XOR'd");
        assert_ne!(image[0x21F], 0x00, "last padding byte XOR'd");
    }

    #[test]
    fn xor_noop_when_virt_size_equals_raw_size() {
        let mut image = vec![0u8; 0x200];
        image[0x100] = 0x41;
        let sec = SectionTable {
            name: [0u8; 8],
            real_name: None,
            virtual_size: 0x200,
            virtual_address: 0x1000,
            size_of_raw_data: 0x200,
            pointer_to_raw_data: 0x000,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: 0x4000_0040,
        };
        let n = xor_zero_runs_in_rdata(&mut image, &[sec], 0xABC).unwrap();
        assert_eq!(n, 0, "no padding when virt_size == raw_size");
        assert_eq!(image[0x100], 0x41, "data unchanged");
    }
}
