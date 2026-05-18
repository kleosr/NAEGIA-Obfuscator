//! RVA ↔ file-offset mapping via the section table.

use goblin::pe::section_table::SectionTable;

/// Map `(rva, size)` to `(file_offset, length)` when fully contained in one section.
pub fn rva_range_file_bounds(
    sections: &[SectionTable],
    rva: u32,
    size: u32,
) -> Option<(usize, usize)> {
    if size == 0 {
        return None;
    }
    let end_rva = rva.checked_add(size.saturating_sub(1))?;
    for sec in sections {
        let va = sec.virtual_address;
        let virt_end = va.checked_add(sec.virtual_size.max(sec.size_of_raw_data))?;
        if rva >= va && end_rva < virt_end {
            let start = sec.pointer_to_raw_data as usize + (rva - va) as usize;
            return Some((start, size as usize));
        }
    }
    None
}
