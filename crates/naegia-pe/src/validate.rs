use goblin::pe::PE;

use crate::config::MAX_INPUT_BYTES;
use crate::error::{NaegiaPeError, Result};
use crate::layout::{
    IMAGE_FILE_MACHINE_AMD64, IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, PE32_PLUS_MAGIC,
};
use crate::raw::{pe_optional_header_raw_offset, pe_signature_offset};

/// Rejects images larger than [`MAX_INPUT_BYTES`].
pub fn ensure_image_fits(len: usize) -> Result<()> {
    if len > MAX_INPUT_BYTES {
        return Err(NaegiaPeError::InvalidPe(
            "image exceeds maximum size (256 MiB)",
        ));
    }
    Ok(())
}

/// Parses and validates a PE32+ (AMD64) executable image suitable for NAEGIA processing.
pub fn parse_and_validate_pe64(image: &[u8]) -> Result<PE<'_>> {
    ensure_image_fits(image.len())?;
    if image.len() < 64 {
        return Err(NaegiaPeError::InvalidPe("image too small"));
    }

    let pe = PE::parse(image)?;

    if pe.header.coff_header.machine != IMAGE_FILE_MACHINE_AMD64 {
        return Err(NaegiaPeError::InvalidPe(
            "expected AMD64 (PE32+) machine type",
        ));
    }

    let Some(optional) = pe.header.optional_header.as_ref() else {
        return Err(NaegiaPeError::InvalidPe("missing optional header"));
    };

    if optional.standard_fields.magic != PE32_PLUS_MAGIC {
        return Err(NaegiaPeError::InvalidPe(
            "expected PE32+ optional header magic (0x20B)",
        ));
    }

    validate_section_raw_layout(image, &pe, optional.windows_fields.file_alignment)?;
    Ok(pe)
}

fn validate_section_raw_layout(image: &[u8], pe: &PE<'_>, file_alignment: u32) -> Result<()> {
    if file_alignment == 0 || !file_alignment.is_power_of_two() {
        return Err(NaegiaPeError::InvalidPe("invalid FileAlignment"));
    }

    let align = file_alignment as usize;
    for section in &pe.sections {
        let raw_size = section.size_of_raw_data as usize;
        let raw_ptr = section.pointer_to_raw_data as usize;
        if raw_size > 0 {
            if raw_ptr % align != 0 {
                return Err(NaegiaPeError::InvalidPe(
                    "section raw pointer not FileAlignment-aligned",
                ));
            }
            let end = raw_ptr
                .checked_add(raw_size)
                .ok_or(NaegiaPeError::InvalidPe("section overflow"))?;
            if end > image.len() {
                return Err(NaegiaPeError::InvalidPe("section raw data out of bounds"));
            }
        }
    }

    Ok(())
}

struct SectionTableRow {
    virtual_size: u32,
    virtual_address: u32,
    raw_size: usize,
    raw_ptr: usize,
    characteristics: u32,
}

fn read_u32_le(image: &[u8], off: usize, what: &'static str) -> Result<u32> {
    image[off..off + 4]
        .try_into()
        .map(u32::from_le_bytes)
        .map_err(|_| NaegiaPeError::InvalidPe(what))
}

fn read_section_row(image: &[u8], sh: usize) -> Result<SectionTableRow> {
    Ok(SectionTableRow {
        virtual_size: read_u32_le(image, sh + 8, "section virtual size")?,
        virtual_address: read_u32_le(image, sh + 12, "section virtual address")?,
        raw_size: read_u32_le(image, sh + 16, "section raw size")? as usize,
        raw_ptr: read_u32_le(image, sh + 20, "section raw pointer")? as usize,
        characteristics: read_u32_le(image, sh + 36, "section characteristics")?,
    })
}

fn validate_section_raw_bounds(image: &[u8], raw_ptr: usize, raw_sz: usize) -> Result<()> {
    if raw_sz == 0 {
        return Ok(());
    }
    let end = raw_ptr
        .checked_add(raw_sz)
        .ok_or(NaegiaPeError::InvalidPe("section raw overflow"))?;
    if end > image.len() {
        return Err(NaegiaPeError::InvalidPe("section raw data out of bounds"));
    }
    Ok(())
}

fn section_is_executable(characteristics: u32) -> bool {
    (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 || (characteristics & IMAGE_SCN_CNT_CODE) != 0
}

fn section_covers_rva(row: &SectionTableRow, rva: u32) -> bool {
    let span = row.virtual_size.max(row.raw_size as u32);
    rva >= row.virtual_address && rva < row.virtual_address.saturating_add(span)
}

fn entry_point_in_executable_section(
    image: &[u8],
    opt: usize,
    size_opt: usize,
    num_sections: usize,
) -> Result<()> {
    let ep = read_u32_le(image, opt + 16, "entry point read")?;
    if ep == 0 {
        return Ok(());
    }
    let mut ep_ok = false;
    for i in 0..num_sections {
        let sh = opt + size_opt + i * 40;
        let row = read_section_row(image, sh)?;
        validate_section_raw_bounds(image, row.raw_ptr, row.raw_size)?;
        if section_covers_rva(&row, ep) && section_is_executable(row.characteristics) {
            ep_ok = true;
        }
    }
    if ep_ok {
        Ok(())
    } else {
        Err(NaegiaPeError::InvalidPe(
            "AddressOfEntryPoint not in an executable section",
        ))
    }
}

fn validate_coff_and_section_table(image: &[u8], pe_off: usize) -> Result<(usize, usize, usize)> {
    if pe_off + 24 > image.len() || &image[pe_off..pe_off + 4] != b"PE\0\0" {
        return Err(NaegiaPeError::InvalidPe("invalid PE signature"));
    }
    let machine = u16::from_le_bytes([image[pe_off + 4], image[pe_off + 5]]);
    if machine != IMAGE_FILE_MACHINE_AMD64 {
        return Err(NaegiaPeError::InvalidPe(
            "expected AMD64 (PE32+) machine type",
        ));
    }
    let num_sections = u16::from_le_bytes([image[pe_off + 6], image[pe_off + 7]]) as usize;
    if num_sections > 100 {
        return Err(NaegiaPeError::InvalidPe("excessive section count"));
    }
    let size_opt = u16::from_le_bytes([image[pe_off + 20], image[pe_off + 21]]) as usize;
    let opt = pe_optional_header_raw_offset(image)?;
    if opt + 2 > image.len() {
        return Err(NaegiaPeError::InvalidPe("optional header truncated"));
    }
    let magic = u16::from_le_bytes([image[opt], image[opt + 1]]);
    if magic != PE32_PLUS_MAGIC {
        return Err(NaegiaPeError::InvalidPe(
            "expected PE32+ optional header magic (0x20B)",
        ));
    }
    let table_end = opt
        .checked_add(size_opt)
        .and_then(|o| o.checked_add(num_sections.checked_mul(40)?))
        .ok_or(NaegiaPeError::InvalidPe("section table overflow"))?;
    if table_end > image.len() {
        return Err(NaegiaPeError::InvalidPe("section headers out of bounds"));
    }
    Ok((opt, size_opt, num_sections))
}

/// Header/section layout checks without relying on goblin string/import parsing.
pub fn validate_pe64_structural(image: &[u8]) -> Result<()> {
    ensure_image_fits(image.len())?;
    if image.len() < 64 {
        return Err(NaegiaPeError::InvalidPe("image too small"));
    }
    if image[0] != b'M' || image[1] != b'Z' {
        return Err(NaegiaPeError::InvalidPe("missing MZ signature"));
    }
    let pe_off = pe_signature_offset(image)?;
    let (opt, size_opt, num_sections) = validate_coff_and_section_table(image, pe_off)?;
    entry_point_in_executable_section(image, opt, size_opt, num_sections)
}

/// Prefer full goblin validation; fall back to structural checks when content parsing fails.
pub fn validate_pe64_after_transform(image: &[u8]) -> Result<()> {
    match parse_and_validate_pe64(image) {
        Ok(_) => Ok(()),
        Err(NaegiaPeError::Parse(_)) => validate_pe64_structural(image),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_image_fits_rejects_over_limit() {
        assert!(ensure_image_fits(MAX_INPUT_BYTES + 1).is_err());
        assert!(ensure_image_fits(MAX_INPUT_BYTES).is_ok());
    }
}
