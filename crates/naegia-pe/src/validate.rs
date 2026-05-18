use goblin::pe::PE;

use crate::error::{NaegiaPeError, Result};
use crate::layout::{
    IMAGE_FILE_MACHINE_AMD64, IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, PE32_PLUS_MAGIC,
};
use crate::raw::{pe_optional_header_raw_offset, pe_signature_offset};

/// Parses and validates a PE32+ (AMD64) executable image suitable for NAEGIA processing.
pub fn parse_and_validate_pe64(image: &[u8]) -> Result<PE<'_>> {
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

/// Header/section layout checks without relying on goblin string/import parsing.
pub fn validate_pe64_structural(image: &[u8]) -> Result<()> {
    if image.len() < 64 {
        return Err(NaegiaPeError::InvalidPe("image too small"));
    }
    if image[0] != b'M' || image[1] != b'Z' {
        return Err(NaegiaPeError::InvalidPe("missing MZ signature"));
    }
    let pe_off = pe_signature_offset(image)?;
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

    let ep = u32::from_le_bytes(
        image[opt + 16..opt + 20]
            .try_into()
            .map_err(|_| NaegiaPeError::InvalidPe("entry point read"))?,
    );
    let mut ep_ok = ep == 0;
    for i in 0..num_sections {
        let sh = opt + size_opt + i * 40;
        let va = u32::from_le_bytes(image[sh + 12..sh + 16].try_into().unwrap());
        let vs = u32::from_le_bytes(image[sh + 8..sh + 12].try_into().unwrap());
        let raw_ptr = u32::from_le_bytes(image[sh + 20..sh + 24].try_into().unwrap()) as usize;
        let raw_sz = u32::from_le_bytes(image[sh + 16..sh + 20].try_into().unwrap()) as usize;
        let ch = u32::from_le_bytes(image[sh + 36..sh + 40].try_into().unwrap());
        if raw_sz > 0 {
            let end = raw_ptr
                .checked_add(raw_sz)
                .ok_or(NaegiaPeError::InvalidPe("section raw overflow"))?;
            if end > image.len() {
                return Err(NaegiaPeError::InvalidPe("section raw data out of bounds"));
            }
        }
        let span = vs.max(u32::from_le_bytes(
            image[sh + 16..sh + 20].try_into().unwrap(),
        ));
        if ep >= va && ep < va.saturating_add(span) {
            let exec = (ch & IMAGE_SCN_MEM_EXECUTE) != 0 || (ch & IMAGE_SCN_CNT_CODE) != 0;
            if exec {
                ep_ok = true;
            }
        }
    }
    if !ep_ok {
        return Err(NaegiaPeError::InvalidPe(
            "AddressOfEntryPoint not in an executable section",
        ));
    }
    Ok(())
}

/// Prefer full goblin validation; fall back to structural checks when content parsing fails.
pub fn validate_pe64_after_transform(image: &[u8]) -> Result<()> {
    match parse_and_validate_pe64(image) {
        Ok(_) => Ok(()),
        Err(NaegiaPeError::Parse(_)) => validate_pe64_structural(image),
        Err(e) => Err(e),
    }
}
