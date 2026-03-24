use goblin::pe::PE;

use crate::error::{NaegiaPeError, Result};
use crate::layout::{IMAGE_FILE_MACHINE_AMD64, PE32_PLUS_MAGIC};

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
