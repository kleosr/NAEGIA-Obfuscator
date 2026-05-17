use crate::error::{NaegiaPeError, Result};
use crate::layout::{
    IMAGE_DIRECTORY_ENTRY_DEBUG, OPTIONAL_HEADER_CHECKSUM_OFFSET,
    PE32_PLUS_DATA_DIRECTORIES_OFFSET, PE32_PLUS_MAGIC,
};

/// File offset of the `PE\0\0` signature (start of `IMAGE_NT_HEADERS`).
pub fn pe_signature_offset(image: &[u8]) -> Result<usize> {
    if image.len() < 0x40 {
        return Err(NaegiaPeError::InvalidPe("image too small for DOS header"));
    }
    let pe_off = u32::from_le_bytes(
        image[0x3c..0x40]
            .try_into()
            .expect("slice is exactly 4 bytes after len >= 0x40 check"),
    ) as usize;
    if pe_off + 24 > image.len() {
        return Err(NaegiaPeError::InvalidPe("invalid e_lfanew"));
    }
    Ok(pe_off)
}

/// File offset of the PE optional header (COFF optional header), after `IMAGE_NT_HEADERS`.
pub fn pe_optional_header_raw_offset(image: &[u8]) -> Result<usize> {
    pe_signature_offset(image).map(|off| off + 4 + 20)
}

/// File offset of the PE `CheckSum` field inside the optional header.
pub fn pe_checksum_field_offset(image: &[u8]) -> Result<usize> {
    let opt = pe_optional_header_raw_offset(image)?;
    let off = opt + OPTIONAL_HEADER_CHECKSUM_OFFSET;
    if off + 4 > image.len() {
        return Err(NaegiaPeError::InvalidPe("checksum field out of bounds"));
    }
    Ok(off)
}

/// RVA and size of the Debug data directory entry (`IMAGE_DIRECTORY_ENTRY_DEBUG`).
pub fn debug_data_directory_entry(image: &[u8]) -> Result<(u32, u32)> {
    let opt = pe_optional_header_raw_offset(image)?;
    if opt + 2 > image.len() {
        return Err(NaegiaPeError::InvalidPe("optional header truncated"));
    }
    let magic = u16::from_le_bytes([image[opt], image[opt + 1]]);
    if magic != PE32_PLUS_MAGIC {
        return Err(NaegiaPeError::InvalidPe("optional header magic mismatch"));
    }
    let dir_off = opt + PE32_PLUS_DATA_DIRECTORIES_OFFSET + IMAGE_DIRECTORY_ENTRY_DEBUG * 8;
    if dir_off + 8 > image.len() {
        return Err(NaegiaPeError::InvalidPe(
            "debug data directory out of bounds",
        ));
    }
    let rva = u32::from_le_bytes(
        image[dir_off..dir_off + 4]
            .try_into()
            .expect("slice is exactly 4 bytes after bounds check"),
    );
    let size = u32::from_le_bytes(
        image[dir_off + 4..dir_off + 8]
            .try_into()
            .expect("slice is exactly 4 bytes after bounds check"),
    );
    Ok((rva, size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_header_offset_rejects_truncated_image() {
        assert!(pe_optional_header_raw_offset(&[0u8; 16]).is_err());
    }
}
