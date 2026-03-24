//! PE image checksum per Windows loader conventions (see PE optional header `CheckSum`).

use crate::error::Result;
use crate::raw::pe_checksum_field_offset;

/// Computes the PE checksum for `image`, skipping the checksum field in the optional header.
pub fn compute_pe_checksum(image: &[u8]) -> Result<u32> {
    let checksum_field = pe_checksum_field_offset(image)?;

    let mut sum = 0u64;
    let mut i = 0usize;
    while i < image.len() {
        if i == checksum_field {
            i += 4;
            continue;
        }
        let word = if i + 1 < image.len() {
            u16::from_le_bytes([image[i], image[i + 1]]) as u64
        } else {
            image[i] as u64
        };
        sum += word;
        sum = (sum & 0xffff) + (sum >> 16);
        i += 2;
    }
    sum += image.len() as u64;
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    Ok(sum as u32)
}

/// Writes the computed checksum into `image` at the optional header `CheckSum` field.
pub fn write_pe_checksum(image: &mut [u8]) -> Result<()> {
    let checksum_field = pe_checksum_field_offset(image)?;
    let value = compute_pe_checksum(image)?;
    image[checksum_field..checksum_field + 4].copy_from_slice(&value.to_le_bytes());
    Ok(())
}
