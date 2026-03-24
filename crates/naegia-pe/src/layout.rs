//! PE32+ layout constants aligned with Microsoft PE specification.

/// `IMAGE_NT_OPTIONAL_HDR64_MAGIC`
pub const PE32_PLUS_MAGIC: u16 = 0x20B;

/// `IMAGE_FILE_MACHINE_AMD64`
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

/// `IMAGE_DIRECTORY_ENTRY_DEBUG`
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;

/// `IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT`
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;

/// Offset of `NumberOfRvaAndSizes` from the start of the optional header (PE32+).
pub const PE32_PLUS_NUMBER_OF_RVA_AND_SIZES_OFFSET: usize = 108;

/// Offset of the first `IMAGE_DATA_DIRECTORY` entry from the start of the optional header (PE32+).
pub const PE32_PLUS_DATA_DIRECTORIES_OFFSET: usize = PE32_PLUS_NUMBER_OF_RVA_AND_SIZES_OFFSET + 4;

/// Offset of `CheckSum` in the optional header (same for PE32 and PE32+ Windows-specific block).
pub const OPTIONAL_HEADER_CHECKSUM_OFFSET: usize = 64;
