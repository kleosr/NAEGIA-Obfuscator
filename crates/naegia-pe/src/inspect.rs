//! Read-only PE inspection for CLI / tooling.

use crate::error::{NaegiaPeError, Result};
use crate::imports::import_dll_names;
use crate::layout::IMAGE_DIRECTORY_ENTRY_SECURITY;
use crate::raw::{debug_data_directory_entry, pe_optional_header_raw_offset};
use crate::validate::parse_and_validate_pe64;

/// Summary of PE layout relevant to NAEGIA transforms.
#[derive(Debug, Clone)]
pub struct PeInspectReport {
    /// COFF machine type (e.g. AMD64).
    pub machine: String,
    /// `AddressOfEntryPoint` RVA.
    pub entry_rva: u32,
    /// `(name, virtual_address, virtual_size)` per section.
    pub sections: Vec<(String, u32, u32)>,
    /// Sorted unique import DLLs.
    pub import_dlls: Vec<String>,
    /// Debug data directory has non-zero RVA/size.
    pub debug_directory_set: bool,
    /// Certificate directory present (Authenticode likely — avoid overlay).
    pub authenticode_likely: bool,
    /// On-disk file size in bytes.
    pub file_len: usize,
}

impl PeInspectReport {
    /// Parse and build a report for `image`.
    pub fn from_image(image: &[u8]) -> Result<Self> {
        let pe = parse_and_validate_pe64(image)?;
        let opt = pe
            .header
            .optional_header
            .as_ref()
            .ok_or(NaegiaPeError::InvalidPe("missing optional header"))?;

        let cert = security_directory_entry(image)?;
        let (dbg_rva, dbg_sz) = debug_data_directory_entry(image).unwrap_or((0, 0));

        let sections = pe
            .sections
            .iter()
            .map(|s| {
                let name = String::from_utf8_lossy(&s.name)
                    .trim_end_matches('\0')
                    .to_string();
                (name, s.virtual_address, s.virtual_size)
            })
            .collect();

        Ok(Self {
            machine: format!("0x{:04X}", pe.header.coff_header.machine),
            entry_rva: opt.standard_fields.address_of_entry_point as u32,
            sections,
            import_dlls: import_dll_names(&pe),
            debug_directory_set: dbg_rva != 0 || dbg_sz != 0,
            authenticode_likely: cert.0 != 0 && cert.1 != 0,
            file_len: image.len(),
        })
    }

    /// Human-readable multi-line summary.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("machine:       {}\n", self.machine));
        out.push_str(&format!("entry_rva:     0x{:X}\n", self.entry_rva));
        out.push_str(&format!("file_size:     {} bytes\n", self.file_len));
        out.push_str(&format!(
            "debug_dir:     {}\n",
            if self.debug_directory_set {
                "present"
            } else {
                "cleared/absent"
            }
        ));
        out.push_str(&format!(
            "authenticode:  {}\n",
            if self.authenticode_likely {
                "likely (do not append overlay)"
            } else {
                "not detected"
            }
        ));
        out.push_str(&format!("imports ({}):\n", self.import_dlls.len()));
        for dll in &self.import_dlls {
            out.push_str(&format!("  - {dll}\n"));
        }
        out.push_str(&format!("sections ({}):\n", self.sections.len()));
        for (name, va, vs) in &self.sections {
            out.push_str(&format!("  - {name:<10} VA=0x{va:X} VS=0x{vs:X}\n"));
        }
        out
    }
}

fn security_directory_entry(image: &[u8]) -> Result<(u32, u32)> {
    let opt = pe_optional_header_raw_offset(image)?;
    let dir_off =
        opt + crate::layout::PE32_PLUS_DATA_DIRECTORIES_OFFSET + IMAGE_DIRECTORY_ENTRY_SECURITY * 8;
    if dir_off + 8 > image.len() {
        return Err(NaegiaPeError::InvalidPe(
            "security data directory out of bounds",
        ));
    }
    let rva = u32::from_le_bytes(image[dir_off..dir_off + 4].try_into().unwrap());
    let size = u32::from_le_bytes(image[dir_off + 4..dir_off + 8].try_into().unwrap());
    Ok((rva, size))
}
