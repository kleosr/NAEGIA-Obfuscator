//! Entry redirection through a code cave (executable section padding).
//!
//! Emits x64: optional anti-debug preamble + `jmp rel32` to the original entry RVA.

use goblin::pe::section_table::SectionTable;

use crate::error::{NaegiaPeError, Result};
use crate::layout::PE32_PLUS_MAGIC;
use crate::raw::pe_optional_header_raw_offset;

const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// `AddressOfEntryPoint` offset from the start of the PE32+ optional header.
const OPTIONAL_ENTRY_POINT_RVA_OFFSET: usize = 16;

static ANTI_DEBUG_PREAMBLE: &[u8] = &[
    0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, // mov rax, gs:[0x60]
    0x0f, 0xb6, 0x40, 0x02, // movzx eax, byte [rax+2]  ; BeingDebugged
    0x85, 0xc0, // test eax, eax
    0x74, 0x02, // jz +2
    0xeb, 0xfe, // jmp $ (spin if debugger)
];

fn section_is_executable(c: u32) -> bool {
    (c & IMAGE_SCN_MEM_EXECUTE) != 0 || (c & IMAGE_SCN_CNT_CODE) != 0
}

fn trampoline_len(anti_debug: bool) -> usize {
    (if anti_debug {
        ANTI_DEBUG_PREAMBLE.len()
    } else {
        0
    }) + 5
}

/// Returns `(file_offset, rva)` of a cave with at least `need_len` bytes of 0x00 or 0xCC.
pub fn find_executable_cave(
    image: &[u8],
    sections: &[SectionTable],
    need_len: usize,
) -> Result<(usize, u32)> {
    if need_len < 5 {
        return Err(NaegiaPeError::InvalidPe("cave too small for jmp"));
    }
    for sec in sections {
        if !section_is_executable(sec.characteristics) {
            continue;
        }
        let raw = sec.pointer_to_raw_data as usize;
        let sz = sec.size_of_raw_data as usize;
        if raw + sz > image.len() {
            continue;
        }
        let data = &image[raw..raw + sz];
        if data.len() < need_len {
            continue;
        }
        for start in (0..=data.len() - need_len).rev() {
            if data[start..start + need_len]
                .iter()
                .all(|&b| b == 0 || b == 0xCC)
            {
                let fo = raw + start;
                let rva = sec
                    .virtual_address
                    .checked_add(start as u32)
                    .ok_or(NaegiaPeError::InvalidPe("cave RVA overflow"))?;
                return Ok((fo, rva));
            }
        }
    }
    Err(NaegiaPeError::InvalidPe(
        "no executable code cave (need larger .text padding or a custom build)",
    ))
}

fn assemble_trampoline(orig_ep_rva: u32, cave_rva: u32, anti_debug: bool) -> Vec<u8> {
    let mut code = Vec::new();
    if anti_debug {
        code.extend_from_slice(ANTI_DEBUG_PREAMBLE);
    }
    let jmp_from = cave_rva.saturating_add(code.len() as u32).saturating_add(5);
    let rel = orig_ep_rva as i32 - jmp_from as i32;
    code.push(0xE9);
    code.extend_from_slice(&rel.to_le_bytes());
    code
}

/// Patch `image` in place: write trampoline at a cave and point the optional header EP at `cave_rva`.
pub fn redirect_entry_through_cave(
    image: &mut [u8],
    sections: &[SectionTable],
    anti_debug: bool,
) -> Result<(u32, u32)> {
    let opt = pe_optional_header_raw_offset(image)?;
    if opt + 24 > image.len() {
        return Err(NaegiaPeError::InvalidPe("optional header"));
    }
    let magic = u16::from_le_bytes([image[opt], image[opt + 1]]);
    if magic != PE32_PLUS_MAGIC {
        return Err(NaegiaPeError::InvalidPe("not PE32+"));
    }
    let orig_ep = u32::from_le_bytes(
        image[opt + OPTIONAL_ENTRY_POINT_RVA_OFFSET..opt + OPTIONAL_ENTRY_POINT_RVA_OFFSET + 4]
            .try_into()
            .map_err(|_| NaegiaPeError::InvalidPe("entry read"))?,
    );
    let need = trampoline_len(anti_debug);
    let (fo, cave_rva) = find_executable_cave(image, sections, need)?;
    let stub = assemble_trampoline(orig_ep, cave_rva, anti_debug);
    debug_assert_eq!(stub.len(), need);
    if fo + stub.len() > image.len() {
        return Err(NaegiaPeError::InvalidPe("cave write OOB"));
    }
    image[fo..fo + stub.len()].copy_from_slice(&stub);
    image[opt + OPTIONAL_ENTRY_POINT_RVA_OFFSET..opt + OPTIONAL_ENTRY_POINT_RVA_OFFSET + 4]
        .copy_from_slice(&cave_rva.to_le_bytes());
    Ok((orig_ep, cave_rva))
}
