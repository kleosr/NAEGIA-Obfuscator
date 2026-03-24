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

/// Returns `Some(Ok((file_offset, rva)))` if `sec` contains a cave of `need_len` zero/CC bytes.
fn search_section_for_cave(
    image: &[u8],
    sec: &SectionTable,
    need_len: usize,
) -> Option<Result<(usize, u32)>> {
    let raw = sec.pointer_to_raw_data as usize;
    let sz = sec.size_of_raw_data as usize;
    if raw + sz > image.len() {
        return None;
    }
    let data = &image[raw..raw + sz];
    if data.len() < need_len {
        return None;
    }
    for start in (0..=data.len() - need_len).rev() {
        if data[start..start + need_len]
            .iter()
            .all(|&b| b == 0 || b == 0xCC)
        {
            let fo = raw + start;
            let rva = match sec.virtual_address.checked_add(start as u32) {
                Some(r) => r,
                None => return Some(Err(NaegiaPeError::InvalidPe("cave RVA overflow"))),
            };
            return Some(Ok((fo, rva)));
        }
    }
    None
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
        if let Some(result) = search_section_for_cave(image, sec, need_len) {
            return result;
        }
    }
    Err(NaegiaPeError::InvalidPe(
        "no executable code cave (need larger .text padding or a custom build)",
    ))
}

fn assemble_plain_trampoline(orig_ep_rva: u32, cave_rva: u32) -> Vec<u8> {
    let jmp_from = cave_rva.saturating_add(5);
    let rel = orig_ep_rva as i32 - jmp_from as i32;
    let mut code = vec![0xE9u8];
    code.extend_from_slice(&rel.to_le_bytes());
    code
}

fn assemble_anti_debug_trampoline(orig_ep_rva: u32, cave_rva: u32) -> Vec<u8> {
    let mut code = ANTI_DEBUG_PREAMBLE.to_vec();
    let jmp_from = cave_rva
        .saturating_add(ANTI_DEBUG_PREAMBLE.len() as u32)
        .saturating_add(5);
    let rel = orig_ep_rva as i32 - jmp_from as i32;
    code.push(0xE9);
    code.extend_from_slice(&rel.to_le_bytes());
    code
}

/// Returns `(opt_header_offset, orig_ep_rva)` after validating the PE32+ optional header.
fn read_validated_entry_point(image: &[u8]) -> Result<(usize, u32)> {
    let opt = pe_optional_header_raw_offset(image)?;
    if opt + 24 > image.len() {
        return Err(NaegiaPeError::InvalidPe("optional header"));
    }
    let magic = u16::from_le_bytes([image[opt], image[opt + 1]]);
    if magic != PE32_PLUS_MAGIC {
        return Err(NaegiaPeError::InvalidPe("not PE32+"));
    }
    let ep_bytes = image
        [opt + OPTIONAL_ENTRY_POINT_RVA_OFFSET..opt + OPTIONAL_ENTRY_POINT_RVA_OFFSET + 4]
        .try_into()
        .map_err(|_| NaegiaPeError::InvalidPe("entry read"))?;
    Ok((opt, u32::from_le_bytes(ep_bytes)))
}

fn write_entry_stub_at(
    image: &mut [u8],
    opt: usize,
    fo: usize,
    cave_rva: u32,
    stub: &[u8],
) -> Result<()> {
    if fo + stub.len() > image.len() {
        return Err(NaegiaPeError::InvalidPe("cave write OOB"));
    }
    image[fo..fo + stub.len()].copy_from_slice(stub);
    image[opt + OPTIONAL_ENTRY_POINT_RVA_OFFSET..opt + OPTIONAL_ENTRY_POINT_RVA_OFFSET + 4]
        .copy_from_slice(&cave_rva.to_le_bytes());
    Ok(())
}

/// Patch `image`: write a plain `jmp rel32` trampoline at a code cave and redirect the EP.
pub fn redirect_entry_plain(image: &mut [u8], sections: &[SectionTable]) -> Result<(u32, u32)> {
    let (opt, orig_ep) = read_validated_entry_point(image)?;
    let (fo, cave_rva) = find_executable_cave(image, sections, 5)?;
    let stub = assemble_plain_trampoline(orig_ep, cave_rva);
    write_entry_stub_at(image, opt, fo, cave_rva, &stub)?;
    Ok((orig_ep, cave_rva))
}

/// Patch `image`: write anti-debug preamble + `jmp rel32` at a code cave and redirect the EP.
pub fn redirect_entry_with_anti_debug(
    image: &mut [u8],
    sections: &[SectionTable],
) -> Result<(u32, u32)> {
    let (opt, orig_ep) = read_validated_entry_point(image)?;
    let need = ANTI_DEBUG_PREAMBLE.len() + 5;
    let (fo, cave_rva) = find_executable_cave(image, sections, need)?;
    let stub = assemble_anti_debug_trampoline(orig_ep, cave_rva);
    write_entry_stub_at(image, opt, fo, cave_rva, &stub)?;
    Ok((orig_ep, cave_rva))
}
