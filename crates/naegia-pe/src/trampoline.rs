//! Entry redirection through a code cave (executable section padding).
//!
//! Emits x64: optional anti-debug preamble + `jmp rel32` to the original entry RVA.
//! The anti-debug preamble uses a register index chosen by the obfuscation seed to avoid
//! a fixed byte signature.

use goblin::pe::section_table::SectionTable;

use crate::error::{NaegiaPeError, Result};
use crate::layout::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, PE32_PLUS_MAGIC};
use crate::raw::pe_optional_header_raw_offset;

/// `AddressOfEntryPoint` offset from the start of the PE32+ optional header.
const OPTIONAL_ENTRY_POINT_RVA_OFFSET: usize = 16;

/// Pre-assembled anti-debug preamble variants, each using a different scratch register.
///
/// Each variant:
///   1. Loads PEB (`gs:[0x60]`) into the chosen register
///   2. Zero-extends `PEB.BeingDebugged` (byte at offset 2) into eax
///   3. Tests eax
///   4. Jumps over the spin loop if zero (no debugger)
///   5. Spins infinitely (jmp $) if debugger detected
///
/// The variant is selected at trampoline-assembly time so no two protected binaries
/// share the same anti-debug byte sequence.
static ANTI_DEBUG_PREAMBLES: &[&[u8]] = &[
    // rax
    &[
        0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, //
        0x0f, 0xb6, 0x40, 0x02, //
        0x85, 0xc0, 0x74, 0x02, 0xeb, 0xfe,
    ],
    // rcx
    &[
        0x65, 0x48, 0x8b, 0x0c, 0x25, 0x60, 0x00, 0x00, 0x00, //
        0x0f, 0xb6, 0x41, 0x02, //
        0x85, 0xc0, 0x74, 0x02, 0xeb, 0xfe,
    ],
    // rdx
    &[
        0x65, 0x48, 0x8b, 0x14, 0x25, 0x60, 0x00, 0x00, 0x00, //
        0x0f, 0xb6, 0x42, 0x02, //
        0x85, 0xc0, 0x74, 0x02, 0xeb, 0xfe,
    ],
    // rbx
    &[
        0x65, 0x48, 0x8b, 0x1c, 0x25, 0x60, 0x00, 0x00, 0x00, //
        0x0f, 0xb6, 0x43, 0x02, //
        0x85, 0xc0, 0x74, 0x02, 0xeb, 0xfe,
    ],
    // r8  (REX.B prefix needed)
    &[
        0x65, 0x4c, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, //
        0x41, 0x0f, 0xb6, 0x40, 0x02, //
        0x85, 0xc0, 0x74, 0x02, 0xeb, 0xfe,
    ],
    // r9
    &[
        0x65, 0x4c, 0x8b, 0x0c, 0x25, 0x60, 0x00, 0x00, 0x00, //
        0x41, 0x0f, 0xb6, 0x41, 0x02, //
        0x85, 0xc0, 0x74, 0x02, 0xeb, 0xfe,
    ],
    // r10
    &[
        0x65, 0x4c, 0x8b, 0x14, 0x25, 0x60, 0x00, 0x00, 0x00, //
        0x41, 0x0f, 0xb6, 0x42, 0x02, //
        0x85, 0xc0, 0x74, 0x02, 0xeb, 0xfe,
    ],
    // r11
    &[
        0x65, 0x4c, 0x8b, 0x1c, 0x25, 0x60, 0x00, 0x00, 0x00, //
        0x41, 0x0f, 0xb6, 0x43, 0x02, //
        0x85, 0xc0, 0x74, 0x02, 0xeb, 0xfe,
    ],
];

fn section_is_executable(c: u32) -> bool {
    (c & IMAGE_SCN_MEM_EXECUTE) != 0 || (c & IMAGE_SCN_CNT_CODE) != 0
}

/// Returns `Some(Ok((file_offset, rva)))` if `sec` contains a cave of `need_len` zero/CC bytes.
/// Scan `sec` for a contiguous block of zero (`0x00`) or int3 (`0xCC`) bytes of
/// at least `need_len`.
///
/// Search direction: **reverse** (end → start).  This finds the *last* cave in
/// the section rather than the first, which reduces the chance that the cave
/// overlaps with header-like content near the beginning of `.text`.  The
/// trampoline stub is written at the cave location; as long as the bytes are
/// truly padding (zero / int3), any valid offset works.
///
/// Returns `None` when the section's raw data extends past the end of the
/// image (treated as a non-fatal skip — `find_executable_cave` will try the
/// next section or fail with a clear error if no section has room).
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

fn assemble_plain_trampoline(orig_ep_rva: u32, cave_rva: u32) -> Result<Vec<u8>> {
    let jmp_from = cave_rva.saturating_add(5);
    // jmp rel32 has a ±2 GiB range; verify we stay within it
    let diff = orig_ep_rva.abs_diff(jmp_from);
    if diff > 0x7FFF_FFFF {
        return Err(NaegiaPeError::InvalidPe(
            "entry redirect target out of jmp rel32 range (±2 GiB)",
        ));
    }
    let rel = orig_ep_rva as i32 - jmp_from as i32;
    let mut code = vec![0xE9u8];
    code.extend_from_slice(&rel.to_le_bytes());
    Ok(code)
}

fn assemble_anti_debug_trampoline(orig_ep_rva: u32, cave_rva: u32, seed: u64) -> Result<Vec<u8>> {
    // Select anti-debug preamble variant based on seed so no two protected binaries
    // share the same preamble byte sequence.
    let preamble = ANTI_DEBUG_PREAMBLES[seed as usize % ANTI_DEBUG_PREAMBLES.len()];
    let jmp_off = (preamble.len() as u32).saturating_add(5);
    let jmp_from = cave_rva.saturating_add(jmp_off);
    let diff = orig_ep_rva.abs_diff(jmp_from);
    if diff > 0x7FFF_FFFF {
        return Err(NaegiaPeError::InvalidPe(
            "anti-debug entry redirect target out of jmp rel32 range (±2 GiB)",
        ));
    }
    let mut code = preamble.to_vec();
    let rel = orig_ep_rva as i32 - jmp_from as i32;
    code.push(0xE9);
    code.extend_from_slice(&rel.to_le_bytes());
    Ok(code)
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
    let stub = assemble_plain_trampoline(orig_ep, cave_rva)?;
    write_entry_stub_at(image, opt, fo, cave_rva, &stub)?;
    Ok((orig_ep, cave_rva))
}

/// Patch `image`: write anti-debug preamble + `jmp rel32` at a code cave and redirect the EP.
/// The anti-debug variant is selected by `seed` to vary the byte signature.
pub fn redirect_entry_with_anti_debug(
    image: &mut [u8],
    sections: &[SectionTable],
    seed: u64,
) -> Result<(u32, u32)> {
    let (opt, orig_ep) = read_validated_entry_point(image)?;
    // Use the longest preamble for cave-size calculation (all variants are the same length).
    let preamble_len = ANTI_DEBUG_PREAMBLES
        .iter()
        .map(|p| p.len())
        .max()
        .unwrap_or(19);
    let need = preamble_len + 5;
    let (fo, cave_rva) = find_executable_cave(image, sections, need)?;
    let stub = assemble_anti_debug_trampoline(orig_ep, cave_rva, seed)?;
    write_entry_stub_at(image, opt, fo, cave_rva, &stub)?;
    Ok((orig_ep, cave_rva))
}
