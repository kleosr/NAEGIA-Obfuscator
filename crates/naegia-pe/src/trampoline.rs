//! Entry redirection through padding caves: two-hop `jmp rel32` chains and layered anti-debug.

use goblin::pe::section_table::SectionTable;

use crate::error::{NaegiaPeError, Result};
use crate::layout::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, PE32_PLUS_MAGIC};
use crate::raw::pe_optional_header_raw_offset;

const OPTIONAL_ENTRY_POINT_RVA_OFFSET: usize = 16;

/// Anti-debug preludes: `PEB.BeingDebugged`, register variants.
static ANTI_DEBUG_PREAMBLES: &[&[u8]] = &[
    &[
        0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x0f, 0xb6, 0x40, 0x02, 0x85, 0xc0,
        0x74, 0x02, 0xeb, 0xfe,
    ],
    &[
        0x65, 0x48, 0x8b, 0x0c, 0x25, 0x60, 0x00, 0x00, 0x00, 0x0f, 0xb6, 0x41, 0x02, 0x85, 0xc0,
        0x74, 0x02, 0xeb, 0xfe,
    ],
    &[
        0x65, 0x48, 0x8b, 0x14, 0x25, 0x60, 0x00, 0x00, 0x00, 0x0f, 0xb6, 0x42, 0x02, 0x85, 0xc0,
        0x74, 0x02, 0xeb, 0xfe,
    ],
    &[
        0x65, 0x48, 0x8b, 0x1c, 0x25, 0x60, 0x00, 0x00, 0x00, 0x0f, 0xb6, 0x43, 0x02, 0x85, 0xc0,
        0x74, 0x02, 0xeb, 0xfe,
    ],
    &[
        0x65, 0x4c, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x41, 0x0f, 0xb6, 0x40, 0x02, 0x85,
        0xc0, 0x74, 0x02, 0xeb, 0xfe,
    ],
    &[
        0x65, 0x4c, 0x8b, 0x0c, 0x25, 0x60, 0x00, 0x00, 0x00, 0x41, 0x0f, 0xb6, 0x41, 0x02, 0x85,
        0xc0, 0x74, 0x02, 0xeb, 0xfe,
    ],
    &[
        0x65, 0x4c, 0x8b, 0x14, 0x25, 0x60, 0x00, 0x00, 0x00, 0x41, 0x0f, 0xb6, 0x42, 0x02, 0x85,
        0xc0, 0x74, 0x02, 0xeb, 0xfe,
    ],
    &[
        0x65, 0x4c, 0x8b, 0x1c, 0x25, 0x60, 0x00, 0x00, 0x00, 0x41, 0x0f, 0xb6, 0x43, 0x02, 0x85,
        0xc0, 0x74, 0x02, 0xeb, 0xfe,
    ],
];

fn section_is_executable(c: u32) -> bool {
    (c & IMAGE_SCN_MEM_EXECUTE) != 0 || (c & IMAGE_SCN_CNT_CODE) != 0
}

fn range_overlaps(fo: usize, len: usize, exclude: (usize, usize)) -> bool {
    let (ex_lo, ex_hi) = exclude;
    fo < ex_hi && fo.saturating_add(len) > ex_lo
}

fn search_section_for_cave(
    image: &[u8],
    sec: &SectionTable,
    need_len: usize,
    exclude: Option<(usize, usize)>,
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
        if !data[start..start + need_len]
            .iter()
            .all(|&b| b == 0 || b == 0xCC)
        {
            continue;
        }
        let fo = raw + start;
        if let Some(ex) = exclude {
            if range_overlaps(fo, need_len, ex) {
                continue;
            }
        }
        let rva = match sec.virtual_address.checked_add(start as u32) {
            Some(r) => r,
            None => return Some(Err(NaegiaPeError::InvalidPe("cave RVA overflow"))),
        };
        return Some(Ok((fo, rva)));
    }
    None
}

/// Find a padding cave, optionally avoiding a file range already used by another stub.
pub fn find_executable_cave(
    image: &[u8],
    sections: &[SectionTable],
    need_len: usize,
) -> Result<(usize, u32)> {
    find_executable_cave_excluding(image, sections, need_len, None)
}

pub fn find_executable_cave_excluding(
    image: &[u8],
    sections: &[SectionTable],
    need_len: usize,
    exclude: Option<(usize, usize)>,
) -> Result<(usize, u32)> {
    if need_len < 5 {
        return Err(NaegiaPeError::InvalidPe("cave too small for jmp"));
    }
    for sec in sections {
        if !section_is_executable(sec.characteristics) {
            continue;
        }
        if let Some(result) = search_section_for_cave(image, sec, need_len, exclude) {
            return result;
        }
    }
    Err(NaegiaPeError::InvalidPe(
        "no executable code cave (need larger .text padding or a custom build)",
    ))
}

fn assemble_jmp_rel32(from_rva: u32, to_rva: u32) -> Result<Vec<u8>> {
    let jmp_from = from_rva.saturating_add(5);
    if to_rva.abs_diff(jmp_from) > 0x7FFF_FFFF {
        return Err(NaegiaPeError::InvalidPe(
            "entry redirect target out of jmp rel32 range (±2 GiB)",
        ));
    }
    let rel = to_rva as i32 - jmp_from as i32;
    let mut code = vec![0xE9];
    code.extend_from_slice(&rel.to_le_bytes());
    Ok(code)
}

struct TwoHopCaves {
    fo_entry: usize,
    rva_entry: u32,
    fo_hop2: usize,
    rva_hop2: u32,
}

fn find_two_hop_caves(
    image: &[u8],
    sections: &[SectionTable],
    entry_stub_len: usize,
) -> Result<TwoHopCaves> {
    let (fo_entry, rva_entry) = find_executable_cave(image, sections, entry_stub_len)?;
    let exclude = (fo_entry, fo_entry + entry_stub_len);
    let (fo_hop2, rva_hop2) = find_executable_cave_excluding(image, sections, 5, Some(exclude))?;
    if fo_entry == fo_hop2 {
        return Err(NaegiaPeError::InvalidPe(
            "need two disjoint code caves for entry redirect",
        ));
    }
    Ok(TwoHopCaves {
        fo_entry,
        rva_entry,
        fo_hop2,
        rva_hop2,
    })
}

fn redirect_entry_single_hop(
    image: &mut [u8],
    opt: usize,
    orig_ep: u32,
    sections: &[SectionTable],
    entry_stub_len: usize,
    preamble: Option<&[u8]>,
) -> Result<(u32, u32)> {
    let (fo, rva) = find_executable_cave(image, sections, entry_stub_len)?;
    let stub = if let Some(pre) = preamble {
        let jmp_from = rva.saturating_add((pre.len() + 5) as u32);
        let mut code = pre.to_vec();
        let rel = orig_ep as i32 - jmp_from as i32;
        if orig_ep.abs_diff(jmp_from) > 0x7FFF_FFFF {
            return Err(NaegiaPeError::InvalidPe(
                "anti-debug entry redirect target out of jmp rel32 range (±2 GiB)",
            ));
        }
        code.push(0xE9);
        code.extend_from_slice(&rel.to_le_bytes());
        code
    } else {
        assemble_jmp_rel32(rva, orig_ep)?
    };
    write_entry_stub_at(image, opt, fo, rva, &stub)?;
    Ok((orig_ep, rva))
}

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
    entry_rva: u32,
    stub: &[u8],
) -> Result<()> {
    if fo + stub.len() > image.len() {
        return Err(NaegiaPeError::InvalidPe("cave write OOB"));
    }
    image[fo..fo + stub.len()].copy_from_slice(stub);
    image[opt + OPTIONAL_ENTRY_POINT_RVA_OFFSET..opt + OPTIONAL_ENTRY_POINT_RVA_OFFSET + 4]
        .copy_from_slice(&entry_rva.to_le_bytes());
    Ok(())
}

fn write_stub_at_offset(image: &mut [u8], fo: usize, stub: &[u8]) -> Result<()> {
    if fo + stub.len() > image.len() {
        return Err(NaegiaPeError::InvalidPe("cave write OOB"));
    }
    image[fo..fo + stub.len()].copy_from_slice(stub);
    Ok(())
}

fn assemble_entry_stub_to_hop2(
    preamble: Option<&[u8]>,
    entry_rva: u32,
    hop2_rva: u32,
) -> Result<Vec<u8>> {
    let pre_len = preamble.map(|p| p.len()).unwrap_or(0);
    let jmp_from = entry_rva.saturating_add((pre_len + 5) as u32);
    let mut code = preamble.map(|p| p.to_vec()).unwrap_or_default();
    let rel = hop2_rva as i32 - jmp_from as i32;
    if hop2_rva.abs_diff(jmp_from) > 0x7FFF_FFFF {
        return Err(NaegiaPeError::InvalidPe(
            "hop2 target out of jmp rel32 range (±2 GiB)",
        ));
    }
    code.push(0xE9);
    code.extend_from_slice(&rel.to_le_bytes());
    Ok(code)
}

/// Entry redirect: prefers EP → cave₁ → cave₂ → original EP; falls back to a single hop.
pub fn redirect_entry_plain(image: &mut [u8], sections: &[SectionTable]) -> Result<(u32, u32)> {
    let (opt, orig_ep) = read_validated_entry_point(image)?;
    if let Ok(caves) = find_two_hop_caves(image, sections, 5) {
        let stub_entry = assemble_entry_stub_to_hop2(None, caves.rva_entry, caves.rva_hop2)?;
        let stub_hop2 = assemble_jmp_rel32(caves.rva_hop2, orig_ep)?;
        write_stub_at_offset(image, caves.fo_hop2, &stub_hop2)?;
        write_entry_stub_at(image, opt, caves.fo_entry, caves.rva_entry, &stub_entry)?;
        return Ok((orig_ep, caves.rva_entry));
    }
    redirect_entry_single_hop(image, opt, orig_ep, sections, 5, None)
}

/// Entry redirect with anti-debug preamble; two-hop when padding allows.
pub fn redirect_entry_with_anti_debug(
    image: &mut [u8],
    sections: &[SectionTable],
    seed: u64,
) -> Result<(u32, u32)> {
    let (opt, orig_ep) = read_validated_entry_point(image)?;
    let preamble = ANTI_DEBUG_PREAMBLES[seed as usize % ANTI_DEBUG_PREAMBLES.len()];
    let entry_len = preamble.len() + 5;
    if let Ok(caves) = find_two_hop_caves(image, sections, entry_len) {
        let stub_entry =
            assemble_entry_stub_to_hop2(Some(preamble), caves.rva_entry, caves.rva_hop2)?;
        let stub_hop2 = assemble_jmp_rel32(caves.rva_hop2, orig_ep)?;
        write_stub_at_offset(image, caves.fo_hop2, &stub_hop2)?;
        write_entry_stub_at(image, opt, caves.fo_entry, caves.rva_entry, &stub_entry)?;
        return Ok((orig_ep, caves.rva_entry));
    }
    redirect_entry_single_hop(image, opt, orig_ep, sections, entry_len, Some(preamble))
}
