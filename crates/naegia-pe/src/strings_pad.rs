//! Low-risk “string hiding” on disk: only XORs long runs of **0x00** inside `.rdata` raw data.
//! Real string encryption needs relocation / codegen awareness.

use goblin::pe::section_table::SectionTable;

use crate::error::Result;

fn section_name_str(s: &SectionTable) -> String {
    let end = s.name.iter().position(|&b| b == 0).unwrap_or(8);
    String::from_utf8_lossy(&s.name[..end]).into_owned()
}

/// XOR each byte in zero-only runs (min `min_run`) inside sections whose name starts with `.rdata`.
pub fn xor_zero_runs_in_rdata(
    image: &mut [u8],
    sections: &[SectionTable],
    seed: u64,
) -> Result<usize> {
    let mut changed = 0usize;
    for sec in sections {
        if !section_name_str(sec).starts_with(".rdata") {
            continue;
        }
        let raw = sec.pointer_to_raw_data as usize;
        let sz = sec.size_of_raw_data as usize;
        if raw.saturating_add(sz) > image.len() || sz < 64 {
            continue;
        }
        let slice = &mut image[raw..raw + sz];
        xor_zero_runs_in_slice(slice, seed, 32, &mut changed);
    }
    Ok(changed)
}

fn xor_zero_runs_in_slice(buf: &mut [u8], seed: u64, min_run: usize, changed: &mut usize) {
    let mut i = 0usize;
    while i + min_run <= buf.len() {
        if buf[i..i + min_run].iter().all(|&b| b == 0) {
            let mut j = i + min_run;
            while j < buf.len() && buf[j] == 0 {
                j += 1;
            }
            for (ki, b) in buf[i..j].iter_mut().enumerate() {
                let k = i + ki;
                let k0 = k as u64;
                *b ^= ((seed >> (k0 % 56)) as u8).wrapping_add(k as u8);
                *changed += 1;
            }
            i = j;
        } else {
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_zero_run_changes_only_zeros() {
        let mut v = vec![
            0x48u8, 0x45, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let mut n = 0usize;
        xor_zero_runs_in_slice(&mut v, 0xABC, 32, &mut n);
        assert!(n > 0);
        assert_eq!(v[0], 0x48);
        assert_eq!(v[1], 0x45);
    }
}
