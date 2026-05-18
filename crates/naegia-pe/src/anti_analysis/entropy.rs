//! File tail entropy (post-image bytes the loader ignores for normal EXEs).

/// Pseudorandom tail appended after the mapped PE image (loader ignores it for normal exes).
pub const DEFAULT_ENTROPY_OVERLAY_LEN: usize = 1536;

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

/// Append high-entropy bytes after the image (raises file entropy; breaks Authenticode if present).
pub fn push_entropy_overlay(image: &mut Vec<u8>, seed: u64, len: usize) {
    if len == 0 {
        return;
    }
    let mut st = seed ^ 0xCAFE_F00D_D15C_A5ED;
    let old_len = image.len();
    image.reserve(len);
    let mut written = 0usize;
    while written < len {
        let w = splitmix64(&mut st);
        let chunk = w.to_le_bytes();
        let take = (len - written).min(8);
        image.extend_from_slice(&chunk[..take]);
        written += take;
    }
    debug_assert_eq!(image.len(), old_len + len);
}

/// High / low / NOP-like blocks to skew naive entropy plots (file tail only).
pub fn push_patterned_entropy_overlay(image: &mut Vec<u8>, seed: u64, total_len: usize) {
    if total_len == 0 {
        return;
    }
    // Pre-allocate to avoid repeated reallocation during byte-by-byte push.
    image.reserve(total_len);
    let target_len = image.len().saturating_add(total_len);
    let mut st = seed ^ 0xBADC0FFEEBAD0000;
    let mut phase: u64 = 0;
    while image.len() < target_len {
        let remain = target_len - image.len();
        let take = remain.min(256);
        match phase % 3 {
            0 => {
                for _ in 0..take {
                    let w = splitmix64(&mut st);
                    image.push(w as u8);
                }
            }
            1 => {
                for _ in 0..take {
                    let w = splitmix64(&mut st);
                    image.push((w >> 8) as u8);
                }
            }
            _ => {
                image.extend(std::iter::repeat_n(0x90u8, take));
            }
        }
        phase = phase.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_entropy_overlay_exact_len() {
        let mut v = vec![1u8, 2, 3];
        push_entropy_overlay(&mut v, 0x1234, 100);
        assert_eq!(v.len(), 103);
    }

    #[test]
    fn patterned_overlay_matches_length() {
        let mut v = vec![0u8; 10];
        push_patterned_entropy_overlay(&mut v, 0xABCD, 512);
        assert_eq!(v.len(), 522);
    }
}
