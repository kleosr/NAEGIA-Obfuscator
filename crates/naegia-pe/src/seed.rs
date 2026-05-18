//! Protect-seed derivation: content hash plus optional OS randomness.

use crate::error::{NaegiaPeError, Result};

const FNV_OFFSET: u64 = 14695981039346656037;
const FNV_PRIME: u64 = 1099511628211;

/// Deterministic FNV-1a over image prefix/tail (stable CI and reproducible builds).
pub fn content_seed(image: &[u8]) -> u64 {
    let mut h = fnv1a_prefix(image, image.len().min(4096));
    if image.len() > 8192 {
        let start = image.len().saturating_sub(4096);
        let tail = fnv1a_prefix(&image[start..], image.len() - start);
        h ^= tail.rotate_left(32);
    }
    h ^ ((image.len() as u64) << 1)
}

/// Mix content seed with optional CSPRNG bytes (`--random-seed`).
pub fn protect_seed(image: &[u8], random_entropy: Option<u64>) -> u64 {
    let base = content_seed(image);
    match random_entropy {
        Some(r) => base ^ r.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ r.rotate_left(33),
        None => base,
    }
}

/// Read eight bytes from the OS CSPRNG.
pub fn os_random_u64() -> Result<u64> {
    let mut buf = [0u8; 8];
    getrandom::fill(&mut buf).map_err(|_| NaegiaPeError::InvalidPe("CSPRNG unavailable"))?;
    Ok(u64::from_le_bytes(buf))
}

fn fnv1a_prefix(buf: &[u8], take: usize) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in &buf[..take] {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protect_seed_deterministic_without_random() {
        let img = vec![0u8; 1024];
        assert_eq!(protect_seed(&img, None), protect_seed(&img, None));
    }

    #[test]
    fn protect_seed_differs_with_random() {
        let img = vec![0u8; 1024];
        let a = protect_seed(&img, None);
        let b = protect_seed(&img, Some(0xDEAD_BEEF_CAFE_BABE));
        assert_ne!(a, b);
    }
}
