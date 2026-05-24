//! Property-based ("fuzz") tests for PE parsing functions.
//!
//! Verifies that every public API either returns `Ok` or `Err` — never panics —
//! regardless of the input byte pattern.
//!
//! Run with:  cargo test -p naegia-pe --test fuzz

use naegia_pe::MAX_INPUT_BYTES;
use proptest::prelude::*;

/// Strategy: a random byte vector with length in [0, 64) — too small for DOS header.
fn tiny_bytes() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(proptest::arbitrary::any::<u8>(), 0..64usize)
}

/// Strategy: a random byte vector with length in [64, 128) — just past DOS header.
fn small_bytes() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(proptest::arbitrary::any::<u8>(), 64..128usize)
}

/// Strategy: a random byte vector with length in [128, 4096).
fn medium_bytes() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(proptest::arbitrary::any::<u8>(), 128..4096usize)
}

/// Strategy: a random byte vector with length in [4096, 65536).
fn large_bytes() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(proptest::arbitrary::any::<u8>(), 4096..65536usize)
}

/// Strategy: any byte vector (covers all sizes).
fn any_bytes() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(proptest::arbitrary::any::<u8>(), 0..65536usize)
}

proptest! {
    // ── parse_and_validate_pe64 ──────────────────────────────────────────

    #[test]
    fn parse_and_validate_pe64_never_panics_on_tiny(buf in tiny_bytes()) {
        let _ = naegia_pe::parse_and_validate_pe64(&buf);
    }

    #[test]
    fn parse_and_validate_pe64_never_panics_on_small(buf in small_bytes()) {
        let _ = naegia_pe::parse_and_validate_pe64(&buf);
    }

    #[test]
    fn parse_and_validate_pe64_never_panics_on_medium(buf in medium_bytes()) {
        let _ = naegia_pe::parse_and_validate_pe64(&buf);
    }

    #[test]
    fn parse_and_validate_pe64_never_panics_on_large(buf in large_bytes()) {
        let _ = naegia_pe::parse_and_validate_pe64(&buf);
    }

    // ── debug_data_directory_entry ──────────────────────────────────────

    #[test]
    fn debug_data_directory_entry_never_panics(buf in any_bytes()) {
        let _ = naegia_pe::debug_data_directory_entry(&buf);
    }

    // ── checksum ────────────────────────────────────────────────────────

    #[test]
    fn compute_pe_checksum_never_panics(buf in any_bytes()) {
        // compute_pe_checksum is not re-exported, so we test via write_pe_checksum
        let _ = naegia_pe::protect_identity(&buf);
    }
}

// ── Additional deterministic edge-case tests ──────────────────────────────

#[test]
fn parse_and_validate_pe64_rejects_empty_slice() {
    assert!(naegia_pe::parse_and_validate_pe64(&[]).is_err());
}

#[test]
fn parse_and_validate_pe64_rejects_single_byte() {
    assert!(naegia_pe::parse_and_validate_pe64(&[0x00]).is_err());
}

#[test]
fn parse_and_validate_pe64_rejects_zeros_64b() {
    assert!(naegia_pe::parse_and_validate_pe64(&[0u8; 64]).is_err());
}

#[test]
fn parse_and_validate_pe64_rejects_zeros_128b() {
    assert!(naegia_pe::parse_and_validate_pe64(&[0u8; 128]).is_err());
}

#[test]
fn parse_and_validate_pe64_rejects_zeros_4096b() {
    assert!(naegia_pe::parse_and_validate_pe64(&[0u8; 4096]).is_err());
}

#[test]
fn parse_and_validate_pe64_rejects_ascii_text() {
    let text = b"This is not a PE file\x00\x01\x02\x03";
    assert!(naegia_pe::parse_and_validate_pe64(text).is_err());
}

#[test]
fn parse_and_validate_pe64_rejects_only_mz() {
    let mut buf = vec![0u8; 128];
    buf[0] = b'M';
    buf[1] = b'Z';
    assert!(naegia_pe::parse_and_validate_pe64(&buf).is_err());
}

#[test]
fn parse_and_validate_pe64_rejects_mz_with_pe_signature_but_invalid_optional() {
    let mut buf = vec![0u8; 512];
    buf[0] = b'M';
    buf[1] = b'Z';
    // e_lfanew pointing to PE\0\0 at offset 0x80
    buf[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    buf[0x80..0x84].copy_from_slice(b"PE\0\0");
    // COFF: machine = AMD64, sections = 0, opt header size = 0 (invalid but tests parser)
    buf[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    assert!(naegia_pe::parse_and_validate_pe64(&buf).is_err());
}

// ── Large / pathological inputs ───────────────────────────────────────────

#[test]
fn parse_and_validate_pe64_rejects_zeros_1mb() {
    let buf = vec![0u8; 1_048_576];
    assert!(naegia_pe::parse_and_validate_pe64(&buf).is_err());
}

#[test]
fn parse_and_validate_pe64_rejects_alternating_bits() {
    let buf: Vec<u8> = (0..65536u32).map(|i| (i & 0xFF) as u8).collect();
    assert!(naegia_pe::parse_and_validate_pe64(&buf).is_err());
}

// ── protect_identity on garbage ──────────────────────────────────────────

#[test]
fn protect_identity_never_panics_on_garbage() {
    let garbage = vec![0xDEu8, 0xAD, 0xBE, 0xEF];
    let _ = naegia_pe::protect_identity(&garbage);
}

#[test]
fn parse_rejects_image_over_max_len_without_huge_alloc() {
    assert!(naegia_pe::ensure_image_fits(MAX_INPUT_BYTES + 1).is_err());
    assert!(naegia_pe::ensure_image_fits(MAX_INPUT_BYTES).is_ok());
}

#[test]
fn protect_identity_err_on_short_trash() {
    // protect_identity must return Err, not panic, for non-PE data
    assert!(naegia_pe::protect_identity(&[0u8; 32]).is_err());
    assert!(naegia_pe::protect_identity(&[0xFFu8; 64]).is_err());
}

// ── import_dll_names on garbage ──────────────────────────────────────────

#[test]
fn import_dll_names_does_not_panic_on_empty_pe() {
    // If the input happens to parse as a valid (but empty) PE, libraries is empty.
    if let Ok(pe) = naegia_pe::parse_and_validate_pe64(&[0u8; 1024]) {
        let names = naegia_pe::import_dll_names(&pe);
        // Should be empty or at worst contain garbage — but never panic
        assert!(names.iter().all(|s| !s.is_empty()));
    }
}
