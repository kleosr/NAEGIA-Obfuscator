//! ROR13 uppercase import hashing (common shellcode / packer convention).
//! Full “scramble imports” still needs: strip or shrink the import directory, emit a resolver
//! stub, and run it before any IAT use (entry trampoline). Wired as API + tests only for now.

/// Case-insensitive ROR13 additive hash over ASCII (typical malware import-by-hash style).
pub fn hash_name_ror13_upper(name: &str) -> u32 {
    let mut h: u32 = 0;
    for byte in name.to_ascii_uppercase().bytes() {
        h = h.rotate_right(13);
        h = h.wrapping_add(byte as u32);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel32_dll_hash_stable() {
        let h = hash_name_ror13_upper("kernel32.dll");
        assert_ne!(h, 0);
        assert_eq!(h, hash_name_ror13_upper("KERNEL32.DLL"));
    }

    #[test]
    fn getprocaddress_hash_stable() {
        let h = hash_name_ror13_upper("GetProcAddress");
        assert_ne!(h, 0);
    }
}
