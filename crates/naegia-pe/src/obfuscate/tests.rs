use super::*;

#[test]
fn section_table_offsets_sane_on_minimal_header() {
    let mut buf = vec![0u8; 0x200];
    buf[0] = b'M';
    buf[1] = b'Z';
    buf[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    let pe = 0x80usize;
    buf[pe..pe + 4].copy_from_slice(b"PE\0\0");
    buf[pe + 4..pe + 6].copy_from_slice(&0x8664u16.to_le_bytes());
    buf[pe + 6..pe + 8].copy_from_slice(&0u16.to_le_bytes());
    buf[pe + 20..pe + 22].copy_from_slice(&240u16.to_le_bytes());
    let offs = section_name_raw_offsets(&buf)
        .expect("section_name_raw_offsets should succeed on minimal valid PE header");
    assert!(offs.is_empty());
}
