#![cfg(windows)]

mod common;

use std::process::Command;

use naegia_pe::{
    debug_data_directory_entry, import_dll_names, parse_and_validate_pe64,
    DEFAULT_ENTROPY_OVERLAY_LEN,
};

#[test]
fn protect_identity_preserves_imports_and_runs() {
    let exe = common::fixture_exe();
    let out = common::workspace_target_dir().join("naegia_it_identity.exe");
    let _ = std::fs::remove_file(&out);

    let status = common::naegia()
        .args([
            "protect",
            exe.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--identity",
        ])
        .status()
        .expect("spawn naegia");
    assert!(status.success(), "naegia protect (identity) failed");

    let before = std::fs::read(exe).unwrap();
    let after = std::fs::read(&out).unwrap();
    assert_eq!(before, after, "identity pass-through must preserve bytes");

    let pe_in = parse_and_validate_pe64(&before).unwrap();
    let pe_out = parse_and_validate_pe64(&after).unwrap();
    assert_eq!(import_dll_names(&pe_in), import_dll_names(&pe_out));

    let run = Command::new(&out).output().expect("run protected exe");
    assert!(
        run.status.success(),
        "protected exe failed: {:?}",
        run.stderr
    );
    assert_eq!(String::from_utf8_lossy(&run.stdout), "HELLO");
}

#[test]
fn protect_default_obfuscates_preserves_loader_surface_and_runs() {
    let exe = common::fixture_exe();
    let out = common::workspace_target_dir().join("naegia_obfuscate_default.exe");
    let _ = std::fs::remove_file(&out);

    let status = common::naegia()
        .args([
            "protect",
            exe.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .expect("spawn naegia");
    assert!(
        status.success(),
        "naegia protect (default obfuscate) failed"
    );

    let before = std::fs::read(exe).unwrap();
    let after = std::fs::read(&out).unwrap();
    assert_ne!(
        before, after,
        "default protect must change metadata (not byte-identical)"
    );

    let pe_in = parse_and_validate_pe64(&before).unwrap();
    let pe_out = parse_and_validate_pe64(&after).unwrap();
    assert_eq!(import_dll_names(&pe_in), import_dll_names(&pe_out));
    common::assert_loader_relevant_layout_eq(&pe_in, &pe_out);

    let opt_in = pe_in.header.optional_header.as_ref().expect("opt in");
    let opt_out = pe_out.header.optional_header.as_ref().expect("opt out");
    assert_ne!(
        (
            opt_in.standard_fields.major_linker_version,
            opt_in.standard_fields.minor_linker_version
        ),
        (
            opt_out.standard_fields.major_linker_version,
            opt_out.standard_fields.minor_linker_version
        ),
        "linker version bytes should be obfuscated (loader ignores them)"
    );

    let win_in = &opt_in.windows_fields;
    let win_out = &opt_out.windows_fields;
    assert_ne!(
        (win_in.major_image_version, win_in.minor_image_version),
        (win_out.major_image_version, win_out.minor_image_version),
        "image version words should be obfuscated (cosmetic for the loader)"
    );

    let names_in: Vec<[u8; 8]> = pe_in.sections.iter().map(|s| s.name).collect();
    let names_out: Vec<[u8; 8]> = pe_out.sections.iter().map(|s| s.name).collect();
    assert_ne!(
        names_in, names_out,
        "section names should be obfuscated for this fixture"
    );

    assert_eq!(&before[0..2], &after[0..2], "MZ signature must remain");
    assert_eq!(
        &before[0x3c..0x40],
        &after[0x3c..0x40],
        "e_lfanew must remain"
    );
    assert_eq!(
        after.len(),
        before.len() + DEFAULT_ENTROPY_OVERLAY_LEN,
        "default path appends fixed-size entropy tail"
    );

    let run = Command::new(&out).output().expect("run obfuscated exe");
    assert!(
        run.status.success(),
        "obfuscated exe failed: {:?}",
        run.stderr
    );
    assert_eq!(String::from_utf8_lossy(&run.stdout), "HELLO");
}

#[test]
fn protect_obfuscate_is_deterministic() {
    let exe = common::fixture_exe();
    let out_a = common::workspace_target_dir().join("naegia_obf_det_a.exe");
    let out_b = common::workspace_target_dir().join("naegia_obf_det_b.exe");
    let _ = std::fs::remove_file(&out_a);
    let _ = std::fs::remove_file(&out_b);

    assert!(common::naegia()
        .args([
            "protect",
            exe.to_str().unwrap(),
            "-o",
            out_a.to_str().unwrap()
        ])
        .status()
        .expect("spawn naegia")
        .success());
    assert!(common::naegia()
        .args([
            "protect",
            exe.to_str().unwrap(),
            "-o",
            out_b.to_str().unwrap()
        ])
        .status()
        .expect("spawn naegia")
        .success());

    let a = std::fs::read(&out_a).unwrap();
    let b = std::fs::read(&out_b).unwrap();
    assert_eq!(a, b, "same input must yield identical obfuscated output");
}

#[test]
fn protect_strip_debug_with_obfuscation_keeps_imports_and_runs() {
    let exe = common::fixture_exe();
    let out = common::workspace_target_dir().join("naegia_it_strip.exe");
    let _ = std::fs::remove_file(&out);

    let status = common::naegia()
        .args([
            "protect",
            exe.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--strip-debug",
        ])
        .status()
        .expect("spawn naegia");
    assert!(status.success(), "naegia protect --strip-debug failed");

    let before = std::fs::read(exe).unwrap();
    let after = std::fs::read(&out).unwrap();
    assert_ne!(before, after, "strip-debug should change the image");

    let pe_in = parse_and_validate_pe64(&before).unwrap();
    let pe_out = parse_and_validate_pe64(&after).unwrap();
    assert_eq!(import_dll_names(&pe_in), import_dll_names(&pe_out));
    common::assert_loader_relevant_layout_eq(&pe_in, &pe_out);

    assert_eq!(
        debug_data_directory_entry(&after).unwrap(),
        (0, 0),
        "debug data directory entry must be cleared"
    );

    let run = Command::new(&out).output().expect("run stripped exe");
    assert!(
        run.status.success(),
        "stripped exe failed: {:?}",
        run.stderr
    );
    assert_eq!(String::from_utf8_lossy(&run.stdout), "HELLO");
}

#[test]
fn protect_no_overlay_keeps_on_disk_size_and_runs() {
    let exe = common::fixture_exe();
    let out = common::workspace_target_dir().join("naegia_no_overlay.exe");
    let _ = std::fs::remove_file(&out);

    assert!(common::naegia()
        .args([
            "protect",
            exe.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--no-overlay"
        ])
        .status()
        .expect("spawn naegia")
        .success());

    let before = std::fs::read(exe).unwrap();
    let after = std::fs::read(&out).unwrap();
    assert_eq!(
        after.len(),
        before.len(),
        "--no-overlay must not append bytes after the image"
    );

    let run = Command::new(&out).output().expect("run no-overlay exe");
    assert!(
        run.status.success(),
        "no-overlay exe failed: {:?}",
        run.stderr
    );
    assert_eq!(String::from_utf8_lossy(&run.stdout), "HELLO");
}

#[test]
fn protect_dry_run_succeeds() {
    let exe = common::fixture_exe();
    let dummy = common::workspace_target_dir().join("naegia_dry_run_unused.exe");
    let status = common::naegia()
        .args([
            "protect",
            exe.to_str().unwrap(),
            "-o",
            dummy.to_str().unwrap(),
            "--dry-run",
        ])
        .status()
        .expect("spawn naegia");
    assert!(status.success(), "dry-run should validate only");
    assert!(!dummy.exists(), "dry-run must not create the output path");
}
