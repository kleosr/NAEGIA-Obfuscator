//! Broad regression coverage: CLI edge cases, round-trips, invalid input, identity precedence.

#![cfg(windows)]

mod common;

use naegia_pe::parse_and_validate_pe64;

#[test]
fn identity_ignores_aggressive_flags_byte_identical() {
    let exe = common::fixture_exe();
    let out = common::workspace_target_dir().join("naegia_regr_identity_wins.exe");
    let _ = std::fs::remove_file(&out);
    assert!(common::naegia()
        .args([
            "protect",
            exe.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--identity",
            "--redirect-entry",
            "--decoy-metadata",
            "--nuclear-metadata",
            "--patterned-overlay",
            "--xor-rdata-zero-runs",
        ])
        .status()
        .unwrap()
        .success());

    let before = std::fs::read(exe).unwrap();
    let after = std::fs::read(&out).unwrap();
    assert_eq!(
        before, after,
        "--identity must ignore aggressive flags and copy verbatim"
    );
    common::assert_runs_hello(&out);
}

#[test]
fn anti_debug_without_redirect_is_rejected() {
    let exe = common::fixture_exe();
    let out = common::workspace_target_dir().join("naegia_regr_ad_only.exe");
    let _ = std::fs::remove_file(&out);
    let st = common::naegia()
        .args([
            "protect",
            exe.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--anti-debug-entry",
            "--no-overlay",
        ])
        .status()
        .unwrap();
    assert!(
        !st.success(),
        "anti-debug without redirect-entry must fail validation"
    );
    assert!(
        !out.exists(),
        "failed run must not leave a partial output file"
    );
}

#[test]
fn dry_run_never_writes_output_even_with_other_flags() {
    let exe = common::fixture_exe();
    let out = common::workspace_target_dir().join("naegia_regr_dry_never.exe");
    let _ = std::fs::remove_file(&out);
    assert!(common::naegia()
        .args([
            "protect",
            exe.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--dry-run",
            "--redirect-entry",
            "--decoy-metadata",
        ])
        .status()
        .unwrap()
        .success());
    assert!(!out.exists(), "dry-run must not create -o path");
}

#[test]
fn invalid_file_fails_cleanly() {
    let garbage = common::workspace_target_dir().join("naegia_regr_not_pe.bin");
    std::fs::write(&garbage, b"this is not a PE file\x00\x01\x02").unwrap();
    let out = common::workspace_target_dir().join("naegia_regr_bad_out.exe");
    let _ = std::fs::remove_file(&out);
    let st = common::naegia()
        .args([
            "protect",
            garbage.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(!st.success(), "non-PE input should fail");
}

#[test]
fn default_protect_twice_still_runs() {
    let exe = common::fixture_exe();
    let mid = common::workspace_target_dir().join("naegia_regr_once.exe");
    let final_out = common::workspace_target_dir().join("naegia_regr_twice.exe");
    let _ = std::fs::remove_file(&mid);
    let _ = std::fs::remove_file(&final_out);

    assert!(common::naegia()
        .args([
            "protect",
            exe.to_str().unwrap(),
            "-o",
            mid.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());
    assert!(common::naegia()
        .args([
            "protect",
            mid.to_str().unwrap(),
            "-o",
            final_out.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());

    parse_and_validate_pe64(&std::fs::read(&final_out).unwrap()).expect("second pass still PE64");
    common::assert_runs_hello(&final_out);
}

#[test]
fn full_implemented_stack_runs() {
    let exe = common::fixture_exe();
    let out = common::workspace_target_dir().join("naegia_regr_full_stack.exe");
    let _ = std::fs::remove_file(&out);
    assert!(
        common::naegia()
            .args([
                "protect",
                exe.to_str().unwrap(),
                "-o",
                out.to_str().unwrap(),
                "--strip-debug",
                "--decoy-metadata",
                "--nuclear-metadata",
                "--patterned-overlay",
                "--redirect-entry",
                "--anti-debug-entry",
                "--xor-rdata-zero-runs",
            ])
            .status()
            .unwrap()
            .success(),
        "all implemented flags together should succeed on fixture",
    );
    common::assert_runs_hello(&out);
}

#[test]
fn unsupported_does_not_create_output() {
    let exe = common::fixture_exe();
    let out = common::workspace_target_dir().join("naegia_regr_no_out_scramble.exe");
    let _ = std::fs::remove_file(&out);
    let st = common::naegia()
        .args([
            "protect",
            exe.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--scramble-imports",
        ])
        .status()
        .unwrap();
    assert!(!st.success());
    assert!(!out.exists());
}

#[test]
fn identity_with_unsupported_flag_still_copies() {
    let exe = common::fixture_exe();
    let out = common::workspace_target_dir().join("naegia_regr_id_scramble.exe");
    let _ = std::fs::remove_file(&out);
    assert!(common::naegia()
        .args([
            "protect",
            exe.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--identity",
            "--scramble-imports",
        ])
        .status()
        .unwrap()
        .success());

    assert_eq!(std::fs::read(exe).unwrap(), std::fs::read(&out).unwrap());
}
