#![cfg(windows)]

mod common;

use std::process::Command;

use naegia_pe::hash_name_ror13_upper;

#[test]
fn protect_redirect_entry_with_antidebug_runs_without_debugger() {
    let exe = common::fixture_exe();
    let out = common::workspace_target_dir().join("naegia_layer_redirect_ad.exe");
    let _ = std::fs::remove_file(&out);
    assert!(common::naegia()
        .args([
            "protect",
            exe.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--redirect-entry",
            "--anti-debug-entry",
            "--no-overlay",
        ])
        .status()
        .unwrap()
        .success());
    let run = Command::new(&out).output().unwrap();
    assert!(run.status.success(), "stderr: {:?}", run.stderr);
    assert_eq!(String::from_utf8_lossy(&run.stdout), "HELLO");
}

#[test]
fn protect_redirect_entry_runs_hello() {
    let exe = common::fixture_exe();
    let out = common::workspace_target_dir().join("naegia_layer_redirect.exe");
    let _ = std::fs::remove_file(&out);
    assert!(
        common::naegia()
            .args([
                "protect",
                exe.to_str().unwrap(),
                "-o",
                out.to_str().unwrap(),
                "--redirect-entry",
                "--no-overlay",
            ])
            .status()
            .unwrap()
            .success(),
        "redirect-entry protect failed"
    );
    let run = Command::new(&out).output().unwrap();
    assert!(run.status.success(), "stderr: {:?}", run.stderr);
    assert_eq!(String::from_utf8_lossy(&run.stdout), "HELLO");
}

#[test]
fn protect_decoy_and_patterned_overlay_runs() {
    let exe = common::fixture_exe();
    let out = common::workspace_target_dir().join("naegia_layer_decoy.exe");
    let _ = std::fs::remove_file(&out);
    assert!(common::naegia()
        .args([
            "protect",
            exe.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--decoy-metadata",
            "--patterned-overlay",
        ])
        .status()
        .unwrap()
        .success());
    let run = Command::new(&out).output().unwrap();
    assert!(run.status.success());
    assert_eq!(String::from_utf8_lossy(&run.stdout), "HELLO");
}

#[test]
fn protect_nuclear_and_xor_rdata_runs() {
    let exe = common::fixture_exe();
    let out = common::workspace_target_dir().join("naegia_layer_nuclear.exe");
    let _ = std::fs::remove_file(&out);
    assert!(common::naegia()
        .args([
            "protect",
            exe.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--nuclear-metadata",
            "--xor-rdata-zero-runs",
            "--no-overlay",
        ])
        .status()
        .unwrap()
        .success());
    let run = Command::new(&out).output().unwrap();
    assert!(run.status.success());
    assert_eq!(String::from_utf8_lossy(&run.stdout), "HELLO");
}

#[test]
fn protect_scramble_imports_rejected() {
    let exe = common::fixture_exe();
    let out = common::workspace_target_dir().join("naegia_layer_scramble_unused.exe");
    let st = common::naegia()
        .args([
            "protect",
            exe.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--scramble-imports",
            "--no-overlay",
        ])
        .status()
        .unwrap();
    assert!(!st.success(), "scramble-imports should be unsupported");
}

#[test]
fn protect_flatten_cfg_rejected() {
    let exe = common::fixture_exe();
    let st = common::naegia()
        .args([
            "protect",
            exe.to_str().unwrap(),
            "-o",
            common::workspace_target_dir()
                .join("naegia_flatten_unused.exe")
                .to_str()
                .unwrap(),
            "--flatten-cfg",
            "--no-overlay",
        ])
        .status()
        .unwrap();
    assert!(!st.success());
}

#[test]
fn protect_junk_imports_rejected() {
    let exe = common::fixture_exe();
    let st = common::naegia()
        .args([
            "protect",
            exe.to_str().unwrap(),
            "-o",
            common::workspace_target_dir()
                .join("naegia_junk_unused.exe")
                .to_str()
                .unwrap(),
            "--junk-imports",
            "3",
            "--no-overlay",
        ])
        .status()
        .unwrap();
    assert!(!st.success());
}

#[test]
fn protect_opaque_predicates_rejected() {
    let exe = common::fixture_exe();
    let st = common::naegia()
        .args([
            "protect",
            exe.to_str().unwrap(),
            "-o",
            common::workspace_target_dir()
                .join("naegia_opaque_unused.exe")
                .to_str()
                .unwrap(),
            "--opaque-predicates",
            "--no-overlay",
        ])
        .status()
        .unwrap();
    assert!(!st.success());
}

#[test]
fn iat_hash_nonzero_for_common_apis() {
    assert_ne!(hash_name_ror13_upper("LoadLibraryA"), 0);
    assert_ne!(hash_name_ror13_upper("GetProcAddress"), 0);
}
