#![cfg(windows)]

mod common;

use std::process::Command;

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
