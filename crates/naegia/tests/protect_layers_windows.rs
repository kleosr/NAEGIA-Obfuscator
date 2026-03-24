#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use naegia_pe::hash_name_ror13_upper;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn workspace_target_dir() -> PathBuf {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    workspace_root().join("target").join(profile)
}

fn fixture_exe() -> &'static std::path::Path {
    static FIXTURE: OnceLock<PathBuf> = OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let root = workspace_root();
            let manifest = root.join("fixtures/hello-windows/Cargo.toml");
            let target_dir = root.join("fixtures/hello-windows/target");
            let status = Command::new("cargo")
                .args([
                    "build",
                    "--release",
                    "--manifest-path",
                    manifest.to_str().expect("utf8 manifest"),
                ])
                .env("CARGO_TARGET_DIR", &target_dir)
                .status()
                .expect("spawn cargo for fixture build");
            assert!(status.success(), "fixture cargo build failed");
            target_dir.join("release").join("hello-windows.exe")
        })
        .as_path()
}

fn naegia() -> Command {
    Command::new(env!("CARGO_BIN_EXE_naegia"))
}

#[test]
fn protect_redirect_entry_with_antidebug_runs_without_debugger() {
    let exe = fixture_exe();
    let out = workspace_target_dir().join("naegia_layer_redirect_ad.exe");
    let _ = std::fs::remove_file(&out);
    assert!(naegia()
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
    let exe = fixture_exe();
    let out = workspace_target_dir().join("naegia_layer_redirect.exe");
    let _ = std::fs::remove_file(&out);
    assert!(
        naegia()
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
    let exe = fixture_exe();
    let out = workspace_target_dir().join("naegia_layer_decoy.exe");
    let _ = std::fs::remove_file(&out);
    assert!(naegia()
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
    let exe = fixture_exe();
    let out = workspace_target_dir().join("naegia_layer_nuclear.exe");
    let _ = std::fs::remove_file(&out);
    assert!(naegia()
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
    let exe = fixture_exe();
    let out = workspace_target_dir().join("naegia_layer_scramble_unused.exe");
    let st = naegia()
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
    let exe = fixture_exe();
    let st = naegia()
        .args([
            "protect",
            exe.to_str().unwrap(),
            "-o",
            workspace_target_dir()
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
    let exe = fixture_exe();
    let st = naegia()
        .args([
            "protect",
            exe.to_str().unwrap(),
            "-o",
            workspace_target_dir()
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
    let exe = fixture_exe();
    let st = naegia()
        .args([
            "protect",
            exe.to_str().unwrap(),
            "-o",
            workspace_target_dir()
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
