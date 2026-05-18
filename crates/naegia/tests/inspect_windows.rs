#![cfg(windows)]

mod common;

#[test]
fn inspect_fixture_succeeds() {
    let exe = common::fixture_exe();
    let status = common::naegia()
        .args(["inspect", exe.to_str().unwrap()])
        .status()
        .expect("spawn naegia inspect");
    assert!(status.success(), "inspect failed");
}

#[test]
fn preset_release_runs_without_overlay() {
    let exe = common::fixture_exe();
    let out = common::workspace_target_dir().join("naegia_preset_release.exe");
    let _ = std::fs::remove_file(&out);
    assert!(common::naegia()
        .args([
            "protect",
            exe.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--preset",
            "release",
        ])
        .status()
        .unwrap()
        .success());
    let before = std::fs::read(exe).unwrap();
    let after = std::fs::read(&out).unwrap();
    assert_eq!(
        after.len(),
        before.len(),
        "release preset must not grow file"
    );
    common::assert_runs_hello(&out);
}
