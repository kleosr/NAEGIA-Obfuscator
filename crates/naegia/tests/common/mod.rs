// compiled per-test-binary by Rust; each integration test binary includes this via `mod common;`
#![allow(dead_code)]
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use goblin::pe::PE;

pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn workspace_target_dir() -> PathBuf {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    workspace_root().join("target").join(profile)
}

pub fn fixture_exe() -> &'static Path {
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

pub fn naegia() -> Command {
    Command::new(env!("CARGO_BIN_EXE_naegia"))
}

pub fn assert_runs_hello(path: &Path) {
    let run = Command::new(path).output().expect("spawn protected exe");
    assert!(
        run.status.success(),
        "exe failed: stderr={:?}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&run.stdout), "HELLO");
}

pub fn assert_loader_relevant_layout_eq(a: &PE<'_>, b: &PE<'_>) {
    let oa = a.header.optional_header.as_ref().expect("optional a");
    let ob = b.header.optional_header.as_ref().expect("optional b");
    assert_eq!(
        oa.standard_fields.address_of_entry_point,
        ob.standard_fields.address_of_entry_point
    );
    assert_eq!(a.sections.len(), b.sections.len());
    for (s, t) in a.sections.iter().zip(b.sections.iter()) {
        assert_eq!(s.virtual_address, t.virtual_address);
        assert_eq!(s.virtual_size, t.virtual_size);
        assert_eq!(s.size_of_raw_data, t.size_of_raw_data);
        assert_eq!(s.pointer_to_raw_data, t.pointer_to_raw_data);
        assert_eq!(s.characteristics, t.characteristics);
    }
}
