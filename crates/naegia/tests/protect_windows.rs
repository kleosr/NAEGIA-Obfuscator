#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use goblin::pe::PE;

use naegia_pe::{
    debug_data_directory_entry, import_dll_names, parse_and_validate_pe64,
    DEFAULT_ENTROPY_OVERLAY_LEN,
};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Workspace `target/{debug|release}` (matches how this test crate was built).
fn workspace_target_dir() -> PathBuf {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    workspace_root().join("target").join(profile)
}

fn fixture_exe() -> &'static Path {
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

fn run_naegia(args: &[&str]) -> std::process::ExitStatus {
    let bin = env!("CARGO_BIN_EXE_naegia");
    Command::new(bin).args(args).status().expect("spawn naegia")
}

/// Entry point, section RVAs/raw layout; must survive metadata-only obfuscation.
fn assert_loader_relevant_layout_eq(a: &PE<'_>, b: &PE<'_>) {
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

#[test]
fn protect_identity_preserves_imports_and_runs() {
    let exe = fixture_exe();
    let out = workspace_target_dir().join("naegia_it_identity.exe");
    let _ = std::fs::remove_file(&out);

    let status = run_naegia(&[
        "protect",
        exe.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "--identity",
    ]);
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
    let exe = fixture_exe();
    let out = workspace_target_dir().join("naegia_obfuscate_default.exe");
    let _ = std::fs::remove_file(&out);

    let status = run_naegia(&[
        "protect",
        exe.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ]);
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
    assert_loader_relevant_layout_eq(&pe_in, &pe_out);

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
    let exe = fixture_exe();
    let out_a = workspace_target_dir().join("naegia_obf_det_a.exe");
    let out_b = workspace_target_dir().join("naegia_obf_det_b.exe");
    let _ = std::fs::remove_file(&out_a);
    let _ = std::fs::remove_file(&out_b);

    let args_base = ["protect", exe.to_str().unwrap(), "-o"];
    assert!(run_naegia(&[
        args_base[0],
        args_base[1],
        args_base[2],
        out_a.to_str().unwrap()
    ])
    .success());
    assert!(run_naegia(&[
        args_base[0],
        args_base[1],
        args_base[2],
        out_b.to_str().unwrap()
    ])
    .success());

    let a = std::fs::read(&out_a).unwrap();
    let b = std::fs::read(&out_b).unwrap();
    assert_eq!(a, b, "same input must yield identical obfuscated output");
}

#[test]
fn protect_strip_debug_with_obfuscation_keeps_imports_and_runs() {
    let exe = fixture_exe();
    let out = workspace_target_dir().join("naegia_it_strip.exe");
    let _ = std::fs::remove_file(&out);

    let status = run_naegia(&[
        "protect",
        exe.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "--strip-debug",
    ]);
    assert!(status.success(), "naegia protect --strip-debug failed");

    let before = std::fs::read(exe).unwrap();
    let after = std::fs::read(&out).unwrap();
    assert_ne!(before, after, "strip-debug should change the image");

    let pe_in = parse_and_validate_pe64(&before).unwrap();
    let pe_out = parse_and_validate_pe64(&after).unwrap();
    assert_eq!(import_dll_names(&pe_in), import_dll_names(&pe_out));
    assert_loader_relevant_layout_eq(&pe_in, &pe_out);

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
    let exe = fixture_exe();
    let out = workspace_target_dir().join("naegia_no_overlay.exe");
    let _ = std::fs::remove_file(&out);

    assert!(run_naegia(&[
        "protect",
        exe.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "--no-overlay",
    ])
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
    let exe = fixture_exe();
    let dummy = workspace_target_dir().join("naegia_dry_run_unused.exe");
    let status = run_naegia(&[
        "protect",
        exe.to_str().unwrap(),
        "-o",
        dummy.to_str().unwrap(),
        "--dry-run",
    ]);
    assert!(status.success(), "dry-run should validate only");
    assert!(!dummy.exists(), "dry-run must not create the output path");
}
