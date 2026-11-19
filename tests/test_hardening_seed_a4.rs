//! The seed drives' real content (the Python goldens in tests/golden/seed-*) against this module's validators and
//! staging (the parts of tests/test_hardening_seed.py and tests/test_hardening_windows.py that hand the generated
//! files to `validate_seed_files` / `validate_seed_label`). The generators of the content are not under test here.

use epma_usb_creator::seed::{
    stage_seed_files, validate_seed_files, validate_seed_label, SEED_MAX_FILES, SEED_MAX_FILE_BYTES,
    SEED_MAX_TOTAL_BYTES,
};
use epma_usb_creator::types::{Files, SeedTarget};
use std::fs;
use std::path::{Path, PathBuf};

fn golden(target: SeedTarget) -> (String, Files) {
    if target == SeedTarget::MacOs {
        // There is no Python golden for the macOS seed (it is new in the Rust build): the generated set stands in.
        let (label, files) =
            epma_usb_creator::seed_files::hardening_files_seed(target, epma_usb_creator::types::Hardening::Baseline)
                .expect("the macOS seed files");
        let mut sorted: Vec<_> = files.into_iter().collect();
        sorted.sort(); // the golden directories are read in name order
        return (label, sorted.into_iter().collect());
    }
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("golden").join(format!("seed-{target}"));
    let label = fs::read_to_string(dir.join("LABEL")).expect("LABEL");
    let mut names: Vec<_> = fs::read_dir(&dir)
        .expect("golden dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|n| n != "LABEL")
        .collect();
    names.sort();
    let files = names.into_iter().map(|n| (n.clone(), fs::read(dir.join(&n)).expect("file"))).collect();
    (label, files)
}

fn expected_names(target: SeedTarget) -> &'static [&'static str] {
    match target {
        SeedTarget::Ubuntu => &["README.txt", "harden-linux.sh", "meta-data", "user-data"],
        SeedTarget::Fedora => &["README.txt", "harden-linux.sh", "ks.cfg"],
        SeedTarget::Debian => &["README.txt", "harden-linux.sh", "preseed.cfg"],
        SeedTarget::Windows => &["README.txt", "audit.cmd", "harden.cmd", "harden.ps1", "undo.cmd"],
        SeedTarget::MacOs => &["README.txt", "audit.command", "harden-macos.sh", "harden.command", "undo.command"],
    }
}

/// The files `hardening_files_windows` adds to a Windows install drive (they go through the same validator).
fn golden_windows_install_files() -> Files {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        for entry in fs::read_dir(dir).expect("golden dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                walk(&path, root, out);
            } else {
                let rel = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
                out.push((rel, fs::read(&path).expect("file")));
            }
        }
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("golden").join("windows-files");
    let mut found = Vec::new();
    walk(&root, &root, &mut found);
    found.sort();
    found.into_iter().collect()
}

#[test]
fn the_files_added_to_a_windows_install_drive_pass_the_shared_validator() {
    let files = golden_windows_install_files();
    let names: Vec<&str> = files.keys().map(String::as_str).collect();
    assert_eq!(
        names,
        ["sources/$OEM$/$$/Setup/Scripts/SetupComplete.cmd", "sources/$OEM$/$$/Setup/Scripts/harden.ps1"]
    );
    assert_eq!(validate_seed_files(&files).unwrap(), files);
    let stage = stage_seed_files(&files).unwrap();
    for (name, data) in &files {
        assert_eq!(&fs::read(stage.join(name)).unwrap(), data, "{name}");
    }
    let _ = fs::remove_dir_all(&stage);
}

#[test]
fn the_label_of_every_target_is_a_valid_fat32_label() {
    let want = [
        (SeedTarget::Ubuntu, "CIDATA"),
        (SeedTarget::Fedora, "OEMDRV"),
        (SeedTarget::Debian, "EPMA-SEED"),
        (SeedTarget::Windows, "EPMA-SEED"),
        (SeedTarget::MacOs, "EPMA-SEED"),
    ];
    for (target, expected) in want {
        let (label, _) = golden(target);
        assert_eq!(label, expected, "{target}");
        assert_eq!(validate_seed_label(&label).unwrap(), label);
    }
}

#[test]
fn the_files_of_every_target_pass_the_drive_validator_unchanged() {
    for target in SeedTarget::ALL {
        let (_, files) = golden(target);
        let names: Vec<&str> = files.keys().map(String::as_str).collect();
        assert_eq!(names, expected_names(target), "{target}");
        assert_eq!(validate_seed_files(&files).unwrap(), files, "{target}");
        assert!(files.len() <= SEED_MAX_FILES);
        for (name, data) in &files {
            assert!(!data.is_empty(), "{target}/{name} is empty");
            assert!(data.len() as u64 <= SEED_MAX_FILE_BYTES, "{target}/{name}");
        }
        assert!(files.values().map(|d| d.len() as u64).sum::<u64>() <= SEED_MAX_TOTAL_BYTES);
    }
}

#[test]
fn the_windows_files_have_plain_flat_ascii_names_and_keep_crlf_and_the_bom_when_staged() {
    let (_, files) = golden(SeedTarget::Windows);
    let name_ok = |n: &str| {
        n.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
            && n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    };
    assert!(files.keys().all(|n| name_ok(n)));
    let stage = stage_seed_files(&files).unwrap();
    for (name, data) in &files {
        assert_eq!(&fs::read(stage.join(name)).unwrap(), data, "{name} was changed by the staging");
    }
    assert!(fs::read(stage.join("harden.ps1")).unwrap().starts_with(b"\xef\xbb\xbf"), "the BOM is not dropped");
    assert!(fs::read(stage.join("harden.cmd")).unwrap().windows(2).any(|w| w == b"\r\n"));
    let _ = fs::remove_dir_all(&stage);
}

#[test]
fn every_golden_set_stages_byte_for_byte_into_a_private_directory() {
    for target in SeedTarget::ALL {
        let (_, files) = golden(target);
        let stage = stage_seed_files(&files).unwrap();
        for (name, data) in &files {
            assert_eq!(&fs::read(stage.join(name)).unwrap(), data, "{target}/{name}");
        }
        assert_eq!(fs::read_dir(&stage).unwrap().count(), files.len(), "{target}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o7777;
            assert_eq!(mode(&stage), 0o700);
            assert!(files.keys().all(|n| mode(&stage.join(n)) == 0o600));
        }
        let _ = fs::remove_dir_all(&stage);
    }
}
