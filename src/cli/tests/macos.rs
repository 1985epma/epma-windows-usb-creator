//! The `macos` image type on the command line: `--mode macos`, what `detect` and `--mode auto` do with a macOS image,
//! and the refusals that happen before anything is erased. (New in the Rust build; the Python program has no such mode.)

use super::*;
use crate::cli::EXIT_USAGE;

/// A 2 MiB file that ends with the 512-byte "koly" trailer of an Apple disk image and has no boot signature: a
/// compressed .dmg.
fn compressed_dmg(t: &T) -> String {
    let mut data: Vec<u8> = (0..2 * MIB).map(|i| (i.wrapping_mul(7) % 241) as u8).collect();
    data[510] = 0;
    data[511] = 0;
    let at = data.len() - 512;
    data[at..at + 4].copy_from_slice(b"koly");
    t.write_file("compressed.dmg", &data)
}

#[test]
fn an_explicit_macos_mode_plans_a_raw_write() {
    let t = T::new();
    let image = t.make_iso("macos.img", 2 * MIB, true); // has the boot signature a whole-disk image carries
    let (code, out, err) = t.run(&t.write_args(&image, &["--dry-run", "--mode", "macos"]));
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Mode : macos"), "{out}");
    assert!(out.contains("byte for byte"), "{out}");
    assert!(out.contains("Read the drive back and compare it with the image"), "{out}");
    assert!(t.engine.builds().is_empty());
    assert_eq!(t.engine.auth_calls(), 0);
}

#[test]
fn auto_mode_takes_macos_from_the_content() {
    let t = T::new();
    let image = t.make_iso("macos.img", 2 * MIB, true);
    *lock(&t.engine.detect) = Some(IsoKind::MacOs);
    let (code, out, err) = t.run(&t.write_args(&image, &["--dry-run"]));
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Mode : macos"), "{out}");
}

#[test]
fn detect_reports_macos() {
    let t = T::new();
    let image = t.make_iso("macos.img", 2 * MIB, true);
    *lock(&t.engine.detect) = Some(IsoKind::MacOs);
    let (code, out, _err) = t.run(&["detect", &image]);
    assert_eq!(code, 0);
    assert!(out.contains("macos"), "{out}");
}

#[test]
fn a_mode_that_disagrees_with_the_content_only_warns() {
    let t = T::new();
    let image = t.make_iso("macos.img", 2 * MIB, true);
    *lock(&t.engine.detect) = Some(IsoKind::Linux);
    let (code, out, err) = t.run(&t.write_args(&image, &["--dry-run", "--mode", "macos"]));
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("looks like a linux image but --mode macos was requested"), "{err}");
    assert!(out.contains("Mode : macos"), "{out}");
}

#[test]
fn an_image_without_a_partition_table_is_refused_before_anything_is_erased() {
    let t = T::new();
    let image = t.make_iso("volume.img", 2 * MIB, false); // no boot signature: one volume, not a whole disk
    let (code, out, err) = t.run(&t.write_args(&image, &["--yes", "--mode", "macos"]));
    assert_eq!((code, out.as_str()), (1, ""));
    assert!(err.contains("no partition table"), "{err}");
    assert!(t.engine.builds().is_empty());
    assert_eq!(t.engine.auth_calls(), 0);
}

#[test]
fn a_compressed_dmg_is_refused_and_the_message_says_how_to_convert_it() {
    let t = T::new();
    let image = compressed_dmg(&t);
    let (code, out, err) = t.run(&t.write_args(&image, &["--yes", "--mode", "macos"]));
    assert_eq!((code, out.as_str()), (1, ""));
    assert!(err.contains("hdiutil convert"), "{err}");
    assert!(err.contains("-format UDRW"), "{err}");
    assert!(t.engine.builds().is_empty());
}

#[test]
fn hardening_is_for_windows_images_only() {
    let t = T::new();
    let image = t.make_iso("macos.img", 2 * MIB, true);
    let (code, out, err) = t.run(&t.write_args(&image, &["--yes", "--hardened", "--mode", "macos"]));
    assert_eq!((code, out.as_str()), (EXIT_USAGE, ""));
    assert!(err.contains("--hardened"), "{err}");
    assert!(t.engine.builds().is_empty());
}

#[test]
fn a_real_write_hands_the_macos_mode_to_the_engine() {
    let t = T::new();
    let image = t.make_iso("macos.img", 2 * MIB, true);
    let (code, _out, err) = t.run(&t.write_args(&image, &["--yes", "--mode", "macos"]));
    assert_eq!(code, 0, "{err}");
    let builds = t.engine.builds();
    assert_eq!(builds.len(), 1);
    assert_eq!(builds[0].mode, Mode::MacOs);
}

// ---- the macOS hardening seed ----

#[test]
fn harden_seed_macos_plans_the_five_files_by_name() {
    let t = T::new();
    let (code, out, err) = t.run(&["harden-seed", "--target", "macos", "--disk", "disk9", "--dry-run"]);
    assert_eq!(code, 0, "{err}");
    for name in ["harden.command", "audit.command", "undo.command", "harden-macos.sh", "README.txt", "EPMA-SEED"] {
        assert!(out.contains(name), "{name} missing from:\n{out}");
    }
    assert!(t.engine.seeds().is_empty(), "a dry run writes nothing");
    assert_eq!(t.engine.auth_calls(), 0);
}

#[test]
fn harden_seed_macos_for_real_hands_the_target_to_the_engine() {
    let t = T::new();
    let (code, _out, err) = t.run(&["harden-seed", "--target", "macos", "--disk", "disk9", "--yes"]);
    assert_eq!(code, 0, "{err}");
    let seeds = t.engine.seeds();
    assert_eq!(seeds.len(), 1);
    assert_eq!(seeds[0].target, SeedTarget::MacOs);
}

#[test]
fn harden_files_macos_writes_the_files_into_a_new_folder() {
    let t = T::new();
    let out_dir = t.path("macos-seed");
    let (code, _out, err) = t.run(&["harden-files", "--target", "macos", "--out", &out_dir]);
    assert_eq!(code, 0, "{err}");
    let mut names: Vec<String> =
        std::fs::read_dir(&out_dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    assert_eq!(names, ["README.txt", "audit.command", "harden-macos.sh", "harden.command", "undo.command"]);
}

#[test]
fn macos_is_a_seed_target_and_not_the_same_usb_set() {
    use crate::cli::parser::FilesKind;
    assert_eq!(FilesKind::parse("macos"), Some(FilesKind::Seed(SeedTarget::MacOs)));
    assert_eq!(FilesKind::of_seed_target(SeedTarget::MacOs), FilesKind::Seed(SeedTarget::MacOs));
    assert_eq!(FilesKind::Seed(SeedTarget::MacOs).as_str(), "macos");
    let t = T::new();
    let (_c, out, _e) = t.run(&["harden-seed", "--help"]);
    assert!(out.contains("macos"), "{out}");
}
