//! Port of the engine-side parts of tests/test_chromeos.py: build_usb's dispatch of ChromeOS Flex to the raw write,
//! the safety re-check before writing, the size and type refusals before anything happens, and the dependencies of
//! the raw modes. (Cards, download, extraction and the command line are other agents'.)

mod common_a2;

use common_a2::*;
use epma_usb_creator::engine::{build_usb_on, get_missing_dependencies_on, Os};
use epma_usb_creator::types::{BuildOptions, Error, Hardening, Mode};
use std::path::PathBuf;

struct Build {
    tmp: Tmp,
    image: PathBuf,
}

impl Build {
    fn new() -> Self {
        let tmp = Tmp::new();
        // a ChromeOS image: a protective MBR with the boot signature (4 MiB)
        let image = tmp.make_iso("flex.bin", 4 * MIB, true);
        Build { tmp, image }
    }
    fn run(&self, ops: &FakeOps, mode: Mode, expected_size: Option<u64>) -> Result<bool, Error> {
        let sink = Sink::new();
        let opts = BuildOptions { expected_size, mode, eject: true, hardening: Hardening::None };
        let _ = &self.tmp;
        build_usb_on(ops, &self.image, dev(), &sink.ctx(None), &NoPriv, &opts)
    }
}

#[test]
fn chromeos_uses_the_raw_write_on_every_system() {
    for os in [Os::Mac, Os::Linux, Os::Windows] {
        let t = Build::new();
        let ops = FakeOps::new(os);
        assert!(t.run(&ops, Mode::ChromeOs, None).unwrap());
        assert!(ops.called("raw"), "{os:?}");
        assert!(!ops.called("win"), "{os:?}: the files of an image are not copied");
    }
}

#[test]
fn windows_still_copies_files() {
    let t = Build::new();
    let ops = FakeOps::new(Os::Mac);
    t.run(&ops, Mode::Windows, None).unwrap();
    assert!(ops.called("win"));
    assert!(!ops.called("raw"));
}

#[test]
fn the_drive_is_rechecked_before_writing() {
    let t = Build::new();
    let ops = FakeOps::new(Os::Mac);
    t.run(&ops, Mode::ChromeOs, None).unwrap();
    let steps: Vec<String> =
        ops.calls().into_iter().filter(|c| matches!(c.as_str(), "hash" | "reverify" | "raw")).collect();
    assert_eq!(steps, ["hash", "reverify", "raw"]);
}

#[test]
fn refuses_an_image_larger_than_the_drive_before_anything_happens() {
    let t = Build::new();
    let ops = FakeOps::new(Os::Mac);
    let err = t.run(&ops, Mode::ChromeOs, Some(2 * MIB as u64)).unwrap_err();
    assert!(matches!(err, Error::Value(_)));
    assert!(err.to_string().contains("larger than the drive"), "{err}");
    assert!(!ops.called("reverify"));
    assert!(!ops.called("raw"));
}

#[test]
fn refuses_the_zip() {
    let t = Build::new();
    let mut data = std::fs::read(&t.image).unwrap();
    data[..4].copy_from_slice(b"PK\x03\x04");
    let zip = t.tmp.write("latest.bin.zip", &data);
    let ops = FakeOps::new(Os::Mac);
    let sink = Sink::new();
    let opts = BuildOptions { mode: Mode::ChromeOs, ..BuildOptions::default() };
    let err = build_usb_on(&ops, &zip, dev(), &sink.ctx(None), &NoPriv, &opts).unwrap_err();
    assert!(err.to_string().contains("ZIP archive"), "{err}");
    assert!(!ops.called("raw"));
}

#[test]
fn refuses_a_non_bootable_image() {
    let t = Build::new();
    let mut data = std::fs::read(&t.image).unwrap();
    data[510..512].copy_from_slice(&[0, 0]);
    let bad = t.tmp.write("bad.bin", &data);
    let ops = FakeOps::new(Os::Mac);
    let sink = Sink::new();
    let opts = BuildOptions { mode: Mode::ChromeOs, ..BuildOptions::default() };
    let err = build_usb_on(&ops, &bad, dev(), &sink.ctx(None), &NoPriv, &opts).unwrap_err();
    assert!(err.to_string().contains("not a bootable disk image"), "{err}");
    assert!(!ops.called("raw"));
}

#[test]
fn an_unknown_mode_is_refused() {
    // the Python test passes "plan9"; here the modes are an enum, so the closest thing is a mode that is not an
    // image type (the seed drive has no image, "auto" is the command line's placeholder)
    let t = Build::new();
    for mode in [Mode::Seed, Mode::Auto] {
        let ops = FakeOps::new(Os::Mac);
        let err = t.run(&ops, mode, None).unwrap_err();
        assert_eq!(err.to_string(), format!("Unknown image type: '{}'", mode.as_str()));
        assert!(ops.calls().is_empty());
    }
}

#[test]
fn linux_mode_also_checks_the_size() {
    let t = Build::new();
    let ops = FakeOps::new(Os::Mac);
    let err = t.run(&ops, Mode::Linux, Some(MIB as u64)).unwrap_err();
    assert!(err.to_string().contains("larger than the drive"), "{err}");
}

#[test]
fn dependencies_for_the_raw_modes_are_just_dd() {
    let mut ops = FakeOps::new(Os::Mac);
    ops.missing = None;
    ops.which_fn = Some(Box::new(|_| true));
    assert_eq!(get_missing_dependencies_on(&ops, Mode::ChromeOs), Vec::<String>::new());
    ops.which_fn = Some(Box::new(|_| false));
    assert_eq!(get_missing_dependencies_on(&ops, Mode::ChromeOs), ["dd"]);
    assert_eq!(get_missing_dependencies_on(&ops, Mode::Linux), ["dd"]);
    // Windows mode on macOS needs wimlib
    assert_eq!(get_missing_dependencies_on(&ops, Mode::Windows), ["wimlib-imagex"]);
}
