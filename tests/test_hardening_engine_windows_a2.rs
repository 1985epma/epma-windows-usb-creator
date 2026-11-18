//! Port of the engine-side parts of tests/test_hardening_engine_windows.py: validate_hardening, the order of the
//! steps of build_usb with a hardening profile, write / verify of the hardening files, copy_windows_payload with the
//! extra files, the clash detection and refusal (macOS and Linux peek) and the peek scripts.
//! (The macOS and Linux backends' own tests - MacosBuildUsbTests, LinuxBuildUsbTests, BuildUsbWithAnOemImageTests'
//! clean-image cases - belong to A3.)

mod common_a2;

use common_a2::*;
use epma_usb_creator::audit::AuditLevel;
use epma_usb_creator::copyverify::{copy_windows_payload, verify_windows_payload, VERIFY_RAW_SCRIPT};
use epma_usb_creator::engine::{
    build_usb_on, capture_audit, check_image_for_hardening_clash, collect_hardening_files_on, find_hardening_clashes,
    hardening_audit_text, needs_admin_on, refuse_hardening_clash_on, validate_hardening, validate_hardening_name,
    verify_hardening_files, write_hardening_files, Os, LINUX_ISO_PEEK_CLEANUP_SCRIPT, LINUX_ISO_PEEK_SCRIPT,
};
use epma_usb_creator::types::{BuildOptions, CancelToken, Error, Files, Hardening, Log, Mode, Privilege, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

const OEM: &str = "sources/$OEM$/$$/Setup/Scripts";
/// A path of an OEM image's own file, spelled differently from ours.
const OEM_CMD: &str = "sources/$oem$/$$/Setup/Scripts/SETUPCOMPLETE.CMD";

fn files() -> Files {
    let mut f = Files::new();
    f.insert("answer-standin.xml".into(), b"<?xml version='1.0'?><unattend/>\n".to_vec());
    f.insert(format!("{OEM}/SetupComplete.cmd"), b"@echo off\r\npowershell -File %~dp0harden.ps1\r\n".to_vec());
    let mut ps = "# harden éà ".as_bytes().to_vec();
    ps.extend(0..=255u8);
    f.insert(format!("{OEM}/harden.ps1"), ps);
    f
}

fn sha(text: &str) -> String {
    Sha256::digest(text.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// A fake ISO tree (`make_iso_tree`); `with_unattend` adds the ISO's own copy of one of our files.
fn make_iso_tree(tmp: &Tmp, name: &str, with_unattend: bool) -> (PathBuf, Vec<(String, Vec<u8>)>) {
    let mut tree: Vec<(String, Vec<u8>)> = vec![
        ("bootmgr".into(), b"boot manager".to_vec()),
        ("efi/boot/bootx64.efi".into(), pseudo_random(3000, 11)),
        ("sources/boot.wim".into(), pseudo_random(9000, 12)),
        ("sources/install.wim".into(), pseudo_random(12000, 13)),
    ];
    if with_unattend {
        tree.push(("answer-standin.xml".into(), b"<!-- the ISO's own file -->".to_vec()));
    }
    for (rel, data) in &tree {
        tmp.write(&format!("{name}/{rel}"), data);
    }
    (tmp.path(name), tree)
}

fn read(root: &std::path::Path, rel: &str) -> Vec<u8> {
    let mut p = root.to_path_buf();
    for part in rel.split('/') {
        p.push(part);
    }
    fs::read(p).unwrap()
}

fn message(err: Error) -> String {
    err.to_string()
}

// ---------------------------------------------------------------------------------------------------------------
// ValidateHardeningTests
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn baseline_is_only_accepted_for_the_windows_type() {
    validate_hardening(Mode::Windows, Hardening::Baseline).unwrap();
    for mode in [Mode::Linux, Mode::ChromeOs] {
        let err = validate_hardening(mode, Hardening::Baseline).unwrap_err();
        assert!(matches!(err, Error::Value(_)));
        assert!(err.to_string().contains("only be added to a Windows drive"), "{mode}");
    }
}

#[test]
fn none_is_accepted_everywhere() {
    for mode in Mode::ALL {
        validate_hardening(mode, Hardening::None).unwrap();
    }
}

#[test]
fn an_unknown_profile_is_refused() {
    for name in ["strict", "", "BASELINE"] {
        let err = validate_hardening_name(Mode::Windows, name).unwrap_err();
        assert_eq!(err.to_string(), format!("Unknown hardening profile: '{name}'"));
    }
    assert_eq!(validate_hardening_name(Mode::Windows, "baseline").unwrap(), Hardening::Baseline);
    assert_eq!(validate_hardening_name(Mode::Linux, "none").unwrap(), Hardening::None);
    let err = validate_hardening_name(Mode::Linux, "baseline").unwrap_err();
    assert!(err.to_string().contains("Windows drive"));
}

#[test]
fn build_usb_has_the_documented_default() {
    assert_eq!(BuildOptions::default().hardening, Hardening::None);
}

#[test]
fn the_audit_text_names_the_profile_and_the_files_sorted() {
    assert_eq!(hardening_audit_text(Hardening::None, None), "");
    assert_eq!(hardening_audit_text(Hardening::Baseline, Some(&Files::new())), "");
    let text = hardening_audit_text(Hardening::Baseline, Some(&files()));
    assert_eq!(
        text,
        ", hardening=baseline, hardening files=['answer-standin.xml', 'sources/$OEM$/$$/Setup/Scripts/SetupComplete.cmd', \
         'sources/$OEM$/$$/Setup/Scripts/harden.ps1']"
    );
}

// ---------------------------------------------------------------------------------------------------------------
// BuildUsbOrderTests: everything is validated before the ISO is hashed, the drive re-checked or anything erased
// ---------------------------------------------------------------------------------------------------------------

struct Order {
    tmp: Tmp,
    iso: PathBuf,
    ops: FakeOps,
}

impl Order {
    fn new(os: Os) -> Self {
        let tmp = Tmp::new();
        let iso = tmp.make_iso("Win11.iso", 2 * MIB, false);
        let mut ops = FakeOps::new(os);
        ops.hardening = Some(files());
        Order { tmp, iso, ops }
    }
    fn build(&self, mode: Mode, hardening: Hardening) -> (Result<bool>, Vec<(String, AuditLevel)>) {
        let sink = Sink::new();
        let opts = BuildOptions { expected_size: None, mode, eject: true, hardening };
        capture_audit(|| build_usb_on(&self.ops, &self.iso, dev(), &sink.ctx(None), &NoPriv, &opts))
    }
    fn assert_nothing_started(&self) {
        for step in ["hash", "reverify", "win", "raw", "sleep"] {
            assert!(!self.ops.called(step), "{step} must not have run: {:?}", self.ops.calls());
        }
    }
}

#[test]
fn raw_modes_with_a_profile_are_refused_first() {
    for mode in [Mode::Linux, Mode::ChromeOs] {
        let t = Order::new(Os::Mac);
        let (result, _) = t.build(mode, Hardening::Baseline);
        assert!(message(result.unwrap_err()).contains("Windows drive"));
        t.assert_nothing_started();
        assert_eq!(t.ops.calls(), Vec::<String>::new(), "not even the files were asked for");
    }
}

#[test]
fn a_bad_seed_never_reaches_the_drive() {
    let mut t = Order::new(Os::Mac);
    t.ops.seed_invalid = true;
    let (result, _) = t.build(Mode::Windows, Hardening::Baseline);
    assert!(message(result.unwrap_err()).contains("bad seed"));
    t.assert_nothing_started();
}

#[test]
fn a_profile_without_files_is_refused() {
    let mut t = Order::new(Os::Mac);
    t.ops.hardening = Some(Files::new());
    let (result, _) = t.build(Mode::Windows, Hardening::Baseline);
    assert_eq!(
        message(result.unwrap_err()),
        "The hardening profile 'baseline' has no files to add. Nothing was changed."
    );
    t.assert_nothing_started();
}

#[test]
fn the_files_are_built_and_validated_by_name_at_call_time() {
    let t = Order::new(Os::Mac);
    assert!(t.build(Mode::Windows, Hardening::Baseline).0.unwrap());
    let calls = t.ops.calls();
    assert_eq!(calls.iter().filter(|c| *c == "hardening_files").count(), 1);
    assert_eq!(calls.iter().filter(|c| *c == "validate_files").count(), 1);
    assert_eq!(t.ops.last_hardening_files.lock().unwrap().clone(), Some(files()));
}

#[test]
fn none_does_not_ask_for_files() {
    let t = Order::new(Os::Mac);
    assert!(t.build(Mode::Windows, Hardening::None).0.unwrap());
    assert!(!t.ops.called("hardening_files"));
    assert!(!t.ops.called("validate_files"));
    assert_eq!(t.ops.last_hardening_files.lock().unwrap().clone(), None, "the backend gets no extra files");
    assert_eq!(collect_hardening_files_on(&t.ops, Hardening::None).unwrap(), None);
}

#[test]
fn the_image_is_checked_for_clashes_before_hashing_or_erasing() {
    let t = Order::new(Os::Mac);
    assert!(t.build(Mode::Windows, Hardening::Baseline).0.unwrap());
    let order: Vec<String> =
        t.ops.calls().into_iter().filter(|c| matches!(c.as_str(), "clash" | "hash" | "reverify" | "win")).collect();
    assert_eq!(order, ["clash", "hash", "reverify", "win"]);
    let (iso, given) = t.ops.clash_args.lock().unwrap().clone().unwrap();
    assert_eq!(iso, fs::canonicalize(&t.iso).unwrap());
    assert_eq!(given, files());
    let _ = &t.tmp;
}

#[test]
fn an_image_that_already_has_a_hardening_file_is_refused_and_nothing_starts() {
    let mut t = Order::new(Os::Mac);
    t.ops.clash = Some(Box::new(|| Err(Error::value("This Windows image already contains x. Adding ..."))));
    let (result, audits) = t.build(Mode::Windows, Hardening::Baseline);
    assert!(message(result.unwrap_err()).contains("already contains x"));
    t.assert_nothing_started();
    assert!(!audits.iter().any(|(m, _)| m.contains("OPERATION START")));
}

#[test]
fn the_backends_receive_the_validated_files() {
    for os in [Os::Mac, Os::Linux] {
        let t = Order::new(os);
        assert!(t.build(Mode::Windows, Hardening::Baseline).0.unwrap());
        assert_eq!(t.ops.last_hardening_files.lock().unwrap().clone(), Some(files()), "{os:?}");
        assert!(t.ops.called("win") && !t.ops.called("raw"));
    }
}

fn start_message(audits: &[(String, AuditLevel)]) -> String {
    let starts: Vec<&String> = audits.iter().map(|(m, _)| m).filter(|m| m.contains("OPERATION START")).collect();
    assert_eq!(starts.len(), 1);
    starts[0].clone()
}

#[test]
fn the_audit_start_line_names_the_profile_and_the_files_but_not_their_contents() {
    let t = Order::new(Os::Mac);
    let (result, audits) = t.build(Mode::Windows, Hardening::Baseline);
    result.unwrap();
    let line = start_message(&audits);
    assert!(line.contains("hardening=baseline"));
    for rel in files().keys() {
        assert!(line.contains(rel.as_str()), "{rel}");
    }
    assert!(!line.contains("unattend/"));
    assert!(!line.contains("powershell"));
}

#[test]
fn the_audit_start_line_is_unchanged_without_hardening() {
    let t = Order::new(Os::Mac);
    let (result, audits) = t.build(Mode::Windows, Hardening::None);
    result.unwrap();
    let size = fs::metadata(&t.iso).unwrap().len();
    assert_eq!(
        start_message(&audits),
        format!(
            "DESTRUCTIVE OPERATION START: erasing /dev/{} and writing windows image (iso sha256={}, size={size})",
            dev(),
            "0".repeat(64)
        )
    );
}

#[test]
fn a_canceled_run_is_still_audited_the_same_way() {
    let t = Order::new(Os::Mac);
    *t.ops.windows.lock().unwrap() = Some(Err(Error::canceled_with("stop", true, false)));
    let (result, audits) = t.build(Mode::Windows, Hardening::Baseline);
    assert!(result.unwrap_err().is_canceled());
    assert!(audits.iter().any(|(m, _)| m.contains("left unusable")));
}

// ---------------------------------------------------------------------------------------------------------------
// build_usb end to end with the real clash check (backends faked below the mount)
// ---------------------------------------------------------------------------------------------------------------

/// "Mounts" the ISO tree for the macOS peek: `hdiutil attach` copies it into the mount point, `detach` removes it.
fn fake_hdiutil(tree: PathBuf) -> RunFn {
    Box::new(move |args: &[String]| {
        if args.len() > 1 && args[0] == "hdiutil" && args[1] == "attach" {
            let at = args.iter().position(|a| a == "-mountpoint").unwrap();
            copy_tree(&tree, std::path::Path::new(&args[at + 1]));
        } else if args.len() > 2 && args[0] == "hdiutil" && args[1] == "detach" {
            let _ = fs::remove_dir_all(&args[2]);
        }
        Ok(0)
    })
}

#[test]
fn macos_refuses_an_oem_image_before_erasing() {
    let tmp = Tmp::new();
    let iso = tmp.make_iso("Win11.iso", 2 * MIB, false);
    let (tree, _) = make_iso_tree(&tmp, "oem", false);
    tmp.write(&format!("oem/{OEM_CMD}"), b"@echo oem");
    let mut ops = FakeOps::new(Os::Mac);
    ops.hardening = Some(files());
    ops.clash = None; // the real refuse_hardening_clash
    ops.run = Some(fake_hdiutil(tree));
    let sink = Sink::new();
    let opts = BuildOptions { hardening: Hardening::Baseline, ..BuildOptions::default() };
    let (result, audits) = capture_audit(|| build_usb_on(&ops, &iso, dev(), &sink.ctx(None), &NoPriv, &opts));
    let text = message(result.unwrap_err());
    assert!(text.contains("SetupComplete.cmd") && text.contains("Untick the hardening"), "{text}");
    assert!(!ops.commands().iter().any(|c| c[0] == "diskutil"), "the drive must not be touched");
    assert!(!ops.called("hash") && !ops.called("win"));
    assert!(audits.iter().any(|(m, _)| m.contains("HARDENING REFUSED")));
    assert!(!audits.iter().any(|(m, _)| m.contains("OPERATION START")));
}

#[test]
fn linux_refuses_an_oem_image_before_wiping() {
    let tmp = Tmp::new();
    let iso = tmp.make_iso("Win11.iso", 2 * MIB, false);
    let (tree, _) = make_iso_tree(&tmp, "oem", true);
    let priv_ = RecordingPriv::new(&tree);
    let mut ops = FakeOps::new(Os::Linux);
    ops.hardening = Some(files());
    ops.clash = None;
    let sink = Sink::new();
    let opts = BuildOptions { hardening: Hardening::Baseline, ..BuildOptions::default() };
    let (result, audits) = capture_audit(|| build_usb_on(&ops, &iso, dev(), &sink.ctx(None), &priv_, &opts));
    assert!(message(result.unwrap_err()).contains("already contains answer-standin.xml"));
    assert_eq!(priv_.kinds(), ["peek", "peek-cleanup"]); // no prep script: the drive was never touched
    assert!(!audits.iter().any(|(m, _)| m.contains("OPERATION START")));
    priv_.cleanup();
}

// ---------------------------------------------------------------------------------------------------------------
// WriteHardeningFilesTests
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn every_file_is_written_with_its_exact_bytes() {
    let tmp = Tmp::new();
    let root = tmp.mkdir("usb");
    write_hardening_files(&root, &files(), None).unwrap();
    for (rel, data) in files() {
        assert_eq!(read(&root, &rel), data, "{rel}");
    }
}

#[test]
fn the_dollar_signs_of_the_oem_path_are_literal() {
    let tmp = Tmp::new();
    let root = tmp.mkdir("usb");
    write_hardening_files(&root, &files(), None).unwrap();
    let names = |p: PathBuf| -> Vec<String> {
        let mut v: Vec<String> =
            fs::read_dir(p).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    };
    assert_eq!(names(root.join("sources")), ["$OEM$"]);
    assert_eq!(names(root.join("sources").join("$OEM$")), ["$$"]);
    assert_eq!(names(root.join("sources/$OEM$/$$/Setup/Scripts")), ["SetupComplete.cmd", "harden.ps1"]);
}

#[test]
fn a_file_of_the_iso_is_replaced() {
    let tmp = Tmp::new();
    tmp.write("usb/answer-standin.xml", b"old");
    write_hardening_files(&tmp.path("usb"), &files(), None).unwrap();
    assert_eq!(tmp.read("usb/answer-standin.xml"), files()["answer-standin.xml"]);
}

#[test]
fn unsafe_paths_are_refused_even_if_the_validator_missed_them() {
    let tmp = Tmp::new();
    let root = tmp.mkdir("usb");
    for rel in ["../evil.txt", "/etc/evil", "a/../../evil", "a\\b", "a//b", "", "./a", "a/\0b"] {
        let mut f = Files::new();
        f.insert(rel.to_string(), b"x".to_vec());
        let err = write_hardening_files(&root, &f, None).unwrap_err();
        assert!(matches!(err, Error::Value(_)), "{rel:?}: {err:?}");
        assert!(err.to_string().starts_with("Refusing an unsafe hardening file path: "));
    }
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    assert!(!tmp.path("evil.txt").exists());
}

#[cfg(unix)]
#[test]
fn a_symlinked_folder_cannot_lead_outside_the_drive() {
    let tmp = Tmp::new();
    let root = tmp.mkdir("usb");
    let outside = tmp.mkdir("outside");
    std::os::unix::fs::symlink(&outside, root.join("sources")).unwrap();
    let mut f = Files::new();
    f.insert("sources/x.txt".into(), b"x".to_vec());
    let err = write_hardening_files(&root, &f, None).unwrap_err();
    assert!(matches!(err, Error::Runtime(_)));
    assert!(err.to_string().contains("outside the drive"), "{err}");
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn a_dangling_symlink_is_never_written_through() {
    let tmp = Tmp::new();
    let root = tmp.mkdir("usb");
    std::os::unix::fs::symlink(tmp.path("nowhere/at/all"), root.join("sources")).unwrap();
    let mut f = Files::new();
    f.insert("sources/x.txt".into(), b"x".to_vec());
    assert!(write_hardening_files(&root, &f, None).is_err());
    assert!(!tmp.path("nowhere").exists());
}

#[cfg(unix)]
#[test]
fn a_symlinked_file_is_not_written_through() {
    let tmp = Tmp::new();
    let root = tmp.mkdir("usb");
    let victim = tmp.write("victim.txt", b"keep");
    std::os::unix::fs::symlink(&victim, root.join("answer-standin.xml")).unwrap();
    let mut f = Files::new();
    f.insert("answer-standin.xml".into(), b"new".to_vec());
    let err = write_hardening_files(&root, &f, None).unwrap_err();
    assert!(matches!(err, Error::Runtime(_)));
    assert_eq!(tmp.read("victim.txt"), b"keep");
}

#[test]
fn a_cancel_stops_between_files() {
    let tmp = Tmp::new();
    let root = tmp.mkdir("usb");
    let token = CancelToken::new();
    token.set();
    let err = write_hardening_files(&root, &files(), Some(&token)).unwrap_err();
    assert!(err.is_canceled());
    assert!(err.drive_touched());
    assert!(!err.written());
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
}

// ---------------------------------------------------------------------------------------------------------------
// VerifyHardeningFilesTests
// ---------------------------------------------------------------------------------------------------------------

fn written_drive() -> (Tmp, PathBuf) {
    let tmp = Tmp::new();
    let root = tmp.mkdir("usb");
    write_hardening_files(&root, &files(), None).unwrap();
    (tmp, root)
}

#[test]
fn identical_files_pass() {
    let (_tmp, root) = written_drive();
    let sink = Sink::new();
    verify_hardening_files(&root, &files(), sink.log(), None).unwrap();
    assert!(sink.has_line_containing("verified"));
    assert!(sink.has_line_containing("Hardening files verified: 3 file(s) identical."));
}

#[test]
fn one_flipped_byte_fails() {
    let (_tmp, root) = written_drive();
    let path = root.join("sources/$OEM$/$$/Setup/Scripts/harden.ps1");
    let mut data = fs::read(&path).unwrap();
    data[100] ^= 0xFF;
    fs::write(&path, data).unwrap();
    let (result, audits) = capture_audit(|| verify_hardening_files(&root, &files(), &|_| {}, None));
    let text = message(result.unwrap_err());
    assert!(text.contains("Verification FAILED") && text.contains("harden.ps1"), "{text}");
    assert!(text.contains("NOT ejected"));
    assert!(audits
        .iter()
        .any(|(m, l)| m == "VERIFICATION FAILED: 1 hardening file(s) differ" && *l == AuditLevel::Error));
}

#[test]
fn a_missing_file_fails() {
    let (_tmp, root) = written_drive();
    fs::remove_file(root.join("answer-standin.xml")).unwrap();
    let text = message(verify_hardening_files(&root, &files(), &|_| {}, None).unwrap_err());
    assert!(text.contains("Verification FAILED"), "{text}");
    assert!(text.contains("answer-standin.xml (missing)"), "{text}");
}

#[test]
fn a_longer_file_fails() {
    let (_tmp, root) = written_drive();
    let path = root.join("answer-standin.xml");
    let mut data = fs::read(&path).unwrap();
    data.push(b'x');
    fs::write(&path, data).unwrap();
    assert!(
        message(verify_hardening_files(&root, &files(), &|_| {}, None).unwrap_err()).contains("Verification FAILED")
    );
}

#[test]
fn a_truncated_file_fails() {
    let (_tmp, root) = written_drive();
    let path = root.join("answer-standin.xml");
    let data = fs::read(&path).unwrap();
    fs::write(&path, &data[..3]).unwrap();
    assert!(
        message(verify_hardening_files(&root, &files(), &|_| {}, None).unwrap_err()).contains("Verification FAILED")
    );
}

#[test]
fn a_cancel_is_a_cancel_not_a_failure() {
    let (_tmp, root) = written_drive();
    let token = CancelToken::new();
    token.set();
    assert!(verify_hardening_files(&root, &files(), &|_| {}, Some(&token)).unwrap_err().is_canceled());
}

// ---------------------------------------------------------------------------------------------------------------
// CopyWindowsPayloadWithExtrasTests (rsync required, like the Python)
// ---------------------------------------------------------------------------------------------------------------

struct Extras {
    tmp: Tmp,
    src: PathBuf,
    dst: PathBuf,
    tree: Vec<(String, Vec<u8>)>,
}

impl Extras {
    fn new(with_unattend: bool) -> Option<Self> {
        if !have("rsync") {
            eprintln!("skipped: rsync not installed");
            return None;
        }
        let tmp = Tmp::new();
        let (src, tree) = make_iso_tree(&tmp, "iso", with_unattend);
        let dst = tmp.mkdir("usb");
        Some(Extras { tmp, src, dst, tree })
    }
}

#[test]
fn the_extras_are_added_and_verified_next_to_the_iso_files() {
    let Some(t) = Extras::new(false) else { return };
    let sink = Sink::new();
    copy_windows_payload(&t.src, &t.dst, &sink.ctx(None), "wimlib hint", None, Some(&files())).unwrap();
    for (rel, data) in t.tree.iter().cloned().chain(files()) {
        assert_eq!(read(&t.dst, &rel), data, "{rel}");
    }
    assert!(sink.lines().iter().any(|l| l == "Adding hardening files..."));
    assert!(sink.calls().iter().any(|c| c.2 == "Adding hardening files..."));
    assert!(sink.has_line_containing("Hardening files verified"));
    assert!(sink.has_line_containing("Verification passed"));
    let _ = &t.tmp;
}

#[test]
fn an_iso_that_already_has_one_of_the_files_is_refused_before_anything_is_copied() {
    let Some(t) = Extras::new(true) else { return };
    let sink = Sink::new();
    let (result, audits) =
        capture_audit(|| copy_windows_payload(&t.src, &t.dst, &sink.ctx(None), "wimlib hint", None, Some(&files())));
    let err = result.unwrap_err();
    assert!(matches!(err, Error::Value(_)));
    assert!(err.to_string().contains("already contains answer-standin.xml"), "{err}");
    assert_eq!(fs::read_dir(&t.dst).unwrap().count(), 0, "not even the ISO's own files were copied");
    assert!(audits.iter().any(|(m, l)| m.contains("HARDENING REFUSED") && *l == AuditLevel::Warning));
}

#[test]
fn the_verification_has_no_exemption_for_a_replaced_iso_file() {
    // Even if a clash slipped past the checks, the byte comparison against the ISO must flag it: the drive holds
    // the ISO's files with one of them replaced by ours.
    let Some(t) = Extras::new(true) else { return };
    copy_tree(&t.src, &t.dst);
    write_hardening_files(&t.dst, &files(), None).unwrap();
    let big = t.src.join("sources/install.wim");
    let sink = Sink::new();
    let err =
        verify_windows_payload(&t.src, &t.dst, "sources/install.wim", &big, &sink.ctx(None), Some(&files()), None)
            .unwrap_err();
    let text = err.to_string();
    assert!(text.contains("Verification FAILED") && text.contains("answer-standin.xml"), "{text}");
}

#[test]
fn a_flipped_byte_in_an_extra_file_is_a_verification_failure() {
    let Some(t) = Extras::new(false) else { return };
    let sink = Sink::new();
    let dst = t.dst.clone();
    // the remount before the read-back: the drive "changes" one byte of an extra file meanwhile
    let reopen = move || -> Result<PathBuf> {
        let path = dst.join("answer-standin.xml");
        let mut data = fs::read(&path)?;
        data[5] ^= 0x01;
        fs::write(&path, data)?;
        Ok(dst.clone())
    };
    let err = copy_windows_payload(&t.src, &t.dst, &sink.ctx(None), "wimlib hint", Some(&reopen), Some(&files()))
        .unwrap_err();
    let text = err.to_string();
    assert!(text.contains("Verification FAILED") && text.contains("answer-standin.xml"), "{text}");
}

#[test]
fn the_iso_files_are_still_checked_when_extras_are_present() {
    let Some(t) = Extras::new(false) else { return };
    let sink = Sink::new();
    let dst = t.dst.clone();
    let reopen = move || -> Result<PathBuf> {
        let path = dst.join("bootmgr");
        let mut data = fs::read(&path)?;
        data[0] = 0xff;
        fs::write(&path, data)?;
        Ok(dst.clone())
    };
    let err = copy_windows_payload(&t.src, &t.dst, &sink.ctx(None), "wimlib hint", Some(&reopen), Some(&files()))
        .unwrap_err();
    assert!(err.to_string().contains("Verification FAILED"), "{err}");
}

#[test]
fn a_cancel_while_adding_leaves_an_unverified_incomplete_drive() {
    let Some(t) = Extras::new(false) else { return };
    let token = CancelToken::new();
    let inner = token.clone();
    // the user clicks Cancel as the hardening files are being added
    let progress = move |_done: u64, _total: u64, text: &str| {
        if text == "Adding hardening files..." {
            inner.set();
        }
    };
    let log = |_: &str| {};
    let ctx = epma_usb_creator::types::Ctx::new(&log, Some(&progress), Some(&token));
    let err = copy_windows_payload(&t.src, &t.dst, &ctx, "hint", None, Some(&files())).unwrap_err();
    assert!(err.is_canceled());
    assert!(err.drive_touched());
    assert!(!err.written());
    assert!(!t.dst.join("answer-standin.xml").exists(), "none of the extras was written");
}

#[test]
fn without_extras_nothing_changes() {
    let Some(t) = Extras::new(false) else { return };
    let sink = Sink::new();
    copy_windows_payload(&t.src, &t.dst, &sink.ctx_no_progress(None), "hint", None, None).unwrap();
    let mut got: Vec<String> =
        fs::read_dir(&t.dst).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    got.sort();
    let mut want: Vec<String> = t.tree.iter().map(|(r, _)| r.split('/').next().unwrap().to_string()).collect();
    want.sort();
    want.dedup();
    assert_eq!(got, want);
    assert!(!sink.lines().iter().any(|l| l.to_lowercase().contains("hardening")));
}

#[test]
fn needs_admin_mirrors_the_platform_and_mode() {
    // Linux and Windows always; macOS only for the byte-for-byte modes
    assert!(needs_admin_on(Os::Linux, Mode::Windows));
    assert!(!needs_admin_on(Os::Mac, Mode::Windows));
    assert!(needs_admin_on(Os::Mac, Mode::Linux));
}

// ---------------------------------------------------------------------------------------------------------------
// the scripts as they were before the hardening feature
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn the_verify_script_is_byte_identical() {
    assert_eq!(sha(VERIFY_RAW_SCRIPT), "41f2378a9194c4218dac1b5ceaac97ab7893a0a0c94302a3a7676da1e3062902");
}

// ---------------------------------------------------------------------------------------------------------------
// FindHardeningClashesTests
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn a_clean_tree_has_no_clash() {
    let tmp = Tmp::new();
    let (root, _) = make_iso_tree(&tmp, "iso", false);
    assert!(find_hardening_clashes(&root, &files()).is_empty());
}

#[test]
fn an_exact_match_is_found() {
    let tmp = Tmp::new();
    let (root, _) = make_iso_tree(&tmp, "iso", true);
    assert_eq!(find_hardening_clashes(&root, &files()), ["answer-standin.xml"]);
}

#[test]
fn the_match_ignores_case_in_every_folder_and_in_the_file_name() {
    let tmp = Tmp::new();
    let (root, _) = make_iso_tree(&tmp, "iso", false);
    tmp.write(&format!("iso/{OEM_CMD}"), b"@echo oem");
    // reported with the spelling of the hardening file, not of the image
    assert_eq!(find_hardening_clashes(&root, &files()), [format!("{OEM}/SetupComplete.cmd")]);
}

#[test]
fn every_folder_of_the_path_is_matched_ignoring_case_even_the_first() {
    let tmp = Tmp::new();
    tmp.write("bare/SOURCES/$Oem$/$$/SETUP/scripts/setupcomplete.CMD", b"@echo oem");
    assert_eq!(find_hardening_clashes(&tmp.path("bare"), &files()), [format!("{OEM}/SetupComplete.cmd")]);
}

#[test]
fn an_existing_folder_alone_is_not_a_clash() {
    let tmp = Tmp::new();
    let (root, _) = make_iso_tree(&tmp, "iso", false);
    fs::create_dir_all(root.join("sources/$OEM$/$$/Setup/Scripts")).unwrap();
    assert!(find_hardening_clashes(&root, &files()).is_empty());
}

#[test]
fn several_clashes_are_all_reported_sorted() {
    let tmp = Tmp::new();
    let (root, _) = make_iso_tree(&tmp, "iso", true);
    tmp.write("iso/sources/$OEM$/$$/Setup/Scripts/harden.ps1", b"x");
    assert_eq!(
        find_hardening_clashes(&root, &files()),
        ["answer-standin.xml".to_string(), format!("{OEM}/harden.ps1")]
    );
}

#[test]
fn a_file_where_a_folder_is_expected_is_no_crash_and_no_clash() {
    let tmp = Tmp::new();
    let (root, _) = make_iso_tree(&tmp, "iso", false);
    tmp.write("iso/sources/$OEM$", b"a file, not a folder");
    assert!(find_hardening_clashes(&root, &files()).is_empty());
}

#[test]
fn no_names_are_hardcoded() {
    let tmp = Tmp::new();
    let (root, _) = make_iso_tree(&tmp, "iso", false);
    tmp.write("iso/other/thing.txt", b"x");
    let mut f = Files::new();
    f.insert("other/Thing.TXT".into(), b"y".to_vec());
    assert_eq!(find_hardening_clashes(&root, &f), ["other/Thing.TXT"]);
}

#[test]
fn the_refusal_names_the_files_and_is_audited() {
    let tmp = Tmp::new();
    let (root, _) = make_iso_tree(&tmp, "iso", true);
    let (result, audits) = capture_audit(|| check_image_for_hardening_clash(&root, &files()));
    let err = result.unwrap_err();
    assert!(matches!(err, Error::Value(_)));
    assert_eq!(
        err.to_string(),
        "This Windows image already contains answer-standin.xml. Adding the hardening files would replace them, so \
         nothing was changed. Untick the hardening option or use another image."
    );
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].1, AuditLevel::Warning);
    assert_eq!(
        audits[0].0,
        "HARDENING REFUSED: the image already contains ['answer-standin.xml']; nothing was changed"
    );
}

#[test]
fn a_clean_tree_is_not_audited() {
    let tmp = Tmp::new();
    let (root, _) = make_iso_tree(&tmp, "iso", false);
    let (result, audits) = capture_audit(|| check_image_for_hardening_clash(&root, &files()));
    result.unwrap();
    assert!(audits.is_empty());
}

// ---------------------------------------------------------------------------------------------------------------
// RefuseHardeningClashTests: both systems against a fake ISO tree (nothing is mounted for real)
// ---------------------------------------------------------------------------------------------------------------

/// Fakes the privileged scripts: "mounts" (copies) the ISO tree into the folder the peek script is given, records
/// every call.
struct RecordingPriv {
    tree: PathBuf,
    fail_on: Mutex<Option<&'static str>>,
    scripts: Mutex<Vec<(String, Vec<String>)>>,
    mounts: Mutex<Vec<PathBuf>>,
}

impl RecordingPriv {
    fn new(tree: &std::path::Path) -> Self {
        RecordingPriv {
            tree: tree.to_path_buf(),
            fail_on: Mutex::new(None),
            scripts: Mutex::new(Vec::new()),
            mounts: Mutex::new(Vec::new()),
        }
    }
    fn failing_on(tree: &std::path::Path, script: &'static str) -> Self {
        let p = Self::new(tree);
        *p.fail_on.lock().unwrap() = Some(script);
        p
    }
    fn cleanup(&self) {
        for folder in self.mounts.lock().unwrap().iter() {
            let _ = fs::remove_dir_all(folder);
        }
    }
    fn recorded(&self) -> Vec<(String, Vec<String>)> {
        self.scripts.lock().unwrap().clone()
    }
    fn kinds(&self) -> Vec<&'static str> {
        self.recorded()
            .iter()
            .map(|(s, _)| {
                if s == LINUX_ISO_PEEK_SCRIPT {
                    "peek"
                } else if s == LINUX_ISO_PEEK_CLEANUP_SCRIPT {
                    "peek-cleanup"
                } else {
                    "other"
                }
            })
            .collect()
    }
}

impl Privilege for RecordingPriv {
    fn run_script(&self, script: &str, _log: Log, args: &[String]) -> Result<()> {
        self.scripts.lock().unwrap().push((script.to_string(), args.to_vec()));
        if *self.fail_on.lock().unwrap() == Some(if script == LINUX_ISO_PEEK_SCRIPT { "peek" } else { "peek-cleanup" })
        {
            return Err(Error::runtime("Privileged command failed"));
        }
        if script == LINUX_ISO_PEEK_SCRIPT {
            copy_tree(&self.tree, std::path::Path::new(&args[1]));
            self.mounts.lock().unwrap().push(PathBuf::from(&args[1]));
        }
        Ok(())
    }
    fn authenticate(&self, _reason: &str) -> Result<bool> {
        Ok(true)
    }
}

fn refuse_tree(tmp: &Tmp, clash: bool) -> PathBuf {
    let (root, _) = make_iso_tree(tmp, "isotree", false);
    if clash {
        tmp.write(&format!("isotree/{OEM_CMD}"), b"@echo oem");
    }
    root
}

fn attach_args(ops: &FakeOps) -> Vec<String> {
    ops.commands().into_iter().find(|c| c.len() > 1 && c[1] == "attach").expect("hdiutil attach")
}

fn hdiutil_calls(ops: &FakeOps) -> Vec<(String, String)> {
    ops.commands().iter().filter(|c| c[0] == "hdiutil").map(|c| (c[0].clone(), c[1].clone())).collect()
}

#[test]
fn macos_reads_the_iso_read_only_and_detaches_it() {
    let tmp = Tmp::new();
    let mut ops = FakeOps::new(Os::Mac);
    ops.run = Some(fake_hdiutil(refuse_tree(&tmp, false)));
    let sink = Sink::new();
    let (result, audits) = capture_audit(|| {
        refuse_hardening_clash_on(&ops, std::path::Path::new("/x/Win11.iso"), &files(), &sink.ctx(None), &NoPriv)
    });
    result.unwrap();
    let attach = attach_args(&ops);
    assert_eq!(attach[2], "/x/Win11.iso");
    assert!(attach.contains(&"-readonly".to_string()));
    assert!(attach.contains(&"-nobrowse".to_string()));
    assert_eq!(
        hdiutil_calls(&ops),
        [("hdiutil".to_string(), "attach".to_string()), ("hdiutil".to_string(), "detach".to_string())]
    );
    let mount = attach[attach.iter().position(|a| a == "-mountpoint").unwrap() + 1].clone();
    assert!(mount.contains("win11peek_"));
    assert!(!std::path::Path::new(&mount).exists(), "the peek folder is gone");
    assert!(audits.is_empty());
    assert!(sink.has_line_containing("Checking that the image does not already contain the hardening files..."));
}

#[test]
fn macos_refuses_an_image_that_has_the_file_and_still_detaches() {
    let tmp = Tmp::new();
    let mut ops = FakeOps::new(Os::Mac);
    ops.run = Some(fake_hdiutil(refuse_tree(&tmp, true)));
    let sink = Sink::new();
    let (result, audits) = capture_audit(|| {
        refuse_hardening_clash_on(&ops, std::path::Path::new("/x/Win11.iso"), &files(), &sink.ctx(None), &NoPriv)
    });
    let text = message(result.unwrap_err());
    assert!(
        text.contains("already contains") && text.contains("SetupComplete.cmd") && text.contains("nothing was changed"),
        "{text}"
    );
    assert_eq!(
        hdiutil_calls(&ops),
        [("hdiutil".to_string(), "attach".to_string()), ("hdiutil".to_string(), "detach".to_string())]
    );
    assert!(audits.iter().any(|(m, _)| m.contains("HARDENING REFUSED")));
}

#[test]
fn macos_detaches_even_when_the_attach_fails() {
    let mut ops = FakeOps::new(Os::Mac);
    ops.run = Some(Box::new(
        |args: &[String]| {
            if args[1] == "attach" {
                Err(Error::runtime("attach failed"))
            } else {
                Ok(0)
            }
        },
    ));
    let sink = Sink::new();
    let err = refuse_hardening_clash_on(&ops, std::path::Path::new("/x/Win11.iso"), &files(), &sink.ctx(None), &NoPriv)
        .unwrap_err();
    assert!(err.to_string().contains("attach failed"));
    assert_eq!(
        hdiutil_calls(&ops),
        [("hdiutil".to_string(), "attach".to_string()), ("hdiutil".to_string(), "detach".to_string())]
    );
}

#[test]
fn linux_mounts_read_only_with_one_script_and_unmounts() {
    let tmp = Tmp::new();
    let priv_ = RecordingPriv::new(&refuse_tree(&tmp, false));
    let ops = FakeOps::new(Os::Linux);
    let sink = Sink::new();
    let (result, audits) = capture_audit(|| {
        refuse_hardening_clash_on(&ops, std::path::Path::new("/x/Win11.iso"), &files(), &sink.ctx(None), &priv_)
    });
    result.unwrap();
    assert_eq!(priv_.kinds(), ["peek", "peek-cleanup"]);
    let recorded = priv_.recorded();
    let (script, args) = &recorded[0];
    let (_cleanup, cleanup_args) = &recorded[1];
    assert_eq!(script, LINUX_ISO_PEEK_SCRIPT);
    assert_eq!(args[0], "/x/Win11.iso");
    let owner: Vec<&str> = args[2].split(':').collect();
    assert!(
        owner.len() == 2 && owner.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())),
        "{}",
        args[2]
    );
    assert_eq!(cleanup_args, &vec![args[1].clone()]);
    for value in args {
        assert!(!script.contains(value.as_str()), "positional parameters only: {value}");
    }
    assert!(script.contains("loop,ro,"));
    assert!(audits.is_empty());
    priv_.cleanup();
}

#[test]
fn linux_refuses_an_image_that_has_the_file_and_still_unmounts() {
    let tmp = Tmp::new();
    let priv_ = RecordingPriv::new(&refuse_tree(&tmp, true));
    let ops = FakeOps::new(Os::Linux);
    let sink = Sink::new();
    let (result, audits) = capture_audit(|| {
        refuse_hardening_clash_on(&ops, std::path::Path::new("/x/Win11.iso"), &files(), &sink.ctx(None), &priv_)
    });
    let text = message(result.unwrap_err());
    assert!(text.contains("already contains") && text.contains("SetupComplete.cmd"), "{text}");
    assert_eq!(priv_.kinds(), ["peek", "peek-cleanup"]);
    assert!(audits.iter().any(|(m, _)| m.contains("HARDENING REFUSED")));
    priv_.cleanup();
}

#[test]
fn linux_unmounts_even_when_the_mount_script_fails_and_never_repeats_it() {
    let tmp = Tmp::new();
    let priv_ = RecordingPriv::failing_on(&refuse_tree(&tmp, false), "peek");
    let ops = FakeOps::new(Os::Linux);
    let sink = Sink::new();
    let err = refuse_hardening_clash_on(&ops, std::path::Path::new("/x/Win11.iso"), &files(), &sink.ctx(None), &priv_)
        .unwrap_err();
    assert!(err.to_string().contains("Privileged command"));
    assert_eq!(priv_.kinds(), ["peek", "peek-cleanup"]);
}

#[test]
fn a_failing_unmount_is_only_a_warning() {
    let tmp = Tmp::new();
    let priv_ = RecordingPriv::failing_on(&refuse_tree(&tmp, false), "peek-cleanup");
    let ops = FakeOps::new(Os::Linux);
    let sink = Sink::new();
    refuse_hardening_clash_on(&ops, std::path::Path::new("/x/Win11.iso"), &files(), &sink.ctx(None), &priv_).unwrap();
    assert!(sink.lines().iter().any(|l| l.starts_with("Warning: cleanup failed")));
    priv_.cleanup();
}

#[test]
fn nothing_is_mounted_when_there_are_no_hardening_files() {
    let tmp = Tmp::new();
    let priv_ = RecordingPriv::new(&refuse_tree(&tmp, false));
    let ops = FakeOps::new(Os::Linux);
    let sink = Sink::new();
    refuse_hardening_clash_on(&ops, std::path::Path::new("/x/Win11.iso"), &Files::new(), &sink.ctx(None), &priv_)
        .unwrap();
    assert!(priv_.recorded().is_empty());
    let mac = FakeOps::new(Os::Mac);
    refuse_hardening_clash_on(&mac, std::path::Path::new("/x/Win11.iso"), &Files::new(), &sink.ctx(None), &NoPriv)
        .unwrap();
    assert!(mac.commands().is_empty());
    assert!(sink.lines().is_empty(), "nothing is even logged");
}

// ---------------------------------------------------------------------------------------------------------------
// PeekScriptTests
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn the_scripts_are_strict_ignore_ctrl_c_and_take_positional_arguments() {
    for script in [LINUX_ISO_PEEK_SCRIPT, LINUX_ISO_PEEK_CLEANUP_SCRIPT] {
        assert!(script.starts_with("set -eu\ntrap '' INT\n"));
        if have("bash") {
            let out = std::process::Command::new("bash").arg("-n").arg("-c").arg(script).output().unwrap();
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        }
    }
    assert!(LINUX_ISO_PEEK_SCRIPT.contains("\"$ISO\" \"$ISO_MNT\""));
    assert!(LINUX_ISO_PEEK_CLEANUP_SCRIPT.contains("umount \"$1\" || true"));
}

#[test]
fn it_mounts_with_the_udf_then_iso9660_type_first_and_autodetection_as_the_last_resort() {
    // The same two mount lines as the prep script of the Linux backend, so the listing matches the copy.
    let typed = "mount -t udf,iso9660 -o loop,ro,uid=\"${OWNER%%:*}\",gid=\"${OWNER##*:}\" \"$ISO\" \"$ISO_MNT\"";
    let untyped = "mount -o loop,ro,uid=\"${OWNER%%:*}\",gid=\"${OWNER##*:}\" \"$ISO\" \"$ISO_MNT\"";
    assert!(LINUX_ISO_PEEK_SCRIPT.contains(typed));
    assert!(LINUX_ISO_PEEK_SCRIPT.contains(untyped));
    assert!(LINUX_ISO_PEEK_SCRIPT.find(typed).unwrap() < LINUX_ISO_PEEK_SCRIPT.find(untyped).unwrap());
}
