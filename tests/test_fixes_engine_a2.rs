//! Port of the parts of tests/test_fixes_engine.py that exercise A2's modules: the preflight (missing tools, capacity),
//! the identity of the drive the user confirmed, the SIGINT-proof verify script, the cancel contract of build_usb,
//! the case-insensitive "sources" lookup and the lenient decoding of privileged output.
//! (Download, extraction, sleep inhibitor, backend and CLI details belong to other agents.)

mod common_a2;

use common_a2::*;
use epma_usb_creator::audit::AuditLevel;
use epma_usb_creator::copyverify::{
    copy_windows_payload_on, find_case_insensitive, verify_raw_write_chunked, CopyHost, VERIFY_RAW_SCRIPT,
};
use epma_usb_creator::diskrisk::make_identity;
use epma_usb_creator::engine::{
    build_usb_on, capture_audit, missing_dependencies_hint_on, pin_target_identity, pinned_identity,
    reverify_target_disk_on, validate_image_for_mode_on, Os,
};
use epma_usb_creator::privilege::{CliPrivilege, PrivilegeHelper};
use epma_usb_creator::types::{
    BuildOptions, CancelToken, Disk, Error, Hardening, Identity, Log, Mode, Privilege, Result,
};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

fn opts(mode: Mode, expected_size: Option<u64>) -> BuildOptions {
    BuildOptions { expected_size, mode, eject: true, hardening: Hardening::None }
}

fn value_text(err: Error) -> String {
    match err {
        Error::Value(text) => text,
        other => panic!("expected a ValueError, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// 1 + 8. Missing tools and capacity are refused before anything is touched
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn windows_mode_refuses_when_a_tool_is_missing_and_says_how_to_get_it_on_macos() {
    let tmp = Tmp::new();
    let iso = tmp.make_iso("Win11.iso", 2 * MIB, false);
    let mut ops = FakeOps::new(Os::Mac);
    ops.missing = Some(vec!["wimlib-imagex".to_string()]);
    let text = value_text(validate_image_for_mode_on(&ops, &iso, Mode::Windows, Some(16 * GIB)).unwrap_err());
    assert!(text.contains("wimlib-imagex"), "{text}");
    assert!(text.contains("brew install wimlib"), "{text}");
    assert!(text.contains("Nothing was changed"), "{text}");
}

#[test]
fn windows_mode_names_every_missing_linux_tool_and_the_install_command() {
    let tmp = Tmp::new();
    let iso = tmp.make_iso("Win11.iso", 2 * MIB, false);
    let missing: Vec<String> = ["parted", "mkfs.vfat", "partprobe"].iter().map(|s| s.to_string()).collect();
    let mut ops = FakeOps::new(Os::Linux);
    ops.missing = Some(missing.clone());
    ops.install_cmd = Some(Ok("apt-get install -y dosfstools parted".to_string()));
    let text = value_text(validate_image_for_mode_on(&ops, &iso, Mode::Windows, None).unwrap_err());
    for tool in &missing {
        assert!(text.contains(tool.as_str()), "{text}");
    }
    assert!(text.contains("apt-get install -y dosfstools parted"), "{text}");
    assert!(text.contains("sudo apt-get install"), "{text}");
}

#[test]
fn unknown_package_manager_still_gives_a_hint() {
    let mut ops = FakeOps::new(Os::Linux);
    ops.install_cmd = Some(Err(()));
    let hint = missing_dependencies_hint_on(&ops, &["parted".to_string()]);
    assert!(hint.contains("package manager"), "{hint}");
}

#[test]
fn the_hint_per_system() {
    let ops = FakeOps::new(Os::Windows);
    assert!(missing_dependencies_hint_on(&ops, &["dism.exe".to_string()]).contains("sfc /scannow"));
    let ops = FakeOps::new(Os::Mac);
    assert_eq!(
        missing_dependencies_hint_on(&ops, &["wimlib-imagex".to_string()]),
        "Install wimlib with: brew install wimlib (or use the 'Install missing dependencies' button)."
    );
    assert_eq!(
        missing_dependencies_hint_on(&ops, &["dd".to_string()]),
        "They are part of macOS; the system looks incomplete."
    );
}

#[test]
fn build_usb_stops_before_anything_is_touched() {
    let tmp = Tmp::new();
    let iso = tmp.make_iso("Win11.iso", 2 * MIB, false);
    let mut ops = FakeOps::new(Os::Mac);
    ops.missing = Some(vec!["wimlib-imagex".to_string()]);
    ops.install_cmd = Some(Err(()));
    let sink = Sink::new();
    let err =
        build_usb_on(&ops, &iso, dev(), &sink.ctx(None), &NoPriv, &opts(Mode::Windows, Some(16 * GIB))).unwrap_err();
    assert!(value_text(err).contains("wimlib-imagex"));
    // no hash, no safety re-check, no backend, no sleep inhibitor
    assert_eq!(ops.calls(), Vec::<String>::new());
}

#[test]
fn windows_mode_refuses_an_iso_larger_than_the_drive() {
    let tmp = Tmp::new();
    let iso = tmp.make_iso("Win11.iso", 2 * MIB, false);
    let ops = FakeOps::new(Os::Mac);
    let text = value_text(validate_image_for_mode_on(&ops, &iso, Mode::Windows, Some(MIB as u64)).unwrap_err());
    assert!(text.contains("larger than the drive"), "{text}");
    assert!(text.ends_with("Nothing was changed."), "{text}");
    // exactly as large as the drive is not "larger"
    let ok = validate_image_for_mode_on(&ops, &iso, Mode::Windows, Some(2 * MIB as u64)).unwrap();
    assert_eq!(ok, fs::canonicalize(&iso).unwrap());
}

// ---------------------------------------------------------------------------------------------------------------
// 2. The identity of the drive the user confirmed is pinned and enforced by the re-check
// ---------------------------------------------------------------------------------------------------------------

fn identity(serial: &str) -> Identity {
    make_identity(&[("model", Some("Fake Stick".to_string())), ("serial", Some(serial.to_string()))])
}

fn listed(id: &str, identity: Identity) -> Disk {
    Disk { id: id.into(), size: 16 * GIB, label: "stick".into(), identity, ..Default::default() }
}

fn ops_listing(disks: Vec<Disk>) -> FakeOps {
    let mut ops = FakeOps::new(Os::Linux);
    ops.fake_reverify = false;
    ops.listings = Mutex::new(vec![disks].into());
    ops
}

#[test]
fn a_different_drive_under_the_same_name_is_refused_by_the_real_recheck() {
    let tmp = Tmp::new();
    let iso = tmp.make_iso("ubuntu.iso", 2 * MIB, true);
    // the user confirmed serial ABC123; the re-check sees another stick under the same name
    pin_target_identity("disk901", Some(identity("ABC123")));
    let ops = ops_listing(vec![listed("disk901", identity("ZZZ999"))]);
    let sink = Sink::new();
    let (result, audits) = capture_audit(|| {
        build_usb_on(&ops, &iso, "disk901", &sink.ctx(None), &NoPriv, &opts(Mode::Linux, Some(16 * GIB)))
    });
    let text = result.unwrap_err().to_string();
    assert!(text.contains("no longer looks like the drive you confirmed"), "{text}");
    assert!(text.contains("(serial changed)"), "{text}");
    assert!(!ops.called("raw"), "nothing may be written");
    assert!(audits.iter().any(|(m, l)| m.contains("identity changed") && *l == AuditLevel::Error));
    assert!(pinned_identity("disk901").is_none(), "the pin is consumed by the re-check");
}

#[test]
fn the_same_drive_passes_the_recheck_and_the_pin_is_consumed() {
    pin_target_identity("disk902", Some(identity("ABC123")));
    assert_eq!(pinned_identity("disk902"), Some(identity("ABC123")));
    let ops = ops_listing(vec![listed("disk902", identity("ABC123"))]);
    let sink = Sink::new();
    reverify_target_disk_on(&ops, "disk902", Some(16 * GIB), sink.log(), None).unwrap();
    assert!(
        sink.has_line_containing("Safety re-check passed: /dev/disk902 is still the same external drive (16.0 GB).")
    );
    assert!(pinned_identity("disk902").is_none());
}

#[test]
fn an_explicit_identity_wins_and_leaves_the_pin_alone() {
    pin_target_identity("disk903", Some(identity("PINNED")));
    let ops = ops_listing(vec![listed("disk903", identity("ABC123"))]);
    let sink = Sink::new();
    reverify_target_disk_on(&ops, "disk903", None, sink.log(), Some(&identity("ABC123"))).unwrap();
    assert_eq!(pinned_identity("disk903"), Some(identity("PINNED")));
    pin_target_identity("disk903", None);
}

#[test]
fn an_empty_identity_pins_nothing_and_clears_a_pin() {
    pin_target_identity("disk904", Some(identity("ABC123")));
    pin_target_identity("disk904", Some(Vec::new()));
    assert!(pinned_identity("disk904").is_none());
    pin_target_identity("disk904", Some(identity("ABC123")));
    pin_target_identity("disk904", None);
    assert!(pinned_identity("disk904").is_none());
}

#[test]
fn a_listing_without_identity_pins_nothing_so_nothing_is_compared() {
    let ops = ops_listing(vec![listed("disk905", Vec::new())]);
    reverify_target_disk_on(&ops, "disk905", None, &|_| {}, None).unwrap();
}

#[test]
fn a_disk_that_is_gone_or_resized_aborts() {
    let ops = ops_listing(vec![listed("disk906", Vec::new())]);
    let (gone, audits) = capture_audit(|| reverify_target_disk_on(&ops, "disk907", None, &|_| {}, None));
    let text = gone.unwrap_err().to_string();
    assert!(text.contains("Aborted for safety: /dev/disk907 is no longer listed as an external drive."), "{text}");
    assert!(text.contains("Click 'Refresh USB drives list'"), "{text}");
    assert!(audits.iter().any(|(m, _)| m == "ABORTED: disk907 is no longer an eligible external disk"));

    let (resized, audits) = capture_audit(|| reverify_target_disk_on(&ops, "disk906", Some(8 * GIB), &|_| {}, None));
    let text = resized.unwrap_err().to_string();
    assert!(text.contains("now reports a different size (16.0 GB instead of 8.0 GB)"), "{text}");
    assert!(audits.iter().any(|(m, _)| m == &format!("ABORTED: disk906 size changed {} -> {}", 8 * GIB, 16 * GIB)));
}

// ---------------------------------------------------------------------------------------------------------------
// 3. Ctrl-C reaches the root script: the verify script must ignore SIGINT and stop through the flag file
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn the_verify_script_starts_with_set_eu_then_ignores_sigint() {
    let lines: Vec<&str> = VERIFY_RAW_SCRIPT.lines().collect();
    assert_eq!(lines[0], "set -eu");
    assert_eq!(lines[1], "trap '' INT");
}

#[cfg(unix)]
#[test]
fn the_verify_script_survives_ctrl_c_and_reports_the_cancel() {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let tmp = Tmp::new();
    let bin = tmp.mkdir("bin");
    let pidfile = tmp.path("dd.pid");
    let flag = tmp.path("cancel-flag");
    // A slow `dd` makes the first chunk last long enough to interrupt it.
    let stub = bin.join("dd");
    fs::write(&stub, format!("#!/bin/sh\necho $$ > \"{}\"\nsleep 1.5\n", pidfile.display())).unwrap();
    fs::set_permissions(&stub, fs::Permissions::from_mode(0o700)).unwrap();
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    // Own process group, so the SIGINT below reaches only this script and its children.
    let mut child = Command::new("bash")
        .args(["-c", VERIFY_RAW_SCRIPT, "win11_usb_creator"])
        .arg(tmp.path("in.iso"))
        .arg(tmp.path("dev"))
        .args(["20", "10"])
        .arg(&flag)
        .env("PATH", path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(6);
    while !pidfile.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(pidfile.exists(), "the stub dd never started");
    // what a terminal Ctrl-C does
    unsafe { libc::kill(-(child.id() as i32), libc::SIGINT) };
    std::thread::sleep(Duration::from_millis(400));
    assert!(child.try_wait().unwrap().is_none(), "Ctrl-C killed the verification script");
    fs::File::create(&flag).unwrap();
    let mut out = String::new();
    child.stdout.take().unwrap().read_to_string(&mut out).unwrap();
    let status = child.wait().unwrap();
    assert!(status.success());
    assert!(out.contains("VERIFY_CANCELED"), "{out}");
}

// ---------------------------------------------------------------------------------------------------------------
// 6. Cancel: was the drive touched?
// ---------------------------------------------------------------------------------------------------------------

struct Cancel {
    tmp: Tmp,
    iso: PathBuf,
    ops: FakeOps,
}

impl Cancel {
    fn new() -> Self {
        let tmp = Tmp::new();
        let iso = tmp.make_iso("ubuntu.iso", 2 * MIB, true);
        Cancel { tmp, iso, ops: FakeOps::new(Os::Mac) }
    }
    fn build(&self, cancel: Option<&CancelToken>) -> (Result<bool>, Vec<String>) {
        let sink = Sink::new();
        let (result, audits) = capture_audit(|| {
            build_usb_on(&self.ops, &self.iso, dev(), &sink.ctx(cancel), &NoPriv, &opts(Mode::Linux, Some(16 * GIB)))
        });
        let _ = &self.tmp;
        (result, audits.into_iter().map(|(m, _)| m).collect())
    }
}

fn canceled_flags(err: &Error) -> (bool, bool) {
    assert!(err.is_canceled(), "expected a cancel, got {err:?}");
    (err.drive_touched(), err.written())
}

#[test]
fn the_cancel_defaults() {
    let e = Error::canceled();
    assert_eq!(canceled_flags(&e), (true, false));
    assert_eq!(e.to_string(), "Canceled by the user.");
    assert_eq!(canceled_flags(&Error::canceled_with("x", false, false)), (false, false));
    assert_eq!(canceled_flags(&Error::canceled_with("x", true, true)), (true, true));
}

#[test]
fn canceled_while_hashing_leaves_the_drive_untouched() {
    let mut t = Cancel::new();
    t.ops.hash = None; // the real hash_iso_for_audit: it sees the cancel flag
    let token = CancelToken::new();
    token.set();
    let (result, audits) = t.build(Some(&token));
    let err = result.unwrap_err();
    assert_eq!(canceled_flags(&err), (false, false));
    assert_eq!(err.to_string(), "Canceled by the user before the drive was touched.");
    assert!(audits.iter().any(|a| a.contains("before the drive was touched")), "{audits:?}");
    assert!(!audits.iter().any(|a| a.contains("left unusable")));
    assert!(!t.ops.called("raw"));
}

#[test]
fn canceled_just_before_the_destructive_step() {
    let mut t = Cancel::new();
    let token = CancelToken::new();
    let inner = token.clone();
    t.ops.hash = Some(Box::new(move || {
        inner.set();
        Ok("0".repeat(64))
    }));
    let (result, audits) = t.build(Some(&token));
    assert_eq!(canceled_flags(&result.unwrap_err()), (false, false));
    assert!(!audits.iter().any(|a| a.starts_with("DESTRUCTIVE OPERATION START")), "{audits:?}");
    assert!(!t.ops.called("raw"));
}

#[test]
fn canceled_during_the_write_means_an_unusable_drive() {
    let t = Cancel::new();
    *t.ops.raw.lock().unwrap() = Some(Err(Error::canceled_with("stopped", true, false)));
    let (result, audits) = t.build(None);
    assert_eq!(canceled_flags(&result.unwrap_err()), (true, false));
    assert!(audits.iter().any(|a| a.contains("left unusable")), "{audits:?}");
}

#[test]
fn canceled_during_verification_says_written_but_not_verified() {
    let t = Cancel::new();
    *t.ops.raw.lock().unwrap() = Some(Err(Error::canceled_with("stopped", true, true)));
    let (result, audits) = t.build(None);
    assert_eq!(canceled_flags(&result.unwrap_err()), (true, true));
    assert!(audits.iter().any(|a| a.contains("written but NOT verified")), "{audits:?}");
    assert!(!audits.iter().any(|a| a.contains("left unusable")));
}

#[test]
fn a_failure_is_audited_with_the_python_exception_name() {
    let t = Cancel::new();
    *t.ops.raw.lock().unwrap() = Some(Err(Error::runtime("dd failed")));
    let (result, audits) = t.build(None);
    assert_eq!(result.unwrap_err().to_string(), "dd failed");
    assert!(
        audits.iter().any(|a| a.contains("DESTRUCTIVE OPERATION FAILED on /dev/disk9: RuntimeError")),
        "{audits:?}"
    );
}

#[test]
fn a_completed_write_is_audited_with_the_eject_result() {
    let t = Cancel::new();
    *t.ops.raw.lock().unwrap() = Some(Ok(false));
    let (result, audits) = t.build(None);
    assert!(!result.unwrap());
    assert!(audits.iter().any(|a| a == "DESTRUCTIVE OPERATION COMPLETED on /dev/disk9 (ejected=False)"), "{audits:?}");
    assert!(t.ops.called("sleep"), "the sleep inhibitor is held for the write");
}

struct CancelingPriv;
impl Privilege for CancelingPriv {
    fn run_script(&self, _script: &str, log: Log, _args: &[String]) -> Result<()> {
        log("VERIFY_CANCELED");
        Ok(())
    }
    fn authenticate(&self, _reason: &str) -> Result<bool> {
        Ok(true)
    }
}

#[test]
fn verify_raw_write_cancel_is_marked_as_written() {
    let tmp = Tmp::new();
    let iso = tmp.make_iso("ubuntu.iso", 2 * MIB, true);
    let sink = Sink::new();
    let err = verify_raw_write_chunked(
        &iso,
        "/dev/null-test",
        &sink.ctx_no_progress(None),
        &CancelingPriv,
        16 * MIB as u64,
        &|| 0.0,
    )
    .unwrap_err();
    assert_eq!(canceled_flags(&err), (true, true));
    assert!(sink.has_line_containing("NOT verified"));
}

#[test]
fn verify_raw_write_cancel_before_start_is_marked_as_written() {
    let tmp = Tmp::new();
    let iso = tmp.make_iso("ubuntu.iso", 2 * MIB, true);
    let token = CancelToken::new();
    token.set();
    let sink = Sink::new();
    let err =
        verify_raw_write_chunked(&iso, "/dev/null-test", &sink.ctx(Some(&token)), &NoPriv, 16 * MIB as u64, &|| 0.0)
            .unwrap_err();
    assert_eq!(canceled_flags(&err), (true, true));
}

// ---------------------------------------------------------------------------------------------------------------
// 9. Case-insensitive "sources" lookup
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn find_case_insensitive_returns_the_spelling_on_disk() {
    let tmp = Tmp::new();
    tmp.write("iso/Sources/Install.WIM", b"x");
    assert_eq!(find_case_insensitive(&tmp.path("iso"), "sources"), Some(tmp.path("iso/Sources")));
    assert_eq!(
        find_case_insensitive(&tmp.path("iso/Sources"), "install.wim"),
        Some(tmp.path("iso/Sources/Install.WIM"))
    );
    assert_eq!(find_case_insensitive(&tmp.path("iso"), "nothing"), None);
    assert_eq!(find_case_insensitive(&tmp.path("missing-dir"), "sources"), None);
    // a file is not a directory: nothing to list
    assert_eq!(find_case_insensitive(&tmp.path("iso/Sources/Install.WIM"), "x"), None);
}

/// Records the commands instead of running them (`mock.patch.object(app, "run_cmd", fake_run_cmd)`).
struct RecordingHost {
    commands: Mutex<Vec<Vec<String>>>,
}

impl CopyHost for RecordingHost {
    fn is_windows(&self) -> bool {
        false
    }
    fn which(&self, _tool: &str) -> bool {
        false
    }
    fn run_cmd(&self, args: &[String], _log: Log, _cancel: Option<&CancelToken>) -> Result<i32> {
        self.commands.lock().unwrap().push(args.to_vec());
        Ok(0)
    }
    fn sync_filesystems(&self, _log: Log) {}
}

fn copy_recording(tmp: &Tmp, rel: &str) -> Vec<Vec<String>> {
    tmp.write(&format!("iso/{rel}"), &b"wim data".repeat(100));
    tmp.write("iso/BOOTMGR", b"boot");
    let usb = tmp.mkdir("usb");
    let host = RecordingHost { commands: Mutex::new(Vec::new()) };
    let sink = Sink::new();
    copy_windows_payload_on(&host, &tmp.path("iso"), &usb, &sink.ctx_no_progress(None), "no wimlib", None, None)
        .unwrap();
    let commands = host.commands.lock().unwrap().clone();
    commands
}

#[test]
fn mixed_case_directory_and_file_are_found() {
    let tmp = Tmp::new();
    let commands = copy_recording(&tmp, "Sources/Install.wim");
    let rsync = commands.iter().find(|c| c[..2] == ["rsync", "-rv"]).expect("the copy command");
    // the real spelling, not "sources/install.wim"
    assert!(rsync.contains(&"--exclude=Sources/Install.wim".to_string()), "{rsync:?}");
    let copied: Vec<String> = fs::read_dir(tmp.path("usb"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.to_lowercase() == "sources")
        .collect();
    assert_eq!(copied.len(), 1);
    assert!(tmp.path(&format!("usb/{}/Install.wim", copied[0])).is_file());
}

#[test]
fn upper_case_esd() {
    let tmp = Tmp::new();
    let commands = copy_recording(&tmp, "SOURCES/INSTALL.ESD");
    let rsync = commands.iter().find(|c| c[..2] == ["rsync", "-rv"]).expect("the copy command");
    assert!(rsync.contains(&"--exclude=SOURCES/INSTALL.ESD".to_string()), "{rsync:?}");
}

#[test]
fn still_fails_clearly_without_an_install_image() {
    let tmp = Tmp::new();
    tmp.write("iso/Sources/boot.wim", b"x");
    let usb = tmp.mkdir("usb");
    let host = RecordingHost { commands: Mutex::new(Vec::new()) };
    let sink = Sink::new();
    let err = copy_windows_payload_on(&host, &tmp.path("iso"), &usb, &sink.ctx_no_progress(None), "h", None, None)
        .unwrap_err();
    assert!(err.to_string().contains("Could not find sources/install.wim"), "{err}");
    assert!(host.commands.lock().unwrap().is_empty());
}

// ---------------------------------------------------------------------------------------------------------------
// 12. Output that is not UTF-8 must not abort a copy
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn cli_privilege_run_script_as_root_decodes_leniently() {
    if !have("bash") {
        return;
    }
    let sink = Sink::new();
    let priv_ = CliPrivilege::with_sys(Arc::new(RootSys));
    priv_.run_script("printf 'caf\\351 file.txt\\n'", sink.log(), &[]).unwrap();
    assert!(sink.lines().contains(&"caf\u{FFFD} file.txt".to_string()), "{:?}", sink.lines());
}

#[test]
fn privilege_helper_run_script_as_root_decodes_leniently() {
    if !have("bash") {
        return;
    }
    let sink = Sink::new();
    let helper = PrivilegeHelper::with_sys(FakePrompt::with_answers(&[]), Arc::new(RootSys));
    helper.run_script("printf 'caf\\351 file.txt\\n'", sink.log(), &[]).unwrap();
    assert!(sink.lines().contains(&"caf\u{FFFD} file.txt".to_string()), "{:?}", sink.lines());
}
