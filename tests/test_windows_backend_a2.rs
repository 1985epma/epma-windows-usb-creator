//! Port of the parts of tests/test_windows_backend.py that exercise A2's modules: the plain-Rust tree copy and compare,
//! the split-part hashing, copy_windows_payload / verify_windows_payload with the Windows flow (DISM instead of
//! wimlib, no rsync), the missing-tools check, needs_admin and the privilege helpers of Windows, and the dispatch of
//! build_usb to the Windows backend. (The PowerShell scripts, the disk list parser and the raw disk handle are A4's.)

mod common_a2;

use common_a2::*;
use epma_usb_creator::copyverify::{
    compare_trees, copy_tree_with_progress, copy_windows_payload_on, hash_split_parts, CopyHost,
};
use epma_usb_creator::engine::{build_usb_on, get_missing_dependencies_on, needs_admin_on, Os};
use epma_usb_creator::hash::sha256_file;
use epma_usb_creator::privilege::{
    windows_authenticate, windows_cli_authenticate, WindowsCliPrivilege, WindowsPrivilege,
};
use epma_usb_creator::types::{BuildOptions, CancelToken, Error, Hardening, Log, Mode, Privilege, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

// ---------------------------------------------------------------------------------------------------------------
// TreeCopyTests
// ---------------------------------------------------------------------------------------------------------------

fn make_tree(tmp: &Tmp) -> (PathBuf, PathBuf) {
    tmp.write("src/bootmgr", &b"boot".repeat(100));
    tmp.write("src/Sources/boot.wim", &vec![b'B'; 5000]);
    tmp.write("src/Sources/install.wim", &vec![b'I'; 9000]);
    tmp.write("src/efi/boot/bootx64.efi", &vec![b'E'; 300]);
    (tmp.path("src"), tmp.path("dst"))
}

fn sep_join(a: &str, b: &str) -> String {
    format!("{a}{}{b}", std::path::MAIN_SEPARATOR)
}

#[test]
fn copy_skips_the_big_file_and_reports_bytes() {
    let tmp = Tmp::new();
    let (src, dst) = make_tree(&tmp);
    let seen = Mutex::new(Vec::new());
    let total = copy_tree_with_progress(
        &src,
        &dst,
        Some(&sep_join("Sources", "install.wim")),
        &|n| seen.lock().unwrap().push(n),
        None,
        None,
    )
    .unwrap();
    assert_eq!(total, 400 + 5000 + 300);
    assert_eq!(*seen.lock().unwrap().last().unwrap(), total);
    assert!(dst.join("efi/boot/bootx64.efi").is_file());
    assert!(!dst.join("Sources/install.wim").exists());
}

#[test]
fn skip_ignores_letter_case() {
    let tmp = Tmp::new();
    let (src, dst) = make_tree(&tmp);
    copy_tree_with_progress(&src, &dst, Some("sources/INSTALL.WIM"), &|_| {}, None, None).unwrap();
    assert!(!dst.join("Sources/install.wim").exists());
    assert!(dst.join("Sources/boot.wim").exists());
}

#[test]
fn the_copy_logs_every_file_with_forward_slashes() {
    let tmp = Tmp::new();
    let (src, dst) = make_tree(&tmp);
    let sink = Sink::new();
    copy_tree_with_progress(&src, &dst, None, &|_| {}, None, Some(sink.log())).unwrap();
    // the root's files first (sorted), then the directories in order
    assert_eq!(
        sink.lines(),
        ["bootmgr", "Sources/boot.wim", "Sources/install.wim", "efi/boot/bootx64.efi"].map(String::from).to_vec()
    );
}

#[test]
fn identical_trees_compare_clean() {
    let tmp = Tmp::new();
    let (src, dst) = make_tree(&tmp);
    copy_tree_with_progress(&src, &dst, None, &|_| {}, None, None).unwrap();
    assert_eq!(compare_trees(&src, &dst, None, None).unwrap(), Vec::<String>::new());
}

#[test]
fn missing_and_changed_files_are_reported() {
    let tmp = Tmp::new();
    let (src, dst) = make_tree(&tmp);
    let skip = sep_join("Sources", "install.wim");
    copy_tree_with_progress(&src, &dst, Some(&skip), &|_| {}, None, None).unwrap();
    fs::remove_file(dst.join("bootmgr")).unwrap();
    let path = dst.join("Sources/boot.wim");
    let mut data = fs::read(&path).unwrap();
    data[10] = b'X';
    fs::write(&path, data).unwrap();
    let bad = compare_trees(&src, &dst, Some(&skip), None).unwrap();
    assert_eq!(bad.len(), 2);
    assert!(bad.iter().any(|b| b.contains("bootmgr") && b.contains("missing")), "{bad:?}");
    assert!(bad.iter().any(|b| b.contains("boot.wim") && b.contains("differs")), "{bad:?}");
    assert!(bad.contains(&"bootmgr (missing)".to_string()));
}

#[test]
fn a_file_of_another_size_differs() {
    let tmp = Tmp::new();
    let (src, dst) = make_tree(&tmp);
    copy_tree_with_progress(&src, &dst, None, &|_| {}, None, None).unwrap();
    fs::write(dst.join("bootmgr"), b"short").unwrap();
    assert_eq!(compare_trees(&src, &dst, None, None).unwrap(), ["bootmgr (differs)"]);
}

#[test]
fn a_cancel_stops_the_copy() {
    let tmp = Tmp::new();
    let (src, dst) = make_tree(&tmp);
    let token = CancelToken::new();
    token.set();
    let err = copy_tree_with_progress(&src, &dst, None, &|_| {}, Some(&token), None).unwrap_err();
    assert!(err.is_canceled());
}

#[test]
fn a_cancel_during_the_comparison_is_a_cancel_with_the_image_written() {
    let tmp = Tmp::new();
    let (src, dst) = make_tree(&tmp);
    copy_tree_with_progress(&src, &dst, None, &|_| {}, None, None).unwrap();
    let token = CancelToken::new();
    token.set();
    let err = compare_trees(&src, &dst, None, Some(&token)).unwrap_err();
    assert!(err.is_canceled());
    assert!(err.written());
}

#[test]
fn split_parts_are_hashed_by_name() {
    let tmp = Tmp::new();
    tmp.write("s/install.swm", b"a");
    tmp.write("s/install2.swm", b"b");
    tmp.write("s/boot.wim", b"c");
    let parts = hash_split_parts(&tmp.path("s"), "install", None).unwrap();
    let names: Vec<&str> = parts.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["install.swm", "install2.swm"]);
    assert_eq!(parts[0].1, sha256_file(tmp.path("s/install.swm"), None, None).unwrap());
    // a missing directory is an error, not "no parts"
    assert!(hash_split_parts(&tmp.path("missing"), "install", None).is_err());
}

// ---------------------------------------------------------------------------------------------------------------
// PayloadTests: copy_windows_payload / verify_windows_payload with the Windows flow
// ---------------------------------------------------------------------------------------------------------------

type Runner = Box<dyn Fn(&[String], Log) -> Result<i32> + Send + Sync>;

/// "We are on Windows" (`IS_WINDOWS` patched): no rsync, DISM splits, a tiny FAT32 limit when asked.
struct WindowsHost {
    fat32_max: u64,
    have_wimlib: bool,
    runner: Runner,
    commands: Mutex<Vec<Vec<String>>>,
}

impl WindowsHost {
    fn new(fat32_max: u64) -> Self {
        WindowsHost {
            fat32_max,
            have_wimlib: true,
            runner: Box::new(|_, _| panic!("no command expected")),
            commands: Mutex::new(Vec::new()),
        }
    }
}

impl CopyHost for WindowsHost {
    fn is_windows(&self) -> bool {
        true
    }
    fn fat32_max_file_size(&self) -> u64 {
        self.fat32_max
    }
    fn which(&self, _tool: &str) -> bool {
        self.have_wimlib
    }
    fn run_cmd(&self, args: &[String], log: Log, _cancel: Option<&CancelToken>) -> Result<i32> {
        self.commands.lock().unwrap().push(args.to_vec());
        (self.runner)(args, log)
    }
    fn sync_filesystems(&self, _log: Log) {}
    fn dism_exe(&self) -> PathBuf {
        PathBuf::from("C:\\Windows\\System32\\dism.exe")
    }
}

fn make_iso_tree(tmp: &Tmp, wim_size: usize) -> (PathBuf, PathBuf) {
    tmp.write("iso/bootmgr", &[b'm'; 200]);
    tmp.write("iso/sources/boot.wim", &vec![b'b'; 3000]);
    tmp.write("iso/sources/install.wim", &vec![b'w'; wim_size]);
    tmp.write("iso/efi/boot/bootx64.efi", &[b'e'; 100]);
    (tmp.path("iso"), tmp.mkdir("usb"))
}

fn run_payload(
    host: &WindowsHost,
    iso: &Path,
    usb: &Path,
    reopen: Option<&dyn Fn() -> Result<PathBuf>>,
) -> (Result<()>, Sink) {
    let sink = Sink::new();
    let result = copy_windows_payload_on(host, iso, usb, &sink.ctx_no_progress(None), "no wimlib", reopen, None);
    (result, sink)
}

#[test]
fn copy_and_verify_a_small_image() {
    let tmp = Tmp::new();
    let (iso, usb) = make_iso_tree(&tmp, 4000);
    let (result, sink) = run_payload(&WindowsHost::new(u64::MAX), &iso, &usb, None);
    result.unwrap();
    assert_eq!(tmp.read("usb/sources/install.wim"), vec![b'w'; 4000]);
    assert!(sink.text().contains("Verification passed"));
}

#[test]
fn a_changed_file_after_the_copy_fails_the_check() {
    let tmp = Tmp::new();
    let (iso, usb) = make_iso_tree(&tmp, 4000);
    let usb2 = usb.clone();
    let reopen = move || -> Result<PathBuf> {
        fs::write(usb2.join("efi/boot/bootx64.efi"), b"corrupt")?;
        Ok(usb2.clone())
    };
    let (result, _) = run_payload(&WindowsHost::new(u64::MAX), &iso, &usb, Some(&reopen));
    let err = result.unwrap_err();
    assert!(matches!(err, Error::Runtime(_)));
    assert!(err.to_string().contains("Verification FAILED"), "{err}");
    assert!(err.to_string().contains("efi") && err.to_string().contains("(differs)"), "{err}");
}

/// The fake DISM: writes two parts next to the `/SWMFile:` name and prints a progress line.
fn fake_dism_two_parts() -> Runner {
    Box::new(|cmd: &[String], log: Log| {
        let dst = cmd.iter().find_map(|a| a.strip_prefix("/SWMFile:")).unwrap().to_string();
        fs::write(&dst, b"part1").unwrap();
        fs::write(dst.replace("install.swm", "install2.swm"), b"part2").unwrap();
        log("[===== 50.0% =====]");
        Ok(0)
    })
}

#[test]
fn a_wim_over_the_fat32_limit_is_split_with_dism_and_checked_after_the_reopen() {
    let tmp = Tmp::new();
    let (iso, usb) = make_iso_tree(&tmp, 5000);
    let mut host = WindowsHost::new(4096);
    host.runner = fake_dism_two_parts();
    let (result, sink) = run_payload(&host, &iso, &usb, None);
    result.unwrap();
    let commands = host.commands.lock().unwrap().clone();
    assert_eq!(commands.len(), 1);
    assert!(commands[0][0].to_lowercase().ends_with("dism.exe"));
    assert!(commands[0].contains(&"/Split-Image".to_string()));
    assert!(commands[0].contains(&"/FileSize:3800".to_string()));
    assert!(commands[0].iter().any(|a| a.starts_with("/ImageFile:") && a.ends_with("install.wim")));
    assert!(sink.has_line_containing("50.0%"));
    assert!(sink.has_line_containing("install.wim is 4.9 KB (over 4GB). Splitting with DISM..."));
    assert!(!usb.join("sources/install.wim").exists());
    assert!(sink.text().contains("Verification passed"));
}

#[test]
fn the_split_progress_is_reported_from_the_percentage_lines() {
    let tmp = Tmp::new();
    let (iso, usb) = make_iso_tree(&tmp, 5000);
    let mut host = WindowsHost::new(4096);
    host.runner = fake_dism_two_parts();
    let sink = Sink::new();
    copy_windows_payload_on(&host, &iso, &usb, &sink.ctx(None), "no wimlib", None, None).unwrap();
    let calls = sink.calls();
    let rest_total = 200 + 3000 + 100;
    let total = rest_total + 5000;
    let split = calls.iter().find(|c| c.2 == "Splitting the install image...").expect("a split progress call");
    assert_eq!((split.0, split.1), (rest_total + 5000 * 50 / 100, total));
    assert!(calls.iter().any(|c| c.2 == "Checking the split install image..." && c.0 == total));
}

#[test]
fn a_split_part_changed_by_the_drive_fails_the_check() {
    let tmp = Tmp::new();
    let (iso, usb) = make_iso_tree(&tmp, 5000);
    let mut host = WindowsHost::new(4096);
    host.runner = Box::new(|cmd: &[String], _log: Log| {
        let dst = cmd.iter().find_map(|a| a.strip_prefix("/SWMFile:")).unwrap().to_string();
        fs::write(dst, b"part1").unwrap();
        Ok(0)
    });
    let usb2 = usb.clone();
    let reopen = move || -> Result<PathBuf> {
        fs::write(usb2.join("sources/install.swm"), b"bitrot")?;
        Ok(usb2.clone())
    };
    let (result, _) = run_payload(&host, &iso, &usb, Some(&reopen));
    assert!(result.unwrap_err().to_string().contains("split install image"));
}

#[test]
fn dism_that_leaves_no_part_is_an_error() {
    let tmp = Tmp::new();
    let (iso, usb) = make_iso_tree(&tmp, 5000);
    let mut host = WindowsHost::new(4096);
    host.runner = Box::new(|_, _| Ok(0));
    let (result, _) = run_payload(&host, &iso, &usb, None);
    assert!(result.unwrap_err().to_string().contains("DISM finished but no .swm part was found on the drive."));
}

#[test]
fn an_esd_over_the_limit_needs_wimlib() {
    let tmp = Tmp::new();
    let (iso, usb) = make_iso_tree(&tmp, 10);
    fs::remove_file(iso.join("sources/install.wim")).unwrap();
    fs::write(iso.join("sources/install.esd"), vec![b'z'; 5000]).unwrap();
    let mut host = WindowsHost::new(4096);
    host.have_wimlib = false;
    let (result, _) = run_payload(&host, &iso, &usb, None);
    assert!(result.unwrap_err().to_string().contains("no wimlib"));
}

#[test]
fn an_esd_over_the_limit_is_split_with_wimlib_not_dism() {
    let tmp = Tmp::new();
    let (iso, usb) = make_iso_tree(&tmp, 10);
    fs::remove_file(iso.join("sources/install.wim")).unwrap();
    fs::write(iso.join("sources/install.esd"), vec![b'z'; 5000]).unwrap();
    let mut host = WindowsHost::new(4096);
    host.runner = Box::new(|cmd: &[String], _log: Log| {
        assert_eq!(cmd[0], "wimlib-imagex");
        if cmd[1] == "split" {
            // wimlib-imagex split <image> <first part> 3800
            assert!(cmd[3].ends_with("install.swm"));
            assert_eq!(cmd[4], "3800");
            fs::write(&cmd[3], b"part1").unwrap();
        }
        Ok(0)
    });
    let (result, sink) = run_payload(&host, &iso, &usb, None);
    result.unwrap();
    assert!(sink.has_line_containing("Splitting with wimlib-imagex..."));
    // only DISM's parts are hashed: the read-back asks wimlib to verify the set
    let subcommands: Vec<String> = host.commands.lock().unwrap().iter().map(|c| c[1].clone()).collect();
    assert_eq!(subcommands, ["split", "verify"]);
}

// ---------------------------------------------------------------------------------------------------------------
// PlatformPiecesTests
// ---------------------------------------------------------------------------------------------------------------

fn windows_ops(is_file: impl Fn(&Path) -> bool + Send + Sync + 'static) -> FakeOps {
    let mut ops = FakeOps::new(Os::Windows);
    ops.missing = None;
    ops.is_file_fn = Some(Box::new(is_file));
    ops
}

#[test]
fn nothing_is_missing_when_the_windows_tools_exist() {
    let ops = windows_ops(|_| true);
    for mode in [Mode::Windows, Mode::Linux, Mode::ChromeOs, Mode::Seed] {
        assert_eq!(get_missing_dependencies_on(&ops, mode), Vec::<String>::new(), "{mode}");
    }
}

#[test]
fn a_missing_dism_is_reported_for_windows_mode_only() {
    let ops = windows_ops(|p| !p.to_string_lossy().to_lowercase().contains("dism"));
    assert_eq!(get_missing_dependencies_on(&ops, Mode::Windows), ["dism.exe"]);
    assert_eq!(get_missing_dependencies_on(&ops, Mode::Linux), Vec::<String>::new());
    let none = windows_ops(|_| false);
    assert_eq!(get_missing_dependencies_on(&none, Mode::Windows), ["powershell.exe", "dism.exe"]);
    assert_eq!(get_missing_dependencies_on(&none, Mode::Seed), ["powershell.exe"]);
}

#[test]
fn admin_is_always_needed_on_windows() {
    for mode in Mode::ALL {
        assert!(needs_admin_on(Os::Windows, mode), "{mode}");
    }
}

#[test]
fn the_privilege_helper_never_prompts() {
    let priv_ = WindowsPrivilege;
    assert!(!priv_.needs_password());
    // not elevated: the window is told false, the command line gets an error that says what to do
    assert!(!windows_authenticate(false));
    let err = windows_cli_authenticate(false).unwrap_err();
    assert!(matches!(err, Error::Runtime(_)));
    assert!(err.to_string().starts_with("Administrator privileges are required. Open Windows Terminal or PowerShell"));
    assert!(err.to_string().ends_with("Nothing was changed."));
    // elevated
    assert!(windows_authenticate(true));
    assert!(windows_cli_authenticate(true).unwrap());
    // scripts are never run there
    let err = priv_.run_script("x", &|_| {}, &[]).unwrap_err();
    assert_eq!(err.to_string(), "Privileged shell scripts are not used on Windows.");
    assert!(WindowsCliPrivilege.run_script("x", &|_| {}, &[]).is_err());
}

#[test]
fn the_engine_dispatches_to_the_windows_backend() {
    let tmp = Tmp::new();
    let iso = tmp.make_iso("README.md", 2 * MIB, false);
    let mut ops = FakeOps::new(Os::Windows);
    ops.image = Some(iso.clone()); // validate_image_for_mode is faked
    let sink = Sink::new();
    for mode in [Mode::Windows, Mode::Linux] {
        let opts = BuildOptions { mode, hardening: Hardening::None, ..BuildOptions::default() };
        build_usb_on(&ops, &iso, dev(), &sink.ctx(None), &WindowsPrivilege, &opts).unwrap();
    }
    let steps: Vec<String> = ops.calls().into_iter().filter(|c| c == "win" || c == "raw").collect();
    assert_eq!(steps, ["win", "raw"]);
}
