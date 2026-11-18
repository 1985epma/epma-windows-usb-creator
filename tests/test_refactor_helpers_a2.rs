//! Port of the parts of tests/test_refactor_helpers.py that exercise A2's modules: SharedRuleTests (needs_admin,
//! image_exceeds_drive, chromeos_drive_too_small), DiskEntryTests, SudoRefreshTests (the keep-alive shared by the
//! window's and the command line's privilege helpers; sudo is faked through `SudoSys`).
//! (SilentRemove, Sha256File, HashStream, PartialDownloadHash, ModeTable, PackageTable, EtaText, DiskutilHelper,
//! ModalDialog, DownloadWidgets belong to other agents.)

mod common_a2;

use common_a2::*;
use epma_usb_creator::constants::{CHROMEOS_MIN_USB_BYTES, SUDO_TIMEOUT};
use epma_usb_creator::diskrisk::{build_disk_label, disk_entry, make_identity};
use epma_usb_creator::engine::{chromeos_drive_too_small, image_exceeds_drive, needs_admin_on, Os};
use epma_usb_creator::privilege::{sudo_refresh_loop, sudo_refresh_with, CliPrivilege, PrivilegeHelper};
use epma_usb_creator::types::{CancelToken, Mode, Privilege, Volume, Volumes};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

// ---------------------------------------------------------------------------------------------------------------
// SharedRuleTests
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn needs_admin_follows_platform_and_mode() {
    for mode in Mode::ALL {
        assert!(needs_admin_on(Os::Linux, mode), "{mode}");
    }
    assert!(!needs_admin_on(Os::Mac, Mode::Windows));
    assert!(needs_admin_on(Os::Mac, Mode::Linux));
    assert!(needs_admin_on(Os::Mac, Mode::ChromeOs));
}

#[test]
fn needs_admin_for_the_seed_drive_mirrors_windows_mode() {
    // tests/test_hardening_engine_seed.py: test_needs_admin_mirrors_windows_mode
    assert!(needs_admin_on(Os::Linux, Mode::Seed));
    assert!(!needs_admin_on(Os::Mac, Mode::Seed));
    for os in [Os::Linux, Os::Mac, Os::Windows] {
        assert_eq!(needs_admin_on(os, Mode::Seed), needs_admin_on(os, Mode::Windows));
    }
}

#[test]
fn image_exceeds_drive_rule() {
    assert!(image_exceeds_drive(9, 8));
    assert!(!image_exceeds_drive(8, 8));
    assert!(!image_exceeds_drive(7, 8));
    // an unknown size (0) is never a reason to refuse
    assert!(!image_exceeds_drive(9, 0));
    assert!(!image_exceeds_drive(0, 8));
}

#[test]
fn chromeos_drive_too_small_rule() {
    let small = CHROMEOS_MIN_USB_BYTES - 1;
    let big = CHROMEOS_MIN_USB_BYTES;
    assert!(chromeos_drive_too_small(Mode::ChromeOs, small));
    assert!(!chromeos_drive_too_small(Mode::ChromeOs, big));
    assert!(!chromeos_drive_too_small(Mode::ChromeOs, 0)); // unknown size
    assert!(!chromeos_drive_too_small(Mode::Linux, small));
    assert!(!chromeos_drive_too_small(Mode::Windows, small));
}

// ---------------------------------------------------------------------------------------------------------------
// DiskEntryTests
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn entry_has_the_six_fields_and_a_label_built_from_them() {
    let vols = vec![Volume {
        name: Some("STICK".into()),
        filesystem: Some("FAT32".into()),
        size: Some(1),
        used: None,
        mountpoint: None,
    }];
    let identity = make_identity(&[("serial", Some("123".to_string())), ("model", Some("Ultra".to_string()))]);
    let size = 58 * 1024 * 1024 * 1024;
    let entry = disk_entry("disk4", size, Some("SanDisk Ultra"), Some(vols.clone()), identity.clone());
    assert_eq!(entry.id, "disk4");
    assert_eq!(entry.size, size);
    assert_eq!(entry.model.as_deref(), Some("SanDisk Ultra"));
    assert_eq!(entry.label, build_disk_label("/dev/disk4", Some("SanDisk Ultra"), size, Some(&vols)));
    assert!(entry.label.starts_with("/dev/disk4 — SanDisk Ultra — 58.0 GB — 1 volume ('STICK')"), "{}", entry.label);
    assert_eq!(entry.volumes, Volumes::List(vols));
    assert_eq!(entry.identity, identity);
}

#[test]
fn unknown_contents_and_no_model() {
    let entry = disk_entry("sdb", 8 * 1024 * 1024 * 1024, Some(""), None, Vec::new());
    assert_eq!(entry.label, "/dev/sdb — 8.0 GB — contents unknown");
    assert_eq!(entry.volumes, Volumes::Unknown);
}

// ---------------------------------------------------------------------------------------------------------------
// SudoRefreshTests
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn refresh_reports_whether_sudo_accepted_us() {
    for (code, expected) in [(0, true), (1, false)] {
        let mut sys = FakeSys::new();
        sys.quiet = Box::new(move |_, _| Some(code));
        assert_eq!(sudo_refresh_with(&sys), expected);
        let calls = sys.calls();
        assert_eq!(
            calls,
            vec![SysCall::Quiet {
                argv: ["sudo", "-n", "-v"].map(String::from).to_vec(),
                input: None,
                timeout: Duration::from_secs(SUDO_TIMEOUT),
            }]
        );
    }
}

#[test]
fn refresh_never_raises() {
    // could not start, or ran out of time
    let mut sys = FakeSys::new();
    sys.quiet = Box::new(|_, _| None);
    assert!(!sudo_refresh_with(&sys));
}

#[test]
fn loop_refreshes_until_stopped() {
    let stop = CancelToken::new();
    let calls = AtomicUsize::new(0);
    let inner = stop.clone();
    sudo_refresh_loop(
        &stop,
        None,
        Duration::from_millis(10),
        &|| {
            if calls.fetch_add(1, Ordering::SeqCst) + 1 == 3 {
                inner.set();
            }
            true
        },
        &|| 0.0,
    );
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[test]
fn loop_gives_up_after_max_seconds() {
    // a fake clock makes this independent of how slow the machine is: the deadline is read once at the start
    // (t=0 -> 5), the first check is inside it, the second is past it
    let ticks = [0.0, 1.0, 9.0];
    let next = AtomicUsize::new(0);
    let refreshed = AtomicUsize::new(0);
    sudo_refresh_loop(
        &CancelToken::new(),
        Some(Duration::from_secs(5)),
        Duration::from_millis(1),
        &|| {
            refreshed.fetch_add(1, Ordering::SeqCst);
            true
        },
        &|| ticks[next.fetch_add(1, Ordering::SeqCst)],
    );
    assert_eq!(refreshed.load(Ordering::SeqCst), 1);
}

#[test]
fn both_helpers_run_the_loop_and_end_it_on_request() {
    // the command line's helper
    let cli = CliPrivilege::with_sys(Arc::new(FakeSys::new()));
    assert!(cli.authenticate("x").unwrap());
    assert!(cli.keepalive_running());
    cli.clear_cached_password();
    assert!(cli.join_keepalive(Duration::from_secs(5)));
    assert!(!cli.keepalive_running());

    // the window's helper: a password that arms sudo's timestamp starts the keep-alive...
    let sys = Arc::new(FakeSys::new());
    let helper = PrivilegeHelper::with_sys(FakePrompt::with_answers(&[Some("secret")]), sys.clone());
    assert!(helper.authenticate("x").unwrap());
    assert!(helper.uses_timestamp());
    // ...and clearing it ends the sudo session (`sudo -k`) and forgets everything
    helper.clear_cached_password();
    assert!(!helper.uses_timestamp());
    assert!(!helper.has_cached_password());
    assert_eq!(sys.quiet_argvs().last().unwrap(), &["sudo", "-k"].map(String::from).to_vec());
}
