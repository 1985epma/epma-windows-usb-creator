//! The macOS hardening script (assets/harden-macos.sh) and the seed drive built around it. New in the Rust build.
//!
//! The script runs for real, in bash, against a throw-away "fake root": every path is taken below a temporary
//! directory and the live commands (`defaults`, `socketfilterfw`, `spctl`, `fdesetup`, `csrutil`, `launchctl`...) are
//! replaced by small stand-ins that keep their state in files. Nothing here can reach the real system settings.
//! The same hidden hook (`EPMA_HARDEN_TEST_ROOT`) is what the Linux script's tests use.
#![cfg(unix)]

use epma_usb_creator::harden_macos::{
    describe_hardening_macos_applied, macos_hardening_script, MACOS_HARDENING_NOT_CHANGED, MACOS_HARDENING_SETTINGS,
};
use epma_usb_creator::seed_files::{
    hardening_files_seed, macos_seed_launcher, seed_label, SEED_MACOS_LAUNCHERS, SEED_MACOS_README_WIDTH,
};
use epma_usb_creator::types::{Hardening, SeedTarget};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const LOGINWINDOW: &str = "com.apple.loginwindow";
const SOFTWAREUPDATE: &str = "com.apple.SoftwareUpdate";

/// One stand-in for every live command. It logs each call to `calls.log` and keeps its state under `store/`.
const STUB: &str = r#"#!/bin/bash
R="${EPMA_HARDEN_TEST_ROOT}"
NAME="$(basename "$0")"
echo "$NAME $*" >>"$R/calls.log"
S="$R/store"
mkdir -p "$S/defaults"
failing() { [ -e "$S/fail.$1" ]; }
dfile() { printf '%s/defaults/%s__%s' "$S" "$(basename "$1")" "$2"; }
case "$NAME" in
  uname) cat "$S/uname" 2>/dev/null || echo Darwin ;;
  sw_vers) echo 15.1 ;;
  defaults)
    sub="$1"
    shift
    case "$sub" in
      read)
        f="$(dfile "$1" "$2")"
        if [ ! -e "$f" ]; then echo "Error: Could not find key '$2' in domain '$1'." >&2; exit 1; fi
        cut -d: -f2- "$f"
        ;;
      read-type)
        f="$(dfile "$1" "$2")"
        if [ ! -e "$f" ]; then exit 1; fi
        case "$(cut -d: -f1 "$f")" in
          bool) echo "Type is boolean" ;;
          string) echo "Type is string" ;;
          int) echo "Type is integer" ;;
          *) echo "Type is array" ;;
        esac
        ;;
      write)
        failing defaults_write && { echo "write refused" >&2; exit 1; }
        f="$(dfile "$1" "$2")"
        case "$3" in
          -bool) if [ "$4" = true ]; then echo "bool:1" >"$f"; else echo "bool:0" >"$f"; fi ;;
          -int) echo "int:$4" >"$f" ;;
          -string) echo "string:$4" >"$f" ;;
        esac
        ;;
      delete)
        failing defaults_delete && { echo "delete refused" >&2; exit 1; }
        rm -f "$(dfile "$1" "$2")"
        ;;
    esac
    ;;
  socketfilterfw)
    case "$1" in
      --getglobalstate)
        v="$(cat "$S/fw_global" 2>/dev/null || echo 0)"
        if [ "$v" = 0 ]; then echo "Firewall is disabled. (State = 0)"; else echo "Firewall is enabled. (State = $v)"; fi
        ;;
      --setglobalstate)
        failing fw && { echo "refused" >&2; exit 1; }
        if [ "$2" = on ]; then echo 1 >"$S/fw_global"; else echo 0 >"$S/fw_global"; fi
        ;;
      --getstealthmode)
        if [ "$(cat "$S/fw_stealth" 2>/dev/null || echo 0)" = 1 ]; then echo "Firewall stealth mode is on"; else echo "Firewall stealth mode is off"; fi
        ;;
      --setstealthmode)
        failing stealth && { echo "refused" >&2; exit 1; }
        if [ "$2" = on ]; then echo 1 >"$S/fw_stealth"; else echo 0 >"$S/fw_stealth"; fi
        ;;
    esac
    ;;
  spctl)
    case "$1" in
      --status)
        if [ "$(cat "$S/gk" 2>/dev/null || echo 1)" = 1 ]; then echo "assessments enabled"; else echo "assessments disabled"; fi
        ;;
      --master-enable)
        failing gk && { echo "refused" >&2; exit 1; }
        echo 1 >"$S/gk"
        ;;
      --master-disable) echo 0 >"$S/gk" ;;
    esac
    ;;
  fdesetup)
    if [ "$(cat "$S/filevault" 2>/dev/null || echo 1)" = 1 ]; then echo "FileVault is On."; else echo "FileVault is Off."; fi
    ;;
  csrutil)
    if [ "$(cat "$S/sip" 2>/dev/null || echo 1)" = 1 ]; then echo "System Integrity Protection status: enabled."; else echo "System Integrity Protection status: disabled."; fi
    ;;
  launchctl)
    [ -e "$S/sshd" ]
    ;;
esac
"#;

const STUB_NAMES: &[&str] =
    &["uname", "sw_vers", "defaults", "socketfilterfw", "spctl", "fdesetup", "csrutil", "launchctl"];

/// What the stand-ins keep: a "fresh Mac" (firewall off, stealth off, Gatekeeper on, nothing set) unless a test
/// changes it.
struct Fake {
    dir: tempfile::TempDir,
}

struct Run {
    code: i32,
    out: String,
    err: String,
}

impl Run {
    fn all(&self) -> String {
        format!("{}{}", self.out, self.err)
    }
}

impl Fake {
    fn new() -> Fake {
        let dir = tempfile::tempdir().expect("tempdir");
        let stubs = dir.path().join("stubs");
        fs::create_dir_all(&stubs).unwrap();
        for name in STUB_NAMES {
            let path = stubs.join(name);
            fs::write(&path, STUB).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::create_dir_all(dir.path().join("store")).unwrap();
        Fake { dir }
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn script(&self) -> PathBuf {
        let path = self.root().join("harden-macos.sh");
        fs::write(&path, macos_hardening_script(Hardening::Baseline).unwrap()).unwrap();
        path
    }

    fn store(&self, name: &str, value: &str) {
        fs::write(self.root().join("store").join(name), format!("{value}\n")).unwrap();
    }

    fn fail(&self, what: &str) {
        fs::write(self.root().join("store").join(format!("fail.{what}")), "").unwrap();
    }

    fn stop_failing(&self, what: &str) {
        let _ = fs::remove_file(self.root().join("store").join(format!("fail.{what}")));
    }

    fn remove_stub(&self, name: &str) {
        fs::remove_file(self.root().join("stubs").join(name)).unwrap();
    }

    /// A preference as `defaults` would hold it: type (bool, string, int, array) and value (bool: 1 or 0).
    fn set_default(&self, domain: &str, key: &str, kind: &str, value: &str) {
        let dir = self.root().join("store").join("defaults");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(format!("{domain}__{key}")), format!("{kind}:{value}\n")).unwrap();
    }

    fn default_of(&self, domain: &str, key: &str) -> Option<String> {
        fs::read_to_string(self.root().join("store").join("defaults").join(format!("{domain}__{key}")))
            .ok()
            .map(|s| s.trim().to_string())
    }

    fn stored(&self, name: &str) -> Option<String> {
        fs::read_to_string(self.root().join("store").join(name)).ok().map(|s| s.trim().to_string())
    }

    fn calls(&self) -> Vec<String> {
        fs::read_to_string(self.root().join("calls.log")).unwrap_or_default().lines().map(String::from).collect()
    }

    /// The calls that would change the system.
    fn mutating_calls(&self) -> Vec<String> {
        self.calls()
            .into_iter()
            .filter(|c| {
                c.starts_with("defaults write")
                    || c.starts_with("defaults delete")
                    || c.contains("--setglobalstate")
                    || c.contains("--setstealthmode")
                    || c.starts_with("spctl --master")
            })
            .collect()
    }

    fn clear_calls(&self) {
        let _ = fs::remove_file(self.root().join("calls.log"));
    }

    fn state_file(&self) -> PathBuf {
        self.root().join("var/db/epma-hardening/previous.list")
    }

    fn log_file(&self) -> PathBuf {
        self.root().join("var/log/epma-hardening.log")
    }

    fn command(&self, args: &[&str], root_user: bool) -> Command {
        let mut cmd = Command::new("bash");
        cmd.arg(self.script()).args(args);
        cmd.env("EPMA_HARDEN_TEST_ROOT", self.root());
        cmd.env("EPMA_HARDEN_TEST_UID", if root_user { "0" } else { "501" });
        cmd
    }

    fn run_with(&self, args: &[&str], root_user: bool, stdin: &str) -> Run {
        let mut child = self
            .command(args, root_user)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        Run {
            code: out.status.code().unwrap_or(-1),
            out: String::from_utf8_lossy(&out.stdout).into_owned(),
            err: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    fn run(&self, args: &[&str]) -> Run {
        self.run_with(args, true, "")
    }
}

/// A Mac that already has every wanted setting.
fn hardened_mac() -> Fake {
    let f = Fake::new();
    f.store("fw_global", "1");
    f.store("fw_stealth", "1");
    f.store("gk", "1");
    for key in ["AutomaticCheckEnabled", "AutomaticDownload", "CriticalUpdateInstall", "ConfigDataInstall"] {
        f.set_default(SOFTWAREUPDATE, key, "bool", "1");
    }
    f.set_default(LOGINWINDOW, "GuestEnabled", "bool", "0");
    f
}

/// A Mac with automatic login on for the user "ada" and the guest account on.
fn loose_mac() -> Fake {
    let f = Fake::new();
    f.set_default(LOGINWINDOW, "autoLoginUser", "string", "ada");
    f.set_default(LOGINWINDOW, "GuestEnabled", "bool", "1");
    f.set_default(SOFTWAREUPDATE, "AutomaticDownload", "bool", "0");
    f
}

// ---------------------------------------------------------------------------------------------------------------
// Running the script: arguments, who may run it
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn help_prints_the_usage_and_changes_nothing() {
    let f = Fake::new();
    let r = f.run(&["--help"]);
    assert_eq!(r.code, 0, "{}", r.all());
    for text in ["--dry-run", "--yes", "--undo", "/var/log/epma-hardening.log"] {
        assert!(r.out.contains(text), "{text}: {}", r.out);
    }
    assert!(f.calls().is_empty(), "--help must not run anything: {:?}", f.calls());
}

#[test]
fn an_unknown_option_is_a_usage_error() {
    let f = Fake::new();
    let r = f.run(&["--force"]);
    assert_eq!(r.code, 2);
    assert!(r.err.contains("unknown option '--force'"), "{}", r.err);
    assert!(f.mutating_calls().is_empty());
}

#[test]
fn applying_needs_root_but_a_report_does_not() {
    let f = loose_mac();
    let r = f.run_with(&["--yes"], false, "");
    assert_eq!(r.code, 2, "{}", r.all());
    assert!(r.err.contains("must run as root"), "{}", r.err);
    assert!(f.calls().is_empty() && !f.state_file().exists());
    let r = f.run_with(&["--undo", "--yes"], false, "");
    assert_eq!(r.code, 2);
    // the report runs as an ordinary user, and never writes a log or a state file
    let r = f.run_with(&["--dry-run"], false, "");
    assert_eq!(r.code, 0, "{}", r.all());
    assert!(f.mutating_calls().is_empty());
    assert!(!f.log_file().exists() && !f.state_file().exists());
    // ... and says that it could not look at what needs root
    assert!(r.out.contains("not checked without administrator rights"), "{}", r.out);
}

#[test]
fn a_system_that_is_not_macos_is_refused() {
    let f = Fake::new();
    f.store("uname", "Linux");
    let r = f.run(&["--yes"]);
    assert_eq!(r.code, 2);
    assert!(r.err.contains("this script is for macOS"), "{}", r.err);
    assert!(f.mutating_calls().is_empty());
}

#[test]
fn without_a_terminal_and_without_yes_it_does_not_go_ahead() {
    let f = loose_mac();
    // test mode feeds stdin; answering n cancels
    let r = f.run_with(&[], true, "n\n");
    assert_eq!(r.code, 1, "{}", r.all());
    assert!(r.out.contains("Cancelled. Nothing was changed."), "{}", r.out);
    assert!(f.mutating_calls().is_empty() && !f.state_file().exists());
    let r = f.run_with(&[], true, "");
    assert_eq!(r.code, 1);
    assert!(f.mutating_calls().is_empty());
}

#[test]
fn answering_y_applies() {
    let f = loose_mac();
    let r = f.run_with(&[], true, "y\n");
    assert_eq!(r.code, 0, "{}", r.all());
    assert_eq!(f.stored("fw_global").as_deref(), Some("1"));
}

// ---------------------------------------------------------------------------------------------------------------
// Dry run
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn a_dry_run_changes_nothing_at_all() {
    let f = loose_mac();
    let r = f.run(&["--dry-run"]);
    assert_eq!(r.code, 0, "{}", r.all());
    assert!(f.mutating_calls().is_empty(), "{:?}", f.mutating_calls());
    assert!(!f.state_file().exists(), "no state file in a dry run");
    assert!(!f.log_file().exists(), "no log in a dry run");
    for text in [
        "[CHANGE] (dry-run) would: turn the Application Firewall on",
        "[CHANGE] (dry-run) would: turn stealth mode on",
        "[CHANGE] (dry-run) would: turn the guest account off",
        "[CHANGE] (dry-run) would: turn automatic login off (it is on for the user 'ada')",
        "[CHANGE] (dry-run) would: check for software updates automatically",
        "This was a dry run: nothing was changed.",
    ] {
        assert!(r.out.contains(text), "{text}:\n{}", r.out);
    }
    // what is already as wanted is said so
    assert!(r.out.contains("[OK]     Gatekeeper is on"), "{}", r.out);
    // the preferences are untouched
    assert_eq!(f.default_of(LOGINWINDOW, "GuestEnabled").as_deref(), Some("bool:1"));
    assert_eq!(f.default_of(LOGINWINDOW, "autoLoginUser").as_deref(), Some("string:ada"));
}

// ---------------------------------------------------------------------------------------------------------------
// Applying
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn applying_to_a_fresh_mac_changes_every_setting_and_remembers_the_originals() {
    let f = loose_mac();
    let r = f.run(&["--yes"]);
    assert_eq!(r.code, 0, "{}", r.all());
    assert_eq!(f.stored("fw_global").as_deref(), Some("1"));
    assert_eq!(f.stored("fw_stealth").as_deref(), Some("1"));
    assert!(f.stored("gk").is_none_or(|v| v == "1"), "Gatekeeper was on and stays on");
    for key in ["AutomaticCheckEnabled", "AutomaticDownload", "CriticalUpdateInstall", "ConfigDataInstall"] {
        assert_eq!(f.default_of(SOFTWAREUPDATE, key).as_deref(), Some("bool:1"), "{key}");
    }
    assert_eq!(f.default_of(LOGINWINDOW, "GuestEnabled").as_deref(), Some("bool:0"));
    assert_eq!(f.default_of(LOGINWINDOW, "autoLoginUser"), None, "automatic login is off");

    let state = fs::read_to_string(f.state_file()).expect("a state file");
    // the ORIGINAL values: firewall and stealth were off, the guest account on, automatic login on for ada
    assert!(state.contains("fw\tglobalstate\t-\tstate\t0"), "{state}");
    assert!(state.contains("fw\tstealth\t-\tstate\t0"), "{state}");
    assert!(state.contains("\tGuestEnabled\tbool\t1"), "{state}");
    assert!(state.contains("\tautoLoginUser\tstring\tada"), "{state}");
    assert!(state.contains("\tAutomaticCheckEnabled\tabsent\t-"), "{state}");
    assert!(state.contains("\tAutomaticDownload\tbool\t0"), "{state}");
    // Gatekeeper was already on: nothing to remember
    assert!(!state.contains("gk\t"), "{state}");
    // the state directory is private
    let mode = fs::metadata(f.root().join("var/db/epma-hardening")).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);

    // the log has every line, and is private
    let log = fs::read_to_string(f.log_file()).expect("a log");
    assert!(log.contains("[CHANGE] turned the Application Firewall on"), "{log}");
    assert_eq!(fs::metadata(f.log_file()).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(r.out.contains("Undo with: sudo bash harden-macos.sh --undo"), "{}", r.out);
}

#[test]
fn gatekeeper_that_was_off_is_turned_on_and_remembered() {
    let f = hardened_mac();
    f.store("gk", "0");
    let r = f.run(&["--yes"]);
    assert_eq!(r.code, 0, "{}", r.all());
    assert_eq!(f.stored("gk").as_deref(), Some("1"));
    assert!(fs::read_to_string(f.state_file()).unwrap().contains("gk\tassessments\t-\tstate\t0"));
}

#[test]
fn running_it_twice_changes_nothing_the_second_time() {
    let f = loose_mac();
    assert_eq!(f.run(&["--yes"]).code, 0);
    let state_before = fs::read_to_string(f.state_file()).unwrap();
    f.clear_calls();
    let r = f.run(&["--yes"]);
    assert_eq!(r.code, 0, "{}", r.all());
    assert!(f.mutating_calls().is_empty(), "second run changed things: {:?}", f.mutating_calls());
    assert!(!r.out.contains("[CHANGE]"), "{}", r.out);
    assert_eq!(fs::read_to_string(f.state_file()).unwrap(), state_before, "the originals are kept, not replaced");
}

#[test]
fn a_mac_that_is_already_hardened_gets_no_change_and_no_state_file() {
    let f = hardened_mac();
    let r = f.run(&["--yes"]);
    assert_eq!(r.code, 0, "{}", r.all());
    assert!(f.mutating_calls().is_empty(), "{:?}", f.mutating_calls());
    assert!(!f.state_file().exists());
    assert!(!r.out.contains("[CHANGE]"), "{}", r.out);
    assert!(r.out.contains("0 changed"), "{}", r.out);
}

#[test]
fn a_firewall_that_blocks_everything_is_stricter_and_left_alone() {
    let f = hardened_mac();
    f.store("fw_global", "2");
    let r = f.run(&["--yes"]);
    assert_eq!(r.code, 0, "{}", r.all());
    assert_eq!(f.stored("fw_global").as_deref(), Some("2"));
    assert!(r.out.contains("blocks all incoming connections (stricter than wanted"), "{}", r.out);
}

#[test]
fn a_preference_with_an_unexpected_type_is_left_alone() {
    let f = hardened_mac();
    f.set_default(LOGINWINDOW, "GuestEnabled", "array", "x");
    let r = f.run(&["--yes"]);
    assert_eq!(r.code, 0, "{}", r.all());
    assert_eq!(f.default_of(LOGINWINDOW, "GuestEnabled").as_deref(), Some("array:x"));
    assert!(r.out.contains("[SKIP]"), "{}", r.out);
    assert!(f.mutating_calls().is_empty());
}

#[test]
fn what_cannot_be_read_is_left_alone_with_a_warning() {
    let f = hardened_mac();
    f.remove_stub("socketfilterfw");
    f.remove_stub("spctl");
    let r = f.run(&["--yes"]);
    assert_eq!(r.code, 0, "{}", r.all());
    assert!(r.out.contains("could not read the Application Firewall state; left alone"), "{}", r.out);
    assert!(r.out.contains("could not read the stealth mode state; left alone"), "{}", r.out);
    assert!(r.out.contains("could not read the Gatekeeper state; left alone"), "{}", r.out);
    assert!(f.mutating_calls().is_empty());
}

// ---------------------------------------------------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn a_refused_change_is_a_warning_an_error_exit_and_is_not_remembered() {
    let f = loose_mac();
    f.fail("fw");
    f.fail("defaults_write");
    let r = f.run(&["--yes"]);
    assert_eq!(r.code, 1, "{}", r.all());
    assert!(r.out.contains("[WARN]   FAILED: turn the Application Firewall on"), "{}", r.out);
    assert!(r.out.contains("[WARN]   FAILED: turn the guest account off"), "{}", r.out);
    assert_eq!(f.stored("fw_global"), None, "the firewall setting did not change");
    // the failed steps left no record, so undo will not "restore" something that never changed
    let state = fs::read_to_string(f.state_file()).unwrap_or_default();
    assert!(!state.contains("globalstate"), "{state}");
    assert!(!state.contains("GuestEnabled"), "{state}");
    // the steps that worked still happened and are remembered
    assert_eq!(f.stored("fw_stealth").as_deref(), Some("1"));
    assert!(state.contains("fw\tstealth"), "{state}");
    // the other steps went on after the failures
    assert_eq!(f.default_of(LOGINWINDOW, "autoLoginUser"), None);
}

#[test]
fn a_failed_gatekeeper_or_login_step_leaves_no_record() {
    let f = hardened_mac();
    f.store("gk", "0");
    f.set_default(LOGINWINDOW, "autoLoginUser", "string", "ada");
    f.fail("gk");
    f.fail("defaults_delete");
    let r = f.run(&["--yes"]);
    assert_eq!(r.code, 1, "{}", r.all());
    let state = fs::read_to_string(f.state_file()).unwrap_or_default();
    assert!(!state.contains("gk\t") && !state.contains("autoLoginUser"), "{state}");
    assert_eq!(f.default_of(LOGINWINDOW, "autoLoginUser").as_deref(), Some("string:ada"));
}

// ---------------------------------------------------------------------------------------------------------------
// Only reported
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn filevault_sip_and_remote_login_are_reported_and_never_changed() {
    let f = hardened_mac();
    f.store("filevault", "0");
    f.store("sip", "0");
    f.store("sshd", "on");
    let r = f.run(&["--yes"]);
    assert_eq!(r.code, 0, "{}", r.all());
    assert!(r.out.contains("[WARN]   FileVault (disk encryption) is OFF"), "{}", r.out);
    assert!(r.out.contains("This script never does it"), "{}", r.out);
    assert!(r.out.contains("[WARN]   System Integrity Protection is OFF"), "{}", r.out);
    assert!(r.out.contains("[WARN]   Remote Login (SSH) looks switched on"), "{}", r.out);
    assert!(f.mutating_calls().is_empty(), "{:?}", f.mutating_calls());
    // none of those tools was ever asked to change anything
    assert!(f.calls().iter().all(|c| !c.starts_with("fdesetup enable") && !c.starts_with("csrutil enable")));
    assert!(!f.state_file().exists());
}

#[test]
fn when_all_is_well_the_reports_say_ok() {
    let f = hardened_mac();
    let r = f.run(&["--yes"]);
    assert!(r.out.contains("[OK]     FileVault (disk encryption) is on"), "{}", r.out);
    assert!(r.out.contains("[OK]     System Integrity Protection is on"), "{}", r.out);
    assert!(r.out.contains("[OK]     Remote Login (SSH) does not look switched on"), "{}", r.out);
}

#[test]
fn a_missing_tool_is_information_not_a_failure() {
    let f = hardened_mac();
    f.remove_stub("fdesetup");
    f.remove_stub("csrutil");
    f.remove_stub("launchctl");
    let r = f.run(&["--yes"]);
    assert_eq!(r.code, 0, "{}", r.all());
    assert!(r.out.contains("[INFO]   FileVault: fdesetup is not available here"), "{}", r.out);
    assert!(r.out.contains("[INFO]   System Integrity Protection: csrutil is not available here"), "{}", r.out);
    assert!(r.out.contains("[INFO]   Remote Login: launchctl is not available here"), "{}", r.out);
}

// ---------------------------------------------------------------------------------------------------------------
// Undo
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn undo_puts_every_original_value_back() {
    let f = loose_mac();
    f.store("gk", "0");
    assert_eq!(f.run(&["--yes"]).code, 0);
    assert_eq!(f.stored("gk").as_deref(), Some("1"));
    let r = f.run(&["--undo", "--yes"]);
    assert_eq!(r.code, 0, "{}", r.all());
    // everything is as it was before
    assert_eq!(f.stored("fw_global").as_deref(), Some("0"));
    assert_eq!(f.stored("fw_stealth").as_deref(), Some("0"));
    assert_eq!(f.stored("gk").as_deref(), Some("0"));
    assert_eq!(f.default_of(LOGINWINDOW, "GuestEnabled").as_deref(), Some("bool:1"));
    assert_eq!(f.default_of(LOGINWINDOW, "autoLoginUser").as_deref(), Some("string:ada"));
    assert_eq!(f.default_of(SOFTWAREUPDATE, "AutomaticDownload").as_deref(), Some("bool:0"));
    // a key that was not there before is gone again
    assert_eq!(f.default_of(SOFTWAREUPDATE, "AutomaticCheckEnabled"), None);
    assert_eq!(f.default_of(SOFTWAREUPDATE, "ConfigDataInstall"), None);
    // and the record is removed
    assert!(!f.state_file().exists());
    assert!(!f.root().join("var/db/epma-hardening").exists());
    assert!(!r.out.contains("Undo with:"), "{}", r.out);
}

#[test]
fn undo_with_nothing_remembered_does_nothing() {
    let f = hardened_mac();
    let r = f.run(&["--undo", "--yes"]);
    assert_eq!(r.code, 0, "{}", r.all());
    assert!(r.out.contains("nothing to undo"), "{}", r.out);
    assert!(f.mutating_calls().is_empty());
}

#[test]
fn undo_twice_is_harmless() {
    let f = loose_mac();
    assert_eq!(f.run(&["--yes"]).code, 0);
    assert_eq!(f.run(&["--undo", "--yes"]).code, 0);
    f.clear_calls();
    let r = f.run(&["--undo", "--yes"]);
    assert_eq!(r.code, 0);
    assert!(f.mutating_calls().is_empty(), "{:?}", f.mutating_calls());
}

#[test]
fn a_dry_run_of_undo_changes_nothing_and_keeps_the_record() {
    let f = loose_mac();
    assert_eq!(f.run(&["--yes"]).code, 0);
    let state = fs::read_to_string(f.state_file()).unwrap();
    f.clear_calls();
    let r = f.run(&["--undo", "--dry-run"]);
    assert_eq!(r.code, 0, "{}", r.all());
    assert!(f.mutating_calls().is_empty(), "{:?}", f.mutating_calls());
    assert!(r.out.contains("would: put the Application Firewall 'globalstate' back to off"), "{}", r.out);
    assert_eq!(fs::read_to_string(f.state_file()).unwrap(), state);
}

#[test]
fn a_failed_undo_keeps_the_record_so_it_can_be_run_again() {
    let f = loose_mac();
    assert_eq!(f.run(&["--yes"]).code, 0);
    f.fail("fw");
    let r = f.run(&["--undo", "--yes"]);
    assert_eq!(r.code, 1, "{}", r.all());
    assert!(r.out.contains("the record is kept so --undo can be run again"), "{}", r.out);
    assert!(f.state_file().exists());
    // once the problem is gone the second try finishes the job
    f.stop_failing("fw");
    let r = f.run(&["--undo", "--yes"]);
    assert_eq!(r.code, 0, "{}", r.all());
    assert_eq!(f.stored("fw_global").as_deref(), Some("0"));
    assert!(!f.state_file().exists());
}

// ---------------------------------------------------------------------------------------------------------------
// The script itself
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn the_script_never_runs_a_command_that_could_hurt_the_disk_or_the_accounts() {
    let script = macos_hardening_script(Hardening::Baseline).unwrap();
    let executable: String =
        script.lines().filter(|l| !l.trim_start().starts_with('#')).map(|l| format!("{l}\n")).collect::<String>();
    for word in [
        "diskutil",
        "dd ",
        "newfs",
        "mkfs",
        "hdiutil",
        "rm -rf",
        "sysadminctl",
        "dscl",
        "passwd",
        "fdesetup enable",
        "csrutil disable",
        "csrutil enable",
        "curl",
        "wget",
        "softwareupdate",
        "nvram",
        "pmset",
        "tmutil",
        "launchctl load",
        "launchctl unload",
        "launchctl bootstrap",
        "launchctl enable",
        "launchctl disable",
        "systemsetup",
    ] {
        assert!(!executable.contains(word), "the script mentions `{word}` in code");
    }
}

#[test]
fn the_script_is_the_one_the_seed_drive_carries_and_its_comments_say_what_it_does_not_do() {
    let script = macos_hardening_script(Hardening::Baseline).unwrap();
    for text in ["never turns FileVault on", "never touches", "never makes a network request", "--undo"] {
        assert!(script.contains(text), "{text}");
    }
    let (_label, files) = hardening_files_seed(SeedTarget::MacOs, Hardening::Baseline).unwrap();
    assert_eq!(files["harden-macos.sh"], script.as_bytes());
}

#[test]
fn the_script_parses_with_the_bash_that_ships_with_macos() {
    // /bin/bash is 3.2 on a Mac; on other systems this is simply the system bash
    let f = Fake::new();
    let bash = if Path::new("/bin/bash").exists() { "/bin/bash" } else { "bash" };
    let out = Command::new(bash).arg("-n").arg(f.script()).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

// ---------------------------------------------------------------------------------------------------------------
// The seed drive: launchers, README, file set
// ---------------------------------------------------------------------------------------------------------------

fn seed_files() -> (String, epma_usb_creator::types::Files) {
    hardening_files_seed(SeedTarget::MacOs, Hardening::Baseline).unwrap()
}

fn text_of(name: &str) -> String {
    String::from_utf8(seed_files().1[name].clone()).expect("ascii")
}

#[test]
fn the_seed_drive_has_the_five_files_and_the_label() {
    let (label, files) = seed_files();
    assert_eq!(label, "EPMA-SEED");
    assert_eq!(seed_label(SeedTarget::MacOs), "EPMA-SEED");
    let mut names: Vec<&str> = files.keys().map(String::as_str).collect();
    names.sort();
    assert_eq!(names, ["README.txt", "audit.command", "harden-macos.sh", "harden.command", "undo.command"]);
    for (name, data) in &files {
        assert!(data.is_ascii(), "{name} is not ASCII");
        assert!(!data.contains(&b'\r'), "{name} has CR: macOS files use LF");
        assert!(data.ends_with(b"\n"), "{name}");
    }
}

#[test]
fn the_launchers_run_the_script_from_their_own_folder_and_say_what_they_do() {
    for l in SEED_MACOS_LAUNCHERS {
        let text = text_of(l.name);
        assert!(text.starts_with("#!/bin/bash\n"), "{}", l.name);
        assert!(text.contains("here=\"$(cd \"$(dirname \"$0\")\" && pwd)\""), "{}: folder with spaces", l.name);
        assert!(text.contains("\"$here/harden-macos.sh\""), "{}", l.name);
        // the only `cd` is the quoted one inside the `here=` line
        assert_eq!(text.matches("cd ").count(), 1, "{}", l.name);
        for line in l.banner {
            assert!(text.contains(line), "{}: banner line missing", l.name);
        }
        assert!(text.ends_with("exit \"$rc\"\n"), "{}", l.name);
    }
    // the report needs no administrator rights and changes nothing
    let audit = text_of("audit.command");
    assert!(!audit.contains("sudo"), "{audit}");
    assert!(audit.contains("harden-macos.sh\" --dry-run"), "{audit}");
    assert!(!audit.contains("Continue?"), "the report does not ask");
    // the two that change things ask first and go through sudo (the password is asked by sudo, not by us)
    for name in ["harden.command", "undo.command"] {
        let text = text_of(name);
        assert!(text.contains("Continue? [y/N]"), "{name}");
        assert!(text.contains("sudo /bin/bash \"$here/harden-macos.sh\""), "{name}");
        assert!(!text.contains("read -rs") && !text.contains("read -s"), "{name} must never read a password");
    }
    assert!(text_of("harden.command").contains("--yes"));
    assert!(text_of("undo.command").contains("--undo --yes"));
    // the answer is checked before anything runs
    let harden = text_of("harden.command");
    assert!(harden.find("Continue? [y/N]").unwrap() < harden.find("sudo /bin/bash").unwrap());
}

#[test]
fn the_launchers_pass_bash_n_and_shellcheck() {
    for l in SEED_MACOS_LAUNCHERS {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(l.name);
        fs::write(&path, macos_seed_launcher(l)).unwrap();
        let out = Command::new("bash").arg("-n").arg(&path).output().unwrap();
        assert!(out.status.success(), "{}: {}", l.name, String::from_utf8_lossy(&out.stderr));
        if let Ok(sc) = Command::new("shellcheck").args(["--shell=bash", "--severity=warning"]).arg(&path).output() {
            assert!(sc.status.success(), "{}: {}", l.name, String::from_utf8_lossy(&sc.stdout));
        } else {
            assert_ne!(std::env::var("REQUIRE_SHELLCHECK").as_deref(), Ok("1"), "shellcheck is required here");
        }
    }
}

/// A `sudo` that does what it is told without asking: the launchers call plain `sudo`.
fn fake_sudo_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sudo");
    fs::write(&path, "#!/bin/bash\necho \"sudo $*\" >>\"$EPMA_HARDEN_TEST_ROOT/sudo.log\"\nexec \"$@\"\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

/// Put the launchers and the script next to each other (a folder with a space in its name) and run one.
fn run_launcher(f: &Fake, name: &str, stdin: &str) -> (Run, PathBuf) {
    let folder = f.root().join("EPMA SEED");
    fs::create_dir_all(&folder).unwrap();
    let (_label, files) = seed_files();
    for (file, data) in &files {
        fs::write(folder.join(file), data).unwrap();
    }
    let sudo = fake_sudo_dir();
    let path = format!("{}:{}", sudo.path().display(), std::env::var("PATH").unwrap_or_default());
    let mut child = Command::new("bash")
        .arg(folder.join(name))
        .env("PATH", path)
        .env("EPMA_HARDEN_TEST_ROOT", f.root())
        .env("EPMA_HARDEN_TEST_UID", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    let run = Run {
        code: out.status.code().unwrap_or(-1),
        out: String::from_utf8_lossy(&out.stdout).into_owned(),
        err: String::from_utf8_lossy(&out.stderr).into_owned(),
    };
    (run, folder)
}

#[test]
fn audit_command_prints_a_report_without_sudo_and_changes_nothing() {
    let f = loose_mac();
    let (r, _) = run_launcher(&f, "audit.command", "\n");
    assert_eq!(r.code, 0, "{}", r.all());
    assert!(r.out.contains("report on this Mac"), "{}", r.out);
    assert!(r.out.contains("[CHANGE] (dry-run) would: turn the Application Firewall on"), "{}", r.out);
    assert!(r.out.contains("Finished with exit code 0"), "{}", r.out);
    assert!(f.mutating_calls().is_empty());
    assert!(!f.root().join("sudo.log").exists(), "the report must not use sudo");
}

#[test]
fn harden_command_asks_then_applies_through_sudo() {
    let f = loose_mac();
    let (r, _) = run_launcher(&f, "harden.command", "y\n\n");
    assert_eq!(r.code, 0, "{}", r.all());
    assert!(r.out.contains("Continue? [y/N]"), "{}", r.out);
    assert_eq!(f.stored("fw_global").as_deref(), Some("1"));
    assert!(fs::read_to_string(f.root().join("sudo.log")).unwrap().contains("harden-macos.sh --yes"));
}

#[test]
fn harden_command_cancelled_changes_nothing() {
    let f = loose_mac();
    for answer in ["n\n\n", "\n\n", "maybe\n\n"] {
        let (r, _) = run_launcher(&f, "harden.command", answer);
        assert_eq!(r.code, 1, "{answer:?}: {}", r.all());
        assert!(r.out.contains("Cancelled. Nothing was changed."), "{}", r.out);
    }
    assert!(f.mutating_calls().is_empty());
    assert!(!f.root().join("sudo.log").exists());
}

#[test]
fn undo_command_goes_back() {
    let f = loose_mac();
    let (r, _) = run_launcher(&f, "harden.command", "y\n\n");
    assert_eq!(r.code, 0, "{}", r.all());
    let (r, _) = run_launcher(&f, "undo.command", "y\n\n");
    assert_eq!(r.code, 0, "{}", r.all());
    assert_eq!(f.stored("fw_global").as_deref(), Some("0"));
    assert_eq!(f.default_of(LOGINWINDOW, "autoLoginUser").as_deref(), Some("string:ada"));
}

#[test]
fn the_readme_is_plain_wrapped_and_names_every_file_and_limit() {
    let readme = text_of("README.txt");
    for (n, line) in readme.lines().enumerate() {
        assert!(line.chars().count() <= SEED_MACOS_README_WIDTH, "line {}: {line}", n + 1);
    }
    for name in ["harden.command", "audit.command", "undo.command", "harden-macos.sh", "EPMA-SEED"] {
        assert!(readme.contains(name), "{name}");
    }
    for text in [
        "NOT a macOS installer",
        "SECOND small USB",
        "audit.command FIRST",
        "sudo bash /Volumes/EPMA-SEED/harden-macos.sh --undo",
        "never on a real Mac",
        "not a compliance claim",
        "/var/log/epma-hardening.log",
    ] {
        let flat = readme.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(flat.contains(text) || flat.contains(&text.to_lowercase()), "the README does not say: {text}");
    }
    // every change and every limit the code lists is in the README
    let flat = readme.split_whitespace().collect::<Vec<_>>().join(" ");
    for (_id, text, _risk) in MACOS_HARDENING_SETTINGS {
        assert!(flat.contains(text), "README lacks: {text}");
    }
    for (_id, text, _why) in MACOS_HARDENING_NOT_CHANGED {
        assert!(flat.contains(text), "README lacks: {text}");
    }
    assert_eq!(describe_hardening_macos_applied(Hardening::Baseline).len(), MACOS_HARDENING_SETTINGS.len());
}

#[test]
fn the_readme_does_not_promise_what_was_not_tested() {
    let flat = text_of("README.txt").split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
    for word in ["cis benchmark", "stig", "nist", "certified", "guarantee"] {
        // "guarantee" and "certification" appear only in the sentence that denies them
        if flat.contains(word) {
            assert!(flat.contains("not a compliance claim, certification or guarantee"), "{word}");
        }
    }
    assert!(flat.contains("tested against stand-in commands, never on a real mac"));
}
