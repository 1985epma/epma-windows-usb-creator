//! The Linux hardening script (`harden-linux.sh`) written by `linux_hardening_script()`.
//! Port of tests/test_hardening_linux.py (127 tests).
//!
//! Nothing here touches the real system: the script has a hidden test mode (EPMA_HARDEN_TEST_ROOT) in which every
//! path lives below a temporary directory, "live" commands (apt-get, systemctl, ufw, sshd, ...) are looked up in
//! <root>/stubs only, and EPMA_HARDEN_TEST_UID may pretend to be root. The tests build a fake root, run the real script
//! text against it and look at the files that result. They skip themselves (with a note on stderr) when bash is not
//! installed, and the shellcheck test when shellcheck is not.
#![cfg(unix)]

mod common_a5;

use common_a5::*;
use regex::Regex;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use epma_usb_creator::harden_linux::linux_hardening_script;
use epma_usb_creator::types::{Error, Hardening};

macro_rules! need_bash {
    () => {
        match need_bash() {
            Some(b) => b,
            None => return,
        }
    };
}

fn has_line_with(out: &str, needle: &str) -> bool {
    out.lines().any(|l| l.contains(needle))
}

fn starts_with_any(c: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|p| c.starts_with(p))
}

fn index_of(calls: &[String], wanted: &str) -> usize {
    calls.iter().position(|c| c == wanted).unwrap_or_else(|| panic!("call {wanted:?} not found in {calls:?}"))
}

// =============================================================================================================
// ScriptTextTests
// =============================================================================================================

#[test]
fn script_text_profiles() {
    assert!(matches!(linux_hardening_script(Hardening::None), Err(Error::Value(_))));
    let text = linux_hardening_script(Hardening::Baseline).unwrap();
    assert_eq!(text, linux_hardening_script(Hardening::Baseline).unwrap());
}

#[test]
fn script_text_shape() {
    let text = script_text();
    assert!(text.is_ascii());
    assert!(!text.contains('\r'));
    assert!(text.starts_with("#!/usr/bin/env bash\n"));
    assert_has(text, "\nset -euo pipefail\n");
    assert!(text.ends_with("main \"$@\"\n"));
}

fn code_lines(text: &str) -> String {
    text.lines().filter(|l| !l.trim_start().starts_with('#')).collect::<Vec<_>>().join("\n")
}

#[test]
fn script_text_forbidden_constructs() {
    let text = script_text();
    let code = code_lines(text);
    assert!(!Regex::new(r"\beval\b").unwrap().is_match(&code));
    for word in ["curl", "wget", "http://", "https://", "ftp://", "ssh-copy-id"] {
        assert_lacks(text, word);
    }
    for pattern in [r"\bpip3?\b", r"\bnc\b", r"\bncat\b", r"\bscp\b", r"\bgit\b", r"\bfetch\b"] {
        assert!(!Regex::new(pattern).unwrap().is_match(text), "{pattern}");
    }
    assert!(!Regex::new(r"\|\s*(ba|z)?sh\b").unwrap().is_match(&code), "never pipe into a shell");
    assert!(!Regex::new(r"(?m)^\s*(source|\.)\s").unwrap().is_match(&code));
    let var_guard = Regex::new(r"\$\{[A-Za-z0-9_]+:\?\}").unwrap();
    let rm = Regex::new(r"\brm\b").unwrap();
    for line in code.lines() {
        if line.contains("rm -rf") {
            assert!(var_guard.is_match(line), "{line}");
        }
        if rm.is_match(line) && line.contains("rm -f") {
            assert!(var_guard.is_match(line), "{line}");
        }
    }
}

#[test]
fn script_text_no_compliance_claims() {
    let text = script_text();
    for word in ["CIS", "STIG", "NIST"] {
        assert_lacks(text, word);
    }
    let lower = text.to_lowercase();
    for word in ["certif", "complian", "benchmark"] {
        assert_lacks(&lower, word);
    }
}

#[test]
fn script_text_never_touches_storage_users_or_secrets() {
    let code = code_lines(script_text());
    for word in [
        "mkfs",
        "parted",
        "fdisk",
        "wipefs",
        "dd if=",
        "useradd",
        "chpasswd",
        "passwd -",
        "usermod",
        "setenforce",
        "aa-enforce",
        "aa-complain",
        "usb-storage",
        "BEGIN",
        "ssh-rsa",
        "ssh-ed25519",
    ] {
        assert_lacks(&code, word);
    }
}

#[test]
fn script_text_modprobe_list_keeps_media_filesystems() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.run(&["--yes"]).ok();
    let conf = fr.read("etc/modprobe.d/epma-hardening.conf");
    for module in ["cramfs", "freevxfs", "hfs", "hfsplus", "jffs2", "dccp", "sctp", "rds", "tipc"] {
        assert_has(&conf, &format!("install {module} /bin/false"));
        assert_has(&conf, &format!("blacklist {module}\n"));
    }
    for module in ["squashfs", "udf", "iso9660", "vfat", "exfat", "ntfs", "usb-storage", "usb_storage", "uas"] {
        assert_lacks(&conf, module);
    }
}

#[test]
fn script_text_bash_syntax() {
    let bash = need_bash!();
    let fr = FakeRoot::new();
    let out = Command::new(bash).arg("-n").arg(&fr.script_path).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn script_text_shellcheck_clean() {
    let Some(shellcheck) = shellcheck() else {
        eprintln!("note: shellcheck is not installed: test skipped");
        return;
    };
    let fr = FakeRoot::new();
    let out =
        Command::new(shellcheck).args(["--shell=bash", "--severity=style"]).arg(&fr.script_path).output().unwrap();
    assert!(out.status.success(), "{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
}

// =============================================================================================================
// SafetyOfInvocationTests
// =============================================================================================================

/// The script as a normal user would start it: no test hooks (unless given).
fn run_plain(args: &[&str], env: &[(&str, &str)]) -> (Run, tempfile::TempDir) {
    let bash = bash().expect("bash");
    let d = tempfile::Builder::new().prefix("epma-harden-plain-").tempdir().unwrap();
    let path = d.path().join("harden-linux.sh");
    fs::write(&path, script_text()).unwrap();
    let mut cmd = Command::new(bash);
    cmd.arg(&path).args(args).env_clear();
    cmd.env("PATH", std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into())).env("LANG", "C");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.current_dir(d.path());
    (run_command(cmd, None, Duration::from_secs(60)), d)
}

#[test]
fn invocation_help_needs_no_root() {
    let _ = need_bash!();
    let (r, _d) = run_plain(&["--help"], &[]);
    r.ok();
    for opt in ["--dry-run", "--yes", "--undo", "--chroot", "--help"] {
        r.out_has(opt);
    }
}

#[test]
fn invocation_not_root_exits_2_and_touches_nothing() {
    let _ = need_bash!();
    if is_root() {
        eprintln!("note: running as root: test skipped");
        return;
    }
    let cases: [&[&str]; 5] = [&["--dry-run"], &["--yes"], &["--undo", "--yes"], &["--chroot", "--yes"], &[]];
    for args in cases {
        let (r, d) = run_plain(args, &[]);
        r.expect_rc(2);
        r.err_has("root");
        let names: Vec<_> =
            fs::read_dir(d.path()).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(names, vec!["harden-linux.sh".to_string()], "{args:?}");
    }
}

#[test]
fn invocation_test_uid_is_ignored_without_the_root_variable() {
    let _ = need_bash!();
    if is_root() {
        eprintln!("note: running as root: test skipped");
        return;
    }
    let (r, _d) = run_plain(&["--dry-run"], &[("EPMA_HARDEN_TEST_UID", "0")]);
    r.expect_rc(2);
}

#[test]
fn invocation_bad_test_root_is_refused() {
    let _ = need_bash!();
    for value in ["relative/dir", "/", "/nonexistent-epma-dir-xyz"] {
        let (r, _d) = run_plain(&["--dry-run"], &[("EPMA_HARDEN_TEST_ROOT", value), ("EPMA_HARDEN_TEST_UID", "0")]);
        r.expect_rc(2);
        r.err_has("EPMA_HARDEN_TEST_ROOT");
    }
}

#[test]
fn invocation_unknown_option() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    let r = fr.run(&["--frobnicate"]);
    r.expect_rc(2);
    r.err_has("unknown option");
    assert!(fr.calls().is_empty());
}

#[test]
fn invocation_unsupported_distribution() {
    let _ = need_bash!();
    let fr = FakeRoot::distro("opensuse");
    let before = fr.snapshot();
    let r = fr.run(&["--yes"]);
    r.expect_rc(2);
    r.err_has("unsupported");
    assert_eq!(fr.snapshot(), before);
}

#[test]
fn invocation_missing_os_release() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fs::remove_file(fr.path("etc/os-release")).unwrap();
    let r = fr.run(&["--yes"]);
    r.expect_rc(2);
    r.err_has("os-release");
}

#[test]
fn invocation_distribution_detection() {
    let _ = need_bash!();
    for (distro, expect) in [("ubuntu", "apt"), ("debian", "apt"), ("fedora", "dnf"), ("rocky", "dnf")] {
        let fr = FakeRoot::distro(distro);
        let r = fr.run(&["--dry-run"]);
        r.ok();
        r.out_has(&format!("[package manager: {expect}]"));
    }
}

#[test]
fn invocation_confirmation_needs_a_terminal_or_yes() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    let before = fr.snapshot();
    let r = fr.run(&[]);
    r.expect_rc(2);
    r.err_has("--yes");
    assert_eq!(fr.snapshot(), before);
}

// =============================================================================================================
// DryRunTests
// =============================================================================================================

#[test]
fn dry_run_changes_nothing() {
    let _ = need_bash!();
    for distro in ["ubuntu", "fedora"] {
        let fr = FakeRoot::distro(distro);
        fr.write("home/alice/.ssh/authorized_keys", "ssh-ed25519 AAAA alice@laptop\n", None);
        let before = fr.snapshot_with(&["calls.log", "tmp"], true, &[]);
        let r = fr.run(&["--dry-run"]);
        r.ok();
        assert_eq!(fr.snapshot_with(&["calls.log", "tmp"], true, &[]), before, "{distro}");
        fr.assert_tmp_empty("scratch files must be removed");
        assert!(!fr.exists("var/log/epma-hardening.log"));
        assert!(!fr.exists("var/lib/epma-hardening"));
        assert!(fr.mutating_calls().is_empty(), "{distro}: {:?}", fr.mutating_calls());
        r.out_has("[CHANGE] (dry-run)");
        r.out_has("Dry run: nothing was changed");
        fr.assert_sentinel_empty();
    }
}

#[test]
fn dry_run_flavours_change_nothing() {
    let _ = need_bash!();
    let flavours: [&[&str]; 3] = [&["--dry-run", "--chroot"], &["--dry-run", "--undo"], &["--dry-run", "--yes"]];
    for flags in flavours {
        let fr = FakeRoot::new();
        let before = fr.snapshot_with(&["calls.log", "tmp"], true, &[]);
        fr.run(flags).ok();
        assert_eq!(fr.snapshot_with(&["calls.log", "tmp"], true, &[]), before, "{flags:?}");
        assert!(fr.mutating_calls().is_empty(), "{flags:?}");
    }
}

#[test]
fn dry_run_after_real_run_reports_nothing_to_do() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    let r = fr.run(&["--dry-run"]);
    r.ok();
    r.out_lacks("[CHANGE]");
}

// =============================================================================================================
// ApplyTests
// =============================================================================================================

fn apply() -> (FakeRoot, Run) {
    let fr = FakeRoot::new();
    let r = fr.run(&["--yes"]);
    (fr, r)
}

#[test]
fn apply_output_lines_and_summary() {
    let _ = need_bash!();
    let (fr, r) = apply();
    r.ok();
    for tag in ["[OK]", "[SKIP]", "[CHANGE]"] {
        r.out_has(tag);
    }
    assert_re(&r.out, r"Summary: \d+ ok, \d+ changed, \d+ skipped, \d+ warnings, 0 errors");
    r.out_has(&format!("To go back: sudo bash {} --undo", fr.script_path.display()));
    let log = fr.read("var/log/epma-hardening.log");
    assert_has(&log, "[CHANGE]");
    assert_has(&log, "harden-linux.sh start");
    fr.assert_sentinel_empty();
    fr.assert_tmp_empty("scratch files");
}

#[test]
fn apply_files_written() {
    let _ = need_bash!();
    let (fr, r) = apply();
    r.ok();
    let sysctl = fr.read("etc/sysctl.d/99-epma-hardening.conf");
    for key in [
        "kernel.kptr_restrict = 2",
        "kernel.dmesg_restrict = 1",
        "kernel.randomize_va_space = 2",
        "kernel.yama.ptrace_scope = 1",
        "net.ipv4.tcp_syncookies = 1",
        "fs.suid_dumpable = 0",
        "fs.protected_symlinks = 1",
        "fs.protected_hardlinks = 1",
        "fs.protected_fifos = 1",
        "fs.protected_regular = 1",
        "net.ipv4.conf.all.rp_filter = 2",
        "net.ipv4.conf.all.accept_redirects = 0",
        "net.ipv6.conf.all.accept_redirects = 0",
        "net.ipv4.conf.all.accept_source_route = 0",
    ] {
        assert_has(&sysctl, key);
    }
    for block in sysctl.split("\n\n").skip(1) {
        let lines: Vec<&str> = block.trim().lines().collect();
        assert_eq!(lines.len(), 2, "{block}");
        assert!(lines[0].starts_with("# ") && lines[1].contains(" = "), "every setting has its own comment: {block}");
    }
    assert_has(&fr.read("etc/security/limits.d/99-epma-hardening.conf"), "* ");
    assert_has(&fr.read("etc/systemd/coredump.conf.d/99-epma-hardening.conf"), "Storage=none");
    assert_has(&fr.read("etc/security/pwquality.conf.d/99-epma-hardening.conf"), "minlen = 12");
    let rules = fr.read("etc/audit/rules.d/99-epma-hardening.rules");
    assert_has(&rules, "-w /etc/passwd -p wa -k identity");
    assert_lacks(&rules, "-e 2");
    let auto = fr.read("etc/apt/apt.conf.d/20auto-upgrades");
    assert_has(&auto, "Unattended-Upgrade \"1\"");
    assert_has(&fr.read("etc/apt/apt.conf.d/52epma-hardening-unattended").to_lowercase(), "security");
    let defs = fr.read("etc/login.defs");
    assert_re(&defs, r"(?m)^PASS_MAX_DAYS\t365$");
    assert_re(&defs, r"(?m)^PASS_WARN_AGE\t14$");
    assert_re(&defs, r"(?m)^HOME_MODE\t0750$");
    assert_re(&defs, r"(?m)^UMASK\t022$"); // UMASK is left alone
    assert_re(&defs, r"(?m)^PASS_MIN_DAYS\t0$");
}

#[test]
fn apply_backups_once() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    let original_defs = fr.read("etc/login.defs");
    let original_auto = fr.read("etc/apt/apt.conf.d/20auto-upgrades");
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    assert_eq!(fr.read("etc/login.defs.epma-bak"), original_defs);
    assert_eq!(fr.read("etc/apt/apt.conf.d/20auto-upgrades.epma-bak"), original_auto);
    // The script modifies a file again later: the first backup must survive.
    fr.write("etc/login.defs", &fr.read("etc/login.defs").replace("365", "400"), None);
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    assert_eq!(fr.read("etc/login.defs.epma-bak"), original_defs);
    assert_has(&fr.read("etc/login.defs"), "PASS_MAX_DAYS\t365");
    for created in ["etc/sysctl.d/99-epma-hardening.conf", "etc/modprobe.d/epma-hardening.conf"] {
        assert!(!fr.exists(&format!("{created}.epma-bak")), "no backup of a file the script created itself");
    }
}

#[test]
fn apply_second_run_changes_nothing() {
    let _ = need_bash!();
    for distro in ["ubuntu", "fedora"] {
        let fr = FakeRoot::distro(distro);
        fr.write("home/alice/.ssh/authorized_keys", "ssh-ed25519 AAAA alice@laptop\n", None);
        let r = fr.run(&["--yes"]);
        r.ok();
        let first_calls = fr.calls().len();
        let snap = fr.snapshot_with(&["calls.log", "tmp", "state", "var"], true, &[]);
        let r = fr.run(&["--yes"]);
        r.ok();
        r.out_lacks("[CHANGE]");
        assert_eq!(fr.snapshot_with(&["calls.log", "tmp", "state", "var"], true, &[]), snap, "{distro}");
        let later: Vec<String> =
            fr.calls().into_iter().skip(first_calls).filter(|c| mutating_calls().is_match(c)).collect();
        assert!(later.is_empty(), "{distro}: {later:?}");
        assert_re(&r.out, r"Summary: \d+ ok, 0 changed");
    }
}

#[test]
fn apply_permissions_are_tightened_and_restored() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    assert_eq!(fr.mode("etc/shadow"), 0o640);
    assert_eq!(fr.mode("etc/group"), 0o644);
    assert_eq!(fr.mode("etc/passwd"), 0o644);
    assert_eq!(fr.mode("etc/gshadow"), 0o640);
    fr.run(&["--undo", "--yes"]).ok();
    assert_eq!(fr.mode("etc/shadow"), 0o644);
    assert_eq!(fr.mode("etc/group"), 0o664);
}

#[test]
fn apply_fedora_style_shadow_is_not_loosened() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.chmod("etc/shadow", 0);
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    assert_eq!(fr.mode("etc/shadow"), 0);
}

#[test]
fn apply_sysctl_only_lists_keys_the_kernel_has() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fs::remove_file(fr.path("proc/sys/kernel/yama/ptrace_scope")).unwrap();
    let r = fr.run(&["--yes"]);
    r.ok();
    assert_lacks(&fr.read("etc/sysctl.d/99-epma-hardening.conf"), "ptrace_scope");
    r.out_has("left out: kernel.yama.ptrace_scope");
    assert_has(&fr.read("etc/sysctl.d/99-epma-hardening.conf"), "kernel.kptr_restrict");
}

#[test]
fn apply_sysctl_without_proc_keeps_the_required_keys() {
    let _ = need_bash!();
    let fr = FakeRoot::with(Opts { proc_: false, ..Opts::default() });
    let _ = fs::remove_dir_all(fr.path("proc"));
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    let conf = fr.read("etc/sysctl.d/99-epma-hardening.conf");
    assert_has(&conf, "kernel.kptr_restrict = 2");
    assert_lacks(&conf, "ptrace_scope");
    assert_lacks(&conf, "protected_regular");
}

#[test]
fn apply_sysctl_loaded_only_when_the_file_changed() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    assert_eq!(fr.calls_matching(|c| c.starts_with("sysctl ")), vec!["sysctl --system".to_string()]);
}

#[test]
fn apply_missing_optional_files_are_skipped() {
    let _ = need_bash!();
    let fr = FakeRoot::with(Opts { login_defs: false, ..Opts::default() });
    fs::remove_file(fr.path("etc/security/pwquality.conf")).unwrap();
    let r = fr.run(&["--yes"]);
    r.ok();
    r.out_has("[SKIP]   /etc/login.defs not found");
    r.out_has("[SKIP]   password quality");
    assert!(!fr.exists("etc/login.defs"));
}

#[test]
fn apply_audit_rules_only_for_existing_paths() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    let rules = fr.read("etc/audit/rules.d/99-epma-hardening.rules");
    assert_lacks(&rules, "/etc/sudoers"); // not present in the fake root
    let fr2 = FakeRoot::new();
    fr2.write("etc/sudoers", "root ALL=(ALL) ALL\n", None);
    assert_eq!(fr2.run(&["--yes"]).rc, 0);
    assert_has(&fr2.read("etc/audit/rules.d/99-epma-hardening.rules"), "-w /etc/sudoers -p wa -k sudoers");
}

// =============================================================================================================
// UndoTests
// =============================================================================================================

#[test]
fn undo_restores_everything() {
    let _ = need_bash!();
    for distro in ["ubuntu", "fedora"] {
        let fr = FakeRoot::distro(distro);
        fr.write("etc/dnf/automatic.conf", "# original dnf-automatic\n", None);
        let before = fr.snapshot_with(&["calls.log", "state", "tmp"], false, &[]);
        assert_eq!(fr.run(&["--yes"]).rc, 0);
        assert_ne!(fr.snapshot_with(&["calls.log", "state", "tmp"], false, &[]), before);
        let r = fr.run(&["--undo", "--yes"]);
        r.ok();
        let after = fr.snapshot_with(&["calls.log", "state", "tmp"], false, &["var/log/epma-hardening.log"]);
        assert_eq!(after, before, "{distro}");
        assert!(!fr.exists("var/lib/epma-hardening"));
        r.out_has("restored from");
        r.out_has("removed (created by this script)");
        fr.assert_sentinel_empty();
    }
}

#[test]
fn undo_without_a_previous_run() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    let r = fr.run(&["--undo", "--yes"]);
    r.ok();
    r.out_has("nothing to undo");
}

#[test]
fn undo_dry_run_lists_but_does_nothing() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    let before = fr.snapshot_with(&["calls.log", "tmp"], true, &[]);
    let r = fr.run(&["--undo", "--dry-run"]);
    r.ok();
    assert_eq!(fr.snapshot_with(&["calls.log", "tmp"], true, &[]), before);
    r.out_has("would be removed");
    r.out_has("would be restored");
}

#[test]
fn undo_ignores_paths_outside_the_expected_places() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    let victim = fr.base.join("victim.txt");
    fs::write(&victim, "keep me").unwrap();
    let mut created = fs::read_to_string(fr.path("var/lib/epma-hardening/created.list")).unwrap();
    created.push_str(&format!("{}\n", victim.display()));
    created.push_str(&format!("{}/etc/../../victim.txt\n", fr.root.display()));
    fs::write(fr.path("var/lib/epma-hardening/created.list"), created).unwrap();
    let r = fr.run(&["--undo", "--yes"]);
    r.ok();
    assert!(victim.exists());
    r.out_has("unexpected path");
}

// =============================================================================================================
// SshTests
// =============================================================================================================

const DROPIN: &str = "etc/ssh/sshd_config.d/99-epma-hardening.conf";

#[test]
fn ssh_dropin_contents_without_keys() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.run(&["--yes"]).ok();
    let conf = fr.read(DROPIN);
    for line in [
        "PermitRootLogin no",
        "X11Forwarding no",
        "LoginGraceTime 30",
        "PermitEmptyPasswords no",
        "ClientAliveInterval 300",
    ] {
        assert_has(&conf, &format!("\n{line}\n"));
    }
    assert_lacks(&conf, "MaxAuthTries"); // the default number of tries is left alone
    assert_lacks(&conf, "PasswordAuthentication");
    assert!(fr.calls().iter().any(|c| c == "sshd -t"));
}

#[test]
fn ssh_password_authentication_untouched_without_keys() {
    let _ = need_bash!();
    for content in [None, Some(""), Some("\n   \n"), Some("# a comment only\n")] {
        let fr = FakeRoot::new();
        if let Some(content) = content {
            fr.write("home/alice/.ssh/authorized_keys", content, None);
        }
        assert_eq!(fr.run(&["--yes"]).rc, 0);
        assert_lacks(&fr.read(DROPIN), "PasswordAuthentication");
    }
}

#[test]
fn ssh_password_authentication_off_when_a_key_exists() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.write("home/alice/.ssh/authorized_keys", "# comment\nssh-ed25519 AAAAC3Nza alice@laptop\n", None);
    let r = fr.run(&["--yes"]);
    r.ok();
    assert_has(&fr.read(DROPIN), "\nPasswordAuthentication no\n");
    assert_has(&fr.read(DROPIN), "\nPermitRootLogin no\n");
    r.out_has("SSH PASSWORD LOGIN IS NOW OFF");
    r.out_has("Please read:");
}

#[test]
fn ssh_never_cuts_off_the_ssh_user_who_has_no_key() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.write("etc/passwd", &(fr.read("etc/passwd") + "bob:x:1001:1001:Bob:/home/bob:/bin/bash\n"), Some(0o644));
    fr.write("etc/group", "root:x:0:\nsudo:x:27:alice,bob\n", None);
    fr.write("home/bob/.ssh/authorized_keys", "ssh-ed25519 AAAA bob@x\n", None);
    let r = fr.run_env(&["--yes"], &[("SSH_CONNECTION", "10.0.0.2 50000 10.0.0.9 22"), ("SUDO_USER", "alice")]);
    r.ok();
    assert_lacks(&fr.read(DROPIN), "PasswordAuthentication");
    r.out_has("password login left as it is");
}

#[test]
fn ssh_keys_for_the_ssh_user_allow_it() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.write("home/alice/.ssh/authorized_keys", "ssh-ed25519 AAAA alice@x\n", None);
    let r = fr.run_env(&["--yes"], &[("SSH_CONNECTION", "10.0.0.2 50000 10.0.0.9 22"), ("SUDO_USER", "alice")]);
    r.ok();
    assert_has(&fr.read(DROPIN), "PasswordAuthentication no");
}

#[test]
fn ssh_revert_when_sshd_t_fails() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.state(&["sshd_t_fail"]);
    let r = fr.run(&["--yes"]);
    r.expect_rc(1);
    assert!(!fr.exists(DROPIN));
    r.out_has("sshd -t rejected");
    r.out_has("reverted");
    assert_lacks(&fr.calls().join("\n"), "systemctl reload");
    let created = fr.read("var/lib/epma-hardening/created.list");
    assert_lacks(&created, "sshd_config.d");
}

#[test]
fn ssh_revert_inside_a_chroot_is_not_an_error_exit() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.state(&["sshd_t_fail"]);
    let r = fr.run(&["--chroot", "--yes"]);
    r.ok();
    assert!(!fr.exists(DROPIN));
    r.out_has("reverted");
}

#[test]
fn ssh_revert_restores_the_previous_dropin() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    let old = "# an older version\nX11Forwarding no\n";
    fr.write(DROPIN, old, None);
    fr.state(&["sshd_t_fail"]);
    fr.run(&["--yes"]).expect_rc(1);
    assert_eq!(fr.read(DROPIN), old);
}

#[test]
fn ssh_reload_only_when_changed_and_running() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.state(&["active_ssh"]);
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    assert_eq!(fr.calls_matching(|c| c.starts_with("systemctl reload")), vec!["systemctl reload ssh".to_string()]);
    let n = fr.calls().len();
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    let later: Vec<String> = fr.calls().into_iter().skip(n).filter(|c| c.starts_with("systemctl reload")).collect();
    assert!(later.is_empty(), "{later:?}");
}

#[test]
fn ssh_sshd_not_installed() {
    let _ = need_bash!();
    let fr = FakeRoot::with(Opts { sshd: false, ..Opts::default() });
    let r = fr.run(&["--yes"]);
    r.ok();
    assert!(!fr.exists("etc/ssh"));
    r.out_has("[SKIP]   SSH: the SSH server is not installed");
}

#[test]
fn ssh_main_config_without_include_is_left_alone() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.write("etc/ssh/sshd_config", "Port 22\nPermitRootLogin yes\n", None);
    let r = fr.run(&["--yes"]);
    r.ok();
    assert!(!fr.exists(DROPIN));
    assert_eq!(fr.read("etc/ssh/sshd_config"), "Port 22\nPermitRootLogin yes\n");
    r.out_has("does not include sshd_config.d");
}

#[test]
fn ssh_root_login_stays_possible_when_there_is_no_normal_user() {
    let _ = need_bash!();
    let fr = FakeRoot::with(Opts { regular_user: false, ..Opts::default() });
    fr.run(&["--yes"]).ok();
    assert_has(&fr.read(DROPIN), "PermitRootLogin prohibit-password");
    assert_lacks(&fr.read(DROPIN), "PermitRootLogin no\n");
}

#[test]
fn ssh_warns_when_an_earlier_file_overrides_ours() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.write("state/sshd_T", "port 22\npermitrootlogin yes\nx11forwarding no\nmaxauthtries 4\n", None);
    let r = fr.run(&["--yes"]);
    r.ok();
    r.out_has("permitrootlogin is yes, not no");
}

// =============================================================================================================
// FirewallTests
// =============================================================================================================

#[test]
fn firewall_ufw_order_and_ssh_port() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.state(&["active_ssh"]);
    fr.run(&["--yes"]).ok();
    let calls = fr.calls();
    let wanted = ["ufw default deny incoming", "ufw default allow outgoing", "ufw allow 22/tcp", "ufw --force enable"];
    let idx: Vec<usize> = wanted.iter().map(|w| index_of(&calls, w)).collect();
    let mut sorted = idx.clone();
    sorted.sort_unstable();
    assert_eq!(idx, sorted);
    assert!(fr.exists("state/ufw_active"));
    assert!(calls.contains(&format!("{APT_INSTALL}ufw")), "{calls:?}");
}

#[test]
fn firewall_ufw_without_ssh_opens_nothing() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.run(&["--yes"]).ok();
    assert!(fr.calls_matching(|c| c.starts_with("ufw allow")).is_empty());
    assert!(fr.calls().contains(&"ufw default deny incoming".to_string()));
}

#[test]
fn firewall_active_ssh_session_port_is_always_allowed() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.run_env(&["--yes"], &[("SSH_CONNECTION", "10.0.0.2 50000 10.0.0.9 2222")]).ok();
    let allows = fr.calls_matching(|c| c.starts_with("ufw allow"));
    assert!(allows.contains(&"ufw allow 2222/tcp".to_string()), "{allows:?}");
    assert!(allows.contains(&"ufw allow 22/tcp".to_string()), "{allows:?}");
    let calls = fr.calls();
    assert!(index_of(&calls, "ufw allow 2222/tcp") < index_of(&calls, "ufw --force enable"));
}

#[test]
fn firewall_garbage_ssh_connection_port_is_ignored() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.run_env(&["--yes"], &[("SSH_CONNECTION", "a b c ;reboot")]).ok();
    assert_eq!(fr.calls_matching(|c| c.starts_with("ufw allow")), vec!["ufw allow 22/tcp".to_string()]);
}

#[test]
fn firewall_existing_active_ufw_is_left_alone() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.state(&["pkg_ufw", "ufw_active"]);
    let r = fr.run(&["--yes"]);
    r.ok();
    assert!(fr.calls_matching(|c| c.starts_with("ufw ") && !c.starts_with("ufw status")).is_empty());
    r.out_has("ufw is already active");
}

#[test]
fn firewall_ufw_failure_does_not_enable_the_firewall() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.state(&["active_ssh"]);
    let stub = fr
        .read("stubs/ufw")
        .replace("--force) touch \"$S/ufw_active\" ;;", "--force) touch \"$S/ufw_active\" ;;\n    allow) exit 1 ;;");
    fr.write("stubs/ufw", &stub, Some(0o755));
    let r = fr.run(&["--yes"]);
    r.expect_rc(1);
    assert!(!fr.calls().contains(&"ufw --force enable".to_string()));
    r.out_has("NOT being enabled");
}

#[test]
fn firewall_firewalld_on_fedora() {
    let _ = need_bash!();
    let fr = FakeRoot::distro("fedora");
    fr.state(&["active_sshd"]);
    fr.run(&["--yes"]).ok();
    let calls = fr.calls();
    assert!(calls.contains(&"dnf -y install firewalld".to_string()), "{calls:?}");
    assert!(calls.contains(&"systemctl enable --now firewalld".to_string()), "{calls:?}");
    assert!(calls.iter().any(|c| c.starts_with("firewall-cmd --permanent --zone=public --add-service=ssh")));
    assert!(
        !calls.iter().any(|c| c.starts_with("firewall-cmd") && c.contains("set-default-zone")),
        "the default zone is not touched"
    );
    assert!(!calls.iter().any(|c| c.starts_with("ufw")));
}

#[test]
fn firewall_firewalld_already_running_is_left_alone() {
    let _ = need_bash!();
    let fr = FakeRoot::distro("fedora");
    fr.state(&["pkg_firewalld", "enabled_firewalld", "active_firewalld"]);
    let r = fr.run(&["--yes"]);
    r.ok();
    assert!(!fr.calls().iter().any(|c| c.starts_with("firewall-cmd --") && c.contains("--add")));
    r.out_has("its zones are left as they are");
}

// =============================================================================================================
// ServicesAndReportsTests
// =============================================================================================================

#[test]
fn services_apt_packages_and_services() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.run(&["--yes"]).ok();
    let calls = fr.calls();
    for pkg in ["ufw", "unattended-upgrades", "auditd"] {
        assert!(calls.contains(&format!("{APT_INSTALL}{pkg}")), "{pkg}: {calls:?}");
    }
    assert!(calls.contains(&"systemctl enable --now auditd".to_string()));
    assert!(calls.contains(&"augenrules --load".to_string()));
    assert!(!calls.iter().any(|c| c.contains("dnf")));
}

#[test]
fn services_dnf_packages_and_automatic_updates() {
    let _ = need_bash!();
    let fr = FakeRoot::distro("fedora");
    fr.run(&["--yes"]).ok();
    let calls = fr.calls();
    for pkg in ["dnf-automatic", "audit", "firewalld"] {
        assert!(calls.contains(&format!("dnf -y install {pkg}")), "{pkg}: {calls:?}");
    }
    assert!(calls.contains(&"systemctl enable --now dnf-automatic-install.timer".to_string()));
    let conf = fr.read("etc/dnf/automatic.conf");
    assert_has(&conf, "upgrade_type = security");
    assert_has(&conf, "apply_updates = yes");
    assert!(!calls.iter().any(|c| c.starts_with("apt-get")));
}

#[test]
fn services_dnf5_uses_its_own_package_and_timer() {
    let _ = need_bash!();
    let fr = FakeRoot::distro("fedora");
    fr.state(&["pkg_dnf5"]);
    fr.run(&["--yes"]).ok();
    let calls = fr.calls();
    assert!(calls.contains(&"dnf -y install dnf5-plugin-automatic".to_string()), "{calls:?}");
    assert!(calls.contains(&"systemctl enable --now dnf-automatic-install.timer".to_string())); // what the stub lists
    assert!(!calls.contains(&"dnf -y install dnf-automatic".to_string()));
}

#[test]
fn services_selinux_and_apparmor_are_only_reported() {
    let _ = need_bash!();
    let fr = FakeRoot::distro("fedora");
    fr.write("stubs/getenforce", "#!/bin/sh\necho Permissive\n", Some(0o755));
    let r = fr.run(&["--yes"]);
    r.ok();
    r.out_has("SELinux is not enforcing");
    r.out_has("[SKIP]   AppArmor");
    assert!(fr.calls_matching(|c| c.contains("setenforce")).is_empty());
    assert_eq!(fr.read("etc/selinux/config"), "SELINUX=enforcing\n");
    let fr2 = FakeRoot::new();
    fr2.write("sys/module/apparmor/parameters/enabled", "N\n", None);
    let r = fr2.run(&["--yes"]);
    r.ok();
    r.out_has("AppArmor is built in but NOT enabled");
    r.out_has("[SKIP]   SELinux");
}

#[test]
fn services_package_failure_is_an_error_exit_but_the_rest_still_runs() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.write(
        "stubs/apt-get",
        "#!/bin/sh\necho \"apt-get $*\" >> \"$EPMA_HARDEN_TEST_ROOT/calls.log\"\nexit 100\n",
        Some(0o755),
    );
    let r = fr.run(&["--yes"]);
    r.expect_rc(1);
    r.out_has("FAILED: install package ufw");
    assert!(fr.exists("etc/sysctl.d/99-epma-hardening.conf"));
    assert!(!fr.exists("state/ufw_active"));
}

// =============================================================================================================
// ChrootTests
// =============================================================================================================

const UNIT: &str = "etc/systemd/system/epma-hardening-firstboot.service";
const WANTS: &str = "etc/systemd/system/multi-user.target.wants/epma-hardening-firstboot.service";
const COPY: &str = "usr/local/sbin/epma-harden-linux.sh";
const MARKER: &str = "var/lib/epma-hardening/firstboot.pending";

#[test]
fn chroot_writes_files_only() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    let r = fr.run(&["--chroot", "--yes"]);
    r.ok();
    assert!(fr.mutating_calls().is_empty(), "{:?}", fr.mutating_calls());
    assert!(!fr.calls().iter().any(|c| starts_with_any(c, &["ufw", "augenrules"])));
    for rel in [
        "etc/sysctl.d/99-epma-hardening.conf",
        "etc/modprobe.d/epma-hardening.conf",
        "etc/ssh/sshd_config.d/99-epma-hardening.conf",
        "etc/security/limits.d/99-epma-hardening.conf",
    ] {
        assert!(fr.exists(rel), "{rel}");
    }
    r.out_has("left to the first boot");
    r.out_has("first boot");
    assert!(!fr.exists("state/ufw_active"));
}

#[test]
fn chroot_first_boot_service_files() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    assert_eq!(fr.run(&["--chroot", "--yes"]).rc, 0);
    let unit = fr.read(UNIT);
    assert_has(&unit, "Type=oneshot");
    assert_has(&unit, "ExecStart=/usr/local/sbin/epma-harden-linux.sh --yes");
    assert_has(&unit, "ConditionPathExists=/var/lib/epma-hardening/firstboot.pending");
    assert_has(&unit, "WantedBy=multi-user.target");
    assert!(fr.is_link(WANTS));
    assert_eq!(fs::read_link(fr.path(WANTS)).unwrap(), PathBuf::from("../epma-hardening-firstboot.service"));
    assert!(fr.exists("var/lib/epma-hardening/firstboot.pending"));
    assert!(fr.mode(COPY) & 0o111 != 0, "the copy must be executable");
    // run from a file: the copy is the script itself
    assert_eq!(fr.read(COPY), fr.script);
}

#[test]
fn chroot_works_through_bash_dash_s() {
    let bash = need_bash!();
    let fr = FakeRoot::new();
    let r = fr.run_stdin(&["--chroot", "--yes"]);
    r.ok();
    assert!(fr.exists(UNIT));
    let copy = fr.path(COPY);
    assert!(copy.exists());
    assert!(Command::new(&bash).arg("-n").arg(&copy).output().unwrap().status.success());
    let p = Command::new(&bash).arg(&copy).arg("--help").output().unwrap();
    assert!(p.status.success(), "{}", String::from_utf8_lossy(&p.stderr));
    assert_has(&String::from_utf8_lossy(&p.stdout), "--chroot");
    // the rebuilt copy behaves like the original: same dry-run report
    let a = fr.run(&["--dry-run"]);
    let moved = PathBuf::from(format!("{}.copy", fr.script_path.display()));
    fs::rename(&copy, &moved).unwrap();
    let mut cmd = Command::new(&bash);
    cmd.arg(&moved).arg("--dry-run").env_clear().envs(fr.env(&[])).current_dir(&fr.scripts);
    let p = run_command(cmd, None, Duration::from_secs(60));
    assert_eq!(p.rc, a.rc, "{}", p.err);
    assert_eq!(p.out, a.out);
}

#[test]
fn chroot_each_option_works_through_bash_dash_s() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    let option_sets: [&[&str]; 4] = [&["--dry-run"], &["--yes"], &["--undo", "--yes"], &["--help"]];
    for flags in option_sets {
        let r = fr.run_stdin(flags);
        r.ok();
    }
    fr.assert_sentinel_empty();
}

#[test]
fn chroot_run_is_idempotent() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    assert_eq!(fr.run(&["--chroot", "--yes"]).rc, 0);
    let skip = ["calls.log", "tmp", "state", "var"];
    let snap = fr.snapshot_with(&skip, true, &[]);
    let r = fr.run(&["--chroot", "--yes"]);
    r.ok();
    r.out_lacks("[CHANGE]");
    assert_eq!(fr.snapshot_with(&skip, true, &[]), snap);
}

#[test]
fn chroot_first_boot_run_finishes_and_switches_the_service_off() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    assert_eq!(fr.run(&["--chroot", "--yes"]).rc, 0);
    fr.state(&["enabled_epma-hardening-firstboot.service"]);
    let r = fr.run(&["--yes"]);
    r.ok();
    assert!(!fr.exists("var/lib/epma-hardening/firstboot.pending"));
    assert!(!fr.exists(WANTS));
    let calls = fr.calls();
    assert!(calls.contains(&"systemctl disable epma-hardening-firstboot.service".to_string()), "{calls:?}");
    assert_has(&calls.join(" "), "auditd");
    r.out_has("first-boot service switched off");
}

#[test]
fn chroot_first_boot_run_stays_on_after_an_error() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    assert_eq!(fr.run(&["--chroot", "--yes"]).rc, 0);
    fr.write("stubs/apt-get", "#!/bin/sh\nexit 100\n", Some(0o755));
    fr.run(&["--yes"]).expect_rc(1);
    assert!(fr.exists("var/lib/epma-hardening/firstboot.pending"));
    assert!(fr.is_link(WANTS));
}

#[test]
fn chroot_undo_removes_the_first_boot_service() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    assert_eq!(fr.run(&["--chroot", "--yes"]).rc, 0);
    assert_eq!(fr.run(&["--undo", "--yes"]).rc, 0);
    for rel in [UNIT, COPY, "var/lib/epma-hardening"] {
        assert!(!fr.exists(rel), "{rel}");
    }
    assert!(!fr.exists(WANTS));
}

// =============================================================================================================
// SshLockoutTests: PermitRootLogin no and PasswordAuthentication no must never leave nobody able to log in
// =============================================================================================================

#[test]
fn lockout_only_root_has_a_key_so_passwords_stay_on() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.write("root/.ssh/authorized_keys", KEY, None);
    let r = fr.run(&["--yes"]);
    r.ok();
    let conf = fr.read(DROPIN);
    assert_lacks(&conf, "PasswordAuthentication");
    assert_has(&conf, "\nPermitRootLogin no\n"); // alice (sudo) can still get in with her password
    r.out_lacks("IS NOW OFF");
    r.out_has("[WARN]   SSH: password login stays ON");
    r.out_has("a key for root or for a service account does not count");
}

#[test]
fn lockout_a_service_account_key_does_not_count() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.add_user("backup", 1001, "/bin/bash", None, false, Some(KEY)); // a real shell, but not in sudo/wheel/admin
    fr.add_user("svc", 500, "/bin/bash", None, true, Some(KEY)); // in sudo, but a system account (UID below 1000)
    let r = fr.run(&["--yes"]);
    r.ok();
    assert_lacks(&fr.read(DROPIN), "PasswordAuthentication");
    r.out_lacks("IS NOW OFF");
}

#[test]
fn lockout_an_admin_without_a_login_shell_does_not_count() {
    let _ = need_bash!();
    let fr = FakeRoot::with(Opts { sudo_user: false, ..Opts::default() });
    fr.add_user("ops", 1002, "/usr/sbin/nologin", None, true, Some(KEY));
    fr.add_user("deploy", 1003, "/bin/false", None, true, Some(KEY));
    fr.run(&["--yes"]).ok();
    let conf = fr.read(DROPIN);
    assert_has(&conf, "\nPermitRootLogin prohibit-password\n");
    assert_lacks(&conf, "PasswordAuthentication");
}

#[test]
fn lockout_a_regular_user_outside_sudo_does_not_allow_refusing_root() {
    let _ = need_bash!();
    let fr = FakeRoot::with(Opts { sudo_user: false, ..Opts::default() });
    fr.write("root/.ssh/authorized_keys", KEY, None);
    fr.write("home/alice/.ssh/authorized_keys", KEY, None);
    let r = fr.run(&["--yes"]);
    r.ok();
    let conf = fr.read(DROPIN);
    assert_has(&conf, "\nPermitRootLogin prohibit-password\n");
    assert_lacks(&conf, "\nPermitRootLogin no\n");
    assert_lacks(&conf, "PasswordAuthentication");
    r.out_has("[WARN]   SSH: no normal user with a login shell is in the sudo/wheel/admin group");
    r.out_has("password logins stay ON");
}

#[test]
fn lockout_comment_only_authorized_keys_do_not_count() {
    let _ = need_bash!();
    for content in ["", "\n  \n", "# ssh-ed25519 AAAA commented@out\n"] {
        let fr = FakeRoot::new();
        fr.write("home/alice/.ssh/authorized_keys", content, None);
        assert_eq!(fr.run(&["--yes"]).rc, 0);
        assert_lacks(&fr.read(DROPIN), "PasswordAuthentication");
    }
}

#[test]
fn lockout_a_key_for_an_admin_allows_both() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.write("home/alice/.ssh/authorized_keys", &format!("# mine\n{KEY}"), None);
    fr.run(&["--yes"]).ok();
    let conf = fr.read(DROPIN);
    assert_has(&conf, "\nPermitRootLogin no\n");
    assert_has(&conf, "\nPasswordAuthentication no\n");
}

#[test]
fn lockout_wheel_through_the_primary_group_counts() {
    let _ = need_bash!();
    let fr = FakeRoot::with(Opts { distro: "fedora", sudo_user: false, ..Opts::default() });
    fr.write("etc/group", "root:x:0:\nwheel:x:10:\n", None);
    fr.add_user("carol", 1005, "/bin/bash", Some(10), false, Some(KEY));
    fr.run(&["--yes"]).ok();
    let conf = fr.read(DROPIN);
    assert_has(&conf, "\nPermitRootLogin no\n");
    assert_has(&conf, "\nPasswordAuthentication no\n");
}

#[test]
fn lockout_the_same_rules_apply_inside_the_installer() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.write("root/.ssh/authorized_keys", KEY, None);
    fr.run(&["--chroot", "--yes"]).ok();
    assert_lacks(&fr.read(DROPIN), "PasswordAuthentication");
    let fr2 = FakeRoot::new();
    fr2.write("home/alice/.ssh/authorized_keys", KEY, None);
    let r = fr2.run(&["--chroot", "--yes"]);
    r.ok();
    assert_has(&fr2.read(DROPIN), "\nPasswordAuthentication no\n");
    r.out_lacks("IS NOW OFF"); // nothing is running inside the installer
    r.out_has("will be refused once its SSH server runs");
}

#[test]
fn lockout_dry_run_does_not_claim_it_is_off() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.write("home/alice/.ssh/authorized_keys", KEY, None);
    let r = fr.run(&["--dry-run"]);
    r.ok();
    r.out_lacks("IS NOW OFF");
    assert!(!fr.exists(DROPIN));
}

// =============================================================================================================
// SshEffectiveTests
// =============================================================================================================

#[test]
fn effective_cloud_init_file_wins_so_password_login_is_not_off() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.write("etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n", None);
    fr.write("home/alice/.ssh/authorized_keys", KEY, None);
    let r = fr.run(&["--yes"]);
    r.ok();
    assert_has(&fr.read(DROPIN), "\nPasswordAuthentication no\n");
    r.out_lacks("IS NOW OFF");
    r.out_has("NOT in effect");
    r.out_has("50-cloud-init.conf");
    r.out_has("STILL ON");
}

#[test]
fn effective_include_below_the_settings_wins() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.write("state/sshd_T", "port 22\npermitrootlogin no\npasswordauthentication yes\n", None);
    fr.write("home/alice/.ssh/authorized_keys", KEY, None);
    let r = fr.run(&["--yes"]);
    r.ok();
    r.out_has("NOT in effect");
    r.out_has("Include");
    r.out_lacks("IS NOW OFF");
}

#[test]
fn effective_still_not_in_effect_on_the_second_run() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.write("etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n", None);
    fr.write("home/alice/.ssh/authorized_keys", KEY, None);
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    let r = fr.run(&["--yes"]);
    r.ok();
    r.out_has("NOT in effect");
}

#[test]
fn effective_confirmed_off() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.write("home/alice/.ssh/authorized_keys", KEY, None);
    let r = fr.run(&["--yes"]);
    r.ok();
    r.out_has("SSH PASSWORD LOGIN IS NOW OFF");
    r.out_lacks("NOT in effect");
    let r = fr.run(&["--yes"]);
    r.out_has("SSH password login is off (confirmed with sshd -T)");
}

#[test]
fn effective_unknown_effective_value_is_not_reported_as_off() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.write("state/sshd_T", "port 22\npermitrootlogin no\n", None);
    fr.write("home/alice/.ssh/authorized_keys", KEY, None);
    let r = fr.run(&["--yes"]);
    r.ok();
    r.out_lacks("IS NOW OFF");
    r.out_has("did not say whether it is in effect");
}

#[test]
fn effective_max_auth_tries_is_not_set_or_checked() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.write("state/sshd_T", "port 22\npermitrootlogin no\nmaxauthtries 6\n", None);
    let r = fr.run(&["--yes"]);
    r.ok();
    assert_lacks(&r.out.to_lowercase(), "maxauthtries");
    assert_lacks(&fr.read(DROPIN), "MaxAuthTries");
}

// =============================================================================================================
// UndoOfRewrittenFilesTests
// =============================================================================================================

#[test]
fn rewritten_second_run_that_changes_a_created_file_leaves_no_backup() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    let before = fr.snapshot_with(&["calls.log", "state", "tmp"], false, &[]);
    assert_eq!(fr.run(&["--chroot", "--yes"]).rc, 0);
    fr.write("home/alice/.ssh/authorized_keys", KEY, None); // the first boot sees a key the installer did not
    let r = fr.run(&["--yes"]);
    r.ok();
    let dropin = "etc/ssh/sshd_config.d/99-epma-hardening.conf";
    assert_has(&fr.read(dropin), "PasswordAuthentication no");
    assert!(!fr.exists(&format!("{dropin}.epma-bak")), "no backup of a file the script created itself");
    let modified = fr.path("var/lib/epma-hardening/modified.list");
    if modified.exists() {
        assert_lacks(&fs::read_to_string(modified).unwrap(), "99-epma-hardening");
    }
    fr.run(&["--undo", "--yes"]).ok();
    assert!(!fr.exists(dropin), "undo must not put the script's own earlier version back");
    fs::remove_file(fr.path("home/alice/.ssh/authorized_keys")).unwrap();
    fs::remove_dir(fr.path("home/alice/.ssh")).unwrap();
    fs::remove_dir(fr.path("home/alice")).unwrap();
    fs::remove_dir(fr.path("home")).unwrap();
    let after = fr.snapshot_with(&["calls.log", "state", "tmp"], false, &["var/log/epma-hardening.log"]);
    assert_eq!(after, before);
}

#[test]
fn rewritten_any_created_file_that_is_rewritten_is_removed_by_undo() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    let target = "etc/modprobe.d/epma-hardening.conf";
    fr.write(target, &(fr.read(target) + "# somebody edited this\n"), None);
    fr.run(&["--yes"]).ok();
    assert!(!fr.exists(&format!("{target}.epma-bak")));
    fr.run(&["--undo", "--yes"]).ok();
    assert!(!fr.exists(target));
    assert!(!fr.exists(&format!("{target}.epma-bak")));
}

fn append_to(path: &std::path::Path, text: &str) {
    use std::io::Write;
    let mut f = fs::OpenOptions::new().append(true).open(path).unwrap();
    f.write_all(text.as_bytes()).unwrap();
}

#[test]
fn rewritten_undo_of_an_old_state_never_restores_a_removed_file() {
    // State written by an earlier version: the path is in created.list AND in modified.list, with a backup.
    let _ = need_bash!();
    let fr = FakeRoot::new();
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    let target = fr.path("etc/modprobe.d/epma-hardening.conf");
    let backup = PathBuf::from(format!("{}.epma-bak", target.display()));
    fs::copy(&target, &backup).unwrap();
    append_to(&fr.path("var/lib/epma-hardening/modified.list"), &format!("{}\n", target.display()));
    fr.run(&["--undo", "--yes"]).ok();
    assert!(!target.exists());
    assert!(!backup.exists());
}

#[test]
fn rewritten_undo_dry_run_says_removed_not_restored_for_those() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    let target = fr.path("etc/modprobe.d/epma-hardening.conf");
    fs::copy(&target, format!("{}.epma-bak", target.display())).unwrap();
    append_to(&fr.path("var/lib/epma-hardening/modified.list"), &format!("{}\n", target.display()));
    let r = fr.run(&["--undo", "--dry-run"]);
    r.ok();
    r.out_lacks("epma-hardening.conf: would be restored");
}

// =============================================================================================================
// SysctlRaiseOnlyTests
// =============================================================================================================

const SYSCTL_CONF: &str = "etc/sysctl.d/99-epma-hardening.conf";

#[test]
fn sysctl_a_stricter_value_in_force_is_never_lowered() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.write("proc/sys/kernel/yama/ptrace_scope", "2\n", None);
    fr.write("proc/sys/fs/protected_regular", "2\n", None);
    fr.write("proc/sys/net/ipv4/conf/all/rp_filter", "1\n", None);
    fr.write("proc/sys/net/ipv4/conf/default/rp_filter", "1\n", None);
    let r = fr.run(&["--yes"]);
    r.ok();
    let conf = fr.read(SYSCTL_CONF);
    for key in [
        "kernel.yama.ptrace_scope",
        "fs.protected_regular",
        "net.ipv4.conf.all.rp_filter",
        "net.ipv4.conf.default.rp_filter",
    ] {
        assert_lacks(&conf, key);
    }
    assert_has(&conf, "kernel.kptr_restrict = 2");
    assert_has(&conf, "fs.protected_fifos = 1");
    r.out_has("already set to something stricter, left alone:");
}

#[test]
fn sysctl_equal_or_weaker_values_are_set() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.write("proc/sys/kernel/yama/ptrace_scope", "1\n", None);
    fr.write("proc/sys/net/ipv4/conf/all/rp_filter", "2\n", None);
    fr.write("proc/sys/net/ipv4/conf/default/rp_filter", "0\n", None);
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    let conf = fr.read(SYSCTL_CONF);
    assert_has(&conf, "kernel.yama.ptrace_scope = 1");
    assert_has(&conf, "net.ipv4.conf.all.rp_filter = 2");
    assert_has(&conf, "net.ipv4.conf.default.rp_filter = 2");
}

#[test]
fn sysctl_stays_stable_on_a_second_run() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.write("proc/sys/kernel/yama/ptrace_scope", "3\n", None);
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    let first = fr.read(SYSCTL_CONF);
    let r = fr.run(&["--yes"]);
    r.ok();
    assert_eq!(fr.read(SYSCTL_CONF), first);
    r.out_lacks("[CHANGE]");
}

#[test]
fn sysctl_other_files_count_inside_the_installer() {
    // Inside the installer /proc/sys belongs to the installer's kernel, but the files of the new system are visible:
    // a stricter value written there must not be lowered by ours.
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.write(
        "etc/sysctl.d/10-network-security.conf",
        "# Ubuntu\nnet.ipv4.conf.default.rp_filter = 1\nnet.ipv4.conf.all.rp_filter=1\n",
        None,
    );
    fr.write("usr/lib/sysctl.d/10-ptrace.conf", "kernel.yama.ptrace_scope = 2\n", None);
    fr.write("proc/sys/fs/protected_regular", "2\n", None); // the installer kernel: ignored in --chroot
    fr.run(&["--chroot", "--yes"]).ok();
    let conf = fr.read(SYSCTL_CONF);
    assert_lacks(&conf, "rp_filter");
    assert_lacks(&conf, "ptrace_scope");
    assert_has(&conf, "fs.protected_regular = 1");
}

#[test]
fn sysctl_values_are_never_lowered_by_the_file_itself() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    let conf = fr.read(SYSCTL_CONF);
    assert_lacks(&conf, "ptrace_scope = 0");
    assert_has(&conf, "raises a setting");
}

// =============================================================================================================
// PermsExactMatchTests / AuditRulesTests
// =============================================================================================================

#[test]
fn perms_shadow_is_not_mistaken_for_shadow_dash() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.chmod("etc/shadow", 0o640);
    fr.write("etc/shadow-", "root:!:19000:0:99999:7:::\n", Some(0o644));
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    // a later change makes /etc/shadow loose; its old mode must be recorded on its own
    fr.chmod("etc/shadow", 0o644);
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    assert_eq!(fr.mode("etc/shadow"), 0o640);
    fr.run(&["--undo", "--yes"]).ok();
    assert_eq!(fr.mode("etc/shadow"), 0o644);
    assert_eq!(fr.mode("etc/shadow-"), 0o644);
}

#[test]
fn perms_each_path_is_recorded_once() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    fr.chmod("etc/shadow", 0o644);
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    let paths: Vec<String> = fr
        .read("var/lib/epma-hardening/perms.list")
        .lines()
        .map(|line| line.split_once(' ').map(|(_, p)| p.trim().to_string()).unwrap_or_default())
        .collect();
    let unique: std::collections::BTreeSet<_> = paths.iter().collect();
    assert_eq!(paths.len(), unique.len(), "{paths:?}");
}

#[test]
fn audit_rules_lastlog_is_not_watched() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.write("var/log/lastlog", "", None);
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    let rules = fr.read("etc/audit/rules.d/99-epma-hardening.rules");
    assert_lacks(&rules, "lastlog");
    assert_has(&rules, "-w /etc/passwd -p wa -k identity");
}

// =============================================================================================================
// UnattendedUpgradesTests
// =============================================================================================================

const ORIGINS: &str = "etc/apt/apt.conf.d/52epma-hardening-unattended";

#[test]
fn uu_security_origins_on_debian_and_ubuntu() {
    let _ = need_bash!();
    for distro in ["ubuntu", "debian"] {
        let fr = FakeRoot::distro(distro);
        fr.run(&["--yes"]).ok();
        let text = fr.read(ORIGINS);
        assert_has(&text, "-security");
        assert_lacks(&text, "Unattended-Upgrade::Automatic-Reboot"); // the administrator's reboot setting is not touched
    }
}

#[test]
fn uu_other_distributions_are_left_alone_with_a_warning() {
    let _ = need_bash!();
    let fr = FakeRoot::distro("mint");
    let r = fr.run(&["--yes"]);
    r.ok();
    assert!(!fr.exists(ORIGINS));
    r.out_has("[WARN]   unattended-upgrades: this system is 'linuxmint'");
    assert_has(&fr.read("etc/apt/apt.conf.d/20auto-upgrades"), "Unattended-Upgrade \"1\"");
}

#[test]
fn uu_without_the_stock_file_nothing_is_replaced() {
    let _ = need_bash!();
    let fr = FakeRoot::with(Opts { uu_stock: false, ..Opts::default() });
    let r = fr.run(&["--chroot", "--yes"]);
    r.ok();
    assert!(!fr.exists(ORIGINS));
    r.out_has("[SKIP]   unattended-upgrades: the stock 50unattended-upgrades does not exist yet");
}

#[test]
fn uu_the_stock_file_installed_by_the_package_is_used_on_the_first_boot() {
    let _ = need_bash!();
    let fr = FakeRoot::with(Opts { uu_stock: false, ..Opts::default() });
    assert_eq!(fr.run(&["--chroot", "--yes"]).rc, 0);
    let r = fr.run(&["--yes"]); // the package install (stub) creates the stock file
    r.ok();
    assert_has(&fr.read(ORIGINS), "-security");
}

#[test]
fn uu_a_deleted_stock_file_is_reported() {
    let _ = need_bash!();
    let fr = FakeRoot::with(Opts { uu_stock: false, ..Opts::default() });
    fr.state(&["pkg_unattended-upgrades"]);
    let r = fr.run(&["--yes"]);
    r.ok();
    assert!(!fr.exists(ORIGINS));
    r.out_has("[WARN]   unattended-upgrades: /etc/apt/apt.conf.d/50unattended-upgrades does not exist");
}

#[test]
fn uu_third_party_origins_are_kept() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.write(
        "etc/apt/apt.conf.d/50unattended-upgrades",
        &STOCK_UU.replacen("};\nUnattended", "        \"LP-PPA-deadsnakes:${distro_codename}\";\n};\nUnattended", 1),
        None,
    );
    let r = fr.run(&["--yes"]);
    r.ok();
    assert!(!fr.exists(ORIGINS));
    r.out_has("LP-PPA-deadsnakes");
    r.out_has("left alone");
}

#[test]
fn uu_third_party_origins_in_another_file_are_kept() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.write(
        "etc/apt/apt.conf.d/51my-origins",
        "Unattended-Upgrade::Origins-Pattern { \"site=packages.example.org\"; };\n",
        None,
    );
    let r = fr.run(&["--yes"]);
    r.ok();
    assert!(!fr.exists(ORIGINS));
    r.out_has("packages.example.org");
}

#[test]
fn uu_commented_out_origins_do_not_count() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.write(
        "etc/apt/apt.conf.d/50unattended-upgrades",
        &format!("{STOCK_UU}//      \"Foo:bar\";\n// Unattended-Upgrade::Automatic-Reboot \"true\";\n"),
        None,
    );
    fr.run(&["--yes"]).ok();
    assert!(fr.exists(ORIGINS));
}

#[test]
fn uu_our_own_file_is_not_a_third_party_on_the_second_run() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    let r = fr.run(&["--yes"]);
    r.ok();
    r.out_lacks("[CHANGE]");
}

#[test]
fn uu_dnf_security_updates_on_centos_stream_install_nothing() {
    let _ = need_bash!();
    let fr = FakeRoot::distro("centos");
    let r = fr.run(&["--yes"]);
    r.ok();
    r.out_has("upgrade_type = security installs NOTHING on CentOS Stream");
    let fr2 = FakeRoot::distro("rocky");
    let r = fr2.run(&["--yes"]);
    r.out_lacks("CentOS Stream");
}

#[test]
fn uu_apt_installs_never_ask_and_wait_for_the_lock() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    let installs = fr.calls_matching(|c| c.starts_with("apt-get install"));
    assert!(!installs.is_empty());
    for call in installs {
        assert_has(&call, "-o DPkg::Lock::Timeout=600");
        assert_has(&call, "-o Dpkg::Options::=--force-confdef");
        assert_has(&call, "-o Dpkg::Options::=--force-confold");
    }
}

// =============================================================================================================
// FirewallPrecheckTests
// =============================================================================================================

const LISTENERS: &str = "tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*\n\
                         tcp LISTEN 0 128 127.0.0.1:631 0.0.0.0:*\n\
                         tcp LISTEN 0 128 [::1]:5432 [::]:*\n\
                         tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n\
                         tcp LISTEN 0 128 [::]:22 [::]:*\n\
                         udp UNCONN 0 0 0.0.0.0:68 0.0.0.0:*\n\
                         udp UNCONN 0 0 *:5353 *:*\n\
                         tcp LISTEN 0 128 [::]:8080 [::]:*\n";

#[test]
fn precheck_other_listening_services_are_listed() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.state(&["active_ssh"]);
    fr.write("state/ss_out", LISTENERS, None);
    let r = fr.run(&["--yes"]);
    r.ok();
    let warn =
        r.out.lines().find(|l| l.contains("these services listen on the network")).expect("the listeners warning");
    assert_has(warn, "8080/tcp");
    assert_has(warn, "5353/udp");
    for not_listed in ["631", "5432", "22/tcp", "68/udp"] {
        assert_lacks(warn, not_listed);
    }
    assert_eq!(warn.matches("8080/tcp").count(), 1);
    assert!(fr.calls().contains(&"ufw --force enable".to_string())); // a warning, not a refusal
}

#[test]
fn precheck_nothing_listening_is_said_so() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    let r = fr.run(&["--yes"]);
    r.ok();
    r.out_has("no other service listens on the network");
}

#[test]
fn precheck_without_ss_a_skip_line_says_it() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fs::remove_file(fr.path("stubs/ss")).unwrap();
    let r = fr.run(&["--yes"]);
    r.ok();
    r.out_has("'ss' command is not available");
}

#[test]
fn precheck_docker_with_yes_warns_and_goes_on() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.state(&["active_docker"]);
    let r = fr.run(&["--yes"]);
    r.ok();
    r.out_has("found docker");
    r.out_has("can break them");
    assert!(fr.calls().contains(&"ufw --force enable".to_string()));
}

#[test]
fn precheck_docker_without_yes_keeps_the_firewall_off() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.state(&["active_docker"]);
    let r = run_with_tty(&fr, &[], "y\n");
    r.ok();
    r.out_has("the firewall was NOT switched on");
    r.out_has("run again with --yes");
    assert!(!fr.calls().contains(&"ufw --force enable".to_string()));
    assert!(fr.calls_matching(|c| c.starts_with("ufw default") || c.starts_with("ufw allow")).is_empty());
    assert!(!fr.exists("state/pkg_ufw"), "ufw is not even installed when it will not be used");
    assert!(fr.exists("etc/sysctl.d/99-epma-hardening.conf"), "everything else still runs");
}

#[test]
fn precheck_tty_run_without_containers_enables_the_firewall() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    let r = run_with_tty(&fr, &[], "y\n");
    r.ok();
    assert!(fr.calls().contains(&"ufw --force enable".to_string()), "{}", r.out);
}

#[test]
fn precheck_other_container_tools_are_detected() {
    let _ = need_bash!();
    for stub in ["virsh", "lxc", "incus", "docker"] {
        let fr = FakeRoot::new();
        fr.write(&format!("stubs/{stub}"), "#!/bin/sh\nexit 0\n", Some(0o755));
        let r = run_with_tty(&fr, &[], "y\n");
        r.ok();
        r.out_has(&format!("found {stub}"));
        assert!(!fr.calls().contains(&"ufw --force enable".to_string()), "{stub}");
    }
    for unit in ["containerd", "libvirtd", "lxd"] {
        let fr = FakeRoot::new();
        fr.state(&[&format!("enabled_{unit}")]);
        let r = run_with_tty(&fr, &[], "y\n");
        r.out_has(&format!("found {unit}"));
    }
}

#[test]
fn precheck_dry_run_reports_it_and_changes_nothing() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.state(&["active_docker"]);
    let before = fr.snapshot();
    let r = fr.run(&["--dry-run"]);
    r.ok();
    r.out_has("would NOT be switched on");
    assert_eq!(fr.snapshot(), before);
}

#[test]
fn precheck_firewalld_checks_too() {
    let _ = need_bash!();
    let fr = FakeRoot::distro("fedora");
    fr.state(&["active_docker"]);
    let r = run_with_tty(&fr, &[], "y\n");
    r.ok();
    r.out_has("found docker");
    assert!(!fr.calls().contains(&"systemctl enable --now firewalld".to_string()));
    let fr2 = FakeRoot::distro("fedora");
    fr2.state(&["active_docker"]);
    fr2.run(&["--yes"]);
    assert!(fr2.calls().contains(&"systemctl enable --now firewalld".to_string()));
}

#[test]
fn precheck_an_active_firewall_is_not_second_guessed() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.state(&["pkg_ufw", "ufw_active", "active_docker"]);
    let r = fr.run(&["--yes"]);
    r.ok();
    r.out_lacks("found docker");
    r.out_has("ufw is already active");
}

// =============================================================================================================
// FirstBootRetryTests
// =============================================================================================================

fn broken_apt(fr: &FakeRoot) {
    fr.write(
        "stubs/apt-get",
        "#!/bin/sh\necho \"apt-get $*\" >> \"$EPMA_HARDEN_TEST_ROOT/calls.log\"\nexit 100\n",
        Some(0o755),
    );
}

#[test]
fn retry_unit_waits_for_cloud_init() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    assert_eq!(fr.run(&["--chroot", "--yes"]).rc, 0);
    let unit = fr.read(UNIT);
    assert_re(&unit, r"(?m)^After=.*\bcloud-final\.service\b");
    assert_re(&unit, r"(?m)^After=.*\bnetwork-online\.target\b");
    assert_has(&unit, "Wants=network-online.target");
}

#[test]
fn retry_marker_counts_the_tries() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    assert_eq!(fr.run(&["--chroot", "--yes"]).rc, 0);
    assert_eq!(fr.read(MARKER).trim(), "attempts=0");
    broken_apt(&fr);
    for n in [1, 2, 3] {
        let r = fr.run(&["--yes"]);
        r.expect_rc(1);
        assert_eq!(fr.read(MARKER).trim(), format!("attempts={n}"));
        r.out_has(&format!("try {n} of 5"));
        assert!(fr.is_link(WANTS));
    }
}

#[test]
fn retry_dry_run_is_not_a_try() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    assert_eq!(fr.run(&["--chroot", "--yes"]).rc, 0);
    assert_eq!(fr.run(&["--dry-run"]).rc, 0);
    assert_eq!(fr.read(MARKER).trim(), "attempts=0");
}

#[test]
fn retry_gives_up_after_five_tries() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    assert_eq!(fr.run(&["--chroot", "--yes"]).rc, 0);
    broken_apt(&fr);
    for _ in 0..5 {
        assert_eq!(fr.run(&["--yes"]).rc, 1);
    }
    assert!(fr.exists(MARKER));
    let n = fr.calls().len();
    let r = fr.run(&["--yes"]);
    r.expect_rc(1);
    r.out_has("gave up after 5 tries");
    assert!(!fr.exists(MARKER));
    assert!(!fr.exists(WANTS));
    let later: Vec<String> = fr.calls().into_iter().skip(n).collect();
    assert!(later.contains(&"systemctl disable epma-hardening-firstboot.service".to_string()), "{later:?}");
    let hardening: Vec<&String> =
        later.iter().filter(|c| starts_with_any(c, &["apt-get", "ufw", "sysctl", "augenrules"])).collect();
    assert!(hardening.is_empty(), "a sixth try must not run the hardening: {hardening:?}");
    let message = fr.read("var/lib/epma-hardening/firstboot-gave-up.txt");
    assert_has(&message, "gave up");
    assert_has(&message, "epma-hardening.log");
    r.out_has("Please read:");
    assert_has(&fr.read("var/log/epma-hardening.log"), "gave up");
    // and the next boot does nothing at all: the marker is gone
    fr.run(&["--undo", "--yes"]).ok();
    assert!(!fr.exists("var/lib/epma-hardening"));
}

#[test]
fn retry_success_still_switches_the_service_off() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    assert_eq!(fr.run(&["--chroot", "--yes"]).rc, 0);
    broken_apt(&fr);
    assert_eq!(fr.run(&["--yes"]).rc, 1);
    fr.write("stubs/apt-get", STUB, Some(0o755));
    let r = fr.run(&["--yes"]);
    r.ok();
    assert!(!fr.exists(MARKER));
    r.out_has("first-boot service switched off");
}

#[test]
fn retry_legacy_marker_text_counts_as_zero() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    assert_eq!(fr.run(&["--chroot", "--yes"]).rc, 0);
    fr.write(MARKER, "pending\n", None);
    assert_eq!(fr.run(&["--yes"]).rc, 0);
    assert!(!fr.exists(MARKER));
}

// =============================================================================================================
// ScriptReferenceTests
// =============================================================================================================

#[test]
fn reference_hint_names_the_installed_copy_inside_the_installer() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    fr.write("root/harden-linux.sh", fr.script, Some(0o700));
    let r = fr.run(&["--chroot", "--yes"]);
    r.ok();
    r.out_has("To go back: sudo bash /root/harden-linux.sh --undo");
}

#[test]
fn reference_hint_without_the_seed_copy_names_the_first_boot_copy() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    let r = fr.run(&["--chroot", "--yes"]);
    r.out_has("To go back: sudo bash /usr/local/sbin/epma-harden-linux.sh --undo");
}

#[test]
fn reference_hint_names_the_real_file_otherwise() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    let r = fr.run(&["--yes"]);
    r.out_has(&format!("To go back: sudo bash {} --undo", fr.script_path.display()));
}

#[test]
fn reference_hint_through_bash_dash_s_does_not_invent_a_path() {
    let _ = need_bash!();
    let fr = FakeRoot::new();
    let r = fr.run_stdin(&["--yes"]);
    r.ok();
    r.out_has("To go back: sudo bash harden-linux.sh --undo");
}

// keep the otherwise unused helpers referenced
#[allow(dead_code)]
fn _unused() {
    let _ = has_line_with("", "");
    let _ = fs::Permissions::from_mode(0o600);
}
