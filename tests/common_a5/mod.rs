//! Helpers of the shell-script tests (A5): a throw-away "fake root" the hardening script runs against, stubs for the
//! live commands, process running with a timeout and a pseudo terminal. Port of the helpers of
//! tests/test_hardening_linux.py. Unix only (the script is bash).
#![cfg(unix)]
#![allow(dead_code)]

use regex::Regex;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use epma_usb_creator::harden_linux::linux_hardening_script;
use epma_usb_creator::types::Hardening;

pub const STUB_NAMES: &[&str] = &[
    "apt-get",
    "dpkg",
    "rpm",
    "dnf",
    "systemctl",
    "sysctl",
    "ufw",
    "firewall-cmd",
    "sshd",
    "augenrules",
    "getenforce",
    "ss",
];

pub const APT_INSTALL: &str = "apt-get install -y --no-install-recommends -o DPkg::Lock::Timeout=600 \
                               -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold ";

pub const STOCK_UU: &str = "// stock\nUnattended-Upgrade::Allowed-Origins {\n        \"${distro_id}:${distro_codename}\";\n        \
                            \"${distro_id}:${distro_codename}-security\";\n};\nUnattended-Upgrade::Automatic-Reboot \"false\";\n";

/// One generic stub for every live command. It logs the call and keeps a little state in <root>/state so a second
/// run can see what the first one did (installed packages, enabled services, ufw).
pub const STUB: &str = include_str!("stub.sh");

pub const KEY: &str = "ssh-ed25519 AAAAC3Nza key@laptop\n";

pub fn mutating_calls() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^(apt-get|dnf) |^systemctl (enable|disable|reload|start|stop)|^sysctl |^ufw (default|allow|--force)|^firewall-cmd .*--add-|^augenrules ",
        )
        .unwrap()
    })
}

// ---------------------------------------------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------------------------------------------

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(name)).find(|p| p.is_file())
}

/// `shutil.which("bash") or "/bin/bash"`; None when there is no bash at all (the tests then skip themselves).
pub fn bash() -> Option<PathBuf> {
    which("bash").or_else(|| Some(PathBuf::from("/bin/bash")).filter(|p| p.exists()))
}

pub fn shellcheck() -> Option<PathBuf> {
    which("shellcheck").or_else(|| Some(PathBuf::from("/opt/homebrew/bin/shellcheck")).filter(|p| p.exists()))
}

/// Print a note and return None when bash is missing: `let Some(bash) = need_bash() else { return };`.
pub fn need_bash() -> Option<PathBuf> {
    let b = bash();
    if b.is_none() {
        eprintln!("note: bash not found: test skipped");
    }
    b
}

pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

pub fn script_text() -> &'static str {
    linux_hardening_script(Hardening::Baseline).expect("baseline script")
}

// ---------------------------------------------------------------------------------------------------------------
// Running processes
// ---------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Run {
    pub rc: i32,
    pub out: String,
    pub err: String,
}

impl Run {
    /// Assert the exit status; the message carries what the script printed.
    #[track_caller]
    pub fn expect_rc(&self, want: i32) -> &Self {
        assert_eq!(self.rc, want, "unexpected exit status\n--- stdout ---\n{}\n--- stderr ---\n{}", self.out, self.err);
        self
    }
    #[track_caller]
    pub fn ok(&self) -> &Self {
        self.expect_rc(0)
    }
    #[track_caller]
    pub fn out_has(&self, needle: &str) {
        assert!(
            self.out.contains(needle),
            "stdout lacks {needle:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.out,
            self.err
        );
    }
    #[track_caller]
    pub fn out_lacks(&self, needle: &str) {
        assert!(
            !self.out.contains(needle),
            "stdout has {needle:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.out,
            self.err
        );
    }
    #[track_caller]
    pub fn err_has(&self, needle: &str) {
        assert!(
            self.err.contains(needle),
            "stderr lacks {needle:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.out,
            self.err
        );
    }
}

#[track_caller]
pub fn assert_has(hay: &str, needle: &str) {
    assert!(hay.contains(needle), "expected {needle:?} in:\n{hay}");
}

#[track_caller]
pub fn assert_lacks(hay: &str, needle: &str) {
    assert!(!hay.contains(needle), "did not expect {needle:?} in:\n{hay}");
}

#[track_caller]
pub fn assert_re(hay: &str, pattern: &str) {
    let re = Regex::new(pattern).unwrap();
    assert!(re.is_match(hay), "expected a match of {pattern:?} in:\n{hay}");
}

fn detach(cmd: &mut Command) {
    // `start_new_session=True`: no controlling terminal, so a prompt cannot hang the test.
    // SAFETY: setsid is async-signal-safe and the closure touches nothing else.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
}

/// Run `cmd`, feed `input`, collect stdout and stderr; kill it after `timeout`.
pub fn run_command(mut cmd: Command, input: Option<&[u8]>, timeout: Duration) -> Run {
    detach(&mut cmd);
    cmd.stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn");
    if let Some(data) = input {
        let mut stdin = child.stdin.take().expect("stdin");
        let data = data.to_vec();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&data);
        });
    }
    let mut stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let t_out = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = stdout.read_to_end(&mut v);
        v
    });
    let t_err = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = stderr.read_to_end(&mut v);
        v
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait().expect("wait") {
            Some(s) => break Some(s),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    };
    let out = t_out.join().unwrap_or_default();
    let err = t_err.join().unwrap_or_default();
    assert!(status.is_some(), "the command timed out after {timeout:?}");
    Run {
        rc: status.and_then(|s| s.code()).unwrap_or(-1),
        out: String::from_utf8_lossy(&out).into_owned(),
        err: String::from_utf8_lossy(&err).into_owned(),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The fake root
// ---------------------------------------------------------------------------------------------------------------

pub fn os_release(distro: &str) -> &'static str {
    match distro {
        "ubuntu" => "PRETTY_NAME=\"Ubuntu 24.04 LTS\"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n",
        "debian" => "PRETTY_NAME=\"Debian GNU/Linux 12\"\nID=debian\n",
        "fedora" => "NAME=\"Fedora Linux\"\nID=fedora\nPRETTY_NAME=\"Fedora Linux 42\"\n",
        "rocky" => {
            "NAME=\"Rocky Linux\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nPRETTY_NAME=\"Rocky Linux 9\"\n"
        }
        "centos" => "NAME=\"CentOS Stream\"\nID=\"centos\"\nID_LIKE=\"rhel fedora\"\nPRETTY_NAME=\"CentOS Stream 9\"\n",
        "mint" => "NAME=\"Linux Mint\"\nID=linuxmint\nID_LIKE=\"ubuntu debian\"\nPRETTY_NAME=\"Linux Mint 22\"\n",
        "opensuse" => "ID=\"opensuse-leap\"\nID_LIKE=\"suse opensuse\"\nPRETTY_NAME=\"openSUSE Leap\"\n",
        other => panic!("unknown distro {other}"),
    }
}

/// The sysctl keys the script lists (`key|default|req|...` rows).
pub fn sysctl_keys(text: &str) -> Vec<String> {
    let re = Regex::new(r"(?m)^([a-z0-9_.]+)\|[^|]*\|(?:req|opt)\|").unwrap();
    re.captures_iter(text).map(|c| c[1].to_string()).collect()
}

/// Options of `FakeRoot::new` (the keyword arguments of the Python class).
#[derive(Clone)]
pub struct Opts {
    pub distro: &'static str,
    pub sshd: bool,
    pub regular_user: bool,
    pub proc_: bool,
    pub login_defs: bool,
    pub sudo_user: bool,
    pub uu_stock: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            distro: "ubuntu",
            sshd: true,
            regular_user: true,
            proc_: true,
            login_defs: true,
            sudo_user: true,
            uu_stock: true,
        }
    }
}

/// What `snapshot` records for one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Link(PathBuf),
    Dir(u32),
    File(u32, Vec<u8>),
}

pub type Snapshot = BTreeMap<String, Entry>;

/// A throw-away root directory with the files the script reads, plus stubs for the live commands.
pub struct FakeRoot {
    _tmp: tempfile::TempDir,
    pub distro: &'static str,
    pub base: PathBuf,
    pub root: PathBuf,
    pub scripts: PathBuf,
    /// HOME and TMPDIR point here: it must stay empty.
    pub sentinel: PathBuf,
    pub script_path: PathBuf,
    pub script: &'static str,
}

impl FakeRoot {
    pub fn new() -> FakeRoot {
        FakeRoot::with(Opts::default())
    }

    pub fn distro(distro: &'static str) -> FakeRoot {
        FakeRoot::with(Opts { distro, ..Opts::default() })
    }

    pub fn with(o: Opts) -> FakeRoot {
        let tmp = tempfile::Builder::new().prefix("epma-harden-test-").tempdir().expect("tempdir");
        let base = tmp.path().canonicalize().expect("canonicalize");
        let root = base.join("root");
        let scripts = base.join("scripts");
        let sentinel = base.join("sentinel");
        for d in [&root, &scripts, &sentinel] {
            fs::create_dir_all(d).unwrap();
        }
        let script_path = scripts.join("harden-linux.sh");
        let script = script_text();
        fs::write(&script_path, script).unwrap();
        let fr = FakeRoot { _tmp: tmp, distro: o.distro, base, root, scripts, sentinel, script_path, script };
        let distro = o.distro;
        fr.write("etc/os-release", os_release(distro), None);
        let mut accounts = String::from("root:x:0:0:root:/root:/bin/bash\n");
        if o.regular_user {
            accounts.push_str("alice:x:1000:1000:Alice:/home/alice:/bin/bash\n");
        }
        fr.write("etc/passwd", &accounts, Some(0o644));
        let mut groups = String::from("root:x:0:\n");
        if o.regular_user && o.sudo_user {
            groups.push_str(if matches!(distro, "fedora" | "rocky") {
                "wheel:x:10:alice\n"
            } else {
                "sudo:x:27:alice\n"
            });
        }
        fr.write("etc/group", &groups, Some(0o664));
        fr.write("etc/shadow", "root:!:19000:0:99999:7:::\n", Some(0o644));
        fr.write("etc/gshadow", "root:*::\n", Some(0o640));
        if o.login_defs {
            fr.write(
                "etc/login.defs",
                "# login.defs\nPASS_MAX_DAYS\t99999\nPASS_MIN_DAYS\t0\nPASS_WARN_AGE\t7\nUMASK\t022\n",
                None,
            );
        }
        fr.write("etc/security/pwquality.conf", "# pwquality\n", None);
        fr.write(
            "etc/apt/apt.conf.d/20auto-upgrades",
            "// original\nAPT::Periodic::Update-Package-Lists \"0\";\n",
            None,
        );
        if o.uu_stock && matches!(distro, "ubuntu" | "debian" | "mint") {
            fr.write("etc/apt/apt.conf.d/50unattended-upgrades", STOCK_UU, None);
        }
        fr.makedirs("tmp");
        fr.makedirs("state");
        fr.makedirs("stubs");
        for name in STUB_NAMES {
            if *name == "sshd" && !o.sshd {
                continue;
            }
            if matches!(distro, "ubuntu" | "debian" | "mint")
                && matches!(*name, "rpm" | "dnf" | "firewall-cmd" | "getenforce")
            {
                continue;
            }
            if matches!(distro, "fedora" | "rocky" | "centos") && matches!(*name, "apt-get" | "dpkg" | "ufw") {
                continue;
            }
            fr.write(&format!("stubs/{name}"), STUB, Some(0o755));
        }
        if o.sshd {
            fr.write("etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n", None);
        }
        if o.proc_ {
            for key in sysctl_keys(fr.script) {
                fr.write(&format!("proc/sys/{}", key.replace('.', "/")), "0\n", None);
            }
        }
        fr.write("sys/module/apparmor/parameters/enabled", "Y\n", None);
        fr.write("etc/selinux/config", "SELINUX=enforcing\n", None);
        fr.makedirs("usr/lib/systemd");
        fr
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    /// Add an account (and optionally put it in sudo/wheel and give it an authorized_keys file).
    pub fn add_user(&self, name: &str, uid: u32, login_shell: &str, gid: Option<u32>, sudo: bool, keys: Option<&str>) {
        let gid = gid.unwrap_or(uid);
        let passwd = self.read("etc/passwd");
        self.write(
            "etc/passwd",
            &format!("{passwd}{name}:x:{uid}:{gid}:{name}:/home/{name}:{login_shell}\n"),
            Some(0o644),
        );
        if sudo {
            let admin = if matches!(self.distro, "fedora" | "rocky" | "centos") { "wheel" } else { "sudo" };
            let mut lines: Vec<String> = self.read("etc/group").lines().map(str::to_string).collect();
            let mut found = false;
            for line in lines.iter_mut() {
                if line.starts_with(&format!("{admin}:")) {
                    let sep = if line.ends_with(':') { "" } else { "," };
                    *line = format!("{line}{sep}{name}");
                    found = true;
                    break;
                }
            }
            if !found {
                lines.push(format!("{admin}:x:27:{name}"));
            }
            self.write("etc/group", &(lines.join("\n") + "\n"), Some(0o664));
        }
        if let Some(keys) = keys {
            self.write(&format!("home/{name}/.ssh/authorized_keys"), keys, None);
        }
    }

    /// `add_user(name, uid, keys=...)` with the defaults of the Python (a bash user, no sudo).
    pub fn add_plain_user(&self, name: &str, uid: u32, keys: &str) {
        self.add_user(name, uid, "/bin/bash", None, false, Some(keys));
    }

    pub fn makedirs(&self, rel: &str) {
        fs::create_dir_all(self.path(rel)).unwrap();
    }

    pub fn write(&self, rel: &str, text: &str, mode: Option<u32>) {
        let p = self.path(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, text).unwrap();
        if let Some(m) = mode {
            fs::set_permissions(&p, fs::Permissions::from_mode(m)).unwrap();
        }
    }

    pub fn read(&self, rel: &str) -> String {
        fs::read_to_string(self.path(rel)).unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
    }

    pub fn exists(&self, rel: &str) -> bool {
        fs::symlink_metadata(self.path(rel)).is_ok()
    }

    /// True when the path exists and is not a symlink or is one (`os.path.exists` follows links).
    pub fn exists_following(&self, rel: &str) -> bool {
        self.path(rel).exists()
    }

    pub fn is_link(&self, rel: &str) -> bool {
        fs::symlink_metadata(self.path(rel)).map(|m| m.file_type().is_symlink()).unwrap_or(false)
    }

    pub fn mode(&self, rel: &str) -> u32 {
        fs::metadata(self.path(rel)).unwrap().permissions().mode() & 0o777
    }

    pub fn chmod(&self, rel: &str, mode: u32) {
        fs::set_permissions(self.path(rel), fs::Permissions::from_mode(mode)).unwrap();
    }

    pub fn state(&self, names: &[&str]) {
        for n in names {
            self.write(&format!("state/{n}"), "", None);
        }
    }

    pub fn calls(&self) -> Vec<String> {
        fs::read_to_string(self.path("calls.log")).map(|t| t.lines().map(str::to_string).collect()).unwrap_or_default()
    }

    pub fn calls_matching(&self, f: impl Fn(&str) -> bool) -> Vec<String> {
        self.calls().into_iter().filter(|c| f(c)).collect()
    }

    pub fn mutating_calls(&self) -> Vec<String> {
        self.calls_matching(|c| mutating_calls().is_match(c))
    }

    pub fn env(&self, extra: &[(&str, Option<&str>)]) -> Vec<(OsString, OsString)> {
        let mut env: BTreeMap<String, String> = BTreeMap::new();
        env.insert("PATH".into(), std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()));
        env.insert("LANG".into(), "C".into());
        env.insert("LC_ALL".into(), "C".into());
        env.insert("HOME".into(), self.sentinel.display().to_string());
        env.insert("TMPDIR".into(), self.sentinel.display().to_string());
        env.insert("EPMA_HARDEN_TEST_ROOT".into(), self.root.display().to_string());
        env.insert("EPMA_HARDEN_TEST_UID".into(), "0".into());
        for (k, v) in extra {
            match v {
                Some(v) => {
                    env.insert((*k).to_string(), (*v).to_string());
                }
                None => {
                    env.remove(*k);
                }
            }
        }
        env.into_iter().map(|(k, v)| (k.into(), v.into())).collect()
    }

    fn command(&self, bash: &Path, args: &[&str], extra: &[(&str, Option<&str>)], via_stdin: bool) -> Command {
        let mut cmd = Command::new(bash);
        if via_stdin {
            cmd.args(["-s", "--"]);
        } else {
            cmd.arg(&self.script_path);
        }
        cmd.args(args).env_clear().envs(self.env(extra)).current_dir(&self.scripts);
        cmd
    }

    /// Run the script. No controlling terminal, so a prompt cannot hang.
    pub fn run(&self, args: &[&str]) -> Run {
        self.run_env(args, &[])
    }

    pub fn run_env(&self, args: &[&str], extra: &[(&str, &str)]) -> Run {
        let extra: Vec<(&str, Option<&str>)> = extra.iter().map(|(k, v)| (*k, Some(*v))).collect();
        let bash = bash().expect("bash");
        run_command(self.command(&bash, args, &extra, false), None, Duration::from_secs(60))
    }

    /// `bash -s -- ARGS` with the script on stdin.
    pub fn run_stdin(&self, args: &[&str]) -> Run {
        let bash = bash().expect("bash");
        run_command(self.command(&bash, args, &[], true), Some(self.script.as_bytes()), Duration::from_secs(60))
    }

    /// `{relative path: (kind, mode, content)}` of everything below the root except the top-level entries in `skip`
    /// (and the exact relative paths in `ignore`). `dirs=false` leaves the directories out.
    pub fn snapshot_with(&self, skip: &[&str], dirs: bool, ignore: &[&str]) -> Snapshot {
        let mut out = Snapshot::new();
        self.walk(&self.root, "", skip, dirs, ignore, &mut out);
        out
    }

    pub fn snapshot(&self) -> Snapshot {
        self.snapshot_with(&["calls.log", "state", "tmp"], true, &[])
    }

    fn walk(&self, dir: &Path, rel_dir: &str, skip: &[&str], dirs: bool, ignore: &[&str], out: &mut Snapshot) {
        let mut names: Vec<_> =
            fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        for name in names {
            let rel = if rel_dir.is_empty() { name.clone() } else { format!("{rel_dir}/{name}") };
            if skip.contains(&rel.split('/').next().unwrap_or("")) || ignore.contains(&rel.as_str()) {
                continue;
            }
            let full = self.root.join(&rel);
            let md = fs::symlink_metadata(&full).unwrap();
            let mode = md.permissions().mode() & 0o7777;
            if md.file_type().is_symlink() {
                out.insert(rel, Entry::Link(fs::read_link(&full).unwrap()));
            } else if md.is_dir() {
                if dirs {
                    out.insert(rel.clone(), Entry::Dir(mode));
                }
                self.walk(&full, &rel, skip, dirs, ignore, out);
            } else {
                out.insert(rel, Entry::File(mode, fs::read(&full).unwrap()));
            }
        }
    }

    #[track_caller]
    pub fn assert_sentinel_empty(&self) {
        let left: Vec<_> = fs::read_dir(&self.sentinel).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert!(left.is_empty(), "the script wrote outside the test root: {left:?}");
    }

    #[track_caller]
    pub fn assert_tmp_empty(&self, why: &str) {
        let left: Vec<_> = fs::read_dir(self.path("tmp")).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert!(left.is_empty(), "{why}: {left:?}");
    }

    pub fn symlink(&self, target: &str, rel: &str) {
        let p = self.path(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        symlink(target, p).unwrap();
    }
}

// ---------------------------------------------------------------------------------------------------------------
// A pseudo terminal (the "Continue?" prompt reads from the controlling terminal)
// ---------------------------------------------------------------------------------------------------------------

/// Run the script on a pseudo terminal, so that the "Continue?" prompt really appears and is answered. Returns
/// (exit status, everything it printed): a terminal has one stream for output and errors. Port of `run_with_tty`
/// (the Python forks a pty from a helper interpreter; here the pty is opened with libc and given to the child as its
/// controlling terminal).
pub fn run_with_tty(fr: &FakeRoot, args: &[&str], answer: &str) -> Run {
    use std::os::fd::{FromRawFd, OwnedFd};
    let bash = bash().expect("bash");
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    // SAFETY: plain libc calls on descriptors this function creates and owns.
    let rc = unsafe {
        libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut())
    };
    assert_eq!(rc, 0, "openpty failed");
    // SAFETY: openpty returned two fresh descriptors.
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    let mut cmd = fr.command(&bash, args, &[], false);
    cmd.stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave.try_clone().unwrap()));
    // SAFETY: setsid and ioctl are async-signal-safe; fd 0 is the slave side of the pty.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::ioctl(0, libc::TIOCSCTTY as _, 0);
            Ok(())
        });
    }
    let mut child = cmd.spawn().expect("spawn on a pty");
    drop(cmd);
    drop(slave); // the child holds the only other copy: EOF/EIO on the master when it exits
    let mut master = std::fs::File::from(master);
    let _ = master.write_all(answer.as_bytes());
    let mut collected = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut buf = [0u8; 65536];
    loop {
        if Instant::now() >= deadline {
            let _ = child.kill();
            break;
        }
        let mut pfd = libc::pollfd { fd: std::os::fd::AsRawFd::as_raw_fd(&master), events: libc::POLLIN, revents: 0 };
        // SAFETY: one valid pollfd.
        let n = unsafe { libc::poll(&mut pfd, 1, 1000) };
        if n == 0 {
            if child.try_wait().ok().flatten().is_some() {
                // the child is gone: drain what is left, then stop
                match master.read(&mut buf) {
                    Ok(k) if k > 0 => collected.extend_from_slice(&buf[..k]),
                    _ => break,
                }
            }
            continue;
        }
        match master.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(k) => collected.extend_from_slice(&buf[..k]),
        }
    }
    let status = child.wait().expect("wait");
    Run {
        rc: status.code().unwrap_or(-1),
        out: String::from_utf8_lossy(&collected).replace("\r\n", "\n"),
        err: String::new(),
    }
}
