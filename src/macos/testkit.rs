//! Test doubles shared by the macOS and Linux unit tests (`#[cfg(test)]` only): a `FakeHost` that records every call
//! that leaves the backends, a `RecPriv` (a recording `Privilege`) and `Fx` (log + progress + cancel for a `Ctx`).
//! Nothing here touches a real disk, runs sudo or the network.

use super::host::Host;
use crate::audit::AuditLevel;
use crate::types::{CancelToken, Ctx, Disk, Error, Files, Identity, Log, Privilege, Progress, Result, Volume};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const GIB: u64 = 1024 * 1024 * 1024;

pub type OutputFn = Box<dyn Fn(&[String]) -> Result<Vec<u8>> + Send + Sync>;
pub type CmdFn = Box<dyn Fn(&[String]) -> Result<i32> + Send + Sync>;
pub type PayloadFn = Box<
    dyn Fn(&Path, &Path, &Ctx<'_>, Option<&dyn Fn() -> Result<PathBuf>>, Option<&Files>) -> Result<()> + Send + Sync,
>;
pub type SeedFn = Box<dyn Fn(&Path, &Files, &Ctx<'_>) -> Result<()> + Send + Sync>;
pub type RawVerifyFn = Box<dyn Fn(&str, &Ctx<'_>) -> Result<()> + Send + Sync>;

/// One thing a backend asked its host to do, in order.
#[derive(Clone, Debug, PartialEq)]
pub enum Call {
    Output { args: Vec<String>, timeout: Duration, quiet: bool },
    Cmd { args: Vec<String>, check: bool, timeout: Option<Duration> },
    Sleep(f64),
    Rmdir(PathBuf),
    Hybrid(PathBuf),
    Payload { src: PathBuf, dst: PathBuf, hint: String, reopen: bool, extra: Option<Vec<String>> },
    VerifyRaw { device: String },
    CopySeed { dst: PathBuf },
    VerifySeed { dst: PathBuf },
}

pub struct FakeHost {
    pub calls: Mutex<Vec<Call>>,
    pub audits: Mutex<Vec<(String, AuditLevel)>>,
    pub output: OutputFn,
    pub cmd: CmdFn,
    pub payload: PayloadFn,
    pub copy_seed: SeedFn,
    pub verify_seed: SeedFn,
    pub verify_raw: RawVerifyFn,
    /// Names `which` finds.
    pub binaries: HashSet<String>,
    /// `used_bytes` answers for these mountpoints.
    pub used: Vec<(String, u64)>,
    pub hybrid_ok: bool,
    pub owner: String,
    pub sys_root: PathBuf,
    pub root: tempfile::TempDir,
    pub counter: AtomicUsize,
}

impl Default for FakeHost {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeHost {
    pub fn new() -> FakeHost {
        FakeHost {
            calls: Mutex::new(Vec::new()),
            audits: Mutex::new(Vec::new()),
            output: Box::new(|args| {
                Err(Error::Io(std::io::Error::new(std::io::ErrorKind::NotFound, format!("no fake for {args:?}"))))
            }),
            cmd: Box::new(|_| Ok(0)),
            payload: Box::new(|_, _, _, _, _| Ok(())),
            copy_seed: Box::new(|_, _, _| Ok(())),
            verify_seed: Box::new(|_, _, _| Ok(())),
            verify_raw: Box::new(|_, _| Ok(())),
            binaries: HashSet::new(),
            used: Vec::new(),
            hybrid_ok: true,
            owner: "1000:1000".to_string(),
            sys_root: PathBuf::from("/nonexistent-sys-block"),
            root: tempfile::tempdir().expect("temp dir"),
            counter: AtomicUsize::new(0),
        }
    }

    pub fn with_output(mut self, f: impl Fn(&[String]) -> Result<Vec<u8>> + Send + Sync + 'static) -> Self {
        self.output = Box::new(f);
        self
    }
    pub fn with_cmd(mut self, f: impl Fn(&[String]) -> Result<i32> + Send + Sync + 'static) -> Self {
        self.cmd = Box::new(f);
        self
    }
    pub fn with_payload(
        mut self,
        f: impl Fn(&Path, &Path, &Ctx<'_>, Option<&dyn Fn() -> Result<PathBuf>>, Option<&Files>) -> Result<()>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.payload = Box::new(f);
        self
    }
    pub fn with_binaries(mut self, names: &[&str]) -> Self {
        self.binaries = names.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }
    /// The `run_cmd` calls: `(args, check, timeout)`.
    pub fn cmds(&self) -> Vec<(Vec<String>, bool, Option<Duration>)> {
        self.calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Cmd { args, check, timeout } => Some((args, check, timeout)),
                _ => None,
            })
            .collect()
    }
    /// The `run_cmd` argument lists only.
    pub fn cmd_args(&self) -> Vec<Vec<String>> {
        self.cmds().into_iter().map(|(a, _, _)| a).collect()
    }
    pub fn outputs(&self) -> Vec<(Vec<String>, Duration, bool)> {
        self.calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Output { args, timeout, quiet } => Some((args, timeout, quiet)),
                _ => None,
            })
            .collect()
    }
    pub fn audit_texts(&self) -> Vec<String> {
        self.audits.lock().unwrap().iter().map(|(m, _)| m.clone()).collect()
    }
    pub fn sleeps(&self) -> usize {
        self.calls().iter().filter(|c| matches!(c, Call::Sleep(_))).count()
    }
    fn record(&self, call: Call) {
        self.calls.lock().unwrap().push(call);
    }
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}

impl Host for FakeHost {
    fn check_output(&self, args: &[&str], timeout: Duration, quiet_stderr: bool) -> Result<Vec<u8>> {
        let args = strings(args);
        self.record(Call::Output { args: args.clone(), timeout, quiet: quiet_stderr });
        (self.output)(&args)
    }
    fn run_cmd(
        &self,
        args: &[&str],
        _log: Log,
        check: bool,
        timeout: Option<Duration>,
        _cancel: Option<&CancelToken>,
    ) -> Result<i32> {
        let args = strings(args);
        self.record(Call::Cmd { args: args.clone(), check, timeout });
        (self.cmd)(&args)
    }
    fn sleep(&self, seconds: f64) {
        self.record(Call::Sleep(seconds));
    }
    fn audit(&self, msg: &str, level: AuditLevel) {
        self.audits.lock().unwrap().push((msg.to_string(), level));
    }
    fn which(&self, name: &str) -> bool {
        self.binaries.contains(name)
    }
    fn used_bytes(&self, mountpoint: &str) -> Option<u64> {
        self.used.iter().find(|(mp, _)| mp == mountpoint).map(|(_, n)| *n)
    }
    fn owner(&self) -> String {
        self.owner.clone()
    }
    fn mkdtemp(&self, prefix: &str) -> Result<PathBuf> {
        let n = self.counter.fetch_add(1, Ordering::SeqCst);
        let dir = self.root.path().join(format!("{prefix}{n}"));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }
    fn silent_rmdir(&self, path: &Path) {
        self.record(Call::Rmdir(path.to_path_buf()));
    }
    fn sys_block_root(&self) -> PathBuf {
        self.sys_root.clone()
    }
    fn disk_entry(
        &self,
        id: &str,
        size: u64,
        model: Option<&str>,
        volumes: Option<Vec<Volume>>,
        identity: Identity,
    ) -> Disk {
        Disk {
            id: id.to_string(),
            size,
            label: format!("/dev/{id} - {}", model.unwrap_or("")),
            model: model.map(str::to_string),
            volumes: match volumes {
                Some(list) => crate::types::Volumes::List(list),
                None => crate::types::Volumes::Unknown,
            },
            identity,
        }
    }
    /// The Python `make_identity`: sorted pairs, empty values dropped.
    fn make_identity(&self, parts: &[(&str, Option<String>)]) -> Identity {
        let mut pairs: Vec<(String, String)> = parts
            .iter()
            .filter_map(|(k, v)| {
                let v = v.as_deref()?.trim().to_string();
                if v.is_empty() {
                    None
                } else {
                    Some((k.to_string(), v))
                }
            })
            .collect();
        pairs.sort();
        pairs
    }
    fn validate_hybrid_iso(&self, path: &Path) -> Result<()> {
        self.record(Call::Hybrid(path.to_path_buf()));
        if self.hybrid_ok {
            Ok(())
        } else {
            Err(Error::value("not a hybrid ISO"))
        }
    }
    fn make_dd_log<'a>(
        &self,
        log: Log<'a>,
        _total: u64,
        _progress: Option<Progress<'a>>,
    ) -> Box<dyn Fn(&str) + Send + Sync + 'a> {
        Box::new(move |line| log(line))
    }
    fn with_cancel_flag(&self, _cancel: Option<&CancelToken>, f: &mut dyn FnMut(&Path) -> Result<()>) -> Result<()> {
        f(&self.root.path().join("cancel"))
    }
    fn verify_raw_write(&self, _iso: &Path, device_path: &str, ctx: &Ctx, _priv: &dyn Privilege) -> Result<()> {
        self.record(Call::VerifyRaw { device: device_path.to_string() });
        (self.verify_raw)(device_path, ctx)
    }
    fn copy_windows_payload(
        &self,
        src_root: &Path,
        dst_root: &Path,
        ctx: &Ctx,
        wimlib_hint: &str,
        reopen: Option<&dyn Fn() -> Result<PathBuf>>,
        extra_files: Option<&Files>,
    ) -> Result<()> {
        self.record(Call::Payload {
            src: src_root.to_path_buf(),
            dst: dst_root.to_path_buf(),
            hint: wimlib_hint.to_string(),
            reopen: reopen.is_some(),
            extra: extra_files.map(|f| f.keys().cloned().collect()),
        });
        (self.payload)(src_root, dst_root, ctx, reopen, extra_files)
    }
    fn copy_seed_files(&self, _stage: &Path, dst_root: &Path, files: &Files, ctx: &Ctx) -> Result<()> {
        self.record(Call::CopySeed { dst: dst_root.to_path_buf() });
        (self.copy_seed)(dst_root, files, ctx)
    }
    fn verify_seed_files(&self, files: &Files, dst_root: &Path, ctx: &Ctx) -> Result<()> {
        self.record(Call::VerifySeed { dst: dst_root.to_path_buf() });
        (self.verify_seed)(dst_root, files, ctx)
    }
}

/// A minimal stand-in for `copy_seed_files`: write every file under `dst`.
pub fn write_files(dst: &Path, files: &Files) -> Result<()> {
    for (rel, data) in files {
        let path = dst.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, data)?;
    }
    Ok(())
}

/// A minimal stand-in for `verify_seed_files`: every file must exist with the same bytes.
pub fn compare_files(dst: &Path, files: &Files) -> Result<()> {
    let mut bad = Vec::new();
    for (rel, data) in files {
        match std::fs::read(dst.join(rel)) {
            Err(_) => bad.push(format!("{rel} (missing)")),
            Ok(found) if found.len() != data.len() => bad.push(format!("{rel} (size differs)")),
            Ok(found) if &found != data => bad.push(format!("{rel} (content differs)")),
            Ok(_) => {}
        }
    }
    if bad.is_empty() {
        Ok(())
    } else {
        Err(Error::runtime(format!(
            "Verification FAILED: {} file(s) on the drive are missing or differ from the seed files (for example: {}).\n\nThe drive was NOT ejected and should not be used.",
            bad.len(),
            bad[0]
        )))
    }
}

// ---------------------------------------------------------------------------------------------------------------

type PrivFn = Box<dyn Fn(usize, &str, &[String], Log) -> Result<()> + Send + Sync>;

/// A `Privilege` that records every script and its arguments and lets a test script what each run does.
pub struct RecPriv {
    pub scripts: Mutex<Vec<(String, Vec<String>)>>,
    on_run: PrivFn,
}

impl RecPriv {
    pub fn new() -> RecPriv {
        RecPriv { scripts: Mutex::new(Vec::new()), on_run: Box::new(|_, _, _, _| Ok(())) }
    }
    /// `f(index, script, args, log)` runs after the call is recorded; its result is the result of `run_script`.
    pub fn with(f: impl Fn(usize, &str, &[String], Log) -> Result<()> + Send + Sync + 'static) -> RecPriv {
        RecPriv { scripts: Mutex::new(Vec::new()), on_run: Box::new(f) }
    }
    pub fn recorded(&self) -> Vec<(String, Vec<String>)> {
        self.scripts.lock().unwrap().clone()
    }
    pub fn count(&self) -> usize {
        self.scripts.lock().unwrap().len()
    }
    /// The script texts, in order.
    pub fn texts(&self) -> Vec<String> {
        self.recorded().into_iter().map(|(s, _)| s).collect()
    }
}

impl Default for RecPriv {
    fn default() -> Self {
        Self::new()
    }
}

impl Privilege for RecPriv {
    fn run_script(&self, script: &str, log: Log, args: &[String]) -> Result<()> {
        let index = {
            let mut scripts = self.scripts.lock().unwrap();
            scripts.push((script.to_string(), args.to_vec()));
            scripts.len() - 1
        };
        (self.on_run)(index, script, args, log)
    }
    fn authenticate(&self, _reason: &str) -> Result<bool> {
        Ok(true)
    }
}

// ---------------------------------------------------------------------------------------------------------------

type ProgressRec = Arc<Mutex<Vec<(u64, u64, String)>>>;
type ProgressFn = Box<dyn Fn(u64, u64, &str) + Send + Sync>;

/// log + progress + cancel for a `Ctx`, recording what was reported.
pub struct Fx {
    lines: Arc<Mutex<Vec<String>>>,
    progress_calls: ProgressRec,
    pub cancel: CancelToken,
    log: Box<dyn Fn(&str) + Send + Sync>,
    progress: ProgressFn,
}

impl Fx {
    pub fn new() -> Fx {
        let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let progress_calls: ProgressRec = Arc::new(Mutex::new(Vec::new()));
        let l = Arc::clone(&lines);
        let p = Arc::clone(&progress_calls);
        Fx {
            lines,
            progress_calls,
            cancel: CancelToken::new(),
            log: Box::new(move |line| l.lock().unwrap().push(line.to_string())),
            progress: Box::new(move |done, total, text| {
                p.lock().unwrap().push((done, total, text.to_string()));
            }),
        }
    }
    pub fn ctx(&self) -> Ctx<'_> {
        Ctx::new(&*self.log, Some(&*self.progress), Some(&self.cancel))
    }
    pub fn lines(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }
    pub fn text(&self) -> String {
        self.lines().join("\n")
    }
    pub fn has(&self, needle: &str) -> bool {
        self.lines().iter().any(|l| l.contains(needle))
    }
    pub fn progress_texts(&self) -> Vec<String> {
        self.progress_calls.lock().unwrap().iter().map(|(_, _, t)| t.clone()).collect()
    }
}

impl Default for Fx {
    fn default() -> Self {
        Self::new()
    }
}

/// A `Log` that discards everything.
pub fn quiet(_line: &str) {}

/// A temp file of `size` bytes standing in for an ISO.
pub fn make_image(dir: &Path, name: &str, size: usize) -> PathBuf {
    let path = dir.join(name);
    let mut data = vec![0x5au8; size];
    if size >= 512 {
        data[510] = 0x55;
        data[511] = 0xaa;
    }
    std::fs::write(&path, data).expect("write image");
    path
}

/// Running the real root scripts with bash against stub tools (unix only; skipped where there is no bash).
#[cfg(unix)]
pub mod script {
    use std::fs;
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    pub fn have_bash() -> bool {
        Command::new("bash").args(["-c", "true"]).status().is_ok_and(|s| s.success())
    }

    pub fn wait_until(mut f: impl FnMut() -> bool, seconds: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        while Instant::now() < deadline {
            if f() {
                return true;
            }
            thread::sleep(Duration::from_millis(25));
        }
        f()
    }

    pub fn alive(pid: i32) -> bool {
        // SAFETY: signal 0 only checks that the process exists.
        unsafe { libc::kill(pid, 0) == 0 }
    }

    /// Write an executable stub named `name` in `bin`.
    pub fn write_stub(bin: &Path, name: &str, body: &str) {
        let path = bin.join(name);
        fs::write(&path, body).expect("write stub");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("chmod stub");
    }

    /// `bash -c <script> win11_usb_creator <args...>` with `bin` first on PATH: `(exit code, stdout, stderr)`.
    pub fn run_script(script: &str, args: &[String], bin: &Path) -> (Option<i32>, String, String) {
        let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap_or_default());
        let out = Command::new("bash")
            .arg("-c")
            .arg(script)
            .arg("win11_usb_creator")
            .args(args)
            .env("PATH", path)
            .stdin(Stdio::null())
            .output()
            .expect("run bash");
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// Stub `dd` (records its pid and sleeps) and `umount`, plus a flag file the app would create to cancel.
    pub struct Stubs {
        pub dir: tempfile::TempDir,
        pub bin: PathBuf,
        pub pidfile: PathBuf,
        pub flag: PathBuf,
    }

    impl Default for Stubs {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Stubs {
        pub fn new() -> Stubs {
            let dir = tempfile::tempdir().expect("temp dir");
            let bin = dir.path().join("bin");
            fs::create_dir_all(&bin).expect("bin dir");
            let pidfile = dir.path().join("dd.pid");
            let flag = dir.path().join("cancel-flag");
            let stubs = Stubs { dir, bin, pidfile, flag };
            // exec keeps the pid, so SIGTERM stops it
            let dd = format!("#!/bin/sh\necho $$ > \"{}\"\nexec sleep 30\n", stubs.pidfile.display());
            write_stub(&stubs.bin, "dd", &dd);
            write_stub(&stubs.bin, "umount", "#!/bin/sh\nexit 0\n");
            stubs
        }
        pub fn path(&self, name: &str) -> String {
            self.dir.path().join(name).to_string_lossy().into_owned()
        }
        pub fn pid(&self) -> Option<i32> {
            fs::read_to_string(&self.pidfile).ok()?.trim().parse().ok()
        }
        /// Own process group, so the SIGINT below reaches only this script and its children.
        pub fn start(&self, script: &str, args: &[String]) -> Child {
            let path = format!("{}:{}", self.bin.display(), std::env::var("PATH").unwrap_or_default());
            Command::new("bash")
                .arg("-c")
                .arg(script)
                .arg("win11_usb_creator")
                .args(args)
                .env("PATH", path)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .process_group(0)
                .spawn()
                .expect("start bash")
        }
        /// Wait for the stub dd, send SIGINT to the group (what a terminal Ctrl-C does); is the script still alive?
        fn interrupt(&self, child: &mut Child) -> bool {
            assert!(wait_until(|| self.pid().is_some(), 10), "the stub dd never started");
            // SAFETY: the child leads its own process group (process_group(0)), so this signals only the script.
            unsafe { libc::killpg(child.id() as i32, libc::SIGINT) };
            thread::sleep(Duration::from_millis(400));
            child.try_wait().expect("poll").is_none()
        }
        pub fn check_raw_script(&self, script: &str, args: &[String]) {
            let mut child = self.start(script, args);
            assert!(self.interrupt(&mut child), "Ctrl-C killed the root script");
            let dd_pid = self.pid().expect("dd pid");
            assert!(alive(dd_pid), "dd died from the Ctrl-C itself (nobody stopped it)");
            fs::File::create(&self.flag).expect("flag"); // the app's cancel flag
            let deadline = Instant::now() + Duration::from_secs(8);
            let status = loop {
                if let Some(status) = child.try_wait().expect("poll") {
                    break status;
                }
                if Instant::now() > deadline {
                    let _ = child.kill();
                    panic!("the script did not stop after the cancel flag appeared");
                }
                thread::sleep(Duration::from_millis(50));
            };
            let mut out = String::new();
            if let Some(mut stdout) = child.stdout.take() {
                let _ = stdout.read_to_string(&mut out);
            }
            assert_eq!(status.code(), Some(0));
            assert!(out.contains(crate::constants::RAW_CANCELED_MARKER), "stdout: {out:?}");
            assert!(wait_until(|| !alive(dd_pid), 5), "the script left dd running");
        }
        /// The control experiment: without the trap, Ctrl-C kills the script and dd is left behind.
        pub fn check_script_dies_and_orphans_dd(&self, script: &str, args: &[String]) {
            let mut child = self.start(script, args);
            let survived = self.interrupt(&mut child);
            let dd_pid = self.pid().expect("dd pid");
            assert!(!survived, "the script should die from the Ctrl-C");
            assert!(alive(dd_pid), "dd should be left behind as an orphan");
            let _ = child.wait();
        }
    }

    impl Drop for Stubs {
        fn drop(&mut self) {
            if let Some(pid) = self.pid() {
                if alive(pid) {
                    // SAFETY: our own stub (its pid came from the pid file the stub wrote), never anything else.
                    unsafe { libc::kill(pid, libc::SIGTERM) };
                }
            }
        }
    }
}
