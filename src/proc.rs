//! Running commands, the cancel-flag file, keeping the computer awake. OWNER: A1.
//! Port of win11_usb_creator.py lines 1467-1486 (OperationCanceled -> `types::Error::Canceled`), 1487-1494, 1533-1724,
//! 1726-1745 (platform_display_name).

use crate::constants::{APP_NAME, IS_LINUX, IS_MAC, IS_WINDOWS, SLEEP_INHIBIT_CHECK_SECONDS, SLEEP_INHIBIT_SECONDS};
use crate::types::{CancelToken, Error, Log, Result};
use crate::util::{py_rstrip, silent_remove, silent_rmdir, which};
use std::collections::HashMap;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// `check_canceled(cancel_event, drive_touched, written)`.
pub fn check_canceled(cancel: Option<&CancelToken>, drive_touched: bool, written: bool) -> Result<()> {
    match cancel {
        Some(c) if c.is_set() => Err(Error::canceled_with("Canceled by the user.", drive_touched, written)),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Stopping a child
// ---------------------------------------------------------------------------------------------------------------

/// `CREATE_NO_WINDOW`: a windowed program must not flash a console for every command it runs.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// The Python `SUBPROCESS_QUIET`: a windowed program (the MSI's GUI) has no console and no standard input to hand on,
/// so on Windows each child gets no window and an empty stdin. Elsewhere nothing changes.
fn quiet(cmd: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
        cmd.stdin(Stdio::null());
    }
    #[cfg(not(windows))]
    {
        let _ = cmd;
    }
}

fn lock_child(child: &Mutex<Child>) -> std::sync::MutexGuard<'_, Child> {
    child.lock().unwrap_or_else(|e| e.into_inner())
}

/// Send the polite (`hard == false`, SIGTERM) or the final (`hard == true`, SIGKILL) stop to a child that has not
/// been reaped yet. With `group`, the child's whole process group gets it (the child must lead its own group).
#[cfg(unix)]
fn send_signal(child: &mut Child, group: bool, hard: bool) -> std::io::Result<()> {
    let pid = child.id() as libc::pid_t;
    let sig = if hard { libc::SIGKILL } else { libc::SIGTERM };
    // SAFETY: plain signal-sending syscalls on a pid we own and have not reaped (the caller holds the lock that
    // guards every reaping), so the pid cannot have been reused.
    let rc = unsafe {
        if group {
            let pgid = libc::getpgid(pid);
            if pgid < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if pgid == libc::getpgrp() {
                // The child shares OUR group (it was not started in its own): never signal that, it would take
                // the whole program down. Stop the child alone instead.
                libc::kill(pid, sig)
            } else {
                libc::killpg(pgid, sig)
            }
        } else {
            libc::kill(pid, sig)
        }
    };
    if rc != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Windows has no process groups to signal and no polite stop either: the child is stopped alone
/// (`TerminateProcess`, which is also what Python's `terminate()` and `kill()` do there).
#[cfg(windows)]
fn send_signal(child: &mut Child, _group: bool, _hard: bool) -> std::io::Result<()> {
    child.kill()
}

/// `_stop_process(proc, group)`: ask a child (or, with `group`, its whole process group) to stop; kill it if it does
/// not within 5 seconds. Every error is swallowed, like the Python `except (OSError, ProcessLookupError)`.
fn stop_process(child: &Mutex<Child>, group: bool) {
    {
        let mut c = lock_child(child);
        // Already gone (and reaped by `try_wait`): never signal a pid that may have been reused.
        if !matches!(c.try_wait(), Ok(None)) {
            return;
        }
        if send_signal(&mut c, group, false).is_err() {
            return;
        }
    }
    let deadline = Instant::now() + Duration::from_secs(5); // proc.wait(timeout=5)
    loop {
        match lock_child(child).try_wait() {
            Ok(None) => {}
            _ => return, // exited (or cannot be asked any more)
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut c = lock_child(child);
    if matches!(c.try_wait(), Ok(None)) {
        let _ = send_signal(&mut c, group, true);
    }
}

/// Wait for the child to exit. With a watchdog thread around, the lock must not be held while waiting, so poll.
fn wait_child(child: &Mutex<Child>, shared: bool) -> std::io::Result<ExitStatus> {
    if !shared {
        return lock_child(child).wait();
    }
    let mut delay = Duration::from_millis(1);
    loop {
        if let Some(status) = lock_child(child).try_wait()? {
            return Ok(status);
        }
        std::thread::sleep(delay);
        delay = (delay * 2).min(Duration::from_millis(10));
    }
}

/// The Python `returncode`: the exit code, or minus the signal number when the child was killed by a signal.
fn exit_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return -sig;
        }
    }
    -1
}

// ---------------------------------------------------------------------------------------------------------------
// run_cmd
// ---------------------------------------------------------------------------------------------------------------

/// A single line is cut here when a command prints without ever ending a line (the Python would keep growing).
const MAX_LINE_BYTES: usize = 1 << 20;

/// Read `reader` to the end and hand each line to `log` the way Python's text mode does: "\n", "\r" and "\r\n" all
/// end a line (so a progress display that rewrites one line with "\r" becomes a series of lines), invalid UTF-8 is
/// replaced (not fatal), and trailing whitespace is stripped.
fn pump_lines(mut reader: impl Read, log: Log) -> std::io::Result<()> {
    let mut buf = [0u8; 8192];
    let mut line: Vec<u8> = Vec::new();
    let mut skip_lf = false; // the last byte seen was "\r": swallow the "\n" of a "\r\n" pair
    let emit = |line: &mut Vec<u8>| {
        log(py_rstrip(&String::from_utf8_lossy(line)));
        line.clear();
    };
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        for &b in &buf[..n] {
            if skip_lf {
                skip_lf = false;
                if b == b'\n' {
                    continue;
                }
            }
            match b {
                b'\n' => emit(&mut line),
                b'\r' => {
                    emit(&mut line);
                    skip_lf = true;
                }
                _ => {
                    line.push(b);
                    if line.len() >= MAX_LINE_BYTES {
                        emit(&mut line);
                    }
                }
            }
        }
    }
    if !line.is_empty() {
        emit(&mut line);
    }
    Ok(())
}

/// What the watchdog thread found out.
#[derive(Default)]
struct WatchState {
    timed_out: AtomicBool,
    canceled: AtomicBool,
}

/// The watchdog of `run_cmd`: every 0.2 s look at the cancel flag and the deadline; on either, stop the child.
fn watchdog(
    child: Arc<Mutex<Child>>,
    finished: CancelToken,
    cancel: Option<CancelToken>,
    timeout: Option<Duration>,
    state: Arc<WatchState>,
) {
    let deadline = timeout.map(|t| Instant::now() + t);
    while !finished.wait(Duration::from_millis(200)) {
        if cancel.as_ref().is_some_and(|c| c.is_set()) {
            state.canceled.store(true, Ordering::SeqCst);
        } else if deadline.is_some_and(|d| Instant::now() >= d) {
            state.timed_out.store(true, Ordering::SeqCst);
        } else {
            continue;
        }
        stop_process(&child, false);
        return;
    }
}

/// The timeout as the Python prints it: `30` for whole seconds, `2.5` otherwise.
fn secs_text(t: Duration) -> String {
    if t.subsec_nanos() == 0 {
        t.as_secs().to_string()
    } else {
        t.as_secs_f64().to_string()
    }
}

/// Run a command as the current user, streaming stdout+stderr line by line to `log` (first logs `$ cmd args`).
/// `timeout` kills a hung command; `cancel` stops it promptly (Error::Canceled). With `check`, a non-zero exit is
/// `Error::Runtime("Command failed (exit code N): ...")`. Returns the exit code. On Windows children get no console
/// window and an empty stdin (the Python SUBPROCESS_QUIET).
///
/// stderr is merged into stdout (the Python `stderr=STDOUT`): both streams are clones of one pipe writer.
pub fn run_cmd<S: AsRef<str>>(
    args: &[S],
    log: Log,
    check: bool,
    timeout: Option<Duration>,
    cancel: Option<&CancelToken>,
) -> Result<i32> {
    let Some(program) = args.first().map(|a| a.as_ref()) else {
        return Err(Error::value("No command to run."));
    };
    let joined = args.iter().map(|a| a.as_ref()).collect::<Vec<_>>().join(" ");
    log(&format!("$ {joined}"));

    let (reader, writer) = std::io::pipe()?;
    let mut cmd = Command::new(program);
    cmd.args(args[1..].iter().map(|a| a.as_ref()));
    cmd.stdout(writer.try_clone()?).stderr(writer);
    quiet(&mut cmd);
    let spawned = cmd.spawn();
    // The command object holds our copies of the write end: drop them, or the reader would never see the end.
    drop(cmd);
    let child = Arc::new(Mutex::new(spawned?));

    let finished = CancelToken::new();
    let state = Arc::new(WatchState::default());
    let watcher: Option<JoinHandle<()>> = if timeout.is_some() || cancel.is_some() {
        let (child, finished, cancel, state) = (child.clone(), finished.clone(), cancel.cloned(), state.clone());
        Some(std::thread::spawn(move || watchdog(child, finished, cancel, timeout, state)))
    } else {
        None
    };

    let pumped = pump_lines(reader, log);
    if pumped.is_err() {
        stop_process(&child, false); // we cannot read its output any more; do not leave it running
    }
    let waited = wait_child(&child, watcher.is_some());
    finished.set();
    if let Some(w) = watcher {
        let _ = w.join();
    }
    pumped?;
    let code = exit_code(waited?);

    if state.canceled.load(Ordering::SeqCst) {
        return Err(Error::canceled());
    }
    if state.timed_out.load(Ordering::SeqCst) {
        let secs = timeout.map(secs_text).unwrap_or_default();
        log(&format!("Command timed out after {secs}s and was stopped: {program}"));
        if check {
            return Err(Error::runtime(format!("Command timed out after {secs}s: {joined}")));
        }
        return Ok(if code != 0 { code } else { -1 });
    }
    if check && code != 0 {
        return Err(Error::runtime(format!("Command failed (exit code {code}): {joined}")));
    }
    Ok(code)
}

/// `sync` on macOS and Linux. Windows has no such command: every file written there is flushed with `fsync`, and
/// the volume is flushed again when it is detached before the read-back. A failure to run `sync` is ignored.
pub fn sync_filesystems(log: Log) {
    if !IS_WINDOWS {
        let _ = run_cmd(&["sync"], log, false, None, None);
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The cancel flag file
// ---------------------------------------------------------------------------------------------------------------

/// The private flag file of `cancel_flag`: its path appears (as an empty file) when the token is set. The privileged
/// write script runs as root and polls for it. Dropping the guard stops the watcher and removes file and directory.
///
/// The privileged write script runs as root, so the app cannot signal it. Instead the script polls for this file and
/// stops `dd` itself. The file lives in a fresh 0700 directory owned by the user; the script only tests whether the
/// path exists.
pub struct CancelFlag {
    dir: PathBuf,
    path: PathBuf,
    stop: CancelToken,
    watcher: Option<JoinHandle<()>>,
}

impl CancelFlag {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for CancelFlag {
    fn drop(&mut self) {
        self.stop.set();
        if let Some(w) = self.watcher.take() {
            let _ = w.join(); // wakes within a quarter of a second
        }
        silent_remove(&self.path);
        silent_rmdir(&self.dir);
    }
}

/// `cancel_flag(cancel_event)`.
pub fn cancel_flag(cancel: Option<&CancelToken>) -> Result<CancelFlag> {
    // mkdtemp semantics: a fresh directory that only the owner can enter (tempfile's default would follow the umask).
    let mut builder = tempfile::Builder::new();
    builder.prefix("win11cancel_");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let dir = builder.tempdir()?.keep();
    let path = dir.join("cancel");
    let stop = CancelToken::new();
    let watcher = cancel.cloned().map(|token| {
        let (stop, path) = (stop.clone(), path.clone());
        std::thread::spawn(move || {
            while !stop.is_set() {
                if token.wait(Duration::from_millis(250)) {
                    let _ = std::fs::File::create(&path); // the script only tests that the path exists
                    return;
                }
            }
        })
    });
    Ok(CancelFlag { dir, path, stop, watcher })
}

// ---------------------------------------------------------------------------------------------------------------
// Keeping the computer awake
// ---------------------------------------------------------------------------------------------------------------

/// A sleep inhibitor child (caffeinate / systemd-inhibit) that is stopped when the guard is dropped.
struct Inhibitor {
    child: Mutex<Child>,
    pid: u32,
}

impl Drop for Inhibitor {
    fn drop(&mut self) {
        at_exit::unregister(self.pid);
        stop_process(&self.child, true); // own process group: stopping it also stops systemd-inhibit's `sleep`
    }
}

/// Keeps the machine awake while alive (caffeinate / systemd-inhibit / SetThreadExecutionState). Best effort.
///
/// On Windows `SetThreadExecutionState` belongs to the thread that called it: create the guard in the thread that
/// writes the drive (the worker thread does) and drop it there. Dropped from another thread it is a no-op and the
/// setting lasts until the creating thread ends. On macOS and Linux the guard can travel between threads.
pub struct SleepGuard {
    inhibitor: Option<Inhibitor>,
    #[cfg(windows)]
    keep_awake_thread: Option<std::thread::ThreadId>,
}

impl SleepGuard {
    /// True while something is really holding the machine awake (an inhibitor that did not exit at once, or the
    /// Windows execution state).
    pub fn is_holding(&self) -> bool {
        #[cfg(windows)]
        {
            if self.keep_awake_thread.is_some() {
                return true;
            }
        }
        self.inhibitor.is_some()
    }
}

#[cfg(windows)]
impl Drop for SleepGuard {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Power::{SetThreadExecutionState, ES_CONTINUOUS};
        if self.keep_awake_thread == Some(std::thread::current().id()) {
            // SAFETY: a plain Win32 call without pointers; ES_CONTINUOUS alone clears the flags set earlier.
            unsafe {
                SetThreadExecutionState(ES_CONTINUOUS);
            }
        }
    }
}

/// `prevent_sleep(log)`: hold the returned guard for the whole operation.
pub fn prevent_sleep(log: Log) -> SleepGuard {
    if IS_WINDOWS {
        return windows_keep_awake(log);
    }
    let cmd: Option<Vec<String>> = if IS_MAC && which("caffeinate").is_some() {
        // -i: no idle sleep; -w: stop by itself when our process exits.
        Some(vec!["caffeinate".into(), "-i".into(), "-w".into(), std::process::id().to_string()])
    } else if IS_LINUX && which("systemd-inhibit").is_some() {
        // A bounded sleep (not "infinity"): if the app is killed without cleanup, the inhibitor still ends by
        // itself instead of keeping the machine awake forever.
        Some(vec![
            "systemd-inhibit".into(),
            "--what=sleep:idle".into(),
            format!("--who={APP_NAME}"),
            "--why=Writing a USB drive".into(),
            "sleep".into(),
            SLEEP_INHIBIT_SECONDS.to_string(),
        ])
    } else {
        None
    };
    prevent_sleep_with(cmd.as_deref(), log)
}

/// The core of `prevent_sleep` with the inhibitor command given (`None`: nothing to run). The command is started in
/// its own process group and given `SLEEP_INHIBIT_CHECK_SECONDS` to prove it keeps running: one that exits at once
/// (no session bus, unsupported...) holds nothing and is not reported.
pub fn prevent_sleep_with(cmd: Option<&[String]>, log: Log) -> SleepGuard {
    let none = SleepGuard {
        inhibitor: None,
        #[cfg(windows)]
        keep_awake_thread: None,
    };
    let Some(cmd) = cmd.filter(|c| !c.is_empty()) else {
        return none;
    };
    let mut command = Command::new(&cmd[0]);
    command.args(&cmd[1..]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    // Own process group, so stopping it also stops systemd-inhibit's `sleep`.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    quiet(&mut command);
    let Ok(mut child) = command.spawn() else {
        return none; // OSError / SubprocessError: ignored
    };
    // proc.wait(timeout=SLEEP_INHIBIT_CHECK_SECONDS)
    let deadline = Instant::now() + Duration::from_secs_f64(SLEEP_INHIBIT_CHECK_SECONDS);
    loop {
        match child.try_wait() {
            Ok(None) => {}
            _ => return none, // it exited at once: nothing is held
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    // Still running after the check: the inhibitor is really holding. Make sure it is also stopped if the program
    // exits without leaving this scope (Python: atexit).
    let pid = child.id();
    at_exit::register(pid);
    log("Sleep is blocked while the drive is being written.");
    SleepGuard {
        inhibitor: Some(Inhibitor { child: Mutex::new(child), pid }),
        #[cfg(windows)]
        keep_awake_thread: None,
    }
}

#[cfg(windows)]
fn windows_keep_awake(log: Log) -> SleepGuard {
    use windows_sys::Win32::System::Power::{SetThreadExecutionState, ES_CONTINUOUS, ES_SYSTEM_REQUIRED};
    // SAFETY: a plain Win32 call without pointers.
    let previous = unsafe { SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED) };
    if previous != 0 {
        log("Sleep is blocked while the drive is being written.");
    }
    SleepGuard { inhibitor: None, keep_awake_thread: Some(std::thread::current().id()) }
}

#[cfg(not(windows))]
fn windows_keep_awake(_log: Log) -> SleepGuard {
    SleepGuard { inhibitor: None }
}

/// The Python `atexit.register(stopper)`: a process-wide list of inhibitor pids that a libc `atexit` hook stops when
/// the program ends without dropping its guard. (`std` has no exit hooks; on Windows nothing is registered.)
mod at_exit {
    #[cfg(unix)]
    mod imp {
        use std::sync::{Mutex, Once};
        static PIDS: Mutex<Vec<u32>> = Mutex::new(Vec::new());
        static HOOK: Once = Once::new();

        extern "C" fn stop_all() {
            // try_lock: never block (or deadlock) inside an exit handler.
            let Ok(pids) = PIDS.try_lock() else {
                return;
            };
            for &pid in pids.iter() {
                // SAFETY: signalling the process group that leads from `pid`, which was started with its own group
                // and is only listed while its guard is alive.
                unsafe {
                    let pgid = libc::getpgid(pid as libc::pid_t);
                    if pgid > 0 && pgid != libc::getpgrp() {
                        libc::killpg(pgid, libc::SIGTERM);
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        libc::killpg(pgid, libc::SIGKILL);
                    }
                }
            }
        }

        pub fn register(pid: u32) {
            HOOK.call_once(|| {
                // SAFETY: registering a plain `extern "C" fn()` that takes no arguments.
                unsafe {
                    libc::atexit(stop_all);
                }
            });
            PIDS.lock().unwrap_or_else(|e| e.into_inner()).push(pid);
        }

        pub fn unregister(pid: u32) {
            PIDS.lock().unwrap_or_else(|e| e.into_inner()).retain(|p| *p != pid);
        }
    }

    #[cfg(unix)]
    pub use imp::{register, unregister};

    #[cfg(not(unix))]
    pub fn register(_pid: u32) {}
    #[cfg(not(unix))]
    pub fn unregister(_pid: u32) {}
}

// ---------------------------------------------------------------------------------------------------------------
// platform_display_name
// ---------------------------------------------------------------------------------------------------------------

/// "macOS", "Windows 11" (build >= 22000) / "Windows 10", or the Linux distribution name.
pub fn platform_display_name() -> String {
    if IS_MAC {
        return "macOS".to_string();
    }
    if IS_WINDOWS {
        // Windows 11 still reports itself as major version 10: the build number tells them apart.
        let (major, minor, build) = windows_version().unwrap_or((0, 0, 0));
        return windows_display_name(major, minor, build);
    }
    if IS_LINUX {
        return linux_display_name();
    }
    // platform.system() for anything else
    let os = std::env::consts::OS;
    let mut chars = os.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// "Windows 11" from build 22000 on, else "Windows " + the release name (`platform.release()`).
pub fn windows_display_name(major: u32, minor: u32, build: u32) -> String {
    if build >= 22000 {
        return "Windows 11".to_string();
    }
    let release = match (major, minor) {
        (6, 3) => "8.1",
        (6, 2) => "8",
        (6, 1) => "7",
        (6, 0) => "Vista",
        _ => "10",
    };
    format!("Windows {release}")
}

/// `(major, minor, build)` out of text such as "Microsoft Windows [Version 10.0.22631.2861]" (the output of `ver`).
pub fn parse_windows_version(text: &str) -> Option<(u32, u32, u32)> {
    static RE: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"(\d+)\.(\d+)\.(\d+)").expect("a valid pattern"));
    let caps = RE.captures(text)?;
    Some((caps[1].parse().ok()?, caps[2].parse().ok()?, caps[3].parse().ok()?))
}

/// The Windows version, asked of `cmd /C ver` (the one source that needs no extra Win32 bindings and, unlike
/// `GetVersionEx`, does not lie to a program without a manifest).
#[cfg(windows)]
fn windows_version() -> Option<(u32, u32, u32)> {
    let mut cmd = Command::new("cmd");
    cmd.args(["/C", "ver"]).stderr(Stdio::null());
    quiet(&mut cmd);
    let out = cmd.output().ok()?;
    parse_windows_version(&String::from_utf8_lossy(&out.stdout))
}

#[cfg(not(windows))]
fn windows_version() -> Option<(u32, u32, u32)> {
    None
}

/// `platform.freedesktop_os_release()["PRETTY_NAME"]`, or "Linux" when it cannot be read.
fn linux_display_name() -> String {
    for file in ["/etc/os-release", "/usr/lib/os-release"] {
        if let Ok(bytes) = std::fs::read(file) {
            let text = String::from_utf8_lossy(&bytes);
            return parse_os_release(&text).remove("PRETTY_NAME").unwrap_or_else(|| "Linux".to_string());
        }
    }
    "Linux".to_string()
}

/// The `KEY=value` lines of an os-release file, with one level of quotes removed and the shell escapes
/// (`\$ \" \' \` \\`) resolved, as Python's `platform.freedesktop_os_release` does.
pub fn parse_os_release(text: &str) -> HashMap<String, String> {
    let mut info = HashMap::new();
    for line in text.lines() {
        let line = py_rstrip(line);
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let value = match value.chars().next() {
            Some(q @ ('"' | '\'')) if value.len() >= 2 && value.ends_with(q) => &value[1..value.len() - 1],
            _ => value,
        };
        let mut out = String::with_capacity(value.len());
        let mut chars = value.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(&next) = chars.peek() {
                    if matches!(next, '$' | '"' | '\'' | '`' | '\\') {
                        out.push(next);
                        chars.next();
                        continue;
                    }
                }
            }
            out.push(c);
        }
        info.insert(name.to_string(), out);
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn collect() -> (Arc<Mutex<Vec<String>>>, impl Fn(&str) + Send + Sync) {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let sink = lines.clone();
        (lines, move |l: &str| sink.lock().unwrap().push(l.to_string()))
    }

    fn lines_of(lines: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
        lines.lock().unwrap().clone()
    }

    // ---- check_canceled ----
    #[test]
    fn check_canceled_passes_the_state_on() {
        let token = CancelToken::new();
        assert!(check_canceled(Some(&token), false, false).is_ok());
        assert!(check_canceled(None, true, true).is_ok());
        token.set();
        let err = check_canceled(Some(&token), false, false).unwrap_err();
        assert!(err.is_canceled());
        assert!(!err.drive_touched());
        assert!(!err.written());
        let err = check_canceled(Some(&token), true, true).unwrap_err();
        assert!(err.drive_touched() && err.written());
        assert_eq!(err.to_string(), "Canceled by the user.");
    }

    // ---- the line reader ----
    #[test]
    fn lines_end_at_newline_carriage_return_or_both() {
        let (lines, log) = collect();
        pump_lines(&b"one\ntwo\r\nthree\rfour  \n\nlast"[..], &log).unwrap();
        assert_eq!(lines_of(&lines), vec!["one", "two", "three", "four", "", "last"]);
    }

    #[test]
    fn a_crlf_split_across_reads_is_one_line_break() {
        struct Pieces(Vec<&'static [u8]>);
        impl Read for Pieces {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0.is_empty() {
                    return Ok(0);
                }
                let piece = self.0.remove(0);
                buf[..piece.len()].copy_from_slice(piece);
                Ok(piece.len())
            }
        }
        let (lines, log) = collect();
        pump_lines(Pieces(vec![b"a\r", b"\nb\r", b"c"]), &log).unwrap();
        assert_eq!(lines_of(&lines), vec!["a", "b", "c"]);
    }

    #[test]
    fn invalid_utf8_is_replaced_not_fatal() {
        let (lines, log) = collect();
        pump_lines(&b"caf\xe9 file.txt\n"[..], &log).unwrap();
        assert_eq!(lines_of(&lines), vec!["caf\u{fffd} file.txt"]);
    }

    // ---- run_cmd (unix: /bin/sh is the portable test program) ----
    #[cfg(unix)]
    fn sh(script: &str) -> Vec<String> {
        vec!["sh".to_string(), "-c".to_string(), script.to_string()]
    }

    #[cfg(unix)]
    #[test]
    fn run_cmd_logs_the_command_and_streams_output_with_stderr_merged() {
        let (lines, log) = collect();
        let args = sh("echo out; echo err >&2; exit 0");
        assert_eq!(run_cmd(&args, &log, true, None, None).unwrap(), 0);
        let got = lines_of(&lines);
        assert_eq!(got[0], "$ sh -c echo out; echo err >&2; exit 0");
        assert!(got.contains(&"out".to_string()) && got.contains(&"err".to_string()), "{got:?}");
    }

    #[cfg(unix)]
    #[test]
    fn run_cmd_non_zero_exit_is_an_error_only_with_check() {
        let (_l, log) = collect();
        let args = sh("exit 3");
        let err = run_cmd(&args, &log, true, None, None).unwrap_err();
        assert!(err.to_string().starts_with("Command failed (exit code 3): sh -c exit 3"), "{err}");
        assert!(matches!(err, Error::Runtime(_)));
        assert_eq!(run_cmd(&args, &log, false, None, None).unwrap(), 3);
    }

    #[cfg(unix)]
    #[test]
    fn run_cmd_a_missing_program_is_an_io_error() {
        let (_l, log) = collect();
        assert!(matches!(run_cmd(&["definitely-not-a-program-xyz"], &log, true, None, None), Err(Error::Io(_))));
    }

    #[test]
    fn run_cmd_without_arguments_is_refused() {
        let (_l, log) = collect();
        assert!(matches!(run_cmd::<&str>(&[], &log, true, None, None), Err(Error::Value(_))));
    }

    #[cfg(unix)]
    #[test]
    fn run_cmd_output_that_is_not_utf8_does_not_abort() {
        let (lines, log) = collect();
        run_cmd(&sh("printf 'caf\\351 file.txt\\n'"), &log, true, None, None).unwrap();
        assert!(lines_of(&lines).contains(&"caf\u{fffd} file.txt".to_string()), "{:?}", lines_of(&lines));
    }

    #[cfg(unix)]
    #[test]
    fn run_cmd_kills_a_command_that_exceeds_its_timeout() {
        let (lines, log) = collect();
        let started = Instant::now();
        let args = sh("sleep 30");
        let err = run_cmd(&args, &log, true, Some(Duration::from_millis(300)), None).unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(err.to_string().starts_with("Command timed out after 0.3s: sh -c sleep 30"), "{err}");
        assert!(lines_of(&lines).iter().any(|l| l.starts_with("Command timed out after 0.3s and was stopped: sh")));
        // without `check` the code comes back (SIGTERM: -15)
        let code = run_cmd(&args, &log, false, Some(Duration::from_millis(300)), None).unwrap();
        assert_ne!(code, 0);
    }

    #[cfg(unix)]
    #[test]
    fn run_cmd_stops_promptly_on_cancel() {
        let (_l, log) = collect();
        let token = CancelToken::new();
        let t = token.clone();
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            t.set();
        });
        let started = Instant::now();
        let err = run_cmd(&sh("sleep 30"), &log, true, None, Some(&token)).unwrap_err();
        canceller.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(err.is_canceled());
        assert!(err.drive_touched() && !err.written()); // OperationCanceled("Canceled by the user.") defaults
    }

    #[cfg(unix)]
    #[test]
    fn run_cmd_with_a_cancel_token_that_never_fires_runs_normally() {
        let (lines, log) = collect();
        let token = CancelToken::new();
        assert_eq!(run_cmd(&sh("echo hi"), &log, true, Some(Duration::from_secs(30)), Some(&token)).unwrap(), 0);
        assert!(lines_of(&lines).contains(&"hi".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn a_command_killed_by_a_signal_reports_the_negative_signal_number() {
        let (_l, log) = collect();
        assert_eq!(run_cmd(&sh("kill -9 $$"), &log, false, None, None).unwrap(), -9);
    }

    #[cfg(unix)]
    #[test]
    fn run_cmd_calls_the_log_from_the_calling_thread() {
        let main = std::thread::current().id();
        let wrong = AtomicUsize::new(0);
        let log = |_l: &str| {
            if std::thread::current().id() != main {
                wrong.fetch_add(1, Ordering::SeqCst);
            }
        };
        run_cmd(&sh("echo a; echo b"), &log, true, Some(Duration::from_secs(30)), None).unwrap();
        assert_eq!(wrong.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn sync_filesystems_runs_without_failing() {
        let (_l, log) = collect();
        sync_filesystems(&log);
    }

    // ---- cancel_flag ----
    #[test]
    fn the_flag_file_appears_only_when_the_token_is_set() {
        let token = CancelToken::new();
        let flag = cancel_flag(Some(&token)).unwrap();
        let path = flag.path().to_path_buf();
        assert!(path.parent().unwrap().is_dir());
        assert!(path.file_name().unwrap() == "cancel");
        std::thread::sleep(Duration::from_millis(400));
        assert!(!path.exists());
        token.set();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !path.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(path.exists(), "the flag file never appeared");
        let dir = path.parent().unwrap().to_path_buf();
        drop(flag);
        assert!(!path.exists() && !dir.exists(), "file and directory are removed with the guard");
    }

    #[cfg(unix)]
    #[test]
    fn the_flag_directory_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let flag = cancel_flag(None).unwrap();
        let mode = std::fs::metadata(flag.path().parent().unwrap()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn a_flag_without_a_token_never_appears() {
        let flag = cancel_flag(None).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert!(!flag.path().exists());
    }

    // ---- sleep inhibition ----
    #[test]
    fn nothing_to_run_holds_nothing() {
        let (lines, log) = collect();
        let guard = prevent_sleep_with(None, &log);
        assert!(!guard.is_holding());
        assert!(lines_of(&lines).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_running_inhibitor_is_reported_held_and_stopped_with_its_group() {
        let (lines, log) = collect();
        let cmd = vec!["sh".to_string(), "-c".to_string(), "sleep 30 & wait".to_string()];
        let guard = prevent_sleep_with(Some(&cmd), &log);
        assert!(guard.is_holding());
        assert_eq!(lines_of(&lines), vec!["Sleep is blocked while the drive is being written."]);
        let pid = guard.inhibitor.as_ref().unwrap().pid as libc::pid_t;
        // the child leads its own process group (so the whole group can be stopped)
        assert_eq!(unsafe { libc::getpgid(pid) }, pid);
        drop(guard);
        // reaped by the guard: the pid is gone (or at least no longer ours)
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        // and the grandchild `sleep` died with the group: nothing of the group is left
        assert_eq!(unsafe { libc::killpg(pid, 0) }, -1);
    }

    #[cfg(unix)]
    #[test]
    fn an_inhibitor_that_exits_at_once_is_not_reported_as_blocking() {
        let (lines, log) = collect();
        let cmd = vec!["sh".to_string(), "-c".to_string(), "exit 1".to_string()];
        let guard = prevent_sleep_with(Some(&cmd), &log);
        assert!(!guard.is_holding());
        assert!(lines_of(&lines).is_empty());
        // a command that cannot even start is ignored too
        let missing = vec!["definitely-not-a-program-xyz".to_string()];
        assert!(!prevent_sleep_with(Some(&missing), &log).is_holding());
    }

    #[test]
    fn the_inhibitor_sleep_is_bounded() {
        assert_eq!(SLEEP_INHIBIT_SECONDS, 12 * 3600);
        const { assert!(SLEEP_INHIBIT_CHECK_SECONDS > 0.0) };
    }

    #[test]
    fn prevent_sleep_never_panics_here() {
        let (_l, log) = collect();
        drop(prevent_sleep(&log));
    }

    // ---- platform_display_name ----
    #[test]
    fn windows_names() {
        assert_eq!(windows_display_name(10, 0, 22000), "Windows 11");
        assert_eq!(windows_display_name(10, 0, 22631), "Windows 11");
        assert_eq!(windows_display_name(10, 0, 21999), "Windows 10");
        assert_eq!(windows_display_name(10, 0, 19045), "Windows 10");
        assert_eq!(windows_display_name(6, 3, 9600), "Windows 8.1");
        assert_eq!(windows_display_name(6, 1, 7601), "Windows 7");
        assert_eq!(windows_display_name(0, 0, 0), "Windows 10"); // unreadable: the Python falls back to build 0
    }

    #[test]
    fn windows_ver_output_is_parsed() {
        assert_eq!(parse_windows_version("\r\nMicrosoft Windows [Version 10.0.22631.2861]\r\n"), Some((10, 0, 22631)));
        assert_eq!(parse_windows_version("Microsoft Windows [Versão 10.0.19045.3693]"), Some((10, 0, 19045)));
        assert_eq!(parse_windows_version("nothing here"), None);
    }

    #[test]
    fn os_release_is_parsed_like_python() {
        let text = "NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n# comment\nID=ubuntu\nVERSION='x \\\"y\\\"'\nBAD LINE\nQ=\"unterminated\n";
        let info = parse_os_release(text);
        assert_eq!(info["PRETTY_NAME"], "Ubuntu 24.04.1 LTS");
        assert_eq!(info["ID"], "ubuntu");
        assert_eq!(info["VERSION"], "x \"y\"");
        assert_eq!(info["Q"], "\"unterminated");
        assert!(!info.contains_key("BAD LINE"));
    }

    #[test]
    fn the_display_name_is_never_empty() {
        let name = platform_display_name();
        assert!(!name.is_empty());
        if IS_MAC {
            assert_eq!(name, "macOS");
        }
    }
}
