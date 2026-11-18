//! Privilege helpers. OWNER: A2. Port of win11_usb_creator.py lines 1886-2135 (sudo refresh + PrivilegeHelper),
//! 12191-12264 (CliPrivilege, WindowsCliPrivilege) and 3103-3128 (WindowsPrivilege).
//!
//! The password dialog is NOT here: `PrivilegeHelper` asks through the `PasswordPrompt` trait (types.rs), which the
//! window implements (its `ask_password` blocks the worker thread until the user answers).
//!
//! Everything that touches the system (is this process root, is `sudo` installed, run a command) goes through the
//! small `SudoSys` trait. `RealSys` is the real thing (`std::process`); the tests inject a fake, exactly as the
//! Python tests patch `os.geteuid`, `shutil.which` and `subprocess`.
//!
//! Security properties (they are the spec): the sudo password reaches a process only on its stdin, never in an
//! argument list and never in a log; a privileged script that fails is NEVER run again; values reach scripts only
//! as positional parameters (`"$1"`...), never pasted into the script text.

use crate::audit::AuditLevel;
use crate::constants::{SUDO_KEEPALIVE_MAX_SECONDS, SUDO_KEEPALIVE_SECONDS, SUDO_TIMEOUT};
use crate::diskrisk::py_repr;
use crate::engine::{audit_event, which_tool};
use crate::i18n::{tr, tr_fmt};
use crate::types::{CancelToken, Error, Log, PasswordPrompt, Privilege, Result};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------------------------------------------
// The system calls the helpers make
// ---------------------------------------------------------------------------------------------------------------

/// What the child's stdin is connected to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StdinMode<'a> {
    /// `/dev/null` (`stdin=subprocess.DEVNULL`).
    Null,
    /// The terminal of this process (the child may prompt there).
    Inherit,
    /// A pipe: this exact text is written (it is the password plus a newline), then the pipe is closed.
    Text(&'a str),
}

/// The calls `PrivilegeHelper` and `CliPrivilege` make into the operating system.
pub trait SudoSys: Send + Sync {
    /// `os.geteuid() == 0`.
    fn is_root(&self) -> bool;
    /// `shutil.which(tool)`: whether `tool` is found on PATH.
    fn which(&self, tool: &str) -> bool;
    /// `subprocess.run(argv, input=..., capture_output=True, timeout=...)`: the exit code, or `None` when the
    /// command could not be started or ran out of time (the Python `except (OSError, SubprocessError)`).
    fn run_quiet(&self, argv: &[&str], input: Option<&str>, timeout: Duration) -> Option<i32>;
    /// `subprocess.call(argv)`: stdio inherited, so the command prompts on the terminal.
    fn call_inherit(&self, argv: &[&str]) -> Result<i32>;
    /// `subprocess.Popen(argv, stdout=PIPE, stderr=STDOUT, text=True, errors="replace")`: start the command, write
    /// the stdin text (if any), call `on_start`, then pass every output line (trailing blanks removed) to `on_line`
    /// until the command ends. Returns its exit code. Lines end at `\n`, `\r\n` or a lone `\r` (universal newlines).
    fn run_streaming(
        &self,
        argv: &[String],
        stdin: StdinMode,
        on_start: &mut dyn FnMut(),
        on_line: &mut dyn FnMut(&str),
    ) -> Result<i32>;
    /// `run_cmd(argv, log)` (check=True): used for the `pkexec` path.
    fn run_logged(&self, argv: &[String], log: Log) -> Result<()>;
}

/// The real system.
#[derive(Clone, Copy, Debug, Default)]
pub struct RealSys;

/// `os.geteuid() == 0` (always false where there is no such thing).
fn euid_is_root() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

impl SudoSys for RealSys {
    fn is_root(&self) -> bool {
        euid_is_root()
    }

    fn which(&self, tool: &str) -> bool {
        which_tool(tool).is_some()
    }

    fn run_quiet(&self, argv: &[&str], input: Option<&str>, timeout: Duration) -> Option<i32> {
        let (program, rest) = argv.split_first()?;
        let mut cmd = Command::new(program);
        cmd.args(rest)
            .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = cmd.spawn().ok()?;
        if let Some(text) = input {
            if let Some(mut stdin) = child.stdin.take() {
                // A closed pipe (the command did not read its stdin) is not an error here.
                let _ = stdin.write_all(text.as_bytes());
                // Dropping `stdin` closes the pipe: the command sees end of input.
            }
        }
        let deadline = Instant::now() + timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Some(status.code().unwrap_or(-1)),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => return None,
            }
        }
    }

    fn call_inherit(&self, argv: &[&str]) -> Result<i32> {
        let (program, rest) = argv.split_first().ok_or_else(|| Error::runtime("empty command"))?;
        let status = Command::new(program).args(rest).status()?;
        Ok(status.code().unwrap_or(-1))
    }

    fn run_streaming(
        &self,
        argv: &[String],
        stdin: StdinMode,
        on_start: &mut dyn FnMut(),
        on_line: &mut dyn FnMut(&str),
    ) -> Result<i32> {
        let (program, rest) = argv.split_first().ok_or_else(|| Error::runtime("empty command"))?;
        // stdout and stderr share one pipe (`stderr=subprocess.STDOUT`), so the lines arrive in order.
        let (reader, writer) = std::io::pipe()?;
        let writer_err = writer.try_clone()?;
        let mut cmd = Command::new(program);
        cmd.args(rest).stdout(writer).stderr(writer_err);
        cmd.stdin(match stdin {
            StdinMode::Null => Stdio::null(),
            StdinMode::Inherit => Stdio::inherit(),
            StdinMode::Text(_) => Stdio::piped(),
        });
        let mut child = cmd.spawn()?;
        // `cmd` still owns the write ends of the pipe: drop it so the reader sees end of file when the child exits.
        drop(cmd);
        if let StdinMode::Text(text) = stdin {
            if let Some(mut pipe) = child.stdin.take() {
                // The password goes only to stdin: it never appears in the process argument list (visible to other
                // users via `ps`) nor in any log.
                let _ = pipe.write_all(text.as_bytes());
                let _ = pipe.flush();
            }
        }
        on_start();
        read_lines(reader, on_line);
        let status = child.wait()?;
        Ok(status.code().unwrap_or(-1))
    }

    fn run_logged(&self, argv: &[String], log: Log) -> Result<()> {
        crate::proc::run_cmd(argv, log, true, None, None).map(|_| ())
    }
}

/// Feed `f` the lines of `reader` with Python's universal-newline splitting and lossy UTF-8 decoding.
fn read_lines(mut reader: impl Read, f: &mut dyn FnMut(&str)) {
    fn emit(line: &mut Vec<u8>, f: &mut dyn FnMut(&str)) {
        f(String::from_utf8_lossy(line).trim_end());
        line.clear();
    }
    let mut line: Vec<u8> = Vec::new();
    let mut skip_lf = false;
    let mut buf = [0u8; 8192];
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        for &b in &buf[..n] {
            if skip_lf {
                skip_lf = false;
                if b == b'\n' {
                    continue;
                }
            }
            match b {
                b'\n' => emit(&mut line, f),
                b'\r' => {
                    emit(&mut line, f);
                    skip_lf = true;
                }
                _ => line.push(b),
            }
        }
    }
    if !line.is_empty() {
        emit(&mut line, f);
    }
}

// ---------------------------------------------------------------------------------------------------------------
// sudo's timestamp keep-alive
// ---------------------------------------------------------------------------------------------------------------

fn query_timeout() -> Duration {
    Duration::from_secs(SUDO_TIMEOUT)
}

/// True if sudo accepts us without a password right now (`sudo -n -v`), which also renews its credential
/// timestamp. Never fails (`_sudo_refresh`).
pub fn sudo_refresh() -> bool {
    sudo_refresh_with(&RealSys)
}

/// `_sudo_refresh` against any `SudoSys`.
pub fn sudo_refresh_with(sys: &dyn SudoSys) -> bool {
    sys.run_quiet(&["sudo", "-n", "-v"], None, query_timeout()) == Some(0)
}

/// Keep sudo's credential timestamp alive while an operation runs (the thread body of both privilege helpers):
/// call `refresh` every `interval` until `stop` is set, or until `max` has passed (None: no limit).
/// `clock` is the monotonic clock in seconds (injected so the tests do not depend on the machine's speed).
pub fn sudo_refresh_loop(
    stop: &CancelToken,
    max: Option<Duration>,
    interval: Duration,
    refresh: &dyn Fn() -> bool,
    clock: &dyn Fn() -> f64,
) {
    let deadline = max.map(|m| clock() + m.as_secs_f64());
    while !stop.wait(interval) && deadline.is_none_or(|d| clock() < d) {
        refresh();
    }
}

fn monotonic_seconds() -> f64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_secs_f64()
}

/// Start the keep-alive thread: refreshes sudo's timestamp every SUDO_KEEPALIVE_SECONDS until `stop` is set.
fn spawn_keepalive(sys: Arc<dyn SudoSys>, stop: CancelToken, max: Option<Duration>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        sudo_refresh_loop(
            &stop,
            max,
            Duration::from_secs(SUDO_KEEPALIVE_SECONDS),
            &|| sudo_refresh_with(&*sys),
            &monotonic_seconds,
        )
    })
}

fn script_log_line(prefix: &str, args: &[String]) -> String {
    let shown: Vec<String> = args.iter().map(|a| py_repr(a)).collect();
    format!("{prefix}bash -c '<privileged script>' {}", shown.join(" "))
}

/// `bash -c SCRIPT NAME ARG1 ARG2 ...` -> inside SCRIPT: `$0`=NAME, `$1`=ARG1, ...
fn bash_argv(script: &str, args: &[String]) -> Vec<String> {
    let mut argv: Vec<String> = vec!["bash".into(), "-c".into(), script.into(), "win11_usb_creator".into()];
    argv.extend(args.iter().cloned());
    argv
}

// ---------------------------------------------------------------------------------------------------------------
// The window's helper
// ---------------------------------------------------------------------------------------------------------------

/// How scripts are authorised once the password has been validated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthMode {
    /// sudo's own timestamp carries the authorisation (`sudo -n`, nothing on stdin).
    Timestamp,
    /// The validated password is held in memory and passed on stdin.
    Password,
}

struct HelperState {
    /// Only set in the stdin fallback mode.
    cached_password: Option<String>,
    /// True: sudo's timestamp is armed, no password held.
    use_timestamp: bool,
    keepalive_stop: Option<CancelToken>,
}

/// Runs privileged scripts through sudo (or pkexec), asking for the password once.
///
/// After the password is validated, sudo's own timestamp carries the authorization: scripts run with `sudo -n`
/// (nothing on stdin) and a small keep-alive refreshes the timestamp while an operation runs, so the password is not
/// held in memory for the whole write. If that does not work on this machine (for example `timestamp_timeout=0` or
/// per-process tickets), the helper falls back to keeping the validated password and passing it on stdin. In every
/// mode a script that fails is NEVER run again.
pub struct PrivilegeHelper {
    prompt: Arc<dyn PasswordPrompt>,
    sys: Arc<dyn SudoSys>,
    state: Mutex<HelperState>,
}

const ATTEMPTS: u32 = 3;

impl PrivilegeHelper {
    pub fn new(prompt: Arc<dyn PasswordPrompt>) -> Self {
        Self::with_sys(prompt, Arc::new(RealSys))
    }

    /// Like `new`, with the system calls replaced (tests).
    pub fn with_sys(prompt: Arc<dyn PasswordPrompt>, sys: Arc<dyn SudoSys>) -> Self {
        PrivilegeHelper {
            prompt,
            sys,
            state: Mutex::new(HelperState { cached_password: None, use_timestamp: false, keepalive_stop: None }),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, HelperState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether a validated password is being held in memory (the stdin fallback mode).
    pub fn has_cached_password(&self) -> bool {
        self.state().cached_password.is_some()
    }

    /// Whether sudo's timestamp carries the authorization (no password held).
    pub fn uses_timestamp(&self) -> bool {
        self.state().use_timestamp
    }

    /// True if `password` is accepted by sudo. Never fails, never logs the password.
    ///
    /// `-k` makes sudo ignore any cached credential, so a wrong password cannot slip through because a previous
    /// sudo session is still valid. The password goes to stdin only, as in `run_script`.
    pub fn check_password(&self, password: &str) -> bool {
        if password.is_empty() {
            return false;
        }
        let input = format!("{password}\n");
        self.sys.run_quiet(&["sudo", "-S", "-k", "-p", "", "true"], Some(&input), query_timeout()) == Some(0)
    }

    /// True if sudo currently accepts us without a password (and refreshes its timestamp).
    fn sudo_probe(&self) -> bool {
        sudo_refresh_with(&*self.sys)
    }

    /// Validate with `sudo -S -v`, then confirm a fresh `sudo -n` process is accepted.
    ///
    /// The second step is what proves the timestamp is shared between our sudo calls on this machine; if it is not,
    /// the caller falls back to the stdin mode.
    fn arm_timestamp(&self, password: &str) -> bool {
        let input = format!("{password}\n");
        let accepted = self.sys.run_quiet(&["sudo", "-S", "-v", "-p", ""], Some(&input), query_timeout()) == Some(0);
        accepted && self.sudo_probe()
    }

    fn start_keepalive(&self) {
        self.stop_keepalive();
        let stop = CancelToken::new();
        self.state().keepalive_stop = Some(stop.clone());
        // The thread is detached: it ends when `stop` is set or after SUDO_KEEPALIVE_MAX_SECONDS, whatever happens.
        spawn_keepalive(self.sys.clone(), stop, Some(Duration::from_secs(SUDO_KEEPALIVE_MAX_SECONDS)));
    }

    fn stop_keepalive(&self) {
        let stop = self.state().keepalive_stop.take();
        if let Some(stop) = stop {
            stop.set();
        }
    }

    /// Take a validated password: arm sudo's timestamp and drop the string if that works.
    fn adopt(&self, secret: String) {
        if self.arm_timestamp(&secret) {
            {
                let mut st = self.state();
                st.use_timestamp = true;
                st.cached_password = None;
            }
            self.start_keepalive();
        } else {
            let mut st = self.state();
            st.use_timestamp = false;
            st.cached_password = Some(secret);
        }
    }

    /// Make sure scripts can run: sudo's timestamp, or the stdin fallback.
    ///
    /// Passwords are validated here, BEFORE any script runs, so a wrong password is never discovered by re-running a
    /// script. Asks at most `max_attempts` times.
    fn ensure_auth(&self, max_attempts: u32) -> Result<AuthMode> {
        if self.uses_timestamp() {
            if self.sudo_probe() {
                return Ok(AuthMode::Timestamp);
            }
            self.state().use_timestamp = false; // expired or revoked: ask again
            self.stop_keepalive();
        }
        if self.has_cached_password() {
            return Ok(AuthMode::Password);
        }
        for attempt in 0..max_attempts {
            let prefix = if attempt > 0 { tr("That password was not accepted. Try again.\n\n") } else { String::new() };
            let message = prefix
                + &tr("Enter your sudo/administrator password to partition and format the drive.\n\
                       It is used only to run local disk commands and is never stored or sent anywhere.");
            // The window shows the dialog on its own thread; this (worker) thread waits for the answer.
            let Some(entered) = self.prompt.ask_password(&tr("Administrator password"), &message) else {
                return Err(Error::runtime("Administrator password entry canceled."));
            };
            if self.check_password(&entered) {
                self.adopt(entered);
                return Ok(if self.uses_timestamp() { AuthMode::Timestamp } else { AuthMode::Password });
            }
        }
        Err(Error::runtime(format!(
            "The administrator password was not accepted after {max_attempts} attempts. Nothing was changed."
        )))
    }

    /// Ask for the administrator password up front and verify it. GUI thread only.
    ///
    /// Doing this before anything touches the drive means a wrong or missing password is caught while the drive is
    /// still untouched, instead of mid-operation. Returns true when privileges are available (sudo's timestamp is
    /// armed, or as a fallback the password is kept in memory for this operation).
    pub fn authenticate_with_attempts(&self, reason: &str, max_attempts: u32) -> bool {
        if !self.needs_password() {
            return true; // already root, or pkexec will show its own prompt
        }
        for attempt in 0..max_attempts {
            let message = tr_fmt(
                "{reason}\n\nEnter your administrator (sudo) password.\nIt is used only to run local disk commands and is never stored or sent anywhere.",
                &[("reason", &reason)],
            );
            let Some(pw) = self.prompt.ask_password(&tr("Administrator password"), &message) else {
                return false; // canceled
            };
            if self.check_password(&pw) {
                self.adopt(pw); // the string is not needed any more once adopted
                return true;
            }
            if attempt + 1 < max_attempts {
                self.prompt.show_error(&tr("Wrong password"), &tr("That password was not accepted. Please try again."));
            }
        }
        self.prompt.show_error(&tr("Wrong password"), &tr("Too many incorrect attempts. Nothing was changed."));
        false
    }

    /// `run_script` with the number of password prompts spelled out (`max_attempts` limits only the prompts).
    pub fn run_script_with_attempts(&self, script: &str, log: Log, args: &[String], max_attempts: u32) -> Result<()> {
        let argv = bash_argv(script, args);

        let mut sudo_prefix: Vec<String> = Vec::new();
        let mut use_stdin = false; // already root: no sudo
        if self.sys.is_root() {
        } else if self.sys.which("sudo") {
            use_stdin = self.ensure_auth(max_attempts)? != AuthMode::Timestamp;
            sudo_prefix = vec!["sudo".into(), "-n".into()]; // used unless the stdin fallback is needed
        } else if self.sys.which("pkexec") {
            let mut full = vec!["pkexec".to_string()];
            full.extend(argv);
            return self.sys.run_logged(&full, log);
        } else {
            return Err(Error::runtime(
                "Neither 'sudo' nor 'pkexec' was found. Install sudo (or run this app as root) \
                 so it can partition and format drives.",
            ));
        }

        let password = if use_stdin { self.state().cached_password.clone() } else { None };
        if use_stdin && password.is_none() {
            return Err(Error::runtime(
                "The administrator session ended before the command started. \
                 Nothing was changed; start the operation again.",
            ));
        }
        let (full, stdin_text) = match &password {
            Some(pw) => {
                let mut full: Vec<String> = vec!["sudo".into(), "-S".into(), "-p".into(), String::new()];
                full.extend(argv);
                (full, Some(format!("{pw}\n")))
            }
            None => {
                let mut full = sudo_prefix;
                full.extend(argv);
                (full, None)
            }
        };
        drop(password);

        let mut refused = false;
        let exit = {
            let stdin = match &stdin_text {
                Some(text) => StdinMode::Text(text),
                None => StdinMode::Null,
            };
            self.sys.run_streaming(&full, stdin, &mut || log(&script_log_line("$ sudo ", args)), &mut |line| {
                if line.contains("a password is required") && line.starts_with("sudo:") {
                    refused = true;
                }
                log(line);
            })?
        };
        if exit == 0 {
            return Ok(());
        }
        audit_event(&format!("Privileged script failed (exit {exit}); not retried"), AuditLevel::Error);
        if refused {
            self.state().use_timestamp = false;
            return Err(Error::runtime(
                "The administrator session expired before the command started, so it did not \
                 run and nothing was changed. Start the operation again.",
            ));
        }
        Err(Error::runtime(format!(
            "Privileged command failed (exit code {exit}). It was not run again; \
             check the log above for the reason."
        )))
    }
}

impl Drop for PrivilegeHelper {
    /// The keep-alive thread must not outlive the helper that started it (the sudo session itself is ended by
    /// `clear_cached_password`, which the callers run at the end of the operation).
    fn drop(&mut self) {
        self.stop_keepalive();
    }
}

impl Privilege for PrivilegeHelper {
    /// Run `script` with root privileges, exactly once. Values are NEVER interpolated into the script text: they
    /// are passed as positional shell parameters (`"$1"`, `"$2"`...) via `args`, so a filename containing quotes,
    /// semicolons or `$(...)` is treated as data, not as code.
    ///
    /// A script that exits non-zero is an error and is never re-run: a failed mkfs or dd must not be repeated
    /// behind the user's back. Password problems are handled before the script starts (`ensure_auth`).
    fn run_script(&self, script: &str, log: Log, args: &[String]) -> Result<()> {
        self.run_script_with_attempts(script, log, args, ATTEMPTS)
    }

    /// Whether a sudo password must be collected before running privileged commands.
    fn needs_password(&self) -> bool {
        !self.sys.is_root() && self.sys.which("sudo")
    }

    fn authenticate(&self, reason: &str) -> Result<bool> {
        Ok(self.authenticate_with_attempts(reason, ATTEMPTS))
    }

    /// Forget the password and end the sudo session as soon as it is no longer needed.
    fn clear_cached_password(&self) {
        self.state().cached_password = None;
        self.stop_keepalive();
        let was_armed = std::mem::replace(&mut self.state().use_timestamp, false);
        if was_armed {
            let _ = self.sys.run_quiet(&["sudo", "-k"], None, Duration::from_secs(10));
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The command line's helper
// ---------------------------------------------------------------------------------------------------------------

/// The command line's helper: sudo asks on the controlling terminal, scripts run once and are never retried.
///
/// Unlike the window's `PrivilegeHelper` it never handles the administrator credential itself.
pub struct CliPrivilege {
    sys: Arc<dyn SudoSys>,
    stop: CancelToken,
    keepalive: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Default for CliPrivilege {
    fn default() -> Self {
        Self::new()
    }
}

impl CliPrivilege {
    pub fn new() -> Self {
        Self::with_sys(Arc::new(RealSys))
    }

    /// Like `new`, with the system calls replaced (tests).
    pub fn with_sys(sys: Arc<dyn SudoSys>) -> Self {
        CliPrivilege { sys, stop: CancelToken::new(), keepalive: Mutex::new(None) }
    }

    pub fn is_root() -> bool {
        euid_is_root()
    }

    /// Writing and verifying a large image can outlast sudo's credential cache: refresh it in the background.
    fn start_keepalive(&self) {
        let mut slot = self.keepalive.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_some() {
            return;
        }
        *slot = Some(spawn_keepalive(self.sys.clone(), self.stop.clone(), None));
    }

    /// Whether the keep-alive thread is running (tests).
    pub fn keepalive_running(&self) -> bool {
        let slot = self.keepalive.lock().unwrap_or_else(|e| e.into_inner());
        slot.as_ref().is_some_and(|h| !h.is_finished())
    }

    /// Wait for the keep-alive thread to end after `clear_cached_password` (tests).
    pub fn join_keepalive(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while self.keepalive_running() {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        true
    }
}

impl Drop for CliPrivilege {
    fn drop(&mut self) {
        self.stop.set();
    }
}

impl Privilege for CliPrivilege {
    /// Run `script` as root once. Values arrive only as `"$1"`.. arguments.
    fn run_script(&self, script: &str, log: Log, args: &[String]) -> Result<()> {
        let root = self.sys.is_root();
        let mut argv = bash_argv(script, args);
        if !root {
            argv.insert(0, "sudo".to_string());
        }
        log(&script_log_line(if root { "$ " } else { "$ sudo " }, args));
        // stdin is inherited: sudo prompts on the terminal.
        let exit = self.sys.run_streaming(&argv, StdinMode::Inherit, &mut || {}, &mut |line| log(line))?;
        if exit != 0 {
            audit_event(&format!("Privileged script failed (exit {exit})"), AuditLevel::Error);
            return Err(Error::runtime(format!(
                "Privileged command failed (exit code {exit}). Check the messages above."
            )));
        }
        Ok(())
    }

    /// Ask sudo for credentials up front, before anything touches the drive. `Err` when sudo is missing or
    /// refuses (the command line prints the message); `Ok(true)` otherwise.
    fn authenticate(&self, _reason: &str) -> Result<bool> {
        if self.sys.is_root() {
            return Ok(true);
        }
        if !self.sys.which("sudo") {
            return Err(Error::runtime(
                "Administrator privileges are required but 'sudo' was not found. \
                 Run this command as root or install sudo.",
            ));
        }
        // stdin/stdout/stderr are inherited, so sudo prompts on the terminal.
        if self.sys.call_inherit(&["sudo", "-v"])? != 0 {
            return Err(Error::runtime(
                "Could not obtain administrator privileges (sudo refused). Nothing was changed.",
            ));
        }
        self.start_keepalive();
        Ok(true)
    }

    /// `self.cached_password` is always None here: sudo owns the credential. Only the keep-alive ends.
    fn clear_cached_password(&self) {
        self.stop.set();
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------------------------------------------

/// `WindowsPrivilege.authenticate`: the process is already elevated or it is not; never prompts.
pub fn windows_authenticate(is_admin: bool) -> bool {
    is_admin
}

/// `WindowsCliPrivilege.authenticate`: the terminal itself must have been opened as Administrator.
pub fn windows_cli_authenticate(is_admin: bool) -> Result<bool> {
    if !is_admin {
        return Err(Error::runtime(
            "Administrator privileges are required. Open Windows Terminal or PowerShell with \
             right-click > Run as administrator and run the command again. \
             Nothing was changed.",
        ));
    }
    Ok(true)
}

/// Privilege helper for Windows: there is nothing to ask for. `authenticate()` says whether the process is elevated
/// and never prompts; the window and the command line explain how to run elevated when it is not.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsPrivilege;

impl WindowsPrivilege {
    /// `WindowsPrivilege.is_admin()`.
    pub fn is_admin() -> bool {
        crate::windows::is_admin()
    }
}

impl Privilege for WindowsPrivilege {
    fn run_script(&self, _script: &str, _log: Log, _args: &[String]) -> Result<()> {
        Err(Error::runtime("Privileged shell scripts are not used on Windows."))
    }
    fn authenticate(&self, _reason: &str) -> Result<bool> {
        Ok(windows_authenticate(crate::windows::is_admin()))
    }
}

/// Command line on Windows: `authenticate` is `Err("Administrator privileges are required...")` when not elevated.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsCliPrivilege;

impl Privilege for WindowsCliPrivilege {
    fn run_script(&self, _script: &str, _log: Log, _args: &[String]) -> Result<()> {
        Err(Error::runtime("Privileged shell scripts are not used on Windows."))
    }
    fn authenticate(&self, _reason: &str) -> Result<bool> {
        windows_cli_authenticate(crate::windows::is_admin())
    }
}

#[cfg(all(test, unix))]
mod tests {
    //! The real system calls (`RealSys`) against harmless programs: line splitting, stdin text, merged streams,
    //! exit codes and the timeout. The helpers' logic is tested with a fake `SudoSys` in tests/.
    use super::*;

    fn lines_of(bytes: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        read_lines(bytes, &mut |l| out.push(l.to_string()));
        out
    }

    #[test]
    fn lines_end_at_lf_crlf_or_lone_cr_like_python_text_mode() {
        assert_eq!(lines_of(b"a\nb\r\nc\rd"), ["a", "b", "c", "d"]);
        assert_eq!(lines_of(b"x  \n\ny\n"), ["x", "", "y"]);
        assert_eq!(lines_of(b""), Vec::<String>::new());
        // dd's progress uses carriage returns
        assert_eq!(lines_of(b"1 bytes\r2 bytes\r3 bytes\n"), ["1 bytes", "2 bytes", "3 bytes"]);
        // invalid UTF-8 is replaced, not fatal
        assert_eq!(lines_of(b"caf\xe9 file.txt\n"), ["caf\u{fffd} file.txt"]);
    }

    #[test]
    fn a_crlf_split_across_two_reads_is_one_line_end() {
        struct Chunks(Vec<&'static [u8]>);
        impl Read for Chunks {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0.is_empty() {
                    return Ok(0);
                }
                let next = self.0.remove(0);
                buf[..next.len()].copy_from_slice(next);
                Ok(next.len())
            }
        }
        let mut out = Vec::new();
        read_lines(Chunks(vec![b"a\r", b"\nb\n"]), &mut |l| out.push(l.to_string()));
        assert_eq!(out, ["a", "b"]);
    }

    #[test]
    fn streaming_merges_stderr_and_passes_stdin_text() {
        let argv: Vec<String> =
            ["sh", "-c", "read x; echo \"got $x\"; echo oops >&2; exit 3"].iter().map(|s| s.to_string()).collect();
        let mut lines = Vec::new();
        let mut started = 0;
        let code = RealSys
            .run_streaming(&argv, StdinMode::Text("hello\n"), &mut || started += 1, &mut |l| lines.push(l.to_string()))
            .unwrap();
        assert_eq!(code, 3);
        assert_eq!(started, 1);
        assert_eq!(lines, ["got hello", "oops"]);
    }

    #[test]
    fn streaming_with_a_null_stdin_sees_end_of_file() {
        let argv: Vec<String> = ["sh", "-c", "cat; echo done"].iter().map(|s| s.to_string()).collect();
        let mut lines = Vec::new();
        let code =
            RealSys.run_streaming(&argv, StdinMode::Null, &mut || {}, &mut |l| lines.push(l.to_string())).unwrap();
        assert_eq!((code, lines), (0, vec!["done".to_string()]));
    }

    #[test]
    fn a_command_that_cannot_start_is_an_error() {
        let argv = vec!["/nonexistent/definitely-not-a-program".to_string()];
        assert!(RealSys.run_streaming(&argv, StdinMode::Null, &mut || {}, &mut |_| {}).is_err());
        assert_eq!(RealSys.run_quiet(&["/nonexistent/definitely-not-a-program"], None, Duration::from_secs(1)), None);
    }

    #[test]
    fn quiet_runs_report_the_exit_code_and_give_up_on_a_hung_command() {
        assert_eq!(RealSys.run_quiet(&["sh", "-c", "exit 0"], None, Duration::from_secs(5)), Some(0));
        assert_eq!(RealSys.run_quiet(&["sh", "-c", "exit 4"], None, Duration::from_secs(5)), Some(4));
        // the input reaches stdin
        assert_eq!(
            RealSys.run_quiet(&["sh", "-c", "read x; [ \"$x\" = pw ]"], Some("pw\n"), Duration::from_secs(5)),
            Some(0)
        );
        let started = Instant::now();
        assert_eq!(RealSys.run_quiet(&["sleep", "10"], None, Duration::from_millis(200)), None);
        assert!(started.elapsed() < Duration::from_secs(5), "the hung command was killed");
    }

    #[test]
    fn a_failed_script_line_never_contains_the_script() {
        let line = script_log_line("$ sudo ", &["a b".to_string(), "it's".to_string()]);
        assert_eq!(line, "$ sudo bash -c '<privileged script>' 'a b' \"it's\"");
        assert_eq!(script_log_line("$ ", &[]), "$ bash -c '<privileged script>' ");
    }
}
