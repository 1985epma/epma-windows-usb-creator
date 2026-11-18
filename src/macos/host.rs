//! What the macOS and Linux backends share: the `Host` seam (every call that leaves this module: commands, the clock,
//! the audit log, the other modules' helpers), `report_eject` and `write_raw_image` (Python lines 2576-2583 and
//! 2630-2649). OWNER: A3.
//!
//! Python's tests monkeypatch `subprocess.check_output`, `run_cmd`, `time.sleep`, `audit`, `copy_windows_payload`...
//! The Rust equivalent is this trait: every method has a default that does the real thing (so `SystemHost` is an empty
//! impl), and a test overrides what it needs. The public functions of `macos` and `linux` take no host (they use
//! `SystemHost`); each has a `*_with(host, ...)` twin that the tests call.

use crate::audit::{self, AuditLevel};
use crate::constants::RAW_CANCELED_MARKER;
use crate::types::{CancelToken, Ctx, Disk, Error, Files, Identity, Log, Privilege, Progress, Result, Volume};
use crate::{copyverify, diskrisk, proc, seed, util, validate};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// Everything the backends need from outside. See the module comment.
pub trait Host: Send + Sync {
    /// `subprocess.check_output(args, timeout=...)`: the stdout of a query command. `Err` when the command cannot
    /// start, times out (it is killed) or exits non-zero. `quiet_stderr` is `stderr=subprocess.DEVNULL`.
    fn check_output(&self, args: &[&str], timeout: Duration, quiet_stderr: bool) -> Result<Vec<u8>> {
        run_capture(args, timeout, quiet_stderr)
    }
    /// `run_cmd(args, log, check, timeout, cancel_event)`.
    fn run_cmd(
        &self,
        args: &[&str],
        log: Log,
        check: bool,
        timeout: Option<Duration>,
        cancel: Option<&CancelToken>,
    ) -> Result<i32> {
        proc::run_cmd(args, log, check, timeout, cancel)
    }
    /// `time.sleep(seconds)`.
    fn sleep(&self, seconds: f64) {
        thread::sleep(Duration::from_secs_f64(seconds.max(0.0)));
    }
    /// `audit(msg, level)`.
    fn audit(&self, msg: &str, level: AuditLevel) {
        audit::audit_at(msg, level);
    }
    /// `shutil.which(name) is not None`.
    fn which(&self, name: &str) -> bool {
        which(name)
    }
    /// `_used_bytes(mountpoint)` for a non-empty mountpoint: bytes in use on the filesystem, or None.
    fn used_bytes(&self, mountpoint: &str) -> Option<u64> {
        used_bytes(mountpoint)
    }
    /// `f"{os.getuid()}:{os.getgid()}"`: the user the drive is mounted for.
    fn owner(&self) -> String {
        owner()
    }
    /// `tempfile.mkdtemp(prefix=...)`: a new private (0700) directory that the caller removes with `silent_rmdir`.
    fn mkdtemp(&self, prefix: &str) -> Result<PathBuf> {
        let mut builder = tempfile::Builder::new();
        builder.prefix(prefix);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Owner only, like Python's mkdtemp (the default of the crate follows the umask: 0755 here).
            builder.permissions(std::fs::Permissions::from_mode(0o700));
        }
        Ok(builder.tempdir()?.keep())
    }
    /// `_silent_rmdir(path)`.
    fn silent_rmdir(&self, path: &Path) {
        util::silent_rmdir(path);
    }
    /// Where the `/sys/block` fallback of the Linux listing looks.
    fn sys_block_root(&self) -> PathBuf {
        PathBuf::from("/sys/block")
    }
    /// `_disk_entry`.
    fn disk_entry(
        &self,
        id: &str,
        size: u64,
        model: Option<&str>,
        volumes: Option<Vec<Volume>>,
        identity: Identity,
    ) -> Disk {
        diskrisk::disk_entry(id, size, model, volumes, identity)
    }
    /// `make_identity(**parts)`.
    fn make_identity(&self, parts: &[(&str, Option<String>)]) -> Identity {
        diskrisk::make_identity(parts)
    }
    /// `validate_hybrid_iso(path)`.
    fn validate_hybrid_iso(&self, path: &Path) -> Result<()> {
        validate::validate_hybrid_iso(path)
    }
    /// `make_dd_log(log, total, progress)`.
    fn make_dd_log<'a>(
        &self,
        log: Log<'a>,
        total: u64,
        progress: Option<Progress<'a>>,
    ) -> Box<dyn Fn(&str) + Send + Sync + 'a> {
        copyverify::make_dd_log(log, total, progress)
    }
    /// `with cancel_flag(cancel_event) as flag: ...`: runs `f` with the path of the flag file (it appears when the
    /// token is set), and removes the flag afterwards.
    fn with_cancel_flag(&self, cancel: Option<&CancelToken>, f: &mut dyn FnMut(&Path) -> Result<()>) -> Result<()> {
        let flag = proc::cancel_flag(cancel)?;
        // The flag is removed when it goes out of scope, after `f` has returned.
        f(flag.path())
    }
    /// `verify_raw_write(iso, device, ...)`.
    fn verify_raw_write(&self, iso_path: &Path, device_path: &str, ctx: &Ctx, priv_: &dyn Privilege) -> Result<()> {
        copyverify::verify_raw_write(iso_path, device_path, ctx, priv_)
    }
    /// `copy_windows_payload(...)`.
    fn copy_windows_payload(
        &self,
        src_root: &Path,
        dst_root: &Path,
        ctx: &Ctx,
        wimlib_hint: &str,
        reopen: Option<&dyn Fn() -> Result<PathBuf>>,
        extra_files: Option<&Files>,
    ) -> Result<()> {
        copyverify::copy_windows_payload(src_root, dst_root, ctx, wimlib_hint, reopen, extra_files)
    }
    /// `copy_seed_files(...)`.
    fn copy_seed_files(&self, stage_dir: &Path, dst_root: &Path, files: &Files, ctx: &Ctx) -> Result<()> {
        seed::copy_seed_files(stage_dir, dst_root, files, ctx)
    }
    /// `verify_seed_files(...)`.
    fn verify_seed_files(&self, files: &Files, dst_root: &Path, ctx: &Ctx) -> Result<()> {
        seed::verify_seed_files(files, dst_root, ctx)
    }
}

/// The real thing: every method keeps its default.
pub struct SystemHost;
impl Host for SystemHost {}

// ---------------------------------------------------------------------------------------------------------------
// Real implementations of the defaults
// ---------------------------------------------------------------------------------------------------------------

/// `subprocess.check_output` with a timeout, stdout captured as bytes.
pub(crate) fn run_capture(args: &[&str], timeout: Duration, quiet_stderr: bool) -> Result<Vec<u8>> {
    let Some((program, rest)) = args.split_first() else {
        return Err(Error::runtime("No command to run."));
    };
    let shown = args.join(" ");
    let mut cmd = Command::new(program);
    cmd.args(rest).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(if quiet_stderr {
        Stdio::null()
    } else {
        Stdio::inherit()
    });
    // The program's name in the message tells the user what is missing ('diskutil: No such file or directory').
    let mut child = cmd.spawn().map_err(|e| Error::Io(std::io::Error::new(e.kind(), format!("{program}: {e}"))))?;
    let Some(mut stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(Error::runtime(format!("Could not read the output of '{shown}'.")));
    };
    // Read on a thread so a chatty command cannot fill the pipe and stall while we wait for it.
    let reader = thread::spawn(move || {
        let mut buf = Vec::new();
        stdout.read_to_end(&mut buf).map(|_| buf)
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    // The reader is not joined: a grandchild could still hold the pipe open.
                    return Err(Error::runtime(format!(
                        "Command '{shown}' timed out after {} seconds.",
                        timeout.as_secs()
                    )));
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
    };
    let out = match reader.join() {
        Ok(Ok(buf)) => buf,
        Ok(Err(e)) => return Err(Error::Io(e)),
        Err(_) => return Err(Error::runtime(format!("Could not read the output of '{shown}'."))),
    };
    if !status.success() {
        return Err(match status.code() {
            Some(code) => Error::runtime(format!("Command '{shown}' returned non-zero exit status {code}.")),
            None => Error::runtime(format!("Command '{shown}' was terminated by a signal.")),
        });
    }
    Ok(out)
}

/// `shutil.which`: is there an executable file called `name` on PATH?
pub(crate) fn which(name: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| is_executable_file(&dir.join(name)))
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.is_file() && meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        meta.is_file()
    }
}

/// `_used_bytes(mountpoint)`: `shutil.disk_usage` total minus free, or None.
#[cfg(unix)]
pub(crate) fn used_bytes(mountpoint: &str) -> Option<u64> {
    use std::ffi::CString;
    if mountpoint.is_empty() {
        return None;
    }
    let path = CString::new(mountpoint).ok()?;
    // SAFETY: `path` is a valid NUL-terminated string and `st` is a plain-old-data struct that statvfs fills in.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(path.as_ptr(), &mut st) };
    if rc != 0 {
        return None;
    }
    #[allow(clippy::unnecessary_cast)] // the field widths differ between unix systems
    let (frsize, blocks, avail) = (st.f_frsize as u64, st.f_blocks as u64, st.f_bavail as u64);
    Some(blocks.saturating_mul(frsize).saturating_sub(avail.saturating_mul(frsize)))
}
#[cfg(not(unix))]
pub(crate) fn used_bytes(_mountpoint: &str) -> Option<u64> {
    None
}

/// `uid:gid` of the current user (for `mount -o uid=,gid=`).
#[cfg(unix)]
pub(crate) fn owner() -> String {
    // SAFETY: getuid and getgid have no preconditions and cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    format!("{uid}:{gid}")
}
#[cfg(not(unix))]
pub(crate) fn owner() -> String {
    "0:0".to_string()
}

/// The Python exception class name an `audit` message quotes (`type(e).__name__`), as close as the port gets.
pub(crate) fn error_kind(e: &Error) -> &'static str {
    match e {
        Error::Runtime(_) => "RuntimeError",
        Error::Value(_) => "ValueError",
        Error::Canceled { .. } => "OperationCanceled",
        Error::Io(_) => "OSError",
    }
}

// ---------------------------------------------------------------------------------------------------------------
// report_eject, write_raw_image
// ---------------------------------------------------------------------------------------------------------------

/// What the user is told about the eject. `skipped`: the caller asked to leave the drive connected.
pub fn report_eject(ejected: bool, log: Log, skipped: bool) {
    if skipped {
        log("The drive was left connected, as requested. Eject it before unplugging.");
    } else if ejected {
        log("Drive ejected — you can unplug it now.");
    } else {
        log("Could not eject automatically. Eject the drive from the file manager before unplugging it.");
    }
}

/// Run a root write script (`MACOS_RAW_SCRIPT` / `LINUX_RAW_SCRIPT`); true if it stopped on request.
///
/// The script runs as root, so the app cannot signal it; `cancel_flag` gives it a file to watch instead. `base_args`
/// are "$1".."$3", the flag path becomes "$4", then `extra_args`.
pub fn write_raw_image(
    priv_: &dyn Privilege,
    script: &str,
    base_args: &[String],
    ctx: &Ctx,
    total: u64,
    extra_args: &[String],
) -> Result<bool> {
    write_raw_image_with(&SystemHost, priv_, script, base_args, ctx, total, extra_args)
}

pub fn write_raw_image_with(
    host: &dyn Host,
    priv_: &dyn Privilege,
    script: &str,
    base_args: &[String],
    ctx: &Ctx,
    total: u64,
    extra_args: &[String],
) -> Result<bool> {
    let canceled = AtomicBool::new(false);
    let dd_log = host.make_dd_log(ctx.log, total, ctx.progress);
    let watch = |line: &str| {
        if line.trim() == RAW_CANCELED_MARKER {
            canceled.store(true, Ordering::SeqCst);
            ctx.log("The write was stopped at your request.");
            return;
        }
        dd_log(line);
    };
    host.with_cancel_flag(ctx.cancel, &mut |flag| {
        let mut args: Vec<String> = base_args.to_vec();
        args.push(flag.to_string_lossy().into_owned());
        args.extend_from_slice(extra_args);
        priv_.run_script(script, &watch, &args)
    })?;
    Ok(canceled.load(Ordering::SeqCst))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[cfg(unix)]
    #[test]
    fn run_capture_returns_stdout() {
        assert_eq!(run_capture(&["echo", "hello"], secs(10), true).unwrap(), b"hello\n");
    }

    #[cfg(unix)]
    #[test]
    fn a_lot_of_output_does_not_stall_the_command() {
        let out = run_capture(&["sh", "-c", "head -c 3000000 /dev/zero"], secs(20), true).unwrap();
        assert_eq!(out.len(), 3_000_000);
    }

    #[cfg(unix)]
    #[test]
    fn a_failing_command_is_an_error_with_its_exit_status() {
        let err = run_capture(&["sh", "-c", "exit 3"], secs(10), true).unwrap_err();
        assert!(matches!(err, Error::Runtime(_)));
        assert!(err.to_string().contains("returned non-zero exit status 3"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn a_hung_command_is_killed_at_the_timeout() {
        let start = Instant::now();
        let err = run_capture(&["sleep", "30"], Duration::from_millis(300), true).unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
        assert!(start.elapsed() < secs(10), "the command was not killed");
    }

    #[test]
    fn a_missing_program_is_an_io_error_and_no_command_is_an_error() {
        let err = run_capture(&["epma-no-such-program-xyz"], secs(5), true).unwrap_err();
        assert!(matches!(err, Error::Io(_)));
        assert!(matches!(run_capture(&[], secs(5), true), Err(Error::Runtime(_))));
    }

    #[cfg(unix)]
    #[test]
    fn which_finds_executables_on_the_path_only() {
        use std::os::unix::fs::PermissionsExt;
        assert!(which("sh"));
        assert!(!which("epma-no-such-tool-xyz"));
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_executable_file(dir.path())); // a directory is not a program
        let file = dir.path().join("tool");
        std::fs::write(&file, "#!/bin/sh\n").unwrap();
        assert!(!is_executable_file(&file)); // not executable
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(is_executable_file(&file));
    }

    #[cfg(unix)]
    #[test]
    fn used_bytes_reads_the_filesystem_and_never_panics() {
        let dir = tempfile::tempdir().unwrap();
        assert!(used_bytes(&dir.path().to_string_lossy()).is_some());
        assert_eq!(used_bytes("/nonexistent/epma/mountpoint"), None);
        assert_eq!(used_bytes(""), None);
        assert_eq!(used_bytes("with\0nul"), None);
    }

    #[cfg(unix)]
    #[test]
    fn the_owner_is_uid_and_gid() {
        let owner = owner();
        let (uid, gid) = owner.split_once(':').expect("uid:gid");
        assert!(uid.parse::<u32>().is_ok() && gid.parse::<u32>().is_ok(), "{owner}");
    }

    #[test]
    fn error_kinds_name_the_python_exceptions() {
        assert_eq!(error_kind(&Error::runtime("x")), "RuntimeError");
        assert_eq!(error_kind(&Error::value("x")), "ValueError");
        assert_eq!(error_kind(&Error::canceled()), "OperationCanceled");
        assert_eq!(error_kind(&Error::Io(std::io::Error::other("x"))), "OSError");
    }

    #[test]
    fn the_default_host_makes_private_temp_directories() {
        let dir = SystemHost.mkdtemp("win11iso_").unwrap();
        assert!(dir.is_dir());
        assert!(dir.file_name().unwrap().to_string_lossy().starts_with("win11iso_"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        }
        std::fs::remove_dir(&dir).unwrap();
    }
}
