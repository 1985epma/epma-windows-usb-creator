#![allow(unused)] // STUB: delete this line when the module is implemented
//! Running commands, the cancel-flag file, keeping the computer awake. OWNER: A1.
//! Port of win11_usb_creator.py lines 1467-1486 (OperationCanceled -> `types::Error::Canceled`), 1487-1494, 1533-1724,
//! 1726-1745 (platform_display_name).

use crate::types::{CancelToken, Log, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// `check_canceled(cancel_event, drive_touched, written)`.
pub fn check_canceled(cancel: Option<&CancelToken>, drive_touched: bool, written: bool) -> Result<()> {
    todo!()
}
/// Run a command as the current user, streaming stdout+stderr line by line to `log` (first logs `$ cmd args`).
/// `timeout` kills a hung command; `cancel` stops it promptly (Error::Canceled). With `check`, a non-zero exit is
/// `Error::Runtime("Command failed (exit code N): ...")`. Returns the exit code. On Windows children get no console
/// window and an empty stdin (the Python SUBPROCESS_QUIET).
pub fn run_cmd<S: AsRef<str>>(
    args: &[S],
    log: Log,
    check: bool,
    timeout: Option<Duration>,
    cancel: Option<&CancelToken>,
) -> Result<i32> {
    todo!()
}
/// `sync` on macOS and Linux; nothing on Windows.
pub fn sync_filesystems(log: Log) {
    todo!()
}

/// The private flag file of `cancel_flag`: its path appears (as an empty file) when the token is set. The privileged
/// write script runs as root and polls for it. Dropping the guard stops the watcher and removes file and directory.
pub struct CancelFlag {/* A1 decides */}
impl CancelFlag {
    pub fn path(&self) -> &Path {
        todo!()
    }
}
/// `cancel_flag(cancel_event)`.
pub fn cancel_flag(cancel: Option<&CancelToken>) -> Result<CancelFlag> {
    todo!()
}

/// Keeps the machine awake while alive (caffeinate / systemd-inhibit / SetThreadExecutionState). Best effort.
pub struct SleepGuard {/* A1 decides */}
/// `prevent_sleep(log)`: hold the returned guard for the whole operation.
pub fn prevent_sleep(log: Log) -> SleepGuard {
    todo!()
}
/// "macOS", "Windows 11" (build >= 22000) / "Windows 10", or the Linux distribution name.
pub fn platform_display_name() -> String {
    todo!()
}
