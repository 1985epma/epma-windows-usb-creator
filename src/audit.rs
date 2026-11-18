//! The audit log (rotating, owner-only file). OWNER: A1. Port of win11_usb_creator.py lines 715-781.
//!
//! Destructive, privileged operations should leave a record. The log is written with owner-only permissions
//! (file 0600, folder 0700) and deliberately never receives passwords: the sudo password is passed on stdin and
//! never appears in an argument list or in any string handed to `audit()` / `log()`.
//!
//! The Python used `logging` with a `RotatingFileHandler`; this is the same thing written by hand: the line format
//! is the Python formatter's `"%(asctime)s %(levelname)s %(message)s"` (`2025-01-31 14:05:09,123 INFO text`, local
//! time), the file rotates at `AUDIT_LOG_MAX_BYTES` keeping `AUDIT_LOG_BACKUPS` copies (`audit.log.1` ... `.N`,
//! the newest being `.1`), and writing never fails the caller: a read-only or unwritable home must not stop the
//! user from making a USB.
//!
//! In the crate's own unit tests (`cfg(test)`) the global log is switched off so the tests never write to the
//! developer's real audit file; integration tests set `WIN11USB_DISABLE_AUDIT_LOG=1` (as the Python test helpers
//! do) or point `WIN11USB_AUDIT_LOG` at a temp file and call `reset_audit_sink()`.

use crate::constants::{AUDIT_LOG_BACKUPS, AUDIT_LOG_MAX_BYTES, ENV_AUDIT_LOG, ENV_DISABLE_AUDIT_LOG, IS_WINDOWS};
use crate::util::{expand_user, py_strip};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditLevel {
    Info,
    Warning,
    Error,
}

impl AuditLevel {
    /// The Python `logging` level name.
    pub fn as_str(self) -> &'static str {
        match self {
            AuditLevel::Info => "INFO",
            AuditLevel::Warning => "WARNING",
            AuditLevel::Error => "ERROR",
        }
    }
}

/// `audit_log_path()`: where the audit log lives (ENV_AUDIT_LOG overrides it).
pub fn audit_log_path() -> PathBuf {
    audit_log_path_with(&real_env, IS_WINDOWS)
}

fn real_env(key: &str) -> Option<String> {
    std::env::var_os(key).map(|v| v.to_string_lossy().into_owned())
}

/// `audit_log_path()` with the environment and the OS passed in (the testable core). An empty variable counts as
/// unset, like Python's `or`.
pub fn audit_log_path_with(env: &dyn Fn(&str) -> Option<String>, windows: bool) -> PathBuf {
    let get = |key: &str| env(key).filter(|v| !v.is_empty());
    if let Some(over) = get(ENV_AUDIT_LOG) {
        return expand_user(over);
    }
    if windows {
        // %LOCALAPPDATA% is private to the user (the folder's ACL is inherited from the profile).
        let base = match get("LOCALAPPDATA") {
            Some(b) => PathBuf::from(b),
            None => expand_user("~").join("AppData").join("Local"),
        };
        return base.join("epma-win11-usb-creator").join("audit.log");
    }
    let base = match get("XDG_STATE_HOME") {
        Some(b) => PathBuf::from(b),
        None => expand_user("~").join(".local").join("state"),
    };
    base.join("epma-win11-usb-creator").join("audit.log")
}

// ---------------------------------------------------------------------------------------------------------------
// The file: rotating, owner-only
// ---------------------------------------------------------------------------------------------------------------

/// A rotating log file that stays owner-only (0600), the live file and the rotated copies alike
/// (`PrivateRotatingFileHandler`).
pub struct AuditLog {
    path: PathBuf,
    file: File,
    size: u64,
    max_bytes: u64,
    backups: u32,
    /// Python only rotates a regular file (not /dev/null and the like).
    rotates: bool,
}

impl AuditLog {
    /// Open (creating it owner-only if needed) the log at `path`. The file is opened without following a symlink.
    pub fn open(path: impl AsRef<Path>, max_bytes: u64, backups: u32) -> io::Result<AuditLog> {
        let path = path.as_ref().to_path_buf();
        let file = open_private(&path)?;
        let meta = file.metadata()?;
        Ok(AuditLog { size: meta.len(), rotates: meta.is_file(), path, file, max_bytes, backups })
    }

    /// Append one record (`"<time> <LEVEL> <message>\n"`), rotating first when it would not fit.
    pub fn write_record(&mut self, level: AuditLevel, msg: &str, when: SystemTime) -> io::Result<()> {
        let line = format_record(level, msg, when);
        self.write_line(&line)
    }

    fn write_line(&mut self, line: &str) -> io::Result<()> {
        // RotatingFileHandler.shouldRollover: current size + the new line reaches the maximum.
        if self.rotates && self.max_bytes > 0 && self.size + line.len() as u64 >= self.max_bytes {
            self.rollover()?;
        }
        self.file.write_all(line.as_bytes())?;
        self.file.flush()?;
        self.size += line.len() as u64;
        Ok(())
    }

    /// `doRollover`: `audit.log.(N-1)` -> `.N` ... `audit.log` -> `.1`, then a fresh live file; every copy is
    /// chmod 0600 afterwards.
    fn rollover(&mut self) -> io::Result<()> {
        if self.backups > 0 {
            for i in (1..self.backups).rev() {
                let (src, dst) = (backup_path(&self.path, i), backup_path(&self.path, i + 1));
                if src.exists() {
                    if dst.exists() {
                        std::fs::remove_file(&dst)?;
                    }
                    std::fs::rename(&src, &dst)?;
                }
            }
            let first = backup_path(&self.path, 1);
            if first.exists() {
                std::fs::remove_file(&first)?;
            }
            std::fs::rename(&self.path, &first)?;
        }
        // Without backups the Python still reopens the file; it truncates by opening with "w"... the handler
        // opens with append here, so a zero-backup configuration simply keeps appending. (Never used: the
        // constant is 5.)
        self.file = open_private(&self.path)?;
        self.size = self.file.metadata().map(|m| m.len()).unwrap_or(0);
        for i in 0..=self.backups {
            let p = if i == 0 { self.path.clone() } else { backup_path(&self.path, i) };
            set_private_mode(&p);
        }
        Ok(())
    }
}

fn backup_path(base: &Path, n: u32) -> PathBuf {
    let mut name = OsString::from(base.as_os_str());
    name.push(format!(".{n}"));
    PathBuf::from(name)
}

/// Open for append, creating with owner-only permissions, never through a symlink, and make sure an existing file
/// is owner-only too (`os.chmod(path, 0o600)`).
fn open_private(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(crate::constants::PRIVATE_FILE_MODE).custom_flags(libc::O_NOFOLLOW);
    }
    let file = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(crate::constants::PRIVATE_FILE_MODE))?;
    }
    Ok(file)
}

/// chmod 0600 by path, ignoring failures (a copy that does not exist, a foreign owner...).
fn set_private_mode(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(crate::constants::PRIVATE_FILE_MODE));
    }
    #[cfg(not(unix))]
    {
        let _ = path; // Windows: the ACL of the profile folder is inherited
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Line format
// ---------------------------------------------------------------------------------------------------------------

/// Broken-down calendar time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CivilTime {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
}

/// UTC calendar time of a Unix timestamp (days-from-civil algorithm, valid for the whole i64 range we can meet).
pub fn civil_from_unix(secs: i64) -> CivilTime {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400) as u32;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe as i64 + era * 400 + if month <= 2 { 1 } else { 0 };
    CivilTime { year, month, day, hour: rem / 3600, minute: rem % 3600 / 60, second: rem % 60 }
}

/// Local calendar time (what the Python `time.localtime` gives the logging formatter).
#[cfg(unix)]
fn local_civil(secs: i64) -> CivilTime {
    let t: libc::time_t = secs as libc::time_t;
    // SAFETY: `tm` is a plain out-structure; localtime_r is the thread-safe variant and only writes into it.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let ok = unsafe { !libc::localtime_r(&t, &mut tm).is_null() };
    if !ok {
        return civil_from_unix(secs);
    }
    CivilTime {
        year: i64::from(tm.tm_year) + 1900,
        month: (tm.tm_mon + 1) as u32,
        day: tm.tm_mday as u32,
        hour: tm.tm_hour as u32,
        minute: tm.tm_min as u32,
        second: tm.tm_sec as u32,
    }
}

/// Windows: the stamps are UTC. The local time zone needs `GetLocalTime`/`SystemTimeToTzSpecificLocalTime`, which
/// are outside the windows-sys features of this crate; a UTC stamp is unambiguous for an audit trail and the
/// difference is the only deviation from the Python (which used local time).
#[cfg(not(unix))]
fn local_civil(secs: i64) -> CivilTime {
    civil_from_unix(secs)
}

/// `"2025-01-31 14:05:09,123 INFO message\n"`: the Python formatter `"%(asctime)s %(levelname)s %(message)s"`.
pub fn format_record(level: AuditLevel, msg: &str, when: SystemTime) -> String {
    let (secs, millis) = match when.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_millis()),
        Err(e) => (-(e.duration().as_secs() as i64), 0),
    };
    format_record_at(level, msg, local_civil(secs), millis)
}

/// The formatting itself, with the calendar time given (testable).
pub fn format_record_at(level: AuditLevel, msg: &str, t: CivilTime, millis: u32) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02},{:03} {} {}\n",
        t.year,
        t.month,
        t.day,
        t.hour,
        t.minute,
        t.second,
        millis,
        level.as_str(),
        msg
    )
}

// ---------------------------------------------------------------------------------------------------------------
// The process-wide log
// ---------------------------------------------------------------------------------------------------------------

enum Sink {
    /// Disabled by the environment, or the file could not be opened: every `audit()` is a no-op.
    Off,
    File(AuditLog),
}

/// Created on the first `audit()` (the Python creates the logger lazily and caches it).
static SINK: Mutex<Option<Sink>> = Mutex::new(None);

fn create_sink() -> Sink {
    if cfg!(test) {
        return Sink::Off; // see the module comment
    }
    let disabled = std::env::var_os(ENV_DISABLE_AUDIT_LOG)
        .map(|v| v.to_string_lossy().into_owned())
        .is_some_and(|v| matches!(py_strip(&v).to_lowercase().as_str(), "1" | "true" | "yes"));
    if disabled {
        return Sink::Off;
    }
    match open_default_log() {
        Ok(log) => Sink::File(log),
        // A read-only or unwritable home must not stop the user from making a USB.
        Err(_) => Sink::Off,
    }
}

fn open_default_log() -> io::Result<AuditLog> {
    let path = audit_log_path();
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(dir)?;
    }
    AuditLog::open(&path, AUDIT_LOG_MAX_BYTES, AUDIT_LOG_BACKUPS)
}

/// Forget the cached log so the next `audit()` reads the environment again (for tests that change
/// `WIN11USB_AUDIT_LOG` / `WIN11USB_DISABLE_AUDIT_LOG`; the Python tests reset `_audit_logger` the same way).
pub fn reset_audit_sink() {
    *SINK.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// `audit(msg)` at INFO level. Never fails (a log that cannot be written is ignored).
pub fn audit(msg: &str) {
    audit_at(msg, AuditLevel::Info);
}

/// `audit(msg, level)`. Record a security-relevant event. Callers must not pass secrets or personal data.
pub fn audit_at(msg: &str, level: AuditLevel) {
    let mut guard = SINK.lock().unwrap_or_else(|e| e.into_inner());
    if let Sink::File(log) = guard.get_or_insert_with(create_sink) {
        // Deliberate: logging must never break the app, so a failed write is dropped.
        let _ = log.write_record(level, msg, SystemTime::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    #[test]
    fn civil_time_of_known_instants() {
        assert_eq!(civil_from_unix(0), CivilTime { year: 1970, month: 1, day: 1, hour: 0, minute: 0, second: 0 });
        assert_eq!(
            civil_from_unix(1_700_000_000),
            CivilTime { year: 2023, month: 11, day: 14, hour: 22, minute: 13, second: 20 }
        );
        // leap day and a negative timestamp
        assert_eq!(civil_from_unix(1_709_164_800).day, 29);
        assert_eq!(civil_from_unix(-1), CivilTime { year: 1969, month: 12, day: 31, hour: 23, minute: 59, second: 59 });
    }

    #[test]
    fn the_line_format_is_the_python_logging_one() {
        let t = CivilTime { year: 2025, month: 1, day: 31, hour: 14, minute: 5, second: 9 };
        assert_eq!(format_record_at(AuditLevel::Info, "hello", t, 123), "2025-01-31 14:05:09,123 INFO hello\n");
        assert_eq!(format_record_at(AuditLevel::Warning, "x", t, 7), "2025-01-31 14:05:09,007 WARNING x\n");
        assert_eq!(format_record_at(AuditLevel::Error, "x", t, 0), "2025-01-31 14:05:09,000 ERROR x\n");
        let live = format_record(AuditLevel::Info, "now", SystemTime::now());
        assert!(live.ends_with(" INFO now\n") && live.len() > 30);
    }

    #[test]
    fn log_path_resolution() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            let map: HashMap<&str, &str> = pairs.iter().copied().collect();
            move |k: &str| map.get(k).map(|v| v.to_string())
        };
        // the override wins and ~ is expanded
        let p = audit_log_path_with(&env(&[(ENV_AUDIT_LOG, "~/custom.log")]), false);
        assert_eq!(p, expand_user("~/custom.log"));
        // XDG_STATE_HOME
        let p = audit_log_path_with(&env(&[("XDG_STATE_HOME", "/state")]), false);
        assert_eq!(p, PathBuf::from("/state/epma-win11-usb-creator/audit.log"));
        // an empty variable counts as unset
        let p = audit_log_path_with(&env(&[("XDG_STATE_HOME", "")]), false);
        assert!(p.ends_with(".local/state/epma-win11-usb-creator/audit.log"), "{p:?}");
        // Windows: %LOCALAPPDATA%
        let p = audit_log_path_with(&env(&[("LOCALAPPDATA", "C:\\Users\\a\\AppData\\Local")]), true);
        let s = p.to_string_lossy();
        assert!(s.starts_with("C:\\Users\\a\\AppData\\Local") && s.ends_with("audit.log"), "{s}");
    }

    #[test]
    fn writes_owner_only_log_and_appends() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join("audit.log");
        std::fs::create_dir(dir.path().join("state")).unwrap();
        let mut log = AuditLog::open(&path, 1_000_000, 5).unwrap();
        log.write_record(AuditLevel::Info, "hello from the tests", SystemTime::now()).unwrap();
        log.write_record(AuditLevel::Warning, "second", SystemTime::now()).unwrap();
        let text = read(&path);
        assert!(text.contains(" INFO hello from the tests\n") && text.contains(" WARNING second\n"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // a second handle appends instead of truncating
        let mut again = AuditLog::open(&path, 1_000_000, 5).unwrap();
        again.write_record(AuditLevel::Info, "third", SystemTime::now()).unwrap();
        assert_eq!(read(&path).lines().count(), 3);
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_loose_file_is_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, b"old\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let _log = AuditLog::open(&path, 1_000_000, 5).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_planted_at_the_log_path_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim.txt");
        std::fs::write(&victim, b"precious").unwrap();
        let link = dir.path().join("audit.log");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(AuditLog::open(&link, 1_000_000, 5).is_err());
        assert_eq!(read(&victim), "precious");
    }

    #[test]
    fn rotation_keeps_the_newest_copy_as_dot_one_and_a_bounded_number_of_copies() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let mut log = AuditLog::open(&path, 200, 3).unwrap();
        for i in 0..40 {
            log.write_record(AuditLevel::Info, &format!("entry number {i:03} padded padded"), SystemTime::now())
                .unwrap();
        }
        assert!(path.exists());
        for n in 1..=3 {
            assert!(backup_path(&path, n).exists(), "audit.log.{n} missing");
        }
        assert!(!backup_path(&path, 4).exists(), "more copies than the limit");
        // .1 is newer than .2, which is newer than .3
        let last = |p: &Path| read(p).lines().last().unwrap().to_string();
        let number = |l: String| l.rsplit("entry number ").next().unwrap()[..3].parse::<u32>().unwrap();
        let (live, one, two, three) = (
            number(last(&path)),
            number(last(&backup_path(&path, 1))),
            number(last(&backup_path(&path, 2))),
            number(last(&backup_path(&path, 3))),
        );
        assert_eq!(live, 39);
        assert!(live > one && one > two && two > three, "{live} {one} {two} {three}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for n in 1..=3 {
                let mode = std::fs::metadata(backup_path(&path, n)).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "audit.log.{n}");
            }
        }
        // no live file ever exceeds the maximum (one line is ~60 bytes, the limit 200)
        assert!(std::fs::metadata(&path).unwrap().len() < 200);
    }

    #[test]
    fn unwritable_location_is_an_error_for_open_but_audit_never_fails() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"a file, not a directory").unwrap();
        assert!(AuditLog::open(blocker.join("audit.log"), 1_000_000, 5).is_err());
        // The global one is disabled in unit tests, but must in any case be a no-op that cannot panic.
        audit("this goes nowhere");
        audit_at("nor this", AuditLevel::Error);
        reset_audit_sink();
    }
}
