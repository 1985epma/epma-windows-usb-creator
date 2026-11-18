//! Windows 11 backend. OWNER: A4. Port of win11_usb_creator.py lines 3030-3421 (PowerShell Storage cmdlets, DISM
//! paths, elevation, the disk list) and 3506-3761 (byte-for-byte writes to `\\.\PhysicalDriveN`, the Windows 11 and
//! seed-drive builders).
//!
//! Everything here uses what ships with Windows 11: the PowerShell Storage cmdlets (`Get-Disk`, `Clear-Disk`,
//! `New-Partition`, `Format-Volume`, `Mount-DiskImage`, ...) and DISM. There is no sudo: the program itself must run
//! as Administrator. Values never become PowerShell code: every script is a fixed text with a typed `param()` block,
//! written to a private temporary file and started with `-File`, so the values arrive as data.
//!
//! Layout: the pure parts (script texts, the `Get-Disk` JSON parser, argument building, alignment math, marker
//! parsing, the raw write/verify loops) compile and are tested on every OS. The few Win32 calls live in the private
//! `win32` module, once for Windows and once as a stub for every other OS. The effects on the outside world (running
//! PowerShell, the other modules, the raw drive handle) go through the small [`WinEnv`] trait so the whole flow is
//! tested here with a fake; [`RealWinEnv`] is the real thing.

use crate::audit::AuditLevel;
use crate::constants::{PROGRESS_UI_INTERVAL, QUERY_TIMEOUT, VERIFY_PROGRESS_INTERVAL, VOL_NAME, WINDOWS_DEVICE_RE};
use crate::macos::report_eject;
use crate::types::{CancelToken, Ctx, Disk, Error, Files, Identity, Log, Privilege, Result, Volume};
use serde_json::Value;
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------------------------------------------

/// Seconds a Storage cmdlet script may run (formatting a big drive can be slow).
pub const POWERSHELL_TIMEOUT: u64 = 900;
/// Windows refuses to format FAT32 volumes over 32 GB: use at most 30 GiB.
pub const WINDOWS_FAT32_MAX_PARTITION: u64 = 30 * 1024 * 1024 * 1024;
/// Bytes written or read per step on a raw drive (a multiple of 4096).
pub const WINDOWS_RAW_BLOCK: u64 = 4 * 1024 * 1024;
/// Every raw offset and length is a multiple of this (covers 512-byte and 4K sectors).
pub const WINDOWS_RAW_ALIGN: u64 = 4096;
/// The start of a raw image (the partition tables) is written LAST, see [`raw_write`].
pub const WINDOWS_RAW_HEAD: u64 = 1024 * 1024;
/// Seconds to wait for a volume's drive letter to appear.
pub const WINDOWS_MOUNT_RETRIES: u32 = 30;
/// Put in front of every script: stop on errors, no progress bars, UTF-8 output.
pub const WINDOWS_PS_PREAMBLE: &str = "$ErrorActionPreference = 'Stop'\n\
$ProgressPreference = 'SilentlyContinue'\n\
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }\n";
pub const EJECTED_MARKER: &str = "EJECTED";
pub const NOT_EJECTED_MARKER: &str = "NOT_EJECTED";

// The PowerShell scripts are DATA, byte for byte from the Python reference (see assets/windows-*.ps1).

/// Lists the disks as JSON. Fixed text, no parameters. The system/boot disk is flagged here and dropped in Rust.
pub const WINDOWS_LIST_SCRIPT: &str = include_str!("../assets/windows-list.ps1");
/// Wipes the disk, then GPT + ONE FAT32 partition (capped: Windows will not format a bigger FAT32 volume) with a
/// drive letter. `$Number` the disk, `$Label` the volume label, `$MaxBytes` the cap. The disk must be an external USB
/// drive that is not the boot disk: checked again here, right before the wipe. Prints `EPMA_VOLUME <letter> <part>`.
pub const WINDOWS_PREPARE_SCRIPT: &str = include_str!("../assets/windows-prepare.ps1");
/// Wipes the disk and leaves it uninitialised (RAW) for a byte-for-byte write. Prints `EPMA_RAW_READY`.
pub const WINDOWS_PREPARE_RAW_SCRIPT: &str = include_str!("../assets/windows-prepare-raw.ps1");
/// Detaches the volumes of the disk from their drive letters (that flushes and dismounts them), so the cache is
/// dropped and the next read comes from the device. Prints `EPMA_VOLUME <letter> <partition>` for the first volume
/// that is attached again (when `$Reattach` is 1) and `EJECTED` / `NOT_EJECTED` when `$Reattach` is 0.
pub const WINDOWS_DETACH_SCRIPT: &str = include_str!("../assets/windows-detach.ps1");
/// Mounts an ISO read-only and prints its drive letter (`EPMA_ISO <letter> <was-already-mounted 0|1>`).
pub const WINDOWS_ISO_MOUNT_SCRIPT: &str = include_str!("../assets/windows-iso-mount.ps1");
pub const WINDOWS_ISO_DISMOUNT_SCRIPT: &str = include_str!("../assets/windows-iso-dismount.ps1");

/// What `build_usb` tells the user when `install.esd` is over the FAT32 limit and nothing can split it.
const ESD_HINT: &str = "install.esd is over 4 GB and Windows cannot split it. Use the ISO from Microsoft's download \
page (it holds install.wim), or install wimlib and run this program again.";

// ---------------------------------------------------------------------------------------------------------------
// System32 paths
// ---------------------------------------------------------------------------------------------------------------

/// The Windows folder: `SystemRoot`, else `windir`, else `C:\Windows` (an empty variable counts as unset).
fn pick_system_root(system_root: Option<OsString>, windir: Option<OsString>) -> PathBuf {
    [system_root, windir]
        .into_iter()
        .flatten()
        .find(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
}

/// `<root>\System32\<parts...>` (pure: the root is given).
fn system32_under(root: &Path, parts: &[&str]) -> PathBuf {
    let mut path = root.join("System32");
    for part in parts {
        path.push(part);
    }
    path
}

fn system32_parts(parts: &[&str]) -> PathBuf {
    let root = pick_system_root(std::env::var_os("SystemRoot"), std::env::var_os("windir"));
    system32_under(&root, parts)
}

/// `windows_system32(name)`: full path of a tool in System32. Absolute on purpose: this program runs as
/// Administrator and must not pick a look-alike from the current folder or from PATH.
pub fn system32(name: &str) -> PathBuf {
    system32_parts(&[name])
}

/// `windows_powershell_exe()`.
pub fn powershell_exe() -> PathBuf {
    system32_parts(&["WindowsPowerShell", "v1.0", "powershell.exe"])
}

/// `windows_dism_exe()`.
pub fn dism_exe() -> PathBuf {
    system32("dism.exe")
}

// ---------------------------------------------------------------------------------------------------------------
// Elevation and DPI (Win32; stubs elsewhere)
// ---------------------------------------------------------------------------------------------------------------

/// `windows_is_admin()`: true when the process runs elevated (Administrator). Always false off Windows.
pub fn is_admin() -> bool {
    win32::is_admin()
}

/// `windows_relaunch_elevated()`: start this program again with the UAC prompt (`runas`). True if Windows accepted
/// the request (the caller then exits); false off Windows.
pub fn relaunch_elevated() -> bool {
    win32::relaunch_elevated()
}

/// `windows_enable_dpi_awareness()`: ask Windows not to bitmap-scale the window (blurry text on high-DPI screens).
/// Cosmetic; failures are ignored.
pub fn enable_dpi_awareness() {
    win32::enable_dpi_awareness()
}

/// Python's `subprocess.list2cmdline`: the Windows command line for `args` (quoting and backslash rules of the
/// MS C runtime), used to hand our own arguments to the elevated copy of this program.
pub fn list2cmdline(args: &[String]) -> String {
    let mut result = String::new();
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            result.push(' ');
        }
        let need_quote = arg.is_empty() || arg.contains(' ') || arg.contains('\t');
        if need_quote {
            result.push('"');
        }
        let mut backslashes = 0usize;
        for c in arg.chars() {
            match c {
                '\\' => backslashes += 1,
                '"' => {
                    // Backslashes before a quote are doubled, then the quote itself is escaped.
                    result.push_str(&"\\".repeat(backslashes * 2));
                    backslashes = 0;
                    result.push_str("\\\"");
                }
                _ => {
                    result.push_str(&"\\".repeat(backslashes));
                    backslashes = 0;
                    result.push(c);
                }
            }
        }
        result.push_str(&"\\".repeat(backslashes));
        if need_quote {
            // Trailing backslashes must be doubled so they do not escape the closing quote.
            result.push_str(&"\\".repeat(backslashes));
            result.push('"');
        }
    }
    result
}

// ---------------------------------------------------------------------------------------------------------------
// Running PowerShell
// ---------------------------------------------------------------------------------------------------------------

/// How a PowerShell script is run (the keyword arguments of `windows_run_ps`).
#[derive(Clone, Copy)]
pub struct PsOptions<'a> {
    /// Seconds the script may run; `None` means no limit.
    pub timeout: Option<Duration>,
    pub cancel: Option<&'a CancelToken>,
    /// A non-zero exit code is an error.
    pub check: bool,
}

impl Default for PsOptions<'_> {
    fn default() -> Self {
        PsOptions { timeout: Some(Duration::from_secs(POWERSHELL_TIMEOUT)), cancel: None, check: true }
    }
}

impl PsOptions<'_> {
    /// The defaults with another time limit (seconds).
    pub fn with_timeout(seconds: u64) -> Self {
        PsOptions { timeout: Some(Duration::from_secs(seconds)), ..Default::default() }
    }
}

/// `run_cmd` as the PowerShell runner needs it (injected so the argument building is testable).
type RunCmdFn<'a> = &'a dyn Fn(&[String], Log, bool, Option<Duration>, Option<&CancelToken>) -> Result<i32>;

/// The exact bytes of the temporary script file: the preamble and the script, CRLF line ends, behind a UTF-8 BOM
/// (PowerShell 5.1 reads UTF-8 only with it). A checkout that already turned LF into CRLF does not change the result.
fn script_bytes(script: &str) -> Vec<u8> {
    let text = format!("{WINDOWS_PS_PREAMBLE}{script}").replace("\r\n", "\n").replace('\n', "\r\n");
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(text.as_bytes());
    bytes
}

/// The command line that runs the script file `path` with `args` (`-File` mode: the values are data, never code).
fn powershell_command(powershell: &Path, path: &Path, args: &[String]) -> Vec<String> {
    let mut cmd: Vec<String> = [powershell.to_string_lossy().into_owned()]
        .into_iter()
        .chain(["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"].map(String::from))
        .collect();
    cmd.push(path.to_string_lossy().into_owned());
    cmd.extend(args.iter().cloned());
    cmd
}

/// Write `script` to a private temporary folder; dropping the returned folder removes it.
fn write_script(script: &str) -> Result<(tempfile::TempDir, PathBuf)> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("epmaps_");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700)); // like `mkdtemp`: owner only
    }
    let folder = builder.tempdir()?;
    let path = folder.path().join("script.ps1");
    std::fs::write(&path, script_bytes(script))?;
    Ok((folder, path))
}

/// `windows_run_ps` with the pieces injected: run a fixed PowerShell `script` (it starts with a typed `param()`
/// block) and stream its output to `log`. The values in `args` are handed over as command-line arguments, never
/// pasted into the text. Returns the runner's exit code.
fn run_ps_with(
    powershell: &Path,
    runner: RunCmdFn,
    script: &str,
    log: Log,
    args: &[String],
    opts: &PsOptions,
) -> Result<i32> {
    for a in args {
        if a.starts_with('-') {
            return Err(Error::value("Refusing an argument that PowerShell would read as a parameter name."));
        }
    }
    let (_folder, path) = write_script(script)?;
    let cmd = powershell_command(powershell, &path, args);
    runner(&cmd, log, opts.check, opts.timeout, opts.cancel)
    // `_folder` goes out of scope here: the temporary script is removed whatever happened.
}

/// `windows_run_ps(script, log, args, timeout, cancel_event, check)`: run a fixed PowerShell script as this
/// (elevated) process through `proc::run_cmd`.
pub fn run_ps(script: &str, log: Log, args: &[String], opts: &PsOptions) -> Result<i32> {
    fn runner(
        cmd: &[String],
        log: Log,
        check: bool,
        timeout: Option<Duration>,
        cancel: Option<&CancelToken>,
    ) -> Result<i32> {
        crate::proc::run_cmd(cmd, log, check, timeout, cancel)
    }
    run_ps_with(&powershell_exe(), &runner, script, log, args, opts)
}

/// The Python exception name for an I/O failure (what the error messages quote).
fn io_kind_name(e: &std::io::Error) -> &'static str {
    match e.kind() {
        std::io::ErrorKind::NotFound => "FileNotFoundError",
        std::io::ErrorKind::PermissionDenied => "PermissionError",
        _ => "OSError",
    }
}

fn quiet(cmd: &mut Command) {
    // No console window and an empty stdin for the children (the Python SUBPROCESS_QUIET).
    cmd.stdin(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
}

/// Run `cmd` to completion, capturing stdout and stderr; kill it when `timeout` passes. `Err` carries the Python
/// exception name (`TimeoutExpired`, `FileNotFoundError`...). `Ok` is `(success, stdout, stderr)`.
fn capture_with_timeout(
    cmd: &mut Command,
    timeout: Duration,
) -> std::result::Result<(bool, Vec<u8>, Vec<u8>), &'static str> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| io_kind_name(&e))?;
    // Both pipes are drained on their own threads so a chatty child can never block on a full pipe.
    let drain = |pipe: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut data = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut data);
            }
            data
        })
    };
    let out_reader = drain(child.stdout.take().map(|p| Box::new(p) as Box<dyn Read + Send>));
    let err_reader = drain(child.stderr.take().map(|p| Box::new(p) as Box<dyn Read + Send>));
    let deadline = Instant::now() + timeout;
    let outcome = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status.success()),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break Err("TimeoutExpired");
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(io_kind_name(&e));
            }
        }
    };
    let out = out_reader.join().unwrap_or_default();
    let err = err_reader.join().unwrap_or_default();
    outcome.map(|ok| (ok, out, err))
}

/// `windows_ps_output(script, args, timeout)`: run a fixed PowerShell script and return its standard output as text.
pub fn ps_output(script: &str, args: &[String], timeout: Duration) -> Result<String> {
    let (_folder, path) = write_script(script)?;
    let cmd_line = powershell_command(&powershell_exe(), &path, args);
    let (program, rest) = cmd_line.split_first().ok_or_else(|| Error::runtime("Could not run PowerShell."))?;
    let mut cmd = Command::new(program);
    cmd.args(rest);
    quiet(&mut cmd);
    let (ok, out, err) = capture_with_timeout(&mut cmd, timeout)
        .map_err(|kind| Error::runtime(format!("Could not run PowerShell ({kind}).")))?;
    if !ok {
        let stderr = String::from_utf8_lossy(&err);
        let detail = stderr.trim().lines().next().map(str::to_string);
        return Err(Error::runtime(format!(
            "PowerShell could not read the drives{}. Run the program as Administrator.",
            detail.map(|d| format!(": {d}")).unwrap_or_default()
        )));
    }
    // utf-8-sig: a leading BOM is not part of the text.
    let text = String::from_utf8_lossy(&out).into_owned();
    Ok(text.strip_prefix('\u{feff}').map(str::to_string).unwrap_or(text))
}

// ---------------------------------------------------------------------------------------------------------------
// The drive list
// ---------------------------------------------------------------------------------------------------------------

/// Python's `int(value)` on a JSON value: `Err` is the Python exception name.
fn py_int(v: &Value) -> std::result::Result<i64, &'static str> {
    match v {
        Value::Number(n) => {
            n.as_i64().or_else(|| n.as_f64().filter(|f| f.is_finite()).map(|f| f.trunc() as i64)).ok_or("ValueError")
        }
        Value::String(s) => s.trim().parse::<i64>().map_err(|_| "ValueError"),
        Value::Bool(b) => Ok(i64::from(*b)),
        _ => Err("TypeError"),
    }
}

/// `_as_int`: `None` when the value is missing or not a number.
fn as_int(v: Option<&Value>) -> Option<i64> {
    v.and_then(|v| py_int(v).ok())
}

/// Python's `str(value or "")`.
fn text_or_empty(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Bool(true)) => "True".to_string(),
        Some(Value::Number(n)) if n.as_f64() == Some(0.0) => String::new(),
        Some(other) => other.to_string(),
    }
}

/// `windows_parse_disks` with the outside world injected: turn the JSON of [`WINDOWS_LIST_SCRIPT`] into the drive
/// list (no I/O besides the audit lines). Only USB drives that do not hold the running Windows are offered; an
/// unreadable record is hidden (fail closed).
pub fn parse_disks_with(env: &dyn WinEnv, text: &str) -> Result<Vec<Disk>> {
    let trimmed = text.trim();
    let data: Value = serde_json::from_str(if trimmed.is_empty() { "[]" } else { trimmed })
        .map_err(|e| Error::value(format!("PowerShell returned a drive list that cannot be read: {e}")))?;
    let records = match data {
        Value::Array(items) => items,
        Value::Object(_) => vec![data],
        _ => return Err(Error::value("PowerShell returned a drive list in an unexpected format.")),
    };
    let mut disks = Vec::new();
    for rec in &records {
        match parse_record(env, rec) {
            Ok(Some(disk)) => disks.push(disk),
            Ok(None) => {}
            Err(kind) => {
                env.audit(&format!("Hiding a drive whose record could not be read ({kind})"), AuditLevel::Warning)
            }
        }
    }
    Ok(disks)
}

/// `windows_parse_disks(text)`.
pub fn parse_disks(text: &str) -> Result<Vec<Disk>> {
    parse_disks_with(&RealWinEnv, text)
}

/// One record of the drive list: `Ok(None)` hides it, `Err(kind)` (a Python exception name) hides an unreadable one.
fn parse_record(env: &dyn WinEnv, rec: &Value) -> std::result::Result<Option<Disk>, &'static str> {
    let obj = rec.as_object().ok_or("TypeError")?;
    let number = py_int(obj.get("Number").ok_or("KeyError")?)?;
    let size = as_int(obj.get("Size")).unwrap_or(0);
    let name = format!("PhysicalDrive{number}");
    if !WINDOWS_DEVICE_RE.is_match(&name) {
        return Ok(None);
    }
    if text_or_empty(obj.get("BusType")).to_uppercase() != "USB" {
        return Ok(None); // only USB drives are offered (no internal disks, SD slots, virtual disks)
    }
    if obj.get("HoldsSystem") != Some(&Value::Bool(false)) {
        env.audit(
            &format!("Hiding {name}: it holds the running Windows (or this could not be told)"),
            AuditLevel::Info,
        );
        return Ok(None);
    }
    let size = match u64::try_from(size) {
        Ok(n) if n > 0 => n,
        _ => {
            env.audit(&format!("Hiding {name}: its size is zero or unreadable"), AuditLevel::Warning);
            return Ok(None); // an empty card reader reports no media
        }
    };
    let model = text_or_empty(obj.get("Model")).trim().to_string();
    let raw_volumes = match obj.get("Volumes") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items.clone(),
        Some(single) if single.is_object() => vec![single.clone()],
        Some(_) => return Err("TypeError"),
    };
    let mut volumes = Vec::new();
    for vol in &raw_volumes {
        let vol = vol.as_object().ok_or("TypeError")?;
        let letter = text_or_empty(vol.get("Letter"));
        let free = as_int(vol.get("Free"));
        let vsize = as_int(vol.get("Size")).unwrap_or(0);
        let label = text_or_empty(vol.get("Label"));
        let shown_name = if !label.is_empty() {
            label
        } else if !letter.is_empty() {
            format!("{letter}:")
        } else {
            String::new()
        };
        volumes.push(Volume {
            name: Some(shown_name),
            filesystem: Some(text_or_empty(vol.get("FileSystem"))),
            size: Some(u64::try_from(vsize).unwrap_or(0)),
            used: match free {
                Some(f) if f >= 0 && vsize >= f => u64::try_from(vsize - f).ok(),
                _ => None,
            },
            mountpoint: (!letter.is_empty()).then(|| format!("{letter}:\\")),
        });
    }
    let text_of = |key: &str| match obj.get(key) {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(other) => Some(other.to_string()),
    };
    let identity = env.make_identity(&[
        ("serial", text_of("Serial")),
        ("uniqueid", text_of("UniqueId")),
        ("model", Some(model.clone())),
    ]);
    let model = (!model.is_empty()).then_some(model);
    Ok(Some(env.disk_entry(&name, size, model.as_deref(), Some(volumes), identity)))
}

/// `windows_get_external_disks()`: list only USB drives that do not hold the running Windows.
pub fn get_external_disks() -> Result<Vec<Disk>> {
    let text = ps_output(WINDOWS_LIST_SCRIPT, &[], Duration::from_secs(QUERY_TIMEOUT * 2))?;
    parse_disks(&text)
}

/// The disk number in `PhysicalDrive3` (the shape is checked here; the caller validated the name before).
pub fn parse_disk_number(dev: &str) -> Result<u32> {
    if WINDOWS_DEVICE_RE.is_match(dev) {
        if let Some(n) = dev.strip_prefix("PhysicalDrive").and_then(|digits| digits.parse::<u32>().ok()) {
            return Ok(n);
        }
    }
    Err(Error::value(format!(
        "Refusing to operate on {dev:?}: it is not a valid disk identifier. \
         Expected something like 'disk4' (macOS), 'sdb' (Linux) or 'PhysicalDrive3' (Windows)."
    )))
}

// ---------------------------------------------------------------------------------------------------------------
// The outside world of the backend
// ---------------------------------------------------------------------------------------------------------------

/// A failure of the drive itself: it refused or failed an open, read or write (as opposed to the image file).
/// `strerror` is what the messages quote; `code` is the Win32 error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveIoError {
    pub code: i32,
    pub strerror: String,
}

impl std::fmt::Display for DriveIoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[Errno {}] {}", self.code, self.strerror)
    }
}

impl std::error::Error for DriveIoError {}

/// What the raw loops can fail with: the drive ([`DriveIoError`]) or anything else (the image file, a cancel, ...).
#[derive(Debug)]
pub enum RawError {
    Drive(DriveIoError),
    Other(Error),
}

impl From<Error> for RawError {
    fn from(e: Error) -> Self {
        RawError::Other(e)
    }
}

impl From<std::io::Error> for RawError {
    fn from(e: std::io::Error) -> Self {
        RawError::Other(Error::Io(e))
    }
}

impl RawError {
    /// A drive failure that nobody handled specially is an `OSError`, like in the Python.
    pub fn into_error(self) -> Error {
        match self {
            RawError::Drive(e) => Error::Io(std::io::Error::other(e.to_string())),
            RawError::Other(e) => e,
        }
    }
}

/// Unbuffered, sector-aligned access to a physical drive (`WindowsRawDisk` on Windows; a file in the tests).
/// Offsets and lengths are multiples of [`WINDOWS_RAW_ALIGN`] and at most one block.
pub trait RawDisk {
    /// `length` bytes read from `offset` (fewer only at the end of the drive).
    fn read_at(&mut self, offset: u64, length: usize) -> std::result::Result<Vec<u8>, DriveIoError>;
    /// Write `data` at `offset`.
    fn write_at(&mut self, offset: u64, data: &[u8]) -> std::result::Result<(), DriveIoError>;
    /// Flush the device's cache (best effort).
    fn flush(&mut self);
}

/// What the Windows backend needs from the rest of the program and from Windows itself. [`RealWinEnv`] is the real
/// thing; the tests use a fake, which is how the whole flow (order of steps, cancel handling, markers) is checked
/// without PowerShell or a drive.
pub trait WinEnv {
    /// `audit(msg, level)`.
    fn audit(&self, msg: &str, level: AuditLevel);
    /// `make_identity(**parts)`.
    fn make_identity(&self, parts: &[(&str, Option<String>)]) -> Identity;
    /// `_disk_entry(...)`.
    fn disk_entry(
        &self,
        id: &str,
        size: u64,
        model: Option<&str>,
        volumes: Option<Vec<Volume>>,
        identity: Identity,
    ) -> Disk;
    /// `windows_disk_number(dev)`: validated, then the number in `PhysicalDrive3`.
    fn disk_number(&self, dev: &str) -> Result<u32>;
    /// `dev_path(dev)`: how the drive is shown (`\\.\PhysicalDrive3`).
    fn dev_path(&self, dev: &str) -> String;
    /// `validate_hybrid_iso(path)`.
    fn validate_hybrid_iso(&self, path: &Path) -> Result<()>;
    /// Run a fixed PowerShell script, streaming the output to `log`; returns the exit code.
    fn run_ps(&self, script: &str, log: Log, args: &[String], opts: &PsOptions) -> Result<i32>;
    /// `windows_wait_for_root(letter)`: the root path of the drive, once Windows lets us list it.
    fn wait_for_root(&self, letter: char, log: Log) -> Result<PathBuf>;
    /// `open_windows_raw_disk(number, write)`.
    fn open_raw_disk(&self, number: u32, write: bool) -> std::result::Result<Box<dyn RawDisk>, RawError>;
    /// `copy_windows_payload(...)`.
    fn copy_windows_payload(
        &self,
        src_root: &Path,
        dst_root: &Path,
        ctx: &Ctx,
        wimlib_hint: &str,
        reopen: Option<&dyn Fn() -> Result<PathBuf>>,
        extra_files: Option<&Files>,
    ) -> Result<()>;
    /// `copy_seed_files(...)`.
    fn copy_seed_files(&self, stage_dir: &Path, dst_root: &Path, files: &Files, ctx: &Ctx) -> Result<()>;
    /// `verify_seed_files(...)`.
    fn verify_seed_files(&self, files: &Files, dst_root: &Path, ctx: &Ctx) -> Result<()>;

    /// `windows_run_collect(...)`: [`WinEnv::run_ps`], also returning every output line (stripped) for the `EPMA_*`
    /// marker lines.
    fn run_collect(&self, script: &str, log: Log, args: &[String], opts: &PsOptions) -> Result<Vec<String>> {
        let seen = Mutex::new(Vec::<String>::new());
        let watch = |line: &str| {
            seen.lock().unwrap_or_else(|e| e.into_inner()).push(line.trim().to_string());
            log(line);
        };
        self.run_ps(script, &watch, args, opts)?;
        Ok(seen.into_inner().unwrap_or_else(|e| e.into_inner()))
    }
}

/// The real [`WinEnv`]: PowerShell through `proc::run_cmd`, the Win32 raw drive, and the other modules.
pub struct RealWinEnv;

impl WinEnv for RealWinEnv {
    fn audit(&self, msg: &str, level: AuditLevel) {
        crate::audit::audit_at(msg, level)
    }
    fn make_identity(&self, parts: &[(&str, Option<String>)]) -> Identity {
        crate::diskrisk::make_identity(parts)
    }
    fn disk_entry(
        &self,
        id: &str,
        size: u64,
        model: Option<&str>,
        volumes: Option<Vec<Volume>>,
        identity: Identity,
    ) -> Disk {
        crate::diskrisk::disk_entry(id, size, model, volumes, identity)
    }
    fn disk_number(&self, dev: &str) -> Result<u32> {
        crate::validate::validate_device_name(dev)?;
        parse_disk_number(dev)
    }
    fn dev_path(&self, dev: &str) -> String {
        crate::validate::dev_path(dev)
    }
    fn validate_hybrid_iso(&self, path: &Path) -> Result<()> {
        crate::validate::validate_hybrid_iso(path)
    }
    fn run_ps(&self, script: &str, log: Log, args: &[String], opts: &PsOptions) -> Result<i32> {
        run_ps(script, log, args, opts)
    }
    fn wait_for_root(&self, letter: char, _log: Log) -> Result<PathBuf> {
        wait_for_root_with(letter, WINDOWS_MOUNT_RETRIES, &|root| root.is_dir(), &|| {
            std::thread::sleep(Duration::from_secs(1))
        })
    }
    fn open_raw_disk(&self, number: u32, write: bool) -> std::result::Result<Box<dyn RawDisk>, RawError> {
        win32::open_raw_disk(number, write)
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
        crate::copyverify::copy_windows_payload(src_root, dst_root, ctx, wimlib_hint, reopen, extra_files)
    }
    fn copy_seed_files(&self, stage_dir: &Path, dst_root: &Path, files: &Files, ctx: &Ctx) -> Result<()> {
        crate::seed::copy_seed_files(stage_dir, dst_root, files, ctx)
    }
    fn verify_seed_files(&self, files: &Files, dst_root: &Path, ctx: &Ctx) -> Result<()> {
        crate::seed::verify_seed_files(files, dst_root, ctx)
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Output markers, volumes, eject, the mounted ISO
// ---------------------------------------------------------------------------------------------------------------

/// `_marker_values`: the words after `marker` on the first output line that starts with it, or `None`.
fn marker_values<'a>(lines: &'a [String], marker: &str) -> Option<Vec<&'a str>> {
    lines.iter().find_map(|line| {
        let mut words = line.split_whitespace();
        (words.next() == Some(marker)).then(|| words.collect())
    })
}

/// A word that is exactly one ASCII letter (`[A-Za-z]`), as a capital: a drive letter.
fn drive_letter(word: &str) -> Option<char> {
    let mut chars = word.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) if c.is_ascii_alphabetic() => Some(c.to_ascii_uppercase()),
        _ => None,
    }
}

/// `windows_wait_for_root` with the file system and the pause injected: the root path of drive `letter`, once
/// Windows lets us list it (up to `retries` looks, a pause between them).
fn wait_for_root_with(letter: char, retries: u32, is_dir: &dyn Fn(&Path) -> bool, pause: &dyn Fn()) -> Result<PathBuf> {
    let root = PathBuf::from(format!("{letter}:\\"));
    for _ in 0..retries {
        if is_dir(&root) {
            return Ok(root);
        }
        pause();
    }
    Err(Error::runtime(format!("Windows did not make the drive {letter}: available after formatting it.")))
}

/// `windows_prepare_fat32`: erase the disk and make GPT + one FAT32 volume. Returns (root path, partition number).
pub fn prepare_fat32(
    env: &dyn WinEnv,
    number: u32,
    label: &str,
    log: Log,
    cancel: Option<&CancelToken>,
) -> Result<(PathBuf, u32)> {
    let args = [number.to_string(), label.to_string(), WINDOWS_FAT32_MAX_PARTITION.to_string()];
    let opts = PsOptions { cancel, ..Default::default() };
    let lines = env.run_collect(WINDOWS_PREPARE_SCRIPT, log, &args, &opts)?;
    let found = marker_values(&lines, "EPMA_VOLUME").and_then(|vals| {
        let letter = drive_letter(vals.first()?)?;
        let digits = vals.get(1)?;
        if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        Some((letter, digits.parse::<u32>().ok()?))
    });
    let Some((letter, partition)) = found else {
        return Err(Error::runtime("Windows formatted the drive but did not report its drive letter."));
    };
    Ok((env.wait_for_root(letter, log)?, partition))
}

/// `windows_reopen_volume`: detach the volume and attach it again, so the read-back comes from the device. Returns
/// the new root path.
pub fn reopen_volume(env: &dyn WinEnv, number: u32, log: Log) -> Result<PathBuf> {
    let lines =
        env.run_collect(WINDOWS_DETACH_SCRIPT, log, &[number.to_string(), "1".to_string()], &PsOptions::default())?;
    let letter = marker_values(&lines, "EPMA_VOLUME").and_then(|vals| drive_letter(vals.first()?));
    let Some(letter) = letter else {
        return Err(Error::runtime("Could not mount the drive again to read it back."));
    };
    env.wait_for_root(letter, log)
}

/// `windows_eject`: flush and detach every volume of the disk; after that the drive can be unplugged. True on
/// success.
pub fn eject_disk(env: &dyn WinEnv, number: u32, log: Log) -> bool {
    log("Ejecting the USB drive...");
    let args = [number.to_string(), "0".to_string()];
    match env.run_collect(WINDOWS_DETACH_SCRIPT, log, &args, &PsOptions::with_timeout(120)) {
        Ok(lines) => lines.iter().any(|l| l == EJECTED_MARKER),
        Err(e) => {
            log(&format!("Warning: could not run the eject step: {e}"));
            false
        }
    }
}

/// Dismounts the ISO when dropped (only armed when this program mounted it).
struct DismountGuard<'a> {
    env: &'a dyn WinEnv,
    log: Log<'a>,
    iso: String,
    armed: bool,
}

impl Drop for DismountGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            // contextlib.suppress(Exception): a failed dismount must not hide the real result.
            let opts = PsOptions { check: false, ..PsOptions::with_timeout(120) };
            let _ = self.env.run_ps(WINDOWS_ISO_DISMOUNT_SCRIPT, self.log, std::slice::from_ref(&self.iso), &opts);
        }
    }
}

/// `windows_mounted_iso(iso_path, log)` as a closure API: mount the ISO read-only, call `f` with its root (for
/// example `F:\`), dismount it afterwards (only if we mounted it, and also after an error).
pub fn with_mounted_iso_env<T>(
    env: &dyn WinEnv,
    iso_path: &Path,
    log: Log,
    f: impl FnOnce(&Path) -> Result<T>,
) -> Result<T> {
    let iso = iso_path.to_string_lossy().into_owned();
    let lines =
        env.run_collect(WINDOWS_ISO_MOUNT_SCRIPT, log, std::slice::from_ref(&iso), &PsOptions::with_timeout(300))?;
    let mounted = marker_values(&lines, "EPMA_ISO").and_then(|vals| {
        let letter = drive_letter(vals.first()?)?;
        Some((letter, vals.get(1) == Some(&"1")))
    });
    let Some((letter, already)) = mounted else {
        return Err(Error::runtime("Could not mount the ISO."));
    };
    let _guard = DismountGuard { env, log, iso, armed: !already };
    f(Path::new(&format!("{letter}:\\")))
}

/// `windows_mounted_iso(iso_path, log)`: mount the ISO read-only, call `f` with its root (for example `F:\`),
/// dismount it afterwards (only if we mounted it).
pub fn with_mounted_iso<T>(iso_path: &Path, log: Log, f: impl FnOnce(&Path) -> Result<T>) -> Result<T> {
    with_mounted_iso_env(&RealWinEnv, iso_path, log, f)
}

// ---------------------------------------------------------------------------------------------------------------
// Byte-for-byte writes to \\.\PhysicalDriveN (Linux and other hybrid ISOs, ChromeOS Flex)
// ---------------------------------------------------------------------------------------------------------------

/// `_align_up(n)`: the next multiple of [`WINDOWS_RAW_ALIGN`].
fn align_up(n: u64) -> u64 {
    n.div_ceil(WINDOWS_RAW_ALIGN) * WINDOWS_RAW_ALIGN
}

/// Read until `buf` is full or the file ends (Python's buffered `read(n)`); returns the bytes read.
fn read_fill(src: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match src.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Lets a progress report through at most every `interval`, and always when `force` is set.
struct Throttle {
    interval: Duration,
    last: Option<Instant>,
}

impl Throttle {
    fn new(seconds: f64) -> Self {
        Throttle { interval: Duration::from_secs_f64(seconds), last: None }
    }
    fn should_report(&mut self, force: bool) -> bool {
        let due = self.last.is_none_or(|t| t.elapsed() >= self.interval);
        if due || force {
            self.last = Some(Instant::now());
            true
        } else {
            false
        }
    }
}

/// `windows_raw_write`: write the image to `disk` byte for byte. Returns the image size.
///
/// The first [`WINDOWS_RAW_HEAD`] bytes (where the partition tables live) are written LAST. Until then the drive has
/// no partitions, so Windows cannot mount (and thereby lock) the volumes of the half-written image and refuse the
/// rest of the writes. A cancel before the end therefore leaves a drive with no partition table at all. The last
/// block is padded with zeros up to the sector size. `block` must be a multiple of [`WINDOWS_RAW_ALIGN`].
pub fn raw_write(iso_path: &Path, disk: &mut dyn RawDisk, ctx: &Ctx, block: u64) -> std::result::Result<u64, RawError> {
    let total = std::fs::metadata(iso_path)?.len();
    let head = WINDOWS_RAW_HEAD.min(total);
    let mut throttle = Throttle::new(PROGRESS_UI_INTERVAL);
    let mut report = |done: u64| {
        if throttle.should_report(done >= total) {
            ctx.report(done.min(total), total, "Writing the image...");
        }
    };

    let mut src = File::open(iso_path)?;
    let mut head_data = vec![0u8; head as usize];
    let got = read_fill(&mut src, &mut head_data)?;
    head_data.truncate(got);
    let mut offset = head;
    src.seek(SeekFrom::Start(head))?;
    let mut buf = vec![0u8; block as usize];
    while offset < total {
        ctx.check_canceled(true, false)?;
        let want = block.min(total - offset) as usize;
        let n = read_fill(&mut src, &mut buf[..want])?;
        if n == 0 {
            return Err(Error::runtime("The image ended earlier than its size said. Nothing more was written.").into());
        }
        let padded = align_up(n as u64) as usize;
        buf[n..padded].fill(0);
        disk.write_at(offset, &buf[..padded]).map_err(RawError::Drive)?;
        offset += n as u64;
        report(offset);
    }
    ctx.check_canceled(true, false)?;
    head_data.resize(align_up(head_data.len() as u64) as usize, 0);
    disk.write_at(0, &head_data).map_err(RawError::Drive)?;
    disk.flush();
    report(total);
    Ok(total)
}

/// `windows_raw_verify`: read the drive back and compare it with the image. Fails on any difference (same wording as
/// elsewhere).
pub fn raw_verify(
    iso_path: &Path,
    disk: &mut dyn RawDisk,
    ctx: &Ctx,
    block: u64,
    audit: &dyn Fn(&str, AuditLevel),
) -> std::result::Result<(), RawError> {
    let total = std::fs::metadata(iso_path)?.len();
    ctx.log("Verifying the written image: reading the drive back and comparing it with the ISO...");
    let mut throttle = Throttle::new(VERIFY_PROGRESS_INTERVAL);
    let mut src = File::open(iso_path)?;
    let mut want_buf = vec![0u8; block as usize];
    let mut offset = 0u64;
    while offset < total {
        ctx.check_canceled(true, true)?;
        let want_len = block.min(total - offset) as usize;
        let n = read_fill(&mut src, &mut want_buf[..want_len])?;
        if n == 0 {
            return Err(Error::runtime("The image ended earlier than its size said.").into());
        }
        let want = &want_buf[..n];
        let mut got = disk.read_at(offset, align_up(n as u64) as usize).map_err(RawError::Drive)?;
        got.truncate(n);
        if got != want {
            let first = got.iter().zip(want).position(|(x, y)| x != y).unwrap_or(got.len().min(want.len()));
            let at = offset + first as u64;
            audit(&format!("VERIFICATION FAILED at byte {at}"), AuditLevel::Error);
            return Err(Error::runtime(format!(
                "Verification FAILED: the data on the drive differs from the ISO (first difference near byte {at}).\n\n\
                 The drive was NOT ejected and should not be used. \
                 Try again, and if it fails again, the USB drive or its port may be faulty."
            ))
            .into());
        }
        offset += n as u64;
        if throttle.should_report(offset >= total) {
            ctx.report(offset.min(total), total, "Verifying the written image...");
        }
    }
    audit("Verification passed (raw write matches the ISO)", AuditLevel::Info);
    ctx.log("Verification passed: the drive content is identical to the ISO.");
    Ok(())
}

/// `windows_write_raw` with the outside world injected: write the ISO byte-for-byte to the whole disk (Linux, other
/// hybrid ISOs, ChromeOS Flex). `Ok(ejected)`.
pub fn write_raw_env(env: &dyn WinEnv, iso_path: &Path, dev: &str, ctx: &Ctx, eject: bool) -> Result<bool> {
    env.validate_hybrid_iso(iso_path)?;
    ctx.check_canceled(false, false)?;
    let number = env.disk_number(dev)?;
    let total = std::fs::metadata(iso_path)?.len();
    ctx.log(&format!("Erasing {} (administrator privileges required)...", env.dev_path(dev)));
    let opts = PsOptions { cancel: ctx.cancel, ..Default::default() };
    env.run_collect(WINDOWS_PREPARE_RAW_SCRIPT, ctx.log, &[number.to_string()], &opts)?;
    ctx.check_canceled(false, false)?; // clearing the partition table is not a write of the image
    ctx.log(&format!("Writing the ISO to {}. This can take several minutes.", env.dev_path(dev)));
    let written = (|| -> std::result::Result<u64, RawError> {
        let mut disk = env.open_raw_disk(number, true)?;
        raw_write(iso_path, &mut *disk, ctx, WINDOWS_RAW_BLOCK)
        // the handle is closed here
    })();
    match written {
        Ok(_) => {}
        Err(RawError::Drive(e)) => {
            return Err(Error::runtime(format!(
                "Windows refused the write to {} ({}). Close any program that is using the drive (File Explorer \
                 windows, antivirus scans), unplug it and plug it in again, then try again.",
                env.dev_path(dev),
                e.strerror
            )));
        }
        Err(RawError::Other(e)) => {
            if e.is_canceled() {
                ctx.log("Canceled. The drive holds a partial image and is unusable until written again.");
            }
            return Err(e);
        }
    }
    ctx.report(total, total, "Written");
    {
        let mut disk = env.open_raw_disk(number, false).map_err(RawError::into_error)?;
        let audit = |msg: &str, level: AuditLevel| env.audit(msg, level);
        raw_verify(iso_path, &mut *disk, ctx, WINDOWS_RAW_BLOCK, &audit).map_err(RawError::into_error)?;
    }
    ctx.log(
        "Note: Windows cannot read Linux or ChromeOS partitions (ext4 and others), so it may offer to format the \
         drive - click Cancel, never Format. That is normal; the content was just verified byte-for-byte.",
    );
    let ejected = eject && eject_disk(env, number, ctx.log);
    ctx.log("Done! The USB drive is ready to boot.");
    report_eject(ejected, ctx.log, !eject);
    Ok(ejected)
}

/// `windows_write_raw(iso_path, dev, ...)`: write a Linux / ChromeOS image byte for byte. `Ok(ejected)`.
pub fn write_raw(iso_path: &Path, dev: &str, ctx: &Ctx, eject: bool) -> Result<bool> {
    write_raw_env(&RealWinEnv, iso_path, dev, ctx, eject)
}

// ---------------------------------------------------------------------------------------------------------------
// Windows 11 mode and the seed drive
// ---------------------------------------------------------------------------------------------------------------

/// What to log when the user cancels after the drive was touched (and then eject it).
fn log_canceled_and_eject(env: &dyn WinEnv, e: &Error, number: u32, log: Log) {
    if let Error::Canceled { written, .. } = e {
        if *written {
            log("Canceled during verification. The files were copied completely but NOT verified.");
        } else {
            log("Canceled. The drive is left incomplete and unusable.");
        }
        eject_disk(env, number, log);
    }
}

/// `windows_build_usb` with the outside world injected: Windows 11 mode, GPT + FAT32, the ISO's files copied
/// (`install.wim` split with DISM when over 4 GB) and read back. `Ok(ejected)`.
pub fn build_usb_env(
    env: &dyn WinEnv,
    iso_path: &Path,
    dev: &str,
    ctx: &Ctx,
    eject: bool,
    hardening_files: Option<&Files>,
) -> Result<bool> {
    ctx.check_canceled(false, false)?; // nothing has been changed yet
    let number = env.disk_number(dev)?;
    // Read-only and harmless: any problem with the ISO shows up BEFORE the erase.
    with_mounted_iso_env(env, iso_path, ctx.log, |iso_root| {
        ctx.check_canceled(false, false)?;
        ctx.log(&format!("Erasing and formatting {} as GPT + FAT32 ('{VOL_NAME}')...", env.dev_path(dev)));
        let (target, _partition) = prepare_fat32(env, number, VOL_NAME, ctx.log, ctx.cancel)?;
        ctx.log(&format!("USB drive ready at: {}", target.display()));
        let copied = (|| -> Result<()> {
            ctx.check_canceled(true, false)?;
            let reopen = || -> Result<PathBuf> {
                ctx.log("Detaching and attaching the drive again to read it back from the device...");
                reopen_volume(env, number, ctx.log)
            };
            let extra = hardening_files.filter(|f| !f.is_empty());
            env.copy_windows_payload(iso_root, &target, ctx, ESD_HINT, Some(&reopen), extra)
        })();
        if let Err(e) = &copied {
            log_canceled_and_eject(env, e, number, ctx.log);
        }
        copied
    })?;
    let ejected = eject && eject_disk(env, number, ctx.log);
    ctx.log("Done! The USB drive is ready to install Windows 11.");
    report_eject(ejected, ctx.log, !eject);
    Ok(ejected)
}

/// `windows_build_usb(...)`: Windows 11 mode, GPT + FAT32. `Ok(ejected)`. Nothing is asked of `priv_` (the process
/// is already elevated or it is not).
pub fn build_usb(
    iso_path: &Path,
    dev: &str,
    ctx: &Ctx,
    _priv: &dyn Privilege,
    eject: bool,
    hardening_files: Option<&Files>,
) -> Result<bool> {
    build_usb_env(&RealWinEnv, iso_path, dev, ctx, eject, hardening_files)
}

/// `windows_build_seed_usb` with the outside world injected: the hardening seed drive (GPT + FAT32 with `label`,
/// `files` copied from `stage_dir`, read back through a remount). `Ok(ejected)`.
pub fn build_seed_usb_env(
    env: &dyn WinEnv,
    label: &str,
    files: &Files,
    stage_dir: &Path,
    dev: &str,
    ctx: &Ctx,
    eject: bool,
) -> Result<bool> {
    ctx.check_canceled(false, false)?; // nothing has been changed yet
    let number = env.disk_number(dev)?;
    ctx.log(&format!("Erasing and formatting {} as GPT + FAT32 ('{label}')...", env.dev_path(dev)));
    let done = (|| -> Result<()> {
        let (target, _partition) = prepare_fat32(env, number, label, ctx.log, ctx.cancel)?;
        ctx.log(&format!("USB drive ready at: {}", target.display()));
        ctx.check_canceled(true, false)?;
        env.copy_seed_files(stage_dir, &target, files, ctx)?;
        ctx.log("Detaching and attaching the drive again to read it back from the device...");
        let target = reopen_volume(env, number, ctx.log)?;
        env.verify_seed_files(files, &target, ctx)
    })();
    if let Err(e) = done {
        log_canceled_and_eject(env, &e, number, ctx.log);
        return Err(e);
    }
    let ejected = eject && eject_disk(env, number, ctx.log);
    ctx.log("Done! The seed drive is ready: plug it in next to the installer USB drive.");
    report_eject(ejected, ctx.log, !eject);
    Ok(ejected)
}

/// `windows_build_seed_usb(...)`. `Ok(ejected)`.
pub fn build_seed_usb(label: &str, files: &Files, stage_dir: &Path, dev: &str, ctx: &Ctx, eject: bool) -> Result<bool> {
    build_seed_usb_env(&RealWinEnv, label, files, stage_dir, dev, ctx, eject)
}

/// `windows_eject(number, log)` for a device id such as `PhysicalDrive3`: flush and detach every volume. True on
/// success.
pub fn eject(dev: &str, log: Log) -> bool {
    match parse_disk_number(dev) {
        Ok(number) => eject_disk(&RealWinEnv, number, log),
        Err(e) => {
            log(&format!("Warning: could not run the eject step: {e}"));
            false
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Win32 (the only platform-specific code)
// ---------------------------------------------------------------------------------------------------------------

#[cfg(windows)]
mod win32 {
    //! Small and careful: IsUserAnAdmin, ShellExecuteW "runas", SetProcessDpiAwareness, and the raw PhysicalDrive
    //! handle. The raw drive is opened through `std::fs::OpenOptions` with `FILE_FLAG_NO_BUFFERING |
    //! FILE_FLAG_WRITE_THROUGH`, so there is no hand-written `CreateFileW` / `ReadFile` / `WriteFile`.

    use super::{list2cmdline, DriveIoError, RawDisk, RawError, WINDOWS_RAW_ALIGN, WINDOWS_RAW_BLOCK};
    use std::ffi::OsStr;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_NO_BUFFERING, FILE_FLAG_WRITE_THROUGH, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    use windows_sys::Win32::UI::HiDpi::{SetProcessDpiAwareness, PROCESS_SYSTEM_DPI_AWARE};
    use windows_sys::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
    use windows_sys::Win32::UI::WindowsAndMessaging::{SetProcessDPIAware, SW_SHOWNORMAL};

    /// True when the process runs elevated.
    pub fn is_admin() -> bool {
        // SAFETY: IsUserAnAdmin takes no arguments and only reads the process token.
        unsafe { IsUserAnAdmin() != 0 }
    }

    /// NUL-terminated UTF-16 for the Win32 "W" functions.
    fn wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Start this program again with the UAC prompt. True if Windows accepted the request.
    pub fn relaunch_elevated() -> bool {
        let Ok(exe) = std::env::current_exe() else {
            return false;
        };
        let args: Vec<String> = std::env::args_os().skip(1).map(|a| a.to_string_lossy().into_owned()).collect();
        let verb = wide(OsStr::new("runas"));
        let file = wide(exe.as_os_str());
        let params = wide(OsStr::new(&list2cmdline(&args)));
        // SAFETY: every pointer is a NUL-terminated UTF-16 buffer that outlives the call (`verb`, `file`, `params`);
        // the window handle and the working directory are null, which ShellExecuteW documents as "none".
        let result = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_ptr(),
                file.as_ptr(),
                params.as_ptr(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        };
        // ShellExecute reports success with a value greater than 32 (it is an HINSTANCE only for historical reasons).
        (result as usize) > 32
    }

    /// Ask Windows not to bitmap-scale the window. Cosmetic: failures are ignored.
    pub fn enable_dpi_awareness() {
        // E_ACCESSDENIED means the awareness was already fixed (by a manifest or an earlier call): nothing to do.
        const E_ACCESSDENIED: i32 = 0x8007_0005_u32 as i32;
        // SAFETY: both functions take plain integers / nothing and have no preconditions.
        unsafe {
            let hr = SetProcessDpiAwareness(PROCESS_SYSTEM_DPI_AWARE);
            if hr < 0 && hr != E_ACCESSDENIED {
                SetProcessDPIAware();
            }
        }
    }

    fn drive_error(e: &std::io::Error, what: String) -> DriveIoError {
        DriveIoError { code: e.raw_os_error().unwrap_or(0), strerror: what }
    }

    /// Unbuffered, sector-aligned access to a physical drive. Reads and writes go straight to the device
    /// (`FILE_FLAG_NO_BUFFERING`), writes are write-through, so what a read returns is what the drive holds, not
    /// what the system cache remembers. Offsets and lengths must be multiples of [`WINDOWS_RAW_ALIGN`]. The buffer
    /// that reaches the device is page-aligned: a slice of an over-allocated `Vec`.
    pub struct WindowsRawDisk {
        file: File,
        buf: Vec<u8>,
        /// Where the aligned part of `buf` starts.
        start: usize,
        block: usize,
    }

    impl WindowsRawDisk {
        /// Open `path` (for example `\\.\PhysicalDrive3`). The share mode lets Windows keep its own handles.
        pub fn open(path: &str, write: bool, block: usize) -> Result<Self, DriveIoError> {
            let mut flags = FILE_FLAG_NO_BUFFERING;
            if write {
                flags |= FILE_FLAG_WRITE_THROUGH;
            }
            let file = OpenOptions::new()
                .read(true)
                .write(write)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(flags)
                .open(path)
                .map_err(|e| drive_error(&e, format!("Could not open {path}")))?;
            let buf = vec![0u8; block + WINDOWS_RAW_ALIGN as usize];
            // `align_offset` on a byte pointer always succeeds, and the extra ALIGN bytes make room for it.
            let start = buf.as_ptr().align_offset(WINDOWS_RAW_ALIGN as usize);
            Ok(WindowsRawDisk { file, buf, start, block })
        }

        fn seek(&mut self, offset: u64) -> Result<(), DriveIoError> {
            self.file
                .seek(SeekFrom::Start(offset))
                .map(|_| ())
                .map_err(|e| drive_error(&e, format!("Could not move to offset {offset}")))
        }
    }

    impl RawDisk for WindowsRawDisk {
        fn read_at(&mut self, offset: u64, length: usize) -> Result<Vec<u8>, DriveIoError> {
            if length > self.block {
                return Err(DriveIoError { code: 0, strerror: format!("Could not read the drive at offset {offset}") });
            }
            self.seek(offset)?;
            let (start, end) = (self.start, self.start + length);
            let got = self
                .file
                .read(&mut self.buf[start..end])
                .map_err(|e| drive_error(&e, format!("Could not read the drive at offset {offset}")))?;
            Ok(self.buf[start..start + got].to_vec())
        }

        fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), DriveIoError> {
            let failed =
                |code: i32| DriveIoError { code, strerror: format!("Could not write to the drive at offset {offset}") };
            if data.len() > self.block {
                return Err(failed(0));
            }
            self.seek(offset)?;
            let (start, end) = (self.start, self.start + data.len());
            self.buf[start..end].copy_from_slice(data);
            match self.file.write(&self.buf[start..end]) {
                Ok(put) if put == data.len() => Ok(()),
                Ok(_) => Err(failed(0)),
                Err(e) => Err(failed(e.raw_os_error().unwrap_or(0))),
            }
        }

        fn flush(&mut self) {
            // FlushFileBuffers; the Python ignores its result as well.
            let _ = self.file.sync_all();
        }
    }

    /// `open_windows_raw_disk(number, write)`: open `\\.\PhysicalDrive<number>`.
    pub fn open_raw_disk(number: u32, write: bool) -> Result<Box<dyn RawDisk>, RawError> {
        let path = format!("\\\\.\\PhysicalDrive{number}");
        let disk = WindowsRawDisk::open(&path, write, WINDOWS_RAW_BLOCK as usize).map_err(RawError::Drive)?;
        Ok(Box::new(disk))
    }
}

#[cfg(not(windows))]
mod win32 {
    //! Every Win32 call has a stand-in on the other systems: they report "not elevated" or an error.

    use super::{Error, RawDisk, RawError};

    pub fn is_admin() -> bool {
        false
    }

    pub fn relaunch_elevated() -> bool {
        false
    }

    pub fn enable_dpi_awareness() {}

    pub fn open_raw_disk(_number: u32, _write: bool) -> Result<Box<dyn RawDisk>, RawError> {
        Err(RawError::Other(Error::runtime("Raw access to a physical drive is only available on Windows.")))
    }
}

#[cfg(test)]
mod tests;
