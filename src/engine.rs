//! The engine: the safety checks and the dispatcher between the platform backends. OWNER: A2.
//! Port of win11_usb_creator.py lines 2289-2299 (pin_target_identity), 3768-3947 (hardening files on the image:
//! validate_hardening ... refuse_hardening_clash, LINUX_ISO_PEEK_* scripts, get_external_disks), 3948-4127
//! (reverify_target_disk, hash_iso_for_audit, missing_dependencies_hint, validate_image_for_mode, build_usb,
//! needs_admin, image_exceeds_drive) and 5919-5948 (chromeos_drive_too_small, windows_missing_tools,
//! get_missing_dependencies).
//!
//! # Dispatch and testing
//!
//! Everything the engine hands to a backend or asks of the operating system goes through the `EngineOps` trait. Its
//! provided methods ARE the dispatch (macOS / Windows / Linux backends, `proc`, `validate`, `hash`...): `SystemOps`
//! is the empty implementation the program uses, and the free functions without a suffix (`build_usb`,
//! `reverify_target_disk`, `get_missing_dependencies`...) are `<name>_on(&SystemOps, ...)`. The Python tests replace
//! module functions with `mock.patch`; the Rust tests implement `EngineOps` and override the methods they fake. The
//! order of the steps of `build_usb_on` (what is validated, hashed and re-checked before the drive is touched) is
//! the part to review.

use crate::audit::{audit_at, AuditLevel};
use crate::constants::{CHROMEOS_MIN_USB_BYTES, DISKUTIL_TIMEOUT, LINUX_REQUIRED_TOOLS};
use crate::diskrisk::{identity_mismatch, py_repr, py_repr_list};
use crate::hash::sha256_file;
use crate::types::{
    BuildOptions, CancelToken, Ctx, Disk, Error, Files, Hardening, Identity, Log, Mode, Privilege, Result,
};
use crate::util::{human_size, silent_rmdir};
use crate::validate::{dev_path, validate_device_name, validate_disk_image, validate_hybrid_iso, validate_iso_path};
use crate::{harden_windows, linux, macos, seed, windows};
use std::any::Any;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

// ---------------------------------------------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------------------------------------------

thread_local! {
    /// Audit lines captured instead of written (see `capture_audit`).
    static AUDIT_CAPTURE: RefCell<Option<Vec<(String, AuditLevel)>>> = const { RefCell::new(None) };
}

/// One line of the audit trail (`audit(msg, level)`). Every audit line of the engine, the privilege helpers and the
/// copy / verify code goes through here so the tests can look at them.
pub fn audit_event(msg: &str, level: AuditLevel) {
    let captured = AUDIT_CAPTURE.with(|c| match c.borrow_mut().as_mut() {
        Some(lines) => {
            lines.push((msg.to_string(), level));
            true
        }
        None => false,
    });
    if !captured {
        audit_at(msg, level);
    }
}

/// Run `f` and return its result with every audit line the engine wrote on this thread meanwhile (nothing reaches
/// the real audit log during the call). For tests; the Python tests patch `app.audit` the same way.
pub fn capture_audit<R>(f: impl FnOnce() -> R) -> (R, Vec<(String, AuditLevel)>) {
    let previous = AUDIT_CAPTURE.with(|c| c.replace(Some(Vec::new())));
    let result = f();
    let lines = AUDIT_CAPTURE.with(|c| c.replace(previous)).unwrap_or_default();
    (result, lines)
}

/// `shutil.which(name)`: the first executable file called `name` on PATH (or `name` itself when it has a directory).
pub fn which_tool(name: &str) -> Option<PathBuf> {
    fn is_executable(path: &Path) -> bool {
        let Ok(meta) = fs::metadata(path) else {
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
    fn candidates(base: PathBuf) -> Vec<PathBuf> {
        let mut out = vec![base.clone()];
        if cfg!(windows) {
            let exts = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
            for ext in exts.split(';').filter(|e| !e.is_empty()) {
                let mut s = base.clone().into_os_string();
                s.push(ext);
                out.push(PathBuf::from(s));
            }
        }
        out
    }
    if name.is_empty() {
        return None;
    }
    if name.contains('/') || (cfg!(windows) && name.contains('\\')) {
        return candidates(PathBuf::from(name)).into_iter().find(|p| is_executable(p));
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for candidate in candidates(dir.join(name)) {
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

/// `e.strerror` of an `OSError`: the system's message without Rust's " (os error N)" suffix; "OSError" (the Python
/// class name, the fallback of the Python code) when the error carries no system message.
pub fn os_strerror(e: &std::io::Error) -> String {
    if e.raw_os_error().is_some() {
        let text = e.to_string();
        if let Some(i) = text.rfind(" (os error ") {
            return text[..i].to_string();
        }
        return text;
    }
    "OSError".to_string()
}

/// `type(e).__name__` of the Python exception an `Error` stands for (what the audit line records).
fn py_error_name(e: &Error) -> &'static str {
    match e {
        Error::Runtime(_) => "RuntimeError",
        Error::Value(_) => "ValueError",
        Error::Canceled { .. } => "OperationCanceled",
        Error::Io(io) => match io.kind() {
            std::io::ErrorKind::NotFound => "FileNotFoundError",
            std::io::ErrorKind::PermissionDenied => "PermissionError",
            std::io::ErrorKind::AlreadyExists => "FileExistsError",
            _ => "OSError",
        },
    }
}

/// `os.path.realpath(path)` for a path whose tail may not exist yet: the existing part is resolved (symbolic links
/// included), the rest is appended as it is. `None` when a symbolic link on the way points nowhere: nothing may be
/// written through a link that cannot be resolved.
fn realpath_lenient(path: &Path) -> Option<PathBuf> {
    let mut tail: Vec<OsString> = Vec::new();
    let mut current = path.to_path_buf();
    loop {
        match fs::canonicalize(&current) {
            Ok(mut real) => {
                real.extend(tail.iter().rev());
                return Some(real);
            }
            Err(_) => {
                let dangling = fs::symlink_metadata(&current).map(|m| m.file_type().is_symlink()).unwrap_or(false);
                if dangling {
                    return None;
                }
                match (current.file_name().map(OsString::from), current.parent().map(Path::to_path_buf)) {
                    (Some(name), Some(parent)) => {
                        tail.push(name);
                        current = parent;
                    }
                    _ => return Some(path.to_path_buf()),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The seams
// ---------------------------------------------------------------------------------------------------------------

/// The operating system the engine runs on (`IS_MAC` / `IS_WINDOWS` / otherwise Linux).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    Mac,
    Linux,
    Windows,
}

impl Os {
    pub fn current() -> Os {
        if crate::constants::IS_WINDOWS {
            Os::Windows
        } else if crate::constants::IS_MAC {
            Os::Mac
        } else {
            Os::Linux
        }
    }
}

/// What the engine hands to the backends and asks of the system. The provided methods are the real dispatch.
pub trait EngineOps {
    fn os(&self) -> Os {
        Os::current()
    }
    /// `shutil.which(tool)`.
    fn which(&self, tool: &str) -> bool {
        which_tool(tool).is_some()
    }
    /// `os.path.isfile(path)`.
    fn is_file(&self, path: &Path) -> bool {
        path.is_file()
    }
    fn powershell_exe(&self) -> PathBuf {
        windows::powershell_exe()
    }
    fn dism_exe(&self) -> PathBuf {
        windows::dism_exe()
    }
    /// `get_external_disks()`: the OS-specific listing.
    fn list_disks(&self) -> Result<Vec<Disk>> {
        match self.os() {
            Os::Mac => macos::get_external_disks(),
            Os::Windows => windows::get_external_disks(),
            Os::Linux => linux::get_external_disks(),
        }
    }
    /// `linux_build_install_command(linux_detect_pkg_manager(), missing)`.
    fn install_command(&self, missing: &[String]) -> Result<String> {
        linux::build_install_command(linux::detect_pkg_manager().as_deref(), missing)
    }
    fn missing_dependencies(&self, mode: Mode) -> Vec<String> {
        get_missing_dependencies_on(self, mode)
    }
    fn validate_image(&self, iso_path: &Path, mode: Mode, expected_size: Option<u64>) -> Result<PathBuf> {
        validate_image_for_mode_on(self, iso_path, mode, expected_size)
    }
    fn hash_iso(&self, iso_path: &Path, ctx: &Ctx) -> Result<String> {
        hash_iso_for_audit(iso_path, ctx)
    }
    fn reverify(
        &self,
        dev: &str,
        expected_size: Option<u64>,
        log: Log,
        expected_identity: Option<&Identity>,
    ) -> Result<()> {
        reverify_target_disk_on(self, dev, expected_size, log, expected_identity)
    }
    fn refuse_clash(&self, iso_path: &Path, files: &Files, ctx: &Ctx, priv_: &dyn Privilege) -> Result<()> {
        refuse_hardening_clash_on(self, iso_path, files, ctx, priv_)
    }
    /// `hardening_files_windows(profile)` (harden_windows.rs).
    fn hardening_files(&self, profile: Hardening) -> Result<Files> {
        harden_windows::hardening_files_windows(profile)
    }
    /// `validate_seed_files(files)` (seed.rs).
    fn validate_files(&self, files: &Files) -> Result<Files> {
        seed::validate_seed_files(files)
    }
    /// `prevent_sleep(log)`: hold the returned guard for the whole operation.
    fn prevent_sleep(&self, log: Log) -> Box<dyn Any> {
        Box::new(crate::proc::prevent_sleep(log))
    }
    /// The byte-for-byte modes (Linux, ChromeOS) per OS.
    fn write_raw(&self, iso_path: &Path, dev: &str, ctx: &Ctx, priv_: &dyn Privilege, eject: bool) -> Result<bool> {
        match self.os() {
            Os::Mac => macos::write_raw(iso_path, dev, ctx, priv_, eject),
            Os::Windows => windows::write_raw(iso_path, dev, ctx, eject),
            Os::Linux => linux::write_raw(iso_path, dev, ctx, priv_, eject),
        }
    }
    /// The Windows mode (copy the ISO's files onto a FAT32 drive) per OS. `hardening_files`: the extra files.
    fn build_windows_usb(
        &self,
        iso_path: &Path,
        dev: &str,
        ctx: &Ctx,
        priv_: &dyn Privilege,
        eject: bool,
        hardening_files: Option<&Files>,
    ) -> Result<bool> {
        match self.os() {
            Os::Mac => macos::build_usb(iso_path, dev, ctx, eject, hardening_files),
            Os::Windows => windows::build_usb(iso_path, dev, ctx, priv_, eject, hardening_files),
            Os::Linux => linux::build_usb(iso_path, dev, ctx, priv_, eject, hardening_files),
        }
    }
    /// `run_cmd(args, log, check=..., timeout=..., cancel_event=...)`.
    fn run_cmd(
        &self,
        args: &[String],
        log: Log,
        check: bool,
        timeout: Option<Duration>,
        cancel: Option<&CancelToken>,
    ) -> Result<i32> {
        crate::proc::run_cmd(args, log, check, timeout, cancel)
    }
    /// The Windows branch of `refuse_hardening_clash`: mount the ISO read-only, look, dismount.
    fn check_clash_windows(&self, iso_path: &Path, files: &Files, log: Log) -> Result<()> {
        windows::with_mounted_iso(iso_path, log, |root| check_image_for_hardening_clash(root, files))
    }
    /// `f"{os.getuid()}:{os.getgid()}"`: who owns the files the read-only peek mount shows.
    fn owner(&self) -> String {
        #[cfg(unix)]
        {
            // SAFETY: getuid and getgid have no preconditions and cannot fail.
            unsafe { format!("{}:{}", libc::getuid(), libc::getgid()) }
        }
        #[cfg(not(unix))]
        {
            "0:0".to_string()
        }
    }
}

/// The real thing: every method is the provided one.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemOps;
impl EngineOps for SystemOps {}

// ---------------------------------------------------------------------------------------------------------------
// Pinned identity of the drive the user confirmed
// ---------------------------------------------------------------------------------------------------------------

/// Identity recorded for the drive the user selected; checked again right before erasing. (Kept here, not in
/// `build_usb`'s signature, so the check cannot be forgotten by a caller.) `_pinned_identities`.
static PINNED_IDENTITIES: LazyLock<Mutex<HashMap<String, Identity>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn pinned() -> std::sync::MutexGuard<'static, HashMap<String, Identity>> {
    PINNED_IDENTITIES.lock().unwrap_or_else(|e| e.into_inner())
}

/// Remember the identity of the drive the user confirmed; `reverify_target_disk` enforces it (None, or an empty
/// identity, clears the pin).
pub fn pin_target_identity(dev: &str, identity: Option<Identity>) {
    match identity.filter(|i| !i.is_empty()) {
        Some(identity) => {
            pinned().insert(dev.to_string(), identity);
        }
        None => {
            pinned().remove(dev);
        }
    }
}

/// The identity pinned for `dev` right now, without consuming it (`_pinned_identities.get(dev)`).
pub fn pinned_identity(dev: &str) -> Option<Identity> {
    pinned().get(dev).cloned()
}

// ---------------------------------------------------------------------------------------------------------------
// Hardening files on the image
// ---------------------------------------------------------------------------------------------------------------
// Extra files for a Windows drive (a SetupComplete script and its PowerShell script, see hardening_files_windows).
// They are checked first, written after the ISO's own files, read back from the device and compared byte for byte.

/// Refuse a profile on an image type that cannot take extra files.
///
/// Only the Windows type copies files onto the drive; a raw-written image (Linux, ChromeOS) has no room for them.
/// Called before anything is hashed, listed or erased.
pub fn validate_hardening(mode: Mode, hardening: Hardening) -> Result<()> {
    if hardening != Hardening::None && mode != Mode::Windows {
        return Err(Error::value(
            "Hardening files can only be added to a Windows drive; an image of this type is \
             written byte for byte and has no room for them. Nothing was changed.",
        ));
    }
    Ok(())
}

/// `validate_hardening` for a profile given by name (the command line and the window pass the enum; this is for
/// text that comes from outside): refuses an unknown profile, then as `validate_hardening`.
pub fn validate_hardening_name(mode: Mode, name: &str) -> Result<Hardening> {
    let Some(hardening) = Hardening::parse(name) else {
        return Err(Error::value(format!("Unknown hardening profile: {}", py_repr(name))));
    };
    validate_hardening(mode, hardening)?;
    Ok(hardening)
}

/// The validated {relative posix path: bytes} to add for `hardening` (None for none).
pub fn collect_hardening_files(hardening: Hardening) -> Result<Option<Files>> {
    collect_hardening_files_on(&SystemOps, hardening)
}

/// `collect_hardening_files` against any `EngineOps`.
pub fn collect_hardening_files_on<O: EngineOps + ?Sized>(ops: &O, hardening: Hardening) -> Result<Option<Files>> {
    if hardening == Hardening::None {
        return Ok(None);
    }
    let files = ops.validate_files(&ops.hardening_files(hardening)?)?;
    if files.is_empty() {
        return Err(Error::value(format!(
            "The hardening profile {} has no files to add. Nothing was changed.",
            py_repr(hardening.as_str())
        )));
    }
    Ok(Some(files))
}

/// What the audit START line says about the hardening files: the profile and the file names (no contents).
pub fn hardening_audit_text(hardening: Hardening, files: Option<&Files>) -> String {
    match files.filter(|f| !f.is_empty()) {
        None => String::new(),
        Some(files) => {
            let mut names: Vec<&String> = files.keys().collect();
            names.sort();
            let names: Vec<&str> = names.into_iter().map(String::as_str).collect();
            format!(", hardening={}, hardening files={}", hardening.as_str(), py_repr_list(&names))
        }
    }
}

/// The path of `rel` (a relative posix path) below `root`; refuses anything that would leave `root`.
fn hardening_target(root: &Path, rel: &str) -> Result<PathBuf> {
    let parts: Vec<&str> = rel.split('/').collect();
    if rel.is_empty()
        || rel.starts_with('/')
        || rel.contains('\\')
        || rel.contains('\0')
        || parts.iter().any(|p| matches!(*p, "" | "." | ".."))
    {
        return Err(Error::value(format!("Refusing an unsafe hardening file path: {}", py_repr(rel))));
    }
    let outside = || Error::runtime(format!("Refusing to write outside the drive: {}", py_repr(rel)));
    let real_root = realpath_lenient(root).ok_or_else(outside)?;
    let mut target = real_root.clone();
    target.extend(&parts);
    let real_target = realpath_lenient(&target).ok_or_else(outside)?;
    let inside = if cfg!(windows) {
        // os.path.commonpath compares case-insensitively on Windows
        let (r, t) = (real_root.to_string_lossy().to_lowercase(), real_target.to_string_lossy().to_lowercase());
        Path::new(&t).starts_with(Path::new(&r))
    } else {
        real_target.starts_with(&real_root)
    };
    if !inside {
        return Err(outside());
    }
    Ok(target)
}

/// Open options that refuse to follow a symbolic link at the final component (unix; elsewhere a plain open).
fn nofollow(opts: &mut fs::OpenOptions) -> &mut fs::OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW)
    }
    #[cfg(not(unix))]
    {
        opts
    }
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).map(|m| m.file_type().is_symlink()).unwrap_or(false)
}

/// Write `files` ({relative posix path: bytes}) below the directory `root`, as the current user.
///
/// Plain file I/O: no shell, so a `$` in a name (sources/$OEM$/$$/...) is just a character. Parent folders are
/// created; each file is flushed to the device. Fails with `Error::Canceled` between files.
pub fn write_hardening_files(root: &Path, files: &Files, cancel: Option<&CancelToken>) -> Result<()> {
    let mut names: Vec<&String> = files.keys().collect();
    names.sort();
    for rel in names {
        crate::proc::check_canceled(cancel, true, false)?;
        let target = hardening_target(root, rel)?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        if is_symlink(&target) {
            return Err(Error::runtime(format!("Refusing to write over a symbolic link: {}", py_repr(rel))));
        }
        let mut options = fs::OpenOptions::new();
        let mut fh = nofollow(options.write(true).create(true).truncate(true)).open(&target)?;
        fh.write_all(&files[rel.as_str()])?;
        fh.flush()?;
        fh.sync_all()?;
    }
    Ok(())
}

/// Read the hardening files back from `root` and compare each one byte for byte. Fails on any mismatch.
pub fn verify_hardening_files(root: &Path, files: &Files, log: Log, cancel: Option<&CancelToken>) -> Result<()> {
    log("Verifying the hardening files (reading them back from the drive)...");
    let mut bad: Vec<String> = Vec::new();
    let mut names: Vec<&String> = files.keys().collect();
    names.sort();
    for rel in names {
        crate::proc::check_canceled(cancel, true, false)?;
        let expected = &files[rel.as_str()];
        let path = hardening_target(root, rel)?;
        let found = (|| -> std::io::Result<Vec<u8>> {
            if is_symlink(&path) {
                return Err(std::io::Error::other("symbolic link"));
            }
            let mut options = fs::OpenOptions::new();
            let fh = nofollow(options.read(true)).open(&path)?;
            // one byte more than expected: a longer file must not pass
            let mut found = Vec::new();
            fh.take(expected.len() as u64 + 1).read_to_end(&mut found)?;
            Ok(found)
        })();
        match found {
            Err(_) => bad.push(format!("{rel} (missing)")),
            Ok(found) if found != *expected => bad.push(format!("{rel} (differs)")),
            Ok(_) => {}
        }
    }
    if !bad.is_empty() {
        audit_event(&format!("VERIFICATION FAILED: {} hardening file(s) differ", bad.len()), AuditLevel::Error);
        return Err(Error::runtime(format!(
            "Verification FAILED: {} hardening file(s) on the drive are missing or differ from what \
             was written (for example: {}).\n\nThe drive was NOT ejected and should not be used.",
            bad.len(),
            bad[0]
        )));
    }
    log(&format!("Hardening files verified: {} file(s) identical.", files.len()));
    Ok(())
}

// --- the hardening files must never replace a file the image already ships -------------------------------
// An image of its own (an OEM or custom build) may already carry e.g. sources/$OEM$/$$/Setup/Scripts/
// SetupComplete.cmd. Writing ours over it would silently drop that content, so such an image is refused.
// The check looks at the ISO's tree (read-only) BEFORE the drive is touched (refuse_hardening_clash, called
// by build_usb); copy_windows_payload repeats it on the mounted tree as a last line of defence, and the
// post-copy verification has no exemption for these paths either.

/// The paths of `files` ({relative posix path: bytes}) that already exist below `root`, ignoring case.
///
/// FAT32 (and a Windows setup) treat names case-insensitively, so "Sources/$OEM$/..." clashes with
/// "sources/$oem$/...". Returns the paths as spelled in `files`, sorted.
pub fn find_hardening_clashes(root: &Path, files: &Files) -> Vec<String> {
    let mut names: Vec<&String> = files.keys().collect();
    names.sort();
    let mut clashes = Vec::new();
    for rel in names {
        let mut path = Some(root.to_path_buf());
        for part in rel.split('/') {
            path = path.and_then(|p| crate::copyverify::find_case_insensitive(&p, part));
            if path.is_none() {
                break;
            }
        }
        if path.is_some() {
            clashes.push(rel.clone());
        }
    }
    clashes
}

/// Fail with `Error::Value` (and audit the refusal) when the image tree at `root` already holds any of `files`.
pub fn check_image_for_hardening_clash(root: &Path, files: &Files) -> Result<()> {
    let clashes = find_hardening_clashes(root, files);
    if clashes.is_empty() {
        return Ok(());
    }
    audit_event(
        &format!("HARDENING REFUSED: the image already contains {}; nothing was changed", py_repr_list(&clashes)),
        AuditLevel::Warning,
    );
    Err(Error::value(format!(
        "This Windows image already contains {}. Adding the hardening \
         files would replace them, so nothing was changed. Untick the hardening option \
         or use another image.",
        clashes.join(", ")
    )))
}

/// Root script that mounts the ISO read-only so the app (as the user) can list it BEFORE the drive is touched (the
/// prep script of linux::build_usb mounts it only after wiping). Same mount calls as that script; "$1" the ISO,
/// "$2" an empty folder, "$3" uid:gid. Nothing is written anywhere and no drive is involved.
pub const LINUX_ISO_PEEK_SCRIPT: &str = include_str!("../assets/linux-iso-peek.sh");
/// Unmounts the folder the peek script mounted ("$1").
pub const LINUX_ISO_PEEK_CLEANUP_SCRIPT: &str = include_str!("../assets/linux-iso-peek-cleanup.sh");

/// Before the drive is touched: mount the ISO read-only, and refuse (`Error::Value`) if it already holds any of the
/// hardening `files`. Does nothing when there are no files. The ISO is unmounted again either way.
pub fn refuse_hardening_clash(iso_path: &Path, files: &Files, ctx: &Ctx, priv_: &dyn Privilege) -> Result<()> {
    refuse_hardening_clash_on(&SystemOps, iso_path, files, ctx, priv_)
}

/// `refuse_hardening_clash` against any `EngineOps`.
pub fn refuse_hardening_clash_on<O: EngineOps + ?Sized>(
    ops: &O,
    iso_path: &Path,
    files: &Files,
    ctx: &Ctx,
    priv_: &dyn Privilege,
) -> Result<()> {
    if files.is_empty() {
        return Ok(());
    }
    ctx.log("Checking that the image does not already contain the hardening files...");
    if ops.os() == Os::Windows {
        return ops.check_clash_windows(iso_path, files, ctx.log);
    }
    let mount_dir = tempfile::Builder::new().prefix("win11peek_").tempdir()?.keep();
    let iso = iso_path.to_string_lossy().into_owned();
    let mount = mount_dir.to_string_lossy().into_owned();
    let is_mac = ops.os() == Os::Mac;
    let mut result: Result<()> = if is_mac {
        let args: Vec<String> = ["hdiutil", "attach", &iso, "-nobrowse", "-readonly", "-mountpoint", &mount]
            .into_iter()
            .map(String::from)
            .collect();
        ops.run_cmd(&args, ctx.log, true, Some(Duration::from_secs(300)), None).map(|_| ())
    } else {
        priv_.run_script(LINUX_ISO_PEEK_SCRIPT, ctx.log, &[iso.clone(), mount.clone(), ops.owner()])
    };
    if result.is_ok() {
        result = check_image_for_hardening_clash(&mount_dir, files);
    }
    // The ISO is unmounted again either way (the mount was attempted above, so the unmount always is).
    if is_mac {
        let args: Vec<String> = ["hdiutil", "detach", &mount, "-force"].into_iter().map(String::from).collect();
        let detached = ops.run_cmd(&args, ctx.log, false, Some(Duration::from_secs(DISKUTIL_TIMEOUT)), None);
        if let Err(e) = detached {
            result = Err(e); // an error in the cleanup replaces the one in flight, as with try/finally
        }
    } else if let Err(cleanup_err) =
        priv_.run_script(LINUX_ISO_PEEK_CLEANUP_SCRIPT, ctx.log, std::slice::from_ref(&mount))
    {
        ctx.log(&format!("Warning: cleanup failed: {cleanup_err}"));
    }
    silent_rmdir(&mount_dir);
    result
}

// ---------------------------------------------------------------------------------------------------------------
// Platform dispatch
// ---------------------------------------------------------------------------------------------------------------

/// Eligible external (USB) disks on this OS (dispatches to macos / windows / linux `get_external_disks`).
pub fn get_external_disks() -> Result<Vec<Disk>> {
    SystemOps.list_disks()
}

/// Re-check, immediately before erasing, that `dev` is still the disk we listed.
///
/// Device names are recycled by the operating system: if a drive is unplugged and another plugged in between
/// listing and writing, '/dev/sdb' can point somewhere else entirely. Re-enumerating here closes that window.
pub fn reverify_target_disk(
    dev: &str,
    expected_size: Option<u64>,
    log: Log,
    expected_identity: Option<&Identity>,
) -> Result<()> {
    reverify_target_disk_on(&SystemOps, dev, expected_size, log, expected_identity)
}

/// `reverify_target_disk` against any `EngineOps`.
pub fn reverify_target_disk_on<O: EngineOps + ?Sized>(
    ops: &O,
    dev: &str,
    expected_size: Option<u64>,
    log: Log,
    expected_identity: Option<&Identity>,
) -> Result<()> {
    validate_device_name(dev)?;
    // The identity the user confirmed: passed explicitly or pinned by the UI (see pin_target_identity).
    let expected_identity: Identity = match expected_identity.filter(|i| !i.is_empty()) {
        Some(identity) => identity.clone(),
        None => pinned().remove(dev).unwrap_or_default(),
    };
    let current = ops.list_disks()?;
    let Some(disk) = current.iter().rev().find(|d| d.id == dev) else {
        audit_event(&format!("ABORTED: {dev} is no longer an eligible external disk"), AuditLevel::Error);
        return Err(Error::runtime(format!(
            "Aborted for safety: {} is no longer listed as an external drive.\n\n\
             It may have been unplugged, or the name may now refer to a different disk. \
             Click 'Refresh USB drives list' and select the drive again.",
            dev_path(dev)
        )));
    };
    let actual_size = disk.size;
    if let Some(expected) = expected_size.filter(|s| *s != 0) {
        if actual_size != expected {
            audit_event(&format!("ABORTED: {dev} size changed {expected} -> {actual_size}"), AuditLevel::Error);
            return Err(Error::runtime(format!(
                "Aborted for safety: {} now reports a different size \
                 ({} instead of {}).\n\n\
                 This means the name now points to a different device. Refresh the list \
                 and select the drive again.",
                dev_path(dev),
                human_size(actual_size),
                human_size(expected)
            )));
        }
    }
    if let Some(changed) = identity_mismatch(&expected_identity, &disk.identity) {
        audit_event(&format!("ABORTED: {dev} identity changed ({changed})"), AuditLevel::Error);
        return Err(Error::runtime(format!(
            "Aborted for safety: {} no longer looks like the drive you confirmed \
             ({changed}).\n\n\
             This means the name now points to a different device. Refresh the list \
             and select the drive again.",
            dev_path(dev)
        )));
    }
    log(&format!(
        "Safety re-check passed: {} is still the same external drive ({}).",
        dev_path(dev),
        human_size(actual_size)
    ));
    Ok(())
}

/// SHA-256 of the ISO for the audit trail. Runs in the worker thread, before the drive is touched.
pub fn hash_iso_for_audit(iso_path: &Path, ctx: &Ctx) -> Result<String> {
    ctx.log("Hashing the ISO (recorded in the audit log)...");
    ctx.report(0, 0, "Hashing the ISO...");
    let digest = match sha256_file(iso_path, ctx.cancel, None) {
        Ok(digest) => digest,
        Err(Error::Io(e)) => {
            return Err(Error::runtime(format!(
                "Could not read the ISO file: {}. The drive was not modified.",
                os_strerror(&e)
            )))
        }
        Err(other) => return Err(other),
    };
    ctx.log(&format!("ISO SHA-256: {digest}"));
    Ok(digest)
}

/// One sentence telling the user how to get the missing tools on this system.
pub fn missing_dependencies_hint(missing: &[String]) -> String {
    missing_dependencies_hint_on(&SystemOps, missing)
}

/// `missing_dependencies_hint` against any `EngineOps`.
pub fn missing_dependencies_hint_on<O: EngineOps + ?Sized>(ops: &O, missing: &[String]) -> String {
    let button = "or use the 'Install missing dependencies' button";
    match ops.os() {
        Os::Windows => {
            "They are part of Windows 11; this installation looks incomplete (run 'sfc /scannow' as Administrator)."
                .to_string()
        }
        Os::Mac => {
            if missing.iter().any(|m| m == "wimlib-imagex") {
                format!("Install wimlib with: brew install wimlib ({button}).")
            } else {
                "They are part of macOS; the system looks incomplete.".to_string()
            }
        }
        Os::Linux => match ops.install_command(missing) {
            Ok(cmd) => format!("Install them with: sudo {cmd} ({button})."),
            Err(_) => format!("Install them with your package manager ({button})."),
        },
    }
}

/// Check, before anything is touched, that the image suits `mode`, fits the drive and the tools exist.
/// Returns the resolved image path. `Error::Value` with the Python message otherwise.
///
/// Also refuses, with a message that says how to fix it, when a tool the chosen type needs is missing: otherwise
/// that would only be discovered after the drive had been erased.
pub fn validate_image_for_mode(iso_path: impl AsRef<Path>, mode: Mode, expected_size: Option<u64>) -> Result<PathBuf> {
    validate_image_for_mode_on(&SystemOps, iso_path.as_ref(), mode, expected_size)
}

/// `validate_image_for_mode` against any `EngineOps`.
pub fn validate_image_for_mode_on<O: EngineOps + ?Sized>(
    ops: &O,
    iso_path: &Path,
    mode: Mode,
    expected_size: Option<u64>,
) -> Result<PathBuf> {
    if !mode.is_image_mode() {
        return Err(Error::value(format!("Unknown image type: {}", py_repr(mode.as_str()))));
    }
    let iso_path = validate_iso_path(iso_path)?;
    match mode {
        Mode::Linux => validate_hybrid_iso(&iso_path)?,
        Mode::ChromeOs => validate_disk_image(&iso_path)?,
        _ => {}
    }
    // Raw modes write the image as it is; Windows mode copies its contents. Either way it must fit (the copy of a
    // Windows ISO needs at least the ISO's size).
    let image_size = fs::metadata(&iso_path)?.len();
    let drive_size = expected_size.unwrap_or(0);
    if image_exceeds_drive(image_size, drive_size) {
        return Err(Error::value(format!(
            "The image ({}) is larger than the drive ({}). Nothing was changed.",
            human_size(image_size),
            human_size(drive_size)
        )));
    }
    let missing = ops.missing_dependencies(mode);
    if !missing.is_empty() {
        return Err(Error::value(format!(
            "Cannot continue: required tool(s) not found: {}. {} Nothing was changed.",
            missing.join(", "),
            missing_dependencies_hint_on(ops, &missing)
        )));
    }
    Ok(iso_path)
}

/// Create the bootable drive. `Ok(ejected)`. `Error::Canceled` carries `drive_touched` / `written` (see
/// `types::Error`): `drive_touched` is false when nothing on the drive was changed.
/// `opts.hardening` (Windows mode only) adds the hardening files, validated before the drive is touched.
pub fn build_usb(
    iso_path: impl AsRef<Path>,
    dev: &str,
    ctx: &Ctx,
    priv_: &dyn Privilege,
    opts: &BuildOptions,
) -> Result<bool> {
    build_usb_on(&SystemOps, iso_path.as_ref(), dev, ctx, priv_, opts)
}

/// `build_usb` against any `EngineOps`: the order of the steps is the safety property.
pub fn build_usb_on<O: EngineOps + ?Sized>(
    ops: &O,
    iso_path: &Path,
    dev: &str,
    ctx: &Ctx,
    priv_: &dyn Privilege,
    opts: &BuildOptions,
) -> Result<bool> {
    let mode = opts.mode;
    // 1. Everything that can be refused without reading the image or the drive.
    validate_hardening(mode, opts.hardening)?;
    let hardening_files = collect_hardening_files_on(ops, opts.hardening)?;
    let iso_path = ops.validate_image(iso_path, mode, opts.expected_size)?;
    validate_device_name(dev)?;
    let no_files = Files::new();
    ops.refuse_clash(&iso_path, hardening_files.as_ref().unwrap_or(&no_files), ctx, priv_)?;

    // 2. Hashing and the safety re-check change nothing: a cancel here leaves the drive exactly as it was.
    let checks = || -> Result<String> {
        let iso_sha = ops.hash_iso(&iso_path, ctx)?;
        ops.reverify(dev, opts.expected_size, ctx.log, None)?;
        ctx.check_canceled(false, false)?;
        Ok(iso_sha)
    };
    let iso_sha = match checks() {
        Ok(sha) => sha,
        Err(Error::Canceled { .. }) => {
            audit_event(
                &format!(
                    "OPERATION CANCELED by the user before the drive was touched ({}); nothing was changed",
                    dev_path(dev)
                ),
                AuditLevel::Warning,
            );
            return Err(Error::canceled_with("Canceled by the user before the drive was touched.", false, false));
        }
        Err(other) => return Err(other),
    };

    // 3. The destructive part.
    let iso_size = fs::metadata(&iso_path)?.len();
    let start = format!(
        "DESTRUCTIVE OPERATION START: erasing {} and writing {} image (iso sha256={iso_sha}, size={iso_size})",
        dev_path(dev),
        mode.as_str()
    ) + &hardening_audit_text(opts.hardening, hardening_files.as_ref());
    audit_event(&start, AuditLevel::Info);
    let outcome = {
        let _awake = ops.prevent_sleep(ctx.log);
        if mode.is_raw() {
            ops.write_raw(&iso_path, dev, ctx, priv_, opts.eject)
        } else {
            ops.build_windows_usb(&iso_path, dev, ctx, priv_, opts.eject, hardening_files.as_ref())
        }
    };
    match outcome {
        Ok(ejected) => {
            audit_event(
                &format!(
                    "DESTRUCTIVE OPERATION COMPLETED on {} (ejected={})",
                    dev_path(dev),
                    if ejected { "True" } else { "False" }
                ),
                AuditLevel::Info,
            );
            Ok(ejected)
        }
        Err(e @ Error::Canceled { .. }) => {
            let text = if !e.drive_touched() {
                format!(
                    "DESTRUCTIVE OPERATION CANCELED by the user on {} before the drive was touched; \
                     nothing was changed",
                    dev_path(dev)
                )
            } else if e.written() {
                format!(
                    "DESTRUCTIVE OPERATION CANCELED by the user on {} during verification; \
                     the image was written but NOT verified",
                    dev_path(dev)
                )
            } else {
                format!("DESTRUCTIVE OPERATION CANCELED by the user on {}; the drive was left unusable", dev_path(dev))
            };
            audit_event(&text, AuditLevel::Warning);
            Err(e)
        }
        Err(e) => {
            audit_event(
                &format!("DESTRUCTIVE OPERATION FAILED on {}: {}", dev_path(dev), py_error_name(&e)),
                AuditLevel::Error,
            );
            Err(e)
        }
    }
}

/// Whether writing a drive in `mode` needs administrator rights: always on Linux and Windows, and on macOS only for
/// the byte-for-byte modes (diskutil and hdiutil need no root, writing /dev/rdiskN does).
pub fn needs_admin(mode: Mode) -> bool {
    needs_admin_on(Os::current(), mode)
}

/// `needs_admin` for a given operating system.
pub fn needs_admin_on(os: Os, mode: Mode) -> bool {
    os == Os::Linux || os == Os::Windows || mode.is_raw()
}

/// True when an image of `image_size` bytes cannot fit a drive of `drive_size` bytes.
///
/// An unknown size (0) is never a reason to refuse. Pure: the window and the command line each word the refusal
/// themselves (translated in the window, English on the command line).
pub fn image_exceeds_drive(image_size: u64, drive_size: u64) -> bool {
    image_size != 0 && drive_size != 0 && image_size > drive_size
}

/// True when ChromeOS Flex is going to a drive below the 16 GB Google asks for (a warning, not a refusal).
pub fn chromeos_drive_too_small(mode: Mode, drive_size: u64) -> bool {
    mode == Mode::ChromeOs && drive_size != 0 && drive_size < CHROMEOS_MIN_USB_BYTES
}

use crate::seed::LINUX_SEED_TOOLS; // the partitioning tools only: no rsync, no wimlib

/// The Windows tools this mode needs and this machine lacks (they ship with Windows, so normally none).
pub fn windows_missing_tools(mode: Mode) -> Vec<String> {
    windows_missing_tools_on(&SystemOps, mode)
}

/// `windows_missing_tools` against any `EngineOps`.
pub fn windows_missing_tools_on<O: EngineOps + ?Sized>(ops: &O, mode: Mode) -> Vec<String> {
    let mut needed: Vec<(&str, PathBuf)> = vec![("powershell.exe", ops.powershell_exe())];
    if mode == Mode::Windows {
        needed.push(("dism.exe", ops.dism_exe()));
    }
    needed.into_iter().filter(|(_, path)| !ops.is_file(path)).map(|(name, _)| name.to_string()).collect()
}

/// Names of the tools this OS lacks for `mode` (Mode::Seed included).
pub fn get_missing_dependencies(mode: Mode) -> Vec<String> {
    get_missing_dependencies_on(&SystemOps, mode)
}

/// `get_missing_dependencies` against any `EngineOps`.
pub fn get_missing_dependencies_on<O: EngineOps + ?Sized>(ops: &O, mode: Mode) -> Vec<String> {
    let os = ops.os();
    if os == Os::Windows {
        return windows_missing_tools_on(ops, mode);
    }
    if mode == Mode::Seed {
        // the seed drive needs no ISO tools: no rsync, no wimlib (see LINUX_SEED_TOOLS)
        return if os == Os::Mac {
            Vec::new()
        } else {
            LINUX_SEED_TOOLS.iter().filter(|t| !ops.which(t)).map(|t| t.to_string()).collect()
        };
    }
    if mode.is_raw() {
        // raw write needs nothing else
        return if ops.which("dd") { Vec::new() } else { vec!["dd".to_string()] };
    }
    if os == Os::Mac {
        return if ops.which("wimlib-imagex") { Vec::new() } else { vec!["wimlib-imagex".to_string()] };
    }
    LINUX_REQUIRED_TOOLS.iter().filter(|t| !ops.which(t)).map(|t| t.to_string()).collect()
}

#[cfg(test)]
mod tests {
    //! The small helpers of this file that tests/ cannot reach (they are private): the system lookups.
    use super::*;

    #[test]
    fn which_finds_programs_by_path_and_name() {
        #[cfg(unix)]
        {
            assert!(which_tool("sh").is_some());
            assert!(which_tool("/bin/sh").is_some());
            assert!(which_tool("definitely-not-a-program-xyz").is_none());
            assert!(which_tool("/nonexistent/sh").is_none());
            // a directory is not a program
            assert!(which_tool("/tmp").is_none());
        }
        assert!(which_tool("").is_none());
    }

    #[test]
    fn strerror_has_no_os_error_suffix() {
        let e = fs::metadata("/nonexistent/definitely/not/here").unwrap_err();
        let text = os_strerror(&e);
        assert!(!text.contains("os error"), "{text}");
        assert!(!text.is_empty());
        assert_eq!(os_strerror(&std::io::Error::other("custom")), "OSError");
    }

    #[test]
    fn realpath_resolves_what_exists_and_keeps_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        fs::create_dir_all(root.join("a")).unwrap();
        assert_eq!(realpath_lenient(&root.join("a").join("b").join("c")), Some(root.join("a").join("b").join("c")));
        #[cfg(unix)]
        {
            let outside = tempfile::tempdir().unwrap();
            std::os::unix::fs::symlink(outside.path(), root.join("link")).unwrap();
            let real = realpath_lenient(&root.join("link").join("x.txt")).unwrap();
            assert_eq!(real, fs::canonicalize(outside.path()).unwrap().join("x.txt"));
            // a link that points nowhere cannot be resolved: never write through it
            std::os::unix::fs::symlink(root.join("nowhere"), root.join("dangling")).unwrap();
            assert_eq!(realpath_lenient(&root.join("dangling").join("x.txt")), None);
        }
    }

    #[test]
    fn python_exception_names_for_the_audit_line() {
        assert_eq!(py_error_name(&Error::runtime("x")), "RuntimeError");
        assert_eq!(py_error_name(&Error::value("x")), "ValueError");
        assert_eq!(py_error_name(&Error::canceled()), "OperationCanceled");
        let missing = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert_eq!(py_error_name(&Error::Io(missing)), "FileNotFoundError");
        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert_eq!(py_error_name(&Error::Io(denied)), "PermissionError");
        assert_eq!(py_error_name(&Error::Io(std::io::Error::other("x"))), "OSError");
    }
}
