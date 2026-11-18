//! The hardening seed drive engine: validation, staging, copy, verify and the dispatcher. OWNER: A4.
//! Port of win11_usb_creator.py lines 8462-8661 (SEED_* limits, validate_seed_label/files, stage/copy/verify)
//! and 8792-8868 (check_seed_target_size, build_seed_usb).
//!
//! The "seed drive" is a small GPT + FAT32 drive with a special volume label that carries only the hardening seed
//! files (cloud-init / kickstart / preseed / a Windows script). It holds no operating system, so none of the ISO
//! machinery is involved; the erase, the copy, the read-back and the eject follow the Windows-mode path and keep all
//! of its protections.
//!
//! [`build_seed_usb`] mirrors the Python flow exactly: validation first, stage, re-verify the target, cancel check,
//! audit lines, keep the computer awake, dispatch per OS, audit the result, always remove the stage directory. The
//! effects on the rest of the program go through the small [`SeedEnv`] trait so that flow is tested with a fake.

use crate::audit::AuditLevel;
#[cfg(unix)]
use crate::constants::PRIVATE_FILE_MODE;
use crate::types::{Ctx, Error, Files, Hardening, Log, Mode, Privilege, Result, SeedTarget};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;

#[cfg(not(test))]
use crate::util::human_size;

/// The unit tests run without `util` (another module's work): this stand-in has the same format.
#[cfg(test)]
fn human_size(n: u64) -> String {
    let mut n = n as f64;
    for unit in ["B", "KB", "MB", "GB", "TB"] {
        if n < 1024.0 {
            return format!("{n:.1} {unit}");
        }
        n /= 1024.0;
    }
    format!("{n:.1} PB")
}

// ---------------------------------------------------------------------------------------------------------------
// Limits and constants
// ---------------------------------------------------------------------------------------------------------------

/// One seed file.
pub const SEED_MAX_FILE_BYTES: u64 = 256 * 1024;
/// All seed files together.
pub const SEED_MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024;
/// A relative path on the drive.
pub const SEED_MAX_PATH_CHARS: usize = 240;
pub const SEED_MAX_FILES: usize = 128;
/// A smaller drive is refused (it cannot hold a FAT32 volume anyway).
pub const SEED_MIN_DRIVE_BYTES: u64 = 64 * 1024 * 1024;
/// FAT volume labels have 11 characters at most.
pub const SEED_LABEL_MAX: usize = 11;
/// Never starts with "-". Anchored: it is used as a full match.
pub static SEED_LABEL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Z0-9_][A-Z0-9_-]{0,10}$").unwrap());
/// Not allowed in a FAT long file name (slashes are handled apart).
pub const SEED_FAT_FORBIDDEN_CHARS: &str = "\"*:<>?|";
pub const SEED_RESERVED_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2",
    "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];
/// What the seed drive needs on Linux: no rsync, no wimlib-imagex (those are for copying a Windows ISO).
pub const LINUX_SEED_TOOLS: &[&str] = &["parted", "mkfs.vfat", "wipefs", "partprobe"];
/// Printed by the root seed script (exit status 0) when it stops on request and the drive was not touched yet.
pub const SEED_UNTOUCHED_MARKER: &str = "SEED_NOT_TOUCHED";
/// Printed by the root seed script when it stops on request after the drive was touched (now incomplete).
pub const SEED_CANCELED_MARKER: &str = "SEED_CANCELED";

// ---------------------------------------------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------------------------------------------

/// Python's `repr()` of a string (what the messages quote). Control and other invisible characters are escaped.
fn py_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if c.is_control()
                || (c.is_whitespace() && c != ' ')
                || matches!(c, '\u{ad}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}' | '\u{feff}') =>
            {
                let n = c as u32;
                if n < 0x100 {
                    out.push_str(&format!("\\x{n:02x}"));
                } else if n < 0x10000 {
                    out.push_str(&format!("\\u{n:04x}"));
                } else {
                    out.push_str(&format!("\\U{n:08x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// `_seed_name(path)`: a path for an error message: short and printable, whatever it contains.
fn seed_name(path: &str) -> String {
    let shown = if path.chars().count() <= 80 {
        path.to_string()
    } else {
        let head: String = path.chars().take(77).collect();
        format!("{head}...")
    };
    py_repr(&shown)
}

/// `validate_seed_label(label)`: the FAT32 volume label of a seed drive: 1 to 11 characters of A-Z 0-9 _ -, not
/// starting with "-". Returns the label; `Error::Value` otherwise. The label reaches `mkfs.vfat -n` /
/// `diskutil eraseDisk` as one separate argument, but it is validated all the same so that nothing odd can ever get
/// that far.
pub fn validate_seed_label(label: &str) -> Result<String> {
    if !SEED_LABEL_RE.is_match(label) {
        return Err(Error::value(format!(
            "Invalid seed drive label {}: use 1 to {SEED_LABEL_MAX} characters from A-Z, 0-9, '_' and '-' \
             (not starting with '-').",
            seed_name(label)
        )));
    }
    Ok(label.to_string())
}

/// `_check_seed_path(path)`: `Error::Value` unless `path` is a safe relative POSIX path that FAT32 can store.
fn check_seed_path(path: &str) -> Result<()> {
    let shown = seed_name(path);
    if path.is_empty() {
        return Err(Error::value("A seed file has an empty path."));
    }
    if path.contains('\0') {
        return Err(Error::value(format!("Seed file path {shown} contains a NUL character.")));
    }
    if path.contains('\\') {
        return Err(Error::value(format!("Seed file path {shown} contains a backslash; use '/' to separate folders.")));
    }
    if path.chars().count() > SEED_MAX_PATH_CHARS {
        return Err(Error::value(format!("Seed file path {shown} is longer than {SEED_MAX_PATH_CHARS} characters.")));
    }
    if path.starts_with('/') {
        return Err(Error::value(format!(
            "Seed file path {shown} is absolute; it must be relative to the root of the drive."
        )));
    }
    // (A Rust string is always valid text: Python's "is not valid text" check for lone surrogates cannot happen.)
    if path.chars().any(|c| (c as u32) < 32 || c as u32 == 127) {
        return Err(Error::value(format!("Seed file path {shown} contains a control character.")));
    }
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            return Err(Error::value(format!("Seed file path {shown} has an empty or '.' component.")));
        }
        if part == ".." {
            return Err(Error::value(format!("Seed file path {shown} contains '..'.")));
        }
        if part.ends_with(' ') || part.ends_with('.') {
            return Err(Error::value(format!("Seed file path {shown} has a name ending in a space or a dot.")));
        }
        let mut bad: Vec<char> = SEED_FAT_FORBIDDEN_CHARS.chars().filter(|c| part.contains(*c)).collect();
        if !bad.is_empty() {
            bad.sort_unstable();
            let bad: String = bad.into_iter().collect();
            return Err(Error::value(format!(
                "Seed file path {shown} contains {}, which FAT32 cannot store.",
                py_repr(&bad)
            )));
        }
        let stem = part.split('.').next().unwrap_or("").trim_end().to_uppercase();
        if SEED_RESERVED_NAMES.contains(&stem.as_str()) {
            return Err(Error::value(format!("Seed file path {shown} uses a reserved device name.")));
        }
    }
    Ok(())
}

/// Python's `str.casefold()` for the cases that matter here (`to_lowercase` plus the two special folds).
fn casefold(text: &str) -> String {
    text.to_lowercase().replace('\u{df}', "ss").replace('\u{3c2}', "\u{3c3}")
}

/// `validate_seed_files(files)`: check the files that are going to be written to a drive and return a cleaned copy.
///
/// `files` is `{relative_posix_path: bytes}`. Every path must be relative (no leading "/", no "..", no backslash, no
/// NUL, no control characters, at most 240 characters, nothing FAT32 cannot store); every file at most 256 KiB, all
/// together at most 2 MiB; no two names may differ only by case (FAT32 is case insensitive), and no name may be both
/// a file and a folder. "$" is an ordinary character (Windows media needs `sources/$OEM$/$$/...`). `Error::Value`
/// with a message that names the first offending path.
pub fn validate_seed_files(files: &Files) -> Result<Files> {
    if files.is_empty() {
        return Err(Error::value("There are no seed files to write."));
    }
    if files.len() > SEED_MAX_FILES {
        return Err(Error::value(format!("Too many seed files ({}); the limit is {SEED_MAX_FILES}.", files.len())));
    }
    let mut clean = Files::new();
    let mut folded: Vec<(String, &str)> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut total: u64 = 0;
    for (path, data) in files {
        check_seed_path(path)?;
        let size = data.len() as u64;
        if size > SEED_MAX_FILE_BYTES {
            return Err(Error::value(format!(
                "Seed file {} is {}; the limit is {} per file.",
                seed_name(path),
                human_size(size),
                human_size(SEED_MAX_FILE_BYTES)
            )));
        }
        total += size;
        if total > SEED_MAX_TOTAL_BYTES {
            return Err(Error::value(format!(
                "The seed files are larger than {} together.",
                human_size(SEED_MAX_TOTAL_BYTES)
            )));
        }
        let key = casefold(path);
        if let Some(&earlier) = index.get(&key) {
            return Err(Error::value(format!(
                "Seed file {} has the same name as {} (FAT32 ignores letter case).",
                seed_name(path),
                seed_name(folded[earlier].1)
            )));
        }
        index.insert(key.clone(), folded.len());
        folded.push((key, path));
        clean.insert(path.clone(), data.clone());
    }
    for (key, path) in &folded {
        let parts: Vec<&str> = key.split('/').collect();
        for i in 1..parts.len() {
            if let Some(&parent) = index.get(&parts[..i].join("/")) {
                return Err(Error::value(format!(
                    "Seed file {} is inside {}, which is a file.",
                    seed_name(path),
                    seed_name(folded[parent].1)
                )));
            }
        }
    }
    Ok(clean)
}

/// `_seed_manifest_sha256(files)`: SHA-256 over the names and contents of the seed files (for the audit trail).
pub fn seed_manifest_sha256(files: &Files) -> String {
    let mut paths: Vec<&String> = files.keys().collect();
    paths.sort();
    let mut digest = Sha256::new();
    for path in paths {
        let data = &files[path];
        digest.update(path.as_bytes());
        digest.update([0u8]);
        digest.update(data.len().to_string().as_bytes());
        digest.update([0u8]);
        digest.update(data);
    }
    digest.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// A path with `.` and `..` resolved by text only (no file system access): Python's `abspath` + `normpath`.
fn lexical_normalize(path: &Path) -> PathBuf {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let mut out = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// `_seed_local_path(root, rel)`: `rel` (already validated) below `root`; refuses anything that would resolve
/// outside it.
fn seed_local_path(root: &Path, rel: &str) -> Result<PathBuf> {
    let mut full = root.to_path_buf();
    for part in rel.split('/') {
        full.push(part);
    }
    if !lexical_normalize(&full).starts_with(lexical_normalize(root)) {
        return Err(Error::value(format!("Seed file path {} would leave the drive.", seed_name(rel))));
    }
    Ok(full)
}

// ---------------------------------------------------------------------------------------------------------------
// Staging, copy, verify
// ---------------------------------------------------------------------------------------------------------------

/// Create `dir` and its parents, owner-only on unix (`os.makedirs(..., exist_ok=True)`).
fn make_dirs(dir: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// A new file nobody else can read (0600 on unix), never through a symlink planted at its path.
fn create_private_file(path: &Path) -> std::io::Result<fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(PRIVATE_FILE_MODE).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

/// `stage_seed_files(files)` with the parent folder given: write the (validated) seed files to a new private
/// directory inside `parent` and return its path (owner only, 0700). Nothing is left behind when a file cannot be
/// staged.
fn stage_seed_files_in(parent: &Path, files: &Files) -> Result<PathBuf> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("epmaseed_");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o700)); // `mkdtemp` makes it owner-only; tempfile does not
    }
    let stage = builder.tempdir_in(parent)?;
    for (rel, data) in files {
        let path = seed_local_path(stage.path(), rel)?;
        if let Some(parent) = path.parent() {
            make_dirs(parent)?;
        }
        create_private_file(&path)?.write_all(data)?;
    }
    Ok(stage.keep())
}

/// `stage_seed_files(files)`: write the (validated) seed files to a new private directory and return its path
/// (owner only, 0700), still before the drive is touched.
pub fn stage_seed_files(files: &Files) -> Result<PathBuf> {
    stage_seed_files_in(&std::env::temp_dir(), files)
}

/// Removes the stage directory when dropped (`shutil.rmtree(stage_dir, ignore_errors=True)`).
struct StageGuard(PathBuf);

impl Drop for StageGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// `copy_seed_files(stage_dir, dst_root, files, ...)` with the final `sync` injected: copy the staged seed files onto
/// the mounted drive, flushing each one. Cancelable between files.
pub fn copy_seed_files_with(
    stage_dir: &Path,
    dst_root: &Path,
    files: &Files,
    ctx: &Ctx,
    sync: &dyn Fn(Log),
) -> Result<()> {
    let total: u64 = files.values().map(|d| d.len() as u64).sum();
    let mut done: u64 = 0;
    ctx.log(&format!("Copying {} seed file(s) to the USB drive...", files.len()));
    for (rel, data) in files {
        ctx.check_canceled(true, false)?;
        let dst = seed_local_path(dst_root, rel)?;
        if let Some(parent) = dst.parent() {
            make_dirs(parent)?;
        }
        let mut src = fs::File::open(seed_local_path(stage_dir, rel)?)?;
        let mut out = fs::File::create(&dst)?;
        std::io::copy(&mut src, &mut out)?;
        out.flush()?;
        out.sync_all()?;
        done += data.len() as u64;
        ctx.log(rel);
        ctx.report(done.min(total), total, "Copying files...");
    }
    ctx.report(total, total, "Flushing data to the drive...");
    ctx.check_canceled(true, false)?;
    ctx.log("Syncing writes to disk...");
    sync(ctx.log);
    Ok(())
}

/// `copy_seed_files(stage_dir, dst_root, files, ...)`.
pub fn copy_seed_files(stage_dir: &Path, dst_root: &Path, files: &Files, ctx: &Ctx) -> Result<()> {
    copy_seed_files_with(stage_dir, dst_root, files, ctx, &crate::proc::sync_filesystems)
}

/// What an I/O error says without the "(os error N)" tail (Python's `e.strerror`).
fn io_strerror(e: &std::io::Error) -> String {
    let text = e.to_string();
    match text.rfind(" (os error ") {
        Some(at) if text.ends_with(')') => text[..at].to_string(),
        _ => text,
    }
}

/// How one seed file on the drive differs from the original, if it does.
fn seed_file_problem(path: &Path, data: &[u8]) -> Option<String> {
    let is_link = fs::symlink_metadata(path).map(|m| m.file_type().is_symlink()).unwrap_or(false);
    let size = match fs::metadata(path) {
        Ok(m) if m.is_file() && !is_link => m.len(),
        _ => return Some("missing".to_string()), // a symlink, a folder or nothing at all is not the file
    };
    if size != data.len() as u64 {
        return Some("size differs".to_string());
    }
    let mut read = Vec::with_capacity(data.len() + 1);
    let result = fs::File::open(path).and_then(|fh| fh.take(data.len() as u64 + 1).read_to_end(&mut read));
    match result {
        Ok(_) if read == data => None,
        Ok(_) => Some("content differs".to_string()),
        Err(e) => Some(format!("unreadable: {}", io_strerror(&e))),
    }
}

/// `verify_seed_files(files, dst_root, ...)` with the audit injected: read every seed file back from the drive and
/// compare it byte for byte. `Error::Runtime("Verification FAILED ...")` on any mismatch.
pub fn verify_seed_files_with(
    files: &Files,
    dst_root: &Path,
    ctx: &Ctx,
    audit: &dyn Fn(&str, AuditLevel),
) -> Result<()> {
    ctx.log("Verifying the seed files (reading them back from the drive)...");
    ctx.report(0, 0, "Verifying the copied files...");
    let mut bad: Vec<String> = Vec::new();
    for (rel, data) in files {
        ctx.check_canceled(true, true)?;
        let path = seed_local_path(dst_root, rel)?;
        if let Some(problem) = seed_file_problem(&path, data) {
            bad.push(format!("{rel} ({problem})"));
        }
    }
    if let Some(first) = bad.first() {
        audit(&format!("VERIFICATION FAILED: {} seed file(s) differ", bad.len()), AuditLevel::Error);
        return Err(Error::runtime(format!(
            "Verification FAILED: {} file(s) on the drive are missing or differ from the seed files (for example: \
             {first}).\n\nThe drive was NOT ejected and should not be used.",
            bad.len()
        )));
    }
    audit("Verification passed (seed files match)", AuditLevel::Info);
    ctx.log("Verification passed: the seed files on the drive are identical to the originals.");
    Ok(())
}

/// `verify_seed_files(files, dst_root, ...)`: read every file back from `dst_root` and compare it byte for byte
/// (`Error::Runtime("Verification FAILED ...")`).
pub fn verify_seed_files(files: &Files, dst_root: &Path, ctx: &Ctx) -> Result<()> {
    verify_seed_files_with(files, dst_root, ctx, &crate::audit::audit_at)
}

/// `check_seed_target_size(size)`: refuse a drive whose KNOWN size (bytes) is under [`SEED_MIN_DRIVE_BYTES`]; an
/// unknown size (`None` / 0) passes.
///
/// Pure and cheap: the window and the command line call it right after the drive is chosen, before any dialog or
/// password prompt; `build_seed_usb` calls it again.
pub fn check_seed_target_size(size: Option<u64>) -> Result<()> {
    match size {
        Some(size) if size != 0 && size < SEED_MIN_DRIVE_BYTES => Err(Error::value(format!(
            "The drive ({}) is too small for a seed drive (at least {}). Nothing was changed.",
            human_size(size),
            human_size(SEED_MIN_DRIVE_BYTES)
        ))),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// build_seed_usb
// ---------------------------------------------------------------------------------------------------------------

/// Which backend writes the drive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Mac,
    Windows,
    Linux,
}

/// What `build_seed_usb` needs from the rest of the program. [`RealSeedEnv`] is the real thing; the tests use a fake
/// to check the order of the steps, the audit lines and the cancel semantics without a drive.
pub trait SeedEnv {
    fn validate_device_name(&self, dev: &str) -> Result<String>;
    fn dev_path(&self, dev: &str) -> String;
    /// `hardening_files_seed(target, profile)`: the label and the files.
    fn hardening_files_seed(&self, target: SeedTarget, profile: Hardening) -> Result<(String, Files)>;
    /// `get_missing_dependencies(MODE_SEED)`.
    fn missing_dependencies(&self) -> Vec<String>;
    fn missing_dependencies_hint(&self, missing: &[String]) -> String;
    /// `reverify_target_disk(dev, expected_size, log)`.
    fn reverify_target_disk(&self, dev: &str, expected_size: Option<u64>, log: Log) -> Result<()>;
    fn audit(&self, msg: &str, level: AuditLevel);
    /// `with prevent_sleep(log):` around `run`.
    fn with_sleep_prevented(&self, log: Log, run: &mut dyn FnMut() -> Result<bool>) -> Result<bool>;
    fn platform(&self) -> Platform;
    fn build_mac(
        &self,
        label: &str,
        files: &Files,
        stage_dir: &Path,
        dev: &str,
        ctx: &Ctx,
        eject: bool,
    ) -> Result<bool>;
    fn build_windows(
        &self,
        label: &str,
        files: &Files,
        stage_dir: &Path,
        dev: &str,
        ctx: &Ctx,
        eject: bool,
    ) -> Result<bool>;
    fn build_linux(
        &self,
        label: &str,
        files: &Files,
        stage_dir: &Path,
        dev: &str,
        ctx: &Ctx,
        eject: bool,
    ) -> Result<bool>;
}

/// The real [`SeedEnv`]. `priv_` runs the root scripts of the Linux backend.
pub struct RealSeedEnv<'a> {
    pub priv_: &'a dyn Privilege,
}

impl SeedEnv for RealSeedEnv<'_> {
    fn validate_device_name(&self, dev: &str) -> Result<String> {
        crate::validate::validate_device_name(dev)
    }
    fn dev_path(&self, dev: &str) -> String {
        crate::validate::dev_path(dev)
    }
    fn hardening_files_seed(&self, target: SeedTarget, profile: Hardening) -> Result<(String, Files)> {
        crate::seed_files::hardening_files_seed(target, profile)
    }
    fn missing_dependencies(&self) -> Vec<String> {
        crate::engine::get_missing_dependencies(Mode::Seed)
    }
    fn missing_dependencies_hint(&self, missing: &[String]) -> String {
        crate::engine::missing_dependencies_hint(missing)
    }
    fn reverify_target_disk(&self, dev: &str, expected_size: Option<u64>, log: Log) -> Result<()> {
        crate::engine::reverify_target_disk(dev, expected_size, log, None)
    }
    fn audit(&self, msg: &str, level: AuditLevel) {
        crate::audit::audit_at(msg, level)
    }
    fn with_sleep_prevented(&self, log: Log, run: &mut dyn FnMut() -> Result<bool>) -> Result<bool> {
        let _awake = crate::proc::prevent_sleep(log);
        run()
    }
    fn platform(&self) -> Platform {
        if crate::constants::IS_MAC {
            Platform::Mac
        } else if crate::constants::IS_WINDOWS {
            Platform::Windows
        } else {
            Platform::Linux
        }
    }
    fn build_mac(
        &self,
        label: &str,
        files: &Files,
        stage_dir: &Path,
        dev: &str,
        ctx: &Ctx,
        eject: bool,
    ) -> Result<bool> {
        crate::macos::build_seed_usb(label, files, stage_dir, dev, ctx, eject)
    }
    fn build_windows(
        &self,
        label: &str,
        files: &Files,
        stage_dir: &Path,
        dev: &str,
        ctx: &Ctx,
        eject: bool,
    ) -> Result<bool> {
        crate::windows::build_seed_usb(label, files, stage_dir, dev, ctx, eject)
    }
    fn build_linux(
        &self,
        label: &str,
        files: &Files,
        stage_dir: &Path,
        dev: &str,
        ctx: &Ctx,
        eject: bool,
    ) -> Result<bool> {
        crate::linux::build_seed_usb(label, files, stage_dir, dev, ctx, self.priv_, eject)
    }
}

/// The Python exception class name of an error (what the "FAILED" audit line quotes).
fn python_type_name(e: &Error) -> &'static str {
    match e {
        Error::Runtime(_) => "RuntimeError",
        Error::Value(_) => "ValueError",
        Error::Io(_) => "OSError",
        Error::Canceled { .. } => "OperationCanceled",
    }
}

/// `build_seed_usb` with the outside world injected (see [`SeedEnv`]).
pub fn build_seed_usb_with(
    env: &dyn SeedEnv,
    target: SeedTarget,
    dev: &str,
    ctx: &Ctx,
    expected_size: Option<u64>,
    eject: bool,
    profile: Hardening,
) -> Result<bool> {
    // (The Python also rejects an unknown target or profile here; the enums make that impossible.)
    env.validate_device_name(dev)?;
    let (label, files) = env.hardening_files_seed(target, profile)?;
    let label = validate_seed_label(&label)?;
    let files = validate_seed_files(&files)?;
    check_seed_target_size(expected_size)?;
    let missing = env.missing_dependencies();
    if !missing.is_empty() {
        return Err(Error::value(format!(
            "Cannot continue: required tool(s) not found: {}. {} Nothing was changed.",
            missing.join(", "),
            env.missing_dependencies_hint(&missing)
        )));
    }
    let stage_dir = stage_seed_files(&files)?; // still before the drive is touched
    let _stage = StageGuard(stage_dir.clone());
    let shown = env.dev_path(dev);

    let rechecked =
        env.reverify_target_disk(dev, expected_size, ctx.log).and_then(|()| ctx.check_canceled(false, false));
    match rechecked {
        Ok(()) => {}
        Err(e) if e.is_canceled() => {
            // The safety re-check changes nothing: the drive is exactly as it was.
            env.audit(
                &format!("OPERATION CANCELED by the user before the drive was touched ({shown}); nothing was changed"),
                AuditLevel::Warning,
            );
            return Err(Error::canceled_with("Canceled by the user before the drive was touched.", false, false));
        }
        Err(e) => return Err(e),
    }
    env.audit(
        &format!(
            "DESTRUCTIVE OPERATION START: erasing {shown} and writing the {target} hardening seed (profile={profile}, \
             label={label}, files={}, bytes={}, sha256={})",
            files.len(),
            files.values().map(Vec::len).sum::<usize>(),
            seed_manifest_sha256(&files)
        ),
        AuditLevel::Info,
    );
    let outcome = env.with_sleep_prevented(ctx.log, &mut || match env.platform() {
        Platform::Mac => env.build_mac(&label, &files, &stage_dir, dev, ctx, eject),
        Platform::Windows => env.build_windows(&label, &files, &stage_dir, dev, ctx, eject),
        Platform::Linux => env.build_linux(&label, &files, &stage_dir, dev, ctx, eject),
    });
    let ejected = match outcome {
        Ok(ejected) => ejected,
        Err(Error::Canceled { message, drive_touched, written }) => {
            if !drive_touched {
                env.audit(
                    &format!(
                        "DESTRUCTIVE OPERATION CANCELED by the user on {shown} before the drive was touched; nothing \
                         was changed"
                    ),
                    AuditLevel::Warning,
                );
            } else if written {
                env.audit(
                    &format!(
                        "DESTRUCTIVE OPERATION CANCELED by the user on {shown} during verification; the seed files \
                         were written but NOT verified"
                    ),
                    AuditLevel::Warning,
                );
            } else {
                env.audit(
                    &format!("DESTRUCTIVE OPERATION CANCELED by the user on {shown}; the drive was left unusable"),
                    AuditLevel::Warning,
                );
            }
            return Err(Error::Canceled { message, drive_touched, written });
        }
        Err(e) => {
            env.audit(&format!("DESTRUCTIVE OPERATION FAILED on {shown}: {}", python_type_name(&e)), AuditLevel::Error);
            return Err(e);
        }
    };
    env.audit(
        &format!("DESTRUCTIVE OPERATION COMPLETED on {shown} (ejected={})", if ejected { "True" } else { "False" }),
        AuditLevel::Info,
    );
    Ok(ejected)
}

/// `build_seed_usb(target, dev, ...)`: create a seed drive for `target` (ubuntu, fedora, debian or windows): GPT +
/// FAT32 with the label and the files `hardening_files_seed(target, profile)` returns, verified by reading every file
/// back, then ejected.
///
/// Returns true if the drive was ejected. `Error::Value` (nothing touched) for a bad label, file set or drive, and
/// `Error::Canceled` on a cancel (`drive_touched` is false when nothing on the drive was changed).
pub fn build_seed_usb(
    target: SeedTarget,
    dev: &str,
    ctx: &Ctx,
    priv_: &dyn Privilege,
    expected_size: Option<u64>,
    eject: bool,
    profile: Hardening,
) -> Result<bool> {
    build_seed_usb_with(&RealSeedEnv { priv_ }, target, dev, ctx, expected_size, eject, profile)
}

#[cfg(test)]
mod tests;
