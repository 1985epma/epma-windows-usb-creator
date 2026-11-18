//! Copying and read-back verification. OWNER: A2.
//! Port of win11_usb_creator.py lines 1109-1435 (progress-log wrappers, copy_file_with_progress, VERIFY_RAW_SCRIPT,
//! verify_raw_write, verify_windows_payload, find_case_insensitive, copy_windows_payload) and 3422-3505
//! (copy_tree_with_progress, files_equal, compare_trees, hash_split_parts).
//!
//! The operating-system side of the Windows payload copy (rsync, wimlib-imagex, DISM, sync) goes through the small
//! `CopyHost` trait: `SystemHost` is the real thing, the tests inject a fake (the Python tests patch `run_cmd`,
//! `shutil.which`, `IS_WINDOWS` and `FAT32_MAX_FILE_SIZE`).

use crate::audit::AuditLevel;
use crate::constants::{
    CHUNK_SIZE, DD_LOG_INTERVAL, FAT32_MAX_FILE_SIZE, IS_WINDOWS, VERIFY_CHUNK, VERIFY_PROGRESS_INTERVAL,
};
use crate::engine::{
    audit_event, check_image_for_hardening_clash, os_strerror, verify_hardening_files, which_tool,
    write_hardening_files,
};
use crate::hash::sha256_file;
use crate::proc::{cancel_flag, check_canceled};
use crate::types::{CancelToken, Ctx, Error, Files, Log, Privilege, Progress, Result};
use crate::util::human_size;
use regex::Regex;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Verifying a raw write: the root script that reads the drive back and compares it with the ISO, chunk by chunk.
/// It exits 0 and reports the result as a VERIFY_OK / VERIFY_FAIL marker line (so a mismatch is told apart from a
/// script error). Values arrive as "$1".."$5", never pasted into the text; "$5" is the cancel flag file
/// (VERIFY_CANCELED when it appears). The text is `assets/verify-raw.sh`, copied byte for byte from the Python.
pub const VERIFY_RAW_SCRIPT: &str = include_str!("../assets/verify-raw.sh");

static DD_BYTES_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\d+ bytes").expect("valid regex"));
static DD_COUNT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(\d+) bytes").expect("valid regex"));
static VERIFY_PROGRESS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^VERIFY_PROGRESS (\d+)$").expect("valid regex"));
static RSYNC_DIFF_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(>f|cd|\*deleting)").expect("valid regex"));
static SPLIT_PERCENT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(\d{1,3})(?:\.\d+)?%").expect("valid regex"));

/// `time.time()`.
fn wall_clock() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

// ---------------------------------------------------------------------------------------------------------------
// The operating-system side of the payload copy
// ---------------------------------------------------------------------------------------------------------------

/// What `copy_windows_payload` / `verify_windows_payload` ask of the operating system.
pub trait CopyHost {
    /// `IS_WINDOWS`: no rsync there, the copy and the comparison are done in plain Rust, DISM splits the image.
    fn is_windows(&self) -> bool {
        IS_WINDOWS
    }
    /// `FAT32_MAX_FILE_SIZE`: a file larger than this is split.
    fn fat32_max_file_size(&self) -> u64 {
        FAT32_MAX_FILE_SIZE
    }
    /// `shutil.which(tool)`.
    fn which(&self, tool: &str) -> bool {
        which_tool(tool).is_some()
    }
    /// `run_cmd(args, log, cancel_event=cancel)` (check=True, no timeout). Returns the exit code.
    fn run_cmd(&self, args: &[String], log: Log, cancel: Option<&CancelToken>) -> Result<i32> {
        crate::proc::run_cmd(args, log, true, None, cancel)
    }
    /// `sync_filesystems(log)`.
    fn sync_filesystems(&self, log: Log) {
        crate::proc::sync_filesystems(log)
    }
    /// `windows_dism_exe()`.
    fn dism_exe(&self) -> PathBuf {
        crate::windows::dism_exe()
    }
}

/// The real system.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemHost;
impl CopyHost for SystemHost {}

// ---------------------------------------------------------------------------------------------------------------
// dd progress
// ---------------------------------------------------------------------------------------------------------------

/// `make_progress_log` with the clock injected: wrap `log` so dd's frequent progress lines ("N bytes ...") are
/// shown at most every `interval` seconds. `now` is `time.time()`.
pub fn make_progress_log_with<'a>(
    log: Log<'a>,
    interval: f64,
    now: impl Fn() -> f64 + Send + Sync + 'a,
) -> Box<dyn Fn(&str) + Send + Sync + 'a> {
    let last = Mutex::new(0.0_f64);
    Box::new(move |line: &str| {
        if DD_BYTES_RE.is_match(line) {
            let t = now();
            let mut last = last.lock().unwrap_or_else(|e| e.into_inner());
            if t - *last < interval {
                return;
            }
            *last = t;
        }
        log(line);
    })
}

/// `make_progress_log(log, interval=DD_LOG_INTERVAL)`.
pub fn make_progress_log<'a>(log: Log<'a>, interval: f64) -> Box<dyn Fn(&str) + Send + Sync + 'a> {
    make_progress_log_with(log, interval, wall_clock)
}

/// `make_dd_log`: wraps `log` so dd's "N bytes ..." lines become progress updates (throttled) and log lines.
///
/// GNU dd (`status=progress`) and BSD dd (SIGINFO) both print the running byte count as "<N> bytes ...", so one
/// pattern covers both.
pub fn make_dd_log<'a>(
    log: Log<'a>,
    total: u64,
    progress: Option<Progress<'a>>,
) -> Box<dyn Fn(&str) + Send + Sync + 'a> {
    let throttled = make_progress_log(log, DD_LOG_INTERVAL);
    Box::new(move |line: &str| {
        if let (Some(m), true, Some(progress)) = (DD_COUNT_RE.captures(line), total > 0, progress) {
            // A count too large for u64 is clamped to the total like any other count above it.
            let n = m[1].parse::<u64>().unwrap_or(u64::MAX);
            progress(n.min(total), total, "Writing the image...");
        }
        throttled(line);
    })
}

// ---------------------------------------------------------------------------------------------------------------
// Single file copy
// ---------------------------------------------------------------------------------------------------------------

/// `shutil.copystat`: the modification and access times and the permission bits of `src` onto `dst`.
fn copy_stat(src: &Path, dst: &Path, dst_file: &File) -> Result<()> {
    let meta = fs::metadata(src)?;
    let mut times = fs::FileTimes::new();
    if let Ok(accessed) = meta.accessed() {
        times = times.set_accessed(accessed);
    }
    if let Ok(modified) = meta.modified() {
        times = times.set_modified(modified);
    }
    dst_file.set_times(times)?;
    fs::set_permissions(dst, meta.permissions())?;
    Ok(())
}

/// Copy `src` into `dst_dir` in chunks, reporting the bytes copied so far (`copy_file_with_progress`).
pub fn copy_file_with_progress(
    src: &Path,
    dst_dir: &Path,
    on_bytes: &dyn Fn(u64),
    cancel: Option<&CancelToken>,
) -> Result<()> {
    let name = src.file_name().ok_or_else(|| Error::value("The file to copy has no name."))?;
    let dst = dst_dir.join(name);
    let mut copied: u64 = 0;
    {
        let mut fin = File::open(src)?;
        let mut fout = File::create(&dst)?;
        let mut buf = vec![0u8; CHUNK_SIZE];
        loop {
            check_canceled(cancel, true, false)?;
            let n = read_full(&mut fin, &mut buf)?;
            if n == 0 {
                break;
            }
            fout.write_all(&buf[..n])?;
            copied += n as u64;
            on_bytes(copied);
        }
        copy_stat(src, &dst, &fout)?;
    }
    Ok(())
}

/// Python's `fh.read(n)`: fill `buf` unless the file ends first. Returns the bytes read (0 at the end).
fn read_full(reader: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

// ---------------------------------------------------------------------------------------------------------------
// Raw write verification
// ---------------------------------------------------------------------------------------------------------------

#[derive(Default)]
struct VerifyOutcome {
    ok: Option<bool>,
    canceled: bool,
    offset: String,
    last_progress: f64,
}

/// Read the drive back (privileged script) and compare it byte for byte with the ISO. Raises on any mismatch.
pub fn verify_raw_write(iso_path: impl AsRef<Path>, device_path: &str, ctx: &Ctx, priv_: &dyn Privilege) -> Result<()> {
    verify_raw_write_chunked(iso_path.as_ref(), device_path, ctx, priv_, VERIFY_CHUNK, &wall_clock)
}

/// `verify_raw_write` with the chunk size and the clock injected (the Python tests patch `VERIFY_CHUNK` and `time`).
pub fn verify_raw_write_chunked(
    iso_path: &Path,
    device_path: &str,
    ctx: &Ctx,
    priv_: &dyn Privilege,
    chunk: u64,
    clock: &(dyn Fn() -> f64 + Sync),
) -> Result<()> {
    let total = fs::metadata(iso_path)?.len();
    ctx.log("Verifying the written image: reading the drive back and comparing it with the ISO...");
    let state = Mutex::new(VerifyOutcome::default());

    let watch = |raw: &str| {
        let line = raw.trim();
        if let Some(m) = VERIFY_PROGRESS_RE.captures(line) {
            let done = m[1].parse::<u64>().unwrap_or(u64::MAX);
            let now = clock();
            let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
            if ctx.progress.is_some() && (now - st.last_progress >= VERIFY_PROGRESS_INTERVAL || done >= total) {
                st.last_progress = now;
                ctx.report(done.min(total), total, "Verifying the written image...");
            }
            return;
        }
        let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
        if line == "VERIFY_OK" {
            st.ok = Some(true);
        } else if line == "VERIFY_CANCELED" {
            st.canceled = true;
        } else if line.starts_with("VERIFY_FAIL") {
            st.ok = Some(false);
            st.offset = line.split_whitespace().last().unwrap_or("").to_string();
        } else {
            drop(st);
            ctx.log(line);
        }
    };

    ctx.check_canceled(true, true)?;
    {
        let flag = cancel_flag(ctx.cancel)?;
        let args = vec![
            iso_path.to_string_lossy().into_owned(),
            device_path.to_string(),
            total.to_string(),
            chunk.to_string(),
            flag.path().to_string_lossy().into_owned(),
        ];
        priv_.run_script(VERIFY_RAW_SCRIPT, &watch, &args)?;
    }
    let st = state.into_inner().unwrap_or_else(|e| e.into_inner());
    if st.canceled {
        ctx.log("Verification canceled. The image was written completely but NOT verified.");
        return Err(Error::canceled_with(
            "Canceled by the user during verification. The image was written but not verified.",
            true,
            true,
        ));
    }
    let Some(ok) = st.ok else {
        return Err(Error::runtime(
            "Could not complete the verification of the written drive. Do not trust this drive; run the creation again.",
        ));
    };
    if !ok {
        audit_event(&format!("VERIFICATION FAILED at byte {}", st.offset), AuditLevel::Error);
        return Err(Error::runtime(format!(
            "Verification FAILED: the data on the drive differs from the ISO (first difference \
             near byte {}).\n\nThe drive was NOT ejected and should not be used. \
             Try again, and if it fails again, the USB drive or its port may be faulty.",
            st.offset
        )));
    }
    audit_event("Verification passed (raw write matches the ISO)", AuditLevel::Info);
    ctx.log("Verification passed: the drive content is identical to the ISO.");
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Trees: walk, copy, compare
// ---------------------------------------------------------------------------------------------------------------

fn rel_key(rel: &str) -> String {
    rel.replace('\\', "/").to_lowercase()
}

/// `os.walk(root)` (top-down, the directory and file names sorted, symbolic links to directories not entered and
/// unreadable directories skipped): `f(directory, sorted file names)` for every directory.
fn walk_tree(root: &Path, f: &mut dyn FnMut(&Path, &[OsString]) -> Result<()>) -> Result<()> {
    let Ok(entries) = fs::read_dir(root) else {
        return Ok(());
    };
    let mut dirs: Vec<OsString> = Vec::new();
    let mut files: Vec<OsString> = Vec::new();
    for entry in entries.flatten() {
        // `entry.is_dir()` follows symbolic links, like os.walk: a link to a directory is listed as a directory.
        if entry.path().is_dir() {
            dirs.push(entry.file_name());
        } else {
            files.push(entry.file_name());
        }
    }
    dirs.sort();
    files.sort();
    f(root, &files)?;
    for dir in dirs {
        let path = root.join(&dir);
        let is_link = fs::symlink_metadata(&path).map(|m| m.file_type().is_symlink()).unwrap_or(false);
        if !is_link {
            walk_tree(&path, f)?;
        }
    }
    Ok(())
}

/// `os.path.relpath(path, root)` for a path known to be under `root`.
fn relative_to(path: &Path, root: &Path) -> PathBuf {
    path.strip_prefix(root).map(Path::to_path_buf).unwrap_or_else(|_| path.to_path_buf())
}

/// Copy every file under `src_root` to `dst_root`, except the relative path `skip_rel`; report bytes copied.
/// Returns the bytes copied.
///
/// Each file is flushed to the drive (`sync_all`) before the next one starts. Cancelable between chunks.
pub fn copy_tree_with_progress(
    src_root: &Path,
    dst_root: &Path,
    skip_rel: Option<&str>,
    on_bytes: &dyn Fn(u64),
    cancel: Option<&CancelToken>,
    log: Option<Log>,
) -> Result<u64> {
    let skip = skip_rel.map(rel_key);
    let mut done: u64 = 0;
    let mut buf = vec![0u8; CHUNK_SIZE];
    walk_tree(src_root, &mut |dir, files| {
        let rel_dir = relative_to(dir, src_root);
        let out_dir = if rel_dir.as_os_str().is_empty() { dst_root.to_path_buf() } else { dst_root.join(&rel_dir) };
        fs::create_dir_all(&out_dir)?;
        for name in files {
            let rel = rel_dir.join(name);
            let rel_text = rel.to_string_lossy().into_owned();
            if skip.as_deref().is_some_and(|s| rel_key(&rel_text) == s) {
                continue;
            }
            check_canceled(cancel, true, false)?;
            if let Some(log) = log {
                log(&rel_text.replace('\\', "/"));
            }
            let mut fin = File::open(dir.join(name))?;
            let mut fout = File::create(out_dir.join(name))?;
            loop {
                check_canceled(cancel, true, false)?;
                let n = read_full(&mut fin, &mut buf)?;
                if n == 0 {
                    break;
                }
                fout.write_all(&buf[..n])?;
                done += n as u64;
                on_bytes(done);
            }
            fout.flush()?;
            fout.sync_all()?;
        }
        Ok(())
    })?;
    Ok(done)
}

/// True when the two files hold the same bytes (read in chunks; cancelable).
fn files_equal(a: &Path, b: &Path, cancel: Option<&CancelToken>) -> Result<bool> {
    if fs::metadata(a)?.len() != fs::metadata(b)?.len() {
        return Ok(false);
    }
    let mut fa = File::open(a)?;
    let mut fb = File::open(b)?;
    // Buffers no larger than the file: thousands of small files are compared in one verification.
    let cap = fs::metadata(a)?.len().clamp(1, VERIFY_CHUNK) as usize;
    let mut ca = vec![0u8; cap];
    let mut cb = vec![0u8; cap];
    loop {
        check_canceled(cancel, true, true)?;
        let na = read_full(&mut fa, &mut ca)?;
        let nb = read_full(&mut fb, &mut cb)?;
        if na != nb || ca[..na] != cb[..nb] {
            return Ok(false);
        }
        if na == 0 {
            return Ok(true);
        }
    }
}

/// `filecmp.cmp(a, b, shallow=False)`: same size and same bytes (no cancel inside, like the Python).
fn files_identical(a: &Path, b: &Path) -> Result<bool> {
    if fs::metadata(a)?.len() != fs::metadata(b)?.len() {
        return Ok(false);
    }
    let mut fa = File::open(a)?;
    let mut fb = File::open(b)?;
    let mut ca = vec![0u8; 1024 * 1024];
    let mut cb = vec![0u8; 1024 * 1024];
    loop {
        let na = read_full(&mut fa, &mut ca)?;
        let nb = read_full(&mut fb, &mut cb)?;
        if na != nb || ca[..na] != cb[..nb] {
            return Ok(false);
        }
        if na == 0 {
            return Ok(true);
        }
    }
}

/// Names of the files under `src_root` (except `skip_rel`) that are missing from `dst_root` or differ there.
pub fn compare_trees(
    src_root: &Path,
    dst_root: &Path,
    skip_rel: Option<&str>,
    cancel: Option<&CancelToken>,
) -> Result<Vec<String>> {
    let skip = skip_rel.map(rel_key);
    let mut bad: Vec<String> = Vec::new();
    walk_tree(src_root, &mut |dir, files| {
        let rel_dir = relative_to(dir, src_root);
        for name in files {
            let rel = rel_dir.join(name);
            let rel_text = rel.to_string_lossy().into_owned();
            if skip.as_deref().is_some_and(|s| rel_key(&rel_text) == s) {
                continue;
            }
            let other = dst_root.join(&rel);
            let outcome = if !other.is_file() {
                Ok(Some("missing"))
            } else {
                files_equal(&dir.join(name), &other, cancel).map(|same| (!same).then_some("differs"))
            };
            match outcome {
                Ok(Some(why)) => bad.push(format!("{rel_text} ({why})")),
                Ok(None) => {}
                Err(Error::Io(e)) => bad.push(format!("{rel_text} (unreadable: {})", os_strerror(&e))),
                Err(other) => return Err(other),
            }
        }
        Ok(())
    })?;
    Ok(bad)
}

/// SHA-256 of every `<stem>*.swm` part in `sources_dir` (`hash_split_parts`): file name -> hex (the split install
/// image parts `<stem>.swm`, `<stem>2.swm`, ...), in name order.
pub fn hash_split_parts(sources_dir: &Path, stem: &str, cancel: Option<&CancelToken>) -> Result<Vec<(String, String)>> {
    let mut names: Vec<String> =
        fs::read_dir(sources_dir)?.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    let mut parts = Vec::new();
    for name in names {
        let low = name.to_lowercase();
        if low.starts_with(&stem.to_lowercase()) && low.ends_with(".swm") {
            let digest = sha256_file(sources_dir.join(&name), cancel, None)?;
            parts.push((name, digest));
        }
    }
    Ok(parts)
}

/// The real path of the entry in `directory` named `name` ignoring case, or None.
///
/// ISO detection upper-cases names, so a custom image with "Sources/Install.wim" counts as Windows; the copy must
/// therefore find it on a case-sensitive mount too.
pub fn find_case_insensitive(directory: &Path, name: &str) -> Option<PathBuf> {
    let mut entries: Vec<OsString> = fs::read_dir(directory).ok()?.flatten().map(|e| e.file_name()).collect();
    entries.sort();
    if entries.iter().any(|e| e.to_string_lossy() == name) {
        return Some(directory.join(name));
    }
    let wanted = name.to_lowercase();
    entries
        .into_iter()
        .find(|entry| entry.to_string_lossy().to_lowercase() == wanted)
        .map(|entry| directory.join(entry)) // the spelling on disk, even on a case-insensitive volume
}

// ---------------------------------------------------------------------------------------------------------------
// The Windows payload
// ---------------------------------------------------------------------------------------------------------------

fn path_text(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// `os.path.splitext(os.path.basename(path))[0]`.
fn stem_of(path: &Path) -> String {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    match name.rfind('.') {
        Some(i) if i > 0 => name[..i].to_string(),
        _ => name,
    }
}

/// Compare what is on the drive with the ISO. Raises on any mismatch.
///
/// Every file is compared by checksum (rsync dry run), and the install image is either compared directly or checked
/// with `wimlib-imagex verify` when it was split. On Windows (no rsync) the same check is made in Rust, and an install
/// image split by DISM is checked against `split_hashes` ({part name: SHA-256}, taken when the parts were written)
/// instead of `wimlib-imagex verify`. `extra_files` ({relative path: bytes}, the hardening files) are compared byte for
/// byte too. They never replace a file of the ISO (an image that already holds one is refused before anything is
/// copied), so the rsync comparison has no exemption: a hardening file that overwrote an ISO file shows up as a
/// difference.
pub fn verify_windows_payload(
    src_root: &Path,
    dst_root: &Path,
    rel_big: &str,
    big_file: &Path,
    ctx: &Ctx,
    extra_files: Option<&Files>,
    split_hashes: Option<&[(String, String)]>,
) -> Result<()> {
    verify_windows_payload_on(&SystemHost, src_root, dst_root, rel_big, big_file, ctx, extra_files, split_hashes)
}

/// `verify_windows_payload` against any `CopyHost`.
pub fn verify_windows_payload_on<H: CopyHost + ?Sized>(
    host: &H,
    src_root: &Path,
    dst_root: &Path,
    rel_big: &str,
    big_file: &Path,
    ctx: &Ctx,
    extra_files: Option<&Files>,
    split_hashes: Option<&[(String, String)]>,
) -> Result<()> {
    ctx.log("Verifying the copied files (reading them back from the drive)...");
    ctx.report(0, 0, "Verifying the copied files...");
    let mut bad: Vec<String> = Vec::new();

    if host.is_windows() {
        bad.extend(compare_trees(src_root, dst_root, Some(rel_big), ctx.cancel)?);
    } else {
        let found = Mutex::new(Vec::<String>::new());
        let watch = |line: &str| {
            ctx.log(line);
            if RSYNC_DIFF_RE.is_match(line) {
                found.lock().unwrap_or_else(|e| e.into_inner()).push(line.trim().to_string());
            }
        };
        let args = vec![
            "rsync".to_string(),
            "-rcn".to_string(),
            "-i".to_string(),
            format!("--exclude={rel_big}"),
            format!("{}/", path_text(src_root)),
            format!("{}/", path_text(dst_root)),
        ];
        host.run_cmd(&args, &watch, ctx.cancel)?;
        bad.extend(found.into_inner().unwrap_or_else(|e| e.into_inner()));
    }
    if !bad.is_empty() {
        audit_event(&format!("VERIFICATION FAILED: {} file(s) differ", bad.len()), AuditLevel::Error);
        return Err(Error::runtime(format!(
            "Verification FAILED: {} item(s) on the drive are missing or differ from the \
             ISO (for example: {}).\n\nThe drive was NOT ejected and should not be used.",
            bad.len(),
            bad[0]
        )));
    }

    let name = big_file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let rel_dir = Path::new(rel_big).parent().map(Path::to_path_buf).unwrap_or_default();
    let sources = dst_root.join(rel_dir);
    ctx.report(0, 0, "Verifying the install image...");
    let stem = stem_of(big_file);
    let swm = sources.join(format!("{stem}.swm"));
    if let Some(expected) = split_hashes.filter(|h| !h.is_empty()) {
        let now = hash_split_parts(&sources, &stem, ctx.cancel)?;
        if now != expected {
            return Err(Error::runtime(
                "Verification FAILED: the split install image on the drive differs from what was written.\n\n\
                 The drive was NOT ejected and should not be used.",
            ));
        }
    } else if swm.exists() {
        let args = vec![
            "wimlib-imagex".to_string(),
            "verify".to_string(),
            path_text(&swm),
            format!("--ref={}/{stem}*.swm", path_text(&sources)),
        ];
        match host.run_cmd(&args, ctx.log, ctx.cancel) {
            Ok(_) => {}
            // The Python catches RuntimeError, which OperationCanceled subclasses; a cancel stays a cancel here.
            Err(Error::Runtime(_)) => {
                return Err(Error::runtime(
                    "Verification FAILED: the split install image on the drive is damaged.\n\n\
                     The drive was NOT ejected and should not be used.",
                ))
            }
            Err(other) => return Err(other),
        }
    } else {
        check_canceled(ctx.cancel, true, false)?;
        if !files_identical(big_file, &sources.join(&name))? {
            return Err(Error::runtime(format!(
                "Verification FAILED: {name} on the drive differs from the ISO.\n\n\
                 The drive was NOT ejected and should not be used."
            )));
        }
    }
    if let Some(files) = extra_files.filter(|f| !f.is_empty()) {
        verify_hardening_files(dst_root, files, ctx.log, ctx.cancel)?;
    }
    audit_event("Verification passed (copied files match the ISO)", AuditLevel::Info);
    ctx.log("Verification passed: the files on the drive match the ISO.");
    Ok(())
}

/// Copy the contents of a mounted Windows ISO to the drive, reporting progress.
///
/// Everything except sources/install.wim|esd is copied with rsync; that file is copied directly, or split into
/// <4 GB parts when it exceeds the FAT32 limit. Progress is counted in bytes over the whole payload. The "sources"
/// folder and the install image are looked up ignoring case. `reopen` remounts the drive for the read-back and
/// returns the new root. `extra_files` ({relative path: bytes}, the hardening files) are written after the ISO's
/// files with `write_hardening_files` (plain file I/O as the user: both mounts are user-owned) and read back with
/// the rest.
pub fn copy_windows_payload(
    src_root: &Path,
    dst_root: &Path,
    ctx: &Ctx,
    wimlib_hint: &str,
    reopen: Option<&dyn Fn() -> Result<PathBuf>>,
    extra_files: Option<&Files>,
) -> Result<()> {
    copy_windows_payload_on(&SystemHost, src_root, dst_root, ctx, wimlib_hint, reopen, extra_files)
}

/// `copy_windows_payload` against any `CopyHost`.
pub fn copy_windows_payload_on<H: CopyHost + ?Sized>(
    host: &H,
    src_root: &Path,
    dst_root: &Path,
    ctx: &Ctx,
    wimlib_hint: &str,
    reopen: Option<&dyn Fn() -> Result<PathBuf>>,
    extra_files: Option<&Files>,
) -> Result<()> {
    let extra_files = extra_files.filter(|f| !f.is_empty());
    if let Some(files) = extra_files {
        check_image_for_hardening_clash(src_root, files)?; // before a single byte is copied
    }
    let sources_dir = find_case_insensitive(src_root, "sources");
    let mut big_file: Option<PathBuf> = None;
    for name in ["install.wim", "install.esd"] {
        let found = sources_dir.as_deref().and_then(|d| find_case_insensitive(d, name));
        if let Some(p) = found.filter(|p| p.is_file()) {
            big_file = Some(p);
            break;
        }
    }
    let Some(big_file) = big_file else {
        return Err(Error::runtime("Could not find sources/install.wim or sources/install.esd on the ISO."));
    };

    let mut rest_total: u64 = 0;
    walk_tree(src_root, &mut |dir, files| {
        for fname in files {
            let path = dir.join(fname);
            if path != big_file {
                if let Ok(meta) = fs::metadata(&path) {
                    rest_total += meta.len();
                }
            }
        }
        Ok(())
    })?;
    let size = fs::metadata(&big_file)?.len();
    let total = rest_total + size;
    let rest_done = AtomicU64::new(0);

    let report = |done: u64, text: &str| ctx.report(done.min(total), total, text);

    let rsync_log = |line: &str| {
        ctx.log(line);
        let name = line.trim();
        if name.is_empty() || name.ends_with('/') {
            return;
        }
        let path = src_root.join(name);
        if path.is_file() {
            // header/summary lines never resolve to a file
            let len = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            let now = rest_done.fetch_add(len, Ordering::SeqCst) + len;
            report(now.min(rest_total), "Copying files...");
        }
    };

    let rel_big_path = relative_to(&big_file, src_root);
    let rel_big = path_text(&rel_big_path);
    ctx.log("Copying files from the ISO to the USB drive (this can take several minutes)...");
    if host.is_windows() {
        // no rsync on Windows: the same copy in plain Rust (flushed file by file)
        copy_tree_with_progress(
            src_root,
            dst_root,
            Some(&rel_big),
            &|n| report(n.min(rest_total), "Copying files..."),
            ctx.cancel,
            Some(ctx.log),
        )?;
    } else {
        let args = vec![
            "rsync".to_string(),
            "-rv".to_string(),
            format!("--exclude={rel_big}"),
            format!("{}/", path_text(src_root)),
            format!("{}/", path_text(dst_root)),
        ];
        host.run_cmd(&args, &rsync_log, ctx.cancel)?;
    }
    report(rest_total, "Copying files...");
    ctx.check_canceled(true, false)?;

    // Same folder name as on the ISO (rsync created it); the drive's FAT32 ignores case anyway.
    let target_sources = dst_root.join(rel_big_path.parent().map(Path::to_path_buf).unwrap_or_default());
    fs::create_dir_all(&target_sources)?;

    let big_name = big_file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let big_stem = stem_of(&big_file);
    let mut split_hashes: Option<Vec<(String, String)>> = None;
    if size > host.fat32_max_file_size() {
        // Windows splits a .wim itself, with DISM
        let use_dism = host.is_windows() && big_name.to_lowercase().ends_with(".wim");
        let tool = if use_dism { "DISM" } else { "wimlib-imagex" };
        ctx.log(&format!("{big_name} is {} (over 4GB). Splitting with {tool}...", human_size(size)));
        if !use_dism && !host.which("wimlib-imagex") {
            return Err(Error::runtime(wimlib_hint));
        }
        let out_swm = target_sources.join(format!("{big_stem}.swm"));

        let split_log = |line: &str| {
            ctx.log(line);
            if let Some(m) = SPLIT_PERCENT_RE.captures(line) {
                let pct = m[1].parse::<u64>().unwrap_or(100).min(100);
                report(rest_total + size * pct / 100, "Splitting the install image...");
            }
        };

        if use_dism {
            let args = vec![
                path_text(&host.dism_exe()),
                "/Split-Image".to_string(),
                format!("/ImageFile:{}", path_text(&big_file)),
                format!("/SWMFile:{}", path_text(&out_swm)),
                "/FileSize:3800".to_string(),
            ];
            host.run_cmd(&args, &split_log, ctx.cancel)?;
            // The parts are not byte copies of the source, so the read-back cannot compare them with it: it
            // compares them with what was written (checked after the drive is detached and attached again).
            report(total, "Checking the split install image...");
            let hashes = hash_split_parts(&target_sources, &big_stem, ctx.cancel)?;
            if hashes.is_empty() {
                return Err(Error::runtime("DISM finished but no .swm part was found on the drive."));
            }
            split_hashes = Some(hashes);
        } else {
            let args = vec![
                "wimlib-imagex".to_string(),
                "split".to_string(),
                path_text(&big_file),
                path_text(&out_swm),
                "3800".to_string(),
            ];
            host.run_cmd(&args, &split_log, ctx.cancel)?;
        }
    } else {
        ctx.log(&format!("Copying {big_name} ({})...", human_size(size)));
        copy_file_with_progress(
            &big_file,
            &target_sources,
            &|n| report(rest_total + n, "Copying the install image..."),
            ctx.cancel,
        )?;
    }

    if let Some(files) = extra_files {
        // Hardening files go on after the ISO's own files and before the remount, so the read-back below covers
        // them too.
        report(total, "Adding hardening files...");
        ctx.log("Adding hardening files...");
        ctx.check_canceled(true, false)?;
        write_hardening_files(dst_root, files, ctx.cancel)?;
    }

    report(total, "Flushing data to the drive...");
    ctx.check_canceled(true, false)?;
    ctx.log("Syncing writes to disk...");
    host.sync_filesystems(ctx.log);
    // Remount so the check reads from the device itself and not from the system cache.
    let remounted;
    let dst_root: &Path = match reopen {
        Some(reopen) => {
            remounted = reopen()?;
            &remounted
        }
        None => dst_root,
    };
    verify_windows_payload_on(host, src_root, dst_root, &rel_big, &big_file, ctx, extra_files, split_hashes.as_deref())
        .map_err(|e| match e {
            // everything was copied; only the final check was interrupted
            Error::Canceled { message, drive_touched, .. } => Error::Canceled { message, drive_touched, written: true },
            other => other,
        })
}
