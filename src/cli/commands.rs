//! The read-only commands: `list`, `detect`, `sha256` and `fetch-chromeos` (Python `cmd_list`, `cmd_detect`,
//! `cmd_sha256`, `cmd_fetch_chromeos`, `cli_detect_kind`, `cli_sha256_file`, `_list_disks`).

use super::io::{json_dumps, obj, CliProgress, Env, J};
use super::plan::DiskSummary;
use super::{CliError, Failure, EXIT_OK, EXIT_USAGE, EXIT_VERIFY_FAILED};
use crate::constants::{CHROMEOS_FLEX_FREE_BYTES, CHROMEOS_FLEX_GUIDE_URL, CHROMEOS_FLEX_URL};
use crate::types::{CancelToken, Disk, IsoKind, Result};
use crate::util::{human_size, silent_remove};
use crate::validate::{is_sha256_hex, resolve_path};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// `_list_disks()`: `get_external_disks()` with a failure turned into the command line's `CliError`.
pub fn list_disks(env: &Env) -> std::result::Result<Vec<Disk>, CliError> {
    env.engine.get_external_disks().map_err(|e| CliError::new(format!("Could not list the drives: {e}")))
}

/// `cli_detect_kind(iso)`: `(kind, method)` with kind one of windows, linux, chromeos, macos or unknown.
///
/// Uses `detect_iso_kind()` (reads the ISO), then the hybrid-image boot signature. The FILE NAME is never used: a
/// guess from the name could select the destructive Windows mode for an unrelated image ("darwin-linux.img"
/// contains "win"), so content that cannot be recognised stays "unknown" and the user must pass `--mode`.
pub fn cli_detect_kind(env: &Env, iso: &Path) -> (IsoKind, &'static str) {
    let kind = env.engine.detect_iso_kind(iso); // never fails
    if kind.mode().is_some() {
        return (kind, "content");
    }
    match env.engine.validate_hybrid_iso(iso) {
        Ok(()) => (IsoKind::Linux, "boot-signature"),
        Err(_) => (IsoKind::Unknown, "none"),
    }
}

/// `cli_sha256_file(path, progress)`: reports `(done, total, "Computing SHA-256...")` to the progress line.
pub fn cli_sha256_file(env: &Env, path: &Path, cancel: Option<&CancelToken>, progress: &CliProgress) -> Result<String> {
    let report = |done: u64, total: u64| progress.call(done, total, "Computing SHA-256...");
    env.engine.sha256_file(path, cancel, Some(&report))
}

/// Run `op` with a cancel token that Ctrl-C sets, for the commands that have no signal handling of their own.
/// Returns the result and whether Ctrl-C was pressed (the Python code let `KeyboardInterrupt` propagate).
pub fn interruptible<T>(env: &Env, op: impl FnOnce(&CancelToken) -> T) -> (T, bool) {
    let _guard = env.interrupts.install();
    let cancel = CancelToken::new();
    let stop = AtomicBool::new(false);
    let result = std::thread::scope(|scope| {
        scope.spawn(|| {
            while !stop.load(Ordering::SeqCst) {
                if env.interrupts.count() >= 1 {
                    cancel.set();
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let result = op(&cancel);
        stop.store(true, Ordering::SeqCst);
        result
    });
    (result, env.interrupts.count() >= 1)
}

/// What `str(OSError).strerror` gives: the system's text without Rust's " (os error N)" suffix.
pub fn strerror(err: &std::io::Error) -> String {
    let text = err.to_string();
    match text.rfind(" (os error ") {
        Some(i) if text.ends_with(')') => text[..i].to_string(),
        _ => text,
    }
}

// ---------- commands ----------

pub fn cmd_list(env: &Env, json: bool) -> std::result::Result<i32, Failure> {
    let disks = list_disks(env)?;
    if json {
        let list = J::List(disks.iter().map(|d| DiskSummary::of(d).json()).collect());
        env.out(&json_dumps(&obj(vec![("disks", list)])));
        return Ok(EXIT_OK);
    }
    if disks.is_empty() {
        env.err("No USB drives found. Plug one in and try again.");
        return Ok(EXIT_OK);
    }
    let has_model = disks.iter().any(|d| d.model.as_deref().is_some_and(|m| !m.is_empty()));
    let mut header = vec!["ID".to_string(), "SIZE".to_string()];
    if has_model {
        header.push("MODEL".to_string());
    }
    header.push("LABEL".to_string());
    let mut rows = vec![header];
    for d in &disks {
        let mut row = vec![d.id.clone(), human_size(d.size)];
        if has_model {
            row.push(d.model.clone().unwrap_or_default());
        }
        row.push(d.label.clone());
        rows.push(row);
    }
    let widths: Vec<usize> =
        (0..rows[0].len()).map(|i| rows.iter().map(|r| r[i].chars().count()).max().unwrap_or(0)).collect();
    for row in &rows {
        let cells: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(i, cell)| format!("{cell}{}", " ".repeat(widths[i].saturating_sub(cell.chars().count()))))
            .collect();
        env.out(cells.join("  ").trim_end());
    }
    Ok(EXIT_OK)
}

pub fn cmd_detect(env: &Env, iso: &str, json: bool) -> std::result::Result<i32, Failure> {
    let iso = resolve_path(iso);
    if !iso.is_file() {
        return Err(CliError::new(format!("Not a file: {}", iso.display())).into());
    }
    let (kind, method) = cli_detect_kind(env, &iso);
    if json {
        env.out(&json_dumps(&obj(vec![
            ("iso", J::str(iso.display().to_string())),
            ("kind", J::str(kind.as_str())),
            ("method", J::str(method)),
        ])));
    } else {
        env.out(kind.as_str());
    }
    Ok(EXIT_OK)
}

pub fn cmd_sha256(env: &Env, iso: &str, expected: Option<&str>, json: bool) -> std::result::Result<i32, Failure> {
    let mut expected_hash = None;
    if let Some(given) = expected.filter(|e| !e.is_empty()) {
        let mut value = given.trim().to_lowercase();
        if let Some(rest) = value.strip_prefix("sha256:") {
            value = rest.to_string();
        }
        if !is_sha256_hex(&value) {
            return Err(CliError::with_code(
                "--expected must be a 64-character hexadecimal SHA-256 value.",
                EXIT_USAGE,
            )
            .into());
        }
        expected_hash = Some(value);
    }
    let iso = resolve_path(iso);
    if !iso.is_file() {
        return Err(CliError::new(format!("Not a file: {}", iso.display())).into());
    }
    let progress = env.new_progress();
    let (outcome, interrupted) = interruptible(env, |cancel| cli_sha256_file(env, &iso, Some(cancel), &progress));
    progress.finish();
    if interrupted {
        return Err(Failure::Interrupted);
    }
    let digest = match outcome {
        Ok(digest) => digest,
        Err(crate::types::Error::Io(e)) => {
            return Err(CliError::new(format!("Could not read {}: {}", iso.display(), strerror(&e))).into())
        }
        Err(other) => return Err(other.into()),
    };
    let matched = expected_hash.as_ref().map(|e| *e == digest);
    if json {
        env.out(&json_dumps(&obj(vec![
            ("file", J::str(iso.display().to_string())),
            ("sha256", J::str(&digest)),
            ("expected", J::opt_str(expected_hash.as_deref())),
            ("match", matched.map(J::Bool).unwrap_or(J::Null)),
        ])));
    } else {
        env.out(&format!("{digest}  {}", iso.display()));
    }
    match (matched, expected_hash) {
        (Some(false), Some(expected)) => {
            env.error(&format!("The checksum does not match.\n  expected: {expected}\n  actual:   {digest}"));
            Ok(EXIT_VERIFY_FAILED)
        }
        (Some(true), _) => {
            env.err("Checksum matches.");
            Ok(EXIT_OK)
        }
        _ => Ok(EXIT_OK),
    }
}

/// Download ChromeOS Flex from Google and extract the disk image (nothing is written to a drive).
pub fn cmd_fetch_chromeos(
    env: &Env,
    dest: Option<&str>,
    keep_zip_flag: bool,
    json: bool,
) -> std::result::Result<i32, Failure> {
    let dest_dir = resolve_path(dest.filter(|d| !d.is_empty()).unwrap_or("."));
    if !dest_dir.is_dir() {
        return Err(CliError::new(format!("Not a folder: {}", dest_dir.display())).into());
    }
    let zip_path = dest_dir.join("chromeos_flex_latest.bin.zip");
    let part_path = PathBuf::from(format!("{}.part", zip_path.display()));
    // A complete ZIP from an earlier run (the download finished, the extraction did not) is extracted again instead
    // of being downloaded again; an unfinished ".part" is resumed.
    let reuse_zip = zip_path.exists() && !part_path.exists();
    env.err(&format!("ChromeOS Flex is provided by Google under Google's own terms: {CHROMEOS_FLEX_GUIDE_URL}"));
    if let Some(free) = env.engine.free_space(&dest_dir) {
        if free < CHROMEOS_FLEX_FREE_BYTES {
            env.warn(&format!(
                "Downloading and extracting needs roughly {} free; {} is available in {}.",
                human_size(CHROMEOS_FLEX_FREE_BYTES),
                human_size(free),
                dest_dir.display()
            ));
        }
    }
    let progress = env.new_progress();
    let (outcome, interrupted) = interruptible(env, |cancel| -> Result<(String, PathBuf)> {
        let sha256 = if reuse_zip {
            env.err(&format!(
                "{} is already there: extracting it again instead of downloading it. (Remove that file to download a \
                 fresh copy.)",
                zip_path.display()
            ));
            cli_sha256_file(env, &zip_path, Some(cancel), &progress)?
        } else {
            let report = |done: u64, total: u64, _text: &str| progress.call(done, total, "Downloading");
            env.engine.download(CHROMEOS_FLEX_URL, &zip_path, Some(&report), Some(cancel))?
        };
        let extracting = |done: u64, total: u64| progress.call(done, total, "Extracting");
        let image = env.engine.extract_disk_image(&zip_path, &dest_dir, Some(&extracting), Some(cancel))?;
        Ok((sha256, image))
    });
    progress.finish();
    if interrupted {
        return Err(Failure::Interrupted);
    }
    let (sha256, image) = match outcome {
        Ok(done) => done,
        Err(e) => {
            let mut message = e.to_string();
            if zip_path.exists() && !part_path.exists() {
                message.push_str(&format!(
                    "\n\nThe downloaded file was kept: {}\nFix the problem (for example free up space) and run '{} \
                     fetch-chromeos' again to extract it, or remove the file to download it afresh.",
                    zip_path.display(),
                    super::CLI_PROG
                ));
            }
            return Err(CliError::new(message).into());
        }
    };
    // A ZIP that was already there is the user's to keep; only one downloaded now is removed.
    let keep_zip = keep_zip_flag || reuse_zip;
    if !keep_zip {
        silent_remove(&zip_path);
    }
    let image = image.display().to_string();
    if json {
        env.out(&json_dumps(&obj(vec![
            ("image", J::str(&image)),
            ("zip_sha256", J::str(&sha256)),
            ("kept_zip", J::Bool(keep_zip)),
        ])));
    } else {
        env.out(&image);
    }
    env.err(&format!("Done. Write it with: {} write --iso {image} --disk <DISKID> --mode chromeos", super::CLI_PROG));
    Ok(EXIT_OK)
}
