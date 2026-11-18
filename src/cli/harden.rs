//! The hardening files on the command line: `_hardening_files`, `_hardening_file_names` and `harden-files` (write the
//! files of one target into a new or empty folder; no drive, no privileges). Python `cmd_harden_files`,
//! `_fill_staging_folder`, `_install_staged`.

use super::commands::strerror;
use super::io::{json_dumps, obj, Env, J};
use super::parser::{FilesArgs, FilesKind, HARDEN_FILES_WINDOWS_SAME_USB_NOTE};
use super::{CliError, Failure, EXIT_OK};
use crate::constants::PRIVATE_FILE_MODE;
use crate::types::{Files, Hardening, SeedTarget};
use crate::util::silent_remove;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

/// `_hardening_files(kind)`: `(volume label or None, validated {relative path: bytes})` for 'windows', 'windows-seed'
/// or a seed target.
///
/// The shared validator that `build_usb()` / `build_seed_usb()` apply is used here too, so a plan or a folder never
/// holds files the engine would refuse. A refusal becomes a `CliError`. Note that `Windows` here is always the
/// same-USB set; `harden-seed --target windows` is `WindowsSeed` (see `FilesKind::of_seed_target`).
pub fn hardening_files(env: &Env, kind: FilesKind) -> Result<(Option<String>, Files), CliError> {
    let engine = &*env.engine;
    let built = match kind {
        FilesKind::Windows => engine.hardening_files_windows(Hardening::Baseline).map(|files| (None, files)),
        FilesKind::WindowsSeed => engine
            .hardening_files_seed(SeedTarget::Windows, Hardening::Baseline)
            .map(|(label, files)| (Some(label), files)),
        FilesKind::Seed(target) => {
            engine.hardening_files_seed(target, Hardening::Baseline).map(|(label, files)| (Some(label), files))
        }
    };
    built.and_then(|(label, files)| engine.validate_seed_files(&files).map(|files| (label, files))).map_err(|e| match e
    {
        crate::types::Error::Value(m) => CliError::new(format!("The hardening files are not valid: {m}")),
        other => CliError::new(other.to_string()),
    })
}

/// `_hardening_file_names(kind)`: the names (never the contents) of the hardening files, sorted.
pub fn hardening_file_names(env: &Env, kind: FilesKind) -> Result<Vec<String>, CliError> {
    let (_label, files) = hardening_files(env, kind)?;
    let mut names: Vec<String> = files.keys().cloned().collect();
    names.sort();
    Ok(names)
}

// ---------------------------------------------------------------------------------------------------------------
// Paths (os.path.expanduser / abspath / normpath: lexical, no symlink is resolved)
// ---------------------------------------------------------------------------------------------------------------

/// `os.path.expanduser(path)` for `~` and `~/...` (`~name` is left alone).
fn expanduser(env: &Env, path: &str) -> String {
    if !path.starts_with('~') {
        return path.to_string();
    }
    let end = path.find(['/', '\\']).unwrap_or(path.len());
    if end > 1 {
        return path.to_string();
    }
    let home = env.env_var("HOME").or_else(|| env.env_var("USERPROFILE")).filter(|h| !h.is_empty());
    match home {
        Some(home) => {
            let joined = format!("{}{}", home.trim_end_matches('/'), &path[end..]);
            if joined.is_empty() {
                "/".to_string()
            } else {
                joined
            }
        }
        None => path.to_string(),
    }
}

/// `os.path.normpath`: collapse `.`, `..` and repeated separators without touching the file system.
fn normpath(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() && !path.has_root() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    out
}

/// `os.path.abspath(os.path.expanduser(path))`.
fn abspath(env: &Env, path: &str) -> PathBuf {
    let expanded = PathBuf::from(expanduser(env, path));
    let full = if expanded.is_absolute() {
        expanded
    } else {
        std::env::current_dir().map(|cwd| cwd.join(&expanded)).unwrap_or(expanded)
    };
    normpath(&full)
}

// ---------------------------------------------------------------------------------------------------------------
// Staging folder
// ---------------------------------------------------------------------------------------------------------------

/// Why writing the files failed: an OS error (shown with its `strerror`) or a refused path.
#[derive(Debug)]
pub enum WriteFailure {
    Io(io::Error),
    Value(String),
}

impl WriteFailure {
    fn text(&self) -> String {
        match self {
            WriteFailure::Io(e) => strerror(e),
            WriteFailure::Value(m) => m.clone(),
        }
    }
}

impl From<io::Error> for WriteFailure {
    fn from(e: io::Error) -> Self {
        WriteFailure::Io(e)
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

/// Create a file that must not exist yet, owner-only, never through a symlink (`O_CREAT | O_EXCL | O_NOFOLLOW`).
pub(crate) fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(PRIVATE_FILE_MODE).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

/// Write `files` into the private staging folder `stage`.
///
/// Nothing the user can see is touched here, so a failure leaves nothing behind (the caller removes the staging
/// folder). Folders end up 0700 and files 0600 (private, like every file this program creates), whatever the umask.
/// `create` opens each file (the tests make it fail on purpose).
pub(crate) fn fill_staging_folder_with(
    stage: &Path,
    files: &Files,
    create: &dyn Fn(&Path) -> io::Result<File>,
) -> Result<(), WriteFailure> {
    set_mode(stage, 0o700)?;
    for (rel, data) in files {
        let parts: Vec<&str> = rel.split('/').collect();
        let target = normpath(&stage.join(parts.join("/")));
        // validate_seed_files() already refused these; this is the second lock on the same door.
        if parts.contains(&"..") || parts.contains(&"") || !target.starts_with(stage) || target == stage {
            return Err(WriteFailure::Value(format!("Refusing a path outside the folder: {rel}")));
        }
        let folder = target.parent().unwrap_or(stage);
        if folder != stage && !folder.is_dir() {
            fs::DirBuilder::new().recursive(true).create(folder)?;
            let mut part = folder.to_path_buf();
            while part != stage {
                // create_dir_all applies the umask to every level it creates
                set_mode(&part, 0o700)?;
                if !part.pop() {
                    break;
                }
            }
        }
        let mut file = create(&target)?;
        file.write_all(data)?;
        drop(file);
        set_mode(&target, PRIVATE_FILE_MODE)?;
    }
    Ok(())
}

/// Move the staged entries to `out` (a new name, or an existing empty folder). Undone on failure. `rename` moves one
/// entry (the tests make it fail on purpose).
pub(crate) fn install_staged_with(
    stage: &Path,
    out: &Path,
    out_existed: bool,
    rename: &dyn Fn(&Path, &Path) -> io::Result<()>,
) -> Result<(), WriteFailure> {
    if !out_existed {
        // one atomic step: the folder appears complete or not at all
        return rename(stage, out).map_err(WriteFailure::from);
    }
    let mut moved: Vec<PathBuf> = Vec::new();
    let attempt = (|| -> Result<(), WriteFailure> {
        let mut names: Vec<_> =
            fs::read_dir(stage)?.collect::<Result<Vec<_>, _>>()?.into_iter().map(|e| e.file_name()).collect();
        names.sort();
        for name in names {
            let dest = out.join(&name);
            if fs::symlink_metadata(&dest).is_ok() {
                // the folder was empty a moment ago: never overwrite what appeared
                return Err(WriteFailure::Io(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} appeared while the files were being written", dest.display()),
                )));
            }
            rename(&stage.join(&name), &dest)?;
            moved.push(dest);
        }
        fs::remove_dir(stage)?;
        Ok(())
    })();
    if attempt.is_err() {
        for dest in &moved {
            if dest.is_dir() && !fs::symlink_metadata(dest).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
                let _ = fs::remove_dir_all(dest);
            } else {
                silent_remove(dest);
            }
        }
    }
    attempt
}

/// `harden-files`: write the hardening files for one target into a new or empty folder.
pub fn cmd_harden_files(env: &Env, args: &FilesArgs) -> Result<i32, Failure> {
    let target = args.target;
    let out = abspath(env, &args.out);
    let shown = out.display().to_string();
    if fs::symlink_metadata(&out).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
        return Err(
            CliError::new(format!("{shown} is a symbolic link. Pass a real folder that is new or empty.")).into()
        );
    }
    let out_existed = fs::symlink_metadata(&out).is_ok();
    if out_existed {
        if !out.is_dir() {
            return Err(CliError::new(format!("Not a folder: {shown}")).into());
        }
        let not_empty = fs::read_dir(&out).map_err(|e| CliError::new(e.to_string()))?.next().is_some();
        if not_empty {
            return Err(CliError::new(format!(
                "The folder is not empty: {shown}. Pass a new folder or an empty one; nothing was written."
            ))
            .into());
        }
    }
    let parent = out.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    if !parent.is_dir() {
        return Err(CliError::new(format!("The parent folder does not exist: {}", parent.display())).into());
    }
    let (label, files) = hardening_files(env, target)?;
    write_into(&parent, &out, out_existed, &files).map_err(|failure| {
        CliError::new(format!(
            "Could not write the hardening files to {shown}: {}. Nothing was left behind.",
            failure.text()
        ))
    })?;
    let mut names: Vec<&String> = files.keys().collect();
    names.sort();
    if args.json {
        let listing = J::List(
            names
                .iter()
                .map(|n| obj(vec![("path", J::str(n.as_str())), ("bytes", J::int(files[n.as_str()].len() as u64))]))
                .collect(),
        );
        env.out(&json_dumps(&obj(vec![
            ("target", J::str(target.as_str())),
            ("out", J::str(&shown)),
            ("volume_label", J::opt_str(label.as_deref())),
            ("files", listing),
        ])));
    } else {
        for name in &names {
            env.out(name);
        }
    }
    env.err(&format!(
        "Wrote {} files to {shown}. They are plain text: read them before using them. No drive was touched.",
        names.len()
    ));
    if target == FilesKind::Windows {
        env.err(HARDEN_FILES_WINDOWS_SAME_USB_NOTE);
    }
    Ok(EXIT_OK)
}

/// Stage the files beside the destination (so the final move stays on one file system: an atomic rename), fill the
/// staging folder, move it into place, and always remove what is left of the staging folder.
fn write_into(parent: &Path, out: &Path, out_existed: bool, files: &Files) -> Result<(), WriteFailure> {
    write_into_with(parent, out, out_existed, files, &create_private_file, &|from, to| fs::rename(from, to))
}

pub(crate) fn write_into_with(
    parent: &Path,
    out: &Path,
    out_existed: bool,
    files: &Files,
    create: &dyn Fn(&Path) -> io::Result<File>,
    rename: &dyn Fn(&Path, &Path) -> io::Result<()>,
) -> Result<(), WriteFailure> {
    let stage = tempfile::Builder::new().prefix(".epma-harden-").tempdir_in(parent)?.keep();
    let outcome = fill_staging_folder_with(&stage, files, create)
        .and_then(|()| install_staged_with(&stage, out, out_existed, rename));
    if fs::symlink_metadata(&stage).is_ok() {
        let _ = fs::remove_dir_all(&stage);
    }
    outcome
}
