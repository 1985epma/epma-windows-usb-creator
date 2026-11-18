//! Small helpers. OWNER: A1. Port of win11_usb_creator.py lines 654-712 (human_size, silent_remove/rmdir,
//! eta_text, eta_remaining, rate_tail), plus the few Python standard-library behaviours the other modules lean on
//! (`os.path.expanduser`, `shutil.which`, `shutil.disk_usage`, `repr(str)`, `str.strip()`), because Rust's `std`
//! has no exact equivalent.

use crate::i18n::{fmt_named, tr_fmt};
use std::fmt::Display;
use std::io;
use std::path::{Path, PathBuf};

/// "58.6 GB" style size (one decimal; B, KB, MB, GB, TB, PB with 1024 steps).
pub fn human_size(n: u64) -> String {
    human_size_f64(n as f64)
}

/// `human_size` for a float (the Python function takes any number; `_rate_tail` passes a speed in bytes/second).
pub fn human_size_f64(n: f64) -> String {
    let mut n = n;
    for unit in ["B", "KB", "MB", "GB", "TB"] {
        if n < 1024.0 {
            return format!("{n:.1} {unit}");
        }
        n /= 1024.0;
    }
    format!("{n:.1} PB")
}

/// `_eta_text`: "~2m05s left" for the progress labels; "" when the speed is unknown (nothing to estimate from).
///
/// One helper for every progress label, so a long wait reads the same everywhere (minutes and seconds, never a
/// raw count of seconds). `translate == false` (the command line) keeps it English.
pub fn eta_text(remaining_seconds: f64, speed: f64, translate: bool) -> String {
    // `not speed or speed <= 0 or remaining is None or remaining < 0`; a NaN or infinite remaining time makes the
    // Python `int()` raise (ValueError / OverflowError), which also ends as "".
    if speed <= 0.0 || remaining_seconds < 0.0 || !remaining_seconds.is_finite() {
        return String::new();
    }
    let seconds = remaining_seconds as u64; // truncates toward zero, like int()
    let args: [(&str, &dyn Display); 2] = [("minutes", &(seconds / 60)), ("seconds", &(seconds % 60))];
    if translate {
        tr_fmt("~{minutes}m{seconds:02d}s left", &args)
    } else {
        fmt_named("~{minutes}m{seconds:02d}s left", &args)
    }
}

/// `_eta_remaining`: the time left to move `total - done` bytes at `speed` bytes per second ("" when the speed is
/// unknown).
pub fn eta_remaining(done: u64, total: u64, speed: f64, translate: bool) -> String {
    if speed <= 0.0 {
        return String::new();
    }
    // Not `total.saturating_sub(done)`: a `done` past `total` gives a negative time, which `eta_text` drops.
    eta_text((total as f64 - done as f64) / speed, speed, translate)
}

/// `_rate_tail`: " — 12.0 MB/s — ~2m05s left" for a progress label; "" when the speed is unknown.
pub fn rate_tail(done: u64, total: u64, speed: f64) -> String {
    if speed <= 0.0 {
        return String::new();
    }
    format!(" — {}/s — {}", human_size_f64(speed), eta_remaining(done, total, speed, true))
}

/// Remove a file, ignoring any error (`_silent_remove`).
pub fn silent_remove(path: impl AsRef<Path>) {
    let _ = std::fs::remove_file(path);
}

/// Remove an empty directory, ignoring any error (`_silent_rmdir`).
pub fn silent_rmdir(path: impl AsRef<Path>) {
    let _ = std::fs::remove_dir(path);
}

// ---------------------------------------------------------------------------------------------------------------
// Python standard-library behaviours (new public helpers)
// ---------------------------------------------------------------------------------------------------------------

/// Python's `str.isspace()` for one character: Unicode White_Space plus the ASCII separators U+001C..U+001F that
/// Python also treats as whitespace.
pub fn py_isspace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// Python's `str.strip()` (no argument).
pub fn py_strip(s: &str) -> &str {
    s.trim_matches(py_isspace)
}

/// Python's `str.rstrip()` (no argument).
pub fn py_rstrip(s: &str) -> &str {
    s.trim_end_matches(py_isspace)
}

/// Python's `str.splitlines()` (no `keepends`): the line boundaries are \n, \r, \r\n, \v, \f, \x1c-\x1e, \x85,
/// U+2028 and U+2029. A trailing boundary does not start a new empty line.
pub fn py_splitlines(s: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let is_break =
            matches!(c, '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{1c}'..='\u{1e}' | '\u{85}' | '\u{2028}' | '\u{2029}');
        if !is_break {
            continue;
        }
        lines.push(&s[start..i]);
        let mut next = i + c.len_utf8();
        if c == '\r' {
            if let Some(&(j, '\n')) = chars.peek() {
                chars.next();
                next = j + 1;
            }
        }
        start = next;
    }
    if start < s.len() {
        lines.push(&s[start..]);
    }
    lines
}

/// Python's `repr(str)`, for the `{x!r}` of the messages: single quotes unless the text contains a single quote and
/// no double quote; backslash, quote, \n \r \t and non-printable characters are escaped.
pub fn py_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if !py_printable(c) => {
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

/// `str.isprintable()` for one character. Without the Unicode category tables this treats controls, every
/// whitespace except the plain space, and the usual invisible format characters as non-printable.
fn py_printable(c: char) -> bool {
    if c == ' ' {
        return true;
    }
    if c.is_control() || c.is_whitespace() {
        return false;
    }
    !matches!(c as u32, 0xad | 0x600..=0x605 | 0x61c | 0x6dd | 0x70f | 0x180e | 0x200b..=0x200f | 0x202a..=0x202e
        | 0x2060..=0x206f | 0xfeff | 0xfff9..=0xfffb | 0xe000..=0xf8ff | 0xf0000..=0x10ffff)
}

/// `os.path.expanduser`: `~` and `~/rest` use the home directory (HOME, else the password database; on Windows
/// USERPROFILE, else HOMEDRIVE + HOMEPATH). The `~user` form and a missing home leave the path unchanged.
pub fn expand_user(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.first() != Some(&b'~') {
        return path.to_path_buf();
    }
    let is_sep = |b: &u8| *b == b'/' || (cfg!(windows) && *b == b'\\');
    if bytes.iter().position(is_sep).unwrap_or(bytes.len()) != 1 {
        return path.to_path_buf(); // "~user..." (not supported) or "~something"
    }
    let Some(home) = home_dir() else {
        return path.to_path_buf();
    };
    match path.strip_prefix("~") {
        Ok(rest) if rest.as_os_str().is_empty() => home,
        Ok(rest) => home.join(rest),
        Err(_) => path.to_path_buf(),
    }
}

/// The current user's home directory the way Python's `expanduser` finds it.
pub fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        if let Some(p) = std::env::var_os("USERPROFILE").filter(|v| !v.is_empty()) {
            return Some(PathBuf::from(p));
        }
        let path = std::env::var_os("HOMEPATH")?;
        let drive = std::env::var_os("HOMEDRIVE").unwrap_or_default();
        Some(PathBuf::from(drive).join(path))
    }
    #[cfg(unix)]
    {
        if let Some(p) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
            return Some(PathBuf::from(p));
        }
        passwd_home()
    }
}

#[cfg(unix)]
fn passwd_home() -> Option<PathBuf> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;
    let mut buf = vec![0u8; 4096];
    for _ in 0..4 {
        // SAFETY: `pwd` and `result` are plain out-parameters; `buf` outlives the call and its length is passed.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = unsafe {
            libc::getpwuid_r(libc::getuid(), &mut pwd, buf.as_mut_ptr() as *mut libc::c_char, buf.len(), &mut result)
        };
        if rc == libc::ERANGE {
            buf.resize(buf.len() * 4, 0);
            continue;
        }
        if rc != 0 || result.is_null() || pwd.pw_dir.is_null() {
            return None;
        }
        // SAFETY: getpwuid_r filled `pw_dir` with a NUL-terminated string inside `buf`, which is still alive.
        let dir = unsafe { CStr::from_ptr(pwd.pw_dir) };
        return Some(PathBuf::from(OsStr::from_bytes(dir.to_bytes())));
    }
    None
}

/// `shutil.which(name)`: the first executable called `name` on PATH (a name with a directory part is checked
/// directly). On Windows the extensions of PATHEXT are tried too. The current directory is never searched.
pub fn which(name: &str) -> Option<PathBuf> {
    if name.is_empty() {
        return None;
    }
    let has_dir = name.contains('/') || (cfg!(windows) && name.contains('\\'));
    if has_dir {
        let p = PathBuf::from(name);
        return is_executable_file(&p).then_some(p);
    }
    let path_var = std::env::var_os("PATH")
        .unwrap_or_else(|| std::ffi::OsString::from(if cfg!(windows) { "" } else { ":/bin:/usr/bin" }));
    #[cfg(windows)]
    let exts: Vec<String> = {
        let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
        pathext.split(';').filter(|e| !e.is_empty()).map(|e| e.to_string()).collect()
    };
    for dir in std::env::split_paths(&path_var) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        #[cfg(unix)]
        {
            let candidate = dir.join(name);
            if is_executable_file(&candidate) {
                return Some(candidate);
            }
        }
        #[cfg(windows)]
        {
            // Python: when the name already ends in one of the extensions it is tried as it is first.
            let lower = name.to_lowercase();
            let mut names = Vec::new();
            if exts.iter().any(|e| lower.ends_with(&e.to_lowercase())) {
                names.push(name.to_string());
            }
            names.extend(exts.iter().map(|e| format!("{name}{e}")));
            for n in names {
                let candidate = dir.join(n);
                if is_executable_file(&candidate) {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if meta.is_dir() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        // SAFETY: `c` is a valid NUL-terminated path for the duration of the call.
        unsafe { libc::access(c.as_ptr(), libc::X_OK) == 0 }
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// `os.access(path, os.R_OK)`: can the current (real) user read it?
pub fn is_readable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        // SAFETY: `c` is a valid NUL-terminated path for the duration of the call.
        unsafe { libc::access(c.as_ptr(), libc::R_OK) == 0 }
    }
    #[cfg(not(unix))]
    {
        // Windows has no real/effective split and `access` only looks at the read-only attribute: opening is the
        // honest test (for a directory it fails; callers check for a regular file first).
        std::fs::File::open(path).is_ok()
    }
}

/// `shutil.disk_usage(dir).free`: the bytes available to an unprivileged user on the volume holding `dir`
/// (`statvfs` f_bavail * f_frsize; `GetDiskFreeSpaceExW` "available to the caller" on Windows).
pub fn free_disk_space(dir: impl AsRef<Path>) -> io::Result<u64> {
    free_disk_space_impl(dir.as_ref())
}

#[cfg(unix)]
fn free_disk_space_impl(dir: &Path) -> io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
    // SAFETY: `c` is a valid NUL-terminated path; `st` is a plain out-structure that statvfs fills in.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c.as_ptr(), &mut st) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    #[allow(clippy::unnecessary_cast)] // the field widths differ between platforms
    Ok((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

#[cfg(windows)]
fn free_disk_space_impl(dir: &Path) -> io::Result<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let mut available: u64 = 0;
    let mut total: u64 = 0;
    let mut total_free: u64 = 0;
    // SAFETY: `wide` is a NUL-terminated UTF-16 string and the three out-pointers are valid for the call.
    let ok = unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut available, &mut total, &mut total_free) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(available)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_size_units() {
        assert_eq!(human_size(0), "0.0 B");
        assert_eq!(human_size(1023), "1023.0 B");
        assert_eq!(human_size(1024), "1.0 KB");
        assert_eq!(human_size(1536), "1.5 KB");
        assert_eq!(human_size(5 * 1024 * 1024), "5.0 MB");
        assert_eq!(human_size(16 * 1024 * 1024 * 1024), "16.0 GB");
        assert_eq!(human_size(2 * 1024u64.pow(4)), "2.0 TB");
        assert_eq!(human_size(3 * 1024u64.pow(5)), "3.0 PB");
        assert_eq!(human_size_f64(1536.0), "1.5 KB");
    }

    #[test]
    fn human_size_rounds_like_python() {
        // Python: f"{0.25:.1f}" == "0.2" and f"{0.35:.1f}" == "0.3" (the exact binary value decides).
        assert_eq!(human_size_f64(0.25), "0.2 B");
        assert_eq!(human_size_f64(0.35), "0.3 B");
        assert_eq!(human_size_f64(1024.0 * 1.25), "1.2 KB");
    }

    #[test]
    fn py_repr_matches_python() {
        assert_eq!(py_repr("sdb"), "'sdb'");
        assert_eq!(py_repr("it's"), "\"it's\"");
        assert_eq!(py_repr("a'b\"c"), "'a\\'b\"c'");
        assert_eq!(py_repr("tab\there\n"), "'tab\\there\\n'");
        assert_eq!(py_repr("back\\slash"), "'back\\\\slash'");
        assert_eq!(py_repr("\u{1}x"), "'\\x01x'");
        assert_eq!(py_repr("caf\u{e9}"), "'caf\u{e9}'");
        assert_eq!(py_repr("\u{a0}"), "'\\xa0'");
        assert_eq!(py_repr("\u{200b}"), "'\\u200b'");
    }

    #[test]
    fn splitlines_and_strip() {
        assert_eq!(py_splitlines("a\nb\r\nc\rd"), vec!["a", "b", "c", "d"]);
        assert_eq!(py_splitlines("a\n"), vec!["a"]);
        assert_eq!(py_splitlines("a\n\nb"), vec!["a", "", "b"]);
        assert_eq!(py_splitlines(""), Vec::<&str>::new());
        assert_eq!(py_splitlines("a\u{2028}b\u{b}c"), vec!["a", "b", "c"]);
        assert_eq!(py_strip(" \t x \u{a0}\n"), "x");
        assert_eq!(py_rstrip("x  \r\n"), "x");
    }

    #[test]
    fn eta_text_minutes_and_seconds() {
        assert_eq!(eta_text(125.0, 1.0, true), "~2m05s left");
        assert_eq!(eta_text(0.0, 1.0, true), "~0m00s left");
        assert_eq!(eta_text(3600.0, 1.0, true), "~60m00s left");
    }

    #[test]
    fn eta_text_is_empty_when_nothing_can_be_estimated() {
        for (remaining, speed) in [(10.0, 0.0), (10.0, -1.0), (-1.0, 5.0), (f64::INFINITY, 5.0), (f64::NAN, 5.0)] {
            assert_eq!(eta_text(remaining, speed, true), "", "{remaining} {speed}");
        }
    }

    #[test]
    fn eta_remaining_from_done_total_and_speed() {
        assert_eq!(eta_remaining(0, 1000, 10.0, true), "~1m40s left");
        assert_eq!(eta_remaining(1000, 1000, 10.0, true), "~0m00s left");
        assert_eq!(eta_remaining(0, 1000, 0.0, true), "");
        // done past total: a negative time is not shown
        assert_eq!(eta_remaining(2000, 1000, 10.0, true), "");
    }

    #[test]
    fn rate_tail_text() {
        assert_eq!(rate_tail(0, 2 * 1024 * 1024, 1024.0 * 1024.0), " — 1.0 MB/s — ~0m02s left");
        assert_eq!(rate_tail(0, 100, 0.0), "");
    }

    #[test]
    fn silent_remove_ignores_missing_files_and_non_empty_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        std::fs::write(&a, b"x").unwrap();
        std::fs::write(&b, b"y").unwrap();
        silent_remove(&a);
        silent_remove(dir.path().join("missing.txt"));
        silent_remove(&b);
        assert!(!a.exists() && !b.exists());

        let empty = dir.path().join("empty");
        let full = dir.path().join("full");
        std::fs::create_dir(&empty).unwrap();
        std::fs::create_dir(&full).unwrap();
        std::fs::write(full.join("file"), b"x").unwrap();
        silent_rmdir(&empty);
        silent_rmdir(&full);
        silent_rmdir(dir.path().join("missing"));
        assert!(!empty.exists());
        assert!(full.is_dir()); // not empty: left alone, no panic
    }

    #[test]
    fn free_space_of_the_temp_dir_is_known() {
        let dir = tempfile::tempdir().unwrap();
        assert!(free_disk_space(dir.path()).unwrap() > 0);
        assert!(free_disk_space(dir.path().join("nope")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn which_finds_sh_and_rejects_nonsense() {
        assert!(which("sh").is_some());
        assert!(which("definitely-not-a-command-xyz").is_none());
        assert!(which("").is_none());
        assert!(which("/bin/sh").is_some());
    }

    #[cfg(unix)]
    #[test]
    fn expand_user_uses_home() {
        let home = home_dir().expect("a home directory");
        assert_eq!(expand_user("~"), home);
        assert_eq!(expand_user("~/x/y"), home.join("x/y"));
        assert_eq!(expand_user("/abs/~/x"), PathBuf::from("/abs/~/x"));
        assert_eq!(expand_user("~someoneelse/x"), PathBuf::from("~someoneelse/x"));
        assert_eq!(expand_user("rel/x"), PathBuf::from("rel/x"));
    }
}
