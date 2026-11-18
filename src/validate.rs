//! Validators. OWNER: A1. Port of win11_usb_creator.py lines 783-855 (device/ISO validation), 1059-1107
//! (SHA-256 parsing, validate_disk_image) and 1436-1465 (validate_download_url).

use crate::audit::{audit_at, AuditLevel};
use crate::constants::{
    ALLOWED_URL_SCHEMES, CHROMEOS_FLEX_URL, DEFAULT_TRUSTED_ISO_HOSTS, ENV_ALLOW_ANY_HOST, ENV_TRUSTED_HOSTS, IS_MAC,
    IS_WINDOWS, LINUX_DEVICE_RE, MAC_DEVICE_RE, MBR_SIGNATURE, MBR_SIGNATURE_OFFSET, MIN_IMAGE_BYTES,
    WINDOWS_DEVICE_RE,
};
use crate::types::{Error, Result};
use crate::util::{expand_user, human_size, is_readable, py_repr, py_splitlines, py_strip};
use std::io::Read;
use std::net::Ipv6Addr;
use std::path::{Component, Path, PathBuf};

/// Which family of disk identifiers is valid: the pattern depends on the host OS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostOs {
    Mac,
    Linux,
    Windows,
}

impl HostOs {
    pub fn current() -> HostOs {
        if IS_MAC {
            HostOs::Mac
        } else if IS_WINDOWS {
            HostOs::Windows
        } else {
            HostOs::Linux
        }
    }
}

/// Returns `dev` if it is a plausible disk identifier for this OS (`ValueError` otherwise; audits the rejection).
///
/// Rejecting is safer than escaping: this value reaches privileged commands.
pub fn validate_device_name(dev: &str) -> Result<String> {
    validate_device_name_for(dev, HostOs::current())
}

/// `validate_device_name` for a given OS (the Python tests patch `IS_MAC`).
pub fn validate_device_name_for(dev: &str, host: HostOs) -> Result<String> {
    if dev.is_empty() {
        return Err(Error::value("No disk was selected."));
    }
    let pattern = match host {
        HostOs::Mac => &*MAC_DEVICE_RE,
        HostOs::Windows => &*WINDOWS_DEVICE_RE,
        HostOs::Linux => &*LINUX_DEVICE_RE,
    };
    // Both ends are anchored. (The Python needs fullmatch because "$" also matches before a trailing newline, so
    // "sdb\n" would pass; the Rust regex "$" only matches at the very end, so it cannot.)
    if !pattern.is_match(dev) {
        audit_at(&format!("REJECTED invalid device identifier: {}", py_repr(dev)), AuditLevel::Warning);
        return Err(Error::value(format!(
            "Refusing to operate on {}: it is not a valid disk identifier. \
             Expected something like 'disk4' (macOS), 'sdb' (Linux) or 'PhysicalDrive3' (Windows).",
            py_repr(dev)
        )));
    }
    Ok(dev.to_string())
}

/// How a disk identifier is shown: `/dev/disk4`, `/dev/sdb` or `\\.\PhysicalDrive3`.
pub fn dev_path(dev: &str) -> String {
    dev_path_for(dev, IS_WINDOWS)
}

/// `dev_path` for a given OS.
pub fn dev_path_for(dev: &str, windows: bool) -> String {
    if windows {
        format!("\\\\.\\{dev}")
    } else {
        format!("/dev/{dev}")
    }
}

/// True if `head` (the first bytes of a file) carries the MBR boot signature at offset 510.
pub fn has_mbr_signature(head: &[u8]) -> bool {
    head.get(MBR_SIGNATURE_OFFSET..MBR_SIGNATURE_OFFSET + 2) == Some(&MBR_SIGNATURE[..])
}

/// Absolute, symlink-free form of a path (`~` expanded): `os.path.realpath(os.path.expanduser(path))`. Like Python's
/// non-strict `realpath`, a path that does not exist is resolved as far as it does and the rest is kept (with `..`
/// and `.` folded lexically).
pub fn resolve_path(path: impl AsRef<Path>) -> PathBuf {
    let expanded = expand_user(path);
    let absolute = if expanded.is_absolute() {
        expanded
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(expanded),
            Err(_) => return expanded,
        }
    };
    if let Ok(real) = std::fs::canonicalize(&absolute) {
        return strip_verbatim(real);
    }
    // Find the longest prefix that exists, resolve that, and append the remainder.
    let comps: Vec<Component> = absolute.components().collect();
    for keep in (1..comps.len()).rev() {
        let prefix: PathBuf = comps[..keep].iter().collect();
        if let Ok(real) = std::fs::canonicalize(&prefix) {
            let mut out = strip_verbatim(real);
            for comp in &comps[keep..] {
                match comp {
                    Component::ParentDir => {
                        out.pop();
                    }
                    Component::CurDir => {}
                    other => out.push(other.as_os_str()),
                }
            }
            return out;
        }
    }
    absolute
}

/// Windows `canonicalize` returns `\\?\C:\...`; the rest of the program (messages, other tools) wants `C:\...`.
fn strip_verbatim(p: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        let s = p.to_string_lossy().into_owned();
        if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
            return PathBuf::from(format!(r"\\{rest}"));
        }
        if let Some(rest) = s.strip_prefix(r"\\?\") {
            if rest.as_bytes().get(1) == Some(&b':') {
                return PathBuf::from(rest);
            }
        }
    }
    p
}

/// An absolute, existing, readable, regular-file image path that is at least MIN_IMAGE_BYTES, or `ValueError`.
pub fn validate_iso_path(path: impl AsRef<Path>) -> Result<PathBuf> {
    let path = path.as_ref();
    if path.as_os_str().is_empty() {
        return Err(Error::value("No ISO file has been selected yet."));
    }
    let resolved = resolve_path(path);
    let shown = resolved.display();
    if !resolved.exists() {
        return Err(Error::value(format!("The selected ISO file no longer exists: {shown}")));
    }
    if !resolved.is_file() {
        return Err(Error::value(format!("The selected ISO path is not a regular file: {shown}")));
    }
    if !is_readable(&resolved) {
        return Err(Error::value(format!("The selected ISO file cannot be read: {shown}")));
    }
    let size = std::fs::metadata(&resolved)?.len();
    if size < MIN_IMAGE_BYTES {
        return Err(Error::value(format!(
            "The selected file is too small to be a valid image ({}). It may be an incomplete download.",
            human_size(size)
        )));
    }
    Ok(resolved)
}

/// The first `n` bytes of a file (fewer when it is shorter): `fh.read(n)`.
pub(crate) fn read_head(path: &Path, n: u64) -> std::io::Result<Vec<u8>> {
    let mut head = Vec::new();
    std::fs::File::open(path)?.take(n).read_to_end(&mut head)?;
    Ok(head)
}

/// Raise unless `path` carries an MBR boot signature (isohybrid).
///
/// Writing a non-hybrid ISO byte-for-byte produces a drive that will not boot, so refuse up front instead of erasing
/// the drive for nothing. Windows ISOs are not hybrid; they must use the Windows mode.
pub fn validate_hybrid_iso(path: impl AsRef<Path>) -> Result<()> {
    let head = read_head(path.as_ref(), 512)?;
    if !has_mbr_signature(&head) {
        return Err(Error::value(
            "This ISO is not a bootable hybrid image, so it cannot be written directly to a USB drive.\n\n\
             If this is a Windows ISO, choose 'Windows 11' as the image type. Otherwise use an \
             ISO that is provided as a hybrid/USB-ready image (all current Ubuntu, Debian, Fedora, \
             Mint and Arch ISOs are).",
        ));
    }
    Ok(())
}

/// A raw disk image that can boot from USB as is (ChromeOS), or `ValueError`.
///
/// ChromeOS images are whole-disk images (a partition table plus the partitions), written to the drive byte for byte.
/// They carry the MBR boot signature like a hybrid ISO does.
pub fn validate_disk_image(path: impl AsRef<Path>) -> Result<()> {
    let head = read_head(path.as_ref(), 512)?;
    if head.starts_with(b"PK\x03\x04") {
        return Err(Error::value(
            "This is the ZIP archive, not the disk image inside it. Select it with 'Select existing \
             ISO file...' so the program can extract the .bin file, or extract it yourself.",
        ));
    }
    if !has_mbr_signature(&head) {
        return Err(Error::value(
            "This file is not a bootable disk image, so it cannot be written to a USB drive. \
             For ChromeOS Flex use the .bin file from the official latest.bin.zip.",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Download URL
// ---------------------------------------------------------------------------------------------------------------

/// The scheme and the host of a URL, as Python's `urllib.parse.urlparse` reports them.
struct ParsedUrl {
    scheme: String,
    hostname: Option<String>,
}

/// `urlparse(url)` reduced to what `validate_download_url` reads. `None` is where Python raises `ValueError`
/// (an unbalanced or invalid `[...]` host).
fn urlparse(url: &str) -> Option<ParsedUrl> {
    // Python strips leading control characters and spaces, and removes tab, CR and LF anywhere.
    let cleaned: String =
        url.trim_start_matches(|c: char| c <= ' ').chars().filter(|c| !matches!(c, '\t' | '\r' | '\n')).collect();
    let mut rest: &str = &cleaned;
    let mut scheme = String::new();
    if let Some(i) = rest.find(':') {
        let head = &rest[..i];
        let first_ok = head.chars().next().is_some_and(|c| c.is_ascii_alphabetic());
        if i > 0 && first_ok && head.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) {
            scheme = head.to_ascii_lowercase();
            rest = &rest[i + 1..];
        }
    }
    let mut netloc = "";
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        netloc = &after[..end];
        let (open, close) = (netloc.contains('['), netloc.contains(']'));
        if open != close {
            return None; // "Invalid IPv6 URL"
        }
        if open {
            let inner = netloc.split_once('[').map(|(_, r)| r).unwrap_or("");
            let bracketed = inner.split_once(']').map(|(l, _)| l).unwrap_or(inner);
            // Python (3.12+): an IPvFuture literal starts with "v"; anything else must be an IPv6 address.
            if !bracketed.starts_with('v') {
                let addr = bracketed.split_once('%').map(|(a, _)| a).unwrap_or(bracketed);
                addr.parse::<Ipv6Addr>().ok()?;
            }
        }
    }
    Some(ParsedUrl { scheme, hostname: hostname_of(netloc) })
}

/// The scheme (lowercased, "" when there is none) and the host (lowercased, `None` when empty) of a URL, as
/// `urllib.parse.urlparse(url)` reports them (`.scheme`, `.hostname`). `None` where Python raises `ValueError`.
/// The download code uses it to check the host a redirect ended on.
pub fn url_scheme_and_host(url: &str) -> Option<(String, Option<String>)> {
    urlparse(url).map(|p| (p.scheme, p.hostname))
}

/// `ParseResult.hostname`: the host part of the netloc, lowercased; `None` when empty.
fn hostname_of(netloc: &str) -> Option<String> {
    let hostinfo = netloc.rsplit_once('@').map(|(_, h)| h).unwrap_or(netloc);
    let host = if let Some((_, bracketed)) = hostinfo.split_once('[') {
        bracketed.split_once(']').map(|(h, _)| h).unwrap_or(bracketed)
    } else {
        hostinfo.split_once(':').map(|(h, _)| h).unwrap_or(hostinfo)
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_lowercase())
    }
}

/// `(normalised url, host, untrusted_host_warning)`; `ValueError` explains a rejection. Only HTTPS is accepted; a
/// host outside the trusted list (WIN11USB_TRUSTED_ISO_HOSTS, default Microsoft's download servers) is flagged, not
/// rejected, unless the exact official ChromeOS Flex address is used or WIN11USB_ALLOW_ANY_DOWNLOAD_HOST is set.
pub fn validate_download_url(raw_url: &str) -> Result<(String, String, bool)> {
    validate_download_url_with(raw_url, &|key| std::env::var_os(key).map(|v| v.to_string_lossy().into_owned()))
}

/// `validate_download_url` with the environment passed in (the Python tests patch `os.environ`).
pub fn validate_download_url_with(
    raw_url: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<(String, String, bool)> {
    let url = py_strip(raw_url);
    if url.is_empty() {
        return Err(Error::value("Paste the direct ISO link before downloading."));
    }
    // 'from None': the parser's internal message would only confuse the user.
    let parsed = urlparse(url).ok_or_else(|| Error::value("That does not look like a valid link."))?;
    if !ALLOWED_URL_SCHEMES.contains(&parsed.scheme.as_str()) {
        let allowed = ALLOWED_URL_SCHEMES.iter().map(|s| s.to_uppercase()).collect::<Vec<_>>().join("/");
        let shown = if parsed.scheme.is_empty() { "?" } else { parsed.scheme.as_str() };
        return Err(Error::value(format!(
            "Only {allowed} links are accepted (this one starts with '{shown}://').\n\n\
             An unencrypted link can be modified in transit, which would let someone \
             replace the Windows image with a tampered one."
        )));
    }
    let host = parsed.hostname.unwrap_or_default();
    if host.is_empty() {
        return Err(Error::value("The link has no server address."));
    }
    let url = url.to_string();
    if url == CHROMEOS_FLEX_URL {
        return Ok((url, host, false)); // Google's official ChromeOS Flex image (exact address only)
    }
    let allow_any =
        env(ENV_ALLOW_ANY_HOST).is_some_and(|v| matches!(py_strip(&v).to_lowercase().as_str(), "1" | "true" | "yes"));
    if allow_any {
        return Ok((url, host, false));
    }
    let trusted_hosts: Vec<String> = match env(ENV_TRUSTED_HOSTS).filter(|v| !v.is_empty()) {
        Some(list) => list.split(',').map(|h| py_strip(h).to_lowercase()).filter(|h| !h.is_empty()).collect(),
        None => DEFAULT_TRUSTED_ISO_HOSTS.iter().map(|h| h.to_string()).collect(),
    };
    let is_trusted = trusted_hosts.iter().any(|t| host == *t || host.ends_with(&format!(".{t}")));
    Ok((url, host, !is_trusted))
}

// ---------------------------------------------------------------------------------------------------------------
// SHA-256 text
// ---------------------------------------------------------------------------------------------------------------

/// True if `text` is exactly a SHA-256 in hex (64 digits, either case).
pub fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The first run of exactly 64 hex digits that is not part of a longer run: the Python
/// `(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])` search (the regex crate has no look-around).
fn find_hex64(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_hexdigit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
            i += 1;
        }
        if i - start == 64 {
            return line.get(start..i);
        }
    }
    None
}

/// Lowercase hex SHA-256 found in what the user pasted (a bare hash or a `SHA256SUMS` line), or None if empty.
///
/// Accepts a bare hash, a `sha256sum` line (`<hash> *file.iso` / `<hash>  file.iso`), the BSD form
/// (`SHA256 (file.iso) = <hash>`), or a whole SHA256SUMS file (then `filename` picks the line). `ValueError` with a
/// user-facing message when nothing valid can be found.
pub fn parse_expected_sha256(text: &str, filename: Option<&str>) -> Result<Option<String>> {
    let lines: Vec<&str> = py_splitlines(text).into_iter().map(py_strip).filter(|l| !l.is_empty()).collect();
    if lines.is_empty() {
        return Ok(None);
    }
    let found: Vec<(String, &str)> =
        lines.iter().filter_map(|ln| find_hex64(ln).map(|h| (h.to_ascii_lowercase(), *ln))).collect();
    if found.is_empty() {
        return Err(Error::value("That is not a SHA-256 checksum: it must be 64 characters using only 0-9 and a-f."));
    }
    let all_same = found.iter().all(|(h, _)| *h == found[0].0);
    if found.len() == 1 || all_same {
        return Ok(Some(found[0].0.clone()));
    }
    if let Some(name) = filename.filter(|n| !n.is_empty()) {
        let named: std::collections::HashSet<&String> =
            found.iter().filter(|(_, ln)| ln.contains(name)).map(|(h, _)| h).collect();
        if named.len() == 1 {
            if let Some(only) = named.into_iter().next() {
                return Ok(Some(only.clone()));
            }
        }
    }
    Err(Error::value("The pasted text contains several checksums. Paste only the line for your ISO file."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
    }

    #[test]
    fn device_name_patterns() {
        let good_mac = ["disk0", "disk4", "disk12"];
        let bad_mac = [
            "",
            "disk",
            "diskX",
            "disk4s1",
            "rdisk4",
            "/dev/disk4",
            "sdb",
            "disk4;rm",
            "disk4 ",
            " disk4",
            "../disk4",
            "disk4\n",
        ];
        for g in good_mac {
            assert_eq!(validate_device_name_for(g, HostOs::Mac).unwrap(), g);
        }
        for b in bad_mac {
            assert!(validate_device_name_for(b, HostOs::Mac).is_err(), "{b:?}");
        }
        let long_ok = "x".repeat(32);
        let long_bad = "x".repeat(33);
        for g in ["sdb", "nvme0n1", "mmcblk0", "vda", "a", long_ok.as_str()] {
            assert_eq!(validate_device_name_for(g, HostOs::Linux).unwrap(), g);
        }
        for b in [
            "",
            long_bad.as_str(),
            "sd b",
            "sdb;reboot",
            "../sda",
            "/dev/sdb",
            "sd$(id)",
            "sdb'",
            "sdb\"",
            "sd`id`",
            "sd*",
            "sdb\n",
        ] {
            assert!(validate_device_name_for(b, HostOs::Linux).is_err(), "{b:?}");
        }
        assert_eq!(validate_device_name_for("PhysicalDrive3", HostOs::Windows).unwrap(), "PhysicalDrive3");
        assert!(validate_device_name_for("PhysicalDrive", HostOs::Windows).is_err());
        assert!(validate_device_name_for("disk4", HostOs::Windows).is_err());
    }

    #[test]
    fn device_name_messages() {
        let err = validate_device_name_for("sdb", HostOs::Mac).unwrap_err();
        assert!(matches!(err, Error::Value(_)));
        assert!(err.to_string().contains("'sdb'"), "{err}");
        assert!(err.to_string().starts_with("Refusing to operate on 'sdb': it is not a valid disk identifier."));
        assert!(validate_device_name_for("", HostOs::Linux).unwrap_err().to_string().contains("No disk"));
        // a value with an apostrophe is shown the way Python's repr shows it
        assert!(validate_device_name_for("it's", HostOs::Linux).unwrap_err().to_string().contains("\"it's\""));
    }

    #[test]
    fn dev_paths() {
        assert_eq!(dev_path_for("disk4", false), "/dev/disk4");
        assert_eq!(dev_path_for("PhysicalDrive3", true), "\\\\.\\PhysicalDrive3");
    }

    #[test]
    fn mbr_signature() {
        let mut head = vec![0u8; 512];
        assert!(!has_mbr_signature(&head));
        head[510..512].copy_from_slice(&MBR_SIGNATURE);
        assert!(has_mbr_signature(&head));
        assert!(!has_mbr_signature(&MBR_SIGNATURE)); // a short read never counts
        assert!(!has_mbr_signature(&[]));
        assert!(!has_mbr_signature(&head[..511]));
    }

    #[test]
    fn url_parts_like_python() {
        let p = urlparse("https://User:pw@Example.COM:8443/path?x=1").unwrap();
        assert_eq!((p.scheme.as_str(), p.hostname.as_deref()), ("https", Some("example.com")));
        let p = urlparse("https://microsoft.com@evil.example/x").unwrap();
        assert_eq!(p.hostname.as_deref(), Some("evil.example"));
        let p = urlparse("https://[::1]:8080/x").unwrap();
        assert_eq!(p.hostname.as_deref(), Some("::1"));
        assert!(urlparse("https://[::1/x").is_none());
        assert!(urlparse("https://::1]/x").is_none());
        assert!(urlparse("https://[not-an-address]/x").is_none());
        let p = urlparse("www.microsoft.com/x").unwrap();
        assert_eq!((p.scheme.as_str(), p.hostname), ("", None));
        let p = urlparse("javascript:alert(1)").unwrap();
        assert_eq!((p.scheme.as_str(), p.hostname), ("javascript", None));
        let p = urlparse("https://").unwrap();
        assert_eq!(p.hostname, None);
        let p = urlparse("https:///path").unwrap();
        assert_eq!(p.hostname, None);
        // tab / CR / LF are dropped before parsing, like Python
        let p = urlparse("ht\ttps://exa\nmple.com/").unwrap();
        assert_eq!((p.scheme.as_str(), p.hostname.as_deref()), ("https", Some("example.com")));
    }

    #[test]
    fn download_url_rules() {
        let none = env_of(&[]);
        for url in [
            "https://www.microsoft.com/a",
            "https://microsoft.com/a",
            "https://software.download.prss.microsoft.com/x.iso",
            "https://HOST.download.microsoft.com/x.iso",
        ] {
            assert!(!validate_download_url_with(url, &none).unwrap().2, "{url}");
        }
        let (url, host, untrusted) = validate_download_url_with("https://example.com/win.iso", &none).unwrap();
        assert_eq!((url.as_str(), host.as_str(), untrusted), ("https://example.com/win.iso", "example.com", true));
        for url in [
            "https://microsoft.com.evil.example/x",
            "https://evilmicrosoft.com/x",
            "https://microsoft.com@evil.example/x",
        ] {
            assert!(validate_download_url_with(url, &none).unwrap().2, "{url}");
        }
        for url in [
            "http://www.microsoft.com/x",
            "ftp://www.microsoft.com/x",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "www.microsoft.com/x",
        ] {
            assert!(validate_download_url_with(url, &none).is_err(), "{url}");
        }
        for url in ["", "   ", "https://", "https:///path"] {
            assert!(validate_download_url_with(url, &none).is_err(), "{url:?}");
        }
        assert_eq!(
            validate_download_url_with("  https://www.microsoft.com/x \n", &none).unwrap().0,
            "https://www.microsoft.com/x"
        );
    }

    #[test]
    fn download_url_messages() {
        let none = env_of(&[]);
        let msg = |u: &str| validate_download_url_with(u, &none).unwrap_err().to_string();
        assert_eq!(msg(""), "Paste the direct ISO link before downloading.");
        assert!(msg("http://a/x")
            .starts_with("Only HTTPS links are accepted (this one starts with 'http://').\n\nAn unencrypted link"));
        assert!(msg("www.microsoft.com/x").contains("starts with '?://'"));
        assert_eq!(msg("https://"), "The link has no server address.");
        assert_eq!(msg("https://[::1/x"), "That does not look like a valid link.");
    }

    #[test]
    fn trusted_hosts_env_override() {
        let env = env_of(&[(ENV_TRUSTED_HOSTS, "example.org, mirror.test")]);
        assert!(!validate_download_url_with("https://example.org/x", &env).unwrap().2);
        assert!(!validate_download_url_with("https://cdn.mirror.test/x", &env).unwrap().2);
        assert!(validate_download_url_with("https://www.microsoft.com/x", &env).unwrap().2);
        // set but empty entries only: nothing is trusted (the Python `if trusted` is true for " , ")
        let blank = env_of(&[(ENV_TRUSTED_HOSTS, " , ")]);
        assert!(validate_download_url_with("https://www.microsoft.com/x", &blank).unwrap().2);
        // set but empty string: the defaults apply
        let empty = env_of(&[(ENV_TRUSTED_HOSTS, "")]);
        assert!(!validate_download_url_with("https://www.microsoft.com/x", &empty).unwrap().2);
    }

    #[test]
    fn allow_any_host_env_still_requires_https() {
        let env = env_of(&[(ENV_ALLOW_ANY_HOST, "1")]);
        assert!(!validate_download_url_with("https://whatever.example/x", &env).unwrap().2);
        assert!(validate_download_url_with("http://whatever.example/x", &env).is_err());
        for v in ["true", "YES", " 1 "] {
            let leaked: &'static str = Box::leak(v.to_string().into_boxed_str());
            let pairs: &'static [(&'static str, &'static str)] =
                Box::leak(vec![(ENV_ALLOW_ANY_HOST, leaked)].into_boxed_slice());
            assert!(!validate_download_url_with("https://whatever.example/x", &env_of(pairs)).unwrap().2, "{v:?}");
        }
        let off = env_of(&[(ENV_ALLOW_ANY_HOST, "0")]);
        assert!(validate_download_url_with("https://whatever.example/x", &off).unwrap().2);
    }

    #[test]
    fn the_official_chromeos_link_is_trusted_but_nothing_close_to_it() {
        let none = env_of(&[]);
        let (url, host, untrusted) = validate_download_url_with(CHROMEOS_FLEX_URL, &none).unwrap();
        assert_eq!((url.as_str(), host.as_str(), untrusted), (CHROMEOS_FLEX_URL, "dl.google.com", false));
        let flex_query = format!("{CHROMEOS_FLEX_URL}?x=1");
        for other in [
            "https://dl.google.com/other/file.zip",
            flex_query.as_str(),
            "https://dl.google.com/chromeos-flex/images/latest.bin.zip/..",
            "https://google.com/x.zip",
        ] {
            assert!(validate_download_url_with(other, &none).unwrap().2, "{other}");
        }
        assert!(validate_download_url_with(&CHROMEOS_FLEX_URL.replace("https://", "http://"), &none).is_err());
    }

    #[test]
    fn sha256_hex() {
        let good = "ab".repeat(32);
        assert!(is_sha256_hex(&good));
        assert!(is_sha256_hex(&good.to_uppercase()));
        for bad in [
            &good[..63],
            &format!("{good}0"),
            &format!("{}g", &good[..63]),
            "",
            &format!(" {good}"),
            &format!("{good}\n"),
        ] {
            assert!(!is_sha256_hex(bad), "{bad:?}");
        }
    }

    #[test]
    fn parse_expected_finds_a_hash_inside_a_line() {
        let good = "cd".repeat(32);
        assert_eq!(
            parse_expected_sha256(&format!("{} *ubuntu.iso", good.to_uppercase()), None).unwrap(),
            Some(good.clone())
        );
        assert!(parse_expected_sha256(&"0".repeat(65), None).is_err()); // too long: not a SHA-256
        assert_eq!(parse_expected_sha256("", None).unwrap(), None);
        assert_eq!(parse_expected_sha256("  \n \r\n", None).unwrap(), None);
        // bare, BSD and sha256sum forms
        assert_eq!(parse_expected_sha256(&good, None).unwrap(), Some(good.clone()));
        assert_eq!(parse_expected_sha256(&format!("SHA256 (file.iso) = {good}"), None).unwrap(), Some(good.clone()));
        assert_eq!(parse_expected_sha256(&format!("{good}  file.iso\n"), None).unwrap(), Some(good.clone()));
        // text that holds no hash
        let err = parse_expected_sha256("hello world", None).unwrap_err();
        assert_eq!(err.to_string(), "That is not a SHA-256 checksum: it must be 64 characters using only 0-9 and a-f.");
    }

    #[test]
    fn parse_expected_picks_the_line_of_the_named_file() {
        let (a, b) = ("1".repeat(64), "2".repeat(64));
        let sums = format!("{a} *debian.iso\n{b} *ubuntu.iso\n");
        assert_eq!(parse_expected_sha256(&sums, Some("ubuntu.iso")).unwrap(), Some(b.clone()));
        assert_eq!(parse_expected_sha256(&sums, Some("debian.iso")).unwrap(), Some(a));
        let err = parse_expected_sha256(&sums, None).unwrap_err();
        assert_eq!(
            err.to_string(),
            "The pasted text contains several checksums. Paste only the line for your ISO file."
        );
        assert!(parse_expected_sha256(&sums, Some("fedora.iso")).is_err());
        // the same hash listed twice is not ambiguous
        let twice = format!("{b} *x.iso\n{b} *y.iso\n");
        assert_eq!(parse_expected_sha256(&twice, None).unwrap(), Some(b));
    }
}
