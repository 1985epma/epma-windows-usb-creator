//! HTTPS download with resume. OWNER: A7. Port of win11_usb_creator.py lines 8872-9146 (DownloadThread), of
//! `download_file_blocking` (line 12417) and of `DOWNLOAD_FATAL_ERRNOS` (lines 255-257).
//!
//! Differences from the Python that are on purpose:
//!
//! * Redirects are followed **by hand** (`ureq` is told to follow none): every hop is checked *before* it is
//!   connected to, so a redirect to a host we do not trust is never contacted at all (the Python only looked at the
//!   final address after `urlopen` had followed the chain).
//! * The network layer sits behind the small [`Transport`] trait, so the tests can script a server (redirects,
//!   resets, a failing disk) without a network, and a tiny plain-http server on 127.0.0.1 exercises the real client.

use crate::audit::AuditLevel;
use crate::constants::{
    CHROMEOS_FLEX_HOSTS, CHROMEOS_FLEX_URL, CHUNK_SIZE, DOWNLOAD_BACKOFF_SECONDS, DOWNLOAD_MAX_ATTEMPTS,
    DOWNLOAD_TIMEOUT_SECONDS,
};
use crate::hash::hash_stream;
use crate::types::{CancelToken, Error, Progress};
use crate::util::{human_size, silent_remove};
use crate::validate::validate_download_url;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub type ProgressCb = Box<dyn Fn(u64, u64, f64) + Send + Sync>;
pub type DoneCb = Box<dyn Fn(&Path, &str, bool) + Send + Sync>;
pub type ErrorCb = Box<dyn Fn(&str) + Send + Sync>;

/// The most redirects one download follows (urllib's own limit).
const MAX_REDIRECTS: usize = 10;

const CANCEL_MESSAGE: &str = "Download canceled by user. The partial file was kept, so downloading the same file \
                              again to the same location resumes where it stopped.";

/// `audit(msg)`. Silent in this module's own tests: they must not write the user's audit log.
fn audit(msg: &str) {
    #[cfg(not(test))]
    crate::audit::audit(msg);
    #[cfg(test)]
    let _ = msg;
}

/// `audit(msg, level)` (see [`audit`]).
fn audit_at(msg: &str, level: AuditLevel) {
    #[cfg(not(test))]
    crate::audit::audit_at(msg, level);
    #[cfg(test)]
    let _ = (msg, level);
}

// ---------------------------------------------------------------------------------------------------------------
// DOWNLOAD_FATAL_ERRNOS
// ---------------------------------------------------------------------------------------------------------------

/// What a fatal local write error is about (selects the wording of the message).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocalWrite {
    /// ENOSPC / EDQUOT: no space left.
    Full,
    /// EROFS: read-only file system.
    ReadOnly,
    /// EACCES / EPERM: not allowed.
    Denied,
}

#[cfg(unix)]
fn local_write_kind(code: i32) -> Option<LocalWrite> {
    if code == libc::ENOSPC || code == libc::EDQUOT {
        Some(LocalWrite::Full)
    } else if code == libc::EROFS {
        Some(LocalWrite::ReadOnly)
    } else if code == libc::EACCES || code == libc::EPERM {
        Some(LocalWrite::Denied)
    } else {
        None
    }
}

/// Windows reports Win32 error codes, not errno: ERROR_DISK_FULL (112), ERROR_HANDLE_DISK_FULL (39),
/// ERROR_WRITE_PROTECT (19) and ERROR_ACCESS_DENIED (5) are what the Python's errno tuple maps to there.
#[cfg(windows)]
fn local_write_kind(code: i32) -> Option<LocalWrite> {
    match code {
        112 | 39 => Some(LocalWrite::Full),
        19 => Some(LocalWrite::ReadOnly),
        5 => Some(LocalWrite::Denied),
        _ => None,
    }
}

#[cfg(not(any(unix, windows)))]
fn local_write_kind(_code: i32) -> Option<LocalWrite> {
    None
}

/// `DOWNLOAD_FATAL_ERRNOS`: a write error that retrying cannot fix (and that must not be mistaken for a network
/// problem): ENOSPC, EDQUOT, EROFS, EACCES, EPERM (Windows: ERROR_DISK_FULL, ERROR_ACCESS_DENIED,
/// ERROR_WRITE_PROTECT). Only the raw OS error counts, like the Python's `errno`.
pub fn is_download_fatal_errno(err: &io::Error) -> bool {
    err.raw_os_error().and_then(local_write_kind).is_some()
}

// ---------------------------------------------------------------------------------------------------------------
// Network layer
// ---------------------------------------------------------------------------------------------------------------

/// One answer from the server (a single hop: redirects are not followed here).
pub(crate) struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Box<dyn Read + Send>,
}

impl Response {
    /// A header value by name (case-insensitive).
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// Why a request produced no answer at all (the Python `URLError`: DNS, connect, TLS, timeout, protocol).
#[derive(Debug)]
pub(crate) struct TransportError(pub String);

/// One HTTP GET without redirects: `Ok` for every status code, `Err` when no answer arrived.
pub(crate) trait Transport: Send + Sync {
    fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<Response, TransportError>;
}

/// The real client: `ureq` with no redirects, no gzip surprises and a per-read timeout.
pub(crate) struct UreqTransport {
    agent: ureq::Agent,
}

impl UreqTransport {
    /// `https_only`: refuse plain http at the client too (the tests of this module turn it off to talk to a local
    /// server on 127.0.0.1).
    pub(crate) fn new(https_only: bool) -> Self {
        let timeout = Some(Duration::from_secs(DOWNLOAD_TIMEOUT_SECONDS));
        let config = ureq::Agent::config_builder()
            .max_redirects(0)
            .http_status_as_error(false)
            .https_only(https_only)
            .timeout_connect(timeout)
            .timeout_per_read(timeout)
            .timeout_per_write(timeout)
            .user_agent("Mozilla/5.0")
            // The bytes on the wire are the bytes of the file: offsets, lengths and the hash all rely on it.
            .accept_encoding("identity")
            .build();
        UreqTransport { agent: ureq::Agent::new_with_config(config) }
    }
}

impl Transport for UreqTransport {
    fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<Response, TransportError> {
        let mut request = self.agent.get(url);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = request.call().map_err(|e| TransportError(e.to_string()))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_string(), v.to_string())))
            .collect();
        Ok(Response { status, headers, body: Box::new(response.into_body().into_reader()) })
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Errors of one attempt (the Python exceptions of the download code)
// ---------------------------------------------------------------------------------------------------------------

#[derive(Debug)]
enum DlError {
    /// `_DownloadCanceled`: the partial file is kept.
    Canceled(String),
    /// `_DownloadInterrupted`: the partial file is kept (retried while attempts remain).
    Interrupted(String),
    /// `_RestartDownload`: the answer cannot extend the partial file, which was discarded.
    Restart,
    /// `HTTPError`.
    Http(u16),
    /// `URLError`: no answer (the reason is shown to the user).
    Net(String),
    /// An `OSError` (a failing local write, or a network read that broke).
    Io(io::Error),
    /// Any other exception (`RuntimeError`, `ValueError`): the partial file is discarded.
    Fatal(String),
}

impl From<io::Error> for DlError {
    fn from(e: io::Error) -> Self {
        DlError::Io(e)
    }
}

impl From<Error> for DlError {
    fn from(e: Error) -> Self {
        match e {
            Error::Canceled { message, .. } => DlError::Canceled(message),
            Error::Io(e) => DlError::Io(e),
            other => DlError::Fatal(other.to_string()),
        }
    }
}

fn canceled() -> DlError {
    DlError::Canceled(CANCEL_MESSAGE.to_string())
}

// ---------------------------------------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------------------------------------

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).map(|m| m.file_type().is_symlink()).unwrap_or(false)
}

/// `OpenOptions` that never follows a symlink at the final path component (`O_NOFOLLOW`; unix).
#[cfg_attr(not(unix), allow(unused_mut))]
fn no_follow() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options
}

/// Owner-only permissions for a file we create (unix; Windows files inherit the folder's ACL).
fn private(options: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(crate::constants::PRIVATE_FILE_MODE);
    }
    options
}

/// The host of a URL, lowercase, without credentials, port or IPv6 brackets (the Python `urlparse(url).hostname`).
fn url_host(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
    let host = if let Some(stripped) = host_port.strip_prefix('[') {
        stripped.split(']').next().unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or("")
    };
    host.to_lowercase()
}

/// `urljoin(base, location)` for the cases a redirect uses: absolute, scheme-relative, absolute-path, relative.
fn resolve_redirect(base: &str, location: &str) -> String {
    let location = location.trim();
    let location = location.split('#').next().unwrap_or(location);
    if let Some(i) = location.find("://") {
        let scheme = &location[..i];
        if !scheme.is_empty() && scheme.chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) {
            return location.to_string();
        }
    }
    let Some((scheme, rest)) = base.split_once("://") else { return location.to_string() };
    if let Some(stripped) = location.strip_prefix("//") {
        return format!("{scheme}://{stripped}");
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, path_and_query) = rest.split_at(authority_end);
    let path_and_query = path_and_query.split('#').next().unwrap_or("");
    let (path, _query) = path_and_query.split_once('?').unwrap_or((path_and_query, ""));
    if location.is_empty() {
        return format!("{scheme}://{authority}{path_and_query}");
    }
    if location.starts_with('/') {
        return format!("{scheme}://{authority}{location}");
    }
    if location.starts_with('?') {
        return format!("{scheme}://{authority}{path}{location}");
    }
    let dir = match path.rfind('/') {
        Some(i) => &path[..=i],
        None => "/",
    };
    // Dot segments ("../x") collapse like a browser does.
    let mut segments: Vec<&str> = dir.split('/').collect();
    segments.pop(); // the empty piece after the final '/'
    let (rel_path, rel_query) = location.split_once('?').map(|(p, q)| (p, Some(q))).unwrap_or((location, None));
    for piece in rel_path.split('/') {
        match piece {
            "." => {}
            ".." => {
                if segments.len() > 1 {
                    segments.pop();
                }
            }
            other => segments.push(other),
        }
    }
    let mut joined = segments.join("/");
    if rel_path.ends_with("/.") || rel_path.ends_with("/..") {
        joined.push('/');
    }
    match rel_query {
        Some(q) => format!("{scheme}://{authority}{joined}?{q}"),
        None => format!("{scheme}://{authority}{joined}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

static CONTENT_RANGE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^bytes (\d+)-\d+/(\d+|\*)").unwrap());

/// What a finished attempt reports: `(bytes, sha256, expected sha256 or "")`.
type Finished = (u64, String, String);

// ---------------------------------------------------------------------------------------------------------------
// The downloader (one run of the Python `DownloadThread.run`)
// ---------------------------------------------------------------------------------------------------------------

type Validator<'a> = &'a (dyn Fn(&str) -> crate::types::Result<(String, String, bool)> + Send + Sync);

/// All the state of one download. `DownloadThread` runs it on its own thread, `download_file_blocking` in the
/// caller's thread; the tests drive it with scripted transports.
pub(crate) struct Downloader<'a> {
    pub url: &'a str,
    pub dest_path: &'a Path,
    pub progress_cb: &'a (dyn Fn(u64, u64, f64) + Send + Sync),
    pub done_cb: &'a (dyn Fn(&Path, &str, bool) + Send + Sync),
    pub error_cb: &'a (dyn Fn(&str) + Send + Sync),
    pub cancel: &'a CancelToken,
    pub expected_sha256: Option<&'a str>,
    /// Lowercase host names the download (and every redirect) must stay on; `None` = the trusted-host rules only.
    pub allowed_hosts: Option<Vec<String>>,
    pub transport: &'a dyn Transport,
    /// The URL policy: `(normalised url, host, untrusted)` or `Error::Value`. The real one is
    /// `validate::validate_download_url` (https only); tests may script it.
    pub validate: Validator<'a>,
    /// Plain http allowed (tests against a local server only): no URL validation, every host counts as trusted.
    pub allow_insecure_http: bool,
    /// Seconds to wait before retry 2, 3...
    pub backoff: &'a [u64],
}

impl<'a> Downloader<'a> {
    // ---------- partial-file bookkeeping ----------
    fn part_path(&self) -> PathBuf {
        let mut name = self.dest_path.as_os_str().to_owned();
        name.push(".part");
        PathBuf::from(name)
    }

    fn meta_path(&self) -> PathBuf {
        let mut name = self.dest_path.as_os_str().to_owned();
        name.push(".part.meta");
        PathBuf::from(name)
    }

    /// The validator (ETag / Last-Modified) saved beside the part file, read through no symlink.
    fn read_validator(&self) -> Option<String> {
        let mut file = no_follow().read(true).open(self.meta_path()).ok()?;
        let mut text = String::new();
        file.read_to_string(&mut text).ok()?;
        let value: serde_json::Value = serde_json::from_str(&text).ok()?;
        match value.get("validator")?.as_str() {
            Some(v) if !v.is_empty() => Some(v.to_string()),
            _ => None,
        }
    }

    fn write_validator(&self, validator: &str) {
        let mut options = no_follow();
        private(options.create(true).write(true).truncate(true));
        // Without it the next run simply restarts instead of resuming.
        if let Ok(mut file) = options.open(self.meta_path()) {
            let text = serde_json::to_string(validator).unwrap_or_else(|_| "\"\"".to_string());
            let _ = file.write_all(format!("{{\"validator\": {text}}}").as_bytes());
        }
    }

    /// Removes a symlink itself, never what it points to.
    fn discard_partial(&self, tmp_path: &Path) {
        silent_remove(tmp_path);
        silent_remove(self.meta_path());
    }

    fn strong_validator(response: &Response) -> Option<String> {
        if let Some(etag) = response.header("ETag") {
            if !etag.is_empty() && !etag.starts_with("W/") {
                return Some(etag.to_string());
            }
        }
        response.header("Last-Modified").filter(|v| !v.is_empty()).map(|v| v.to_string())
    }

    fn check_cancel(&self) -> Result<(), DlError> {
        if self.cancel.is_set() {
            Err(canceled())
        } else {
            Ok(())
        }
    }

    fn hash_part(&self, tmp_path: &Path, digest: &mut Sha256, size: u64) -> Result<(), DlError> {
        let mut file = no_follow().read(true).open(tmp_path)?;
        let check = || -> crate::types::Result<()> {
            if self.cancel.is_set() {
                Err(Error::canceled_with(CANCEL_MESSAGE, true, false))
            } else {
                Ok(())
            }
        };
        let read = hash_stream(&mut file, digest, Some(size), Some(&check), None, CHUNK_SIZE)?;
        if read < size {
            return Err(DlError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the partial file is shorter than expected",
            )));
        }
        Ok(())
    }

    // ---------- the URL policy ----------
    /// `(host, untrusted)` of `url` under the active policy.
    fn classify(&self, url: &str) -> Result<(String, bool), DlError> {
        if self.allow_insecure_http {
            return Ok((url_host(url), false));
        }
        let (_normalised, host, untrusted) = (self.validate)(url)?;
        Ok((host.to_lowercase(), untrusted))
    }

    /// The checks the Python made on the final URL, made on every hop and before connecting to it.
    fn check_hop(&self, url: &str, redirected: bool, original_untrusted: bool) -> Result<(), DlError> {
        let (host, untrusted) = if redirected {
            let (host, untrusted) = self.classify(url)?;
            audit(&format!("Download redirected to host: {host}"));
            (host, untrusted)
        } else {
            (url_host(url), false)
        };
        if self.allowed_hosts.is_none() && untrusted && !original_untrusted {
            // The link was on a trusted host, but the server sent us somewhere that is not: that is exactly what
            // the trusted-host list exists to prevent.
            audit_at(
                &format!("Download REFUSED: redirected from a trusted host to an untrusted one ({host})"),
                AuditLevel::Warning,
            );
            return Err(DlError::Fatal(format!(
                "The server redirected the download to an address that is not trusted ({host}), so it was stopped and \
                 what had arrived was discarded.\n\nIf you do trust that server, copy the final link and download it \
                 directly (you will be asked to confirm the host)."
            )));
        }
        if let Some(allowed) = &self.allowed_hosts {
            if !allowed.contains(&host) {
                audit_at(&format!("Download REFUSED: redirected to unexpected host {host}"), AuditLevel::Warning);
                return Err(DlError::Fatal(format!(
                    "The server redirected the download to an unexpected address ({host}), so it was stopped and what \
                     had arrived was discarded."
                )));
            }
        }
        Ok(())
    }

    /// `_open`: one request (with Range / If-Range when resuming) followed through the redirects by hand.
    fn open(&self, offset: u64, validator: Option<&str>, original_untrusted: bool) -> Result<Response, DlError> {
        let mut range = Vec::new();
        if offset > 0 {
            range.push(("Range".to_string(), format!("bytes={offset}-")));
            range.push(("If-Range".to_string(), validator.unwrap_or("").to_string()));
        }
        let mut headers: Vec<(&str, &str)> = vec![("User-Agent", "Mozilla/5.0")];
        headers.extend(range.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        let mut current = self.url.to_string();
        let mut last_redirect = 0;
        for hop in 0..=MAX_REDIRECTS {
            self.check_hop(&current, hop > 0, original_untrusted)?;
            let response = self.transport.get(&current, &headers).map_err(|e| DlError::Net(e.0))?;
            if matches!(response.status, 301 | 302 | 303 | 307 | 308) {
                last_redirect = response.status;
                match response.header("Location").filter(|l| !l.trim().is_empty()) {
                    Some(location) => {
                        current = resolve_redirect(&current, location);
                        continue;
                    }
                    None => return Err(DlError::Http(response.status)),
                }
            }
            if !(200..300).contains(&response.status) {
                return Err(DlError::Http(response.status));
            }
            return Ok(response);
        }
        Err(DlError::Http(last_redirect))
    }

    // ---------- one connection ----------
    /// Download (or resume) once. Returns (bytes, sha256, expected). Fails on any problem.
    fn attempt(&self, tmp_path: &Path) -> Result<Finished, DlError> {
        // A symlink where the part/meta file should be is never followed: it is simply dropped.
        if is_symlink(tmp_path) || is_symlink(&self.meta_path()) {
            audit_at("A symlink was found in place of a partial download file; it was discarded", AuditLevel::Warning);
            self.discard_partial(tmp_path);
        }
        let original_untrusted = if self.allow_insecure_http { false } else { self.classify(self.url)?.1 };
        let mut offset = if tmp_path.is_file() { fs::metadata(tmp_path)?.len() } else { 0 };
        let validator = if offset > 0 { self.read_validator() } else { None };
        if offset > 0 && validator.is_none() {
            self.discard_partial(tmp_path); // nothing proves it belongs to this file
            offset = 0;
        }
        let mut digest = Sha256::new();
        if offset > 0 {
            self.hash_part(tmp_path, &mut digest, offset)?;
        }
        let response = match self.open(offset, validator.as_deref(), original_untrusted) {
            Err(DlError::Http(416)) if offset > 0 => {
                // Range not satisfiable: the part file does not fit the file on the server.
                self.discard_partial(tmp_path);
                offset = 0;
                digest = Sha256::new();
                self.open(0, None, original_untrusted)?
            }
            other => other?,
        };

        let length: u64 = response.header("Content-Length").and_then(|v| v.trim().parse().ok()).unwrap_or(0);
        let total;
        if offset > 0 && response.status == 206 {
            let range = response.header("Content-Range").unwrap_or("");
            let parsed = CONTENT_RANGE_RE.captures(range).and_then(|m| {
                let start: u64 = m.get(1)?.as_str().parse().ok()?;
                Some((start, m.get(2)?.as_str().to_string()))
            });
            let Some((_, whole)) = parsed.filter(|(start, _)| *start == offset) else {
                self.discard_partial(tmp_path);
                return Err(DlError::Restart);
            };
            total = whole.parse::<u64>().unwrap_or(offset + length);
            audit(&format!("Download resumed at {}", human_size(offset)));
        } else {
            if offset > 0 {
                // The server ignored Range (or the file changed): start over cleanly.
                audit("Server did not honour the resume request; restarting the download");
                offset = 0;
                digest = Sha256::new();
                self.discard_partial(tmp_path);
            }
            total = length;
            match Self::strong_validator(&response) {
                Some(fresh) => self.write_validator(&fresh),
                None => silent_remove(self.meta_path()), // never leave a stale validator behind
            }
        }

        let mut body = response.body;
        let mut downloaded = offset;
        let started = Instant::now();
        // Create the partial file readable only by its owner.
        let mut options = no_follow();
        private(options.create(true).write(true));
        if offset > 0 {
            options.append(true);
        } else {
            options.truncate(true);
        }
        let mut file: File = options.open(tmp_path)?;
        let mut buffer = vec![0u8; CHUNK_SIZE];
        loop {
            self.check_cancel()?;
            let n = body.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            file.write_all(&buffer[..n])?;
            digest.update(&buffer[..n]);
            downloaded += n as u64;
            let elapsed = started.elapsed().as_secs_f64().max(0.001);
            (self.progress_cb)(downloaded, total, (downloaded - offset) as f64 / elapsed);
        }
        drop(file);
        drop(body);
        if total > 0 && downloaded < total {
            return Err(DlError::Interrupted(format!(
                "Incomplete download: received {} of {}.",
                human_size(downloaded),
                human_size(total)
            )));
        }
        if total > 0 && downloaded > total {
            self.discard_partial(tmp_path);
            return Err(DlError::Fatal("The server sent more data than announced. The file was discarded.".into()));
        }
        let sha256 = hex(&digest.finalize());
        let expected = self.expected_sha256.unwrap_or("").trim().to_lowercase();
        if !expected.is_empty() && expected != sha256 {
            audit_at("Downloaded ISO FAILED SHA-256 verification", AuditLevel::Error);
            self.discard_partial(tmp_path);
            return Err(DlError::Fatal(format!(
                "SHA-256 verification FAILED \u{2014} the downloaded file is NOT the one you expected and was \
                 discarded.\n\nExpected: {expected}\nReceived: {sha256}\n\nDo not use this file. Download it again \
                 from the official Microsoft page."
            )));
        }
        fs::rename(tmp_path, self.dest_path)?;
        silent_remove(self.meta_path());
        Ok((downloaded, sha256, expected))
    }

    /// User-facing text for a local write error that must not be retried.
    fn local_write_message(&self, err: &io::Error) -> String {
        let absolute = std::path::absolute(self.dest_path).unwrap_or_else(|_| self.dest_path.to_path_buf());
        let folder = absolute.parent().map(|p| p.display().to_string()).unwrap_or_default();
        match err.raw_os_error().and_then(local_write_kind) {
            Some(LocalWrite::Full) => format!(
                "There is not enough free space in {folder}. The download was stopped and the partial file was \
                 deleted to free the space. Free up space or choose another folder or drive, then download again."
            ),
            Some(LocalWrite::ReadOnly) => format!(
                "{folder} is read-only, so the file cannot be saved there. The download was stopped; choose another \
                 folder."
            ),
            _ => format!(
                "The program is not allowed to write in {folder}. The download was stopped; choose a folder you can \
                 write to."
            ),
        }
    }

    // ---------- retry loop ----------
    fn run_inner(&self, tmp_path: &Path) -> Result<Finished, DlError> {
        // The URL was validated before this thread started; re-check here so the guarantee holds even if this
        // class is reused elsewhere.
        if !self.allow_insecure_http {
            (self.validate)(self.url)?;
        }
        let mut attempt: u32 = 0;
        let mut restarts = 0;
        loop {
            attempt += 1;
            let problem = match self.attempt(tmp_path) {
                Ok(done) => return Ok(done),
                Err(DlError::Restart) => {
                    restarts += 1;
                    if restarts > 2 {
                        return Err(DlError::Fatal(
                            "The server keeps answering the resume request with unusable data. Try the download \
                             again."
                                .into(),
                        ));
                    }
                    attempt -= 1;
                    continue;
                }
                Err(DlError::Http(code)) => {
                    if code < 500 && code != 408 && code != 429 {
                        return Err(DlError::Interrupted(format!(
                            "The server refused the download (HTTP {code}). If the link has expired, copy a fresh one \
                             from the Microsoft page; the partial file is kept and will be resumed if it is the same \
                             file."
                        )));
                    }
                    format!("HTTP {code}")
                }
                Err(DlError::Net(reason)) => reason,
                Err(DlError::Interrupted(message)) => message,
                Err(DlError::Io(e)) => {
                    if is_download_fatal_errno(&e) {
                        // A problem with the destination, not the network: retrying cannot help.
                        return Err(DlError::Fatal(self.local_write_message(&e)));
                    }
                    let text = e.to_string();
                    if text.is_empty() {
                        format!("{:?}", e.kind())
                    } else {
                        text
                    }
                }
                Err(other) => return Err(other),
            };
            if attempt >= DOWNLOAD_MAX_ATTEMPTS {
                return Err(DlError::Interrupted(format!(
                    "The download was interrupted ({problem}) and could not be continued after {attempt} attempts. \
                     The partial file was kept; start the download again to resume it."
                )));
            }
            let index = (attempt as usize - 1).min(self.backoff.len().saturating_sub(1));
            let delay = self.backoff.get(index).copied().unwrap_or(0);
            audit(&format!("Download attempt {attempt} failed; retrying in {delay}s"));
            if self.cancel.wait(Duration::from_secs(delay)) {
                return Err(canceled());
            }
        }
    }

    /// `DownloadThread.run`: download, then report through exactly one of the callbacks.
    pub(crate) fn run(&self) {
        let tmp_path = self.part_path();
        match self.run_inner(&tmp_path) {
            Ok((downloaded, sha256, expected)) => {
                audit(&format!(
                    "ISO downloaded ({}) sha256={sha256}{}",
                    human_size(downloaded),
                    if expected.is_empty() { " [not verified]" } else { " [verified against expected value]" }
                ));
                (self.done_cb)(self.dest_path, &sha256, !expected.is_empty());
            }
            Err(DlError::Canceled(message)) | Err(DlError::Interrupted(message)) => {
                (self.error_cb)(&message); // the partial file stays on disk for a later resume
            }
            Err(other) => {
                self.discard_partial(&tmp_path);
                let message = match other {
                    DlError::Fatal(m) | DlError::Net(m) => m,
                    DlError::Io(e) => e.to_string(),
                    DlError::Http(code) => format!("HTTP Error {code}"),
                    DlError::Restart => "The download had to be restarted.".to_string(),
                    DlError::Canceled(m) | DlError::Interrupted(m) => m,
                };
                (self.error_cb)(&message);
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// DownloadThread
// ---------------------------------------------------------------------------------------------------------------

/// Downloads one file over HTTPS, resuming and retrying where that is safe.
///
/// * The data goes to `<dest>.part` (owner-only). On cancel or a network error the part file is KEPT; the next run
///   resumes it with a Range request. The SHA-256 always covers the whole file (the bytes already on disk are
///   hashed first).
/// * A resume is only attempted when the first response carried a strong ETag or a Last-Modified date (saved beside
///   the part file) and is sent with If-Range, so a file that changed on the server is downloaded again from scratch
///   instead of being stitched together. A server that ignores Range also leads to a clean restart.
/// * Transient errors are retried (DOWNLOAD_MAX_ATTEMPTS, with backoff).
/// * A checksum mismatch or an unexpected failure deletes the part file.
///
/// Callbacks run on the download thread: `progress(done, total, speed)`, `done(path, sha256, verified)`,
/// `error(message)`.
pub struct DownloadThread {
    pub url: String,
    pub dest_path: PathBuf,
    pub progress_cb: ProgressCb,
    pub done_cb: DoneCb,
    pub error_cb: ErrorCb,
    pub cancel: CancelToken,
    pub expected_sha256: Option<String>,
    pub allowed_hosts: Option<Vec<String>>,
}

/// `tuple(h.lower() for h in allowed_hosts) if allowed_hosts else None`.
fn lowercase_hosts(hosts: Option<&[String]>) -> Option<Vec<String>> {
    hosts.filter(|h| !h.is_empty()).map(|h| h.iter().map(|x| x.to_lowercase()).collect())
}

impl DownloadThread {
    /// A download that has not started yet (`allowed_hosts`: the only hosts the URL and its redirects may use).
    pub fn new(
        url: impl Into<String>,
        dest_path: impl Into<PathBuf>,
        progress_cb: ProgressCb,
        done_cb: DoneCb,
        error_cb: ErrorCb,
        cancel: CancelToken,
        expected_sha256: Option<String>,
        allowed_hosts: Option<Vec<String>>,
    ) -> Self {
        DownloadThread {
            url: url.into(),
            dest_path: dest_path.into(),
            progress_cb,
            done_cb,
            error_cb,
            cancel,
            expected_sha256,
            allowed_hosts,
        }
    }

    /// Run the download in the calling thread with an explicit transport (tests).
    pub(crate) fn run_with(
        &self,
        transport: &dyn Transport,
        validate: Validator,
        allow_insecure_http: bool,
        backoff: &[u64],
    ) {
        Downloader {
            url: &self.url,
            dest_path: &self.dest_path,
            progress_cb: &*self.progress_cb,
            done_cb: &*self.done_cb,
            error_cb: &*self.error_cb,
            cancel: &self.cancel,
            expected_sha256: self.expected_sha256.as_deref(),
            allowed_hosts: lowercase_hosts(self.allowed_hosts.as_deref()),
            transport,
            validate,
            allow_insecure_http,
            backoff,
        }
        .run();
    }

    /// Start it on its own (daemon-like) thread: the process does not wait for it when it exits.
    pub fn start(self) -> JoinHandle<()> {
        std::thread::spawn(move || {
            let transport = UreqTransport::new(true);
            self.run_with(&transport, &validate_download_url, false, DOWNLOAD_BACKOFF_SECONDS);
        })
    }
}

/// The hosts a download of `url` may use: only ChromeOS Flex is restricted (to its own host list).
pub fn allowed_hosts_for(url: &str) -> Option<Vec<String>> {
    (url == CHROMEOS_FLEX_URL).then(|| CHROMEOS_FLEX_HOSTS.iter().map(|h| h.to_string()).collect())
}

/// `download_file_blocking`: run the download to completion in the calling thread and return the SHA-256 of the
/// file. `Error::Runtime` carries the user-facing reason when it fails. `progress` is called as
/// `(done, total, "Downloading")`.
pub fn download_file_blocking(
    url: &str,
    dest: &Path,
    progress: Option<Progress>,
    cancel: Option<&CancelToken>,
) -> crate::types::Result<String> {
    download_blocking_with(
        url,
        dest,
        progress,
        cancel,
        &UreqTransport::new(true),
        &validate_download_url,
        false,
        DOWNLOAD_BACKOFF_SECONDS,
    )
}

fn download_blocking_with(
    url: &str,
    dest: &Path,
    progress: Option<Progress>,
    cancel: Option<&CancelToken>,
    transport: &dyn Transport,
    validate: Validator,
    allow_insecure_http: bool,
    backoff: &[u64],
) -> crate::types::Result<String> {
    let outcome: Mutex<Option<Result<String, String>>> = Mutex::new(None);
    let own_cancel = CancelToken::new();
    let on_progress = |done: u64, total: u64, _speed: f64| {
        if let Some(p) = progress {
            p(done, total, "Downloading");
        }
    };
    let on_done = |_path: &Path, sha256: &str, _verified: bool| {
        *outcome.lock().unwrap_or_else(|e| e.into_inner()) = Some(Ok(sha256.to_string()));
    };
    let on_error = |message: &str| {
        *outcome.lock().unwrap_or_else(|e| e.into_inner()) = Some(Err(message.to_string()));
    };
    Downloader {
        url,
        dest_path: dest,
        progress_cb: &on_progress,
        done_cb: &on_done,
        error_cb: &on_error,
        cancel: cancel.unwrap_or(&own_cancel),
        expected_sha256: None,
        allowed_hosts: lowercase_hosts(allowed_hosts_for(url).as_deref()),
        transport,
        validate,
        allow_insecure_http,
        backoff,
    }
    .run();
    let result = outcome.lock().unwrap_or_else(|e| e.into_inner()).take();
    match result {
        Some(Ok(sha256)) => Ok(sha256),
        Some(Err(message)) => Err(Error::Runtime(message)),
        None => Err(Error::Runtime("The download ended without a result.".into())),
    }
}

#[cfg(test)]
mod tests;
