//! Tests of the download: Python tests/test_fixes_engine.py (RedirectTrustTests, LocalWriteErrorTests,
//! DownloadSymlinkTests) and tests/test_chromeos.py (FlexRedirectTests, DownloadBlockingTests) against scripted
//! transports; plus a tiny plain-http server on 127.0.0.1 that exercises the real `ureq` client (resume, redirects,
//! retries). Nothing here touches the network beyond 127.0.0.1.

use super::*;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

const MS: &str = "https://software.download.prss.microsoft.com/Win11.iso";

fn sha_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

// ----- the URL policy the tests script (the real one is validate::validate_download_url) -----
fn policy(allow_any: bool) -> impl Fn(&str) -> crate::types::Result<(String, String, bool)> + Send + Sync {
    move |url: &str| {
        let Some(rest) = url.strip_prefix("https://") else {
            return Err(Error::value("Only https:// download addresses are allowed."));
        };
        let host = rest.split(['/', '?', '#']).next().unwrap_or("").to_lowercase();
        let trusted = ["software.download.prss.microsoft.com", "download.microsoft.com", "microsoft.com"]
            .contains(&host.as_str())
            || url == CHROMEOS_FLEX_URL;
        Ok((url.to_string(), host, !trusted && !allow_any))
    }
}

// ----- a scripted transport -----
type Call = (String, Vec<(String, String)>);
type Policy = Box<dyn Fn(&str) -> crate::types::Result<(String, String, bool)> + Send + Sync>;
type Script = Box<dyn Fn(&str, usize, &[(String, String)]) -> Result<Response, TransportError> + Send + Sync>;

struct Fake {
    script: Script,
    calls: Mutex<Vec<Call>>,
}

impl Fake {
    fn new(
        script: impl Fn(&str, usize, &[(String, String)]) -> Result<Response, TransportError> + Send + Sync + 'static,
    ) -> Self {
        Fake { script: Box::new(script), calls: Mutex::new(Vec::new()) }
    }
    fn always(make: impl Fn() -> Response + Send + Sync + 'static) -> Self {
        Fake::new(move |_, _, _| Ok(make()))
    }
    fn urls(&self) -> Vec<String> {
        self.calls.lock().unwrap().iter().map(|(u, _)| u.clone()).collect()
    }
    fn header_of(&self, call: usize, name: &str) -> Option<String> {
        self.calls.lock().unwrap()[call].1.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone())
    }
}

impl Transport for Fake {
    fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<Response, TransportError> {
        let headers: Vec<(String, String)> = headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let n = {
            let mut calls = self.calls.lock().unwrap();
            calls.push((url.to_string(), headers.clone()));
            calls.len() - 1
        };
        (self.script)(url, n, &headers)
    }
}

/// A body that hands out `step` bytes per read and optionally fails once the first read happened.
struct Body {
    data: Vec<u8>,
    pos: usize,
    step: usize,
    fail: Option<(Option<i32>, io::ErrorKind)>,
}

impl Read for Body {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some((errno, kind)) = self.fail {
            if self.pos > 0 {
                return Err(match errno {
                    Some(code) => io::Error::from_raw_os_error(code),
                    None => io::Error::new(kind, "scripted failure"),
                });
            }
        }
        let n = buf.len().min(self.step).min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

fn response(status: u16, body: &[u8], headers: &[(&str, &str)]) -> Response {
    let mut all = vec![("Content-Length".to_string(), body.len().to_string()), ("ETag".to_string(), "\"abc\"".into())];
    for (k, v) in headers {
        all.retain(|(name, _)| !name.eq_ignore_ascii_case(k));
        all.push((k.to_string(), v.to_string()));
    }
    Response {
        status,
        headers: all,
        body: Box::new(Body { data: body.to_vec(), pos: 0, step: usize::MAX, fail: None }),
    }
}

/// A 200 whose body breaks after the first 4 bytes.
#[cfg_attr(windows, allow(dead_code))]
fn failing(body: &[u8], errno: Option<i32>, kind: io::ErrorKind) -> Response {
    let mut r = response(200, body, &[]);
    r.body = Box::new(Body { data: body.to_vec(), pos: 0, step: 4, fail: Some((errno, kind)) });
    r
}

/// A 200 that hands out 4 bytes per read.
fn slow(body: &[u8]) -> Response {
    let mut r = response(200, body, &[]);
    r.body = Box::new(Body { data: body.to_vec(), pos: 0, step: 4, fail: None });
    r
}

fn redirect(location: &str) -> Response {
    response(302, b"", &[("Location", location), ("Content-Length", "0")])
}

#[derive(Default)]
struct Outcome {
    done: Option<(PathBuf, String, bool)>,
    error: Option<String>,
    progress: Vec<(u64, u64)>,
}

struct Cfg {
    allowed: Option<Vec<String>>,
    expected: Option<String>,
    insecure: bool,
    cancel: CancelToken,
    validate: Policy,
    on_progress: Option<Box<dyn Fn(u64, u64) + Send + Sync>>,
}

impl Default for Cfg {
    fn default() -> Self {
        Cfg {
            allowed: None,
            expected: None,
            insecure: false,
            cancel: CancelToken::new(),
            validate: Box::new(policy(false)),
            on_progress: None,
        }
    }
}

fn go(url: &str, dest: &Path, transport: &dyn Transport, cfg: Cfg) -> Outcome {
    let outcome = Arc::new(Mutex::new(Outcome::default()));
    let (o1, o2, o3) = (outcome.clone(), outcome.clone(), outcome.clone());
    let on_progress = cfg.on_progress;
    let thread = DownloadThread::new(
        url,
        dest,
        Box::new(move |d, t, _s| {
            o1.lock().unwrap().progress.push((d, t));
            if let Some(f) = &on_progress {
                f(d, t);
            }
        }),
        Box::new(move |p, sha, verified| o2.lock().unwrap().done = Some((p.to_path_buf(), sha.to_string(), verified))),
        Box::new(move |m| o3.lock().unwrap().error = Some(m.to_string())),
        cfg.cancel.clone(),
        cfg.expected.clone(),
        cfg.allowed.clone(),
    );
    thread.run_with(transport, &*cfg.validate, cfg.insecure, &[0, 0]);
    let mut guard = outcome.lock().unwrap();
    std::mem::take(&mut *guard)
}

fn part(dest: &Path) -> PathBuf {
    PathBuf::from(format!("{}.part", dest.display()))
}

fn meta(dest: &Path) -> PathBuf {
    PathBuf::from(format!("{}.part.meta", dest.display()))
}

const ABC_META: &[u8] = br#"{"validator": "\"abc\""}"#;

/// Run `f` with a `Downloader` for `dest` whose callbacks do nothing.
fn with_downloader<R>(dest: &Path, f: impl FnOnce(&Downloader) -> R) -> R {
    let fake = Fake::always(|| response(200, b"", &[]));
    let cancel = CancelToken::new();
    let nothing = |_: u64, _: u64, _: f64| {};
    let done = |_: &Path, _: &str, _: bool| {};
    let error = |_: &str| {};
    let validate = policy(false);
    f(&Downloader {
        url: MS,
        dest_path: dest,
        progress_cb: &nothing,
        done_cb: &done,
        error_cb: &error,
        cancel: &cancel,
        expected_sha256: None,
        allowed_hosts: None,
        transport: &fake,
        validate: &validate,
        allow_insecure_http: false,
        backoff: &[0],
    })
}

// ===== RedirectTrustTests =====
#[test]
fn trusted_origin_redirected_to_an_untrusted_host_is_refused_and_discarded() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("Win11.iso");
    let fake = Fake::new(|url, _, _| {
        Ok(if url == MS { redirect("https://evil.example.com/Win11.iso") } else { response(200, b"payload", &[]) })
    });
    let out = go(MS, &dest, &fake, Cfg::default());
    let error = out.error.unwrap();
    assert!(error.contains("not trusted"), "{error}");
    assert!(error.contains("evil.example.com"), "{error}");
    assert!(out.done.is_none());
    assert!(!dest.exists() && !part(&dest).exists() && !meta(&dest).exists());
    // Better than the Python: the untrusted host was never contacted.
    assert_eq!(fake.urls(), vec![MS.to_string()]);
}

#[test]
fn look_alike_hosts_are_untrusted_too() {
    for host in ["microsoft.com.evil.example", "notmicrosoft.com"] {
        let dir = tempfile::tempdir().unwrap();
        let target = format!("https://{host}/x.iso");
        let fake =
            Fake::new(move |url, _, _| Ok(if url == MS { redirect(&target) } else { response(200, b"payload", &[]) }));
        let out = go(MS, &dir.path().join("Win11.iso"), &fake, Cfg::default());
        assert!(out.error.unwrap().contains("not trusted"), "{host}");
    }
}

#[test]
fn trusted_to_trusted_is_fine() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("Win11.iso");
    let fake = Fake::new(|url, _, _| {
        Ok(if url == MS {
            redirect("https://download.microsoft.com/Win11.iso")
        } else {
            response(200, b"payload", &[])
        })
    });
    let out = go(MS, &dest, &fake, Cfg::default());
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fs::read(&dest).unwrap(), b"payload");
    assert_eq!(fake.urls().len(), 2);
}

#[test]
fn relative_and_scheme_relative_redirects_are_resolved_and_checked() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("Win11.iso");
    let fake = Fake::new(|url, _, _| {
        Ok(match url {
            MS => redirect("/dl/real.iso"),
            "https://software.download.prss.microsoft.com/dl/real.iso" => redirect("//download.microsoft.com/x.iso"),
            _ => response(200, b"payload", &[]),
        })
    });
    let out = go(MS, &dest, &fake, Cfg::default());
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(
        fake.urls(),
        vec![
            MS.to_string(),
            "https://software.download.prss.microsoft.com/dl/real.iso".to_string(),
            "https://download.microsoft.com/x.iso".to_string()
        ]
    );
}

#[test]
fn an_origin_the_user_already_accepted_as_untrusted_keeps_todays_behaviour() {
    let dir = tempfile::tempdir().unwrap();
    let url = "https://downloads.example.org/a.iso";
    let fake = Fake::new(move |u, _, _| {
        Ok(if u == url { redirect("https://cdn.other.example/a.iso") } else { response(200, b"payload", &[]) })
    });
    let out = go(url, &dir.path().join("a.iso"), &fake, Cfg::default());
    assert!(out.error.is_none(), "{:?}", out.error);
}

#[test]
fn the_allow_any_host_switch_disables_the_rule() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake::new(|u, _, _| {
        Ok(if u == MS { redirect("https://evil.example.com/Win11.iso") } else { response(200, b"payload", &[]) })
    });
    let cfg = Cfg { validate: Box::new(policy(true)), ..Cfg::default() };
    let out = go(MS, &dir.path().join("Win11.iso"), &fake, cfg);
    assert!(out.error.is_none(), "{:?}", out.error);
}

#[test]
fn downgrade_to_http_is_still_refused() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("Win11.iso");
    let fake = Fake::new(|u, _, _| {
        Ok(if u == MS { redirect("http://software.download.prss.microsoft.com/x") } else { response(200, b"p", &[]) })
    });
    let out = go(MS, &dest, &fake, Cfg::default());
    assert!(out.error.is_some());
    assert!(!dest.exists());
    assert_eq!(fake.urls(), vec![MS.to_string()], "the plain-http address must never be contacted");
}

#[test]
fn a_redirect_loop_ends_with_the_refused_message() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake::new(|_, _, _| Ok(redirect(MS)));
    let out = go(MS, &dir.path().join("Win11.iso"), &fake, Cfg::default());
    assert!(out.error.unwrap().contains("HTTP 302"));
    assert_eq!(fake.urls().len(), MAX_REDIRECTS + 1);
}

// ===== FlexRedirectTests =====
const VERSIONED: &str = "https://dl.google.com/dl/edgedl/chromeos/recovery/\
                         chromeos_16765.41.0_reven_recovery_stable-channel_RevenMPKeys-v11.bin.zip";

fn flex_download(final_url: &str, allowed: Option<Vec<String>>) -> (PathBuf, Outcome, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("latest.bin.zip");
    let target = final_url.to_string();
    let fake = Fake::new(move |u, _, _| {
        Ok(if u == CHROMEOS_FLEX_URL { redirect(&target) } else { response(200, b"hello flex", &[]) })
    });
    let out = go(CHROMEOS_FLEX_URL, &dest, &fake, Cfg { allowed, ..Cfg::default() });
    (dest, out, dir)
}

#[test]
fn the_versioned_file_on_the_same_google_host_is_accepted() {
    let (dest, out, _dir) = flex_download(VERSIONED, allowed_hosts_for(CHROMEOS_FLEX_URL));
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fs::read(&dest).unwrap(), b"hello flex");
    assert_eq!(out.done.unwrap().1, sha_hex(b"hello flex"));
}

#[test]
fn a_redirect_to_another_host_is_refused_and_nothing_is_kept() {
    let (dest, out, _dir) =
        flex_download("https://evil.example.com/latest.bin.zip", allowed_hosts_for(CHROMEOS_FLEX_URL));
    assert!(out.error.unwrap().contains("unexpected address (evil.example.com)"));
    assert!(out.done.is_none());
    assert!(!dest.exists() && !part(&dest).exists());
}

#[test]
fn a_look_alike_flex_host_is_refused() {
    for host in ["dl.google.com.evil.example", "xdl.google.com", "google.com"] {
        let (_dest, out, _dir) = flex_download(&format!("https://{host}/x.zip"), allowed_hosts_for(CHROMEOS_FLEX_URL));
        assert!(out.error.unwrap().contains("unexpected address"), "{host}");
    }
}

#[test]
fn other_downloads_are_not_restricted() {
    let (_dest, out, _dir) = flex_download("https://software.download.prss.microsoft.com/x.iso", None);
    assert!(out.error.is_none(), "{:?}", out.error);
}

#[test]
fn flex_downloads_keep_using_their_own_host_list() {
    let (_dest, out, _dir) =
        flex_download("https://dl.google.com/dl/edgedl/x.bin.zip", allowed_hosts_for(CHROMEOS_FLEX_URL));
    assert!(out.error.is_none(), "{:?}", out.error);
}

#[test]
fn the_first_address_is_held_to_the_allowed_hosts_too() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake::always(|| response(200, b"x", &[]));
    let cfg = Cfg { allowed: Some(vec!["DL.Google.com".into()]), ..Cfg::default() };
    let out = go("https://evil.example.com/x.zip", &dir.path().join("x.zip"), &fake, cfg);
    assert!(out.error.unwrap().contains("unexpected address (evil.example.com)"));
    assert!(fake.urls().is_empty());
}

#[test]
fn the_blocking_helper_restricts_only_the_flex_address() {
    assert_eq!(allowed_hosts_for(CHROMEOS_FLEX_URL), Some(vec!["dl.google.com".to_string()]));
    assert_eq!(allowed_hosts_for("https://example.com/x"), None);
}

// ===== DownloadBlockingTests =====
#[test]
fn the_blocking_helper_returns_the_hash_or_the_reason() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("z");
    let seen = Mutex::new(Vec::new());
    let progress = |d: u64, t: u64, text: &str| seen.lock().unwrap().push((d, t, text.to_string()));
    let ok = Fake::always(|| response(200, b"abcdef", &[]));
    let policy = policy(false);
    let sha =
        download_blocking_with("https://x/y", &dest, Some(&progress), None, &ok, &policy, false, &[0, 0]).unwrap();
    assert_eq!(sha, sha_hex(b"abcdef"));
    assert_eq!(seen.lock().unwrap().last().unwrap(), &(6, 6, "Downloading".to_string()));
    // a cancel comes back as the user-facing reason
    let cancel = CancelToken::new();
    cancel.set();
    let err =
        download_blocking_with("https://x/y", &dest, None, Some(&cancel), &ok, &policy, false, &[0, 0]).unwrap_err();
    assert!(matches!(&err, Error::Runtime(m) if m.contains("canceled")), "{err}");
}

// ===== LocalWriteErrorTests =====
#[cfg(unix)]
#[test]
fn a_full_disk_stops_at_once_and_deletes_the_partial_file() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("Win11.iso");
    let fake = Fake::always(|| failing(&[b'x'; 64], Some(libc::ENOSPC), io::ErrorKind::Other));
    let out = go(MS, &dest, &fake, Cfg::default());
    assert_eq!(fake.urls().len(), 1, "a full disk must not be retried");
    let error = out.error.unwrap();
    assert!(error.contains("not enough free space"), "{error}");
    assert!(error.contains("deleted"), "{error}");
    assert!(out.done.is_none());
    assert!(!part(&dest).exists() && !meta(&dest).exists());
}

#[cfg(unix)]
#[test]
fn the_other_local_errors_are_not_retried_either() {
    for (code, text) in
        [(libc::EROFS, "read-only"), (libc::EACCES, "not allowed to write"), (libc::EPERM, "not allowed to write")]
    {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("Win11.iso");
        let fake = Fake::always(move || failing(&[b'x'; 64], Some(code), io::ErrorKind::Other));
        let out = go(MS, &dest, &fake, Cfg::default());
        assert_eq!(fake.urls().len(), 1);
        assert!(out.error.unwrap().contains(text), "errno {code}");
        assert!(!part(&dest).exists());
    }
}

#[cfg(unix)]
#[test]
fn a_network_reset_is_still_retried_and_the_partial_file_kept() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("Win11.iso");
    let fake = Fake::always(|| failing(&[b'x'; 64], Some(libc::ECONNRESET), io::ErrorKind::ConnectionReset));
    let out = go(MS, &dest, &fake, Cfg::default());
    assert_eq!(fake.urls().len(), DOWNLOAD_MAX_ATTEMPTS as usize);
    assert!(out.error.unwrap().contains("interrupted"));
    assert!(part(&dest).exists());
}

#[cfg(unix)]
#[test]
fn the_fatal_errnos_are_exactly_the_local_ones() {
    for code in [libc::ENOSPC, libc::EDQUOT, libc::EROFS, libc::EACCES, libc::EPERM] {
        assert!(is_download_fatal_errno(&io::Error::from_raw_os_error(code)), "{code}");
    }
    for code in [libc::ECONNRESET, libc::ETIMEDOUT, libc::EPIPE, libc::ENOENT] {
        assert!(!is_download_fatal_errno(&io::Error::from_raw_os_error(code)), "{code}");
    }
    assert!(!is_download_fatal_errno(&io::Error::new(io::ErrorKind::PermissionDenied, "no raw code")));
}

// ===== DownloadSymlinkTests =====
#[cfg(unix)]
#[test]
fn symlinked_part_and_meta_files_are_dropped_not_followed() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("Win11.iso");
    let victim = dir.path().join("victim-part.txt");
    let victim_meta = dir.path().join("victim-meta.txt");
    fs::write(&victim, b"precious part").unwrap();
    fs::write(&victim_meta, b"precious meta").unwrap();
    symlink(&victim, part(&dest)).unwrap();
    symlink(&victim_meta, meta(&dest)).unwrap();
    let fake = Fake::always(|| response(200, b"fresh payload", &[]));
    let out = go(MS, &dest, &fake, Cfg::default());
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fs::read(&dest).unwrap(), b"fresh payload");
    assert_eq!(fs::read(&victim).unwrap(), b"precious part");
    assert_eq!(fs::read(&victim_meta).unwrap(), b"precious meta");
}

#[cfg(unix)]
#[test]
fn the_validator_is_not_written_through_a_symlink() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("Win11.iso");
    let victim = dir.path().join("victim-meta.txt");
    fs::write(&victim, b"precious meta").unwrap();
    with_downloader(&dest, |d| {
        symlink(&victim, d.meta_path()).unwrap();
        d.write_validator("\"etag\"");
        assert_eq!(d.read_validator(), None);
    });
    assert_eq!(fs::read(&victim).unwrap(), b"precious meta");
}

#[cfg(unix)]
#[test]
fn the_part_and_meta_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("Win11.iso");
    // The body breaks after the first chunk, so the part file and its validator stay on disk.
    let fake = Fake::always(|| failing(&[b'x'; 64], None, io::ErrorKind::ConnectionReset));
    let _ = go(MS, &dest, &fake, Cfg::default());
    for path in [part(&dest), meta(&dest)] {
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{}", path.display());
    }
}

#[test]
fn resuming_a_regular_part_file_still_works() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("Win11.iso");
    fs::write(part(&dest), b"01234").unwrap();
    fs::write(meta(&dest), ABC_META).unwrap();
    let fake = Fake::always(|| response(206, b"56789", &[("Content-Range", "bytes 5-9/10")]));
    let out = go(MS, &dest, &fake, Cfg::default());
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fake.header_of(0, "Range").as_deref(), Some("bytes=5-"));
    assert_eq!(fake.header_of(0, "If-Range").as_deref(), Some("\"abc\""));
    assert_eq!(fs::read(&dest).unwrap(), b"0123456789");
    // the hash covers the bytes that were already on disk
    assert_eq!(out.done.unwrap().1, sha_hex(b"0123456789"));
    assert!(!part(&dest).exists() && !meta(&dest).exists());
}

// ===== resume details =====
#[test]
fn a_part_file_without_a_validator_is_not_resumed() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("Win11.iso");
    fs::write(part(&dest), b"01234").unwrap();
    let fake = Fake::always(|| response(200, b"0123456789", &[]));
    let out = go(MS, &dest, &fake, Cfg::default());
    assert!(out.error.is_none());
    assert_eq!(fake.header_of(0, "Range"), None);
    assert_eq!(fs::read(&dest).unwrap(), b"0123456789");
}

#[test]
fn a_server_that_ignores_range_leads_to_a_clean_restart() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("Win11.iso");
    fs::write(part(&dest), b"01234").unwrap();
    fs::write(meta(&dest), ABC_META).unwrap();
    let fake = Fake::always(|| response(200, b"0123456789", &[]));
    let out = go(MS, &dest, &fake, Cfg::default());
    assert!(out.error.is_none());
    assert_eq!(fake.header_of(0, "Range").as_deref(), Some("bytes=5-"));
    assert_eq!(fs::read(&dest).unwrap(), b"0123456789");
    assert_eq!(out.done.unwrap().1, sha_hex(b"0123456789"), "the old bytes must not be hashed twice");
}

#[test]
fn range_not_satisfiable_restarts_from_zero() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("Win11.iso");
    fs::write(part(&dest), b"01234").unwrap();
    fs::write(meta(&dest), ABC_META).unwrap();
    let fake =
        Fake::new(|_, n, _| Ok(if n == 0 { response(416, b"", &[]) } else { response(200, b"0123456789", &[]) }));
    let out = go(MS, &dest, &fake, Cfg::default());
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fake.header_of(0, "Range").as_deref(), Some("bytes=5-"));
    assert_eq!(fake.header_of(1, "Range"), None);
    assert_eq!(fs::read(&dest).unwrap(), b"0123456789");
}

#[test]
fn a_content_range_for_another_offset_discards_the_part_and_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("Win11.iso");
    fs::write(part(&dest), b"01234").unwrap();
    fs::write(meta(&dest), ABC_META).unwrap();
    let fake = Fake::new(|_, n, _| {
        Ok(if n == 0 {
            response(206, b"abc", &[("Content-Range", "bytes 3-5/10")])
        } else {
            response(200, b"0123456789", &[])
        })
    });
    let out = go(MS, &dest, &fake, Cfg::default());
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fs::read(&dest).unwrap(), b"0123456789");
    assert_eq!(fake.urls().len(), 2, "the restart does not use up an attempt");
    assert_eq!(fake.header_of(1, "Range"), None);
}

#[test]
fn a_checksum_mismatch_discards_everything_and_a_match_is_reported_verified() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("Win11.iso");
    let fake = Fake::always(|| response(200, b"payload", &[]));
    let cfg = Cfg { expected: Some("0".repeat(64)), ..Cfg::default() };
    let out = go(MS, &dest, &fake, cfg);
    let error = out.error.unwrap();
    assert!(error.contains("SHA-256 verification FAILED"), "{error}");
    assert!(error.contains(&sha_hex(b"payload")));
    assert!(!dest.exists() && !part(&dest).exists() && !meta(&dest).exists());

    let cfg = Cfg { expected: Some(format!("  {}  ", sha_hex(b"payload").to_uppercase())), ..Cfg::default() };
    let out = go(MS, &dest, &fake, cfg);
    assert!(out.error.is_none(), "{:?}", out.error);
    let (path, sha, verified) = out.done.unwrap();
    assert_eq!((path, sha, verified), (dest.clone(), sha_hex(b"payload"), true));
    assert_eq!(fs::read(&dest).unwrap(), b"payload");
    assert!(!part(&dest).exists() && !meta(&dest).exists());
}

#[test]
fn cancel_keeps_the_part_file_and_the_validator() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("Win11.iso");
    let cancel = CancelToken::new();
    let c2 = cancel.clone();
    let fake = Fake::always(|| slow(&[b'x'; 64]));
    let cfg = Cfg { cancel, on_progress: Some(Box::new(move |_, _| c2.set())), ..Cfg::default() };
    let out = go(MS, &dest, &fake, cfg);
    assert!(out.error.unwrap().contains("Download canceled by user"));
    assert!(out.done.is_none());
    assert_eq!(fs::read(part(&dest)).unwrap(), b"xxxx");
    assert!(meta(&dest).exists());
    assert!(!dest.exists());
    assert_eq!(fake.urls().len(), 1, "a cancel is not retried");
}

#[test]
fn an_incomplete_body_is_retried_and_reported_with_the_partial_file_kept() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("Win11.iso");
    let fake = Fake::always(|| response(200, b"12345", &[("Content-Length", "10")]));
    let out = go(MS, &dest, &fake, Cfg::default());
    let error = out.error.unwrap();
    assert!(error.contains("Incomplete download: received 5.0 B of 10.0 B."), "{error}");
    assert!(error.contains("after 3 attempts"), "{error}");
    assert_eq!(fake.urls().len(), DOWNLOAD_MAX_ATTEMPTS as usize);
    assert!(part(&dest).exists());
}

#[test]
fn more_data_than_announced_is_discarded() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("Win11.iso");
    let fake = Fake::always(|| response(200, b"1234567890", &[("Content-Length", "5")]));
    let out = go(MS, &dest, &fake, Cfg::default());
    assert!(out.error.unwrap().contains("more data than announced"));
    assert!(!part(&dest).exists() && !dest.exists());
}

#[test]
fn http_errors_below_500_are_final_and_keep_the_part_file() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("Win11.iso");
    fs::write(part(&dest), b"01234").unwrap();
    fs::write(meta(&dest), ABC_META).unwrap();
    let fake = Fake::always(|| response(404, b"", &[]));
    let out = go(MS, &dest, &fake, Cfg::default());
    assert!(out.error.unwrap().contains("The server refused the download (HTTP 404)"));
    assert_eq!(fake.urls().len(), 1);
    assert!(part(&dest).exists() && meta(&dest).exists());
}

#[test]
fn server_errors_and_throttling_are_retried() {
    for code in [500u16, 503, 408, 429] {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("Win11.iso");
        let fake =
            Fake::new(move |_, n, _| Ok(if n < 2 { response(code, b"", &[]) } else { response(200, b"payload", &[]) }));
        let out = go(MS, &dest, &fake, Cfg::default());
        assert!(out.error.is_none(), "{code}: {:?}", out.error);
        assert_eq!(fake.urls().len(), 3);
        assert_eq!(fs::read(&dest).unwrap(), b"payload");
    }
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake::always(|| response(503, b"", &[]));
    let out = go(MS, &dir.path().join("Win11.iso"), &fake, Cfg::default());
    let error = out.error.unwrap();
    assert!(error.contains("interrupted (HTTP 503)") && error.contains("3 attempts"), "{error}");
}

#[test]
fn a_transport_failure_is_retried_with_its_reason() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake::new(|_, _, _| Err(TransportError("connection refused".into())));
    let out = go(MS, &dir.path().join("Win11.iso"), &fake, Cfg::default());
    let error = out.error.unwrap();
    assert!(error.contains("connection refused") && error.contains("3 attempts"), "{error}");
}

#[test]
fn a_cancel_during_the_backoff_stops_the_retries() {
    let dir = tempfile::tempdir().unwrap();
    let cancel = CancelToken::new();
    let c2 = cancel.clone();
    let fake = Fake::new(move |_, _, _| {
        c2.set();
        Err(TransportError("down".into()))
    });
    let out = go(MS, &dir.path().join("Win11.iso"), &fake, Cfg { cancel, ..Cfg::default() });
    assert!(out.error.unwrap().contains("Download canceled by user"));
    assert_eq!(fake.urls().len(), 1);
}

#[test]
fn progress_reports_every_chunk_and_the_total() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake::always(|| slow(&[b'z'; 10]));
    let out = go(MS, &dir.path().join("f"), &fake, Cfg::default());
    assert_eq!(out.progress, vec![(4, 10), (8, 10), (10, 10)]);
}

#[test]
fn an_invalid_address_is_refused_before_any_connection() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake::always(|| response(200, b"x", &[]));
    let out = go("http://software.download.prss.microsoft.com/x", &dir.path().join("f"), &fake, Cfg::default());
    assert!(out.error.is_some());
    assert!(fake.urls().is_empty());
}

// ===== helpers =====
#[test]
fn hosts_are_read_like_urlparse_hostname() {
    assert_eq!(url_host("https://User:pw@Example.COM:8443/a?b#c"), "example.com");
    assert_eq!(url_host("http://[::1]:80/x"), "::1");
    assert_eq!(url_host("https://dl.google.com"), "dl.google.com");
    assert_eq!(url_host("https://a.example?x=1"), "a.example");
}

#[test]
fn redirect_locations_are_resolved_like_urljoin() {
    let base = "https://a.example/dir/sub/file.iso?x=1";
    assert_eq!(resolve_redirect(base, "https://b.example/z"), "https://b.example/z");
    assert_eq!(resolve_redirect(base, "//b.example/z"), "https://b.example/z");
    assert_eq!(resolve_redirect(base, "/abs/z"), "https://a.example/abs/z");
    assert_eq!(resolve_redirect(base, "other.iso"), "https://a.example/dir/sub/other.iso");
    assert_eq!(resolve_redirect(base, "../up.iso?y=2"), "https://a.example/dir/up.iso?y=2");
    assert_eq!(resolve_redirect(base, "?only=query"), "https://a.example/dir/sub/file.iso?only=query");
    assert_eq!(resolve_redirect(base, "/x#frag"), "https://a.example/x");
    assert_eq!(resolve_redirect("https://a.example", "next"), "https://a.example/next");
}

#[test]
fn the_validator_file_is_read_defensively() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("f");
    with_downloader(&dest, |d| {
        assert_eq!(d.read_validator(), None); // missing
        for text in ["not json", "[1, 2]", r#"{"validator": 5}"#, r#"{"validator": ""}"#, r#"{"other": "x"}"#, ""] {
            fs::write(d.meta_path(), text).unwrap();
            assert_eq!(d.read_validator(), None, "{text}");
        }
        d.write_validator("W/\"weak\"");
        assert_eq!(d.read_validator().as_deref(), Some("W/\"weak\""));
        assert_eq!(fs::read_to_string(d.meta_path()).unwrap(), r#"{"validator": "W/\"weak\""}"#);
    });
}

#[test]
fn the_strong_validator_prefers_a_strong_etag_then_last_modified() {
    let strong = response(200, b"", &[("ETag", "\"v1\"")]);
    assert_eq!(Downloader::strong_validator(&strong).as_deref(), Some("\"v1\""));
    let weak = response(200, b"", &[("ETag", "W/\"v1\""), ("Last-Modified", "Tue, 01 Jan 2030 00:00:00 GMT")]);
    assert_eq!(Downloader::strong_validator(&weak).as_deref(), Some("Tue, 01 Jan 2030 00:00:00 GMT"));
    let mut none = response(200, b"", &[]);
    none.headers.clear();
    assert_eq!(Downloader::strong_validator(&none), None);
}

// ===== the real client against a local plain-http server =====
struct Req {
    path: String,
    headers: Vec<(String, String)>,
}

impl Req {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// Content-Length to announce when it must differ from the body (a connection that dies halfway).
    declared: Option<usize>,
}

fn reply(status: u16, body: &[u8]) -> Reply {
    Reply { status, headers: Vec::new(), body: body.to_vec(), declared: None }
}

impl Reply {
    fn header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.to_string(), v.to_string()));
        self
    }
}

struct TestServer {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<Req>>>,
    stop: Arc<AtomicBool>,
}

impl TestServer {
    fn start(handler: impl Fn(&Req, usize) -> Reply + Send + Sync + 'static) -> TestServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let handler = Arc::new(handler);
        let counter = Arc::new(AtomicUsize::new(0));
        let (reqs, stopped) = (requests.clone(), stop.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stopped.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let (handler, reqs, counter) = (handler.clone(), reqs.clone(), counter.clone());
                std::thread::spawn(move || serve(stream, &*handler, &reqs, &counter));
            }
        });
        TestServer { addr, requests, stop }
    }
    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.addr.port())
    }
    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
    fn header_of(&self, n: usize, name: &str) -> Option<String> {
        self.requests.lock().unwrap()[n].header(name).map(|s| s.to_string())
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr); // wakes the accept loop
    }
}

fn serve(mut stream: TcpStream, handler: &dyn Fn(&Req, usize) -> Reply, reqs: &Mutex<Vec<Req>>, counter: &AtomicUsize) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
        if head.len() > 16 * 1024 {
            return;
        }
    }
    let text = String::from_utf8_lossy(&head).to_string();
    let mut lines = text.split("\r\n");
    let path = lines.next().unwrap_or("").split_whitespace().nth(1).unwrap_or("/").to_string();
    let headers =
        lines.filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))).collect();
    let req = Req { path, headers };
    let n = counter.fetch_add(1, Ordering::SeqCst);
    let answer = handler(&req, n);
    reqs.lock().unwrap().push(req);
    let reason = match answer.status {
        200 => "OK",
        206 => "Partial Content",
        302 => "Found",
        404 => "Not Found",
        416 => "Range Not Satisfiable",
        500 => "Internal Server Error",
        _ => "Status",
    };
    let mut out = format!("HTTP/1.1 {} {reason}\r\n", answer.status);
    for (k, v) in &answer.headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        answer.declared.unwrap_or(answer.body.len())
    ));
    let _ = stream.write_all(out.as_bytes());
    let _ = stream.write_all(&answer.body);
    let _ = stream.flush();
}

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 % 251) as u8).collect()
}

fn http(url: &str, dest: &Path, cfg: Cfg) -> Outcome {
    let transport = UreqTransport::new(false);
    go(url, dest, &transport, Cfg { insecure: true, ..cfg })
}

fn range_start(range: &str) -> usize {
    range.trim_start_matches("bytes=").trim_end_matches('-').parse().unwrap()
}

#[test]
fn a_plain_download_over_the_real_client() {
    let data = payload(300_000);
    let body = data.clone();
    let server = TestServer::start(move |_, _| reply(200, &body).header("ETag", "\"v1\""));
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("a.iso");
    let out = http(&server.url("/a.iso"), &dest, Cfg::default());
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fs::read(&dest).unwrap(), data);
    let (path, sha, verified) = out.done.unwrap();
    assert_eq!((path, sha, verified), (dest.clone(), sha_hex(&data), false));
    assert_eq!(out.progress.last(), Some(&(300_000, 300_000)));
    assert!(!part(&dest).exists() && !meta(&dest).exists());
    assert_eq!(server.header_of(0, "User-Agent").as_deref(), Some("Mozilla/5.0"));
    assert_eq!(server.header_of(0, "Range"), None);
    assert_eq!(server.header_of(0, "Accept-Encoding").as_deref(), Some("identity"));
}

#[test]
fn a_resume_over_the_real_client_sends_range_and_if_range() {
    let data = payload(100_000);
    let body = data.clone();
    let server = TestServer::start(move |req, _| match req.header("Range") {
        Some(range) => {
            let start = range_start(range);
            reply(206, &body[start..])
                .header("Content-Range", &format!("bytes {start}-{}/{}", body.len() - 1, body.len()))
                .header("ETag", "\"v1\"")
        }
        None => reply(200, &body).header("ETag", "\"v1\""),
    });
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("a.iso");
    fs::write(part(&dest), &data[..40_000]).unwrap();
    fs::write(meta(&dest), br#"{"validator": "\"v1\""}"#).unwrap();
    let out = http(&server.url("/a.iso"), &dest, Cfg::default());
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(server.header_of(0, "Range").as_deref(), Some("bytes=40000-"));
    assert_eq!(server.header_of(0, "If-Range").as_deref(), Some("\"v1\""));
    assert_eq!(fs::read(&dest).unwrap(), data);
    assert_eq!(out.done.unwrap().1, sha_hex(&data));
}

#[test]
fn a_server_that_ignores_range_restarts_over_the_real_client() {
    let data = payload(50_000);
    let body = data.clone();
    let server = TestServer::start(move |_, _| reply(200, &body).header("ETag", "\"v2\""));
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("a.iso");
    fs::write(part(&dest), &data[..10_000]).unwrap();
    fs::write(meta(&dest), br#"{"validator": "\"v1\""}"#).unwrap();
    let out = http(&server.url("/a.iso"), &dest, Cfg::default());
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fs::read(&dest).unwrap(), data);
    assert_eq!(out.done.unwrap().1, sha_hex(&data));
    assert_eq!(server.count(), 1);
}

#[test]
fn redirects_are_followed_by_hand_over_the_real_client() {
    let data = payload(20_000);
    let body = data.clone();
    let server = TestServer::start(move |req, _| match req.path.as_str() {
        "/start" => reply(302, b"").header("Location", "/mid/next"),
        "/mid/next" => reply(302, b"").header("Location", "final.iso"),
        "/mid/final.iso" => reply(200, &body),
        _ => reply(404, b""),
    });
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("a.iso");
    let out = http(&server.url("/start"), &dest, Cfg::default());
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fs::read(&dest).unwrap(), data);
    assert_eq!(server.count(), 3);
}

#[test]
fn a_redirect_to_a_host_outside_the_allowed_ones_is_never_contacted() {
    let other = TestServer::start(|_, _| reply(200, b"should never be asked"));
    let location = other.url("/x").replace("127.0.0.1", "localhost");
    let server = TestServer::start(move |_, _| reply(302, b"").header("Location", &location));
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("b.iso");
    let cfg = Cfg { allowed: Some(vec!["127.0.0.1".into()]), ..Cfg::default() };
    let out = http(&server.url("/start"), &dest, cfg);
    assert!(out.error.unwrap().contains("unexpected address (localhost)"));
    assert!(!dest.exists() && !part(&dest).exists());
    assert_eq!(server.count(), 1);
    assert_eq!(other.count(), 0);
}

#[test]
fn a_connection_that_dies_halfway_is_retried_and_resumed_over_the_real_client() {
    let data = payload(200_000);
    let body = data.clone();
    let server = TestServer::start(move |req, n| {
        if let Some(range) = req.header("Range") {
            let start = range_start(range);
            return reply(206, &body[start..])
                .header("Content-Range", &format!("bytes {start}-{}/{}", body.len() - 1, body.len()))
                .header("ETag", "\"v1\"");
        }
        assert_eq!(n, 0);
        let mut r = reply(200, &body[..70_000]).header("ETag", "\"v1\"");
        r.declared = Some(body.len());
        r
    });
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("a.iso");
    let out = http(&server.url("/a.iso"), &dest, Cfg::default());
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fs::read(&dest).unwrap(), data);
    assert_eq!(out.done.unwrap().1, sha_hex(&data));
    assert_eq!(server.count(), 2);
    assert_eq!(server.header_of(1, "Range").as_deref(), Some("bytes=70000-"));
    assert_eq!(server.header_of(1, "If-Range").as_deref(), Some("\"v1\""));
}

#[test]
fn http_statuses_over_the_real_client() {
    let server = TestServer::start(|req, n| match req.path.as_str() {
        "/missing" => reply(404, b"nope"),
        "/flaky" if n % 2 == 1 => reply(200, b"fine"),
        "/flaky" => reply(500, b"oops"),
        _ => reply(404, b""),
    });
    let dir = tempfile::tempdir().unwrap();
    let out = http(&server.url("/missing"), &dir.path().join("m"), Cfg::default());
    assert!(out.error.unwrap().contains("HTTP 404"));
    let dest = dir.path().join("f");
    let out = http(&server.url("/flaky"), &dest, Cfg::default());
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fs::read(&dest).unwrap(), b"fine");
}

#[test]
fn a_refused_connection_is_retried_then_reported() {
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let dir = tempfile::tempdir().unwrap();
    let out = http(&format!("http://127.0.0.1:{port}/x"), &dir.path().join("x"), Cfg::default());
    let error = out.error.unwrap();
    assert!(error.contains("interrupted") && error.contains("3 attempts"), "{error}");
}

#[test]
fn the_production_client_refuses_plain_http() {
    let transport = UreqTransport::new(true);
    assert!(transport.get("http://127.0.0.1:9/x", &[]).is_err());
}
