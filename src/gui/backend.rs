//! Everything the window calls in the rest of the program, behind one trait. The window's logic only ever talks to a
//! `dyn Backend`, so the tests drive it with a fake and only `RealBackend` (a thin wiring) touches the real modules.

use crate::audit::AuditLevel;
use crate::diskrisk::RiskLevel;
use crate::download::{DoneCb, ErrorCb, ProgressCb};
use crate::types::{BuildOptions, CancelToken, Ctx, Disk, Hardening, Identity, IsoKind, Log, Mode, Privilege, Progress2, Result, SeedTarget};
use std::path::{Path, PathBuf};

/// The operating system the window is running on (the Python `IS_MAC` / `IS_WINDOWS` flags; a value so tests can
/// pretend).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Mac,
    Linux,
    Windows,
}

impl Platform {
    pub fn current() -> Platform {
        if crate::constants::IS_WINDOWS {
            Platform::Windows
        } else if crate::constants::IS_MAC {
            Platform::Mac
        } else {
            Platform::Linux
        }
    }
}

/// One HTTPS download (the arguments of `download::DownloadThread`).
pub struct DownloadRequest {
    pub url: String,
    pub dest: PathBuf,
    pub cancel: CancelToken,
    pub expected_sha256: Option<String>,
    pub allowed_hosts: Option<Vec<String>>,
    /// `progress(done, total, speed)`
    pub progress: ProgressCb,
    /// `done(path, sha256, verified)`
    pub done: DoneCb,
    /// `error(message)`
    pub error: ErrorCb,
}

pub trait Backend: Send + Sync {
    fn platform(&self) -> Platform;

    // ---- drives and tools ----
    fn get_external_disks(&self) -> Result<Vec<Disk>>;
    fn get_missing_dependencies(&self, mode: Mode) -> Vec<String>;
    fn missing_dependencies_hint(&self, missing: &[String]) -> String;
    fn needs_admin(&self, mode: Mode) -> bool;
    fn pin_target_identity(&self, dev: &str, identity: Option<Identity>);
    fn image_exceeds_drive(&self, image_size: u64, drive_size: u64) -> bool;
    fn chromeos_drive_too_small(&self, mode: Mode, drive_size: u64) -> bool;
    fn check_seed_target_size(&self, size: Option<u64>) -> Result<()>;
    fn assess_disk_risk(&self, disk: &Disk) -> (RiskLevel, Vec<String>);
    fn describe_disk_for_confirmation(&self, disk: &Disk) -> String;

    // ---- writing ----
    fn build_usb(&self, iso: &Path, dev: &str, ctx: &Ctx, priv_: &dyn Privilege, opts: &BuildOptions) -> Result<bool>;
    fn build_seed_usb(
        &self,
        target: SeedTarget,
        dev: &str,
        ctx: &Ctx,
        priv_: &dyn Privilege,
        expected_size: Option<u64>,
        eject: bool,
        profile: Hardening,
    ) -> Result<bool>;

    // ---- images ----
    fn detect_iso_kind(&self, path: &Path) -> IsoKind;
    fn extract_disk_image(
        &self,
        zip: &Path,
        dest_dir: &Path,
        progress: Option<Progress2>,
        cancel: Option<&CancelToken>,
    ) -> Result<PathBuf>;
    fn sha256_file(&self, path: &Path, cancel: Option<&CancelToken>, progress: Option<Progress2>) -> Result<String>;
    fn validate_download_url(&self, raw: &str) -> Result<(String, String, bool)>;
    fn is_sha256_hex(&self, text: &str) -> bool;
    fn parse_expected_sha256(&self, text: &str, filename: Option<&str>) -> Result<Option<String>>;
    fn start_download(&self, request: DownloadRequest);

    // ---- dependencies ----
    fn detect_pkg_manager(&self) -> Option<String>;
    fn build_install_command(&self, mgr: Option<&str>, missing: &[String]) -> Result<String>;
    fn run_cmd(&self, args: &[String], log: Log) -> Result<i32>;
    fn which(&self, name: &str) -> bool;

    // ---- information ----
    fn describe_hardening_applied(&self) -> Vec<String>;
    fn help_sections(&self) -> Vec<(String, String)>;
    fn audit(&self, msg: &str, level: AuditLevel);
    fn audit_log_path(&self) -> PathBuf;
    fn disk_free(&self, dir: &Path) -> Option<u64>;
    fn open_url(&self, url: &str);
}

/// The real thing: every call goes straight to the module that owns it.
pub struct RealBackend;

impl Backend for RealBackend {
    fn platform(&self) -> Platform {
        Platform::current()
    }

    fn get_external_disks(&self) -> Result<Vec<Disk>> {
        crate::engine::get_external_disks()
    }
    fn get_missing_dependencies(&self, mode: Mode) -> Vec<String> {
        crate::engine::get_missing_dependencies(mode)
    }
    fn missing_dependencies_hint(&self, missing: &[String]) -> String {
        crate::engine::missing_dependencies_hint(missing)
    }
    fn needs_admin(&self, mode: Mode) -> bool {
        crate::engine::needs_admin(mode)
    }
    fn pin_target_identity(&self, dev: &str, identity: Option<Identity>) {
        crate::engine::pin_target_identity(dev, identity)
    }
    fn image_exceeds_drive(&self, image_size: u64, drive_size: u64) -> bool {
        crate::engine::image_exceeds_drive(image_size, drive_size)
    }
    fn chromeos_drive_too_small(&self, mode: Mode, drive_size: u64) -> bool {
        crate::engine::chromeos_drive_too_small(mode, drive_size)
    }
    fn check_seed_target_size(&self, size: Option<u64>) -> Result<()> {
        crate::seed::check_seed_target_size(size)
    }
    fn assess_disk_risk(&self, disk: &Disk) -> (RiskLevel, Vec<String>) {
        crate::diskrisk::assess_disk_risk(disk, true)
    }
    fn describe_disk_for_confirmation(&self, disk: &Disk) -> String {
        crate::diskrisk::describe_disk_for_confirmation(disk, true)
    }

    fn build_usb(&self, iso: &Path, dev: &str, ctx: &Ctx, priv_: &dyn Privilege, opts: &BuildOptions) -> Result<bool> {
        crate::engine::build_usb(iso, dev, ctx, priv_, opts)
    }
    fn build_seed_usb(
        &self,
        target: SeedTarget,
        dev: &str,
        ctx: &Ctx,
        priv_: &dyn Privilege,
        expected_size: Option<u64>,
        eject: bool,
        profile: Hardening,
    ) -> Result<bool> {
        crate::seed::build_seed_usb(target, dev, ctx, priv_, expected_size, eject, profile)
    }

    fn detect_iso_kind(&self, path: &Path) -> IsoKind {
        crate::isoinfo::detect_iso_kind(path)
    }
    fn extract_disk_image(
        &self,
        zip: &Path,
        dest_dir: &Path,
        progress: Option<Progress2>,
        cancel: Option<&CancelToken>,
    ) -> Result<PathBuf> {
        crate::isoinfo::extract_disk_image(zip, dest_dir, progress, cancel)
    }
    fn sha256_file(&self, path: &Path, cancel: Option<&CancelToken>, progress: Option<Progress2>) -> Result<String> {
        crate::hash::sha256_file(path, cancel, progress)
    }
    fn validate_download_url(&self, raw: &str) -> Result<(String, String, bool)> {
        crate::validate::validate_download_url(raw)
    }
    fn is_sha256_hex(&self, text: &str) -> bool {
        crate::validate::is_sha256_hex(text)
    }
    fn parse_expected_sha256(&self, text: &str, filename: Option<&str>) -> Result<Option<String>> {
        crate::validate::parse_expected_sha256(text, filename)
    }
    fn start_download(&self, request: DownloadRequest) {
        let thread = crate::download::DownloadThread {
            url: request.url,
            dest_path: request.dest,
            progress_cb: request.progress,
            done_cb: request.done,
            error_cb: request.error,
            cancel: request.cancel,
            expected_sha256: request.expected_sha256,
            allowed_hosts: request.allowed_hosts,
        };
        // Runs on its own thread; the callbacks only post messages to the window.
        let _ = thread.start();
    }

    fn detect_pkg_manager(&self) -> Option<String> {
        crate::linux::detect_pkg_manager()
    }
    fn build_install_command(&self, mgr: Option<&str>, missing: &[String]) -> Result<String> {
        crate::linux::build_install_command(mgr, missing)
    }
    fn run_cmd(&self, args: &[String], log: Log) -> Result<i32> {
        crate::proc::run_cmd(args, log, true, None, None)
    }
    fn which(&self, name: &str) -> bool {
        which(name)
    }

    fn describe_hardening_applied(&self) -> Vec<String> {
        crate::harden_windows::describe_hardening_windows_applied(Hardening::Baseline)
    }
    fn help_sections(&self) -> Vec<(String, String)> {
        crate::help::help_sections()
    }
    fn audit(&self, msg: &str, level: AuditLevel) {
        crate::audit::audit_at(msg, level)
    }
    fn audit_log_path(&self) -> PathBuf {
        crate::audit::audit_log_path()
    }
    fn disk_free(&self, dir: &Path) -> Option<u64> {
        disk_free(dir)
    }
    fn open_url(&self, url: &str) {
        let _ = webbrowser::open(url);
    }
}

/// `shutil.which(name)`: is there an executable called `name` on the PATH.
pub fn which(name: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if is_executable_file(&candidate) {
            return true;
        }
        if cfg!(windows) && is_executable_file(&dir.join(format!("{name}.exe"))) {
            return true;
        }
    }
    false
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// `shutil.disk_usage(dir).free`: the bytes a normal user can still write in the folder (None when unknown).
#[cfg(unix)]
pub fn disk_free(dir: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    // SAFETY: `c` is a valid NUL-terminated path and `st` is a properly sized, writable statvfs buffer.
    unsafe {
        let mut st: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c.as_ptr(), &mut st) != 0 {
            return None;
        }
        Some((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
    }
}

/// `GetDiskFreeSpaceExW`: the bytes available to the caller in the folder (None when it fails).
#[cfg(windows)]
pub fn disk_free(dir: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let (mut available, mut total, mut free) = (0u64, 0u64, 0u64);
    // SAFETY: `wide` is NUL-terminated and the three out-pointers are valid for the duration of the call.
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(wide.as_ptr(), &mut available, &mut total, &mut free)
    };
    if ok != 0 {
        Some(available)
    } else {
        None
    }
}

#[cfg(not(any(unix, windows)))]
pub fn disk_free(_dir: &Path) -> Option<u64> {
    None
}
