//! The seam between the command line and the rest of the program.
//!
//! The Python tests replace engine functions with `mock.patch`; here every call the command line makes into the
//! engine, the validators, the privilege helpers and the network goes through the [`Engine`] trait. [`RealEngine`]
//! (every method keeps its default) delegates to `crate::engine`, `crate::seed`, `crate::isoinfo`, `crate::hash`,
//! `crate::validate`, `crate::privilege`, `crate::download` and friends; the tests implement the trait with fakes.

use crate::audit::{audit_at, AuditLevel};
use crate::constants::{IS_LINUX, IS_MAC, IS_WINDOWS};
use crate::types::{
    BuildOptions, CancelToken, Ctx, Disk, Files, Hardening, Identity, IsoKind, Mode, Privilege, Progress, Progress2,
    Result, SeedTarget,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub trait Engine: Send + Sync {
    /// `IS_MAC or IS_LINUX or IS_WINDOWS`.
    fn supported_platform(&self) -> bool {
        IS_MAC || IS_LINUX || IS_WINDOWS
    }

    // ---- drives and tools ----
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
    fn image_exceeds_drive(&self, image_size: u64, drive_size: u64) -> bool {
        crate::engine::image_exceeds_drive(image_size, drive_size)
    }
    fn chromeos_drive_too_small(&self, mode: Mode, drive_size: u64) -> bool {
        crate::engine::chromeos_drive_too_small(mode, drive_size)
    }
    /// Bind the safety re-check (right before erasing) to the drive that was planned; `None` releases the pin.
    fn pin_target_identity(&self, dev: &str, identity: Option<Identity>) {
        crate::engine::pin_target_identity(dev, identity)
    }
    /// Free bytes on the file system holding `dir` (`shutil.disk_usage(dir).free`); `None` when unknown.
    fn free_space(&self, dir: &Path) -> Option<u64> {
        free_space_of(dir)
    }

    // ---- validation and inspection ----
    fn validate_iso_path(&self, path: &str) -> Result<PathBuf> {
        crate::validate::validate_iso_path(path)
    }
    fn validate_device_name(&self, dev: &str) -> Result<String> {
        crate::validate::validate_device_name(dev)
    }
    fn validate_hybrid_iso(&self, path: &Path) -> Result<()> {
        crate::validate::validate_hybrid_iso(path)
    }
    fn validate_disk_image(&self, path: &Path) -> Result<()> {
        crate::validate::validate_disk_image(path)
    }
    fn validate_macos_image(&self, path: &Path) -> Result<()> {
        crate::validate::validate_macos_image(path)
    }
    fn detect_iso_kind(&self, path: &Path) -> IsoKind {
        crate::isoinfo::detect_iso_kind(path)
    }
    fn sha256_file(&self, path: &Path, cancel: Option<&CancelToken>, progress: Option<Progress2>) -> Result<String> {
        crate::hash::sha256_file(path, cancel, progress)
    }

    // ---- the destructive engine ----
    /// The privilege helper of the command line: sudo on the terminal, or the elevated Windows terminal.
    fn privilege(&self) -> Arc<dyn Privilege> {
        if IS_WINDOWS {
            Arc::new(crate::privilege::WindowsCliPrivilege)
        } else {
            Arc::new(crate::privilege::CliPrivilege::new())
        }
    }
    fn build_usb(
        &self,
        iso_path: &Path,
        dev: &str,
        ctx: &Ctx,
        priv_: &dyn Privilege,
        opts: &BuildOptions,
    ) -> Result<bool> {
        crate::engine::build_usb(iso_path, dev, ctx, priv_, opts)
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

    // ---- ChromeOS Flex ----
    /// `download_file_blocking`: the SHA-256 of the downloaded file, or `Error::Runtime` with the reason.
    fn download(
        &self,
        url: &str,
        dest: &Path,
        progress: Option<Progress>,
        cancel: Option<&CancelToken>,
    ) -> Result<String> {
        crate::download::download_file_blocking(url, dest, progress, cancel)
    }
    fn extract_disk_image(
        &self,
        zip_path: &Path,
        dest_dir: &Path,
        progress: Option<Progress2>,
        cancel: Option<&CancelToken>,
    ) -> Result<PathBuf> {
        crate::isoinfo::extract_disk_image(zip_path, dest_dir, progress, cancel)
    }

    // ---- the hardening files ----
    fn hardening_files_windows(&self, profile: Hardening) -> Result<Files> {
        crate::harden_windows::hardening_files_windows(profile)
    }
    fn hardening_files_seed(&self, target: SeedTarget, profile: Hardening) -> Result<(String, Files)> {
        crate::seed_files::hardening_files_seed(target, profile)
    }
    fn validate_seed_files(&self, files: &Files) -> Result<Files> {
        crate::seed::validate_seed_files(files)
    }
    fn check_seed_target_size(&self, size: Option<u64>) -> Result<()> {
        crate::seed::check_seed_target_size(size)
    }

    // ---- the audit trail and the window ----
    fn audit(&self, msg: &str, level: AuditLevel) {
        audit_at(msg, level)
    }
    /// Open the window (`gui::run`).
    fn run_gui(&self) -> i32 {
        crate::gui::run()
    }
    /// Windows only, before the window opens: DPI awareness, then ask for Administrator (UAC) when the process is not.
    /// `Some(code)` ends the program (the elevated copy takes over); `err` prints a message on stderr.
    fn prepare_gui(&self, err: &dyn Fn(&str)) -> Option<i32> {
        if !IS_WINDOWS {
            return None;
        }
        crate::windows::enable_dpi_awareness();
        if !crate::windows::is_admin() {
            // Writing a drive needs Administrator: ask Windows for it now (the UAC prompt) instead of failing later.
            if crate::windows::relaunch_elevated() {
                return Some(super::EXIT_OK); // the elevated copy takes over
            }
            err("EPMA USB Creator needs Administrator rights to write a USB drive, and they were not granted. Drives \
                 can be listed but not written.");
        }
        None
    }
}

/// The real thing: every method keeps its default.
pub struct RealEngine;

impl Engine for RealEngine {}

/// `shutil.disk_usage(dir).free`.
#[cfg(unix)]
#[allow(clippy::unnecessary_cast)]
fn free_space_of(dir: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    // SAFETY: `statvfs` only fills the zeroed struct we hand it; `path` is a valid NUL-terminated string.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    Some((stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64))
}

#[cfg(windows)]
fn free_space_of(dir: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let mut free_to_caller: u64 = 0;
    let mut total: u64 = 0;
    let mut total_free: u64 = 0;
    // SAFETY: `wide` is NUL-terminated and the three out-pointers are valid for the call.
    let ok = unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut free_to_caller, &mut total, &mut total_free) };
    (ok != 0).then_some(free_to_caller)
}

#[cfg(not(any(unix, windows)))]
fn free_space_of(_dir: &Path) -> Option<u64> {
    None
}
