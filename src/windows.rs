#![allow(unused)] // STUB: delete this line when the module is implemented
//! Windows 11 backend. OWNER: A4. Port of win11_usb_creator.py lines 3030-3766 (PowerShell Storage cmdlets, DISM, raw
//! PhysicalDrive I/O) and 3739-3766 (windows_build_seed_usb). Everything platform-independent (script texts, the disk
//! list parser, argument building) compiles and is tested on every OS; only the Win32 calls are `#[cfg(windows)]`.

use crate::types::{Ctx, Disk, Files, Log, Privilege, Result};
use std::path::{Path, PathBuf};

pub fn get_external_disks() -> Result<Vec<Disk>> {
    todo!()
}
pub fn build_usb(
    iso_path: &Path,
    dev: &str,
    ctx: &Ctx,
    priv_: &dyn Privilege,
    eject: bool,
    hardening_files: Option<&Files>,
) -> Result<bool> {
    todo!()
}
pub fn write_raw(iso_path: &Path, dev: &str, ctx: &Ctx, eject: bool) -> Result<bool> {
    todo!()
}
pub fn build_seed_usb(label: &str, files: &Files, stage_dir: &Path, dev: &str, ctx: &Ctx, eject: bool) -> Result<bool> {
    todo!()
}
/// `windows_mounted_iso(iso_path, log)` as a closure API: mount the ISO read-only, call `f` with its root (for example
/// `F:\\`), dismount it afterwards (only if we mounted it).
pub fn with_mounted_iso<T>(iso_path: &Path, log: Log, f: impl FnOnce(&Path) -> Result<T>) -> Result<T> {
    todo!()
}
/// `windows_is_admin()`.
pub fn is_admin() -> bool {
    todo!()
}
/// `windows_relaunch_elevated()`: relaunch this program elevated (UAC); true if the relaunch was started.
pub fn relaunch_elevated() -> bool {
    todo!()
}
/// `windows_enable_dpi_awareness()`.
pub fn enable_dpi_awareness() {
    todo!()
}
/// `windows_system32(name)`, `windows_powershell_exe()`, `windows_dism_exe()`.
pub fn system32(name: &str) -> PathBuf {
    todo!()
}
pub fn powershell_exe() -> PathBuf {
    todo!()
}
pub fn dism_exe() -> PathBuf {
    todo!()
}
