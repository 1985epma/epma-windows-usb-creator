#![allow(unused)] // STUB: delete this line when the module is implemented
//! Linux backend. OWNER: A3. Port of win11_usb_creator.py lines 2684-3030 (lsblk listing, package manager,
//! LINUX_RAW_SCRIPT, linux_write_raw, linux_build_usb) and 8662-8702 + 8731-8791 (LINUX_SEED_* scripts,
//! linux_build_seed_usb). Compiles on every OS; it only *runs* commands on Linux.

use crate::types::{Ctx, Disk, Files, Log, Privilege, Result};
use std::path::Path;

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
pub fn write_raw(iso_path: &Path, dev: &str, ctx: &Ctx, priv_: &dyn Privilege, eject: bool) -> Result<bool> {
    todo!()
}
pub fn build_seed_usb(
    label: &str,
    files: &Files,
    stage_dir: &Path,
    dev: &str,
    ctx: &Ctx,
    priv_: &dyn Privilege,
    eject: bool,
) -> Result<bool> {
    todo!()
}
/// `linux_detect_pkg_manager()`: apt-get, dnf, yum, pacman, zypper or apk (None when none is found).
pub fn detect_pkg_manager() -> Option<String> {
    todo!()
}
/// The install command (without sudo) for the missing tools; `Error::Value` for an unknown/absent manager.
pub fn build_install_command(mgr: Option<&str>, missing_tools: &[String]) -> Result<String> {
    todo!()
}
