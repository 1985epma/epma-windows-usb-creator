#![allow(unused)] // STUB: delete this line when the module is implemented
//! macOS backend. OWNER: A3. Port of win11_usb_creator.py lines 2302-2683 (diskutil/hdiutil/ioreg listing, build,
//! eject, raw write, MACOS_RAW_SCRIPT, write_raw_image) and 8703-8730 (macos_build_seed_usb). Compiles on every OS
//! (the listing parsers are pure and unit-testable); it only *runs* commands on macOS.

use crate::types::{Ctx, Disk, Files, Log, Privilege, Result};
use std::path::Path;

pub fn get_external_disks() -> Result<Vec<Disk>> {
    todo!()
}
/// Windows-mode build: erase, GPT + FAT32 (label WIN11USB), copy, verify, eject. `Ok(ejected)`.
pub fn build_usb(iso_path: &Path, dev: &str, ctx: &Ctx, eject: bool, hardening_files: Option<&Files>) -> Result<bool> {
    todo!()
}
/// Raw (byte-for-byte) write of a Linux / ChromeOS image, verified by read-back. `Ok(ejected)`.
pub fn write_raw(iso_path: &Path, dev: &str, ctx: &Ctx, priv_: &dyn Privilege, eject: bool) -> Result<bool> {
    todo!()
}
/// The hardening seed drive (GPT + FAT32 with `label`, `files` copied from `stage_dir`, verified). `Ok(ejected)`.
pub fn build_seed_usb(label: &str, files: &Files, stage_dir: &Path, dev: &str, ctx: &Ctx, eject: bool) -> Result<bool> {
    todo!()
}
pub fn eject(dev: &str, log: Log) -> bool {
    todo!()
}
