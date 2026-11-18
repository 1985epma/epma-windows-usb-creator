#![allow(unused)] // STUB: delete this line when the module is implemented
//! The hardening seed drive engine: validation, staging, copy, verify and the dispatcher. OWNER: A4.
//! Port of win11_usb_creator.py lines 8462-8661 (SEED_* limits, validate_seed_label/files, stage/copy/verify)
//! and 8792-8868 (check_seed_target_size, build_seed_usb).

use crate::types::{Ctx, Files, Hardening, Privilege, Result, SeedTarget};
use std::path::{Path, PathBuf};

pub const SEED_MIN_DRIVE_BYTES: u64 = 64 * 1024 * 1024;
pub fn validate_seed_label(label: &str) -> Result<String> {
    todo!()
}
/// Validates names, sizes and counts; returns the (normalised) files. `Error::Value` with the Python message.
pub fn validate_seed_files(files: &Files) -> Result<Files> {
    todo!()
}
/// Write the files into a fresh private staging directory (still before the drive is touched).
pub fn stage_seed_files(files: &Files) -> Result<PathBuf> {
    todo!()
}
pub fn copy_seed_files(stage_dir: &Path, dst_root: &Path, files: &Files, ctx: &Ctx) -> Result<()> {
    todo!()
}
/// Read every file back from `dst_root` and compare it byte for byte (`Error::Runtime("Verification FAILED ...")`).
pub fn verify_seed_files(files: &Files, dst_root: &Path, ctx: &Ctx) -> Result<()> {
    todo!()
}
pub fn check_seed_target_size(size: Option<u64>) -> Result<()> {
    todo!()
}
/// Create a seed drive for `target` (GPT + FAT32 with the label and files of `seed_files::hardening_files_seed`).
pub fn build_seed_usb(
    target: SeedTarget,
    dev: &str,
    ctx: &Ctx,
    priv_: &dyn Privilege,
    expected_size: Option<u64>,
    eject: bool,
    profile: Hardening,
) -> Result<bool> {
    todo!()
}
