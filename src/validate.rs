#![allow(unused)] // STUB: delete this line when the module is implemented
//! Validators. OWNER: A1. Port of win11_usb_creator.py lines 783-855 (device/ISO validation), 1059-1107
//! (SHA-256 parsing, validate_disk_image) and 1436-1465 (validate_download_url).

use crate::types::Result;
use std::path::{Path, PathBuf};

/// Returns `dev` if it is a plausible disk identifier for this OS (`ValueError` otherwise; audits the rejection).
pub fn validate_device_name(dev: &str) -> Result<String> {
    todo!()
}
/// How a disk identifier is shown: `/dev/disk4`, `/dev/sdb` or `\\.\PhysicalDrive3`.
pub fn dev_path(dev: &str) -> String {
    todo!()
}
pub fn has_mbr_signature(head: &[u8]) -> bool {
    todo!()
}
/// Absolute, symlink-free form of a path (`~` expanded).
pub fn resolve_path(path: impl AsRef<Path>) -> PathBuf {
    todo!()
}
/// An absolute, existing, readable, regular-file image path that is at least MIN_IMAGE_BYTES, or `ValueError`.
pub fn validate_iso_path(path: impl AsRef<Path>) -> Result<PathBuf> {
    todo!()
}
pub fn validate_hybrid_iso(path: impl AsRef<Path>) -> Result<()> {
    todo!()
}
/// A raw disk image that can boot from USB as is (ChromeOS), or `ValueError`.
pub fn validate_disk_image(path: impl AsRef<Path>) -> Result<()> {
    todo!()
}
/// `(normalised url, host, untrusted_host_warning)`; `ValueError` explains a rejection.
pub fn validate_download_url(raw_url: &str) -> Result<(String, String, bool)> {
    todo!()
}
pub fn is_sha256_hex(text: &str) -> bool {
    todo!()
}
/// Lowercase hex SHA-256 found in what the user pasted (a bare hash or a `SHA256SUMS` line), or None if empty.
pub fn parse_expected_sha256(text: &str, filename: Option<&str>) -> Result<Option<String>> {
    todo!()
}
