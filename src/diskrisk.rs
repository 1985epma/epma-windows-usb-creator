#![allow(unused)] // STUB: delete this line when the module is implemented
//! Disk description and risk assessment (pure functions). OWNER: A2. Port of win11_usb_creator.py lines 2138-2287.

use crate::types::{Disk, Identity, Volume};

pub const LARGE_DISK_BYTES: u64 = 256 * 1024 * 1024 * 1024;
pub const SUBSTANTIAL_USED_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const MANY_VOLUMES: usize = 4;
pub const MAX_VOLUMES_SHOWN: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RiskLevel {
    High,
    Normal,
}

/// `make_identity(**parts)`: sorted `(key, value)` pairs, empty / None values dropped.
pub fn make_identity(parts: &[(&str, Option<String>)]) -> Identity {
    todo!()
}
/// How `actual` differs from `expected` ("serial changed"), or None when it is the same drive.
pub fn identity_mismatch(expected: &Identity, actual: &Identity) -> Option<String> {
    todo!()
}
pub fn format_volume_line(vol: &Volume, translate: bool) -> String {
    todo!()
}
/// The text shown in the drive list: `/dev/disk4 — SanDisk Ultra — 58.6 GB — 2 volumes ('A', 'B')`.
/// `volumes`: None = could not be inspected.
pub fn build_disk_label(dev_path: &str, model: Option<&str>, size: u64, volumes: Option<&[Volume]>) -> String {
    todo!()
}
/// `_disk_entry`: the record the drive list holds for one disk (label built here from `validate::dev_path`).
pub fn disk_entry(
    dev_id: &str,
    size: u64,
    model: Option<&str>,
    volumes: Option<Vec<Volume>>,
    identity: Identity,
) -> Disk {
    todo!()
}
/// `(level, reasons)`: High needs the identifier typed before the drive can be erased.
pub fn assess_disk_risk(disk: &Disk, translate: bool) -> (RiskLevel, Vec<String>) {
    todo!()
}
/// Multi-line summary (model, size, every volume) for the final confirmation.
pub fn describe_disk_for_confirmation(disk: &Disk, translate: bool) -> String {
    todo!()
}
