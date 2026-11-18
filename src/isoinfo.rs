#![allow(unused)] // STUB: delete this line when the module is implemented
//! ISO / disk image inspection and the ChromeOS ZIP extraction. OWNER: A1.
//! Port of win11_usb_creator.py lines 856-1058 (+ has_mbr_signature users).

use crate::types::{CancelToken, IsoKind, Progress2, Result};
use std::path::{Path, PathBuf};

/// Classify an image by its content: Windows, Linux (hybrid), ChromeOS or Unknown. Never fails; reads a few MB at most.
pub fn detect_iso_kind(path: impl AsRef<Path>) -> IsoKind {
    todo!()
}
/// Extract the single .bin disk image from Google's ZIP into `dest_dir`; returns its path (see the Python docstring
/// for the safety rules: base name only, never overwrite, size and free-space checks, CRC verified, temp + rename).
pub fn extract_disk_image(
    zip_path: impl AsRef<Path>,
    dest_dir: impl AsRef<Path>,
    progress: Option<Progress2>,
    cancel: Option<&CancelToken>,
) -> Result<PathBuf> {
    todo!()
}
