#![allow(unused)] // STUB: delete this line when the module is implemented
//! Contents of the hardening seed drives: cloud-init (Ubuntu), kickstart (Fedora/RHEL), preseed (Debian) and the
//! Windows 11 seed (harden.cmd / audit.cmd / undo.cmd / harden.ps1 / README.txt). OWNER: A5.
//! Port of win11_usb_creator.py lines 7940-8461. Output must be byte-identical to the Python (tests/golden/seed-*).

use crate::types::{Files, Hardening, Result, SeedTarget};

pub const SEED_HARDEN_FILE: &str = "harden-linux.sh";
pub const SEED_WINDOWS_LABEL: &str = "EPMA-SEED";
/// FAT volume label of each seed drive (Ubuntu CIDATA, Fedora OEMDRV, Debian EPMA-SEED, Windows EPMA-SEED).
pub fn seed_label(target: SeedTarget) -> &'static str {
    todo!()
}
/// `(FAT32 volume label, {relative path: bytes})` of the seed drive for `target`.
pub fn hardening_files_seed(target: SeedTarget, profile: Hardening) -> Result<(String, Files)> {
    todo!()
}
