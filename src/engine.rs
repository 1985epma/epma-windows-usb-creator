#![allow(unused)] // STUB: delete this line when the module is implemented
//! The engine: the safety checks and the dispatcher between the platform backends. OWNER: A2.
//! Port of win11_usb_creator.py lines 2289-2299 (pin_target_identity), 3768-3947 (hardening files on the image:
//! validate_hardening ... refuse_hardening_clash, LINUX_ISO_PEEK_* scripts, get_external_disks), 3948-4127
//! (reverify_target_disk, hash_iso_for_audit, missing_dependencies_hint, validate_image_for_mode, build_usb,
//! needs_admin, image_exceeds_drive) and 5919-5948 (chromeos_drive_too_small, windows_missing_tools,
//! get_missing_dependencies).

use crate::types::{BuildOptions, Ctx, Disk, Files, Hardening, Identity, Log, Mode, Privilege, Result};
use std::path::{Path, PathBuf};

/// Remember the identity of the drive the user confirmed; `reverify_target_disk` enforces it (None clears the pin).
pub fn pin_target_identity(dev: &str, identity: Option<Identity>) {
    todo!()
}
/// Eligible external (USB) disks on this OS (dispatches to macos / windows / linux `get_external_disks`).
pub fn get_external_disks() -> Result<Vec<Disk>> {
    todo!()
}
/// Re-check, right before erasing, that `dev` is still the disk that was listed (size and pinned identity).
pub fn reverify_target_disk(
    dev: &str,
    expected_size: Option<u64>,
    log: Log,
    expected_identity: Option<&Identity>,
) -> Result<()> {
    todo!()
}
/// Check, before anything is touched, that the image suits `mode`, fits the drive and the tools exist.
/// Returns the resolved image path. `Error::Value` with the Python message otherwise.
pub fn validate_image_for_mode(iso_path: impl AsRef<Path>, mode: Mode, expected_size: Option<u64>) -> Result<PathBuf> {
    todo!()
}
/// Create the bootable drive (see the Python docstring). `Ok(ejected)`. Error::Canceled carries drive_touched/written.
pub fn build_usb(
    iso_path: impl AsRef<Path>,
    dev: &str,
    ctx: &Ctx,
    priv_: &dyn Privilege,
    opts: &BuildOptions,
) -> Result<bool> {
    todo!()
}
/// Whether writing in `mode` needs administrator rights.
pub fn needs_admin(mode: Mode) -> bool {
    todo!()
}
/// True when an image of `image_size` bytes cannot fit a drive of `drive_size` bytes (unknown sizes never refuse).
pub fn image_exceeds_drive(image_size: u64, drive_size: u64) -> bool {
    todo!()
}
/// True when ChromeOS Flex is going to a drive below CHROMEOS_MIN_USB_BYTES (a warning, not a refusal).
pub fn chromeos_drive_too_small(mode: Mode, drive_size: u64) -> bool {
    todo!()
}
/// Names of the tools this OS lacks for `mode` (Mode::Seed included).
pub fn get_missing_dependencies(mode: Mode) -> Vec<String> {
    todo!()
}
/// One sentence telling the user how to get the missing tools on this system.
pub fn missing_dependencies_hint(missing: &[String]) -> String {
    todo!()
}
/// `validate_hardening(mode, hardening)`: Error::Value unless hardening is None or mode is Windows.
pub fn validate_hardening(mode: Mode, hardening: Hardening) -> Result<()> {
    todo!()
}
/// `collect_hardening_files(hardening)`: the extra files for the Windows image (None when there are none).
pub fn collect_hardening_files(hardening: Hardening) -> Result<Option<Files>> {
    todo!()
}
