#![allow(unused)] // STUB: delete this line when the module is implemented
//! The Windows 11 hardening content: harden.ps1 (apply / audit / undo), SetupComplete.cmd, the settings tables and the
//! descriptions shown to the user. OWNER: A6. Port of win11_usb_creator.py lines 5950-7940. Output must be
//! byte-identical to the Python (goldens in tests/golden/windows*/).

use crate::types::{Files, Hardening, Result};

pub const WINDOWS_HARDENING_LOG: &str = "%windir%\\Temp\\epma-hardening.log";
/// `WINDOWS_HARDENING_NOT_CHANGED`: (id, text, why) rows.
pub const WINDOWS_HARDENING_NOT_CHANGED: &[(&str, &str, &str)] = &[];
/// The exact bytes of harden.ps1 (UTF-8 BOM, CRLF, pure ASCII). Empty for `Hardening::None`.
pub fn windows_hardening_ps1(profile: Hardening) -> Result<Vec<u8>> {
    todo!()
}
/// The two files of the Windows 11 install media: SetupComplete.cmd and harden.ps1 under
/// `sources/$OEM$/$$/Setup/Scripts`. Empty for `Hardening::None`.
pub fn hardening_files_windows(profile: Hardening) -> Result<Files> {
    todo!()
}
/// `describe_hardening_windows(profile)`: one line per setting (with its risk note) for "What does it change?".
pub fn describe_hardening_windows(profile: Hardening) -> Vec<String> {
    todo!()
}
/// `describe_hardening_windows_applied(profile)`.
pub fn describe_hardening_windows_applied(profile: Hardening) -> Vec<String> {
    todo!()
}
