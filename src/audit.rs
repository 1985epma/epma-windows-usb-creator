#![allow(unused)] // STUB: delete this line when the module is implemented
//! The audit log (rotating, owner-only file). OWNER: A1. Port of win11_usb_creator.py lines 715-781.

use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditLevel {
    Info,
    Warning,
    Error,
}

/// `audit_log_path()`: where the audit log lives (ENV_AUDIT_LOG overrides it).
pub fn audit_log_path() -> PathBuf {
    todo!()
}
/// `audit(msg)` at INFO level. Never fails (a log that cannot be written is ignored).
pub fn audit(msg: &str) {
    todo!()
}
/// `audit(msg, level)`.
pub fn audit_at(msg: &str, level: AuditLevel) {
    todo!()
}
