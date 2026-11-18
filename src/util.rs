#![allow(unused)] // STUB: delete this line when the module is implemented
//! Small helpers. OWNER: A1. Port of win11_usb_creator.py lines 654-712 (human_size, silent_remove/rmdir,
//! eta_text, eta_remaining, rate_tail).

use std::path::Path;

/// "58.6 GB" style size (one decimal; B, KB, MB, GB, TB, PB with 1024 steps).
pub fn human_size(n: u64) -> String {
    todo!()
}
/// `_eta_text`: "about 2 min left" style text; `translate` goes through `i18n::tr`.
pub fn eta_text(remaining_seconds: f64, speed: f64, translate: bool) -> String {
    todo!()
}
/// `_eta_remaining`.
pub fn eta_remaining(done: u64, total: u64, speed: f64, translate: bool) -> String {
    todo!()
}
/// `_rate_tail`.
pub fn rate_tail(done: u64, total: u64, speed: f64) -> String {
    todo!()
}
/// Remove a file, ignoring any error (`_silent_remove`).
pub fn silent_remove(path: impl AsRef<Path>) {
    todo!()
}
/// Remove an empty directory, ignoring any error (`_silent_rmdir`).
pub fn silent_rmdir(path: impl AsRef<Path>) {
    todo!()
}
