#![allow(unused)] // STUB: delete this line when the module is implemented
//! Internationalization (GUI texts only). OWNER: A1. Port of win11_usb_creator.py lines 284-653.
//! The table is `crate::i18n_table::PT_BR` (generated; do not retype it).

use std::fmt::Display;

/// `detect_language(env)`: `Some("pt")` selects Portuguese (EPMA_LANG only; the system locale is never consulted).
/// Returns `LANG_EN` or `LANG_PT`.
pub fn detect_language(epma_lang: Option<&str>) -> &'static str {
    todo!()
}
/// The language decided once at startup (from the real environment) unless `set_active_language` changed it.
pub fn active_language() -> &'static str {
    todo!()
}
/// For the window and for tests (the Python tests patch ACTIVE_LANGUAGE).
pub fn set_active_language(lang: &'static str) {
    todo!()
}
/// `_(text)`: the text in the active language; unknown texts (and English) come back unchanged.
pub fn tr(text: &str) -> String {
    todo!()
}
/// Translate, then substitute `{name}` placeholders: `tr_fmt("{size} used", &[("size", &x)])`
/// (the Python `_("{size} used").format(size=x)`).
pub fn tr_fmt(text: &str, args: &[(&str, &dyn Display)]) -> String {
    todo!()
}
/// Substitute `{name}` placeholders without translating (`"...".format(...)` on an English literal).
pub fn fmt_named(template: &str, args: &[(&str, &dyn Display)]) -> String {
    todo!()
}
