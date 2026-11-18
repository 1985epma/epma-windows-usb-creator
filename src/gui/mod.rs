#![allow(unused)] // STUB: delete this line when the module is implemented
//! The window (egui / eframe). OWNER: A8. Port of win11_usb_creator.py lines 1747-1885 (dialogs), 9148-12040
//! (macOS app name, widgets, help window, the `App` class). Split into submodules as needed (files under src/gui/).

/// Open the window and block until it closes. Returns the process exit code. Must exist with and without feature
/// `gui` (without it: print a hint that this build has no window, return EXIT_ERROR). Put everything that needs
/// egui/eframe in submodules behind `#[cfg(feature = "gui")]`; keep the window's state and logic (testable without a
/// display) always compiled.
pub fn run() -> i32 {
    todo!()
}
