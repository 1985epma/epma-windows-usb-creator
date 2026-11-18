//! The window (egui / eframe). OWNER: A8. Port of win11_usb_creator.py lines 1747-1885 (dialogs), 9148-12040 (macOS app
//! name, widgets, help window, the `App` class).
//!
//! Layers:
//! * always compiled and unit-tested without a display: `model` (the window's state and logic: `AppState`),
//!   `widgets` (the state of the widgets), `dialogs`, `flows` (the worker threads), `texts`, `backend` (the one trait
//!   through which the window reaches the rest of the program), `tx` (translation helpers);
//! * behind feature `gui`: `view` (the egui drawing and `run`).

pub mod backend;
pub mod dialogs;
pub mod flows;
pub mod model;
pub mod shared;
pub mod texts;
pub mod tx;
pub mod widgets;

#[cfg(feature = "gui")]
mod view;

#[cfg(test)]
mod testkit;
#[cfg(test)]
mod tests;

pub use dialogs::{normalize_typed_identifier, Dialogs, HubDialogs};
pub use model::{set_macos_app_name, AppState};

/// Open the window and block until it closes. Returns the process exit code.
#[cfg(feature = "gui")]
pub fn run() -> i32 {
    view::run()
}

/// Built without the window: print a hint and return the error exit code.
#[cfg(not(feature = "gui"))]
pub fn run() -> i32 {
    eprintln!(
        "This build of EPMA USB CREATOR has no window (it was compiled without the `gui` feature).\n\
         Use the command line instead: run it with --help to see the commands."
    );
    crate::cli::EXIT_ERROR
}
