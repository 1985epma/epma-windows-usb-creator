#![allow(unused)] // STUB: delete this line when the module is implemented
//! The command line. OWNER: A7. Port of win11_usb_creator.py lines 12040-13039 (and `main`, lines 12985-13039).

pub const EXIT_OK: i32 = 0;
pub const EXIT_ERROR: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_VERIFY_FAILED: i32 = 3;
pub const EXIT_EJECT_FAILED: i32 = 4;
pub const EXIT_INTERRUPTED: i32 = 130;

/// `main(argv)`: no arguments opens the window (`gui::run`, which always exists and prints a hint when built without feature `gui`), anything else is the
/// command line. Returns the process exit code.
pub fn main(argv: &[String]) -> i32 {
    todo!()
}
