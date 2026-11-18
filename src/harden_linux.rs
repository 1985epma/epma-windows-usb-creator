#![allow(unused)] // STUB: delete this line when the module is implemented
//! The Linux hardening script (harden-linux.sh). OWNER: A5. Port of win11_usb_creator.py lines 4124-5917.
//! The text is `assets/harden-linux.sh` (extracted verbatim from the Python by tools/py_dump.py); embed it with
//! `include_str!`. Golden: tests/golden/linux/harden-linux.sh.

use crate::types::{Hardening, Result};

/// The text of harden-linux.sh for `profile` (pure ASCII). `Hardening::None` and unknown profiles are `Error::Value`.
pub fn linux_hardening_script(profile: Hardening) -> Result<&'static str> {
    todo!()
}
