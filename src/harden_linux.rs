//! The Linux hardening script (harden-linux.sh). Port of win11_usb_creator.py lines 4124-4128 and 5907-5917.
//!
//! The text is `assets/harden-linux.sh` (extracted verbatim from the Python by tools/py_dump.py and embedded with
//! `include_str!`): the script a hardened Linux setup runs on the NEW system (from the seed drive, or inside the
//! installer's chroot). Debian/Ubuntu (apt) and Fedora/RHEL (dnf). It is only ever written to a drive as a file; this
//! program never runs it. Settings are inspired by common baselines. The behaviour of the script itself (shellcheck,
//! fake-root runs, dry-run, undo, idempotence) is tested in `tests/test_hardening_linux_a5.rs`.
//! Golden: tests/golden/linux/harden-linux.sh.

use crate::types::{Error, Hardening, Result};

/// `_HARDEN_LINUX_SH`: the script, byte for byte (pure ASCII, LF line endings).
const HARDEN_LINUX_SH: &str = include_str!("../assets/harden-linux.sh");

/// The text of harden-linux.sh for `profile` (pure ASCII). `Hardening::None` has nothing to harden and is
/// `Error::Value`, as is any profile other than `Hardening::Baseline`.
pub fn linux_hardening_script(profile: Hardening) -> Result<&'static str> {
    match profile {
        Hardening::None => Err(Error::value("nothing to harden: the profile is 'none'")),
        Hardening::Baseline => Ok(HARDEN_LINUX_SH),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_is_the_golden_script() {
        let text = linux_hardening_script(Hardening::Baseline).unwrap();
        assert_eq!(text.as_bytes(), include_bytes!("../tests/golden/linux/harden-linux.sh"));
    }

    #[test]
    fn script_is_pure_ascii_with_a_shebang_and_lf_endings() {
        let text = linux_hardening_script(Hardening::Baseline).unwrap();
        assert!(text.is_ascii());
        assert!(text.starts_with("#!/usr/bin/env bash\n"));
        assert!(!text.contains('\r'));
        assert!(text.ends_with("main \"$@\"\n"));
    }

    #[test]
    fn none_profile_has_nothing_to_harden() {
        let err = linux_hardening_script(Hardening::None).unwrap_err();
        assert!(matches!(err, Error::Value(_)));
        assert_eq!(err.to_string(), "nothing to harden: the profile is 'none'");
    }
}
