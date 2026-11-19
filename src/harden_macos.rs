//! The macOS hardening script (harden-macos.sh) and the lists the README and the help quote. New in the Rust build:
//! the Python program has no macOS seed.
//!
//! The text is `assets/harden-macos.sh`, embedded with `include_str!`: the script a hardened Mac runs AFTER macOS is
//! installed (from the seed drive, by one of its `.command` launchers). It is only ever written to a drive as a file;
//! this program never runs it. The settings are inspired by common baselines and kept conservative on purpose. The
//! behaviour of the script itself (shellcheck, fake-root runs with stand-in commands, dry-run, undo, idempotence) is
//! tested in `tests/test_hardening_macos.rs`.

use crate::types::{Error, Hardening, Result};

/// `harden-macos.sh`, byte for byte (pure ASCII, LF line endings).
const HARDEN_MACOS_SH: &str = include_str!("../assets/harden-macos.sh");

/// The text of harden-macos.sh for `profile` (pure ASCII). `Hardening::None` has nothing to harden and is
/// `Error::Value`, as for the Linux script.
pub fn macos_hardening_script(profile: Hardening) -> Result<&'static str> {
    match profile {
        Hardening::None => Err(Error::value("nothing to harden: the profile is 'none'")),
        Hardening::Baseline => Ok(HARDEN_MACOS_SH),
    }
}

/// What the script changes: (id, text, risk). The ids are the ones of `MACOS_HARDENING_NOT_CHANGED`'s style.
pub const MACOS_HARDENING_SETTINGS: &[(&str, &str, &str)] = &[
    (
        "firewall",
        "Turn the Application Firewall on",
        "Programs that are not signed ask before they accept incoming connections; a few sharing or server tools may \
         need to be allowed again in System Settings > Network > Firewall.",
    ),
    (
        "stealth",
        "Turn stealth mode on",
        "The Mac no longer answers ping or connection attempts on closed ports, so some network scanners and \
         discovery tools will not see it.",
    ),
    (
        "gatekeeper",
        "Keep Gatekeeper on",
        "It only acts when Gatekeeper was switched off; apps from unidentified developers are blocked again (open \
         them with right-click > Open, or allow them in Privacy & Security).",
    ),
    (
        "updates",
        "Check for updates, download them and install security responses and system data files automatically",
        "Major macOS upgrades are NOT installed automatically; a background download uses bandwidth.",
    ),
    ("guest", "Turn the guest account off", "Nobody can use the Mac without an account."),
    (
        "autologin",
        "Turn automatic login off",
        "It only acts when automatic login was on; the account password is then asked at every start.",
    ),
];

/// Deliberately NOT done, with the reason: (id, text, why). Quoted by the README of the seed drive and the help.
pub const MACOS_HARDENING_NOT_CHANGED: &[(&str, &str, &str)] = &[
    (
        "filevault",
        "FileVault is not turned on automatically (the script only reports it)",
        "It needs a choice of where the recovery key goes and the owner's consent; a wrong default can lock someone \
         out of their own data.",
    ),
    (
        "sharing",
        "Sharing (Remote Login, Screen Sharing, File Sharing) is only reported, never changed",
        "Turning a service off can cut off remote help, backups or other computers that rely on it.",
    ),
    (
        "sip",
        "System Integrity Protection is never touched",
        "It can only be changed from macOS Recovery, and turning it off weakens the whole system.",
    ),
    (
        "major_updates",
        "Major macOS upgrades are not installed automatically",
        "They change a lot at once, and not every app or device works with a new release on its first day.",
    ),
    (
        "accounts",
        "Accounts, passwords, disks, language and Apple Account",
        "Setup Assistant and System Settings stay in your hands; the script never touches them.",
    ),
];

/// `describe_hardening_macos_applied(profile)`: one line per change, `"text -- risk: risk"` (empty for `None`).
pub fn describe_hardening_macos_applied(profile: Hardening) -> Vec<String> {
    if profile == Hardening::None {
        return Vec::new();
    }
    MACOS_HARDENING_SETTINGS.iter().map(|(_id, text, risk)| format!("{text} -- risk: {risk}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_is_the_script_on_disk() {
        let text = macos_hardening_script(Hardening::Baseline).unwrap();
        assert_eq!(text.as_bytes(), std::fs::read("assets/harden-macos.sh").unwrap());
    }

    #[test]
    fn script_is_pure_ascii_with_a_shebang_and_lf_endings() {
        let text = macos_hardening_script(Hardening::Baseline).unwrap();
        assert!(text.is_ascii());
        assert!(text.starts_with("#!/bin/bash\n"));
        assert!(!text.contains('\r'));
        assert!(text.ends_with("main \"$@\"\n"));
    }

    #[test]
    fn none_profile_has_nothing_to_harden() {
        let err = macos_hardening_script(Hardening::None).unwrap_err();
        assert!(matches!(err, Error::Value(_)));
        assert_eq!(err.to_string(), "nothing to harden: the profile is 'none'");
        assert!(describe_hardening_macos_applied(Hardening::None).is_empty());
    }

    #[test]
    fn every_change_has_a_risk_and_every_line_says_so() {
        let lines = describe_hardening_macos_applied(Hardening::Baseline);
        assert_eq!(lines.len(), MACOS_HARDENING_SETTINGS.len());
        for (line, (_id, text, risk)) in lines.iter().zip(MACOS_HARDENING_SETTINGS) {
            assert!(!risk.is_empty());
            assert_eq!(line, &format!("{text} -- risk: {risk}"));
        }
    }

    #[test]
    fn the_ids_are_unique() {
        let mut ids: Vec<&str> = MACOS_HARDENING_SETTINGS.iter().map(|s| s.0).collect();
        ids.extend(MACOS_HARDENING_NOT_CHANGED.iter().map(|s| s.0));
        let all = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), all);
    }
}
