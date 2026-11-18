//! Port (A1 part) of tests/test_engine.py: the audit trail (AuditTests), the device-name validator
//! (DeviceNameTests) and the "human_size works without the window" check of ImportWithoutTkTests. The other classes of
//! that file belong to the copy/verify engine and the backends.
//!
//! The audit tests change the process environment, so they all hold `ENV_LOCK`; every one starts from a fresh sink
//! (`reset_audit_sink`, the Python `_audit_logger = None`) and leaves the log disabled again.

mod common_a1;

use common_a1::{Tmp, ENV_LOCK};
use epma_usb_creator::audit::{audit, audit_at, audit_log_path, audit_log_path_with, reset_audit_sink, AuditLevel};
use epma_usb_creator::constants::{ENV_AUDIT_LOG, ENV_DISABLE_AUDIT_LOG};
use epma_usb_creator::types::Error;
use epma_usb_creator::util::{expand_user, human_size};
use epma_usb_creator::validate::{validate_device_name_for, HostOs};
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::MutexGuard;

/// Runs a test body with a brand-new audit sink configured by `env` (`None` removes a variable); restores the
/// environment and disables the log again afterwards.
struct FreshLogger {
    _guard: MutexGuard<'static, ()>,
    saved: Vec<(String, Option<OsString>)>,
}

impl FreshLogger {
    fn new(env: &[(&str, Option<&std::ffi::OsStr>)]) -> FreshLogger {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        common_a1::init();
        let mut saved = Vec::new();
        for key in [ENV_DISABLE_AUDIT_LOG, ENV_AUDIT_LOG, "XDG_STATE_HOME"] {
            saved.push((key.to_string(), std::env::var_os(key)));
        }
        std::env::remove_var(ENV_DISABLE_AUDIT_LOG);
        for (key, value) in env {
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        reset_audit_sink();
        FreshLogger { _guard: guard, saved }
    }
}

impl Drop for FreshLogger {
    fn drop(&mut self) {
        reset_audit_sink();
        for (key, value) in &self.saved {
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        reset_audit_sink();
    }
}

#[test]
fn never_raises() {
    // The Python mocks get_audit_logger to raise; here the sink is pointed at places that cannot work.
    let t = Tmp::new();
    let blocker = t.write_file("blocker", b"a file, not a directory");
    let bad = blocker.join("audit.log");
    let _f = FreshLogger::new(&[(ENV_AUDIT_LOG, Some(bad.as_os_str()))]);
    audit("message");
    audit_at("message", AuditLevel::Error);
    audit_at("message", AuditLevel::Warning);
}

#[test]
fn disabled_by_environment() {
    let t = Tmp::new();
    let path = t.path("state/audit.log");
    let _f = FreshLogger::new(&[(ENV_AUDIT_LOG, Some(path.as_os_str())), (ENV_DISABLE_AUDIT_LOG, Some("1".as_ref()))]);
    audit("this goes nowhere");
    assert!(!path.exists(), "a disabled log must not even create its file");
    assert!(!path.parent().unwrap().exists());
}

#[test]
fn disabled_values() {
    let t = Tmp::new();
    for value in ["1", "true", "YES", " yes "] {
        let path = t.path(&format!("off-{}/audit.log", value.trim()));
        let _f =
            FreshLogger::new(&[(ENV_AUDIT_LOG, Some(path.as_os_str())), (ENV_DISABLE_AUDIT_LOG, Some(value.as_ref()))]);
        audit("nothing");
        assert!(!path.exists(), "{value:?}");
    }
    // any other value leaves it enabled
    let path = t.path("on/audit.log");
    let _f = FreshLogger::new(&[(ENV_AUDIT_LOG, Some(path.as_os_str())), (ENV_DISABLE_AUDIT_LOG, Some("0".as_ref()))]);
    audit("recorded");
    assert!(path.exists());
}

#[test]
fn writes_owner_only_log() {
    let t = Tmp::new();
    let log_path = t.path("state/audit.log");
    let _f = FreshLogger::new(&[(ENV_AUDIT_LOG, Some(log_path.as_os_str()))]);
    audit("hello from the tests");
    audit_at("a warning", AuditLevel::Warning);
    let text = std::fs::read_to_string(&log_path).unwrap();
    assert!(text.contains("hello from the tests"), "{text}");
    assert!(text.contains(" INFO hello from the tests\n") && text.contains(" WARNING a warning\n"), "{text}");
    // "2025-01-31 14:05:09,123 INFO ..."
    let first = text.lines().next().unwrap();
    let stamp: Vec<char> = first.chars().take(23).collect();
    assert_eq!(stamp[4], '-');
    assert_eq!(stamp[10], ' ');
    assert_eq!(stamp[13], ':');
    assert_eq!(stamp[19], ',');
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&log_path).unwrap().permissions().mode() & 0o777, 0o600);
        // the folder is created owner-only too
        assert_eq!(std::fs::metadata(log_path.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
    }
}

#[test]
fn unwritable_location_degrades_silently() {
    let t = Tmp::new();
    let blocker = t.write_file("blocker", b"a file, not a directory");
    let bad = blocker.join("audit.log");
    let _f = FreshLogger::new(&[(ENV_AUDIT_LOG, Some(bad.as_os_str()))]);
    audit("still fine"); // must not panic or fail
}

#[test]
fn log_path_resolution() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    common_a1::init();
    let saved: Vec<(&str, Option<OsString>)> =
        [ENV_AUDIT_LOG, "XDG_STATE_HOME"].iter().map(|k| (*k, std::env::var_os(k))).collect();
    std::env::set_var(ENV_AUDIT_LOG, "~/custom.log");
    let overridden = audit_log_path();
    std::env::remove_var(ENV_AUDIT_LOG);
    let t = Tmp::new();
    std::env::set_var("XDG_STATE_HOME", &t.root);
    let xdg = audit_log_path();
    for (key, value) in saved {
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }
    assert_eq!(overridden, expand_user("~/custom.log"));
    if !cfg!(windows) {
        assert_eq!(xdg, t.root.join("epma-win11-usb-creator").join("audit.log"));
    }
}

#[test]
fn the_audit_log_goes_to_local_app_data_on_windows() {
    // PlatformPiecesTests (test_windows_backend.py): the path logic for Windows, tested here on any OS.
    let env = |k: &str| match k {
        "LOCALAPPDATA" => Some("C:\\Users\\a\\AppData\\Local".to_string()),
        _ => None,
    };
    let path = audit_log_path_with(&env, true);
    let text = path.to_string_lossy().into_owned();
    assert!(text.starts_with("C:\\Users\\a\\AppData\\Local"), "{text}");
    assert!(text.ends_with("audit.log"), "{text}");
    assert!(text.contains("epma-win11-usb-creator"), "{text}");
    // without LOCALAPPDATA: under the profile folder
    let none = |_: &str| None::<String>;
    let fallback: PathBuf = audit_log_path_with(&none, true);
    assert!(fallback.to_string_lossy().ends_with("audit.log"));
    assert!(fallback.to_string_lossy().contains("AppData"));
}

// ---- DeviceNameTests ----
#[test]
fn trailing_newline_is_rejected() {
    common_a1::init();
    // "$" matches just before a trailing newline in Python, so the code uses fullmatch(); the Rust patterns are
    // anchored at the real end, and the result is the same.
    for (dev, host) in [("disk4\n", HostOs::Mac), ("sdb\n", HostOs::Linux)] {
        assert!(matches!(validate_device_name_for(dev, host), Err(Error::Value(_))), "{dev:?}");
    }
}

#[test]
fn valid_names_are_accepted() {
    common_a1::init();
    assert_eq!(validate_device_name_for("disk4", HostOs::Mac).unwrap(), "disk4");
    assert_eq!(validate_device_name_for("sdb", HostOs::Linux).unwrap(), "sdb");
}

// ---- ImportWithoutTkTests.test_module_imports_and_gui_refuses_politely (the human_size line) ----
#[test]
fn human_size_works_without_a_window() {
    assert_eq!(human_size(1024), "1.0 KB");
}
