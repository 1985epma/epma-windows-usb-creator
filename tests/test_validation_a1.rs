//! Port (A1 part) of tests/test_validation.py: human_size, the device-name and ISO-path validators, and the download
//! URL rules. (LinuxPartitionPathTests and LinuxInstallCommandTests belong to the Linux backend.)

mod common_a1;

use common_a1::{Tmp, ENV_LOCK, MIB};
use epma_usb_creator::constants::{ENV_ALLOW_ANY_HOST, ENV_TRUSTED_HOSTS};
use epma_usb_creator::types::Error;
use epma_usb_creator::util::{human_size, human_size_f64};
use epma_usb_creator::validate::{
    validate_device_name, validate_device_name_for, validate_download_url, validate_download_url_with,
    validate_hybrid_iso, validate_iso_path, HostOs,
};
use std::path::PathBuf;

fn err_text<T: std::fmt::Debug>(result: epma_usb_creator::types::Result<T>) -> String {
    match result {
        Err(Error::Value(m)) => m,
        other => panic!("expected a ValueError, got {other:?}"),
    }
}

// ---- HumanSizeTests ----
#[test]
fn human_size_units() {
    assert_eq!(human_size(0), "0.0 B");
    assert_eq!(human_size(1023), "1023.0 B");
    assert_eq!(human_size(1024), "1.0 KB");
    assert_eq!(human_size(1536), "1.5 KB");
    assert_eq!(human_size(5 * 1024 * 1024), "5.0 MB");
    assert_eq!(human_size(16 * 1024 * 1024 * 1024), "16.0 GB");
    assert_eq!(human_size(2 * 1024u64.pow(4)), "2.0 TB");
}

#[test]
fn human_size_beyond_terabytes() {
    assert_eq!(human_size(3 * 1024u64.pow(5)), "3.0 PB");
}

#[test]
fn human_size_accepts_floats() {
    assert_eq!(human_size_f64(1536.0), "1.5 KB");
}

// ---- ValidateDeviceNameTests ----
fn check_devices(host: HostOs, good: &[&str], bad: &[&str]) {
    init();
    for name in good {
        assert_eq!(validate_device_name_for(name, host).unwrap(), *name, "{name:?}");
    }
    for name in bad {
        assert!(matches!(validate_device_name_for(name, host), Err(Error::Value(_))), "{name:?}");
    }
}

fn init() {
    common_a1::init();
}

#[test]
fn macos_pattern() {
    check_devices(
        HostOs::Mac,
        &["disk0", "disk4", "disk12"],
        &["", "disk", "diskX", "disk4s1", "rdisk4", "/dev/disk4", "sdb", "disk4;rm", "disk4 ", " disk4", "../disk4"],
    );
}

#[test]
fn linux_pattern() {
    let long_ok = "x".repeat(32);
    let long_bad = "x".repeat(33);
    check_devices(
        HostOs::Linux,
        &["sdb", "nvme0n1", "mmcblk0", "vda", "a", long_ok.as_str()],
        &[
            "",
            long_bad.as_str(),
            "sd b",
            "sdb;reboot",
            "../sda",
            "/dev/sdb",
            "sd$(id)",
            "sdb'",
            "sdb\"",
            "sd`id`",
            "sd*",
        ],
    );
}

#[test]
fn error_message_mentions_the_value() {
    init();
    let msg = err_text(validate_device_name_for("sdb", HostOs::Mac));
    assert!(msg.contains("'sdb'"), "{msg}");
}

#[test]
fn no_selection_message() {
    init();
    // the Python calls it with the real host; the empty text is refused the same way everywhere
    assert!(err_text(validate_device_name("")).contains("No disk"));
}

#[test]
fn the_real_host_accepts_its_own_names_only() {
    init();
    let (own, other) = if cfg!(target_os = "macos") {
        ("disk4", "sdb")
    } else if cfg!(windows) {
        ("PhysicalDrive3", "disk4")
    } else {
        ("sdb", "sd b")
    };
    assert_eq!(validate_device_name(own).unwrap(), own);
    assert!(validate_device_name(other).is_err());
}

// ---- ValidateIsoPathTests ----
#[cfg(unix)]
#[test]
fn returns_real_absolute_path() {
    let t = Tmp::new();
    let iso = t.make_iso("a.iso", 2 * MIB, true);
    let link = t.path("link.iso");
    std::os::unix::fs::symlink(&iso, &link).unwrap();
    assert_eq!(validate_iso_path(&link).unwrap(), std::fs::canonicalize(&iso).unwrap());
}

#[cfg(unix)]
#[test]
fn expands_user() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let t = Tmp::new();
    let iso = t.make_iso("home.iso", 2 * MIB, true);
    let saved = std::env::var_os("HOME");
    std::env::set_var("HOME", &t.root);
    let result = validate_iso_path("~/home.iso");
    match saved {
        Some(v) => std::env::set_var("HOME", v),
        None => std::env::remove_var("HOME"),
    }
    assert_eq!(result.unwrap(), std::fs::canonicalize(&iso).unwrap());
}

#[test]
fn rejects_empty() {
    init();
    assert!(matches!(validate_iso_path(""), Err(Error::Value(_))));
    assert_eq!(err_text(validate_iso_path("")), "No ISO file has been selected yet.");
}

#[test]
fn rejects_missing_file() {
    let t = Tmp::new();
    let msg = err_text(validate_iso_path(t.path("nope.iso")));
    assert!(msg.contains("no longer exists"), "{msg}");
    assert!(msg.starts_with("The selected ISO file no longer exists: "), "{msg}");
}

#[test]
fn rejects_directory() {
    let t = Tmp::new();
    std::fs::create_dir(t.path("dir.iso")).unwrap();
    assert!(err_text(validate_iso_path(t.path("dir.iso"))).contains("not a regular file"));
}

#[test]
fn rejects_tiny_file() {
    let t = Tmp::new();
    let small = t.write_file("small.iso", &[b'x'; 1000]);
    assert!(err_text(validate_iso_path(small)).contains("too small"));
}

#[test]
fn small_file_message_is_about_an_image() {
    // ValidateIsoPathWording (test_fixes_gui.py)
    let t = Tmp::new();
    let tiny = t.write_file("tiny.img", &[b'x'; 1000]);
    let msg = err_text(validate_iso_path(tiny));
    assert!(msg.contains("too small to be a valid image"), "{msg}");
    assert!(!msg.contains("Windows 11"), "{msg}");
    assert!(msg.contains("(1000.0 B)") && msg.contains("It may be an incomplete download."), "{msg}");
}

#[test]
fn one_mebibyte_is_enough() {
    let t = Tmp::new();
    let exact = t.write_file("exact.iso", &vec![0u8; MIB]);
    assert_eq!(validate_iso_path(&exact).unwrap(), exact);
}

#[cfg(unix)]
#[test]
fn rejects_unreadable_file() {
    use std::os::unix::fs::PermissionsExt;
    // root can read anything
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let t = Tmp::new();
    let iso = t.make_iso("secret.iso", 2 * MIB, true);
    std::fs::set_permissions(&iso, std::fs::Permissions::from_mode(0o000)).unwrap();
    let msg = err_text(validate_iso_path(&iso));
    std::fs::set_permissions(&iso, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(msg.contains("cannot be read"), "{msg}");
}

// ---- ValidateHybridIsoTests ----
#[test]
fn accepts_boot_signature() {
    let t = Tmp::new();
    validate_hybrid_iso(t.make_iso("ubuntu.iso", 2 * MIB, true)).unwrap();
}

#[test]
fn rejects_missing_signature() {
    let t = Tmp::new();
    let msg = err_text(validate_hybrid_iso(t.make_iso("ubuntu.iso", 2 * MIB, false)));
    assert!(msg.contains("not a bootable hybrid"), "{msg}");
    assert!(msg.contains("choose 'Windows 11' as the image type"), "{msg}");
}

#[test]
fn rejects_short_file() {
    let t = Tmp::new();
    assert!(matches!(validate_hybrid_iso(t.write_file("short.iso", &[0x55, 0xaa])), Err(Error::Value(_))));
}

#[test]
fn signature_must_be_at_offset_510() {
    let t = Tmp::new();
    let mut data = vec![0u8; 2048];
    data[1022..1024].copy_from_slice(&[0x55, 0xaa]);
    assert!(matches!(validate_hybrid_iso(t.write_file("late.iso", &data)), Err(Error::Value(_))));
}

// ---- ValidateDownloadUrlTests ----
// The Python removes the two override variables from os.environ for each test; here the environment is passed in,
// and one test at the end exercises the real environment under a lock.
fn no_env(_: &str) -> Option<String> {
    None
}

fn env_with(key: &'static str, value: &'static str) -> impl Fn(&str) -> Option<String> {
    move |k: &str| (k == key).then(|| value.to_string())
}

#[test]
fn trusted_microsoft_hosts() {
    for url in [
        "https://www.microsoft.com/a",
        "https://microsoft.com/a",
        "https://software.download.prss.microsoft.com/x.iso",
        "https://HOST.download.microsoft.com/x.iso",
    ] {
        let (_u, _h, untrusted) = validate_download_url_with(url, &no_env).unwrap();
        assert!(!untrusted, "{url}");
    }
}

#[test]
fn untrusted_host_is_flagged_not_rejected() {
    let got = validate_download_url_with("https://example.com/win.iso", &no_env).unwrap();
    assert_eq!(got, ("https://example.com/win.iso".to_string(), "example.com".to_string(), true));
}

#[test]
fn lookalike_hosts_are_untrusted() {
    for url in
        ["https://microsoft.com.evil.example/x", "https://evilmicrosoft.com/x", "https://microsoft.com@evil.example/x"]
    {
        assert!(validate_download_url_with(url, &no_env).unwrap().2, "{url}");
    }
}

#[test]
fn only_https() {
    for url in [
        "http://www.microsoft.com/x",
        "ftp://www.microsoft.com/x",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "www.microsoft.com/x",
    ] {
        assert!(validate_download_url_with(url, &no_env).is_err(), "{url}");
    }
}

#[test]
fn empty_and_hostless() {
    for url in ["", "   ", "https://", "https:///path"] {
        assert!(validate_download_url_with(url, &no_env).is_err(), "{url:?}");
    }
}

#[test]
fn strips_whitespace() {
    assert_eq!(
        validate_download_url_with("  https://www.microsoft.com/x \n", &no_env).unwrap().0,
        "https://www.microsoft.com/x"
    );
}

#[test]
fn trusted_hosts_env_override() {
    let env = env_with(ENV_TRUSTED_HOSTS, "example.org, mirror.test");
    assert!(!validate_download_url_with("https://example.org/x", &env).unwrap().2);
    assert!(!validate_download_url_with("https://cdn.mirror.test/x", &env).unwrap().2);
    assert!(validate_download_url_with("https://www.microsoft.com/x", &env).unwrap().2);
}

#[test]
fn allow_any_host_env_still_requires_https() {
    let env = env_with(ENV_ALLOW_ANY_HOST, "1");
    assert!(!validate_download_url_with("https://whatever.example/x", &env).unwrap().2);
    assert!(validate_download_url_with("http://whatever.example/x", &env).is_err());
}

#[test]
fn the_real_environment_is_honoured() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    init();
    let saved: Vec<(&str, Option<std::ffi::OsString>)> =
        [ENV_TRUSTED_HOSTS, ENV_ALLOW_ANY_HOST].iter().map(|k| (*k, std::env::var_os(k))).collect();
    std::env::remove_var(ENV_ALLOW_ANY_HOST);
    std::env::set_var(ENV_TRUSTED_HOSTS, "example.org, mirror.test");
    let trusted = validate_download_url("https://cdn.mirror.test/x").map(|r| r.2);
    let microsoft = validate_download_url("https://www.microsoft.com/x").map(|r| r.2);
    std::env::set_var(ENV_ALLOW_ANY_HOST, "yes");
    let any = validate_download_url("https://whatever.example/x").map(|r| r.2);
    for (key, value) in saved {
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }
    assert!(!trusted.unwrap());
    assert!(microsoft.unwrap());
    assert!(!any.unwrap());
}

#[test]
fn paths_are_returned_as_paths() {
    // the signature check: validate_iso_path hands back an owned PathBuf
    let t = Tmp::new();
    let p: PathBuf = validate_iso_path(t.make_iso("x.iso", MIB, true)).unwrap();
    assert!(p.is_absolute());
}
