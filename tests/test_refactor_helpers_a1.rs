//! Port (A1 part) of tests/test_refactor_helpers.py: the small helpers that replaced duplicated code
//! (silent_remove/rmdir, sha256_file, hash_stream, the SHA-256 text rules, resolve_path, has_mbr_signature and the
//! ETA text). The other classes of that file belong to the engine, the CLI and the backends.

mod common_a1;

use common_a1::{random_bytes, Tmp};
use epma_usb_creator::constants::MBR_SIGNATURE;
use epma_usb_creator::hash::{hash_stream, hex, sha256_file, sha256_file_chunked};
use epma_usb_creator::i18n::{translations, with_language};
use epma_usb_creator::types::{CancelToken, Error};
use epma_usb_creator::util::{eta_remaining, eta_text, rate_tail, silent_remove, silent_rmdir};
use epma_usb_creator::validate::{has_mbr_signature, is_sha256_hex, parse_expected_sha256, resolve_path};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::io::Cursor;
use std::sync::Mutex;

fn reference(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

// ---- SilentRemoveTests ----
#[test]
fn removes_files_and_ignores_missing_ones() {
    let t = Tmp::new();
    let a = t.write_file("a.txt", b"x");
    let b = t.write_file("b.txt", b"y");
    silent_remove(&a);
    silent_remove(t.path("missing.txt"));
    silent_remove(&b);
    assert!(!a.exists());
    assert!(!b.exists());
}

#[cfg(unix)]
#[test]
fn swallows_os_errors_from_remove() {
    use std::os::unix::fs::PermissionsExt;
    // the Python makes os.remove raise PermissionError; here a directory cannot be removed as a file
    let t = Tmp::new();
    let dir = t.path("a-directory");
    std::fs::create_dir(&dir).unwrap();
    silent_remove(&dir); // must not panic
    assert!(dir.is_dir());
    // and a file in a folder that does not let us delete (not for root)
    let locked = t.path("locked");
    std::fs::create_dir(&locked).unwrap();
    let file = t.write_file("locked/f.txt", b"x");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();
    silent_remove(&file);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn rmdir_removes_empty_dirs_and_ignores_the_rest() {
    let t = Tmp::new();
    let empty = t.path("empty");
    std::fs::create_dir(&empty).unwrap();
    let full = t.path("full");
    std::fs::create_dir(&full).unwrap();
    t.write_file("full/file", b"x");
    silent_rmdir(&empty);
    silent_rmdir(&full);
    silent_rmdir(t.path("missing"));
    assert!(!empty.exists());
    assert!(full.is_dir()); // not empty: left alone, no exception
}

// ---- Sha256FileTests ----
fn blob() -> (Tmp, std::path::PathBuf, Vec<u8>) {
    let t = Tmp::new();
    let data = random_bytes(1_300_000, 42);
    let path = t.write_file("blob.bin", &data);
    (t, path, data)
}

#[test]
fn sha256_matches_the_reference() {
    let (_t, path, data) = blob();
    assert_eq!(sha256_file(&path, None, None).unwrap(), reference(&data));
}

#[test]
fn sha256_of_an_empty_file() {
    let t = Tmp::new();
    let empty = t.write_file("empty.bin", b"");
    assert_eq!(sha256_file(&empty, None, None).unwrap(), reference(b""));
}

#[test]
fn progress_reports_done_and_total_per_chunk() {
    let (_t, path, data) = blob();
    let seen = Mutex::new(Vec::new());
    let progress = |d: u64, t: u64| seen.lock().unwrap().push((d, t));
    let digest = sha256_file_chunked(&path, None, Some(&progress), 500_000).unwrap();
    assert_eq!(digest, reference(&data));
    assert_eq!(*seen.lock().unwrap(), vec![(500_000, 1_300_000), (1_000_000, 1_300_000), (1_300_000, 1_300_000)]);
}

#[test]
fn cancel_event_stops_with_operation_canceled() {
    let (_t, path, _data) = blob();
    let token = CancelToken::new();
    token.set();
    let err = sha256_file(&path, Some(&token), None).unwrap_err();
    assert!(err.is_canceled());
    assert!(!err.written());
}

#[test]
fn missing_file_is_an_oserror() {
    let (_t, path, _data) = blob();
    let gone = path.with_extension("bin.nope");
    let progress = |_d: u64, _t: u64| {};
    assert!(matches!(sha256_file(&gone, None, Some(&progress)), Err(Error::Io(_))));
}

// ---- HashStreamTests ----
#[test]
fn limit_reads_only_that_many_bytes() {
    let mut digest = Sha256::new();
    let mut fh = Cursor::new(vec![b'a'; 100]);
    assert_eq!(hash_stream(&mut fh, &mut digest, Some(40), None, None, 16).unwrap(), 40);
    assert_eq!(hex(&digest.finalize()), reference(&[b'a'; 40]));
    assert_eq!(fh.position(), 40);
}

#[test]
fn a_short_stream_returns_fewer_bytes_than_the_limit() {
    let mut digest = Sha256::new();
    let n = hash_stream(&mut Cursor::new(b"abc".to_vec()), &mut digest, Some(10), None, None, 4 * 1024 * 1024).unwrap();
    assert_eq!(n, 3);
}

#[test]
fn check_runs_before_every_read_and_can_stop_it() {
    let calls = RefCell::new(0);
    let check = || {
        *calls.borrow_mut() += 1;
        if *calls.borrow() == 3 {
            Err(Error::runtime("stop"))
        } else {
            Ok(())
        }
    };
    let err =
        hash_stream(&mut Cursor::new(vec![b'x'; 100]), &mut Sha256::new(), None, Some(&check), None, 10).unwrap_err();
    assert_eq!(err.to_string(), "stop");
    assert_eq!(*calls.borrow(), 3);
}

// ---- SharedRuleTests (the part about these helpers) ----
#[test]
fn is_sha256_hex_rules() {
    let good = "ab".repeat(32);
    assert!(is_sha256_hex(&good));
    assert!(is_sha256_hex(&good.to_uppercase()));
    for bad in [
        good[..63].to_string(),
        format!("{good}0"),
        format!("{}g", &good[..63]),
        String::new(),
        format!(" {good}"),
        format!("{good}\n"),
    ] {
        assert!(!is_sha256_hex(&bad), "{bad:?}");
    }
}

#[test]
fn parse_expected_sha256_still_finds_a_hash_inside_a_line() {
    let good = "cd".repeat(32);
    assert_eq!(parse_expected_sha256(&format!("{} *ubuntu.iso", good.to_uppercase()), None).unwrap(), Some(good));
    assert!(matches!(parse_expected_sha256(&"0".repeat(65), None), Err(Error::Value(_))));
    // too long: not a SHA-256
}

#[cfg(unix)]
#[test]
fn resolve_path_expands_home_and_symlinks() {
    let t = Tmp::new();
    let target = t.write_file("real.iso", b"x");
    let link = t.path("link.iso");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert_eq!(resolve_path(&link), std::fs::canonicalize(&target).unwrap());
    let home = epma_usb_creator::util::home_dir().expect("a home directory");
    assert_eq!(resolve_path("~"), std::fs::canonicalize(home).unwrap());
}

#[test]
fn resolve_path_keeps_the_part_that_does_not_exist() {
    let t = Tmp::new();
    // like Python's non-strict realpath: the existing prefix is resolved, the rest kept, ".." folded
    assert_eq!(resolve_path(t.path("missing/dir/../file.iso")), t.root.join("missing/file.iso"));
    assert_eq!(resolve_path(t.path("./a/./b")), t.root.join("a/b"));
    assert!(resolve_path("relative/not-there.iso").is_absolute());
}

#[test]
fn has_mbr_signature_rules() {
    let mut head = vec![0u8; 512];
    assert!(!has_mbr_signature(&head));
    head[510..512].copy_from_slice(&MBR_SIGNATURE);
    assert!(has_mbr_signature(&head));
    assert!(!has_mbr_signature(&MBR_SIGNATURE)); // a short read never counts
    assert!(!has_mbr_signature(b""));
}

// ---- EtaTextTests ----
#[test]
fn eta_text_minutes_and_seconds() {
    assert_eq!(eta_text(125.0, 1.0, true), "~2m05s left");
    assert_eq!(eta_text(0.0, 1.0, true), "~0m00s left");
    assert_eq!(eta_text(3600.0, 1.0, true), "~60m00s left");
}

#[test]
fn eta_text_is_empty_when_nothing_can_be_estimated() {
    // the Python also tries speed None and remaining None: an absent value is a 0 speed / NaN time here
    for (remaining, speed) in [(10.0, 0.0), (10.0, -1.0), (-1.0, 5.0), (f64::INFINITY, 5.0), (f64::NAN, 5.0)] {
        assert_eq!(eta_text(remaining, speed, true), "", "{remaining} {speed}");
    }
}

#[test]
fn translate_flag_picks_the_language() {
    with_language("pt", || {
        assert_eq!(eta_text(125.0, 1.0, true), "faltam ~2m05s");
        assert_eq!(eta_text(125.0, 1.0, false), "~2m05s left"); // the CLI stays English
    });
}

#[test]
fn eta_remaining_from_done_total_and_speed() {
    assert_eq!(eta_remaining(0, 1000, 10.0, true), "~1m40s left");
    assert_eq!(eta_remaining(1000, 1000, 10.0, true), "~0m00s left");
    assert_eq!(eta_remaining(0, 1000, 0.0, true), "");
}

#[test]
fn rate_tail_text() {
    assert_eq!(rate_tail(0, 2 * 1024 * 1024, 1024.0 * 1024.0), " — 1.0 MB/s — ~0m02s left");
    assert_eq!(rate_tail(0, 100, 0.0), "");
}

// ---- EtaTextTests of test_fixes_gui.py ----
#[test]
fn minutes_and_seconds_never_raw_seconds() {
    assert_eq!(eta_text(80.0, 10.0, true), "~1m20s left");
    assert_eq!(eta_text(7200.0, 10.0, true), "~120m00s left");
    assert_eq!(eta_text(5.9, 1.0, true), "~0m05s left");
}

#[test]
fn unknown_speed_gives_nothing() {
    for speed in [0.0, -1.0] {
        assert_eq!(eta_text(100.0, speed, true), "");
    }
    assert_eq!(eta_text(-5.0, 10.0, true), "");
}

#[test]
fn it_is_translated() {
    with_language("pt", || assert_eq!(eta_text(125.0, 10.0, true), "faltam ~2m05s"));
    assert!(translations().iter().any(|(k, _)| *k == "calculating..."));
}
