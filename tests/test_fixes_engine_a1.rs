//! Port (A1 part) of tests/test_fixes_engine.py: extraction turns every damaged-archive failure into a ValueError,
//! the temporary file is never written through a symlink, check_canceled, the sleep inhibitor, and lenient decoding of
//! command output.

#![cfg_attr(windows, allow(unused_imports))]

mod common_a1;

use common_a1::{random_bytes, Collector, Tmp, MIB};
use epma_usb_creator::constants::SLEEP_INHIBIT_SECONDS;
use epma_usb_creator::isoinfo::extract_disk_image;
use epma_usb_creator::proc::{check_canceled, prevent_sleep_with, run_cmd};
use epma_usb_creator::types::{CancelToken, Error};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// 5. extract_disk_image turns every damaged-archive failure into a ValueError
// ---------------------------------------------------------------------------
struct Extraction {
    t: Tmp,
    dest: PathBuf,
}

fn extraction() -> Extraction {
    let t = Tmp::new();
    let dest = t.path("out");
    std::fs::create_dir_all(&dest).unwrap();
    Extraction { t, dest }
}

impl Extraction {
    /// The Python `make_zip`: one `flex.bin` member, stored by default.
    fn make_zip(&self, deflate: bool, data: &[u8]) -> PathBuf {
        self.t.make_zip("flex.zip", &[("flex.bin", data)], deflate)
    }

    fn assert_clean_failure(&self, zip_path: &Path, pattern: &str) {
        let err = extract_disk_image(zip_path, &self.dest, None, None).unwrap_err();
        assert!(matches!(err, Error::Value(_)), "{err:?}");
        assert!(err.to_string().contains(pattern), "{err}");
        let left: Vec<_> = std::fs::read_dir(&self.dest).unwrap().collect();
        assert!(left.is_empty(), "no half-written file may be left behind");
    }
}

/// Patch the 2-byte value at `offset` of every header that starts with `magic` (local file header "PK\3\4" or
/// central directory header "PK\1\2").
fn patch_headers(zip_path: &Path, magic: &[u8], offset: usize, value: u16) {
    let mut data = std::fs::read(zip_path).unwrap();
    let mut at = 0;
    while let Some(rel) = data[at..].windows(4).position(|w| w == magic) {
        let pos = at + rel;
        data[pos + offset..pos + offset + 2].copy_from_slice(&value.to_le_bytes());
        at = pos + 4;
    }
    std::fs::write(zip_path, data).unwrap();
}

#[test]
fn a_corrupt_deflate_stream() {
    let x = extraction();
    let mut payload = random_bytes(300_000, 21);
    payload.extend(vec![0u8; 2 * MIB]);
    let zip_path = x.make_zip(true, &payload);
    let mut data = std::fs::read(&zip_path).unwrap();
    data[150_000..150_000 + 4096].fill(0xff); // damage the middle of the compressed data
    std::fs::write(&zip_path, data).unwrap();
    x.assert_clean_failure(&zip_path, "damaged");
}

#[test]
fn a_stored_entry_with_a_bad_checksum_is_damaged() {
    // stands in for test_zlib_error_from_the_reader / test_truncated_stream: any failure of the data stream is the
    // same user-facing "damaged" message (the Python mocks the reader; here the stream really fails)
    let x = extraction();
    let zip_path = x.make_zip(false, &vec![0u8; 2 * MIB]);
    let mut data = std::fs::read(&zip_path).unwrap();
    let mid = data.len() / 2;
    data[mid] = 0x55;
    std::fs::write(&zip_path, data).unwrap();
    x.assert_clean_failure(&zip_path, "damaged");
}

#[test]
fn unsupported_compression() {
    let x = extraction();
    let zip_path = x.make_zip(false, &vec![0u8; 2 * MIB]);
    // an unknown compression method (not 99: that is the AES marker) in the local header (offset 8) and the central
    // directory (offset 10)
    patch_headers(&zip_path, b"PK\x03\x04", 8, 77);
    patch_headers(&zip_path, b"PK\x01\x02", 10, 77);
    x.assert_clean_failure(&zip_path, "not supported");
}

#[test]
fn encrypted_entry() {
    let x = extraction();
    let zip_path = x.make_zip(false, &vec![0u8; 2 * MIB]);
    // general purpose flag bit 0 (encrypted) in the local header (offset 6) and the central directory (offset 8)
    patch_headers(&zip_path, b"PK\x03\x04", 6, 1);
    patch_headers(&zip_path, b"PK\x01\x02", 8, 1);
    x.assert_clean_failure(&zip_path, "not supported");
}

#[test]
fn cancel_is_still_a_cancel() {
    let x = extraction();
    let zip_path = x.make_zip(false, &vec![0u8; 2 * MIB]);
    let token = CancelToken::new();
    token.set();
    let err = extract_disk_image(&zip_path, &x.dest, None, Some(&token)).unwrap_err();
    assert!(err.is_canceled());
    assert!(std::fs::read_dir(&x.dest).unwrap().next().is_none());
}

#[test]
fn a_good_archive_still_extracts() {
    let x = extraction();
    let out = extract_disk_image(x.make_zip(false, &vec![0u8; 2 * MIB]), &x.dest, None, None).unwrap();
    assert_eq!(std::fs::metadata(out).unwrap().len(), 2 * MIB as u64);
}

// ---- 13: the temporary file is never written through a symlink ----
#[cfg(unix)]
#[test]
fn a_symlink_at_the_temp_name_is_replaced_not_followed() {
    let x = extraction();
    let victim = x.t.write_file("victim.txt", b"precious");
    std::os::unix::fs::symlink(&victim, x.dest.join("flex.bin.part")).unwrap();
    let out = extract_disk_image(x.make_zip(false, &vec![0u8; 2 * MIB]), &x.dest, None, None).unwrap();
    assert_eq!(std::fs::read(&victim).unwrap(), b"precious");
    assert_eq!(std::fs::metadata(&out).unwrap().len(), 2 * MIB as u64);
    assert!(!std::fs::symlink_metadata(&out).unwrap().file_type().is_symlink());
}

#[cfg(unix)]
#[test]
fn a_stale_part_file_is_removed_and_the_new_one_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let x = extraction();
    x.t.write_file("out/flex.bin.part", b"stale");
    let out = extract_disk_image(x.make_zip(false, &vec![0u8; 2 * MIB]), &x.dest, None, None).unwrap();
    assert_eq!(std::fs::metadata(&out).unwrap().len(), 2 * MIB as u64);
    assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o077, 0);
}

// ---------------------------------------------------------------------------
// check_canceled passes the state on
// ---------------------------------------------------------------------------
#[test]
fn check_canceled_passes_the_state_on() {
    let token = CancelToken::new();
    token.set();
    let err = check_canceled(Some(&token), false, false).unwrap_err();
    assert!(err.is_canceled());
    assert!(!err.drive_touched());
    assert!(check_canceled(None, true, false).is_ok());
    assert!(check_canceled(Some(&CancelToken::new()), true, false).is_ok());
}

// ---------------------------------------------------------------------------
// 7. Sleep inhibitor
// ---------------------------------------------------------------------------
#[cfg(unix)]
mod prevent_sleep {
    use super::*;

    /// What Python's `FakeProc(running=True)` stands for: a command that keeps running.
    fn running() -> Vec<String> {
        ["sleep", "30"].iter().map(|s| s.to_string()).collect()
    }

    /// A command that exits at once (`FakeProc(running=False)`).
    fn exits_at_once() -> Vec<String> {
        ["sh", "-c", "exit 1"].iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_sleep_is_bounded_and_cleaned_up() {
        // the bound is the command line the real call builds
        assert_eq!(SLEEP_INHIBIT_SECONDS, 12 * 3600);
        let collector = Collector::new();
        let log = collector.log();
        let guard = prevent_sleep_with(Some(&running()), &log);
        assert!(guard.is_holding());
        assert_eq!(collector.lines(), vec!["Sleep is blocked while the drive is being written."]);
        drop(guard); // stops the child (and, in its own process group, anything it started)
    }

    #[test]
    fn an_inhibitor_that_exits_at_once_is_not_reported_as_blocking() {
        let collector = Collector::new();
        let log = collector.log();
        let guard = prevent_sleep_with(Some(&exits_at_once()), &log);
        assert!(!guard.is_holding());
        assert!(!collector.lines().contains(&"Sleep is blocked while the drive is being written.".to_string()));
    }
}

// ---------------------------------------------------------------------------
// 12. Output that is not UTF-8 must not abort a copy
// ---------------------------------------------------------------------------
#[cfg(unix)]
#[test]
fn run_cmd_decodes_leniently() {
    let collector = Collector::new();
    let log = collector.log();
    run_cmd(&["sh", "-c", "printf 'caf\\351 file.txt\\n'"], &log, true, None, None).unwrap();
    assert!(collector.lines().contains(&"caf\u{fffd} file.txt".to_string()), "{:?}", collector.lines());
}
