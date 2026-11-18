//! Port (A1 part) of tests/test_chromeos.py: image checks, content detection, safe extraction and the official
//! download address. Everything runs on temp files; no network, no sudo and no device is touched.
//!
//! Not ported here because they belong to other modules: CardTests (4), the ConstantsTests raw-modes test, FlexRedirect
//! (5), BuildUsbTests (10), CliTests (10), DownloadBlockingTests (1).

mod common_a1;

use common_a1::{gpt_image, random_bytes, Tmp, CHROMEOS_NAMES, MIB};
use epma_usb_creator::constants::{CHROMEOS_FLEX_URL, CHROMEOS_MIN_USB_BYTES};
use epma_usb_creator::isoinfo::{detect_iso_kind, extract_disk_image, extract_disk_image_with};
use epma_usb_creator::types::{CancelToken, Error, IsoKind};
use epma_usb_creator::validate::{validate_disk_image, validate_download_url_with};
use std::sync::Mutex;

fn value_error(result: epma_usb_creator::types::Result<impl std::fmt::Debug>) -> String {
    match result {
        Err(Error::Value(msg)) => msg,
        other => panic!("expected a ValueError, got {other:?}"),
    }
}

// ---- ConstantsTests (the two that read constants) ----
#[test]
fn the_official_address_is_https_on_dl_google_com() {
    assert_eq!(CHROMEOS_FLEX_URL, "https://dl.google.com/chromeos-flex/images/latest.bin.zip");
}

#[test]
fn minimum_drive_is_a_16gb_stick() {
    // a stick sold as "16 GB" holds about 15.5e9 bytes and must not be warned about
    const { assert!(CHROMEOS_MIN_USB_BYTES < 15_500_000_000) };
    const { assert!(CHROMEOS_MIN_USB_BYTES > 8_000_000_000) };
}

// ---- ValidateDiskImageTests ----
#[test]
fn accepts_an_image_with_the_boot_signature() {
    let t = Tmp::new();
    validate_disk_image(t.write_file("a.bin", &gpt_image(&CHROMEOS_NAMES, 2 * MIB, true))).unwrap();
}

#[test]
fn refuses_a_file_without_the_boot_signature() {
    let t = Tmp::new();
    let path = t.write_file("a.bin", &gpt_image(&CHROMEOS_NAMES, 2 * MIB, false));
    assert!(value_error(validate_disk_image(path)).contains("not a bootable disk image"));
}

#[test]
fn refuses_the_zip_and_says_what_to_do() {
    let t = Tmp::new();
    let zip_path = t.make_zip("latest.bin.zip", &[("x.bin", &random_bytes(MIB, 1))], true);
    assert!(value_error(validate_disk_image(zip_path)).contains("ZIP archive, not the disk image"));
}

#[test]
fn a_missing_file_is_an_io_error_not_a_value_error() {
    let t = Tmp::new();
    assert!(matches!(validate_disk_image(t.path("nope.bin")), Err(Error::Io(_))));
}

// ---- DetectionTests ----
#[test]
fn a_chromeos_gpt_is_recognised_by_its_partition_names() {
    let t = Tmp::new();
    let path = t.write_file("a.bin", &gpt_image(&CHROMEOS_NAMES, 2 * MIB, true));
    assert_eq!(detect_iso_kind(path), IsoKind::ChromeOs);
}

#[test]
fn the_minimum_set_of_names_is_enough() {
    let t = Tmp::new();
    let path = t.write_file("a.bin", &gpt_image(&["KERN-A", "ROOT-A", "STATE"], 2 * MIB, true));
    assert_eq!(detect_iso_kind(path), IsoKind::ChromeOs);
}

#[test]
fn other_gpt_disks_are_not_chromeos() {
    let t = Tmp::new();
    let sets: [&[&str]; 4] = [
        &["EFI System Partition", "Basic data partition"],
        &["ROOT-A"],
        &["KERN-A", "STATE"],
        &["root", "boot", "home"],
    ];
    for names in sets {
        let path = t.write_file("b.bin", &gpt_image(names, 2 * MIB, true));
        assert_ne!(detect_iso_kind(path), IsoKind::ChromeOs, "{names:?}");
    }
}

#[test]
fn a_hybrid_iso_is_still_linux() {
    // the smallest thing the detector accepts as a hybrid ISO: a primary volume descriptor ("CD001") and the MBR
    // boot signature
    let t = Tmp::new();
    let mut data = random_bytes(2 * MIB, 3);
    data[510..512].copy_from_slice(&[0x55, 0xaa]);
    let pvd = 16 * 2048;
    data[pvd..pvd + 8].copy_from_slice(b"\x01CD001\x01\x00");
    data[pvd + 156..pvd + 190].fill(0); // empty root directory record
    assert_eq!(detect_iso_kind(t.write_file("u2.iso", &data)), IsoKind::Linux);
}

#[test]
fn garbage_and_missing_files_never_raise() {
    let t = Tmp::new();
    assert_eq!(detect_iso_kind(t.write_file("g.bin", &random_bytes(4096, 5))), IsoKind::Unknown);
    assert_eq!(detect_iso_kind(t.path("missing.bin")), IsoKind::Unknown);
}

#[test]
fn an_empty_gpt_slot_is_ignored() {
    let t = Tmp::new();
    let mut data = gpt_image(&CHROMEOS_NAMES, 2 * MIB, true);
    data[1024 + 6 * 128..1024 + 7 * 128].fill(0);
    assert_eq!(detect_iso_kind(t.write_file("c.bin", &data)), IsoKind::ChromeOs);
}

// ---- ExtractionTests ----
struct Extraction {
    t: Tmp,
    dest: std::path::PathBuf,
    image: Vec<u8>,
}

fn extraction() -> Extraction {
    let t = Tmp::new();
    let dest = t.path("out");
    std::fs::create_dir_all(&dest).unwrap();
    Extraction { image: gpt_image(&CHROMEOS_NAMES, 3 * MIB, true), t, dest }
}

fn listing(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> =
        std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    names
}

#[test]
fn extracts_the_image_and_reports_progress() {
    let x = extraction();
    let zip_path = x.t.make_zip("latest.bin.zip", &[("chromeos_flex.bin", &x.image)], true);
    let seen = Mutex::new(Vec::new());
    let progress = |d: u64, t: u64| seen.lock().unwrap().push((d, t));
    let out = extract_disk_image(&zip_path, &x.dest, Some(&progress), None).unwrap();
    assert_eq!(out, x.dest.join("chromeos_flex.bin"));
    assert_eq!(std::fs::read(&out).unwrap(), x.image);
    let seen = seen.lock().unwrap();
    let len = x.image.len() as u64;
    assert_eq!(*seen.last().unwrap(), (len, len));
    let dones: Vec<u64> = seen.iter().map(|(d, _)| *d).collect();
    let mut sorted = dones.clone();
    sorted.sort();
    assert_eq!(dones, sorted);
    assert_eq!(listing(&x.dest), vec!["chromeos_flex.bin"]); // no .part left behind
}

#[cfg(unix)]
#[test]
fn the_extracted_file_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let x = extraction();
    let zip_path = x.t.make_zip("latest.bin.zip", &[("a.bin", &x.image)], true);
    let out = extract_disk_image(&zip_path, &x.dest, None, None).unwrap();
    assert_eq!(std::fs::metadata(out).unwrap().permissions().mode() & 0o077, 0);
}

#[test]
fn a_path_in_the_zip_cannot_escape_the_folder() {
    let x = extraction();
    let zip_path = x.t.make_zip("latest.bin.zip", &[("../../evil.bin", &x.image)], true);
    let out = extract_disk_image(&zip_path, &x.dest, None, None).unwrap();
    assert_eq!(out.parent().unwrap(), x.dest);
    assert_eq!(out.file_name().unwrap(), "evil.bin");
    assert!(!x.dest.parent().unwrap().join("evil.bin").exists());
}

#[test]
fn an_odd_member_name_is_replaced_by_a_safe_one() {
    let x = extraction();
    let zip_path = x.t.make_zip("latest.bin.zip", &[("we ird$name;.bin", &x.image)], true);
    let out = extract_disk_image(&zip_path, &x.dest, None, None).unwrap();
    assert_eq!(out.file_name().unwrap(), "chromeos_flex.bin");
}

#[test]
fn a_backslash_path_in_the_zip_keeps_only_the_base_name() {
    let x = extraction();
    let zip_path = x.t.make_zip("latest.bin.zip", &[("dir\\sub\\flex.bin", &x.image)], true);
    let out = extract_disk_image(&zip_path, &x.dest, None, None).unwrap();
    assert_eq!(out.file_name().unwrap(), "flex.bin");
}

#[test]
fn picks_the_largest_bin_when_there_are_several() {
    let x = extraction();
    let small = random_bytes(2 * MIB, 11);
    let zip_path =
        x.t.make_zip("latest.bin.zip", &[("small.bin", &small), ("big.bin", &x.image), ("readme.txt", b"x")], true);
    let out = extract_disk_image(&zip_path, &x.dest, None, None).unwrap();
    assert_eq!(out.file_name().unwrap(), "big.bin");
}

#[test]
fn never_overwrites_an_existing_file() {
    let x = extraction();
    x.t.write_file("out/chromeos_flex.bin", b"precious");
    let zip_path = x.t.make_zip("latest.bin.zip", &[("chromeos_flex.bin", &x.image)], true);
    let out = extract_disk_image(&zip_path, &x.dest, None, None).unwrap();
    assert_eq!(out.file_name().unwrap(), "chromeos_flex-1.bin");
    assert_eq!(std::fs::read(x.dest.join("chromeos_flex.bin")).unwrap(), b"precious");
    // and again: -2
    let again = extract_disk_image(&zip_path, &x.dest, None, None).unwrap();
    assert_eq!(again.file_name().unwrap(), "chromeos_flex-2.bin");
}

#[test]
fn refuses_a_zip_without_a_bin() {
    let x = extraction();
    let zip_path = x.t.make_zip("latest.bin.zip", &[("readme.txt", b"hello")], true);
    assert!(value_error(extract_disk_image(&zip_path, &x.dest, None, None)).contains("does not contain a .bin"));
}

#[test]
fn refuses_an_implausibly_small_image() {
    let x = extraction();
    let zip_path = x.t.make_zip("latest.bin.zip", &[("a.bin", b"tiny")], true);
    assert!(value_error(extract_disk_image(&zip_path, &x.dest, None, None)).contains("implausible size"));
}

#[test]
fn refuses_an_implausibly_large_image() {
    let x = extraction();
    let zip_path = x.t.make_zip("latest.bin.zip", &[("a.bin", &x.image)], true);
    // the Python patches DISK_IMAGE_MAX_BYTES to one MiB
    let msg = value_error(extract_disk_image_with(&zip_path, &x.dest, None, None, MIB as u64, &|_| Ok(u64::MAX)));
    assert!(msg.contains("implausible size"), "{msg}");
    assert!(msg.contains("3.0 MB"), "{msg}");
}

#[test]
fn refuses_when_there_is_not_enough_free_space() {
    let x = extraction();
    let zip_path = x.t.make_zip("latest.bin.zip", &[("a.bin", &x.image)], true);
    let msg = value_error(extract_disk_image_with(&zip_path, &x.dest, None, None, u64::MAX, &|_| Ok(1024)));
    assert!(msg.contains("Not enough free space"), "{msg}");
    assert!(listing(&x.dest).is_empty());
    // the margin is 256 MiB on top of the image
    let need = x.image.len() as u64 + 256 * 1024 * 1024;
    assert!(extract_disk_image_with(&zip_path, &x.dest, None, None, u64::MAX, &|_| Ok(need - 1)).is_err());
    assert!(extract_disk_image_with(&zip_path, &x.dest, None, None, u64::MAX, &|_| Ok(need)).is_ok());
}

#[test]
fn not_a_zip() {
    let x = extraction();
    let path = x.t.write_file("x.zip", b"this is not a zip");
    assert!(value_error(extract_disk_image(&path, &x.dest, None, None)).contains("not a valid ZIP"));
    // a missing file reads the same to the user
    assert!(value_error(extract_disk_image(x.t.path("missing.zip"), &x.dest, None, None)).contains("not a valid ZIP"));
}

#[test]
fn a_missing_destination_folder() {
    let x = extraction();
    let zip_path = x.t.make_zip("latest.bin.zip", &[("a.bin", &x.image)], true);
    assert!(value_error(extract_disk_image(&zip_path, x.t.path("nope"), None, None)).contains("does not exist"));
}

#[test]
fn a_damaged_zip_is_detected_and_leaves_nothing_behind() {
    let x = extraction();
    let zip_path = x.t.make_zip("latest.bin.zip", &[("a.bin", &x.image)], false);
    let mut data = std::fs::read(&zip_path).unwrap();
    let mid = data.len() / 2;
    data[mid] ^= 0xFF; // flip a byte inside the stored image: the CRC no longer matches
    std::fs::write(&zip_path, data).unwrap();
    assert!(value_error(extract_disk_image(&zip_path, &x.dest, None, None)).contains("damaged"));
    assert!(listing(&x.dest).is_empty());
}

#[test]
fn cancel_stops_and_cleans_up() {
    let x = extraction();
    let zip_path = x.t.make_zip("latest.bin.zip", &[("a.bin", &x.image)], true);
    let token = CancelToken::new();
    let progress = |_d: u64, _t: u64| token.set(); // cancel as soon as the first chunk is written
    let err = extract_disk_image(&zip_path, &x.dest, Some(&progress), Some(&token)).unwrap_err();
    assert!(err.is_canceled());
    assert!(listing(&x.dest).is_empty());
}

// ---- DownloadAddressTests ----
fn no_env(_: &str) -> Option<String> {
    None
}

#[test]
fn the_official_link_is_trusted() {
    let (url, host, untrusted) = validate_download_url_with(CHROMEOS_FLEX_URL, &no_env).unwrap();
    assert_eq!((url.as_str(), host.as_str(), untrusted), (CHROMEOS_FLEX_URL, "dl.google.com", false));
}

#[test]
fn any_other_google_address_is_still_unknown() {
    let with_query = format!("{CHROMEOS_FLEX_URL}?x=1");
    for other in [
        "https://dl.google.com/other/file.zip",
        with_query.as_str(),
        "https://dl.google.com/chromeos-flex/images/latest.bin.zip/..",
        "https://google.com/x.zip",
    ] {
        assert!(validate_download_url_with(other, &no_env).unwrap().2, "{other}");
    }
}

#[test]
fn plain_http_is_still_refused() {
    assert!(validate_download_url_with(&CHROMEOS_FLEX_URL.replace("https://", "http://"), &no_env).is_err());
}
