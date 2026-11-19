//! The command line parts of tests/test_fixes_engine.py (PreflightTests, CliPinsIdentityTests,
//! FetchChromeosExistingZipTests, CliDetailsTests) and of tests/test_chromeos.py (CliTests), plus `fetch-chromeos`
//! behaviour the Python left implicit.

use super::*;
use crate::cli::commands::cli_detect_kind;
use crate::cli::EXIT_INTERRUPTED;
use crate::constants::{CHROMEOS_FLEX_FREE_BYTES, CHROMEOS_FLEX_URL};
use std::fs;
use std::time::{Duration, Instant};

fn s(text: &str) -> String {
    text.to_string()
}

const FLEX_ZIP: &str = "chromeos_flex_latest.bin.zip";

// ===== PreflightTests (the command line parts) =====
#[test]
fn cli_refuses_a_windows_iso_larger_than_the_drive() {
    let t = T::new();
    let iso = t.make_iso("Win11.iso", 2 * MIB, false);
    t.engine.set_disks(vec![Disk { id: s("disk9"), size: MIB, label: s("tiny"), ..Disk::default() }]);
    let (code, _out, err) = t.run(&["write", "--iso", &iso, "--disk", "disk9", "--mode", "windows", "--yes"]);
    assert_eq!(code, 1);
    assert!(err.contains("larger than the drive"), "{err}");
    assert!(err.contains("The ISO (2.0 MB) is larger than the drive (1.0 MB)."), "{err}");
    assert!(t.engine.builds().is_empty());
}

#[test]
fn cli_missing_tools_message_includes_the_hint() {
    let t = T::new();
    let iso = t.make_iso("Win11.iso", 2 * MIB, false);
    *lock(&t.engine.missing) = vec![s("wimlib-imagex")];
    *lock(&t.engine.hint) = s("Install them with: brew install wimlib");
    let (code, _out, err) = t.run(&["write", "--iso", &iso, "--disk", "disk9", "--mode", "windows", "--yes"]);
    assert_eq!(code, 1);
    assert!(err.contains("brew install wimlib"), "{err}");
    assert!(t.engine.builds().is_empty());
}

// ===== CliPinsIdentityTests =====
fn identity() -> Identity {
    vec![(s("model"), s("Fake Stick")), (s("serial"), s("ABC123"))]
}

fn pinned_case() -> (T, String) {
    let t = T::new();
    t.engine.set_disks(vec![Disk {
        id: s("disk9"),
        size: 16 * GIB,
        label: s("stick"),
        identity: identity(),
        ..Disk::default()
    }]);
    let iso = t.iso();
    (t, iso)
}

#[test]
fn the_identity_is_pinned_when_the_engine_is_called_and_released_afterwards() {
    let (t, iso) = pinned_case();
    let seen = Arc::new(Mutex::new(None));
    let (probe, engine) = (seen.clone(), t.engine.clone());
    t.engine.on_build(move |_, _| {
        *lock(&probe) = engine.pin_log().last().cloned();
        Ok(true)
    });
    let (code, _out, _err) = t.run(&["write", "--iso", &iso, "--disk", "disk9", "--yes"]);
    assert_eq!(code, 0);
    assert_eq!(*lock(&seen), Some((s("disk9"), Some(identity()))));
    assert_eq!(t.engine.pin_log().last().unwrap(), &(s("disk9"), None));
}

#[test]
fn dry_run_json_shows_the_identity_as_an_object() {
    let (t, iso) = pinned_case();
    let (code, out, _err) = t.run(&["write", "--iso", &iso, "--disk", "disk9", "--dry-run", "--json"]);
    assert_eq!(code, 0);
    assert_eq!(json(&out)["identity"], serde_json::json!({"model": "Fake Stick", "serial": "ABC123"}));
    // and the object keeps the order of the pairs
    assert!(out.find("\"model\": \"Fake Stick\"").unwrap() < out.find("\"serial\"").unwrap());
}

#[test]
fn a_listing_without_identity_pins_nothing() {
    let t = T::new();
    t.engine.set_disks(vec![Disk { id: s("disk9"), size: 16 * GIB, label: s("stick"), ..Disk::default() }]);
    let iso = t.iso();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (probe, engine) = (seen.clone(), t.engine.clone());
    t.engine.on_build(move |_, _| {
        *lock(&probe) = engine.pin_log();
        Ok(true)
    });
    let (code, _out, _err) = t.run(&["write", "--iso", &iso, "--disk", "disk9", "--yes"]);
    assert_eq!(code, 0);
    assert_eq!(*lock(&seen), [(s("disk9"), None)], "an empty identity clears the pin instead of setting one");
}

// ===== FetchChromeosExistingZipTests =====
struct Fetch {
    t: T,
    dest: String,
    zip: String,
}

fn fetch_case() -> Fetch {
    let t = T::new();
    let zip = t.write_file(&format!("dl/{FLEX_ZIP}"), b"PK\x03\x04 pretend this is the ZIP from Google");
    let dest = t.path("dl");
    // the fake extraction: the image appears beside the ZIP
    *lock(&t.engine.extract) = Box::new(|_zip, dest_dir| {
        let image = dest_dir.join("chromeos_flex_1.bin");
        fs::write(&image, b"image")?;
        Ok(image)
    });
    Fetch { t, dest, zip }
}

#[test]
fn a_complete_zip_is_extracted_again_not_refused_and_not_downloaded() {
    let f = fetch_case();
    let (code, out, err) = f.t.run(&["fetch-chromeos", "--dest", &f.dest, "--json"]);
    assert_eq!(code, 0, "{err}");
    assert!(lock(&f.t.engine.download_calls).is_empty());
    let data = json(&out);
    assert!(Path::new(data["image"].as_str().unwrap()).is_file());
    assert_eq!(data["kept_zip"], true); // a ZIP that was already there is not deleted
    assert!(Path::new(&f.zip).exists());
    assert!(err.contains("extracting it again"), "{err}");
    // its checksum is computed, not made up
    let bytes = fs::read(&f.zip).unwrap();
    let expected: String = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect()
    };
    assert_eq!(data["zip_sha256"], expected.as_str());
}

#[test]
fn a_failed_extraction_keeps_the_zip_and_says_what_to_do_next() {
    let f = fetch_case();
    *lock(&f.t.engine.extract) = Box::new(|_, _| Err(Error::value("Not enough free space in x")));
    let (code, _out, err) = f.t.run(&["fetch-chromeos", "--dest", &f.dest]);
    assert_eq!(code, 1);
    assert!(err.contains("Not enough free space"), "{err}");
    assert!(err.contains("run 'epma-usb-creator fetch-chromeos' again to extract it"), "{err}");
    assert!(!err.contains("Remove it"));
    assert!(err.contains(&format!("The downloaded file was kept: {}", f.zip)), "{err}");
    assert!(Path::new(&f.zip).exists());
}

#[test]
fn an_unfinished_part_file_still_means_download() {
    let f = fetch_case();
    f.t.write_file(&format!("dl/{FLEX_ZIP}.part"), b"half");
    *lock(&f.t.engine.download) = Box::new(|_, _, _| Ok("ab".repeat(32)));
    let (code, _out, _err) = f.t.run(&["fetch-chromeos", "--dest", &f.dest]);
    assert_eq!(code, 0);
    assert_eq!(lock(&f.t.engine.download_calls).len(), 1);
}

// ===== test_chromeos CliTests (fetch-chromeos) =====
fn flex_case() -> (T, String) {
    let t = T::new();
    let out_dir = t.path("dl");
    fs::create_dir_all(&out_dir).unwrap();
    *lock(&t.engine.download) = Box::new(|url, dest, _| {
        assert_eq!(url, CHROMEOS_FLEX_URL);
        fs::write(dest, b"the zip")?;
        Ok("ab".repeat(32))
    });
    *lock(&t.engine.extract) = Box::new(|_zip, dest_dir| {
        let image = dest_dir.join("chromeos_flex_1.bin");
        fs::write(&image, b"image")?;
        Ok(image)
    });
    (t, out_dir)
}

#[test]
fn fetch_downloads_extracts_and_removes_the_zip() {
    let (t, out_dir) = flex_case();
    let (code, out, err) = t.run(&["fetch-chromeos", "--dest", &out_dir, "--json"]);
    assert_eq!(code, 0, "{err}");
    let info = json(&out);
    assert_eq!(Path::new(info["image"].as_str().unwrap()).parent().unwrap(), fs::canonicalize(&out_dir).unwrap());
    assert_eq!(info["zip_sha256"], "ab".repeat(32).as_str());
    assert_eq!(info["kept_zip"], false);
    let names: Vec<String> =
        fs::read_dir(&out_dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
    assert_eq!(names, ["chromeos_flex_1.bin"]); // the zip is gone
    assert!(err.contains("Google's own terms"), "{err}");
    assert!(err.contains("Downloading") && err.contains("Extracting"), "progress is shown: {err}");
    let image = info["image"].as_str().unwrap();
    assert!(
        err.contains(&format!(
            "Done. Write it with: epma-usb-creator write --iso {image} --disk <DISKID> --mode chromeos"
        )),
        "{err}"
    );
    // the image path is the data on stdout; without --json it is the whole of stdout
    let (_t2, out_dir2) = flex_case();
    let _ = out_dir2;
}

#[test]
fn fetch_prints_just_the_image_path_without_json() {
    let (t, out_dir) = flex_case();
    let (code, out, _err) = t.run(&["fetch-chromeos", "--dest", &out_dir]);
    assert_eq!(code, 0);
    assert_eq!(out, format!("{}/chromeos_flex_1.bin\n", fs::canonicalize(&out_dir).unwrap().display()));
}

#[test]
fn fetch_keep_zip() {
    let (t, out_dir) = flex_case();
    let (code, _out, _err) = t.run(&["fetch-chromeos", "--dest", &out_dir, "--keep-zip"]);
    assert_eq!(code, 0);
    assert!(Path::new(&out_dir).join(FLEX_ZIP).exists());
}

#[test]
fn fetch_reports_a_download_failure() {
    let (t, out_dir) = flex_case();
    *lock(&t.engine.download) = Box::new(|_, _, _| Err(Error::runtime("Could not reach the server.")));
    let (code, _out, err) = t.run(&["fetch-chromeos", "--dest", &out_dir]);
    assert_eq!(code, 1);
    assert!(err.contains("Could not reach the server"), "{err}");
    assert!(!err.contains("The downloaded file was kept"), "nothing was downloaded");
}

#[test]
fn fetch_refuses_a_missing_folder_and_re_extracts_an_existing_zip() {
    let (t, out_dir) = flex_case();
    let (code, _out, err) = t.run(&["fetch-chromeos", "--dest", &t.path("nope")]);
    assert_eq!(code, 1);
    assert!(err.contains("Not a folder"), "{err}");
    t.write_file(&format!("dl/{FLEX_ZIP}"), b"old");
    // An existing ZIP is no longer refused: it is extracted again (here it is not a ZIP at all, so the reason is
    // shown together with how to continue).
    *lock(&t.engine.extract) = Box::new(|_, _| Err(Error::value("The file is not a valid ZIP archive.")));
    let (code, _out, err) = t.run(&["fetch-chromeos", "--dest", &out_dir]);
    assert_eq!(code, 1);
    assert!(err.contains("not a valid ZIP"), "{err}");
    assert!(err.contains("remove the file"), "{err}");
    assert!(Path::new(&out_dir).join(FLEX_ZIP).exists());
}

#[test]
fn fetch_warns_when_there_is_little_free_space() {
    let (t, out_dir) = flex_case();
    *lock(&t.engine.free) = Some(CHROMEOS_FLEX_FREE_BYTES / 2);
    let (code, _out, err) = t.run(&["fetch-chromeos", "--dest", &out_dir]);
    assert_eq!(code, 0);
    assert!(err.contains("warning:") && err.contains("needs roughly 11.2 GB free; 5.6 GB is available in"), "{err}");
    *lock(&t.engine.free) = Some(CHROMEOS_FLEX_FREE_BYTES * 2);
    let (_code, _out, err) = t.run(&["fetch-chromeos", "--dest", &out_dir]);
    assert!(!err.contains("needs roughly"), "{err}");
    *lock(&t.engine.free) = None; // unknown: no warning, no failure
    assert_eq!(t.run(&["fetch-chromeos", "--dest", &out_dir]).0, 0);
}

#[test]
fn fetch_stops_on_ctrl_c_with_exit_130() {
    let (t, out_dir) = flex_case();
    let presses = t.interrupts.clone();
    *lock(&t.engine.download) = Box::new(move |_, _, cancel| {
        presses.press();
        let cancel = cancel.unwrap().clone();
        let until = Instant::now() + Duration::from_secs(5);
        while !cancel.is_set() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(2));
        }
        Err(Error::runtime("Download canceled by user."))
    });
    let (code, out, err) = t.run(&["fetch-chromeos", "--dest", &out_dir]);
    assert_eq!((code, out.as_str()), (EXIT_INTERRUPTED, ""));
    assert!(err.contains("Interrupted."), "{err}");
}

#[test]
fn fetch_uses_the_current_folder_by_default() {
    let t = T::new();
    *lock(&t.engine.download) = Box::new(|_, _, _| Err(Error::runtime("stop here")));
    let (code, _out, err) = t.run(&["fetch-chromeos"]);
    assert_eq!(code, 1);
    assert!(err.contains("stop here"), "{err}");
    let (_c, _o, err) = t.run(&["fetch-chromeos", "--dest", &t.path("a_file")]);
    assert!(err.contains("Not a folder"), "{err}");
    let calls = lock(&t.engine.download_calls).clone();
    assert_eq!(calls[0].1, fs::canonicalize(".").unwrap().join(FLEX_ZIP));
}

// ===== test_chromeos CliTests (write and detect) =====
struct Chrome {
    t: T,
    image: String,
}

fn chrome_case() -> Chrome {
    let t = T::new();
    let image = t.make_iso("flex.bin", 4 * MIB, true);
    *lock(&t.engine.detect) = Some(IsoKind::ChromeOs);
    Chrome { t, image }
}

#[test]
fn detect_prints_chromeos() {
    let c = chrome_case();
    let (code, out, _err) = c.t.run(&["detect", &c.image]);
    assert_eq!((code, out.trim()), (0, "chromeos"));
    let (_code, out, _err) = c.t.run(&["detect", &c.image, "--json"]);
    assert_eq!(json(&out)["kind"], "chromeos");
    assert_eq!(json(&out)["method"], "content");
}

#[test]
fn write_auto_selects_chromeos() {
    let c = chrome_case();
    let (code, out, _err) = c.t.run(&["write", "--iso", &c.image, "--disk", "disk9", "--dry-run", "--json"]);
    assert_eq!(code, 0);
    let plan = json(&out);
    assert_eq!(plan["mode"], "chromeos");
    assert!(plan["steps"].as_array().unwrap().iter().any(|st| st.as_str().unwrap().contains("byte for byte")));
}

#[test]
fn write_chromeos_passes_the_mode_to_the_engine() {
    let c = chrome_case();
    let (code, _out, _err) = c.t.run(&["write", "--iso", &c.image, "--disk", "disk9", "--yes"]);
    assert_eq!(code, 0);
    assert_eq!(c.t.engine.builds()[0].mode, Mode::ChromeOs);
}

#[test]
fn a_small_drive_gets_a_warning_but_is_allowed() {
    let c = chrome_case();
    let (code, _out, err) = c.t.run(&["write", "--iso", &c.image, "--disk", "disk8", "--dry-run"]);
    assert_eq!(code, 0);
    assert!(err.contains("16 GB or larger"), "{err}");
    assert!(err.contains("this one is 8.0 GB."), "{err}");
    assert!(err.contains("warning:"), "{err}");
}

#[test]
fn an_image_bigger_than_the_drive_is_refused() {
    let c = chrome_case();
    c.t.engine.set_disks(vec![Disk { size: 2 * MIB, ..fake_disks().remove(0) }]);
    let (code, _out, err) = c.t.run(&["write", "--iso", &c.image, "--disk", "disk9", "--dry-run"]);
    assert_eq!(code, 1);
    assert!(err.contains("larger than the drive"), "{err}");
}

#[test]
fn the_zip_is_refused_with_a_hint() {
    let c = chrome_case();
    let mut zip = vec![0u8; 2 * MIB as usize];
    zip[..4].copy_from_slice(b"PK\x03\x04");
    let path = c.t.write_file("flex.zip", &zip);
    let (code, _out, err) = c.t.run(&["write", "--iso", &path, "--disk", "disk9", "--mode", "chromeos", "--dry-run"]);
    assert_eq!(code, 1);
    assert!(err.contains("ZIP archive"), "{err}");
}

#[test]
fn mode_choices_include_chromeos() {
    let t = T::new();
    let (code, out, _err) = t.run(&["write", "--help"]);
    assert_eq!(code, 0);
    assert!(out.contains("chromeos"));
}

// ===== CliDetailsTests =====
#[test]
fn a_wrong_confirmation_exits_with_the_usage_code() {
    let mut t = T::new();
    t.interactive = true;
    let iso = t.iso();
    let (code, _out, err) = t.run_in(&["write", "--iso", &iso, "--disk", "disk9"], "nope\n");
    assert_eq!(code, 2);
    assert_eq!(crate::cli::EXIT_USAGE, 2);
    assert!(err.contains("did not match"), "{err}");
    assert!(t.engine.builds().is_empty());
}

#[test]
fn the_file_name_never_selects_the_windows_mode() {
    let t = T::new();
    for name in ["darwin-linux.img", "win11.iso", "Windows_install.iso"] {
        let path = t.make_iso(name, 2 * MIB, false);
        let (out, err) = (Buf::default(), Buf::default());
        let env = t.env("", &out, &err);
        assert_eq!(cli_detect_kind(&env, Path::new(&path)), (IsoKind::Unknown, "none"), "{name}");
        let (_code, out, _err) = t.run(&["detect", &path, "--json"]);
        assert_eq!(json(&out)["kind"], "unknown", "{name}");
    }
}

#[test]
fn auto_mode_demands_an_explicit_mode_for_unknown_content() {
    let t = T::new();
    let path = t.make_iso("darwin-linux.img", 2 * MIB, false);
    let (code, _out, err) = t.run(&["write", "--iso", &path, "--disk", "disk9", "--yes"]);
    assert_eq!(code, 2);
    assert!(err.contains("--mode"), "{err}");
    assert!(
        err.contains(
            "Could not tell what kind of image this is. Pass --mode windows, --mode linux, --mode chromeos or --mode macos."
        ),
        "{err}"
    );
    assert!(t.engine.builds().is_empty());
}

#[test]
fn the_method_stays_accurate() {
    let t = T::new();
    let hybrid = t.make_iso("windows.iso", 2 * MIB, true); // name says windows, content is hybrid
    let (out, err) = (Buf::default(), Buf::default());
    let env = t.env("", &out, &err);
    assert_eq!(cli_detect_kind(&env, Path::new(&hybrid)), (IsoKind::Linux, "boot-signature"));
    *lock(&t.engine.detect) = Some(IsoKind::Windows);
    assert_eq!(cli_detect_kind(&env, Path::new(&hybrid)), (IsoKind::Windows, "content"));
}

#[test]
fn plain_detect_prints_unknown() {
    let t = T::new();
    let (code, out, _err) = t.run(&["detect", &t.make_iso("mystery.bin", 2 * MIB, false)]);
    assert_eq!((code, out.as_str()), (0, "unknown\n"));
}

// ===== what only the port has =====
#[test]
fn a_panic_in_a_command_is_reported_not_propagated() {
    let t = T::new();
    t.engine.disks_panic.store(true, Ordering::SeqCst);
    let (code, out, err) = t.run(&["list"]);
    assert_eq!((code, out.as_str()), (1, ""));
    assert!(err.contains("error: Unexpected failure (panic): the drive list exploded"), "{err}");
    let (_code, _out, err) = t.run(&["--debug", "list"]);
    assert!(err.contains("Traceback"), "{err}");
}

#[test]
fn errors_go_to_stderr_with_the_error_prefix() {
    let t = T::new();
    let (code, out, err) = t.run(&["detect", &t.path("nope")]);
    assert_eq!((code, out.as_str()), (1, ""));
    assert!(err.starts_with("error: Not a file: "), "{err}");
}

#[test]
fn colour_is_only_used_on_a_terminal_without_no_color() {
    let mut t = T::new();
    t.env_vars = vec![];
    let (out, err) = (Buf::default(), Buf::default());
    let env = t.env("", &out, &err);
    env.error("plain");
    assert_eq!(err.text(), "error: plain\n"); // the fake streams are not terminals
}
