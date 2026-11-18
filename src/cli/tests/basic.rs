//! Port of tests/test_cli.py (the parts that belong to the command line: `CliPrivilegeTests` test `CliPrivilege`,
//! which lives in privilege.rs, and `ModuleEntryPointTests` is tests/test_cli_a7.rs).

use super::*;
use crate::cli::io::{json_dumps, obj, CliLogger, CliProgress, J};
use crate::cli::{normalize_typed_identifier_for, CliError, EXIT_INTERRUPTED};
use crate::constants::{
    ENV_ALLOW_ANY_HOST, ENV_AUDIT_LOG, ENV_DISABLE_AUDIT_LOG, ENV_EXPECTED_SHA256, ENV_LANG, ENV_TRUSTED_HOSTS, VERSION,
};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

fn sha_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

fn s(text: &str) -> String {
    text.to_string()
}

// ===== VersionAndHelpTests =====
#[test]
fn version() {
    let t = T::new();
    // The version itself is pinned in tests/test_docs_consistency.py (one place to touch on a bump).
    assert_eq!(t.run(&["--version"]), (0, format!("epma-usb-creator {VERSION}\n"), s("")));
}

#[test]
fn help_documents_commands_and_exit_codes() {
    let t = T::new();
    let (code, out, _err) = t.run(&["--help"]);
    assert_eq!(code, 0);
    for word in ["list", "detect", "sha256", "write", "gui", "exit codes", "130", "NO_COLOR"] {
        assert!(out.contains(word), "{word} is missing from:\n{out}");
    }
}

#[test]
fn help_lists_every_exit_code_and_environment_variable() {
    // --help is generated from CLI_EXIT_CODE_HELP / CLI_ENV_HELP; this fails when a new EXIT_* or ENV_* constant is
    // added to the program but not to those lists.
    let t = T::new();
    let (_code, out, _err) = t.run(&["--help"]);
    use crate::cli::{EXIT_EJECT_FAILED, EXIT_ERROR, EXIT_OK, EXIT_USAGE, EXIT_VERIFY_FAILED};
    for code in [EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_VERIFY_FAILED, EXIT_EJECT_FAILED, EXIT_INTERRUPTED] {
        assert!(Regex::new(&format!(r"(?m)^  {code} ")).unwrap().is_match(&out), "exit code {code}:\n{out}");
    }
    for name in
        [ENV_AUDIT_LOG, ENV_DISABLE_AUDIT_LOG, ENV_TRUSTED_HOSTS, ENV_ALLOW_ANY_HOST, ENV_EXPECTED_SHA256, ENV_LANG]
    {
        assert!(Regex::new(&format!(r"(?m)^  {name} ")).unwrap().is_match(&out), "{name}:\n{out}");
    }
    assert!(Regex::new(r"(?m)^  NO_COLOR ").unwrap().is_match(&out));
}

#[test]
fn help_keeps_the_epilog_unwrapped_and_at_the_end() {
    // The Python epilog is printed verbatim (RawDescriptionHelpFormatter): no line of it may be re-wrapped.
    let t = T::new();
    let (_code, out, _err) = t.run(&["--help"]);
    for line in crate::cli::cli_epilog().lines() {
        assert!(out.lines().any(|l| l == line), "the line {line:?} was altered in:\n{out}");
    }
}

#[test]
fn write_help_documents_flags() {
    let t = T::new();
    let (code, out, _err) = t.run(&["write", "--help"]);
    assert_eq!(code, 0);
    for flag in ["--iso", "--disk", "--mode", "--yes", "--dry-run", "--no-eject", "--json"] {
        assert!(out.contains(flag), "{flag}");
    }
}

#[test]
fn there_is_no_way_to_skip_verification() {
    let t = T::new();
    assert!(!t.run(&["write", "--help"]).1.replace("verify it", "").contains("verify"));
    let iso = t.iso();
    for flag in ["--no-verify", "--skip-verify", "--no"] {
        let (code, _out, _err) = t.run(&t.write_args(&iso, &["--yes", flag]));
        assert_eq!(code, 2, "{flag}");
    }
    assert!(t.engine.builds().is_empty());
}

#[test]
fn usage_errors_exit_2() {
    let t = T::new();
    let cases: [&[&str]; 6] = [
        &["bogus"],
        &["write"],
        &["write", "--iso", "x"],
        &["sha256"],
        &["list", "--nope"],
        &["write", "--iso", "x", "--disk", "y", "--mode", "weird"],
    ];
    for argv in cases {
        let (code, out, err) = t.run(argv);
        assert_eq!(code, 2, "{argv:?}");
        assert_eq!(out, "", "{argv:?}");
        assert!(err.contains("usage:"), "{argv:?}: {err}");
    }
}

#[test]
fn usage_errors_are_worded_like_argparse() {
    let t = T::new();
    let (_c, _o, err) = t.run(&["write", "--iso", "x"]);
    assert!(err.contains("epma-usb-creator write: error: the following arguments are required: --disk"), "{err}");
    let (_c, _o, err) = t.run(&["write", "--iso", "x", "--disk", "y", "--mode", "weird"]);
    assert!(
        err.contains("argument --mode: invalid choice: 'weird' (choose from 'auto', 'windows', 'linux', 'chromeos')"),
        "{err}"
    );
    let (_c, _o, err) = t.run(&["list", "--nope"]);
    assert!(err.contains("unrecognized arguments: --nope"), "{err}");
    let (_c, _o, err) = t.run(&["bogus"]);
    assert!(err.contains("invalid choice: 'bogus'"), "{err}");
}

// ===== GuiDispatchTests =====
#[test]
fn no_arguments_and_gui_open_the_window() {
    for argv in [&[][..], &["gui"][..], &["--debug"][..]] {
        let t = T::new();
        assert_eq!(t.run(argv), (0, s(""), s("")), "{argv:?}");
        assert_eq!(t.engine.gui_calls.load(Ordering::SeqCst), 1, "{argv:?}");
    }
}

#[test]
fn the_window_decides_its_own_exit_code() {
    // The Python tests for a missing Tk print the hint from gui::run (A8); the command line only passes the code on.
    for argv in [&[][..], &["gui"][..]] {
        let t = T::new();
        t.engine.gui_code.store(1, Ordering::SeqCst);
        assert_eq!(t.run(argv), (1, s(""), s("")));
    }
}

#[test]
fn cli_commands_do_not_open_the_window() {
    let t = T::new();
    assert_eq!(t.run(&["list"]).0, 0);
    assert_eq!(t.engine.gui_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn an_unsupported_system_is_refused_for_the_commands_that_need_one() {
    let t = T::new();
    t.engine.supported.store(false, Ordering::SeqCst);
    for argv in [&["list"][..], &["gui"][..], &[][..]] {
        let (code, out, err) = t.run(argv);
        assert_eq!((code, out.as_str()), (1, ""), "{argv:?}");
        assert!(err.contains("This script supports Windows 11, macOS and Linux only."), "{err}");
    }
    // detect and sha256 work anywhere
    let iso = t.iso();
    assert_eq!(t.run(&["detect", &iso]).0, 0);
}

// ===== ListTests =====
#[test]
fn list_table() {
    let t = T::new();
    let (code, out, _err) = t.run(&["list"]);
    assert_eq!(code, 0);
    let lines = first_lines(&out);
    assert_eq!(lines[0].split_whitespace().collect::<Vec<_>>(), ["ID", "SIZE", "MODEL", "LABEL"]);
    assert!(lines[1].contains("disk9") && lines[1].contains("16.0 GB"), "{}", lines[1]);
    assert!(lines[2].contains("disk8") && lines[2].contains("Fake Stick"), "{}", lines[2]);
    assert_eq!(lines.len(), 3);
}

#[test]
fn list_table_without_any_model_has_no_model_column() {
    let t = T::new();
    t.engine.set_disks(vec![fake_disks().remove(0)]);
    let (_code, out, _err) = t.run(&["list"]);
    assert_eq!(first_lines(&out)[0].split_whitespace().collect::<Vec<_>>(), ["ID", "SIZE", "LABEL"]);
    assert!(out.lines().all(|l| l == l.trim_end()), "no trailing blanks");
}

#[test]
fn list_json_shape() {
    let t = T::new();
    let (code, out, err) = t.run(&["list", "--json"]);
    assert_eq!((code, err.as_str()), (0, ""));
    let data = json(&out);
    let ids: Vec<&str> = data["disks"].as_array().unwrap().iter().map(|d| d["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["disk9", "disk8"]);
    let first = &data["disks"][0];
    assert_eq!(first["size"], 16 * GIB);
    assert_eq!(first["size_human"], "16.0 GB");
    assert!(first.get("label").is_some());
    assert_eq!(data["disks"][1]["model"], "Fake Stick");
}

#[test]
fn list_json_is_written_like_python_json_dumps() {
    let t = T::new();
    t.engine.set_disks(vec![fake_disks().remove(0)]);
    let (_code, out, _err) = t.run(&["list", "--json"]);
    // two-space indent, ensure_ascii (the em dash of the label is escaped), keys in the order they were built
    assert_eq!(
        out,
        "{\n  \"disks\": [\n    {\n      \"id\": \"disk9\",\n      \"size\": 17179869184,\n      \"label\": \"/dev/disk9 \\u2014 16.0 GB\",\n      \"model\": null,\n      \"size_human\": \"16.0 GB\"\n    }\n  ]\n}\n"
    );
}

#[test]
fn list_with_no_drives() {
    let t = T::new();
    t.engine.set_disks(Vec::new());
    let (code, out, err) = t.run(&["list"]);
    assert_eq!((code, out.as_str()), (0, ""));
    assert!(err.contains("No USB drives"), "{err}");
    assert_eq!(json(&t.run(&["list", "--json"]).1), serde_json::json!({"disks": []}));
}

#[test]
fn list_enumeration_failure() {
    let t = T::new();
    *lock(&t.engine.disks_error) = Some(s("diskutil"));
    let (code, out, err) = t.run(&["list"]);
    assert_eq!((code, out.as_str()), (1, ""));
    assert!(err.contains("Could not list the drives"), "{err}");
    assert!(!err.contains("Traceback"));
}

#[test]
fn labels_survive_a_terminal_that_cannot_take_them() {
    // Python: UnicodeEncodeError on an ASCII terminal. Here text is written as UTF-8 bytes; what must hold is that a
    // stream that fails (a closed pipe) never takes the program down.
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _data: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }
    }
    let t = T::new();
    let (out, err) = (Buf::default(), Buf::default());
    let mut env = t.env("", &out, &err);
    env.out("disk9 \u{2014} 16 GB");
    assert_eq!(out.text(), "disk9 \u{2014} 16 GB\n");
    env.out = OutStream::new(Box::new(Broken), false);
    env.out("disk9 \u{2014} 16 GB"); // must not panic
    env.error("still fine");
    assert!(err.text().contains("error: still fine"));
}

// ===== DetectTests =====
#[test]
fn detect_signature_heuristic_and_no_filename_guess() {
    let t = T::new();
    let win_named = t.make_iso("Win11_English_x64.iso", 2 * MIB, false);
    let ubuntu = t.make_iso("ubuntu-24.04.iso", 2 * MIB, true);
    let other = t.make_iso("mystery.iso", 2 * MIB, false);
    assert_eq!(t.run(&["detect", &ubuntu]).1, "linux\n");
    assert_eq!(t.run(&["detect", &other]).1, "unknown\n");
    // The name alone never selects the destructive Windows mode (see test_fixes_engine).
    assert_eq!(t.run(&["detect", &win_named]).1, "unknown\n");
}

#[test]
fn detect_json() {
    let t = T::new();
    let iso = t.make_iso("ubuntu.iso", 2 * MIB, true);
    let data = json(&t.run(&["detect", &iso, "--json"]).1);
    assert_eq!(data["kind"], "linux");
    assert_eq!(data["method"], "boot-signature");
    assert!(Path::new(data["iso"].as_str().unwrap()).is_absolute());
}

#[test]
fn detect_uses_the_content_detector() {
    let t = T::new();
    let win_named = t.make_iso("win-looking.iso", 2 * MIB, false);
    *lock(&t.engine.detect) = Some(IsoKind::Linux);
    let (_code, out, _err) = t.run(&["detect", &win_named, "--json"]);
    assert_eq!(*lock(&t.engine.detect_calls), vec![PathBuf::from(&win_named)]);
    let data = json(&out);
    assert_eq!((data["kind"].as_str(), data["method"].as_str()), (Some("linux"), Some("content")));
}

#[test]
fn an_unknown_content_result_falls_back_to_the_boot_signature() {
    let t = T::new();
    let hybrid = t.make_iso("ubuntu.iso", 2 * MIB, true);
    let plain = t.make_iso("windows.iso", 2 * MIB, false);
    *lock(&t.engine.detect) = Some(IsoKind::Unknown);
    assert_eq!(t.run(&["detect", &hybrid]).1, "linux\n");
    assert_eq!(t.run(&["detect", &plain]).1, "unknown\n");
}

#[test]
fn detect_missing_file() {
    let t = T::new();
    let (code, out, err) = t.run(&["detect", &t.path("nope.iso")]);
    assert_eq!((code, out.as_str()), (1, ""));
    assert!(err.contains("Not a file"), "{err}");
}

// ===== Sha256Tests =====
fn sha_fixture(t: &T) -> (String, String) {
    let data = b"epma".repeat(300_000);
    (t.write_file("data.iso", &data), sha_hex(&data))
}

#[test]
fn sha256_prints_digest_and_filename() {
    let t = T::new();
    let (iso, digest) = sha_fixture(&t);
    let (code, out, err) = t.run(&["sha256", &iso]);
    assert_eq!(code, 0);
    assert_eq!(out, format!("{digest}  {iso}\n"));
    assert!(err.contains('%'), "progress goes to stderr: {err}");
}

#[test]
fn sha256_matching_expected_value() {
    let t = T::new();
    let (iso, digest) = sha_fixture(&t);
    for expected in [digest.clone(), digest.to_uppercase(), format!("sha256:{digest}"), format!("  {digest}\n")] {
        let (code, out, err) = t.run(&["sha256", &iso, "--expected", &expected]);
        assert_eq!(code, 0, "{expected:?}");
        assert!(out.contains(&digest));
        assert!(err.contains("matches"), "{err}");
    }
}

#[test]
fn sha256_mismatch_exits_3_but_still_prints_digest() {
    let t = T::new();
    let (iso, digest) = sha_fixture(&t);
    let (code, out, err) = t.run(&["sha256", &iso, "--expected", &"0".repeat(64)]);
    assert_eq!(code, 3);
    assert!(out.contains(&digest));
    assert!(err.contains("does not match"), "{err}");
    assert!(err.contains(&format!("expected: {}", "0".repeat(64))) && err.contains(&format!("actual:   {digest}")));
}

#[test]
fn sha256_malformed_expected_is_a_usage_error() {
    let t = T::new();
    let (iso, _digest) = sha_fixture(&t);
    for bad in ["abc".to_string(), "z".repeat(64), "0".repeat(63)] {
        let (code, out, err) = t.run(&["sha256", &iso, "--expected", &bad]);
        assert_eq!((code, out.as_str()), (2, ""), "{bad}");
        assert!(err.contains("64-character"), "{err}");
    }
}

#[test]
fn sha256_json() {
    let t = T::new();
    let (iso, digest) = sha_fixture(&t);
    let data = json(&t.run(&["sha256", &iso, "--json", "--expected", &digest]).1);
    assert_eq!(data, serde_json::json!({"file": iso, "sha256": digest, "expected": digest, "match": true}));
    let data = json(&t.run(&["sha256", &iso, "--json"]).1);
    assert!(data["match"].is_null());
    assert!(data["expected"].is_null());
}

#[test]
fn sha256_missing_file() {
    let t = T::new();
    let (code, out, err) = t.run(&["sha256", &t.path("nope")]);
    assert_eq!((code, out.as_str()), (1, ""));
    assert!(err.contains("Not a file"), "{err}");
}

#[test]
fn the_hashing_helper_reports_progress_up_to_the_whole_file() {
    // Python: cli_sha256_file(chunk=500_000) -> three reports. The chunk size now belongs to hash::sha256_file; what
    // the command line owns is the shape of the reports: (done, total, "Computing SHA-256...") ending at the total.
    let t = T::new();
    let (iso, digest) = sha_fixture(&t);
    let (out, err) = (Buf::default(), Buf::default());
    let env = t.env("", &out, &err);
    let progress = env.new_progress();
    let got = crate::cli::commands::cli_sha256_file(&env, Path::new(&iso), None, &progress).unwrap();
    assert_eq!(got, digest);
    let text = err.text();
    assert!(text.contains("Computing SHA-256...") && text.contains("100.0%"), "{text}");
    assert!(text.contains("1.1 MB / 1.1 MB"), "{text}");
}

#[test]
fn sha256_stops_on_ctrl_c_with_exit_130() {
    let t = T::new();
    let (iso, _digest) = sha_fixture(&t);
    let presses = t.interrupts.clone();
    *lock(&t.engine.sha) = Some(Box::new(move |_, cancel| {
        presses.press();
        let cancel = cancel.unwrap().clone();
        let until = Instant::now() + Duration::from_secs(5);
        while !cancel.is_set() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(2));
        }
        Err(Error::canceled())
    }));
    let (code, out, err) = t.run(&["sha256", &iso]);
    assert_eq!((code, out.as_str()), (EXIT_INTERRUPTED, ""));
    assert!(err.contains("Interrupted."), "{err}");
    assert!(!err.contains("error:"), "{err}");
}

// ===== WriteValidationTests =====
fn write_with_disk(iso: &str, disk: &str, extra: &[&str]) -> Vec<String> {
    let mut argv = vec![s("write"), s("--iso"), s(iso), s("--disk"), s(disk)];
    argv.extend(extra.iter().map(|e| s(e)));
    argv
}

fn run_vec(t: &T, argv: &[String]) -> (i32, String, String) {
    let refs: Vec<&str> = argv.iter().map(|a| a.as_str()).collect();
    t.run(&refs)
}

#[test]
fn everything_is_validated_before_anything_runs() {
    let t = T::new();
    let iso = t.iso();
    let tiny = t.write_file("tiny.iso", b"x");
    let plain = t.make_iso("plain.iso", 2 * MIB, false);
    let cases: Vec<(&str, Vec<String>)> = vec![
        ("not a valid disk identifier", write_with_disk(&iso, "disk4; rm -rf /", &["--yes"])),
        ("not an eligible USB drive", write_with_disk(&iso, "disk3", &["--yes"])),
        ("no longer exists", write_with_disk(&t.path("nope.iso"), "disk9", &["--yes"])),
        ("too small", write_with_disk(&tiny, "disk9", &["--yes"])),
        ("not a bootable hybrid", write_with_disk(&plain, "disk9", &["--yes", "--mode", "linux"])),
    ];
    for (fragment, argv) in cases {
        let (code, out, err) = run_vec(&t, &argv);
        assert_eq!((code, out.as_str()), (1, ""), "{fragment}");
        assert!(err.contains(fragment), "{fragment}: {err}");
    }
    assert!(t.engine.builds().is_empty());
    assert_eq!(t.engine.auth_calls(), 0);
}

#[test]
fn dev_prefix_is_accepted() {
    let t = T::new();
    let iso = t.iso();
    let (code, out, _err) = run_vec(&t, &write_with_disk(&iso, "/dev/disk9", &["--dry-run"]));
    assert_eq!(code, 0);
    assert!(out.contains("/dev/disk9"), "{out}");
}

#[test]
fn auto_mode_needs_a_recognisable_iso() {
    let t = T::new();
    let mystery = t.make_iso("mystery.iso", 2 * MIB, false);
    let (code, _out, err) = t.run(&t.write_args(&mystery, &["--yes"]));
    assert_eq!(code, 2);
    assert!(err.contains("--mode"), "{err}");
    assert!(t.engine.builds().is_empty());
}

#[test]
fn explicit_mode_overrides_detection_with_a_warning() {
    let t = T::new();
    let win = t.make_iso("win11.iso", 2 * MIB, true);
    *lock(&t.engine.detect) = Some(IsoKind::Windows);
    let (code, out, err) = t.run(&t.write_args(&win, &["--dry-run", "--mode", "linux"]));
    assert_eq!(code, 0);
    assert!(err.contains("looks like a windows image"), "{err}");
    assert!(out.contains("Mode : linux"), "{out}");
}

#[test]
fn iso_larger_than_drive_is_refused_for_raw_writes() {
    let t = T::new();
    t.engine.set_disks(vec![Disk { id: s("disk9"), size: MIB, label: s("tiny"), ..Disk::default() }]);
    let iso = t.make_iso("ubuntu.iso", 2 * MIB, true);
    let (code, _out, err) = t.run(&t.write_args(&iso, &["--yes"]));
    assert_eq!(code, 1);
    assert!(err.contains("larger than the drive"), "{err}");
    assert!(t.engine.builds().is_empty());
}

#[test]
fn missing_tools_are_reported() {
    let t = T::new();
    *lock(&t.engine.missing) = vec![s("wimlib-imagex")];
    let win = t.make_iso("win11.iso", 2 * MIB, false);
    let (code, _out, err) = t.run(&t.write_args(&win, &["--yes", "--mode", "windows"]));
    assert_eq!(code, 1);
    assert!(err.contains("wimlib-imagex"), "{err}");
    assert!(err.contains("Missing required tools: wimlib-imagex. Install them with your package manager."), "{err}");
    assert!(t.engine.builds().is_empty());
}

// ===== WriteDryRunTests =====
#[test]
fn dry_run_prints_plan_and_touches_nothing() {
    let t = T::new();
    let iso = t.make_iso("ubuntu.iso", 2 * MIB, true);
    let (code, out, err) = t.run(&t.write_args(&iso, &["--dry-run"]));
    assert_eq!(code, 0);
    for text in ["Plan", "/dev/disk9", "16.0 GB", &iso, "Mode : linux", "byte for byte", "Eject the drive"] {
        assert!(out.contains(text), "{text} missing from:\n{out}");
    }
    assert!(err.contains("Dry run"), "{err}");
    assert!(t.engine.builds().is_empty());
    assert_eq!(t.engine.auth_calls(), 0);
}

#[test]
fn dry_run_plan_text_is_the_python_one() {
    let t = T::new();
    let iso = t.make_iso("ubuntu.iso", 2 * MIB, true);
    let (_code, out, _err) = t.run(&t.write_args(&iso, &["--dry-run"]));
    assert_eq!(
        out,
        format!(
            "Plan\n  Disk : /dev/disk9  16.0 GB  /dev/disk9 \u{2014} 16.0 GB\n  ISO  : {iso} (2.0 MB)\n  Mode : linux\n  Steps:\n    \
             1. Re-check that /dev/disk9 is still the listed USB drive\n    \
             2. Unmount /dev/disk9 and write the image to it byte for byte\n    \
             3. Read the drive back and compare it with the image\n    4. Eject the drive\n"
        )
    );
}

#[test]
fn windows_plan() {
    let t = T::new();
    let iso = t.make_iso("Win11.iso", 2 * MIB, false);
    let (code, out, _err) = t.run(&t.write_args(&iso, &["--dry-run", "--mode", "windows"]));
    assert_eq!(code, 0);
    assert!(out.contains("GPT + FAT32 ('WIN11USB')"), "{out}");
    assert!(out.contains("Mode : windows"));
    assert!(out.contains("Verify the copied files"));
}

#[test]
fn a_model_is_shown_in_the_plan() {
    let t = T::new();
    let iso = t.iso();
    let (_code, out, _err) = t.run(&["write", "--iso", &iso, "--disk", "disk8", "--dry-run"]);
    assert!(out.contains("  Model: Fake Stick\n"), "{out}");
}

#[test]
fn dry_run_never_needs_confirmation() {
    let t = T::new();
    let iso = t.iso();
    assert_eq!(t.run(&t.write_args(&iso, &["--dry-run"])).0, 0);
}

#[test]
fn dry_run_json_plan() {
    let t = T::new();
    let iso = t.make_iso("ubuntu.iso", 2 * MIB, true);
    let (code, out, err) = t.run(&t.write_args(&iso, &["--dry-run", "--json", "--no-eject"]));
    assert_eq!((code, err.as_str()), (0, ""));
    let plan = json(&out);
    assert_eq!(plan["mode"], "linux");
    assert_eq!(plan["iso"], iso.as_str());
    assert_eq!(plan["iso_size"], 2 * MIB);
    assert_eq!(plan["disk"]["id"], "disk9");
    assert_eq!(plan["dry_run"], true);
    assert_eq!(plan["eject"], false);
    assert!(plan["steps"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .as_str()
        .unwrap()
        .contains("Leave the drive connected (--no-eject)"));
    // the keys come in the order of the Python plan dict
    let keys =
        ["iso", "iso_size", "mode", "disk", "identity", "steps", "eject", "dry_run", "hardening", "hardening_files"];
    let positions: Vec<usize> = keys.iter().map(|k| out.find(&format!("\n  \"{k}\"")).unwrap()).collect();
    assert!(positions.windows(2).all(|w| w[0] < w[1]), "{out}");
}

// ===== WriteConfirmationTests =====
#[test]
fn non_interactive_without_yes_is_refused() {
    let t = T::new();
    let iso = t.iso();
    let (code, out, err) = t.run(&t.write_args(&iso, &[]));
    assert_eq!((code, out.as_str()), (2, ""));
    assert!(err.contains("--yes"), "{err}");
    assert!(err.contains("Plan"), "the plan was still shown: {err}");
    assert!(t.engine.builds().is_empty());
    assert_eq!(t.engine.auth_calls(), 0);
}

#[test]
fn non_interactive_ignores_typed_input() {
    let t = T::new();
    let iso = t.iso();
    let (code, _out, _err) = t.run_in(&t.write_args(&iso, &[]), "disk9\n");
    assert_eq!(code, 2);
    assert!(t.engine.builds().is_empty());
    assert!(!t.stdin_touched.load(Ordering::SeqCst), "stdin must not even be read");
}

#[test]
fn interactive_user_must_type_the_disk_id() {
    let mut t = T::new();
    t.interactive = true;
    let iso = t.iso();
    let (code, _out, err) = t.run_in(&t.write_args(&iso, &[]), "disk9\n");
    assert_eq!(code, 0);
    assert!(err.contains("Type the disk id (disk9)"), "{err}");
    assert!(err.contains("This will PERMANENTLY ERASE all data on /dev/disk9."), "{err}");
    assert_eq!(t.engine.builds().len(), 1);
}

#[test]
fn interactive_wrong_or_empty_answer_aborts() {
    let mut t = T::new();
    t.interactive = true;
    let iso = t.iso();
    for answer in ["yes\n", "disk8\n", "\n", "", "DISK9\n", "/dev/disk9\n"] {
        lock(&t.engine.build_calls).clear();
        let (code, _out, err) = t.run_in(&t.write_args(&iso, &[]), answer);
        assert_eq!(code, 2, "{answer:?}"); // the documented code for a wrong confirmation
        assert!(err.contains("Nothing was changed"), "{answer:?}: {err}");
        assert!(t.engine.builds().is_empty(), "{answer:?}");
    }
}

#[test]
fn yes_skips_the_prompt() {
    let mut t = T::new();
    t.interactive = true;
    let iso = t.iso();
    let (code, _out, err) = t.run_in(&t.write_args(&iso, &["--yes"]), "");
    assert_eq!(code, 0);
    assert!(!err.contains("Type the disk id"));
}

#[test]
fn privileges_are_requested_after_confirmation_and_before_the_write() {
    let mut t = T::new();
    t.interactive = true;
    let iso = t.iso();
    t.run_in(&t.write_args(&iso, &[]), "disk9\n");
    let order: Vec<String> = t.engine.events().into_iter().filter(|e| e != "pin").collect();
    assert_eq!(order, ["auth", "build"]);
}

// ===== WriteRunTests =====
fn run_write(t: &T, iso: &str, extra: &[&str]) -> (i32, String, String) {
    let mut flags = vec!["--yes"];
    flags.extend_from_slice(extra);
    t.run(&t.write_args(iso, &flags))
}

#[test]
fn success_passes_the_right_arguments_to_the_engine() {
    let t = T::new();
    let iso = t.make_iso("ubuntu.iso", 2 * MIB, true);
    let seen = Arc::new(Mutex::new((false, false)));
    let probe = seen.clone();
    t.engine.on_build(move |_, ctx| {
        ctx.log("hello");
        ctx.report(1, 2, "x");
        *lock(&probe) = (ctx.progress.is_some(), ctx.cancel.is_some());
        Ok(true)
    });
    let (code, out, err) = run_write(&t, &iso, &[]);
    assert_eq!((code, out.as_str()), (0, ""));
    assert!(err.contains("ejected"), "{err}");
    let calls = t.engine.builds();
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    assert_eq!(call.iso, PathBuf::from(&iso));
    assert_eq!(call.dev, "disk9");
    assert_eq!(call.priv_addr, t.engine.priv_addr(), "the engine gets the command line's privilege helper");
    assert_eq!(call.mode, Mode::Linux);
    assert_eq!(call.expected_size, Some(16 * GIB));
    assert_eq!(call.hardening, Hardening::None);
    assert!(call.eject);
    assert_eq!(*lock(&seen), (true, true));
    assert_eq!(t.engine.auth_calls(), 1);
    assert_eq!(t.engine.priv_.cleared.load(Ordering::SeqCst), 1);
}

#[test]
fn windows_mode_on_macos_needs_no_privileges() {
    let t = T::new();
    // macOS: diskutil and hdiutil need no root, only the byte-for-byte modes do
    *lock(&t.engine.admin) = Admin::RawOnly;
    let win = t.make_iso("Win11.iso", 2 * MIB, false);
    let (code, _out, _err) = t.run(&t.write_args(&win, &["--yes", "--mode", "windows"]));
    assert_eq!(code, 0);
    assert_eq!(t.engine.auth_calls(), 0);
    assert_eq!(t.engine.builds()[0].mode, Mode::Windows);
}

#[test]
fn cancel_event_is_passed_to_the_engine() {
    let t = T::new();
    let iso = t.iso();
    let seen = Arc::new(Mutex::new(None));
    let probe = seen.clone();
    t.engine.on_build(move |_, ctx| {
        *lock(&probe) = ctx.cancel.map(|c| c.is_set());
        Ok(true)
    });
    assert_eq!(run_write(&t, &iso, &[]).0, 0);
    assert_eq!(*lock(&seen), Some(false));
}

#[test]
fn json_result_on_success() {
    let t = T::new();
    let iso = t.make_iso("ubuntu.iso", 2 * MIB, true);
    let (code, out, err) = run_write(&t, &iso, &["--json"]);
    assert_eq!(code, 0);
    let result = json(&out);
    for (key, expected) in [
        ("ok", serde_json::json!(true)),
        ("mode", serde_json::json!("linux")),
        ("iso", serde_json::json!(iso)),
        ("disk", serde_json::json!("disk9")),
        ("verified", serde_json::json!(true)),
        ("ejected", serde_json::json!(true)),
        ("error", serde_json::Value::Null),
        ("exit_code", serde_json::json!(0)),
    ] {
        assert_eq!(result[key], expected, "{key}");
    }
    assert!(result.get("elapsed_seconds").is_some());
    assert!(!err.contains("\"ok\""), "stdout carries the data, stderr the messages");
    // the keys come in the order of the Python result dict, elapsed_seconds last
    let order = ["ok", "mode", "iso", "disk", "verified", "ejected", "error", "exit_code", "elapsed_seconds"];
    let positions: Vec<usize> = order.iter().map(|k| out.find(&format!("\n  \"{k}\"")).unwrap()).collect();
    assert!(positions.windows(2).all(|w| w[0] < w[1]), "{out}");
}

#[test]
fn eject_failure_exits_4() {
    let t = T::new();
    let iso = t.iso();
    t.engine.on_build(|_, _| Ok(false));
    let (code, out, err) = run_write(&t, &iso, &["--json"]);
    assert_eq!(code, 4);
    let result = json(&out);
    assert_eq!(result["verified"], true);
    assert_eq!(result["ejected"], false);
    assert_eq!(result["exit_code"], 4);
    assert_eq!(result["error"], "eject failed");
    assert!(err.contains("could not be ejected"), "{err}");
}

#[test]
fn no_eject_is_passed_to_the_engine_and_is_not_a_failure() {
    let t = T::new();
    let iso = t.iso();
    t.engine.on_build(|_, _| Ok(false));
    let (code, _out, err) = run_write(&t, &iso, &["--no-eject"]);
    assert_eq!(code, 0); // not ejecting on request is not a failure
    assert!(!t.engine.builds()[0].eject);
    assert!(err.contains("left connected"), "{err}");
}

#[test]
fn eject_is_requested_by_default() {
    let t = T::new();
    let iso = t.iso();
    let (code, _out, _err) = run_write(&t, &iso, &[]);
    assert_eq!(code, 0);
    assert!(t.engine.builds()[0].eject);
}

#[test]
fn verification_failure_exits_3() {
    let t = T::new();
    let iso = t.iso();
    t.engine.on_build(|_, _| Err(Error::runtime("Verification FAILED: the data differs near byte 4096.")));
    let (code, out, err) = run_write(&t, &iso, &["--json"]);
    assert_eq!(code, 3);
    let result = json(&out);
    assert_eq!(result["ok"], false);
    assert_eq!(result["verified"], false);
    assert!(result["error"].as_str().unwrap().contains("Verification FAILED"));
    assert_eq!(result["exit_code"], 3);
    assert!(err.contains("Verification FAILED"), "{err}");
    // "could not complete the verification" is the other spelling of the same thing
    t.engine.on_build(|_, _| Err(Error::runtime("The engine could not complete the verification.")));
    assert_eq!(run_write(&t, &iso, &[]).0, 3);
}

#[test]
fn engine_errors_exit_1_without_traceback() {
    let t = T::new();
    let iso = t.iso();
    type Make = fn() -> Error;
    let makers: [(&str, Make); 4] = [
        ("Privileged command failed", || Error::runtime("Privileged command failed")),
        ("bad value", || Error::value("bad value")),
        ("device vanished", || Error::Io(io::Error::other("device vanished"))),
        ("panic", || panic!("oops")),
    ];
    for (name, make) in makers {
        t.engine.on_build(move |_, _| Err(make()));
        let (code, out, err) = run_write(&t, &iso, &[]);
        assert_eq!((code, out.as_str()), (1, ""), "{name}");
        assert!(!err.contains("Traceback"), "{name}: {err}");
        assert!(err.contains("error:"), "{name}: {err}");
    }
    // an OS error and a bug are "unexpected" and say so
    t.engine.on_build(|_, _| Err(Error::Io(io::Error::other("device vanished"))));
    assert!(run_write(&t, &iso, &[]).2.contains("Unexpected failure (OSError): device vanished"));
    t.engine.on_build(|_, _| -> Result<bool> { panic!("oops") });
    assert!(run_write(&t, &iso, &[]).2.contains("Unexpected failure (panic): oops"));
}

#[test]
fn debug_shows_the_details() {
    let t = T::new();
    let iso = t.iso();
    t.engine.on_build(|_, _| -> Result<bool> { panic!("oops") });
    let mut argv = vec!["--debug"];
    argv.extend(t.write_args(&iso, &["--yes"]));
    let (code, _out, err) = t.run(&argv);
    assert_eq!(code, 1);
    assert!(err.contains("Traceback"), "{err}");
    // and the flag is accepted after the command too
    let (code, _out, err) = t.run(&t.write_args(&iso, &["--yes", "--debug"]));
    assert_eq!(code, 1);
    assert!(err.contains("Traceback"), "{err}");
}

#[test]
fn recent_log_lines_are_shown_on_failure() {
    let t = T::new();
    let iso = t.iso();
    t.engine.on_build(|_, ctx| {
        ctx.log("$ diskutil eraseDisk");
        ctx.log("Error: could not unmount");
        Err(Error::runtime("Command failed (exit code 1)"))
    });
    let (code, _out, err) = run_write(&t, &iso, &[]);
    assert_eq!(code, 1);
    assert!(err.contains("Last log lines:"), "{err}");
    assert!(err.contains("  $ diskutil eraseDisk"), "{err}");
}

#[test]
fn keyboard_interrupt_exits_130() {
    let t = T::new();
    let iso = t.iso();
    let presses = t.interrupts.clone();
    t.engine.on_build(move |_, _| {
        // the second Ctrl-C forces the quit while the engine is still busy
        presses.press();
        presses.press();
        std::thread::sleep(Duration::from_secs(2));
        Err(Error::runtime("too late"))
    });
    let started = Instant::now();
    let (code, out, err) = run_write(&t, &iso, &["--json"]);
    assert_eq!(code, EXIT_INTERRUPTED);
    assert_eq!(json(&out)["error"], "interrupted");
    assert!(err.contains("must not be used"), "{err}");
    assert!(started.elapsed() < Duration::from_millis(1500), "the forced quit must not wait for the engine");
    assert_eq!(t.engine.pin_log().last().unwrap(), &(s("disk9"), None));
}

#[test]
fn the_first_ctrl_c_sets_the_cancel_flag_and_exits_130() {
    let t = T::new();
    let iso = t.iso();
    let presses = t.interrupts.clone();
    let seen = Arc::new(Mutex::new(false));
    let probe = seen.clone();
    t.engine.on_build(move |_, ctx| {
        presses.press();
        let cancel = ctx.cancel.unwrap().clone();
        let until = Instant::now() + Duration::from_secs(5);
        while !cancel.is_set() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(2));
        }
        *lock(&probe) = cancel.is_set();
        Err(Error::runtime("Canceled"))
    });
    let (code, _out, err) = run_write(&t, &iso, &[]);
    assert_eq!(code, EXIT_INTERRUPTED);
    assert!(*lock(&seen), "the engine saw its cancel flag set");
    assert!(err.contains("press Ctrl-C again"), "{err}");
    assert!(err.contains("Interrupted: finishing safely (unmounting)"), "{err}");
}

#[test]
fn a_ctrl_c_that_arrives_too_late_does_not_turn_a_success_into_a_failure() {
    let t = T::new();
    let iso = t.iso();
    let presses = t.interrupts.clone();
    t.engine.on_build(move |_, _| {
        presses.press();
        Ok(true)
    });
    assert_eq!(run_write(&t, &iso, &[]).0, 0);
}

#[test]
fn privilege_failure_stops_before_the_engine() {
    let t = T::new();
    let iso = t.iso();
    *lock(&t.engine.priv_.auth_error) = Some(s("Could not obtain administrator privileges"));
    let (code, _out, err) = run_write(&t, &iso, &[]);
    assert_eq!(code, 1);
    assert!(err.contains("administrator privileges"), "{err}");
    assert!(t.engine.builds().is_empty());
    assert_eq!(t.engine.priv_.cleared.load(Ordering::SeqCst), 1, "the credential is forgotten whatever happens");
}

#[test]
fn progress_and_log_reach_stderr_only() {
    let t = T::new();
    let iso = t.iso();
    t.engine.on_build(|_, ctx| {
        ctx.log("Erasing /dev/disk9...");
        ctx.log("rsync noise line");
        ctx.report(10, 100, "Copying files...");
        ctx.report(100, 100, "Copying files...");
        Ok(true)
    });
    let (code, out, err) = run_write(&t, &iso, &[]);
    assert_eq!((code, out.as_str()), (0, ""));
    assert!(err.contains("Erasing /dev/disk9..."), "{err}");
    assert!(!err.contains("rsync noise line"), "{err}");
    assert!(err.contains("Copying files..."), "{err}");
    let (_code, _out, verbose_err) = run_write(&t, &iso, &["--verbose"]);
    assert!(verbose_err.contains("rsync noise line"), "{verbose_err}");
}

#[test]
fn the_audit_line_of_a_write() {
    let t = T::new();
    let iso = t.iso();
    run_write(&t, &iso, &[]);
    let lines: Vec<String> =
        lock(&t.engine.audits).iter().filter(|l| l.starts_with("CLI write requested")).cloned().collect();
    assert_eq!(lines, ["CLI write requested: /dev/disk9 mode=linux"]);
}

#[test]
fn the_pin_is_set_before_the_engine_and_released_after() {
    let t = T::new();
    let iso = t.iso();
    t.engine.set_disks(vec![Disk {
        identity: vec![(s("model"), s("Fake Stick")), (s("serial"), s("ABC123"))],
        ..fake_disks().remove(0)
    }]);
    let order = t.events.clone();
    t.engine.on_build(move |_, _| {
        lock(&order).push("build".into());
        Ok(true)
    });
    run_write(&t, &iso, &[]);
    let pins = t.engine.pin_log();
    assert_eq!(pins[0], (s("disk9"), Some(vec![(s("model"), s("Fake Stick")), (s("serial"), s("ABC123"))])));
    assert_eq!(pins.last().unwrap(), &(s("disk9"), None));
    assert_eq!(t.engine.events(), ["auth", "pin", "build", "pin"]);
}

// ===== OutputHelpersTests =====
fn tty_stream() -> (Arc<OutStream>, Buf) {
    let buf = Buf::default();
    (OutStream::new(Box::new(buf.clone()), true), buf)
}

fn plain_stream() -> (Arc<OutStream>, Buf) {
    let buf = Buf::default();
    (OutStream::new(Box::new(buf.clone()), false), buf)
}

fn clock(now: &Arc<Mutex<f64>>) -> Arc<dyn Fn() -> f64 + Send + Sync> {
    let now = now.clone();
    Arc::new(move || *lock(&now))
}

#[test]
fn color_rules() {
    let mut t = T::new();
    let (tty, _a) = tty_stream();
    let (plain, _b) = plain_stream();
    let style = |t: &T, stream: &OutStream| {
        let (out, err) = (Buf::default(), Buf::default());
        t.env("", &out, &err).style(stream, "x", "31")
    };
    t.env_vars = vec![(s("TERM"), s("xterm"))];
    assert!(style(&t, &tty).contains("\x1b["));
    assert_eq!(style(&t, &plain), "x");
    t.env_vars = vec![(s("TERM"), s("xterm")), (s("NO_COLOR"), s("1"))];
    assert_eq!(style(&t, &tty), "x");
    t.env_vars = vec![(s("TERM"), s("dumb"))];
    assert_eq!(style(&t, &tty), "x");
}

#[test]
fn progress_on_a_terminal_updates_one_line() {
    let (stream, buf) = tty_stream();
    let now = Arc::new(Mutex::new(0.0));
    let progress = CliProgress::new(stream, clock(&now));
    progress.call(10, 100, "Writing...");
    *lock(&now) = 0.1;
    progress.call(20, 100, "Writing..."); // throttled
    *lock(&now) = 0.5;
    progress.call(50, 100, "Writing...");
    progress.clear();
    progress.call(60, 100, "Verifying..."); // new stage: shown at once
    progress.finish();
    let text = buf.text();
    assert_eq!(text.matches('\r').count(), 5, "{text:?}");
    assert!(!text.contains("20.0%"));
    assert!(text.contains("50.0%"));
    assert!(text.contains("Verifying..."));
    assert!(text.ends_with('\n'));
}

#[test]
fn progress_without_a_terminal_prints_periodic_lines() {
    let (stream, buf) = plain_stream();
    let now = Arc::new(Mutex::new(0.0));
    let progress = CliProgress::new(stream, clock(&now));
    progress.call(1, 100, "Copying...");
    *lock(&now) = 3.0;
    progress.call(2, 100, "Copying..."); // within 10 s: skipped
    *lock(&now) = 11.0;
    progress.call(3, 100, "Copying...");
    progress.call(100, 100, "Copying..."); // completion is always shown
    progress.call(0, 0, "Syncing...");
    let text = buf.text();
    let lines = first_lines(&text);
    assert_eq!(lines.len(), 4, "{text:?}");
    assert!(!text.contains('\r'));
    assert!(lines[2].contains("100.0%"), "{}", lines[2]);
    assert_eq!(lines[3], "Syncing...");
}

#[test]
fn progress_shows_speed_and_eta() {
    let (stream, buf) = plain_stream();
    let now = Arc::new(Mutex::new(0.0));
    let progress = CliProgress::new(stream, clock(&now));
    progress.call(0, 100 * MIB, "Writing...");
    *lock(&now) = 20.0;
    progress.call(20 * MIB, 100 * MIB, "Writing...");
    let text = buf.text();
    let last = text.lines().last().unwrap().to_string();
    assert!(last.contains("20.0%"), "{last}");
    assert!(last.contains("1.0 MB/s"), "{last}");
    assert!(last.contains("~1m20s left"), "{last}");
}

#[test]
fn the_logger_filters_noise_unless_verbose() {
    let (stream, buf) = plain_stream();
    let now = Arc::new(Mutex::new(0.0));
    let quiet = CliLogger::new(Arc::new(CliProgress::new(stream.clone(), clock(&now))), stream.clone(), false);
    for line in [
        "$ diskutil eraseDisk FAT32",
        "sources/boot.wim",
        "Erasing and formatting /dev/disk9...",
        "Verification passed: identical",
        "",
        "   ",
    ] {
        quiet.call(line);
    }
    let loud = CliLogger::new(Arc::new(CliProgress::new(stream.clone(), clock(&now))), stream, true);
    loud.call("sources/boot.wim");
    assert_eq!(
        first_lines(&buf.text()),
        ["Erasing and formatting /dev/disk9...", "Verification passed: identical", "sources/boot.wim"]
    );
    assert_eq!(quiet.recent()[..2], ["$ diskutil eraseDisk FAT32", "sources/boot.wim"]);
}

#[test]
fn the_logger_remembers_only_the_last_twenty_lines() {
    let (stream, buf) = plain_stream();
    let now = Arc::new(Mutex::new(0.0));
    let logger = CliLogger::new(Arc::new(CliProgress::new(stream.clone(), clock(&now))), stream, false);
    for i in 0..30 {
        logger.call(&format!("line {i}  "));
    }
    let recent = logger.recent();
    assert_eq!((recent.len(), recent[0].as_str(), recent[19].as_str()), (20, "line 10", "line 29"));
    logger.dump_recent();
    let text = buf.text();
    assert!(text.starts_with("Last log lines:\n  line 10\n"), "{text}");
}

#[test]
fn a_log_line_replaces_the_progress_line() {
    let (stream, buf) = tty_stream();
    let now = Arc::new(Mutex::new(0.0));
    let progress = Arc::new(CliProgress::new(stream.clone(), clock(&now)));
    let logger = CliLogger::new(progress.clone(), stream, false);
    progress.call(10, 100, "Copying files...");
    logger.call("Warning: something");
    let text = buf.text();
    // the progress line is wiped (spaces, then a carriage return) before the message is printed
    assert!(text.contains("\r") && text.ends_with("Warning: something\n"), "{text:?}");
}

// ===== helpers that exist only in the port =====
#[test]
fn typed_identifiers_are_normalised_per_platform() {
    for (text, expected) in
        [("disk9", "disk9"), ("/dev/disk9", "disk9"), ("  /dev/sdb \n", "sdb"), ("", ""), ("/dev/", "")]
    {
        assert_eq!(normalize_typed_identifier_for(text, false), expected, "{text:?}");
    }
    for (text, expected) in [
        ("3", "PhysicalDrive3"),
        ("disk 3", "PhysicalDrive3"),
        ("DISK3", "PhysicalDrive3"),
        ("\\\\.\\PhysicalDrive3", "PhysicalDrive3"),
        ("\\\\.\\3", "PhysicalDrive3"),
        ("0007", "PhysicalDrive7"),
        ("PhysicalDrive3", "PhysicalDrive3"),
        ("disk4; rm", "disk4; rm"),
        ("12345", "12345"),
    ] {
        assert_eq!(normalize_typed_identifier_for(text, true), expected, "{text:?}");
    }
}

#[test]
fn json_is_dumped_like_python() {
    let value = obj(vec![
        ("empty_list", J::List(vec![])),
        ("empty_map", J::Map(vec![])),
        ("text", J::str("a\"b\\c\nd\u{e9}\u{1f600}\u{7f}")),
        ("n", J::Int(-3)),
        ("f", J::Float(12.0)),
        ("g", J::Float(0.5)),
        ("null", J::Null),
        ("list", J::strings(&["x", "y"])),
        ("nested", obj(vec![("k", J::Bool(true))])),
    ]);
    assert_eq!(
        json_dumps(&value),
        "{\n  \"empty_list\": [],\n  \"empty_map\": {},\n  \"text\": \"a\\\"b\\\\c\\nd\\u00e9\\ud83d\\ude00\\u007f\",\n  \"n\": -3,\n  \"f\": 12.0,\n  \"g\": 0.5,\n  \"null\": null,\n  \"list\": [\n    \"x\",\n    \"y\"\n  ],\n  \"nested\": {\n    \"k\": true\n  }\n}"
    );
}

#[test]
fn a_cli_error_carries_its_exit_code() {
    assert_eq!(CliError::new("x"), CliError { message: s("x"), code: 1 });
    assert_eq!(CliError::with_code("x", 2).code, 2);
}
