//! Port of tests/test_cli_hardening.py: `write --hardened`, `harden-seed` and `harden-files`. The engine functions that
//! build the files and the seed drive belong to other parts of the program, so the fake engine stands in for them:
//! these tests are about what the command line does with them (arguments, safety flow, exit codes, what it writes to
//! a folder). Nothing touches a real drive. (`HelpAndDocsTests` are in tests/test_help_a7.rs: they read `help.rs`.)

use super::*;
#[cfg_attr(windows, allow(unused_imports))]
use crate::cli::harden::{create_private_file, write_into_with};
use crate::cli::parser::{parse, CliCommand};
use crate::cli::{EXIT_EJECT_FAILED, EXIT_ERROR, EXIT_INTERRUPTED, EXIT_USAGE, EXIT_VERIFY_FAILED};
use std::fs;
use std::time::{Duration, Instant};

fn s(text: &str) -> String {
    text.to_string()
}

fn serial() -> Identity {
    vec![(s("serial"), s("ABC123"))]
}

/// `HardeningCliCase`: the first fake drive carries an identity.
fn case() -> T {
    let t = T::new();
    let mut disks = fake_disks();
    disks[0].identity = serial();
    t.engine.set_disks(disks);
    t
}

fn interactive(mut t: T) -> T {
    t.interactive = true;
    t
}

fn seed(t: &T, extra: &[&str], target: &str) -> (i32, String, String) {
    t.run(&t.seed_args(extra, target, "disk9"))
}

fn seed_in(t: &T, extra: &[&str], target: &str, stdin: &str) -> (i32, String, String) {
    t.run_in(&t.seed_args(extra, target, "disk9"), stdin)
}

// ===== ParserTests =====
fn parsed(argv: &[&str]) -> CliCommand {
    let argv: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
    parse(&argv).unwrap_or_else(|e| panic!("{argv:?}: {e:?}")).command
}

#[test]
fn the_new_commands_and_flags_are_accepted() {
    let CliCommand::Write(args) = parsed(&["write", "--iso", "a.iso", "--disk", "disk9", "--hardened"]) else {
        panic!()
    };
    assert!(args.hardened);
    let CliCommand::Write(args) = parsed(&["write", "--iso", "a.iso", "--disk", "disk9"]) else { panic!() };
    assert!(!args.hardened);
    assert_eq!(args.mode, Mode::Auto);
    let CliCommand::HardenSeed(args) =
        parsed(&["harden-seed", "--target", "fedora", "--disk", "sdb", "--dry-run", "--yes", "--json", "--no-eject"])
    else {
        panic!()
    };
    assert_eq!((args.target, args.disk.as_str()), (SeedTarget::Fedora, "sdb"));
    assert!(args.flags.dry_run && args.flags.yes && args.flags.json && args.flags.no_eject);
    let CliCommand::HardenFiles(args) =
        parsed(&["harden-files", "--target", "windows", "--out", "somewhere", "--json"])
    else {
        panic!()
    };
    assert_eq!((args.target.as_str(), args.out.as_str(), args.json), ("windows", "somewhere", true));
}

#[test]
fn every_target_is_accepted() {
    for target in SeedTarget::ALL {
        let CliCommand::HardenSeed(args) = parsed(&["harden-seed", "--target", target.as_str(), "--disk", "d"]) else {
            panic!()
        };
        assert_eq!(args.target, target);
    }
    for target in ["windows", "windows-seed", "ubuntu", "fedora", "debian"] {
        let CliCommand::HardenFiles(args) = parsed(&["harden-files", "--target", target, "--out", "x"]) else {
            panic!()
        };
        assert_eq!(args.target.as_str(), target);
    }
    assert_eq!(crate::cli::HARDEN_FILES_TARGETS, ["windows", "windows-seed", "ubuntu", "fedora", "debian"]);
}

#[test]
fn the_during_setup_flag_no_longer_exists() {
    let t = T::new();
    // argparse: an unrecognised argument exits with status 2 (usage error)
    let cases: [&[&str]; 4] = [
        &["harden-seed", "--target", "windows", "--disk", "d", "--during-setup"],
        &["harden-seed", "--target", "ubuntu", "--disk", "d", "--during-setup"],
        &["harden-files", "--target", "windows-seed", "--out", "x", "--during-setup"],
        &["harden-files", "--target", "windows", "--out", "x", "--during-setup"],
    ];
    for argv in cases {
        let (code, out, err) = t.run(argv);
        assert_eq!((code, out.as_str()), (2, ""), "{argv:?}");
        assert!(err.contains("unrecognized arguments: --during-setup"), "{err}");
        assert!(!err.contains("Traceback"));
    }
}

#[test]
fn bad_arguments_are_usage_errors() {
    let t = T::new();
    let cases: [&[&str]; 14] = [
        &["harden-seed"],
        &["harden-seed", "--target", "ubuntu"],
        &["harden-seed", "--disk", "disk9"],
        &["harden-seed", "--target", "windows-seed", "--disk", "disk9"], // that name is for harden-files
        &["harden-seed", "--target", "arch", "--disk", "disk9"],
        &["harden-seed", "--target", "ubuntu", "--disk", "disk9", "--hardened"],
        &["harden-seed", "--target", "ubuntu", "--disk", "disk9", "--no-verify"],
        &["harden-files"],
        &["harden-files", "--target", "windows"],
        &["harden-files", "--target", "windows-seed"],
        &["harden-files", "--out", "x"],
        &["harden-files", "--target", "macos", "--out", "x"],
        &["harden-files", "--target", "windows", "--out", "x", "--yes"], // no drive, nothing to confirm
        &["harden-files", "--target", "windows", "--out", "x", "--dry-run"],
    ];
    for argv in cases {
        let (code, out, err) = t.run(argv);
        assert_eq!(code, EXIT_USAGE, "{argv:?}");
        assert_eq!(out, "", "{argv:?}");
        assert!(err.contains("usage:"), "{argv:?}: {err}");
    }
}

#[test]
fn the_commands_are_known_to_the_parser_and_dispatched() {
    let names: Vec<String> =
        crate::cli::build_cli_parser().get_subcommands().map(|c| c.get_name().to_string()).collect();
    assert_eq!(names, ["gui", "list", "detect", "sha256", "fetch-chromeos", "write", "harden-seed", "harden-files"]);
    let t = case();
    assert_eq!(seed(&t, &["--dry-run"], "ubuntu").0, 0);
    assert_eq!(t.run(&["harden-files", "--target", "ubuntu", "--out", &t.path("o")]).0, 0);
}

#[test]
fn help_text_names_the_commands_and_flags() {
    let t = T::new();
    let (_code, out, _err) = t.run(&["--help"]);
    assert!(out.contains("harden-seed") && out.contains("harden-files"));
    assert!(t.run(&["write", "--help"]).1.contains("--hardened"));
    let text = t.run(&["harden-seed", "--help"]).1;
    for flag in ["--target", "--disk", "--dry-run", "--yes", "--json", "--no-eject"] {
        assert!(text.contains(flag), "{flag}");
    }
    assert!(!text.contains("--during-setup"));
    assert!(!text.contains("EXPERIMENTAL"));
    assert!(!text.contains("--no-verify")); // verification of the seed drive cannot be switched off either
    let files_help = t.run(&["harden-files", "--help"]).1;
    for flag in ["--target", "--out", "--json"] {
        assert!(files_help.contains(flag), "{flag}");
    }
    assert!(!files_help.contains("--during-setup"));
}

// ===== WriteHardenedTests =====
struct WriteCase {
    t: T,
    win: String,
    linux: String,
}

fn write_case() -> WriteCase {
    let t = case();
    let win = t.make_iso("Win11.iso", 2 * MIB, false);
    let linux = t.make_iso("ubuntu.iso", 2 * MIB, true);
    WriteCase { t, win, linux }
}

#[test]
fn dry_run_lists_the_extra_files_by_name_only() {
    let c = write_case();
    let (code, out, err) = c.t.run(&c.t.write_args(&c.win, &["--dry-run", "--hardened", "--mode", "windows"]));
    assert_eq!(code, 0);
    for name in win_files().keys() {
        assert!(out.contains(name.as_str()), "{name}");
    }
    assert!(out.contains("Hardened (recommended settings)"));
    for content in ["<unattend/>", "@echo off", "# harden"] {
        assert!(!out.contains(content), "names, never contents: {content}");
    }
    assert!(err.contains("Dry run"));
    assert!(c.t.engine.builds().is_empty());
    assert_eq!(c.t.engine.auth_calls(), 0);
    assert!(
        out.contains(&format!("  Extra: Hardened (recommended settings): {}\n", sorted_names(&win_files()).join(", ")))
    );
}

#[test]
fn write_dry_run_json_shape() {
    let c = write_case();
    let (code, out, err) =
        c.t.run(&c.t.write_args(&c.win, &["--dry-run", "--hardened", "--mode", "windows", "--json"]));
    assert_eq!((code, err.as_str()), (0, ""));
    let plan = json(&out);
    assert_eq!(plan["hardening"], "baseline");
    assert_eq!(plan["hardening_files"], serde_json::json!(sorted_names(&win_files())));
    assert!(plan["steps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|st| st.as_str().unwrap().contains("Hardened (recommended settings)")));
    // the extra step sits before "Verify the copied files"
    let steps: Vec<&str> = plan["steps"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
    assert!(steps[steps.len() - 3].starts_with("Add the Hardened (recommended settings) files: "), "{steps:?}");
    assert!(steps[steps.len() - 2].starts_with("Verify the copied files"), "{steps:?}");
    // and without the flag the plan says so, so a script can tell the two apart
    let plain = json(&c.t.run(&c.t.write_args(&c.win, &["--dry-run", "--mode", "windows", "--json"])).1);
    assert_eq!(
        (plain["hardening"].as_str(), plain["hardening_files"].as_array().map(|a| a.len())),
        (Some("none"), Some(0))
    );
}

#[test]
fn the_engine_gets_the_baseline_profile() {
    let c = write_case();
    let (code, _out, _err) = c.t.run(&c.t.write_args(&c.win, &["--yes", "--hardened", "--mode", "windows"]));
    assert_eq!(code, 0);
    let call = &c.t.engine.builds()[0];
    assert_eq!((call.hardening, call.mode), (Hardening::Baseline, Mode::Windows));
    assert_eq!(*lock(&c.t.engine.files_windows_calls), [Hardening::Baseline]);
}

#[test]
fn auto_mode_that_finds_a_windows_image_accepts_it() {
    let c = write_case();
    *lock(&c.t.engine.detect) = Some(IsoKind::Windows);
    let (code, _out, _err) = c.t.run(&c.t.write_args(&c.win, &["--yes", "--hardened"]));
    assert_eq!(code, 0);
    assert_eq!(c.t.engine.builds()[0].hardening, Hardening::Baseline);
}

#[test]
fn without_the_flag_the_engine_is_called_as_before() {
    let c = write_case();
    c.t.run(&c.t.write_args(&c.win, &["--yes", "--mode", "windows"]));
    assert_eq!(c.t.engine.builds()[0].hardening, Hardening::None);
    assert!(lock(&c.t.engine.files_windows_calls).is_empty(), "no hardening file is even built");
}

#[test]
fn a_linux_or_chromeos_mode_is_a_usage_error_before_anything_else() {
    let c = write_case();
    for mode in ["linux", "chromeos"] {
        let (code, out, err) = c.t.run(&c.t.write_args(&c.linux, &["--yes", "--hardened", "--mode", mode]));
        assert_eq!((code, out.as_str()), (EXIT_USAGE, ""), "{mode}");
        assert!(err.contains("--hardened"), "{err}");
        assert!(err.contains("harden-seed"), "tells the user where to go instead: {err}");
    }
    assert_eq!(c.t.engine.list_calls.load(Ordering::SeqCst), 0);
    assert!(c.t.engine.builds().is_empty());
    assert_eq!(c.t.engine.auth_calls(), 0);
}

#[test]
fn auto_mode_that_resolves_to_linux_is_a_usage_error() {
    let c = write_case();
    let (code, out, err) = c.t.run(&c.t.write_args(&c.linux, &["--yes", "--hardened"]));
    assert_eq!((code, out.as_str()), (EXIT_USAGE, ""));
    assert!(err.contains("--hardened"), "{err}");
    assert!(c.t.engine.builds().is_empty());
    assert_eq!(c.t.engine.auth_calls(), 0);
}

#[test]
fn the_usage_error_is_in_the_json_result_too() {
    let c = write_case();
    let (code, out, _err) = c.t.run(&c.t.write_args(&c.linux, &["--yes", "--hardened", "--json"]));
    assert_eq!(code, EXIT_USAGE);
    let result = json(&out);
    assert_eq!(result["ok"], false);
    assert_eq!(result["exit_code"], EXIT_USAGE);
}

#[test]
fn the_typed_confirmation_is_still_required() {
    let mut c = write_case();
    let (code, _out, err) = c.t.run(&c.t.write_args(&c.win, &["--hardened", "--mode", "windows"]));
    assert_eq!(code, EXIT_USAGE); // not a terminal and no --yes
    assert!(err.contains("--yes"));
    c.t.interactive = true;
    for answer in ["", "yes\n", "disk8\n"] {
        let (code, _out, _err) = c.t.run_in(&c.t.write_args(&c.win, &["--hardened", "--mode", "windows"]), answer);
        assert_eq!(code, EXIT_USAGE, "{answer:?}");
    }
    let (code, _out, err) = c.t.run_in(&c.t.write_args(&c.win, &["--hardened", "--mode", "windows"]), "disk9\n");
    assert_eq!(code, 0);
    assert!(err.contains("Type the disk id (disk9)"));
}

#[test]
fn files_the_validator_refuses_stop_the_plan() {
    let c = write_case();
    *lock(&c.t.engine.validate_files) = Box::new(|_| Err(Error::value("path escapes the drive")));
    let (code, out, err) = c.t.run(&c.t.write_args(&c.win, &["--yes", "--hardened", "--mode", "windows"]));
    assert_eq!((code, out.as_str()), (EXIT_ERROR, ""));
    assert!(err.contains("path escapes the drive"), "{err}");
    assert!(err.contains("The hardening files are not valid: path escapes the drive"), "{err}");
    assert!(c.t.engine.builds().is_empty());
}

// ===== HardenSeedTests =====
#[test]
fn seed_dry_run_prints_the_plan_and_touches_nothing() {
    let t = case();
    let (code, out, err) = seed(&t, &["--dry-run"], "ubuntu");
    assert_eq!(code, 0);
    for text in [
        "Plan",
        "/dev/disk9",
        "16.0 GB",
        "ubuntu",
        "CIDATA",
        "GPT + FAT32",
        "harden-linux.sh",
        "user-data",
        "Mode : seed",
        "byte for byte",
        "Eject the drive",
    ] {
        assert!(out.contains(text), "{text} missing from:\n{out}");
    }
    assert!(err.contains("Dry run"));
    assert!(t.engine.seeds().is_empty());
    assert_eq!(t.engine.auth_calls(), 0);
    assert!(t.engine.pin_log().is_empty());
}

#[test]
fn seed_dry_run_plan_text() {
    let t = case();
    let (_code, out, _err) = seed(&t, &["--dry-run"], "fedora");
    assert_eq!(
        out,
        "Plan\n  Disk : /dev/disk9  16.0 GB  /dev/disk9 \u{2014} 16.0 GB\n  Seed : fedora (volume label OEMDRV)\n  \
         Files: README.txt, harden-linux.sh, ks.cfg\n  Mode : seed\n  Steps:\n    \
         1. Re-check that /dev/disk9 is still the listed USB drive\n    \
         2. Erase /dev/disk9 and format it as GPT + FAT32 ('OEMDRV')\n    \
         3. Copy 3 seed files: README.txt, harden-linux.sh, ks.cfg\n    \
         4. Read the drive back and compare every file byte for byte\n    5. Eject the drive\n"
    );
}

#[test]
fn seed_dry_run_json_shape() {
    let t = case();
    let (code, out, err) = seed(&t, &["--dry-run", "--json", "--no-eject"], "fedora");
    assert_eq!((code, err.as_str()), (0, ""));
    let plan = json(&out);
    assert_eq!(
        (plan["mode"].as_str(), plan["target"].as_str(), plan["volume_label"].as_str()),
        (Some("seed"), Some("fedora"), Some("OEMDRV"))
    );
    assert_eq!(plan["files"], serde_json::json!(sorted_names(&seed_files(SeedTarget::Fedora).1)));
    assert_eq!(plan["disk"]["id"], "disk9");
    assert_eq!(plan["identity"], serde_json::json!({"serial": "ABC123"}));
    assert_eq!(plan["dry_run"], true);
    assert_eq!(plan["eject"], false);
    assert!(plan["steps"].as_array().unwrap().last().unwrap().as_str().unwrap().contains("--no-eject"));
    assert!(plan["iso"].is_null());
    assert_eq!(plan["iso_size"], 0);
    // the keys come in the order of the Python plan dict
    let keys = [
        "iso",
        "iso_size",
        "mode",
        "target",
        "volume_label",
        "files",
        "disk",
        "identity",
        "steps",
        "eject",
        "dry_run",
        "hardening",
        "hardening_files",
    ];
    let positions: Vec<usize> = keys.iter().map(|k| out.find(&format!("\n  \"{k}\"")).unwrap()).collect();
    assert!(positions.windows(2).all(|w| w[0] < w[1]), "{out}");
}

#[test]
fn every_target_uses_its_own_files_and_label() {
    let t = case();
    for target in SeedTarget::ALL {
        let (label, files) = seed_files(target);
        let (code, out, _err) = seed(&t, &["--dry-run"], target.as_str());
        assert_eq!(code, 0, "{target}");
        assert!(out.contains(&label), "{target}: {out}");
        for name in files.keys() {
            assert!(out.contains(name.as_str()), "{target}: {name}");
        }
    }
}

#[test]
fn seed_validation_happens_before_anything_runs() {
    let t = case();
    for (fragment, disk) in [("not a valid disk identifier", "disk4; rm -rf /"), ("not an eligible USB drive", "disk3")]
    {
        let (code, out, err) = t.run(&t.seed_args(&["--yes"], "ubuntu", disk));
        assert_eq!((code, out.as_str()), (1, ""), "{fragment}");
        assert!(err.contains(fragment), "{fragment}: {err}");
    }
    assert!(t.engine.seeds().is_empty());
    assert_eq!(t.engine.auth_calls(), 0);
}

#[test]
fn seed_dev_prefix_is_accepted() {
    let t = case();
    let (code, out, _err) = t.run(&t.seed_args(&["--dry-run"], "ubuntu", "/dev/disk9"));
    assert_eq!(code, 0);
    assert!(out.contains("/dev/disk9"));
}

#[test]
fn seed_missing_tools_are_reported() {
    let t = case();
    *lock(&t.engine.missing) = vec![s("parted")];
    let (code, _out, err) = seed(&t, &["--yes"], "ubuntu");
    assert_eq!(code, 1);
    assert!(err.contains("parted"), "{err}");
    assert_eq!(lock(&t.engine.missing_calls).last(), Some(&Mode::Seed));
    assert!(t.engine.seeds().is_empty());
}

#[test]
fn seed_files_the_validator_refuses_stop_the_command() {
    let t = case();
    *lock(&t.engine.validate_files) = Box::new(|_| Err(Error::value("file too large")));
    let (code, out, err) = seed(&t, &["--yes"], "ubuntu");
    assert_eq!((code, out.as_str()), (1, ""));
    assert!(err.contains("file too large"), "{err}");
    assert!(t.engine.seeds().is_empty());
    assert_eq!(t.engine.auth_calls(), 0);
}

// -- the confirmation: the same as `write` --
#[test]
fn seed_non_interactive_without_yes_is_refused() {
    let t = case();
    let (code, out, err) = seed(&t, &[], "ubuntu");
    assert_eq!((code, out.as_str()), (EXIT_USAGE, ""));
    assert!(err.contains("--yes"), "{err}");
    assert!(err.contains("Plan"), "the plan was still shown: {err}");
    assert!(t.engine.seeds().is_empty());
    assert_eq!(t.engine.auth_calls(), 0);
}

#[test]
fn seed_non_interactive_ignores_typed_input() {
    let t = case();
    let (code, _out, _err) = seed_in(&t, &[], "ubuntu", "disk9\n");
    assert_eq!(code, EXIT_USAGE);
    assert!(t.engine.seeds().is_empty());
}

#[test]
fn the_user_must_type_the_disk_id() {
    let t = interactive(case());
    for answer in ["yes\n", "disk8\n", "\n", "", "DISK9\n", "/dev/disk9\n"] {
        let (code, _out, err) = seed_in(&t, &[], "ubuntu", answer);
        assert_eq!(code, EXIT_USAGE, "{answer:?}");
        assert!(err.contains("Nothing was changed"), "{answer:?}: {err}");
        assert!(t.engine.seeds().is_empty());
    }
    let (code, _out, err) = seed_in(&t, &[], "ubuntu", "disk9\n");
    assert_eq!(code, 0);
    assert!(err.contains("Type the disk id (disk9)"));
    assert!(err.contains("PERMANENTLY ERASE"));
    assert_eq!(t.engine.seeds().len(), 1);
}

#[test]
fn seed_yes_skips_the_prompt() {
    let t = interactive(case());
    let (code, _out, err) = seed_in(&t, &["--yes"], "ubuntu", "");
    assert_eq!(code, 0);
    assert!(!err.contains("Type the disk id"));
}

// -- the run --
#[test]
fn seed_success_passes_the_right_arguments_to_the_engine() {
    let t = case();
    let cancel_seen = Arc::new(Mutex::new(None));
    let probe = cancel_seen.clone();
    t.engine.on_seed(move |_, ctx| {
        ctx.log("x");
        ctx.report(1, 2, "x");
        *lock(&probe) = ctx.cancel.map(|c| c.is_set());
        Ok(true)
    });
    let (code, out, err) = seed(&t, &["--yes"], "debian");
    assert_eq!((code, out.as_str()), (0, ""));
    assert!(err.contains("ejected"), "{err}");
    let call = &t.engine.seeds()[0];
    assert_eq!((call.target, call.dev.as_str()), (SeedTarget::Debian, "disk9"));
    assert_eq!(call.priv_addr, t.engine.priv_addr());
    assert_eq!(call.expected_size, Some(16 * GIB));
    assert!(call.eject);
    assert_eq!(call.profile, Hardening::Baseline);
    assert_eq!(*lock(&cancel_seen), Some(false));
    assert!(t.engine.builds().is_empty(), "an image writer is never involved");
}

#[test]
fn the_drive_identity_is_pinned_before_the_engine_and_released_after() {
    let t = case();
    seed(&t, &["--yes"], "ubuntu");
    let pins = t.engine.pin_log();
    assert_eq!(pins[0], (s("disk9"), Some(serial())));
    assert_eq!(pins.last().unwrap(), &(s("disk9"), None));
    let order: Vec<String> = t.engine.events().into_iter().filter(|e| e != "auth").collect();
    assert_eq!(order, ["pin", "build", "pin"]);
}

#[test]
fn privileges_follow_needs_admin_and_come_after_the_confirmation() {
    let t = interactive(case());
    seed_in(&t, &[], "ubuntu", "disk9\n");
    let order: Vec<String> = t.engine.events().into_iter().filter(|e| e != "pin").collect();
    assert_eq!(order, ["auth", "build"]);
    // macOS: like Windows mode, no administrator rights needed
    let t = case();
    *lock(&t.engine.admin) = Admin::RawOnly;
    assert_eq!(seed(&t, &["--yes"], "ubuntu").0, 0);
    assert_eq!(t.engine.auth_calls(), 0);
}

#[test]
fn seed_privilege_failure_stops_before_the_engine() {
    let t = case();
    *lock(&t.engine.priv_.auth_error) = Some(s("Could not obtain administrator privileges"));
    let (code, _out, err) = seed(&t, &["--yes"], "ubuntu");
    assert_eq!(code, 1);
    assert!(err.contains("administrator privileges"), "{err}");
    assert!(t.engine.seeds().is_empty());
}

#[test]
fn seed_json_result_on_success() {
    let t = case();
    let (code, out, err) = seed(&t, &["--yes", "--json"], "ubuntu");
    assert_eq!(code, 0);
    let result = json(&out);
    for (key, expected) in [
        ("ok", serde_json::json!(true)),
        ("mode", serde_json::json!("seed")),
        ("target", serde_json::json!("ubuntu")),
        ("disk", serde_json::json!("disk9")),
        ("verified", serde_json::json!(true)),
        ("ejected", serde_json::json!(true)),
        ("error", serde_json::Value::Null),
        ("exit_code", serde_json::json!(0)),
    ] {
        assert_eq!(result[key], expected, "{key}");
    }
    assert_eq!(result["files"], serde_json::json!(sorted_names(&seed_files(SeedTarget::Ubuntu).1)));
    assert!(result.get("elapsed_seconds").is_some());
    assert!(!err.contains("\"ok\""), "stdout carries the data, stderr the messages");
    // the keys come in the order of the Python result dict
    let order = [
        "ok",
        "mode",
        "target",
        "disk",
        "verified",
        "ejected",
        "error",
        "exit_code",
        "volume_label",
        "files",
        "elapsed_seconds",
    ];
    let positions: Vec<usize> = order.iter().map(|k| out.find(&format!("\n  \"{k}\"")).unwrap()).collect();
    assert!(positions.windows(2).all(|w| w[0] < w[1]), "{out}");
}

#[test]
fn seed_eject_failure_exits_4() {
    let t = case();
    t.engine.on_seed(|_, _| Ok(false));
    let (code, out, err) = seed(&t, &["--yes", "--json"], "ubuntu");
    assert_eq!(code, EXIT_EJECT_FAILED);
    let result = json(&out);
    assert_eq!(
        (result["verified"].as_bool(), result["ejected"].as_bool(), result["exit_code"].as_i64()),
        (Some(true), Some(false), Some(4))
    );
    assert!(err.contains("could not be ejected"), "{err}");
}

#[test]
fn seed_no_eject_is_passed_to_the_engine_and_is_not_a_failure() {
    let t = case();
    t.engine.on_seed(|_, _| Ok(false));
    let (code, _out, err) = seed(&t, &["--yes", "--no-eject"], "ubuntu");
    assert_eq!(code, 0);
    assert!(!t.engine.seeds()[0].eject);
    assert!(err.contains("left connected"), "{err}");
}

#[test]
fn seed_verification_failure_exits_3() {
    let t = case();
    t.engine.on_seed(|_, _| Err(Error::runtime("Verification FAILED: user-data differs.")));
    let (code, out, err) = seed(&t, &["--yes", "--json"], "ubuntu");
    assert_eq!(code, EXIT_VERIFY_FAILED);
    let result = json(&out);
    assert_eq!(
        (result["ok"].as_bool(), result["verified"].as_bool(), result["exit_code"].as_i64()),
        (Some(false), Some(false), Some(3))
    );
    assert!(err.contains("Verification FAILED"), "{err}");
}

#[test]
fn seed_engine_errors_exit_1_without_traceback() {
    let t = case();
    type Make = fn() -> Error;
    let makers: [Make; 3] = [
        || Error::runtime("Privileged command failed"),
        || Error::value("bad value"),
        || Error::Io(io::Error::other("device vanished")),
    ];
    for make in makers {
        t.engine.on_seed(move |_, _| Err(make()));
        let (code, out, err) = seed(&t, &["--yes"], "ubuntu");
        assert_eq!((code, out.as_str()), (1, ""));
        assert!(!err.contains("Traceback"));
    }
    t.engine.on_seed(|_, _| -> Result<bool> { panic!("oops") });
    let (code, out, err) = seed(&t, &["--yes"], "ubuntu");
    assert_eq!((code, out.as_str()), (1, ""));
    assert!(!err.contains("Traceback"));
}

#[test]
fn seed_keyboard_interrupt_exits_130() {
    let t = case();
    let presses = t.interrupts.clone();
    t.engine.on_seed(move |_, _| {
        presses.press();
        presses.press();
        std::thread::sleep(Duration::from_secs(2));
        Err(Error::runtime("too late"))
    });
    let (code, out, err) = seed(&t, &["--yes", "--json"], "ubuntu");
    assert_eq!(code, EXIT_INTERRUPTED);
    assert_eq!(json(&out)["error"], "interrupted");
    assert!(err.contains("must not be used"), "{err}");
    assert_eq!(t.engine.pin_log().last().unwrap(), &(s("disk9"), None));
}

#[test]
fn ctrl_c_sets_the_cancel_event_and_exits_130() {
    let t = case();
    let presses = t.interrupts.clone();
    let seen = Arc::new(Mutex::new(false));
    let probe = seen.clone();
    t.engine.on_seed(move |_, ctx| {
        presses.press();
        let cancel = ctx.cancel.unwrap().clone();
        let until = Instant::now() + Duration::from_secs(5);
        while !cancel.is_set() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(2));
        }
        *lock(&probe) = cancel.is_set();
        Err(Error::runtime("Canceled"))
    });
    let (code, _out, err) = seed(&t, &["--yes"], "ubuntu");
    assert_eq!(code, EXIT_INTERRUPTED);
    assert!(*lock(&seen));
    assert!(err.contains("press Ctrl-C again"), "{err}");
}

#[test]
fn seed_progress_and_log_reach_stderr_only() {
    let t = case();
    t.engine.on_seed(|_, ctx| {
        ctx.log("Erasing /dev/disk9...");
        ctx.report(10, 100, "Copying files...");
        ctx.report(100, 100, "Copying files...");
        Ok(true)
    });
    let (code, out, err) = seed(&t, &["--yes"], "ubuntu");
    assert_eq!((code, out.as_str()), (0, ""));
    assert!(err.contains("Erasing /dev/disk9..."), "{err}");
    assert!(err.contains("Copying files..."), "{err}");
}

#[test]
fn seed_unsupported_system_is_refused() {
    let t = case();
    t.engine.supported.store(false, Ordering::SeqCst);
    let (code, _out, err) = seed(&t, &["--yes"], "ubuntu");
    assert_eq!(code, 1);
    assert!(err.contains("macOS and Linux only"), "{err}");
    assert!(t.engine.seeds().is_empty());
}

// ===== hardening2: the Windows seed drive =====
#[test]
fn windows_dry_run_lists_the_file_names_and_the_label() {
    let t = case();
    let (code, out, err) = seed(&t, &["--dry-run"], "windows");
    assert_eq!(code, 0);
    for text in [
        "Seed : windows (volume label EPMA-SEED)",
        "harden.cmd",
        "audit.cmd",
        "undo.cmd",
        "harden.ps1",
        "README.txt",
        "GPT + FAT32",
        "byte for byte",
    ] {
        assert!(out.contains(text), "{text} missing from:\n{out}");
    }
    for text in ["autounattend.xml", "EPMA-SEED.txt", "SetupComplete.cmd", "EXPERIMENTAL"] {
        assert!(!out.contains(text), "{text}");
    }
    assert!(err.contains("Dry run"));
    assert_eq!(*lock(&t.engine.files_seed_calls), [(SeedTarget::Windows, Hardening::Baseline)]);
    assert!(lock(&t.engine.files_windows_calls).is_empty(), "the same-USB set is a different thing");
    assert!(t.engine.seeds().is_empty());
    assert_eq!(t.engine.auth_calls(), 0);
    assert!(t.engine.pin_log().is_empty());
}

#[test]
fn windows_dry_run_json_has_no_during_setup_key() {
    let t = case();
    let (code, out, err) = seed(&t, &["--dry-run", "--json"], "windows");
    assert_eq!((code, err.as_str()), (0, ""));
    let plan = json(&out);
    assert!(plan.get("during_setup").is_none());
    assert_eq!(
        (plan["mode"].as_str(), plan["target"].as_str(), plan["volume_label"].as_str()),
        (Some("seed"), Some("windows"), Some("EPMA-SEED"))
    );
    assert_eq!(plan["files"], serde_json::json!(sorted_names(&seed_files(SeedTarget::Windows).1)));
    assert!(!plan["steps"].as_array().unwrap().iter().any(|st| st.as_str().unwrap().contains("EXPERIMENTAL")));
    assert!(json(&seed(&t, &["--dry-run", "--json"], "debian").1).get("during_setup").is_none());
}

#[test]
fn during_setup_is_an_unrecognised_argument_for_harden_seed() {
    let t = case();
    for target in ["windows", "ubuntu", "fedora", "debian"] {
        let (code, out, err) = t.run(&t.seed_args(&["--during-setup", "--yes"], target, "disk9"));
        assert_eq!((code, out.as_str()), (2, ""), "{target}");
        assert!(err.contains("unrecognized arguments: --during-setup"), "{err}");
    }
    assert_eq!(t.engine.list_calls.load(Ordering::SeqCst), 0, "not even the drives were listed");
    assert!(lock(&t.engine.files_seed_calls).is_empty());
    assert_eq!(t.engine.auth_calls(), 0);
    assert!(t.engine.pin_log().is_empty());
    assert!(t.engine.seeds().is_empty());
}

#[test]
fn windows_reaches_the_engine_without_the_removed_option() {
    let t = case();
    let (code, out, _err) = seed(&t, &["--yes"], "windows");
    assert_eq!((code, out.as_str()), (0, ""));
    let call = &t.engine.seeds()[0];
    assert_eq!((call.target, call.dev.as_str()), (SeedTarget::Windows, "disk9"));
    assert_eq!(call.profile, Hardening::Baseline);
    assert!(call.eject);
    assert!(t.engine.builds().is_empty());
}

#[test]
fn windows_json_result() {
    let t = case();
    let (code, out, _err) = seed(&t, &["--yes", "--json"], "windows");
    assert_eq!(code, 0);
    let result = json(&out);
    assert_eq!(
        (result["ok"].as_bool(), result["mode"].as_str(), result["target"].as_str(), result["disk"].as_str()),
        (Some(true), Some("seed"), Some("windows"), Some("disk9"))
    );
    assert!(result.get("during_setup").is_none());
    assert_eq!(result["files"], serde_json::json!(sorted_names(&seed_files(SeedTarget::Windows).1)));
    assert_eq!(result["volume_label"], "EPMA-SEED");
}

#[test]
fn the_confirmation_pinning_and_exit_codes_are_the_same_for_windows() {
    let mut t = case();
    let (code, out, err) = seed(&t, &[], "windows"); // not a terminal, no --yes
    assert_eq!((code, out.as_str()), (EXIT_USAGE, ""));
    assert!(err.contains("--yes"));
    assert!(err.contains("harden.cmd"), "the plan was still shown");
    assert!(t.engine.seeds().is_empty());
    t.interactive = true;
    assert_eq!(seed_in(&t, &[], "windows", "disk8\n").0, EXIT_USAGE);
    lock(&t.engine.pins).clear();
    lock(&t.events).clear();
    assert_eq!(seed_in(&t, &[], "windows", "disk9\n").0, 0);
    let pins = t.engine.pin_log();
    assert_eq!((pins[0].clone(), pins[1].clone()), ((s("disk9"), Some(serial())), (s("disk9"), None)));
    t.engine.on_seed(|_, _| Ok(false));
    assert_eq!(seed(&t, &["--yes"], "windows").0, EXIT_EJECT_FAILED);
    t.engine.on_seed(|_, _| Err(Error::runtime("Verification FAILED: harden.cmd differs.")));
    assert_eq!(seed(&t, &["--yes"], "windows").0, EXIT_VERIFY_FAILED);
}

#[test]
fn the_audit_log_line_of_a_windows_seed_write() {
    let t = case();
    seed(&t, &["--yes"], "windows");
    let lines: Vec<String> =
        lock(&t.engine.audits).iter().filter(|l| l.starts_with("CLI write requested")).cloned().collect();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("target=windows"), "{}", lines[0]);
    assert!(!lines[0].contains("during_setup"));
    assert_eq!(lines[0], "CLI write requested: /dev/disk9 mode=seed target=windows hardening=baseline");
}

#[test]
fn a_windows_file_set_the_validator_refuses_stops_the_command() {
    let t = case();
    *lock(&t.engine.validate_files) = Box::new(|_| Err(Error::value("name harden.cmd. ends with a dot")));
    let (code, out, err) = seed(&t, &["--yes"], "windows");
    assert_eq!((code, out.as_str()), (1, ""));
    assert!(err.contains("ends with a dot"), "{err}");
    assert!(t.engine.seeds().is_empty());
}

// ===== HardenFilesTests =====
struct Folder {
    t: T,
}

impl Folder {
    fn new() -> Folder {
        Folder { t: case() }
    }
    fn out_dir(&self, name: &str) -> String {
        self.t.path(name)
    }
    fn files(&self, target: &str, out: &str, extra: &[&str]) -> (i32, String, String) {
        let mut argv = vec!["harden-files", "--target", target, "--out", out];
        argv.extend_from_slice(extra);
        self.t.run(&argv)
    }
    /// Anything the command may have left next to the destination (staging folders).
    fn leftovers(&self) -> Vec<String> {
        let mut found: Vec<String> = fs::read_dir(&self.t.tmp)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with(".epma-harden-"))
            .collect();
        found.sort();
        found
    }
    fn tree(&self, root: &str) -> Vec<(String, bool)> {
        fn walk(dir: &Path, base: &Path, found: &mut Vec<(String, bool)>) {
            let Ok(entries) = fs::read_dir(dir) else { return };
            for entry in entries {
                let entry = entry.unwrap();
                let path = entry.path();
                let is_dir = path.is_dir();
                found.push((path.strip_prefix(base).unwrap().display().to_string(), is_dir));
                if is_dir {
                    walk(&path, base, found);
                }
            }
        }
        let mut found = Vec::new();
        walk(Path::new(root), Path::new(root), &mut found);
        found.sort();
        found
    }
}

#[test]
fn writes_every_target_into_a_new_folder() {
    let f = Folder::new();
    // "windows" is the same-USB set; "windows-seed" is the seed drive's set (its own files)
    let cases: Vec<(&str, Files)> = vec![
        ("windows", win_files()),
        ("windows-seed", seed_files(SeedTarget::Windows).1),
        ("ubuntu", seed_files(SeedTarget::Ubuntu).1),
        ("fedora", seed_files(SeedTarget::Fedora).1),
        ("debian", seed_files(SeedTarget::Debian).1),
    ];
    for (target, files) in cases {
        let out = f.out_dir(&format!("out-{target}"));
        let (code, stdout, err) = f.files(target, &out, &[]);
        assert_eq!(code, 0, "{target}: {err}");
        assert_eq!(stdout.lines().map(|l| l.to_string()).collect::<Vec<_>>(), sorted_names(&files), "{target}"); // data on stdout: the names
        assert!(err.contains("No drive was touched"), "{err}");
        for (rel, data) in &files {
            let path = rel.split('/').fold(PathBuf::from(&out), |p, part| p.join(part));
            assert_eq!(&fs::read(&path).unwrap(), data, "{target}: {rel}");
        }
        assert_eq!(f.leftovers(), Vec::<String>::new());
    }
}

#[cfg(unix)]
#[test]
fn permissions_are_normal_and_do_not_depend_on_the_umask() {
    use std::os::unix::fs::PermissionsExt;
    static UMASK: Mutex<()> = Mutex::new(());
    let _guard = lock(&UMASK);
    let f = Folder::new();
    let out = f.out_dir("seed-files");
    // SAFETY: umask only changes this process's file-creation mask; it is restored right after the command.
    let old = unsafe { libc::umask(0o077) };
    let (code, _stdout, _err) = f.files("windows", &out, &[]);
    unsafe {
        libc::umask(old);
    }
    assert_eq!(code, 0);
    for (rel, is_dir) in f.tree(&out) {
        let mode = fs::metadata(Path::new(&out).join(&rel)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, if is_dir { 0o700 } else { 0o600 }, "{rel} is {mode:o}");
    }
    assert_eq!(fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o700);
}

#[cfg(unix)]
#[test]
fn an_existing_empty_folder_is_filled_and_keeps_its_identity() {
    use std::os::unix::fs::MetadataExt;
    let f = Folder::new();
    let out = f.out_dir("seed-files");
    fs::create_dir(&out).unwrap();
    let inode = fs::metadata(&out).unwrap().ino();
    let (code, _stdout, _err) = f.files("ubuntu", &out, &[]);
    assert_eq!(code, 0);
    assert_eq!(fs::metadata(&out).unwrap().ino(), inode);
    let mut names: Vec<String> =
        fs::read_dir(&out).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
    names.sort();
    assert_eq!(names, sorted_names(&seed_files(SeedTarget::Ubuntu).1));
    assert_eq!(f.leftovers(), Vec::<String>::new());
}

#[test]
fn a_folder_that_is_not_empty_is_refused_and_left_alone() {
    let f = Folder::new();
    let out = f.out_dir("seed-files");
    f.t.write_file("seed-files/notes.txt", b"mine");
    let before = f.tree(&out);
    for target in ["windows", "ubuntu"] {
        let (code, stdout, err) = f.files(target, &out, &[]);
        assert_eq!((code, stdout.as_str()), (EXIT_ERROR, ""), "{target}");
        assert!(err.contains("not empty"), "{err}");
        assert_eq!(f.tree(&out), before);
        assert_eq!(fs::read(Path::new(&out).join("notes.txt")).unwrap(), b"mine");
    }
    assert_eq!(f.leftovers(), Vec::<String>::new());
}

#[test]
fn a_name_that_already_exists_is_never_overwritten() {
    let f = Folder::new();
    let out = f.out_dir("seed-files");
    f.t.write_file("seed-files/user-data", b"precious");
    let (code, _stdout, err) = f.files("ubuntu", &out, &[]);
    assert_eq!(code, EXIT_ERROR);
    assert_eq!(fs::read(Path::new(&out).join("user-data")).unwrap(), b"precious");
    assert_eq!(fs::read_dir(&out).unwrap().count(), 1);
    assert!(err.contains("not empty"), "{err}");
}

#[test]
fn a_hidden_file_counts_as_content() {
    let f = Folder::new();
    let out = f.out_dir("seed-files");
    f.t.write_file("seed-files/.hidden", b"");
    assert_eq!(f.files("windows", &out, &[]).0, EXIT_ERROR);
    assert_eq!(fs::read_dir(&out).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn a_symbolic_link_is_refused_even_when_it_points_at_an_empty_folder() {
    use std::os::unix::fs::symlink;
    let f = Folder::new();
    let real = f.t.path("real-empty");
    fs::create_dir(&real).unwrap();
    let link = f.t.path("link");
    symlink(&real, &link).unwrap();
    let (code, stdout, err) = f.files("windows", &link, &[]);
    assert_eq!((code, stdout.as_str()), (EXIT_ERROR, ""));
    assert!(err.contains("symbolic link"), "{err}");
    assert_eq!(fs::read_dir(&real).unwrap().count(), 0);
    // a dangling link too (it must not be "created through")
    let dangling = f.t.path("dangling");
    symlink(f.t.path("nowhere"), &dangling).unwrap();
    assert_eq!(f.files("windows", &dangling, &[]).0, EXIT_ERROR);
    assert!(!Path::new(&f.t.path("nowhere")).exists());
    assert_eq!(f.leftovers(), Vec::<String>::new());
}

#[test]
fn a_file_or_a_missing_parent_is_refused() {
    let f = Folder::new();
    let a_file = f.t.write_file("plain.txt", b"x");
    let (code, _stdout, err) = f.files("windows", &a_file, &[]);
    assert_eq!(code, EXIT_ERROR);
    assert!(err.contains("Not a folder"), "{err}");
    let (code, _stdout, err) = f.files("windows", &f.t.path("a/b"), &[]);
    assert_eq!(code, EXIT_ERROR);
    assert!(err.contains("parent folder does not exist"), "{err}");
    assert!(!Path::new(&f.t.path("a")).exists());
}

#[test]
fn invalid_files_write_nothing() {
    let f = Folder::new();
    *lock(&f.t.engine.validate_files) = Box::new(|_| Err(Error::value("path is absolute")));
    let out = f.out_dir("seed-files");
    let (code, stdout, err) = f.files("windows", &out, &[]);
    assert_eq!((code, stdout.as_str()), (EXIT_ERROR, ""));
    assert!(err.contains("path is absolute"), "{err}");
    assert!(!Path::new(&out).exists());
    assert_eq!(f.leftovers(), Vec::<String>::new());
}

#[test]
fn the_shared_validator_checks_what_gets_written() {
    let f = Folder::new();
    f.files("debian", &f.out_dir("seed-files"), &[]);
    assert_eq!(*lock(&f.t.engine.validate_calls), [seed_files(SeedTarget::Debian).1]);
}

#[cfg(unix)]
#[test]
fn a_failure_halfway_leaves_nothing_behind() {
    // Python: os.open fails on its third call (ENOSPC). Here the file opener handed to the writer fails the same way.
    let f = Folder::new();
    let out = PathBuf::from(f.out_dir("seed-files"));
    let calls = AtomicUsize::new(0);
    let flaky = |path: &Path| {
        if calls.fetch_add(1, Ordering::SeqCst) + 1 == 3 {
            return Err(io::Error::from_raw_os_error(libc::ENOSPC));
        }
        create_private_file(path)
    };
    let failure = write_into_with(&f.t.tmp, &out, false, &win_files(), &flaky, &|a, b| fs::rename(a, b)).unwrap_err();
    assert!(format!("{failure:?}").contains("Io"), "{failure:?}");
    assert!(!out.exists());
    assert_eq!(f.leftovers(), Vec::<String>::new());
}

#[cfg(unix)]
#[test]
fn a_failure_while_filling_an_empty_folder_puts_it_back_as_it_was() {
    let f = Folder::new();
    let out = PathBuf::from(f.out_dir("seed-files"));
    fs::create_dir(&out).unwrap();
    let calls = AtomicUsize::new(0);
    let flaky = |from: &Path, to: &Path| {
        if calls.fetch_add(1, Ordering::SeqCst) + 1 == 2 {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        fs::rename(from, to)
    };
    let failure =
        write_into_with(&f.t.tmp, &out, true, &seed_files(SeedTarget::Ubuntu).1, &create_private_file, &flaky)
            .unwrap_err();
    assert!(format!("{failure:?}").contains("Io"), "{failure:?}");
    assert_eq!(fs::read_dir(&out).unwrap().count(), 0);
    assert_eq!(f.leftovers(), Vec::<String>::new());
}

#[test]
fn a_file_that_cannot_be_created_halfway_is_reported_and_leaves_nothing() {
    // The same promise through the whole command: "a" is a file, so "a/b" cannot be created under it.
    let f = Folder::new();
    *lock(&f.t.engine.files_seed) = Box::new(|_| Ok((s("CIDATA"), files_of(&[("a", b"x"), ("a/b", b"y")]))));
    let out = f.out_dir("seed-files");
    let (code, stdout, err) = f.files("ubuntu", &out, &[]);
    assert_eq!((code, stdout.as_str()), (EXIT_ERROR, ""));
    assert!(err.contains("Could not write the hardening files to"), "{err}");
    assert!(err.contains("Nothing was left behind."), "{err}");
    assert!(!Path::new(&out).exists());
    assert_eq!(f.leftovers(), Vec::<String>::new());
}

#[test]
fn paths_that_escape_the_folder_are_never_written() {
    // Defence in depth: even a validator that let a bad path through cannot make the command write outside.
    let f = Folder::new();
    for bad in ["../evil.txt", "/abs/evil.txt", "a//b.txt", "a/../../evil.txt", ""] {
        *lock(&f.t.engine.files_seed) = Box::new(move |_| Ok((s("CIDATA"), files_of(&[(bad, b"x")]))));
        let out = f.out_dir("seed-files");
        let (code, _stdout, err) = f.files("ubuntu", &out, &[]);
        assert_eq!(code, EXIT_ERROR, "{bad:?}");
        assert!(err.contains("Refusing a path outside the folder"), "{bad:?}: {err}");
        assert!(!Path::new(&f.t.path("evil.txt")).exists());
        assert!(!Path::new(&out).exists());
        assert_eq!(f.leftovers(), Vec::<String>::new());
    }
}

#[test]
fn harden_files_json_shape() {
    let f = Folder::new();
    let out = f.out_dir("seed-files");
    let (code, stdout, err) = f.files("fedora", &out, &["--json"]);
    assert_eq!(code, 0);
    let data = json(&stdout);
    assert_eq!(data["target"], "fedora");
    assert_eq!(data["out"], out.as_str());
    assert_eq!(data["volume_label"], "OEMDRV");
    let files = seed_files(SeedTarget::Fedora).1;
    let expected: Vec<serde_json::Value> =
        sorted_names(&files).iter().map(|n| serde_json::json!({"path": n, "bytes": files[n.as_str()].len()})).collect();
    assert_eq!(data["files"], serde_json::Value::Array(expected));
    assert!(!err.contains("\"files\""));
    let windows = json(&f.files("windows", &f.out_dir("w"), &["--json"]).1);
    assert!(windows["volume_label"].is_null());
}

#[test]
fn no_drive_and_no_privileges_are_involved() {
    let f = Folder::new();
    let (code, _stdout, _err) = f.files("windows", &f.out_dir("seed-files"), &[]);
    assert_eq!(code, 0);
    assert_eq!(f.t.engine.list_calls.load(Ordering::SeqCst), 0);
    assert_eq!(f.t.engine.auth_calls(), 0);
    assert!(f.t.engine.builds().is_empty() && f.t.engine.seeds().is_empty() && f.t.engine.pin_log().is_empty());
}

#[test]
fn it_works_where_no_drive_can_be_written() {
    let f = Folder::new();
    f.t.engine.supported.store(false, Ordering::SeqCst);
    assert_eq!(f.files("ubuntu", &f.out_dir("seed-files"), &[]).0, 0);
}

#[test]
fn the_tilde_is_expanded() {
    let mut f = Folder::new();
    f.t.env_vars.push((s("HOME"), f.t.tmp.display().to_string()));
    let (code, _stdout, err) = f.files("windows", "~/from-home", &[]);
    assert_eq!(code, 0, "{err}");
    assert!(f.t.tmp.join("from-home").join("answer-standin.xml").is_file());
    assert!(err.contains(&format!("{}/from-home", f.t.tmp.display())), "{err}");
}

#[test]
fn the_out_path_is_made_absolute_and_normalised_lexically() {
    let f = Folder::new();
    let (code, _stdout, err) = f.files("windows", &format!("{}/definitely/not/here/../x", f.t.tmp.display()), &[]);
    assert_eq!(code, EXIT_ERROR);
    assert!(
        err.contains(&format!("The parent folder does not exist: {}/definitely/not\n", f.t.tmp.display())),
        "{err}"
    );
}

// ===== hardening2: engine-cli tests (windows-seed) =====
#[cfg(unix)]
#[test]
fn windows_seed_writes_the_seed_drive_files() {
    use std::os::unix::fs::PermissionsExt;
    let f = Folder::new();
    let files = seed_files(SeedTarget::Windows).1;
    let out = f.out_dir("out-ws");
    let (code, stdout, err) = f.files("windows-seed", &out, &[]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(stdout.lines().map(|l| l.to_string()).collect::<Vec<_>>(), sorted_names(&files));
    assert!(err.contains("No drive was touched"));
    assert!(!err.contains("EXPERIMENTAL"));
    let mut names: Vec<String> =
        fs::read_dir(&out).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
    names.sort();
    assert_eq!(names, sorted_names(&files), "flat, with the Windows names");
    for (rel, data) in &files {
        let path = Path::new(&out).join(rel);
        assert_eq!(&fs::read(&path).unwrap(), data, "CRLF and BOM untouched");
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    assert_eq!(fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(f.leftovers(), Vec::<String>::new());
    for removed in ["autounattend.xml", "EPMA-SEED.txt", "SetupComplete.cmd"] {
        assert!(!names.contains(&removed.to_string()));
    }
}

#[test]
fn windows_seed_asks_the_content_function_for_the_windows_seed() {
    let f = Folder::new();
    f.files("windows-seed", &f.out_dir("a"), &[]);
    assert_eq!(*lock(&f.t.engine.files_seed_calls), [(SeedTarget::Windows, Hardening::Baseline)]);
    assert!(lock(&f.t.engine.files_windows_calls).is_empty());
}

#[test]
fn windows_still_means_the_same_usb_set() {
    let f = Folder::new();
    let out = f.out_dir("seed-files");
    let (code, stdout, _err) = f.files("windows", &out, &[]);
    assert_eq!(code, 0);
    assert_eq!(stdout.lines().map(|l| l.to_string()).collect::<Vec<_>>(), sorted_names(&win_files()));
    assert_eq!(*lock(&f.t.engine.files_windows_calls), [Hardening::Baseline]);
    assert!(lock(&f.t.engine.files_seed_calls).is_empty());
    assert!(Path::new(&out)
        .join("sources")
        .join("$OEM$")
        .join("$$")
        .join("Setup")
        .join("Scripts")
        .join("harden.ps1")
        .is_file());
}

#[test]
fn windows_points_to_windows_seed_for_the_seed_drive_files_on_stderr_only() {
    let f = Folder::new();
    for (i, flag) in [vec![], vec!["--json"]].into_iter().enumerate() {
        let (code, stdout, err) = f.files("windows", &f.out_dir(&format!("same-usb{i}")), &flag);
        assert_eq!(code, 0);
        assert!(err.contains("--target windows-seed"), "{err}");
        assert!(err.contains("SAME USB"), "{err}");
        assert!(!stdout.contains("windows-seed"), "the data on stdout (names or JSON) is unchanged");
        if !flag.is_empty() {
            let paths: Vec<String> = json(&stdout)["files"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["path"].as_str().unwrap().to_string())
                .collect();
            assert_eq!(paths, sorted_names(&win_files()));
        }
    }
    for target in ["windows-seed", "ubuntu", "fedora", "debian"] {
        let err = f.files(target, &f.out_dir(&format!("o-{target}")), &[]).2; // the note is for the same-USB set only
        assert!(!err.contains("SAME USB"), "{target}");
    }
}

#[test]
fn during_setup_is_an_unrecognised_argument_for_harden_files() {
    let f = Folder::new();
    for target in ["windows", "windows-seed", "ubuntu", "fedora", "debian"] {
        let out = f.out_dir(&format!("out-{target}"));
        let (code, stdout, err) = f.files(target, &out, &["--during-setup"]);
        assert_eq!((code, stdout.as_str()), (2, ""), "{target}");
        assert!(err.contains("unrecognized arguments: --during-setup"), "{err}");
        assert!(!Path::new(&out).exists());
    }
    assert!(lock(&f.t.engine.files_seed_calls).is_empty());
    assert!(lock(&f.t.engine.files_windows_calls).is_empty());
    assert_eq!(f.leftovers(), Vec::<String>::new());
}

#[test]
fn a_folder_that_is_not_empty_is_still_refused_for_windows_seed() {
    let f = Folder::new();
    let out = f.out_dir("seed-files");
    f.t.write_file("seed-files/notes.txt", b"mine");
    let before = f.tree(&out);
    let (code, stdout, err) = f.files("windows-seed", &out, &[]);
    assert_eq!((code, stdout.as_str()), (EXIT_ERROR, ""));
    assert!(err.contains("not empty"), "{err}");
    assert_eq!(f.tree(&out), before);
    assert_eq!(f.leftovers(), Vec::<String>::new());
}

#[cfg(unix)]
#[test]
fn a_symbolic_link_is_still_refused_for_windows_seed() {
    use std::os::unix::fs::symlink;
    let f = Folder::new();
    let real = f.t.path("real-empty");
    fs::create_dir(&real).unwrap();
    let link = f.t.path("link");
    symlink(&real, &link).unwrap();
    let (code, _stdout, err) = f.files("windows-seed", &link, &[]);
    assert_eq!(code, EXIT_ERROR);
    assert!(err.contains("symbolic link"), "{err}");
    assert_eq!(fs::read_dir(&real).unwrap().count(), 0);
}

#[test]
fn windows_seed_files_are_checked_by_the_shared_validator() {
    let f = Folder::new();
    f.files("windows-seed", &f.out_dir("seed-files"), &[]);
    assert_eq!(*lock(&f.t.engine.validate_calls), [seed_files(SeedTarget::Windows).1]);
    *lock(&f.t.engine.validate_files) = Box::new(|_| Err(Error::value("name is reserved")));
    let out = f.out_dir("refused");
    let (code, stdout, err) = f.files("windows-seed", &out, &[]);
    assert_eq!((code, stdout.as_str()), (EXIT_ERROR, ""));
    assert!(err.contains("name is reserved"), "{err}");
    assert!(!Path::new(&out).exists());
}

#[test]
fn json_shape_has_no_during_setup_and_keeps_its_keys() {
    let f = Folder::new();
    let keys = ["files", "out", "target", "volume_label"];
    let data = json(&f.files("windows-seed", &f.out_dir("j1"), &["--json"]).1);
    let mut got: Vec<&str> = data.as_object().unwrap().keys().map(|k| k.as_str()).collect();
    got.sort();
    assert_eq!(got, keys);
    assert_eq!((data["target"].as_str(), data["volume_label"].as_str()), (Some("windows-seed"), Some("EPMA-SEED")));
    let files = seed_files(SeedTarget::Windows).1;
    let expected: Vec<serde_json::Value> =
        sorted_names(&files).iter().map(|n| serde_json::json!({"path": n, "bytes": files[n.as_str()].len()})).collect();
    assert_eq!(data["files"], serde_json::Value::Array(expected));
    for target in ["windows", "debian"] {
        let data = json(&f.files(target, &f.out_dir(&format!("j{target}")), &["--json"]).1);
        let mut got: Vec<&str> = data.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        got.sort();
        assert_eq!(got, keys);
    }
}

// ===== SeedSizeAndConflictTests =====
const TOO_SMALL: &str = "The drive (16.0 MB) is too small for a seed drive (at least 64.0 MB). Nothing was changed.";

#[test]
fn the_size_is_checked_with_the_size_of_the_listed_drive() {
    let t = case();
    let (code, _out, _err) = seed(&t, &["--dry-run"], "ubuntu");
    assert_eq!(code, 0);
    assert_eq!(*lock(&t.engine.size_calls), [Some(16 * GIB)]);
}

#[test]
fn a_dry_run_flags_a_too_small_drive() {
    let t = case();
    *lock(&t.engine.size_check) = Box::new(|_| Err(Error::value(TOO_SMALL)));
    let (code, out, err) = seed(&t, &["--dry-run"], "ubuntu");
    assert_eq!(code, EXIT_USAGE);
    assert_eq!(out, "", "no plan was printed");
    assert!(err.contains("too small for a seed drive"), "{err}");
    assert!(!err.contains("Traceback"));
    assert!(!err.contains("Dry run: nothing was changed"));
    assert!(t.engine.seeds().is_empty());
}

#[test]
fn the_refusal_comes_before_any_confirmation_or_password() {
    let t = interactive(case());
    *lock(&t.engine.size_check) = Box::new(|_| Err(Error::value(TOO_SMALL)));
    let (code, _out, err) = seed_in(&t, &[], "ubuntu", "disk9\n");
    assert_eq!(code, EXIT_USAGE);
    assert!(!t.stdin_touched.load(Ordering::SeqCst), "the typed identifier was never asked for");
    assert!(!err.contains("PERMANENTLY ERASE"));
    assert_eq!(t.engine.auth_calls(), 0);
    assert!(t.engine.pin_log().is_empty());
    assert!(t.engine.seeds().is_empty());
}

#[test]
fn the_refusal_is_a_json_error_too() {
    let t = case();
    *lock(&t.engine.size_check) = Box::new(|_| Err(Error::value(TOO_SMALL)));
    let (code, out, _err) = seed(&t, &["--json", "--yes"], "ubuntu");
    assert_eq!(code, EXIT_USAGE);
    let result = json(&out);
    assert_eq!(result["ok"], false);
    assert_eq!(result["exit_code"], 2);
    assert!(result["error"].as_str().unwrap().contains("too small"));
}

#[test]
fn an_iso_that_already_holds_the_hardening_files_exits_2_with_the_message() {
    let c = write_case();
    let text = "This ISO already contains the hardening files (answer-standin.xml). Nothing was changed.";
    c.t.engine.on_build(move |_, _| Err(Error::value(text)));
    let (code, out, err) = c.t.run(&c.t.write_args(&c.win, &["--yes", "--hardened", "--mode", "windows", "--json"]));
    assert_eq!(code, EXIT_USAGE);
    assert_eq!(json(&out)["exit_code"], 2);
    assert!(err.contains("already contains the hardening files"), "{err}");
    assert!(!err.contains("Traceback"));
    assert!(!err.contains("Unexpected failure"));
    assert_eq!(c.t.engine.pin_log().last().unwrap(), &(s("disk9"), None));
}

#[test]
fn other_engine_value_errors_keep_exit_1() {
    let c = write_case();
    c.t.engine.on_build(|_, _| Err(Error::value("bad value")));
    let (code, _out, _err) = c.t.run(&c.t.write_args(&c.win, &["--yes", "--hardened", "--mode", "windows"]));
    assert_eq!(code, 1);
}

// ===== EpilogTests =====
#[test]
fn the_read_back_claim_is_true_for_every_write_command() {
    let text = crate::cli::cli_epilog();
    assert!(text.contains("compared with its source"));
    assert!(!text.contains("compared with the ISO"));
}
