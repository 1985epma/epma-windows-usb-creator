//! The built-in documentation (Help menu) must stay in step with the program. Port of tests/test_help.py (21 tests).
//!
//! Everything it states that can drift - commands, exit codes, environment variables, thresholds, messages, the audit
//! log path - is checked here against the code itself. No window is needed: the documentation is plain data.
//!
//! `help_sections()` needs three other modules (the audit log path, the platform name, the Windows hardening
//! descriptions), so most tests call `help_sections_with`, which takes those pieces as arguments; the tests that
//! compare with the real modules need the other modules (all merged now).

use epma_usb_creator::cli::{EXIT_EJECT_FAILED, EXIT_ERROR, EXIT_INTERRUPTED, EXIT_OK, EXIT_USAGE, EXIT_VERIFY_FAILED};
use epma_usb_creator::constants::*;
use epma_usb_creator::diskrisk::{LARGE_DISK_BYTES, MANY_VOLUMES, SUBSTANTIAL_USED_BYTES};
use epma_usb_creator::help::{help_sections, help_sections_with};
use regex::Regex;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const GOLDEN: &str = include_str!("golden/help_sections.json");
const WINDOWS_DESCRIBE: &str = include_str!("golden/windows_describe.json");
const FAKE_AUDIT_PATH: &str = "/home/someone/.local/state/epma-win11-usb-creator/audit.log";
const FAKE_PLATFORM: &str = "Testix 1.0";

/// Rows of `WINDOWS_HARDENING_NOT_CHANGED` as the Python has them (the real constant is `harden_windows`'s).
const NOT_CHANGED: &[(&str, &str, &str)] = &[
    (
        "bitlocker",
        "BitLocker is not turned on automatically",
        "It needs a TPM, a choice of where the recovery key goes and the owner's consent; a wrong default can lock someone out of their own data.",
    ),
    (
        "ntlm",
        "NTLM authentication levels are left as they are",
        "Stricter levels can break access to older file shares, printers and NAS devices without any warning.",
    ),
    (
        "accounts_disks",
        "Accounts, passwords, disks, language, licence and product key",
        "Windows Setup stays fully interactive; the hardening script never touches them.",
    ),
    (
        "device_guard",
        "Memory Integrity (HVCI), Credential Guard and Exploit Protection are only reported, never turned on",
        "They depend on the hardware, drivers and apps of each PC and can stop a PC from starting or a program from running; Audit mode shows their state so the owner can decide.",
    ),
];

fn applied_lines() -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(WINDOWS_DESCRIBE).unwrap();
    v["applied"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect()
}

fn pairs_with(audit_path: &str, platform: &str) -> Vec<(String, String)> {
    help_sections_with(audit_path, platform, &applied_lines(), NOT_CHANGED)
}

fn pairs() -> Vec<(String, String)> {
    pairs_with(FAKE_AUDIT_PATH, FAKE_PLATFORM)
}

fn section(title: &str) -> String {
    pairs().into_iter().find(|(t, _)| t == title).unwrap_or_else(|| panic!("no section {title}")).1
}

fn all_text() -> String {
    pairs().iter().map(|(t, b)| format!("{t}\n{b}")).collect::<Vec<_>>().join("\n")
}

fn re(p: &str) -> Regex {
    Regex::new(p).unwrap()
}

const GIB: u64 = 1024 * 1024 * 1024;

// ---------------------------------------------------------------------------------------------------------------
// StructureTests
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn every_section_has_a_unique_title_and_a_body() {
    let pairs = pairs();
    let titles: BTreeSet<&str> = pairs.iter().map(|(t, _)| t.as_str()).collect();
    assert_eq!(titles.len(), pairs.len());
    for (title, body) in &pairs {
        assert!(!title.trim().is_empty());
        assert!(body.trim().len() > 80, "{title}");
    }
}

#[test]
fn expected_sections_exist_in_a_sensible_order() {
    let pairs = pairs();
    let titles: Vec<&str> = pairs.iter().map(|(t, _)| t.as_str()).collect();
    assert_eq!(titles[0], "Overview");
    assert_eq!(titles[titles.len() - 1], "About");
    for needed in [
        "Quick start: Windows 11",
        "Quick start: Linux and other ISOs",
        "Safety",
        "Verification and eject",
        "Command line",
        "Troubleshooting",
    ] {
        assert!(titles.contains(&needed), "{needed}");
    }
    // the whole list, in the order the Python had (the Help window renders them in this order)
    assert_eq!(
        titles,
        [
            "Overview",
            "Quick start: Windows 11",
            "Quick start: Linux and other ISOs",
            "Hardened setup (optional)",
            "ChromeOS Flex",
            "Getting the image",
            "The drive and the Create button",
            "Safety",
            "Verification and eject",
            "Command line",
            "Troubleshooting",
            "Files, logs and settings",
            "About",
        ]
    );
}

#[test]
fn lines_use_only_the_supported_markup() {
    for (title, body) in pairs() {
        for line in body.lines() {
            assert!(!(line.starts_with("##") && !line.starts_with("## ")), "{title}: {line}");
            assert!(!(line.starts_with('•') && !line.starts_with("• ")), "{title}: {line}");
        }
    }
}

#[test]
fn no_unformatted_placeholders_are_left() {
    let text = all_text();
    assert!(!re(r"\{[A-Za-z_]+\}").is_match(&text));
    for marker in [
        "@HOSTS@",
        "@GUIDE@",
        "@REQUIREMENTS@",
        "@URL@",
        "@RETRIES@",
        "@ATTEMPTS@",
        "@WINDOWS_SETTINGS@",
        "@NOT_CHANGED@",
    ] {
        assert!(!text.contains(marker), "{marker}");
    }
    assert!(!text.contains("noqa")); // a lint comment must never end up inside the text
}

// ---------------------------------------------------------------------------------------------------------------
// MatchesTheCodeTests
// ---------------------------------------------------------------------------------------------------------------

/// The sub-commands of the command line (`build_cli_parser`'s choices). The Python test reads them from the parser;
/// the clap definition lives in `cli` (not available to this crate's tests as a list), so they are named here.
const CLI_COMMANDS: [&str; 8] =
    ["gui", "list", "detect", "sha256", "fetch-chromeos", "write", "harden-seed", "harden-files"];

#[test]
fn every_cli_command_is_documented() {
    let text = section("Command line");
    for command in CLI_COMMANDS {
        let pattern = format!(r"(?m)^• {}\b", regex::escape(command));
        assert!(re(&pattern).is_match(&text), "{command}");
    }
}

#[test]
fn every_exit_code_is_documented_with_its_value() {
    let text = section("Command line");
    for (name, value) in [
        ("EXIT_OK", EXIT_OK),
        ("EXIT_ERROR", EXIT_ERROR),
        ("EXIT_USAGE", EXIT_USAGE),
        ("EXIT_VERIFY_FAILED", EXIT_VERIFY_FAILED),
        ("EXIT_EJECT_FAILED", EXIT_EJECT_FAILED),
        ("EXIT_INTERRUPTED", EXIT_INTERRUPTED),
    ] {
        assert!(re(&format!(r"(?m)^• {value} ")).is_match(&text), "{name}");
    }
}

#[test]
fn the_documented_write_flags_exist_in_the_text() {
    // (the Python also checks the flags against the parser's `write --help`; that part needs the `cli` module)
    let command_line = section("Command line");
    for flag in ["--iso", "--disk", "--mode", "--dry-run", "--yes", "--no-eject", "--json"] {
        assert!(command_line.contains(flag), "{flag}");
    }
    // verification is not optional and the help must not suggest otherwise
    assert!(!all_text().contains("--no-verify"));
    assert!(section("Verification and eject").contains("cannot be skipped"));
}

#[test]
fn environment_variables_come_from_the_code() {
    let text = section("Files, logs and settings");
    for name in
        [ENV_AUDIT_LOG, ENV_DISABLE_AUDIT_LOG, ENV_TRUSTED_HOSTS, ENV_ALLOW_ANY_HOST, ENV_EXPECTED_SHA256, ENV_LANG]
    {
        assert!(text.contains(name), "{name}");
    }
}

#[test]
fn the_audit_log_path_is_the_one_given() {
    assert!(section("Files, logs and settings").contains(FAKE_AUDIT_PATH));
}

#[test]
fn the_audit_log_path_is_the_real_one() {
    let real = epma_usb_creator::audit::audit_log_path().display().to_string();
    let text = help_sections().into_iter().find(|(t, _)| t == "Files, logs and settings").unwrap().1;
    assert!(text.contains(&real));
}

#[test]
fn risk_thresholds_match_the_constants() {
    let text = section("The drive and the Create button");
    assert!(text.contains(&format!("larger than {} GB", LARGE_DISK_BYTES / GIB)));
    assert!(text.contains(&format!("{} GB or more in use", SUBSTANTIAL_USED_BYTES / GIB)));
    assert!(text.contains(&format!("{MANY_VOLUMES} or more volumes")));
}

#[test]
fn trusted_download_hosts_are_listed() {
    let text = section("Getting the image");
    for host in DEFAULT_TRUSTED_ISO_HOSTS {
        assert!(text.contains(host), "{host}");
    }
    assert!(
        text.contains(&format!("up to {} retries, {DOWNLOAD_MAX_ATTEMPTS} attempts in all", DOWNLOAD_MAX_ATTEMPTS - 1))
    );
}

#[test]
fn version_license_and_project_link() {
    let about = section("About");
    assert!(about.contains(VERSION));
    assert!(about.contains(PROJECT_URL));
    assert!(about.contains("GNU General Public License v3"));
    assert!(section("Overview").contains(&format!("EPMA USB CREATOR {VERSION}")));
    assert!(about.contains(&format!("Platform: {FAKE_PLATFORM}")));
}

#[test]
fn about_describes_the_rust_build() {
    let about = section("About");
    assert!(about.ends_with("The program is written in Rust and bundles its libraries."));
    for stale in ["Python", "Tkinter", "standard library", "third-party dependencies"] {
        assert!(!all_text().contains(stale), "{stale}");
    }
}

#[test]
fn filesystem_label_matches() {
    assert!(section("Overview").contains(VOL_NAME));
}

/// The documentation quotes messages users will see; they must exist in the code. (Python: `inspect.getsource(app)`.)
const QUOTED_MESSAGES: [&str; 7] = [
    "Could not find sources/install.wim or sources/install.esd on the ISO",
    "This ISO is not a bootable hybrid image",
    "Aborted for safety",
    "Neither 'sudo' nor 'pkexec' was found",
    "wimlib-imagex not found",
    "Verification FAILED",
    "Drive ejected \u{2014} you can unplug it now.",
];

#[test]
fn quoted_messages_are_in_the_documentation() {
    let documentation = all_text();
    for message in QUOTED_MESSAGES {
        assert!(documentation.contains(message), "{message}");
    }
}

/// All the Rust source of the crate except the help text itself.
fn crate_source(subdir: &str) -> String {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(subdir), &mut files);
    files.sort();
    files
        .iter()
        .filter(|p| p.file_name().is_some_and(|n| n != "help.rs"))
        .map(|p| std::fs::read_to_string(p).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn quoted_messages_exist_in_the_code() {
    // Troubleshooting quotes the exact messages users will see. If one is reworded in the code, the documentation
    // must be reworded too (this test then fails).
    let source = crate_source("");
    for message in QUOTED_MESSAGES {
        assert!(source.contains(message), "{message}");
    }
}

// ---------------------------------------------------------------------------------------------------------------
// ChromeOSSectionTests
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn chromeos_section_exists_and_uses_the_real_addresses() {
    let text = section("ChromeOS Flex");
    for url in [CHROMEOS_FLEX_URL, CHROMEOS_FLEX_GUIDE_URL, CHROMEOS_FLEX_REQUIREMENTS_URL] {
        assert!(text.contains(url), "{url}");
    }
}

#[test]
fn chromeos_says_regular_chromeos_is_not_offered_and_what_is_required() {
    let text = section("ChromeOS Flex");
    assert!(text.contains("does not publish regular ChromeOS"));
    assert!(text.contains("16 GB or larger"));
    assert!(text.contains("4 GB of RAM"));
}

#[test]
fn chromeos_the_overview_and_command_line_mention_it() {
    assert!(section("Overview").contains("ChromeOS Flex"));
    assert!(section("Overview").contains("Google Chrome"));
    assert!(re(r"(?m)^• fetch-chromeos ").is_match(&section("Command line")));
    assert!(section("Command line").contains("--mode auto|windows|linux|chromeos"));
}

#[test]
fn chromeos_the_ui_strings_it_quotes_exist() {
    let source = crate_source("");
    for label in [
        "Download ChromeOS Flex from Google",
        "Select existing ISO file...",
        "Create Bootable USB Drive",
        "Refresh USB drives list",
        "Install missing dependencies",
        "Calculate SHA-256",
        "Open Microsoft's official page",
    ] {
        assert!(source.contains(label), "{label}");
    }
}

#[test]
fn chromeos_the_cards_it_names_are_in_the_text() {
    let named = [
        section("Overview"),
        section("Quick start: Windows 11"),
        section("Quick start: Linux and other ISOs"),
        section("ChromeOS Flex"),
        section("The drive and the Create button"),
    ]
    .join("");
    for card in ["Google Chrome", "Windows 11", "Linux", "Other ISO"] {
        assert!(named.contains(&format!("\"{card}\"")), "{card}");
    }
}

#[test]
fn chromeos_the_cards_it_names_exist_in_the_window() {
    let source = crate_source("gui");
    for card in ["Google Chrome", "Windows 11", "Linux", "Other ISO"] {
        assert!(source.contains(&format!("\"{card}\"")), "{card}");
    }
}

#[test]
fn no_section_still_talks_about_tabs() {
    let tabs = re(r"(?i)\btab [0-9]\b|\bthe tab\b|\bthat tab\b|\bon tab\b");
    for (title, body) in pairs() {
        assert!(!tabs.is_match(&body), "{title}");
    }
}

// ---------------------------------------------------------------------------------------------------------------
// AboutAndProjectTests
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn project_url_is_https_github() {
    assert!(re(r"^https://github\.com/[^/]+/[^/]+$").is_match(PROJECT_URL));
}

// ---------------------------------------------------------------------------------------------------------------
// Golden: the text of the Python `help_sections()` (tests/golden/help_sections.json)
// ---------------------------------------------------------------------------------------------------------------

fn golden() -> Vec<(String, String)> {
    let v: Vec<Vec<String>> = serde_json::from_str(GOLDEN).unwrap();
    v.into_iter().map(|p| (p[0].clone(), p[1].clone())).collect()
}

/// The golden text with the three deliberate changes of the Rust build applied (see the header of `help.rs`).
fn expected_for_rust(title: &str, body: &str) -> String {
    match title {
        "Command line" => body.replace("(no Tkinter needed)", "(no window is needed)"),
        "Troubleshooting" => {
            let start = body.find("## \"Tkinter is not available").expect("tkinter entry in the golden");
            let end = body.find("## The computer does not boot").expect("next entry in the golden");
            format!("{}{}", &body[..start], &body[end..])
        }
        "About" => body.replace(
            "The program has no third-party dependencies: it uses only the Python standard library.",
            "The program is written in Rust and bundles its libraries.",
        ),
        _ => body.to_string(),
    }
}

fn golden_line_value(prefix: &str) -> String {
    let all: String = golden().iter().map(|(_, b)| b.as_str()).collect::<Vec<_>>().join("\n");
    all.lines().find_map(|l| l.strip_prefix(prefix)).expect(prefix).to_string()
}

#[test]
fn text_matches_the_python_golden_except_the_deliberate_changes() {
    let audit_path = golden_line_value("• Location: ");
    let platform = golden_line_value("Platform: ");
    let got = pairs_with(&audit_path, &platform);
    let want = golden();
    assert_eq!(got.len(), want.len());
    for ((got_title, got_body), (want_title, want_body)) in got.iter().zip(&want) {
        assert_eq!(got_title, want_title);
        let expected = expected_for_rust(want_title, want_body);
        if *got_body != expected {
            // show the first differing line
            let (g, e): (Vec<&str>, Vec<&str>) = (got_body.lines().collect(), expected.lines().collect());
            let n = g.iter().zip(&e).position(|(a, b)| a != b).unwrap_or(g.len().min(e.len()));
            panic!("section {got_title:?} differs at line {n}:\n  got:  {:?}\n  want: {:?}", g.get(n), e.get(n));
        }
    }
}

#[test]
fn the_deliberate_changes_are_exactly_these() {
    // What the Python text said about Python and Tk is gone; nothing else was dropped from those sections.
    let want = golden();
    for (title, body) in &want {
        let changed = expected_for_rust(title, body) != *body;
        assert_eq!(changed, matches!(title.as_str(), "Command line" | "Troubleshooting" | "About"), "{title}");
    }
}

#[test]
fn text_matches_the_python_golden_with_the_real_modules() {
    // The platform-specific pieces (audit log path, platform name) differ between machines: compare the rest.
    let normalise = |s: &str| {
        s.lines()
            .map(|l| {
                if l.starts_with("• Location: ") {
                    "• Location: <audit log>".to_string()
                } else if l.starts_with("Platform: ") {
                    "Platform: <platform>".to_string()
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let got = help_sections();
    let want = golden();
    assert_eq!(got.len(), want.len());
    for ((got_title, got_body), (want_title, want_body)) in got.iter().zip(&want) {
        assert_eq!(got_title, want_title);
        assert_eq!(normalise(got_body), normalise(&expected_for_rust(want_title, want_body)), "{got_title}");
    }
}
