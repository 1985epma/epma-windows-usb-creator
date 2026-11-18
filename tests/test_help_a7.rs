//! Port of the command line parts of tests/test_help.py (`MatchesTheCodeTests`, `ChromeOSSectionTests`) and of
//! `HelpAndDocsTests` of tests/test_cli_hardening.py: the Help window's "Command line" section (src/help.rs, A5) must
//! agree with the parser and the exit codes of the command line (src/cli, A7).

use epma_usb_creator::cli::{
    build_cli_parser, EXIT_EJECT_FAILED, EXIT_ERROR, EXIT_INTERRUPTED, EXIT_OK, EXIT_USAGE, EXIT_VERIFY_FAILED,
};
use epma_usb_creator::help::help_sections;
use regex::Regex;

fn sections() -> Vec<(String, String)> {
    help_sections()
}

fn section(title: &str) -> String {
    sections().into_iter().find(|(t, _)| t == title).map(|(_, b)| b).unwrap_or_else(|| panic!("no section {title:?}"))
}

fn all_text() -> String {
    sections().iter().map(|(t, b)| format!("{t}\n{b}")).collect::<Vec<_>>().join("\n")
}

fn subcommand_help(name: &str) -> String {
    let mut parser = build_cli_parser();
    parser.build();
    parser.find_subcommand_mut(name).unwrap_or_else(|| panic!("no command {name}")).render_help().to_string()
}

#[test]
fn every_cli_command_is_documented() {
    let commands: Vec<String> = build_cli_parser().get_subcommands().map(|c| c.get_name().to_string()).collect();
    assert!(!commands.is_empty(), "could not read the sub-commands from the parser");
    let text = section("Command line");
    for command in commands {
        let re = Regex::new(&format!(r"(?m)^• {}\b", regex::escape(&command))).unwrap();
        assert!(re.is_match(&text), "{command} is not documented in:\n{text}");
    }
}

#[test]
fn every_exit_code_is_documented_with_its_value() {
    let text = section("Command line");
    for code in [EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_VERIFY_FAILED, EXIT_EJECT_FAILED, EXIT_INTERRUPTED] {
        let re = Regex::new(&format!(r"(?m)^• {code} ")).unwrap();
        assert!(re.is_match(&text), "exit code {code} is not documented in:\n{text}");
    }
}

#[test]
fn the_documented_write_flags_exist_in_the_parser() {
    let write_help = subcommand_help("write");
    let documented = section("Command line");
    for flag in ["--iso", "--disk", "--mode", "--dry-run", "--yes", "--no-eject", "--json"] {
        assert!(write_help.contains(flag), "{flag} is not a write flag");
        assert!(documented.contains(flag), "{flag} is not documented");
    }
    // verification is not optional and the help must not suggest otherwise
    assert!(!write_help.contains("--no-verify"));
    assert!(!all_text().contains("--no-verify"));
    assert!(section("Verification and eject").contains("cannot be skipped"));
}

#[test]
fn the_overview_and_command_line_mention_chromeos() {
    let text = section("Command line");
    assert!(Regex::new(r"(?m)^• fetch-chromeos ").unwrap().is_match(&text));
    assert!(text.contains("--mode auto|windows|linux|chromeos"));
}

#[test]
fn the_command_line_help_section_documents_the_new_commands() {
    let text = section("Command line");
    for needle in ["• harden-seed ", "• harden-files ", "--hardened", "windows-seed"] {
        assert!(text.contains(needle), "{needle}");
    }
    assert!(!text.contains("--during-setup"));
    assert!(!text.contains("autounattend"));
    let claims = Regex::new(r"(?i)\b(CIS|STIG|NIST|certified|compliant|compliance)\b").unwrap();
    assert!(!claims.is_match(&text), "no compliance claims");
}

#[test]
fn the_help_flags_exist_in_the_parser() {
    let text = section("Command line");
    for (command, flags) in [
        ("harden-seed", &["--target", "--disk", "--dry-run", "--yes", "--no-eject", "--json"][..]),
        ("harden-files", &["--target", "--out", "--json"][..]),
        ("write", &["--hardened"][..]),
    ] {
        let help = subcommand_help(command);
        for flag in flags {
            assert!(help.contains(flag), "{command} {flag} is not in the parser");
            assert!(text.contains(flag), "{command} {flag} is not documented");
        }
    }
}

#[test]
fn every_documented_write_option_value_is_a_parser_choice() {
    // "--mode auto|windows|linux|chromeos" and "--target ubuntu|fedora|debian|windows" are spelled out in the help
    let mode_help = subcommand_help("write");
    for choice in ["auto", "windows", "linux", "chromeos"] {
        assert!(mode_help.contains(choice), "{choice}");
    }
    let seed_help = subcommand_help("harden-seed");
    for choice in ["ubuntu", "fedora", "debian", "windows"] {
        assert!(seed_help.contains(choice), "{choice}");
    }
}
