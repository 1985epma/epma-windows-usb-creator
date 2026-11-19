//! The argument parser (Python `build_cli_parser`, `cli_epilog`, `_add_write_flags`) on top of `clap`, plus the
//! typed arguments every command receives. Usage errors are worded like argparse's (`usage: ...` / `prog: error:
//! ...` on stderr, exit code 2) because scripts and the tests of the Python program rely on that shape.

use super::{CLI_PROG, EXIT_EJECT_FAILED, EXIT_ERROR, EXIT_INTERRUPTED, EXIT_OK, EXIT_USAGE, EXIT_VERIFY_FAILED};
use crate::constants::{
    APP_TAGLINE, ENV_ALLOW_ANY_HOST, ENV_AUDIT_LOG, ENV_DISABLE_AUDIT_LOG, ENV_EXPECTED_SHA256, ENV_LANG,
    ENV_TRUSTED_HOSTS, VERSION,
};
use crate::types::{Mode, SeedTarget};
use clap::builder::PossibleValuesParser;
use clap::error::{ContextKind, ContextValue, ErrorKind};
use clap::{Arg, ArgAction, ArgMatches, ColorChoice, Command};

/// `harden-files --target windows-seed`: the files of the Windows seed drive (`--target windows` is the set that goes
/// on the same USB as the Windows installer).
pub const HARDEN_FILES_WINDOWS_SEED: &str = "windows-seed";
/// `HARDEN_FILES_TARGETS`: "windows", "windows-seed", then the seed targets other than Windows (the macOS seed is new
/// in the Rust build).
pub const HARDEN_FILES_TARGETS: [&str; 6] =
    ["windows", HARDEN_FILES_WINDOWS_SEED, "ubuntu", "fedora", "debian", "macos"];

pub const HARDENED_WINDOWS_ONLY: &str = "--hardened is only available for Windows images (--mode windows). For Linux \
                                         use 'epma-usb-creator harden-seed' with a separate USB drive.";
pub const HARDEN_FILES_WINDOWS_SAME_USB_NOTE: &str = "Note: --target windows is the file set for the SAME USB as the \
                                                      Windows installer (sources\\$OEM$). For the files of a separate \
                                                      Windows seed drive (harden.cmd, audit.cmd, undo.cmd), use \
                                                      --target windows-seed.";

/// What `--help` says about the exit codes. Written out here, next to the constants, and the docs-consistency test
/// fails when an `EXIT_*` constant is missing from this list, so `--help` cannot fall behind the code.
pub const CLI_EXIT_CODE_HELP: [(i32, &str); 6] = [
    (EXIT_OK, "success"),
    (EXIT_ERROR, "error"),
    (EXIT_USAGE, "usage error (also: confirmation missing, ISO kind unknown)"),
    (EXIT_VERIFY_FAILED, "verification failed / checksum mismatch"),
    (EXIT_EJECT_FAILED, "written and verified, but the drive could not be ejected"),
    (EXIT_INTERRUPTED, "interrupted (Ctrl-C)"),
];

/// What `--help` says about the environment variables (same rule as the exit codes: every `ENV_*` constant).
pub const CLI_ENV_HELP: [(&str, &str); 7] = [
    (ENV_AUDIT_LOG, "path of the audit log"),
    (ENV_DISABLE_AUDIT_LOG, "1 = do not write the audit log"),
    (ENV_TRUSTED_HOSTS, "comma-separated trusted download hosts (replaces the Microsoft list)"),
    (ENV_ALLOW_ANY_HOST, "1 = no warning for unrecognised download servers (lowers security)"),
    (ENV_EXPECTED_SHA256, "expected SHA-256 pre-filled in the window (window only)"),
    (ENV_LANG, "pt = Portuguese window (the command line is always English)"),
    ("NO_COLOR", "disable colored messages"),
];

/// The text under `--help`: exit codes and environment variables, built from the constants.
pub fn cli_epilog() -> String {
    let codes: Vec<String> =
        CLI_EXIT_CODE_HELP.iter().map(|(code, meaning)| format!("  {code:<4} {meaning}")).collect();
    let env: Vec<String> = CLI_ENV_HELP.iter().map(|(name, meaning)| format!("  {name:<34} {meaning}")).collect();
    format!(
        "exit codes:\n{}\n\nenvironment (all optional):\n{}\n\nData is written to stdout; messages, errors and \
         progress to stderr.\nThe written drive is always read back and compared with its source (the ISO, or the \
         seed files).",
        codes.join("\n"),
        env.join("\n")
    )
}

// ---------------------------------------------------------------------------------------------------------------
// Typed arguments
// ---------------------------------------------------------------------------------------------------------------

/// The confirmation, dry-run, eject, output and verbosity flags every drive-writing command shares.
#[derive(Clone, Debug, Default)]
pub struct WriteFlags {
    pub yes: bool,
    pub dry_run: bool,
    pub no_eject: bool,
    pub json: bool,
    pub verbose: bool,
    pub debug: bool,
}

#[derive(Clone, Debug)]
pub struct WriteArgs {
    pub iso: String,
    pub disk: String,
    /// `Mode::Auto` (the default), Windows, Linux, ChromeOs or MacOs.
    pub mode: Mode,
    pub hardened: bool,
    pub flags: WriteFlags,
}

#[derive(Clone, Debug)]
pub struct SeedArgs {
    pub target: SeedTarget,
    pub disk: String,
    pub flags: WriteFlags,
}

/// What `harden-files --target` names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilesKind {
    /// The files for the SAME USB as the Windows installer.
    Windows,
    /// The files of the separate Windows seed drive.
    WindowsSeed,
    Seed(SeedTarget),
}

impl FilesKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FilesKind::Windows => "windows",
            FilesKind::WindowsSeed => HARDEN_FILES_WINDOWS_SEED,
            FilesKind::Seed(target) => target.as_str(),
        }
    }
    /// The kind `harden-seed --target` uses: its `windows` is the seed drive, not the same-USB set.
    pub fn of_seed_target(target: SeedTarget) -> FilesKind {
        if target == SeedTarget::Windows {
            FilesKind::WindowsSeed
        } else {
            FilesKind::Seed(target)
        }
    }
    pub fn parse(text: &str) -> Option<FilesKind> {
        match text {
            "windows" => Some(FilesKind::Windows),
            HARDEN_FILES_WINDOWS_SEED => Some(FilesKind::WindowsSeed),
            other => SeedTarget::parse(other).filter(|t| *t != SeedTarget::Windows).map(FilesKind::Seed),
        }
    }
}

#[derive(Clone, Debug)]
pub struct FilesArgs {
    pub target: FilesKind,
    pub out: String,
    pub json: bool,
}

#[derive(Clone, Debug)]
pub enum CliCommand {
    Gui,
    List { json: bool },
    Detect { iso: String, json: bool },
    Sha256 { iso: String, expected: Option<String>, json: bool },
    FetchChromeos { dest: Option<String>, keep_zip: bool, json: bool },
    Write(WriteArgs),
    HardenSeed(SeedArgs),
    HardenFiles(FilesArgs),
}

/// `parse_args()` result: `command` is `Gui` when no command was given (`["--debug"]`).
#[derive(Clone, Debug)]
pub struct Parsed {
    pub command: CliCommand,
    pub debug: bool,
}

/// What a parse that does not lead to a command produces: `--help`, `--version` (exit 0, on stdout) or a usage
/// error (exit 2, on stderr).
#[derive(Debug)]
pub struct Early {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

// ---------------------------------------------------------------------------------------------------------------
// The parser
// ---------------------------------------------------------------------------------------------------------------

fn flag(name: &'static str, long: &'static str, help: &'static str) -> Arg {
    Arg::new(name).long(long).action(ArgAction::SetTrue).help(help)
}

/// `_add_write_flags`.
fn add_write_flags(cmd: Command) -> Command {
    cmd.arg(flag("yes", "yes", "do not ask for confirmation (required when not in an interactive terminal)"))
        .arg(flag("dry_run", "dry-run", "print the plan and exit without touching anything"))
        .arg(flag("no_eject", "no-eject", "leave the drive connected when done"))
        .arg(flag("json", "json", "machine-readable result on stdout"))
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue)
                .help("show every engine log line"),
        )
}

fn json_flag(cmd: Command) -> Command {
    cmd.arg(flag("json", "json", "machine-readable output"))
}

fn sub(name: &'static str, help: &'static str) -> Command {
    Command::new(name).about(help)
}

/// `build_cli_parser()`.
pub fn build_cli_parser() -> Command {
    let disk_help = "drive id as shown by 'list' (disk4 on macOS, sdb on Linux, PhysicalDrive3 on Windows)";
    let mode_choices: Vec<&str> =
        std::iter::once(Mode::Auto.as_str()).chain(Mode::ALL.iter().map(|m| m.as_str())).collect();
    let seed_targets: Vec<&str> = SeedTarget::ALL.iter().map(|t| t.as_str()).collect();
    Command::new(CLI_PROG)
        .bin_name(CLI_PROG)
        .about(format!("{APP_TAGLINE}.\nRun without arguments to open the graphical interface."))
        .after_help(cli_epilog())
        .version(VERSION)
        .disable_version_flag(true)
        .disable_help_subcommand(true)
        .color(ColorChoice::Never)
        .subcommand_value_name("COMMAND")
        .subcommand_help_heading("commands")
        .arg(
            Arg::new("version")
                .long("version")
                .action(ArgAction::Version)
                .help("show program's version number and exit"),
        )
        .arg(
            Arg::new("debug")
                .long("debug")
                .action(ArgAction::SetTrue)
                .global(true)
                .help("show debugging details (like a traceback) for unexpected errors"),
        )
        .subcommand(sub("gui", "open the graphical interface (the default with no arguments)"))
        .subcommand(json_flag(sub("list", "list the USB drives that can be written")))
        .subcommand(json_flag(
            sub("detect", "tell whether an image is windows, linux, chromeos or macos (or unknown)")
                .arg(Arg::new("iso").value_name("ISO").required(true)),
        ))
        .subcommand(json_flag(
            sub("sha256", "compute the SHA-256 of a file, optionally comparing it with a known value")
                .arg(Arg::new("iso").value_name("ISO").required(true))
                .arg(
                    Arg::new("expected")
                        .long("expected")
                        .value_name("HASH")
                        .help("expected SHA-256; exit code 3 if it differs"),
                ),
        ))
        .subcommand(json_flag(
            sub(
                "fetch-chromeos",
                "download ChromeOS Flex from Google and extract the disk image (does not write a drive)",
            )
            .arg(
                Arg::new("dest")
                    .long("dest")
                    .value_name("DIR")
                    .help("folder for the image (default: the current folder)"),
            )
            .arg(flag("keep_zip", "keep-zip", "keep latest.bin.zip after extracting it")),
        ))
        .subcommand(add_write_flags(
            sub("write", "write an ISO or disk image to a USB drive, verify it and eject")
                .after_help("The drive is ERASED. Use --dry-run first to see the plan without changing anything.")
                .arg(
                    Arg::new("iso")
                        .long("iso")
                        .required(true)
                        .value_name("ISO")
                        .help("path of the ISO or disk image (.bin for ChromeOS Flex; use fetch-chromeos to get it)"),
                )
                .arg(Arg::new("disk").long("disk").required(true).value_name("DISKID").help(disk_help))
                .arg(
                    Arg::new("mode")
                        .long("mode")
                        .value_name("MODE")
                        .value_parser(PossibleValuesParser::new(mode_choices))
                        .default_value(Mode::Auto.as_str())
                        .help(
                            "windows: GPT+FAT32 file copy; linux: raw write of a hybrid ISO; chromeos: raw write of a \
                             ChromeOS Flex disk image; macos: raw write of a whole-disk macOS image; auto: detect \
                             (default)",
                        ),
                )
                .arg(flag(
                    "hardened",
                    "hardened",
                    "also add the optional Hardened (recommended settings) files to the Windows drive (Windows mode \
                     only; --dry-run lists them)",
                )),
        ))
        .subcommand(add_write_flags(
            sub(
                "harden-seed",
                "erase a small separate USB drive and write the hardening seed files on it (no operating system image)",
            )
            .after_help(
                "The drive is ERASED. Use --dry-run first to see the plan without changing anything. The seed files \
                 never choose a disk or create accounts.",
            )
            .arg(
                Arg::new("target")
                    .long("target")
                    .required(true)
                    .value_parser(PossibleValuesParser::new(seed_targets))
                    .help(
                        "ubuntu (autoinstall), fedora (kickstart), debian (script + preseed), windows (Windows 11: \
                         harden.cmd to run after install) or macos (macOS: harden.command to run after install)",
                    ),
            )
            .arg(Arg::new("disk").long("disk").required(true).value_name("DISKID").help(disk_help)),
        ))
        .subcommand(json_flag(
            sub("harden-files", "write the hardening files into a new or empty folder (no drive is touched)")
                .after_help("Nothing is overwritten: a folder that is not empty is refused.")
                .arg(
                    Arg::new("target")
                        .long("target")
                        .required(true)
                        .value_parser(PossibleValuesParser::new(HARDEN_FILES_TARGETS))
                        .help(
                            "windows (files for the same USB as Windows), windows-seed (files for the Windows seed \
                             drive), ubuntu, fedora, debian or macos",
                        ),
                )
                .arg(
                    Arg::new("out").long("out").required(true).value_name("DIR").help("a new folder, or an empty one"),
                ),
        ))
}

fn flags_from(m: &ArgMatches) -> WriteFlags {
    WriteFlags {
        yes: m.get_flag("yes"),
        dry_run: m.get_flag("dry_run"),
        no_eject: m.get_flag("no_eject"),
        json: m.get_flag("json"),
        verbose: m.get_flag("verbose"),
        debug: m.get_flag("debug"),
    }
}

fn text(m: &ArgMatches, name: &str) -> String {
    m.get_one::<String>(name).cloned().unwrap_or_default()
}

fn extract(matches: &ArgMatches) -> Parsed {
    let debug = matches.get_flag("debug");
    let command = match matches.subcommand() {
        None | Some(("gui", _)) => CliCommand::Gui,
        Some(("list", m)) => CliCommand::List { json: m.get_flag("json") },
        Some(("detect", m)) => CliCommand::Detect { iso: text(m, "iso"), json: m.get_flag("json") },
        Some(("sha256", m)) => CliCommand::Sha256 {
            iso: text(m, "iso"),
            expected: m.get_one::<String>("expected").cloned(),
            json: m.get_flag("json"),
        },
        Some(("fetch-chromeos", m)) => CliCommand::FetchChromeos {
            dest: m.get_one::<String>("dest").cloned(),
            keep_zip: m.get_flag("keep_zip"),
            json: m.get_flag("json"),
        },
        Some(("write", m)) => CliCommand::Write(WriteArgs {
            iso: text(m, "iso"),
            disk: text(m, "disk"),
            mode: Mode::parse(&text(m, "mode")).unwrap_or(Mode::Auto),
            hardened: m.get_flag("hardened"),
            flags: flags_from(m),
        }),
        Some(("harden-seed", m)) => CliCommand::HardenSeed(SeedArgs {
            target: SeedTarget::parse(&text(m, "target")).unwrap_or(SeedTarget::Ubuntu),
            disk: text(m, "disk"),
            flags: flags_from(m),
        }),
        Some(("harden-files", m)) => CliCommand::HardenFiles(FilesArgs {
            target: FilesKind::parse(&text(m, "target")).unwrap_or(FilesKind::Windows),
            out: text(m, "out"),
            json: m.get_flag("json"),
        }),
        Some(_) => CliCommand::Gui,
    };
    Parsed { command, debug }
}

// ---------------------------------------------------------------------------------------------------------------
// Usage errors in argparse's words
// ---------------------------------------------------------------------------------------------------------------

/// `Usage: prog ...` -> `usage: prog ...` (argparse's capitalisation).
fn usage_text(cmd: &mut Command) -> String {
    let usage = cmd.render_usage().to_string();
    match usage.strip_prefix("Usage:") {
        Some(rest) => format!("usage:{rest}"),
        None => usage,
    }
}

fn strings(value: Option<&ContextValue>) -> Vec<String> {
    match value {
        Some(ContextValue::String(s)) => vec![s.clone()],
        Some(ContextValue::Strings(v)) => v.clone(),
        _ => Vec::new(),
    }
}

/// `--iso <ISO>` -> `--iso`.
fn arg_name(shown: &str) -> String {
    shown.split_whitespace().next().unwrap_or(shown).to_string()
}

fn first_command(argv: &[String], root: &Command) -> Option<String> {
    argv.iter()
        .filter(|a| !a.starts_with('-'))
        .find(|a| root.get_subcommands().any(|s| s.get_name() == a.as_str()))
        .cloned()
}

fn usage_error(root: &mut Command, argv: &[String], err: &clap::Error) -> Early {
    let message = match err.kind() {
        ErrorKind::UnknownArgument => {
            format!(
                "unrecognized arguments: {}",
                strings(err.get(ContextKind::InvalidArg)).iter().map(|a| arg_name(a)).collect::<Vec<_>>().join(" ")
            )
        }
        ErrorKind::MissingRequiredArgument => {
            let names: Vec<String> = strings(err.get(ContextKind::InvalidArg)).iter().map(|a| arg_name(a)).collect();
            format!("the following arguments are required: {}", names.join(", "))
        }
        ErrorKind::InvalidValue => {
            let arg = strings(err.get(ContextKind::InvalidArg)).first().map(|a| arg_name(a)).unwrap_or_default();
            let value = strings(err.get(ContextKind::InvalidValue)).first().cloned().unwrap_or_default();
            let choices: Vec<String> =
                strings(err.get(ContextKind::ValidValue)).iter().map(|c| format!("'{c}'")).collect();
            format!("argument {arg}: invalid choice: '{value}' (choose from {})", choices.join(", "))
        }
        ErrorKind::InvalidSubcommand => {
            let value = strings(err.get(ContextKind::InvalidSubcommand)).first().cloned().unwrap_or_default();
            let choices: Vec<String> = root.get_subcommands().map(|s| format!("'{}'", s.get_name())).collect();
            format!("argument COMMAND: invalid choice: '{value}' (choose from {})", choices.join(", "))
        }
        _ => {
            let rendered = err.to_string();
            let first = rendered.lines().next().unwrap_or("").trim();
            first.strip_prefix("error: ").unwrap_or(first).to_string()
        }
    };
    root.build();
    let sub = first_command(argv, root);
    let (usage, prog) = match sub.as_deref().and_then(|name| root.find_subcommand_mut(name)) {
        Some(cmd) => (usage_text(cmd), format!("{CLI_PROG} {}", cmd.get_name())),
        None => (usage_text(root), CLI_PROG.to_string()),
    };
    Early {
        code: EXIT_USAGE,
        stdout: String::new(),
        stderr: format!("{}\n{prog}: error: {message}\n", usage.trim_end()),
    }
}

/// `build_cli_parser().parse_args(argv)` with the outcomes of `main` folded in: `Ok` with the typed command, or the
/// text and exit code of `--help`, `--version` and usage errors.
pub fn parse(argv: &[String]) -> Result<Parsed, Early> {
    let mut root = build_cli_parser();
    let mut full = vec![CLI_PROG.to_string()];
    full.extend(argv.iter().cloned());
    match root.clone().try_get_matches_from(full) {
        Ok(matches) => Ok(extract(&matches)),
        Err(err) => match err.kind() {
            ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                let mut text = err.render().to_string();
                // The epilog is printed as it is written (argparse's RawDescriptionHelpFormatter); clap would wrap
                // its long lines, so the root help gets the unwrapped text instead.
                if let Some(at) = text.find("exit codes:") {
                    text.truncate(at);
                    text.push_str(&cli_epilog());
                    text.push('\n');
                }
                Err(Early { code: EXIT_OK, stdout: text, stderr: String::new() })
            }
            _ => Err(usage_error(&mut root, argv, &err)),
        },
    }
}
