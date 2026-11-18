//! The command line. OWNER: A7. Port of win11_usb_creator.py lines 12040-13039 (and `main`, lines 12985-13039).
//!
//!   epma-usb-creator                 open the window (same as `epma-usb-creator gui`)
//!   epma-usb-creator list            list the USB drives that can be written
//!   epma-usb-creator detect ISO      windows / linux / chromeos / unknown
//!   epma-usb-creator sha256 ISO      checksum, optionally compared with --expected
//!   epma-usb-creator write ...       create the bootable drive
//!   epma-usb-creator fetch-chromeos | harden-seed | harden-files
//!
//! Data goes to stdout; messages, errors and progress go to stderr. Verification of the written drive is part of
//! `write` and cannot be switched off.
//!
//! Layout: [`api`] is the seam to the engine (the [`Engine`] trait: the Python tests monkeypatch the engine, the Rust
//! tests inject a fake one), [`io`] the streams / progress line / logger / JSON, [`parser`] the `clap` definition,
//! [`plan`] the plan a write shows before it asks, [`commands`], [`write`] and [`harden`] the commands, [`signals`]
//! Ctrl-C.

mod api;
mod commands;
mod harden;
mod io;
mod parser;
mod plan;
mod signals;
mod write;

#[cfg(test)]
mod tests;

pub use api::{Engine, RealEngine};
pub use io::{CliLogger, CliProgress, Env, OutStream, CLI_MILESTONE_RE};
pub use parser::{
    build_cli_parser, cli_epilog, CliCommand, Early, FilesArgs, FilesKind, Parsed, SeedArgs, WriteArgs, WriteFlags,
    CLI_ENV_HELP, CLI_EXIT_CODE_HELP, HARDENED_WINDOWS_ONLY, HARDEN_FILES_TARGETS, HARDEN_FILES_WINDOWS_SAME_USB_NOTE,
    HARDEN_FILES_WINDOWS_SEED,
};
pub use signals::Interrupts;

use crate::constants::APP_NAME;
use regex::Regex;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, LazyLock};

pub const EXIT_OK: i32 = 0;
pub const EXIT_ERROR: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
/// The drive does not match the ISO, or the checksum differs.
pub const EXIT_VERIFY_FAILED: i32 = 3;
/// Written and verified, but the drive could not be ejected.
pub const EXIT_EJECT_FAILED: i32 = 4;
/// Ctrl-C.
pub const EXIT_INTERRUPTED: i32 = 130;

pub const CLI_PROG: &str = APP_NAME;

/// A failure the command line reports as a plain message with an exit code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliError {
    pub message: String,
    pub code: i32,
}

impl CliError {
    pub fn new(message: impl Into<String>) -> CliError {
        CliError { message: message.into(), code: EXIT_ERROR }
    }
    pub fn with_code(message: impl Into<String>, code: i32) -> CliError {
        CliError { message: message.into(), code }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Why a command did not return an exit code by itself.
#[derive(Debug)]
pub enum Failure {
    /// `CliError`: `error: message` and its exit code.
    Cli(CliError),
    /// Ctrl-C reached a command with no handling of its own (`KeyboardInterrupt`): "Interrupted." and 130.
    Interrupted,
}

impl From<CliError> for Failure {
    fn from(e: CliError) -> Self {
        Failure::Cli(e)
    }
}

/// Any other engine error ends the command with `error: message` and exit code 1 (the Python catch-all).
impl From<crate::types::Error> for Failure {
    fn from(e: crate::types::Error) -> Self {
        Failure::Cli(CliError::new(e.to_string()))
    }
}

static WINDOWS_DISK_NUMBER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(?:disk\s*)?([0-9]{1,4})$").unwrap());

/// What the user typed as a disk identifier, with whitespace and a `/dev/` prefix removed (on Windows: '3', 'disk 3'
/// and '\\.\PhysicalDrive3' all become 'PhysicalDrive3'). The window's confirmation dialog and the command line
/// (`--disk`, the typed confirmation) both use it.
pub fn normalize_typed_identifier(text: &str) -> String {
    normalize_typed_identifier_for(text, crate::constants::IS_WINDOWS)
}

/// [`normalize_typed_identifier`] for an explicit platform (the Python reads the global `IS_WINDOWS`).
pub fn normalize_typed_identifier_for(text: &str, windows: bool) -> String {
    let mut text = text.trim();
    if windows {
        // Windows people say "disk 3" (Disk Management, diskpart): accept it, "3" and the device path.
        if let Some(rest) = text.strip_prefix("\\\\.\\") {
            text = rest;
        }
        return match WINDOWS_DISK_NUMBER_RE
            .captures(text)
            .and_then(|m| m.get(1))
            .and_then(|n| n.as_str().parse::<u32>().ok())
        {
            Some(n) => format!("PhysicalDrive{n}"),
            None => text.to_string(),
        };
    }
    text.strip_prefix("/dev/").unwrap_or(text).to_string()
}

/// The text a caught panic carried.
fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(text) => *text,
        Err(payload) => match payload.downcast::<&'static str>() {
            Ok(text) => (*text).to_string(),
            Err(_) => "the program stopped unexpectedly".to_string(),
        },
    }
}

/// `main(argv)`: no arguments opens the window (`gui::run`, which always exists and prints a hint when built without
/// feature `gui`), anything else is the command line. Returns the process exit code.
pub fn main(argv: &[String]) -> i32 {
    let env = Env::real(Arc::new(RealEngine));
    run(argv, &env)
}

/// `main` against an explicit environment: streams, engine, clock and Ctrl-C (the tests use fakes).
pub fn run(argv: &[String], env: &Env) -> i32 {
    let (command, debug) = if argv.is_empty() {
        (CliCommand::Gui, false)
    } else {
        match parser::parse(argv) {
            Ok(parsed) => (parsed.command, parsed.debug), // no command at all is the window too
            Err(early) => {
                // --help / --version (0) or a usage error (2)
                if !early.stdout.is_empty() {
                    env.out.emit(&early.stdout, "");
                }
                if !early.stderr.is_empty() {
                    env.err.emit(&early.stderr, "");
                }
                return early.code;
            }
        }
    };
    let needs_platform =
        matches!(command, CliCommand::Gui | CliCommand::List { .. } | CliCommand::Write(_) | CliCommand::HardenSeed(_));
    if needs_platform && !env.engine.supported_platform() {
        env.err("This script supports Windows 11, macOS and Linux only.");
        return EXIT_ERROR;
    }
    if matches!(command, CliCommand::Gui) {
        if let Some(code) = env.engine.prepare_gui(&|text| env.err(text)) {
            return code;
        }
    }
    match catch_unwind(AssertUnwindSafe(|| dispatch(env, &command))) {
        Ok(Ok(code)) => code,
        Ok(Err(Failure::Cli(e))) => {
            env.error(&e.message);
            e.code
        }
        Ok(Err(Failure::Interrupted)) => {
            env.err("Interrupted.");
            EXIT_INTERRUPTED
        }
        Err(payload) => {
            let message = panic_message(payload);
            if debug {
                env.err(&format!("Traceback (debug output):\npanic: {message}"));
            }
            env.error(&format!("Unexpected failure (panic): {message}"));
            EXIT_ERROR
        }
    }
}

/// `COMMANDS[command](args)`.
fn dispatch(env: &Env, command: &CliCommand) -> Result<i32, Failure> {
    match command {
        CliCommand::Gui => Ok(env.engine.run_gui()),
        CliCommand::List { json } => commands::cmd_list(env, *json),
        CliCommand::Detect { iso, json } => commands::cmd_detect(env, iso, *json),
        CliCommand::Sha256 { iso, expected, json } => commands::cmd_sha256(env, iso, expected.as_deref(), *json),
        CliCommand::FetchChromeos { dest, keep_zip, json } => {
            commands::cmd_fetch_chromeos(env, dest.as_deref(), *keep_zip, *json)
        }
        CliCommand::Write(args) => write::cmd_write(env, args),
        CliCommand::HardenSeed(args) => write::cmd_harden_seed(env, args),
        CliCommand::HardenFiles(args) => harden::cmd_harden_files(env, args),
    }
}
