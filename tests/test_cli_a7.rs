//! The command line as a real process (Python `ModuleEntryPointTests`): the binary starts, answers `--version` and
//! `--help`, and reports usage errors with exit code 2, without touching a drive, the network or the window.

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_epma-usb-creator"))
        .args(args)
        .env("WIN11USB_DISABLE_AUDIT_LOG", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("the binary starts")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}

#[test]
fn script_version_flag() {
    let out = run(&["--version"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(text(&out.stdout), format!("epma-usb-creator {}\n", env!("CARGO_PKG_VERSION")));
    assert_eq!(text(&out.stderr), "");
}

#[test]
fn help_goes_to_stdout_with_the_exit_codes() {
    let out = run(&["--help"]);
    assert_eq!(out.status.code(), Some(0));
    let help = text(&out.stdout);
    for word in [
        "list",
        "detect",
        "sha256",
        "write",
        "harden-seed",
        "harden-files",
        "fetch-chromeos",
        "exit codes",
        "130",
        "NO_COLOR",
    ] {
        assert!(help.contains(word), "{word}");
    }
    assert_eq!(text(&out.stderr), "");
}

#[test]
fn usage_errors_exit_2_with_the_usage_on_stderr() {
    for args in [&["bogus"][..], &["write"][..], &["sha256"][..], &["list", "--nope"][..]] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert_eq!(text(&out.stdout), "", "{args:?}");
        assert!(text(&out.stderr).starts_with("usage: "), "{args:?}: {}", text(&out.stderr));
        assert!(text(&out.stderr).contains("error: "), "{args:?}");
    }
}

#[test]
fn a_closed_stdout_does_not_make_the_program_panic() {
    // `epma-usb-creator --help | head -c 1`: the reader goes away, the program must not print a panic.
    use std::io::Read;
    use std::process::Stdio;
    let mut child = Command::new(env!("CARGO_BIN_EXE_epma-usb-creator"))
        .arg("--help")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary starts");
    let mut first = [0u8; 1];
    child.stdout.take().unwrap().read_exact(&mut first).unwrap();
    // stdout is dropped here: the pipe is closed
    let mut err = String::new();
    child.stderr.take().unwrap().read_to_string(&mut err).unwrap();
    child.wait().unwrap();
    assert!(!err.contains("panicked"), "{err}");
}
