//! ShellCheck over every shell script the program runs with administrator rights.
//!
//! The scripts live in `assets/*.sh` (embedded with `include_str!`), so the files themselves are linted, plus the
//! package-install one-liners built from `constants::LINUX_INSTALL_CMD_TEMPLATE` (`{pkgs}` becomes `pkg`).
//! Only findings of severity "warning" or worse fail. With `REQUIRE_SHELLCHECK=1` (CI) a missing `shellcheck` is a
//! failure; otherwise the test prints a note and passes.

use std::path::PathBuf;
use std::process::Command;

fn shellcheck_available() -> bool {
    Command::new("shellcheck").arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
}

fn require() -> bool {
    std::env::var("REQUIRE_SHELLCHECK").map(|v| v == "1").unwrap_or(false)
}

fn lint(path: &std::path::Path) -> Result<(), String> {
    let out = Command::new("shellcheck")
        .args(["--shell=bash", "--severity=warning", "--format=gcc"])
        .arg(path)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr))
    }
}

#[test]
fn every_embedded_shell_script_passes_shellcheck() {
    if !shellcheck_available() {
        assert!(!require(), "REQUIRE_SHELLCHECK=1 but shellcheck is not installed");
        eprintln!("note: shellcheck is not installed; skipping");
        return;
    }
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets");
    let mut scripts: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("assets/ exists")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "sh").unwrap_or(false))
        .collect();
    scripts.sort();
    // The extractor of the Python version refused to pass "blank" when it found too few scripts; same idea.
    assert!(scripts.len() >= 10, "expected at least 10 embedded shell scripts in assets/, found {}", scripts.len());
    let mut failures = Vec::new();
    for script in &scripts {
        if let Err(report) = lint(script) {
            failures.push(format!("{}:\n{report}", script.display()));
        }
    }
    assert!(failures.is_empty(), "ShellCheck findings:\n{}", failures.join("\n"));
}

#[test]
fn the_install_commands_pass_shellcheck() {
    if !shellcheck_available() {
        assert!(!require(), "REQUIRE_SHELLCHECK=1 but shellcheck is not installed");
        eprintln!("note: shellcheck is not installed; skipping");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let mut failures = Vec::new();
    for (manager, template) in epma_usb_creator::constants::LINUX_INSTALL_CMD_TEMPLATE {
        let path = tmp.path().join(format!("install_{manager}.sh"));
        std::fs::write(&path, format!("#!/usr/bin/env bash\n{}\n", template.replace("{pkgs}", "pkg"))).unwrap();
        if let Err(report) = lint(&path) {
            failures.push(format!("{manager}:\n{report}"));
        }
    }
    assert!(failures.is_empty(), "ShellCheck findings:\n{}", failures.join("\n"));
}
