//! Port of tests/test_hardening_windows.py (123 tests) plus byte-exact comparisons with the goldens in tests/golden/.
//!
//! The content is pure text built in memory. PowerShell (`pwsh`) is not needed: like the Python tests, the script is
//! checked structurally (balanced blocks, markers, banned commands) and never executed.

use super::*;
use crate::i18n_table::PT_BR;
use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::sync::LazyLock;

const CMD_PATH: &str = "sources/$OEM$/$$/Setup/Scripts/SetupComplete.cmd";
const PS1_PATH: &str = "sources/$OEM$/$$/Setup/Scripts/harden.ps1";
const MAX_FILE: usize = 256 * 1024;
const MAX_TOTAL: usize = 2 * 1024 * 1024;
const MAX_PATH: usize = 240;

const GOLDEN_PS1: &[u8] = include_bytes!("../../tests/golden/windows/harden.ps1");
const GOLDEN_CMD: &[u8] =
    include_bytes!("../../tests/golden/windows-files/sources/$OEM$/$$/Setup/Scripts/SetupComplete.cmd");
const GOLDEN_PS1_IN_FILES: &[u8] =
    include_bytes!("../../tests/golden/windows-files/sources/$OEM$/$$/Setup/Scripts/harden.ps1");
const GOLDEN_DESCRIBE: &str = include_str!("../../tests/golden/windows_describe.json");

// ---------------------------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------------------------

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|e| panic!("bad test pattern {pattern:?}: {e}"))
}

/// `assertRegex` (a search, not a full match).
fn assert_re(hay: &str, pattern: &str) {
    assert!(re(pattern).is_match(hay), "pattern {pattern:?} not found in: {:.300}", hay);
}

fn assert_no_re(hay: &str, pattern: &str) {
    assert!(!re(pattern).is_match(hay), "pattern {pattern:?} found in: {:.300}", hay);
}

fn assert_has(hay: &str, needle: &str) {
    assert!(hay.contains(needle), "{needle:?} not found in: {:.300}", hay);
}

fn assert_hasnt(hay: &str, needle: &str) {
    assert!(!hay.contains(needle), "{needle:?} found in: {:.300}", hay);
}

/// `str.index`: the position of `needle`, a failure if it is missing.
fn at(hay: &str, needle: &str) -> usize {
    hay.find(needle).unwrap_or_else(|| panic!("{needle:?} not found in: {:.300}", hay))
}

fn rat(hay: &str, needle: &str) -> usize {
    hay.rfind(needle).unwrap_or_else(|| panic!("{needle:?} not found in: {:.300}", hay))
}

/// `assertLess(a.index(x), a.index(y))` on two positions.
fn before(hay: &str, first: &str, second: &str) {
    assert!(at(hay, first) < at(hay, second), "{first:?} must come before {second:?}");
}

/// `(?<!\r)\n` never matches: every line feed is preceded by a carriage return.
fn only_crlf(bytes: &[u8]) -> bool {
    bytes.iter().enumerate().all(|(i, b)| *b != b'\n' || (i > 0 && bytes[i - 1] == b'\r'))
}

fn count(hay: &str, needle: &str) -> usize {
    hay.matches(needle).count()
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

struct Base {
    files: Files,
    cmd_bytes: Vec<u8>,
    ps1_bytes: Vec<u8>,
    cmd_text: String,
    /// `decode("utf-8-sig")`: the BOM is dropped, the CRLF stay.
    ps1_text: String,
    /// The same with LF only.
    ps1_lf: String,
}

static BASE: LazyLock<Base> = LazyLock::new(|| {
    let files = hardening_files_windows(Hardening::Baseline).unwrap();
    let cmd_bytes = files[CMD_PATH].clone();
    let ps1_bytes = files[PS1_PATH].clone();
    let cmd_text = String::from_utf8(cmd_bytes.clone()).unwrap();
    let ps1_text = String::from_utf8(ps1_bytes[3..].to_vec()).unwrap();
    let ps1_lf = ps1_text.replace("\r\n", "\n");
    Base { files, cmd_bytes, ps1_bytes, cmd_text, ps1_text, ps1_lf }
});

fn base() -> &'static Base {
    &BASE
}

fn ps1() -> &'static str {
    &base().ps1_text
}

fn ps1_lf() -> &'static str {
    &base().ps1_lf
}

fn ids() -> Vec<&'static str> {
    WINDOWS_HARDENING_SETTINGS.iter().map(|s| s.0).collect()
}

fn setting(sid: &str) -> (&'static str, &'static str, &'static str) {
    *WINDOWS_HARDENING_SETTINGS.iter().find(|s| s.0 == sid).unwrap_or_else(|| panic!("no setting {sid}"))
}

fn keys(table: &PsTable) -> Vec<&'static str> {
    table.iter().map(|(k, _)| *k).collect()
}

/// `re.split(r"^# setting: (\w+)\s*$", text, flags=re.MULTILINE)`: [(id, text up to the next marker)].
fn split_settings(text: &str) -> Vec<(String, String)> {
    let marker = re(r"(?m)^# setting: (\w+)\s*$");
    let found: Vec<(usize, usize, String)> = marker
        .captures_iter(text)
        .map(|c| (c.get(0).unwrap().start(), c.get(0).unwrap().end(), c[1].to_string()))
        .collect();
    let mut out = Vec::new();
    for (i, (_, end, sid)) in found.iter().enumerate() {
        let stop = found.get(i + 1).map(|n| n.0).unwrap_or(text.len());
        out.push((sid.clone(), text[*end..stop].to_string()));
    }
    out
}

/// The part of one setting that comes before the tail of the script ("whole" in the Python tests).
fn whole(sid: &str) -> String {
    let body =
        split_settings(ps1_lf()).into_iter().find(|(s, _)| s == sid).unwrap_or_else(|| panic!("no setting {sid}")).1;
    body.split("\nif ($Mode -eq 'Audit') {\n").next().unwrap().to_string()
}

/// (Apply, Audit, Undo) code of one setting, split at the three top-level mode branches.
fn branches(sid: &str) -> (String, String, String) {
    let pattern = r"(?s)\A\s*if \(\$Mode -eq 'Apply'\) \{\n(.*?)\n\} elseif \(\$Mode -eq 'Audit'\) \{\n(.*?)\n\} else \{\n(.*)\n\}\s*\z";
    let w = whole(sid);
    let caps = re(pattern).captures(&w).unwrap_or_else(|| panic!("three mode branches not found in {sid}"));
    (caps[1].to_string(), caps[2].to_string(), caps[3].to_string())
}

fn apply_of(sid: &str) -> String {
    branches(sid).0
}

fn audit_of(sid: &str) -> String {
    branches(sid).1
}

fn undo_of(sid: &str) -> String {
    branches(sid).2
}

/// The body of `function NAME { ... }` (at the start of a line, closed by a `}` at the start of a line).
fn function(name: &str) -> String {
    let pattern = format!(r"(?ms)^function {} \{{\n(.*?)\n\}}\n", regex::escape(name));
    re(&pattern).captures(ps1_lf()).unwrap_or_else(|| panic!("function {name} not found"))[1].to_string()
}

/// `str.splitlines()` of the script, without the line ends.
fn ps1_lines() -> Vec<&'static str> {
    ps1().lines().collect()
}

fn pt_for(line: &str) -> Option<&'static str> {
    PT_BR.iter().find(|(en, _)| *en == line).map(|(_, pt)| *pt)
}

// ---------------------------------------------------------------------------------------------------------------
// Goldens: byte-for-byte with the output of the Python generators
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn golden_ps1_is_byte_identical_to_the_python_output() {
    let got = windows_hardening_ps1(Hardening::Baseline).unwrap();
    if got != GOLDEN_PS1 {
        let n = got.iter().zip(GOLDEN_PS1.iter()).position(|(a, b)| a != b).unwrap_or(got.len().min(GOLDEN_PS1.len()));
        panic!(
            "harden.ps1 differs at byte {n} (got {} bytes, want {}): {:?} vs {:?}",
            got.len(),
            GOLDEN_PS1.len(),
            String::from_utf8_lossy(&got[n.saturating_sub(60)..(n + 60).min(got.len())]),
            String::from_utf8_lossy(&GOLDEN_PS1[n.saturating_sub(60)..(n + 60).min(GOLDEN_PS1.len())])
        );
    }
    assert_eq!(got.len(), 107_571);
}

#[test]
fn golden_file_set_is_byte_identical_to_the_python_output() {
    let files = hardening_files_windows(Hardening::Baseline).unwrap();
    assert_eq!(files.keys().map(String::as_str).collect::<Vec<_>>(), [WINDOWS_HARDENING_CMD, WINDOWS_HARDENING_PS1]);
    assert_eq!(files[WINDOWS_HARDENING_CMD], GOLDEN_CMD);
    assert_eq!(files[WINDOWS_HARDENING_PS1], GOLDEN_PS1_IN_FILES);
    assert_eq!(GOLDEN_PS1_IN_FILES, GOLDEN_PS1);
}

#[derive(Deserialize)]
struct DescribeGolden {
    describe: Vec<String>,
    applied: Vec<String>,
}

#[test]
fn golden_describe_lines() {
    let want: DescribeGolden = serde_json::from_str(GOLDEN_DESCRIBE).unwrap();
    assert_eq!(describe_hardening_windows(Hardening::Baseline), want.describe);
    assert_eq!(describe_hardening_windows_applied(Hardening::Baseline), want.applied);
}

// ---------------------------------------------------------------------------------------------------------------
// ProfileTests
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn none_profile_returns_nothing() {
    assert!(hardening_files_windows(Hardening::None).unwrap().is_empty());
    assert!(describe_hardening_windows(Hardening::None).is_empty());
    assert!(describe_hardening_windows_applied(Hardening::None).is_empty());
    assert!(windows_hardening_ps1(Hardening::None).unwrap().is_empty());
}

#[test]
fn unknown_profile_is_refused() {
    // The Python raised ValueError for an unknown profile name; with the enum no such value can reach these
    // functions, the parser is where it is refused.
    for bad in ["", "strict", "BASELINE", "None", "1"] {
        assert_eq!(Hardening::parse(bad), None, "{bad:?}");
    }
}

#[test]
fn baseline_is_a_known_profile() {
    assert!(Hardening::ALL.contains(&Hardening::Baseline));
}

#[test]
fn contract_constants() {
    assert_eq!(crate::types::Mode::Seed.as_str(), "seed");
    assert_eq!(Hardening::ALL, [Hardening::None, Hardening::Baseline]);
    assert_eq!(crate::types::SeedTarget::Windows.as_str(), "windows");
    let targets: Vec<&str> = crate::types::SeedTarget::ALL.iter().map(|t| t.as_str()).collect();
    assert_eq!(targets, ["ubuntu", "fedora", "debian", "windows"]);
}

#[test]
fn profile_deterministic() {
    assert_eq!(base().files, hardening_files_windows(Hardening::Baseline).unwrap());
}

// ---------------------------------------------------------------------------------------------------------------
// FileSetTests
// ---------------------------------------------------------------------------------------------------------------

/// A simple relative-path check, mirroring the shared validator's rules (written out here on purpose).
fn check_relative_path(path: &str) -> bool {
    if path.is_empty() || path.len() > MAX_PATH {
        return false;
    }
    let drive = re(r"^[A-Za-z]:");
    if path.contains('\\') || path.contains('\0') || path.starts_with('/') || drive.is_match(path) {
        return false;
    }
    path.split('/').all(|p| !(p.is_empty() || p == "." || p == ".."))
}

#[test]
fn exact_paths() {
    let got: BTreeSet<&str> = base().files.keys().map(String::as_str).collect();
    assert_eq!(got, BTreeSet::from([CMD_PATH, PS1_PATH]));
    assert_eq!(WINDOWS_HARDENING_CMD, CMD_PATH);
    assert_eq!(WINDOWS_HARDENING_PS1, PS1_PATH);
    assert_eq!(WINDOWS_HARDENING_SCRIPTS_DIR, "sources/$OEM$/$$/Setup/Scripts");
}

#[test]
fn no_answer_file_anywhere() {
    // The $OEM$ mechanism needs no answer file, and Windows Setup must stay fully interactive.
    for (path, data) in &base().files {
        assert!(!path.to_lowercase().contains("unattend"), "{path}");
        assert!(!String::from_utf8_lossy(data).to_lowercase().contains("unattend"), "{path}");
    }
}

#[test]
fn oem_paths_are_literal() {
    // `$OEM$` and `$$` are what Windows Setup looks for: they must reach the drive unchanged.
    assert_eq!(CMD_PATH, "sources/$OEM$/$$/Setup/Scripts/SetupComplete.cmd");
    assert!(base().files.contains_key("sources/$OEM$/$$/Setup/Scripts/SetupComplete.cmd"));
    assert!(base().files.contains_key("sources/$OEM$/$$/Setup/Scripts/harden.ps1"));
}

#[test]
fn values_are_bytes() {
    for (path, data) in &base().files {
        assert!(!data.is_empty(), "{path}");
    }
}

#[test]
fn paths_are_safe_relative_posix() {
    for path in base().files.keys() {
        assert!(check_relative_path(path), "{path}");
    }
}

#[test]
fn path_check_itself() {
    let long = "x".repeat(241);
    for bad in ["", "/etc/x", "../x", "a/../b", "a\\b", "a//b", "C:/x", "a\0b", long.as_str()] {
        assert!(!check_relative_path(bad), "{bad:?}");
    }
}

#[test]
fn sizes_within_limits() {
    for (path, data) in &base().files {
        assert!(data.len() <= MAX_FILE, "{path}");
    }
    assert!(base().files.values().map(|d| d.len()).sum::<usize>() <= MAX_TOTAL);
}

/// `validate_seed_files` is A4's (seed.rs); until that module is merged it is a stub, so this runs with
/// `cargo test -- --ignored` after the merge.
#[test]
#[ignore = "needs seed::validate_seed_files (A4); run with --ignored once the modules are merged"]
fn shared_validator_accepts_the_files() {
    assert_eq!(crate::seed::validate_seed_files(&base().files).unwrap(), base().files);
}

#[test]
fn plain_ascii_everywhere() {
    for (path, data) in &base().files {
        let body: &[u8] = if path == PS1_PATH { &data[3..] } else { data };
        assert!(body.is_ascii(), "{path}");
    }
}

#[test]
fn never_claims_a_compliance_standard() {
    let blob = [base().cmd_text.as_str(), ps1(), &describe_hardening_windows(Hardening::Baseline).join(" ")].join(" ");
    for word in ["CIS", "STIG", "NIST", "compliant", "certified"] {
        assert_no_re(&blob, &format!(r"(?i)\b{word}\b"));
    }
}

// ---------------------------------------------------------------------------------------------------------------
// SetupCompleteTests
// ---------------------------------------------------------------------------------------------------------------

const PS: &str = "%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

fn cmd_lines() -> Vec<&'static str> {
    // `text.split("\r\n")[:-1]`
    let mut parts: Vec<&str> = base().cmd_text.split("\r\n").collect();
    parts.pop();
    parts
}

fn want() -> String {
    let m = re(r#"(?m)^set "EPMA_WANT=([0-9a-f]+)"\r?$"#).captures(&base().cmd_text).expect("EPMA_WANT line");
    m[1].to_string()
}

#[test]
fn cmd_crlf_only_and_no_bom() {
    assert!(!base().cmd_bytes.starts_with(&[0xef, 0xbb, 0xbf]));
    assert!(base().cmd_bytes.windows(2).any(|w| w == b"\r\n"));
    assert!(only_crlf(&base().cmd_bytes));
}

#[test]
fn cmd_runs_the_script_the_documented_way_by_full_path() {
    assert_has(&base().cmd_text, &format!("{PS} -NoProfile -ExecutionPolicy Bypass -File \"%~dp0harden.ps1\""));
    for line in cmd_lines() {
        assert!(!line.to_lowercase().starts_with("powershell"), "{line}"); // never the bare name
    }
}

#[test]
fn cmd_logs_to_the_documented_file() {
    assert_has(&base().cmd_text, "%windir%\\Temp\\epma-hardening.log");
    assert_has(&base().cmd_text, ">> \"%EPMA_LOG%\" 2>&1");
    assert_eq!(WINDOWS_HARDENING_LOG, "%windir%\\Temp\\epma-hardening.log");
}

#[test]
fn cmd_never_fails_the_setup() {
    let lines: Vec<String> =
        base().cmd_text.lines().map(|l| l.trim().to_lowercase()).filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.last().unwrap(), "exit /b 0");
    // Every exit of the batch file must be a success code.
    for ln in &lines {
        if ln.starts_with("exit") {
            assert_eq!(ln, "exit /b 0");
        }
    }
    let low = base().cmd_text.to_lowercase();
    assert_hasnt(&low, "shutdown");
    assert_hasnt(&low, "reboot");
}

#[test]
fn cmd_errorlevel_is_not_read_inside_a_block() {
    // %errorlevel% inside a parenthesised block is expanded before the command runs: the only parentheses are the
    // single-line `for /f` command and the words in two log lines.
    let text = base().cmd_text.replace("(ignored)", "").replace("(certutil failed)", "");
    let text = re(r"in \('[^']*'\)").replace_all(&text, "").into_owned();
    assert_hasnt(&text, "(");
    assert_hasnt(&text, ")");
}

#[test]
fn cmd_does_not_use_the_network() {
    let low = base().cmd_text.to_lowercase();
    for word in ["curl", "wget", "bitsadmin", "http://", "https://", "invoke-webrequest", "downloadfile"] {
        assert_hasnt(&low, word);
    }
    // certutil is only used with -hashfile, which reads a local file and prints its hash
    let used: Vec<String> =
        re(r"certutil\.exe\s+(\S+)").captures_iter(&base().cmd_text).map(|c| c[1].to_string()).collect();
    assert_eq!(used, ["-hashfile"]);
}

#[test]
fn cmd_embedded_hash_is_the_sha256_of_the_shipped_script() {
    let digest = sha256_hex(&base().ps1_bytes);
    assert_eq!(want(), digest);
    assert_eq!(want(), sha256_hex(&windows_hardening_ps1(Hardening::Baseline).unwrap()));
    assert_eq!(want().len(), 64);
}

#[test]
fn cmd_the_hash_line_changes_when_the_script_changes() {
    let basecmd = base().files[CMD_PATH].clone();
    let other: &[u8] = b"\xef\xbb\xbf# another harden.ps1\r\n";
    let changed = windows_setupcomplete_cmd(Hardening::Baseline, Some(other)).unwrap();
    assert_ne!(changed, basecmd);
    let line = format!("set \"EPMA_WANT={}\"", sha256_hex(other));
    assert!(changed.windows(line.len()).any(|w| w == line.as_bytes()));
    let old_want = want();
    assert!(!changed.windows(old_want.len()).any(|w| w == old_want.as_bytes()));
    // same shape otherwise: only the hash line differs
    let strip = |data: &[u8]| -> Vec<Vec<u8>> {
        data.split(|b| *b == b'\n').filter(|ln| !ln.starts_with(b"set \"EPMA_WANT=")).map(|l| l.to_vec()).collect()
    };
    assert_eq!(strip(&basecmd), strip(&changed));
}

#[test]
fn cmd_the_hash_matches_the_bytes_that_are_written_in_same_usb_mode() {
    // same-USB mode: the script and SetupComplete.cmd come out of one call
    let script = &base().files[PS1_PATH];
    assert_eq!(want(), sha256_hex(script));
}

/// Seed drive mode: harden.ps1 of the seed is the same script, and the seed drive has no SetupComplete.cmd. The seed
/// files are A5's (seed_files.rs); runs with `--ignored` once the modules are merged.
#[test]
#[ignore = "needs seed_files::hardening_files_seed (A5); run with --ignored once the modules are merged"]
fn cmd_the_hash_matches_the_bytes_that_are_written_in_seed_mode() {
    let (_label, seed) =
        crate::seed_files::hardening_files_seed(crate::types::SeedTarget::Windows, Hardening::Baseline).unwrap();
    assert_eq!(sha256_hex(&seed["harden.ps1"]), want());
    assert!(!seed.contains_key("SetupComplete.cmd"));
}

#[test]
fn cmd_none_profile_and_empty_script_are_refused() {
    // Hardening::None has no script: the generator asks for one and gets nothing.
    let err = windows_setupcomplete_cmd(Hardening::None, None).unwrap_err();
    assert!(matches!(err, Error::Value(_)), "{err:?}");
    assert_eq!(err.to_string(), "The Windows hardening script is empty");
    let err = windows_setupcomplete_cmd(Hardening::Baseline, Some(b"  \r\n")).unwrap_err();
    assert!(matches!(err, Error::Value(_)), "{err:?}");
}

#[test]
fn cmd_hash_is_read_with_certutil_by_full_path_second_line() {
    let text = base().cmd_text.as_str();
    assert_has(
        text,
        "for /f \"skip=1 delims=\" %%H in ('%SystemRoot%\\System32\\certutil.exe -hashfile \"%~dp0harden.ps1\" SHA256 2^>nul') do if not defined EPMA_GOT set \"EPMA_GOT=%%H\"",
    );
    assert_has(text, "set \"EPMA_GOT=%EPMA_GOT: =%\""); // older Windows prints the bytes separated by spaces
    assert_has(text, "if /i not \"%EPMA_GOT%\"==\"%EPMA_WANT%\" goto mismatch"); // /i: case-insensitive
    before(text, "certutil", "goto mismatch");
    before(text, "goto mismatch", PS); // the check comes before the run
    assert_eq!(count(text, "-File"), 1); // harden.ps1 is started in exactly one place
}

/// Walk the batch file's `goto`/`if ... goto` lines for one scenario; returns the lines that run.
fn simulate(got: Option<&str>, exists: bool) -> Vec<String> {
    let want = want();
    let lines = cmd_lines();
    let labels: std::collections::HashMap<&str, usize> =
        lines.iter().enumerate().filter(|(_, ln)| ln.starts_with(':')).map(|(i, ln)| (&ln[1..], i)).collect();
    let mut ran: Vec<String> = Vec::new();
    let mut i = 0;
    let mut steps = 0;
    let mut env_got: Option<String> = None;
    while i < lines.len() {
        steps += 1;
        assert!(steps < 200, "loop");
        let ln = lines[i];
        i += 1;
        if ln.starts_with('@')
            || ln.starts_with("rem ")
            || ln.starts_with(':')
            || ln.starts_with("set \"EPMA_LOG")
            || ln.starts_with("set \"EPMA_WANT")
        {
            continue;
        }
        let target = |ln: &str| labels[ln.rsplit("goto ").next().unwrap()];
        if ln == "set \"EPMA_GOT=\"" {
            env_got = None;
        } else if ln.starts_with("for /f") {
            env_got = got.map(str::to_string);
        } else if ln == "set \"EPMA_GOT=%EPMA_GOT: =%\"" {
            env_got = env_got.map(|g| g.replace(' ', ""));
        } else if ln.starts_with("if not exist") {
            if !exists {
                i = target(ln);
            }
        } else if ln.starts_with("if not defined") {
            if env_got.is_none() {
                i = target(ln);
            }
        } else if ln.starts_with("if /i not") {
            if env_got.as_deref().unwrap().to_lowercase() != want.to_lowercase() {
                i = target(ln);
            }
        } else if let Some(label) = ln.strip_prefix("goto ") {
            i = labels[label];
        } else if ln == "exit /b 0" {
            ran.push(ln.to_string());
            break;
        } else {
            ran.push(ln.to_string());
        }
    }
    ran
}

#[test]
fn cmd_only_a_matching_hash_runs_the_script() {
    let want = want();
    let spaced: String = (0..64).step_by(2).map(|i| &want[i..i + 2]).collect::<Vec<_>>().join(" ");
    for (label, got) in
        [("lower case", want.clone()), ("upper case", want.to_uppercase()), ("bytes separated by spaces", spaced)]
    {
        let ran = simulate(Some(&got), true);
        assert!(ran.iter().any(|ln| ln.contains(PS)), "{label}: {ran:?}");
    }
    let last = want.chars().last().unwrap();
    let off_by_one = format!("{}{}", &want[..63], if last != '0' { '0' } else { '1' });
    let zeros = "0".repeat(64);
    let cases: [(&str, Option<&str>, bool); 4] = [
        ("other hash", Some(&zeros), true),
        ("one digit off", Some(&off_by_one), true),
        ("certutil gave nothing", None, true),
        ("script missing", Some(&want), false),
    ];
    for (label, got, exists) in cases {
        let ran = simulate(got, exists);
        assert!(!ran.iter().any(|ln| ln.contains(PS)), "{label}: {ran:?}");
        assert_eq!(ran.last().unwrap(), "exit /b 0", "{label}");
        assert!(ran.iter().any(|ln| ln.contains("[SKIP]")), "{label}: {ran:?}");
        // the log says why
    }
}

#[test]
fn cmd_a_mismatch_is_written_to_the_log_with_both_values() {
    let ran = simulate(Some(&"0".repeat(64)), true);
    let text = ran.join(" ");
    assert_has(&text, "does not match the SHA-256 recorded in SetupComplete.cmd");
    assert_has(&text, "harden.ps1 was NOT run");
    assert_has(&text, "expected %EPMA_WANT% but found %EPMA_GOT%");
    for ln in &ran {
        if ln.starts_with("echo") {
            assert!(ln.ends_with(">> \"%EPMA_LOG%\""), "{ln}");
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// HardenScriptTests
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn script_bom_and_crlf() {
    // PowerShell 5.1 reads a file without a BOM as ANSI; the BOM makes it UTF-8.
    assert!(base().ps1_bytes.starts_with(&[0xef, 0xbb, 0xbf]));
    let body = &base().ps1_bytes[3..];
    assert!(body.windows(2).any(|w| w == b"\r\n"));
    assert!(only_crlf(body));
}

#[test]
fn script_blocks_are_balanced() {
    let text = ps1();
    for (open, close) in [('{', '}'), ('(', ')'), ('[', ']')] {
        assert_eq!(text.matches(open).count(), text.matches(close).count(), "{open}{close}");
    }
    // Never negative while scanning (a closer before its opener).
    let mut depth: i64 = 0;
    for ch in text.chars() {
        if ch == '{' {
            depth += 1;
        } else if ch == '}' {
            depth -= 1;
            assert!(depth >= 0);
        }
    }
    assert_eq!(depth, 0);
}

#[test]
fn script_quotes_are_balanced() {
    // Single quotes: an even number per line once doubled quotes are removed (no multi-line strings used).
    for (n, line) in ps1_lines().iter().enumerate() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        assert_eq!(line.replace("''", "").matches('\'').count() % 2, 0, "line {}: {line}", n + 1);
    }
}

#[test]
fn script_every_try_has_a_catch() {
    let tries = re(r"\btry\s*\{").find_iter(ps1()).count();
    let catches = re(r"\bcatch\s*\{").find_iter(ps1()).count();
    assert_eq!(tries, catches);
    assert!(tries >= WINDOWS_HARDENING_SETTINGS.len());
}

#[test]
fn script_every_setting_id_is_in_the_script_once() {
    let found: Vec<String> = re(r"(?m)^# setting: (\w+)\s*$").captures_iter(ps1()).map(|c| c[1].to_string()).collect();
    assert_eq!(found, ids());
    for sid in ids() {
        assert_has(ps1(), sid);
    }
}

#[test]
fn script_every_setting_has_its_own_handler() {
    // Split the script at the markers; each part must carry its own try and catch.
    let parts = split_settings(ps1());
    assert_eq!(parts.len(), WINDOWS_HARDENING_SETTINGS.len());
    for ((sid, _t, _r), (_, part)) in WINDOWS_HARDENING_SETTINGS.iter().zip(parts.iter()) {
        assert_re(part, r"\btry\s*\{");
        assert_re(part, r"\bcatch\s*\{");
        assert!(part.contains("Write-Result 'FAIL'"), "{sid}");
    }
}

#[test]
fn script_code_and_settings_match() {
    assert_eq!(ids(), keys(&WINDOWS_PS_CODE));
}

#[test]
fn script_every_setting_has_text_and_a_risk_note() {
    let mut seen = BTreeSet::new();
    for (sid, text, risk) in WINDOWS_HARDENING_SETTINGS {
        assert_re(sid, r"^[a-z0-9_]+$");
        assert!(seen.insert(*sid), "{sid} twice");
        assert!(text.len() > 10, "{sid}");
        assert!(risk.len() > 20, "{sid}");
        assert!(risk.ends_with('.'), "{sid}");
        // The risk note is in the script header too.
        assert_has(ps1(), risk);
    }
}

#[test]
fn script_log_line_format() {
    for tag in ["OK", "SKIP", "WARN", "FAIL"] {
        assert_has(ps1(), &format!("'{tag}'"));
    }
    // The line goes to the console (Write-Host, inside Write-Log) and, when allowed, to the log file.
    assert_has(ps1(), "Write-Log ('[' + $Status + '] ' + $What + ' (' + $Why + ')')");
    // Every Write-Result call passes a status, what and why.
    let call = re(r"(?m)^\s*Write-Result (.*)$");
    let shape = re(r"^('(OK|SKIP|WARN|FAIL)'|\$Status) ['($]");
    for m in call.captures_iter(ps1()) {
        assert!(shape.is_match(&m[1]), "{}", &m[0]);
    }
}

#[test]
fn script_exit_code_is_zero_unless_it_refuses_to_start() {
    assert!(ps1().trim_end().ends_with("exit 0"));
    // The only non-zero exits are refusals to start, each right after the SYSTEM guard "exit 0": Windows Setup
    // (which runs as SYSTEM) therefore never sees a failing exit code.
    let lines: Vec<&str> = ps1().lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let nonzero: Vec<usize> =
        lines.iter().enumerate().filter(|(_, ln)| re(r"^exit\s+[1-9]").is_match(ln)).map(|(i, _)| i).collect();
    assert!(!nonzero.is_empty());
    for i in nonzero {
        assert_eq!(lines[i - 1], "if ($isSystem) { exit 0 }");
    }
}

#[test]
fn script_no_network_downloads_or_external_tools() {
    let banned = [
        "invoke-webrequest",
        "invoke-restmethod",
        "iwr ",
        "irm ",
        "downloadstring",
        "downloadfile",
        "start-bitstransfer",
        "net.webclient",
        "system.net",
        "http://",
        "https://",
        "curl",
        "wget",
        "choco",
        "winget",
        "scoop",
        "msiexec",
        "start-process",
        "invoke-expression",
        "iex ",
        "restart-computer",
        "stop-computer",
        "shutdown",
    ];
    let low = ps1().to_lowercase();
    for word in banned {
        assert_hasnt(&low, word);
    }
}

#[test]
fn script_decisions_that_are_left_to_the_owner() {
    let low = ps1().to_lowercase();
    // BitLocker and NTLM are explained in comments but never touched.
    for call in ["enable-bitlocker", "manage-bde", "lmcompatibilitylevel", "restrictntlm", "restrictsendingntlm"] {
        assert_hasnt(&low, call);
    }
    assert_has(&low, "bitlocker is not turned on automatically");
    assert_has(&low, "ntlm authentication levels are left as they are");
}

#[test]
fn script_does_not_weaken_anything() {
    let low = ps1().to_lowercase();
    for bad in [
        "enablelua' -value 0",
        "-enabled false",
        "disableantispyware",
        "-disablerealtimemonitoring",
        "-defaultinboundaction allow",
        "enablesmb1protocol $true",
        "-puaprotection disabled",
    ] {
        assert_hasnt(&low, bad);
    }
}

#[test]
fn script_lsass_is_the_only_block_rule() {
    assert_has(ps1(), "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"); // LSASS credential theft
    assert_eq!(count(ps1(), "-Action 'Enabled'"), 1);
    // One call inside each of the two audit-only loops (the original four rules and the three added later).
    assert_eq!(count(ps1(), "-Action 'AuditMode'"), 2);
}

#[test]
fn script_audit_policy_uses_guids_not_translated_names() {
    assert_no_re(ps1(), r#"/subcategory:""#);
    let guids: BTreeSet<String> = re(r"\{0CCE92[0-9A-F]{2}-69AE-11D9-BED3-505054503030\}")
        .find_iter(ps1())
        .map(|m| m.as_str().to_string())
        .collect();
    let want: BTreeSet<String> = WINDOWS_AUDIT_SUBCATEGORIES.iter().map(|(g, ..)| g.to_string()).collect();
    assert_eq!(guids, want);
    assert_eq!(WINDOWS_AUDIT_SUBCATEGORIES.len(), 6);
    assert_eq!(want.len(), 6);
}

#[test]
fn script_audit_uses_advanced_subcategories_and_says_so() {
    let text = setting("audit").1;
    assert_has(text, "Advanced audit policy");
    assert_hasnt(ps1(), "Basic audit policy");
    assert_hasnt(&text.to_lowercase(), "basic audit");
}

#[test]
fn script_audit_raises_the_security_log_size_and_never_lowers_it() {
    let part = apply_of("audit");
    assert_has(&part, "134217728"); // 128 MiB
    assert_has(&part, "wevtutil.exe sl Security");
    assert_re(&part, r"\$oldBytes -ge \$wantBytes"); // only raised, never lowered
    assert_has(&part, "Security log size raised from"); // old and new size are logged
    assert_has(&part, "MiB to");
    let risk = setting("audit").2;
    assert_has(risk, "128 MiB");
    assert_has(risk, "Retention is still limited");
    assert_eq!(134217728, 128 * 1024 * 1024);
}

#[test]
fn script_audit_reports_each_rejected_subcategory_and_names_the_listing_command() {
    let part = apply_of("audit");
    assert_re(&part, r"Write-Result 'FAIL' \('Audit subcategory '");
    assert_has(&part, "auditpol /list /subcategory:* /v");
    // The exit code of auditpol is checked in the helper that calls it.
    assert_has(ps1().split("function Set-AuditSubcategory").nth(1).unwrap(), "$LASTEXITCODE -ne 0");
}

#[test]
fn script_settings_are_read_back_before_saying_ok() {
    for sid in ["firewall", "defender_cloud", "asr_lsass", "asr_audit", "asr_audit_extra"] {
        let part = apply_of(sid);
        assert_re(&part, r"Write-Result 'WARN' '[^']* not in effect'");
        assert_has(&part, "likely reason");
    }
    assert_eq!(count(&apply_of("firewall"), "Get-NetFirewallProfile"), 2); // before and after setting
    assert_eq!(count(&apply_of("defender_cloud"), "Get-MpPreference"), 2);
    assert_has(&apply_of("asr_lsass"), "Get-AsrAction $ruleId");
    assert_has(&apply_of("asr_audit"), "Get-AsrAction $id");
    assert_has(&apply_of("asr_audit_extra"), "Get-AsrAction $id");
    assert_has(ps1(), "Tamper Protection");
}

#[test]
fn script_warn_is_counted_and_reported_in_the_summary() {
    assert_has(ps1(), "$script:CountWarn++");
    assert_has(ps1(), "not in effect, ' + $script:CountFail");
}

#[test]
fn script_header_and_notes_say_it_runs_once_and_does_not_retry() {
    let head = ps1().split("function Write-Result").next().unwrap();
    assert_has(head, "does NOT retry");
    for sid in ["firewall", "defender_cloud", "asr_lsass", "asr_audit", "asr_audit_extra"] {
        assert_has(setting(sid).2, "runs once at the end of Setup and does not retry");
    }
}

#[test]
fn script_powershell_2_is_disabled_not_removed() {
    let text = setting("ps2").1;
    assert!(text.starts_with("Disable"));
    for sid in ["ps2", "smb1"] {
        let part = apply_of(sid);
        assert_hasnt(&part, "removed");
        assert_has(&part, "disabled");
    }
    assert_hasnt(ps1(), "Remove the PowerShell");
}

#[test]
fn script_optional_features_are_listed_only_once() {
    // One slow Get-WindowsOptionalFeature call for the whole script, cached by Get-FeatureState.
    assert_eq!(count(ps1(), "Get-WindowsOptionalFeature -Online"), 1);
    assert_hasnt(&apply_of("smb1"), "Get-WindowsOptionalFeature");
    assert_hasnt(&apply_of("ps2"), "Get-WindowsOptionalFeature");
    assert_has(&apply_of("smb1"), "Get-FeatureState");
    assert_has(&apply_of("ps2"), "Get-FeatureState");
}

#[test]
fn script_autorun_note_mentions_phones_and_cameras() {
    let risk = setting("autorun").2;
    assert_has(risk, "phones");
    assert_has(risk, "cameras");
}

#[test]
fn script_idempotence_helpers_exist() {
    for name in ["Set-RegDword", "Set-AsrRule", "Get-AsrAction", "Get-FeatureState", "Write-Result"] {
        assert_has(ps1(), &format!("function {name}"));
    }
}

#[test]
fn script_powershell_51_syntax_only() {
    // Syntax that does not exist in Windows PowerShell 5.1.
    for token in ["?:", "&&", "||", "??", "?.", "-AsHashtable", "ForEach-Object -Parallel", "$IsWindows"] {
        assert_hasnt(ps1(), token);
    }
}

// ---------------------------------------------------------------------------------------------------------------
// DescribeTests
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn describe_one_line_per_setting() {
    let lines = describe_hardening_windows(Hardening::Baseline);
    assert_eq!(lines.len(), WINDOWS_HARDENING_SETTINGS.len());
    for (line, (_sid, text, risk)) in lines.iter().zip(WINDOWS_HARDENING_SETTINGS) {
        assert_has(line, text);
        assert_has(line, risk);
        assert!(line.is_ascii());
    }
}

#[test]
fn describe_every_line_has_a_portuguese_translation() {
    // The GUI shows these lines through _() in a Portuguese window: a line without an entry stays English. The
    // lookup goes to the generated table itself; `i18n::tr` is A1's and has its own tests.
    let lines = describe_hardening_windows(Hardening::Baseline);
    for line in &lines {
        let pt = pt_for(line).unwrap_or_else(|| panic!("no Portuguese text for {:.60}", line));
        assert!(!pt.trim().is_empty());
        assert_ne!(pt, line);
        assert_has(pt, " -- risco: ");
        assert_eq!(count(line, "[WARN]"), count(pt, "[WARN]"), "{:.60}", line);
    }
    assert_eq!(count(pt_for(&lines[0]).unwrap(), " -- risco: "), 1);
}

#[test]
fn describe_returns_a_fresh_list() {
    let mut a = describe_hardening_windows(Hardening::Baseline);
    a.push("x".to_string());
    assert!(!describe_hardening_windows(Hardening::Baseline).contains(&"x".to_string()));
}

#[test]
fn describe_applied_leaves_out_the_opt_in_settings() {
    let all = describe_hardening_windows(Hardening::Baseline);
    let applied = describe_hardening_windows_applied(Hardening::Baseline);
    assert_eq!(applied.len(), all.len() - WINDOWS_HARDENING_OPTIN.len());
    assert!(applied.iter().all(|l| !l.contains("-DisableLegacyNetwork")));
    let expect: Vec<String> = WINDOWS_HARDENING_SETTINGS
        .iter()
        .filter(|(sid, ..)| !WINDOWS_HARDENING_OPTIN.contains(sid))
        .map(|(_, t, r)| format!("{t} -- risk: {r}"))
        .collect();
    assert_eq!(applied, expect);
}

#[test]
fn describe_not_changed_notes_exist() {
    let found: BTreeSet<&str> = WINDOWS_HARDENING_NOT_CHANGED.iter().map(|r| r.0).collect();
    assert!(found.contains("bitlocker") && found.contains("ntlm"));
    for (_sid, text, why) in WINDOWS_HARDENING_NOT_CHANGED {
        assert!(!text.is_empty() && !why.is_empty());
    }
}

// ---------------------------------------------------------------------------------------------------------------
// hardening2: WIN-SCRIPT tests
// ---------------------------------------------------------------------------------------------------------------

const GUID_RE: &str = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";
/// Commands that change something. Nothing in the Audit branches or in the helpers they use may contain them.
const MUTATORS: &str = r"\b(Set|New|Remove|Add|Enable|Disable|Save|Restore|Move|Rename|Clear|Import|Initialize|Out)-[A-Za-z]+|auditpol\.exe /(set|backup|restore)|wevtutil\.exe sl";
const ORIGINAL_ASR_RULES: [&str; 5] = [
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc",
    "d3e037e1-3eb8-44c8-a917-57927947596d",
];

// ---- ParameterTests

#[test]
fn param_block_comes_first_and_is_a_cmdlet_binding() {
    let code: Vec<&str> =
        ps1().lines().filter(|ln| !ln.trim().is_empty() && !ln.trim_start().starts_with('#')).collect();
    assert_eq!(code[0], "[CmdletBinding()]");
    assert_eq!(code[1], "param(");
}

#[test]
fn param_parameters_and_safe_defaults() {
    let text = ps1();
    assert_has(text, "[ValidateSet('Apply', 'Audit', 'Undo')]");
    assert_has(text, "[string]$Mode = 'Apply'");
    assert_has(text, "[switch]$DisableLegacyNetwork"); // a switch is $false unless given
    assert_has(text, "[string]$LogPath = (Join-Path $env:windir 'Temp\\epma-hardening.log')");
    assert!(WINDOWS_HARDENING_LOG.ends_with("\\Temp\\epma-hardening.log"));
    assert_eq!(WINDOWS_HARDENING_MODES, ["Apply", "Audit", "Undo"]);
}

#[test]
fn param_setupcomplete_is_unchanged_and_passes_no_arguments() {
    assert_has(&base().cmd_text, "-File \"%~dp0harden.ps1\" >> \"%EPMA_LOG%\" 2>&1");
    assert_hasnt(&base().cmd_text, "-Mode");
    assert_hasnt(&base().cmd_text, "DisableLegacyNetwork");
}

#[test]
fn param_refuses_without_administrator_with_a_clear_message() {
    let text = ps1();
    assert_has(text, "IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)");
    assert_has(text, "$isSystem = $identity.IsSystem");
    assert_has(text, "must run as administrator");
    assert_has(text, "Nothing was changed.");
    let i_check = at(text, "if (-not $isAdmin)");
    // The refusal happens before the first setting, the state file and the log file are touched.
    assert!(i_check < at(text, "# setting: smb1"));
    assert!(i_check < at(text, "Import-State)"));
    assert!(i_check < at(text, "Write-Log ('[START]"));
}

#[test]
fn param_console_and_log_file() {
    let body = function("Write-Log");
    assert_has(&body, "Write-Host $Line");
    assert_has(&body, "Add-Content -LiteralPath $LogPath");
    assert_has(&body, "catch"); // a log file that cannot be written never stops the script
                                // SetupComplete.cmd appends the console output itself: as SYSTEM with the default path the file is not written a
                                // second time. Audit mode writes a file only when -LogPath was given on purpose.
    assert_has(ps1(), "$PSBoundParameters.ContainsKey('LogPath')");
    assert_has(ps1(), "($isSystem -or ($Mode -eq 'Audit'))");
}

#[test]
fn param_every_line_goes_through_write_log() {
    // Only the refusal (before the log exists), the log writer itself and its failure notice use Write-Host.
    let hosts: Vec<&str> = ps1().lines().filter(|ln| re(r"^\s*Write-Host\b").is_match(ln)).map(str::trim).collect();
    assert!(hosts.len() <= 4, "{hosts:?}");
}

#[test]
fn param_no_restart_no_iex_no_network_in_any_mode() {
    let low = ps1().to_lowercase();
    for word in
        ["restart-computer", "invoke-expression", "iex ", "invoke-webrequest", "downloadfile", "http://", "https://"]
    {
        assert_hasnt(&low, word);
    }
}

// ---- ModeCoverageTests

#[test]
fn mode_three_tables_cover_the_same_settings_in_order() {
    assert_eq!(ids(), keys(&WINDOWS_PS_CODE));
    assert_eq!(ids(), keys(&WINDOWS_PS_AUDIT));
    assert_eq!(ids(), keys(&WINDOWS_PS_UNDO));
}

#[test]
fn mode_every_setting_is_handled_in_all_three_modes() {
    for sid in ids() {
        let (apply_code, audit_code, undo_code) = branches(sid);
        for code in [&apply_code, &audit_code, &undo_code] {
            assert_re(code, r"\btry \{");
            assert_re(code, r"\bcatch \{");
        }
        assert_has(&apply_code, "Write-Result 'FAIL'");
        assert_has(&audit_code, "Write-Audit");
        assert_hasnt(&audit_code, "Write-Result"); // Audit prints [OK]/[DIFF]/[N/A] only
        assert_has(&audit_code, "Write-Audit 'NA'"); // a check that fails is reported, not fatal
        assert_re(&undo_code, r"Write-UndoSummary|Write-Result '(SKIP|WARN)'");
        assert_hasnt(&undo_code, "Write-Audit");
    }
}

#[test]
fn mode_marker_and_three_branches_once_per_setting() {
    let n = ids().len();
    for token in ["if ($Mode -eq 'Apply') {", "} elseif ($Mode -eq 'Audit') {", "} else {"] {
        assert!(count(ps1(), token) >= n, "{token}");
    }
    assert_eq!(re(r"(?m)^# setting: ").find_iter(ps1()).count(), n);
}

#[test]
fn mode_one_log_line_per_setting_in_audit() {
    // Audit prints a verdict tag: [OK] ... in effect, [DIFF] ... not in effect, [N/A].
    let body = function("Write-Audit");
    for token in ["'[OK] '", "'[DIFF] '", "'[N/A] '", "-- in effect (", "-- not in effect ("] {
        assert_has(&body, token);
    }
}

#[test]
fn mode_audit_branches_and_helpers_change_nothing() {
    let mutators = re(MUTATORS);
    for (sid, code) in WINDOWS_PS_AUDIT.iter() {
        assert!(!mutators.is_match(code), "{sid}: {:?}", mutators.find(code));
    }
    assert!(!mutators.is_match(WINDOWS_PS_AUDIT_INFO));
    for name in
        ["Get-RegDword", "Format-Value", "Get-FeatureState", "Get-AsrAction", "Get-AsrActionName", "Get-AuditSetting"]
    {
        let body = function(name);
        assert!(!mutators.is_match(&body), "{name}: {:?}", mutators.find(&body));
    }
    assert_has(&function("Get-AuditSetting"), "auditpol.exe /get");
}

#[test]
fn mode_audit_never_touches_the_state_file() {
    // State is read and written only when the mode is not Audit.
    assert_re(ps1_lf(), r"if \(\$Mode -ne 'Audit'\) \{\n    if \(-not \(Import-State\)\) \{");
    for (sid, code) in WINDOWS_PS_AUDIT.iter() {
        for token in ["Add-StateOnce", "Save-State", "Import-State", "Initialize-StateFolder", "$script:State"] {
            assert!(!code.contains(token), "{sid}: {token}");
        }
    }
    assert_hasnt(WINDOWS_PS_AUDIT_INFO, "Save-State");
}

#[test]
fn mode_audit_ends_with_the_summary_line() {
    assert_has(
        ps1(),
        "Write-Log ('[DONE] ' + $script:CountOk + ' in effect, ' + $script:CountDiff + ' not in effect')",
    );
    assert_has(ps1(), "$script:CountDiff++");
}

#[test]
fn mode_audit_reports_read_only_facts() {
    let info = WINDOWS_PS_AUDIT_INFO;
    for token in [
        "Get-BitLockerVolume",
        "Get-Tpm",
        "Confirm-SecureBootUEFI",
        "Get-MpComputerStatus",
        "IsTamperProtected",
        "AttackSurfaceReductionRules_Ids",
        "Win32_DeviceGuard",
        "SecurityServicesRunning",
        "LsaCfgFlags",
        "HypervisorEnforcedCodeIntegrity",
    ] {
        assert_has(info, token);
    }
    // Secure Boot throws on legacy BIOS: it is inside its own try/catch.
    assert_re(info, r"(?s)try \{\n\s*if \(Confirm-SecureBootUEFI\).*?\} catch \{");
    // Facts are reported with [INFO] and never counted in the summary.
    assert_hasnt(info, "Write-Audit");
    assert_has(ps1(), "function Write-Info");
    assert_has(ps1(), "'[INFO] '");
}

#[test]
fn mode_credential_guard_hvci_bitlocker_exploit_protection_are_never_enabled() {
    let low = ps1().to_lowercase();
    for token in
        ["enable-bitlocker", "manage-bde", "set-processmitigation", "add-bitlockerkeyprotector", "lsacfgflags' -value"]
    {
        assert_hasnt(&low, token);
    }
    let names: BTreeSet<&str> = WINDOWS_HARDENING_NOT_CHANGED.iter().map(|r| r.0).collect();
    assert!(names.contains("device_guard"));
    assert_hasnt(ps1(), r"Set-RegDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'");
}

// ---- StateAndUndoTests

#[test]
fn state_file_path_constant() {
    assert_eq!(WINDOWS_HARDENING_STATE, "%ProgramData%\\EPMA\\hardening-state.json");
    assert_eq!((WINDOWS_HARDENING_STATE_DIR, WINDOWS_HARDENING_STATE_FILE), ("EPMA", "hardening-state.json"));
    assert_has(ps1(), "$script:StateDir = Join-Path $env:ProgramData 'EPMA'");
    assert_has(ps1(), "$script:StatePath = Join-Path $script:StateDir 'hardening-state.json'");
    assert_has(ps1(), WINDOWS_HARDENING_STATE); // said in the header too
}

#[test]
fn state_folder_is_limited_to_administrators_and_system() {
    // Created in ONE call with its protected access list (no window in which another user could own it).
    let init = function("Initialize-StateFolder");
    assert_has(&init, "[System.IO.Directory]::CreateDirectory($script:StateDir, (New-StateSecurity))");
    for token in ["New-Item", "Set-Acl"] {
        assert_hasnt(&init, token);
    }
    let security = function("New-StateSecurity");
    for token in [
        "DirectorySecurity",
        "SetAccessRuleProtection($true, $false)",
        "'S-1-5-18'",
        "'S-1-5-32-544'",
        "FileSystemAccessRule",
        "'FullControl'",
    ] {
        assert_has(&security, token);
    }
    // Only SYSTEM and Administrators are ever granted anything.
    assert_eq!(re(r"S-1-\d+(?:-\d+)+").find_iter(&security).count(), 2);
}

#[test]
fn state_first_seen_value_is_never_overwritten() {
    let body = function("Add-StateOnce");
    assert_has(&body, "if ($script:State.ContainsKey($Key)) { return }");
    // If the record cannot be saved the change that follows is not made.
    assert_has(&body, "throw");
    assert_has(&body, "Save-State");
}

#[test]
fn state_value_is_recorded_before_it_is_changed() {
    for (name, change) in [
        ("Set-RegDword", "New-ItemProperty"),
        ("Set-AsrRule", "Add-MpPreference"),
        ("Set-AuditSubcategory", "auditpol.exe /set"),
    ] {
        let body = function(name);
        assert_has(&body, "Add-StateOnce");
        before(&body, "Add-StateOnce", change);
    }
    for sid in ["smb1", "ps2"] {
        let code = apply_of(sid);
        before(&code, "Save-FeatureState", "Disable-WindowsOptionalFeature");
    }
    let firewall = apply_of("firewall");
    before(&firewall, "Save-FirewallState", "Set-NetFirewallProfile");
    let defender = apply_of("defender_cloud");
    before(&defender, "Save-DefenderValue 'PUAProtection'", "Set-MpPreference -PUAProtection");
    before(&defender, "Save-DefenderValue 'MAPSReporting'", "Set-MpPreference -MAPSReporting");
    let audit = apply_of("audit");
    before(&audit, "Save-EventLogState", "wevtutil.exe sl");
}

#[test]
fn state_is_json_with_enough_depth() {
    let body = function("Save-State");
    assert_has(&body, "ConvertTo-Json -Depth 6");
    assert_has(&body, "Set-Content -LiteralPath $script:StatePath");
    assert_has(&function("Import-State"), "ConvertFrom-Json");
}

#[test]
fn state_undo_handles_every_kind_of_change_that_apply_records() {
    let alternatives =
        WINDOWS_HARDENING_STATE_PAIRS.iter().map(|(k, _)| regex::escape(k)).collect::<Vec<_>>().join("|");
    let setter_re = re(&format!(r"\b({alternatives})\b"));
    for sid in ids() {
        let (apply_code, _audit, undo_code) = branches(sid);
        let used: BTreeSet<String> = setter_re.captures_iter(&apply_code).map(|c| c[1].to_string()).collect();
        for setter in used {
            let restorer = WINDOWS_HARDENING_STATE_PAIRS.iter().find(|(k, _)| *k == setter).unwrap().1;
            assert!(undo_code.contains(restorer), "{sid}: Apply uses {setter} but Undo never calls {restorer}");
        }
    }
    // Every setter and restorer exists as a function; every recorded kind has a restorer.
    for (setter, restorer) in WINDOWS_HARDENING_STATE_PAIRS {
        assert_has(ps1(), &format!("function {setter} "));
        assert_has(ps1(), &format!("function {restorer} "));
    }
    let kinds: BTreeSet<String> = re(r"kind = '(\w+)'").captures_iter(ps1()).map(|c| c[1].to_string()).collect();
    let want: BTreeSet<String> =
        ["reg", "asr", "audit", "fw", "mp", "feature", "eventlog"].iter().map(|s| s.to_string()).collect();
    assert_eq!(kinds, want);
}

#[test]
fn state_apply_never_changes_without_a_recording_helper() {
    // A raw change command may only appear inside the helpers (which record first) or after a Save-* call.
    for sid in ids() {
        let apply_code = apply_of(sid);
        for raw in
            ["New-ItemProperty", "Set-ItemProperty", "Add-MpPreference", "Remove-MpPreference", "Remove-ItemProperty"]
        {
            // `(?<!Get-Command )` + raw: the regex crate has no look-behind, so check the preceding text by hand.
            for (pos, _) in apply_code.match_indices(raw) {
                assert!(apply_code[..pos].ends_with("Get-Command "), "{sid}: raw {raw} at {pos}");
            }
        }
    }
}

#[test]
fn state_undo_restores_removes_or_reports() {
    let reg = function("Restore-RegValue");
    for token in ["New-ItemProperty", "Remove-ItemProperty", "$rec.existed", "Remove-StateEntry $key", "'no record'"] {
        assert_has(&reg, token);
    }
    let asr = function("Restore-AsrRule");
    assert_has(&asr, "Remove-MpPreference");
    assert_has(&asr, "Add-MpPreference");
    assert_has(&asr, "Get-AsrAction $Id"); // read back
    let audit = function("Restore-AuditSubcategory");
    assert_has(&audit, "/success:disable");
    assert_has(&audit, "auditpol /restore /file:");
    assert_has(&audit, "if (-not $known)"); // an unreadable earlier value is never guessed
    assert_has(&audit, "Get-RecordBool $rec.known");
}

#[test]
fn state_undo_logs_ok_skip_warn_only() {
    for sid in ids() {
        assert_hasnt(&undo_of(sid), "'FAIL'");
    }
    assert_has(&function("Write-UndoSummary"), "Write-Result 'SKIP' $What 'nothing recorded");
    assert_has(&function("Write-UndoSummary"), "Write-Result 'OK' $What");
}

#[test]
fn state_undo_states_what_it_cannot_undo() {
    let feature = function("Restore-FeatureState");
    assert_has(&feature, "Enable-WindowsOptionalFeature -Online -FeatureName");
    for sid in ["smb1", "ps2"] {
        assert_has(&undo_of(sid), "Write-Result 'WARN'");
    }
    assert_has(&function("Restore-EventLogState"), "not shrunk");
    for token in ["Enable-WindowsOptionalFeature", "never shrinks", "auditpol /restore", "already in the wanted state"]
    {
        assert_has(WINDOWS_PS_END_UNDO, token);
    }
}

#[test]
fn state_feature_is_never_turned_back_on_by_undo() {
    // Turning SMBv1 or PowerShell 2.0 back on would weaken the PC: Undo only tells the owner how.
    assert_no_re(ps1(), r"(?m)^\s*Enable-WindowsOptionalFeature");
    assert_no_re(ps1(), r"(?m)^\s*& Enable-WindowsOptionalFeature");
}

#[test]
fn state_audit_policy_is_saved_once_with_auditpol_backup() {
    let body = function("Save-AuditBackup");
    assert_has(&body, "auditpol.exe /backup");
    assert_has(&body, "if (Test-Path -LiteralPath $script:AuditBackupPath) {");
    before(&body, "Initialize-StateFolder", "auditpol.exe /backup");
}

#[test]
fn state_unreadable_state_never_leads_to_unrecorded_changes() {
    assert_has(ps1_lf(), "without a record there would be no way back");
    assert_has(ps1_lf(), "'.unreadable-'");
}

#[test]
fn state_empty_state_file_is_removed_after_undo() {
    assert_has(WINDOWS_PS_END_UNDO, "Remove-Item -LiteralPath $script:StatePath -Force");
    assert_has(WINDOWS_PS_END_UNDO, "$script:State.Count -eq 0");
}

// ---- NewSettingsTests

#[test]
fn new_asr_guids_are_well_formed_and_unique() {
    let every: Vec<&str> = std::iter::once(WINDOWS_ASR_LSASS)
        .chain(WINDOWS_ASR_AUDIT_RULES.iter().copied())
        .chain(WINDOWS_ASR_AUDIT_EXTRA_RULES.iter().copied())
        .collect();
    assert_eq!(every.len(), 8);
    assert_eq!(every.iter().collect::<BTreeSet<_>>().len(), every.len());
    for guid in &every {
        assert_re(guid, GUID_RE);
    }
    // The script mentions exactly these GUIDs (the audit-policy ones have braces and capital letters).
    let in_script: BTreeSet<&str> = re(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
        .find_iter(ps1())
        .map(|m| m.as_str())
        .collect();
    assert_eq!(in_script, every.iter().copied().collect::<BTreeSet<_>>());
}

#[test]
fn new_the_original_five_rules_are_unchanged() {
    let got: Vec<&str> = std::iter::once(WINDOWS_ASR_LSASS).chain(WINDOWS_ASR_AUDIT_RULES.iter().copied()).collect();
    assert_eq!(got, ORIGINAL_ASR_RULES);
}

#[test]
fn new_asr_rules_are_the_certain_ones() {
    assert_eq!(
        WINDOWS_ASR_AUDIT_EXTRA_RULES,
        [
            "56a863a9-875e-4185-98a7-b882c64b5ce5", // abuse of exploited vulnerable signed drivers
            "d1e49aac-8f56-4280-b9ba-993a6d77406c", // process creations from PSExec and WMI
            "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", // untrusted processes from USB
        ]
    );
}

#[test]
fn new_asr_rules_are_audit_mode_only() {
    let apply_code = apply_of("asr_audit_extra");
    assert_has(&apply_code, "-Action 'AuditMode'");
    assert_hasnt(&apply_code, "'Enabled'");
    for guid in WINDOWS_ASR_AUDIT_EXTRA_RULES {
        assert_has(&apply_code, guid);
        assert_hasnt(&apply_of("asr_audit"), guid);
    }
    // Block mode (the only 'Enabled') stays reserved for the LSASS rule.
    assert_eq!(count(ps1(), "-Action 'Enabled'"), 1);
}

#[test]
fn new_opt_in_settings_are_listed_and_gated() {
    assert_eq!(WINDOWS_HARDENING_OPTIN, ["netbios", "wpad"]);
    for sid in WINDOWS_HARDENING_OPTIN {
        assert!(ids().contains(&sid), "{sid}");
        let (apply_code, audit_code, _undo) = branches(sid);
        assert_has(&apply_code, "if (-not $DisableLegacyNetwork) {");
        assert_has(&apply_code, "Write-Result 'SKIP'");
        before(&apply_code, "-not $DisableLegacyNetwork", "Set-RegDword");
        assert_has(&audit_code, "-OptIn $true");
        assert_has(setting(sid).1, "-DisableLegacyNetwork");
    }
    // Only the opt-in settings look at the switch.
    for sid in ids() {
        if !WINDOWS_HARDENING_OPTIN.contains(&sid) {
            assert_hasnt(&apply_of(sid), "DisableLegacyNetwork");
        }
    }
}

#[test]
fn new_opt_in_audit_does_not_count_a_setting_that_was_never_requested() {
    let body = function("Write-Audit");
    assert_has(&body, "-not $DisableLegacyNetwork");
    assert_has(&body, "$Verdict = 'NA'");
    assert_has(&body, "not counted");
}

#[test]
fn new_netbios_and_wpad_do_only_what_is_certain() {
    let net = branches("netbios");
    assert_has(&net.0, r"HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces");
    assert_has(&net.0, "'Tcpip_*'");
    assert_has(&net.0, "-Name 'NetbiosOptions' -Value 2");
    assert_has(&net.2, "NetBT");
    let wpad = branches("wpad");
    assert_has(&wpad.0, r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp");
    assert_has(&wpad.0, "-Name 'DisableWpad' -Value 1");
    // The WinHTTP auto-proxy service is not stopped or disabled, and no service is touched at all.
    let low = ps1().to_lowercase();
    for token in ["stop-service", "set-service", "sc.exe", "winhttpautoproxysvc"] {
        assert_hasnt(&low, token);
    }
}

#[test]
fn new_describe_lines_exist_and_mention_the_switch() {
    let lines = describe_hardening_windows(Hardening::Baseline);
    assert_eq!(lines.len(), ids().len());
    let joined = lines.join("\n");
    assert_has(&joined, "more: abuse of exploited vulnerable signed drivers");
    assert_has(&joined, "NetBIOS over TCP/IP");
    assert_has(&joined, "WPAD");
    assert_eq!(lines.iter().filter(|ln| ln.contains("-DisableLegacyNetwork")).count(), 2);
}

#[test]
fn new_describe_lines_have_portuguese_text() {
    let new: Vec<String> = describe_hardening_windows(Hardening::Baseline)
        .into_iter()
        .filter(|ln| ln.contains("more: abuse") || ln.contains("NetBIOS") || ln.contains("WPAD"))
        .collect();
    assert_eq!(new.len(), 3);
    for line in &new {
        let pt = pt_for(line).unwrap_or_else(|| panic!("no Portuguese text for {:.50}", line));
        assert_ne!(pt, line);
        assert_eq!(count(pt, " -- risco: "), 1);
        assert_eq!(count(line, "-DisableLegacyNetwork"), count(pt, "-DisableLegacyNetwork"));
        assert_eq!(count(line, "[WARN]"), count(pt, "[WARN]"));
    }
}

// ---- PublicHelperTests

#[test]
fn public_bytes_equal_the_file_in_hardening_files_windows() {
    assert_eq!(windows_hardening_ps1(Hardening::Baseline).unwrap(), base().files[PS1_PATH]);
}

#[test]
fn public_format() {
    let data = windows_hardening_ps1(Hardening::Baseline).unwrap();
    assert!(data.starts_with(&[0xef, 0xbb, 0xbf]));
    let body = &data[3..];
    assert!(body.is_ascii());
    assert!(only_crlf(body));
    assert!(data.len() <= MAX_FILE);
}

#[test]
fn public_profiles() {
    assert_eq!(windows_hardening_ps1(Hardening::None).unwrap(), b"");
    assert_eq!(Hardening::parse("strict"), None); // an unknown profile cannot be built (ValueError in the Python)
}

#[test]
fn public_deterministic() {
    assert_eq!(
        windows_hardening_ps1(Hardening::Baseline).unwrap(),
        windows_hardening_ps1(Hardening::Baseline).unwrap()
    );
}

#[test]
fn public_hardening_files_windows_uses_the_same_bytes() {
    // The Python patched `_windows_harden_ps1` with a marker; here both files come out of one generation, so the
    // check is that the SHA-256 recorded in SetupComplete.cmd is that of the harden.ps1 in the same set.
    let files = hardening_files_windows(Hardening::Baseline).unwrap();
    assert_eq!(files[PS1_PATH], windows_harden_ps1().unwrap());
    let cmd = String::from_utf8(files[CMD_PATH].clone()).unwrap();
    assert_has(&cmd, &format!("set \"EPMA_WANT={}\"", sha256_hex(&files[PS1_PATH])));
}

// ---------------------------------------------------------------------------------------------------------------
// hardening3: FIX-PS1 tests (review of harden.ps1: state-file tampering, Undo honesty)
// ---------------------------------------------------------------------------------------------------------------

/// The script between the START line and the first setting.
fn start_part() -> String {
    let text = ps1_lf();
    text[at(text, "Write-Log ('[START]")..at(text, "# setting: smb1")].to_string()
}

// ---- 1. the state folder

#[test]
fn safety_existing_folder_is_checked_for_reparse_point_owner_and_other_writers() {
    let body = function("Test-TrustedPath");
    for token in [
        "[System.IO.FileAttributes]::ReparsePoint",
        "GetOwner([System.Security.Principal.SecurityIdentifier])",
        "'S-1-5-18'",
        "'S-1-5-32-544'",
        "$trusted -notcontains $owner.Value",
        "GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])",
        "AccessControlSections]::Access",
        "$rule.AccessControlType -ne 'Allow'",
        "$script:WriteMask",
    ] {
        assert_has(&body, token);
    }
    // A folder without any access list (a null DACL) means "everyone" and is refused too.
    assert_has(&body, "[string]::IsNullOrEmpty($sddl)");
    // The write mask covers every right that lets someone change the folder and none of the read-only rights.
    let m = re(r"\$script:WriteMask = 0x([0-9A-Fa-f]+)").captures(ps1()).expect("WriteMask");
    let mask = u64::from_str_radix(&m[1], 16).unwrap();
    let write_rights: [u64; 10] = [0x2, 0x4, 0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000, 0x1000_0000, 0x4000_0000];
    let read_rights: [u64; 6] = [0x1, 0x8, 0x20, 0x80, 0x20000, 0x100000];
    for bit in write_rights {
        assert!(mask & bit != 0, "{bit:#x}");
    }
    for bit in read_rights {
        assert!(mask & bit == 0, "{bit:#x}");
    }
    assert_eq!(mask, write_rights.iter().sum::<u64>());
    assert!(mask < 2u64.pow(31)); // fits the [int] it is compared with
}

#[test]
fn safety_a_folder_that_cannot_be_trusted_is_never_used() {
    let assert_folder = function("Assert-StateFolder");
    assert_has(&assert_folder, "Test-TrustedPath $script:StateDir $true");
    assert_has(&assert_folder, "throw (");
    assert_has(&assert_folder, "delete it or rename it");
    let init = function("Initialize-StateFolder");
    // Created, then ALWAYS checked (somebody else may have created it in between): there is no path that skips it.
    before(&init, "CreateDirectory", "Assert-StateFolder");
    assert!(init.trim_end().ends_with("Assert-StateFolder"));
    // Never fail open: none of the checks swallows an error.
    for name in
        ["Initialize-StateFolder", "Assert-StateFolder", "Test-TrustedPath", "Assert-TrustedFile", "New-StateSecurity"]
    {
        assert_no_re(&function(name), r"\bcatch\b");
    }
    assert_has(&function("Assert-TrustedFile"), "throw");
}

#[test]
fn safety_checks_come_before_any_state_write_or_change() {
    let save = function("Save-State");
    before(&save, "Initialize-StateFolder", "Set-Content");
    let start = start_part();
    before(&start, "Initialize-StateFolder", "Import-State)");
    // ... and before the first setting, because START is part of the text before "# setting: smb1".
    assert!(at(ps1(), "Initialize-StateFolder\r\n") < at(ps1(), "# setting: smb1"));
    let imp = function("Import-State");
    before(&imp, "Assert-TrustedFile $script:StatePath", "Get-Content");
    assert_has(&imp, "1048576"); // a state file larger than 1 MiB is not read
    assert_has(&imp, "$doc.version -ne 1");
    assert_has(&imp, "-isnot [System.Management.Automation.PSCustomObject]");
}

#[test]
fn safety_apply_and_undo_refuse_when_the_folder_cannot_be_trusted() {
    let start = start_part();
    let i = at(&start, "Initialize-StateFolder");
    let snippet = &start[i..at(&start, "Import-State)")];
    assert_has(
        snippet,
        "elseif ($null -ne (Get-Item -LiteralPath $script:StateDir -Force -ErrorAction SilentlyContinue)) {\n            Assert-StateFolder",
    );
    assert_re(
        snippet,
        r"\} catch \{\n\s+Write-Log \('\[FAIL\] ' \+ \$_\.Exception\.Message \+ ' Nothing was changed\.'\)\n\s+if \(\$isSystem\) \{ exit 0 \}\n\s+exit 1\n",
    );
    // Apply creates the folder, Undo only looks at an existing one (it never creates anything).
    assert_re(&start, r"if \(\$Mode -eq 'Apply'\) \{\n\s+Initialize-StateFolder\n");
    assert_hasnt(&function("Import-State"), "Initialize-StateFolder");
    for sid in ids() {
        assert_hasnt(&undo_of(sid), "Initialize-StateFolder");
    }
}

#[test]
fn safety_audit_policy_backup_lives_in_the_same_checked_folder() {
    assert_has(ps1(), "$script:AuditBackupPath = Join-Path $script:StateDir 'audit-policy-before.csv'");
    let body = function("Save-AuditBackup");
    before(&body, "Initialize-StateFolder", "Assert-TrustedFile $script:AuditBackupPath");
    before(&body, "Assert-TrustedFile $script:AuditBackupPath", "auditpol.exe /backup");
    // Every change of the audit policy goes through the recorder, so a failing folder check stops it.
    before(&function("Set-AuditSubcategory"), "Add-StateOnce", "auditpol.exe /set");
}

#[test]
fn safety_no_switch_weakens_the_state_check() {
    let params: Vec<String> = re(r"(?m)^\s+\[(?:switch|string|bool|int)\]\$(\w+)")
        .captures_iter(WINDOWS_PS_PARAMS)
        .map(|c| c[1].to_string())
        .collect();
    assert_eq!(params, ["Mode", "DisableLegacyNetwork", "LogPath"]);
    let low = ps1().to_lowercase();
    for word in ["nostatecheck", "skipstatecheck", "-force:$false", "ignorestate"] {
        assert_hasnt(&low, word);
    }
}

// ---- 2. Undo takes VALUES from the file, nothing else

#[test]
fn safety_undo_never_uses_a_path_or_name_from_the_file() {
    let text = ps1();
    assert_no_re(text, r"\$rec\.(path|name|id|guid|kind)\b");
    assert_no_re(text, r"-(Path|Name|LiteralPath|Id|Guid|FeatureName)\s+\$rec\b");
    for m in re(r"Remove-ItemProperty[^\n]*").find_iter(text) {
        assert_eq!(m.as_str().trim(), "Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop");
    }
    for sid in ids() {
        assert_hasnt(&undo_of(sid), "$rec");
    }
    let reg = function("Restore-RegValue");
    // The name and the key are checked against the built-in table before anything else is read or done.
    before(&reg, "Get-KnownRegRange $Path $Name", "$rec = $script:State[$key]");
    before(&reg, "Get-KnownRegRange $Path $Name", "Remove-ItemProperty");
}

#[test]
fn safety_the_builtin_tables_match_the_code() {
    let text = ps1_lf();
    let rows: Vec<(String, String, String, String)> = re(r"(?m)^    '([^|\n]+)\|([^'\n]+)' = @\((-?\d+), (-?\d+)\)$")
        .captures_iter(text)
        .map(|c| (c[1].to_string(), c[2].to_string(), c[3].to_string(), c[4].to_string()))
        .collect();
    let want: Vec<(String, String, String, String)> = WINDOWS_REG_VALUES
        .iter()
        .map(|(p, n, lo, hi)| (p.to_string(), n.to_string(), lo.to_string(), hi.to_string()))
        .collect();
    assert_eq!(rows, want);
    // Every value Undo puts back is in the table, and every value in the table is put back by some setting.
    let pairs: BTreeSet<(String, String)> = re(r"Restore-RegValue -Path '([^']+)' -Name '([^']+)'")
        .captures_iter(text)
        .map(|c| (c[1].to_string(), c[2].to_string()))
        .collect();
    let table: BTreeSet<(String, String)> =
        WINDOWS_REG_VALUES.iter().map(|(p, n, ..)| (p.to_string(), n.to_string())).collect();
    assert_eq!(pairs, table);
    for c in re(r"Set-RegDword -Path '([^']+)' -Name '([^']+)'").captures_iter(text) {
        assert!(pairs.contains(&(c[1].to_string(), c[2].to_string())), "{} {}", &c[1], &c[2]);
    }
    // The attack surface rules and audit subcategories of the tables are exactly the ones the settings use.
    let asr = &re(r"(?s)\$script:KnownAsr = @\(\n(.*?)\n\)").captures(text).unwrap()[1];
    let asr_ids: Vec<&str> = re(r"'([0-9a-f-]{36})'").captures_iter(asr).map(|c| c.get(1).unwrap().as_str()).collect();
    let want_asr: Vec<&str> = std::iter::once(WINDOWS_ASR_LSASS)
        .chain(WINDOWS_ASR_AUDIT_RULES.iter().copied())
        .chain(WINDOWS_ASR_AUDIT_EXTRA_RULES.iter().copied())
        .collect();
    assert_eq!(asr_ids, want_asr);
    let audit = &re(r"(?s)\$script:KnownAudit = @\(\n(.*?)\n\)").captures(text).unwrap()[1];
    let audit_ids: Vec<&str> =
        re(r"'(\{[0-9A-F-]{36}\})'").captures_iter(audit).map(|c| c.get(1).unwrap().as_str()).collect();
    let want_audit: Vec<&str> = WINDOWS_AUDIT_SUBCATEGORIES.iter().map(|(g, ..)| *g).collect();
    assert_eq!(audit_ids, want_audit);
    assert_has(
        text,
        "$script:KnownFeatures = @('SMB1Protocol', 'MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2')",
    );
    assert_has(text, "$script:KnownMp = @('PUAProtection', 'MAPSReporting')");
    for (placeholder, _) in ps_known_tables() {
        assert_hasnt(text, placeholder);
    }
}

#[test]
fn safety_netbios_keys_are_accepted_only_when_they_match_the_interface_pattern() {
    let regex = WINDOWS_NETBT_KEY_REGEX;
    assert_eq!(
        regex,
        r"^HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\Tcpip_\{[0-9A-Fa-f-]{36}\}$"
    );
    assert_has(ps1(), &format!("$script:NetbtPattern = '{regex}'"));
    let pattern = re(regex);
    let base_key = r"HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_";
    let guid = "{12345678-ABCD-abcd-0123-456789abcdef}";
    assert!(pattern.is_match(&format!("{base_key}{guid}")));
    let bad_list = [
        format!("{base_key}{guid}\\extra"),
        format!("{base_key}{{1234}}"),
        format!("{base_key}{{12345678-ABCD-abcd-0123-456789abcdeg}}"),
        format!(r"HKLM:\SOFTWARE\Evil\Tcpip_{guid}"),
        format!("HKCU:{}{guid}", &base_key[5..]),
        format!(" {base_key}{guid}"),
        format!("{}{guid}", base_key.replace("Tcpip_", "tcpip2_")),
    ];
    for bad in &bad_list {
        assert!(!pattern.is_match(bad), "{bad}");
    }
    let net = undo_of("netbios");
    assert_has(&net, "$ifaceKey -match $script:NetbtPattern");
    assert_has(&net, "Restore-RegValue -Path $ifaceKey -Name 'NetbiosOptions'");
    assert_has(&net, r"'^reg\|(.+)\|NetbiosOptions$'");
    let reg = function("Get-KnownRegRange");
    assert_has(
        &reg,
        r"($Name -eq 'NetbiosOptions') -and ($Path -match $script:NetbtPattern) -and ($Path -notmatch '[\r\n]')",
    );
}

#[test]
fn safety_values_read_from_the_file_are_validated() {
    let safe = function("ConvertTo-SafeInt");
    for token in ["-isnot [int]", "-isnot [long]", "-lt $Min", "-gt $Max", "throw"] {
        assert_has(&safe, token);
    }
    let reg = function("Restore-RegValue");
    for token in [
        "Get-RecordBool $rec.existed",
        "Get-RecordChoice $rec.type @('DWord', 'QWord', 'String', 'ExpandString')",
        "ConvertTo-SafeInt $rec.value $range[0] $range[1]",
        r"[\x20-\x7E]{0,260}",
    ] {
        assert_has(&reg, token);
    }
    let asr = function("Restore-AsrRule");
    for token in [
        "$Id -notmatch $script:GuidPattern",
        "$script:KnownAsr -notcontains $Id",
        "ConvertTo-SafeInt $rec.action 0 6",
        "Get-RecordBool $rec.listed",
    ] {
        assert_has(&asr, token);
    }
    assert_has(&function("Restore-DefenderValue"), "ConvertTo-SafeInt $rec.value 0 2");
    assert_has(&function("Restore-DefenderValue"), "$script:KnownMp -notcontains $Name");
    let fw = function("Restore-FirewallState");
    assert_has(&fw, "@('True', 'False', 'NotConfigured')");
    assert_has(&fw, "@('Allow', 'Block', 'NotConfigured')");
    assert_has(&function("Restore-AuditSubcategory"), "$script:KnownAudit -notcontains $Guid");
    let feature = function("Restore-FeatureState");
    assert_has(&feature, "$script:KnownFeatures -notcontains $Name");
    assert_has(&feature, "-notmatch '^[A-Za-z]{1,40}$'");
    assert_has(&function("Restore-EventLogState"), "ConvertTo-SafeInt $rec.bytes");
    // The GUID pattern of the script is the same as the one used here, and it takes the ASR rules but nothing else.
    let m = re(r"\$script:GuidPattern = '([^']+)'").captures(ps1()).expect("GuidPattern");
    assert_eq!(&m[1], "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    let guid_re = re(&m[1]);
    for rule in std::iter::once(WINDOWS_ASR_LSASS)
        .chain(WINDOWS_ASR_AUDIT_RULES.iter().copied())
        .chain(WINDOWS_ASR_AUDIT_EXTRA_RULES.iter().copied())
    {
        assert!(guid_re.is_match(rule), "{rule}");
    }
    let bad_list = [
        "".to_string(),
        "9e6c4e1f".to_string(),
        format!("{WINDOWS_ASR_LSASS}x"),
        "; calc".to_string(),
        WINDOWS_ASR_LSASS.replacen('9', "g", 1),
    ];
    for bad in &bad_list {
        assert!(!guid_re.is_match(bad), "{bad}");
    }
}

#[test]
fn safety_unrecognised_records_are_reported_and_left_alone() {
    let body = function("Test-StateEntries");
    for token in [
        "Get-KnownRegRange $Matches[1] $Matches[2]",
        "$id -match $script:GuidPattern",
        "$script:KnownAsr -contains $id",
        "$script:KnownAudit -contains",
        "$script:KnownMp -contains",
        "$script:KnownFeatures -contains",
        "Write-Result 'WARN' 'Unrecognised record",
    ] {
        assert_has(&body, token);
    }
    assert_hasnt(&body, "Remove-StateEntry"); // an unknown record is kept in the file, not silently deleted
    assert_has(&start_part(), "Test-StateEntries");
}

// ---- 3. Undo is honest

#[test]
fn safety_undo_exits_non_zero_when_anything_was_not_put_back() {
    let undo_end = WINDOWS_PS_END_UNDO;
    assert_has(undo_end, "if (($script:CountWarn + $script:CountFail) -gt 0) { exit 1 }");
    before(undo_end, "[DONE]", "{ exit 1 }");
    for end in [WINDOWS_PS_END_APPLY, WINDOWS_PS_END_AUDIT] {
        // Setup mode (Apply) and Audit keep exit code 0
        assert_hasnt(end, "exit");
    }
    assert!(ps1().trim_end().ends_with("exit 0"));
    let text = ps1_lf();
    let i = at(text, "{ exit 1 }");
    assert!(text[..i].rfind("} elseif ($Mode -eq 'Undo') {").unwrap() < i);
    assert!(i < i + text[i..].find("} else {\n").unwrap());
    // The header and the end of Undo say so.
    assert_has(text, "for Undo, when any [WARN] or [FAIL] was logged");
    assert_has(undo_end, "The exit code is 1.");
}

#[test]
fn safety_smb1_is_never_written_back_as_one() {
    let reg = function("Restore-RegValue");
    let guard = "($Name -eq 'SMB1') -and (($kind -ne 'DWord') -or ($val -ne 0))";
    assert_has(&reg, guard);
    before(&reg, guard, "New-ItemProperty");
    before(&reg, guard, "return 'not restored'");
    before(&reg, guard, "Test-Path -LiteralPath $Path");
    for line in ps1_lf().split('\n') {
        let low = line.trim().to_lowercase();
        if low.contains("smb1") && low.contains("-value 1") {
            // Only ever text of a warning that gives the manual command, never a command of its own.
            assert!(low.starts_with("write-result 'warn'"), "{line}");
        }
    }
    assert_no_re(ps1(), r"(?m)^\s*(Set|New)-ItemProperty[^\n]*SMB1");
    assert_hasnt(ps1(), "'SMB1' -Value 1");
    assert_has(&apply_of("smb1"), "-Name 'SMB1' -Value 0");
    assert_hasnt(&undo_of("smb1"), "New-ItemProperty");
    assert_has(
        &undo_of("smb1"),
        r"Restore-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1'",
    );
    // A previous value of 0, or none at all, is put back like any other.
    assert_has(&reg, "Remove-ItemProperty");
}

#[test]
fn safety_a_record_that_could_not_be_put_back_is_kept() {
    for name in [
        "Restore-RegValue",
        "Restore-AsrRule",
        "Restore-DefenderValue",
        "Restore-AuditSubcategory",
        "Restore-FirewallState",
    ] {
        let body = function(name);
        assert_has(&body, "return 'not restored'");
        assert_has(&body, "run Undo again to retry");
        let last_catch = body.rsplit("} catch {").next().unwrap();
        assert_has(last_catch, "Write-Result 'WARN'");
        assert_hasnt(last_catch, "Remove-StateEntry"); // the record stays
        assert_hasnt(last_catch, "throw"); // and the function does not throw out of Undo
    }
    let reg = function("Restore-RegValue");
    assert_has(&reg, "-ErrorAction Stop"); // a failing removal is an error, not silently ignored
    assert_hasnt(&reg, "SilentlyContinue");
    // The record is dropped only after the change was made AND read back.
    let done = rat(&reg, "Remove-StateEntry $key");
    assert!(done > at(&reg, "$result = 'removed ' + $Name"));
    assert!(done > at(&reg, "$result = 'restored ' + $Name"));
    assert!(at(&reg, "is still there after the removal") > at(&reg, "Remove-ItemProperty"));
    assert!(at(&reg, "after it was put back") > at(&reg, "New-ItemProperty"));
}

#[test]
fn safety_undo_summary_does_not_say_nothing_recorded_when_a_restore_failed() {
    let summary = function("Write-UndoSummary");
    assert_has(&summary, "-ne 'not restored'");
    assert_re(&summary, r"elseif \(\$kept\.Count -eq 0\) \{\n\s+Write-Result 'SKIP' \$What 'nothing recorded");
    let audit = undo_of("audit");
    assert_has(&audit, "$r += Restore-AuditSubcategory $guid");
    assert_eq!(count(&audit, "catch {"), 1); // no inner handler that hides the failure
    assert_has(&function("Restore-AuditSubcategory"), "could not be restored");
    // A WARN line is always counted (and therefore makes the exit code 1).
    assert_has(&function("Write-Result"), "elseif ($Status -eq 'WARN') { $script:CountWarn++ }");
}

#[test]
fn safety_firewall_restore_reads_back_and_reports_what_it_really_did() {
    let fw = function("Restore-FirewallState");
    before(&fw, "Set-NetFirewallProfile @splat", "Get-NetFirewallProfile -Profile $n -PolicyStore PersistentStore");
    before(&fw, "Get-NetFirewallProfile -Profile $n -PolicyStore PersistentStore", "Remove-StateEntry $key");
    assert_has(&fw, "throw ('read back after setting");
    assert_has(&fw, "Write-Result 'WARN' ('Firewall profile ' + $n + ' only partly put back')");
    assert_has(&fw, "NotConfigured, which cannot be set in the local store");
    for ret in ["return 'not restored'", "return 'no record'"] {
        assert_has(&fw, ret);
    }
    // A profile whose parts were all NotConfigured is not reported as restored.
    assert_has(&fw, "if ($splat.Count -gt 1) { $done += ('profile ' + $n) } else { $kept++ }");
}

#[test]
fn safety_undo_summary_lists_what_it_cannot_revert() {
    let notes = WINDOWS_PS_END_UNDO;
    for token in [
        "SMBv1",
        "PowerShell 2.0",
        "Enable-WindowsOptionalFeature",
        "never written back as 1",
        "Security event log keeps its raised size",
        "never shrinks it",
        "already in the wanted state before Apply was never recorded",
        "auditpol /restore",
        "running Undo again retries it",
    ] {
        assert_has(notes, token);
    }
    assert_eq!(count(notes, "[NOTE]"), 6);
}

// ---- 5. optional features

#[test]
fn safety_feature_state_is_read_again_and_each_feature_has_its_own_handler() {
    let get = function("Get-FeatureState");
    assert_has(&get, "[switch]$Fresh");
    assert_has(&get, "$script:Features = $null");
    assert_eq!(count(ps1(), "Get-WindowsOptionalFeature -Online"), 1);
    let code = apply_of("ps2");
    let loop_ = &code[at(&code, "foreach ($name in")..];
    before(loop_, "try {", "Get-FeatureState $name -Fresh:$fresh");
    before(loop_, "Disable-WindowsOptionalFeature", "} catch {");
    before(loop_, "Save-FeatureState $name $state", "Disable-WindowsOptionalFeature");
    assert_has(loop_, "$after = Get-FeatureState $name -Fresh");
    // An error is judged by the state it left: a feature that is already off is not a failure.
    let catch = &loop_[at(loop_, "} catch {")..];
    assert_has(catch, "$again = Get-FeatureState $name -Fresh");
    assert_has(catch, "$disabled += $name");
    assert_has(catch, "$failed += ($name + ': ' + $why)");
}

#[test]
fn safety_pending_feature_changes_need_a_restart_and_are_not_reported_as_off() {
    for sid in ["ps2", "smb1"] {
        let code = apply_of(sid);
        assert_has(&code, "@('DisablePending', 'EnablePending') -contains");
        assert_re(&code, r"Write-Result 'WARN' '[^']* needs a restart'");
        assert_has(&code, "-Fresh");
        assert_has(&audit_of(sid), "DisablePending");
    }
    let code = apply_of("ps2");
    before(&code, "needs a restart", "'already off'");
    let failed = re(r"\$failed\.Count -gt 0\) \{\n\s+Write-Result 'FAIL'").find(&code).expect("failed branch").start();
    assert!(failed < at(&code, "needs a restart"));
    let smb = apply_of("smb1");
    before(&smb, "-contains $state", "optional feature already off");
}

// ---- 6. Audit mode

#[test]
fn safety_audit_mode_says_dism_may_write_its_own_logs() {
    let text = ps1_lf();
    let head = text.split("[CmdletBinding()]").next().unwrap();
    assert_has(head, "C:\\Windows\\Logs\\DISM");
    assert_has(head, "not a configuration change");
    assert_re(
        text,
        r"if \(\$Mode -eq 'Audit'\) \{\n    Write-Info 'Audit mode: nothing is changed[^\n]*\n    Write-Info '[^\n]*DISM[^\n]*C:\\Windows\\Logs\\DISM[^\n]*not a configuration change\.'\n\} else \{",
    );
    // Still no write of any configuration in the Audit branches.
    let mutators = re(MUTATORS);
    for (sid, code) in WINDOWS_PS_AUDIT.iter() {
        assert!(!mutators.is_match(code), "{sid}");
    }
}

#[test]
fn safety_python_side_tables_are_consistent() {
    let tables = ps_known_tables();
    let got: BTreeSet<&str> = tables.iter().map(|(k, _)| *k).collect();
    assert_eq!(
        got,
        BTreeSet::from([
            "@KNOWN_REG@",
            "@KNOWN_ASR@",
            "@KNOWN_AUDIT@",
            "@KNOWN_FEATURES@",
            "@KNOWN_MP@",
            "@NETBT_REGEX@"
        ])
    );
    let names: Vec<(&str, &str)> = WINDOWS_REG_VALUES.iter().map(|(p, n, ..)| (*p, *n)).collect();
    assert_eq!(names.len(), names.iter().collect::<BTreeSet<_>>().len());
    for (_p, _n, lo, hi) in WINDOWS_REG_VALUES {
        assert!(lo <= hi);
    }
    assert_eq!(
        WINDOWS_OPTIONAL_FEATURES,
        ["SMB1Protocol", "MicrosoftWindowsPowerShellV2Root", "MicrosoftWindowsPowerShellV2"]
    );
    assert_eq!(WINDOWS_DEFENDER_PREFERENCES, ["PUAProtection", "MAPSReporting"]);
}

// ---------------------------------------------------------------------------------------------------------------
// Extra checks of this port (not in the Python tests)
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn registry_keys_of_the_generated_blocks_are_in_the_table_and_the_static_blocks_agree() {
    // The generated blocks use the KEY_* constants, the static assets spell the same keys out: both must be the
    // keys of WINDOWS_REG_VALUES (plus the per-adapter NetBIOS family, which is matched by pattern).
    let table: BTreeSet<&str> = WINDOWS_REG_VALUES.iter().map(|r| r.0).collect();
    let used: BTreeSet<String> = re(r"(?:Set-RegDword|Restore-RegValue) -Path '([^']+)'")
        .captures_iter(ps1())
        .map(|c| c[1].to_string())
        .collect();
    for key in &used {
        assert!(table.contains(key.as_str()), "{key}");
    }
    for key in &table {
        assert!(used.contains(*key), "{key}");
    }
}

#[test]
fn no_placeholder_is_left_in_the_output() {
    assert_no_re(ps1(), r"@[A-Z_]+@");
}

#[test]
fn the_assets_are_lf_only_and_ascii() {
    for (sid, code) in WINDOWS_PS_CODE.iter().chain(WINDOWS_PS_AUDIT.iter()).chain(WINDOWS_PS_UNDO.iter()) {
        assert!(code.is_ascii() && !code.contains('\r'), "{sid}");
    }
    for text in [
        WINDOWS_PS_HELPERS,
        WINDOWS_PS_PARAMS,
        WINDOWS_PS_START,
        WINDOWS_PS_AUDIT_INFO,
        WINDOWS_PS_END_APPLY,
        WINDOWS_PS_END_AUDIT,
        WINDOWS_PS_END_UNDO,
        WINDOWS_PS_HEAD,
    ] {
        assert!(text.is_ascii() && !text.contains('\r'));
    }
}

#[test]
fn indent_helper_follows_the_python() {
    assert_eq!(windows_ps_indent("\n\na\n\n  \nb\n"), "    a\n\n  \n    b");
}

#[test]
fn reg_code_optin_wraps_the_apply_block() {
    let blocks = ps_reg_code(&[("HKLM:\\X", "Y", 1)], true, false);
    assert_eq!(
        blocks.apply,
        "try {\n    if (-not $DisableLegacyNetwork) {\n        Write-Result 'SKIP' '@WHAT@' 'opt-in, not requested (run with -DisableLegacyNetwork)'\n    } else {\n        $c1 = Set-RegDword -Path 'HKLM:\\X' -Name 'Y' -Value 1\n        Write-Result 'OK' '@WHAT@' (Get-ChangeText ($c1))\n    }\n} catch {\n    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message\n}\n"
    );
    assert_has(&blocks.audit, "Write-Audit 'DIFF' '@WHAT@' ($bad -join '; ') -OptIn $true");
}
