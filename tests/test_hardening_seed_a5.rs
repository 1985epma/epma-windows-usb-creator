//! Tests for the hardening seed files (`hardening_files_seed`): what goes on the second USB.
//! Port of the seed-CONTENT parts of tests/test_hardening_seed.py (the drive validation / staging / copy tests of that
//! family belong to the `seed` module).
//!
//! The point of these tests is SAFETY. A seed must never partition, format or choose a disk, never create an account,
//! and never carry a password, hash or key. The checks look at the parsed structure of every file (there is no YAML
//! crate here, so a tiny parser for the YAML subset the code emits is included below), not just at a text search.
//!
//! The Python tests patch `linux_hardening_script` / `windows_hardening_ps1` with short fakes; here the scripts are
//! injected through `linux_seed_files_from` / `windows_seed_files_from`, and the same checks run on the real Linux
//! script (and, with the golden harden.ps1, on the Windows drive).

use epma_usb_creator::harden_linux::linux_hardening_script;
use epma_usb_creator::harden_macos::{describe_hardening_macos_applied, MACOS_HARDENING_NOT_CHANGED};
use epma_usb_creator::seed_files::*;
use epma_usb_creator::types::{Error, Files, Hardening, Mode, SeedTarget};
use regex::Regex;
use std::collections::BTreeSet;

const FAKE_SCRIPT: &str = r##"#!/usr/bin/env bash
set -eu
# fake hardening script used by the tests
case "${1:-}" in --undo) echo "undo";; --dry-run) echo "dry run";; *) echo "apply \"$HOME\" $# 'x'";; esac
cat <<'EOF'
  indented heredoc line with % and $ and `backticks`
EOF
"##;

/// Stand-in for the Windows script (the Python patches `windows_hardening_ps1`).
const FAKE_PS1: &[u8] =
    b"\xef\xbb\xbf# fake harden.ps1 used by the tests\r\nparam([string]$Mode = 'Apply')\r\nWrite-Host $Mode\r\n";

/// The real harden.ps1 as the Python wrote it, and the two lists the Windows README quotes.
const REAL_PS1: &[u8] = include_bytes!("golden/windows/harden.ps1");
const WINDOWS_DESCRIBE: &str = include_str!("golden/windows_describe.json");
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

const LINUX_TARGETS: [SeedTarget; 3] = [SeedTarget::Ubuntu, SeedTarget::Fedora, SeedTarget::Debian];
const WINDOWS_CMD_FILES: [&str; 3] = ["harden.cmd", "audit.cmd", "undo.cmd"];
const MAX_FILE: usize = 256 * 1024;
const MAX_TOTAL: usize = 2 * 1024 * 1024;

/// Keys that must never appear (as a key, a kickstart command or a preseed key) in any seed.
const FORBIDDEN_KEYS: &[&str] = &[
    "storage",
    "clearpart",
    "autopart",
    "zerombr",
    "ignoredisk",
    "part",
    "volgroup",
    "logvol",
    "partman",
    "passwd",
    "rootpw",
    "user",
    "sshkey",
    "identity",
    "ssh_authorized_keys",
    "password",
    "hash",
    // also never in a cloud-init/autoinstall seed
    "users",
    "chpasswd",
    "user-data",
    "ssh",
    "reboot",
    "poweroff",
    "halt",
    "shutdown",
    "bootloader",
];

fn expected_files(target: SeedTarget) -> BTreeSet<&'static str> {
    match target {
        SeedTarget::Ubuntu => ["user-data", "meta-data", "harden-linux.sh", "README.txt"].into(),
        SeedTarget::Fedora => ["ks.cfg", "harden-linux.sh", "README.txt"].into(),
        SeedTarget::Debian => ["preseed.cfg", "harden-linux.sh", "README.txt"].into(),
        // Windows: only the "run after install" files (no answer file, no marker, no SetupComplete.cmd)
        SeedTarget::Windows => ["harden.cmd", "audit.cmd", "undo.cmd", "harden.ps1", "README.txt"].into(),
        // macOS: the same idea with double-click launchers; the script is run after macOS is installed
        SeedTarget::MacOs => {
            ["harden.command", "audit.command", "undo.command", "harden-macos.sh", "README.txt"].into()
        }
    }
}

fn script_file(target: SeedTarget) -> &'static str {
    match target {
        SeedTarget::Windows => "harden.ps1",
        SeedTarget::MacOs => "harden-macos.sh",
        _ => "harden-linux.sh",
    }
}

fn config_file(target: SeedTarget) -> &'static str {
    match target {
        SeedTarget::Ubuntu => "user-data",
        SeedTarget::Fedora => "ks.cfg",
        SeedTarget::Debian => "preseed.cfg",
        SeedTarget::Windows => "harden.cmd",
        SeedTarget::MacOs => "harden.command",
    }
}

fn allowed_label(target: SeedTarget) -> &'static str {
    match target {
        SeedTarget::Ubuntu => "CIDATA",
        SeedTarget::Fedora => "OEMDRV",
        SeedTarget::Debian | SeedTarget::Windows | SeedTarget::MacOs => "EPMA-SEED",
    }
}

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap()
}

fn hash_like() -> Regex {
    re(r"\$(?:1|2[abxy]?|5|6|7|y|gy|sha1|md5)\$")
}

fn claims() -> Regex {
    re(r"\b(CIS|STIG|NIST)\b")
}

fn dangerous_words() -> Regex {
    re(
        r"\b(mkfs\w*|wipefs|parted|fdisk|sfdisk|sgdisk|clearpart|autopart|zerombr|ignoredisk|volgroup|logvol|partman\S*|rootpw|sshkey|poweroff|halt|shutdown|reboot|chpasswd|passwd|useradd|usermod|losetup)\b",
    )
}

fn applied_lines() -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(WINDOWS_DESCRIBE).unwrap();
    v["applied"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect()
}

fn describe_lines() -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(WINDOWS_DESCRIBE).unwrap();
    v["describe"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect()
}

/// The seed of `target` for a given Linux script (and the fake Windows script).
fn seed_with(target: SeedTarget, script: &str) -> (String, Files) {
    match target {
        SeedTarget::Windows => windows_seed_files_from(FAKE_PS1.to_vec(), &applied_lines(), NOT_CHANGED).unwrap(),
        SeedTarget::MacOs => macos_seed_files_from(
            script,
            &describe_hardening_macos_applied(Hardening::Baseline),
            MACOS_HARDENING_NOT_CHANGED,
        )
        .unwrap(),
        _ => linux_seed_files_from(target, script).unwrap(),
    }
}

fn seed(target: SeedTarget) -> (String, Files) {
    seed_with(target, FAKE_SCRIPT)
}

/// A file of the seed as text; Windows files use CRLF, shown here with plain newlines.
fn text_of(target: SeedTarget, name: &str) -> String {
    let (_label, files) = seed(target);
    String::from_utf8(files[name].clone()).expect("ascii").replace("\r\n", "\n")
}

fn config_text(target: SeedTarget) -> String {
    text_of(target, config_file(target))
}

fn flat(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn base64_decode(text: &str) -> Vec<u8> {
    // like base64.b64decode(validate=True)
    assert_eq!(text.len() % 4, 0, "bad base64 length");
    let mut out = Vec::new();
    let val = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("not base64: {}", c as char),
        }
    };
    for chunk in text.as_bytes().chunks(4) {
        let pad = chunk.iter().filter(|&&c| c == b'=').count();
        let n = chunk.iter().take(4 - pad).fold(0u32, |acc, &c| (acc << 6) | val(c)) << (6 * pad as u32);
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    out
}

/// The config text without comment lines and without base64 payload lines.
fn executable_text(text: &str) -> String {
    let payload = re(r"^[A-Za-z0-9+/=]{20,}$");
    let mut keep = Vec::new();
    for line in text.split('\n') {
        let stripped = line.trim();
        if stripped.starts_with('#') && !stripped.starts_with("#cloud-config") {
            continue;
        }
        if payload.is_match(stripped) {
            continue;
        }
        keep.push(line);
    }
    keep.join("\n")
}

/// The base64 text between `<<'EPMA_B64'` and the EPMA_B64 line (lines may be indented).
fn heredoc_payload(text: &str) -> Vec<String> {
    let m = re(r"(?s)<<'EPMA_B64'\n(.*?)\n\s*EPMA_B64\n").captures(text).expect("no EPMA_B64 heredoc");
    m[1].split('\n').map(|l| l.trim().to_string()).collect()
}

fn decode_b64(lines: &[String]) -> Vec<u8> {
    base64_decode(&lines.concat())
}

/// Preseed lines with backslash continuations joined; comments and blanks dropped.
fn preseed_logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for line in text.split('\n') {
        if current.is_empty() && (line.trim().is_empty() || line.trim_start().starts_with('#')) {
            continue;
        }
        if let Some(stripped) = line.strip_suffix('\\') {
            current.push_str(stripped);
            current.push(' ');
            continue;
        }
        out.push(format!("{current}{line}").trim().to_string());
        current.clear();
    }
    assert!(current.is_empty(), "preseed ends inside a continuation");
    out
}

fn late_command(text: &str) -> String {
    preseed_logical_lines(text).into_iter().find(|l| l.starts_with("d-i preseed/late_command")).expect("late_command")
}

type KsSections = (Vec<String>, Vec<(String, Vec<String>)>);

/// (commands outside any section, {section header: [body lines]}) of a kickstart file.
fn kickstart_sections(text: &str) -> KsSections {
    let mut commands = Vec::new();
    let mut sections: Vec<(String, Vec<String>)> = Vec::new();
    let mut current: Option<usize> = None;
    for line in text.split('\n') {
        let stripped = line.trim();
        match current {
            None => {
                if stripped.is_empty() || stripped.starts_with('#') {
                    continue;
                }
                if stripped.starts_with('%') {
                    assert!(stripped != "%end", "stray %end");
                    assert!(!sections.iter().any(|(n, _)| n == stripped), "section {stripped} twice");
                    sections.push((stripped.to_string(), Vec::new()));
                    current = Some(sections.len() - 1);
                } else {
                    commands.push(stripped.to_string());
                }
            }
            Some(i) => {
                if stripped == "%end" {
                    current = None;
                } else {
                    sections[i].1.push(line.to_string());
                }
            }
        }
    }
    assert!(current.is_none(), "section without %end");
    (commands, sections)
}

fn section<'a>(sections: &'a [(String, Vec<String>)], name: &str) -> &'a Vec<String> {
    &sections.iter().find(|(n, _)| n == name).unwrap_or_else(|| panic!("no section {name}")).1
}

// ---------------------------------------------------------------------------------------------------------------
// tiny YAML subset parser
// ---------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Y {
    S(String),
    L(Vec<Y>),
    M(Vec<(String, Y)>),
}

impl Y {
    fn get(&self, key: &str) -> Option<&Y> {
        match self {
            Y::M(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    fn keys(&self) -> Vec<&str> {
        match self {
            Y::M(m) => m.iter().map(|(k, _)| k.as_str()).collect(),
            _ => Vec::new(),
        }
    }
    fn list(&self) -> &Vec<Y> {
        match self {
            Y::L(l) => l,
            other => panic!("not a list: {other:?}"),
        }
    }
    fn s(&self) -> &str {
        match self {
            Y::S(s) => s,
            other => panic!("not a scalar: {other:?}"),
        }
    }
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

fn skip_blank(lines: &[&str], mut i: usize) -> usize {
    while i < lines.len() && (lines[i].trim().is_empty() || lines[i].trim_start().starts_with('#')) {
        i += 1;
    }
    i
}

fn scalar(text: &str) -> Y {
    let text = text.trim();
    if text.starts_with('[') && text.ends_with(']') {
        let inner = text[1..text.len() - 1].trim();
        return Y::L(if inner.is_empty() { Vec::new() } else { inner.split(',').map(scalar).collect() });
    }
    let b = text.as_bytes();
    if b.len() >= 2 && b[0] == b[b.len() - 1] && (b[0] == b'"' || b[0] == b'\'') {
        return Y::S(text[1..text.len() - 1].to_string());
    }
    Y::S(text.to_string())
}

/// Parse the mapping or sequence whose first line is at `indent`. Returns (value, next_index).
fn parse_block(lines: &[&str], i: usize, indent: usize) -> (Y, usize) {
    let mut i = skip_blank(lines, i);
    assert!(i < lines.len(), "unexpected end of document");
    assert_eq!(indent_of(lines[i]), indent, "line {}: expected indent {indent}: {:?}", i + 1, lines[i]);
    if lines[i].trim_start().starts_with("- ") {
        let mut seq = Vec::new();
        loop {
            i = skip_blank(lines, i);
            if i >= lines.len() || indent_of(lines[i]) < indent {
                return (Y::L(seq), i);
            }
            assert_eq!(indent_of(lines[i]), indent, "line {}: bad indent", i + 1);
            let item = &lines[i][indent..];
            assert!(item.starts_with("- "), "line {}: sequence expected: {:?}", i + 1, lines[i]);
            let item = &item[2..];
            i += 1;
            if item == "|" {
                let mut body: Vec<String> = Vec::new();
                let mut base: Option<usize> = None;
                while i < lines.len() {
                    let raw = lines[i];
                    if raw.trim().is_empty() {
                        body.push(String::new());
                        i += 1;
                        continue;
                    }
                    if indent_of(raw) <= indent {
                        break;
                    }
                    let b = *base.get_or_insert_with(|| indent_of(raw));
                    assert_eq!(b, indent + 2, "line {}: block scalar not indented by 2", i + 1);
                    assert!(indent_of(raw) >= b, "line {}: block scalar under-indented", i + 1);
                    body.push(raw[b..].to_string());
                    i += 1;
                }
                seq.push(Y::S(format!("{}\n", body.join("\n").trim_end_matches('\n'))));
            } else {
                seq.push(scalar(item));
            }
        }
    }
    let key_line = re(r"^([A-Za-z0-9_-]+):(?: (.+))?$");
    let mut mapping: Vec<(String, Y)> = Vec::new();
    loop {
        i = skip_blank(lines, i);
        if i >= lines.len() || indent_of(lines[i]) < indent {
            return (Y::M(mapping), i);
        }
        assert_eq!(indent_of(lines[i]), indent, "line {}: bad indent", i + 1);
        let m = key_line
            .captures(&lines[i][indent..])
            .unwrap_or_else(|| panic!("line {}: not a 'key: value' line: {:?}", i + 1, lines[i]));
        let key = m[1].to_string();
        assert!(!mapping.iter().any(|(k, _)| *k == key), "duplicate key {key}");
        i += 1;
        match m.get(2) {
            None => {
                let (v, next) = parse_block(lines, i, indent + 2);
                mapping.push((key, v));
                i = next;
            }
            Some(value) => mapping.push((key, scalar(value.as_str()))),
        }
    }
}

/// Parse the YAML subset the seed uses (maps, lists, `- |` block scalars, one-line [a, b] lists).
fn parse_mini_yaml(text: &str) -> Y {
    assert!(!text.contains('\t'), "tab in YAML");
    assert!(!text.contains('\r'), "carriage return in YAML");
    let lines: Vec<&str> = text.split('\n').collect();
    for (n, line) in lines.iter().enumerate() {
        assert_eq!(*line, line.trim_end(), "line {}: trailing whitespace", n + 1);
    }
    let (value, i) = parse_block(&lines, 0, 0);
    assert!(skip_blank(&lines, i) >= lines.len(), "line {}: could not parse the rest", i + 1);
    value
}

/// Every mapping key anywhere in a parsed tree.
fn walk_keys(node: &Y, out: &mut Vec<String>) {
    match node {
        Y::M(m) => {
            for (k, v) in m {
                out.push(k.clone());
                walk_keys(v, out);
            }
        }
        Y::L(l) => l.iter().for_each(|v| walk_keys(v, out)),
        Y::S(_) => {}
    }
}

// =============================================================================================================
// ContractTests / ArgumentTests
// =============================================================================================================

#[test]
fn contract_constants() {
    assert_eq!(Mode::Seed.as_str(), "seed");
    assert_eq!(Hardening::None.as_str(), "none");
    assert_eq!(Hardening::Baseline.as_str(), "baseline");
    assert_eq!(Hardening::ALL, [Hardening::None, Hardening::Baseline]);
    let names: Vec<&str> = SeedTarget::ALL.iter().map(|t| t.as_str()).collect();
    assert_eq!(names, ["ubuntu", "fedora", "debian", "windows", "macos"]);
}

#[test]
fn argument_none_profile_is_refused() {
    for target in SeedTarget::ALL {
        let err = hardening_files_seed(target, Hardening::None).unwrap_err();
        assert!(matches!(err, Error::Value(_)), "{target}");
    }
}

#[test]
fn argument_empty_script_is_refused() {
    for bad in ["", "  \n"] {
        for target in LINUX_TARGETS {
            assert!(matches!(linux_seed_files_from(target, bad), Err(Error::Value(_))), "{target} {bad:?}");
        }
    }
}

#[test]
fn argument_script_comes_from_the_caller_at_call_time() {
    let (_label, files) = seed(SeedTarget::Ubuntu);
    assert_eq!(files["harden-linux.sh"], FAKE_SCRIPT.as_bytes());
    let second = "#!/bin/sh\necho second\n";
    let (_label, files) = seed_with(SeedTarget::Fedora, second);
    assert_eq!(files["harden-linux.sh"], second.as_bytes());
    let encoded = base64_encode(second.as_bytes());
    assert!(String::from_utf8(files["ks.cfg"].clone()).unwrap().contains(&encoded));
}

// =============================================================================================================
// CommonSafetyTests
// =============================================================================================================

#[test]
fn common_labels_are_valid_fat32_labels() {
    let label_re = re(r"^[A-Z0-9_-]{1,11}$");
    for target in SeedTarget::ALL {
        let (label, _files) = seed(target);
        assert_eq!(label, allowed_label(target));
        assert!(label.len() <= 11);
        assert_eq!(label, label.to_uppercase());
        assert!(label_re.is_match(&label));
        assert!(["CIDATA", "OEMDRV", "EPMA-SEED"].contains(&label.as_str()));
        assert_eq!(seed_label(target), label);
    }
}

#[test]
fn common_file_set_and_types() {
    for target in SeedTarget::ALL {
        let (_label, files) = seed(target);
        let names: BTreeSet<&str> = files.keys().map(String::as_str).collect();
        assert_eq!(names, expected_files(target), "{target}");
        for (name, data) in &files {
            assert!(!data.is_empty(), "{name} is empty");
        }
    }
}

#[test]
fn common_paths_are_plain_relative_names() {
    let plain = re(r"^[A-Za-z0-9][A-Za-z0-9._-]*$");
    for target in SeedTarget::ALL {
        let (_label, files) = seed(target);
        for name in files.keys() {
            assert!(!name.contains('\\') && !name.contains('\0'), "{target} {name}");
            assert!(!name.starts_with('/'));
            assert!(!name.split('/').any(|p| p == ".."));
            assert!(name.len() <= 240);
            assert!(plain.is_match(name), "{target} {name}");
        }
    }
}

#[test]
fn common_script_file_is_exactly_the_script() {
    for target in LINUX_TARGETS {
        let (_label, files) = seed(target);
        assert_eq!(files["harden-linux.sh"], FAKE_SCRIPT.as_bytes());
    }
    let (_label, files) = seed(SeedTarget::Windows); // Windows: harden.ps1 is the Windows script
    assert_eq!(files["harden.ps1"], FAKE_PS1);
    assert!(!files.contains_key("harden-linux.sh"));
}

#[test]
fn common_deterministic() {
    for target in SeedTarget::ALL {
        assert_eq!(seed(target), seed(target), "{target}");
    }
}

#[test]
fn common_sizes_within_limits_even_for_a_big_script() {
    let mut big = String::from("#!/usr/bin/env bash\nset -eu\n");
    for n in 0..1500 {
        big.push_str(&format!("echo 'line {n} of a long hardening script ........................'\n"));
    }
    assert!(big.len() > 80_000);
    for (script, is_big) in [(FAKE_SCRIPT, false), (big.as_str(), true)] {
        for target in SeedTarget::ALL {
            if target == SeedTarget::Debian && is_big {
                // too big for one late_command argument
                assert!(matches!(linux_seed_files_from(target, script), Err(Error::Value(_))));
                continue;
            }
            let (_label, files) = seed_with(target, script);
            assert!(files.values().all(|d| d.len() <= MAX_FILE), "{target}");
            assert!(files.values().map(Vec::len).sum::<usize>() <= MAX_TOTAL);
            assert!(files.len() <= 8);
        }
    }
}

#[test]
fn common_config_files_are_clean_ascii() {
    for target in LINUX_TARGETS {
        let (_label, files) = seed(target);
        for (name, data) in &files {
            if name == "harden-linux.sh" {
                continue;
            }
            let text = String::from_utf8(data.clone()).unwrap();
            assert!(text.is_ascii(), "{target}/{name}");
            assert!(!text.contains('\t') && !text.contains('\r'));
            assert!(text.ends_with('\n') && !text.ends_with("\n\n"), "{target}/{name}");
            for (n, line) in text.split('\n').enumerate() {
                assert_eq!(line, line.trim_end(), "{name}:{} trailing whitespace", n + 1);
            }
        }
    }
}

#[test]
fn common_no_password_hashes_keys_or_claims() {
    let secrets = re(r"(?i)\b(token|secret|api[_-]?key)\b");
    for target in SeedTarget::ALL {
        let (_label, files) = seed(target);
        for (name, data) in &files {
            if name == script_file(target) {
                continue;
            }
            let text = String::from_utf8(data.clone()).unwrap();
            assert!(!hash_like().is_match(&text), "{target}/{name}: looks like a password hash");
            for needle in ["ssh-rsa", "ssh-ed25519", "ecdsa-sha2", "BEGIN OPENSSH", "BEGIN PRIVATE"] {
                assert!(!text.contains(needle), "{target}/{name}: {needle}");
            }
            assert!(!claims().is_match(&text), "{target}/{name}: compliance claim");
            assert!(!secrets.is_match(&text), "{target}/{name}");
        }
    }
}

#[test]
fn common_no_disk_or_account_commands_in_executable_text() {
    for target in SeedTarget::ALL {
        let body = executable_text(&config_text(target));
        let found: Vec<String> = dangerous_words().captures_iter(&body).map(|c| c[1].to_string()).collect();
        assert!(found.is_empty(), "dangerous words in {target}: {found:?}");
    }
}

#[test]
fn common_seed_text_never_embeds_the_forbidden_words_as_settings() {
    // A line-oriented search on top of the parsers below: no `key:` / `key ` at the start of a line.
    let sep = re(r"[\s:=]");
    for target in SeedTarget::ALL {
        for line in executable_text(&config_text(target)).split('\n') {
            if line.trim().starts_with("- ") {
                continue; // list items: interactive-sections legitimately names storage and identity
            }
            let first = sep.splitn(line.trim(), 2).next().unwrap().to_lowercase();
            assert!(!FORBIDDEN_KEYS.contains(&first.as_str()), "{target}: {line}");
        }
    }
}

#[test]
fn common_nothing_in_readme_claims_compliance() {
    for target in SeedTarget::ALL {
        let readme = text_of(target, "README.txt");
        assert!(!claims().is_match(&readme));
        assert!(readme.contains("not a compliance claim"), "{target}");
        assert!(readme.replace('\n', " ").contains("inspired by common security baselines"), "{target}");
    }
}

// =============================================================================================================
// ReadmeTests
// =============================================================================================================

#[test]
fn readme_ascii_and_width() {
    for target in SeedTarget::ALL {
        let (_label, files) = seed(target);
        let mut text = String::from_utf8(files["README.txt"].clone()).unwrap();
        assert!(text.is_ascii());
        if target == SeedTarget::Windows {
            // Notepad shows a file properly only with CRLF line ends
            assert_eq!(text.matches('\n').count(), text.matches("\r\n").count(), "bare LF in the Windows README");
            assert_eq!(text.matches('\r').count(), text.matches("\r\n").count(), "bare CR in the Windows README");
            text = text.replace("\r\n", "\n");
        }
        for (n, line) in text.split('\n').enumerate() {
            assert!(line.len() <= 80, "{target} README line {}: {line:?}", n + 1);
            assert_eq!(line, line.trim_end(), "{target} README line {} has trailing spaces", n + 1);
        }
        assert!(!text.contains('\t') && !text.contains('\r'));
        assert!(text.ends_with('\n'));
    }
}

#[test]
fn readme_common_content() {
    for target in LINUX_TARGETS {
        let text = flat(&text_of(target, "README.txt"));
        for needle in
            ["SECOND USB", "Nothing here selects a disk", "creates an account", "--undo", "--dry-run", ".epma-bak"]
        {
            assert!(text.contains(needle), "{target}: {needle}");
        }
    }
}

#[test]
fn readme_ubuntu_explains_the_autoinstall_parameter() {
    let text = flat(&text_of(SeedTarget::Ubuntu, "README.txt"));
    for needle in ["CIDATA", "press e", "add the word autoinstall before the ---", "F10", "asks you to confirm"] {
        assert!(text.contains(needle), "{needle}");
    }
}

#[test]
fn readme_fedora_mentions_automatic_detection() {
    let text = flat(&text_of(SeedTarget::Fedora, "README.txt"));
    assert!(text.contains("OEMDRV"));
    assert!(text.contains("detects by itself"));
    for family in ["Fedora", "RHEL", "Rocky", "Alma"] {
        assert!(text.contains(family), "{family}");
    }
}

#[test]
fn readme_no_firewall_claim_on_fedora_and_no_login_promise() {
    for target in LINUX_TARGETS {
        let text = flat(&text_of(target, "README.txt"));
        assert!(!text.contains("keep your own login working"));
        assert!(!text.replace("cannot promise your login keeps working", "").contains("keeps working"));
        for needle in [
            "tries not to lock you out",
            "cannot promise your login keeps working",
            "sudo (Debian/Ubuntu) or wheel (Fedora/RHEL)",
            "authorized_keys",
            "[WARN]",
            "50-cloud-init.conf",
        ] {
            assert!(text.contains(needle), "{target}: {needle}");
        }
    }
    let fedora = flat(&text_of(SeedTarget::Fedora, "README.txt"));
    assert!(!fedora.contains("blocks unsolicited incoming"));
    assert!(!fedora.contains("blocks incoming connections"));
    assert!(fedora.contains("default zone is left exactly as Fedora/RHEL set it"));
    for target in [SeedTarget::Ubuntu, SeedTarget::Debian] {
        let text = flat(&text_of(target, "README.txt"));
        assert!(text.contains("ufw firewall blocks incoming connections by default"));
        assert!(text.contains("Docker, libvirt or LXD"));
    }
}

#[test]
fn readme_ubuntu_says_every_screen_is_interactive_and_packages_come_later() {
    let text = flat(&text_of(SeedTarget::Ubuntu, "README.txt"));
    assert!(text.contains("Every installer screen stays interactive"));
    assert!(text.contains("installed by the hardening script on the first boot"));
    assert!(!text.contains("are fetched then"));
}

#[test]
fn readme_debian_mentions_su_without_sudo() {
    let text = flat(&text_of(SeedTarget::Debian, "README.txt"));
    for needle in ["If sudo is not installed", "su -", "bash /path/to/harden-linux.sh", "sudo bash harden-linux.sh"] {
        assert!(text.contains(needle), "{needle}");
    }
    let other = flat(&text_of(SeedTarget::Fedora, "README.txt"));
    assert!(!other.contains("If sudo is not installed"));
}

#[test]
fn readme_debian_is_honest_about_detection() {
    let text = flat(&text_of(SeedTarget::Debian, "README.txt"));
    for needle in [
        "does NOT detect this drive by itself",
        "(a) Recommended",
        "sudo bash harden-linux.sh",
        "(b) Advanced",
        "auto=true priority=critical file=...",
        "official Debian installation guide",
    ] {
        assert!(text.contains(needle), "{needle}");
    }
}

// =============================================================================================================
// UbuntuSeedTests
// =============================================================================================================

fn ubuntu_parsed() -> Y {
    let text = text_of(SeedTarget::Ubuntu, "user-data");
    assert!(text.starts_with("#cloud-config\n"));
    parse_mini_yaml(&text)
}

fn late_commands() -> Vec<String> {
    ubuntu_parsed()
        .get("autoinstall")
        .unwrap()
        .get("late-commands")
        .unwrap()
        .list()
        .iter()
        .map(|y| y.s().to_string())
        .collect()
}

#[test]
fn ubuntu_structure() {
    let tree = ubuntu_parsed();
    assert_eq!(tree.keys(), ["autoinstall"]);
    let auto = tree.get("autoinstall").unwrap();
    let keys: BTreeSet<&str> = auto.keys().into_iter().collect();
    assert_eq!(keys, BTreeSet::from(["version", "interactive-sections", "late-commands"]));
    assert_eq!(auto.get("version").unwrap().s(), "1");
}

#[test]
fn ubuntu_every_screen_stays_interactive() {
    // "*" makes EVERY section interactive, storage and identity included: by construction the seed cannot pick a disk
    // or create an account, and a section nobody thought of cannot be skipped.
    let tree = ubuntu_parsed();
    let auto = tree.get("autoinstall").unwrap();
    assert_eq!(auto.get("interactive-sections").unwrap(), &Y::L(vec![Y::S("*".into())]));
    assert_eq!(SEED_UBUNTU_INTERACTIVE, ["*"]);
    assert!(auto.get("storage").is_none());
    assert!(auto.get("identity").is_none());
    assert!(text_of(SeedTarget::Ubuntu, "user-data").contains("    - \"*\"\n"));
}

#[test]
fn ubuntu_no_forbidden_keys_anywhere() {
    let mut keys = Vec::new();
    walk_keys(&ubuntu_parsed(), &mut keys);
    let bad: Vec<&String> = keys.iter().filter(|k| FORBIDDEN_KEYS.contains(&k.to_lowercase().as_str())).collect();
    assert!(bad.is_empty(), "{keys:?}");
}

#[test]
fn ubuntu_identity_and_storage_are_not_configured() {
    let tree = ubuntu_parsed();
    let auto = tree.get("autoinstall").unwrap();
    for key in ["storage", "identity", "user-data", "ssh"] {
        assert!(auto.get(key).is_none(), "{key}");
    }
    // only the names inside interactive-sections, never "storage:" / "identity:" lines
    let forbidden = re(r"^\s*(storage|identity|users?|ssh|chpasswd|password)\s*:");
    for line in text_of(SeedTarget::Ubuntu, "user-data").split('\n') {
        assert!(!forbidden.is_match(line), "{line}");
    }
}

#[test]
fn ubuntu_no_packages_key() {
    // A failing `packages:` entry is fatal in Subiquity; the script / first-boot unit installs what is missing.
    let tree = ubuntu_parsed();
    assert!(tree.get("autoinstall").unwrap().get("packages").is_none());
    let text = text_of(SeedTarget::Ubuntu, "user-data");
    assert!(!text.replace("no packages", "").contains("packages"));
    for name in SEED_PACKAGES_DEB {
        assert!(!text.contains(&format!("    - {name}")), "{name}");
    }
}

#[test]
fn ubuntu_late_commands_write_and_run_the_script() {
    let commands = late_commands();
    assert_eq!(commands.len(), 2);
    let (write, run) = (&commands[0], &commands[1]);
    assert!(write.contains("/target/root/harden-linux.sh"));
    assert!(write.contains("base64 -d"));
    assert!(write.contains("chmod 700 /target/root/harden-linux.sh"));
    assert!(run.contains("curtin in-target --target=/target -- /bin/bash /root/harden-linux.sh --yes --chroot"));
}

#[test]
fn ubuntu_embedded_base64_is_exactly_the_script() {
    let payload = heredoc_payload(&late_commands()[0]);
    assert!(payload.iter().all(|l| !l.is_empty() && l.len() <= 76));
    assert_eq!(decode_b64(&payload), FAKE_SCRIPT.as_bytes());
}

#[test]
fn ubuntu_script_output_is_not_appended_to_its_own_log() {
    let commands = late_commands();
    let run = &commands[1];
    let invocation = run.split('\n').find(|l| l.contains("harden-linux.sh --yes --chroot")).unwrap();
    assert!(!invocation.contains(">>"));
    assert!(!invocation.contains("2>&1"));
    // the script itself writes /var/log/epma-hardening.log; the seed only adds one status line
    assert_eq!(run.matches("epma-hardening.log").count(), 2); // "finished" and "failed" lines
}

#[test]
fn ubuntu_a_failing_script_never_fails_the_install() {
    let commands = late_commands();
    for command in [&commands[0], &commands[1]] {
        // the block ends in `true`, so the exit status of the whole command is always 0
        assert_eq!(command.trim_end_matches('\n').split('\n').next_back().unwrap().trim(), "true");
    }
    let run = &commands[1];
    assert!(run.contains("else"));
    assert!(run.contains("failed"));
    assert!(run.contains("/target/var/log/epma-hardening.log"));
    assert!(!run.contains("set -e"));
}

#[test]
fn ubuntu_meta_data() {
    let text = text_of(SeedTarget::Ubuntu, "meta-data");
    let tree = parse_mini_yaml(&text);
    let keys: BTreeSet<&str> = tree.keys().into_iter().collect();
    assert_eq!(keys, BTreeSet::from(["instance-id", "local-hostname"]));
    assert!(!tree.get("instance-id").unwrap().s().is_empty());
    assert!(re(r"^[a-z0-9-]+$").is_match(tree.get("local-hostname").unwrap().s()));
}

#[test]
fn ubuntu_yaml_indentation_is_two_spaces() {
    let mut previous: i64 = 0;
    let mut in_block = false;
    let mut block_base = 0usize;
    for (n, line) in text_of(SeedTarget::Ubuntu, "user-data").split('\n').enumerate() {
        let n = n + 1;
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let ind = indent_of(line);
        if in_block && ind >= block_base {
            continue; // shell text inside a `- |` block scalar
        }
        in_block = false;
        assert_eq!(ind % 2, 0, "line {n}: odd indentation");
        assert!(ind as i64 - previous <= 2, "line {n}: indentation jumps by more than 2");
        previous = ind as i64;
        if line.trim() == "- |" {
            in_block = true;
            block_base = ind + 2;
            previous = ind as i64 + 2;
        }
    }
}

// =============================================================================================================
// FedoraSeedTests
// =============================================================================================================

fn fedora_sections() -> KsSections {
    kickstart_sections(&text_of(SeedTarget::Fedora, "ks.cfg"))
}

#[test]
fn fedora_no_commands_outside_sections() {
    // No storage, account, bootloader or power command: nothing at all outside %packages/%post.
    let (commands, _sections) = fedora_sections();
    assert!(commands.is_empty(), "{commands:?}");
}

#[test]
fn fedora_only_packages_and_post_sections() {
    let (_commands, sections) = fedora_sections();
    let names: BTreeSet<&str> = sections.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, BTreeSet::from(["%packages --ignoremissing", "%post"]));
    let packages: Vec<&str> =
        section(&sections, "%packages --ignoremissing").iter().map(|p| p.trim()).filter(|p| !p.is_empty()).collect();
    assert_eq!(packages, SEED_PACKAGES_RPM);
    assert!(SEED_PACKAGES_RPM.iter().all(|p| ["firewalld", "audit", "dnf-automatic"].contains(p)));
}

#[test]
fn fedora_post_runs_in_the_installed_system() {
    let text = text_of(SeedTarget::Fedora, "ks.cfg");
    assert!(!text.contains("--nochroot"));
    assert!(!text.contains("--erroronfail"));
    assert!(text.contains("/bin/bash /root/harden-linux.sh --yes --chroot"));
}

#[test]
fn fedora_embedded_base64_is_exactly_the_script() {
    assert_eq!(decode_b64(&heredoc_payload(&text_of(SeedTarget::Fedora, "ks.cfg"))), FAKE_SCRIPT.as_bytes());
}

#[test]
fn fedora_script_output_is_not_appended_to_its_own_log() {
    let (_commands, sections) = fedora_sections();
    let invocation = section(&sections, "%post").iter().find(|l| l.contains("harden-linux.sh --yes --chroot")).unwrap();
    assert!(!invocation.contains(">>"));
    assert!(!invocation.contains("2>&1"));
}

#[test]
fn fedora_post_never_fails_the_install() {
    let (_commands, sections) = fedora_sections();
    let body: Vec<&String> = section(&sections, "%post").iter().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(body.last().unwrap().trim(), "exit 0");
    assert!(body.iter().any(|l| l.trim() == "else"));
    let joined = body.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n");
    assert!(!joined.contains("set -e"));
}

#[test]
fn fedora_no_forbidden_kickstart_command_anywhere() {
    for line in executable_text(&text_of(SeedTarget::Fedora, "ks.cfg")).split('\n') {
        if let Some(first) = line.split_whitespace().next() {
            assert!(!FORBIDDEN_KEYS.contains(&first.trim_start_matches('%')), "{line}");
        }
    }
}

// =============================================================================================================
// DebianSeedTests
// =============================================================================================================

fn debian_text() -> String {
    text_of(SeedTarget::Debian, "preseed.cfg")
}

fn b64_chunks(text: &str) -> Vec<String> {
    re(r"echo ([A-Za-z0-9+/=]+) >> /target/root/harden-linux\.b64")
        .captures_iter(text)
        .map(|c| c[1].to_string())
        .collect()
}

#[test]
fn debian_only_whitelisted_non_disk_keys() {
    let mut keys = Vec::new();
    for line in preseed_logical_lines(&debian_text()) {
        let mut parts = line.split_whitespace();
        let (a, b, c) = (parts.next().unwrap(), parts.next().unwrap(), parts.next().unwrap());
        assert_eq!(a, "d-i", "{line}");
        assert!(["string", "select", "boolean"].contains(&c), "{line}");
        keys.push(b.to_string());
    }
    keys.sort();
    assert_eq!(keys, ["pkgsel/include", "pkgsel/update-policy", "preseed/late_command"]);
}

#[test]
fn debian_no_partman_passwd_or_bootdev() {
    let text = executable_text(&debian_text());
    for needle in ["partman", "passwd/", "grub-installer", "bootdev", "user-fullname", "root-password"] {
        assert!(!text.contains(needle), "{needle}");
    }
}

#[test]
fn debian_embedded_base64_is_exactly_the_script() {
    let chunks = b64_chunks(&debian_text());
    assert!(!chunks.is_empty());
    assert!(chunks.iter().all(|c| c.len() <= SEED_DEBIAN_B64_WIDTH));
    assert_eq!(decode_b64(&chunks), FAKE_SCRIPT.as_bytes());
}

#[test]
fn debian_late_command_uses_long_base64_lines() {
    let script = format!("#!/bin/sh\n{}", "# padding padding padding padding padding\n".repeat(600));
    let (_label, files) = linux_seed_files_from(SeedTarget::Debian, &script).unwrap();
    let text = String::from_utf8(files["preseed.cfg"].clone()).unwrap();
    let chunks = b64_chunks(&text);
    const { assert!(SEED_DEBIAN_B64_WIDTH >= 4096, "several KB per line") };
    assert!(chunks[..chunks.len() - 1].iter().all(|c| c.len() == SEED_DEBIAN_B64_WIDTH));
    assert!(chunks.len() < 10); // a 25 KB script: a handful of echo lines, not 450
    assert_eq!(decode_b64(&chunks), script.as_bytes());
}

#[test]
fn debian_script_output_is_not_appended_to_its_own_log() {
    let late = late_command(&debian_text());
    let invocation = &late[late.find("in-target /bin/sh -c").unwrap()..];
    assert!(invocation.contains("/bin/bash /root/harden-linux.sh --yes --chroot &&"));
    assert!(!invocation.contains("--chroot >>"));
    assert!(!invocation.contains("2>&1"));
}

fn numbered_script(lines: usize) -> String {
    let mut s = String::from("#!/bin/sh\n");
    for n in 0..lines {
        s.push_str(&format!("# line {n:05} ............................................\n"));
    }
    s
}

#[test]
fn debian_late_command_too_big_is_refused() {
    // ~80 KB of script becomes ~107 KB of base64: above the 100,000 byte limit that keeps the command far from
    // MAX_ARG_STRLEN (131,072).
    let script = numbered_script(1500);
    assert!(script.len() * 4 / 3 > SEED_DEBIAN_LATE_MAX);
    let err = linux_seed_files_from(SeedTarget::Debian, &script).unwrap_err();
    assert!(matches!(err, Error::Value(_)));
    assert!(err.to_string().contains("late_command"), "{err}");
    // the other seeds carry the same script without a limit of this kind
    linux_seed_files_from(SeedTarget::Ubuntu, &script).unwrap();
    linux_seed_files_from(SeedTarget::Fedora, &script).unwrap();
}

#[test]
fn debian_late_command_just_under_the_limit_is_accepted() {
    // a script whose late_command is close to, but below, the limit
    let per_line = "# line 00000 ............................................\n".len();
    let script = numbered_script((SEED_DEBIAN_LATE_MAX as f64 * 0.70 / per_line as f64) as usize);
    let (_label, files) = linux_seed_files_from(SeedTarget::Debian, &script).unwrap();
    let late = late_command(&String::from_utf8(files["preseed.cfg"].clone()).unwrap());
    assert!(late.split_once(" string ").unwrap().1.len() < SEED_DEBIAN_LATE_MAX);
}

#[test]
fn debian_late_command_runs_the_script_and_tolerates_failure() {
    let late: Vec<String> = preseed_logical_lines(&debian_text())
        .into_iter()
        .filter(|l| l.starts_with("d-i preseed/late_command"))
        .collect();
    assert_eq!(late.len(), 1);
    let command = &late[0];
    assert!(command.contains("in-target /bin/sh -c"));
    assert!(command.contains("/bin/bash /root/harden-linux.sh --yes --chroot"));
    assert!(command.contains("||")); // failure is logged and swallowed
    assert!(command.trim_end().ends_with("true"));
}

#[test]
fn debian_continuation_lines_are_well_formed() {
    let text = debian_text();
    let raw: Vec<&str> = text.split('\n').collect();
    let start = raw.iter().position(|l| l.starts_with("d-i preseed/late_command")).unwrap();
    let mut block: Vec<&str> = raw[start..].to_vec();
    let blank = block.iter().position(|l| l.is_empty()).unwrap();
    block.remove(blank);
    assert!(block[..block.len() - 1].iter().all(|l| l.ends_with('\\')));
    assert!(!block[block.len() - 1].ends_with('\\'));
    for line in &block[1..] {
        assert!(line.starts_with("    "), "{line}");
    }
}

// The shell checks need bash (and `base64 -d` for the round trips) and use unix paths: unix only.
#[cfg(unix)]
mod shell {
    use super::*;
    use std::io::Write;
    use std::path::Path;
    use std::process::{Command, Stdio};

    fn bash_available() -> bool {
        Command::new("bash").arg("-c").arg("true").output().map(|o| o.status.success()).unwrap_or(false)
    }

    fn run_bash(args: &[&str], input: &str, cwd: Option<&Path>) -> (i32, String) {
        let mut cmd = Command::new("bash");
        cmd.args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        if let Some(cwd) = cwd {
            cmd.current_dir(cwd);
        }
        let mut child = cmd.spawn().unwrap();
        child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).into_owned())
    }

    // =============================================================================================================
    // ShellSyntaxTests / ShellRoundTripTests (need bash; base64 -d for the round trip)
    // =============================================================================================================

    fn check_syntax(snippet: &str, label: &str) {
        let (rc, err) = run_bash(&["-n"], snippet, None);
        assert_eq!(rc, 0, "{label}: {err}");
    }

    #[test]
    fn shell_syntax_ubuntu_late_commands() {
        if !bash_available() {
            eprintln!("note: bash not found: test skipped");
            return;
        }
        for (n, command) in late_commands().iter().enumerate() {
            check_syntax(command, &format!("ubuntu late-command {n}"));
        }
    }

    #[test]
    fn shell_syntax_fedora_post() {
        if !bash_available() {
            eprintln!("note: bash not found: test skipped");
            return;
        }
        let (_commands, sections) = fedora_sections();
        check_syntax(&(section(&sections, "%post").join("\n") + "\n"), "fedora %post");
    }

    #[test]
    fn shell_syntax_debian_late_command() {
        if !bash_available() {
            eprintln!("note: bash not found: test skipped");
            return;
        }
        let late = late_command(&debian_text());
        check_syntax(late.split_once(" string ").unwrap().1, "debian late_command");
    }

    fn base64_decode_works() -> bool {
        let Ok(mut child) =
            Command::new("base64").arg("-d").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn()
        else {
            return false;
        };
        let _ = child.stdin.take().unwrap().write_all(b"aGk=");
        child.wait_with_output().map(|o| o.status.success() && o.stdout == b"hi").unwrap_or(false)
    }

    fn roundtrip_ready() -> bool {
        if bash_available() && base64_decode_works() {
            true
        } else {
            eprintln!("note: needs bash and base64 -d: test skipped");
            false
        }
    }

    fn run_snippet(snippet: &str, tmp: &Path) {
        let (rc, err) = run_bash(&["-e"], snippet, Some(tmp));
        assert_eq!(rc, 0, "{err}");
    }

    #[test]
    fn shell_roundtrip_ubuntu_write_step_recreates_the_script() {
        if !roundtrip_ready() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path().canonicalize().unwrap().display().to_string();
        let snippet = late_commands()[0].replace("/target", &format!("{t}/target"));
        assert_eq!(snippet.matches(&t).count(), snippet.matches("/target").count());
        run_snippet(&snippet, tmp.path());
        let path = tmp.path().join("target/root/harden-linux.sh");
        assert_eq!(std::fs::read(&path).unwrap(), FAKE_SCRIPT.as_bytes());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn shell_roundtrip_fedora_post_step_recreates_the_script() {
        if !roundtrip_ready() {
            return;
        }
        let (_commands, sections) = fedora_sections();
        let body = section(&sections, "%post");
        let end = body.iter().position(|l| l.starts_with("chmod 700")).unwrap();
        let snippet = body[..=end].join("\n") + "\n";
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path().canonicalize().unwrap().display().to_string();
        let snippet = snippet.replace("/root", &format!("{t}/root")).replace("/var/log", &format!("{t}/var/log"));
        run_snippet(&snippet, tmp.path());
        assert_eq!(std::fs::read(tmp.path().join("root/harden-linux.sh")).unwrap(), FAKE_SCRIPT.as_bytes());
    }

    #[test]
    fn shell_roundtrip_debian_chunks_recreate_the_script() {
        if !roundtrip_ready() {
            return;
        }
        let late = late_command(&debian_text());
        let command = late.split_once(" string ").unwrap().1;
        let steps: Vec<&str> = command.split(';').map(str::trim).filter(|s| !s.is_empty()).collect();
        let keep: Vec<&str> = steps
            .iter()
            .copied()
            .filter(|s| s.starts_with("mkdir") || s.starts_with(": >") || s.starts_with("echo"))
            .collect();
        assert!(keep.len() >= 3);
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path().canonicalize().unwrap().display().to_string();
        run_snippet(&(keep.join(";\n").replace("/target", &format!("{t}/target")) + "\n"), tmp.path());
        let encoded = std::fs::read_to_string(tmp.path().join("target/root/harden-linux.b64")).unwrap();
        let pieces: Vec<String> = encoded.split_whitespace().map(str::to_string).collect();
        assert_eq!(decode_b64(&pieces), FAKE_SCRIPT.as_bytes());
    }
}

// =============================================================================================================
// WindowsSeedTests: launchers, script and README (the "run after install" mode, the only one)
// =============================================================================================================

fn win_files() -> Files {
    seed(SeedTarget::Windows).1
}

fn cmd_text(name: &str) -> String {
    String::from_utf8(win_files()[name].clone()).expect("ascii")
}

const WINDOWS_REMOVED_FILES: [&str; 3] = ["autounattend.xml", "EPMA-SEED.txt", "SetupComplete.cmd"];

#[test]
fn windows_label_is_a_valid_fat32_label() {
    let (label, _files) = seed(SeedTarget::Windows);
    assert_eq!(label, "EPMA-SEED");
    assert_eq!(seed_label(SeedTarget::Windows), "EPMA-SEED");
}

#[test]
fn windows_the_seed_is_exactly_the_five_run_after_install_files() {
    let files = win_files();
    let names: BTreeSet<&str> = files.keys().map(String::as_str).collect();
    assert_eq!(names, BTreeSet::from(["harden.cmd", "audit.cmd", "undo.cmd", "harden.ps1", "README.txt"]));
    assert_eq!(names, expected_files(SeedTarget::Windows));
    for removed in WINDOWS_REMOVED_FILES {
        assert!(!files.contains_key(removed));
        assert!(!names.iter().any(|n| n.eq_ignore_ascii_case(removed)));
    }
}

#[test]
fn windows_files_are_flat_ascii_names_within_the_drive_limits() {
    // (the drive validator itself is checked in `windows_files_pass_the_drive_validator`, which needs the `seed` module)
    let files = win_files();
    for (name, data) in &files {
        assert!(re(r"^[A-Za-z0-9][A-Za-z0-9._-]*$").is_match(name), "{name}");
        assert!(!data.is_empty(), "{name}");
        assert!(data.len() <= MAX_FILE);
    }
    assert!(files.values().map(Vec::len).sum::<usize>() <= MAX_TOTAL);
}

#[test]
fn windows_files_pass_the_drive_validator() {
    let files = win_files();
    let validated = epma_usb_creator::seed::validate_seed_files(&files).unwrap();
    assert_eq!(validated, files);
    assert_eq!(epma_usb_creator::seed::validate_seed_label("EPMA-SEED").unwrap(), "EPMA-SEED");
}

#[test]
fn windows_script_comes_from_the_other_part_at_call_time() {
    assert_eq!(win_files()["harden.ps1"], FAKE_PS1);
    let second = b"\xef\xbb\xbf# second\r\n".to_vec();
    let (_label, files) = windows_seed_files_from(second.clone(), &applied_lines(), NOT_CHANGED).unwrap();
    assert_eq!(files["harden.ps1"], second);
}

#[test]
fn windows_empty_pieces_are_refused() {
    for bad in [&b""[..], b"  \r\n"] {
        assert!(matches!(windows_seed_files_from(bad.to_vec(), &applied_lines(), NOT_CHANGED), Err(Error::Value(_))));
    }
}

#[test]
fn windows_profile_is_validated() {
    assert!(matches!(hardening_files_seed(SeedTarget::Windows, Hardening::None), Err(Error::Value(_))));
}

#[test]
fn windows_deterministic() {
    assert_eq!(seed(SeedTarget::Windows), seed(SeedTarget::Windows));
}

// ---- the launchers
#[test]
fn windows_launchers_are_crlf_ascii_without_bom() {
    for name in WINDOWS_CMD_FILES {
        let data = win_files()[name].clone();
        assert!(!data.starts_with(b"\xef\xbb\xbf"), "BOM");
        let text = String::from_utf8(data).unwrap();
        assert!(text.is_ascii());
        assert!(!text.contains('\0') && !text.contains('\t'));
        assert!(text.ends_with("\r\n"));
        assert_eq!(text.matches('\n').count(), text.matches("\r\n").count(), "bare LF");
        assert_eq!(text.matches('\r').count(), text.matches("\r\n").count(), "bare CR");
        let lines: Vec<&str> = text.split("\r\n").collect();
        for (n, line) in lines[..lines.len() - 1].iter().enumerate() {
            assert_eq!(*line, line.trim_end(), "{name}:{} trailing whitespace", n + 1);
            assert!(line.len() <= 200, "{name}:{}", n + 1);
        }
        assert!(text.starts_with("@echo off\r\n"));
    }
}

#[test]
fn windows_launchers_say_what_they_do() {
    for name in WINDOWS_CMD_FILES {
        let text = cmd_text(name);
        let head: Vec<&str> =
            text.split("\r\n").filter(|l| l.starts_with("rem ") || l.starts_with("echo ")).take(12).collect();
        let joined = head.join(" ");
        assert!(joined.contains("EPMA"), "{name}");
        assert!(joined.contains("EXPERIMENTAL"), "{name}");
        assert!(
            flat(&joined).replace("echo ", "").contains("Nothing is installed and nothing is downloaded"),
            "{name}"
        );
        let first_echo = text.split("\r\n").find(|l| l.starts_with("echo ") && l.len() > 6).unwrap();
        assert!(first_echo.starts_with("echo EPMA USB CREATOR"), "{first_echo}");
    }
}

const PS_EXE: &str = "\"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"";

#[test]
fn windows_every_launcher_runs_the_script_from_its_own_folder_quoted() {
    for (name, mode) in [("harden.cmd", "Apply"), ("audit.cmd", "Audit"), ("undo.cmd", "Undo")] {
        let text = cmd_text(name);
        let run: Vec<&str> = text.split("\r\n").filter(|l| l.starts_with(PS_EXE) && l.contains("-File \"")).collect();
        assert_eq!(
            run,
            [format!("{PS_EXE} -NoProfile -ExecutionPolicy Bypass -File \"%~dp0harden.ps1\" -Mode {mode}")],
            "{name}"
        );
        // always inside double quotes: paths with spaces work
        for (start, _) in text.match_indices("%~dp0") {
            assert_eq!(&text[start - 1..start], "\"", "unquoted %~dp0");
            assert_eq!(&text[start + 5..start + 16], "harden.ps1\"");
        }
        assert!(!text.to_lowercase().contains("%cd%")); // never the current folder: it is System32 after elevation
        assert!(!text.contains("%0"));
        assert_eq!(text.matches("-Mode").count(), 1 + text.matches("rem Runs harden.ps1 -Mode").count());
        for other in ["Apply", "Audit", "Undo"].iter().filter(|m| **m != mode) {
            assert!(!text.contains(&format!("-Mode {other}")), "{name}: {other}");
        }
    }
}

#[test]
fn windows_system_tools_are_called_by_full_path_and_the_current_folder_is_not_searched() {
    let bare = re(r"^(net|fltmc|powershell|choice|certutil|cmd|reg|sc|where|timeout)\b");
    let bare_ps = re(r#"^"?powershell"#);
    for name in WINDOWS_CMD_FILES {
        let text = cmd_text(name);
        let lines: Vec<&str> = text.split("\r\n").collect();
        assert_eq!(lines[..3], ["@echo off", "setlocal", "set \"NoDefaultCurrentDirectoryInExePath=1\""]);
        for tool in ["net.exe session", "fltmc.exe"] {
            let hits: Vec<&&str> = lines.iter().filter(|l| l.contains(tool)).collect();
            assert_eq!(hits.len(), 1, "{name}: {tool}");
            assert!(hits[0].starts_with("%SystemRoot%\\System32\\"), "{}", hits[0]);
        }
        for line in &lines {
            // no command is started by its bare name
            assert!(!bare.is_match(line), "{line}");
            assert!(!bare_ps.is_match(line), "{line}");
        }
        assert_eq!(
            text.to_lowercase().matches("powershell.exe").count(),
            text.matches("\\WindowsPowerShell\\v1.0\\powershell.exe").count()
        );
    }
}

#[test]
fn windows_every_launcher_checks_for_admin_and_elevates_itself() {
    for name in WINDOWS_CMD_FILES {
        let text = cmd_text(name);
        for needle in [
            "%SystemRoot%\\System32\\net.exe session >nul 2>&1",
            "%SystemRoot%\\System32\\fltmc.exe >nul 2>&1",
            "Start-Process",
            "-Verb RunAs",
            "-ArgumentList 'elevated'", // the elevated copy must not elevate again
            "if /i \"%~1\"==\"elevated\" goto :noadmin",
            "Administrator rights were not granted. Nothing was changed.",
        ] {
            assert!(text.contains(needle), "{name}: {needle}");
        }
        assert!(text.find("net.exe session").unwrap() < text.find("Start-Process").unwrap());
        assert!(text.find("Start-Process").unwrap() < text.find("-File \"").unwrap());
    }
}

#[test]
fn windows_the_launcher_path_reaches_powershell_through_the_environment_only() {
    // A folder name with ' or a typographic apostrophe (U+2018/2019/201A/201B) must not be able to leave a PowerShell
    // string: the path is never put into the command text, only into an environment variable.
    let percent = re(r"%[^%]*%");
    for name in WINDOWS_CMD_FILES {
        let text = cmd_text(name);
        assert!(text.contains("set \"EPMA_SELF=%~f0\""));
        let starts: Vec<&str> = text.split("\r\n").filter(|l| l.contains("Start-Process")).collect();
        assert_eq!(starts.len(), 1, "{name}");
        let start = starts[0];
        assert!(start.contains("-FilePath $env:EPMA_SELF"));
        assert!(!start.contains("%~f0"));
        assert!(!start.contains("%EPMA_SELF%"));
        let vars: Vec<&str> = percent.find_iter(start).map(|m| m.as_str()).collect();
        assert_eq!(vars, ["%SystemRoot%"]); // no other variable inside it
        assert_eq!(start.matches('\'').count(), 2); // only 'elevated', a constant
        assert!(!text.contains("SELF_PS"));
        assert!(!text.contains("'=''")); // the old quote-doubling workaround is gone
        for quote in ['\u{2018}', '\u{2019}', '\u{201a}', '\u{201b}'] {
            assert!(!text.contains(quote));
        }
    }
}

#[test]
fn windows_harden_and_undo_ask_for_confirmation_audit_does_not() {
    let choice = "%SystemRoot%\\System32\\choice.exe /c yn /n /m \"Continue? [y/N] \"";
    for name in ["harden.cmd", "undo.cmd"] {
        let text = cmd_text(name);
        assert!(text.contains(choice), "{name}");
        assert!(text.find("Continue? [y/N]").unwrap() < text.find("-File \"").unwrap());
        // only the answer "y" (errorlevel 1) leads to the run; 2 (n), 0 (Ctrl+C) and errors cancel
        assert!(text.contains("if errorlevel 2 goto :cancel\r\nif errorlevel 1 goto :run\r\n:cancel\r\n"));
        assert!(text.contains("Cancelled. Nothing was changed."));
        let cancel = text.find(":cancel").unwrap();
        assert!(cancel < text.find("-File \"").unwrap());
        assert!(text[cancel..text.find("\r\n:run\r\n").unwrap()].contains("exit /b 1"));
        // nothing the user types is ever expanded by cmd: no set /p, no %ANSWER% in an if
        assert!(!text.contains("set /p"));
        assert!(!text.contains("ANSWER"));
    }
    let audit = cmd_text("audit.cmd");
    assert!(!audit.contains("Continue?"));
    assert!(!audit.contains("choice"));
    assert!(!audit.contains(":cancel"));
    assert!(audit.contains("changes nothing"));
}

#[test]
fn windows_the_window_stays_open() {
    for (name, flag) in [("harden.cmd", "WARN"), ("audit.cmd", "DIFF"), ("undo.cmd", "WARN")] {
        let text = cmd_text(name);
        let tail = text.split("-File \"").nth(1).unwrap();
        assert!(tail.contains("\r\npause\r\n"), "{name}");
        assert!(tail.contains("exit /b %RC%"), "{name}");
        assert!(tail.contains(&format!("a [{flag}] line means a")), "{name}");
        let other = if flag == "WARN" { "DIFF" } else { "WARN" };
        assert!(!text.contains(other), "{name}: {other}");
    }
    assert!(cmd_text("undo.cmd").contains("non-zero exit code"));
}

#[test]
fn windows_launchers_have_no_destructive_or_download_commands() {
    let bad = re(
        r"(?i)\b(del|erase|format|diskpart|rd|rmdir|reg|regedit|mountvol|bcdedit|cipher|shutdown|takeown|icacls|robocopy|xcopy|copy|move|ren|rename|mkdir|md|taskkill|sc|netsh|wmic|curl|wget|bitsadmin|certutil|Invoke-WebRequest|Invoke-Expression|iex|DownloadFile|DownloadString|msiexec|winget|choco)\b",
    );
    let absolute = re(r"\\\\|[A-Za-z]:\\");
    for name in WINDOWS_CMD_FILES {
        let text = cmd_text(name);
        let found: Vec<&str> = bad.find_iter(&text).map(|m| m.as_str()).collect();
        assert!(found.is_empty(), "{name}: {found:?}");
        assert!(!text.to_lowercase().contains("reg delete"));
        assert!(!text.to_lowercase().contains("http"));
        assert!(!absolute.is_match(&text.replace("C:\\Windows\\Temp", "")), "absolute path");
        assert!(!text.contains("-WindowStyle Hidden")); // nothing runs out of sight
    }
}

#[test]
fn windows_percent_signs_are_only_the_known_safe_forms() {
    let allowed = re(r"%~dp0|%~f0|%~1|%SystemRoot%|%RC%|%errorlevel%");
    for name in WINDOWS_CMD_FILES {
        let text = cmd_text(name);
        assert!(!allowed.replace_all(&text, "").contains('%'), "{name}");
        assert!(!text.contains('!'), "{name}"); // no delayed expansion surprises
    }
}

#[test]
fn windows_labels_and_gotos_match() {
    let goto = re(r"goto (:\w+)");
    for name in WINDOWS_CMD_FILES {
        let text = cmd_text(name);
        let lines: Vec<&str> = text.split("\r\n").collect();
        let labels: Vec<&str> = lines.iter().copied().filter(|l| l.starts_with(':')).collect();
        let unique: BTreeSet<&str> = labels.iter().copied().collect();
        assert_eq!(labels.len(), unique.len(), "{name}");
        for c in goto.captures_iter(&lines.join("\r\n")) {
            assert!(labels.contains(&&c[1]), "{name}: {}", &c[1]);
        }
        assert_eq!(lines.iter().filter(|l| **l == "@echo off").count(), 1);
    }
}

#[test]
fn windows_echo_lines_use_no_special_characters() {
    // & | < > ( ) ^ " and % in an echo line would run something or break the line
    let special = re(r#"[&|<>()^"%!]"#);
    for name in WINDOWS_CMD_FILES {
        for line in cmd_text(name).split("\r\n") {
            if let Some(rest) = line.strip_prefix("echo ") {
                assert!(!special.is_match(&rest.replace("%RC%", "")), "{name}: {line}");
            }
        }
    }
}

#[test]
fn windows_no_secrets_or_account_changes_in_the_launchers() {
    let accounts = re(r"(?i)\b(net user|net localgroup|password|secret|token|key)\b");
    for name in WINDOWS_CMD_FILES {
        let text = cmd_text(name);
        assert!(!hash_like().is_match(&text));
        assert!(!claims().is_match(&text));
        assert!(!accounts.is_match(&text), "{name}");
    }
}

// ---- the README
fn win_readme_flat() -> String {
    flat(&text_of(SeedTarget::Windows, "README.txt"))
}

#[test]
fn windows_readme_is_crlf_ascii_and_at_most_80_columns() {
    let data = win_files()["README.txt"].clone();
    assert!(!data.starts_with(b"\xef\xbb\xbf"));
    let text = String::from_utf8(data).unwrap();
    assert!(text.is_ascii());
    assert!(text.ends_with("\r\n"));
    assert_eq!(text.matches('\n').count(), text.matches("\r\n").count());
    let lines: Vec<&str> = text.split("\r\n").collect();
    for (n, line) in lines[..lines.len() - 1].iter().enumerate() {
        assert!(line.len() <= 80, "README line {}: {line:?}", n + 1);
        assert_eq!(*line, line.trim_end());
    }
    assert!(!text.contains('\t'));
}

#[test]
fn windows_readme_explains_what_the_drive_is_and_how_to_use_it() {
    let text = win_readme_flat();
    for needle in [
        "SECOND small USB",
        "NOT a Windows installer",
        "does not boot",
        "Nothing is installed and nothing is downloaded",
        "RUN IT AFTER WINDOWS IS INSTALLED",
        "File Explorer",
        "audit.cmd",
        "harden.cmd",
        "undo.cmd",
        "FIRST",
        "User Account Control",
        "choose Yes",
        "Continue? [y/N]",
        "C:\\Windows\\Temp\\epma-hardening.log",
        "A restart may be needed",
        "A [WARN] line means that a setting is NOT in effect",
        "plain text files",
        "Notepad",
    ] {
        assert!(text.contains(needle), "{needle}");
    }
    assert!(text.find("audit.cmd").unwrap() < text.find("harden.cmd").unwrap(), "audit comes first");
}

#[test]
fn windows_readme_lists_every_setting_and_what_is_left_alone() {
    let text = win_readme_flat();
    let lines = applied_lines();
    assert!(lines.len() > 5);
    assert!(lines.len() < describe_lines().len());
    for line in &lines {
        let summary = line.split(" -- risk:").next().unwrap();
        assert!(text.contains(&flat(summary)), "{summary}");
    }
    assert!(text.contains("-DisableLegacyNetwork")); // the opt-in settings are named as opt-in, not listed as applied
    assert!(!text.contains("-- risk"));
    for (_sid, item, _why) in NOT_CHANGED {
        assert!(text.contains(item), "{item}");
    }
    assert!(text.contains("WHAT IT LEAVES ALONE"));
}

#[test]
fn windows_readme_is_honest() {
    let text = win_readme_flat();
    assert!(text.to_uppercase().contains("EXPERIMENTAL")); // the scripts were never run by their authors on real Windows
    for needle in [
        "never executed by its authors on a real Windows",
        "not a compliance claim, certification or guarantee",
        "inspired by common security baselines",
        "spare PC",
        "virtual machine",
        "Tamper Protection",
        "[WARN]",
        "Nothing here selects a disk",
        "nothing creates an account",
        "This drive is not protected or authenticated in any way",
    ] {
        assert!(text.contains(needle), "{needle}");
    }
    assert!(text.to_lowercase().contains("another antivirus"));
    assert!(!claims().is_match(&text), "compliance word");
    for word in ["CIS", "STIG", "NIST", "compliant", "certified", "guaranteed"] {
        assert!(!text.contains(word), "{word}");
    }
    for claim in [
        "tamper-proof",
        "digitally signed",
        "verified drive",
        "trusted drive",
        "secure drive",
        "authenticated drive",
        "protects the drive",
    ] {
        assert!(!text.to_lowercase().contains(claim), "{claim}");
    }
}

#[test]
fn windows_readme_has_no_during_setup_text() {
    let text = win_readme_flat();
    for needle in [
        "autounattend.xml",
        "answer file",
        "EPMA-SEED.txt",
        "specialize",
        "SetupComplete.cmd",
        "SHA-256",
        "Panther",
        "ARM64",
        "amd64",
        "marker",
        "Way 1",
        "Way 2",
        "WHILE WINDOWS IS BEING",
        "BEFORE you start Setup",
        "first restart",
        "Windows could not parse",
    ] {
        assert!(!text.contains(needle), "{needle}");
    }
    assert!(!text.contains("EXPERIMENTAL:"));
    assert!(text.contains("RUN IT AFTER WINDOWS IS INSTALLED"));
}

#[test]
fn windows_readme_audit_and_launcher_sentences_are_accurate() {
    let text = win_readme_flat();
    assert!(text.contains("audit.cmd does not ask you to confirm anything"));
    assert!(text.contains("[DIFF] means NOT in effect"));
    assert!(text.contains("harden.cmd and undo.cmd also ask you to confirm; audit.cmd does not"));
    assert!(!text.contains("Each launcher only asks for administrator rights, asks you to confirm"));
    assert!(!text.contains("audit.cmd prints a [WARN]"));
}

#[test]
fn windows_readme_explains_the_opt_in_switch_and_the_undo_limits() {
    let text = win_readme_flat();
    assert!(text.contains("powershell -ExecutionPolicy Bypass -File harden.ps1 -Mode Apply -DisableLegacyNetwork"));
    assert!(text.contains("open PowerShell as administrator"));
    assert!(text.contains("LIMITS OF UNDO.CMD"));
    for needle in [
        "It does not turn SMBv1 or PowerShell 2.0 on again",
        "does not lower the Security log size",
        "already in the wanted state before harden.cmd ran is not recorded",
        "undo.cmd can finish with a non-zero exit code when one of its steps failed",
    ] {
        assert!(text.contains(needle), "{needle}");
    }
}

#[test]
fn windows_readme_says_where_the_log_is() {
    let text = win_readme_flat();
    assert!(text.contains(
        "harden.cmd and undo.cmd write a log to C:\\Windows\\Temp\\epma-hardening.log. audit.cmd only prints in its window"
    ));
}

// ---- the whole drive
#[test]
fn windows_no_secrets_or_hash_like_strings_anywhere() {
    let base64_like = re(r"[A-Za-z0-9+/]{40,}={0,2}");
    let hex_like = re(r"(?i)\b[0-9a-f]{32,}\b");
    for (name, data) in &win_files() {
        if name == "harden.ps1" {
            continue; // a stand-in here; the real one is checked below
        }
        let text = String::from_utf8(data.clone()).unwrap();
        assert!(!hash_like().is_match(&text), "{name}");
        assert!(!base64_like.is_match(&text), "{name}: long base64-like string");
        assert!(!hex_like.is_match(&text), "{name}: hash-like string");
        for needle in ["BEGIN PRIVATE", "BEGIN OPENSSH", "ssh-rsa", "ssh-ed25519"] {
            assert!(!text.contains(needle), "{name}: {needle}");
        }
    }
}

// =============================================================================================================
// RealWindowsSeedTests: the same drive with the real script (here: the golden harden.ps1)
// =============================================================================================================

fn real_windows_seed() -> (String, Files) {
    windows_seed_files_from(REAL_PS1.to_vec(), &applied_lines(), NOT_CHANGED).unwrap()
}

#[test]
fn real_windows_pieces_end_up_on_the_drive_unchanged() {
    let (label, files) = real_windows_seed();
    assert_eq!(label, "EPMA-SEED");
    let names: BTreeSet<&str> = files.keys().map(String::as_str).collect();
    assert_eq!(names, expected_files(SeedTarget::Windows));
    assert_eq!(files["harden.ps1"], REAL_PS1);
    for name in ["harden.cmd", "audit.cmd", "undo.cmd", "README.txt"] {
        assert!(String::from_utf8(files[name].clone()).unwrap().is_ascii(), "{name}");
    }
    assert_eq!(real_windows_seed(), (label, files));
}

#[test]
fn real_windows_launchers_call_parameters_the_real_script_declares() {
    let ps1 = String::from_utf8(REAL_PS1.to_vec()).unwrap();
    let ps1 = ps1.strip_prefix('\u{feff}').unwrap_or(&ps1);
    assert!(re(r"(?is)param\s*\(.*\$Mode").is_match(ps1));
    for mode in ["Apply", "Audit", "Undo"] {
        assert!(ps1.contains(mode), "the real harden.ps1 does not mention -Mode {mode}");
    }
}

#[test]
fn real_windows_pieces_hold_no_secrets_or_claims() {
    let (_label, files) = real_windows_seed();
    let text = String::from_utf8(files["harden.ps1"].clone()).unwrap();
    assert!(!hash_like().is_match(&text));
    assert!(!claims().is_match(&text));
    assert!(!text.contains("BEGIN PRIVATE"));
}

#[test]
fn real_windows_seed_through_the_public_entry_point() {
    let ps1 = epma_usb_creator::harden_windows::windows_hardening_ps1(Hardening::Baseline).unwrap();
    let (label, files) = hardening_files_seed(SeedTarget::Windows, Hardening::Baseline).unwrap();
    assert_eq!(label, "EPMA-SEED");
    assert_eq!(files["harden.ps1"], ps1);
    assert_eq!(hardening_files_seed(SeedTarget::Windows, Hardening::Baseline).unwrap(), (label, files));
}

// =============================================================================================================
// RealScriptTests: the structural checks with the real Linux script
// =============================================================================================================

#[test]
fn real_script_round_trips_in_every_seed() {
    let script = linux_hardening_script(Hardening::Baseline).unwrap().as_bytes();
    for target in LINUX_TARGETS {
        let (label, files) = hardening_files_seed(target, Hardening::Baseline).unwrap();
        assert_eq!(label, allowed_label(target));
        assert_eq!(files["harden-linux.sh"], script);
        assert!(files.values().all(|d| d.len() <= MAX_FILE));
        assert!(files.values().map(Vec::len).sum::<usize>() <= MAX_TOTAL);
        let text = String::from_utf8(files[config_file(target)].clone()).unwrap();
        if target == SeedTarget::Debian {
            let chunks = b64_chunks(&text);
            assert_eq!(decode_b64(&chunks), script);
            let late = late_command(&text);
            let command = late.split_once(" string ").unwrap().1;
            assert!(command.len() < SEED_DEBIAN_LATE_MAX, "the real late_command must fit with room to spare");
            assert!(command.len() < 131_072);
            assert!(chunks.len() <= 30, "long base64 lines, few echo commands");
        } else {
            assert_eq!(decode_b64(&heredoc_payload(&text)), script);
        }
        for (name, data) in &files {
            if name == "harden-linux.sh" {
                continue;
            }
            let body = String::from_utf8(data.clone()).unwrap();
            assert!(!hash_like().is_match(&body));
            assert!(!claims().is_match(&body));
        }
        assert_eq!(hardening_files_seed(target, Hardening::Baseline).unwrap(), (label, files));
    }
}
