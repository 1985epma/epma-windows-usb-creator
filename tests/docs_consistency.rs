//! Documentation and knowledge drift: every fact written in more than one place must agree.
//!
//! Port of tests/test_docs_consistency.py. The same facts (the one-line description of the product, how the sudo
//! password is handled, the ChromeOS Flex sizes, the Rust minimum, the critical mount points, the project address...)
//! are written in the program, the built-in help, both READMEs, SECURITY.md, CHANGELOG.md, the Homebrew formula and
//! the CI files. Here they are compared with the constants and with each other, so a change in one place that
//! forgets the others fails a test.
//!
//! The tests read files; they never touch a device, use sudo or the network. Several are written to be correct for
//! ANY set of strings (no hard-coded counts), because the program keeps growing.

use epma_usb_creator::constants::*;
use epma_usb_creator::diskrisk::{LARGE_DISK_BYTES, MANY_VOLUMES, SUBSTANTIAL_USED_BYTES};
use epma_usb_creator::help::help_sections;
use regex::Regex;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(parts: &[&str]) -> String {
    let mut p = root();
    for part in parts {
        p.push(part);
    }
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

/// Collapse whitespace (and markdown emphasis) so a sentence wrapped over lines still matches.
fn squash(text: &str) -> String {
    static WS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());
    WS.replace_all(&text.replace("**", "").replace('`', ""), " ").into_owned()
}

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|e| panic!("bad regex {pattern}: {e}"))
}

static README: LazyLock<String> = LazyLock::new(|| read(&["README.md"]));
static README_PT: LazyLock<String> = LazyLock::new(|| read(&["README.pt-BR.md"]));
static SECURITY: LazyLock<String> = LazyLock::new(|| read(&["SECURITY.md"]));
static CHANGELOG: LazyLock<String> = LazyLock::new(|| read(&["CHANGELOG.md"]));
static FORMULA: LazyLock<String> = LazyLock::new(|| read(&["Formula", "epma-windows-usb-creator.rb"]));
static HELP_SECTIONS: LazyLock<Vec<(String, String)>> = LazyLock::new(help_sections);
static HELP: LazyLock<String> =
    LazyLock::new(|| HELP_SECTIONS.iter().map(|(t, b)| format!("{t}\n{b}")).collect::<Vec<_>>().join("\n"));

fn help_section(title: &str) -> String {
    HELP_SECTIONS
        .iter()
        .find(|(t, _)| t == title)
        .map(|(_, b)| b.clone())
        .unwrap_or_else(|| panic!("no help section {title}"))
}

/// Every `.rs` file of src/ (the program), as one text; the generated PT_BR table is left out.
static SOURCE: LazyLock<String> = LazyLock::new(|| {
    let mut files = Vec::new();
    collect_rs(&root().join("src"), &mut files);
    files.sort();
    files
        .iter()
        .filter(|p| !p.ends_with("i18n_table.rs"))
        .map(|p| std::fs::read_to_string(p).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n")
});

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_rs(&path, out);
            } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
                out.push(path);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 4. One description of the product
// ---------------------------------------------------------------------------
const KEYWORDS: [&str; 3] = ["Windows 11", "Linux", "ChromeOS Flex"];

fn check_scope(whence: &str, text: &str) {
    for word in KEYWORDS {
        assert!(text.contains(word), "{whence} no longer mentions {word}: it describes an older product");
    }
}

#[test]
fn the_tagline_names_every_supported_image() {
    check_scope("APP_TAGLINE", APP_TAGLINE);
    assert!(APP_TAGLINE.contains("verified"));
}

#[test]
fn help_about_uses_the_tagline() {
    assert!(help_section("About").contains(APP_TAGLINE));
}

#[test]
fn cargo_description_is_the_tagline() {
    let cargo = read(&["Cargo.toml"]);
    let m = re(r#"(?m)^description = "([^"]+)""#).captures(&cargo).expect("Cargo.toml has a description");
    assert_eq!(&m[1], APP_TAGLINE, "Cargo.toml description and APP_TAGLINE must be the same sentence");
}

#[test]
fn readmes_open_with_the_same_scope() {
    for (name, text) in [("README.md", &*README), ("README.pt-BR.md", &*README_PT)] {
        check_scope(name, text.split("## ").next().unwrap());
    }
}

#[test]
fn homebrew_formula_description() {
    let m = re(r#"(?m)^\s*desc "([^"]+)""#).captures(&FORMULA).expect("the formula has a desc");
    let desc = &m[1];
    check_scope("the Formula desc", desc);
    // Homebrew style (brew audit --strict): under 80 characters, no leading article, no trailing period, capital letter.
    assert!(desc.chars().count() < 80);
    assert!(!desc.ends_with('.'));
    assert!(!re(r"(?i)^(a|an|the)\s").is_match(desc));
    assert!(desc.chars().next().unwrap().is_uppercase());
}

#[test]
fn sbom_description() {
    let text = read(&[".github", "scripts", "make_sbom.py"]);
    let m = re(r#""name": "epma-usb-creator",\s*"version": clean,\s*"description":\s*"([^"]+)""#)
        .captures(&text)
        .expect("the SBOM main component has a description");
    check_scope("the SBOM description", &m[1]);
}

// ---------------------------------------------------------------------------
// 1. The sudo password: every statement must match what PrivilegeHelper really does
// ---------------------------------------------------------------------------
fn documents() -> HashMap<&'static str, String> {
    HashMap::from([
        ("README.md", README.clone()),
        ("README.pt-BR.md", README_PT.clone()),
        ("SECURITY.md", SECURITY.clone()),
        ("CHANGELOG.md", CHANGELOG.clone()),
        ("help", HELP.clone()),
        ("Formula", FORMULA.clone()),
    ])
}

#[test]
fn no_document_claims_the_old_password_behaviour() {
    const STALE: [&str; 8] = [
        "asks again",
        "asked again",
        "ask again",
        "pergunta de novo",
        "perguntar de novo",
        "not kept in memory for the whole operation",
        "is not held",
        "não é guardada",
    ];
    for (name, text) in documents() {
        let text = squash(&text);
        for pattern in STALE {
            assert!(!re(&format!("(?i){pattern}")).is_match(&text), "{name} states the old behaviour: {pattern}");
        }
    }
}

#[test]
fn the_fallback_that_keeps_the_password_is_documented() {
    // The honest statement: normally dropped (sudo's timestamp is used), but when the machine keeps no timestamp the
    // password stays in memory until the operation ends.
    let docs = documents();
    for (name, pattern) in [
        ("README.md", "only until the operation ends"),
        ("SECURITY.md", "only until the operation ends"),
        ("CHANGELOG.md", "only until the operation ends"),
        ("README.pt-BR.md", "até o fim da operação"),
        ("help", "until the operation ends"),
    ] {
        assert!(re(pattern).is_match(&squash(&docs[name])), "{name} does not document the password fallback");
    }
}

#[test]
fn the_documents_say_it_is_never_logged_or_written_to_disk() {
    let docs = documents();
    for name in ["README.md", "SECURITY.md"] {
        assert!(
            re(r"(?i)never (written to (any )?(log|disk)|logged)").is_match(&squash(&docs[name])),
            "{name} must say the password is never logged or written to disk"
        );
    }
    assert!(squash(&README_PT).contains("Nunca é registrada em log, gravada em disco"));
    assert!(squash(&HELP).contains("never logged, written to disk or sent anywhere"));
}

#[test]
fn the_password_never_reaches_a_command_line() {
    // "stdin only" is a claim of every document: no value named like a password may be part of the argument list of
    // a spawned command. A textual check on the code that builds the commands of privilege.rs.
    let privilege = read(&["src", "privilege.rs"]);
    let mut checked = 0;
    for m in re(r"(?s)Command::new\(([^)]*)\)(.{0,400}?)\.spawn|Command::new\(([^)]*)\)(.{0,400}?)\.output")
        .captures_iter(&privilege)
    {
        checked += 1;
        let chunk = format!("{}{}{}{}", &m[1.min(m.len() - 1)], m.get(2).map(|x| x.as_str()).unwrap_or(""), "", "");
        for line in chunk.lines().filter(|l| l.contains(".arg(") || l.contains(".args(")) {
            let lower = line.to_lowercase();
            assert!(!lower.contains("password") && !lower.contains("secret"), "password in an argument list: {line}");
        }
    }
    assert!(checked >= 1, "no spawned command found in privilege.rs: the check is blind");
}

// ---------------------------------------------------------------------------
// 2. Numbers in the help that must come from the constants
// ---------------------------------------------------------------------------
#[test]
fn overview_counts_the_five_image_cards() {
    let overview = help_section("Overview");
    assert!(!overview.contains("Three image types") && !overview.contains("Four image types"));
    assert!(overview.contains("Five image types"));
    for card in ["Google Chrome", "Windows 11", "Linux", "macOS", "Other ISO"] {
        assert!(overview.contains(card), "the overview does not name {card}");
    }
    use epma_usb_creator::types::{Card, Mode};
    let image_cards: Vec<Card> = Card::ORDER.iter().copied().filter(|c| *c != Card::Seed).collect();
    assert_eq!(image_cards, vec![Card::Chrome, Card::Windows, Card::Linux, Card::Mac, Card::Other]);
    // macOS is a raw whole-disk write of its own
    assert_eq!(Card::Mac.mode(), Mode::MacOs);
    assert!(Mode::MacOs.is_raw());
    // Linux and Other ISO are two cards that write the same way
    assert_eq!(Card::Linux.mode(), Card::Other.mode());
    assert_eq!(Card::Linux.mode(), Mode::Linux);
}

#[test]
fn download_retries_come_from_the_constant() {
    let text = squash(&help_section("Getting the image"));
    let m = re(r"retried automatically \(up to (\d+) retries, (\d+) attempts in all\)")
        .captures(&text)
        .expect("the retry sentence is missing");
    assert_eq!(m[2].parse::<u32>().unwrap(), DOWNLOAD_MAX_ATTEMPTS);
    assert_eq!(m[1].parse::<u32>().unwrap(), DOWNLOAD_MAX_ATTEMPTS - 1);
    assert!(!re(r"retried up to \d+ times").is_match(&text));
    // and the constant itself matches the backoff table: one wait per retry
    assert_eq!(DOWNLOAD_BACKOFF_SECONDS.len() as u32, DOWNLOAD_MAX_ATTEMPTS - 1);
}

#[test]
fn audit_log_rotation_comes_from_the_constants() {
    let megabytes = format!("{}", AUDIT_LOG_MAX_BYTES as f64 / 1_000_000.0);
    let old_files = AUDIT_LOG_BACKUPS.to_string();
    let pattern = re(r"(\d+(?:\.\d+)?) MB(?: \(|,)? ?(?:keeping )?(\d+) (?:older|old) files");
    for (name, text) in [("help", &*HELP), ("SECURITY.md", &*SECURITY), ("CHANGELOG.md", &*CHANGELOG)] {
        let squashed = squash(text);
        let m = pattern.captures(&squashed).unwrap_or_else(|| panic!("{name} does not state the audit log rotation"));
        assert_eq!((m[1].to_string(), m[2].to_string()), (megabytes.clone(), old_files.clone()), "{name}");
    }
}

#[test]
fn every_critical_mount_point_is_documented() {
    // CRITICAL_MOUNTPOINTS has more entries than the old lists (/boot/efi): the help, both READMEs and SECURITY.md
    // must name each one.
    assert!(CRITICAL_MOUNTPOINTS.len() >= 6);
    let safety = help_section("Safety");
    for mount in CRITICAL_MOUNTPOINTS {
        assert!(safety.contains(mount), "help Safety does not name {mount}");
        for (name, text) in [("README.md", &*README), ("README.pt-BR.md", &*README_PT), ("SECURITY.md", &*SECURITY)] {
            assert!(text.contains(&format!("`{mount}`")), "{name} does not name `{mount}`");
        }
    }
    // the code also hides anything under /boot, and the documents say so
    assert!(
        SOURCE.contains(r#"starts_with("/boot")"#) || SOURCE.contains(r#"starts_with('/boot')"#),
        "the code no longer hides everything under /boot"
    );
    for text in [&safety, &*README, &*SECURITY, &*README_PT] {
        assert!(re(r"(anything under|qualquer coisa sob)").is_match(&squash(text)));
    }
}

#[test]
fn no_document_mentions_python_or_tk_requirements() {
    // The program is Rust now: nothing may still tell the user to install Python or Tkinter.
    for (name, text) in [("README.md", &*README), ("README.pt-BR.md", &*README_PT), ("help", &*HELP)] {
        for word in ["python-tk", "python3-tk", "pip install", "Tkinter is not available"] {
            assert!(!text.contains(word), "{name} still mentions {word}");
        }
    }
    assert!(!FORMULA.contains("python"), "the Homebrew formula still depends on Python");
}

#[test]
fn no_document_claims_zero_dependencies() {
    // The Python version had none; the Rust program links crates (Cargo.toml / Cargo.lock).
    for (name, text) in
        [("README.md", &*README), ("README.pt-BR.md", &*README_PT), ("SECURITY.md", &*SECURITY), ("help", &*HELP)]
    {
        assert!(
            !re(r"(?i)(zero|no) third-party|sem depend[êe]ncias de terceiros|no third-party dependencies")
                .is_match(&squash(text)),
            "{name} claims there are no third-party dependencies"
        );
    }
}

#[test]
fn no_tabs_in_the_documents() {
    // The window has four cards on one page, not tabs.
    for (name, text) in [("README.md", &*README), ("help", &*HELP)] {
        assert!(!re(r"(?i)\btabs?\b").is_match(text), "{name} talks about tabs");
    }
    assert!(!re(r"(?i)\babas?\b").is_match(&README_PT));
    let changelog = CHANGELOG.split("## [1.0.0]").next().unwrap().replace("replace the three tabs", "");
    assert!(!re(r"(?i)\btabs?\b").is_match(&changelog));
}

#[test]
fn new_behaviours_are_mentioned() {
    // Closing the window during a write asks first; dependencies are checked before erasing.
    for text in [&*HELP, &*README, &*SECURITY] {
        assert!(squash(text).contains("Closing the window"));
    }
    assert!(README_PT.contains("Fechar a janela"));
    for text in [&*HELP, &*README, &*SECURITY] {
        assert!(re(r"(?i)(missing (system )?(tools|dependencies)|dependencies).{0,200}before (anything|the drive)")
            .is_match(&squash(text)));
    }
    assert!(re(r"ausentes são detectadas \*?\*?antes\*?\*? de apagar").is_match(&squash(&README_PT)));
}

// ---------------------------------------------------------------------------
// 5. Release tripwires and hard-coded counts
// ---------------------------------------------------------------------------
#[test]
fn changelog_has_the_current_version() {
    // THE one place that fails on a version bump: update the CHANGELOG (and the Formula after the release) together
    // with the version in Cargo.toml.
    let version = regex::escape(VERSION);
    assert!(
        re(&format!(r"(?m)^## \[{version}\]( - .+)?$")).is_match(&CHANGELOG),
        "no `## [{VERSION}]` in the CHANGELOG"
    );
    assert!(re(&format!(r"(?m)^\[{version}\]: https://github\.com/")).is_match(&CHANGELOG));
}

#[test]
fn release_notes_can_be_extracted() {
    // The release workflow publishes the CHANGELOG section of the tag (.github/scripts/changelog_section.py): same rule.
    let heading = re(&format!(r"^##\s+\[{}\](?:\s.*)?$", regex::escape(VERSION)));
    let mut inside = false;
    let mut body = Vec::new();
    for line in CHANGELOG.lines() {
        if inside {
            if line.starts_with("## ") || re(r"^\[[^\]]+\]:\s").is_match(line) {
                break;
            }
            body.push(line);
        } else if heading.is_match(line) {
            inside = true;
        }
    }
    assert!(body.join("\n").trim().len() > 200, "the release workflow would publish empty notes");
}

#[test]
fn an_unreleased_version_is_marked_as_such() {
    let m =
        re(&format!(r"(?m)^## \[{}\] - (.+)$", regex::escape(VERSION))).captures(&CHANGELOG).expect("version heading");
    assert!(re(r"^(unreleased|\d{4}-\d{2}-\d{2})$").is_match(&m[1]));
}

#[test]
fn cargo_version_is_the_constant() {
    let cargo = read(&["Cargo.toml"]);
    let m = re(r#"(?m)^version = "([^"]+)""#).captures(&cargo).unwrap();
    assert_eq!(&m[1], VERSION);
}

#[test]
fn no_check_counts_are_hard_coded() {
    // "27 proteções", "44 verificações" ... went stale every time a check was added.
    let pattern = re(
        r"(?i)(?:^|[^-\d.])\b(\d+)\s+(prote[cç][õo]es|verifica[cç][õo]es|testes automatizados|audit fixes|regress[õo]es simuladas|correç[õo]es da auditoria)",
    );
    for name in
        ["README.md", "README.pt-BR.md", "SECURITY.md", ".github/workflows/ci.yml", ".github/workflows/security.yml"]
    {
        let text = read(&name.split('/').collect::<Vec<_>>());
        assert!(!pattern.is_match(&text), "{name} hard-codes a number of checks; say 'the checks' instead");
    }
}

// ---------------------------------------------------------------------------
// 6. Dead translations
// ---------------------------------------------------------------------------
/// Every string literal of the program (src/**/*.rs), unescaped.
fn source_literals() -> BTreeSet<String> {
    let lit = re(r#""((?:[^"\\]|\\(?s:.))*)""#);
    let mut out = BTreeSet::new();
    for m in lit.captures_iter(&SOURCE) {
        out.insert(unescape(&m[1]));
    }
    out
}

fn unescape(raw: &str) -> String {
    let mut out = String::new();
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('"') => out.push('"'),
            Some('\'') => out.push('\''),
            Some('\\') => out.push('\\'),
            Some('0') => out.push('\0'),
            Some('u') => {
                if chars.peek() == Some(&'{') {
                    chars.next();
                    let hex: String = chars.by_ref().take_while(|c| *c != '}').collect();
                    if let Some(ch) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                        out.push(ch);
                    }
                }
            }
            // a backslash at the end of a line continues the literal and skips the next line's indentation
            Some('\n') => {
                while matches!(chars.peek(), Some(' ' | '\t' | '\n' | '\r')) {
                    chars.next();
                }
            }
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => {}
        }
    }
    out
}

#[test]
fn no_pt_br_key_is_unused() {
    use epma_usb_creator::harden_windows::describe_hardening_windows;
    use epma_usb_creator::types::Hardening;
    let mut used = source_literals();
    // the window passes every line of describe_hardening_windows() to tr() as a variable
    used.extend(describe_hardening_windows(Hardening::Baseline));
    assert!(used.len() > 500, "the scan found suspiciously few literals");
    let dead: Vec<String> = epma_usb_creator::i18n::translations()
        .iter()
        .map(|(k, _)| *k)
        .filter(|k| !used.contains(*k))
        .map(|k| k.chars().take(80).collect())
        .collect();
    assert!(
        dead.is_empty(),
        "PT_BR keys that no string literal of the program uses (delete them, or fix the text that no longer matches): {dead:#?}"
    );
}

// ---------------------------------------------------------------------------
// 7. The two READMEs have the same structure
// ---------------------------------------------------------------------------
/// (heading levels, tables as (rows, columns), number of code blocks) of a markdown file.
fn outline(text: &str) -> (Vec<usize>, Vec<(usize, usize)>, usize) {
    let (mut headings, mut tables, mut blocks) = (Vec::new(), Vec::new(), 0);
    let (mut in_code, mut table): (bool, Vec<&str>) = (false, Vec::new());
    let flush = |table: &mut Vec<&str>, tables: &mut Vec<(usize, usize)>| {
        if !table.is_empty() {
            tables.push((table.len(), table[0].matches('|').count() - 1));
            table.clear();
        }
    };
    for line in text.lines() {
        if line.starts_with("```") {
            in_code = !in_code;
            if !in_code {
                blocks += 1;
            }
            continue;
        }
        if in_code {
            continue;
        }
        if line.starts_with('|') {
            table.push(line);
            continue;
        }
        flush(&mut table, &mut tables);
        let hashes = line.chars().take_while(|c| *c == '#').count();
        if (1..=6).contains(&hashes) && line[hashes..].starts_with(' ') {
            headings.push(hashes);
        }
    }
    flush(&mut table, &mut tables);
    (headings, tables, blocks)
}

#[test]
fn readmes_have_the_same_headings_tables_and_code_blocks() {
    let (en, pt) = (outline(&README), outline(&README_PT));
    assert_eq!(en.0, pt.0, "README.pt-BR.md has different ## / ### headings than README.md");
    assert_eq!(en.1, pt.1, "the tables differ (rows, columns)");
    assert_eq!(en.2, pt.2, "the number of code blocks differs");
    assert!(en.0.len() > 20);
    assert_eq!(en.1.len(), 3);
}

fn anchor(heading: &str) -> String {
    // GitHub's slug: lowercase, drop punctuation (keep word characters, '-' and spaces), spaces become '-'
    let lowered = heading.to_lowercase().replace('`', "");
    let kept: String = lowered.chars().filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == ' ').collect();
    kept.trim().replace(' ', "-")
}

#[test]
fn table_of_contents_links_exist() {
    for (name, text) in [("README.md", &*README), ("README.pt-BR.md", &*README_PT)] {
        let headings: BTreeSet<String> = re(r"(?m)^#{2,3} (.+)$").captures_iter(text).map(|m| anchor(&m[1])).collect();
        for link in re(r"\]\(#([^)]+)\)").captures_iter(text) {
            assert!(headings.contains(&link[1]), "{name}: no heading for the link #{}", &link[1]);
        }
    }
}

#[test]
fn readmes_link_each_other_and_the_same_files() {
    assert!(README.contains("README.pt-BR.md"));
    assert!(README_PT.contains("README.md"));
    let local = re(r"\]\(((?:[^h#)][^)]*|h[^t][^)]*))\)");
    for (name, text) in [("README.md", &*README), ("README.pt-BR.md", &*README_PT)] {
        for m in local.captures_iter(text) {
            let target = m[1].split('#').next().unwrap().to_string();
            if target.is_empty() || target.starts_with("http") {
                continue;
            }
            assert!(root().join(&target).exists(), "{name} links to a file that does not exist: {target}");
        }
    }
}

// ---------------------------------------------------------------------------
// 8. Facts written in 20+ places (ChromeOS Flex and friends)
// ---------------------------------------------------------------------------
fn gb(value: &str) -> f64 {
    value.replace(',', ".").parse().unwrap()
}

/// Every text where a fact may be written: the program (code and texts) and the documents.
fn corpus() -> Vec<(&'static str, String)> {
    vec![
        ("source", SOURCE.clone()),
        ("help", HELP.clone()),
        ("README.md", README.clone()),
        ("README.pt-BR.md", README_PT.clone()),
        ("SECURITY.md", SECURITY.clone()),
        ("CHANGELOG.md", CHANGELOG.clone()),
    ]
}

#[test]
fn usb_minimum_for_chromeos_flex() {
    // Google asks for "16 GB or larger"; a stick sold as 16 GB holds ~15.5e9 bytes, which is why the threshold in
    // bytes is lower than 16e9. The marketed size is the smallest standard size that is not below the threshold.
    let marketed =
        [4u64, 8, 16, 32, 64, 128, 256].into_iter().find(|s| s * 1_000_000_000 >= CHROMEOS_MIN_USB_BYTES).unwrap();
    assert!(
        CHROMEOS_MIN_USB_BYTES as f64 > (marketed * 1_000_000_000) as f64 * 0.85,
        "the threshold is far below the marketed size: is 15 GB still right?"
    );
    let pattern = re(r"(\d+) GB (?:or larger|ou maior)");
    let mut found = 0;
    for (name, text) in corpus() {
        for m in pattern.captures_iter(&squash(&text)) {
            found += 1;
            assert_eq!(m[1].parse::<u64>().unwrap(), marketed, "{name} says {} GB; the code says {marketed} GB", &m[1]);
        }
    }
    assert!(found > 8, "the scan found too few mentions of the drive minimum ({found})");
}

#[test]
fn large_drive_threshold() {
    let limit = LARGE_DISK_BYTES / 1024u64.pow(3);
    let pattern = re(r"(?i)(?:drives?|disks?|discos?)[^.;]{0,40}?(?:larger than|over|maior que|>)\s*(\d+) GB");
    let mut found = 0;
    for (name, text) in corpus() {
        for m in pattern.captures_iter(&squash(&text)) {
            found += 1;
            assert_eq!(m[1].parse::<u64>().unwrap(), limit, "{name} says {} GB for a large drive", &m[1]);
        }
    }
    assert!(found > 4, "the scan found too few mentions of the large-drive threshold ({found})");
}

#[test]
fn substantial_use_and_volume_thresholds_in_help() {
    let text = squash(&help_section("The drive and the Create button"));
    assert!(text.contains(&format!("{} GB or more in use", SUBSTANTIAL_USED_BYTES / 1024u64.pow(3))));
    assert!(text.contains(&format!("{MANY_VOLUMES} or more volumes")));
}

#[test]
fn download_and_image_sizes_match_the_measured_constants() {
    let constants = read(&["src", "constants.rs"]);
    let m = re(r"(?i)the ZIP is about ([\d.]+) GB and the image inside it about ([\d.]+) GB")
        .captures(&constants)
        .expect("the comment with the measured sizes next to CHROMEOS_FLEX_FREE_BYTES is gone");
    let (zip_gb, image_gb) = (gb(&m[1]), gb(&m[2]));
    let free_gb = CHROMEOS_FLEX_FREE_BYTES as f64 / 1e9;
    // both files are on disk at once, so the warning threshold must cover their sum
    assert!(free_gb >= zip_gb + image_gb);
    assert!(free_gb <= (zip_gb + image_gb) * 1.5, "the free-space threshold is far too generous");
    const { assert!(CHROMEOS_FLEX_FREE_BYTES < DISK_IMAGE_MAX_BYTES) };
    assert!(image_gb * 1e9 < DISK_IMAGE_MAX_BYTES as f64);
    // every "about X GB" the program or the help states is one of the two measured sizes
    let texts = [("help", squash(&help_section("ChromeOS Flex"))), ("source", SOURCE.clone())];
    let mut seen = 0;
    for (name, text) in &texts {
        for m in re(r"about ([\d.]+) GB").captures_iter(text) {
            if name == &"source" && !(m[1].contains('.')) {
                continue; // a comment about something else
            }
            seen += 1;
            let value = gb(&m[1]);
            assert!(value == zip_gb || value == image_gb, "{name} says about {value} GB");
        }
        for m in re(r"(?:roughly|about) (\d+) GB free").captures_iter(text) {
            assert_eq!(m[1].parse::<f64>().unwrap(), free_gb.round());
        }
    }
    assert!(seen >= 3, "the scan found too few size statements ({seen})");
    // the Portuguese text uses a decimal comma
    for (key, value) in epma_usb_creator::i18n::translations() {
        if key.contains("Not much free space") {
            continue;
        }
        for m in re(r"cerca de ([\d,]+) GB").captures_iter(value) {
            let v = gb(&m[1]);
            assert!(v == zip_gb || v == image_gb, "PT_BR says about {v} GB");
        }
    }
}

#[test]
fn rust_minimum_is_the_same_everywhere() {
    let cargo = read(&["Cargo.toml"]);
    let m = re(r#"(?m)^rust-version = "(\d+\.\d+)""#).captures(&cargo).expect("Cargo.toml states rust-version");
    let minimum = m[1].to_string();
    let checks: Vec<(&str, String, &str)> = vec![
        ("README.md badge", README.clone(), r"rust-(\d+\.\d+)%2B"),
        ("README.pt-BR.md badge", README_PT.clone(), r"rust-(\d+\.\d+)%2B"),
        ("README.md text", README.clone(), r"Rust (\d+\.\d+) or newer"),
        ("README.pt-BR.md text", README_PT.clone(), r"Rust (\d+\.\d+) ou mais novo"),
    ];
    for (name, text, pattern) in checks {
        for m in re(pattern).captures_iter(&text) {
            assert_eq!(&m[1], minimum, "{name} says Rust {}; Cargo.toml says {minimum}", &m[1]);
        }
        assert!(re(pattern).is_match(&text), "{name}: the Rust minimum is not stated");
    }
}

#[test]
fn project_address_is_the_same_everywhere() {
    let slug = PROJECT_URL.split("github.com/").nth(1).unwrap();
    let (owner, repo) = slug.split_once('/').unwrap();
    assert!(FORMULA.contains(&format!("homepage \"{PROJECT_URL}\"")));
    assert!(FORMULA.contains(&format!("head \"{PROJECT_URL}.git\"")));
    assert!(FORMULA.contains(&format!("url \"{PROJECT_URL}/archive/refs/tags/")));
    assert!(read(&[".github", "scripts", "make_sbom.py"]).contains(&format!("DEFAULT_REPO = \"{slug}\"")));
    assert!(read(&["Cargo.toml"]).contains(&format!("repository = \"{PROJECT_URL}\"")));
    let link = re(r"github\.com/([A-Za-z0-9-]+)/([A-Za-z0-9._-]+)");
    let files = [
        ("README.md", README.clone()),
        ("README.pt-BR.md", README_PT.clone()),
        ("SECURITY.md", SECURITY.clone()),
        ("CHANGELOG.md", CHANGELOG.clone()),
        ("Formula", FORMULA.clone()),
        ("source", read(&["src", "constants.rs"])),
        ("update-formula.sh", read(&["Formula", "update-formula.sh"])),
    ];
    let mut checked = 0;
    for (name, text) in &files {
        for m in link.captures_iter(text) {
            let found_repo = m[2].trim_end_matches(".git").trim_end_matches('.').to_string();
            if found_repo.to_lowercase().starts_with("epma-") {
                checked += 1;
                assert_eq!((&m[1], found_repo.as_str()), (owner, repo), "{name} links to another repository");
            }
        }
        for m in re(r"--repo (\S+)").captures_iter(text) {
            assert_eq!(&m[1], slug, "{name}: --repo points to another repository");
        }
    }
    assert!(checked > 8, "the scan found too few repository links ({checked})");
}

#[test]
fn homebrew_tap_name_is_consistent() {
    let tap = format!("{}/tap", PROJECT_URL.split('/').nth(3).unwrap());
    for (name, text) in [("README.md", &*README), ("README.pt-BR.md", &*README_PT), ("Formula", &*FORMULA)] {
        assert!(text.contains(&format!("brew tap {tap}")), "{name} does not show `brew tap {tap}`");
    }
}

#[test]
fn google_requirements_are_stated_alike() {
    // Computer requirements Google lists: 4 GB of RAM, 16 GB of storage.
    for (name, text) in [("help", squash(&help_section("ChromeOS Flex"))), ("README.md", squash(&README))] {
        assert!(text.contains("4 GB of RAM"), "{name}");
        assert!(text.contains("16 GB of internal storage"), "{name}");
    }
    assert!(README_PT.contains("4 GB de RAM"));
    assert!(README_PT.contains("16 GB de armazenamento interno"));
}

#[test]
fn urls_in_the_documents_are_the_constants() {
    for url in [CHROMEOS_FLEX_GUIDE_URL, CHROMEOS_FLEX_REQUIREMENTS_URL] {
        for (name, text) in [("README.md", &*README), ("README.pt-BR.md", &*README_PT), ("help", &*HELP)] {
            assert!(text.contains(url), "{name} does not contain {url}");
        }
    }
    assert!(SECURITY.contains(CHROMEOS_FLEX_URL));
    assert!(README.contains(CHROMEOS_FLEX_HOSTS[0]));
}

// ---------------------------------------------------------------------------
// Screenshots
// ---------------------------------------------------------------------------
#[test]
fn the_readmes_point_to_an_existing_screenshot() {
    for name in ["README.md", "README.pt-BR.md"] {
        let text = read(&[name]);
        let links: Vec<String> =
            re(r#"<img[^>]+src="([^"]+)""#).captures_iter(&text).map(|m| m[1].to_string()).collect();
        assert!(links.iter().any(|l| l == "docs/images/interface.png"), "{name}");
        for link in links {
            let path = root().join(&link);
            let bytes = std::fs::read(&path).unwrap_or_else(|_| panic!("{link} does not exist"));
            assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n", "{link} is not a PNG");
            assert!(bytes.len() < 1_500_000, "{link} is too big for a README");
        }
        assert!(!text.contains("alt=\"\""));
    }
}
