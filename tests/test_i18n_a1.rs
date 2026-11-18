//! Port (A1 part) of tests/test_i18n.py: the language lookup that reads the real environment, the process-wide
//! language switch, and the source-coverage check ("a text wrapped in tr() but forgotten in the table fails here
//! instead of silently showing English to a Portuguese user").
//!
//! The pure parts (detect_language values, tr / tr_fmt in both languages, the shape of the table, the formatter) are
//! unit tests inside `src/i18n.rs`, where the generated table is reachable.

mod common_a1;

use common_a1::ENV_LOCK;
use epma_usb_creator::constants::{ENV_LANG, LANG_EN, LANG_PT};
use epma_usb_creator::i18n::{
    active_language, detect_language, detect_language_from_env, fmt_named, set_active_language, tr, tr_fmt,
    translations, with_language,
};
use std::collections::HashSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

// ---- DetectLanguageTests (the ones that read os.environ) ----
#[test]
fn default_environment_is_the_process_environment() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved: Option<OsString> = std::env::var_os(ENV_LANG);
    std::env::set_var(ENV_LANG, "pt");
    let pt = detect_language_from_env();
    std::env::set_var(ENV_LANG, "en");
    let en = detect_language_from_env();
    std::env::remove_var(ENV_LANG);
    let unset = detect_language_from_env();
    match saved {
        Some(v) => std::env::set_var(ENV_LANG, v),
        None => std::env::remove_var(ENV_LANG),
    }
    assert_eq!((pt, en, unset), (LANG_PT, LANG_EN, LANG_EN));
}

#[test]
fn the_system_locale_is_never_used() {
    // The interface is always US English; a Portuguese system must not change it. (The Python passes whole
    // environments; here only EPMA_LANG is ever looked at, so the locale variables cannot matter.)
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let keys = ["LANG", "LC_ALL", "LC_MESSAGES", ENV_LANG];
    let saved: Vec<(&str, Option<OsString>)> = keys.iter().map(|k| (*k, std::env::var_os(k))).collect();
    std::env::remove_var(ENV_LANG);
    for (lang, lc_all) in [("pt_BR.UTF-8", "pt_BR"), ("pt", "pt_PT"), ("en_US.UTF-8", "C"), ("de_DE.UTF-8", "")] {
        std::env::set_var("LANG", lang);
        std::env::set_var("LC_ALL", lc_all);
        std::env::set_var("LC_MESSAGES", lc_all);
        assert_eq!(detect_language_from_env(), LANG_EN, "{lang} {lc_all}");
    }
    std::env::set_var("LANG", "en_US.UTF-8");
    std::env::set_var(ENV_LANG, "pt");
    assert_eq!(detect_language_from_env(), LANG_PT);
    for (key, value) in saved {
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }
}

#[test]
fn epma_lang_is_the_only_way_to_get_portuguese() {
    assert_eq!(detect_language(Some("en")), "en");
    assert_eq!(detect_language(Some("pt")), "pt");
    assert_eq!(detect_language(None), "en");
}

#[test]
fn the_test_suite_runs_in_english() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // this binary never sets EPMA_LANG for its own sake and never switches the global language outside this lock
    set_active_language("en");
    assert_eq!(active_language(), "en");
}

// ---- TranslateTests (the process-wide switch the window uses) ----
#[test]
fn set_active_language_switches_tr_for_every_thread() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    set_active_language("pt");
    let from_this_thread = tr("Cancel");
    let from_another = std::thread::spawn(|| tr("Cancel")).join().unwrap();
    set_active_language("en");
    let english = tr("Cancel");
    assert_eq!(
        (from_this_thread.as_str(), from_another.as_str(), english.as_str()),
        ("Cancelar", "Cancelar", "Cancel")
    );
}

#[test]
fn a_thread_override_wins_over_the_global_language() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    set_active_language("en");
    with_language("pt", || {
        assert_eq!(tr("Cancel"), "Cancelar");
        // another thread still sees the global (English) value
        assert_eq!(std::thread::spawn(|| tr("Cancel")).join().unwrap(), "Cancel");
    });
    assert_eq!(tr("Cancel"), "Cancel");
}

#[test]
fn format_after_translating() {
    with_language("pt", || {
        assert_eq!(tr_fmt("Could not list disks: {error}", &[("error", &"x")]), "Não foi possível listar os discos: x");
    });
    with_language("en", || {
        assert_eq!(tr_fmt("Missing: {tools}", &[("tools", &"rsync, parted")]), "Missing: rsync, parted");
    });
}

// ---- SourceCoverageTests ----
// "Every text the code passes to _()/tr() must have an entry in PT_BR." The Python test walks the syntax tree;
// this one scans the Rust sources for `tr("literal")` / `tr_fmt("literal", ...)` calls and unescapes the literal.

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The string literal that starts at `s[0] == '"'` (or a raw string), unescaped; `None` when it is not one.
fn parse_literal(s: &str) -> Option<String> {
    if let Some(raw) = s.strip_prefix('r') {
        let hashes = raw.chars().take_while(|c| *c == '#').count();
        let body = raw[hashes..].strip_prefix('"')?;
        let end = format!("\"{}", "#".repeat(hashes));
        return Some(body[..body.find(&end)?].to_string());
    }
    let mut chars = s.strip_prefix('"')?.chars().peekable();
    let mut out = String::new();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => match chars.next()? {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                '0' => out.push('\0'),
                '\\' => out.push('\\'),
                '"' => out.push('"'),
                '\'' => out.push('\''),
                '\n' => {
                    // line continuation: the newline and the indentation of the next line are dropped
                    while chars.peek().is_some_and(|c| c.is_whitespace()) {
                        chars.next();
                    }
                }
                'u' => {
                    let mut hex = String::new();
                    for h in chars.by_ref() {
                        if h == '{' {
                            continue;
                        }
                        if h == '}' {
                            break;
                        }
                        hex.push(h);
                    }
                    out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                }
                _ => return None,
            },
            c => out.push(c),
        }
    }
    None
}

fn translated_literals(source: &str) -> Vec<String> {
    let mut found = Vec::new();
    for name in ["tr(", "tr_fmt("] {
        let mut from = 0;
        while let Some(rel) = source[from..].find(name) {
            let at = from + rel;
            from = at + name.len();
            // a whole identifier: not `str(`, `ctr(`, `fn tr(`
            let before = source[..at].chars().last();
            if before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
                continue;
            }
            if source[..at].trim_end().ends_with("fn") {
                continue;
            }
            let arg = source[from..].trim_start();
            if arg.starts_with('"') || arg.starts_with("r\"") || arg.starts_with("r#") {
                if let Some(text) = parse_literal(arg) {
                    found.push(text);
                }
            }
        }
    }
    found
}

#[test]
fn every_literal_passed_to_translate_is_in_the_dictionary() {
    let mut files = Vec::new();
    rust_sources(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut files);
    assert!(!files.is_empty(), "no sources found");
    let known: HashSet<&str> = translations().iter().map(|(k, _)| *k).collect();
    let mut missing = Vec::new();
    let mut checked = 0;
    for file in files {
        if file.file_name().is_some_and(|n| n == "i18n_table.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&file).unwrap_or_default();
        // The unit tests of i18n.rs deliberately use made-up texts to test the fallback.
        let production = if file.ends_with("i18n.rs") { String::new() } else { text };
        for literal in translated_literals(&production) {
            checked += 1;
            if !known.contains(literal.as_str()) {
                missing.push(format!("{}: {:.70?}", file.display(), literal));
            }
        }
    }
    // The GUI (written by another agent) is what normally supplies the calls; before it exists there are none.
    eprintln!("checked {checked} translated literals");
    assert!(missing.is_empty(), "texts passed to tr() without a table entry:\n{}", missing.join("\n"));
}

#[test]
fn the_literal_scanner_itself_works() {
    let src = r#"
        let a = tr("Cancel");
        let b = tr_fmt("Could not list disks: {error}", &[("error", &e)]);
        let c = tr(
            "Two \
             lines\nand an escape \" quote");
        let d = tr(r"raw text");
        fn tr(text: &str) -> String { todo!() }
        let e = str("not translated");
        let f = tr(some_variable);
    "#;
    assert_eq!(
        translated_literals(src),
        vec![
            "Cancel".to_string(),
            "Two lines\nand an escape \" quote".to_string(),
            "raw text".to_string(),
            "Could not list disks: {error}".to_string()
        ]
    );
    assert_eq!(fmt_named("{a}", &[("a", &1)]), "1");
}
