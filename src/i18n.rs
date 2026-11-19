//! Internationalization (GUI texts only). OWNER: A1. Port of win11_usb_creator.py lines 284-653.
//! The table is `crate::i18n_table::PT_BR` (generated; do not retype it).
//!
//! English is the default and the source language. Brazilian Portuguese is looked up in the table (English text ->
//! Portuguese text); an unknown text falls back to the English one, so a missing translation can never break the
//! program. Only text the GUI shows to the user goes through `tr` / `tr_fmt`: engine and CLI output, error messages,
//! the audit log, shell scripts and anything code or tests match by substring stay in English on purpose.
//! Placeholders use the `{name}` subset of Python's `str.format` and must be identical in both languages:
//! translate first, then format (`tr_fmt` does both). Portuguese is used only when `EPMA_LANG=pt` is set; the system
//! locale (LC_ALL / LANG) is never consulted.

use crate::constants::{ENV_LANG, LANG_EN, LANG_PT};
use crate::i18n_table::PT_BR;
use crate::util::py_strip;
use std::cell::Cell;
use std::collections::HashMap;
use std::fmt::Display;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::LazyLock;

/// The language decided once at startup: 0 = not decided yet, 1 = English, 2 = Portuguese.
static ACTIVE: AtomicU8 = AtomicU8::new(0);
const CODE_EN: u8 = 1;
const CODE_PT: u8 = 2;

thread_local! {
    /// A per-thread language that wins over the global one (`with_language`): lets tests run in parallel threads
    /// without touching each other, where the Python tests patched the module global.
    static THREAD_OVERRIDE: Cell<Option<u8>> = const { Cell::new(None) };
}

/// The English text -> Portuguese text lookup table (built once from the generated slice).
static TABLE: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| PT_BR.iter().copied().collect());

/// `detect_language(env)`: "en" (US English) unless Portuguese is requested explicitly. `epma_lang` is the value of
/// the `EPMA_LANG` variable (`None` when unset).
///
/// The interface is always in English. The system locale (LANG, LC_*) is deliberately NOT consulted: only
/// `EPMA_LANG=pt` (or `pt-BR`, case-insensitive) switches the window to Brazilian Portuguese. Any other value, or
/// none, means English. Returns `LANG_EN` or `LANG_PT`.
pub fn detect_language(epma_lang: Option<&str>) -> &'static str {
    let forced = py_strip(epma_lang.unwrap_or(""));
    if forced.to_lowercase().starts_with("pt") {
        LANG_PT
    } else {
        LANG_EN
    }
}

/// `detect_language()` with the real environment (`os.environ`).
pub fn detect_language_from_env() -> &'static str {
    let value = std::env::var_os(ENV_LANG).map(|v| v.to_string_lossy().into_owned());
    detect_language(value.as_deref())
}

fn code_of(lang: &str) -> u8 {
    if lang == LANG_PT {
        CODE_PT
    } else {
        CODE_EN
    }
}

fn active_code() -> u8 {
    // try_with: `tr` may run while a thread is shutting down (a Drop), when the thread-local is already gone.
    if let Some(code) = THREAD_OVERRIDE.try_with(|c| c.get()).ok().flatten() {
        return code;
    }
    let code = ACTIVE.load(Ordering::Relaxed);
    if code != 0 {
        return code;
    }
    let decided = code_of(detect_language_from_env());
    // Another thread may have decided (or `set_active_language` been called) in the meantime: that value wins.
    match ACTIVE.compare_exchange(0, decided, Ordering::Relaxed, Ordering::Relaxed) {
        Ok(_) => decided,
        Err(existing) => existing,
    }
}

/// The language decided once at startup (from the real environment) unless `set_active_language` changed it.
pub fn active_language() -> &'static str {
    if active_code() == CODE_PT {
        LANG_PT
    } else {
        LANG_EN
    }
}

/// For the window and for tests (the Python tests patch ACTIVE_LANGUAGE). Anything but "pt" selects English.
pub fn set_active_language(lang: &'static str) {
    ACTIVE.store(code_of(lang), Ordering::Relaxed);
}

/// Run `f` with `lang` as the active language for the current thread only, then restore the previous one. Meant for
/// tests that run in parallel threads (the global `set_active_language` would leak into the other tests).
pub fn with_language<R>(lang: &'static str, f: impl FnOnce() -> R) -> R {
    struct Restore(Option<u8>);
    impl Drop for Restore {
        fn drop(&mut self) {
            THREAD_OVERRIDE.with(|c| c.set(self.0));
        }
    }
    let _restore = Restore(THREAD_OVERRIDE.with(|c| c.replace(Some(code_of(lang)))));
    f()
}

/// The generated English -> Portuguese table (for tests and tools).
pub fn translations() -> &'static [(&'static str, &'static str)] {
    PT_BR
}

/// `_(text)`: the text in the active language; unknown texts (and English) come back unchanged.
pub fn tr(text: &str) -> String {
    if active_code() == CODE_PT {
        if let Some(translated) = TABLE.get(text) {
            return (*translated).to_string();
        }
    }
    text.to_string()
}

/// Translate, then substitute `{name}` placeholders: `tr_fmt("{size} used", &[("size", &x)])`
/// (the Python `_("{size} used").format(size=x)`).
pub fn tr_fmt(text: &str, args: &[(&str, &dyn Display)]) -> String {
    fmt_named(&tr(text), args)
}

/// Substitute `{name}` placeholders without translating (`"...".format(...)` on an English literal).
///
/// Supports what the program's texts use of Python's `str.format`: `{name}`, `{{` / `}}`, and a format spec
/// `{name:[[fill]align][sign][0][width][.precision][type]}` with type `d f s x X b o` (`{pct:.1f}`,
/// `{seconds:02d}`). The arguments are formatted through `Display`, so a number is re-read from its text for a
/// numeric spec. A name that was not supplied, or a spec that does not fit the value, leaves the placeholder as it
/// is (the Python raises there); this function never panics.
pub fn fmt_named(template: &str, args: &[(&str, &dyn Display)]) -> String {
    let mut out = String::with_capacity(template.len() + 16);
    let mut rest = template;
    while let Some(pos) = rest.find(['{', '}']) {
        out.push_str(&rest[..pos]);
        let tail = &rest[pos..];
        if let Some(after) = tail.strip_prefix("{{") {
            out.push('{');
            rest = after;
        } else if let Some(after) = tail.strip_prefix("}}") {
            out.push('}');
            rest = after;
        } else if tail.starts_with('{') {
            match tail.find('}') {
                Some(end) => {
                    match render_field(&tail[1..end], args) {
                        Some(text) => out.push_str(&text),
                        None => out.push_str(&tail[..=end]),
                    }
                    rest = &tail[end + 1..];
                }
                None => {
                    // An unclosed "{": the Python raises ValueError; keep the text as it is.
                    out.push_str(tail);
                    rest = "";
                }
            }
        } else {
            out.push('}'); // a lone "}": the Python raises ValueError; keep it
            rest = &tail[1..];
        }
    }
    out.push_str(rest);
    out
}

/// One `{name}` / `{name:spec}` field. `None` when the name is unknown or the spec cannot be applied.
fn render_field(field: &str, args: &[(&str, &dyn Display)]) -> Option<String> {
    let (name_part, spec) = match field.split_once(':') {
        Some((n, s)) => (n, s),
        None => (field, ""),
    };
    // A conversion ("!s", "!r") is accepted and ignored: Display is the only rendering available.
    let name = name_part.split('!').next().unwrap_or(name_part);
    let value = args.iter().find(|(n, _)| *n == name)?.1.to_string();
    if spec.is_empty() {
        Some(value)
    } else {
        apply_spec(&value, spec)
    }
}

/// The parsed `[[fill]align][sign][0][width][.precision][type]` of a format spec.
struct Spec {
    fill: Option<char>,
    align: Option<char>,
    sign: Option<char>,
    zero: bool,
    width: usize,
    precision: Option<usize>,
    kind: Option<char>,
}

fn parse_spec(spec: &str) -> Option<Spec> {
    let chars: Vec<char> = spec.chars().collect();
    let is_align = |c: char| matches!(c, '<' | '>' | '^' | '=');
    let mut i = 0;
    let (mut fill, mut align) = (None, None);
    if chars.len() >= 2 && is_align(chars[1]) {
        fill = Some(chars[0]);
        align = Some(chars[1]);
        i = 2;
    } else if !chars.is_empty() && is_align(chars[0]) {
        align = Some(chars[0]);
        i = 1;
    }
    let mut sign = None;
    if i < chars.len() && matches!(chars[i], '+' | '-' | ' ') {
        sign = Some(chars[i]);
        i += 1;
    }
    let mut zero = false;
    if i < chars.len() && chars[i] == '0' {
        zero = true;
        i += 1;
    }
    let mut width = 0usize;
    while i < chars.len() && chars[i].is_ascii_digit() {
        width = width.checked_mul(10)?.checked_add(chars[i].to_digit(10)? as usize)?;
        i += 1;
    }
    let mut precision = None;
    if i < chars.len() && chars[i] == '.' {
        i += 1;
        let mut p = 0usize;
        let start = i;
        while i < chars.len() && chars[i].is_ascii_digit() {
            p = p.checked_mul(10)?.checked_add(chars[i].to_digit(10)? as usize)?;
            i += 1;
        }
        if i == start {
            return None; // "." without digits
        }
        precision = Some(p);
    }
    let kind = if i < chars.len() {
        let k = chars[i];
        i += 1;
        Some(k)
    } else {
        None
    };
    if i != chars.len() || width > 4096 || precision.is_some_and(|p| p > 4096) {
        return None;
    }
    Some(Spec { fill, align, sign, zero, width, precision, kind })
}

fn apply_spec(value: &str, spec: &str) -> Option<String> {
    let spec = parse_spec(spec)?;
    let trimmed = value.trim();
    // (text of the number or string, is_numeric)
    let (mut body, numeric) = match spec.kind {
        Some('d') => (trimmed.parse::<i128>().ok()?.to_string(), true),
        Some('f') | Some('F') => {
            let v: f64 = trimmed.parse().ok()?;
            (format!("{:.*}", spec.precision.unwrap_or(6), v), true)
        }
        // Python prints the magnitude with a minus sign (not two's complement).
        Some(k @ ('x' | 'X' | 'b' | 'o')) => {
            let n = trimmed.parse::<i128>().ok()?;
            let mag = n.unsigned_abs();
            let digits = match k {
                'x' => format!("{mag:x}"),
                'X' => format!("{mag:X}"),
                'b' => format!("{mag:b}"),
                _ => format!("{mag:o}"),
            };
            (if n < 0 { format!("-{digits}") } else { digits }, true)
        }
        Some('s') | None => {
            let text = match spec.precision {
                Some(p) => value.chars().take(p).collect::<String>(),
                None => value.to_string(),
            };
            // No type: Python right-aligns numbers and left-aligns strings; Display text hides which one this was.
            let numeric = spec.kind.is_none() && (trimmed.parse::<i128>().is_ok() || trimmed.parse::<f64>().is_ok());
            (text, numeric)
        }
        Some(_) => return None,
    };
    if numeric {
        match spec.sign {
            Some('+') if !body.starts_with('-') => body.insert(0, '+'),
            Some(' ') if !body.starts_with('-') => body.insert(0, ' '),
            _ => {}
        }
    }
    let len = body.chars().count();
    if len >= spec.width {
        return Some(body);
    }
    let pad = spec.width - len;
    // "0" in front of the width means fill "0" with sign-aware alignment, unless an alignment was given.
    let (fill, align) = match (spec.align, spec.zero) {
        (Some(a), _) => (spec.fill.unwrap_or(' '), a),
        (None, true) => ('0', '='),
        (None, false) => (' ', if numeric { '>' } else { '<' }),
    };
    let fill_str = |n: usize| fill.to_string().repeat(n);
    Some(match align {
        '<' => format!("{body}{}", fill_str(pad)),
        '^' => format!("{}{body}{}", fill_str(pad / 2), fill_str(pad - pad / 2)),
        '=' => {
            let sign_len = if body.starts_with(['-', '+', ' ']) { 1 } else { 0 };
            format!("{}{}{body_rest}", &body[..sign_len], fill_str(pad), body_rest = &body[sign_len..])
        }
        _ => format!("{}{body}", fill_str(pad)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn names(s: &str) -> Vec<String> {
        // The placeholders ({...}) of a text, in order: the Python tests compare them as sets.
        let mut out = Vec::new();
        let mut rest = s;
        while let Some(start) = rest.find('{') {
            match rest[start..].find('}') {
                Some(end) => {
                    out.push(rest[start..start + end + 1].to_string());
                    rest = &rest[start + end + 1..];
                }
                None => break,
            }
        }
        out
    }

    // ---- DetectLanguageTests ----
    #[test]
    fn default_is_english() {
        assert_eq!(detect_language(None), "en");
        assert_eq!(detect_language(Some("")), "en");
    }

    #[test]
    fn epma_lang_values() {
        for v in ["pt", "pt-BR", "PT-br", "pt_BR", " pt "] {
            assert_eq!(detect_language(Some(v)), "pt", "{v:?}");
        }
        for v in ["en", "EN", "en-US", "fr", "xx"] {
            assert_eq!(detect_language(Some(v)), "en", "{v:?}");
        }
    }

    // ---- TranslateTests ----
    #[test]
    fn english_returns_the_text_unchanged() {
        with_language("en", || {
            assert_eq!(tr("Cancel"), "Cancel");
            assert_eq!(tr("Writing the image..."), "Writing the image...");
        });
    }

    #[test]
    fn portuguese_returns_the_translation() {
        with_language("pt", || {
            assert_eq!(tr("Cancel"), "Cancelar");
            assert_eq!(tr("Writing the image..."), "Gravando a imagem...");
        });
    }

    #[test]
    fn unknown_text_falls_back_to_english() {
        for lang in ["en", "pt"] {
            with_language(lang, || {
                assert_eq!(tr("Text that nobody translated {x}"), "Text that nobody translated {x}");
                assert_eq!(tr(""), "");
            });
        }
    }

    #[test]
    fn format_after_translating() {
        with_language("pt", || {
            assert_eq!(
                tr_fmt("Could not list disks: {error}", &[("error", &"x")]),
                "Não foi possível listar os discos: x"
            );
        });
        with_language("en", || {
            assert_eq!(tr_fmt("Missing: {tools}", &[("tools", &"rsync, parted")]), "Missing: rsync, parted");
        });
    }

    #[test]
    fn same_input_gives_the_same_output() {
        with_language("pt", || {
            assert_eq!(tr("Copying files..."), tr("Copying files..."));
            assert_ne!(tr("Copying files..."), tr("Writing the image..."));
        });
    }

    #[test]
    fn with_language_restores_the_previous_value() {
        with_language("pt", || {
            with_language("en", || assert_eq!(active_language(), "en"));
            assert_eq!(active_language(), "pt");
        });
    }

    // ---- DictionaryTests ----
    #[test]
    fn dictionary_is_not_empty_and_entries_are_filled() {
        assert!(translations().len() > 50);
        for (key, value) in translations() {
            assert!(!key.trim().is_empty(), "empty key");
            assert!(!value.trim().is_empty(), "empty translation for {key:.60}");
        }
    }

    #[test]
    fn placeholders_match_the_english_text() {
        for (key, value) in translations() {
            let a: HashSet<String> = names(key).into_iter().collect();
            let b: HashSet<String> = names(value).into_iter().collect();
            assert_eq!(a, b, "placeholders differ for {key:.60}");
        }
    }

    #[test]
    fn translations_format_like_the_english_text() {
        // Catches stray or unbalanced braces: both must accept the same arguments, so with every placeholder
        // supplied nothing of the form {name} may be left behind in either text.
        for (key, value) in translations() {
            let all: HashSet<String> = names(key)
                .into_iter()
                .map(|p| p.trim_matches(|c| c == '{' || c == '}').split(':').next().unwrap_or("").to_string())
                .collect();
            let one: &dyn Display = &1;
            let args: Vec<(&str, &dyn Display)> = all.iter().map(|n| (n.as_str(), one)).collect();
            for text in [key, value] {
                let formatted = fmt_named(text, &args);
                assert!(!formatted.contains('{') && !formatted.contains('}'), "unformatted braces in {text:.80}");
            }
        }
    }

    #[test]
    fn no_duplicate_keys_in_the_table() {
        let mut seen = HashSet::new();
        for (key, _) in translations() {
            assert!(seen.insert(*key), "duplicate key {key:.60}");
        }
        assert_eq!(seen.len(), TABLE.len());
    }

    #[test]
    fn translation_is_really_different_text_for_prose() {
        // Most entries must differ from the English key; the few that may be equal are names, product names and
        // placeholder-only templates. (The Python test's `assertLessEqual(sorted(same), ["OK", "Windows 11"])` was
        // vacuous because of how lists compare; this checks the real list of the table.)
        let same: HashSet<&str> = translations().iter().filter(|(k, v)| k == v).map(|(k, _)| *k).collect();
        let expected: HashSet<&str> = [
            "OK",
            "{done} / {total} ({pct:.1f}%) — {speed}/s — {eta}",
            "SHA-256: {digest}",
            "USB",
            "1 volume ({names})",
            "{count} volumes ({names})",
            "Windows 11",
            "ChromeOS Flex",
            "Google Chrome",
            "macOS",
            "Linux",
            "Ubuntu, Fedora...",
            "Ubuntu (autoinstall)",
            "Fedora / RHEL (kickstart)",
            "Debian (script + preseed)",
        ]
        .into_iter()
        .collect();
        assert_eq!(same, expected);
    }

    // ---- the formatter ----
    #[test]
    fn fmt_named_substitutes_and_escapes() {
        assert_eq!(fmt_named("Hello {name}!", &[("name", &"Ada")]), "Hello Ada!");
        assert_eq!(fmt_named("{{literal}} {n}", &[("n", &3)]), "{literal} 3");
        assert_eq!(fmt_named("{a}{b}{a}", &[("a", &1), ("b", &"x")]), "1x1");
        assert_eq!(fmt_named("no placeholders", &[]), "no placeholders");
        assert_eq!(fmt_named("héllo {x} wörld", &[("x", &"é")]), "héllo é wörld");
    }

    #[test]
    fn fmt_named_never_panics_on_malformed_templates() {
        assert_eq!(fmt_named("{unknown}", &[]), "{unknown}");
        assert_eq!(fmt_named("open {brace", &[]), "open {brace");
        assert_eq!(fmt_named("lone } brace", &[]), "lone } brace");
        assert_eq!(fmt_named("{x:zzz}", &[("x", &1)]), "{x:zzz}");
        assert_eq!(fmt_named("{x:d}", &[("x", &"text")]), "{x:d}");
        assert_eq!(fmt_named("{}", &[]), "{}");
    }

    #[test]
    fn fmt_named_format_specs() {
        assert_eq!(fmt_named("{seconds:02d}", &[("seconds", &5)]), "05");
        assert_eq!(fmt_named("{seconds:02d}", &[("seconds", &45)]), "45");
        assert_eq!(fmt_named("{pct:.1f}%", &[("pct", &33.333333f64)]), "33.3%");
        assert_eq!(fmt_named("{pct:.0f}", &[("pct", &99.5f64)]), "100");
        assert_eq!(fmt_named("{pct:.1f}", &[("pct", &100)]), "100.0");
        assert_eq!(fmt_named("{x:5.1f}", &[("x", &2.25f64)]), "  2.2");
        assert_eq!(fmt_named("{x:<4}|", &[("x", &"ab")]), "ab  |");
        assert_eq!(fmt_named("{x:>4}|", &[("x", &"ab")]), "  ab|");
        assert_eq!(fmt_named("{x:^5}|", &[("x", &"ab")]), " ab  |");
        assert_eq!(fmt_named("{x:*^6}", &[("x", &"ab")]), "**ab**");
        assert_eq!(fmt_named("{x:04d}", &[("x", &-7)]), "-007");
        assert_eq!(fmt_named("{x:x}", &[("x", &255)]), "ff");
        // Python prints a negative number's magnitude with a minus sign, not two's complement
        assert_eq!(fmt_named("{x:x}", &[("x", &-255)]), "-ff");
        assert_eq!(fmt_named("{x:b}", &[("x", &-5)]), "-101");
        assert_eq!(fmt_named("{x:08b}", &[("x", &5)]), "00000101");
        assert_eq!(fmt_named("{x:.3}", &[("x", &"abcdef")]), "abc");
    }

    #[test]
    fn the_table_formats_with_real_values() {
        with_language("pt", || {
            let text = tr_fmt(
                "{done} / {total} ({pct:.1f}%) — {speed}/s — {eta}",
                &[
                    ("done", &"1.0 GB"),
                    ("total", &"2.0 GB"),
                    ("pct", &50.0f64),
                    ("speed", &"10 MB"),
                    ("eta", &"~1m05s"),
                ],
            );
            assert_eq!(text, "1.0 GB / 2.0 GB (50.0%) — 10 MB/s — ~1m05s");
            assert_eq!(tr_fmt("~{minutes}m{seconds:02d}s left", &[("minutes", &2), ("seconds", &5)]), "faltam ~2m05s");
        });
    }
}
