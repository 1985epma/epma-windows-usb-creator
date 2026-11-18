//! Text helpers of the window: translation with Python-style `{name}` / `{name:.1f}` / `{name:02d}` placeholders,
//! and the few pure helpers of other modules the window uses for its texts (`human_size`, the ETA tail, `dev_path`).
//!
//! Outside tests every function here forwards to the real module (`i18n`, `util`, `validate`). Under `cfg(test)` the
//! helpers use small self-contained implementations (the Python semantics) so the window's logic tests run on their
//! own, whatever state the other modules are in; the language of the tests is a thread-local (`set_test_language`).

use std::fmt::Write as _;

/// One argument of a template: the Python `.format(name=value)` keyword.
#[derive(Clone, Debug, PartialEq)]
pub enum Arg {
    S(String),
    I(i64),
    F(f64),
}

impl From<&str> for Arg {
    fn from(v: &str) -> Self {
        Arg::S(v.to_string())
    }
}
impl From<String> for Arg {
    fn from(v: String) -> Self {
        Arg::S(v)
    }
}
impl From<&String> for Arg {
    fn from(v: &String) -> Self {
        Arg::S(v.clone())
    }
}
impl From<std::path::PathBuf> for Arg {
    fn from(v: std::path::PathBuf) -> Self {
        Arg::S(v.to_string_lossy().into_owned())
    }
}
impl From<&std::path::Path> for Arg {
    fn from(v: &std::path::Path) -> Self {
        Arg::S(v.to_string_lossy().into_owned())
    }
}
impl From<u64> for Arg {
    fn from(v: u64) -> Self {
        Arg::I(v as i64)
    }
}
impl From<usize> for Arg {
    fn from(v: usize) -> Self {
        Arg::I(v as i64)
    }
}
impl From<i64> for Arg {
    fn from(v: i64) -> Self {
        Arg::I(v)
    }
}
impl From<i32> for Arg {
    fn from(v: i32) -> Self {
        Arg::I(v as i64)
    }
}
impl From<f64> for Arg {
    fn from(v: f64) -> Self {
        Arg::F(v)
    }
}

fn render(arg: &Arg, spec: &str) -> String {
    // spec: [0][width][.precision][f|d]
    let mut rest = spec;
    let zero = rest.starts_with('0');
    if zero {
        rest = &rest[1..];
    }
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    rest = &rest[digits.len()..];
    let width: usize = digits.parse().unwrap_or(0);
    let mut precision: Option<usize> = None;
    if let Some(r) = rest.strip_prefix('.') {
        let p: String = r.chars().take_while(|c| c.is_ascii_digit()).collect();
        precision = p.parse().ok();
        rest = &r[p.len()..];
    }
    let kind = rest.chars().next();
    let mut out = String::new();
    match (arg, kind) {
        (Arg::F(v), Some('f')) => {
            let _ = write!(out, "{:.*}", precision.unwrap_or(6), v);
        }
        (Arg::I(v), Some('f')) => {
            let _ = write!(out, "{:.*}", precision.unwrap_or(6), *v as f64);
        }
        (Arg::I(v), _) => {
            let _ = write!(out, "{v}");
        }
        (Arg::F(v), _) => {
            let _ = write!(out, "{v}");
        }
        (Arg::S(s), _) => out.push_str(s),
    }
    let len = out.chars().count();
    if len < width {
        let pad = width - len;
        if zero && !matches!(arg, Arg::S(_)) {
            let (sign, body) = match out.strip_prefix('-') {
                Some(b) => ("-", b.to_string()),
                None => ("", out.clone()),
            };
            return format!("{sign}{}{body}", "0".repeat(pad));
        }
        if matches!(arg, Arg::S(_)) {
            return format!("{out}{}", " ".repeat(pad));
        }
        return format!("{}{out}", " ".repeat(pad));
    }
    out
}

/// Substitute `{name}` placeholders (with the optional Python format spec) in `template`; `{{` and `}}` are literal
/// braces. An unknown name is left as it is.
pub fn format_template(template: &str, args: &[(&str, Arg)]) -> String {
    let mut out = String::with_capacity(template.len() + 16);
    let chars: Vec<char> = template.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '{' {
            if chars.get(i + 1) == Some(&'{') {
                out.push('{');
                i += 2;
                continue;
            }
            if let Some(end) = chars[i + 1..].iter().position(|&x| x == '}') {
                let inner: String = chars[i + 1..i + 1 + end].iter().collect();
                let (name, spec) = match inner.split_once(':') {
                    Some((n, s)) => (n, s),
                    None => (inner.as_str(), ""),
                };
                if let Some((_, arg)) = args.iter().find(|(k, _)| *k == name) {
                    out.push_str(&render(arg, spec));
                } else {
                    out.push('{');
                    out.push_str(&inner);
                    out.push('}');
                }
                i += end + 2;
                continue;
            }
        } else if c == '}' && chars.get(i + 1) == Some(&'}') {
            out.push('}');
            i += 2;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// `_("text")`: the text in the active language.
pub fn tr(text: &str) -> String {
    #[cfg(test)]
    {
        test_tr(text)
    }
    #[cfg(not(test))]
    {
        crate::i18n::tr(text)
    }
}

/// `_("text").format(name=value, ...)`: translate, then substitute the placeholders.
pub fn trf(text: &str, args: &[(&str, Arg)]) -> String {
    format_template(&tr(text), args)
}

/// `"text".format(...)` without translating (English texts of the engine side).
pub fn fmt(template: &str, args: &[(&str, Arg)]) -> String {
    format_template(template, args)
}

/// `trf!("... {name} ...", name = value, ...)`.
#[macro_export]
macro_rules! gui_trf {
    ($text:expr $(, $k:ident = $v:expr)* $(,)?) => {
        $crate::gui::tx::trf($text, &[$((stringify!($k), $crate::gui::tx::Arg::from($v))),*])
    };
}

/// `"...".format(name=value)` for English literals.
#[macro_export]
macro_rules! gui_fmt {
    ($text:expr $(, $k:ident = $v:expr)* $(,)?) => {
        $crate::gui::tx::fmt($text, &[$((stringify!($k), $crate::gui::tx::Arg::from($v))),*])
    };
}

/// "58.6 GB" style size.
pub fn human_size(n: u64) -> String {
    #[cfg(test)]
    {
        test_human_size(n as f64)
    }
    #[cfg(not(test))]
    {
        crate::util::human_size(n)
    }
}

/// `human_size` of a (fractional) speed in bytes per second.
pub fn human_size_f(n: f64) -> String {
    let n = if n.is_finite() && n > 0.0 { n } else { 0.0 };
    human_size(n as u64)
}

/// `_eta_remaining(done, total, speed)` (translated; "" when the speed is unknown).
pub fn eta_remaining(done: u64, total: u64, speed: f64) -> String {
    #[cfg(test)]
    {
        test_eta_remaining(done, total, speed)
    }
    #[cfg(not(test))]
    {
        crate::util::eta_remaining(done, total, speed, true)
    }
}

/// `_rate_tail(done, total, speed)`: " — 12.0 MB/s — ~2m05s left" ("" when the speed is unknown).
pub fn rate_tail(done: u64, total: u64, speed: f64) -> String {
    #[cfg(test)]
    {
        if speed.is_nan() || speed <= 0.0 {
            return String::new();
        }
        format!(" — {}/s — {}", human_size_f(speed), eta_remaining(done, total, speed))
    }
    #[cfg(not(test))]
    {
        crate::util::rate_tail(done, total, speed)
    }
}

/// How a disk identifier is shown: `/dev/disk4`, `/dev/sdb` or `\\.\PhysicalDrive3`.
pub fn dev_path(dev: &str) -> String {
    #[cfg(test)]
    {
        if crate::constants::IS_WINDOWS {
            format!("\\\\.\\{dev}")
        } else {
            format!("/dev/{dev}")
        }
    }
    #[cfg(not(test))]
    {
        crate::validate::dev_path(dev)
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Test-only implementations (the Python semantics), independent of the other modules
// ---------------------------------------------------------------------------------------------------------------
#[cfg(test)]
thread_local! {
    static TEST_LANG: std::cell::Cell<&'static str> = const { std::cell::Cell::new("en") };
}

/// Tests: switch the language of the calling thread ("en" or "pt").
#[cfg(test)]
pub fn set_test_language(lang: &'static str) {
    TEST_LANG.with(|l| l.set(lang));
}

#[cfg(test)]
fn test_tr(text: &str) -> String {
    if TEST_LANG.with(|l| l.get()) == "pt" {
        if let Some((_, v)) = crate::i18n_table::PT_BR.iter().find(|(k, _)| *k == text) {
            return (*v).to_string();
        }
    }
    text.to_string()
}

#[cfg(test)]
fn test_human_size(n: f64) -> String {
    let mut n = n;
    for unit in ["B", "KB", "MB", "GB", "TB"] {
        if n < 1024.0 {
            return format!("{n:.1} {unit}");
        }
        n /= 1024.0;
    }
    format!("{n:.1} PB")
}

#[cfg(test)]
fn test_eta_remaining(done: u64, total: u64, speed: f64) -> String {
    if speed.is_nan() || speed <= 0.0 {
        return String::new();
    }
    let remaining = (total as f64 - done as f64) / speed;
    if remaining < 0.0 {
        return String::new();
    }
    let seconds = remaining as u64;
    trf("~{minutes}m{seconds:02d}s left", &[("minutes", (seconds / 60).into()), ("seconds", (seconds % 60).into())])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_with_python_specs() {
        let s = format_template(
            "{done} / {total} ({pct:.1f}%) — {speed}/s — {eta}",
            &[
                ("done", "1.0 KB".into()),
                ("total", "2.0 KB".into()),
                ("pct", 50.0f64.into()),
                ("speed", "3 B".into()),
                ("eta", "x".into()),
            ],
        );
        assert_eq!(s, "1.0 KB / 2.0 KB (50.0%) — 3 B/s — x");
        assert_eq!(format_template("~{minutes}m{seconds:02d}s left", &[("minutes", 1u64.into()), ("seconds", 5u64.into())]), "~1m05s left");
        assert_eq!(format_template("{pct:.0f}%", &[("pct", 49.6f64.into())]), "50%");
        assert_eq!(format_template("{{a}} {x}", &[("x", "b".into())]), "{a} b");
        assert_eq!(format_template("{unknown}", &[]), "{unknown}");
    }

    #[test]
    fn eta_is_minutes_and_seconds() {
        assert_eq!(eta_remaining(0, 72000, 10.0), "~120m00s left");
        assert_eq!(eta_remaining(500, 1000, 0.0), "");
        set_test_language("pt");
        assert_eq!(eta_remaining(500, 1000, 10.0), "faltam ~0m50s");
        set_test_language("en");
    }
}
