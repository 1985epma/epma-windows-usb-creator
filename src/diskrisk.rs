//! Disk description and risk assessment (pure functions: no I/O, unit-testable). OWNER: A2.
//! Port of win11_usb_creator.py lines 2138-2287.
//!
//! A disk record always has `id`, `size`, `label`. The listing code adds, when it can: `model` (vendor + product
//! name, e.g. "SanDisk Ultra"), `volumes` (what is on the drive; `Volumes::Unknown` = could not be inspected) and
//! `identity` (stable identifiers: serial, WWN, DiskUUID, model).

use crate::i18n::{fmt_named, tr, tr_fmt};
use crate::types::{Disk, Identity, Volume, Volumes};
use crate::util::human_size;
use crate::validate::dev_path;
use regex::Regex;
use std::fmt::Display;
use std::sync::LazyLock;

/// Bigger than this is more likely a backup disk than a stick.
pub const LARGE_DISK_BYTES: u64 = 256 * 1024 * 1024 * 1024;
/// An old installer stick holds ~6 GB; more means real data.
pub const SUBSTANTIAL_USED_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const MANY_VOLUMES: usize = 4;
pub const MAX_VOLUMES_SHOWN: usize = 8;

static DATA_VOLUME_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)back\s*-?up|bkp|time\s*machine|archive|arquivo|photos?|fotos?|document|dados|\bdata\b|storage|media|movies|music|clone|vault|\bhd\b|\bfiles\b",
    )
    .expect("DATA_VOLUME_NAME_RE is a valid regex")
});
static DATA_DRIVE_MODEL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)passport|elements|expansion|backup\s*plus|my\s*book|canvio|portable|\bssd\b|\bhdd\b|external|rugged",
    )
    .expect("DATA_DRIVE_MODEL_RE is a valid regex")
});

/// The two risk levels of `assess_disk_risk` ("high" / "normal").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RiskLevel {
    High,
    Normal,
}

impl RiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            RiskLevel::High => "high",
            RiskLevel::Normal => "normal",
        }
    }
}

/// Python's `repr()` of a `str` (what the Python code puts in labels, audit lines and messages with `{x!r}`).
pub fn py_repr(s: &str) -> String {
    // Python picks double quotes only when the text holds a single quote and no double quote.
    let quote = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if c.is_control() => {
                let n = c as u32;
                if n <= 0xff {
                    out.push_str(&format!("\\x{n:02x}"));
                } else if n <= 0xffff {
                    out.push_str(&format!("\\u{n:04x}"));
                } else {
                    out.push_str(&format!("\\U{n:08x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Python's `repr()` of a list of `str`: `['a', 'b']`.
pub fn py_repr_list<S: AsRef<str>>(items: &[S]) -> String {
    let inner: Vec<String> = items.iter().map(|s| py_repr(s.as_ref())).collect();
    format!("[{}]", inner.join(", "))
}

/// `make_identity(**parts)`: sorted `(key, value)` pairs, empty / None values dropped.
pub fn make_identity(parts: &[(&str, Option<String>)]) -> Identity {
    let mut out: Identity = parts
        .iter()
        .filter_map(|(k, v)| {
            let v = v.as_deref()?.trim();
            (!v.is_empty()).then(|| ((*k).to_string(), v.to_string()))
        })
        .collect();
    out.sort();
    out
}

/// How `actual` differs from `expected` ("serial changed"), or None when it is the same drive.
///
/// Every identifier recorded at listing time must still be present and equal. Identifiers that only show up now
/// are ignored. With no recorded identity there is nothing to compare.
pub fn identity_mismatch(expected: &Identity, actual: &Identity) -> Option<String> {
    for (key, value) in expected {
        let now = actual.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v);
        if now != Some(value) {
            return Some(format!("{key} changed"));
        }
    }
    None
}

/// `_` when the text is for the GUI, a pass-through for engine/CLI callers (always English).
fn text_for(translate: bool, text: &str) -> String {
    if translate {
        tr(text)
    } else {
        text.to_string()
    }
}

/// `_(text).format(**args)` with the same translate switch.
fn text_fmt(translate: bool, text: &str, args: &[(&str, &dyn Display)]) -> String {
    if translate {
        tr_fmt(text, args)
    } else {
        fmt_named(text, args)
    }
}

/// One human-readable line describing a volume, e.g. 'Untitled (FAT32, 58.0 GB, 12.3 GB used)'.
///
/// `translate = true` is for the GUI dialogs only; the default of the callers keeps the English text.
pub fn format_volume_line(vol: &Volume, translate: bool) -> String {
    let mut bits: Vec<String> = Vec::new();
    if let Some(fs) = vol.filesystem.as_deref().filter(|f| !f.is_empty()) {
        bits.push(fs.to_string());
    }
    if let Some(size) = vol.size.filter(|s| *s != 0) {
        bits.push(human_size(size));
    }
    if let Some(used) = vol.used {
        bits.push(text_fmt(translate, "{size} used", &[("size", &human_size(used))]));
    } else if vol.mountpoint.is_none() {
        bits.push(text_for(translate, "not mounted, usage unknown"));
    }
    let name = match vol.name.as_deref().filter(|n| !n.is_empty()) {
        Some(n) => n.to_string(),
        None => text_for(translate, "(unnamed)"),
    };
    if bits.is_empty() {
        name
    } else {
        format!("{name} ({})", bits.join(", "))
    }
}

/// The text shown in the drive list: `/dev/disk4 — SanDisk Ultra — 58.6 GB — 2 volumes ('A', 'B')`.
/// `volumes`: None = could not be inspected.
pub fn build_disk_label(dev_path: &str, model: Option<&str>, size: u64, volumes: Option<&[Volume]>) -> String {
    let mut parts: Vec<String> = vec![dev_path.to_string()];
    if let Some(m) = model.filter(|m| !m.is_empty()) {
        parts.push(m.to_string());
    }
    parts.push(human_size(size));
    match volumes {
        None => parts.push("contents unknown".to_string()),
        Some([]) => parts.push("no volumes".to_string()),
        Some(vols) => {
            let mut names: Vec<String> = vols
                .iter()
                .take(3)
                .map(|v| {
                    let shown = v
                        .name
                        .as_deref()
                        .filter(|n| !n.is_empty())
                        .or(v.filesystem.as_deref().filter(|f| !f.is_empty()))
                        .unwrap_or("unnamed");
                    py_repr(shown)
                })
                .collect();
            if vols.len() > 3 {
                names.push("…".to_string());
            }
            let noun = if vols.len() == 1 { "volume" } else { "volumes" };
            parts.push(format!("{} {} ({})", vols.len(), noun, names.join(", ")));
        }
    }
    parts.join(" — ")
}

/// `_disk_entry`: the record the drive list holds for one disk (label built here from `validate::dev_path`).
pub fn disk_entry(
    dev_id: &str,
    size: u64,
    model: Option<&str>,
    volumes: Option<Vec<Volume>>,
    identity: Identity,
) -> Disk {
    let label = build_disk_label(&dev_path(dev_id), model, size, volumes.as_deref());
    Disk {
        id: dev_id.to_string(),
        size,
        label,
        model: model.map(str::to_string),
        volumes: match volumes {
            Some(list) => Volumes::List(list),
            None => Volumes::Unknown,
        },
        identity,
    }
}

/// `(level, reasons)`: High needs the identifier typed before the drive can be erased.
///
/// High means "this does not look like a spare USB stick": it is large, holds a lot of data, has a name that
/// suggests backups/personal data, looks like an external HDD/SSD, has many partitions, or its contents could not
/// be read. A disk without a `volumes` entry (not inspected at all) is not penalised for that; `Volumes::Unknown`
/// (inspection failed) is. `translate = true` (GUI dialogs only) words the reasons in the active language.
pub fn assess_disk_risk(disk: &Disk, translate: bool) -> (RiskLevel, Vec<String>) {
    let mut reasons: Vec<String> = Vec::new();
    let size = disk.size;
    if size > LARGE_DISK_BYTES {
        reasons.push(text_fmt(
            translate,
            "It is large ({size}); installer sticks are usually much smaller. This may be an external hard disk or SSD.",
            &[("size", &human_size(size))],
        ));
    }
    let model = disk.model.as_deref().unwrap_or("");
    if !model.is_empty() && DATA_DRIVE_MODEL_RE.is_match(model) {
        reasons.push(text_fmt(
            translate,
            "Its model name ({model}) suggests an external hard disk or SSD.",
            &[("model", &model)],
        ));
    }
    match &disk.volumes {
        Volumes::NotInspected => {}
        Volumes::Unknown => reasons.push(text_for(
            translate,
            "What is stored on it could not be read, so there is no way to tell what would be lost.",
        )),
        Volumes::List(volumes) => {
            let used: u64 = volumes.iter().map(|v| v.used.unwrap_or(0)).sum();
            if used >= SUBSTANTIAL_USED_BYTES {
                reasons.push(text_fmt(
                    translate,
                    "It holds a lot of data ({size} in use).",
                    &[("size", &human_size(used))],
                ));
            }
            let named: Vec<&str> = volumes
                .iter()
                .filter_map(|v| v.name.as_deref())
                .filter(|n| !n.is_empty() && DATA_VOLUME_NAME_RE.is_match(n))
                .collect();
            if !named.is_empty() {
                let shown: Vec<String> = named.iter().take(3).map(|n| py_repr(n)).collect();
                reasons.push(text_fmt(
                    translate,
                    "Volume name(s) suggest personal data or backups: {names}.",
                    &[("names", &shown.join(", "))],
                ));
            }
            if volumes.len() >= MANY_VOLUMES {
                reasons.push(text_fmt(
                    translate,
                    "It has {count} volumes, which is unusual for a USB stick.",
                    &[("count", &volumes.len())],
                ));
            }
        }
    }
    let level = if reasons.is_empty() { RiskLevel::Normal } else { RiskLevel::High };
    (level, reasons)
}

/// Multi-line summary (model, size, every volume with its used space) for the final confirmation.
///
/// `translate = true` is for the GUI dialog only; the callers' default keeps the English text.
pub fn describe_disk_for_confirmation(disk: &Disk, translate: bool) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(text_fmt(translate, "Drive: {path}", &[("path", &dev_path(&disk.id))]));
    if let Some(model) = disk.model.as_deref().filter(|m| !m.is_empty()) {
        lines.push(text_fmt(translate, "Model: {model}", &[("model", &model)]));
    }
    lines.push(text_fmt(translate, "Size: {size}", &[("size", &human_size(disk.size))]));
    match &disk.volumes {
        // A disk dict without the key and one with `None` both read as "could not be read" here.
        Volumes::NotInspected | Volumes::Unknown => lines.push(text_for(translate, "Contents: could not be read")),
        Volumes::List(volumes) if volumes.is_empty() => {
            lines.push(text_for(translate, "Contents: no volumes found (the drive looks empty)"))
        }
        Volumes::List(volumes) => {
            lines.push(text_for(translate, "Contents that will be DESTROYED:"));
            lines.extend(
                volumes.iter().take(MAX_VOLUMES_SHOWN).map(|v| format!("  - {}", format_volume_line(v, translate))),
            );
            if volumes.len() > MAX_VOLUMES_SHOWN {
                lines.push(text_fmt(
                    translate,
                    "  - ... and {count} more",
                    &[("count", &(volumes.len() - MAX_VOLUMES_SHOWN))],
                ));
            }
        }
    }
    lines.join("\n")
}
