//! The plan of a drive-writing command (Python `_disk_summary`, `_write_steps`, `_print_plan` and the plan dict that
//! `--dry-run --json` prints). A plan is built before anything is touched and is what the user confirms.

use super::io::{obj, Env, J};
use crate::constants::VOL_NAME;
use crate::types::{Disk, Hardening, Identity, Mode, SeedTarget};
use crate::util::human_size;
use crate::validate::dev_path;

/// `_disk_summary(disk)`: the scalar fields of a listed disk plus its human-readable size.
#[derive(Clone, Debug, PartialEq)]
pub struct DiskSummary {
    pub id: String,
    pub size: u64,
    pub label: String,
    pub model: Option<String>,
    pub size_human: String,
}

impl DiskSummary {
    pub fn of(disk: &Disk) -> DiskSummary {
        DiskSummary {
            id: disk.id.clone(),
            size: disk.size,
            label: disk.label.clone(),
            model: disk.model.clone(),
            size_human: human_size(disk.size),
        }
    }

    pub fn json(&self) -> J {
        obj(vec![
            ("id", J::str(&self.id)),
            ("size", J::int(self.size)),
            ("label", J::str(&self.label)),
            ("model", J::opt_str(self.model.as_deref())),
            ("size_human", J::str(&self.size_human)),
        ])
    }
}

/// What a write will do. `mode` is `Mode::Seed` for `harden-seed` (then `target`, `volume_label` and `files` are set
/// and there is no ISO).
#[derive(Clone, Debug)]
pub struct Plan {
    pub iso: Option<String>,
    pub iso_size: u64,
    pub mode: Mode,
    pub target: Option<SeedTarget>,
    pub volume_label: Option<String>,
    pub files: Vec<String>,
    pub disk: DiskSummary,
    /// Stable identifiers of the listed drive, kept for the safety re-check right before erasing.
    pub identity: Identity,
    pub steps: Vec<String>,
    pub eject: bool,
    pub dry_run: bool,
    pub hardening: Hardening,
    pub hardening_files: Vec<String>,
}

impl Plan {
    /// The plan as `--dry-run --json` prints it (the identity, a list of pairs, shown as an object). The key order is
    /// the order the Python plan dicts were built in.
    pub fn json(&self) -> J {
        let identity = J::Map(self.identity.iter().map(|(k, v)| (k.clone(), J::str(v))).collect());
        let mut pairs = vec![
            ("iso", J::opt_str(self.iso.as_deref())),
            ("iso_size", J::int(self.iso_size)),
            ("mode", J::str(self.mode.as_str())),
        ];
        if self.mode == Mode::Seed {
            pairs.push(("target", J::opt_str(self.target.map(|t| t.as_str()))));
            pairs.push(("volume_label", J::opt_str(self.volume_label.as_deref())));
            pairs.push(("files", J::strings(&self.files)));
        }
        pairs.push(("disk", self.disk.json()));
        pairs.push(("identity", identity));
        pairs.push(("steps", J::strings(&self.steps)));
        pairs.push(("eject", J::Bool(self.eject)));
        pairs.push(("dry_run", J::Bool(self.dry_run)));
        pairs.push(("hardening", J::str(self.hardening.as_str())));
        pairs.push(("hardening_files", J::strings(&self.hardening_files)));
        obj(pairs)
    }
}

/// `_write_steps(mode, disk_id, eject, hardening_files)`.
pub fn write_steps(mode: Mode, disk_id: &str, eject: bool, hardening_files: &[String]) -> Vec<String> {
    let dev = dev_path(disk_id);
    let mut steps = vec![format!("Re-check that {dev} is still the listed USB drive")];
    if mode.is_raw() {
        steps.push(format!("Unmount {dev} and write the image to it byte for byte"));
        steps.push("Read the drive back and compare it with the image".to_string());
    } else {
        steps.push(format!("Erase {dev} and format it as GPT + FAT32 ('{VOL_NAME}')"));
        steps.push("Copy the ISO contents (install.wim is split when it exceeds 4 GB)".to_string());
        steps.push("Verify the copied files against the ISO".to_string());
        if !hardening_files.is_empty() {
            let at = steps.len() - 1;
            steps.insert(at, format!("Add the Hardened (recommended settings) files: {}", hardening_files.join(", ")));
        }
    }
    steps.push(if eject {
        "Eject the drive".to_string()
    } else {
        "Leave the drive connected (--no-eject)".to_string()
    });
    steps
}

/// The steps of `harden-seed`.
pub fn seed_steps(disk_id: &str, label: &str, names: &[String], eject: bool) -> Vec<String> {
    let dev = dev_path(disk_id);
    vec![
        format!("Re-check that {dev} is still the listed USB drive"),
        format!("Erase {dev} and format it as GPT + FAT32 ('{label}')"),
        format!("Copy {} seed files: {}", names.len(), names.join(", ")),
        "Read the drive back and compare every file byte for byte".to_string(),
        if eject { "Eject the drive".to_string() } else { "Leave the drive connected (--no-eject)".to_string() },
    ]
}

/// `_print_plan(plan, to_stdout)`.
pub fn print_plan(env: &Env, plan: &Plan, to_stdout: bool) {
    let emit = |text: &str| if to_stdout { env.out(text) } else { env.err(text) };
    let disk = &plan.disk;
    emit("Plan");
    emit(format!("  Disk : {}  {}  {}", dev_path(&disk.id), disk.size_human, disk.label).trim_end());
    if let Some(model) = disk.model.as_deref().filter(|m| !m.is_empty()) {
        emit(&format!("  Model: {model}"));
    }
    if plan.mode == Mode::Seed {
        emit(&format!(
            "  Seed : {} (volume label {})",
            plan.target.map(|t| t.as_str()).unwrap_or(""),
            plan.volume_label.as_deref().unwrap_or("")
        ));
        emit(&format!("  Files: {}", plan.files.join(", ")));
    } else {
        emit(&format!("  ISO  : {} ({})", plan.iso.as_deref().unwrap_or(""), human_size(plan.iso_size)));
    }
    emit(&format!("  Mode : {}", plan.mode.as_str()));
    if !plan.hardening_files.is_empty() {
        emit(&format!("  Extra: Hardened (recommended settings): {}", plan.hardening_files.join(", ")));
    }
    emit("  Steps:");
    for (i, step) in plan.steps.iter().enumerate() {
        emit(&format!("    {}. {step}", i + 1));
    }
}
