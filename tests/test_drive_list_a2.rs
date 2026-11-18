//! The pure disk functions behind the drive list (diskrisk.rs: identity, label, volume line, risk, confirmation text).
//! tests/test_drive_list.py itself tests the window's DriveList widget and `drive_row_texts` (A8); the Python suite
//! covers these functions only through test_refactor_helpers.py (`_disk_entry`, ported in test_refactor_helpers_a2.rs)
//! and test_i18n.py (ported in test_i18n_a2.rs), so the rest is written from the Python docstrings and code.
//! English only: the translated texts are in test_i18n_a2.rs (the language is process-wide).

use epma_usb_creator::diskrisk::{
    assess_disk_risk, build_disk_label, describe_disk_for_confirmation, format_volume_line, identity_mismatch,
    make_identity, py_repr, py_repr_list, RiskLevel, LARGE_DISK_BYTES, MANY_VOLUMES, MAX_VOLUMES_SHOWN,
    SUBSTANTIAL_USED_BYTES,
};
use epma_usb_creator::types::{Disk, Volume, Volumes};

const GIB: u64 = 1024 * 1024 * 1024;

fn vol(name: &str, fs: &str, size: u64, used: Option<u64>, mountpoint: Option<&str>) -> Volume {
    Volume {
        name: (!name.is_empty()).then(|| name.to_string()),
        filesystem: (!fs.is_empty()).then(|| fs.to_string()),
        size: (size != 0).then_some(size),
        used,
        mountpoint: mountpoint.map(str::to_string),
    }
}

fn disk(size: u64, model: &str, volumes: Volumes) -> Disk {
    Disk {
        id: "disk9".into(),
        size,
        model: (!model.is_empty()).then(|| model.to_string()),
        volumes,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------------------------------------------
// the thresholds quoted by the help text
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn the_thresholds_are_the_documented_ones() {
    assert_eq!(LARGE_DISK_BYTES / GIB, 256);
    assert_eq!(SUBSTANTIAL_USED_BYTES / GIB, 16);
    assert_eq!(MANY_VOLUMES, 4);
    assert_eq!(MAX_VOLUMES_SHOWN, 8);
}

// ---------------------------------------------------------------------------------------------------------------
// identity
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn make_identity_sorts_and_drops_empty_values() {
    let id = make_identity(&[
        ("serial", Some("  123 ".to_string())),
        ("model", Some("Ultra".to_string())),
        ("wwn", None),
        ("uuid", Some("   ".to_string())),
        ("bus", Some(String::new())),
    ]);
    assert_eq!(id, [("model".to_string(), "Ultra".to_string()), ("serial".to_string(), "123".to_string())]);
    assert!(make_identity(&[]).is_empty());
}

#[test]
fn identity_mismatch_names_the_first_changed_identifier() {
    let a = make_identity(&[("model", Some("Fake".into())), ("serial", Some("ABC".into()))]);
    let same = a.clone();
    let other_serial = make_identity(&[("model", Some("Fake".into())), ("serial", Some("XYZ".into()))]);
    let gone = make_identity(&[("model", Some("Fake".into()))]);
    let more =
        make_identity(&[("model", Some("Fake".into())), ("serial", Some("ABC".into())), ("wwn", Some("5".into()))]);
    assert_eq!(identity_mismatch(&a, &same), None);
    assert_eq!(identity_mismatch(&a, &other_serial), Some("serial changed".to_string()));
    assert_eq!(
        identity_mismatch(&a, &gone),
        Some("serial changed".to_string()),
        "a recorded identifier must still be present"
    );
    assert_eq!(identity_mismatch(&a, &more), None, "identifiers that only show up now are ignored");
    assert_eq!(identity_mismatch(&a, &Vec::new()), Some("model changed".to_string()));
    // with no recorded identity there is nothing to compare
    assert_eq!(identity_mismatch(&Vec::new(), &other_serial), None);
    assert_eq!(identity_mismatch(&Vec::new(), &Vec::new()), None);
}

// ---------------------------------------------------------------------------------------------------------------
// repr (the Python repr of strings in labels and audit lines)
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn py_repr_matches_python() {
    assert_eq!(py_repr("abc"), "'abc'");
    assert_eq!(py_repr("it's"), "\"it's\"");
    assert_eq!(py_repr("say \"hi\""), "'say \"hi\"'");
    assert_eq!(py_repr("both ' and \""), "'both \\' and \"'");
    assert_eq!(py_repr("a\\b\nc\td\re"), "'a\\\\b\\nc\\td\\re'");
    assert_eq!(py_repr("nul\0 bell\u{7} del\u{7f}"), "'nul\\x00 bell\\x07 del\\x7f'");
    assert_eq!(py_repr("é — 日本"), "'é — 日本'");
    assert_eq!(py_repr(""), "''");
    assert_eq!(py_repr_list(&["a", "b'c"]), "['a', \"b'c\"]");
    assert_eq!(py_repr_list::<&str>(&[]), "[]");
}

// ---------------------------------------------------------------------------------------------------------------
// labels
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn the_label_shows_path_model_size_and_volumes() {
    let vols = [vol("A", "FAT32", 1, None, None), vol("B", "", 1, None, None)];
    assert_eq!(
        build_disk_label("/dev/disk4", Some("SanDisk Ultra"), 58 * GIB, Some(&vols)),
        "/dev/disk4 — SanDisk Ultra — 58.0 GB — 2 volumes ('A', 'B')"
    );
    assert_eq!(build_disk_label("/dev/sdb", None, 8 * GIB, Some(&[])), "/dev/sdb — 8.0 GB — no volumes");
    assert_eq!(build_disk_label("/dev/sdb", Some(""), 8 * GIB, None), "/dev/sdb — 8.0 GB — contents unknown");
}

#[test]
fn the_label_names_at_most_three_volumes_and_falls_back_to_the_filesystem() {
    let vols: Vec<Volume> = ["A", "B", "C", "D"].iter().map(|n| vol(n, "", 0, None, None)).collect();
    assert_eq!(
        build_disk_label("/dev/sdb", None, GIB, Some(&vols)),
        "/dev/sdb — 1.0 GB — 4 volumes ('A', 'B', 'C', …)"
    );
    let one = [vol("", "exFAT", 0, None, None)];
    assert_eq!(build_disk_label("/dev/sdb", None, GIB, Some(&one)), "/dev/sdb — 1.0 GB — 1 volume ('exFAT')");
    let none = [vol("", "", 0, None, None)];
    assert_eq!(build_disk_label("/dev/sdb", None, GIB, Some(&none)), "/dev/sdb — 1.0 GB — 1 volume ('unnamed')");
    let quoted = [vol("Bob's", "", 0, None, None)];
    assert_eq!(build_disk_label("/dev/sdb", None, GIB, Some(&quoted)), "/dev/sdb — 1.0 GB — 1 volume (\"Bob's\")");
}

// ---------------------------------------------------------------------------------------------------------------
// the volume line
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn a_volume_line_shows_filesystem_size_and_usage() {
    assert_eq!(
        format_volume_line(&vol("Untitled", "FAT32", 58 * GIB, Some(12 * GIB), Some("/Volumes/Untitled")), false),
        "Untitled (FAT32, 58.0 GB, 12.0 GB used)"
    );
    // not mounted: usage unknown
    assert_eq!(
        format_volume_line(&vol("Old", "HFS+", GIB, None, None), false),
        "Old (HFS+, 1.0 GB, not mounted, usage unknown)"
    );
    // mounted but usage unknown: nothing is said about it
    assert_eq!(format_volume_line(&vol("M", "NTFS", GIB, None, Some("/mnt")), false), "M (NTFS, 1.0 GB)");
    // used 0 is a known value
    assert_eq!(format_volume_line(&vol("E", "", 0, Some(0), Some("/mnt")), false), "E (0.0 B used)");
    // no name, nothing to say: "(unnamed)"
    assert_eq!(format_volume_line(&vol("", "", 0, None, Some("/mnt")), false), "(unnamed)");
    assert_eq!(format_volume_line(&vol("", "", 0, None, None), false), "(unnamed) (not mounted, usage unknown)");
}

// ---------------------------------------------------------------------------------------------------------------
// risk
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn a_small_plain_stick_is_normal_risk() {
    let d =
        disk(32 * GIB, "SanDisk Ultra", Volumes::List(vec![vol("Untitled", "FAT32", 30 * GIB, Some(GIB), Some("/m"))]));
    assert_eq!(assess_disk_risk(&d, false), (RiskLevel::Normal, Vec::new()));
    assert_eq!(RiskLevel::Normal.as_str(), "normal");
    assert_eq!(RiskLevel::High.as_str(), "high");
}

#[test]
fn a_disk_that_was_not_inspected_is_not_penalised_but_one_that_failed_is() {
    let not_inspected = disk(32 * GIB, "", Volumes::NotInspected);
    assert_eq!(assess_disk_risk(&not_inspected, false).0, RiskLevel::Normal);
    let unknown = disk(32 * GIB, "", Volumes::Unknown);
    let (level, reasons) = assess_disk_risk(&unknown, false);
    assert_eq!(level, RiskLevel::High);
    assert_eq!(reasons, ["What is stored on it could not be read, so there is no way to tell what would be lost."]);
}

#[test]
fn a_large_disk_is_high_risk_only_above_the_threshold() {
    let at = disk(LARGE_DISK_BYTES, "", Volumes::List(vec![]));
    assert_eq!(assess_disk_risk(&at, false).0, RiskLevel::Normal);
    let above = disk(LARGE_DISK_BYTES + 1, "", Volumes::List(vec![]));
    let (level, reasons) = assess_disk_risk(&above, false);
    assert_eq!(level, RiskLevel::High);
    assert_eq!(
        reasons,
        ["It is large (256.0 GB); installer sticks are usually much smaller. This may be an external hard disk or SSD."]
    );
}

#[test]
fn the_model_name_can_suggest_an_external_disk() {
    for model in [
        "WD My Passport 25E2",
        "Seagate Expansion",
        "Samsung Portable SSD T7",
        "Generic external",
        "LaCie Rugged",
        "Canvio Basics",
        "Backup Plus Slim",
    ] {
        let (level, reasons) = assess_disk_risk(&disk(GIB, model, Volumes::List(vec![])), false);
        assert_eq!(level, RiskLevel::High, "{model}");
        assert_eq!(reasons, [format!("Its model name ({model}) suggests an external hard disk or SSD.")]);
    }
    for model in ["SanDisk Ultra", "Kingston DataTraveler", "Cruzer Glide"] {
        assert_eq!(assess_disk_risk(&disk(GIB, model, Volumes::List(vec![])), false).0, RiskLevel::Normal, "{model}");
    }
}

#[test]
fn a_lot_of_data_in_use_is_high_risk() {
    let used = disk(
        64 * GIB,
        "",
        Volumes::List(vec![vol("A", "", 0, Some(10 * GIB), None), vol("B", "", 0, Some(6 * GIB), None)]),
    );
    let (level, reasons) = assess_disk_risk(&used, false);
    assert_eq!(level, RiskLevel::High);
    assert_eq!(reasons, ["It holds a lot of data (16.0 GB in use)."]);
    let below = disk(64 * GIB, "", Volumes::List(vec![vol("A", "", 0, Some(16 * GIB - 1), None)]));
    assert_eq!(assess_disk_risk(&below, false).0, RiskLevel::Normal);
}

#[test]
fn volume_names_that_suggest_personal_data_are_named_at_most_three() {
    let names = ["Time Machine Backups", "Fotos 2023", "my data", "Documents", "Untitled"];
    let vols: Vec<Volume> = names.iter().map(|n| vol(n, "", 0, None, Some("/m"))).collect();
    let (level, reasons) = assess_disk_risk(&disk(GIB, "", Volumes::List(vols[..3].to_vec())), false);
    assert_eq!(level, RiskLevel::High);
    assert_eq!(
        reasons,
        ["Volume name(s) suggest personal data or backups: 'Time Machine Backups', 'Fotos 2023', 'my data'."]
    );
    let (_, reasons) = assess_disk_risk(&disk(GIB, "", Volumes::List(vols.clone())), false);
    assert_eq!(
        reasons[0],
        "Volume name(s) suggest personal data or backups: 'Time Machine Backups', 'Fotos 2023', 'my data'."
    );
    // "data" has to be a word of its own; plain names are fine
    assert_eq!(
        assess_disk_risk(
            &disk(GIB, "", Volumes::List(vec![vol("metadata", "", 0, None, None), vol("WIN11USB", "", 0, None, None)])),
            false
        )
        .0,
        RiskLevel::Normal
    );
}

#[test]
fn many_volumes_are_unusual_for_a_stick() {
    let vols: Vec<Volume> = (0..4).map(|i| vol(&format!("P{i}"), "", 0, None, None)).collect();
    let (level, reasons) = assess_disk_risk(&disk(GIB, "", Volumes::List(vols.clone())), false);
    assert_eq!(level, RiskLevel::High);
    assert_eq!(reasons, ["It has 4 volumes, which is unusual for a USB stick."]);
    assert_eq!(assess_disk_risk(&disk(GIB, "", Volumes::List(vols[..3].to_vec())), false).0, RiskLevel::Normal);
}

#[test]
fn every_reason_is_listed_in_order() {
    let vols = vec![
        vol("Backup", "", 0, Some(20 * GIB), None),
        vol("B", "", 0, None, None),
        vol("C", "", 0, None, None),
        vol("D", "", 0, None, None),
    ];
    let (level, reasons) = assess_disk_risk(&disk(300 * GIB, "My Book", Volumes::List(vols)), false);
    assert_eq!(level, RiskLevel::High);
    assert_eq!(reasons.len(), 5);
    assert!(reasons[0].starts_with("It is large"));
    assert!(reasons[1].starts_with("Its model name"));
    assert!(reasons[2].starts_with("It holds a lot of data"));
    assert!(reasons[3].starts_with("Volume name(s)"));
    assert!(reasons[4].starts_with("It has 4 volumes"));
}

// ---------------------------------------------------------------------------------------------------------------
// the confirmation text
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn the_confirmation_lists_model_size_and_every_volume() {
    let d = Disk {
        id: "disk4".into(),
        size: 58 * GIB,
        model: Some("SanDisk Ultra".into()),
        volumes: Volumes::List(vec![
            vol("Untitled", "FAT32", 58 * GIB, Some(12 * GIB), Some("/m")),
            vol("Old", "HFS+", GIB, None, None),
        ]),
        ..Default::default()
    };
    assert_eq!(
        describe_disk_for_confirmation(&d, false),
        "Drive: /dev/disk4\nModel: SanDisk Ultra\nSize: 58.0 GB\nContents that will be DESTROYED:\n  - Untitled (FAT32, 58.0 GB, 12.0 GB used)\n  - Old (HFS+, 1.0 GB, not mounted, usage unknown)"
    );
}

#[test]
fn the_confirmation_handles_unknown_and_empty_contents() {
    let mut d = disk(8 * GIB, "", Volumes::Unknown);
    d.id = "sdb".into();
    assert_eq!(describe_disk_for_confirmation(&d, false), "Drive: /dev/sdb\nSize: 8.0 GB\nContents: could not be read");
    // a disk that was never inspected reads the same (the Python `disk.get("volumes")` is None either way)
    d.volumes = Volumes::NotInspected;
    assert!(describe_disk_for_confirmation(&d, false).ends_with("Contents: could not be read"));
    d.volumes = Volumes::List(vec![]);
    assert_eq!(
        describe_disk_for_confirmation(&d, false),
        "Drive: /dev/sdb\nSize: 8.0 GB\nContents: no volumes found (the drive looks empty)"
    );
}

#[test]
fn the_confirmation_shows_at_most_eight_volumes() {
    let vols: Vec<Volume> = (0..11).map(|i| vol(&format!("V{i}"), "", 0, None, Some("/m"))).collect();
    let text = describe_disk_for_confirmation(&disk(GIB, "", Volumes::List(vols)), false);
    assert!(text.contains("  - V7"));
    assert!(!text.contains("  - V8"));
    assert!(text.ends_with("  - ... and 3 more"), "{text}");
}
