//! Port (A1 part) of tests/test_fixes_gui.py: the pure helpers that file checks without a window (the Windows volume
//! id pattern, content-based image detection). The EtaText and ValidateIsoPathWording classes are in
//! test_refactor_helpers_a1.rs and test_validation_a1.rs.

mod common_a1;

use common_a1::{Tmp, MIB};
use epma_usb_creator::isoinfo::{detect_iso_kind, is_windows_volume_id};
use epma_usb_creator::types::IsoKind;

// ---- WindowsVolumeIdTests ----
#[test]
fn microsoft_volume_ids_match() {
    for vid in [
        "CCCOMA_X64FRE_EN-US_DV9",
        "WIN11_23H2",
        "Win10_22H2_EnglishInternational_x64",
        "Win11_24H2_English_x64",
        "WIN11",
        "WINDOWS_SERVER_2022",
        "WIN7SP1",
        "CCSA_X86FRE_EN-US_DV5",
    ] {
        assert!(is_windows_volume_id(&vid.to_uppercase()), "{vid}");
    }
}

#[test]
fn other_volume_ids_do_not_match() {
    for vid in [
        "Ubuntu 24.04 LTS amd64",
        "ARCH_202610",
        "Fedora-WS-Live-41",
        "DEBIAN 12",
        "WINE_11",
        "WIN100",
        "Linux Mint 22",
        "TAILS 6.0",
        "GPARTED-LIVE",
    ] {
        assert!(!is_windows_volume_id(&vid.to_uppercase()), "{vid}");
    }
}

// ---- ImageTypeChoiceTests (the detection part) ----
/// A file with an ISO 9660 primary volume descriptor (what every real ISO has).
fn make_pvd_iso(t: &Tmp, name: &str, volume_id: &str, hybrid: bool) -> std::path::PathBuf {
    let mut data = vec![0u8; 2 * MIB];
    let pvd = 16 * 2048;
    data[pvd..pvd + 7].copy_from_slice(b"\x01CD001\x01");
    let mut vid = [b' '; 32];
    let n = volume_id.len().min(32); // the field is 32 bytes wide
    vid[..n].copy_from_slice(&volume_id.as_bytes()[..n]);
    data[pvd + 40..pvd + 72].copy_from_slice(&vid);
    data[pvd + 128..pvd + 130].copy_from_slice(&2048u16.to_le_bytes());
    if hybrid {
        data[510..512].copy_from_slice(&[0x55, 0xaa]);
    }
    t.write_file(name, &data)
}

#[test]
fn volume_ids_are_detected_as_windows() {
    let t = Tmp::new();
    for vid in ["CCCOMA_X64FRE_EN-US_DV9", "WIN11_23H2", "Win10_22H2_EnglishInternational_x64"] {
        let path = make_pvd_iso(&t, "w.iso", vid, false);
        assert_eq!(detect_iso_kind(path), IsoKind::Windows, "{vid}");
    }
    for vid in ["Ubuntu 24.04 LTS amd64", "ARCH_202610"] {
        let path = make_pvd_iso(&t, "l.iso", vid, true);
        assert_eq!(detect_iso_kind(path), IsoKind::Linux, "{vid}");
    }
}

#[test]
fn unknown_content_stays_unknown_whatever_the_name_says() {
    let t = Tmp::new();
    // not hybrid, no descriptor: the name (darwin-linux.img / win11-notes.img) must not matter
    for name in ["darwin-linux.img", "win11-notes.img"] {
        let path = t.make_iso(name, 2 * MIB, false);
        assert_eq!(detect_iso_kind(path), IsoKind::Unknown, "{name}");
    }
}

#[test]
fn known_content_still_preselects() {
    let t = Tmp::new();
    let path = make_pvd_iso(&t, "ubuntu.iso", "Ubuntu 24.04 LTS amd64", true);
    assert_eq!(detect_iso_kind(path), IsoKind::Linux);
    // the kinds map to a mode and a card that agree (ModeTableTests of test_refactor_helpers.py)
    for kind in [IsoKind::Windows, IsoKind::Linux, IsoKind::ChromeOs] {
        let (mode, card) = (kind.mode().unwrap(), kind.card().unwrap());
        assert_eq!(card.mode(), mode);
    }
    assert!(IsoKind::Unknown.mode().is_none());
}
