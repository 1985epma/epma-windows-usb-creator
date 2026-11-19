//! The macOS image type: how a macOS disk image is recognised, what is refused before a drive is erased, and how the
//! type is wired into the shared enums. New in the Rust build (the Python program has no such image type).
//!
//! Nothing here touches a device: the images are small files in a temporary directory.

mod common_a1;

use common_a1::{gpt_image, random_bytes, Tmp, MIB};
use epma_usb_creator::engine::validate_image_for_mode;
use epma_usb_creator::isoinfo::detect_iso_kind;
use epma_usb_creator::types::{Card, Error, IsoKind, Mode};
use epma_usb_creator::validate::{validate_disk_image, validate_macos_image};

/// GPT partition type GUIDs in their on-disk byte order.
const HFS_PLUS: [u8; 16] =
    [0x00, 0x53, 0x46, 0x48, 0x00, 0x00, 0xAA, 0x11, 0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC];
const APFS: [u8; 16] = [0xEF, 0x57, 0x34, 0x7C, 0x00, 0x00, 0xAA, 0x11, 0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC];
const APPLE_BOOT: [u8; 16] =
    [0x74, 0x6F, 0x6F, 0x42, 0x00, 0x00, 0xAA, 0x11, 0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC];
const CORE_STORAGE: [u8; 16] =
    [0x72, 0x6F, 0x74, 0x53, 0x67, 0x61, 0xAA, 0x11, 0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC];
/// EFI System Partition (C12A7328-F81F-11D2-BA4B-00A0C93EC93B): what an OpenCore disk has next to its Apple partitions.
const EFI_SYSTEM: [u8; 16] =
    [0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B];

/// A whole-disk image: protective MBR, a GPT, and one entry per partition type in `types`.
fn gpt_disk(types: &[[u8; 16]]) -> Vec<u8> {
    let mut data = gpt_image(&[], 2 * MIB, true);
    for (i, kind) in types.iter().enumerate() {
        let at = 1024 + i * 128;
        data[at..at + 16].copy_from_slice(kind);
        data[at + 16..at + 32].copy_from_slice(&[(i + 1) as u8; 16]); // unique GUID
    }
    data
}

/// A compressed .dmg as far as the program can tell: no boot signature, and the 512-byte "koly" trailer at the end.
fn compressed_dmg() -> Vec<u8> {
    let mut data = random_bytes(2 * MIB, 5);
    data[510..512].copy_from_slice(&[0, 0]);
    let at = data.len() - 512;
    data[at..at + 4].copy_from_slice(b"koly");
    data
}

/// A hybrid ISO 9660 image (a volume descriptor at 0x8000 and a boot signature) whose GPT also lists an HFS+
/// partition, as some distributions' ISOs do for Macs.
fn hybrid_iso_with_an_apple_partition() -> Vec<u8> {
    let mut data = vec![0u8; 2 * MIB];
    data[0x8000] = 1;
    data[0x8001..0x8006].copy_from_slice(b"CD001");
    data[0x8006] = 1;
    data[0x8000 + 40..0x8000 + 72].fill(b' ');
    data[0x8000 + 40..0x8000 + 46].copy_from_slice(b"MYDISC");
    data[0x8000 + 128..0x8000 + 130].copy_from_slice(&2048u16.to_le_bytes());
    data[510..512].copy_from_slice(&[0x55, 0xaa]);
    data[512..520].copy_from_slice(b"EFI PART");
    data[1024..1040].copy_from_slice(&HFS_PLUS);
    data
}

fn message(err: Error) -> String {
    err.to_string()
}

// ---- detection ----

#[test]
fn a_gpt_disk_with_an_apple_partition_is_a_macos_image() {
    common_a1::init();
    let tmp = Tmp::new();
    for (name, kind) in
        [("hfs.img", HFS_PLUS), ("apfs.img", APFS), ("boot.img", APPLE_BOOT), ("core.img", CORE_STORAGE)]
    {
        let path = tmp.write_file(name, &gpt_disk(&[kind]));
        assert_eq!(detect_iso_kind(&path), IsoKind::MacOs, "{name}");
    }
}

#[test]
fn an_opencore_style_disk_with_an_efi_partition_and_an_apple_one_is_a_macos_image() {
    common_a1::init();
    let tmp = Tmp::new();
    let path = tmp.write_file("opencore.img", &gpt_disk(&[EFI_SYSTEM, APPLE_BOOT, APFS]));
    assert_eq!(detect_iso_kind(&path), IsoKind::MacOs);
}

#[test]
fn a_disk_with_no_apple_partition_is_not_called_macos() {
    common_a1::init();
    let tmp = Tmp::new();
    let path = tmp.write_file("efi-only.img", &gpt_disk(&[EFI_SYSTEM]));
    assert_eq!(detect_iso_kind(&path), IsoKind::Unknown);
    // and a ChromeOS image is still a ChromeOS image
    let chromeos = tmp.write_file("flex.bin", &gpt_image(&common_a1::CHROMEOS_NAMES, 2 * MIB, true));
    assert_eq!(detect_iso_kind(&chromeos), IsoKind::ChromeOs);
}

#[test]
fn a_dmg_is_recognised_by_its_trailer() {
    common_a1::init();
    let tmp = Tmp::new();
    let path = tmp.write_file("installer.dmg", &compressed_dmg());
    assert_eq!(detect_iso_kind(&path), IsoKind::MacOs);
}

#[test]
fn a_hybrid_iso_that_lists_an_apple_partition_stays_a_linux_image() {
    common_a1::init();
    let tmp = Tmp::new();
    let path = tmp.write_file("distro.iso", &hybrid_iso_with_an_apple_partition());
    assert_eq!(detect_iso_kind(&path), IsoKind::Linux);
}

#[test]
fn random_data_and_tiny_files_are_not_macos() {
    common_a1::init();
    let tmp = Tmp::new();
    let noise = tmp.write_file("noise.bin", &random_bytes(2 * MIB, 11));
    assert_eq!(detect_iso_kind(&noise), IsoKind::Unknown);
    let tiny = tmp.write_file("tiny.bin", b"koly");
    assert_eq!(detect_iso_kind(&tiny), IsoKind::Unknown);
    let missing = tmp.path("nope.img");
    assert_eq!(detect_iso_kind(&missing), IsoKind::Unknown);
}

// ---- validation ----

#[test]
fn a_whole_disk_image_passes_validation() {
    common_a1::init();
    let tmp = Tmp::new();
    let path = tmp.write_file("macos.img", &gpt_disk(&[EFI_SYSTEM, HFS_PLUS]));
    validate_macos_image(&path).expect("a GPT disk with a boot signature");
}

#[test]
fn a_compressed_dmg_is_refused_with_the_command_that_converts_it() {
    common_a1::init();
    let tmp = Tmp::new();
    let path = tmp.write_file("installer.dmg", &compressed_dmg());
    let text = message(validate_macos_image(&path).unwrap_err());
    assert!(text.contains("hdiutil convert"), "{text}");
    assert!(text.contains("-format UDRW"), "{text}");
    assert!(text.contains("createinstallmedia"), "{text}");
}

#[test]
fn a_file_without_a_partition_table_is_refused() {
    common_a1::init();
    let tmp = Tmp::new();
    let path = tmp.write_file(
        "volume.img",
        &random_bytes(2 * MIB, 3)
            .iter()
            .enumerate()
            .map(|(i, b)| if (510..512).contains(&i) { 0 } else { *b })
            .collect::<Vec<u8>>(),
    );
    let text = message(validate_macos_image(&path).unwrap_err());
    assert!(text.contains("no partition table"), "{text}");
}

#[test]
fn a_zip_is_refused_with_a_hint() {
    common_a1::init();
    let tmp = Tmp::new();
    let mut data = random_bytes(2 * MIB, 4);
    data[..4].copy_from_slice(b"PK\x03\x04");
    data[510..512].copy_from_slice(&[0, 0]);
    let path = tmp.write_file("image.zip", &data);
    let text = message(validate_macos_image(&path).unwrap_err());
    assert!(text.contains("ZIP archive"), "{text}");
}

#[test]
fn the_engine_validates_the_macos_mode_before_anything_else() {
    common_a1::init();
    let tmp = Tmp::new();
    let bad = tmp.write_file("volume.img", &vec![0u8; 2 * MIB]);
    let text = message(validate_image_for_mode(&bad, Mode::MacOs, None).unwrap_err());
    assert!(text.contains("no partition table"), "{text}");
    let dmg = tmp.write_file("installer.dmg", &compressed_dmg());
    assert!(message(validate_image_for_mode(&dmg, Mode::MacOs, None).unwrap_err()).contains("hdiutil convert"));
    // too big for the drive: refused with the shared message, after the image itself was accepted
    let good = tmp.write_file("macos.img", &gpt_disk(&[APFS]));
    let text = message(validate_image_for_mode(&good, Mode::MacOs, Some(MIB as u64)).unwrap_err());
    assert!(text.contains("larger than the drive"), "{text}");
}

#[cfg(unix)]
#[test]
fn the_engine_accepts_a_whole_disk_image_in_the_macos_mode() {
    common_a1::init();
    let tmp = Tmp::new();
    let good = tmp.write_file("macos.img", &gpt_disk(&[APFS]));
    let resolved = validate_image_for_mode(&good, Mode::MacOs, Some(64 * MIB as u64)).expect("accepted");
    assert!(resolved.ends_with("macos.img"));
}

#[test]
fn the_chromeos_check_still_says_chromeos() {
    // the macOS check is its own: it must not have changed what the ChromeOS card tells the user
    common_a1::init();
    let tmp = Tmp::new();
    let path = tmp.write_file("not-flex.bin", &vec![0u8; 2 * MIB]);
    assert!(message(validate_disk_image(&path).unwrap_err()).contains("ChromeOS Flex"));
}

// ---- the shared enums ----

#[test]
fn the_macos_type_is_wired_into_modes_kinds_and_cards() {
    assert_eq!(Mode::parse("macos"), Some(Mode::MacOs));
    assert_eq!(Mode::MacOs.as_str(), "macos");
    assert!(Mode::ALL.contains(&Mode::MacOs));
    assert!(Mode::MacOs.is_image_mode() && Mode::MacOs.is_raw());
    assert_eq!(IsoKind::MacOs.as_str(), "macos");
    assert_eq!(IsoKind::MacOs.mode(), Some(Mode::MacOs));
    assert_eq!(IsoKind::MacOs.card(), Some(Card::Mac));
    assert_eq!(Card::Mac.mode(), Mode::MacOs);
    assert_eq!(Card::Mac.as_str(), "mac");
    assert!(Card::ORDER.contains(&Card::Mac));
}
