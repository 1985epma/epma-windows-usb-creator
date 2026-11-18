//! Port of the two tests of tests/test_i18n.py that exercise diskrisk.rs: the engine's texts stay English unless the
//! window asks for `translate`. They change the active language, which is process-wide, so this file holds nothing
//! else (a test binary of its own) and the two tests take a lock.

use epma_usb_creator::diskrisk::{assess_disk_risk, describe_disk_for_confirmation};
use epma_usb_creator::i18n::set_active_language;
use epma_usb_creator::types::{Disk, Volume, Volumes};
use std::sync::Mutex;

static LANGUAGE: Mutex<()> = Mutex::new(());

struct Language(&'static str, #[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

impl Language {
    fn set(code: &'static str) -> Language {
        let guard = LANGUAGE.lock().unwrap_or_else(|e| e.into_inner());
        set_active_language(code);
        Language(code, guard)
    }
}

impl Drop for Language {
    fn drop(&mut self) {
        let _ = self.0;
        set_active_language("en");
    }
}

const GIB: u64 = 1024 * 1024 * 1024;

#[test]
fn engine_text_stays_english_by_default() {
    let disk = Disk {
        id: "disk9".into(),
        size: 8 * GIB,
        model: Some("Fake Stick".into()),
        volumes: Volumes::List(vec![Volume {
            name: Some("Backup".into()),
            filesystem: Some("HFS+".into()),
            size: Some(GIB),
            used: None,
            mountpoint: None,
        }]),
        ..Default::default()
    };
    let _pt = Language::set("pt");
    let plain = describe_disk_for_confirmation(&disk, false);
    assert!(plain.contains("Contents that will be DESTROYED:"), "{plain}");
    assert!(plain.contains("not mounted, usage unknown"), "{plain}");
    let translated = describe_disk_for_confirmation(&disk, true);
    assert!(translated.contains("Conteúdo que será DESTRUÍDO:"), "{translated}");
    assert!(translated.contains("não montado, uso desconhecido"), "{translated}");
    assert!(!translated.contains("Contents that will be DESTROYED:"));
    assert_eq!(assess_disk_risk(&disk, false).0, assess_disk_risk(&disk, true).0);
    assert!(assess_disk_risk(&disk, false).1.join(" ").contains("suggest personal data or backups"));
    assert!(assess_disk_risk(&disk, true).1.join(" ").contains("sugere(m) dados pessoais"));
}

#[test]
fn translate_flag_in_english_is_identical() {
    let disk = Disk {
        id: "disk9".into(),
        size: 512 * GIB,
        model: Some("My Passport".into()),
        volumes: Volumes::Unknown,
        ..Default::default()
    };
    let _en = Language::set("en");
    assert_eq!(describe_disk_for_confirmation(&disk, false), describe_disk_for_confirmation(&disk, true));
    assert_eq!(assess_disk_risk(&disk, false), assess_disk_risk(&disk, true));
}
