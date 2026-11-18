//! The window's texts that depend on a choice or an outcome (pure functions; the Python `staticmethod`s of `App` and
//! the tables of the hardening part of the window).

use super::tx::{tr, trf};
use crate::types::SeedTarget;

/// Where the Windows hardening log is after Windows setup (`WINDOWS_HARDENING_LOG_SHOWN`).
pub const WINDOWS_HARDENING_LOG_SHOWN: &str = "C:\\Windows\\Temp\\epma-hardening.log";

/// `SEED_CHOICES`: each radio button of the Hardening seed card has a key; this table says which seed target the key
/// means for the engine (the keys are the target names).
pub const SEED_CHOICES: [(&str, SeedTarget); 4] = [
    ("ubuntu", SeedTarget::Ubuntu),
    ("fedora", SeedTarget::Fedora),
    ("debian", SeedTarget::Debian),
    ("windows", SeedTarget::Windows),
];

/// `SEED_CHOICES.get(choice)`.
pub fn seed_target(choice: &str) -> Option<SeedTarget> {
    SEED_CHOICES.iter().find(|(k, _)| *k == choice).map(|(_, t)| *t)
}

/// `App.seed_target_texts()`: `(choice key, translated name)` for the four radio buttons.
pub fn seed_target_texts() -> Vec<(&'static str, String)> {
    vec![
        ("ubuntu", tr("Ubuntu (autoinstall)")),
        ("fedora", tr("Fedora / RHEL (kickstart)")),
        ("debian", tr("Debian (script + preseed)")),
        ("windows", tr("Windows 11 (run after install)")),
    ]
}

/// `App.seed_step_heading(choice)`: the title of step 2 on the Hardening seed card: what the chosen drive carries.
pub fn seed_step_heading(choice: &str) -> String {
    if choice == "windows" {
        tr("Hardening scripts")
    } else {
        tr("Auto-install files")
    }
}

/// `App.seed_target_note(choice)`: how the chosen system finds the seed drive (or, for Windows, how it is used).
pub fn seed_target_note(choice: &str) -> String {
    match choice {
        "ubuntu" => tr("Ubuntu's installer looks for settings on a drive labelled CIDATA. It still asks for \
                        the disk and your account."),
        "fedora" => tr("The installer looks for a kickstart file on a drive labelled OEMDRV. It still asks for \
                        the disk and your account."),
        "debian" => tr("Debian does not look for the drive by itself: the README on it explains the boot \
                        parameter, and the script to run after the install is on it too."),
        "windows" => tr("Run harden.cmd as administrator on a Windows 11 that is already installed; \
                         audit.cmd shows a report first, undo.cmd goes back."),
        _ => String::new(),
    }
}

/// `App._canceled_texts(drive_touched, written, seed)`: `(log line, dialog title, dialog text)` after a cancel. The
/// engine says whether it had already started to change the drive (when it did not, the drive must not be called
/// unusable) and whether the whole image had been written (canceled during the final check).
pub fn canceled_texts(drive_touched: bool, written: bool, seed: bool) -> (String, String, String) {
    if drive_touched && written && seed {
        return (
            tr("Canceled during verification. The seed files were written but NOT verified; do not rely \
                on this drive."),
            tr("Canceled"),
            tr("The operation was canceled during verification.\n\nThe seed files were written to the \
                drive but NOT verified, so do not rely on it. Create it again to verify it."),
        );
    }
    if drive_touched && written {
        return (
            tr("Canceled during verification. The image was written but NOT verified; do not rely \
                on this drive."),
            tr("Canceled"),
            tr("The operation was canceled during verification.\n\nThe image was written to the \
                drive but NOT verified, so do not rely on it. Create it again to verify it."),
        );
    }
    if drive_touched {
        return (
            tr("Canceled. The drive was left unusable; create it again before use."),
            tr("Canceled"),
            tr("The operation was canceled.\n\nThe USB drive was left incomplete and \
                unusable. Create it again before using it."),
        );
    }
    (
        tr("Canceled. The drive was not modified."),
        tr("Canceled"),
        tr("The operation was canceled.\n\nThe USB drive was NOT modified."),
    )
}

/// `App._windows_seed_success_texts(ejected)`: `(title, text)` of the success panel for the Windows seed drive.
pub fn windows_seed_success_texts(ejected: bool) -> (String, String) {
    let note = if ejected {
        tr("The files were checked on the drive and it was ejected — you can unplug it now.")
    } else {
        tr("The files were checked on the drive, but it could not be ejected automatically. Eject it from \
            the file manager before unplugging.")
    };
    (
        tr("Windows 11 hardening drive created and verified"),
        note + " "
            + &tr("On a Windows 11 that is already installed, open this drive and run audit.cmd \
                   (shows a report, changes nothing), harden.cmd (as administrator) or undo.cmd (goes \
                   back). The scripts were never run on real Windows: try them on a test machine first."),
    )
}

/// The `(title, text)` of the success panel of a Linux / Windows / ChromeOS write (`_show_create_success`).
pub fn create_success_texts(ejected: bool, hardened: bool) -> (String, String) {
    let mut note = if ejected {
        tr("It was verified against the ISO and ejected — you can unplug it now.")
    } else {
        tr("It was verified against the ISO, but could not be ejected automatically. \
            Eject it from the file manager before unplugging.")
    };
    if hardened {
        note += " ";
        note += &trf(
            "The hardening files were written to the drive and checked byte for byte. After \
             Windows setup finishes, their log will be at {log}.",
            &[("log", WINDOWS_HARDENING_LOG_SHOWN.into())],
        );
    }
    (tr("Bootable USB drive created successfully!"), note)
}

/// The `(title, text)` of the success panel of a (Linux style) seed drive.
pub fn seed_success_texts(ejected: bool) -> (String, String) {
    let note = if ejected {
        tr("The seed files were checked on the drive and it was ejected — you can unplug it now. \
            Plug it in next to the installer USB drive before you start the installation.")
    } else {
        tr("The seed files were checked on the drive, but it could not be ejected automatically. \
            Eject it from the file manager before unplugging, then plug it in next to the installer \
            USB drive before you start the installation.")
    };
    (tr("Seed drive created and verified"), note)
}

/// `App._hardening_details_text()`: the list of settings the Windows option applies, from the engine's own
/// description (`lines`), each translated and bulleted, then the footer.
pub fn hardening_details_text(lines: &[String]) -> String {
    let mut out: Vec<String> =
        lines.iter().map(|l| tr(l)).map(|l| if l.starts_with('•') { l } else { format!("• {l}") }).collect();
    out.push(String::new());
    out.push(trf(
        "The settings are applied at the end of Windows setup by a script, and every change is written \
         to {log}. You choose the disk, the account and the edition during setup as usual.",
        &[("log", WINDOWS_HARDENING_LOG_SHOWN.into())],
    ));
    out.join("\n")
}

/// The explanation at the top of the panel of a card (`_build_sources`).
pub fn panel_text(card: crate::types::Card) -> String {
    use crate::types::Card;
    match card {
        Card::Chrome => tr("ChromeOS Flex is Google's free version of ChromeOS for PCs and Macs. Google does not publish \
                            regular ChromeOS for ordinary computers. It needs a USB drive of 16 GB or larger; the \
                            computer you install it on needs an Intel or AMD 64-bit processor, 4 GB of RAM and 16 GB \
                            of storage, and Google only guarantees certified models."),
        Card::Windows => tr("Microsoft only gives out the direct ISO link after you choose the edition and language: \
                             open the official page, pick 'Windows 11 (multi-edition ISO)', right-click the blue 64-bit \
                             button, choose 'Copy Link Address' (do NOT click it) and paste the link here."),
        Card::Linux => tr("Download the ISO from your distribution's website (Ubuntu, Debian, Fedora, Mint, Arch...), \
                           then choose the file below. It is written to the drive as it is, so it must be a hybrid \
                           image; all current Linux ISOs are. Check its SHA-256 below if the site publishes one."),
        Card::Other => tr("Any bootable hybrid ISO or disk image is written to the drive exactly as it is. Choose the \
                           file below. Images that cannot boot from a USB drive are refused before anything is erased."),
        Card::Seed => tr("Makes a SECOND, small USB drive (not the installer) with settings for a hardened Linux or \
                          Windows 11 install. Write the installer on its own drive (Linux or Windows card) and plug \
                          both in. It never chooses or erases a disk on that PC. No image is needed; writing this \
                          drive ERASES it."),
    }
}

/// The one-line explanation under the hardening checkbox of the Windows 11 card.
pub fn hardening_explanation() -> String {
    trf(
        "Adds a few files to the same drive. A script applies the settings at the END of Windows setup \
         and writes its log to {log}.",
        &[("log", WINDOWS_HARDENING_LOG_SHOWN.into())],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gui::tx::set_test_language;
    use crate::i18n_table::PT_BR;

    fn pt() -> std::collections::HashMap<&'static str, &'static str> {
        PT_BR.iter().copied().collect()
    }

    // ---- tests/test_fixes_gui.py: CanceledTextsTests, CanceledAfterWriteTextsTests ----
    #[test]
    fn touched_drive_is_called_unusable() {
        let (log, _title, body) = canceled_texts(true, false, false);
        assert!(log.contains("unusable"));
        assert!(body.contains("unusable"));
    }

    #[test]
    fn untouched_drive_is_not_called_unusable() {
        let (log, _title, body) = canceled_texts(false, false, false);
        assert!(log.contains("not modified"));
        assert!(body.contains("NOT modified"));
        assert!(!log.to_lowercase().contains("unusable"));
        assert!(!body.to_lowercase().contains("unusable"));
    }

    #[test]
    fn the_canceled_texts_are_translated() {
        set_test_language("pt");
        let (log, _title, body) = canceled_texts(false, false, false);
        set_test_language("en");
        assert!(log.contains("não foi modificado"), "{log}");
        assert!(body.contains("NÃO foi modificado"), "{body}");
    }

    #[test]
    fn canceled_during_the_final_check_says_not_verified() {
        let (log, _title, body) = canceled_texts(true, true, false);
        assert!(log.contains("NOT verified") && body.contains("NOT verified"));
        assert!(!format!("{log}{body}").contains("unusable"));
        assert!(canceled_texts(true, false, false).2.contains("unusable"));
        assert!(canceled_texts(false, false, false).2.contains("NOT modified"));
        // nothing was written when the drive was never touched, whatever `written` says
        assert!(canceled_texts(false, true, false).2.contains("NOT modified"));
    }

    // ---- tests/test_gui_hardening.py ----
    #[test]
    fn canceled_during_the_seed_verification_says_the_seed_files_are_unverified() {
        let (log, _title, body) = canceled_texts(true, true, true);
        assert!(log.contains("seed files"));
        assert!(body.contains("NOT verified") && body.contains("seed files"));
        assert!(canceled_texts(true, true, false).0.contains("image"));
        set_test_language("pt");
        let pt_log = canceled_texts(true, true, true).0;
        set_test_language("en");
        assert!(pt_log.contains("kit"), "{pt_log}");
    }

    #[test]
    fn the_radio_texts_are_the_ones_fixed_by_the_design() {
        let texts: Vec<String> = seed_target_texts().into_iter().map(|(_, t)| t).collect();
        assert_eq!(
            texts,
            vec![
                "Ubuntu (autoinstall)",
                "Fedora / RHEL (kickstart)",
                "Debian (script + preseed)",
                "Windows 11 (run after install)"
            ]
        );
    }

    #[test]
    fn there_are_four_radios_and_each_key_maps_to_its_target_only() {
        assert_eq!(SEED_CHOICES.len(), 4);
        let keys: Vec<&str> = seed_target_texts().into_iter().map(|(k, _)| k).collect();
        assert_eq!(keys, SEED_CHOICES.iter().map(|(k, _)| *k).collect::<Vec<_>>());
        for (key, target) in SEED_CHOICES {
            assert_eq!(key, target.as_str());
            assert_eq!(seed_target(key), Some(target));
        }
        let targets: std::collections::HashSet<_> = SEED_CHOICES.iter().map(|(_, t)| *t).collect();
        assert_eq!(targets.len(), 4);
        for t in SeedTarget::ALL {
            assert!(targets.contains(&t));
        }
        assert_eq!(seed_target("bogus"), None);
    }

    #[test]
    fn no_radio_and_no_note_mentions_the_experimental_mode() {
        for lang in ["en", "pt"] {
            set_test_language(lang);
            let mut texts: Vec<String> = seed_target_texts().into_iter().map(|(_, t)| t).collect();
            texts.extend(SEED_CHOICES.iter().map(|(k, _)| seed_target_note(k)));
            texts.extend(SEED_CHOICES.iter().map(|(k, _)| seed_step_heading(k)));
            for ejected in [true, false] {
                let (a, b) = windows_seed_success_texts(ejected);
                texts.push(a);
                texts.push(b);
            }
            set_test_language("en");
            for text in texts {
                let lower = text.to_lowercase();
                assert!(!lower.contains("experimental"), "{lang}: {text}");
                assert!(!lower.contains("answer file"), "{lang}: {text}");
                assert!(!lower.contains("arquivo de resposta"), "{lang}: {text}");
            }
        }
    }

    #[test]
    fn the_target_notes_are_translated() {
        set_test_language("pt");
        let table = pt();
        for (key, _) in SEED_CHOICES {
            let note = seed_target_note(key);
            assert!(!note.is_empty());
            assert!(table.values().any(|v| *v == note), "{note}");
        }
        set_test_language("en");
    }

    #[test]
    fn the_step_heading_follows_the_choice() {
        for key in ["ubuntu", "fedora", "debian"] {
            assert_eq!(seed_step_heading(key), "Auto-install files");
        }
        assert_eq!(seed_step_heading("windows"), "Hardening scripts");
    }

    #[test]
    fn the_run_after_install_note_is_the_one_fixed_by_the_design() {
        assert_eq!(
            seed_target_note("windows"),
            "Run harden.cmd as administrator on a Windows 11 that is already installed; \
             audit.cmd shows a report first, undo.cmd goes back."
        );
        assert_eq!(seed_target_note("bogus"), "");
        assert!(seed_target_note("fedora").contains("OEMDRV"));
        assert!(seed_target_note("ubuntu").contains("CIDATA"));
        assert!(seed_target_note("debian").contains("README"));
    }

    #[test]
    fn the_windows_success_texts_are_honest() {
        let after = windows_seed_success_texts(true);
        for name in ["audit.cmd", "harden.cmd", "undo.cmd"] {
            assert!(after.1.contains(name), "{name}");
        }
        assert!(after.1.contains("never run on real Windows"));
        assert!(!format!("{}{}", after.1, after.0).contains("EXPERIMENTAL"));
        assert!(after.1.contains("you can unplug it now"));
        let not_ejected = windows_seed_success_texts(false);
        assert!(not_ejected.1.contains("could not be ejected automatically"));
        assert!(!not_ejected.1.contains("you can unplug it now"));
        assert_eq!(not_ejected.0, after.0);
        let re = regex::Regex::new(r"\b(cis|stig|nist|complian|certif)").unwrap();
        for text in [&after.0, &after.1, &not_ejected.1] {
            assert!(!re.is_match(&text.to_lowercase()), "{text}");
            assert!(!text.contains("ISO"), "there is no image: {text}");
        }
    }

    #[test]
    fn the_windows_radios_and_notes_are_translated_when_the_language_is_portuguese() {
        set_test_language("pt");
        let texts: Vec<String> = seed_target_texts().into_iter().map(|(_, t)| t).collect();
        let note = seed_target_note("windows");
        let after = windows_seed_success_texts(true);
        set_test_language("en");
        assert_eq!(texts[3], "Windows 11 (executar depois de instalar)");
        assert!(note.contains("harden.cmd") && note.contains("administrador"));
        assert!(after.0.contains("Pendrive"));
        assert!(after.1.contains("undo.cmd"));
    }

    #[test]
    fn the_portuguese_name_of_the_run_later_mode_is_the_same_everywhere_in_the_window() {
        let name = "executar depois de instalar";
        set_test_language("pt");
        let mut texts: Vec<String> = seed_target_texts().into_iter().map(|(_, t)| t).collect();
        texts.push(seed_target_note("windows"));
        let (a, b) = windows_seed_success_texts(true);
        texts.push(a);
        texts.push(b);
        set_test_language("en");
        assert!(texts[3].contains(name));
        for (key, value) in PT_BR {
            if key.contains("run after install") {
                assert!(value.contains(name), "{}", &key[..key.len().min(60)]);
            }
        }
        for text in &texts {
            assert!(!text.contains("após a instalação"));
            assert!(!text.contains("executar após"));
            assert!(!text.contains("rodar depois"));
        }
    }

    #[test]
    fn the_real_description_goes_through_the_translation_and_gets_bullets() {
        let lines = vec!["Turns thing A on -- risk: x".to_string(), "• Already bulleted".to_string()];
        let text = hardening_details_text(&lines);
        assert!(text.contains("• Turns thing A on -- risk: x"));
        assert!(text.contains("• Already bulleted") && !text.contains("• • "));
        assert!(text.contains("applied at the end of Windows setup by a script"));
        assert!(text.contains("C:\\Windows\\Temp\\epma-hardening.log"));
    }

    #[test]
    fn every_line_of_the_list_goes_through_the_translation() {
        // each English line is looked up in the table like any other text (a known entry stands in for the engine's)
        set_test_language("pt");
        let text = hardening_details_text(&["Install target:".to_string(), "Hide the list".to_string()]);
        set_test_language("en");
        let table = pt();
        assert!(text.contains(&format!("• {}", table["Install target:"])), "{text}");
        assert!(text.contains(&format!("• {}", table["Hide the list"])), "{text}");
        assert!(!text.contains("• Install target:"));
    }

    #[test]
    fn success_texts_for_every_kind_of_write() {
        let (title, note) = create_success_texts(true, false);
        assert_eq!(title, "Bootable USB drive created successfully!");
        assert!(note.contains("verified against the ISO and ejected") && note.contains("unplug it now"));
        let (_, note) = create_success_texts(false, false);
        assert!(note.contains("could not be ejected automatically") && note.contains("Eject it from the file manager"));
        assert!(!note.contains("you can unplug it now"));
        let (_, note) = create_success_texts(true, true);
        assert!(note.contains("written to the drive and checked byte for byte"));
        assert!(note.contains("C:\\Windows\\Temp\\epma-hardening.log"));
        assert!(note.contains("After Windows setup finishes"));
        let (title, note) = seed_success_texts(true);
        assert!(title.starts_with("Seed drive created and verified"));
        assert!(note.contains("ejected") && note.contains("next to the installer USB drive"));
        assert!(!note.contains("ISO"));
        assert!(!seed_success_texts(false).1.contains("you can unplug it now"));
    }

    #[test]
    fn the_new_texts_are_translated_and_differ() {
        let table = pt();
        let new_texts = [
            "Hardening seed",
            "Auto-install files",
            "Second USB drive",
            "Hardening scripts",
            "Add hardening settings to the Windows installation (optional)",
            "What does it change?",
            "Hide the list",
            "Install target:",
            "Create Seed Drive",
            "the hardening seed files",
            "Windows 11 and add the hardening files",
            "Seed drive created and verified",
            "Wait for the download to finish or cancel it first.",
            "Download in progress",
            "Windows 11 (run after install)",
            "Windows 11 hardening drive created and verified",
        ];
        for text in new_texts {
            let value = table.get(text).unwrap_or_else(|| panic!("no PT_BR entry: {text}"));
            assert!(!value.is_empty());
            assert_ne!(*value, text, "{text}");
        }
        assert_eq!(table["the hardening seed files"], "os arquivos do kit de reforço");
    }

    #[test]
    fn the_panel_texts_say_what_the_design_says() {
        use crate::types::Card;
        let seed = panel_text(Card::Seed);
        assert!(seed.contains("SECOND, small USB drive (not the installer)"));
        assert!(seed.contains("ERASES it"));
        assert!(seed.contains("No image is needed"));
        assert!(seed.contains("Windows 11"));
        assert!(!seed.contains("never run on a real Windows"), "the caveat lives in the note and the result texts");
        assert!(panel_text(Card::Chrome).contains("does not publish regular ChromeOS"));
        assert!(panel_text(Card::Chrome).contains("16 GB or larger"));
        assert!(panel_text(Card::Chrome).contains("4 GB of RAM"));
        assert!(panel_text(Card::Windows).contains("Copy Link Address"));
        assert!(panel_text(Card::Linux).contains("hybrid"));
        assert!(panel_text(Card::Other).contains("refused before anything is erased"));
        let explain = hardening_explanation();
        assert!(explain.contains("END of Windows setup"));
        assert!(explain.contains("C:\\Windows\\Temp\\epma-hardening.log"));
        assert!(!explain.contains("safer settings"));
    }
}
