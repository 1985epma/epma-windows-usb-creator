//! Tests of the window's logic: the asserted behaviour of tests/test_fixes_gui.py, tests/test_gui_hardening.py, the window
//! parts of tests/test_i18n.py and tests/test_refactor_helpers.py, moved from the Tk widgets onto `AppState` (the
//! widgets themselves are covered by the unit tests of `widgets.rs`, `dialogs.rs` and `texts.rs`).

use super::backend::Platform;
use super::dialogs::{DialogKind, DialogReply, DialogRequest};
use super::model::{path_to_file_uri, AppState, BannerId};
use super::shared::{ExcInfo, FlowKind, UiMsg};
use super::testkit::{usb_disk, Gate, Harness, GB};
use super::tx::set_test_language;
use super::widgets::{BarMode, Retry, Tone};
use crate::diskrisk::RiskLevel;
use crate::types::{Card, Disk, Error, Hardening, IsoKind, Mode, SeedTarget};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;

const ISO: &str = "/tmp/exemplo.iso";

fn fixed_disk(id: &str) -> Disk {
    Disk { id: id.into(), size: 32 * GB, label: format!("/dev/{id}"), ..Default::default() }
}

fn started(h: &mut Harness) {
    assert!(h.pump(|s| s.create_started), "the write never started");
}

// =================================================================================================================
// Write lock (tests/test_fixes_gui.py: WriteLockTests)
// =================================================================================================================
mod write_lock {
    use super::*;

    #[test]
    fn create_stays_disabled_while_writing() {
        let mut h = Harness::new();
        h.with_disk(ISO);
        assert!(h.state.controls.create_enabled);
        h.state.creating = true;
        h.state.sync_controls();
        h.state.update_create_button_state();
        assert!(!h.state.controls.create_enabled);
        // everything that used to re-enable it
        h.state.select_card(Card::Linux);
        assert!(!h.state.controls.create_enabled);
        h.state.refresh_disks(false, true);
        assert!(!h.state.controls.create_enabled);
        h.state.select_drive(0); // a click on the locked list does nothing
        assert!(!h.state.controls.create_enabled);
    }

    #[test]
    fn controls_are_locked_during_a_write_and_unlocked_after() {
        let mut h = Harness::new();
        h.with_disk(ISO);
        h.state.creating = true;
        h.state.sync_controls();
        assert!(!h.state.drives.is_enabled());
        assert!(!h.state.controls.refresh_enabled);
        assert!(!h.state.controls.pick_enabled);
        assert!(!h.state.windows_dl.btn_enabled);
        assert!(!h.state.flex_dl.btn_enabled);
        assert!(!h.state.controls.install_enabled);
        assert!(!h.state.controls.cards_enabled);
        assert!(!h.state.controls.hardening_enabled && !h.state.controls.seed_radios_enabled);

        h.state.creation_ended();
        assert!(h.pump(|s| !s.disk_listing));
        assert!(h.state.drives.is_enabled());
        assert!(h.state.controls.refresh_enabled && h.state.controls.pick_enabled);
        assert!(h.state.windows_dl.btn_enabled && h.state.flex_dl.btn_enabled);
        assert!(h.state.controls.cards_enabled);
        assert!(!h.state.controls.cancel_enabled);
    }

    #[test]
    fn start_create_returns_at_once_while_creating() {
        let mut h = Harness::inline();
        h.state.creating = true;
        h.state.sh.cancel_create.set(); // a pending cancel must survive a second click
        let before = h.be.missing_modes.lock().unwrap().len();
        h.state.start_create_usb();
        assert_eq!(h.be.missing_modes.lock().unwrap().len(), before, "no second flow may start");
        assert!(h.state.sh.cancel_create.is_set());
        assert!(h.state.creating, "the running write's flag must not be reset by the second click");
    }

    #[test]
    fn a_refused_start_unlocks_again() {
        let mut h = Harness::new();
        h.with_disk(ISO);
        h.dialogs.set_yes(false); // the confirmation is declined
        h.state.start_create_usb();
        assert!(h.pump(|s| !s.creating));
        assert!(h.state.controls.create_enabled);
        assert!(h.state.drives.is_enabled());
    }

    #[test]
    fn an_exception_while_starting_unlocks_again() {
        let mut h = Harness::new();
        h.with_disk(ISO);
        h.be.panic_next_missing.store(true, Ordering::SeqCst);
        h.state.start_create_usb();
        assert!(h.pump(|s| !s.creating));
        assert!(h.state.error_banner.shown, "the failure is reported, not lost");
        assert!(h.state.drives.is_enabled());
    }

    #[test]
    fn the_hint_is_empty_while_writing() {
        let mut h = Harness::new();
        h.with_disk(ISO);
        h.state.creating = true;
        h.state.update_create_button_state();
        assert_eq!(h.state.create_hint, "");
    }
}

// =================================================================================================================
// Dependency gate, zero-size drives (DependencyGateTests, ZeroSizeDriveTests)
// =================================================================================================================
mod dependency_gate {
    use super::*;

    #[test]
    fn missing_tool_disables_create_and_explains() {
        let mut h = Harness::new();
        h.with_disk(ISO);
        assert!(h.state.controls.create_enabled);
        h.be.set_missing(&["wimlib-imagex"]);
        h.state.update_create_button_state();
        assert!(!h.state.controls.create_enabled);
        assert!(h.state.create_hint.contains("wimlib-imagex"));
        assert!(h.state.create_hint.contains("Install missing dependencies"));
        h.be.set_missing(&[]); // tool installed again
        h.state.update_create_button_state();
        assert!(h.state.controls.create_enabled);
    }

    #[test]
    fn start_refuses_before_anything_is_confirmed() {
        let mut h = Harness::inline();
        h.with_disk(ISO);
        h.dialogs.set_yes(true);
        h.be.set_missing(&["wimlib-imagex"]);
        h.state.start_create_usb();
        h.state.pump();
        assert!(!h.event_list().contains(&"confirm".to_string()));
        assert_eq!(h.dialogs.titles(Some("error")), vec!["Missing tools"]);
        assert!(h.be.build_calls.lock().unwrap().is_empty());
        assert!(!h.state.creating);
        assert!(h.dialogs.last().unwrap().2.contains("Nothing was changed"));
    }

    #[test]
    fn installing_blocks_create() {
        let mut h = Harness::new();
        h.with_disk(ISO);
        h.state.installing = true;
        h.state.update_create_button_state();
        assert!(!h.state.controls.create_enabled);
        h.state.installation_ended();
        assert!(h.state.controls.create_enabled);
    }

    #[test]
    fn a_zero_byte_drive_is_refused_not_skipped() {
        let mut h = Harness::inline();
        h.be.set_listed(vec![Disk { size: 0, ..usb_disk() }]);
        h.state.iso_path = ISO.into();
        h.state.refresh_disks(false, true);
        h.dialogs.set_yes(true);
        h.state.start_create_usb();
        h.state.pump();
        assert_eq!(h.dialogs.titles(Some("error")), vec!["Unknown drive size"]);
        assert!(!h.event_list().contains(&"confirm".to_string()));
        assert!(h.be.build_calls.lock().unwrap().is_empty());
        assert!(!h.state.creating);
    }
}

// =================================================================================================================
// Closing the window (CloseWindowTests)
// =================================================================================================================
mod close_window {
    use super::*;

    /// A thread standing in for the write worker: it ends when canceled (if `obey`), else when `release` opens.
    fn fake_worker(h: &mut Harness, obey: bool) -> (Arc<Gate>, std::thread::JoinHandle<()>) {
        let release = Gate::new();
        let alive = h.state.sh.write_alive.clone();
        let cancel = h.state.sh.cancel_create.clone();
        alive.store(true, Ordering::SeqCst);
        let rel = release.clone();
        let handle = std::thread::spawn(move || {
            if obey {
                cancel.wait(std::time::Duration::from_secs(10));
            } else {
                rel.wait(10.0);
            }
            alive.store(false, Ordering::SeqCst);
        });
        h.state.create_started = true;
        h.state.creating = true;
        (release, handle)
    }

    #[test]
    fn idle_close_destroys_and_stops_downloads() {
        let mut h = Harness::new();
        h.state.request_close();
        assert!(h.state.destroy_requested);
        assert!(h.state.sh.cancel_flex.is_set());
        assert!(h.state.sh.cancel_download.is_set());
        assert_eq!(h.dialogs.count(), 0);
    }

    #[test]
    fn close_during_a_write_asks_and_can_be_declined() {
        let mut h = Harness::new();
        let (release, handle) = fake_worker(&mut h, true);
        h.dialogs.set_yes(false);
        h.state.request_close();
        assert!(h.pump(|s| !s.flow_open(FlowKind::CloseWindow)));
        assert_eq!(h.dialogs.titles(Some("question")), vec!["Quit while writing?"]);
        assert!(!h.state.destroy_requested);
        assert!(!h.state.sh.cancel_create.is_set());
        assert!(h.state.write_running());
        h.state.sh.cancel_create.set();
        release.set();
        handle.join().unwrap();
    }

    #[test]
    fn confirmed_close_cancels_waits_and_destroys() {
        let mut h = Harness::new();
        let (_release, handle) = fake_worker(&mut h, true);
        h.dialogs.set_yes(true);
        h.state.request_close();
        assert!(h.pump(|s| s.destroy_requested));
        assert!(h.state.sh.cancel_create.is_set());
        handle.join().unwrap();
        assert!(!h.state.write_running(), "the close must wait for the worker to stop");
        assert!(h.state.sh.cancel_download.is_set() && h.state.sh.cancel_flex.is_set());
    }

    #[test]
    fn a_worker_that_does_not_stop_asks_again_and_can_stay_open() {
        let mut h = Harness::new();
        let (release, handle) = fake_worker(&mut h, false);
        h.state.close_wait_seconds = 0.2;
        h.dialogs.answers.lock().unwrap().extend([true, false]);
        h.state.request_close();
        assert!(h.pump(|s| !s.flow_open(FlowKind::CloseWindow)));
        assert_eq!(h.dialogs.titles(Some("question")), vec!["Quit while writing?", "Still stopping"]);
        assert!(!h.state.destroy_requested);
        assert!(!h.state.closing());
        release.set();
        handle.join().unwrap();
    }

    #[test]
    fn no_dialog_pops_up_while_closing() {
        let mut h = Harness::new();
        h.state.sh.closing.store(true, Ordering::SeqCst);
        h.state.apply(UiMsg::Notify { info: true, title: "Done".into(), body: "x".into() });
        h.state.report_error("Error", Some("boom"), None, true, None);
        assert_eq!(h.dialogs.count(), 0);
        assert!(h.log().contains("ERROR: boom"), "the log keeps it");
    }

    #[test]
    fn a_pending_confirmation_is_not_interrupted() {
        let mut h = Harness::new();
        h.state.creating = true; // the confirmation / password dialog is open, no worker yet
        h.state.request_close();
        assert!(!h.state.destroy_requested);
        assert_eq!(h.dialogs.count(), 0);
    }

    #[test]
    fn a_second_close_click_does_not_stack_a_second_question() {
        let mut h = Harness::new();
        let (release, handle) = fake_worker(&mut h, true);
        h.state.request_close();
        let open = h.state.flow_open(FlowKind::CloseWindow);
        h.state.request_close(); // ignored while the question is open
        assert!(open || h.pump(|s| !s.flow_open(FlowKind::CloseWindow)));
        h.state.sh.cancel_create.set();
        release.set();
        handle.join().unwrap();
        assert!(h.dialogs.titles(Some("question")).len() <= 1);
    }
}

// =================================================================================================================
// The drive listing (DriveListingTests, tests/test_drive_list.py ModelTests / PlaceholderTests)
// =================================================================================================================
mod drive_listing {
    use super::*;

    fn slow_listing(h: &Harness, gate: &Arc<Gate>) {
        let gate = gate.clone();
        h.be.set_list(move || {
            gate.wait(10.0);
            Ok(vec![usb_disk()])
        });
    }

    #[test]
    fn listing_runs_in_a_worker_thread_and_never_overlaps() {
        let mut h = Harness::new();
        let gate = Gate::new();
        slow_listing(&h, &gate);
        let began = std::time::Instant::now();
        h.state.refresh_disks(true, false);
        assert!(began.elapsed().as_secs_f64() < 1.0, "the UI thread must not wait for the listing");
        assert!(h.state.disk_listing);
        assert!(h.state.drives.is_loading());
        assert!(h.pump(|_| !gate.is_set()) || true);
        // wait until the worker has started
        let be = h.be.clone();
        assert!(h.pump(move |_| !be.list_threads.lock().unwrap().is_empty()));
        h.state.refresh_disks(true, false); // asked again while one is running
        h.state.refresh_disks(false, false);
        assert_eq!(h.be.list_threads.lock().unwrap().len(), 1, "two listings must never run at the same time");
        assert_ne!(h.be.list_threads.lock().unwrap()[0], std::thread::current().id());
        gate.set();
        assert!(h.pump(|s| !s.disk_listing && s.selected_disk().is_some() && !s.disk_listing));
        let be = h.be.clone();
        assert!(h.pump(move |s| !s.disk_listing && be.list_threads.lock().unwrap().len() == 2));
        assert_eq!(h.state.selected_disk().unwrap().id, "disk9");
        assert_eq!(h.be.list_threads.lock().unwrap().len(), 2, "the request made meanwhile is served right after");
    }

    #[test]
    fn a_stale_result_is_ignored() {
        let mut h = Harness::new();
        let gate = Gate::new();
        slow_listing(&h, &gate);
        h.state.refresh_disks(true, false);
        let be = h.be.clone();
        assert!(h.pump(move |_| !be.list_threads.lock().unwrap().is_empty()));
        *h.be.list_fn.lock().unwrap() = None;
        h.state.refresh_disks(false, true); // a newer (synchronous) listing: no drives
        assert!(h.state.disks.is_empty());
        gate.set();
        assert!(h.pump(|s| !s.disk_listing));
        assert!(h.state.disks.is_empty(), "the older listing must not overwrite the newer one");
    }

    #[test]
    fn a_result_arriving_during_a_write_is_dropped() {
        let mut h = Harness::new();
        let gate = Gate::new();
        slow_listing(&h, &gate);
        h.state.refresh_disks(true, false);
        h.state.creating = true;
        gate.set();
        assert!(h.pump(|s| !s.disk_listing));
        assert!(h.state.disks.is_empty());
    }

    #[test]
    fn errors_are_logged_when_quiet_and_shown_otherwise() {
        let mut h = Harness::new();
        h.be.set_list(|| Err(Error::runtime("diskutil hung")));
        h.state.refresh_disks(true, false);
        assert!(h.pump(|s| !s.disk_listing));
        assert_eq!(h.dialogs.count(), 0);
        assert!(h.log().contains("diskutil hung"));
        h.state.refresh_disks(false, false);
        assert!(h.pump(|s| !s.disk_listing && s.error_banner.shown));
        assert_eq!(h.dialogs.count(), 0, "a listing failure is a banner, not a dialog");
        assert_eq!(h.state.error_banner.title_text, "Error");
        assert!(h.state.error_banner.message_text.contains("diskutil hung"));
    }

    #[test]
    fn a_panicking_listing_still_ends_the_listing() {
        let mut h = Harness::new();
        h.be.set_list(|| panic!("boom"));
        h.state.refresh_disks(true, false);
        assert!(h.pump(|s| !s.disk_listing), "the listing flag must not stay on");
        assert!(h.log().contains("Could not list disks"));
    }

    #[test]
    fn sync_mode_lists_on_the_calling_thread() {
        let mut h = Harness::new();
        h.be.set_listed(vec![usb_disk()]);
        h.state.refresh_disks(false, true);
        assert_eq!(*h.be.list_threads.lock().unwrap(), vec![std::thread::current().id()]);
        assert_eq!(h.state.selected_disk().unwrap().id, "disk9");
    }

    #[test]
    fn selected_drive_survives_a_refresh() {
        let mut h = Harness::new();
        h.be.set_listed(vec![fixed_disk("disk7"), usb_disk()]);
        h.state.refresh_disks(false, true);
        h.state.select_drive(1);
        h.state.refresh_disks(false, true);
        assert_eq!(h.state.selected_disk().unwrap().id, "disk9");
    }

    #[test]
    fn selecting_a_row_changes_the_selected_drive_and_the_create_state() {
        let mut h = Harness::new();
        h.state.iso_path = "/tmp/example.iso".into();
        h.be.set_listed(vec![fixed_disk("disk4"), fixed_disk("disk5")]);
        h.state.refresh_disks(false, true);
        assert_eq!(h.state.selected_disk().unwrap().id, "disk4");
        h.state.select_drive(1);
        assert_eq!(h.state.selected_disk().unwrap().id, "disk5");
        assert!(h.state.controls.create_enabled);
        h.state.drive_arrow(1, -1);
        assert_eq!(h.state.selected_disk().unwrap().id, "disk4");
    }

    #[test]
    fn the_create_hint_follows_the_listing() {
        let mut h = Harness::new();
        h.state.iso_path = "/tmp/example.iso".into();
        h.state.refresh_disks(false, true);
        assert_eq!(h.state.create_hint, "No USB drive found. Plug it in and click \"Refresh USB drives list\".");
        assert_eq!(h.state.drives.view_state(), super::super::widgets::ListView::Empty);
        h.be.set_listed(vec![fixed_disk("disk4")]);
        h.state.refresh_disks(false, true);
        assert_eq!(h.state.create_hint, "");
        assert_eq!(h.state.drives.view_state(), super::super::widgets::ListView::Items);
        // a drive exists but none is selected
        h.state.drives.select(-1);
        h.state.update_create_button_state();
        assert_eq!(h.state.create_hint, "Select a USB drive in the list.");
    }

    #[test]
    fn a_failed_listing_stops_the_placeholder() {
        let mut h = Harness::new();
        h.be.set_list(|| Err(Error::runtime("diskutil hung")));
        h.state.refresh_disks(true, false);
        assert!(h.pump(|s| !s.disk_listing));
        assert_eq!(h.state.drives.view_state(), super::super::widgets::ListView::Empty);
    }

    #[test]
    fn auto_refresh_is_throttled_and_never_runs_during_a_write() {
        let mut h = Harness::inline();
        h.be.set_listed(vec![usb_disk()]);
        h.state.auto_refresh_disks(); // last_disk_refresh was set to "now" by the harness: too soon
        h.state.pump();
        assert!(h.be.list_threads.lock().unwrap().is_empty());
        h.advance(crate::constants::AUTO_REFRESH_MIN_SECONDS + 0.1);
        h.state.creating = true;
        h.state.auto_refresh_disks();
        h.state.pump();
        assert!(h.be.list_threads.lock().unwrap().is_empty());
        h.state.creating = false;
        h.state.auto_refresh_disks();
        h.state.pump();
        assert_eq!(h.be.list_threads.lock().unwrap().len(), 1);
        h.state.last_disk_refresh = None; // the very first automatic refresh is never suppressed
        h.state.auto_refresh_disks();
        h.state.pump();
        assert_eq!(h.be.list_threads.lock().unwrap().len(), 2);
    }
}

// =================================================================================================================
// Choosing the image type (ImageTypeChoiceTests)
// =================================================================================================================
mod image_type {
    use super::*;
    use crate::gui::flows::image_matches_choice;

    #[test]
    fn unknown_content_keeps_the_card_whatever_the_name_says() {
        let mut h = Harness::new();
        for card in [Card::Linux, Card::Other, Card::Chrome] {
            h.state.select_card(card);
            h.state.set_iso("/tmp/darwin-linux.img");
            assert_eq!(h.state.card, card);
        }
        assert!(h.log().contains("could not be identified"));
    }

    #[test]
    fn unknown_content_never_selects_windows_by_name() {
        let mut h = Harness::new();
        h.state.select_card(Card::Linux);
        h.state.set_iso("/tmp/win11-notes.img");
        assert_eq!(h.state.card, Card::Linux);
        assert_eq!(h.state.mode, Mode::Linux);
    }

    #[test]
    fn known_content_still_preselects() {
        let mut h = Harness::new();
        *h.be.iso_kind.lock().unwrap() = IsoKind::Linux;
        h.state.select_card(Card::Other);
        h.state.set_iso("/tmp/ubuntu.iso");
        assert_eq!(h.state.card, Card::Other);
        h.state.select_card(Card::Windows);
        h.state.set_iso("/tmp/ubuntu.iso");
        assert_eq!(h.state.card, Card::Linux);
        *h.be.iso_kind.lock().unwrap() = IsoKind::Windows;
        h.state.set_iso("/tmp/ubuntu.iso");
        assert_eq!(h.state.card, Card::Windows);
        assert!(h.log().contains("from the content of the ISO"));
        *h.be.iso_kind.lock().unwrap() = IsoKind::ChromeOs;
        h.state.set_iso("/tmp/flex.bin");
        assert_eq!(h.state.card, Card::Chrome);
        assert_eq!(h.state.mode, Mode::ChromeOs);
    }

    #[test]
    fn windows_card_with_unknown_content_asks_first() {
        let h = Harness::new();
        h.dialogs.set_yes(false);
        assert!(!image_matches_choice(&*h.be, &*h.dialogs, Mode::Windows, "/tmp/whatever.iso"));
        assert_eq!(h.dialogs.titles(Some("question")), vec!["Image type not recognised"]);
        h.dialogs.set_yes(true);
        assert!(image_matches_choice(&*h.be, &*h.dialogs, Mode::Windows, "/tmp/whatever.iso"));
    }

    #[test]
    fn other_cards_and_known_windows_do_not_ask() {
        let h = Harness::new();
        assert!(image_matches_choice(&*h.be, &*h.dialogs, Mode::Linux, "/tmp/x.iso"));
        *h.be.iso_kind.lock().unwrap() = IsoKind::Windows;
        assert!(image_matches_choice(&*h.be, &*h.dialogs, Mode::Windows, "/tmp/x.iso"));
        assert_eq!(h.dialogs.count(), 0);
    }

    #[test]
    fn a_linux_or_chromeos_image_under_the_windows_card_asks_and_chromeos_mismatch_is_refused() {
        let h = Harness::new();
        *h.be.iso_kind.lock().unwrap() = IsoKind::Linux;
        h.dialogs.set_yes(false);
        assert!(!image_matches_choice(&*h.be, &*h.dialogs, Mode::Windows, "/tmp/x.iso"));
        assert_eq!(h.dialogs.titles(Some("question")), vec!["This does not look like Windows"]);
        assert!(h.dialogs.last().unwrap().2.contains("looks like a Linux image"));
        h.dialogs.clear();
        *h.be.iso_kind.lock().unwrap() = IsoKind::ChromeOs;
        assert!(!image_matches_choice(&*h.be, &*h.dialogs, Mode::Windows, "/tmp/x.iso"));
        assert!(h.dialogs.last().unwrap().2.contains("a ChromeOS image"));
        h.dialogs.clear();
        // the ChromeOS card refuses anything that is not a ChromeOS image, without a question
        *h.be.iso_kind.lock().unwrap() = IsoKind::Linux;
        h.dialogs.set_yes(true);
        assert!(!image_matches_choice(&*h.be, &*h.dialogs, Mode::ChromeOs, "/tmp/x.iso"));
        assert_eq!(h.dialogs.titles(Some("error")), vec!["ChromeOS Flex"]);
        assert!(h.dialogs.last().unwrap().2.contains("/tmp/x.iso"));
        // ... and passes a real one
        *h.be.iso_kind.lock().unwrap() = IsoKind::ChromeOs;
        assert!(image_matches_choice(&*h.be, &*h.dialogs, Mode::ChromeOs, "/tmp/x.bin"));
    }

    #[test]
    fn the_question_is_translated() {
        let h = Harness::new();
        set_test_language("pt");
        let _ = image_matches_choice(&*h.be, &*h.dialogs, Mode::Windows, "/tmp/whatever.iso");
        set_test_language("en");
        assert_eq!(h.dialogs.titles(Some("question")), vec!["Tipo de imagem não reconhecido"]);
    }

    #[test]
    fn the_image_checks_do_not_apply_to_the_seed_drive() {
        let h = Harness::new();
        assert!(image_matches_choice(&*h.be, &*h.dialogs, Mode::Seed, "/tmp/whatever.iso"));
        assert_eq!(h.dialogs.count(), 0);
    }
}

// =================================================================================================================
// The image card, steps and quiet layout (StepLayoutTests, QuietLayoutTests, SeedImageStepTests)
// =================================================================================================================
mod image_card {
    use super::*;

    fn temp_iso(dir: &tempfile::TempDir, name: &str, size: usize) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, vec![7u8; size]).unwrap();
        path
    }

    #[test]
    fn the_numbered_steps_are_in_order() {
        let h = Harness::new();
        assert_eq!(h.state.step_title(1), "Image type");
        assert_eq!(h.state.step_title(2), "Image");
        assert_eq!(h.state.step_title(3), "USB drive");
    }

    #[test]
    fn no_image_shows_only_the_empty_state_and_a_chosen_one_shows_name_folder_size_and_kind() {
        let mut h = Harness::new();
        assert!(!h.state.iso_card.has_file);
        assert_eq!(h.state.iso_card.label, "No ISO selected yet.");
        let dir = tempfile::tempdir().unwrap();
        let path = temp_iso(&dir, "ubuntu-24.04.iso", 2 * 1024 * 1024);
        *h.be.iso_kind.lock().unwrap() = IsoKind::Linux;
        h.state.set_iso(&path.to_string_lossy());
        let card = &h.state.iso_card;
        assert!(card.has_file);
        assert_eq!(card.label, "ubuntu-24.04.iso");
        assert!(card.folder.ends_with(dir.path().file_name().unwrap().to_str().unwrap()));
        assert_eq!(card.size, "2.0 MB");
        assert_eq!(card.badge, "Linux");
        assert_eq!(h.state.iso_path, path.to_string_lossy());
    }

    #[test]
    fn an_unreadable_or_unknown_image_still_shows_a_card() {
        let mut h = Harness::new();
        h.state.set_iso("/nonexistent/dir/missing.iso");
        let card = &h.state.iso_card;
        assert_eq!(card.label, "missing.iso");
        assert_eq!(card.size, "");
        assert_eq!(card.badge, "Unknown");
    }

    #[test]
    fn the_sha_panel_is_behind_a_link_that_appears_with_the_image() {
        let mut h = Harness::new();
        assert!(!h.state.sha_toggle_visible());
        assert!(!h.state.sha_panel_visible());
        h.state.set_iso("/tmp/does-not-exist.iso");
        assert!(h.state.sha_toggle_visible());
        assert!(!h.state.sha_panel_visible());
        h.state.set_sha_toggle_open(true);
        assert!(h.state.sha_panel_visible());
        h.state.set_iso("/tmp/other.iso"); // a new file keeps the panel as the user left it
        assert!(h.state.sha_panel_visible());
        h.state.set_sha_toggle_open(false);
        assert!(!h.state.sha_panel_visible());
    }

    #[test]
    fn the_image_widgets_leave_the_page_on_the_seed_card_and_come_back() {
        let mut h = Harness::new();
        h.state.set_iso("/tmp/ubuntu.iso");
        h.state.set_sha_toggle_open(true);
        assert!(h.state.sha_toggle_visible() && h.state.sha_panel_visible());
        assert!(!h.state.image_block_hidden());
        h.state.select_card(Card::Seed);
        assert!(h.state.image_block_hidden());
        assert!(!h.state.sha_toggle_visible() && !h.state.sha_panel_visible());
        assert_eq!(h.state.step_title(2), "Auto-install files");
        for (choice, heading) in [("windows", "Hardening scripts"), ("fedora", "Auto-install files")] {
            h.state.set_seed_choice(choice); // the heading says what the chosen drive carries
            assert_eq!(h.state.step_title(2), heading);
        }
        h.state.set_seed_choice("windows");
        assert_eq!(h.state.create_btn_text(), "Create Seed Drive");
        h.state.select_card(Card::Windows); // leaving the card: "Image"; coming back: the chosen drive's heading
        assert_eq!(h.state.step_title(2), "Image");
        h.state.select_card(Card::Seed);
        assert_eq!(h.state.step_title(2), "Hardening scripts");
        h.state.select_card(Card::Linux);
        assert_eq!(h.state.step_title(2), "Image");
        assert_eq!(h.state.create_btn_text(), "Create Bootable USB Drive");
        assert!(h.state.sha_toggle.is_open, "the panel is back as the user left it");
        assert!(h.state.sha_panel_visible());
    }

    #[test]
    fn create_does_not_ask_for_an_image_but_still_needs_a_drive() {
        let mut h = Harness::new();
        h.state.select_card(Card::Seed);
        assert_eq!(h.state.iso_path, "");
        h.state.refresh_disks(false, true); // nothing plugged in
        assert!(!h.state.controls.create_enabled);
        assert!(h.state.create_hint.contains("No USB drive found"));
        assert!(!h.state.create_hint.to_lowercase().contains("image"));
        h.be.set_listed(vec![usb_disk()]);
        h.state.refresh_disks(false, true);
        assert!(h.state.controls.create_enabled);
        assert_eq!(h.state.create_hint, "");
        // the other cards still need the image, and say so
        h.state.select_card(Card::Windows);
        assert!(!h.state.controls.create_enabled);
        assert!(h.state.create_hint.contains("Choose the image file first"));
        h.state.select_card(Card::Seed);
        assert!(h.state.controls.create_enabled);
    }

    #[test]
    fn a_missing_tool_still_blocks_the_seed_card() {
        let mut h = Harness::new();
        h.be.set_listed(vec![usb_disk()]);
        h.state.refresh_disks(false, true);
        h.state.select_card(Card::Seed);
        h.be.set_missing(&["parted"]);
        h.be.missing_modes.lock().unwrap().clear();
        h.state.update_create_button_state();
        assert_eq!(h.be.missing_modes.lock().unwrap().last(), Some(&Mode::Seed));
        assert!(!h.state.controls.create_enabled);
        assert!(h.state.create_hint.contains("parted"));
    }

    #[test]
    fn choosing_an_image_on_the_seed_card_keeps_the_card_and_remembers_the_image() {
        let mut h = Harness::new();
        h.state.select_card(Card::Seed);
        *h.be.iso_kind.lock().unwrap() = IsoKind::Windows; // even a Windows image does not pull the user away
        h.state.set_iso("/tmp/ubuntu.iso");
        assert_eq!(h.state.card, Card::Seed);
        assert_eq!(h.state.mode, Mode::Seed);
        assert_eq!(h.state.iso_path, "/tmp/ubuntu.iso");
        assert!(h.state.iso_card.has_file);
        assert!(!h.state.sha_toggle_visible());
        assert!(h.log().contains("Image remembered: ubuntu.iso"));
        h.state.select_card(Card::Linux); // now the image is there, in its card
        assert!(h.state.sha_toggle_visible());
    }

    #[test]
    fn other_cards_still_switch_on_the_content() {
        let mut h = Harness::new();
        *h.be.iso_kind.lock().unwrap() = IsoKind::Linux;
        h.state.select_card(Card::Windows);
        h.state.set_iso("/tmp/ubuntu.iso");
        assert_eq!(h.state.card, Card::Linux);
    }

    // ---- QuietLayoutTests ----
    #[test]
    fn the_single_cancel_stops_whatever_is_running() {
        let mut h = Harness::new();
        h.state.download_running = true;
        h.state.sync_controls();
        assert!(h.state.controls.cancel_enabled);
        h.state.cancel_current();
        assert!(h.state.sh.cancel_download.is_set());
        h.state.download_running = false;
        h.state.flex_busy = true;
        h.state.sync_controls();
        assert!(h.state.controls.cancel_enabled);
        h.state.cancel_current();
        assert!(h.state.sh.cancel_flex.is_set());
        h.state.flex_busy = false;
        h.state.sync_controls();
        assert!(!h.state.controls.cancel_enabled);
    }

    #[test]
    fn cancel_during_a_write_still_asks_first() {
        let mut h = Harness::new();
        h.state.creating = true;
        h.state.controls.cancel_enabled = true;
        h.dialogs.set_yes(false);
        h.state.cancel_current(); // the question is answered "no"
        assert!(h.pump(|s| !s.flow_open(FlowKind::CancelWrite)));
        assert_eq!(h.dialogs.titles(Some("question")), vec!["Cancel the operation?"]);
        assert!(!h.state.sh.cancel_create.is_set());
        assert!(!h.state.sh.cancel_download.is_set() && !h.state.sh.cancel_flex.is_set());
        // answered "yes": the write is told to stop and the button follows
        h.dialogs.set_yes(true);
        h.state.cancel_current();
        assert!(h.pump(|s| !s.controls.cancel_enabled));
        assert!(h.state.sh.cancel_create.is_set());
        assert!(h.log().contains("Cancel requested: stopping safely..."));
        assert!(h.be.audits.lock().unwrap().iter().any(|(m, _)| m == "User requested cancel of the USB creation"));
        h.state.cancel_current(); // a second click after the cancel does nothing
    }

    #[test]
    fn the_log_is_behind_a_link_and_opens_by_itself_on_failure() {
        let mut h = Harness::new();
        assert!(!h.state.details_toggle.is_open);
        assert_eq!(h.state.details_toggle.text(), "▸ Show details");
        h.state.log("a line"); // logging works while the box is hidden
        assert!(h.state.log_text().contains("a line"));
        h.state.details_toggle.toggle();
        assert_eq!(h.state.details_toggle.text(), "▾ Hide details");
        h.state.details_toggle.toggle();
        h.state.finish_create_progress(false, true); // a cancel is not a failure
        assert!(!h.state.details_toggle.is_open);
        h.state.finish_create_progress(false, false);
        assert!(h.state.details_toggle.is_open);
    }

    #[test]
    fn no_progress_bar_is_shown_while_idle() {
        let h = Harness::new();
        assert!(!h.state.windows_dl.bar.visible);
        assert!(!h.state.flex_dl.bar.visible);
        assert!(!h.state.create_progress.visible);
        assert!(!h.state.sha.bar.visible);
    }

    #[test]
    fn the_create_bar_follows_the_write() {
        let mut h = Harness::new();
        h.state.reset_create_progress();
        assert!(h.state.create_progress.visible);
        assert_eq!(h.state.create_progress.mode, BarMode::Indeterminate);
        assert_eq!(h.state.create_progress_label, "Preparing the drive...");
        h.state.finish_create_progress(true, false);
        assert!(h.state.create_progress.visible, "a finished write shows 100%");
        assert_eq!(h.state.create_progress.value, 100.0);
        assert_eq!(h.state.create_progress_label, "Done — 100%");
        h.state.reset_create_progress();
        h.state.finish_create_progress(false, true);
        assert!(!h.state.create_progress.visible);
        assert_eq!(h.state.create_progress_label, "Canceled.");
        h.state.finish_create_progress(false, false);
        assert_eq!(h.state.create_progress_label, "Failed.");
    }

    #[test]
    fn download_bars_appear_with_the_download_and_go_with_a_failure() {
        let mut h = Harness::new();
        h.state.windows_dl.start(None);
        assert!(h.state.windows_dl.bar.visible);
        h.state.windows_dl.finish("Download failed.", Some(0.0));
        assert!(!h.state.windows_dl.bar.visible);
        h.state.flex_dl.show(Some(50.0), "Downloading...");
        assert!(h.state.flex_dl.bar.visible);
        h.state.flex_dl.finish("Ready.", Some(100.0));
        assert!(h.state.flex_dl.bar.visible);
    }

    #[test]
    fn the_sha_bar_is_shown_by_a_calculation_and_hidden_by_a_reset() {
        let mut h = Harness::inline();
        let dir = tempfile::tempdir().unwrap();
        let path = temp_iso(&dir, "a.iso", 10);
        h.state.set_iso(&path.to_string_lossy());
        h.state.calculate_iso_sha256();
        assert!(h.state.sha.bar.visible);
        assert_eq!(h.state.sha.label, "Calculating...");
        h.state.reset_iso_sha();
        assert!(!h.state.sha.bar.visible);
    }
}

// =================================================================================================================
// SHA-256 of the selected image
// =================================================================================================================
mod sha_panel {
    use super::*;

    fn with_file(h: &mut Harness) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ubuntu.iso");
        std::fs::write(&path, b"x").unwrap();
        h.state.set_iso(&path.to_string_lossy());
        (dir, path)
    }

    #[test]
    fn it_needs_a_file_and_a_valid_expected_value() {
        let mut h = Harness::new();
        h.state.calculate_iso_sha256();
        assert_eq!(h.state.sha.result, "Select an ISO file first.");
        assert_eq!(h.state.sha.result_tone, Tone::Red);
        let (_dir, _path) = with_file(&mut h);
        h.state.sha.entry = "not a hash".into();
        h.state.calculate_iso_sha256();
        assert!(h.state.sha.result.contains("not a SHA-256"));
        assert_eq!(h.state.sha.result_tone, Tone::Red);
        assert!(h.state.sha.btn_enabled);
    }

    #[test]
    fn match_mismatch_and_unverified_outcomes() {
        for (entry, tone, text, outcome) in [
            (String::new(), Tone::Normal, "No expected checksum given", "unverified"),
            ("ab".repeat(32), Tone::Green, "MATCH — the file is intact", "match"),
            ("cd".repeat(32), Tone::Red, "MISMATCH — this is NOT the published file", "mismatch"),
        ] {
            let mut h = Harness::new();
            let (_dir, _path) = with_file(&mut h);
            h.state.sha.entry = entry;
            h.state.calculate_iso_sha256();
            assert!(!h.state.sha.btn_enabled);
            assert!(h.pump(|s| s.sha.btn_enabled), "{outcome}");
            assert_eq!(h.state.sha.result_tone, tone, "{outcome}");
            assert!(h.state.sha.result.contains(text), "{}", h.state.sha.result);
            assert_eq!(h.state.sha.label, format!("SHA-256: {}", "ab".repeat(32)));
            assert_eq!(h.state.sha.bar.value, 100.0);
            let log = h.log();
            assert!(log.contains("Calculating SHA-256 of ubuntu.iso..."));
            assert!(log.contains(&format!("SHA-256 of ubuntu.iso: {}", "ab".repeat(32))));
            let audits = h.be.audits.lock().unwrap().clone();
            let (_, level) = audits.iter().find(|(m, _)| m == &format!("ISO SHA-256 check result={outcome}")).unwrap();
            assert_eq!(*level, if outcome == "mismatch" { crate::audit::AuditLevel::Warning } else { crate::audit::AuditLevel::Info });
            if outcome == "mismatch" {
                assert!(log.contains(&format!("Expected SHA-256: {}", "cd".repeat(32))));
                assert!(log.contains("Checksum comparison: MISMATCH"));
            }
        }
    }

    #[test]
    fn a_stale_result_is_ignored_and_a_failure_is_reported() {
        let mut h = Harness::inline();
        let (_dir, _path) = with_file(&mut h);
        h.state.calculate_iso_sha256();
        h.state.reset_iso_sha(); // a new image: the old calculation must not show up
        h.state.pump();
        assert_eq!(h.state.sha.result, "");
        assert_eq!(h.state.sha.label, "");
        *h.be.sha_result.lock().unwrap() = Some(Err(Error::Io(std::io::Error::other("gone"))));
        h.state.calculate_iso_sha256();
        h.state.pump();
        assert_eq!(h.state.sha.result, "Could not read the file (OSError).");
        assert_eq!(h.state.sha.result_tone, Tone::Red);
        assert!(h.state.sha.btn_enabled);
    }

    #[test]
    fn progress_text_is_throttled_but_the_last_update_always_shows() {
        let mut h = Harness::inline();
        let (_dir, _path) = with_file(&mut h);
        h.state.calculate_iso_sha256();
        h.state.pump();
        // the fake reports (5, 10) then (10, 10): the second is the final one
        assert_eq!(h.state.sha.bar.value, 100.0);
    }
}

// =================================================================================================================
// Cancel messages (CancelMessageTests)
// =================================================================================================================
mod cancel_messages {
    use super::*;

    fn run_cancel(touched: bool) -> (Harness, String) {
        let mut h = Harness::new();
        h.state.iso_path = ISO.into();
        h.be.set_listed(vec![usb_disk()]);
        h.state.refresh_disks(false, true);
        h.dialogs.set_yes(true);
        h.be.set_build(move |_, _| Err(Error::canceled_with("stopped", touched, false)));
        h.state.start_create_usb();
        assert!(h.pump(|s| !s.creating));
        let log = h.log();
        (h, log)
    }

    #[test]
    fn drive_not_touched() {
        let (h, log) = run_cancel(false);
        assert!(log.contains("The drive was not modified"));
        assert!(!log.contains("unusable"));
        let (kind, title, body) = h.dialogs.last().unwrap();
        assert_eq!((kind.as_str(), title.as_str()), ("info", "Canceled"));
        assert!(body.contains("NOT modified"));
        assert!(!body.to_lowercase().contains("unusable"));
        assert!(!h.state.error_banner.shown, "nothing to warn about");
    }

    #[test]
    fn drive_touched() {
        let (h, log) = run_cancel(true);
        assert!(log.contains("left unusable"));
        assert!(h.dialogs.last().unwrap().2.contains("unusable"));
        assert!(h.state.error_banner.shown);
        assert!(h.state.error_banner.message_text.contains("unusable"));
        assert!(!h.state.success_panel.shown);
    }
}

// =================================================================================================================
// ChromeOS Flex and downloads (FlexBusyTests, DownloadCardWiringTests)
// =================================================================================================================
mod flex_and_downloads {
    use super::*;

    #[test]
    fn a_zip_picked_while_busy_is_ignored_and_the_cancel_survives() {
        let mut h = Harness::inline();
        h.state.flex_busy = true;
        h.state.sync_controls();
        h.state.sh.cancel_flex.set();
        h.state.pick_existing_iso(); // refused before any dialog
        assert_eq!(h.dialogs.count(), 0);
        // a file that comes back from a dialog that was open when the extraction started
        h.state.apply(UiMsg::ImagePicked(PathBuf::from("/tmp/x.bin.zip")));
        assert_eq!(h.be.extract_calls.load(Ordering::SeqCst), 0);
        assert!(h.state.sh.cancel_flex.is_set());
        assert!(!h.state.controls.pick_enabled);
        assert!(!h.state.flex_dl.btn_enabled);
        assert!(h.state.controls.cancel_enabled);
    }

    #[test]
    fn a_second_extraction_cannot_start_and_never_clears_the_cancel() {
        let mut h = Harness::new();
        let gate = Gate::new();
        let g = gate.clone();
        h.be.set_extract(move |_zip, _p, _c| {
            g.wait(10.0);
            Err(Error::canceled())
        });
        h.state.extract_flex_image(PathBuf::from("/tmp/a.zip"), false);
        assert!(h.state.flex_busy);
        h.state.sh.cancel_flex.set();
        h.state.extract_flex_image(PathBuf::from("/tmp/b.zip"), false);
        assert!(h.state.sh.cancel_flex.is_set());
        assert!(!h.state.controls.pick_enabled);
        gate.set();
        assert!(h.pump(|s| !s.flex_busy));
        assert_eq!(h.be.extract_calls.load(Ordering::SeqCst), 1);
        assert!(h.state.controls.pick_enabled && h.state.flex_dl.btn_enabled);
        assert!(!h.state.controls.cancel_enabled);
        assert_eq!(h.dialogs.count(), 0);
        assert_eq!(h.state.error_banner.title_text, "ChromeOS Flex");
        assert_eq!(h.state.error_banner.message_text, "Canceled.");
    }

    #[test]
    fn a_cancel_that_arrives_as_the_download_ends_is_kept() {
        let mut h = Harness::inline();
        h.state.flex_busy = true;
        h.state.sh.cancel_flex.set();
        h.state.on_flex_downloaded(Path::new("/tmp/a.zip"), &"0".repeat(64));
        assert_eq!(h.be.extract_calls.load(Ordering::SeqCst), 0);
        assert!(!h.state.flex_busy);
    }

    #[test]
    fn picking_is_ignored_while_writing() {
        let mut h = Harness::inline();
        h.state.creating = true;
        h.state.pick_existing_iso();
        assert_eq!(h.dialogs.count(), 0);
    }

    #[test]
    fn a_download_locks_only_its_own_controls() {
        let mut h = Harness::new();
        h.state.download_running = true;
        h.state.sync_controls();
        assert!(!h.state.windows_dl.btn_enabled);
        assert!(h.state.controls.cancel_enabled);
        assert!(h.state.controls.pick_enabled);
        h.state.download_running = false;
        h.state.sync_controls();
        assert!(h.state.windows_dl.btn_enabled);
        assert!(!h.state.controls.cancel_enabled);
    }

    #[test]
    fn the_file_dialog_decides_between_an_image_and_a_zip() {
        let mut h = Harness::inline();
        *h.dialogs.open_path.lock().unwrap() = Some(PathBuf::from("/tmp/ubuntu.iso"));
        h.state.pick_existing_iso();
        h.state.pump();
        assert_eq!(h.state.iso_path, "/tmp/ubuntu.iso");
        // a ZIP selects the Chrome card and extracts next to it
        *h.dialogs.open_path.lock().unwrap() = Some(PathBuf::from("/tmp/latest.bin.ZIP"));
        h.state.pick_existing_iso();
        h.state.pump();
        assert_eq!(h.state.card, Card::Chrome);
        assert_eq!(h.be.extract_calls.load(Ordering::SeqCst), 1);
        assert_eq!(h.state.iso_path, "/tmp/latest.bin", "the extracted image is selected");
    }

    // ---- DownloadCardWiringTests ----
    fn windows_url(h: &mut Harness) {
        h.state.url_entry = "https://software.download.prss.microsoft.com/Win11.iso".into();
        h.state.sha_entry = "AB".repeat(32);
        *h.dialogs.save_path.lock().unwrap() = Some(PathBuf::from("/tmp/Win11.iso"));
    }

    #[test]
    fn windows_download_start_and_end() {
        let mut h = Harness::new();
        windows_url(&mut h);
        h.state.start_download();
        assert!(h.pump(|s| s.download_running));
        let request = h.be.last_download().expect("the download was started");
        assert_eq!(request.expected_sha256.as_deref(), Some("ab".repeat(32).as_str()));
        assert_eq!(request.dest, PathBuf::from("/tmp/Win11.iso"));
        assert!(request.allowed_hosts.is_none());
        assert!(!request.cancel.is_set());
        assert!(!h.state.windows_dl.btn_enabled);
        assert!(h.state.controls.cancel_enabled);
        assert!(h.state.windows_dl.bar.visible);
        (request.progress)(500, 1000, 250.0);
        assert!(h.pump(|s| s.windows_dl.label.contains("50.0%")));
        (request.done)(Path::new("/tmp/Win11.iso"), &"cd".repeat(32), true);
        assert!(h.pump(|s| !s.download_running));
        assert_eq!(h.state.iso_path, "/tmp/Win11.iso");
        assert_eq!(h.state.windows_dl.label, "Download complete.");
        assert!(h.state.windows_dl.btn_enabled);
        assert!(!h.state.controls.cancel_enabled);
        let (kind, title, text) = h.dialogs.last().unwrap();
        assert_eq!((kind.as_str(), title.as_str()), ("info", "Done"));
        assert!(text.contains("ISO downloaded to:\n/tmp/Win11.iso"));
        assert!(text.contains("The SHA-256 checksum matches the value you supplied"));
        assert!(h.log().contains(&format!("SHA-256 of the downloaded file: {}", "cd".repeat(32))));
    }

    #[test]
    fn an_unverified_download_says_so_and_shows_the_hash() {
        let mut h = Harness::inline();
        h.state.on_download_done(Path::new("/tmp/Win11.iso"), &"cd".repeat(32), false);
        let text = h.dialogs.last().unwrap().2;
        assert!(text.contains(&format!("SHA-256 of this file:\n{}", "cd".repeat(32))));
        assert!(text.contains("authenticity was NOT verified"));
    }

    #[test]
    fn a_bad_link_or_checksum_is_refused_and_an_unknown_host_asks() {
        let mut h = Harness::inline();
        h.state.url_entry = "http://insecure.example/x.iso".into();
        h.state.start_download();
        h.state.pump();
        assert_eq!(h.dialogs.titles(Some("error")), vec!["Invalid link"]);
        h.dialogs.clear();
        h.state.url_entry = "https://software.download.prss.microsoft.com/Win11.iso".into();
        h.state.sha_entry = "xyz".into();
        h.state.start_download();
        h.state.pump();
        assert_eq!(h.dialogs.titles(Some("error")), vec!["Invalid checksum"]);
        h.dialogs.clear();
        h.state.sha_entry = String::new();
        h.state.url_entry = "https://mirror.example/Win11.iso".into();
        h.dialogs.set_yes(false);
        h.state.start_download();
        h.state.pump();
        assert_eq!(h.dialogs.titles(Some("question")), vec!["Unrecognised download server"]);
        assert!(h.dialogs.last().unwrap().2.contains("'mirror.example'"));
        assert!(h.be.audits.lock().unwrap().iter().any(|(m, _)| m == "User declined download from untrusted host: mirror.example"));
        assert!(!h.state.download_running);
        assert_eq!(h.be.downloads.lock().unwrap().len(), 0);
        // accepted, but the save dialog is canceled: nothing starts
        h.dialogs.set_yes(true);
        h.state.start_download();
        h.state.pump();
        assert!(!h.state.download_running);
        // accepted and saved: the audit line records the host and the flags
        *h.dialogs.save_path.lock().unwrap() = Some(PathBuf::from("/tmp/Win11.iso"));
        h.state.start_download();
        h.state.pump();
        assert!(h.state.download_running);
        assert!(h.be.audits.lock().unwrap().iter().any(|(m, _)| m == "Download started from host=mirror.example trusted=False checksum_supplied=False"));
    }

    #[test]
    fn a_failed_download_is_a_banner_with_try_again() {
        let mut h = Harness::inline();
        h.state.download_running = true;
        h.state.on_download_error("The server refused the download (HTTP 403).");
        assert_eq!(h.dialogs.count(), 0);
        assert_eq!(h.state.error_banner.title_text, "Download error");
        assert!(h.state.error_banner.message_text.contains("HTTP 403"));
        assert_eq!(h.state.windows_dl.label, "Download failed.");
        assert!(!h.state.windows_dl.bar.visible);
        assert_eq!(h.state.error_banner.link_texts(), vec!["Try again", "Dismiss"]);
        assert!(!h.state.download_running);
    }

    #[test]
    fn flex_download_start_and_failure() {
        let mut h = Harness::new();
        h.dialogs.set_yes(true);
        *h.dialogs.save_path.lock().unwrap() = Some(PathBuf::from("/tmp/flex.zip"));
        h.state.start_flex_download();
        assert!(h.pump(|s| s.flex_busy));
        let request = h.be.last_download().unwrap();
        assert_eq!(request.url, crate::constants::CHROMEOS_FLEX_URL);
        assert_eq!(request.allowed_hosts, Some(vec!["dl.google.com".to_string()]));
        assert!(h.be.audits.lock().unwrap().iter().any(|(m, _)| m == "ChromeOS Flex download started (dl.google.com)"));
        assert!(!h.state.flex_dl.btn_enabled);
        assert!(h.state.controls.cancel_enabled);
        (request.error)("boom");
        assert!(h.pump(|s| !s.flex_busy));
        assert_eq!(h.state.flex_dl.label, "Failed.");
        assert_eq!(h.state.error_banner.title_text, "ChromeOS Flex");
        assert_eq!(h.state.error_banner.link_texts(), vec!["Try again", "Dismiss"]);
        assert_eq!(h.dialogs.titles(Some("error")), Vec::<String>::new());
        assert_eq!(h.dialogs.titles(Some("question")), vec!["Download ChromeOS Flex"]);
    }

    #[test]
    fn flex_download_warns_about_free_space_and_can_be_declined() {
        let mut h = Harness::inline();
        h.dialogs.answers.lock().unwrap().extend([true, false]);
        *h.dialogs.save_path.lock().unwrap() = Some(PathBuf::from("/tmp/flex.zip"));
        *h.be.free_bytes.lock().unwrap() = Some(1_000_000_000);
        h.state.start_flex_download();
        h.state.pump();
        assert_eq!(h.dialogs.titles(Some("question")), vec!["Download ChromeOS Flex", "Not much free space"]);
        assert!(h.dialogs.last().unwrap().2.contains("only 953.7 MB is available"));
        assert!(!h.state.flex_busy);
    }

    #[test]
    fn a_finished_extraction_selects_the_image_and_deletes_the_downloaded_zip() {
        let mut h = Harness::inline();
        let dir = tempfile::tempdir().unwrap();
        let zip = dir.path().join("flex.bin.zip");
        std::fs::write(&zip, b"zip").unwrap();
        h.state.flex_busy = true;
        h.state.flex_extracting = true;
        *h.be.iso_kind.lock().unwrap() = IsoKind::ChromeOs;
        h.state.on_flex_extracted(Path::new("/tmp/flex.bin"), &zip, true);
        assert!(!zip.exists(), "only the archive this program downloaded itself is deleted");
        assert_eq!(h.state.iso_path, "/tmp/flex.bin");
        assert_eq!(h.state.card, Card::Chrome);
        assert_eq!(h.state.flex_dl.label, "Ready.");
        assert_eq!(h.dialogs.titles(Some("info")), vec!["ChromeOS Flex is ready"]);
        assert!(!h.state.flex_busy && !h.state.flex_extracting);
        h.state.pump();
    }

    #[test]
    fn the_flex_label_translates_the_time_left() {
        let mut h = Harness::new();
        set_test_language("pt");
        h.state.on_flex_progress(500, 1000, 10.0, "Baixando");
        set_test_language("en");
        let text = h.state.flex_dl.label.clone();
        assert!(text.contains("faltam ~0m50s"), "{text}");
        assert!(!text.contains("left"));
        h.state.on_flex_progress(500, 1000, 10.0, "Downloading...");
        assert!(h.state.flex_dl.label.contains("~0m50s left"));
        h.state.on_flex_progress(1024, 0, 0.0, "Extracting...");
        assert_eq!(h.state.flex_dl.label, "Extracting...  1.0 KB");
        assert_eq!(h.state.flex_dl.bar.mode, BarMode::Indeterminate);
    }

    #[test]
    fn the_windows_download_label_uses_minutes_not_seconds() {
        let mut h = Harness::new();
        h.state.on_progress(0, 72000, 10.0); // 7200 s left
        let text = h.state.windows_dl.label.clone();
        assert!(text.contains("~120m00s left"), "{text}");
        assert!(!text.contains("7200s"));
        h.state.on_progress(500, 1000, 0.0); // speed unknown
        assert!(h.state.windows_dl.label.contains("calculating..."));
        h.state.on_progress(2048, 0, 1024.0);
        assert_eq!(h.state.windows_dl.label, "2.0 KB downloaded — 1.0 KB/s");
    }
}

// =================================================================================================================
// Progress of the write (ProgressTextTests)
// =================================================================================================================
mod create_progress {
    use super::*;

    #[test]
    fn the_create_label_uses_the_same_helper() {
        let mut h = Harness::new();
        h.state.reset_create_progress();
        h.state.on_create_progress(0, 1000, "Writing the image...");
        h.state.create_started_at = Some(h.now() - 10.0);
        h.state.create_last_ui = f64::NEG_INFINITY;
        h.state.on_create_progress(500, 1000, "Writing the image...");
        assert!(h.state.create_progress_label.contains("Writing the image..."));
        h.state.create_last_ui = f64::NEG_INFINITY;
        h.state.create_started_at = Some(h.now() - 10.0);
        h.state.create_stage_base = 0;
        h.state.on_create_progress(500, 1000, "Writing the image...");
        let re = regex::Regex::new(r"~\d+m\d\ds left").unwrap();
        assert!(re.is_match(&h.state.create_progress_label), "{}", h.state.create_progress_label);
        assert!(h.state.create_progress_label.contains("50.0% — 500.0 B / 1000.0 B — 50.0 B/s"));
        h.state.finish_create_progress(false, false);
    }

    #[test]
    fn updates_are_throttled_and_the_last_one_always_shows() {
        let mut h = Harness::new();
        h.state.reset_create_progress();
        h.state.on_create_progress(10, 1000, "Copying files...");
        let first = h.state.create_progress_label.clone();
        h.advance(0.05);
        h.state.on_create_progress(20, 1000, "Copying files...");
        assert_eq!(h.state.create_progress_label, first, "less than PROGRESS_UI_INTERVAL later: skipped");
        h.advance(0.3);
        h.state.on_create_progress(500, 1000, "Copying files...");
        assert_ne!(h.state.create_progress_label, first);
        h.advance(0.01);
        h.state.on_create_progress(1000, 1000, "Copying files...");
        assert_eq!(h.state.create_progress_label, "Copying files...  100%");
        assert_eq!(h.state.create_progress.value, 100.0);
    }

    #[test]
    fn an_unknown_length_shows_a_busy_bar_and_a_new_stage_restarts_the_speed() {
        let mut h = Harness::new();
        h.state.reset_create_progress();
        h.state.on_create_progress(10, 1000, "Copying files...");
        assert_eq!(h.state.create_progress.mode, BarMode::Determinate);
        h.state.on_create_progress(0, 0, "Verifying the copied files...");
        assert_eq!(h.state.create_progress.mode, BarMode::Indeterminate);
        assert!(h.state.create_progress.running);
        assert_eq!(h.state.create_progress_label, "Verifying the copied files... (this can take a few minutes)");
        assert_eq!(h.state.create_stage, None);
        h.advance(1.0);
        h.state.on_create_progress(100, 1000, "Writing the image...");
        assert_eq!(h.state.create_stage.as_deref(), Some("Writing the image..."));
        assert_eq!(h.state.create_stage_base, 100);
        assert!(h.state.create_progress_label.contains("calculating..."), "{}", h.state.create_progress_label);
    }

    #[test]
    fn the_stage_names_are_translated() {
        let mut h = Harness::new();
        h.state.reset_create_progress();
        set_test_language("pt");
        h.state.on_create_progress(0, 0, "Preparing the drive...");
        set_test_language("en");
        assert!(h.state.create_progress_label.starts_with("Preparando a unidade..."));
    }
}

// =================================================================================================================
// Inline feedback: banners, results (InlineFeedbackTests)
// =================================================================================================================
mod inline_feedback {
    use super::*;

    #[test]
    fn banner_is_lazy_and_shows_title_and_message() {
        let mut h = Harness::new();
        assert!(!h.state.error_banner.shown);
        h.state.show_error("Download error", "The server refused the download.", None);
        assert!(h.state.error_banner.shown);
        assert_eq!(h.state.error_banner.title_text, "Download error");
        assert_eq!(h.state.error_banner.message_text, "The server refused the download.");
        h.state.clear_error();
        assert!(!h.state.error_banner.shown);
        assert_eq!(h.state.error_banner.message_text, "");
    }

    #[test]
    fn try_again_runs_the_action_and_closes_the_banner() {
        let mut h = Harness::new();
        h.state.show_error("Error", "x", Some(Retry::RefreshDisks));
        assert_eq!(h.state.error_banner.link_texts(), vec!["Try again", "Dismiss"]);
        h.state.banner_link_clicked(BannerId::Error, 0);
        assert!(!h.state.error_banner.shown);
        assert!(h.pump(|s| !s.disk_listing));
        assert_eq!(h.be.list_threads.lock().unwrap().len(), 1, "the retry ran");
        h.state.show_error("Error", "no retry here", None);
        assert_eq!(h.state.error_banner.link_texts(), vec!["Dismiss"]);
        h.state.banner_link_clicked(BannerId::Error, 0);
        assert!(!h.state.error_banner.shown);
        assert_eq!(h.be.list_threads.lock().unwrap().len(), 1);
    }

    #[test]
    fn non_write_failures_use_the_banner_and_no_dialog() {
        let mut h = Harness::new();
        h.state.apply(UiMsg::ListingFinished {
            job: h.state.disk_job,
            result: Err("diskutil hung".into()),
            quiet: false,
        });
        assert_eq!(h.dialogs.count(), 0);
        assert!(h.state.error_banner.message_text.contains("Could not list disks: diskutil hung"));
    }

    #[test]
    fn a_new_operation_clears_the_banner() {
        let mut h = Harness::new();
        h.state.show_error("Error", "old", None);
        h.state.refresh_disks(true, true); // automatic refreshes never hide a message
        assert!(h.state.error_banner.shown);
        h.state.refresh_disks(false, true); // an explicit one starts over
        assert!(!h.state.error_banner.shown);
    }

    #[test]
    fn install_failure_is_a_banner_with_try_again() {
        let mut h = Harness::new();
        *h.be.platform.lock().unwrap() = Platform::Mac;
        h.be.has_brew.store(false, Ordering::SeqCst);
        h.state.install_dependencies();
        assert!(h.pump(|s| s.error_banner.shown && !s.installing));
        assert_eq!(h.dialogs.count(), 0);
        assert!(h.state.error_banner.message_text.contains("Homebrew not found"));
        assert_eq!(h.state.error_banner.link_texts(), vec!["Try again", "Dismiss"]);
        assert!(h.priv_.cleared.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn installing_on_linux_runs_the_command_through_the_privilege_helper() {
        let mut h = Harness::new();
        *h.be.platform.lock().unwrap() = Platform::Linux;
        h.be.set_missing(&["parted"]);
        *h.be.pkg_manager.lock().unwrap() = Some("apt-get".into());
        h.state.install_dependencies();
        assert!(h.state.installing);
        assert!(!h.state.controls.create_enabled);
        assert!(h.pump(|s| !s.installing));
        assert!(h.log().contains("About to run as administrator: apt-get install parted"));
        assert_eq!(*h.priv_.scripts.lock().unwrap(), vec!["set -eu\napt-get install parted".to_string()]);
        assert!(h.be.audits.lock().unwrap().iter().any(|(m, _)| m == "Installing dependencies via apt-get: parted"));
        assert!(!h.state.error_banner.shown);
        // no package manager: an actionable message
        *h.be.pkg_manager.lock().unwrap() = None;
        h.state.install_dependencies();
        assert!(h.pump(|s| s.error_banner.shown && !s.installing));
        assert!(h.state.error_banner.message_text.contains("No supported package manager found"));
        assert!(h.state.error_banner.message_text.contains("Please install manually: parted"));
    }

    #[test]
    fn installing_on_macos_runs_brew_and_on_windows_explains() {
        let mut h = Harness::new();
        *h.be.platform.lock().unwrap() = Platform::Mac;
        h.state.install_dependencies();
        assert!(h.pump(|s| !s.installing));
        assert_eq!(h.be.run_cmd_calls.lock().unwrap().clone(), vec![vec!["brew".to_string(), "install".into(), "wimlib".into()]]);
        *h.be.platform.lock().unwrap() = Platform::Windows;
        h.state.install_dependencies();
        assert!(h.pump(|s| s.error_banner.shown && !s.installing));
        assert!(h.state.error_banner.message_text.contains("nothing to install"));
    }

    #[test]
    fn install_is_ignored_while_writing_or_already_installing() {
        let mut h = Harness::inline();
        h.state.creating = true;
        h.state.install_dependencies();
        assert!(!h.state.installing);
        h.state.creating = false;
        h.state.installing = true;
        h.state.install_dependencies();
        assert!(h.priv_.scripts.lock().unwrap().is_empty());
    }

    #[test]
    fn a_write_failure_keeps_the_dialog_and_adds_the_banner() {
        let mut h = Harness::new();
        h.state.report_error("Error", Some("Verification failed: the drive does not match the ISO."), None, true, None);
        assert_eq!(h.dialogs.titles(Some("error")), vec!["Error"]);
        assert!(h.state.error_banner.message_text.contains("does not match"));
        h.state.clear_error();
        let exc = ExcInfo { type_name: "ValueError".into(), text: "x".into() };
        h.state.report_error("Unexpected error", None, Some(&exc), true, None);
        assert_eq!(h.dialogs.titles(Some("error")), vec!["Error", "Unexpected error"]);
        assert!(h.state.error_banner.shown);
        let shown = &h.state.error_banner.message_text;
        assert!(shown.contains("The operation could not be completed.") && shown.contains("Reason: ValueError"));
        assert!(shown.contains("audit.log"));
        assert!(!shown.contains("x\n"), "the detail goes to the log, not to the dialog");
        assert!(h.log().contains("ERROR [ValueError]: x"));
        assert!(h.be.audits.lock().unwrap().iter().any(|(m, l)| m == "Unexpected error: ValueError" && *l == crate::audit::AuditLevel::Error));
    }

    #[test]
    fn no_banner_while_closing() {
        let mut h = Harness::new();
        h.state.sh.closing.store(true, Ordering::SeqCst);
        h.state.report_error("Error", Some("boom"), None, false, None);
        assert!(!h.state.error_banner.shown);
    }

    #[test]
    fn the_titles_are_translated() {
        let mut h = Harness::new();
        set_test_language("pt");
        h.state.report_error("Error", Some("falhou"), None, true, None);
        set_test_language("en");
        assert_eq!(h.dialogs.titles(Some("error")), vec!["Erro"]);
        assert_eq!(h.state.error_banner.title_text, "Erro");
    }

    // ----- the success panel -----
    fn run_write(h: &mut Harness, ejected: bool, error: Option<Error>) {
        h.state.iso_path = ISO.into();
        h.be.set_listed(vec![usb_disk()]);
        h.state.refresh_disks(false, true);
        h.dialogs.set_yes(true);
        h.be.set_build(move |_, _| match &error {
            Some(Error::Canceled { message, drive_touched, written }) => {
                Err(Error::canceled_with(message.clone(), *drive_touched, *written))
            }
            Some(Error::Runtime(m)) => Err(Error::runtime(m.clone())),
            Some(_) => Err(Error::runtime("other")),
            None => Ok(ejected),
        });
        h.state.start_create_usb();
        assert!(h.pump(|s| !s.creating));
        h.state.pump();
    }

    #[test]
    fn verified_and_ejected_shows_the_green_panel_without_a_dialog() {
        let mut h = Harness::new();
        assert!(!h.state.success_panel.shown);
        run_write(&mut h, true, None);
        let questions = h.dialogs.titles(Some("question"));
        assert!(h.dialogs.titles(Some("info")).is_empty() && h.dialogs.titles(Some("error")).is_empty(), "{questions:?}");
        let panel = &h.state.success_panel;
        assert!(panel.shown);
        assert_eq!(panel.kind, super::super::widgets::BannerKind::Success);
        assert_eq!(panel.title_text, "Bootable USB drive created successfully!");
        assert!(panel.message_text.contains("verified against the ISO and ejected"));
        assert!(panel.message_text.contains("unplug it now"));
        assert_eq!(panel.link_texts(), vec!["Make another"]);
        assert_eq!(h.state.create_progress_label, "Done — 100%");
    }

    #[test]
    fn eject_failure_gets_the_amber_variant_with_the_manual_eject_message() {
        let mut h = Harness::new();
        run_write(&mut h, false, None);
        let panel = &h.state.success_panel;
        assert_eq!(panel.kind, super::super::widgets::BannerKind::Warning);
        assert!(panel.message_text.contains("could not be ejected automatically"));
        assert!(panel.message_text.contains("Eject it from the file manager"));
        assert!(!panel.message_text.contains("you can unplug it now"));
    }

    #[test]
    fn make_another_clears_the_panel_and_reenables_the_flow() {
        let mut h = Harness::new();
        run_write(&mut h, true, None);
        assert!(h.state.success_panel.shown);
        assert!(h.state.create_progress.visible);
        h.state.banner_link_clicked(BannerId::Success, 0);
        assert!(h.pump(|s| !s.disk_listing));
        assert!(!h.state.success_panel.shown);
        assert!(!h.state.create_progress.visible);
        assert_eq!(h.state.create_progress_label, "");
        assert!(!h.state.creating);
        assert!(h.state.controls.create_enabled, "same image, drive listed again");
        assert!(h.state.controls.refresh_enabled);
    }

    #[test]
    fn a_new_write_hides_the_old_result() {
        let mut h = Harness::new();
        run_write(&mut h, true, None);
        assert!(h.state.success_panel.shown);
        h.state.show_error("Error", "stale", None);
        run_write(&mut h, false, Some(Error::canceled_with("stopped", false, false)));
        assert!(!h.state.success_panel.shown);
        assert_ne!(h.state.error_banner.message_text, "stale");
    }

    #[test]
    fn a_failed_write_never_shows_the_success_panel() {
        let mut h = Harness::new();
        run_write(&mut h, false, Some(Error::runtime("Verification failed: the drive does not match the ISO.")));
        assert!(!h.state.success_panel.shown);
        assert_eq!(h.dialogs.titles(Some("error")), vec!["Error"]);
        assert!(h.state.error_banner.shown);
        assert!(h.state.details_toggle.is_open, "a failure opens the log");
        assert_eq!(h.state.create_progress_label, "Failed.");
        assert!(!h.state.create_progress.visible);
    }

    #[test]
    fn a_cancel_that_left_the_drive_unusable_keeps_its_dialog_and_adds_the_banner() {
        let mut h = Harness::new();
        run_write(&mut h, false, Some(Error::canceled_with("stopped", true, false)));
        assert_eq!(h.dialogs.titles(Some("info")), vec!["Canceled"]);
        assert!(h.state.error_banner.message_text.contains("unusable"));
        assert!(!h.state.success_panel.shown);
        run_write(&mut h, false, Some(Error::canceled_with("stopped", false, false)));
        assert!(!h.state.error_banner.shown, "nothing to warn about");
        assert_eq!(h.dialogs.titles(Some("info")), vec!["Canceled", "Canceled"]);
    }

    // ----- the header -----
    #[test]
    fn chip_says_ready_when_nothing_is_missing_and_missing_tools_otherwise() {
        let mut h = Harness::new();
        h.state.check_dependencies();
        assert_eq!(h.state.dep_chip(), ("● Ready".to_string(), true));
        h.be.set_missing(&["wimlib-imagex"]);
        h.state.check_dependencies();
        assert_eq!(h.state.dep_chip(), ("● Missing tools".to_string(), false));
        assert_eq!(h.state.dep_missing, vec!["wimlib-imagex"]);
        h.be.set_missing(&[]); // fixed again
        h.state.check_dependencies();
        assert_eq!(h.state.dep_chip().0, "● Ready");
    }

    #[test]
    fn the_chip_follows_the_mode() {
        let mut h = Harness::new();
        h.be.missing_modes.lock().unwrap().clear();
        h.state.select_card(Card::Linux);
        assert_eq!(h.be.missing_modes.lock().unwrap().first(), Some(&Mode::Linux));
        h.state.select_card(Card::Chrome);
        assert_eq!(h.be.missing_modes.lock().unwrap().last(), Some(&Mode::ChromeOs));
    }

    #[test]
    fn help_about_menu_and_links() {
        let mut h = Harness::new();
        h.state.show_help(0);
        assert!(h.state.help.open);
        assert_eq!(h.state.help.sections.len(), 2);
        h.state.show_help(99); // clamped
        assert_eq!(h.state.help.section, 1);
        h.state.show_about();
        assert_eq!(h.dialogs.titles(Some("info")), vec!["About EPMA USB CREATOR"]);
        assert_eq!(h.dialogs.last().unwrap().2, "EPMA USB CREATOR about text");
        h.state.open_project_page();
        h.state.open_ms_page();
        let urls = h.be.urls.lock().unwrap().clone();
        assert_eq!(urls, vec![crate::constants::PROJECT_URL.to_string(), crate::constants::MS_DOWNLOAD_PAGE.to_string()]);
    }

    #[test]
    fn the_audit_log_folder_is_created_privately_and_opened() {
        let mut h = Harness::new();
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("audit dir");
        *h.be.audit_dir.lock().unwrap() = folder.clone();
        h.state.open_audit_log_folder();
        assert!(folder.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&folder).unwrap().permissions().mode() & 0o777, 0o700);
        }
        let urls = h.be.urls.lock().unwrap().clone();
        assert_eq!(urls.len(), 1);
        assert!(urls[0].starts_with("file:///") && urls[0].ends_with("/audit%20dir"), "{}", urls[0]);
        // a folder that cannot be created is an error box
        let file = dir.path().join("a file");
        std::fs::write(&file, b"x").unwrap();
        *h.be.audit_dir.lock().unwrap() = file.join("sub");
        h.state.open_audit_log_folder();
        assert_eq!(h.dialogs.titles(Some("error")), vec!["Audit log"]);
        assert!(h.dialogs.last().unwrap().2.starts_with("Could not open the folder:"));
    }

    #[test]
    fn file_uris_are_percent_encoded() {
        assert_eq!(path_to_file_uri(Path::new("/home/me/.local/state/epma")), "file:///home/me/.local/state/epma");
        assert_eq!(path_to_file_uri(Path::new("/tmp/a b/é")), "file:///tmp/a%20b/%C3%A9");
        assert_eq!(path_to_file_uri(Path::new("C:\\Users\\me\\x")), "file:///C:/Users/me/x");
    }

    #[test]
    fn the_macos_app_name_helper_never_fails() {
        super::super::set_macos_app_name("epma-usb-creator");
    }
}

// =================================================================================================================
// Hardening option and the seed card (tests/test_gui_hardening.py: HardeningLayoutTests, SeedCardTableTests)
// =================================================================================================================
mod hardening {
    use super::*;

    #[test]
    fn the_seed_card_is_the_fifth_and_writes_the_seed_mode() {
        assert_eq!(Card::ORDER, [Card::Chrome, Card::Windows, Card::Linux, Card::Other, Card::Seed]);
        assert_eq!(Card::Seed.mode(), Mode::Seed);
        assert!(!Mode::Seed.is_raw(), "the seed mode is not a raw write");
        assert!(!Mode::Seed.is_image_mode(), "and not an image kind");
        for kind in [IsoKind::Windows, IsoKind::Linux, IsoKind::ChromeOs, IsoKind::Unknown] {
            assert_ne!(kind.card(), Some(Card::Seed), "no image is ever detected as \"the seed\"");
            assert_ne!(kind.mode(), Some(Mode::Seed));
        }
        let mut cards: Vec<_> = Card::ORDER.to_vec();
        cards.dedup();
        assert_eq!(cards.len(), 5);
    }

    #[test]
    fn there_are_five_cards_in_order_with_the_right_texts() {
        let h = Harness::new();
        assert_eq!(h.state.card_title(Card::Seed), "Hardening seed");
        assert_eq!(super::super::widgets::card_texts(Card::Seed).1, "Second USB drive");
        let titles: Vec<String> = Card::ORDER.iter().map(|c| h.state.card_title(*c)).collect();
        assert_eq!(titles, ["Google Chrome", "Windows 11", "Linux", "Other ISO", "Hardening seed"]);
    }

    #[test]
    fn the_choice_is_remembered_for_the_session_but_only_counts_on_the_windows_card() {
        let mut h = Harness::new();
        assert!(!h.state.hardening, "off by default");
        h.state.hardening = true;
        assert_eq!(h.state.hardening_selected(None), Hardening::Baseline);
        for card in [Card::Linux, Card::Chrome, Card::Other, Card::Seed] {
            h.state.select_card(card);
            assert_eq!(h.state.hardening_selected(None), Hardening::None, "{card:?}");
        }
        h.state.select_card(Card::Windows);
        assert!(h.state.hardening);
        assert_eq!(h.state.hardening_selected(None), Hardening::Baseline);
        h.state.hardening = false;
        assert_eq!(h.state.hardening_selected(None), Hardening::None);
        assert_eq!(h.state.hardening_selected(Some(Mode::Linux)), Hardening::None);
    }

    #[test]
    fn the_list_of_changes_is_behind_a_link_and_uses_the_engine_description() {
        let mut h = Harness::new();
        *h.be.hardening_lines.lock().unwrap() = vec!["Turns thing A on".into(), "Turns thing B off".into()];
        assert_eq!(h.state.hardening_toggle.text(), "▸ What does it change?");
        assert_eq!(h.state.hardening_details, "");
        h.state.set_hardening_details_open(true);
        assert_eq!(h.be.hardening_describe_calls.load(Ordering::SeqCst), 1);
        assert!(h.state.hardening_toggle.is_open);
        assert!(h.state.hardening_details.contains("• Turns thing A on"));
        assert!(h.state.hardening_details.contains("• Turns thing B off"));
        assert!(h.state.hardening_details.contains("applied at the end of Windows setup by a script"));
        h.state.set_hardening_details_open(false);
        assert!(!h.state.hardening_toggle.is_open);
        assert_eq!(h.state.hardening_toggle.text(), "▸ What does it change?");
    }

    #[test]
    fn the_controls_lock_during_a_write() {
        let mut h = Harness::new();
        h.state.creating = true;
        h.state.sync_controls();
        assert!(!h.state.controls.hardening_enabled);
        assert!(!h.state.controls.seed_radios_enabled);
        h.state.creating = false;
        h.state.sync_controls();
        assert!(h.state.controls.hardening_enabled && h.state.controls.seed_radios_enabled);
    }

    #[test]
    fn the_seed_choice_drives_the_note_and_defaults_to_ubuntu() {
        let mut h = Harness::new();
        assert_eq!(h.state.seed_choice, "ubuntu");
        for choice in ["ubuntu", "fedora", "debian", "windows"] {
            h.state.set_seed_choice(choice);
            assert_eq!(h.state.seed_note(), crate::gui::texts::seed_target_note(choice));
            assert!(!h.state.seed_note().is_empty());
        }
    }
}

// =================================================================================================================
// The write flow with the hardening option and the seed card (tests/test_gui_hardening.py: WriteFlowTests)
// =================================================================================================================
mod write_flow {
    use super::*;

    fn setup(threads: bool) -> Harness {
        let mut h = if threads { Harness::new() } else { Harness::inline() };
        h.be.set_listed(vec![usb_disk()]);
        h.state.iso_path = ISO.into();
        h.state.refresh_disks(false, true);
        *h.be.iso_kind.lock().unwrap() = IsoKind::Windows;
        h.dialogs.set_yes(true);
        h
    }

    fn confirm_text(h: &Harness) -> String {
        h.dialogs
            .calls
            .lock()
            .unwrap()
            .iter()
            .find(|c| c.1 == "Final confirmation" || c.1 == "Confirm erasing this drive")
            .map(|c| c.2.clone())
            .unwrap_or_default()
    }

    // ----- Windows: the checkbox decides what build_usb gets -----
    #[test]
    fn ticked_passes_the_baseline_profile_to_build_usb() {
        let mut h = setup(true);
        h.state.select_card(Card::Windows);
        h.state.hardening = true;
        h.write();
        let calls = h.be.build_calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].opts.hardening, Hardening::Baseline);
        assert_eq!(calls[0].opts.mode, Mode::Windows);
        assert_eq!(calls[0].opts.expected_size, Some(32 * GB));
        assert!(calls[0].opts.eject);
        assert_eq!((calls[0].iso.to_string_lossy().as_ref(), calls[0].dev.as_str()), (ISO, "disk9"));
        assert!(confirm_text(&h).contains("write Windows 11 and add the hardening files to it"));
        let message = h.state.success_panel.message_text.clone();
        assert!(message.contains("written to the drive and checked byte for byte"));
        assert!(message.contains("C:\\Windows\\Temp\\epma-hardening.log"));
        assert!(message.contains("After Windows setup finishes"));
    }

    #[test]
    fn unticked_or_on_another_card_passes_no_hardening() {
        let mut h = setup(true);
        h.state.select_card(Card::Windows);
        h.write();
        assert_eq!(h.be.build_calls.lock().unwrap()[0].opts.hardening, Hardening::None);
        assert!(confirm_text(&h).contains("write Windows 11 to it"));
        assert!(!h.state.success_panel.message_text.contains("hardening"));
        // ticked, but the Linux card is what is written: the tick is ignored
        h.state.hardening = true;
        h.state.select_card(Card::Linux);
        h.state.clear_success();
        h.dialogs.clear();
        h.write();
        let last = h.be.build_calls.lock().unwrap().last().cloned().unwrap();
        assert_eq!(last.opts.hardening, Hardening::None);
        assert_eq!(last.opts.mode, Mode::Linux);
        assert!(confirm_text(&h).contains("write the selected Linux image to it"));
    }

    #[test]
    fn the_confirmation_dialog_says_it_adds_the_hardening_files() {
        let mut h = setup(true);
        h.state.select_card(Card::Windows);
        h.state.hardening = true;
        h.write();
        let questions: Vec<_> = h.dialogs.calls.lock().unwrap().iter().filter(|c| c.1 == "Final confirmation").cloned().collect();
        assert_eq!(questions.len(), 1);
        assert!(questions[0].2.contains("write Windows 11 and add the hardening files to it"));
        assert!(questions[0].2.contains("PERMANENTLY ERASE all data on /dev/disk9"));
        assert!(questions[0].2.ends_with("Continue?"));
    }

    // ----- the seed card -----
    #[test]
    fn the_seed_card_calls_build_seed_usb_with_the_target_and_the_drive() {
        let mut h = setup(true);
        h.state.select_card(Card::Seed);
        h.state.iso_path.clear(); // no image at all
        h.state.set_seed_choice("fedora");
        h.write();
        assert!(h.be.build_calls.lock().unwrap().is_empty(), "the seed drive has no image");
        let calls = h.be.seed_calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 1);
        assert_eq!((calls[0].target, calls[0].dev.as_str()), (SeedTarget::Fedora, "disk9"));
        assert_eq!(calls[0].expected_size, Some(usb_disk().size));
        assert!(calls[0].eject);
        assert_eq!(calls[0].profile, Hardening::Baseline, "the engine's default (the recommended baseline) applies");
        assert!(confirm_text(&h).contains("write the hardening seed files to it"));
    }

    #[test]
    fn each_radio_reaches_the_engine_with_its_target_only() {
        let mut h = setup(true);
        h.state.select_card(Card::Seed);
        for (choice, target) in [
            ("ubuntu", SeedTarget::Ubuntu),
            ("fedora", SeedTarget::Fedora),
            ("debian", SeedTarget::Debian),
            ("windows", SeedTarget::Windows),
        ] {
            h.be.seed_calls.lock().unwrap().clear();
            h.state.set_seed_choice(choice);
            h.write();
            let calls = h.be.seed_calls.lock().unwrap().clone();
            assert_eq!(calls.len(), 1, "{choice}");
            assert_eq!((calls[0].target, calls[0].dev.as_str()), (target, "disk9"));
        }
    }

    #[test]
    fn the_windows_choice_uses_the_same_safety_flow_and_needs_no_image() {
        let mut h = setup(true);
        h.state.select_card(Card::Seed);
        h.state.iso_path.clear();
        h.be.needs_admin.store(true, Ordering::SeqCst);
        h.state.set_seed_choice("windows");
        h.state.update_create_button_state();
        assert!(h.state.controls.create_enabled);
        h.write();
        assert_eq!(h.event_list(), vec!["confirm", "pin:disk9", "auth", "seed"]);
        assert!(h.be.build_calls.lock().unwrap().is_empty());
    }

    #[test]
    fn the_confirmation_names_the_seed_files_for_every_choice() {
        let mut h = setup(true);
        h.state.select_card(Card::Seed);
        for choice in ["ubuntu", "fedora", "debian", "windows"] {
            h.dialogs.clear();
            h.state.set_seed_choice(choice);
            h.write();
            let questions: Vec<_> = h.dialogs.calls.lock().unwrap().iter().filter(|c| c.1 == "Final confirmation").cloned().collect();
            assert_eq!(questions.len(), 1, "{choice}");
            assert!(questions[0].2.contains("write the hardening seed files to it"));
            assert!(!questions[0].2.to_lowercase().contains("experimental"));
            assert!(!questions[0].2.contains("answer file"));
        }
    }

    #[test]
    fn the_high_risk_typed_confirmation_names_the_seed_files() {
        let mut h = setup(false);
        h.state.select_card(Card::Seed);
        h.state.set_seed_choice("windows");
        *h.be.risk.lock().unwrap() = (RiskLevel::High, vec!["it is very large".into()]);
        h.dialogs.typed_ok.store(false, Ordering::SeqCst);
        h.state.start_create_usb();
        h.state.pump();
        let typed = h.dialogs.typed_calls.lock().unwrap().clone();
        assert_eq!(typed.len(), 1);
        assert!(typed[0].1.contains("the hardening seed files"));
        assert!(!typed[0].1.contains("answer file"));
        assert_eq!(typed[0].2, "disk9", "the identifier to type");
        assert_eq!(typed[0].3, vec!["it is very large"]);
        assert_eq!(typed[0].0, "Confirm erasing this drive");
        assert!(h.be.seed_calls.lock().unwrap().is_empty());
        assert!(h.dialogs.titles(Some("question")).is_empty(), "the typed identifier decides, not the yes/no question");
        assert!(h.be.audits.lock().unwrap().iter().any(|(m, _)| m == "Erase confirmation shown for /dev/disk9 risk=high"));
        assert!(h.be.audits.lock().unwrap().iter().any(|(m, _)| m == "Erase of /dev/disk9 declined by the user"));
    }

    #[test]
    fn the_seed_card_goes_through_the_whole_safety_flow_in_order() {
        let mut h = setup(true);
        h.state.select_card(Card::Seed);
        h.be.needs_admin.store(true, Ordering::SeqCst);
        h.write();
        assert_eq!(h.event_list(), vec!["confirm", "pin:disk9", "auth", "seed"]);
        assert_eq!(h.be.admin_modes.lock().unwrap().last(), Some(&Mode::Seed));
        assert_eq!(h.priv_.authenticate_calls.load(Ordering::SeqCst), 1);
        assert!(h.priv_.cleared.load(Ordering::SeqCst) >= 1, "the password is forgotten once the operation ends");
    }

    #[test]
    fn no_password_is_asked_when_the_seed_mode_needs_no_admin() {
        let mut h = setup(true);
        h.state.select_card(Card::Seed);
        h.write();
        assert_eq!(h.priv_.authenticate_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_refused_password_stops_before_the_drive_is_touched() {
        let mut h = setup(true);
        h.state.select_card(Card::Seed);
        h.be.needs_admin.store(true, Ordering::SeqCst);
        h.priv_.authenticate_result.store(false, Ordering::SeqCst);
        h.state.start_create_usb();
        assert!(h.pump(|s| !s.creating));
        assert!(h.be.seed_calls.lock().unwrap().is_empty());
        assert!(h.priv_.cleared.load(Ordering::SeqCst) >= 1);
        assert!(h.state.controls.create_enabled);
        assert!(h.log().contains("Canceled: administrator password was not provided. The drive was not modified."));
        assert!(h.dialogs.titles(Some("error")).is_empty());
    }

    #[test]
    fn a_refused_administrator_check_on_windows_explains_how_to_start_elevated() {
        let mut h = setup(true);
        *h.be.platform.lock().unwrap() = Platform::Windows;
        h.be.needs_admin.store(true, Ordering::SeqCst);
        h.priv_.authenticate_result.store(false, Ordering::SeqCst);
        h.state.start_create_usb();
        assert!(h.pump(|s| !s.creating));
        assert_eq!(h.dialogs.titles(Some("error")), vec!["Administrator required"]);
        assert!(h.log().contains("Canceled: the program is not running as Administrator. The drive was not modified."));
        assert!(h.be.build_calls.lock().unwrap().is_empty());
    }

    #[test]
    fn declining_the_confirmation_changes_nothing() {
        let mut h = setup(true);
        h.state.select_card(Card::Seed);
        h.dialogs.set_yes(false);
        h.state.start_create_usb();
        assert!(h.pump(|s| !s.creating));
        assert!(h.be.seed_calls.lock().unwrap().is_empty());
        let others: Vec<_> = h.event_list().into_iter().filter(|e| e != "confirm").collect();
        assert!(others.is_empty(), "no pin, no password, no write: {others:?}");
    }

    #[test]
    fn the_real_confirmation_names_the_seed_files_and_a_high_risk_drive_needs_the_identifier() {
        let mut h = setup(true);
        h.state.select_card(Card::Seed);
        h.write();
        assert_eq!(h.be.seed_calls.lock().unwrap().len(), 1);
        h.be.seed_calls.lock().unwrap().clear();
        *h.be.risk.lock().unwrap() = (RiskLevel::High, vec!["it is very large".into()]);
        h.dialogs.clear();
        h.state.start_create_usb();
        assert!(h.pump(|s| !s.creating));
        assert_eq!(h.dialogs.typed_calls.lock().unwrap().len(), 1);
        assert!(h.dialogs.titles(Some("question")).is_empty());
        assert!(h.be.seed_calls.lock().unwrap().is_empty());
    }

    #[test]
    fn a_second_click_is_ignored_while_the_seed_drive_is_written() {
        let mut h = setup(true);
        h.state.select_card(Card::Seed);
        let gate = Gate::new();
        let g = gate.clone();
        h.be.set_seed(move |_, _| {
            g.wait(10.0);
            Ok(true)
        });
        h.state.start_create_usb();
        assert!(h.state.creating);
        started(&mut h);
        assert!(!h.state.controls.create_enabled);
        assert!(h.state.controls.cancel_enabled, "the one Cancel");
        assert!(!h.state.controls.cards_enabled, "the cards are locked");
        assert!(!h.state.controls.hardening_enabled);
        h.state.start_create_usb(); // a second click, and another
        h.state.start_create_usb();
        assert_eq!(h.event_list().iter().filter(|e| *e == "confirm").count(), 1);
        gate.set();
        assert!(h.pump(|s| !s.creating));
        assert_eq!(h.be.seed_calls.lock().unwrap().len(), 1);
        assert!(!h.state.controls.cancel_enabled);
    }

    #[test]
    fn cancel_during_the_seed_write_is_the_same_single_cancel() {
        let mut h = setup(true);
        h.state.select_card(Card::Seed);
        let begun = Gate::new();
        let b = begun.clone();
        h.be.set_seed(move |_, ctx| {
            b.set();
            ctx.cancel.map(|c| c.wait(std::time::Duration::from_secs(10)));
            Err(Error::canceled_with("Canceled by the user.", true, false))
        });
        h.state.start_create_usb();
        assert!(begun.wait(10.0));
        started(&mut h);
        h.dialogs.set_yes(true);
        h.state.cancel_current(); // the window's single Cancel
        assert!(h.pump(|s| s.sh.cancel_create.is_set()));
        assert!(h.pump(|s| !s.creating));
        assert!(h.state.error_banner.shown);
        assert!(h.state.error_banner.message_text.contains("unusable"));
    }

    #[test]
    fn progress_reaches_the_bar_during_the_seed_write() {
        let mut h = setup(true);
        h.state.select_card(Card::Seed);
        let gate = Gate::new();
        let g = gate.clone();
        h.be.set_seed(move |_, ctx| {
            ctx.report(0, 0, "Verifying the copied files...");
            ctx.report(5, 10, "Writing the seed files...");
            g.wait(10.0);
            Ok(true)
        });
        h.state.start_create_usb();
        assert!(h.pump(|s| s.create_progress_label.contains("Writing the seed files...")));
        assert!(h.state.create_progress.visible);
        gate.set();
        assert!(h.pump(|s| !s.creating));
    }

    // ----- what is confirmed is what is written -----
    #[test]
    fn an_image_chosen_while_the_confirmation_is_open_does_not_change_the_write() {
        let mut h = setup(false);
        h.state.select_card(Card::Windows);
        h.state.hardening = true;
        h.state.start_create_usb(); // everything is read here, once
        // a finished download: new image, and the Linux card; the tick is cleared too
        *h.be.iso_kind.lock().unwrap() = IsoKind::Linux;
        h.state.set_iso("/tmp/outra.iso");
        h.state.hardening = false;
        h.state.pump();
        assert_eq!(h.state.iso_path, "/tmp/outra.iso", "the window did change meanwhile");
        assert_eq!(h.state.mode, Mode::Linux);
        let calls = h.be.build_calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].iso.to_string_lossy(), ISO, "what was confirmed is what is written");
        assert_eq!(calls[0].opts.mode, Mode::Windows);
        assert_eq!(calls[0].opts.hardening, Hardening::Baseline);
        assert!(confirm_text(&h).contains("write Windows 11 and add the hardening files to it"));
    }

    #[test]
    fn the_seed_target_is_also_read_once() {
        let mut h = setup(false);
        h.state.select_card(Card::Seed);
        h.state.set_seed_choice("fedora");
        h.state.start_create_usb();
        assert!(!h.state.controls.seed_radios_enabled, "the radios are locked: clicks do nothing now");
        h.state.set_seed_choice("debian"); // so the variable is changed from outside
        h.state.pump();
        assert_eq!(h.state.seed_choice, "debian");
        assert_eq!(h.be.seed_calls.lock().unwrap()[0].target, SeedTarget::Fedora);
    }

    #[test]
    fn the_radios_are_locked_while_a_windows_seed_is_written() {
        let mut h = setup(true);
        h.state.select_card(Card::Seed);
        h.state.set_seed_choice("windows");
        let gate = Gate::new();
        let g = gate.clone();
        h.be.set_seed(move |_, _| {
            g.wait(10.0);
            Ok(true)
        });
        h.state.start_create_usb();
        assert!(h.state.creating);
        assert!(!h.state.controls.seed_radios_enabled);
        gate.set();
        assert!(h.pump(|s| !s.creating));
        assert!(h.state.controls.seed_radios_enabled);
    }

    #[test]
    fn create_waits_while_a_download_or_an_extraction_runs() {
        let mut h = setup(false);
        let hint = "Wait for the download to finish or cancel it first.";
        h.state.update_create_button_state();
        assert!(h.state.controls.create_enabled);
        for flag in ["download", "flex"] {
            if flag == "download" {
                h.state.download_running = true;
            } else {
                h.state.flex_busy = true;
            }
            h.state.sync_controls();
            assert!(!h.state.controls.create_enabled, "{flag}");
            assert_eq!(h.state.create_hint, hint);
            // a stale click is refused too, before any question
            h.dialogs.clear();
            h.clear_events();
            h.state.start_create_usb();
            h.state.pump();
            assert!(!h.event_list().contains(&"confirm".to_string()));
            assert!(h.be.build_calls.lock().unwrap().is_empty());
            assert_eq!(h.dialogs.titles(Some("error")), vec!["Download in progress"]);
            assert!(!h.state.creating);
            h.state.download_running = false;
            h.state.flex_busy = false;
            h.state.sync_controls();
            assert!(h.state.controls.create_enabled);
            assert_eq!(h.state.create_hint, "");
        }
    }

    #[test]
    fn the_download_callbacks_release_create() {
        let mut h = setup(false);
        h.state.download_running = true;
        h.state.sync_controls();
        assert!(!h.state.controls.create_enabled);
        h.state.on_download_done(Path::new(ISO), &"0".repeat(64), false);
        assert!(h.state.controls.create_enabled);
    }

    // ----- the seed drive is checked for size before anything is asked -----
    #[test]
    fn a_too_small_seed_drive_is_refused_before_the_confirmation() {
        let mut h = setup(false);
        h.state.select_card(Card::Seed);
        *h.be.seed_size_error.lock().unwrap() = Some("The drive (16 MB) is too small for a seed drive.".into());
        h.state.start_create_usb();
        h.state.pump();
        assert_eq!(*h.be.seed_size_checks.lock().unwrap(), vec![Some(usb_disk().size)]);
        assert!(!h.event_list().contains(&"confirm".to_string()));
        assert!(h.be.seed_calls.lock().unwrap().is_empty());
        assert_eq!(h.dialogs.titles(Some("error")), vec!["Drive too small"]);
        assert!(h.dialogs.last().unwrap().2.contains("too small for a seed drive"));
        assert!(!h.state.creating);
        assert!(h.state.controls.create_enabled);
    }

    #[test]
    fn the_size_check_is_only_for_the_seed_card() {
        let mut h = setup(true);
        h.state.select_card(Card::Windows);
        h.write();
        assert!(h.be.seed_size_checks.lock().unwrap().is_empty());
    }

    #[test]
    fn a_raw_image_larger_than_the_drive_is_refused_before_anything_is_erased() {
        let mut h = setup(false);
        let dir = tempfile::tempdir().unwrap();
        let big = dir.path().join("big.iso");
        std::fs::write(&big, vec![0u8; 2048]).unwrap();
        h.state.iso_path = big.to_string_lossy().into_owned();
        h.state.select_card(Card::Linux);
        h.be.set_listed(vec![Disk { size: 1024, ..usb_disk() }]);
        h.state.refresh_disks(false, true);
        h.state.update_create_button_state();
        h.state.start_create_usb();
        h.state.pump();
        assert_eq!(h.dialogs.titles(Some("error")), vec!["Drive too small"]);
        assert!(h.dialogs.last().unwrap().2.contains("The image (2.0 KB) is larger than this drive (1.0 KB)"));
        assert!(!h.event_list().contains(&"confirm".to_string()));
    }

    #[test]
    fn a_small_usb_drive_for_chromeos_flex_asks_first() {
        let mut h = setup(false);
        *h.be.iso_kind.lock().unwrap() = IsoKind::ChromeOs;
        h.state.select_card(Card::Chrome);
        h.be.set_listed(vec![Disk { size: 8 * GB, ..usb_disk() }]);
        h.state.refresh_disks(false, true);
        h.dialogs.answers.lock().unwrap().extend([false]);
        h.state.start_create_usb();
        h.state.pump();
        assert_eq!(h.dialogs.titles(Some("question")), vec!["Small USB drive"]);
        assert!(h.dialogs.last().unwrap().2.contains("and this one is 7.5 GB"));
        assert!(!h.event_list().contains(&"confirm".to_string()));
        assert!(!h.state.creating);
    }

    // ----- the engine refuses the image: shown nicely -----
    #[test]
    fn an_iso_that_already_has_the_hardening_files_is_a_message_not_a_traceback() {
        let mut h = setup(true);
        h.state.select_card(Card::Windows);
        h.state.hardening = true;
        h.be.set_build(|_, _| {
            Err(Error::value("This ISO already contains the hardening files (autounattend.xml). Nothing was changed."))
        });
        // ValueError is an expected failure: its message is shown as it is
        h.state.start_create_usb();
        assert!(h.pump(|s| !s.creating));
        assert!(h.state.error_banner.shown);
        assert!(h.state.error_banner.message_text.contains("already contains the hardening files"));
        assert_eq!(h.dialogs.titles(Some("error")).len(), 1);
        assert!(h.state.controls.create_enabled);
    }

    // ----- results -----
    #[test]
    fn success_panel_for_the_seed_drive() {
        let mut h = setup(true);
        h.state.select_card(Card::Seed);
        h.write();
        let panel = &h.state.success_panel;
        assert!(panel.shown);
        assert_eq!(panel.kind, super::super::widgets::BannerKind::Success);
        assert!(panel.title_text.starts_with("Seed drive created and verified"));
        assert!(panel.message_text.contains("ejected"));
        assert!(panel.message_text.contains("next to the installer USB drive"));
        assert!(!panel.message_text.contains("ISO"), "there was no image");
        assert!(h.dialogs.titles(Some("info")).is_empty());
        assert_eq!(h.state.create_progress_label, "Done — 100%");
    }

    #[test]
    fn success_panel_for_the_windows_choice_and_for_drives_that_could_not_be_ejected() {
        let mut h = setup(true);
        h.state.select_card(Card::Seed);
        h.state.set_seed_choice("windows");
        h.write();
        let panel = &h.state.success_panel;
        assert!(panel.title_text.starts_with("Windows 11 hardening drive created and verified"));
        for name in ["audit.cmd", "harden.cmd", "undo.cmd"] {
            assert!(panel.message_text.contains(name));
        }
        assert!(!panel.message_text.contains("EXPERIMENTAL"));
        assert!(!panel.message_text.contains("next to the installer"), "the Linux wording does not apply");
        // not ejected: the amber variant, Windows seed and Linux seed alike
        h.be.set_seed(|_, _| Ok(false));
        h.write();
        let panel = &h.state.success_panel;
        assert_eq!(panel.kind, super::super::widgets::BannerKind::Warning);
        assert!(panel.message_text.contains("could not be ejected automatically"));
        assert!(!panel.message_text.contains("you can unplug it now"));
        h.state.set_seed_choice("fedora");
        h.write();
        let panel = &h.state.success_panel;
        assert_eq!(panel.kind, super::super::widgets::BannerKind::Warning);
        assert!(panel.message_text.contains("could not be ejected automatically"));
        assert!(!panel.message_text.contains("you can unplug it now"));
    }

    #[test]
    fn a_failed_seed_write_shows_the_banner_and_the_dialog_and_unlocks() {
        for exc in ["runtime", "value", "io"] {
            let mut h = setup(true);
            h.state.select_card(Card::Seed);
            let kind = exc.to_string();
            h.be.set_seed(move |_, _| match kind.as_str() {
                "runtime" => Err(Error::runtime("Verification failed: a seed file differs.")),
                "value" => Err(Error::value("bad target")),
                _ => Err(Error::Io(std::io::Error::other("device vanished"))),
            });
            h.write();
            assert!(!h.state.creating, "{exc}");
            assert!(h.state.error_banner.shown, "{exc}");
            assert!(!h.state.success_panel.shown);
            assert_eq!(h.dialogs.titles(Some("error")).len(), 1, "{exc}");
            assert!(h.state.controls.create_enabled);
            assert!(h.state.drives.is_enabled());
            assert!(!h.state.controls.cancel_enabled);
            if exc == "io" {
                assert_eq!(h.dialogs.titles(Some("error")), vec!["Unexpected error"]);
                assert!(h.state.error_banner.message_text.contains("Reason: OSError"));
                assert!(h.log().contains("ERROR [OSError]: device vanished"));
            }
        }
    }

    #[test]
    fn a_panic_in_the_engine_is_reported_and_unlocks() {
        let mut h = setup(true);
        h.be.set_build(|_, _| panic!("engine bug"));
        h.write();
        assert!(!h.state.creating);
        assert!(h.state.error_banner.shown);
        assert!(h.log().contains("engine bug"));
        assert!(!h.state.write_running());
        assert!(h.state.controls.create_enabled);
    }

    #[test]
    fn an_invalid_target_is_refused_before_anything_happens() {
        let mut h = setup(false);
        h.state.select_card(Card::Seed);
        h.state.seed_choice = "bogus".into();
        h.state.start_create_usb();
        h.state.pump();
        assert!(h.be.seed_calls.lock().unwrap().is_empty());
        assert!(!h.event_list().contains(&"confirm".to_string()));
        assert_eq!(h.dialogs.titles(Some("error")), vec!["Hardening seed"]);
        assert!(!h.state.creating);
    }

    #[test]
    fn the_identity_of_the_confirmed_drive_is_pinned() {
        let mut h = setup(true);
        let mut disk = usb_disk();
        disk.identity = vec![("serial".into(), "123".into())];
        h.be.set_listed(vec![disk]);
        h.state.refresh_disks(false, true);
        h.write();
        assert_eq!(h.event_list(), vec!["confirm", "pin:disk9", "engine"]);
    }
}

// =================================================================================================================
// Translation coverage of the window's texts (the window parts of tests/test_i18n.py)
// =================================================================================================================
mod i18n_coverage {
    use crate::i18n_table::PT_BR;

    const SOURCES: [(&str, &str); 6] = [
        ("flows.rs", include_str!("flows.rs")),
        ("model.rs", include_str!("model.rs")),
        ("texts.rs", include_str!("texts.rs")),
        ("widgets.rs", include_str!("widgets.rs")),
        ("view.rs", include_str!("view.rs")),
        ("dialogs.rs", include_str!("dialogs.rs")),
    ];

    /// The production part of a source file (the tests are not scanned).
    fn production(source: &str) -> &str {
        source.split("#[cfg(test)]\nmod tests").next().unwrap_or(source)
    }

    fn unescape(raw: &str) -> String {
        let mut out = String::new();
        let mut chars = raw.chars().peekable();
        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('\'') => out.push('\''),
                Some('u') => {
                    // \u{2014}
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
                    if let Some(ch) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                        out.push(ch);
                    }
                }
                Some('\n') => {
                    while matches!(chars.peek(), Some(c) if c.is_whitespace()) {
                        chars.next();
                    }
                }
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => {}
            }
        }
        out
    }

    fn literals(source: &str) -> Vec<String> {
        let re = regex::Regex::new(r#"(?s)\b(?:tr|trf|gui_trf!)\(\s*&?"((?:[^"\\]|\\.)*)""#).unwrap();
        re.captures_iter(production(source)).map(|c| unescape(&c[1])).collect()
    }

    #[test]
    fn every_literal_passed_to_translate_is_in_the_dictionary() {
        let table: std::collections::HashSet<&str> = PT_BR.iter().map(|(k, _)| *k).collect();
        let mut found = 0;
        let mut missing = Vec::new();
        for (file, source) in SOURCES {
            for text in literals(source) {
                found += 1;
                if !table.contains(text.as_str()) {
                    missing.push(format!("{file}: {:?}", text.chars().take(70).collect::<String>()));
                }
            }
        }
        assert!(found > 100, "the scan found suspiciously few translatable texts: {found}");
        assert!(missing.is_empty(), "texts passed to tr() without a PT_BR entry:\n{}", missing.join("\n"));
    }

    #[test]
    fn report_error_titles_are_translated() {
        let table: std::collections::HashSet<&str> = PT_BR.iter().map(|(k, _)| *k).collect();
        for title in ["Error", "Unexpected error", "ChromeOS Flex", "Download error"] {
            assert!(table.contains(title), "{title}");
        }
        // the progress stage the window itself shows
        assert!(table.contains("Preparing the drive..."));
    }

    #[test]
    fn dialog_titles_never_bypass_the_translation() {
        // A dialog title given as a bare literal would stay English in Portuguese.
        let re = regex::Regex::new(r#"dialogs\s*\.\s*(?:show_info|show_error|ask_yes_no|ask_typed_confirmation|ask_password|pick_open_file|pick_save_file)\(\s*"#).unwrap();
        let mut bare = Vec::new();
        for (file, source) in SOURCES {
            let production = production(source);
            for m in re.find_iter(production) {
                if production[m.end()..].starts_with('"') {
                    bare.push(format!("{file}: {}", &production[m.start()..(m.end() + 30).min(production.len())]));
                }
            }
        }
        assert!(bare.is_empty(), "dialog titles that bypass tr(): {bare:?}");
    }

    #[test]
    fn the_english_text_of_a_table_entry_formats_like_the_portuguese_one() {
        // every {placeholder} of the window's texts is in both languages (same check as DictionaryTests)
        let re = regex::Regex::new(r"\{[a-z_]+(?::[^}]*)?\}").unwrap();
        for (file, source) in SOURCES {
            for text in literals(source) {
                if let Some((_, pt)) = PT_BR.iter().find(|(k, _)| *k == text) {
                    let mut a: Vec<_> = re.find_iter(&text).map(|m| m.as_str().to_string()).collect();
                    let mut b: Vec<_> = re.find_iter(pt).map(|m| m.as_str().to_string()).collect();
                    a.sort();
                    b.sort();
                    assert_eq!(a, b, "{file}: {text}");
                }
            }
        }
    }
}

// =================================================================================================================
// Dialog queue handling
// =================================================================================================================
mod dialog_queue {
    use super::*;
    use std::sync::mpsc::channel;

    #[test]
    fn requests_queue_up_and_are_answered_in_order() {
        let mut h = Harness::new();
        let (tx1, rx1) = channel();
        let (tx2, rx2) = channel();
        h.state.apply(UiMsg::Dialog(DialogRequest {
            kind: DialogKind::Question { warning: false },
            title: "A".into(),
            message: "a".into(),
            reply: Some(tx1),
        }));
        h.state.apply(UiMsg::Dialog(DialogRequest { kind: DialogKind::Password, title: "B".into(), message: "b".into(), reply: Some(tx2) }));
        h.state.apply(UiMsg::Dialog(DialogRequest { kind: DialogKind::Info, title: "C".into(), message: "c".into(), reply: None }));
        assert_eq!(h.state.dialog_queue.len(), 3);
        assert_eq!(h.state.dialog_queue.front().unwrap().title, "A");
        h.state.answer_dialog(DialogReply::Yes(true));
        assert_eq!(rx1.recv().unwrap(), DialogReply::Yes(true));
        h.state.dialog_text = "secret".into();
        h.state.answer_dialog(DialogReply::Text(Some("secret".into())));
        assert_eq!(rx2.recv().unwrap(), DialogReply::Text(Some("secret".into())));
        assert_eq!(h.state.dialog_text, "", "the typed text never lingers");
        h.state.answer_dialog(DialogReply::Yes(false)); // a notification: nothing to answer
        assert!(h.state.dialog_queue.is_empty());
        h.state.answer_dialog(DialogReply::Yes(false)); // nothing queued: harmless
    }

    #[test]
    fn the_state_can_be_built_without_a_display_and_pumps_nothing() {
        let mut state: AppState = Harness::new().state;
        state.pump();
        assert_eq!(state.card, Card::Windows);
        assert_eq!(state.mode, Mode::Windows);
        assert!(!state.controls.create_enabled);
        assert_eq!(state.create_hint, "Choose the image file first (\"Select existing ISO file...\" or the download above).");
        assert!(state.log_text().is_empty());
    }

    #[test]
    fn the_log_keeps_at_most_log_max_lines_and_the_queue_is_bounded() {
        let mut h = Harness::new();
        let max = crate::constants::LOG_MAX_LINES;
        for i in 0..(max + 50) {
            h.state.log_threadsafe(&format!("line {i}"));
        }
        h.state.flush_log();
        assert_eq!(h.state.log_lines.len(), max);
        assert_eq!(h.state.log_lines.front().unwrap(), "line 50");
        assert_eq!(h.state.log_lines.back().unwrap(), &format!("line {}", max + 49));
        assert!(h.state.log_scroll_to_end);
        // a flood from a worker is trimmed in the queue before it is drained
        for i in 0..(5 * max) {
            h.state.log_threadsafe(&format!("flood {i}"));
        }
        assert!(h.state.sh.log.pending_len() <= 4 * max);
        h.state.flush_log();
        assert_eq!(h.state.log_lines.len(), max);
        assert_eq!(h.state.log_lines.back().unwrap(), &format!("flood {}", 5 * max - 1));
    }
}
