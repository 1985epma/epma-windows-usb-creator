"""Tests for the window's part of the hardening feature: the optional checkbox on the Windows 11 card and the
fifth card, "Hardening seed" (a second, small drive that carries auto-install files).

The engine functions (build_usb(hardening=...), build_seed_usb, describe_hardening_windows) belong to other parts of
the feature, so they are always replaced here: these tests only prove that the window asks for the right thing and
that every write goes through the same safety flow (confirmation, typed identifier, password, identity pin, write
lock, single Cancel, progress, result panels). Nothing touches a real device.

Like the other window tests they are skipped when Tk or a display is missing (see tests.test_fixes_gui.GuiTestCase).
"""
import threading
import unittest
from unittest import mock

from tests.helpers import TempDirTestCase, app
from tests.test_fixes_gui import USB_DISK, GuiTestCase

NEW_TEXTS = (
    "Hardening seed", "Auto-install files", "Second USB drive", "Hardening scripts",
    "Hardening scripts and answer file", "More about this choice", "Add hardening settings to the Windows installation (optional)",
    "What does it change?", "Hide the list", "Install target:", "Ubuntu (autoinstall)", "Fedora / RHEL (kickstart)",
    "Debian (script + preseed)", "Create Seed Drive", "the hardening seed files",
    "Windows 11 and add the hardening files", "Seed drive created and verified",
    "The hardening files were written to the drive and checked byte for byte. After Windows setup finishes, "
    "their log will be at {log}.",
    "Adds a few files to the same drive. A script applies the settings at the END of Windows setup and writes "
    "its log to {log}.",
    "The settings are applied at the end of Windows setup by a script, and every change is written to {log}. "
    "You choose the disk, the account and the edition during setup as usual.",
    "Wait for the download to finish or cancel it first.", "Download in progress",
)

# hardening2: the texts the Windows 11 choices of the seed card add (each needs a Portuguese text that differs)
NEW_TEXTS_WINDOWS = (
    "Windows 11 (run after install)", "Windows 11 (during setup, experimental)",
    "Run harden.cmd as administrator on a Windows 11 that is already installed; audit.cmd shows a report first, "
    "undo.cmd goes back.",
    "EXPERIMENTAL, never tested on real Windows. Plug this drive in BEFORE you start the Windows installer and "
    "keep it in until after the first restart. Only 64-bit Intel/AMD (x64) PCs; on ARM use \"run after install\".",
    "the hardening seed files (experimental: includes an answer file for Windows Setup)",
    "The files were checked on the drive and it was ejected — you can unplug it now.",
    "The files were checked on the drive, but it could not be ejected automatically. Eject it from the file "
    "manager before unplugging.",
    "Windows 11 setup drive (experimental) created and verified",
    "Windows 11 hardening drive created and verified",
    "EXPERIMENTAL: plug it in next to the Windows installer USB drive BEFORE you start the Windows installer, and "
    "keep it in until after the first restart of the installation (the hardening runs at the end of Setup). Only "
    "64-bit Intel/AMD (x64) PCs are covered; on an ARM PC use \"run after install\". If nothing was hardened, run "
    "audit.cmd on this drive to see what is in effect; the log is {log}. An invalid answer file can stop an "
    "installation, and the scripts were never run on real Windows: try it on a test machine first.",
    "On a Windows 11 that is already installed, open this drive and run audit.cmd (shows a report, changes "
    "nothing), harden.cmd (as administrator) or undo.cmd (goes back). The scripts were never run on real Windows: "
    "try them on a test machine first.",
)
RADIO_TEXTS = ("Ubuntu (autoinstall)", "Fedora / RHEL (kickstart)", "Debian (script + preseed)",
               "Windows 11 (run after install)", "Windows 11 (during setup, experimental)")
# what the (patched) engine description of the answer file says: the first lines are shown in the card's note
FAKE_DURING_SETUP = ["EXPERIMENTAL: this adds an answer file (autounattend.xml) for Windows Setup.",
                     "An invalid answer file can stop an installation.",
                     "Setup stays interactive for the disk, the account and the edition.",
                     "A fourth line that is not shown."]


class SeedCardTableTests(unittest.TestCase):
    """The tables behind the cards (no window needed)."""

    def test_the_seed_card_is_the_fifth_and_writes_the_seed_mode(self):
        self.assertEqual(app.CARD_ORDER, (app.CARD_CHROME, app.CARD_WINDOWS, app.CARD_LINUX, app.CARD_OTHER,
                                          app.CARD_SEED))
        self.assertEqual(app.CARD_MODE[app.CARD_SEED], app.MODE_SEED)
        self.assertEqual(set(app.CARD_ORDER), set(app.CARD_MODE))

    def test_the_seed_mode_is_not_a_raw_write_and_not_an_image_kind(self):
        self.assertNotIn(app.MODE_SEED, app.RAW_MODES)
        self.assertNotIn(app.MODE_SEED, app.KIND_MODE.values())
        self.assertNotIn(app.CARD_SEED, app.KIND_CARD.values())  # no image is ever detected as "the seed"

    def test_the_new_texts_are_translated(self):
        for text in NEW_TEXTS:
            with self.subTest(text=text):
                self.assertIn(text, app.PT_BR)

    def test_the_card_texts_are_the_ones_fixed_by_the_design(self):
        self.assertEqual(app.SEED_TARGETS, (app.SEED_UBUNTU, app.SEED_FEDORA, app.SEED_DEBIAN, app.SEED_WINDOWS))
        self.assertEqual([t for _k, t in app.App.seed_target_texts()], list(RADIO_TEXTS))

    def test_each_radio_key_maps_to_a_target_and_the_answer_file_flag(self):
        self.assertEqual([k for k, _t in app.App.seed_target_texts()], list(app.SEED_CHOICES))
        self.assertEqual(app.SEED_CHOICES, {
            app.SEED_UBUNTU: (app.SEED_UBUNTU, False), app.SEED_FEDORA: (app.SEED_FEDORA, False),
            app.SEED_DEBIAN: (app.SEED_DEBIAN, False), app.SEED_WINDOWS: (app.SEED_WINDOWS, False),
            app.SEED_CHOICE_WINDOWS_SETUP: (app.SEED_WINDOWS, True)})
        for target, _during in app.SEED_CHOICES.values():
            self.assertIn(target, app.SEED_TARGETS)
        self.assertEqual({t for t, _d in app.SEED_CHOICES.values()}, set(app.SEED_TARGETS))

    def test_the_target_notes_are_translated(self):
        with mock.patch.object(app, "ACTIVE_LANGUAGE", "pt"):
            for choice in app.SEED_CHOICES:
                if choice == app.SEED_CHOICE_WINDOWS_SETUP:
                    continue  # its text comes from the engine; see the next tests
                note = app.App.seed_target_note(None, choice)
                self.assertTrue(note)
                self.assertIn(note, app.PT_BR.values())

    def test_the_during_setup_note_is_short_and_has_the_facts_that_matter(self):
        note = app.App.seed_target_note(None, app.SEED_CHOICE_WINDOWS_SETUP)
        self.assertEqual(note.count("EXPERIMENTAL"), 1)
        self.assertIn("BEFORE you start the Windows installer", note)
        self.assertIn("until after the first restart", note)
        self.assertIn("64-bit Intel/AMD (x64)", note)
        self.assertIn("run after install", note)  # what to use on ARM: the radio's own wording
        self.assertLessEqual(len(note), 240)
        self.assertNotRegex(note.lower(), r"\b(cis|stig|nist|complian|certif)")

    def test_the_full_description_of_the_during_setup_choice_comes_from_the_engine(self):
        with mock.patch.object(app, "describe_windows_seed_during_setup", create=True,
                               return_value=FAKE_DURING_SETUP):
            text = app.App._seed_experimental_details()
        self.assertEqual(text.splitlines(), ["• " + line for line in FAKE_DURING_SETUP])
        with mock.patch.object(app, "describe_windows_seed_during_setup", create=True,
                               return_value="Adds an answer file.\n\nIt may stop Setup.\n"):
            self.assertEqual(app.App._seed_experimental_details(), "• Adds an answer file.\n• It may stop Setup.")

    def test_the_step_heading_follows_the_choice(self):
        headings = {choice: app.App.seed_step_heading(choice) for choice in app.SEED_CHOICES}
        self.assertEqual({headings[c] for c in (app.SEED_UBUNTU, app.SEED_FEDORA, app.SEED_DEBIAN)},
                         {"Auto-install files"})
        self.assertEqual(headings[app.SEED_WINDOWS], "Hardening scripts")
        self.assertEqual(headings[app.SEED_CHOICE_WINDOWS_SETUP], "Hardening scripts and answer file")
        for text in set(headings.values()):
            self.assertIn(text, app.PT_BR)

    def test_the_run_after_install_note_is_the_one_fixed_by_the_design(self):
        self.assertEqual(app.App.seed_target_note(None, app.SEED_WINDOWS),
                         "Run harden.cmd as administrator on a Windows 11 that is already installed; "
                         "audit.cmd shows a report first, undo.cmd goes back.")
        self.assertEqual(app.App.seed_target_note(None, "bogus"), "")

    def test_the_windows_success_texts_are_honest_per_choice(self):
        after = app.App._windows_seed_success_texts(True, False)
        setup = app.App._windows_seed_success_texts(True, True)
        for name in ("audit.cmd", "harden.cmd", "undo.cmd"):
            self.assertIn(name, after[1])
        self.assertIn("never run on real Windows", after[1])
        self.assertNotIn("EXPERIMENTAL", after[1] + after[0])
        self.assertIn("BEFORE you start the Windows installer", setup[1])
        self.assertIn("until after the first restart of the installation", setup[1])
        self.assertIn("Only 64-bit Intel/AMD (x64) PCs are covered", setup[1])
        self.assertIn("on an ARM PC use \"run after install\"", setup[1])
        self.assertIn("run audit.cmd on this drive", setup[1])
        self.assertIn("C:\\Windows\\Temp\\epma-hardening.log", setup[1])
        self.assertNotIn("{log}", setup[1])
        self.assertIn("EXPERIMENTAL", setup[1])
        self.assertIn("experimental", setup[0])
        self.assertIn("never run on real Windows", setup[1])
        self.assertNotEqual(after[0], setup[0])
        self.assertIn("you can unplug it now", after[1])
        notejected = app.App._windows_seed_success_texts(False, False)[1]
        self.assertIn("could not be ejected automatically", notejected)
        self.assertNotIn("you can unplug it now", notejected)
        for text in (*after, *setup, notejected):
            self.assertNotRegex(text.lower(), r"\b(cis|stig|nist|complian|certif)")
            self.assertNotIn("ISO", text)  # there is no image


class HardeningLayoutTests(GuiTestCase):
    def pad_sum(self, card):
        left, right = (int(str(p)) for p in card.grid_info()["padx"])
        return left, right

    def test_there_are_five_cards_in_order_with_the_right_texts(self):
        win = self.win
        self.assertEqual(list(win.cards), list(app.CARD_ORDER))
        self.assertEqual(win.card_titles[app.CARD_SEED], "Hardening seed")
        seed = win.cards[app.CARD_SEED]
        self.assertEqual(seed._subtitle, "Second USB drive")  # true for all five choices (not only "auto-install")
        self.assertEqual([int(win.cards[k].grid_info()["column"]) for k in app.CARD_ORDER], [0, 1, 2, 3, 4])

    def test_the_five_columns_are_equal_and_the_gaps_are_the_same(self):
        win = self.win
        row = win.cards_row
        for column in range(5):
            info = row.grid_columnconfigure(column)
            self.assertEqual((int(info["weight"]), info["uniform"]), (1, "cards"))
        pads = [self.pad_sum(win.cards[k]) for k in app.CARD_ORDER]
        self.assertEqual(len({left + right for left, right in pads}), 1, "every card must be as wide as the others")
        gaps = {pads[i][1] + pads[i + 1][0] for i in range(4)}
        self.assertEqual(len(gaps), 1, "the gap between two neighbours must be the same everywhere")
        self.assertEqual((pads[0][0], pads[-1][1]), (0, 2), "the row is flush with the page on the left")
        # when the window is really laid out, the widths agree too
        win.geometry("780x700")
        win.update_idletasks()
        widths = [win.cards[k].winfo_width() for k in app.CARD_ORDER]
        if min(widths) > 1:
            self.assertLessEqual(max(widths) - min(widths), 1, widths)
            total = sum(widths) + 4 * 12
            self.assertLessEqual(total, win.cards_row.winfo_width() + 1)

    def test_a_long_title_shrinks_to_fit_the_narrower_card(self):
        card = self.win.cards[app.CARD_SEED]
        card._on_resize(mock.Mock(width=96))
        family, size, *_style = card._fit_font(card._title_font, card._title)
        self.assertLess(size, card._title_font[1])
        self.assertGreaterEqual(size, 8)
        card._on_resize(mock.Mock(width=300))
        self.assertEqual(card._fit_font(card._title_font, card._title)[1], card._title_font[1])

    def test_the_seed_card_draws_a_shield_selected_or_not_and_follows_the_state(self):
        card = self.win.cards[app.CARD_SEED]
        kinds = {card.type(i) for i in card.find_all()}
        self.assertIn("polygon", kinds)
        self.assertIn("line", kinds)                 # the tick
        card.set_selected(True)
        self.assertTrue(any(card.itemcget(i, "outline") == card.ACCENT for i in card.find_all()
                            if card.type(i) == "polygon"))
        card.set_enabled(False)                      # locked during a write: still drawn
        self.assertTrue(card.find_all())
        card.set_enabled(True)

    def test_each_card_shows_only_its_own_panel(self):
        win = self.win
        for key in app.CARD_ORDER:
            win.select_card(key)
            win.update_idletasks()
            shown = [k for k, panel in win.panels.items() if panel.winfo_manager() == "grid"]
            self.assertEqual(shown, [key])
            self.assertEqual(win.mode_var.get(), app.CARD_MODE[key])
            self.assertEqual(win.card_var.get(), key)

    def test_the_hardening_checkbox_lives_only_on_the_windows_card_and_is_off_by_default(self):
        win = self.win
        self.assertFalse(win.hardening_var.get())
        self.assertEqual(str(win.hardening_check.cget("text")),
                         "Add hardening settings to the Windows installation (optional)")
        self.assertIs(win.hardening_check.master.master, win.panels[app.CARD_WINDOWS])
        for key in app.CARD_ORDER:
            win.select_card(key)
            visible = win.panels[app.CARD_WINDOWS].winfo_manager() == "grid"
            self.assertEqual(visible, key == app.CARD_WINDOWS)
        for panel_key in (k for k in app.CARD_ORDER if k != app.CARD_WINDOWS):
            self.assertNotIn(win.hardening_check.master, win.panels[panel_key].winfo_children())

    def test_the_choice_is_remembered_for_the_session_but_only_counts_on_the_windows_card(self):
        win = self.win
        win.hardening_var.set(True)
        self.assertEqual(win.hardening_selected(), app.HARDENING_BASELINE)
        for key in (app.CARD_LINUX, app.CARD_CHROME, app.CARD_OTHER, app.CARD_SEED):
            win.select_card(key)
            self.assertEqual(win.hardening_selected(), app.HARDENING_NONE, key)
        win.select_card(app.CARD_WINDOWS)
        self.assertTrue(win.hardening_var.get())
        self.assertEqual(win.hardening_selected(), app.HARDENING_BASELINE)
        win.hardening_var.set(False)
        self.assertEqual(win.hardening_selected(), app.HARDENING_NONE)

    def test_the_list_of_changes_is_behind_a_link_and_uses_the_engine_description(self):
        win = self.win
        self.assertEqual(win.hardening_toggle.cget("text"), "▸ What does it change?")
        self.assertEqual(win.hardening_details.winfo_manager(), "")
        with mock.patch.object(app, "describe_hardening_windows_applied", create=True,
                               return_value=["Turns thing A on", "Turns thing B off"]) as describe:
            win.hardening_toggle.set_open(True)
        describe.assert_called_once_with(app.HARDENING_BASELINE)
        self.assertEqual(win.hardening_details.winfo_manager(), "pack")
        text = str(win.hardening_details.cget("text"))
        self.assertIn("• Turns thing A on", text)
        self.assertIn("• Turns thing B off", text)
        win.hardening_toggle.set_open(False)
        self.assertEqual(win.hardening_details.winfo_manager(), "")

    def test_the_real_description_has_no_compliance_claims(self):
        text = app.App._hardening_details_text()
        self.assertGreaterEqual(text.count("• "), 8)
        self.assertNotRegex(text.lower(), r"\b(cis|stig|nist|complian|certif)")

    def test_the_seed_panel_explains_and_offers_the_three_targets(self):
        win = self.win
        panel = win.panels[app.CARD_SEED]
        texts = " ".join(str(w.cget("text")) for w in panel.winfo_children() if w.winfo_class() == "TLabel")
        self.assertIn("SECOND, small USB drive (not the installer)", texts)
        self.assertIn("ERASES it", texts)
        self.assertIn("No image is needed", texts)
        self.assertEqual(win.seed_target_var.get(), app.SEED_UBUNTU)
        self.assertEqual(list(win.seed_radios), list(app.SEED_CHOICES))
        self.assertEqual([str(r.cget("text")) for r in win.seed_radios.values()], list(RADIO_TEXTS))
        self.assertIn("Windows 11", texts)
        self.assertNotIn("never run on a real Windows", texts, "the caveat lives in the note and the result texts")
        for choice, radio in win.seed_radios.items():
            self.assertEqual(radio.winfo_class(), "TRadiobutton")
            self.assertEqual(self.state(radio), "normal", "every choice is equally usable")
            with mock.patch.object(app, "describe_windows_seed_during_setup", create=True,
                                   return_value=FAKE_DURING_SETUP):
                radio.invoke()
                self.assertEqual(win.seed_target_var.get(), choice)
                self.assertEqual(str(win.seed_note.cget("text")), win.seed_target_note(choice))
                self.assertTrue(str(win.seed_note.cget("text")))
        win.seed_radios[app.SEED_UBUNTU].invoke()
        self.assertIn("harden.cmd", win.seed_target_note(app.SEED_WINDOWS))
        self.assertIn("OEMDRV", win.seed_target_note(app.SEED_FEDORA))
        self.assertIn("CIDATA", win.seed_target_note(app.SEED_UBUNTU))
        self.assertIn("README", win.seed_target_note(app.SEED_DEBIAN))

    def test_the_panel_holder_follows_the_seed_panel(self):
        win = self.win
        win.select_card(app.CARD_SEED)
        win.update_idletasks()
        self.assertEqual(win._panel_holder.winfo_reqheight(), win.panels[app.CARD_SEED].winfo_reqheight())

    def test_the_five_radios_are_in_a_grid_and_none_is_clipped(self):
        win = self.win
        win.geometry("780x700")
        win.select_card(app.CARD_SEED)
        win.update()
        area = win.seed_radio_area
        self.assertEqual(len(win.seed_radios), 5)
        rows = []
        for radio in win.seed_radios.values():
            if radio.master not in rows:
                rows.append(radio.master)
        self.assertEqual(len(rows), 2, "two rows")
        self.assertEqual([len([w for w in r.winfo_children() if w in win.seed_radios.values()]) for r in rows],
                         [3, 2])
        for row in rows:
            self.assertIs(row.master, area)
        self.assertLessEqual(area.winfo_reqwidth(), 780, "the radio area asks for more than the window is wide")
        self.assertLessEqual(area.winfo_reqwidth(), app.PANEL_WRAP)
        if area.winfo_width() > 1:  # the window is really laid out: every radio is fully inside the area
            for choice, radio in win.seed_radios.items():
                self.assertLessEqual(radio.winfo_x() + radio.winfo_width(), area.winfo_width() + 1, choice)
        for radio in win.seed_radios.values():
            self.assertLessEqual(radio.winfo_reqwidth(), area.winfo_reqwidth())

    def test_the_longest_note_fits_the_panel_width_and_the_holder_follows_it(self):
        win = self.win
        win.geometry("780x700")
        win.select_card(app.CARD_SEED)
        with mock.patch.object(app, "describe_windows_seed_during_setup", create=True,
                               return_value=FAKE_DURING_SETUP):
            win.seed_radios[app.SEED_CHOICE_WINDOWS_SETUP].invoke()
            win.update()
        self.assertEqual(int(str(win.seed_note.cget("wraplength"))), app.PANEL_WRAP)
        self.assertLessEqual(win.seed_note.winfo_reqwidth(), app.PANEL_WRAP + 2)
        self.assertEqual(win._panel_holder.winfo_reqheight(), win.panels[app.CARD_SEED].winfo_reqheight())

    def test_the_controls_lock_during_a_write(self):
        win = self.win
        win._creating = True
        win._sync_controls()
        self.assertEqual(self.state(win.hardening_check), "disabled")
        self.assertEqual(len(win.seed_radios), 5)
        self.assertTrue(all(self.state(r) == "disabled" for r in win.seed_radios.values()))
        win._creating = False
        win._sync_controls()
        self.assertEqual(self.state(win.hardening_check), "normal")
        self.assertTrue(all(self.state(r) == "normal" for r in win.seed_radios.values()))

    # ----- wording that must not over-promise -----
    def test_the_checkbox_explanation_says_when_and_where_the_log_is(self):
        labels = " ".join(str(w.cget("text")) for w in self.win.hardening_check.master.winfo_children()
                          if w.winfo_class() == "TLabel")
        self.assertIn("END of Windows setup", labels)
        self.assertIn("C:\\Windows\\Temp\\epma-hardening.log", labels)
        self.assertNotIn("safer settings", labels)
        self.assertEqual(str(self.win.hardening_check.cget("text")),
                         "Add hardening settings to the Windows installation (optional)")

    def test_the_list_footer_says_when_the_settings_are_applied(self):
        text = app.App._hardening_details_text()
        self.assertIn("applied at the end of Windows setup by a script", text)
        self.assertIn("C:\\Windows\\Temp\\epma-hardening.log", text)

    def test_every_line_of_the_list_goes_through_the_translation(self):
        lines = ["Turns thing A on -- risk: x", "Turns thing B off -- risk: y"]
        translated = {lines[0]: "Liga A -- risco: x", lines[1]: "Desliga B -- risco: y"}
        with mock.patch.object(app, "describe_hardening_windows_applied", create=True, return_value=lines), \
                mock.patch.dict(app.PT_BR, translated), mock.patch.object(app, "ACTIVE_LANGUAGE", "pt"):
            text = app.App._hardening_details_text()
        self.assertIn("• Liga A -- risco: x", text)
        self.assertIn("• Desliga B -- risco: y", text)
        self.assertNotIn("Turns thing", text)

    def test_a_long_title_is_cut_with_an_ellipsis_when_even_8_pt_does_not_fit(self):
        card = self.win.cards[app.CARD_SEED]
        card._on_resize(mock.Mock(width=780 // 5 - 12))   # the width of one of five cards in a 780 px window
        long_title = "Härtungsunterstützungsdatenträger-Erstellungsassistent"
        font, shown = card._fit(card._title_font, long_title)
        self.assertEqual(font[1], 8)
        self.assertTrue(shown.endswith("\u2026"))
        self.assertLess(len(shown), len(long_title))
        self.assertTrue(long_title.startswith(shown[:-1]))
        self.assertLessEqual(app.tkfont.Font(family=font[0], size=font[1], weight="bold").measure(shown),
                             card._cw - 16)
        # a text that fits is left alone
        self.assertEqual(card._fit(card._title_font, "Hardening seed")[1], "Hardening seed")

    def test_the_card_draws_the_cut_text(self):
        card = self.win.cards[app.CARD_SEED]
        card._title = "Härtungsunterstützungsdatenträger-Erstellungsassistent"
        card._on_resize(mock.Mock(width=130))
        card._draw()
        drawn = [card.itemcget(i, "text") for i in card.find_all() if card.type(i) == "text"]
        self.assertTrue(any(t.endswith("\u2026") for t in drawn), drawn)



class SeedImageStepTests(GuiTestCase, TempDirTestCase):
    """The seed card needs no image: the file row goes away, Create does not ask for one, set_iso is calm."""

    def setUp(self):
        GuiTestCase.setUp(self)
        TempDirTestCase.setUp(self)

    def order(self):
        return self.win.iso_card.master.pack_slaves()

    def test_the_image_widgets_leave_the_page_and_come_back_in_place(self):
        win = self.win
        before = self.order()
        self.assertIn(win.image_row, before)
        win.select_card(app.CARD_SEED)
        for widget in (win.image_row, win.iso_card, win.sha_toggle, win.iso_check_frame):
            self.assertEqual(widget.winfo_manager(), "", widget)
        self.assertEqual(str(win.step_headings[2].label.cget("text")), "Auto-install files")
        self.assertEqual(win.step_headings[2].title, "Auto-install files")
        for choice, heading in ((app.SEED_WINDOWS, "Hardening scripts"),
                                (app.SEED_CHOICE_WINDOWS_SETUP, "Hardening scripts and answer file"),
                                (app.SEED_FEDORA, "Auto-install files")):
            win.seed_radios[choice].invoke()  # the heading says what the chosen drive carries
            self.assertEqual(str(win.step_headings[2].label.cget("text")), heading)
            self.assertEqual(win.step_headings[2].title, heading)
        win.seed_radios[app.SEED_WINDOWS].invoke()
        self.assertEqual(win.create_btn.cget("text"), "Create Seed Drive")
        win.select_card(app.CARD_WINDOWS)  # leaving the card: "Image"; coming back: the chosen drive's heading
        self.assertEqual(win.step_headings[2].title, "Image")
        win.select_card(app.CARD_SEED)
        self.assertEqual(win.step_headings[2].title, "Hardening scripts")
        win.seed_radios[app.SEED_UBUNTU].invoke()
        win.select_card(app.CARD_WINDOWS)
        win.select_card(app.CARD_SEED)
        win.select_card(app.CARD_LINUX)
        self.assertEqual(self.order(), before)
        self.assertEqual(win.step_headings[2].title, "Image")
        self.assertEqual(str(win.step_headings[2].label.cget("text")), "Image")
        self.assertEqual(win.create_btn.cget("text"), "Create Bootable USB Drive")

    def test_the_checksum_link_and_panel_return_for_a_chosen_image(self):
        win = self.win
        path = self.make_iso("ubuntu.iso", hybrid=True)
        win.set_iso(path)
        win.sha_toggle.set_open(True)
        shown = self.order()
        self.assertIn(win.sha_toggle, shown)
        self.assertIn(win.iso_check_frame, shown)
        win.select_card(app.CARD_SEED)
        self.assertNotIn(win.sha_toggle, self.order())
        self.assertNotIn(win.iso_check_frame, self.order())
        win.select_card(app.CARD_LINUX)
        self.assertEqual(self.order(), shown)
        self.assertTrue(win.sha_toggle.is_open)

    def test_create_does_not_ask_for_an_image_but_still_needs_a_drive(self):
        win = self.win
        win.select_card(app.CARD_SEED)
        self.assertEqual(win.iso_path.get(), "")
        win.refresh_disks(sync=True)                       # nothing plugged in
        self.assertEqual(self.state(win.create_btn), "disabled")
        self.assertIn("No USB drive found", str(win.create_hint.cget("text")))
        self.assertNotIn("image", str(win.create_hint.cget("text")).lower())
        self.listed = [USB_DISK]
        win.refresh_disks(sync=True)
        self.assertEqual(self.state(win.create_btn), "normal")
        self.assertEqual(str(win.create_hint.cget("text")), "")
        # the other cards still need the image, and say so
        win.select_card(app.CARD_WINDOWS)
        self.assertEqual(self.state(win.create_btn), "disabled")
        self.assertIn("Choose the image file first", str(win.create_hint.cget("text")))
        win.select_card(app.CARD_SEED)
        self.assertEqual(self.state(win.create_btn), "normal")

    def test_a_missing_tool_still_blocks_the_seed_card(self):
        win = self.win
        self.listed = [USB_DISK]
        win.refresh_disks(sync=True)
        win.select_card(app.CARD_SEED)
        with mock.patch.object(app, "get_missing_dependencies", return_value=["parted"]) as missing:
            win.update_create_button_state()
        missing.assert_called_with(app.MODE_SEED)
        self.assertEqual(self.state(win.create_btn), "disabled")
        self.assertIn("parted", str(win.create_hint.cget("text")))

    def test_the_image_checks_do_not_apply_to_the_seed_drive(self):
        win = self.win
        win.iso_path.set(self.make_iso("whatever.iso", hybrid=False))
        with mock.patch.object(app, "detect_iso_kind", side_effect=AssertionError("must not look at the image")):
            self.assertTrue(win._image_matches_choice(app.MODE_SEED))
        self.assertEqual(self.box.calls, [])

    def test_choosing_an_image_on_the_seed_card_keeps_the_card_and_remembers_the_image(self):
        win = self.win
        win.select_card(app.CARD_SEED)
        path = self.make_iso("ubuntu.iso", hybrid=True)
        with mock.patch.object(app, "detect_iso_kind", return_value=app.ISO_KIND_WINDOWS):
            win.set_iso(path)                               # even a Windows image does not pull the user away
        self.assertEqual(win.card_var.get(), app.CARD_SEED)
        self.assertEqual(win.mode_var.get(), app.MODE_SEED)
        self.assertEqual(win.iso_path.get(), path)
        self.assertTrue(win.iso_card.has_file)
        for widget in (win.iso_card, win.sha_toggle):
            self.assertEqual(widget.winfo_manager(), "")
        win._flush_log()
        self.assertIn("Image remembered: ubuntu.iso", win.log_text.get("1.0", "end"))
        win.select_card(app.CARD_LINUX)                     # now the image is there, in its card
        self.assertEqual(win.iso_card.winfo_manager(), "pack")
        self.assertEqual(win.sha_toggle.winfo_manager(), "pack")

    def test_other_cards_still_switch_on_the_content(self):
        win = self.win
        path = self.make_iso("ubuntu.iso", hybrid=True)
        with mock.patch.object(app, "detect_iso_kind", return_value=app.ISO_KIND_LINUX):
            win.select_card(app.CARD_WINDOWS)
            win.set_iso(path)
        self.assertEqual(win.card_var.get(), app.CARD_LINUX)


class WriteFlowTests(GuiTestCase):
    """start_create_usb for the Windows option and for the seed card: same safety flow, the right engine call."""

    def setUp(self):
        super().setUp()
        self.events = []
        self.listed = [USB_DISK]
        self.win.iso_path.set("/tmp/exemplo.iso")
        self.win.refresh_disks(sync=True)
        self.win.priv.authenticate = mock.Mock(side_effect=lambda *a, **k: self.events.append("auth") or True)
        self.pin = self.patch(app, "pin_target_identity", side_effect=lambda *a: self.events.append(("pin", a)))
        self.admin = self.patch(app, "needs_admin", return_value=False)
        self.gate = threading.Event()   # holds a fake engine call until the test lets it go
        self.calls = []
        # added by the engine part of the feature: replaced here so these tests do not depend on it
        self.size_check = self.patch(app, "check_seed_target_size", create=True)

    def patch(self, obj, name, **kw):
        patcher = mock.patch.object(obj, name, **kw)
        mocked = patcher.start()
        self.addCleanup(patcher.stop)
        return mocked

    def fake_engine(self, result=True, exc=None, wait=False, name="engine"):
        def engine(*args, **kwargs):
            self.events.append(name)
            self.calls.append((args, kwargs))
            if wait:
                self.gate.wait(10)
            if exc is not None:
                raise exc
            return result
        return engine

    def confirmed(self, yes=True):
        self.win.confirm_erase = mock.Mock(side_effect=lambda *a: self.events.append("confirm") or yes)
        return self.win.confirm_erase

    def write(self):
        self.win.start_create_usb()
        self.assertTrue(self.pump(lambda: not self.win._creating))
        self.win.update()

    # ----- Windows: the checkbox decides what build_usb gets -----
    def test_ticked_passes_the_baseline_profile_to_build_usb(self):
        win = self.win
        win.select_card(app.CARD_WINDOWS)
        win.hardening_var.set(True)
        self.confirmed()
        self.patch(win, "_image_matches_choice", return_value=True)
        engine = self.patch(app, "build_usb", side_effect=self.fake_engine(True))
        self.write()
        engine.assert_called_once()
        self.assertEqual(engine.call_args.kwargs["hardening"], app.HARDENING_BASELINE)
        self.assertEqual(engine.call_args.kwargs["mode"], app.MODE_WINDOWS)
        self.assertEqual(engine.call_args.args[:2], ("/tmp/exemplo.iso", "disk9"))
        self.assertEqual(win.confirm_erase.call_args.args[1], "Windows 11 and add the hardening files")
        self.assertIn("written to the drive and checked byte for byte", win.success_panel.message_text)
        self.assertIn("C:\\Windows\\Temp\\epma-hardening.log", win.success_panel.message_text)
        self.assertIn("After Windows setup finishes", win.success_panel.message_text)

    def test_unticked_or_on_another_card_passes_no_hardening(self):
        win = self.win
        self.confirmed()
        self.patch(win, "_image_matches_choice", return_value=True)
        engine = self.patch(app, "build_usb", side_effect=self.fake_engine(True))
        win.select_card(app.CARD_WINDOWS)
        self.write()
        self.assertNotEqual(engine.call_args.kwargs.get("hardening", app.HARDENING_NONE), app.HARDENING_BASELINE)
        self.assertEqual(win.confirm_erase.call_args.args[1], "Windows 11")
        self.assertNotIn("hardening", win.success_panel.message_text)
        # ticked, but the Linux card is what is written: the tick is ignored
        win.hardening_var.set(True)
        win.select_card(app.CARD_LINUX)
        win.clear_success()
        self.write()
        self.assertEqual(engine.call_args.kwargs.get("hardening", app.HARDENING_NONE), app.HARDENING_NONE)
        self.assertEqual(engine.call_args.kwargs["mode"], app.MODE_LINUX)
        self.assertEqual(win.confirm_erase.call_args.args[1], "the selected Linux image")

    def test_the_confirmation_dialog_says_it_adds_the_hardening_files(self):
        win = self.win
        win.select_card(app.CARD_WINDOWS)
        win.hardening_var.set(True)
        self.box.yes = True
        self.patch(win, "_image_matches_choice", return_value=True)
        self.patch(app, "assess_disk_risk", return_value=("low", []))
        self.patch(app, "build_usb", side_effect=self.fake_engine(True))
        self.write()
        question = [c for c in self.box.calls if c[1] == "Final confirmation"]
        self.assertEqual(len(question), 1)
        self.assertIn("write Windows 11 and add the hardening files to it", question[0][2])
        self.assertIn("PERMANENTLY ERASE all data on /dev/disk9", question[0][2])

    # ----- the seed card -----
    def test_the_seed_card_calls_build_seed_usb_with_the_target_and_the_drive(self):
        win = self.win
        win.select_card(app.CARD_SEED)
        win.iso_path.set("")                              # no image at all
        win.seed_radios[app.SEED_FEDORA].invoke()
        self.confirmed()
        seed = self.patch(app, "build_seed_usb", create=True, side_effect=self.fake_engine(True, name="seed"))
        image = self.patch(app, "build_usb", side_effect=AssertionError("the seed drive has no image"))
        self.write()
        image.assert_not_called()
        seed.assert_called_once()
        args, kwargs = seed.call_args
        self.assertEqual(args[:2], (app.SEED_FEDORA, "disk9"))
        self.assertEqual(args[2], win.log_threadsafe)
        self.assertIs(args[3], win.priv)
        self.assertEqual(kwargs["expected_size"], USB_DISK["size"])
        self.assertIs(kwargs["cancel_event"], win.create_cancel_event)
        self.assertTrue(callable(kwargs["progress"]))
        self.assertEqual(win.confirm_erase.call_args.args[1], "the hardening seed files")

    def test_each_radio_reaches_the_engine_with_its_target_and_during_setup(self):
        win = self.win
        win.select_card(app.CARD_SEED)
        self.confirmed()
        self.patch(app, "describe_windows_seed_during_setup", create=True, return_value=FAKE_DURING_SETUP)
        seed = self.patch(app, "build_seed_usb", create=True, side_effect=self.fake_engine(True))
        expected = {app.SEED_UBUNTU: (app.SEED_UBUNTU, False), app.SEED_FEDORA: (app.SEED_FEDORA, False),
                    app.SEED_DEBIAN: (app.SEED_DEBIAN, False), app.SEED_WINDOWS: ("windows", False),
                    app.SEED_CHOICE_WINDOWS_SETUP: ("windows", True)}
        self.assertEqual(list(win.seed_radios), list(expected))
        for choice, (target, during_setup) in expected.items():
            with self.subTest(choice=choice):
                seed.reset_mock()
                win.seed_radios[choice].invoke()
                self.write()
                seed.assert_called_once()
                self.assertEqual(seed.call_args.args[0], target)
                self.assertIs(seed.call_args.kwargs["during_setup"], during_setup)
                self.assertEqual(seed.call_args.args[1], "disk9")

    def test_the_windows_choices_use_the_same_safety_flow_and_need_no_image(self):
        win = self.win
        win.select_card(app.CARD_SEED)
        win.iso_path.set("")
        self.admin.return_value = True
        self.patch(app, "describe_windows_seed_during_setup", create=True, return_value=FAKE_DURING_SETUP)
        image = self.patch(app, "build_usb", side_effect=AssertionError("the seed drive has no image"))
        self.confirmed()
        self.patch(app, "build_seed_usb", create=True, side_effect=self.fake_engine(True, name="seed"))
        for choice in (app.SEED_WINDOWS, app.SEED_CHOICE_WINDOWS_SETUP):
            with self.subTest(choice=choice):
                self.events.clear()
                win.seed_radios[choice].invoke()
                self.assertEqual(self.state(win.create_btn), "normal")
                self.write()
                self.assertEqual(self.events, ["confirm", ("pin", ("disk9", USB_DISK.get("identity"))), "auth", "seed"])
        image.assert_not_called()

    def test_the_confirmation_names_the_experimental_answer_file_only_for_during_setup(self):
        win = self.win
        win.select_card(app.CARD_SEED)
        self.box.yes = True
        self.patch(app, "describe_windows_seed_during_setup", create=True, return_value=FAKE_DURING_SETUP)
        self.patch(app, "assess_disk_risk", return_value=("low", []))
        seed = self.patch(app, "build_seed_usb", create=True, side_effect=self.fake_engine(True))
        wanted = {
            app.SEED_WINDOWS: ("write the hardening seed files to it", False),
            app.SEED_CHOICE_WINDOWS_SETUP: (
                "write the hardening seed files (experimental: includes an answer file for Windows Setup) to it",
                True),
        }
        for choice, (phrase, during_setup) in wanted.items():
            with self.subTest(choice=choice):
                self.box.calls.clear()
                win.seed_radios[choice].invoke()
                self.write()
                question = [c for c in self.box.calls if c[1] == "Final confirmation"]
                self.assertEqual(len(question), 1)
                self.assertIn(phrase, question[0][2])
                self.assertIs("answer file" in question[0][2], during_setup)
                self.assertIs(seed.call_args.kwargs["during_setup"], during_setup)

    def test_the_high_risk_typed_confirmation_also_names_the_experimental_files(self):
        win = self.win
        win.select_card(app.CARD_SEED)
        self.patch(app, "describe_windows_seed_during_setup", create=True, return_value=FAKE_DURING_SETUP)
        win.seed_radios[app.SEED_CHOICE_WINDOWS_SETUP].invoke()
        seed = self.patch(app, "build_seed_usb", create=True, side_effect=AssertionError("must not run"))
        self.patch(app, "assess_disk_risk", return_value=("high", ["it is very large"]))
        typed = self.patch(app, "ask_typed_confirmation", return_value=False)
        win.start_create_usb()
        typed.assert_called_once()
        self.assertIn("includes an answer file for Windows Setup", typed.call_args.args[2])
        seed.assert_not_called()

    def test_the_seed_card_goes_through_the_whole_safety_flow_in_order(self):
        win = self.win
        win.select_card(app.CARD_SEED)
        self.admin.return_value = True
        self.confirmed()
        self.patch(app, "build_seed_usb", create=True, side_effect=self.fake_engine(True, name="seed"))
        self.write()
        self.assertEqual(self.events, ["confirm", ("pin", ("disk9", USB_DISK.get("identity"))), "auth", "seed"])
        self.admin.assert_called_with(app.MODE_SEED)
        self.assertEqual(win.priv.authenticate.call_count, 1)

    def test_no_password_is_asked_when_the_seed_mode_needs_no_admin(self):
        win = self.win
        win.select_card(app.CARD_SEED)
        self.confirmed()
        self.patch(app, "build_seed_usb", create=True, side_effect=self.fake_engine(True))
        self.write()
        win.priv.authenticate.assert_not_called()

    def test_a_refused_password_stops_before_the_drive_is_touched(self):
        win = self.win
        win.select_card(app.CARD_SEED)
        self.admin.return_value = True
        win.priv.authenticate = mock.Mock(return_value=False)
        win.priv.clear_cached_password = mock.Mock()
        self.confirmed()
        seed = self.patch(app, "build_seed_usb", create=True, side_effect=AssertionError("must not run"))
        win.start_create_usb()
        seed.assert_not_called()
        self.assertFalse(win._creating)
        win.priv.clear_cached_password.assert_called()
        self.assertEqual(self.state(win.create_btn), "normal")

    def test_declining_the_confirmation_changes_nothing(self):
        win = self.win
        win.select_card(app.CARD_SEED)
        self.confirmed(yes=False)
        seed = self.patch(app, "build_seed_usb", create=True, side_effect=AssertionError("must not run"))
        win.start_create_usb()
        seed.assert_not_called()
        self.assertEqual([e for e in self.events if e != "confirm"], [], "no pin, no password, no write")
        self.assertFalse(win._creating)

    def test_the_real_confirmation_names_the_seed_files_and_a_high_risk_drive_needs_the_identifier(self):
        win = self.win
        win.select_card(app.CARD_SEED)
        self.box.yes = True
        seed = self.patch(app, "build_seed_usb", create=True, side_effect=self.fake_engine(True))
        self.patch(app, "assess_disk_risk", return_value=("low", []))
        self.write()
        question = [c for c in self.box.calls if c[1] == "Final confirmation"]
        self.assertEqual(len(question), 1)
        self.assertIn("write the hardening seed files to it", question[0][2])
        seed.assert_called_once()
        # a high-risk drive: the typed identifier dialog decides, not the yes/no question
        self.box.calls.clear()
        seed.reset_mock()
        self.patch(app, "assess_disk_risk", return_value=("high", ["it is very large"]))
        typed = self.patch(app, "ask_typed_confirmation", return_value=False)
        win.start_create_usb()
        typed.assert_called_once()
        self.assertEqual(typed.call_args.args[3], "disk9")
        self.assertIn("write the hardening seed files to it", typed.call_args.args[2])
        self.assertEqual(self.box.titles("question"), [])
        seed.assert_not_called()

    def test_a_second_click_is_ignored_while_the_seed_drive_is_written(self):
        win = self.win
        win.select_card(app.CARD_SEED)
        confirm = self.confirmed()
        seed = self.patch(app, "build_seed_usb", create=True, side_effect=self.fake_engine(True, wait=True))
        win.start_create_usb()
        self.assertTrue(win._creating)
        self.assertEqual(self.state(win.create_btn), "disabled")
        self.assertEqual(self.state(win.cancel_create_btn), "normal")   # the one Cancel
        self.assertFalse(win.cards[app.CARD_WINDOWS]._enabled)          # the cards are locked
        self.assertEqual(self.state(win.hardening_check), "disabled")
        win.start_create_usb()                                           # a second click, and another
        win.create_btn.invoke()
        self.assertEqual(confirm.call_count, 1)
        self.gate.set()
        self.assertTrue(self.pump(lambda: not win._creating))
        seed.assert_called_once()
        self.assertEqual(self.state(win.cancel_create_btn), "disabled")

    def test_cancel_during_the_seed_write_is_the_same_single_cancel(self):
        win = self.win
        win.select_card(app.CARD_SEED)
        self.confirmed()
        started = threading.Event()

        def engine(*args, **kwargs):
            started.set()
            kwargs["cancel_event"].wait(10)
            raise app.OperationCanceled("Canceled by the user.", drive_touched=True)

        self.patch(app, "build_seed_usb", create=True, side_effect=engine)
        win.start_create_usb()
        self.assertTrue(started.wait(10))
        self.box.yes = True
        win.cancel_current()                                           # the window's single Cancel
        self.assertTrue(win.create_cancel_event.is_set())
        self.assertTrue(self.pump(lambda: not win._creating))
        self.assertTrue(win.error_banner.shown)
        self.assertIn("unusable", win.error_banner.message_text)

    def test_canceled_during_the_seed_verification_says_the_seed_files_are_unverified(self):
        log, _title, body = app.App._canceled_texts(True, True, seed=True)
        self.assertIn("seed files", log)
        self.assertIn("NOT verified", body)
        self.assertIn("seed files", body)
        generic = app.App._canceled_texts(True, True)
        self.assertIn("image", generic[0])
        with mock.patch.object(app, "ACTIVE_LANGUAGE", "pt"):
            self.assertIn("kit", app.App._canceled_texts(True, True, seed=True)[0])

    def test_progress_reaches_the_bar_during_the_seed_write(self):
        win = self.win
        win.select_card(app.CARD_SEED)
        self.confirmed()

        def engine(*args, **kwargs):
            kwargs["progress"](0, 0, "Verifying the copied files...")
            kwargs["progress"](5, 10, "Writing the seed files...")
            self.gate.wait(10)
            return True

        self.patch(app, "build_seed_usb", create=True, side_effect=engine)
        win.start_create_usb()
        self.assertTrue(self.pump(lambda: "Writing the seed files..." in str(win.create_progress_label.cget("text"))))
        self.assertEqual(win.create_progress.winfo_manager(), "pack")
        self.gate.set()
        self.assertTrue(self.pump(lambda: not win._creating))

    # ----- what is confirmed is what is written -----
    def test_an_image_chosen_while_the_confirmation_is_open_does_not_change_the_write(self):
        win = self.win
        win.select_card(app.CARD_WINDOWS)
        win.hardening_var.set(True)
        checked = self.patch(win, "_image_matches_choice", return_value=True)

        def confirm_while_a_download_finishes(*_args):
            self.events.append("confirm")
            with mock.patch.object(app, "detect_iso_kind", return_value=app.ISO_KIND_LINUX):
                win.set_iso("/tmp/outra.iso")      # a finished download: new image, and the Linux card
            win.hardening_var.set(False)
            return True

        win.confirm_erase = mock.Mock(side_effect=confirm_while_a_download_finishes)
        engine = self.patch(app, "build_usb", side_effect=self.fake_engine(True))
        self.write()
        self.assertEqual(win.iso_path.get(), "/tmp/outra.iso")      # the window did change meanwhile
        self.assertEqual(win.mode_var.get(), app.MODE_LINUX)
        checked.assert_called_once_with(app.MODE_WINDOWS, "/tmp/exemplo.iso")
        engine.assert_called_once()
        self.assertEqual(engine.call_args.args[0], "/tmp/exemplo.iso")      # what was confirmed is what is written
        self.assertEqual(engine.call_args.kwargs["mode"], app.MODE_WINDOWS)
        self.assertEqual(engine.call_args.kwargs["hardening"], app.HARDENING_BASELINE)
        self.assertEqual(win.confirm_erase.call_args.args[1], "Windows 11 and add the hardening files")

    def test_the_seed_target_is_also_read_once(self):
        win = self.win
        win.select_card(app.CARD_SEED)
        win.seed_radios[app.SEED_FEDORA].invoke()

        def change_the_target(*_args):
            win.seed_target_var.set(app.SEED_DEBIAN)
            return True

        win.confirm_erase = mock.Mock(side_effect=change_the_target)
        seed = self.patch(app, "build_seed_usb", create=True, side_effect=self.fake_engine(True))
        self.write()
        self.assertEqual(seed.call_args.args[0], app.SEED_FEDORA)
        self.assertIs(seed.call_args.kwargs["during_setup"], False)

    def test_the_windows_choice_is_read_once_in_both_directions(self):
        win = self.win
        win.select_card(app.CARD_SEED)
        self.patch(app, "describe_windows_seed_during_setup", create=True, return_value=FAKE_DURING_SETUP)
        seed = self.patch(app, "build_seed_usb", create=True, side_effect=self.fake_engine(True))
        for first, changed_to, expected in (
                (app.SEED_CHOICE_WINDOWS_SETUP, app.SEED_WINDOWS, ("windows", True)),
                (app.SEED_WINDOWS, app.SEED_CHOICE_WINDOWS_SETUP, ("windows", False)),
                (app.SEED_CHOICE_WINDOWS_SETUP, app.SEED_UBUNTU, ("windows", True))):
            with self.subTest(first=first, changed_to=changed_to):
                win.seed_radios[first].invoke()

                def change_the_choice(*_args, changed_to=changed_to):
                    self.assertEqual(self.state(win.seed_radios[changed_to]), "disabled")  # clicks do nothing now
                    win.seed_target_var.set(changed_to)     # so the variable is changed from outside
                    return True

                win.confirm_erase = mock.Mock(side_effect=change_the_choice)
                self.write()
                self.assertEqual(win.seed_target_var.get(), changed_to, "the window did change meanwhile")
                self.assertEqual((seed.call_args.args[0], seed.call_args.kwargs["during_setup"]), expected)

    def test_the_radios_are_locked_while_a_windows_seed_is_written(self):
        win = self.win
        win.select_card(app.CARD_SEED)
        self.patch(app, "describe_windows_seed_during_setup", create=True, return_value=FAKE_DURING_SETUP)
        win.seed_radios[app.SEED_CHOICE_WINDOWS_SETUP].invoke()
        self.confirmed()
        self.patch(app, "build_seed_usb", create=True, side_effect=self.fake_engine(True, wait=True))
        win.start_create_usb()
        self.assertTrue(win._creating)
        self.assertEqual({c: self.state(r) for c, r in win.seed_radios.items()},
                         dict.fromkeys(app.SEED_CHOICES, "disabled"))
        self.gate.set()
        self.assertTrue(self.pump(lambda: not win._creating))
        self.assertEqual({self.state(r) for r in win.seed_radios.values()}, {"normal"})

    def test_create_waits_while_a_download_or_an_extraction_runs(self):
        win = self.win
        hint = "Wait for the download to finish or cancel it first."
        self.assertEqual(self.state(win.create_btn), "normal")
        for flag in ("_download_running", "_flex_busy"):
            with self.subTest(flag=flag):
                setattr(win, flag, True)
                win._sync_controls()                    # the same call the download code makes
                self.assertEqual(self.state(win.create_btn), "disabled")
                self.assertEqual(str(win.create_hint.cget("text")), hint)
                # a stale click is refused too, before any question
                confirm = self.confirmed()
                engine = self.patch(app, "build_usb", side_effect=AssertionError("must not run"))
                self.box.calls.clear()
                win.start_create_usb()
                confirm.assert_not_called()
                engine.assert_not_called()
                self.assertEqual(self.box.titles("error"), ["Download in progress"])
                self.assertFalse(win._creating)
                setattr(win, flag, False)
                win._sync_controls()
                self.assertEqual(self.state(win.create_btn), "normal")
                self.assertEqual(str(win.create_hint.cget("text")), "")

    def test_the_download_callbacks_release_create(self):
        win = self.win
        win._download_running = True
        win._sync_controls()
        self.assertEqual(self.state(win.create_btn), "disabled")
        with mock.patch.object(app.messagebox, "showinfo", create=True):
            win._on_download_done("/tmp/exemplo.iso", "0" * 64, False)
        self.assertEqual(self.state(win.create_btn), "normal")

    # ----- the seed drive is checked for size before anything is asked -----
    def test_a_too_small_seed_drive_is_refused_before_the_confirmation(self):
        win = self.win
        win.select_card(app.CARD_SEED)
        self.size_check.side_effect = ValueError("The drive (16 MB) is too small for a seed drive.")
        confirm = self.confirmed()
        seed = self.patch(app, "build_seed_usb", create=True, side_effect=AssertionError("must not run"))
        win.start_create_usb()
        self.size_check.assert_called_once_with(USB_DISK["size"])
        confirm.assert_not_called()
        seed.assert_not_called()
        self.assertEqual(self.box.titles("error"), ["Drive too small"])
        self.assertIn("too small for a seed drive", self.box.calls[-1][2])
        self.assertFalse(win._creating)
        self.assertEqual(self.state(win.create_btn), "normal")

    def test_the_size_check_is_only_for_the_seed_card(self):
        win = self.win
        win.select_card(app.CARD_WINDOWS)
        self.confirmed()
        self.patch(win, "_image_matches_choice", return_value=True)
        self.patch(app, "build_usb", side_effect=self.fake_engine(True))
        self.write()
        self.size_check.assert_not_called()

    # ----- the engine refuses the image: shown nicely -----
    def test_an_iso_that_already_has_the_hardening_files_is_a_message_not_a_traceback(self):
        win = self.win
        win.select_card(app.CARD_WINDOWS)
        win.hardening_var.set(True)
        self.confirmed()
        self.patch(win, "_image_matches_choice", return_value=True)
        text = "This ISO already contains the hardening files (autounattend.xml). Nothing was changed."
        self.patch(app, "build_usb", side_effect=self.fake_engine(exc=ValueError(text)))
        self.write()
        self.assertTrue(win.error_banner.shown)
        self.assertIn("already contains the hardening files", win.error_banner.message_text)
        self.assertEqual(len(self.box.titles("error")), 1)
        self.assertFalse(win._creating)
        self.assertEqual(self.state(win.create_btn), "normal")

    # ----- results -----
    def test_success_panel_for_the_seed_drive(self):
        win = self.win
        win.select_card(app.CARD_SEED)
        self.confirmed()
        self.patch(app, "build_seed_usb", create=True, side_effect=self.fake_engine(True))
        self.write()
        panel = win.success_panel
        self.assertTrue(panel.shown)
        self.assertEqual(panel.kind, "success")
        self.assertTrue(panel.title_text.startswith("Seed drive created and verified"))
        self.assertIn("ejected", panel.message_text)
        self.assertIn("next to the installer USB drive", panel.message_text)
        self.assertNotIn("ISO", panel.message_text)       # there was no image
        self.assertEqual(self.box.calls, [])
        self.assertEqual(str(win.create_progress_label.cget("text")), "Done — 100%")

    def test_success_panel_for_the_windows_choices(self):
        win = self.win
        win.select_card(app.CARD_SEED)
        self.confirmed()
        self.patch(app, "describe_windows_seed_during_setup", create=True, return_value=FAKE_DURING_SETUP)
        self.patch(app, "build_seed_usb", create=True, side_effect=self.fake_engine(True))
        win.seed_radios[app.SEED_WINDOWS].invoke()
        self.write()
        panel = win.success_panel
        self.assertTrue(panel.shown)
        self.assertEqual(panel.kind, "success")
        self.assertTrue(panel.title_text.startswith("Windows 11 hardening drive created and verified"))
        for name in ("audit.cmd", "harden.cmd", "undo.cmd"):
            self.assertIn(name, panel.message_text)
        self.assertNotIn("EXPERIMENTAL", panel.message_text)
        self.assertNotIn("next to the installer", panel.message_text)   # the Linux wording does not apply
        win.clear_success()
        win.seed_radios[app.SEED_CHOICE_WINDOWS_SETUP].invoke()
        self.write()
        panel = win.success_panel
        self.assertTrue(panel.shown)
        self.assertTrue(panel.title_text.startswith("Windows 11 setup drive (experimental) created and verified"))
        self.assertIn("BEFORE you start the Windows installer", panel.message_text)
        self.assertIn("EXPERIMENTAL", panel.message_text)
        self.assertIn("64-bit Intel/AMD (x64)", panel.message_text)
        self.assertIn("epma-hardening.log", panel.message_text)

    def test_success_panel_for_a_windows_drive_that_could_not_be_ejected(self):
        win = self.win
        win.select_card(app.CARD_SEED)
        self.confirmed()
        self.patch(app, "build_seed_usb", create=True, side_effect=self.fake_engine(False))
        win.seed_radios[app.SEED_WINDOWS].invoke()
        self.write()
        panel = win.success_panel
        self.assertEqual(panel.kind, "warning")
        self.assertIn("could not be ejected automatically", panel.message_text)
        self.assertNotIn("you can unplug it now", panel.message_text)

    def test_success_panel_for_the_seed_drive_that_could_not_be_ejected(self):
        win = self.win
        win.select_card(app.CARD_SEED)
        self.confirmed()
        self.patch(app, "build_seed_usb", create=True, side_effect=self.fake_engine(False))
        self.write()
        panel = win.success_panel
        self.assertEqual(panel.kind, "warning")
        self.assertIn("could not be ejected automatically", panel.message_text)
        self.assertNotIn("you can unplug it now", panel.message_text)

    def test_a_failed_seed_write_shows_the_banner_and_the_dialog_and_unlocks(self):
        for exc in (RuntimeError("Verification failed: a seed file differs."), ValueError("bad target"),
                    OSError("device vanished")):
            with self.subTest(exc=type(exc).__name__):
                self.box.calls.clear()
                win = self.win
                win.select_card(app.CARD_SEED)
                self.confirmed()
                with mock.patch.object(app, "build_seed_usb", create=True, side_effect=self.fake_engine(exc=exc)):
                    self.write()
                self.assertFalse(win._creating)
                self.assertTrue(win.error_banner.shown)
                self.assertFalse(win.success_panel.shown)
                self.assertEqual(len(self.box.titles("error")), 1)
                self.assertEqual(self.state(win.create_btn), "normal")
                self.assertTrue(win.disk_list.is_enabled())
                self.assertEqual(self.state(win.cancel_create_btn), "disabled")
                win.clear_error()

    def test_an_invalid_target_is_refused_before_anything_happens(self):
        win = self.win
        win.select_card(app.CARD_SEED)
        win.seed_target_var.set("bogus")
        confirm = self.confirmed()
        seed = self.patch(app, "build_seed_usb", create=True, side_effect=AssertionError("must not run"))
        win.start_create_usb()
        seed.assert_not_called()
        confirm.assert_not_called()
        self.assertEqual(self.box.titles("error"), ["Hardening seed"])
        self.assertFalse(win._creating)


class PortugueseSeedLayoutTests(GuiTestCase):
    """The Portuguese radio texts are longer: they must still fit the window (no clipping)."""

    def setUp(self):
        patcher = mock.patch.object(app, "ACTIVE_LANGUAGE", "pt")
        patcher.start()
        self.addCleanup(patcher.stop)
        super().setUp()

    def test_the_five_portuguese_radios_fit_a_780_px_window(self):
        win = self.win
        win.geometry("780x700")
        win.select_card(app.CARD_SEED)
        win.update()
        self.assertEqual(str(win.seed_radios[app.SEED_CHOICE_WINDOWS_SETUP].cget("text")),
                         "Windows 11 (durante a instalação, experimental)")
        self.assertLessEqual(win.seed_radio_area.winfo_reqwidth(), 780)
        self.assertLessEqual(win.seed_radio_area.winfo_reqwidth(), app.PANEL_WRAP)


class SeedCardHeightTests(GuiTestCase):
    """The Hardening seed card must not push the Create button off a small screen (1440x900 laptops).

    Real (unmocked) panel and notes, the engine's own description of the during-setup mode, 780 px wide. The
    limit was measured on the development machine (macOS, linespace 16 px); on a platform whose default font is
    taller the limit grows in proportion, so a different font cannot fail this test by itself.
    """

    LIMIT = 760           # measured here: 738 (EN) and 754 (PT), the worst case being the longest note
    REFERENCE_LINESPACE = 16
    LANGUAGE = "en"

    def setUp(self):
        patcher = mock.patch.object(app, "ACTIVE_LANGUAGE", self.LANGUAGE)
        patcher.start()
        self.addCleanup(patcher.stop)
        super().setUp()

    @staticmethod
    def linespace():
        return app.tkfont.nametofont("TkDefaultFont").metrics("linespace")

    def limit(self):
        return self.LIMIT * max(1.0, self.linespace() / self.REFERENCE_LINESPACE)

    def test_every_choice_keeps_the_requested_window_height_within_the_limit(self):
        win = self.win
        win.geometry("780x700")
        win.select_card(app.CARD_SEED)
        for choice in app.SEED_CHOICES:
            with self.subTest(choice=choice, language=self.LANGUAGE):
                win.seed_radios[choice].invoke()
                win.update()
                self.assertLessEqual(win.winfo_reqheight(), self.limit(),
                                     f"{choice}: the window asks for {win.winfo_reqheight()} px")
                note_lines = win.seed_note.winfo_reqheight() / self.linespace()
                self.assertLessEqual(note_lines, 2.5, "at most two short note lines")
                self.assertEqual(win._panel_holder.winfo_reqheight(), win.panels[app.CARD_SEED].winfo_reqheight())
                self.assertLessEqual(win.seed_radio_area.winfo_reqwidth(), app.PANEL_WRAP)

    def test_the_link_to_the_full_text_is_only_on_the_experimental_choice_and_opens_the_engine_text(self):
        win = self.win
        win.geometry("780x700")
        win.select_card(app.CARD_SEED)
        for choice in app.SEED_CHOICES:
            win.seed_radios[choice].invoke()
            self.assertEqual(bool(win.seed_more.winfo_manager()), choice == app.SEED_CHOICE_WINDOWS_SETUP, choice)
        win.update()
        before = win.winfo_reqheight()
        win.seed_more.set_open(True)
        win.update()
        shown = str(win.seed_more_text.cget("text"))
        self.assertTrue(shown.startswith("• "))
        self.assertEqual(shown, app.App._seed_experimental_details())
        self.assertGreater(win.winfo_reqheight(), before)  # the window grows only while the text is open
        self.assertLessEqual(win.seed_radio_area.winfo_reqwidth(), app.PANEL_WRAP, "the open link text fits too")
        win.seed_radios[app.SEED_UBUNTU].invoke()  # another choice: the text and its link are gone again
        win.update()
        self.assertFalse(win.seed_more.is_open)
        self.assertEqual(win.seed_more_text.winfo_manager(), "")
        self.assertEqual(win.seed_more.winfo_manager(), "")


class SeedCardHeightPortugueseTests(SeedCardHeightTests):
    LANGUAGE = "pt"


class PortugueseWindowTests(unittest.TestCase):
    def test_every_new_text_has_a_different_portuguese_text(self):
        for text in NEW_TEXTS:
            with self.subTest(text=text):
                self.assertTrue(app.PT_BR[text])
        translated = [app.PT_BR[t] for t in NEW_TEXTS if t not in ("Ubuntu (autoinstall)", "Fedora / RHEL (kickstart)",
                                                                    "Debian (script + preseed)")]
        self.assertTrue(all(t not in NEW_TEXTS for t in translated))

    def test_every_windows_text_has_a_different_portuguese_text(self):
        for text in NEW_TEXTS_WINDOWS:
            with self.subTest(text=text[:50]):
                self.assertIn(text, app.PT_BR)
                self.assertNotEqual(app.PT_BR[text], text)

    def test_the_windows_radios_and_notes_are_translated_when_the_language_is_portuguese(self):
        with mock.patch.object(app, "ACTIVE_LANGUAGE", "pt"):
            texts = [t for _k, t in app.App.seed_target_texts()]
            self.assertEqual(texts[3:], ["Windows 11 (executar depois de instalar)",
                                         "Windows 11 (durante a instalação, experimental)"])
            self.assertIn("harden.cmd", app.App.seed_target_note(None, app.SEED_WINDOWS))
            self.assertIn("administrador", app.App.seed_target_note(None, app.SEED_WINDOWS))
            after = app.App._windows_seed_success_texts(True, False)
            setup = app.App._windows_seed_success_texts(False, True)
            self.assertIn("Pendrive", after[0])
            self.assertIn("undo.cmd", after[1])
            self.assertIn("EXPERIMENTAL", setup[1])
            self.assertIn("ANTES", setup[1])
            key = "the hardening seed files (experimental: includes an answer file for Windows Setup)"
            self.assertEqual(app._(key), app.PT_BR[key])
            with mock.patch.object(app, "describe_windows_seed_during_setup", create=True,
                                   return_value=["Line one."]):
                self.assertTrue(app.App.seed_target_note(None, app.SEED_CHOICE_WINDOWS_SETUP).startswith(
                    "EXPERIMENTAL, nunca testado"))

    def test_the_portuguese_name_of_the_run_later_mode_is_the_same_everywhere_in_the_window(self):
        name = "executar depois de instalar"
        with mock.patch.object(app, "ACTIVE_LANGUAGE", "pt"):
            texts = [t for _k, t in app.App.seed_target_texts()]
            texts += [app.App.seed_target_note(None, app.SEED_CHOICE_WINDOWS_SETUP)]
            texts += list(app.App._windows_seed_success_texts(True, True))
        self.assertIn(name, texts[3])
        self.assertIn(name, texts[5])
        self.assertIn(name, texts[-1])
        for text in texts:
            self.assertNotIn("após a instalação", text)
            self.assertNotIn("executar após", text)
            self.assertNotIn("rodar depois", text)

    def test_the_confirmation_wording_is_translated(self):
        with mock.patch.object(app, "ACTIVE_LANGUAGE", "pt"):
            self.assertEqual(app._("the hardening seed files"), "os arquivos do kit de reforço")


if __name__ == "__main__":
    unittest.main()
