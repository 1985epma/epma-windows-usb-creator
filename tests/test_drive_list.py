"""Tests for the USB drive list (DriveList): one selectable row per drive, a placeholder while the drives
are listed, a message when there are none, and the lock during a write.

The row texts are pure logic and always run. The widget tests need a window and are skipped without a
display. Nothing here touches a real device: the drive listing and the dialogs are replaced.
"""
import threading
import unittest
from unittest import mock

from tests import test_fixes_gui as base
from tests.helpers import app

GB = 1000 ** 3


def drive(dev_id, model="SanDisk Ultra", size=32 * GB, volumes=()):
    return {"id": dev_id, "size": size, "label": f"/dev/{dev_id}", "model": model, "volumes": list(volumes),
            "identity": ()}


FIRST = drive("disk4", "SanDisk Ultra", 32 * GB, [{"name": "Untitled", "filesystem": "FAT32"}])
SECOND = drive("disk5", "Kingston", 64 * GB)


class RowTextTests(unittest.TestCase):
    def test_model_size_device_and_volumes(self):
        name, size, detail = app.drive_row_texts(FIRST)
        self.assertEqual(name, "SanDisk Ultra")
        self.assertEqual(size, "29.8 GB")
        self.assertEqual(detail, "/dev/disk4 · 1 volume (Untitled)")

    def test_several_volumes_are_summarised(self):
        vols = [{"name": n} for n in ("A", "B", "C", "D")]
        self.assertEqual(app.drive_row_texts(drive("sdb", volumes=vols))[2], "/dev/sdb · 4 volumes (A, B, C, …)")

    def test_no_volumes_and_unknown_contents(self):
        self.assertEqual(app.drive_row_texts(drive("sdb"))[2], "/dev/sdb · no volumes")
        self.assertEqual(app.drive_row_texts(dict(drive("sdb"), volumes=None))[2], "/dev/sdb · contents unknown")

    def test_without_a_model_the_device_is_the_name(self):
        name, _size, detail = app.drive_row_texts(drive("sdb", model=""))
        self.assertEqual(name, "/dev/sdb")
        self.assertEqual(detail, "no volumes")

    def test_an_old_record_without_model_size_or_volumes_still_works(self):
        self.assertEqual(app.drive_row_texts({"id": "disk9", "label": "x"}), ("/dev/disk9", "", ""))

    def test_the_texts_are_translated(self):
        with mock.patch.object(app, "ACTIVE_LANGUAGE", "pt"):
            self.assertEqual(app.drive_row_texts(drive("sdb"))[2], "/dev/sdb · sem volumes")


class DriveListTestCase(base.GuiTestCase):
    def setUp(self):
        super().setUp()
        self.list = self.win.disk_list

    def refresh(self, *drives):
        self.listed = list(drives)
        self.win.refresh_disks(sync=True)

    def packed(self, widget):
        return str(widget.winfo_manager()) == "pack"


class ModelTests(DriveListTestCase):
    def test_it_replaces_the_combobox_and_keeps_the_refresh_button(self):
        self.assertFalse(hasattr(self.win, "disk_combo"))
        self.assertIn("Refresh USB drives list", str(self.win.refresh_btn.cget("text")))
        self.assertTrue(self.packed(self.list))

    def test_one_row_per_drive_and_the_first_is_selected(self):
        self.refresh(FIRST, SECOND)
        self.assertEqual(self.list.view_state(), "items")
        self.assertEqual(len(self.list.rows), 2)
        self.assertTrue(all(self.packed(row) for row in self.list.rows))
        self.assertEqual(self.list.selected_index(), 0)
        self.assertEqual(self.win.selected_disk()["id"], "disk4")
        self.assertEqual([row.selected for row in self.list.rows], [True, False])

    def test_selecting_a_row_changes_the_selected_drive_and_the_create_state(self):
        self.win.iso_path.set("/tmp/example.iso")
        self.refresh(FIRST, SECOND)
        self.list._row_pressed(self.list.rows[1])  # what a click on the row (or Space/Return on it) does
        self.assertEqual(self.win.selected_disk()["id"], "disk5")
        self.assertEqual([row.selected for row in self.list.rows], [False, True])
        self.assertEqual(self.state(self.win.create_btn), "normal")

    def test_select_calls_on_select_only_when_the_selection_changes(self):
        calls = []
        widget = app.DriveList(self.win, on_select=lambda: calls.append(1))
        widget.set_items([FIRST, SECOND])
        self.assertEqual(calls, [], "set_items is not a user choice")
        widget.select(0)
        self.assertEqual(calls, [])
        widget.select(1)
        self.assertEqual(calls, [1])
        widget.select(99)  # out of range clears the selection
        self.assertEqual(widget.selected_index(), -1)
        self.assertIsNone(widget.selected_item())

    def test_the_selection_stays_on_the_same_drive_by_id_across_refreshes(self):
        self.refresh(FIRST, SECOND)
        self.list.select(1)
        self.refresh(SECOND, FIRST)  # the order changed
        self.assertEqual(self.win.selected_disk()["id"], "disk5")
        self.assertEqual(self.list.selected_index(), 0)
        self.refresh(dict(SECOND, model="Kingston DataTraveler"), FIRST)  # same id, another text
        self.assertEqual(self.win.selected_disk()["id"], "disk5")

    def test_the_selection_goes_to_the_first_drive_when_the_chosen_one_is_gone(self):
        self.refresh(FIRST, SECOND)
        self.list.select(1)
        self.refresh(FIRST)
        self.assertEqual(self.win.selected_disk()["id"], "disk4")

    def test_no_drive_means_no_selection(self):
        self.refresh(FIRST)
        self.refresh()
        self.assertIsNone(self.win.selected_disk())
        self.assertEqual(self.list.selected_index(), -1)
        self.assertEqual(self.list.rows, [])

    def test_the_rows_are_reused_when_the_count_does_not_change(self):
        self.refresh(FIRST, SECOND)
        before = list(self.list.rows)
        self.refresh(FIRST, SECOND)
        self.assertEqual(self.list.rows, before)


class WriteLockTests(DriveListTestCase):
    def test_a_locked_list_ignores_clicks_and_the_keyboard_and_unlocks_after(self):
        self.refresh(FIRST, SECOND)
        self.win._creating = True
        self.win._sync_controls()
        self.assertFalse(self.list.is_enabled())
        self.list._row_pressed(self.list.rows[1])
        self.list._row_arrow(self.list.rows[0], 1)
        self.assertEqual(self.list.selected_index(), 0)
        self.assertFalse(any(str(row.cget("takefocus")) in ("1", "True") for row in self.list.rows))
        self.win._creating = False
        self.win._sync_controls()
        self.assertTrue(self.list.is_enabled())
        self.list._row_pressed(self.list.rows[1])
        self.assertEqual(self.list.selected_index(), 1)

    def test_the_refresh_button_is_locked_too(self):
        self.win._creating = True
        self.win._sync_controls()
        self.assertEqual(self.state(self.win.refresh_btn), "disabled")


class PlaceholderTests(DriveListTestCase):
    def test_two_grey_rows_while_listing_and_nothing_is_shown_yet(self):
        gate, started = threading.Event(), threading.Event()
        self.addCleanup(gate.set)

        def slow():
            started.set()
            gate.wait(10)
            return [dict(FIRST)]

        with mock.patch.object(app, "get_external_disks", slow):
            self.win.refresh_disks(quiet=True)
            self.assertTrue(started.wait(5))
            self.assertEqual(self.list.view_state(), "loading")
            self.assertTrue(self.list.is_loading())
            self.assertEqual(len(self.list.skeleton), 2)
            self.assertTrue(all(self.packed(row) for row in self.list.skeleton))
            self.assertFalse(self.packed(self.list.empty))
            gate.set()
            self.pump(lambda: not self.win._disk_listing)
        self.assertFalse(self.list.is_loading())
        self.assertEqual(self.list.view_state(), "items")
        self.assertFalse(any(self.packed(row) for row in self.list.skeleton))

    def test_a_refresh_with_drives_already_shown_keeps_the_rows(self):
        self.refresh(FIRST)
        gate = threading.Event()
        self.addCleanup(gate.set)
        with mock.patch.object(app, "get_external_disks", lambda: (gate.wait(10), [dict(FIRST)])[1]):
            self.win.refresh_disks(quiet=True)
            self.assertTrue(self.list.is_loading())
            self.assertEqual(self.list.view_state(), "items")
            self.assertFalse(any(self.packed(row) for row in self.list.skeleton))
            gate.set()
            self.pump(lambda: not self.win._disk_listing)

    def test_the_empty_message_when_the_listing_found_nothing(self):
        self.refresh()
        self.assertEqual(self.list.view_state(), "empty")
        self.assertTrue(self.packed(self.list.empty))
        self.assertFalse(any(self.packed(row) for row in self.list.skeleton))
        texts = [str(child.cget("text")) for child in self.list.empty.winfo_children()]
        self.assertEqual(texts, ["No USB drive found", "Plug in a USB drive (8 GB or more) and it will appear here."])

    def test_the_create_hint_is_unchanged(self):
        self.win.iso_path.set("/tmp/example.iso")
        self.refresh()
        self.assertEqual(str(self.win.create_hint.cget("text")),
                         'No USB drive found. Plug it in and click "Refresh USB drives list".')

    def test_the_empty_message_goes_away_when_a_drive_appears(self):
        self.refresh()
        self.refresh(FIRST)
        self.assertEqual(self.list.view_state(), "items")
        self.assertFalse(self.packed(self.list.empty))

    def test_a_failed_listing_stops_the_placeholder(self):
        with mock.patch.object(app, "get_external_disks", side_effect=RuntimeError("diskutil hung")):
            self.win.refresh_disks(quiet=True)
            self.pump(lambda: not self.win._disk_listing)
        self.assertNotEqual(self.list.view_state(), "loading")
        self.assertEqual(self.list.view_state(), "empty")

    def test_the_messages_are_translated(self):
        with mock.patch.object(app, "ACTIVE_LANGUAGE", "pt"):
            widget = app.DriveList(self.win)
            texts = [str(child.cget("text")) for child in widget.empty.winfo_children()]
        self.assertEqual(texts[0], "Nenhum pendrive USB encontrado")


class KeyboardTests(DriveListTestCase):
    def test_only_the_selected_row_takes_the_tab_focus(self):
        self.refresh(FIRST, SECOND)
        focus = [str(row.cget("takefocus")) in ("1", "True") for row in self.list.rows]
        self.assertEqual(focus, [True, False])
        self.list.select(1)
        focus = [str(row.cget("takefocus")) in ("1", "True") for row in self.list.rows]
        self.assertEqual(focus, [False, True])

    def test_up_and_down_move_the_selection(self):
        self.refresh(FIRST, SECOND)
        first, second = self.list.rows
        self.assertEqual(self.list._row_arrow(first, 1), "break")
        self.assertEqual(self.list.selected_index(), 1)
        self.list._row_arrow(second, 1)  # at the end: stays
        self.assertEqual(self.list.selected_index(), 1)
        self.list._row_arrow(second, -1)
        self.assertEqual(self.list.selected_index(), 0)

    def test_the_keys_are_bound_on_the_rows(self):
        self.refresh(FIRST, SECOND)
        for row in self.list.rows:
            for key in ("<Up>", "<Down>", "<space>", "<Return>", "<Button-1>"):
                with self.subTest(key=key):
                    self.assertTrue(row.bind(key))

    def test_pressing_a_row_chooses_it(self):
        self.refresh(FIRST, SECOND)
        self.list._row_pressed(self.list.rows[1])
        self.assertEqual(self.win.selected_disk()["id"], "disk5")


if __name__ == "__main__":
    unittest.main()
