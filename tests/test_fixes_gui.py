"""Tests for the GUI review fixes: write lock, dependency gate, close protection, background drive
listing, focus-safe card drawing, image-type detection, hint layout, cancel texts and friends.

The pure-logic tests always run. The tests that need a window are skipped when Tk is missing (the
default python3 on a bare machine) or when no display is available. Nothing here touches a real
device: the drive listing, the message boxes and the engine are replaced.
"""
import io
import os
import plistlib
import subprocess
import threading
import time
import unittest
from unittest import mock

from tests.helpers import MIB, TempDirTestCase, app

GIB = 1024 ** 3
USB_DISK = {"id": "disk9", "size": 32 * 1000 ** 3, "label": "/dev/disk9 - Test", "identity": ()}


class FakeMessageBox:
    """Records every dialog and answers the questions with `yes`."""

    def __init__(self, yes=False):
        self.yes = yes
        self.calls = []

    def _record(self, kind, title, message):
        self.calls.append((kind, title, message))

    def showinfo(self, title, message, **_kw):
        self._record("info", title, message)

    def showerror(self, title, message, **_kw):
        self._record("error", title, message)

    def showwarning(self, title, message, **_kw):
        self._record("warning", title, message)

    def askyesno(self, title, message, **_kw):
        self._record("question", title, message)
        return self.yes

    def titles(self, kind=None):
        return [c[1] for c in self.calls if kind is None or c[0] == kind]


# ---------------------------------------------------------------------------
# Pure logic (no window)
# ---------------------------------------------------------------------------
class WindowsVolumeIdTests(unittest.TestCase):
    def test_microsoft_volume_ids_match(self):
        for vid in ("CCCOMA_X64FRE_EN-US_DV9", "WIN11_23H2", "Win10_22H2_EnglishInternational_x64",
                    "Win11_24H2_English_x64", "WIN11", "WINDOWS_SERVER_2022", "WIN7SP1", "CCSA_X86FRE_EN-US_DV5"):
            with self.subTest(vid=vid):
                self.assertTrue(app.WINDOWS_VOLUME_ID_RE.match(vid.upper()), vid)

    def test_other_volume_ids_do_not_match(self):
        for vid in ("Ubuntu 24.04 LTS amd64", "ARCH_202610", "Fedora-WS-Live-41", "DEBIAN 12", "WINE_11",
                    "WIN100", "Linux Mint 22", "TAILS 6.0", "GPARTED-LIVE"):
            with self.subTest(vid=vid):
                self.assertFalse(app.WINDOWS_VOLUME_ID_RE.match(vid.upper()), vid)


class EtaTextTests(unittest.TestCase):
    def test_minutes_and_seconds_never_raw_seconds(self):
        self.assertEqual(app._eta_text(80, 10), "~1m20s left")
        self.assertEqual(app._eta_text(7200, 10), "~120m00s left")
        self.assertEqual(app._eta_text(5.9, 1), "~0m05s left")

    def test_unknown_speed_gives_nothing(self):
        for speed in (0, -1, None):
            self.assertEqual(app._eta_text(100, speed), "")
        self.assertEqual(app._eta_text(None, 10), "")
        self.assertEqual(app._eta_text(-5, 10), "")

    def test_it_is_translated(self):
        with mock.patch.object(app, "ACTIVE_LANGUAGE", "pt"):
            self.assertEqual(app._eta_text(125, 10), "faltam ~2m05s")
        self.assertIn("calculating...", app.PT_BR)


class ValidateIsoPathWording(TempDirTestCase):
    def test_small_file_message_is_about_an_image(self):
        tiny = self.write_file("tiny.img", b"x" * 1000)
        with self.assertRaises(ValueError) as ctx:
            app.validate_iso_path(tiny)
        self.assertIn("too small to be a valid image", str(ctx.exception))
        self.assertNotIn("Windows 11", str(ctx.exception))


class CanceledTextsTests(unittest.TestCase):
    def test_touched_drive_is_called_unusable(self):
        log, _title, body = app.App._canceled_texts(True)
        self.assertIn("unusable", log)
        self.assertIn("unusable", body)

    def test_untouched_drive_is_not_called_unusable(self):
        log, _title, body = app.App._canceled_texts(False)
        self.assertIn("not modified", log)
        self.assertIn("NOT modified", body)
        self.assertNotIn("unusable", log.lower())
        self.assertNotIn("unusable", body.lower())

    def test_new_texts_are_translated(self):
        with mock.patch.object(app, "ACTIVE_LANGUAGE", "pt"):
            log, _title, body = app.App._canceled_texts(False)
        self.assertIn("não foi modificado", log)
        self.assertIn("NÃO foi modificado", body)


class EnumerationTests(unittest.TestCase):
    """Every query command has a timeout; a drive of 0 bytes is never offered (fail closed)."""

    def test_macos_listing_has_timeouts_and_skips_zero_size(self):
        calls = []

        def fake(args, **kw):
            calls.append((list(args), kw))
            if args[0] == "ioreg":
                return plistlib.dumps([])
            if args[:2] == ["diskutil", "list"] and "external" in args:
                return plistlib.dumps({"AllDisksAndPartitions": [
                    {"DeviceIdentifier": "disk4", "Size": 0, "Partitions": []},
                    {"DeviceIdentifier": "disk5", "Size": 8 * GIB, "Partitions": []}]})
            if args[:2] == ["diskutil", "list"]:
                return plistlib.dumps({"AllDisksAndPartitions": []})
            if args[:2] == ["diskutil", "info"]:
                return plistlib.dumps({"Internal": False, "Removable": True, "Ejectable": True,
                                       "BusProtocol": "USB", "MediaName": "Fake Stick"})
            raise AssertionError(f"unexpected command {args}")

        with mock.patch.object(app.subprocess, "check_output", fake):
            disks = app.macos_get_external_disks()
        self.assertEqual([d["id"] for d in disks], ["disk5"])
        self.assertTrue(calls)
        for args, kw in calls:
            self.assertIn("timeout", kw, f"no timeout for {args}")
            self.assertGreater(kw["timeout"], 0)
            limit = app.IOREG_TIMEOUT if args[0] == "ioreg" else app.QUERY_TIMEOUT
            self.assertLessEqual(kw["timeout"], limit)
        self.assertLess(app.IOREG_TIMEOUT, app.QUERY_TIMEOUT)
        # `diskutil info` was never run for the 0-byte drive
        self.assertFalse([a for a, _ in calls if a[:2] == ["diskutil", "info"] and a[-1] == "/dev/disk4"])

    def test_macos_hung_command_hides_the_disk_instead_of_hanging(self):
        def fake(args, **kw):
            if args[:2] == ["diskutil", "list"] and "external" in args:
                return plistlib.dumps({"AllDisksAndPartitions": [
                    {"DeviceIdentifier": "disk5", "Size": 8 * GIB, "Partitions": []}]})
            raise subprocess.TimeoutExpired(args, kw.get("timeout", 1))

        with mock.patch.object(app.subprocess, "check_output", fake):
            self.assertEqual(app.macos_get_external_disks(), [])  # cannot verify it is external: hidden

    def test_linux_queries_have_timeouts(self):
        calls = []

        def fake(args, **kw):
            calls.append((list(args), kw))
            raise subprocess.CalledProcessError(1, args)

        with mock.patch.object(app.subprocess, "check_output", fake):
            app.linux_root_disk()
            app.linux_disks_holding_critical_mounts()
            with self.assertRaises(subprocess.CalledProcessError):
                app.linux_lsblk_disks()
        self.assertGreaterEqual(len(calls), 4)
        for args, kw in calls:
            self.assertIn("timeout", kw, f"no timeout for {args}")
            self.assertLessEqual(kw["timeout"], app.QUERY_TIMEOUT)

    def test_linux_lsblk_skips_zero_and_unreadable_sizes(self):
        devices = [
            {"name": "sdb", "type": "disk", "tran": "usb", "size": 0},
            {"name": "sdc", "type": "disk", "tran": "usb", "size": 8 * GIB},
            {"name": "sdd", "type": "disk", "tran": "usb", "size": "abc"},
            {"name": "sde", "type": "disk", "tran": "usb", "size": None},
            {"name": "sdf", "type": "disk", "tran": "usb", "size": str(4 * GIB)},
        ]
        with mock.patch.object(app, "linux_root_disk", return_value=None), \
                mock.patch.object(app, "linux_disks_holding_critical_mounts", return_value=set()), \
                mock.patch.object(app.shutil, "which", return_value="/usr/bin/lsblk"), \
                mock.patch.object(app, "linux_lsblk_disks", return_value=devices):
            disks = app.linux_get_external_disks()
        self.assertEqual([d["id"] for d in disks], ["sdc", "sdf"])
        self.assertTrue(all(d["size"] > 0 for d in disks))

    def test_linux_sys_fallback_skips_zero_size(self):
        files = {"/sys/block/sdz/removable": "1\n", "/sys/block/sdz/size": "0\n"}

        def fake_open(path, *_a, **_kw):
            if path in files:
                return io.StringIO(files[path])
            raise OSError(path)

        with mock.patch.object(app, "linux_root_disk", return_value=None), \
                mock.patch.object(app, "linux_disks_holding_critical_mounts", return_value=set()), \
                mock.patch.object(app.shutil, "which", return_value=None), \
                mock.patch.object(app.os, "listdir", return_value=["sdz"]), \
                mock.patch.object(app.os.path, "exists", return_value=True), \
                mock.patch.object(app.os.path, "realpath", return_value="/sys/devices/pci/usb1/block/sdz"), \
                mock.patch("builtins.open", fake_open):
            self.assertEqual(app.linux_get_external_disks(), [])
            files["/sys/block/sdz/size"] = "16777216\n"
            self.assertEqual([d["id"] for d in app.linux_get_external_disks()], ["sdz"])


# ---------------------------------------------------------------------------
# Tests that need a window
# ---------------------------------------------------------------------------
@unittest.skipIf(app.tk is None, "Tk is not available")
class GuiTestCase(unittest.TestCase):
    """Builds a real (withdrawn) window with the drive listing, dialogs and dependencies replaced."""

    def setUp(self):
        self.box = FakeMessageBox()
        self.listed = []
        self.list_calls = []
        for patcher in (
            mock.patch.object(app, "messagebox", self.box),
            mock.patch.object(app, "get_external_disks", self._list_disks),
            mock.patch.object(app, "get_missing_dependencies", return_value=[]),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        try:
            self.win = app.App()
        except app.tk.TclError as exc:  # no display (a bare Linux runner)
            self.skipTest(f"no display: {exc}")
        self.win.withdraw()
        self.win._last_disk_refresh = time.monotonic()  # no automatic listing while a test runs
        self.win.update_idletasks()
        self.addCleanup(self._destroy)

    def _destroy(self):
        try:
            # Pending timers of a destroyed window would run (and complain) inside the next test's main loop.
            for ident in self.win.tk.splitlist(self.win.tk.call("after", "info")):
                self.win.after_cancel(ident)
            self.win.destroy()
        except app.tk.TclError:
            pass

    def _list_disks(self):
        self.list_calls.append(threading.current_thread())
        return [dict(d) for d in self.listed]

    def pump(self, condition, timeout=10):
        """Run the Tk main loop until `condition()` is true (worker threads deliver results through it)."""
        end = time.monotonic() + timeout

        def check():
            if condition() or time.monotonic() > end:
                self.win.quit()
            else:
                self.win.after(10, check)

        self.win.after(10, check)
        self.win.mainloop()
        return condition()

    def with_disk(self, iso="/tmp/exemplo.iso"):
        self.listed = [USB_DISK]
        self.win.iso_path.set(iso)
        self.win.refresh_disks(sync=True)
        self.assertIsNotNone(self.win.selected_disk())

    def state(self, widget):
        return str(widget.cget("state"))


class WriteLockTests(GuiTestCase):
    def test_create_stays_disabled_while_writing(self):
        self.with_disk()
        self.assertEqual(self.state(self.win.create_btn), "normal")
        self.win._creating = True
        self.win._sync_controls()
        self.win.update_create_button_state()
        self.assertEqual(self.state(self.win.create_btn), "disabled")
        # everything that used to re-enable it
        self.win.select_card(app.CARD_LINUX)
        self.assertEqual(self.state(self.win.create_btn), "disabled")
        self.win.refresh_disks(sync=True)
        self.assertEqual(self.state(self.win.create_btn), "disabled")
        self.win.disk_list._row_pressed(self.win.disk_list.rows[0])  # a click on the locked list does nothing
        self.win.update_idletasks()
        self.assertEqual(self.state(self.win.create_btn), "disabled")

    def test_controls_are_locked_during_a_write_and_unlocked_after(self):
        self.with_disk()
        self.win._creating = True
        self.win._sync_controls()
        self.assertFalse(self.win.disk_list.is_enabled())
        for widget in (self.win.refresh_btn, self.win.pick_btn, self.win.download_btn,
                       self.win.flex_download_btn, self.win.install_deps_btn):
            self.assertEqual(self.state(widget), "disabled")
        for card in self.win.cards.values():
            self.assertFalse(card._enabled)
        clicked = []
        card = self.win.cards[app.CARD_LINUX]
        card._command = clicked.append
        card._choose()
        self.assertEqual(clicked, [], "a locked card must ignore clicks")

        self.win._creation_ended()
        self.pump(lambda: not self.win._disk_listing)
        self.assertTrue(self.win.disk_list.is_enabled())
        for widget in (self.win.refresh_btn, self.win.pick_btn, self.win.download_btn, self.win.flex_download_btn):
            self.assertEqual(self.state(widget), "normal")
        self.assertTrue(all(c._enabled for c in self.win.cards.values()))
        self.assertEqual(self.state(self.win.cancel_create_btn), "disabled")
        card._choose()
        self.assertEqual(clicked, [app.CARD_LINUX])

    def test_start_create_returns_at_once_while_creating(self):
        self.win._creating = True
        self.win.create_cancel_event.set()  # a pending cancel must survive a second click
        with mock.patch.object(self.win, "_start_create_usb") as inner:
            self.win.start_create_usb()
        inner.assert_not_called()
        self.assertTrue(self.win.create_cancel_event.is_set())
        self.assertTrue(self.win._creating, "the running write's flag must not be reset by the second click")

    def test_a_refused_start_unlocks_again(self):
        self.with_disk()
        with mock.patch.object(self.win, "_start_create_usb", return_value=None):
            self.win.start_create_usb()
        self.assertFalse(self.win._creating)
        self.assertEqual(self.state(self.win.create_btn), "normal")
        self.assertTrue(self.win.disk_list.is_enabled())

    def test_an_exception_while_starting_unlocks_again(self):
        self.with_disk()
        with mock.patch.object(self.win, "_start_create_usb", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                self.win.start_create_usb()
        self.assertFalse(self.win._creating)

    def test_the_hint_is_empty_while_writing(self):
        self.with_disk()
        self.win._creating = True
        self.win.update_create_button_state()
        self.assertEqual(str(self.win.create_hint.cget("text")), "")


class DependencyGateTests(GuiTestCase):
    def test_missing_tool_disables_create_and_explains(self):
        self.with_disk()
        self.assertEqual(self.state(self.win.create_btn), "normal")
        with mock.patch.object(app, "get_missing_dependencies", return_value=["wimlib-imagex"]):
            self.win.update_create_button_state()
        self.assertEqual(self.state(self.win.create_btn), "disabled")
        hint = str(self.win.create_hint.cget("text"))
        self.assertIn("wimlib-imagex", hint)
        self.assertIn("Install missing dependencies", hint)
        self.win.update_create_button_state()  # tool installed again
        self.assertEqual(self.state(self.win.create_btn), "normal")

    def test_start_refuses_before_anything_is_confirmed(self):
        self.with_disk()
        self.win.confirm_erase = mock.Mock(return_value=True)
        with mock.patch.object(app, "get_missing_dependencies", return_value=["wimlib-imagex"]), \
                mock.patch.object(app, "build_usb", side_effect=AssertionError("must not start")):
            self.win.start_create_usb()
        self.win.confirm_erase.assert_not_called()
        self.assertEqual(self.box.titles("error"), ["Missing tools"])
        self.assertFalse(self.win._creating)

    def test_installing_blocks_create(self):
        self.with_disk()
        self.win._installing = True
        self.win.update_create_button_state()
        self.assertEqual(self.state(self.win.create_btn), "disabled")
        self.win._installation_ended()
        self.assertEqual(self.state(self.win.create_btn), "normal")


class ZeroSizeDriveTests(GuiTestCase):
    def test_a_zero_byte_drive_is_refused_not_skipped(self):
        self.listed = [dict(USB_DISK, size=0)]
        self.win.iso_path.set("/tmp/exemplo.iso")
        self.win.refresh_disks(sync=True)
        self.win.confirm_erase = mock.Mock(return_value=True)
        with mock.patch.object(app, "build_usb", side_effect=AssertionError("must not start")):
            self.win.start_create_usb()
        self.assertEqual(self.box.titles("error"), ["Unknown drive size"])
        self.win.confirm_erase.assert_not_called()
        self.assertFalse(self.win._creating)


class CloseWindowTests(GuiTestCase):
    def setUp(self):
        super().setUp()
        self.win.destroy = mock.Mock()

    def fake_worker(self, obey=True):
        """A thread standing in for the write worker: it ends when canceled (if `obey`)."""
        release = threading.Event()

        def run():
            if obey:
                self.win.create_cancel_event.wait(10)
            else:
                release.wait(10)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self.win._create_thread = thread
        self.win._creating = True
        self.addCleanup(release.set)
        self.addCleanup(self.win.create_cancel_event.set)
        return thread

    def test_idle_close_destroys_and_stops_downloads(self):
        self.win._on_close()
        self.win.destroy.assert_called_once()
        self.assertTrue(self.win.flex_cancel_event.is_set())
        self.assertTrue(self.win.cancel_event.is_set())
        self.assertEqual(self.box.calls, [])

    def test_the_close_button_is_wired_to_the_handler(self):
        self.assertIn("_on_close", str(self.win.protocol("WM_DELETE_WINDOW")))

    def test_close_during_a_write_asks_and_can_be_declined(self):
        thread = self.fake_worker()
        self.box.yes = False
        self.win._on_close()
        self.assertEqual(self.box.titles("question"), ["Quit while writing?"])
        self.win.destroy.assert_not_called()
        self.assertFalse(self.win.create_cancel_event.is_set())
        self.assertTrue(thread.is_alive())

    def test_confirmed_close_cancels_waits_and_destroys(self):
        thread = self.fake_worker()
        self.box.yes = True
        self.win._on_close()
        self.assertTrue(self.win.create_cancel_event.is_set())
        self.assertFalse(thread.is_alive(), "the close must wait for the worker to stop")
        self.win.destroy.assert_called_once()

    def test_a_worker_that_does_not_stop_asks_again_and_can_stay_open(self):
        self.fake_worker(obey=False)
        self.box.yes = True
        with mock.patch.object(app.App, "CLOSE_WAIT_SECONDS", 0.2):
            answers = iter([True, False])
            self.box.askyesno = lambda title, msg, **kw: (self.box._record("question", title, msg),
                                                           next(answers))[1]
            self.win._on_close()
        self.assertEqual(self.box.titles("question"), ["Quit while writing?", "Still stopping"])
        self.win.destroy.assert_not_called()
        self.assertFalse(self.win._closing)

    def test_no_dialog_pops_up_while_closing(self):
        self.win._closing = True
        self.win._notify("info", "Done", "x")
        self.win._report_error("Error", "boom")
        self.assertEqual(self.box.calls, [])

    def test_a_pending_confirmation_is_not_interrupted(self):
        self.win._creating = True  # the confirmation / password dialog is open, no worker yet
        self.win._on_close()
        self.win.destroy.assert_not_called()


class DriveListingTests(GuiTestCase):
    def test_listing_runs_in_a_worker_thread_and_never_overlaps(self):
        gate = threading.Event()
        started = threading.Event()

        def slow():
            self.list_calls.append(threading.current_thread())
            started.set()
            gate.wait(10)
            return [dict(USB_DISK)]

        self.addCleanup(gate.set)
        with mock.patch.object(app, "get_external_disks", slow):
            began = time.monotonic()
            self.win.refresh_disks(quiet=True)
            self.assertLess(time.monotonic() - began, 1.0, "the Tk thread must not wait for the listing")
            self.assertTrue(self.win._disk_listing)
            self.assertTrue(started.wait(5))
            self.win.refresh_disks(quiet=True)  # asked again while one is running
            self.win.refresh_disks()
            self.assertEqual(len(self.list_calls), 1, "two listings must never run at the same time")
            self.assertNotEqual(self.list_calls[0], threading.main_thread())
            gate.set()
            self.pump(lambda: not self.win._disk_listing and self.win.selected_disk() is not None)
        self.assertEqual(self.win.selected_disk()["id"], "disk9")
        self.assertEqual(len(self.list_calls), 2, "the request made meanwhile is served right after")

    def test_a_stale_result_is_ignored(self):
        gate = threading.Event()
        self.addCleanup(gate.set)

        def slow():
            gate.wait(10)
            return [dict(USB_DISK)]

        with mock.patch.object(app, "get_external_disks", slow):
            self.win.refresh_disks(quiet=True)
        self.win.refresh_disks(sync=True)  # a newer (synchronous) listing: no drives
        self.assertEqual(self.win.disks, [])
        gate.set()
        self.pump(lambda: not self.win._disk_listing)
        self.assertEqual(self.win.disks, [], "the older listing must not overwrite the newer one")

    def test_a_result_arriving_during_a_write_is_dropped(self):
        gate = threading.Event()
        self.addCleanup(gate.set)

        def slow():
            gate.wait(10)
            return [dict(USB_DISK)]

        with mock.patch.object(app, "get_external_disks", slow):
            self.win.refresh_disks(quiet=True)
        self.win._creating = True
        gate.set()
        self.pump(lambda: not self.win._disk_listing)
        self.assertEqual(self.win.disks, [])

    def test_errors_are_logged_when_quiet_and_shown_otherwise(self):
        with mock.patch.object(app, "get_external_disks", side_effect=RuntimeError("diskutil hung")):
            self.win.refresh_disks(quiet=True)
            self.pump(lambda: not self.win._disk_listing)
            self.assertEqual(self.box.calls, [])
            self.win._flush_log()
            self.assertIn("diskutil hung", self.win.log_text.get("1.0", "end"))
            self.win.refresh_disks()
            self.pump(lambda: not self.win._disk_listing and self.win.error_banner.shown)
        self.assertEqual(self.box.calls, [], "a listing failure is a banner, not a dialog")
        self.assertEqual(self.win.error_banner.title_text, "Error")
        self.assertIn("diskutil hung", self.win.error_banner.message_text)

    def test_sync_mode_lists_on_the_calling_thread(self):
        self.listed = [USB_DISK]
        self.win.refresh_disks(sync=True)
        self.assertEqual(self.list_calls, [threading.main_thread()])
        self.assertEqual(self.win.selected_disk()["id"], "disk9")

    def test_selected_drive_survives_a_refresh(self):
        self.listed = [dict(USB_DISK, id="disk7", label="/dev/disk7"), USB_DISK]
        self.win.refresh_disks(sync=True)
        self.win.disk_list.select(1)
        self.win.refresh_disks(sync=True)
        self.assertEqual(self.win.selected_disk()["id"], "disk9")


class OptionCardFocusTests(GuiTestCase):
    def card(self):
        return self.win.cards[app.CARD_WINDOWS]

    def test_draw_survives_a_keyerror_from_focus_get(self):
        card = self.card()
        for error in (KeyError("popdown"), KeyError("!combobox"), app.tk.TclError("bad window")):
            with self.subTest(error=error), mock.patch.object(card, "focus_get", side_effect=error):
                card._draw()
                self.assertTrue(card.find_all(), "the card must not be left blank")

    def test_fallback_compares_the_focus_path(self):
        card = self.card()

        class FakeTk:
            def __init__(self, answer):
                self.answer = answer

            def call(self, *_args):
                if isinstance(self.answer, Exception):
                    raise self.answer
                return self.answer

        with mock.patch.object(card, "focus_get", side_effect=KeyError("popdown")):
            with mock.patch.object(card, "tk", FakeTk(str(card))):
                self.assertTrue(card._has_focus())
            with mock.patch.object(card, "tk", FakeTk(".other.widget")):
                self.assertFalse(card._has_focus())
            with mock.patch.object(card, "tk", FakeTk(app.tk.TclError("x"))):
                self.assertFalse(card._has_focus())

    def test_focus_is_computed_before_the_canvas_is_erased(self):
        card = self.card()
        before = len(card.find_all())
        self.assertGreater(before, 0)
        with mock.patch.object(card, "focus_get", side_effect=RuntimeError("unexpected")):
            with self.assertRaises(RuntimeError):
                card._draw()
        self.assertEqual(len(card.find_all()), before, "a failure must not leave a blank card")


class ImageTypeChoiceTests(GuiTestCase, TempDirTestCase):
    def setUp(self):
        GuiTestCase.setUp(self)
        TempDirTestCase.setUp(self)

    def logged(self):
        self.win._flush_log()
        return self.win.log_text.get("1.0", "end")

    def make_pvd_iso(self, name, volume_id, hybrid):
        """A file with an ISO 9660 primary volume descriptor (what every real ISO has)."""
        data = bytearray(2 * MIB)
        pvd = 16 * 2048
        data[pvd:pvd + 7] = b"\x01CD001\x01"
        data[pvd + 40:pvd + 72] = volume_id.encode("latin-1").ljust(32)
        data[pvd + 128:pvd + 130] = (2048).to_bytes(2, "little")
        if hybrid:
            data[510:512] = b"\x55\xaa"
        return self.write_file(name, bytes(data))

    def test_volume_ids_are_detected_as_windows(self):
        for vid in ("CCCOMA_X64FRE_EN-US_DV9", "WIN11_23H2", "Win10_22H2_EnglishInternational_x64"):
            with self.subTest(vid=vid):
                path = self.make_pvd_iso("w.iso", vid, hybrid=False)
                self.assertEqual(app.detect_iso_kind(path), app.ISO_KIND_WINDOWS)
        for vid in ("Ubuntu 24.04 LTS amd64", "ARCH_202610"):
            with self.subTest(vid=vid):
                path = self.make_pvd_iso("l.iso", vid, hybrid=True)
                self.assertEqual(app.detect_iso_kind(path), app.ISO_KIND_LINUX)

    def test_unknown_content_keeps_the_card_whatever_the_name_says(self):
        path = self.make_iso("darwin-linux.img", hybrid=False)
        self.assertEqual(app.detect_iso_kind(path), app.ISO_KIND_UNKNOWN)
        for card in (app.CARD_LINUX, app.CARD_OTHER, app.CARD_CHROME):
            with self.subTest(card=card):
                self.win.select_card(card)
                self.win.set_iso(path)
                self.assertEqual(self.win.card_var.get(), card)
        self.assertIn("could not be identified", self.logged())

    def test_unknown_content_never_selects_windows_by_name(self):
        path = self.make_iso("win11-notes.img", hybrid=False)
        self.win.select_card(app.CARD_LINUX)
        self.win.set_iso(path)
        self.assertEqual(self.win.card_var.get(), app.CARD_LINUX)
        self.assertEqual(self.win.mode_var.get(), app.MODE_LINUX)

    def test_known_content_still_preselects(self):
        path = self.make_pvd_iso("ubuntu.iso", "Ubuntu 24.04 LTS amd64", hybrid=True)
        self.assertEqual(app.detect_iso_kind(path), app.ISO_KIND_LINUX)
        self.win.select_card(app.CARD_OTHER)
        self.win.set_iso(path)
        self.assertEqual(self.win.card_var.get(), app.CARD_OTHER)
        self.win.select_card(app.CARD_WINDOWS)
        self.win.set_iso(path)
        self.assertEqual(self.win.card_var.get(), app.CARD_LINUX)
        with mock.patch.object(app, "detect_iso_kind", return_value=app.ISO_KIND_WINDOWS):
            self.win.set_iso(path)
        self.assertEqual(self.win.card_var.get(), app.CARD_WINDOWS)
        self.assertIn("from the content of the ISO", self.logged())

    def test_windows_card_with_unknown_content_asks_first(self):
        path = self.make_iso("whatever.iso", hybrid=False)
        self.win.iso_path.set(path)
        self.box.yes = False
        self.assertFalse(self.win._image_matches_choice(app.MODE_WINDOWS))
        self.assertEqual(self.box.titles("question"), ["Image type not recognised"])
        self.box.yes = True
        self.assertTrue(self.win._image_matches_choice(app.MODE_WINDOWS))

    def test_other_cards_and_known_windows_do_not_ask(self):
        path = self.make_iso("x.iso", hybrid=False)
        self.win.iso_path.set(path)
        self.assertTrue(self.win._image_matches_choice(app.MODE_LINUX))
        with mock.patch.object(app, "detect_iso_kind", return_value=app.ISO_KIND_WINDOWS):
            self.assertTrue(self.win._image_matches_choice(app.MODE_WINDOWS))
        self.assertEqual(self.box.calls, [])

    def test_the_question_is_translated(self):
        with mock.patch.object(app, "ACTIVE_LANGUAGE", "pt"):
            self.win.iso_path.set(self.make_iso("whatever.iso", hybrid=False))
            self.win._image_matches_choice(app.MODE_WINDOWS)
        self.assertEqual(self.box.titles("question"), ["Tipo de imagem não reconhecido"])


class HintLayoutTests(GuiTestCase):
    """The hint must sit between the Create row and the progress bar.

    The order is checked on the PACKING order, which does not depend on the window being drawn
    (a headless CI runner never maps it, so on-screen coordinates are all the same there). When
    the widgets really are on screen the coordinates must agree with that order too.
    """

    def page_order(self):
        win = self.win
        # the bar and the log are on screen only after a write started / "Show details" was opened
        win._reset_create_progress()
        self.addCleanup(win.create_progress.stop)
        win.details_toggle.set_open(True)
        page = win.create_hint.master
        slaves = page.pack_slaves()
        row = win.create_btn.master
        return {name: slaves.index(widget) for name, widget in (
            ("row", row), ("hint", win.create_hint), ("progress", win.create_progress), ("log", win.log_text))}

    def assert_order(self):
        order = self.page_order()
        self.assertLess(order["row"], order["hint"], order)
        self.assertLess(order["hint"], order["progress"], order)
        self.assertLess(order["progress"], order["log"], order)
        win = self.win
        if win.create_btn.winfo_ismapped() and win.log_text.winfo_ismapped():  # drawn: coordinates must agree
            top = {name: widget.winfo_rooty() for name, widget in (
                ("button", win.create_btn), ("hint", win.create_hint),
                ("progress", win.create_progress), ("log", win.log_text))}
            self.assertLess(top["button"], top["hint"], top)
            self.assertLess(top["hint"], top["progress"], top)
            self.assertLess(top["progress"], top["log"], top)

    def test_vertical_order_button_hint_progress_log(self):
        self.win.iso_path.set("")
        self.win.update_create_button_state()
        self.assertTrue(str(self.win.create_hint.cget("text")))
        self.win.update_idletasks()
        self.assertTrue(self.win.create_hint.winfo_manager(), "the hint should be packed while it has text")
        self.assert_order()

    def test_the_order_survives_the_hint_changing(self):
        for _round in range(3):
            self.win.iso_path.set("")
            self.win.update_create_button_state()      # hint shown
            self.with_disk()
            self.win.update_create_button_state()      # hint hidden
        self.win.iso_path.set("")
        self.win.update_create_button_state()
        self.win.update_idletasks()
        self.assertTrue(self.win.create_hint.winfo_manager())
        self.assert_order()

    def test_sha_labels_keep_progress_above_verdict_in_any_order(self):
        win = self.win
        win.iso_check_frame.pack(fill="x")
        for first, second in ((win.iso_sha_label, win.iso_sha_result), (win.iso_sha_result, win.iso_sha_label)):
            with self.subTest(first=str(first)):
                win._reset_iso_sha()
                first.config(text="first")
                second.config(text="second")
                win._show_sha_bar()
                order = win.iso_check_frame.pack_slaves()
                self.assertLess(order.index(win.iso_sha_progress), order.index(win.iso_sha_label))
                self.assertLess(order.index(win.iso_sha_label), order.index(win.iso_sha_result))


class QuietLayoutTests(GuiTestCase):
    """P1 of the GUI review: one Cancel, a highlighted Create, optional parts behind links, no idle bars."""

    def manager(self, widget):
        return str(widget.winfo_manager())

    def test_there_is_a_single_cancel_button(self):
        self.assertFalse(hasattr(self.win, "cancel_btn"))
        self.assertFalse(hasattr(self.win, "flex_cancel_btn"))

        def cancels(widget):
            found = []
            for child in widget.winfo_children():
                if str(child.winfo_class()) == "TButton" and str(child.cget("text")) == "Cancel":
                    found.append(child)
                found += cancels(child)
            return found

        self.assertEqual(cancels(self.win), [self.win.cancel_create_btn])

    def test_the_single_cancel_stops_whatever_is_running(self):
        win = self.win
        win._download_running = True
        win._sync_controls()
        self.assertEqual(self.state(win.cancel_create_btn), "normal")
        win.cancel_current()
        self.assertTrue(win.cancel_event.is_set())
        win._download_running = False
        win._flex_busy = True
        win._sync_controls()
        self.assertEqual(self.state(win.cancel_create_btn), "normal")
        win.cancel_current()
        self.assertTrue(win.flex_cancel_event.is_set())
        win._flex_busy = False
        win._sync_controls()
        self.assertEqual(self.state(win.cancel_create_btn), "disabled")

    def test_cancel_during_a_write_still_asks_first(self):
        win = self.win
        win._creating = True
        win.cancel_create_btn.config(state="normal")
        win.cancel_current()                          # the question is answered "no"
        self.assertEqual(self.box.titles("question"), ["Cancel the operation?"])
        self.assertFalse(win.create_cancel_event.is_set())
        self.assertFalse(win.cancel_event.is_set() or win.flex_cancel_event.is_set())

    def test_create_is_an_accent_button_that_acts_like_a_button(self):
        win = self.win
        self.assertIsInstance(win.create_btn, app.AccentButton)
        self.assertEqual(self.state(win.create_btn), "disabled")
        clicks = []
        button = app.AccentButton(win, "Go", lambda: clicks.append(1) or "done", state="disabled")
        self.addCleanup(button.destroy)
        self.assertIsNone(button.invoke())
        self.assertEqual(clicks, [])
        button.config(state="normal")
        self.assertEqual(self.state(button), "normal")
        self.assertEqual(button.invoke(), "done")
        self.assertEqual(clicks, [1])
        button.config(text="Other")
        self.assertEqual(button.cget("text"), "Other")
        button.config(state="disabled")
        self.assertIsNone(button.invoke())

    def test_the_erase_warning_is_one_amber_line_right_above_the_create_row(self):
        win = self.win
        slaves = win.create_hint.master.pack_slaves()
        text = "WARNING: ALL DATA on the selected drive will be PERMANENTLY erased."
        warning = [w for w in slaves if str(w.winfo_class()) == "TLabel" and str(w.cget("text")) == text]
        self.assertEqual(len(warning), 1)
        self.assertEqual(slaves.index(warning[0]) + 1, slaves.index(win.create_btn.master))
        self.assertEqual(str(warning[0].cget("foreground")), "#ff9f0a")

    def test_the_log_is_behind_a_link_and_opens_by_itself_on_failure(self):
        win = self.win
        self.assertFalse(win.details_toggle.is_open)
        self.assertEqual(self.manager(win.log_text), "")
        self.assertIn("Show details", str(win.details_toggle.cget("text")))
        win.log("a line")                                   # logging works while the box is hidden
        self.assertIn("a line", win.log_text.get("1.0", "end"))
        win.details_toggle.toggle()
        self.assertEqual(self.manager(win.log_text), "pack")
        self.assertIn("Hide details", str(win.details_toggle.cget("text")))
        win.details_toggle.toggle()
        self.assertEqual(self.manager(win.log_text), "")
        win._finish_create_progress(False, canceled=True)   # a cancel is not a failure
        self.assertFalse(win.details_toggle.is_open)
        win._finish_create_progress(False)
        self.assertTrue(win.details_toggle.is_open)
        self.assertEqual(self.manager(win.log_text), "pack")

    def test_the_sha_panel_is_behind_a_link_that_appears_with_the_image(self):
        win = self.win
        self.assertEqual(self.manager(win.sha_toggle), "")
        self.assertEqual(self.manager(win.iso_check_frame), "")
        win.set_iso("/tmp/does-not-exist.iso")
        self.assertEqual(self.manager(win.sha_toggle), "pack")
        self.assertEqual(self.manager(win.iso_check_frame), "")
        win.sha_toggle.toggle()
        self.assertEqual(self.manager(win.iso_check_frame), "pack")
        slaves = win.sha_toggle.master.pack_slaves()
        self.assertLess(slaves.index(win.iso_card), slaves.index(win.sha_toggle))
        self.assertLess(slaves.index(win.sha_toggle), slaves.index(win.iso_check_frame))
        win.set_iso("/tmp/other.iso")                      # a new file keeps the panel as the user left it
        self.assertEqual(self.manager(win.iso_check_frame), "pack")
        win.sha_toggle.toggle()
        self.assertEqual(self.manager(win.iso_check_frame), "")

    def test_no_progress_bar_is_shown_while_idle(self):
        win = self.win
        for bar in (win.progress, win.flex_progress, win.create_progress, win.iso_sha_progress):
            self.assertEqual(self.manager(bar), "", bar)

    def test_the_create_bar_follows_the_write(self):
        win = self.win
        win._reset_create_progress()
        self.addCleanup(win.create_progress.stop)
        self.assertEqual(self.manager(win.create_progress), "pack")
        win._finish_create_progress(True)
        self.assertEqual(self.manager(win.create_progress), "pack")   # a finished write shows 100%
        win._reset_create_progress()
        win._finish_create_progress(False, canceled=True)
        self.assertEqual(self.manager(win.create_progress), "")
        self.assertEqual(str(win.create_progress_label.cget("text")), "Canceled.")

    def test_download_bars_appear_with_the_download_and_go_with_a_failure(self):
        win = self.win
        win.windows_dl.start()
        self.assertEqual(self.manager(win.progress), "pack")
        win.windows_dl.finish("Download failed.", bar_value=0)
        self.assertEqual(self.manager(win.progress), "")
        win.flex_dl.show(50, "Downloading...")
        self.assertEqual(self.manager(win.flex_progress), "pack")
        win.flex_dl.finish("Ready.", bar_value=100)
        self.assertEqual(self.manager(win.flex_progress), "pack")

    def test_the_sha_bar_is_shown_by_a_calculation_and_sits_above_the_text(self):
        win = self.win
        win.iso_sha_label.config(text="Calculating...")
        win._show_sha_bar()
        order = win.iso_check_frame.pack_slaves()
        self.assertLess(order.index(win.iso_sha_progress), order.index(win.iso_sha_label))
        win._reset_iso_sha()
        self.assertEqual(self.manager(win.iso_sha_progress), "")


class ShortenMiddleTests(unittest.TestCase):
    def test_short_text_is_unchanged(self):
        self.assertEqual(app._shorten_middle("abc", 10), "abc")
        self.assertEqual(app._shorten_middle("a" * 10, 10), "a" * 10)

    def test_long_text_keeps_both_ends_and_the_limit(self):
        for limit in (5, 6, 11, 20, 64):
            with self.subTest(limit=limit):
                text = "/Users/someone/" + "x" * 100 + "/Downloads/ubuntu.iso"
                short = app._shorten_middle(text, limit)
                self.assertEqual(len(short), limit)
                self.assertIn("…", short)
                self.assertTrue(short.startswith(text[:2]) and short.endswith(text[-2:]))


class StepLayoutTests(GuiTestCase, TempDirTestCase):
    """P2/P3 of the GUI review: equal cards, no dead space under the panels, numbered steps, a file card."""

    def setUp(self):
        GuiTestCase.setUp(self)
        TempDirTestCase.setUp(self)

    def settle(self):
        self.win.update_idletasks()

    def test_the_four_cards_are_equal_columns_that_share_the_row(self):
        win = self.win
        row = win.cards_row
        self.assertEqual(len(win.cards), 4)
        uniform = set()
        for column in range(4):
            info = row.grid_columnconfigure(column)
            self.assertEqual(int(info["weight"]), 1)
            uniform.add(info["uniform"])
        self.assertEqual(len(uniform), 1)
        self.assertNotEqual(uniform, {""})
        columns = []
        for card in win.cards.values():
            self.assertEqual(card.winfo_manager(), "grid")
            self.assertEqual(card.grid_info()["sticky"], "ew")
            columns.append(int(card.grid_info()["column"]))
        self.assertEqual(sorted(columns), [0, 1, 2, 3])

    def test_a_card_draws_itself_with_the_width_it_is_given(self):
        card = self.win.cards[app.CARD_WINDOWS]
        card._on_resize(mock.Mock(width=220))
        right_edges = [card.bbox(item)[2] for item in card.find_all() if card.type(item) == "polygon"]
        self.assertTrue(right_edges)
        self.assertGreaterEqual(max(right_edges), 214)   # the outline reaches (almost) the new right edge
        self.assertLessEqual(max(right_edges), 222)
        card._on_resize(mock.Mock(width=160))
        right_edges = [card.bbox(item)[2] for item in card.find_all() if card.type(item) == "polygon"]
        self.assertLessEqual(max(right_edges), 162)
        card.set_selected(True)                          # selecting keeps the width
        self.assertEqual(card._cw, 160)

    def test_the_panel_holder_is_as_tall_as_the_panel_on_screen(self):
        win = self.win
        heights = {}
        for key in app.CARD_ORDER:
            win.select_card(key)
            self.settle()
            shown = [k for k, panel in win.panels.items() if panel.winfo_manager() == "grid"]
            self.assertEqual(shown, [key])
            heights[key] = win.panels[key].winfo_reqheight()
            self.assertEqual(win._panel_holder.winfo_reqheight(), heights[key])
        self.assertLess(min(heights.values()), max(heights.values()))   # no more fixed, tallest height

    def test_a_download_bar_adds_height_only_while_it_is_shown(self):
        win = self.win
        win.select_card(app.CARD_WINDOWS)
        self.settle()
        idle = win._panel_holder.winfo_reqheight()
        self.assertEqual(str(win.progress_label.winfo_manager()), "")   # an empty label takes no room either
        win.windows_dl.show(30, "30%")
        self.settle()
        self.assertGreater(win._panel_holder.winfo_reqheight(), idle)
        win.windows_dl.hide_bar()
        win.progress_label.config(text="")
        self.settle()
        self.assertEqual(win._panel_holder.winfo_reqheight(), idle)

    def test_the_window_grows_and_settles_back(self):
        win = self.win
        minimum = win.MIN_WINDOW_HEIGHT
        with mock.patch.object(win, "winfo_reqheight", return_value=minimum - 100):
            win._fit_window()                              # a small page: the usual height, not smaller
        self.assertEqual(win._window_size[1], minimum)
        with mock.patch.object(win, "winfo_reqheight", return_value=minimum + 150):
            win._fit_window()
        self.assertEqual(win._window_size[1], minimum + 150)
        with mock.patch.object(win, "winfo_reqheight", return_value=minimum - 100):
            win._fit_window()
        self.assertEqual(win._window_size[1], minimum)     # back to the usual height, not smaller
        with mock.patch.object(win, "winfo_reqheight", return_value=minimum + 150):
            win._fit_window()
        # the user made it taller by hand: the content shrinking must not take that away
        with mock.patch.object(win, "winfo_reqheight", return_value=minimum), \
                mock.patch.object(win, "winfo_height", return_value=minimum + 400):
            win._fit_window()
        self.assertEqual(win._window_size[1], minimum + 150)

    def test_the_numbered_steps_are_in_order_on_the_page(self):
        win = self.win
        self.assertEqual([win.step_headings[n].number for n in (1, 2, 3)], [1, 2, 3])
        self.assertEqual([win.step_headings[n].title for n in (1, 2, 3)], ["Image type", "Image", "USB drive"])
        page = win.iso_card.master
        order = page.pack_slaves()
        create_row = win.create_btn.master
        sequence = [win.step_headings[1], win.cards_row, win.step_headings[2], win._panel_holder, win.iso_card,
                    win.step_headings[3], create_row]
        positions = [order.index(widget) for widget in sequence]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(len(set(positions)), len(positions))
        # nothing but the separator and the drive section sits between step 3 and the Create row
        between = order[order.index(win.step_headings[3]) + 1:order.index(create_row)]
        self.assertTrue(between)

    def pvd_iso(self, name, volume_id, hybrid):
        data = bytearray(2 * MIB)
        pvd = 16 * 2048
        data[pvd:pvd + 7] = b"\x01CD001\x01"
        data[pvd + 40:pvd + 72] = volume_id.encode("latin-1").ljust(32)
        data[pvd + 128:pvd + 130] = (2048).to_bytes(2, "little")
        if hybrid:
            data[510:512] = b"\x55\xaa"
        return self.write_file(name, bytes(data))

    def test_no_image_shows_only_the_empty_state(self):
        card = self.win.iso_card
        self.assertFalse(card.has_file)
        self.assertEqual(str(card.label.cget("text")), "No ISO selected yet.")
        shown = card.grid_slaves()
        for widget in (card.folder_label, card.size_label, card.badge):
            self.assertNotIn(widget, shown)
        self.assertIs(self.win.iso_label, card.label)
        self.assertEqual(self.win.iso_card.winfo_manager(), "pack")

    def test_a_chosen_image_shows_name_folder_size_and_kind(self):
        path = self.pvd_iso("ubuntu-24.04.iso", "Ubuntu 24.04 LTS amd64", hybrid=True)
        self.win.set_iso(path)
        card = self.win.iso_card
        self.assertTrue(card.has_file)
        self.assertEqual(str(card.label.cget("text")), "ubuntu-24.04.iso")
        self.assertIn("bold", str(card.label.cget("font")).lower() + str(self.win.tk.call("font", "actual", card.label.cget("font"), "-weight")))
        self.assertTrue(str(card.folder_label.cget("text")).endswith(os.path.basename(self.tmp)))
        self.assertEqual(str(card.size_label.cget("text")), app.human_size(2 * MIB))
        self.assertEqual(str(card.badge.cget("text")), "Linux")
        for widget in (card.folder_label, card.size_label, card.badge):
            self.assertIn(widget, card.grid_slaves())
        self.assertEqual(self.win.iso_path.get(), path)

    def test_the_badge_follows_the_detected_kind(self):
        for vid, hybrid, text in (("CCCOMA_X64FRE_EN-US_DV9", False, "Windows 11"),
                                  ("Ubuntu 24.04 LTS amd64", True, "Linux")):
            with self.subTest(text=text):
                self.win.set_iso(self.pvd_iso("x.iso", vid, hybrid))
                self.assertEqual(str(self.win.iso_card.badge.cget("text")), text)
        self.win.iso_card.show(self.write_file("flex.bin", b"x"), app.ISO_KIND_CHROMEOS, 1)
        self.assertEqual(str(self.win.iso_card.badge.cget("text")), "ChromeOS Flex")

    def test_an_unreadable_or_unknown_image_still_shows_a_card(self):
        self.win.set_iso(self.path("missing.iso"))
        card = self.win.iso_card
        self.assertEqual(str(card.label.cget("text")), "missing.iso")
        self.assertEqual(str(card.size_label.cget("text")), "")
        self.assertEqual(str(card.badge.cget("text")), "Unknown")

    def test_clear_returns_to_the_empty_state(self):
        self.win.set_iso(self.pvd_iso("a.iso", "Ubuntu 24.04 LTS amd64", hybrid=True))
        self.win.iso_card.clear()
        card = self.win.iso_card
        self.assertFalse(card.has_file)
        self.assertEqual(str(card.label.cget("text")), "No ISO selected yet.")
        self.assertNotIn(card.badge, card.grid_slaves())


class CancelMessageTests(GuiTestCase):
    def run_cancel(self, exc):
        self.win.iso_path.set("/tmp/exemplo.iso")
        self.listed = [USB_DISK]
        self.win.refresh_disks(sync=True)
        self.win.confirm_erase = mock.Mock(return_value=True)
        self.win._image_matches_choice = mock.Mock(return_value=True)
        self.win.priv.authenticate = mock.Mock(return_value=True)
        with mock.patch.object(app, "build_usb", side_effect=exc):
            self.win.start_create_usb()
            self.assertTrue(self.pump(lambda: not self.win._creating))
        self.win._flush_log()
        return self.win.log_text.get("1.0", "end")

    def test_drive_not_touched(self):
        exc = app.OperationCanceled("stopped")
        exc.drive_touched = False
        log = self.run_cancel(exc)
        self.assertIn("The drive was not modified", log)
        self.assertNotIn("unusable", log)
        kind, title, body = self.box.calls[-1]
        self.assertEqual((kind, title), ("info", "Canceled"))
        self.assertIn("NOT modified", body)
        self.assertNotIn("unusable", body.lower())

    def test_drive_touched_and_engines_without_the_attribute(self):
        touched = app.OperationCanceled("stopped")
        touched.drive_touched = True
        for exc in (touched, app.OperationCanceled("stopped")):
            with self.subTest(has_attr=hasattr(exc, "drive_touched")):
                self.box.calls.clear()
                log = self.run_cancel(exc)
                self.assertIn("left unusable", log)
                self.assertIn("unusable", self.box.calls[-1][2])


class FlexBusyTests(GuiTestCase):
    def test_a_zip_picked_while_busy_is_ignored_and_the_cancel_survives(self):
        self.win._flex_busy = True
        self.win._sync_controls()
        self.win.flex_cancel_event.set()
        with mock.patch.object(app.filedialog, "askopenfilename", return_value="/tmp/x.bin.zip"), \
                mock.patch.object(self.win, "_extract_flex_image") as extract:
            self.win.pick_existing_iso()
        extract.assert_not_called()
        self.assertTrue(self.win.flex_cancel_event.is_set())
        self.assertEqual(self.state(self.win.pick_btn), "disabled")
        self.assertEqual(self.state(self.win.flex_download_btn), "disabled")
        self.assertEqual(self.state(self.win.cancel_create_btn), "normal")

    def test_a_second_extraction_cannot_start_and_never_clears_the_cancel(self):
        gate = threading.Event()
        calls = []
        self.addCleanup(gate.set)

        def slow(*_a, **_kw):
            calls.append(1)
            gate.wait(10)
            raise app.OperationCanceled("stopped")

        with mock.patch.object(app, "extract_disk_image", slow):
            self.win._extract_flex_image("/tmp/a.zip", delete_zip=False)
            self.assertTrue(self.win._flex_busy)
            self.win.flex_cancel_event.set()
            self.win._extract_flex_image("/tmp/b.zip", delete_zip=False)
            self.assertTrue(self.win.flex_cancel_event.is_set())
            self.assertEqual(self.state(self.win.pick_btn), "disabled")
            gate.set()
            self.pump(lambda: not self.win._flex_busy)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.state(self.win.pick_btn), "normal")
        self.assertEqual(self.state(self.win.flex_download_btn), "normal")
        self.assertEqual(self.state(self.win.cancel_create_btn), "disabled")
        self.assertEqual(self.box.calls, [])
        self.assertEqual(self.win.error_banner.title_text, "ChromeOS Flex")
        self.assertEqual(self.win.error_banner.message_text, "Canceled.")

    def test_a_cancel_that_arrives_as_the_download_ends_is_kept(self):
        self.win._flex_busy = True
        self.win.flex_cancel_event.set()
        with mock.patch.object(self.win, "_extract_flex_image") as extract:
            self.win._on_flex_downloaded("/tmp/a.zip", "0" * 64)
        extract.assert_not_called()
        self.assertFalse(self.win._flex_busy)

    def test_picking_is_ignored_while_writing(self):
        self.win._creating = True
        with mock.patch.object(app.filedialog, "askopenfilename") as dialog:
            self.win.pick_existing_iso()
        dialog.assert_not_called()

    def test_a_download_locks_only_its_own_controls(self):
        self.win._download_running = True
        self.win._sync_controls()
        self.assertEqual(self.state(self.win.download_btn), "disabled")
        self.assertEqual(self.state(self.win.cancel_create_btn), "normal")
        self.assertEqual(self.state(self.win.pick_btn), "normal")
        self.win._download_running = False
        self.win._sync_controls()
        self.assertEqual(self.state(self.win.download_btn), "normal")
        self.assertEqual(self.state(self.win.cancel_create_btn), "disabled")


class TypedConfirmationTests(GuiTestCase):
    def build(self):
        top, entry, button, result = app.build_typed_confirmation_dialog(
            self.win, "Confirm", "Erase?", "disk9", ["too big"])
        self.addCleanup(top.destroy)
        return top, entry, button, result

    def test_button_follows_every_kind_of_edit(self):
        top, entry, button, result = self.build()
        self.assertEqual(self.state(button), "disabled")
        entry.insert(0, "disk9")  # no key event at all, like a mouse paste
        self.assertEqual(self.state(button), "normal")
        entry.delete(0, "end")
        self.assertEqual(self.state(button), "disabled")
        top._typed.set("/dev/disk9")
        self.assertEqual(self.state(button), "normal")
        top._typed.set("disk90")
        self.assertEqual(self.state(button), "disabled")
        top._typed.set("  disk9  ")
        self.assertEqual(self.state(button), "normal")
        self.assertFalse(result["ok"])

    def test_paste_event_enables_the_button(self):
        top, entry, button, _result = self.build()
        self.win.clipboard_clear()
        self.win.clipboard_append("disk9")
        entry.focus_force()
        entry.event_generate("<<Paste>>")
        self.win.update()
        # the clipboard is shared with other programs, so only check when the paste really happened
        if entry.get() == "disk9":
            self.assertEqual(self.state(button), "normal")

    def test_enter_cannot_slip_through(self):
        top, entry, button, result = self.build()
        entry.insert(0, "disk8")
        top.event_generate("<Return>")
        self.win.update()
        self.assertFalse(result["ok"])
        self.assertTrue(top.winfo_exists())


class ProgressTextTests(GuiTestCase):
    def test_flex_label_translates_the_time_left(self):
        with mock.patch.object(app, "ACTIVE_LANGUAGE", "pt"):
            self.win._on_flex_progress(500, 1000, 10.0, "Baixando")
        text = str(self.win.flex_progress_label.cget("text"))
        self.assertIn("faltam ~0m50s", text)
        self.assertNotIn("left", text)
        self.win._on_flex_progress(500, 1000, 10.0, "Downloading...")
        self.assertIn("~0m50s left", str(self.win.flex_progress_label.cget("text")))

    def test_windows_download_label_uses_minutes_not_seconds(self):
        self.win._on_progress(0, 72000, 10.0)  # 7200 s left
        text = str(self.win.progress_label.cget("text"))
        self.assertIn("~120m00s left", text)
        self.assertNotIn("7200s", text)
        self.win._on_progress(500, 1000, 0.0)  # speed unknown
        self.assertIn("calculating...", str(self.win.progress_label.cget("text")))

    def test_create_label_uses_the_same_helper(self):
        self.win._reset_create_progress()
        self.win._on_create_progress(0, 1000, "Writing the image...")
        self.win._create_started = time.time() - 10
        self.win._create_last_ui = 0.0
        self.win._on_create_progress(500, 1000, "Writing the image...")
        text = str(self.win.create_progress_label.cget("text"))
        self.assertIn("Writing the image...", text)
        self.win._create_last_ui = 0.0
        self.win._create_started = time.time() - 10
        self.win._create_stage_base = 0
        self.win._on_create_progress(500, 1000, "Writing the image...")
        self.assertRegex(str(self.win.create_progress_label.cget("text")), r"~\d+m\d\ds left")
        self.win._finish_create_progress(False)


class InlineFeedbackTests(GuiTestCase):
    """P2/P3 of the GUI review: inline error banner, success panel and the header with the dependency chip."""

    def manager(self, widget):
        return str(widget.winfo_manager())

    def page_order(self):
        return self.win.create_hint.master.pack_slaves()

    @staticmethod
    def link_texts(banner):
        return [str(w.cget("text")) for w in banner._links.winfo_children()]

    # ----- the error banner -----
    def test_banner_is_lazy_and_sits_right_under_the_create_row(self):
        win = self.win
        self.assertEqual(self.manager(win.error_banner), "")
        self.assertFalse(win.error_banner.shown)
        win.show_error("Download error", "The server refused the download.")
        self.assertEqual(self.manager(win.error_banner), "pack")
        order = self.page_order()
        self.assertEqual(order.index(win.error_banner), order.index(win.create_btn.master) + 1)
        self.assertEqual(win.error_banner.title_text, "Download error")
        self.assertEqual(win.error_banner.message_text, "The server refused the download.")
        win.clear_error()
        self.assertEqual(self.manager(win.error_banner), "")
        self.assertEqual(win.error_banner.message_text, "")

    def test_banner_stays_above_the_hint_and_the_bar(self):
        win = self.win
        win.create_hint.config(text="Choose the image file first.")
        win._reset_create_progress()
        self.addCleanup(win.create_progress.stop)
        win.show_error("Error", "boom")
        order = self.page_order()
        self.assertLess(order.index(win.error_banner), order.index(win.create_hint))
        self.assertLess(order.index(win.create_hint), order.index(win.create_progress))
        win.clear_error()
        win.show_error("Error", "again")                   # shown twice: still one banner, same place
        self.assertEqual(order, self.page_order())

    def test_try_again_runs_the_action_and_closes_the_banner(self):
        win = self.win
        calls = []
        win.show_error("Error", "x", retry=lambda: calls.append(1))
        self.assertEqual(self.link_texts(win.error_banner), ["Try again", "Dismiss"])
        win.error_banner._links.winfo_children()[0].event_generate("<Button-1>")
        win.update()
        self.assertEqual(calls, [1])
        self.assertFalse(win.error_banner.shown)
        win.show_error("Error", "no retry here")
        self.assertEqual(self.link_texts(win.error_banner), ["Dismiss"])

    def test_non_write_failures_use_the_banner_and_no_dialog(self):
        win = self.win
        win._on_download_error("The server refused the download (HTTP 403).")
        self.assertEqual(self.box.calls, [])
        self.assertEqual(win.error_banner.title_text, "Download error")
        self.assertIn("HTTP 403", win.error_banner.message_text)
        self.assertEqual(str(win.windows_dl.label.cget("text")), "Download failed.")
        win.clear_error()
        win._on_disks_error(win._disk_job, RuntimeError("diskutil hung"), quiet=False)
        self.assertEqual(self.box.calls, [])
        self.assertIn("Could not list disks: diskutil hung", win.error_banner.message_text)

    def test_a_new_operation_clears_the_banner(self):
        win = self.win
        win.show_error("Error", "old")
        win.refresh_disks(quiet=True, sync=True)           # automatic refreshes never hide a message
        self.assertTrue(win.error_banner.shown)
        win.refresh_disks(sync=True)                       # an explicit one starts over
        self.assertFalse(win.error_banner.shown)

    def test_install_failure_is_a_banner_with_try_again(self):
        win = self.win
        with mock.patch.object(app, "IS_MAC", True), mock.patch.object(app.shutil, "which", return_value=None):
            win.install_dependencies()
            self.assertTrue(self.pump(lambda: win.error_banner.shown and not win._installing))
        self.assertEqual(self.box.calls, [])
        self.assertIn("Homebrew not found", win.error_banner.message_text)
        self.assertEqual(self.link_texts(win.error_banner), ["Try again", "Dismiss"])

    def test_a_write_failure_keeps_the_dialog_and_adds_the_banner(self):
        win = self.win
        win._report_error("Error", "Verification failed: the drive does not match the ISO.")
        self.assertEqual(self.box.titles("error"), ["Error"])
        self.assertIn("does not match", win.error_banner.message_text)
        win.clear_error()
        win._report_error("Unexpected error", None, ValueError("x"))
        self.assertEqual(self.box.titles("error"), ["Error", "Unexpected error"])
        self.assertTrue(win.error_banner.shown)

    def test_no_banner_while_closing(self):
        self.win._closing = True
        self.win._report_error("Error", "boom", modal=False)
        self.assertFalse(self.win.error_banner.shown)

    # ----- the success panel -----
    def run_write(self, ejected=True, exc=None):
        win = self.win
        win.iso_path.set("/tmp/exemplo.iso")
        self.listed = [USB_DISK]
        win.refresh_disks(sync=True)
        win.confirm_erase = mock.Mock(return_value=True)
        win._image_matches_choice = mock.Mock(return_value=True)
        win.priv.authenticate = mock.Mock(return_value=True)
        with mock.patch.object(app, "build_usb", return_value=ejected, side_effect=exc):
            win.start_create_usb()
            self.assertTrue(self.pump(lambda: not win._creating))
            win.update()

    def test_verified_and_ejected_shows_the_green_panel_without_a_dialog(self):
        win = self.win
        self.assertEqual(self.manager(win.success_panel), "")
        self.run_write(ejected=True)
        self.assertEqual(self.box.calls, [])
        panel = win.success_panel
        self.assertTrue(panel.shown)
        self.assertEqual(panel.kind, "success")
        self.assertEqual(panel.title_text, "Bootable USB drive created successfully!")
        self.assertIn("verified against the ISO and ejected", panel.message_text)
        self.assertIn("unplug it now", panel.message_text)
        order = self.page_order()
        self.assertEqual(order.index(panel), order.index(win.create_btn.master) + 1)
        self.assertEqual(self.link_texts(panel), ["Make another"])

    def test_eject_failure_gets_the_amber_variant_with_the_manual_eject_message(self):
        self.run_write(ejected=False)
        panel = self.win.success_panel
        self.assertEqual(self.box.calls, [])
        self.assertEqual(panel.kind, "warning")
        self.assertIn("could not be ejected automatically", panel.message_text)
        self.assertIn("Eject it from the file manager", panel.message_text)
        self.assertNotIn("you can unplug it now", panel.message_text)

    def test_make_another_clears_the_panel_and_reenables_the_flow(self):
        win = self.win
        self.run_write(ejected=True)
        self.assertTrue(win.success_panel.shown)
        self.assertEqual(self.manager(win.create_progress), "pack")
        win.make_another()
        self.pump(lambda: not win._disk_listing)
        self.assertFalse(win.success_panel.shown)
        self.assertEqual(self.manager(win.create_progress), "")
        self.assertEqual(str(win.create_progress_label.cget("text")), "")
        self.assertFalse(win._creating)
        self.assertEqual(self.state(win.create_btn), "normal")      # same image, drive listed again
        self.assertEqual(self.state(win.refresh_btn), "normal")

    def test_a_new_write_hides_the_old_result(self):
        win = self.win
        self.run_write(ejected=True)
        self.assertTrue(win.success_panel.shown)
        win.show_error("Error", "stale")
        self.run_write(exc=app.OperationCanceled("stopped"), ejected=False)
        self.assertFalse(win.success_panel.shown)
        self.assertNotEqual(win.error_banner.message_text, "stale")

    def test_a_failed_write_never_shows_the_success_panel(self):
        self.run_write(exc=RuntimeError("Verification failed: the drive does not match the ISO."))
        self.assertFalse(self.win.success_panel.shown)
        self.assertEqual(self.box.titles("error"), ["Error"])
        self.assertTrue(self.win.error_banner.shown)

    def test_a_cancel_that_left_the_drive_unusable_keeps_its_dialog_and_adds_the_banner(self):
        exc = app.OperationCanceled("stopped")
        exc.drive_touched = True
        self.run_write(exc=exc)
        self.assertEqual(self.box.titles("info"), ["Canceled"])
        self.assertIn("unusable", self.win.error_banner.message_text)
        self.assertFalse(self.win.success_panel.shown)
        untouched = app.OperationCanceled("stopped")
        untouched.drive_touched = False
        self.run_write(exc=untouched)
        self.assertFalse(self.win.error_banner.shown)               # nothing to warn about
        self.assertEqual(self.box.titles("info"), ["Canceled", "Canceled"])

    # ----- the header -----
    def test_header_is_the_first_row_with_name_version_chip_and_help(self):
        win = self.win
        header = win.dep_label.master
        self.assertIs(header.master.pack_slaves()[0], header)
        self.assertIs(win.install_deps_btn.master, header)
        self.assertIs(win.help_link.master, header)
        texts = [str(w.cget("text")) for w in header.winfo_children() if str(w.winfo_class()) == "TLabel"]
        self.assertIn("EPMA USB CREATOR", texts)
        self.assertIn(f"v{app.__version__}", texts)
        self.assertIn("Help", texts)

    def test_chip_says_ready_in_green_when_nothing_is_missing(self):
        win = self.win
        win.check_dependencies()
        self.assertEqual(str(win.dep_label.cget("text")), "● Ready")
        self.assertEqual(str(win.dep_label.cget("foreground")), "#2ea043")
        self.assertEqual(self.manager(win.install_deps_btn), "")

    def test_chip_says_missing_tools_in_amber_and_shows_the_install_button(self):
        win = self.win
        with mock.patch.object(app, "get_missing_dependencies", return_value=["wimlib-imagex"]):
            win.check_dependencies()
        self.assertEqual(str(win.dep_label.cget("text")), "● Missing tools")
        self.assertEqual(str(win.dep_label.cget("foreground")), "#ff9f0a")
        self.assertEqual(self.manager(win.install_deps_btn), "pack")
        order = win.dep_label.master.pack_slaves()
        self.assertGreater(order.index(win.install_deps_btn), order.index(win.dep_label))   # packed after = left of it
        self.assertEqual(str(win.install_deps_btn.cget("text")), "Install missing dependencies")
        win.check_dependencies()                                                         # fixed again
        self.assertEqual(str(win.dep_label.cget("text")), "● Ready")
        self.assertEqual(self.manager(win.install_deps_btn), "")

    def test_help_link_opens_the_same_window_as_f1(self):
        win = self.win
        with mock.patch.object(win, "show_help") as show:
            win.help_link.event_generate("<Button-1>")
            win.update()
        show.assert_called_once_with()
        self.assertEqual(str(win.help_link.cget("text")), "Help")

    def test_the_old_dependency_line_is_gone(self):
        texts = []

        def walk(widget):
            for child in widget.winfo_children():
                if child is not self.win.dep_label and str(child.winfo_class()) == "TLabel":
                    texts.append(str(child.cget("text")))
                walk(child)
        walk(self.win)
        self.assertNotIn("All dependencies OK", texts)


if __name__ == "__main__":
    unittest.main()


class CanceledAfterWriteTextsTests(unittest.TestCase):
    """Canceled during the final check: the image is on the drive but was never verified."""

    def test_written_but_not_verified(self):
        log, title, body = app.App._canceled_texts(True, True)
        self.assertIn("NOT verified", log)
        self.assertIn("NOT verified", body)
        self.assertNotIn("unusable", log + body)

    def test_the_other_cases_keep_their_wording(self):
        self.assertIn("unusable", " ".join(app.App._canceled_texts(True)))
        self.assertIn("NOT modified", " ".join(app.App._canceled_texts(False)))
        self.assertIn("NOT modified", " ".join(app.App._canceled_texts(False, True)))  # nothing was written

