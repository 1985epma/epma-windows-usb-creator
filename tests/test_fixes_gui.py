"""Tests for the GUI review fixes: write lock, dependency gate, close protection, background drive
listing, focus-safe card drawing, image-type detection, hint layout, cancel texts and friends.

The pure-logic tests always run. The tests that need a window are skipped when Tk is missing (the
default python3 on a bare machine) or when no display is available. Nothing here touches a real
device: the drive listing, the message boxes and the engine are replaced.
"""
import io
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
        self.win.disk_combo.event_generate("<<ComboboxSelected>>")
        self.win.update_idletasks()
        self.assertEqual(self.state(self.win.create_btn), "disabled")

    def test_controls_are_locked_during_a_write_and_unlocked_after(self):
        self.with_disk()
        self.win._creating = True
        self.win._sync_controls()
        self.assertEqual(self.state(self.win.disk_combo), "disabled")
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
        self.assertEqual(self.state(self.win.disk_combo), "readonly")
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
        self.assertEqual(self.state(self.win.disk_combo), "readonly")

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
            self.pump(lambda: not self.win._disk_listing and bool(self.box.calls))
        self.assertEqual(self.box.titles("error"), ["Error"])

    def test_sync_mode_lists_on_the_calling_thread(self):
        self.listed = [USB_DISK]
        self.win.refresh_disks(sync=True)
        self.assertEqual(self.list_calls, [threading.main_thread()])
        self.assertEqual(self.win.selected_disk()["id"], "disk9")

    def test_selected_drive_survives_a_refresh(self):
        self.listed = [dict(USB_DISK, id="disk7", label="/dev/disk7"), USB_DISK]
        self.win.refresh_disks(sync=True)
        self.win.disk_combo.current(1)
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
                order = win.iso_check_frame.pack_slaves()
                self.assertLess(order.index(win.iso_sha_progress), order.index(win.iso_sha_label))
                self.assertLess(order.index(win.iso_sha_label), order.index(win.iso_sha_result))


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
        self.assertEqual(self.state(self.win.flex_cancel_btn), "normal")

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
        self.assertEqual(self.state(self.win.flex_cancel_btn), "disabled")
        self.assertEqual(self.box.titles("error"), ["ChromeOS Flex"])

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
        self.assertEqual(self.state(self.win.cancel_btn), "normal")
        self.assertEqual(self.state(self.win.pick_btn), "normal")
        self.win._download_running = False
        self.win._sync_controls()
        self.assertEqual(self.state(self.win.download_btn), "normal")
        self.assertEqual(self.state(self.win.cancel_btn), "disabled")


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

