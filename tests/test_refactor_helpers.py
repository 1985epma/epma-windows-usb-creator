"""Tests for the small helpers that replaced duplicated code (see CHANGELOG / refactor commits).

Like the rest of the suite nothing here touches a real device, uses sudo or the network.
"""
import hashlib
import io
import os
import threading
import unittest
from unittest import mock

from tests.helpers import TempDirTestCase, app


class SilentRemoveTests(TempDirTestCase):
    def test_removes_files_and_ignores_missing_ones(self):
        a = self.write_file("a.txt", b"x")
        b = self.write_file("b.txt", b"y")
        app._silent_remove(a, self.path("missing.txt"), b)
        self.assertFalse(os.path.exists(a))
        self.assertFalse(os.path.exists(b))

    def test_swallows_os_errors_from_remove(self):
        with mock.patch.object(app.os, "remove", side_effect=PermissionError("denied")):
            app._silent_remove("/nonexistent/whatever")  # must not raise

    def test_rmdir_removes_empty_dirs_and_ignores_the_rest(self):
        empty = self.path("empty")
        os.mkdir(empty)
        full = self.path("full")
        os.mkdir(full)
        self.write_file("full/file", b"x")
        app._silent_rmdir(empty, full, self.path("missing"))
        self.assertFalse(os.path.exists(empty))
        self.assertTrue(os.path.isdir(full))  # not empty: left alone, no exception


class Sha256FileTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.data = os.urandom(1_300_000)
        self.blob = self.write_file("blob.bin", self.data)
        self.expected = hashlib.sha256(self.data).hexdigest()

    def test_matches_hashlib(self):
        self.assertEqual(app.sha256_file(self.blob), self.expected)

    def test_empty_file(self):
        empty = self.write_file("empty.bin", b"")
        self.assertEqual(app.sha256_file(empty), hashlib.sha256(b"").hexdigest())

    def test_progress_reports_done_and_total_per_chunk(self):
        seen = []
        digest = app.sha256_file(self.blob, progress=lambda d, t: seen.append((d, t)), chunk=500_000)
        self.assertEqual(digest, self.expected)
        self.assertEqual(seen, [(500_000, 1_300_000), (1_000_000, 1_300_000), (1_300_000, 1_300_000)])

    def test_cancel_event_stops_with_operation_canceled(self):
        event = threading.Event()
        event.set()
        with self.assertRaises(app.OperationCanceled) as ctx:
            app.sha256_file(self.blob, cancel_event=event)
        self.assertFalse(ctx.exception.written)

    def test_missing_file_is_an_oserror(self):
        with self.assertRaises(OSError):
            app.sha256_file(self.blob + ".nope", progress=lambda d, t: None)

    def test_cli_adapter_adds_the_stage_text(self):
        seen = []
        digest = app.cli_sha256_file(self.blob, lambda d, t, s: seen.append((d, t, s)), chunk=700_000)
        self.assertEqual(digest, self.expected)
        self.assertEqual(seen[-1], (1_300_000, 1_300_000, "Computing SHA-256..."))
        self.assertEqual(app.cli_sha256_file(self.blob), self.expected)


class HashStreamTests(unittest.TestCase):
    def test_limit_reads_only_that_many_bytes(self):
        digest = hashlib.sha256()
        fh = io.BytesIO(b"a" * 100)
        self.assertEqual(app._hash_stream(fh, digest, limit=40, chunk=16), 40)
        self.assertEqual(digest.hexdigest(), hashlib.sha256(b"a" * 40).hexdigest())
        self.assertEqual(fh.tell(), 40)

    def test_a_short_stream_returns_fewer_bytes_than_the_limit(self):
        digest = hashlib.sha256()
        self.assertEqual(app._hash_stream(io.BytesIO(b"abc"), digest, limit=10), 3)

    def test_check_runs_before_every_read_and_can_stop_it(self):
        calls = []

        def check():
            calls.append(1)
            if len(calls) == 3:
                raise KeyError("stop")

        with self.assertRaises(KeyError):
            app._hash_stream(io.BytesIO(b"x" * 100), hashlib.sha256(), check=check, chunk=10)
        self.assertEqual(len(calls), 3)


class PartialDownloadHashTests(TempDirTestCase):
    def _thread(self, dest):
        return app.DownloadThread("https://example.invalid/x", dest, None, None, None, threading.Event())

    def test_hash_part_covers_exactly_the_requested_prefix(self):
        part = self.write_file("x.part", b"0123456789" * 5)
        digest = hashlib.sha256()
        self._thread(self.path("x"))._hash_part(part, digest, 25)
        self.assertEqual(digest.hexdigest(), hashlib.sha256((b"0123456789" * 5)[:25]).hexdigest())

    def test_hash_part_rejects_a_file_shorter_than_expected(self):
        part = self.write_file("x.part", b"abc")
        with self.assertRaises(OSError):
            self._thread(self.path("x"))._hash_part(part, hashlib.sha256(), 10)

    def test_hash_part_honours_a_cancel(self):
        part = self.write_file("x.part", b"abc")
        thread = self._thread(self.path("x"))
        thread.cancel_event.set()
        with self.assertRaises(app._DownloadCanceled):
            thread._hash_part(part, hashlib.sha256(), 3)


class SharedRuleTests(TempDirTestCase):
    """Rules the window and the command line used to implement twice."""

    def test_needs_admin_follows_platform_and_mode(self):
        with mock.patch.object(app, "IS_LINUX", True):
            self.assertTrue(all(app.needs_admin(m) for m in app.ALL_MODES))
        with mock.patch.object(app, "IS_LINUX", False):
            self.assertFalse(app.needs_admin(app.MODE_WINDOWS))
            self.assertTrue(app.needs_admin(app.MODE_LINUX))
            self.assertTrue(app.needs_admin(app.MODE_CHROMEOS))

    def test_image_exceeds_drive(self):
        self.assertTrue(app.image_exceeds_drive(9, 8))
        self.assertFalse(app.image_exceeds_drive(8, 8))
        self.assertFalse(app.image_exceeds_drive(7, 8))
        for unknown in (0, None):  # an unknown size is never a reason to refuse
            self.assertFalse(app.image_exceeds_drive(9, unknown))
            self.assertFalse(app.image_exceeds_drive(unknown, 8))

    def test_chromeos_drive_too_small(self):
        small, big = app.CHROMEOS_MIN_USB_BYTES - 1, app.CHROMEOS_MIN_USB_BYTES
        self.assertTrue(app.chromeos_drive_too_small(app.MODE_CHROMEOS, small))
        self.assertFalse(app.chromeos_drive_too_small(app.MODE_CHROMEOS, big))
        self.assertFalse(app.chromeos_drive_too_small(app.MODE_CHROMEOS, 0))  # unknown size
        self.assertFalse(app.chromeos_drive_too_small(app.MODE_LINUX, small))
        self.assertFalse(app.chromeos_drive_too_small(app.MODE_WINDOWS, small))

    def test_normalize_typed_identifier(self):
        for text, expected in (("disk4", "disk4"), ("  /dev/disk4 \n", "disk4"), ("/dev/sdb", "sdb"),
                               ("", ""), (None, ""), ("dev/sdb", "dev/sdb")):
            self.assertEqual(app.normalize_typed_identifier(text), expected)

    def test_is_sha256_hex(self):
        good = "ab" * 32
        self.assertTrue(app.is_sha256_hex(good))
        self.assertTrue(app.is_sha256_hex(good.upper()))
        for bad in (good[:-1], good + "0", good[:-1] + "g", "", " " + good, good + "\n"):
            self.assertFalse(app.is_sha256_hex(bad))

    def test_parse_expected_sha256_still_finds_a_hash_inside_a_line(self):
        good = "cd" * 32
        self.assertEqual(app.parse_expected_sha256(f"{good.upper()} *ubuntu.iso"), good)
        with self.assertRaises(ValueError):
            app.parse_expected_sha256("0" * 65)  # too long: not a SHA-256

    def test_resolve_path_expands_home_and_symlinks(self):
        target = self.write_file("real.iso", b"x")
        link = self.path("link.iso")
        os.symlink(target, link)
        self.assertEqual(app.resolve_path(link), os.path.realpath(target))
        self.assertEqual(app.resolve_path("~"), os.path.realpath(os.path.expanduser("~")))

    def test_has_mbr_signature(self):
        head = bytearray(512)
        self.assertFalse(app.has_mbr_signature(bytes(head)))
        head[510:512] = app.MBR_SIGNATURE
        self.assertTrue(app.has_mbr_signature(bytes(head)))
        self.assertFalse(app.has_mbr_signature(app.MBR_SIGNATURE))  # a short read never counts
        self.assertFalse(app.has_mbr_signature(b""))

    def test_list_disks_turns_a_failure_into_a_cli_error(self):
        with mock.patch.object(app, "get_external_disks", side_effect=OSError("boom")):
            with self.assertRaises(app.CliError) as ctx:
                app._list_disks()
        self.assertEqual(ctx.exception.message, "Could not list the drives: boom")


class ModeTableTests(unittest.TestCase):
    def test_all_modes_is_windows_plus_the_raw_modes(self):
        self.assertEqual(set(app.ALL_MODES), {app.MODE_WINDOWS, *app.RAW_MODES})
        self.assertNotIn(app.MODE_AUTO, app.ALL_MODES)

    def test_every_detectable_kind_maps_to_a_mode_and_a_card_that_agree(self):
        kinds = {app.ISO_KIND_WINDOWS, app.ISO_KIND_LINUX, app.ISO_KIND_CHROMEOS}
        self.assertEqual(set(app.KIND_MODE), kinds)
        self.assertEqual(set(app.KIND_CARD), kinds)
        for kind in kinds:
            self.assertEqual(app.CARD_MODE[app.KIND_CARD[kind]], app.KIND_MODE[kind])
        self.assertNotIn(app.KIND_UNKNOWN, app.KIND_MODE)
        self.assertEqual(app.KIND_UNKNOWN, app.ISO_KIND_UNKNOWN)

    def test_every_card_has_a_mode(self):
        self.assertEqual(set(app.CARD_MODE), set(app.CARD_ORDER))
        self.assertTrue(set(app.CARD_MODE.values()) <= set(app.ALL_MODES))

    def test_cli_mode_choices_come_from_the_table(self):
        parser = app.build_cli_parser()
        write = parser._subparsers._group_actions[0].choices["write"]
        mode_action = next(a for a in write._actions if a.dest == "mode")
        self.assertEqual(list(mode_action.choices), [app.MODE_AUTO, *app.ALL_MODES])


class PackageTableTests(unittest.TestCase):
    def test_map_equals_the_original_per_manager_tables(self):
        base = {"parted": "parted", "mkfs.vfat": "dosfstools", "wipefs": "util-linux",
                "partprobe": "parted", "rsync": "rsync"}
        expected = {
            "apt-get": dict(base, **{"wimlib-imagex": "wimtools"}),
            "dnf": dict(base, **{"wimlib-imagex": "wimlib-utils"}),
            "yum": dict(base, **{"wimlib-imagex": "wimlib-utils"}),
            "pacman": dict(base, **{"wimlib-imagex": "wimlib"}),
            "zypper": dict(base, **{"wimlib-imagex": "wimlib"}),
            "apk": dict(base, wipefs="util-linux-misc", **{"wimlib-imagex": "wimlib"}),
        }
        self.assertEqual(app.LINUX_PKG_MAP, expected)

    def test_every_manager_covers_every_required_tool_with_its_own_dict(self):
        for mgr, table in app.LINUX_PKG_MAP.items():
            self.assertEqual(set(table), set(app.LINUX_REQUIRED_TOOLS), mgr)
        tables = list(app.LINUX_PKG_MAP.values())
        self.assertEqual(len({id(t) for t in tables}), len(tables))  # patching one never changes another

    def test_detection_follows_the_template_order(self):
        self.assertEqual(list(app.LINUX_INSTALL_CMD_TEMPLATE), ["apt-get", "dnf", "yum", "pacman", "zypper", "apk"])
        self.assertEqual(set(app.LINUX_PKG_MAP), set(app.LINUX_INSTALL_CMD_TEMPLATE))
        available = {"dnf", "apk"}
        with mock.patch.object(app.shutil, "which", side_effect=lambda m: "/bin/" + m if m in available else None):
            self.assertEqual(app.linux_detect_pkg_manager(), "dnf")
        with mock.patch.object(app.shutil, "which", return_value=None):
            self.assertIsNone(app.linux_detect_pkg_manager())


class DiskEntryTests(unittest.TestCase):
    def test_entry_has_the_six_fields_and_a_label_built_from_them(self):
        vols = [{"name": "STICK", "filesystem": "FAT32", "size": 1, "used": None, "mountpoint": None}]
        identity = app.make_identity(serial="123", model="Ultra")
        entry = app._disk_entry("disk4", 58 * 1024 ** 3, "SanDisk Ultra", vols, identity)
        self.assertEqual(set(entry), {"id", "size", "label", "model", "volumes", "identity"})
        self.assertEqual(entry["label"], app.build_disk_label("/dev/disk4", "SanDisk Ultra", 58 * 1024 ** 3, vols))
        self.assertTrue(entry["label"].startswith("/dev/disk4 — SanDisk Ultra — 58.0 GB — 1 volume ('STICK')"))
        self.assertIs(entry["volumes"], vols)
        self.assertEqual(entry["identity"], identity)

    def test_unknown_contents_and_no_model(self):
        entry = app._disk_entry("sdb", 8 * 1024 ** 3, "", None, ())
        self.assertEqual(entry["label"], "/dev/sdb — 8.0 GB — contents unknown")
        self.assertIsNone(entry["volumes"])


class EtaTextTests(unittest.TestCase):
    def test_eta_text_minutes_and_seconds(self):
        self.assertEqual(app._eta_text(125, 1.0), "~2m05s left")
        self.assertEqual(app._eta_text(0, 1.0), "~0m00s left")
        self.assertEqual(app._eta_text(3600, 1.0), "~60m00s left")

    def test_eta_text_is_empty_when_nothing_can_be_estimated(self):
        for remaining, speed in ((10, 0), (10, None), (10, -1), (None, 5), (-1, 5), (float("inf"), 5)):
            self.assertEqual(app._eta_text(remaining, speed), "", (remaining, speed))

    def test_translate_flag_picks_the_language(self):
        with mock.patch.object(app, "ACTIVE_LANGUAGE", app.LANG_PT):
            self.assertEqual(app._eta_text(125, 1.0), "faltam ~2m05s")
            self.assertEqual(app._eta_text(125, 1.0, translate=False), "~2m05s left")  # the CLI stays English

    def test_eta_remaining_from_done_total_and_speed(self):
        self.assertEqual(app._eta_remaining(0, 1000, 10.0), "~1m40s left")
        self.assertEqual(app._eta_remaining(1000, 1000, 10.0), "~0m00s left")
        self.assertEqual(app._eta_remaining(0, 1000, 0), "")
        self.assertEqual(app._eta_remaining(0, 1000, None), "")

    def test_rate_tail(self):
        self.assertEqual(app._rate_tail(0, 2 * 1024 ** 2, 1024 ** 2), " — 1.0 MB/s — ~0m02s left")
        self.assertEqual(app._rate_tail(0, 100, 0), "")
        self.assertEqual(app._rate_tail(0, 100, None), "")

    def test_cli_progress_line_uses_the_same_wording(self):
        clock = [0.0]
        progress = app.CliProgress(stream=io.StringIO(), clock=lambda: clock[0])
        progress._text, progress._base, progress._stage_start = "Writing", 0, 0.0
        line = progress._format(1024 ** 2, 3 * 1024 ** 2, "Writing", 2.0)
        self.assertEqual(line, "Writing   33.3%  1.0 MB / 3.0 MB  512.0 KB/s  ~0m04s left")
        with mock.patch.object(app, "ACTIVE_LANGUAGE", app.LANG_PT):
            self.assertTrue(progress._format(1024 ** 2, 3 * 1024 ** 2, "Writing", 2.0).endswith("~0m04s left"))


if __name__ == "__main__":
    unittest.main()
