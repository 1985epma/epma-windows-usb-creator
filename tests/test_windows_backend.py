"""Tests of the Windows backend that run on any system.

Nothing here needs Windows, PowerShell or a drive: the pieces that talk to Windows (PowerShell scripts, DISM,
the raw disk handle) are stood in for, and the pure parts (parsing the drive list, copying and comparing a
file tree, the raw write order, identifier handling) run for real on temp files.
"""
import ast
import json
import os
import re
import threading
import unittest
from unittest import mock

from tests.helpers import MIB, Collector, TempDirTestCase, app


def usb_record(number=3, **over):
    rec = {"Number": number, "Model": "SanDisk Ultra", "Serial": "ABC123", "UniqueId": "USBSTOR\\X", "BusType": "USB",
           "Size": 16 * 1024 ** 3, "SectorSize": 512, "HoldsSystem": False,
           "Volumes": [{"Letter": "E", "Label": "OLD", "FileSystem": "FAT32", "Size": 8 * 1024 ** 3,
                        "Free": 6 * 1024 ** 3}]}
    rec.update(over)
    return rec


class FileDisk:
    """A regular file standing in for \\\\.\\PhysicalDriveN: same read_at / write_at / flush surface."""

    def __init__(self, path, size):
        self.path = path
        with open(path, "wb") as fh:
            fh.truncate(size)
        self.fh = open(path, "r+b")
        self.writes = []
        self.flushed = False

    def write_at(self, offset, data):
        assert offset % app.WINDOWS_RAW_ALIGN == 0 and len(data) % app.WINDOWS_RAW_ALIGN == 0
        self.writes.append((offset, len(data)))
        self.fh.seek(offset)
        self.fh.write(data)

    def read_at(self, offset, length):
        assert offset % app.WINDOWS_RAW_ALIGN == 0 and length % app.WINDOWS_RAW_ALIGN == 0
        self.fh.seek(offset)
        return self.fh.read(length)

    def flush(self):
        self.fh.flush()
        self.flushed = True

    def close(self):
        self.fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class ParseDisksTests(unittest.TestCase):
    def parse(self, *records):
        return app.windows_parse_disks(json.dumps(list(records)))

    def test_a_usb_drive_is_listed_with_model_volumes_and_identity(self):
        (disk,) = self.parse(usb_record())
        self.assertEqual(disk["id"], "PhysicalDrive3")
        self.assertEqual(disk["size"], 16 * 1024 ** 3)
        self.assertEqual(disk["model"], "SanDisk Ultra")
        self.assertEqual(disk["volumes"], [{"name": "OLD", "filesystem": "FAT32", "size": 8 * 1024 ** 3,
                                            "used": 2 * 1024 ** 3, "mountpoint": "E:\\"}])
        self.assertIn(("serial", "ABC123"), disk["identity"])

    def test_only_usb_drives_are_offered(self):
        self.assertEqual(self.parse(usb_record(BusType="SATA"), usb_record(BusType="NVMe"),
                                    usb_record(BusType="File Backed Virtual")), [])

    def test_the_disk_holding_windows_is_never_offered(self):
        self.assertEqual(self.parse(usb_record(HoldsSystem=True)), [])

    def test_an_unknown_system_flag_fails_closed(self):
        rec = usb_record()
        del rec["HoldsSystem"]
        self.assertEqual(self.parse(rec), [])
        self.assertEqual(self.parse(usb_record(HoldsSystem=None)), [])

    def test_empty_card_reader_and_broken_records_are_hidden(self):
        self.assertEqual(self.parse(usb_record(Size=0), {"Number": "x"}, {"BusType": "USB"}), [])

    def test_a_single_object_and_empty_output_are_accepted(self):
        self.assertEqual(len(app.windows_parse_disks(json.dumps(usb_record()))), 1)
        self.assertEqual(app.windows_parse_disks(""), [])
        self.assertEqual(app.windows_parse_disks("[]"), [])

    def test_a_volume_without_a_letter_has_no_mountpoint(self):
        (disk,) = self.parse(usb_record(Volumes=[{"Letter": "", "Label": "", "FileSystem": "", "Size": 100,
                                                  "Free": -1}]))
        self.assertIsNone(disk["volumes"][0]["mountpoint"])
        self.assertIsNone(disk["volumes"][0]["used"])

    def test_an_empty_volume_list_is_no_volumes(self):
        (disk,) = self.parse(usb_record(Volumes=[]))
        self.assertEqual(disk["volumes"], [])


class IdentifierTests(unittest.TestCase):
    def test_windows_identifiers(self):
        with mock.patch.object(app, "IS_WINDOWS", True), mock.patch.object(app, "IS_MAC", False):
            self.assertEqual(app.validate_device_name("PhysicalDrive3"), "PhysicalDrive3")
            for bad in ("disk3", "PhysicalDrive", "PhysicalDrive3\n", "PhysicalDrive3; rm", "../PhysicalDrive3", ""):
                with self.assertRaises(ValueError):
                    app.validate_device_name(bad)
            self.assertEqual(app.dev_path("PhysicalDrive3"), "\\\\.\\PhysicalDrive3")

    def test_typed_forms_all_mean_the_same_drive(self):
        with mock.patch.object(app, "IS_WINDOWS", True):
            for typed in ("3", "disk 3", "Disk3", " 3 ", "PhysicalDrive3", "\\\\.\\PhysicalDrive3", "\\\\.\\3"):
                self.assertEqual(app.normalize_typed_identifier(typed), "PhysicalDrive3", typed)

    def test_other_systems_are_unchanged(self):
        with mock.patch.object(app, "IS_WINDOWS", False):
            self.assertEqual(app.dev_path("sdb"), "/dev/sdb")
            self.assertEqual(app.normalize_typed_identifier("/dev/sdb"), "sdb")
            self.assertEqual(app.normalize_typed_identifier("3"), "3")

    def test_the_disk_number(self):
        with mock.patch.object(app, "IS_WINDOWS", True), mock.patch.object(app, "IS_MAC", False):
            self.assertEqual(app.windows_disk_number("PhysicalDrive12"), 12)


class ScriptShapeTests(unittest.TestCase):
    """The PowerShell scripts are fixed text with typed parameters; values never get pasted in."""

    SCRIPTS = ("WINDOWS_LIST_SCRIPT", "WINDOWS_PREPARE_SCRIPT", "WINDOWS_PREPARE_RAW_SCRIPT",
               "WINDOWS_DETACH_SCRIPT", "WINDOWS_ISO_MOUNT_SCRIPT", "WINDOWS_ISO_DISMOUNT_SCRIPT")

    def test_scripts_are_plain_string_constants(self):
        with open(app.__file__, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        found = {}
        for node in tree.body:
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) \
                    and node.targets[0].id in self.SCRIPTS:
                found[node.targets[0].id] = node.value
        self.assertEqual(sorted(found), sorted(self.SCRIPTS))
        for name, value in found.items():
            self.assertIsInstance(value, ast.Constant, f"{name} must be a literal, not built at run time")

    def test_scripts_that_take_values_declare_typed_parameters(self):
        for name in ("WINDOWS_PREPARE_SCRIPT", "WINDOWS_PREPARE_RAW_SCRIPT", "WINDOWS_DETACH_SCRIPT",
                     "WINDOWS_ISO_MOUNT_SCRIPT", "WINDOWS_ISO_DISMOUNT_SCRIPT"):
            self.assertRegex(getattr(app, name).strip(), r"^param\(\[(int|string|long)\]", name)

    def test_destructive_scripts_check_the_disk_again_before_the_wipe(self):
        for name in ("WINDOWS_PREPARE_SCRIPT", "WINDOWS_PREPARE_RAW_SCRIPT"):
            text = getattr(app, name)
            self.assertIn("-ne 'USB'", text)
            self.assertIn("IsBoot", text)
            self.assertLess(text.index("IsBoot"), text.index("Clear-Disk"))

    def test_scripts_are_ascii(self):
        for name in self.SCRIPTS:
            getattr(app, name).encode("ascii")

    def test_an_argument_that_looks_like_a_parameter_is_refused(self):
        with self.assertRaises(ValueError):
            app.windows_run_ps("param([string]$A)", lambda _l: None, args=["-Command"])

    def test_run_ps_uses_the_absolute_powershell_and_file_mode(self):
        calls = []

        def fake_run(cmd, log, **kw):
            with open(cmd[cmd.index("-File") + 1], encoding="utf-8-sig") as fh:
                calls.append((cmd, kw, fh.read()))
            return 0

        with mock.patch.object(app, "run_cmd", fake_run), mock.patch.dict(os.environ, {"SystemRoot": "C:\\Windows"}):
            app.windows_run_ps("param([int]$N)\nGet-Disk -Number $N", lambda _l: None, args=[3])
        cmd, kw, text = calls[0]
        self.assertTrue(cmd[0].lower().endswith("powershell.exe"))
        self.assertIn("C:\\Windows", cmd[0])
        self.assertEqual(cmd[-1], "3")
        self.assertIn("-NonInteractive", cmd)
        self.assertTrue(text.startswith("$ErrorActionPreference = 'Stop'"))
        self.assertIn("Get-Disk -Number $N", text)
        self.assertFalse(os.path.exists(cmd[cmd.index("-File") + 1]), "the temporary script is removed")


class FormatAndMountTests(unittest.TestCase):
    def test_prepare_fat32_reads_the_drive_letter_and_waits_for_the_root(self):
        lines = ["...", "EPMA_VOLUME e 2"]
        with mock.patch.object(app, "windows_run_collect", return_value=lines) as run, \
                mock.patch.object(app, "windows_wait_for_root", side_effect=lambda letter, _log: f"{letter}:\\"):
            root, part = app.windows_prepare_fat32(3, "WIN11USB", lambda _l: None)
        self.assertEqual((root, part), ("E:\\", 2))
        self.assertEqual(run.call_args.kwargs["args"], [3, "WIN11USB", app.WINDOWS_FAT32_MAX_PARTITION])

    def test_prepare_fat32_without_a_marker_is_an_error(self):
        with mock.patch.object(app, "windows_run_collect", return_value=["nothing useful"]):
            with self.assertRaises(RuntimeError):
                app.windows_prepare_fat32(3, "WIN11USB", lambda _l: None)

    def test_a_marker_with_a_bad_letter_is_refused(self):
        with mock.patch.object(app, "windows_run_collect", return_value=["EPMA_VOLUME ../ 2"]):
            with self.assertRaises(RuntimeError):
                app.windows_prepare_fat32(3, "WIN11USB", lambda _l: None)

    def test_the_fat32_cap_is_below_the_windows_limit(self):
        self.assertLess(app.WINDOWS_FAT32_MAX_PARTITION, 32 * 1024 ** 3)

    def test_eject_reports_the_marker(self):
        with mock.patch.object(app, "windows_run_collect", return_value=["EJECTED"]):
            self.assertTrue(app.windows_eject(3, lambda _l: None))
        with mock.patch.object(app, "windows_run_collect", return_value=["NOT_EJECTED"]):
            self.assertFalse(app.windows_eject(3, lambda _l: None))
        with mock.patch.object(app, "windows_run_collect", side_effect=RuntimeError("boom")):
            self.assertFalse(app.windows_eject(3, lambda _l: None))

    def test_mounted_iso_dismounts_only_what_it_mounted(self):
        with mock.patch.object(app, "windows_run_collect", return_value=["EPMA_ISO f 0"]), \
                mock.patch.object(app, "windows_run_ps") as dismount:
            with app.windows_mounted_iso("C:\\x.iso", lambda _l: None) as root:
                self.assertEqual(root, "F:\\")
            dismount.assert_called_once()
        with mock.patch.object(app, "windows_run_collect", return_value=["EPMA_ISO g 1"]), \
                mock.patch.object(app, "windows_run_ps") as dismount:
            with app.windows_mounted_iso("C:\\x.iso", lambda _l: None):
                pass
            dismount.assert_not_called()

    def test_mounted_iso_dismounts_after_an_error_in_the_block(self):
        with mock.patch.object(app, "windows_run_collect", return_value=["EPMA_ISO f 0"]), \
                mock.patch.object(app, "windows_run_ps") as dismount:
            with self.assertRaises(KeyError):
                with app.windows_mounted_iso("C:\\x.iso", lambda _l: None):
                    raise KeyError("x")
            dismount.assert_called_once()


class TreeCopyTests(TempDirTestCase):
    def make_tree(self):
        self.write_file("src/bootmgr", b"boot" * 100)
        self.write_file("src/Sources/boot.wim", b"B" * 5000)
        self.write_file("src/Sources/install.wim", b"I" * 9000)
        self.write_file("src/efi/boot/bootx64.efi", b"E" * 300)
        return self.path("src"), self.path("dst")

    def test_copy_skips_the_big_file_and_reports_bytes(self):
        src, dst = self.make_tree()
        seen = []
        total = app.copy_tree_with_progress(src, dst, os.path.join("Sources", "install.wim"), seen.append)
        self.assertEqual(total, 400 + 5000 + 300)
        self.assertEqual(seen[-1], total)
        self.assertTrue(os.path.isfile(self.path("dst", "efi", "boot", "bootx64.efi")))
        self.assertFalse(os.path.exists(self.path("dst", "Sources", "install.wim")))

    def test_skip_ignores_letter_case(self):
        src, dst = self.make_tree()
        app.copy_tree_with_progress(src, dst, "sources/INSTALL.WIM", lambda _n: None)
        self.assertFalse(os.path.exists(self.path("dst", "Sources", "install.wim")))

    def test_identical_trees_compare_clean(self):
        src, dst = self.make_tree()
        app.copy_tree_with_progress(src, dst, None, lambda _n: None)
        self.assertEqual(app.compare_trees(src, dst, None), [])

    def test_missing_and_changed_files_are_reported(self):
        src, dst = self.make_tree()
        skip = os.path.join("Sources", "install.wim")
        app.copy_tree_with_progress(src, dst, skip, lambda _n: None)
        os.remove(self.path("dst", "bootmgr"))
        with open(self.path("dst", "Sources", "boot.wim"), "r+b") as fh:
            fh.seek(10)
            fh.write(b"X")
        bad = app.compare_trees(src, dst, skip)
        self.assertEqual(len(bad), 2)
        self.assertTrue(any("bootmgr" in b and "missing" in b for b in bad))
        self.assertTrue(any("boot.wim" in b and "differs" in b for b in bad))

    def test_a_cancel_stops_the_copy(self):
        src, dst = self.make_tree()
        ev = threading.Event()
        ev.set()
        with self.assertRaises(app.OperationCanceled):
            app.copy_tree_with_progress(src, dst, None, lambda _n: None, cancel_event=ev)

    def test_split_parts_are_hashed_by_name(self):
        self.write_file("s/install.swm", b"a")
        self.write_file("s/install2.swm", b"b")
        self.write_file("s/boot.wim", b"c")
        parts = app.hash_split_parts(self.path("s"), "install")
        self.assertEqual(sorted(parts), ["install.swm", "install2.swm"])
        self.assertEqual(parts["install.swm"], app.sha256_file(self.path("s", "install.swm")))


class RawWriteTests(TempDirTestCase):
    def image(self, size):
        return self.make_iso("img.iso", size=size)

    def test_the_head_is_written_last_and_the_content_matches(self):
        iso = self.image(3 * MIB + 1000)  # not a multiple of the sector size: the tail is padded
        disk = FileDisk(self.path("disk.bin"), 8 * MIB)
        app.windows_raw_write(iso, disk, lambda _l: None, block=MIB)
        disk.close()
        offsets = [o for o, _n in disk.writes]
        self.assertEqual(offsets[-1], 0, "the partition tables are written last")
        self.assertEqual(sorted(offsets[:-1]), offsets[:-1])
        self.assertTrue(disk.flushed)
        with open(iso, "rb") as a, open(self.path("disk.bin"), "rb") as b:
            data = a.read()
            self.assertEqual(b.read(len(data)), data)

    def test_a_cancel_before_the_head_leaves_it_unwritten(self):
        iso = self.image(4 * MIB)
        disk = FileDisk(self.path("disk.bin"), 8 * MIB)
        ev = threading.Event()
        calls = {"n": 0}
        real = disk.write_at

        def write_then_cancel(offset, data):
            real(offset, data)
            calls["n"] += 1
            if calls["n"] == 2:
                ev.set()

        disk.write_at = write_then_cancel
        with self.assertRaises(app.OperationCanceled):
            app.windows_raw_write(iso, disk, lambda _l: None, cancel_event=ev, block=MIB)
        disk.close()
        with open(self.path("disk.bin"), "rb") as fh:
            self.assertEqual(fh.read(app.WINDOWS_RAW_HEAD), b"\0" * app.WINDOWS_RAW_HEAD)

    def test_a_small_image_is_written_in_one_piece(self):
        iso = self.image(64 * 1024)
        disk = FileDisk(self.path("disk.bin"), MIB)
        app.windows_raw_write(iso, disk, lambda _l: None)
        disk.close()
        self.assertEqual(disk.writes, [(0, 64 * 1024)])

    def test_verify_passes_on_a_good_write_and_fails_on_a_flipped_byte(self):
        iso = self.image(3 * MIB + 700)
        disk = FileDisk(self.path("disk.bin"), 8 * MIB)
        app.windows_raw_write(iso, disk, lambda _l: None, block=MIB)
        app.windows_raw_verify(iso, disk, lambda _l: None, block=MIB)
        disk.fh.seek(2 * MIB + 5)
        disk.fh.write(b"\xff\xfe")
        with self.assertRaises(RuntimeError) as ctx:
            app.windows_raw_verify(iso, disk, lambda _l: None, block=MIB)
        disk.close()
        self.assertIn("Verification FAILED", str(ctx.exception))
        self.assertIn(str(2 * MIB + 5), str(ctx.exception))

    def test_write_raw_end_to_end_with_a_file_for_a_drive(self):
        iso = self.image(2 * MIB)
        holder = {}

        def opener(number, write=False):
            if "disk" not in holder:  # setdefault would build (and truncate) a new file on every call
                holder["disk"] = FileDisk(self.path("disk.bin"), 4 * MIB)
            disk = holder["disk"]
            disk.close = lambda: None  # the same object is opened for the write and again for the check
            self.addCleanup(disk.fh.close)
            return disk

        log = Collector()
        steps = []
        with mock.patch.object(app, "IS_WINDOWS", True), mock.patch.object(app, "IS_MAC", False), \
                mock.patch.object(app, "open_windows_raw_disk", opener), \
                mock.patch.object(app, "windows_run_collect", side_effect=lambda s, _l, **kw: steps.append(s) or []), \
                mock.patch.object(app, "windows_eject", return_value=True):
            ejected = app.windows_write_raw(iso, "PhysicalDrive3", log, None, None, True)
        self.assertTrue(ejected)
        self.assertEqual(steps, [app.WINDOWS_PREPARE_RAW_SCRIPT])
        self.assertIn("Verification passed", " ".join(log.lines))


class PayloadTests(TempDirTestCase):
    """copy_windows_payload / verify_windows_payload with IS_WINDOWS on: pure Python copy and compare."""

    def make_iso_tree(self, wim_size=4000):
        self.write_file("iso/bootmgr", b"m" * 200)
        self.write_file("iso/sources/boot.wim", b"b" * 3000)
        self.write_file("iso/sources/install.wim", b"w" * wim_size)
        self.write_file("iso/efi/boot/bootx64.efi", b"e" * 100)
        os.makedirs(self.path("usb"))
        return self.path("iso"), self.path("usb")

    def run_payload(self, iso, usb, **kw):
        log = Collector()
        with mock.patch.object(app, "IS_WINDOWS", True):
            app.copy_windows_payload(iso, usb, log, None, "no wimlib", **kw)
        return log

    def test_copy_and_verify_a_small_image(self):
        iso, usb = self.make_iso_tree()
        log = self.run_payload(iso, usb)
        with open(self.path("usb", "sources", "install.wim"), "rb") as fh:
            self.assertEqual(fh.read(), b"w" * 4000)
        self.assertIn("Verification passed", " ".join(log.lines))

    def test_a_changed_file_after_the_copy_fails_the_check(self):
        iso, usb = self.make_iso_tree()

        def reopen():
            with open(self.path("usb", "efi", "boot", "bootx64.efi"), "wb") as fh:
                fh.write(b"corrupt")
            return usb

        with self.assertRaises(RuntimeError) as ctx:
            self.run_payload(iso, usb, reopen=reopen)
        self.assertIn("Verification FAILED", str(ctx.exception))

    def test_a_wim_over_the_fat32_limit_is_split_with_dism_and_checked_after_the_reopen(self):
        iso, usb = self.make_iso_tree(wim_size=5000)
        commands = []

        def fake_dism(cmd, log, **kw):
            commands.append(cmd)
            dst = next(a for a in cmd if a.startswith("/SWMFile:"))[len("/SWMFile:"):]
            with open(dst, "wb") as a, open(dst.replace("install.swm", "install2.swm"), "wb") as b:
                a.write(b"part1")
                b.write(b"part2")
            log("[===== 50.0% =====]")
            return 0

        with mock.patch.object(app, "FAT32_MAX_FILE_SIZE", 4096), mock.patch.object(app, "run_cmd", fake_dism):
            log = self.run_payload(iso, usb)
        self.assertEqual(len(commands), 1)
        self.assertTrue(commands[0][0].lower().endswith("dism.exe"))
        self.assertIn("/Split-Image", commands[0])
        self.assertIn("/FileSize:3800", commands[0])
        self.assertTrue(any("50.0%" in line for line in log.lines))
        self.assertFalse(os.path.exists(self.path("usb", "sources", "install.wim")))
        self.assertIn("Verification passed", " ".join(log.lines))

    def test_a_split_part_changed_by_the_drive_fails_the_check(self):
        iso, usb = self.make_iso_tree(wim_size=5000)

        def fake_dism(cmd, log, **kw):
            dst = next(a for a in cmd if a.startswith("/SWMFile:"))[len("/SWMFile:"):]
            with open(dst, "wb") as a:
                a.write(b"part1")
            return 0

        def reopen():
            with open(self.path("usb", "sources", "install.swm"), "wb") as fh:
                fh.write(b"bitrot")
            return usb

        with mock.patch.object(app, "FAT32_MAX_FILE_SIZE", 4096), mock.patch.object(app, "run_cmd", fake_dism):
            with self.assertRaises(RuntimeError) as ctx:
                self.run_payload(iso, usb, reopen=reopen)
        self.assertIn("split install image", str(ctx.exception))

    def test_an_esd_over_the_limit_needs_wimlib(self):
        iso, usb = self.make_iso_tree(wim_size=10)
        os.rename(self.path("iso", "sources", "install.wim"), self.path("iso", "sources", "install.esd"))
        with open(self.path("iso", "sources", "install.esd"), "wb") as fh:
            fh.write(b"z" * 5000)
        with mock.patch.object(app, "FAT32_MAX_FILE_SIZE", 4096), \
                mock.patch.object(app.shutil, "which", return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                self.run_payload(iso, usb)
        self.assertIn("no wimlib", str(ctx.exception))


class PlatformPiecesTests(unittest.TestCase):
    def test_nothing_is_missing_when_the_windows_tools_exist(self):
        with mock.patch.object(app, "IS_WINDOWS", True), mock.patch.object(app.os.path, "isfile", return_value=True):
            for mode in (app.MODE_WINDOWS, app.MODE_LINUX, app.MODE_CHROMEOS, app.MODE_SEED):
                self.assertEqual(app.get_missing_dependencies(mode), [])

    def test_a_missing_dism_is_reported_for_windows_mode_only(self):
        def isfile(path):
            return "dism" not in path.lower()

        with mock.patch.object(app, "IS_WINDOWS", True), mock.patch.object(app.os.path, "isfile", isfile):
            self.assertEqual(app.get_missing_dependencies(app.MODE_WINDOWS), ["dism.exe"])
            self.assertEqual(app.get_missing_dependencies(app.MODE_LINUX), [])

    def test_admin_is_always_needed_on_windows(self):
        with mock.patch.object(app, "IS_WINDOWS", True):
            for mode in app.ALL_MODES:
                self.assertTrue(app.needs_admin(mode))

    def test_the_privilege_helper_never_prompts(self):
        priv = app.WindowsPrivilege()
        self.assertFalse(priv.needs_password())
        with mock.patch.object(app, "windows_is_admin", return_value=False):
            self.assertFalse(priv.authenticate("x"))
            with self.assertRaises(RuntimeError):
                app.WindowsCliPrivilege().authenticate()
        with mock.patch.object(app, "windows_is_admin", return_value=True):
            self.assertTrue(priv.authenticate("x"))
            self.assertTrue(app.WindowsCliPrivilege().authenticate())
        with self.assertRaises(RuntimeError):
            priv.run_script("x", lambda _l: None)

    def test_not_windows_means_not_admin(self):
        with mock.patch.object(app, "IS_WINDOWS", False):
            self.assertFalse(app.windows_is_admin())

    def test_stop_process_on_windows_does_not_use_process_groups(self):
        proc = mock.Mock()
        proc.wait.return_value = 0
        with mock.patch.object(app, "IS_WINDOWS", True), mock.patch.object(app.os, "killpg", create=True) as killpg:
            app._stop_process(proc, group=True)
        killpg.assert_not_called()
        proc.terminate.assert_called_once()

    def test_the_audit_log_goes_to_local_app_data_on_windows(self):
        with mock.patch.object(app, "IS_WINDOWS", True), \
                mock.patch.dict(os.environ, {"LOCALAPPDATA": "C:\\Users\\a\\AppData\\Local"}, clear=False):
            os.environ.pop(app.ENV_AUDIT_LOG, None)
            path = app.audit_log_path()
        self.assertTrue(path.startswith("C:\\Users\\a\\AppData\\Local"))
        self.assertTrue(path.endswith("audit.log"))

    def test_run_cmd_children_get_no_window_on_windows(self):
        self.assertEqual(app.SUBPROCESS_QUIET == {}, not app.IS_WINDOWS)
        self.assertTrue(re.fullmatch(r"[A-Za-z0-9_]+", "SUBPROCESS_QUIET"))

    def test_the_engine_dispatches_to_the_windows_backend(self):
        iso = os.path.join(os.path.dirname(app.__file__), "README.md")
        calls = []
        with mock.patch.object(app, "IS_WINDOWS", True), mock.patch.object(app, "IS_MAC", False), \
                mock.patch.object(app, "validate_image_for_mode", return_value=iso), \
                mock.patch.object(app, "refuse_hardening_clash"), \
                mock.patch.object(app, "hash_iso_for_audit", return_value="0" * 64), \
                mock.patch.object(app, "reverify_target_disk"), \
                mock.patch.object(app, "windows_build_usb", side_effect=lambda *a, **k: calls.append("win") or True), \
                mock.patch.object(app, "windows_write_raw", side_effect=lambda *a, **k: calls.append("raw") or True):
            app.build_usb(iso, "PhysicalDrive3", lambda _l: None, app.WindowsPrivilege(), mode=app.MODE_WINDOWS)
            app.build_usb(iso, "PhysicalDrive3", lambda _l: None, app.WindowsPrivilege(), mode=app.MODE_LINUX)
        self.assertEqual(calls, ["win", "raw"])


if __name__ == "__main__":
    unittest.main()
