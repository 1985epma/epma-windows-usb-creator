"""Hardening files on a Windows drive (build_usb(..., hardening=HARDENING_BASELINE)).

Nothing here touches a real drive, uses sudo or the network. hardening_files_windows and
validate_seed_files belong to other parts of the feature and are patched with small stand-ins;
a temp folder stands in for the mounted FAT32 volume (on Linux it is mounted with the user's uid/gid, so
the files are written by plain file I/O, no privileged copy); a fake tree stands in for the ISO.
"""
import hashlib
import os
import shutil
import subprocess
import threading
import unittest
import warnings
from unittest import mock

from tests.helpers import Collector, TempDirTestCase, app

OEM = "sources/$OEM$/$$/Setup/Scripts"
FILES = {
    "autounattend.xml": b"<?xml version='1.0'?><unattend/>\n",
    f"{OEM}/SetupComplete.cmd": b"@echo off\r\npowershell -File %~dp0harden.ps1\r\n",
    f"{OEM}/harden.ps1": "# harden éà ".encode() + bytes(range(256)),
}


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def patch_files(files=None, valid=True):
    """Patch the two functions owned by other parts of the feature (create=True: they may not exist yet)."""
    files = dict(FILES if files is None else files)

    def validate(given):
        if not valid:
            raise ValueError("bad seed")
        return dict(given)

    return (mock.patch.object(app, "hardening_files_windows", create=True, side_effect=lambda profile: dict(files)),
            mock.patch.object(app, "validate_seed_files", create=True, side_effect=validate))


class HardeningTestCase(TempDirTestCase):
    def setUp(self):
        super().setUp()
        warn = warnings.catch_warnings()
        warn.__enter__()
        self.addCleanup(warn.__exit__, None, None, None)
        warnings.simplefilter("ignore", ResourceWarning)  # run_cmd leaves the child's pipe to the collector
        for patch in patch_files():
            patch.start()
            self.addCleanup(patch.stop)

    def read(self, root, rel):
        with open(os.path.join(root, *rel.split("/")), "rb") as fh:
            return fh.read()

    def make_iso_tree(self, name="iso", with_unattend=False):
        root = self.path(name)
        files = {
            "bootmgr": b"boot manager",
            "efi/boot/bootx64.efi": os.urandom(3000),
            "sources/boot.wim": os.urandom(9000),
            "sources/install.wim": os.urandom(12000),
        }
        if with_unattend:
            files["autounattend.xml"] = b"<!-- the ISO's own file -->"
        for rel, data in files.items():
            self.write_file(os.path.join(name, rel), data)
        return root, files


class ValidateHardeningTests(unittest.TestCase):
    def test_baseline_is_only_accepted_for_the_windows_type(self):
        app.validate_hardening(app.MODE_WINDOWS, app.HARDENING_BASELINE)
        for mode in (app.MODE_LINUX, app.MODE_CHROMEOS):
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, "only be added to a Windows drive"):
                app.validate_hardening(mode, app.HARDENING_BASELINE)

    def test_none_is_accepted_everywhere(self):
        for mode in app.ALL_MODES:
            app.validate_hardening(mode, app.HARDENING_NONE)

    def test_an_unknown_profile_is_refused(self):
        for profile in ("strict", "", None, "BASELINE"):
            with self.subTest(profile=profile), self.assertRaisesRegex(ValueError, "Unknown hardening profile"):
                app.validate_hardening(app.MODE_WINDOWS, profile)

    def test_build_usb_has_the_documented_default(self):
        import inspect
        self.assertEqual(inspect.signature(app.build_usb).parameters["hardening"].default, app.HARDENING_NONE)


class BuildUsbOrderTests(HardeningTestCase):
    """Everything is validated before the ISO is hashed, the drive re-checked or anything erased."""

    def setUp(self):
        super().setUp()
        self.iso = self.make_iso("Win11.iso", hybrid=False)
        names = {
            "hash": mock.patch.object(app, "hash_iso_for_audit", return_value="0" * 64),
            "reverify": mock.patch.object(app, "reverify_target_disk"),
            "sleep": mock.patch.object(app, "prevent_sleep", return_value=mock.MagicMock()),
            "mac": mock.patch.object(app, "macos_build_usb", return_value=True),
            "linux": mock.patch.object(app, "linux_build_usb", return_value=True),
            "raw_mac": mock.patch.object(app, "macos_write_raw", return_value=True),
            "raw_linux": mock.patch.object(app, "linux_write_raw", return_value=True),
            "clash": mock.patch.object(app, "refuse_hardening_clash"),
            "deps": mock.patch.object(app, "get_missing_dependencies", return_value=[]),
            "audit": mock.patch.object(app, "audit"),
        }
        self.m = {}
        for name, patch in names.items():
            self.m[name] = patch.start()
            self.addCleanup(patch.stop)

    def build(self, mode=app.MODE_WINDOWS, hardening=app.HARDENING_BASELINE, is_mac=True, priv=None, **kw):
        with mock.patch.object(app, "IS_MAC", is_mac):
            return app.build_usb(self.iso, "disk9", Collector(), priv, mode=mode, hardening=hardening, **kw)

    def assert_nothing_started(self):
        for name in ("hash", "reverify", "mac", "linux", "raw_mac", "raw_linux"):
            with self.subTest(step=name):
                self.m[name].assert_not_called()

    def test_raw_modes_with_a_profile_are_refused_first(self):
        for mode in (app.MODE_LINUX, app.MODE_CHROMEOS):
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, "Windows drive"):
                self.build(mode=mode)
            self.assert_nothing_started()

    def test_an_unknown_profile_is_refused_first(self):
        with self.assertRaisesRegex(ValueError, "Unknown hardening profile"):
            self.build(hardening="paranoid")
        self.assert_nothing_started()

    def test_a_bad_seed_never_reaches_the_drive(self):
        for patch in patch_files(valid=False):
            patch.start()  # the later patch wins over the one from setUp
            self.addCleanup(patch.stop)
        with self.assertRaisesRegex(ValueError, "bad seed"):
            self.build()
        self.assert_nothing_started()

    def test_a_profile_without_files_is_refused(self):
        for patch in patch_files(files={}):
            patch.start()
            self.addCleanup(patch.stop)
        with self.assertRaisesRegex(ValueError, "no files to add"):
            self.build()
        self.assert_nothing_started()

    def test_the_files_are_built_and_validated_by_name_at_call_time(self):
        self.build()
        app.hardening_files_windows.assert_called_once_with(app.HARDENING_BASELINE)
        app.validate_seed_files.assert_called_once_with(FILES)

    def test_none_does_not_ask_for_files(self):
        self.build(hardening=app.HARDENING_NONE)
        app.hardening_files_windows.assert_not_called()
        app.validate_seed_files.assert_not_called()

    def test_the_image_is_checked_for_clashes_before_hashing_or_erasing(self):
        order = []
        self.m["clash"].side_effect = lambda *a: order.append("clash")
        self.m["hash"].side_effect = lambda *a: order.append("hash") or "0" * 64
        self.m["reverify"].side_effect = lambda *a, **k: order.append("reverify")
        self.m["mac"].side_effect = lambda *a, **k: order.append("write") or True
        self.build()
        self.assertEqual(order, ["clash", "hash", "reverify", "write"])
        args = self.m["clash"].call_args.args
        self.assertEqual((args[0], args[1]), (self.iso, FILES))

    def test_an_image_that_already_has_a_hardening_file_is_refused_and_nothing_starts(self):
        self.m["clash"].side_effect = ValueError("This Windows image already contains x. Adding ...")
        with self.assertRaisesRegex(ValueError, "already contains x"):
            self.build()
        self.assert_nothing_started()
        self.assertFalse(any("OPERATION START" in c.args[0] for c in self.m["audit"].call_args_list))

    def test_macos_receives_the_validated_files(self):
        self.assertTrue(self.build(is_mac=True))
        self.assertEqual(self.m["mac"].call_args.kwargs["hardening_files"], FILES)
        self.m["linux"].assert_not_called()

    def test_linux_receives_the_validated_files(self):
        self.assertTrue(self.build(is_mac=False))
        self.assertEqual(self.m["linux"].call_args.kwargs["hardening_files"], FILES)
        self.m["mac"].assert_not_called()

    def test_none_calls_the_backends_exactly_as_before(self):
        self.build(hardening=app.HARDENING_NONE, is_mac=True)
        self.assertEqual(self.m["mac"].call_args.args, (self.iso, "disk9", mock.ANY))
        self.assertEqual(set(self.m["mac"].call_args.kwargs), {"progress", "cancel_event", "eject"})
        self.build(hardening=app.HARDENING_NONE, is_mac=False)
        self.assertEqual(len(self.m["linux"].call_args.args), 7)
        self.assertEqual(self.m["linux"].call_args.kwargs, {})

    def start_message(self):
        starts = [c.args[0] for c in self.m["audit"].call_args_list if "OPERATION START" in c.args[0]]
        self.assertEqual(len(starts), 1)
        return starts[0]

    def test_the_audit_start_line_names_the_profile_and_the_files_but_not_their_contents(self):
        self.build()
        line = self.start_message()
        self.assertIn("hardening=baseline", line)
        for rel in FILES:
            self.assertIn(rel, line)
        self.assertNotIn("unattend/", line)
        self.assertNotIn("powershell", line)

    def test_the_audit_start_line_is_unchanged_without_hardening(self):
        self.build(hardening=app.HARDENING_NONE)
        size = os.path.getsize(self.iso)
        self.assertEqual(self.start_message(),
                         f"DESTRUCTIVE OPERATION START: erasing /dev/disk9 and writing windows image "
                         f"(iso sha256={'0' * 64}, size={size})")

    def test_a_canceled_run_is_still_audited_the_same_way(self):
        self.m["mac"].side_effect = app.OperationCanceled("stop")
        with self.assertRaises(app.OperationCanceled):
            self.build()
        self.assertTrue(any("left unusable" in c.args[0] for c in self.m["audit"].call_args_list))


@unittest.skipUnless(shutil.which("rsync"), "rsync not installed")
class BuildUsbWithAnOemImageTests(HardeningTestCase):
    """build_usb end to end (backends faked below the mount) with a fake ISO tree: a clash is refused before
    the drive is touched on both systems; a clean image goes through."""

    def setUp(self):
        super().setUp()
        self.iso = self.make_iso("Win11.iso", hybrid=False)
        self.usb = self.path("usb")
        os.makedirs(self.usb)
        patches = [
            mock.patch.object(app, "hash_iso_for_audit", return_value="0" * 64),
            mock.patch.object(app, "reverify_target_disk"),
            mock.patch.object(app, "prevent_sleep", return_value=mock.MagicMock()),
            mock.patch.object(app, "get_missing_dependencies", return_value=[]),
            mock.patch.object(app, "audit"),
            mock.patch.object(app, "macos_find_mountpoint_by_volname", return_value=self.usb),
            mock.patch.object(app, "macos_eject", return_value=True),
            mock.patch.object(app, "linux_eject", return_value=True),
        ]
        self.audit = None
        for patch in patches:
            started = patch.start()
            self.addCleanup(patch.stop)
            if patch.attribute == "audit":
                self.audit = started

    def drive_is_empty(self):
        return os.listdir(self.usb) == []

    def test_macos_refuses_an_oem_image_before_erasing(self):
        tree, _ = self.make_iso_tree("oem", with_unattend=False)
        self.write_file(os.path.join("oem", *OEM_CMD.split("/")), b"@echo oem")
        run_cmd, calls = fake_run_cmd_for(tree)
        with mock.patch.object(app, "IS_MAC", True), mock.patch.object(app, "run_cmd", run_cmd), \
                self.assertRaisesRegex(ValueError, r"already contains .*SetupComplete\.cmd.*Untick the hardening"):
            app.build_usb(self.iso, "disk9", Collector(), None, hardening=app.HARDENING_BASELINE)
        self.assertFalse(any(c[0] == "diskutil" for c in calls), "the drive must not be touched")
        self.assertTrue(self.drive_is_empty())
        self.assertTrue(any("HARDENING REFUSED" in c.args[0] for c in self.audit.call_args_list))
        self.assertFalse(any("OPERATION START" in c.args[0] for c in self.audit.call_args_list))

    def test_linux_refuses_an_oem_image_before_wiping(self):
        tree, _ = self.make_iso_tree("oem", with_unattend=True)
        priv = RecordingPriv(tree)
        self.addCleanup(priv.cleanup)
        with mock.patch.object(app, "IS_MAC", False), \
                self.assertRaisesRegex(ValueError, "already contains autounattend.xml"):
            app.build_usb(self.iso, "sdb", Collector(), priv, hardening=app.HARDENING_BASELINE)
        self.assertEqual(priv.kinds(), ["peek", "peek-cleanup"])  # no prep script: the drive was never touched
        self.assertFalse(any("OPERATION START" in c.args[0] for c in self.audit.call_args_list))

    def test_a_clean_image_goes_through_on_macos_with_the_files_added(self):
        tree, iso_files = self.make_iso_tree("clean")
        run_cmd, calls = fake_run_cmd_for(tree)
        with mock.patch.object(app, "IS_MAC", True), mock.patch.object(app, "run_cmd", run_cmd):
            self.assertTrue(app.build_usb(self.iso, "disk9", Collector(), None, hardening=app.HARDENING_BASELINE))
        for rel, data in {**iso_files, **FILES}.items():
            self.assertEqual(self.read(self.usb, rel), data)
        attaches = [c for c in calls if c[:2] == ["hdiutil", "attach"]]
        self.assertEqual(len(attaches), 2)  # once to look (before the erase), once to copy
        first_attach = calls.index(attaches[0])
        self.assertTrue(all(c[:2] != ["diskutil", "eraseDisk"] for c in calls[:first_attach]))

    def test_a_clean_image_goes_through_on_linux_with_the_files_added(self):
        tree, iso_files = self.make_iso_tree("clean")
        priv = RecordingPriv(tree)
        self.addCleanup(priv.cleanup)
        with mock.patch.object(app, "IS_MAC", False):
            self.assertTrue(app.build_usb(self.iso, "sdb", Collector(), priv, hardening=app.HARDENING_BASELINE))
        self.assertEqual(priv.kinds(), ["peek", "peek-cleanup", "prep", "remount", "cleanup"])
        for rel, data in {**iso_files, **FILES}.items():
            self.assertEqual(self.read(priv.usb_mount, rel), data)

    def test_without_hardening_nothing_extra_is_mounted(self):
        tree, _ = self.make_iso_tree("clean")
        priv = RecordingPriv(tree)
        self.addCleanup(priv.cleanup)
        with mock.patch.object(app, "IS_MAC", False):
            app.build_usb(self.iso, "sdb", Collector(), priv)
        self.assertEqual(priv.kinds(), ["prep", "remount", "cleanup"])


class WriteHardeningFilesTests(HardeningTestCase):
    def test_every_file_is_written_with_its_exact_bytes(self):
        root = self.path("usb")
        os.makedirs(root)
        app.write_hardening_files(root, FILES)
        for rel, data in FILES.items():
            with self.subTest(rel=rel):
                self.assertEqual(self.read(root, rel), data)

    def test_the_dollar_signs_of_the_oem_path_are_literal(self):
        root = self.path("usb")
        os.makedirs(root)
        app.write_hardening_files(root, FILES)
        self.assertEqual(os.listdir(os.path.join(root, "sources")), ["$OEM$"])
        self.assertEqual(os.listdir(os.path.join(root, "sources", "$OEM$")), ["$$"])
        self.assertEqual(sorted(os.listdir(os.path.join(root, "sources", "$OEM$", "$$", "Setup", "Scripts"))),
                         ["SetupComplete.cmd", "harden.ps1"])

    def test_a_file_of_the_iso_is_replaced(self):
        root = self.path("usb")
        self.write_file("usb/autounattend.xml", b"old")
        app.write_hardening_files(root, FILES)
        self.assertEqual(self.read(root, "autounattend.xml"), FILES["autounattend.xml"])

    def test_unsafe_paths_are_refused_even_if_the_validator_missed_them(self):
        root = self.path("usb")
        os.makedirs(root)
        for rel in ("../evil.txt", "/etc/evil", "a/../../evil", "a\\b", "a//b", "", "./a", "a/\0b"):
            with self.subTest(rel=rel), self.assertRaises(ValueError):
                app.write_hardening_files(root, {rel: b"x"})
        self.assertEqual(os.listdir(root), [])
        self.assertFalse(os.path.exists(self.path("evil.txt")))

    def test_a_symlinked_folder_cannot_lead_outside_the_drive(self):
        root = self.path("usb")
        outside = self.path("outside")
        os.makedirs(root)
        os.makedirs(outside)
        os.symlink(outside, os.path.join(root, "sources"))
        with self.assertRaisesRegex(RuntimeError, "outside the drive"):
            app.write_hardening_files(root, {"sources/x.txt": b"x"})
        self.assertEqual(os.listdir(outside), [])

    def test_a_symlinked_file_is_not_written_through(self):
        root = self.path("usb")
        victim = self.write_file("victim.txt", b"keep")
        os.makedirs(root)
        os.symlink(victim, os.path.join(root, "autounattend.xml"))
        with self.assertRaises(RuntimeError):
            app.write_hardening_files(root, {"autounattend.xml": b"new"})
        self.assertEqual(self.read(self.tmp, "victim.txt"), b"keep")

    def test_a_cancel_stops_between_files(self):
        root = self.path("usb")
        os.makedirs(root)
        event = threading.Event()
        event.set()
        with self.assertRaises(app.OperationCanceled) as ctx:
            app.write_hardening_files(root, FILES, event)
        self.assertTrue(ctx.exception.drive_touched)
        self.assertFalse(ctx.exception.written)
        self.assertEqual(os.listdir(root), [])


class VerifyHardeningFilesTests(HardeningTestCase):
    def setUp(self):
        super().setUp()
        self.root = self.path("usb")
        os.makedirs(self.root)
        app.write_hardening_files(self.root, FILES)

    def verify(self):
        log = Collector()
        app.verify_hardening_files(self.root, FILES, log)
        return log

    def test_identical_files_pass(self):
        self.assertTrue(any("verified" in line for line in self.verify().lines))

    def test_one_flipped_byte_fails(self):
        rel = f"{OEM}/harden.ps1"
        path = os.path.join(self.root, *rel.split("/"))
        with open(path, "r+b") as fh:
            fh.seek(100)
            byte = fh.read(1)
            fh.seek(100)
            fh.write(bytes([byte[0] ^ 0xFF]))
        with self.assertRaisesRegex(RuntimeError, "Verification FAILED.*harden.ps1") as ctx:
            self.verify()
        self.assertIn("NOT ejected", str(ctx.exception))

    def test_a_missing_file_fails(self):
        os.remove(os.path.join(self.root, "autounattend.xml"))
        with self.assertRaisesRegex(RuntimeError, r"Verification FAILED.*autounattend.xml \(missing\)"):
            self.verify()

    def test_a_longer_file_fails(self):
        with open(os.path.join(self.root, "autounattend.xml"), "ab") as fh:
            fh.write(b"x")
        with self.assertRaisesRegex(RuntimeError, "Verification FAILED"):
            self.verify()

    def test_a_truncated_file_fails(self):
        with open(os.path.join(self.root, "autounattend.xml"), "r+b") as fh:
            fh.truncate(3)
        with self.assertRaisesRegex(RuntimeError, "Verification FAILED"):
            self.verify()

    def test_a_cancel_is_a_cancel_not_a_failure(self):
        event = threading.Event()
        event.set()
        with self.assertRaises(app.OperationCanceled):
            app.verify_hardening_files(self.root, FILES, Collector(), event)


@unittest.skipUnless(shutil.which("rsync"), "rsync not installed")
class CopyWindowsPayloadWithExtrasTests(HardeningTestCase):
    def copy(self, src, dst, files=FILES):
        log, progress = Collector(), Collector()
        app.copy_windows_payload(src, dst, log, progress, "wimlib hint", extra_files=files)
        return log, progress

    def test_the_extras_are_added_and_verified_next_to_the_iso_files(self):
        src, iso_files = self.make_iso_tree()
        dst = self.path("usb")
        os.makedirs(dst)
        log, progress = self.copy(src, dst)
        for rel, data in {**iso_files, **FILES}.items():
            with self.subTest(rel=rel):
                self.assertEqual(self.read(dst, rel), data)
        self.assertTrue(any(line == "Adding hardening files..." for line in log.lines))
        self.assertTrue(any(c[2] == "Adding hardening files..." for c in progress.calls if len(c) == 3))
        self.assertTrue(any("Hardening files verified" in line for line in log.lines))
        self.assertTrue(any("Verification passed" in line for line in log.lines))

    def test_an_iso_that_already_has_one_of_the_files_is_refused_before_anything_is_copied(self):
        src, _ = self.make_iso_tree(with_unattend=True)
        dst = self.path("usb")
        os.makedirs(dst)
        with mock.patch.object(app, "audit") as audit, \
                self.assertRaisesRegex(ValueError, "already contains autounattend.xml"):
            self.copy(src, dst)
        self.assertEqual(os.listdir(dst), [])  # not even the ISO's own files were copied
        self.assertTrue(any("HARDENING REFUSED" in c.args[0] for c in audit.call_args_list))

    def test_the_verification_has_no_exemption_for_a_replaced_iso_file(self):
        # Even if a clash slipped past the checks, the byte comparison against the ISO must flag it.
        src, _ = self.make_iso_tree(with_unattend=True)
        dst = self.path("usb")
        os.makedirs(dst)
        with mock.patch.object(app, "check_image_for_hardening_clash"), \
                self.assertRaisesRegex(RuntimeError, "Verification FAILED.*autounattend.xml"):
            self.copy(src, dst)

    def test_a_flipped_byte_in_an_extra_file_is_a_verification_failure(self):
        src, _ = self.make_iso_tree()
        dst = self.path("usb")
        os.makedirs(dst)

        real_write = app.write_hardening_files

        def write_then_flip(root, files, cancel_event=None):
            real_write(root, files, cancel_event)
            path = os.path.join(root, "autounattend.xml")
            with open(path, "r+b") as fh:
                fh.seek(5)
                byte = fh.read(1)
                fh.seek(5)
                fh.write(bytes([byte[0] ^ 0x01]))

        with mock.patch.object(app, "write_hardening_files", write_then_flip), \
                self.assertRaisesRegex(RuntimeError, "Verification FAILED.*autounattend.xml"):
            self.copy(src, dst)

    def test_the_iso_files_are_still_checked_when_extras_are_present(self):
        src, _ = self.make_iso_tree()
        dst = self.path("usb")
        os.makedirs(dst)

        real_write = app.write_hardening_files

        def write_and_damage(root, files, cancel_event=None):
            real_write(root, files, cancel_event)
            with open(os.path.join(root, "bootmgr"), "r+b") as fh:
                fh.write(b"\xff")

        with mock.patch.object(app, "write_hardening_files", write_and_damage), \
                self.assertRaisesRegex(RuntimeError, "Verification FAILED"):
            self.copy(src, dst)

    def test_a_cancel_while_adding_leaves_an_unverified_incomplete_drive(self):
        src, _ = self.make_iso_tree()
        dst = self.path("usb")
        os.makedirs(dst)
        event = threading.Event()

        real_write = app.write_hardening_files

        def cancel(root, files, cancel_event=None):
            event.set()
            real_write(root, files, cancel_event)

        with mock.patch.object(app, "write_hardening_files", cancel), \
                self.assertRaises(app.OperationCanceled) as ctx:
            app.copy_windows_payload(src, dst, Collector(), None, "hint", cancel_event=event,
                                     extra_files=FILES)
        self.assertTrue(ctx.exception.drive_touched)
        self.assertFalse(ctx.exception.written)

    def test_without_extras_nothing_changes(self):
        src, iso_files = self.make_iso_tree()
        dst = self.path("usb")
        os.makedirs(dst)
        log = Collector()
        app.copy_windows_payload(src, dst, log, None, "hint")
        self.assertEqual(sorted(os.listdir(dst)), sorted({r.split("/")[0] for r in iso_files}))
        self.assertFalse(any("hardening" in line.lower() for line in log.lines))


def fake_run_cmd_for(tree):
    """A run_cmd that fakes diskutil/hdiutil and really runs rsync and sync."""
    real = app.run_cmd
    calls = []

    def run_cmd(args, log, check=True, timeout=None, cancel_event=None):
        calls.append(list(args))
        if args[0] in ("rsync", "sync"):
            return real(args, log, check=check, timeout=timeout, cancel_event=cancel_event)
        if args[:2] == ["hdiutil", "attach"]:
            shutil.copytree(tree, args[args.index("-mountpoint") + 1], dirs_exist_ok=True)
        elif args[:2] == ["hdiutil", "detach"]:
            shutil.rmtree(args[2], ignore_errors=True)
        return 0

    return run_cmd, calls


@unittest.skipUnless(shutil.which("rsync"), "rsync not installed")
class MacosBuildUsbTests(HardeningTestCase):
    def setUp(self):
        super().setUp()
        self.tree, self.iso_files = self.make_iso_tree()
        self.usb = self.path("usb")
        os.makedirs(self.usb)
        self.run_cmd, self.calls = fake_run_cmd_for(self.tree)
        for patch in (mock.patch.object(app, "run_cmd", self.run_cmd),
                      mock.patch.object(app, "macos_find_mountpoint_by_volname", return_value=self.usb),
                      mock.patch.object(app, "audit")):
            patch.start()
            self.addCleanup(patch.stop)

    def build(self, **kw):
        log = Collector()
        ejected = app.macos_build_usb("/x/Win11.iso", "disk9", log, **kw)
        return ejected, log

    def test_the_files_are_on_the_volume_with_exact_bytes_and_verified_before_the_eject(self):
        ejected, log = self.build(hardening_files=FILES)
        self.assertTrue(ejected)
        for rel, data in {**self.iso_files, **FILES}.items():
            with self.subTest(rel=rel):
                self.assertEqual(self.read(self.usb, rel), data)
        text = "\n".join(log.lines)
        self.assertLess(text.index("Adding hardening files..."), text.index("Hardening files verified"))
        self.assertLess(text.index("Hardening files verified"), text.index("Ejecting"))
        self.assertTrue(os.path.isdir(os.path.join(self.usb, "sources", "$OEM$", "$$")))
        # No shell is involved: nothing but the usual disk tools was run.
        self.assertEqual({c[0] for c in self.calls}, {"diskutil", "hdiutil", "rsync", "sync"})

    def test_without_hardening_the_volume_holds_only_the_iso(self):
        self.build()
        self.assertEqual(sorted(os.listdir(self.usb)), ["bootmgr", "efi", "sources"])
        self.assertEqual(os.listdir(os.path.join(self.usb, "sources")).count("$OEM$"), 0)

    def test_a_cancel_while_adding_unmounts_and_reports_an_incomplete_drive(self):
        event = threading.Event()
        real_write = app.write_hardening_files

        def cancel_then_write(root, files, cancel_event=None):
            event.set()
            real_write(root, files, cancel_event)

        with mock.patch.object(app, "write_hardening_files", cancel_then_write), \
                self.assertRaises(app.OperationCanceled) as ctx:
            self.build(hardening_files=FILES, cancel_event=event)
        self.assertTrue(ctx.exception.drive_touched)
        self.assertFalse(ctx.exception.written)
        self.assertTrue(any(c[:2] == ["diskutil", "unmountDisk"] for c in self.calls))
        self.assertFalse(any(c[:2] == ["diskutil", "eject"] for c in self.calls))
        self.assertFalse(os.path.exists(os.path.join(self.usb, "autounattend.xml")))

    def test_a_write_error_does_not_eject(self):
        with mock.patch.object(app, "write_hardening_files", side_effect=OSError("disk full")), \
                self.assertRaises(OSError):
            self.build(hardening_files=FILES)
        self.assertFalse(any(c[:2] == ["diskutil", "eject"] for c in self.calls))

    def test_no_privileges_are_needed_for_windows_mode(self):
        with mock.patch.object(app, "IS_LINUX", False):
            self.assertFalse(app.needs_admin(app.MODE_WINDOWS))
            self.assertTrue(app.needs_admin(app.MODE_LINUX))


class RecordingPriv:
    """Fakes the privileged scripts: "mounts" (copies) the ISO tree and the empty drive folder, records every call."""

    cached_password = None

    def __init__(self, tree, flip=None, fail_on=None):
        self.tree = tree
        self.flip = flip
        self.fail_on = fail_on
        self.scripts = []
        self.mounts = []

    def cleanup(self):
        for folder in self.mounts:
            shutil.rmtree(folder, ignore_errors=True)

    def run_script(self, script, log, args=None, **_kw):
        args = [str(a) for a in (args or [])]
        self.scripts.append((script, args))
        if self.fail_on is script:
            raise RuntimeError("Privileged command failed")
        if script is app.LINUX_ISO_PEEK_SCRIPT:
            shutil.copytree(self.tree, args[1], dirs_exist_ok=True)
            self.mounts.append(args[1])
        elif len(args) == 6:  # the prep script: "mount" the ISO and the (empty) drive
            shutil.copytree(self.tree, args[3], dirs_exist_ok=True)
            self.usb_mount = args[4]
            self.mounts += [args[3], args[4]]
        elif script.startswith("set -eu\nsync\numount"):  # the read-only remount before the read-back
            if self.flip:
                path = os.path.join(self.usb_mount, *self.flip.split("/"))
                with open(path, "r+b") as fh:
                    first = fh.read(1)
                    fh.seek(0)
                    fh.write(bytes([first[0] ^ 0xFF]))

    def kinds(self):
        names = {id(app.LINUX_ISO_PEEK_SCRIPT): "peek", id(app.LINUX_ISO_PEEK_CLEANUP_SCRIPT): "peek-cleanup"}
        return [names.get(id(s)) or ("remount" if s.startswith("set -eu\nsync\numount")
                                     else "cleanup" if s.startswith("set -eu\numount")
                                     else "prep") for s, _ in self.scripts]


@unittest.skipUnless(shutil.which("rsync"), "rsync not installed")
class LinuxBuildUsbTests(HardeningTestCase):
    def setUp(self):
        super().setUp()
        self.tree, self.iso_files = self.make_iso_tree()
        patch = mock.patch.object(app, "audit")
        patch.start()
        self.addCleanup(patch.stop)

    def build(self, priv, **kw):
        log = Collector()
        self.addCleanup(priv.cleanup)  # the fake priv never unmounts: its mount folders hold copies
        app.linux_build_usb("/x/Win11.iso", "sdb", log, priv, eject=False, **kw)
        return log

    def test_the_files_are_written_by_plain_file_io_on_the_user_owned_mount_and_read_back(self):
        priv = RecordingPriv(self.tree)
        log = self.build(priv, hardening_files=FILES)
        # No privileged copy any more: the drive is mounted with the user's uid/gid (see the prep script),
        # so the only root scripts are the three the plain Windows flow already ran.
        self.assertEqual(priv.kinds(), ["prep", "remount", "cleanup"])
        self.assertFalse(hasattr(app, "HARDENING_COPY_SCRIPT"))
        self.assertFalse(hasattr(app, "copy_hardening_stage"))
        self.assertFalse(hasattr(app, "stage_hardening_files"))
        self.assertIn('uid="${OWNER%%:*}",gid="${OWNER##*:}" "$PART" "$USB_MNT"', priv.scripts[0][0])
        for rel, data in {**self.iso_files, **FILES}.items():
            with self.subTest(rel=rel):
                self.assertEqual(self.read(priv.usb_mount, rel), data)
        self.assertIn("Adding hardening files...", log.lines)
        self.assertTrue(any("Hardening files verified" in line for line in log.lines))

    def test_the_files_are_added_before_the_remount_so_the_read_back_covers_them(self):
        priv = RecordingPriv(self.tree)
        events = []
        real = app.write_hardening_files

        def spy(root, files, cancel_event=None):
            events.append(len(priv.scripts))  # how many scripts had run when the files were written
            real(root, files, cancel_event)

        with mock.patch.object(app, "write_hardening_files", spy):
            self.build(priv, hardening_files=FILES)
        self.assertEqual(events, [1])  # after the prep script, before the remount
        self.assertEqual(priv.kinds()[:2], ["prep", "remount"])

    def test_a_flipped_byte_found_after_the_remount_fails_the_verification(self):
        priv = RecordingPriv(self.tree, flip="autounattend.xml")
        with self.assertRaisesRegex(RuntimeError, "Verification FAILED.*autounattend.xml"):
            self.build(priv, hardening_files=FILES)
        self.assertTrue(priv.scripts[-1][0].startswith("set -eu\numount"))  # the cleanup still ran

    def test_a_cancel_while_formatting_is_a_cancel_and_cleans_up(self):
        event = threading.Event()

        class CancelOnPrep(RecordingPriv):
            def run_script(self, script, log, args=None, **kw):
                if script.startswith("set -eu\nDEV="):
                    event.set()  # the user clicks Cancel while the drive is being formatted
                return super().run_script(script, log, args, **kw)

        priv = CancelOnPrep(self.tree)
        with self.assertRaises(app.OperationCanceled) as ctx:
            self.build(priv, hardening_files=FILES, cancel_event=event)
        self.assertTrue(ctx.exception.drive_touched)
        self.assertEqual(priv.kinds(), ["prep", "cleanup"])

    def test_without_hardening_only_the_existing_scripts_run(self):
        priv = RecordingPriv(self.tree)
        self.build(priv)
        self.assertEqual(priv.kinds(), ["prep", "remount", "cleanup"])

    def test_the_existing_scripts_are_byte_identical(self):
        priv = RecordingPriv(self.tree)
        self.build(priv)
        prep, remount, cleanup = (s for s, _ in priv.scripts)
        self.assertEqual(sha(prep), EXPECTED["prep"])
        self.assertEqual(sha(remount), EXPECTED["remount"])
        self.assertEqual(sha(cleanup), EXPECTED["cleanup"])
        self.assertEqual(sha(app.MACOS_RAW_SCRIPT), EXPECTED["macos_raw"])
        self.assertEqual(sha(app.LINUX_RAW_SCRIPT), EXPECTED["linux_raw"])
        self.assertEqual(sha(app.VERIFY_RAW_SCRIPT), EXPECTED["verify_raw"])
        self.assertEqual(prep.count(app.VOL_NAME), 1)

    def test_an_image_with_a_clash_that_got_this_far_stops_before_anything_is_written(self):
        # Defence in depth: build_usb refuses such an image before the drive is touched; if one ever got here,
        # copy_windows_payload refuses before a single byte is copied or any hardening file is written.
        tree, _ = self.make_iso_tree("iso2", with_unattend=True)
        priv = RecordingPriv(tree)
        with mock.patch.object(app, "run_cmd") as run_cmd, mock.patch.object(app, "write_hardening_files") as write, \
                self.assertRaisesRegex(ValueError, "already contains autounattend.xml"):
            self.build(priv, hardening_files=FILES)
        run_cmd.assert_not_called()  # no rsync, no sync: not a byte was copied
        write.assert_not_called()
        self.assertTrue(priv.scripts[-1][0].startswith("set -eu\numount"))


# SHA-256 of the scripts as they were before the hardening feature (see test_the_existing_scripts_are_byte_identical).
EXPECTED = {
    "prep": "2fe84953fae7ab72da1faac2dd1ecd5a2c4ab6e43e081e92cc00e8301cc978e1",
    "remount": "8b1af16122857c13763d3ffc45d0eb3090b8011491cc0d74cf04ee5210b89fef",
    "cleanup": "19e8a5a771a7c18a04ce5b2169643d4dde6bb55c452fadd74af409d5035d6935",
    "macos_raw": "ed23ca677a6af8e6a30adbb326ce4a4018206f36044ad1fa0dbb2e491a6283f7",
    "linux_raw": "c2bb23050148228cc18ed4433f162e49870cdc0640ecf7629dc53833f9ac9750",
    "verify_raw": "41f2378a9194c4218dac1b5ceaac97ab7893a0a0c94302a3a7676da1e3062902",
}

OEM_CMD = "sources/$oem$/$$/Setup/Scripts/SETUPCOMPLETE.CMD"  # an OEM image's own file, spelled differently


class FindHardeningClashesTests(HardeningTestCase):
    def test_a_clean_tree_has_no_clash(self):
        root, _ = self.make_iso_tree()
        self.assertEqual(app.find_hardening_clashes(root, FILES), [])

    def test_an_exact_match_is_found(self):
        root, _ = self.make_iso_tree(with_unattend=True)
        self.assertEqual(app.find_hardening_clashes(root, FILES), ["autounattend.xml"])

    def test_the_match_ignores_case_in_every_folder_and_in_the_file_name(self):
        root, _ = self.make_iso_tree()
        self.write_file(os.path.join("iso", *OEM_CMD.split("/")), b"@echo oem")
        # reported with the spelling of the hardening file, not of the image
        self.assertEqual(app.find_hardening_clashes(root, FILES), [f"{OEM}/SetupComplete.cmd"])

    def test_every_folder_of_the_path_is_matched_ignoring_case_even_the_first(self):
        root = self.path("bare")
        self.write_file("bare/SOURCES/$Oem$/$$/SETUP/scripts/setupcomplete.CMD", b"@echo oem")
        self.assertEqual(app.find_hardening_clashes(root, FILES), [f"{OEM}/SetupComplete.cmd"])

    def test_an_existing_folder_alone_is_not_a_clash(self):
        root, _ = self.make_iso_tree()
        os.makedirs(os.path.join(root, "sources", "$OEM$", "$$", "Setup", "Scripts"))
        self.assertEqual(app.find_hardening_clashes(root, FILES), [])

    def test_several_clashes_are_all_reported_sorted(self):
        root, _ = self.make_iso_tree(with_unattend=True)
        self.write_file("iso/sources/$OEM$/$$/Setup/Scripts/harden.ps1", b"x")
        self.assertEqual(app.find_hardening_clashes(root, FILES), ["autounattend.xml", f"{OEM}/harden.ps1"])

    def test_a_file_where_a_folder_is_expected_is_no_crash_and_no_clash(self):
        root, _ = self.make_iso_tree()
        self.write_file("iso/sources/$OEM$", b"a file, not a folder")
        self.assertEqual(app.find_hardening_clashes(root, FILES), [])

    def test_no_names_are_hardcoded(self):
        root, _ = self.make_iso_tree()
        self.write_file("iso/other/thing.txt", b"x")
        self.assertEqual(app.find_hardening_clashes(root, {"other/Thing.TXT": b"y"}), ["other/Thing.TXT"])

    def test_the_refusal_names_the_files_and_is_audited(self):
        root, _ = self.make_iso_tree(with_unattend=True)
        with mock.patch.object(app, "audit") as audit, self.assertRaises(ValueError) as ctx:
            app.check_image_for_hardening_clash(root, FILES)
        self.assertEqual(str(ctx.exception),
                         "This Windows image already contains autounattend.xml. Adding the hardening files "
                         "would replace them, so nothing was changed. Untick the hardening option or use "
                         "another image.")
        self.assertIn("HARDENING REFUSED", audit.call_args.args[0])
        self.assertIn("autounattend.xml", audit.call_args.args[0])

    def test_a_clean_tree_is_not_audited(self):
        root, _ = self.make_iso_tree()
        with mock.patch.object(app, "audit") as audit:
            app.check_image_for_hardening_clash(root, FILES)
        audit.assert_not_called()


class RefuseHardeningClashTests(HardeningTestCase):
    """refuse_hardening_clash on both systems, against a fake ISO tree (nothing is mounted for real)."""

    def setUp(self):
        super().setUp()
        patch = mock.patch.object(app, "audit")
        self.audit = patch.start()
        self.addCleanup(patch.stop)
        self.calls = []

    def tree(self, clash=False):
        root, _ = self.make_iso_tree("isotree")
        if clash:
            self.write_file(os.path.join("isotree", *OEM_CMD.split("/")), b"@echo oem")
        return root

    def run_mac(self, root, files=FILES, attach_error=None):
        fake, self.calls = fake_run_cmd_for(root)

        def run_cmd(args, *a, **k):
            if attach_error and args[:2] == ["hdiutil", "attach"]:
                self.calls.append(list(args))
                raise attach_error
            return fake(args, *a, **k)

        with mock.patch.object(app, "IS_MAC", True), mock.patch.object(app, "run_cmd", run_cmd):
            app.refuse_hardening_clash("/x/Win11.iso", files, Collector(), None)

    def hdiutil_calls(self):
        return [c[:2] for c in self.calls if c[0] == "hdiutil"]

    def peek_dirs(self):
        return sorted(n for n in os.listdir(app.tempfile.gettempdir()) if n.startswith("win11peek_"))

    def test_macos_reads_the_iso_read_only_and_detaches_it(self):
        before = self.peek_dirs()
        self.run_mac(self.tree())
        attach = [c for c in self.calls if c[:2] == ["hdiutil", "attach"]][0]
        self.assertEqual(attach[2], "/x/Win11.iso")
        self.assertIn("-readonly", attach)
        self.assertIn("-nobrowse", attach)
        self.assertEqual(self.hdiutil_calls(), [["hdiutil", "attach"], ["hdiutil", "detach"]])
        self.assertEqual(self.peek_dirs(), before)
        self.audit.assert_not_called()

    def test_macos_refuses_an_image_that_has_the_file_and_still_detaches(self):
        before = self.peek_dirs()
        with self.assertRaisesRegex(ValueError, r"already contains .*SetupComplete\.cmd.*nothing was changed"):
            self.run_mac(self.tree(clash=True))
        self.assertEqual(self.hdiutil_calls(), [["hdiutil", "attach"], ["hdiutil", "detach"]])
        self.assertEqual(self.peek_dirs(), before)
        self.assertTrue(any("HARDENING REFUSED" in c.args[0] for c in self.audit.call_args_list))

    def test_macos_detaches_even_when_the_attach_fails(self):
        with self.assertRaisesRegex(RuntimeError, "attach failed"):
            self.run_mac(self.tree(), attach_error=RuntimeError("attach failed"))
        self.assertEqual(self.hdiutil_calls(), [["hdiutil", "attach"], ["hdiutil", "detach"]])

    def run_linux(self, root, files=FILES, fail_on=None, log=None):
        self.priv = RecordingPriv(root, fail_on=fail_on)
        self.addCleanup(self.priv.cleanup)
        with mock.patch.object(app, "IS_MAC", False):
            app.refuse_hardening_clash("/x/Win11.iso", files, log or Collector(), self.priv)

    def test_linux_mounts_read_only_with_one_script_and_unmounts(self):
        self.run_linux(self.tree())
        self.assertEqual(self.priv.kinds(), ["peek", "peek-cleanup"])
        (script, args), (_cleanup, cleanup_args) = self.priv.scripts
        self.assertIs(script, app.LINUX_ISO_PEEK_SCRIPT)
        self.assertEqual(args[0], "/x/Win11.iso")
        self.assertRegex(args[2], r"^\d+:\d+$")
        self.assertEqual(cleanup_args, [args[1]])
        for value in args:
            self.assertNotIn(value, script)  # positional parameters only
        self.assertIn("loop,ro,", script)
        self.audit.assert_not_called()

    def test_linux_refuses_an_image_that_has_the_file_and_still_unmounts(self):
        with self.assertRaisesRegex(ValueError, r"already contains .*SetupComplete\.cmd"):
            self.run_linux(self.tree(clash=True))
        self.assertEqual(self.priv.kinds(), ["peek", "peek-cleanup"])
        self.assertTrue(any("HARDENING REFUSED" in c.args[0] for c in self.audit.call_args_list))

    def test_linux_unmounts_even_when_the_mount_script_fails_and_never_repeats_it(self):
        with self.assertRaisesRegex(RuntimeError, "Privileged command"):
            self.run_linux(self.tree(), fail_on=app.LINUX_ISO_PEEK_SCRIPT)
        self.assertEqual(self.priv.kinds(), ["peek", "peek-cleanup"])

    def test_a_failing_unmount_is_only_a_warning(self):
        log = Collector()
        self.run_linux(self.tree(), fail_on=app.LINUX_ISO_PEEK_CLEANUP_SCRIPT, log=log)
        self.assertTrue(any(line.startswith("Warning: cleanup failed") for line in log.lines))

    def test_nothing_is_mounted_when_there_are_no_hardening_files(self):
        self.run_linux(self.tree(), files={})
        self.assertEqual(self.priv.scripts, [])
        with mock.patch.object(app, "run_cmd") as run_cmd, mock.patch.object(app, "IS_MAC", True):
            app.refuse_hardening_clash("/x/Win11.iso", {}, Collector(), None)
        run_cmd.assert_not_called()


class PeekScriptTests(unittest.TestCase):
    def test_the_scripts_are_strict_ignore_ctrl_c_and_take_positional_arguments(self):
        for script in (app.LINUX_ISO_PEEK_SCRIPT, app.LINUX_ISO_PEEK_CLEANUP_SCRIPT):
            self.assertTrue(script.startswith("set -eu\ntrap '' INT\n"))
            self.assertEqual(subprocess.run(["bash", "-n"], input=script, text=True,
                                            capture_output=True).returncode, 0)
        self.assertIn('"$ISO" "$ISO_MNT"', app.LINUX_ISO_PEEK_SCRIPT)
        self.assertIn('umount "$1" || true', app.LINUX_ISO_PEEK_CLEANUP_SCRIPT)

    def test_it_mounts_the_same_way_as_the_prep_script_so_the_listing_matches_the_copy(self):
        import inspect
        prep = inspect.getsource(app.linux_build_usb)
        for line in ('mount -t udf,iso9660 -o loop,ro,uid="${OWNER%%:*}",gid="${OWNER##*:}" "$ISO" "$ISO_MNT"',
                     'mount -o loop,ro,uid="${OWNER%%:*}",gid="${OWNER##*:}" "$ISO" "$ISO_MNT"'):
            self.assertIn(line, app.LINUX_ISO_PEEK_SCRIPT)
            self.assertIn(line, prep)


if __name__ == "__main__":
    unittest.main()
