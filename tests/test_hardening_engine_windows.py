"""Hardening files on a Windows drive (build_usb(..., hardening=HARDENING_BASELINE)).

Nothing here touches a real drive, uses sudo or the network. hardening_files_windows and
validate_seed_files belong to other parts of the feature and are patched with small stand-ins;
a temp folder stands in for the mounted FAT32 volume; privileged scripts run locally with bash.
"""
import hashlib
import os
import shutil
import stat
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
            "deps": mock.patch.object(app, "get_missing_dependencies", return_value=[]),
            "audit": mock.patch.object(app, "audit"),
        }
        self.m = {}
        for name, patch in names.items():
            self.m[name] = patch.start()
            self.addCleanup(patch.stop)

    def build(self, mode=app.MODE_WINDOWS, hardening=app.HARDENING_BASELINE, is_mac=True, **kw):
        with mock.patch.object(app, "IS_MAC", is_mac):
            return app.build_usb(self.iso, "disk9", Collector(), None, mode=mode, hardening=hardening, **kw)

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
    def copy(self, src, dst, write_extra=None, files=FILES):
        log, progress = Collector(), Collector()
        app.copy_windows_payload(
            src, dst, log, progress, "wimlib hint",
            extra_files=files,
            write_extra=write_extra or (lambda root: app.write_hardening_files(root, files)))
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

    def test_an_iso_with_its_own_autounattend_is_not_reported_as_a_difference(self):
        src, _ = self.make_iso_tree(with_unattend=True)
        dst = self.path("usb")
        os.makedirs(dst)
        self.copy(src, dst)
        self.assertEqual(self.read(dst, "autounattend.xml"), FILES["autounattend.xml"])

    def test_a_flipped_byte_in_an_extra_file_is_a_verification_failure(self):
        src, _ = self.make_iso_tree()
        dst = self.path("usb")
        os.makedirs(dst)

        def write_then_flip(root):
            app.write_hardening_files(root, FILES)
            path = os.path.join(root, "autounattend.xml")
            with open(path, "r+b") as fh:
                fh.seek(5)
                byte = fh.read(1)
                fh.seek(5)
                fh.write(bytes([byte[0] ^ 0x01]))

        with self.assertRaisesRegex(RuntimeError, "Verification FAILED.*autounattend.xml"):
            self.copy(src, dst, write_extra=write_then_flip)

    def test_the_iso_files_are_still_checked_when_extras_are_present(self):
        src, _ = self.make_iso_tree()
        dst = self.path("usb")
        os.makedirs(dst)

        def write_and_damage(root):
            app.write_hardening_files(root, FILES)
            with open(os.path.join(root, "bootmgr"), "r+b") as fh:
                fh.write(b"\xff")

        with self.assertRaisesRegex(RuntimeError, "Verification FAILED"):
            self.copy(src, dst, write_extra=write_and_damage)

    def test_a_cancel_while_adding_leaves_an_unverified_incomplete_drive(self):
        src, _ = self.make_iso_tree()
        dst = self.path("usb")
        os.makedirs(dst)
        event = threading.Event()

        def cancel(root):
            event.set()
            app.write_hardening_files(root, FILES, event)

        with self.assertRaises(app.OperationCanceled) as ctx:
            app.copy_windows_payload(src, dst, Collector(), None, "hint", cancel_event=event,
                                     extra_files=FILES, write_extra=cancel)
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
    """Runs the hardening copy script for real (bash, as the current user) and fakes the disk scripts."""

    cached_password = None

    def __init__(self, tree, flip=None, run_copy=True):
        self.tree = tree
        self.flip = flip
        self.run_copy = run_copy
        self.scripts = []
        self.stage_modes = []
        self.stages = []
        self.mounts = []

    def cleanup(self):
        for folder in self.mounts:
            shutil.rmtree(folder, ignore_errors=True)

    def run_script(self, script, log, args=None, **_kw):
        args = [str(a) for a in (args or [])]
        self.scripts.append((script, args))
        if script is app.HARDENING_COPY_SCRIPT:
            self.stages.append(args[0])
            self.stage_modes.append(stat.S_IMODE(os.stat(args[0]).st_mode))
            if self.run_copy:
                with subprocess.Popen(["bash", "-c", script, "win11_usb_creator"] + args,
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as proc:
                    for line in proc.stdout:
                        log(line.rstrip())
                if proc.returncode != 0:
                    raise RuntimeError(f"script failed ({proc.returncode})")
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

    def test_the_files_are_staged_privately_copied_by_the_new_script_and_read_back(self):
        priv = RecordingPriv(self.tree)
        log = self.build(priv, hardening_files=FILES)
        copies = [a for s, a in priv.scripts if s is app.HARDENING_COPY_SCRIPT]
        self.assertEqual(len(copies), 1)
        stage, mount, flag = copies[0]
        self.assertEqual(mount, priv.usb_mount)
        self.assertEqual(priv.stage_modes, [0o700])
        self.assertTrue(os.path.basename(flag).startswith("cancel"))
        for rel, data in {**self.iso_files, **FILES}.items():
            with self.subTest(rel=rel):
                self.assertEqual(self.read(priv.usb_mount, rel), data)
        self.assertIn("Adding hardening files...", log.lines)
        self.assertTrue(any("Hardening files verified" in line for line in log.lines))
        self.assertFalse(os.path.exists(stage), "the staging folder must be removed afterwards")

    def test_the_script_runs_before_the_remount_so_the_read_back_covers_it(self):
        priv = RecordingPriv(self.tree)
        self.build(priv, hardening_files=FILES)
        kinds = ["copy" if s is app.HARDENING_COPY_SCRIPT else "remount" if s.startswith("set -eu\nsync\numount")
                 else "other" for s, _ in priv.scripts]
        self.assertLess(kinds.index("copy"), kinds.index("remount"))

    def test_a_flipped_byte_found_after_the_remount_fails_the_verification(self):
        priv = RecordingPriv(self.tree, flip="autounattend.xml")
        with self.assertRaisesRegex(RuntimeError, "Verification FAILED.*autounattend.xml"):
            self.build(priv, hardening_files=FILES)
        self.assertFalse(os.path.exists(priv.stages[0]))
        self.assertTrue(priv.scripts[-1][0].startswith("set -eu\numount"))  # the cleanup still ran

    def test_a_failing_script_is_not_repeated(self):
        class Failing(RecordingPriv):
            def run_script(self, script, log, args=None, **kw):
                if script is app.HARDENING_COPY_SCRIPT:
                    self.scripts.append((script, list(args)))
                    raise RuntimeError("Privileged command failed")
                return super().run_script(script, log, args, **kw)

        priv = Failing(self.tree)
        with self.assertRaisesRegex(RuntimeError, "Privileged command failed"):
            self.build(priv, hardening_files=FILES)
        self.assertEqual(sum(s is app.HARDENING_COPY_SCRIPT for s, _ in priv.scripts), 1)

    def test_a_cancel_before_the_copy_is_a_cancel_and_cleans_up(self):
        event = threading.Event()

        class CancelOnCopy(RecordingPriv):
            def run_script(self, script, log, args=None, **kw):
                if script.startswith("set -eu\nDEV="):
                    event.set()  # the user clicks Cancel while the drive is being formatted
                return super().run_script(script, log, args, **kw)

        priv = CancelOnCopy(self.tree)
        with self.assertRaises(app.OperationCanceled) as ctx:
            self.build(priv, hardening_files=FILES, cancel_event=event)
        self.assertTrue(ctx.exception.drive_touched)
        self.assertFalse(any(s is app.HARDENING_COPY_SCRIPT for s, _ in priv.scripts))

    def test_without_hardening_only_the_existing_scripts_run(self):
        priv = RecordingPriv(self.tree)
        self.build(priv)
        self.assertEqual(len(priv.scripts), 3)  # prep, remount, cleanup
        self.assertFalse(any(s is app.HARDENING_COPY_SCRIPT for s, _ in priv.scripts))

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


# SHA-256 of the scripts as they were before the hardening feature (see test_the_existing_scripts_are_byte_identical).
EXPECTED = {
    "prep": "2fe84953fae7ab72da1faac2dd1ecd5a2c4ab6e43e081e92cc00e8301cc978e1",
    "remount": "8b1af16122857c13763d3ffc45d0eb3090b8011491cc0d74cf04ee5210b89fef",
    "cleanup": "19e8a5a771a7c18a04ce5b2169643d4dde6bb55c452fadd74af409d5035d6935",
    "macos_raw": "ed23ca677a6af8e6a30adbb326ce4a4018206f36044ad1fa0dbb2e491a6283f7",
    "linux_raw": "c2bb23050148228cc18ed4433f162e49870cdc0640ecf7629dc53833f9ac9750",
    "verify_raw": "41f2378a9194c4218dac1b5ceaac97ab7893a0a0c94302a3a7676da1e3062902",
}


class StageTests(HardeningTestCase):
    def test_the_stage_is_private_complete_and_free_of_links(self):
        stage = app.stage_hardening_files(FILES)
        try:
            self.assertEqual(stat.S_IMODE(os.stat(stage).st_mode), 0o700)
            found = {}
            for folder, _dirs, names in os.walk(stage):
                for name in names:
                    path = os.path.join(folder, name)
                    self.assertFalse(os.path.islink(path))
                    found[os.path.relpath(path, stage).replace(os.sep, "/")] = self.read(folder, name)
            self.assertEqual(found, FILES)
        finally:
            shutil.rmtree(stage)

    def test_a_staging_failure_leaves_no_folder_behind(self):
        before = {n for n in os.listdir(app.tempfile.gettempdir()) if n.startswith("win11hard_")}
        with mock.patch.object(app, "write_hardening_files", side_effect=OSError("full")), \
                self.assertRaises(OSError):
            app.stage_hardening_files(FILES)
        after = {n for n in os.listdir(app.tempfile.gettempdir()) if n.startswith("win11hard_")}
        self.assertEqual(before, after)


class CopyScriptTests(HardeningTestCase):
    """The real HARDENING_COPY_SCRIPT, run with bash as the current user on temp folders."""

    def setUp(self):
        super().setUp()
        self.stage = self.path("stage")
        self.mnt = self.path("mnt")
        os.makedirs(self.mnt)
        os.makedirs(self.stage)
        app.write_hardening_files(self.stage, FILES)
        self.flag = self.path("flagdir", "cancel")
        os.makedirs(os.path.dirname(self.flag))

    def run_script(self, stage=None, mnt=None, flag=None):
        argv = ["bash", "-c", app.HARDENING_COPY_SCRIPT, "win11_usb_creator",
                stage or self.stage, mnt or self.mnt, flag or self.flag]
        return subprocess.run(argv, capture_output=True, text=True)

    def test_copies_the_tree_with_exact_bytes(self):
        result = self.run_script()
        self.assertEqual((result.returncode, result.stdout.strip()), (0, "HARDENING_COPIED"), result.stderr)
        for rel, data in FILES.items():
            self.assertEqual(self.read(self.mnt, rel), data)

    def test_the_script_is_literal_and_starts_strict(self):
        self.assertTrue(app.HARDENING_COPY_SCRIPT.startswith("set -eu\n"))
        self.assertEqual(subprocess.run(["bash", "-n"], input=app.HARDENING_COPY_SCRIPT, text=True,
                                        capture_output=True).returncode, 0)

    def test_a_symlink_in_the_stage_is_refused_and_nothing_is_copied(self):
        os.symlink("/etc/passwd", os.path.join(self.stage, "link"))
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symbolic link", result.stderr)
        self.assertEqual(os.listdir(self.mnt), [])

    def test_a_symlink_given_as_the_stage_or_the_mount_is_refused(self):
        link = self.path("link-to-stage")
        os.symlink(self.stage, link)
        self.assertNotEqual(self.run_script(stage=link).returncode, 0)
        link2 = self.path("link-to-mnt")
        os.symlink(self.mnt, link2)
        self.assertNotEqual(self.run_script(mnt=link2).returncode, 0)
        self.assertEqual(os.listdir(self.mnt), [])

    def test_arguments_that_are_not_directories_are_refused(self):
        plain = self.write_file("plain", b"x")
        for stage, mnt in ((plain, self.mnt), (self.stage, plain), (self.path("missing"), self.mnt)):
            with self.subTest(stage=stage, mnt=mnt):
                self.assertNotEqual(self.run_script(stage=stage, mnt=mnt).returncode, 0)
        self.assertEqual(os.listdir(self.mnt), [])

    def test_the_cancel_flag_stops_it_before_copying(self):
        open(self.flag, "w").close()
        result = self.run_script()
        self.assertEqual((result.returncode, result.stdout.strip()), (0, "HARDENING_CANCELED"))
        self.assertEqual(os.listdir(self.mnt), [])

    def test_names_that_look_like_options_or_shell_are_just_names(self):
        app.write_hardening_files(self.stage, {"-rf": b"a", "$(touch pwned)": b"b", "a b;c": b"c"})
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual(self.read(self.mnt, "-rf"), b"a")
        self.assertEqual(self.read(self.mnt, "$(touch pwned)"), b"b")
        self.assertEqual(self.read(self.mnt, "a b;c"), b"c")
        self.assertFalse(os.path.exists("pwned"))


class CopyHardeningStageTests(HardeningTestCase):
    def setUp(self):
        super().setUp()
        self.stage = self.path("stage")
        self.mnt = self.path("mnt")
        os.makedirs(self.stage)
        os.makedirs(self.mnt)

    class Priv:
        cached_password = None

        def __init__(self, lines=(), error=None):
            self.lines, self.error, self.calls = lines, error, []

        def run_script(self, script, log, args=None, **_kw):
            self.calls.append((script, list(args)))
            if self.error:
                raise self.error
            for line in self.lines:
                log(line)

    def test_the_arguments_are_the_stage_the_mount_and_a_cancel_flag(self):
        priv = self.Priv(["HARDENING_COPIED"])
        app.copy_hardening_stage(priv, self.stage, self.mnt, Collector())
        script, args = priv.calls[0]
        self.assertIs(script, app.HARDENING_COPY_SCRIPT)
        self.assertEqual(args[:2], [self.stage, self.mnt])
        self.assertEqual(len(args), 3)

    def test_the_markers_are_not_logged_but_other_lines_are(self):
        log = Collector()
        app.copy_hardening_stage(self.Priv(["some note", "HARDENING_COPIED"]), self.stage, self.mnt, log)
        self.assertEqual(log.lines, ["some note"])

    def test_the_cancel_marker_raises_operation_canceled(self):
        with self.assertRaises(app.OperationCanceled) as ctx:
            app.copy_hardening_stage(self.Priv(["HARDENING_CANCELED"]), self.stage, self.mnt, Collector())
        self.assertTrue(ctx.exception.drive_touched)
        self.assertFalse(ctx.exception.written)

    def test_a_script_that_never_confirms_is_an_error(self):
        with self.assertRaisesRegex(RuntimeError, "Could not confirm"):
            app.copy_hardening_stage(self.Priv([]), self.stage, self.mnt, Collector())

    def test_a_cancel_before_the_script_does_not_run_it(self):
        event = threading.Event()
        event.set()
        priv = self.Priv(["HARDENING_COPIED"])
        with self.assertRaises(app.OperationCanceled):
            app.copy_hardening_stage(priv, self.stage, self.mnt, Collector(), event)
        self.assertEqual(priv.calls, [])

    def test_folders_are_checked_in_python_before_the_script(self):
        link = self.path("link")
        os.symlink(self.stage, link)
        for stage, mnt in ((link, self.mnt), (self.stage, self.path("missing"))):
            priv = self.Priv(["HARDENING_COPIED"])
            with self.subTest(stage=stage, mnt=mnt), self.assertRaisesRegex(ValueError, "Not a plain directory"):
                app.copy_hardening_stage(priv, stage, mnt, Collector())
            self.assertEqual(priv.calls, [])


if __name__ == "__main__":
    unittest.main()
