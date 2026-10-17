"""The seed drive engine: validate_seed_files / validate_seed_label / build_seed_usb.

Nothing here touches a real device or uses sudo: every system call is mocked or runs against
temp directories. `hardening_files_seed` belongs to another part of the feature, so it is patched
by name (create=True: it may not exist in this branch).
"""
import contextlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

from tests.helpers import MIB, ROOT, Collector, TempDirTestCase, app

LABEL = "CIDATA"
FILES = {"user-data": b"#cloud-config\n", "README.txt": b"hello\n"}
ONE_GIB = 1024 ** 3


# ---------------------------------------------------------------------------
# 1. validate_seed_files
# ---------------------------------------------------------------------------
class ValidateSeedFilesAcceptTests(unittest.TestCase):
    def test_a_plain_set_is_returned_as_a_copy(self):
        files = {"user-data": b"a", "meta-data": b"b", "README.txt": b"c"}
        clean = app.validate_seed_files(files)
        self.assertEqual(clean, files)
        self.assertIsNot(clean, files)

    def test_dollar_signs_and_nested_folders_are_ordinary(self):
        files = {"sources/$OEM$/$$/Setup/Scripts/SetupComplete.cmd": b"x",
                 "sources/$OEM$/$$/Setup/Scripts/harden.ps1": b"y",
                 "autounattend.xml": b"<z/>"}
        self.assertEqual(app.validate_seed_files(files), files)

    def test_an_empty_file_is_allowed(self):
        self.assertEqual(app.validate_seed_files({"empty": b""}), {"empty": b""})

    def test_bytearray_and_memoryview_become_bytes(self):
        clean = app.validate_seed_files({"a": bytearray(b"12"), "b": memoryview(b"34")})
        self.assertEqual(clean, {"a": b"12", "b": b"34"})
        self.assertTrue(all(type(v) is bytes for v in clean.values()))

    def test_limits_are_inclusive(self):
        big = b"x" * app.SEED_MAX_FILE_BYTES
        self.assertEqual(app.SEED_MAX_FILE_BYTES, 256 * 1024)
        self.assertEqual(app.SEED_MAX_TOTAL_BYTES, 2 * MIB)
        app.validate_seed_files({"one": big})                                   # exactly 256 KiB
        app.validate_seed_files({f"f{i}": big for i in range(8)})               # exactly 2 MiB together
        name = "d/" * 119 + "a"                                                 # 239 characters
        app.validate_seed_files({name: b"x"})
        app.validate_seed_files({"a" * app.SEED_MAX_PATH_CHARS: b"x"})          # exactly 240 characters

    def test_non_ascii_names_are_fine(self):
        app.validate_seed_files({"léame-ação.txt": b"x"})

    def test_same_name_in_different_folders_is_not_a_duplicate(self):
        app.validate_seed_files({"a/x": b"1", "b/x": b"2"})


class ValidateSeedFilesRejectTests(unittest.TestCase):
    def assertRejected(self, files, pattern=None):
        with self.assertRaises(ValueError) as ctx:
            app.validate_seed_files(files)
        if pattern:
            self.assertRegex(str(ctx.exception), pattern)

    def test_parent_directory_components(self):
        for path in ("..", "../etc/passwd", "a/../../b", "a/..", "a/../b"):
            with self.subTest(path=path):
                self.assertRejected({path: b"x"}, r"'\.\.'|\.\.")

    def test_absolute_paths(self):
        for path in ("/etc/passwd", "/user-data", "//server/share"):
            with self.subTest(path=path):
                self.assertRejected({path: b"x"})

    def test_drive_letters_and_colons(self):
        self.assertRejected({"C:/Windows/x": b"x"}, "FAT32")
        self.assertRejected({"a:b": b"x"}, "FAT32")

    def test_backslashes(self):
        for path in ("a\\b", "..\\x", "\\abs"):
            with self.subTest(path=path):
                self.assertRejected({path: b"x"}, "backslash")

    def test_nul_and_control_characters(self):
        self.assertRejected({"a\x00b": b"x"}, "NUL")
        for path in ("a\nb", "a\tb", "a\x7fb", "a\x1fb"):
            with self.subTest(path=path):
                self.assertRejected({path: b"x"}, "control")

    def test_long_names(self):
        self.assertRejected({"a" * 241: b"x"}, "longer than 240")
        self.assertRejected({"d/" * 120 + "ab": b"x"}, "longer than 240")

    def test_empty_and_dot_components(self):
        for path in ("", "a//b", "a/", "./a", "a/./b", "."):
            with self.subTest(path=path):
                self.assertRejected({path: b"x"})

    def test_names_fat32_cannot_store(self):
        for path in ("a?", "a*b", "a<b", 'a"b', "a|b", "name.", "name ", "dir /x", "CON", "nul.txt", "COM1", "lpt9.cfg"):
            with self.subTest(path=path):
                self.assertRejected({path: b"x"})

    def test_a_lone_surrogate_is_not_valid_text(self):
        self.assertRejected({"a\ud800": b"x"}, "not valid text")

    def test_size_limits(self):
        self.assertRejected({"big": b"x" * (app.SEED_MAX_FILE_BYTES + 1)}, "256")
        self.assertRejected({f"f{i}": b"x" * app.SEED_MAX_FILE_BYTES for i in range(9)}, "together")

    def test_names_that_differ_only_by_case(self):
        self.assertRejected({"README.txt": b"1", "readme.TXT": b"2"}, "letter case")
        self.assertRejected({"A/b": b"1", "a/B": b"2"}, "letter case")

    def test_a_file_cannot_also_be_a_folder(self):
        self.assertRejected({"a": b"1", "a/b": b"2"}, "is a file")
        self.assertRejected({"A": b"1", "a/b": b"2"}, "is a file")

    def test_wrong_types(self):
        self.assertRejected({}, "no seed files")
        self.assertRejected(None, "no seed files")
        self.assertRejected([("a", b"x")], "no seed files")
        self.assertRejected({b"a": b"x"}, "not text")
        self.assertRejected({1: b"x"}, "not text")
        self.assertRejected({"a": "text"}, "not bytes")
        self.assertRejected({"a": None}, "not bytes")

    def test_too_many_files(self):
        self.assertRejected({f"f{i}": b"" for i in range(app.SEED_MAX_FILES + 1)}, "Too many")

    def test_the_message_names_the_path_and_stays_short(self):
        with self.assertRaises(ValueError) as ctx:
            app.validate_seed_files({"x" * 5000 + "\\": b""})
        self.assertLess(len(str(ctx.exception)), 400)

    def test_nothing_is_changed_on_failure(self):
        files = {"ok": b"1", "../bad": b"2"}
        with self.assertRaises(ValueError):
            app.validate_seed_files(files)
        self.assertEqual(files, {"ok": b"1", "../bad": b"2"})


class ValidateSeedLabelTests(unittest.TestCase):
    def test_labels_of_the_three_targets_are_valid(self):
        for label in ("CIDATA", "OEMDRV", "EPMA-SEED", "A", "A" * 11, "_X", "0-9_"):
            with self.subTest(label=label):
                self.assertEqual(app.validate_seed_label(label), label)

    def test_invalid_labels(self):
        bad = ["", "A" * 12, "cidata", "CI DATA", "CI.DATA", "CIDATA\n", "-X", "A;B", "$(id)", "A/B", "Á",
               "A\x00", "CIDATA ", " CIDATA", "'"]
        for label in bad:
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    app.validate_seed_label(label)

    def test_non_strings(self):
        for label in (None, 5, b"CIDATA", ["CIDATA"]):
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    app.validate_seed_label(label)

    def test_a_trailing_newline_does_not_slip_through_the_anchor(self):
        with self.assertRaises(ValueError):
            app.validate_seed_label("CIDATA\n")


# ---------------------------------------------------------------------------
# 2. Contract bits: modes, needs_admin, dependencies
# ---------------------------------------------------------------------------
class SeedModeTests(unittest.TestCase):
    def test_contract_constants(self):
        self.assertEqual(app.MODE_SEED, "seed")
        self.assertEqual(app.SEED_TARGETS, ("ubuntu", "fedora", "debian"))
        self.assertEqual(app.HARDENING_PROFILES, ("none", "baseline"))

    def test_seed_is_not_an_image_mode(self):
        # `--mode` and validate_image_for_mode() are about images; a seed drive has none.
        self.assertNotIn(app.MODE_SEED, app.ALL_MODES)
        self.assertNotIn(app.MODE_SEED, app.RAW_MODES)
        with self.assertRaises(ValueError):
            app.validate_image_for_mode("/nonexistent.iso", app.MODE_SEED)

    def test_needs_admin_mirrors_windows_mode(self):
        with mock.patch.object(app, "IS_LINUX", True):
            self.assertTrue(app.needs_admin(app.MODE_SEED))
        with mock.patch.object(app, "IS_LINUX", False):
            self.assertFalse(app.needs_admin(app.MODE_SEED))
            self.assertEqual(app.needs_admin(app.MODE_SEED), app.needs_admin(app.MODE_WINDOWS))

    def test_dependencies_are_only_the_partitioning_tools(self):
        with mock.patch.object(app, "IS_MAC", True), mock.patch.object(app.shutil, "which", return_value=None):
            self.assertEqual(app.get_missing_dependencies(app.MODE_SEED), [])   # diskutil is part of macOS
        with mock.patch.object(app, "IS_MAC", False), mock.patch.object(app.shutil, "which", return_value=None):
            missing = app.get_missing_dependencies(app.MODE_SEED)
        self.assertEqual(sorted(missing), sorted(["parted", "mkfs.vfat", "wipefs", "partprobe"]))
        self.assertNotIn("rsync", missing)
        self.assertNotIn("wimlib-imagex", missing)
        with mock.patch.object(app, "IS_MAC", False), \
                mock.patch.object(app.shutil, "which", side_effect=lambda t: None if t == "parted" else "/bin/" + t):
            self.assertEqual(app.get_missing_dependencies(app.MODE_SEED), ["parted"])

    def test_windows_mode_dependencies_are_unchanged(self):
        with mock.patch.object(app, "IS_MAC", False), mock.patch.object(app.shutil, "which", return_value=None):
            self.assertEqual(app.get_missing_dependencies(app.MODE_WINDOWS), app.LINUX_REQUIRED_TOOLS)

    def test_seed_tools_are_installable_by_the_allow_list(self):
        for tool in app.LINUX_SEED_TOOLS:
            self.assertIn(tool, app.LINUX_REQUIRED_TOOLS)


class CheckSeedTargetSizeTests(unittest.TestCase):
    def test_a_known_size_under_64_mib_is_refused_with_a_friendly_message(self):
        for size in (1, 10 * MIB, app.SEED_MIN_DRIVE_BYTES - 1):
            with self.subTest(size=size), self.assertRaisesRegex(
                    ValueError, r"The drive \(.*\) is too small for a seed drive \(at least 64.*\)\. Nothing was changed\."):
                app.check_seed_target_size(size)

    def test_64_mib_and_more_pass(self):
        for size in (app.SEED_MIN_DRIVE_BYTES, 16 * 1024 * MIB):
            app.check_seed_target_size(size)

    def test_an_unknown_size_passes(self):
        for size in (None, 0):
            app.check_seed_target_size(size)


# ---------------------------------------------------------------------------
# 3. The shell scripts
# ---------------------------------------------------------------------------
class SeedScriptTests(TempDirTestCase):
    SCRIPTS = ("LINUX_SEED_PREP_SCRIPT", "LINUX_SEED_REMOUNT_SCRIPT", "LINUX_SEED_CLEANUP_SCRIPT")

    def test_strict_mode_and_positional_arguments(self):
        for name in self.SCRIPTS:
            script = getattr(app, name)
            with self.subTest(script=name):
                self.assertTrue(script.startswith("set -eu\n"))
                self.assertNotIn("{label}", script)

    def test_every_seed_script_ignores_the_terminals_ctrl_c_like_the_other_cancel_aware_scripts(self):
        # A Ctrl-C in the terminal reaches the root script too (same process group); the app turns it into the
        # cancel flag instead, so the script must not die half way (for example right after `mount`).
        for name in self.SCRIPTS:
            with self.subTest(script=name):
                self.assertTrue(getattr(app, name).startswith("set -eu\ntrap '' INT\n"))
        for other in (app.LINUX_RAW_SCRIPT, app.VERIFY_RAW_SCRIPT):
            self.assertIn("trap '' INT\n", other)

    def test_the_label_reaches_mkfs_as_a_positional_argument(self):
        script = app.LINUX_SEED_PREP_SCRIPT
        self.assertIn('LABEL="$3"', script)
        self.assertIn('mkfs.vfat -F 32 -n "$LABEL" "$PART"', script)
        for label in ("CIDATA", "OEMDRV", "EPMA-SEED"):
            self.assertNotIn(label, script)

    def test_no_efi_system_partition_flag_on_a_data_drive(self):
        self.assertNotIn(" esp ", app.LINUX_SEED_PREP_SCRIPT)

    def test_the_windows_scripts_are_untouched(self):
        # The seed drive has its own scripts; the Windows prep script still names its constant label.
        self.assertNotIn("SEED", app.LINUX_RAW_SCRIPT)
        import inspect
        self.assertIn("mkfs.vfat -F 32 -n {VOL_NAME}", inspect.getsource(app.linux_build_usb))

    def test_the_cancel_flag_is_checked_before_anything_destructive(self):
        script = app.LINUX_SEED_PREP_SCRIPT
        self.assertLess(script.index('[ -e "$FLAG" ]'), script.index("wipefs"))
        self.assertLess(script.index("SEED_CANCELED"), script.index("mkfs.vfat"))
        self.assertLess(script.index("wipefs"), script.index("SEED_CANCELED"))

    def test_markers_match_the_python_constants(self):
        self.assertIn(f"echo {app.SEED_UNTOUCHED_MARKER};", app.LINUX_SEED_PREP_SCRIPT)
        self.assertIn(f"echo {app.SEED_CANCELED_MARKER};", app.LINUX_SEED_PREP_SCRIPT)

    def test_a_requested_cancel_stops_the_real_script_before_any_tool_runs(self):
        bindir = self.path("bin")
        os.makedirs(bindir)
        trace = self.path("trace")
        for tool in ("wipefs", "parted", "partprobe", "mkfs.vfat", "mount", "umount", "udevadm"):
            stub = os.path.join(bindir, tool)
            with open(stub, "w", encoding="utf-8") as fh:
                fh.write(f'#!/bin/sh\necho "{tool} $*" >> "{trace}"\n')
            os.chmod(stub, 0o700)
        flag = self.path("cancel")
        open(flag, "w").close()
        env = dict(os.environ, PATH=bindir + os.pathsep + os.environ["PATH"])
        proc = subprocess.run(
            ["bash", "-c", app.LINUX_SEED_PREP_SCRIPT, "win11_usb_creator", self.path("fakedev"),
             self.path("fakedev1"), "CIDATA", self.path("mnt"), "0:0", flag],
            capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), app.SEED_UNTOUCHED_MARKER)
        self.assertFalse(os.path.exists(trace), "a tool ran although the cancel flag was already set")

    def test_the_prep_script_runs_the_tools_in_order_when_not_canceled(self):
        bindir = self.path("bin")
        os.makedirs(bindir)
        trace = self.path("trace")
        for tool in ("wipefs", "parted", "partprobe", "mkfs.vfat", "mount", "umount", "udevadm", "sleep"):
            stub = os.path.join(bindir, tool)
            with open(stub, "w", encoding="utf-8") as fh:
                fh.write(f'#!/bin/sh\necho "{tool} $*" >> "{trace}"\n')
            os.chmod(stub, 0o700)
        # `[ -b "$PART" ]` needs a block device. /dev/null is a character device, so the partition check
        # fails: the script must stop there (exit 1) AFTER wipefs/parted/partprobe, BEFORE mkfs.vfat.
        part = "/dev/null"
        env = dict(os.environ, PATH=bindir + os.pathsep + os.environ["PATH"])
        proc = subprocess.run(
            ["bash", "-c", app.LINUX_SEED_PREP_SCRIPT, "win11_usb_creator", self.path("fakedev"), part,
             "CIDATA", self.path("mnt"), "0:0", self.path("no-such-flag")],
            capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("did not appear", proc.stdout + proc.stderr)
        with open(trace, encoding="utf-8") as fh:
            tools = [line.split()[0] for line in fh if line.strip()]
        self.assertLess(tools.index("wipefs"), tools.index("parted"))
        self.assertLess(tools.index("parted"), tools.index("partprobe"))
        self.assertNotIn("mkfs.vfat", tools)
        self.assertNotIn("mount", tools)


# ---------------------------------------------------------------------------
# 4. build_seed_usb: order of operations, validation, cancel, audit, eject
# ---------------------------------------------------------------------------
class BuildSeedUsbTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.events = []
        self.audits = []
        self.stage_seen = {}

        self.result = True
        patches = {
            "hardening_files_seed": mock.patch.object(app, "hardening_files_seed", create=True,
                                                      side_effect=self.fake_seed),
            "reverify_target_disk": mock.patch.object(app, "reverify_target_disk",
                                                      side_effect=lambda *a, **k: self.events.append("reverify")),
            "get_missing_dependencies": mock.patch.object(app, "get_missing_dependencies", return_value=[]),
            "prevent_sleep": mock.patch.object(app, "prevent_sleep", return_value=contextlib.nullcontext()),
            "audit": mock.patch.object(app, "audit", side_effect=lambda msg, level=None: self.audits.append(msg)),
            "linux": mock.patch.object(app, "linux_build_seed_usb", side_effect=self.fake_linux),
            "mac": mock.patch.object(app, "macos_build_seed_usb", side_effect=self.fake_mac),
            "stage": mock.patch.object(app, "stage_seed_files", wraps=app.stage_seed_files),
        }
        self.mocks = {}
        for name, patch in patches.items():
            self.mocks[name] = patch.start()
            self.addCleanup(patch.stop)
        platform = mock.patch.object(app, "IS_MAC", False)
        platform.start()
        self.addCleanup(platform.stop)
        self.seed = (LABEL, dict(FILES))

    def fake_seed(self, target, profile):
        self.events.append("seed")
        self.last_seed_args = (target, profile)
        return self.seed

    def inspect_stage(self, args):
        stage = next((a for a in args if isinstance(a, str) and os.path.basename(a).startswith("epmaseed_")), None)
        if not stage:
            return {}
        info = {"stage": stage, "mode": stat.S_IMODE(os.stat(stage).st_mode), "files": {}}
        for root, _dirs, names in os.walk(stage):
            for n in names:
                p = os.path.join(root, n)
                with open(p, "rb") as fh:
                    info["files"][os.path.relpath(p, stage).replace(os.sep, "/")] = (
                        fh.read(), stat.S_IMODE(os.stat(p).st_mode))
        return info

    def fake_linux(self, *args, **kwargs):
        self.events.append("linux")
        self.stage_seen.update(self.inspect_stage(args))
        self.linux_args = (args, kwargs)
        return self.result

    def fake_mac(self, *args, **kwargs):
        self.events.append("mac")
        self.stage_seen.update(self.inspect_stage(args))
        self.mac_args = (args, kwargs)
        return self.result

    def build(self, target="ubuntu", dev="sdb", **kw):
        kw.setdefault("expected_size", ONE_GIB)
        return app.build_seed_usb(target, dev, Collector(), object(), **kw)

    # ----- the happy path -----
    def test_order_of_operations_on_linux(self):
        self.assertIs(self.build(), True)
        self.assertEqual(self.events, ["seed", "reverify", "linux"])
        self.assertEqual(self.last_seed_args, ("ubuntu", app.HARDENING_BASELINE))
        args, _ = self.linux_args
        self.assertEqual(args[0], LABEL)
        self.assertEqual(args[1], FILES)
        self.assertEqual(args[3], "sdb")

    def test_order_of_operations_on_macos(self):
        with mock.patch.object(app, "IS_MAC", True):
            self.assertIs(self.build(dev="disk9"), True)
        self.assertEqual(self.events, ["seed", "reverify", "mac"])
        args, kwargs = self.mac_args
        self.assertEqual(args[0], LABEL)
        self.assertEqual(args[3], "disk9")

    def test_the_target_and_profile_reach_hardening_files_seed(self):
        for target in app.SEED_TARGETS:
            with self.subTest(target=target):
                self.build(target=target, profile=app.HARDENING_NONE)
                self.assertEqual(self.last_seed_args, (target, app.HARDENING_NONE))

    def test_the_files_are_staged_privately_and_removed_afterwards(self):
        self.build()
        info = self.stage_seen
        self.assertEqual(info["mode"], 0o700)
        self.assertEqual({k: v[0] for k, v in info["files"].items()}, FILES)
        self.assertTrue(all(v[1] == 0o600 for v in info["files"].values()))
        self.assertFalse(os.path.exists(info["stage"]), "the staging directory was left behind")

    def test_the_staging_directory_is_removed_after_a_failure_too(self):
        seen = []

        def boom(*args, **kwargs):
            seen.append(args[2])
            self.assertTrue(os.path.isdir(args[2]))
            raise RuntimeError("boom")

        self.mocks["linux"].side_effect = boom
        with self.assertRaises(RuntimeError):
            self.build()
        self.assertFalse(os.path.exists(seen[0]), "the staging directory was left behind")

    def test_files_are_cleaned_by_the_shared_validator(self):
        self.seed = (LABEL, {"a": bytearray(b"1")})
        self.build()
        args, _ = self.linux_args
        self.assertEqual(args[1], {"a": b"1"})

    # ----- the eject result is passed through -----
    def test_eject_result_is_passed_through(self):
        for result, expected in ((True, True), (False, False), (None, False)):
            with self.subTest(result=result):
                self.result = result
                self.audits.clear()
                self.assertIs(self.build(), expected)
                self.assertIn(f"(ejected={expected})", self.audits[-1])

    def test_no_eject_is_forwarded_to_the_backend(self):
        self.result = None
        self.assertIs(self.build(eject=False), False)
        args, kwargs = self.linux_args
        self.assertIs(args[-1], False)

    def test_progress_and_cancel_event_are_forwarded(self):
        progress, cancel = Collector(), threading.Event()
        self.build(progress=progress, cancel_event=cancel)
        args, kwargs = self.linux_args
        self.assertIn(progress, args)
        self.assertIn(cancel, args)

    # ----- validation happens before the drive (or the disk list) is touched -----
    def assertNothingTouched(self):
        self.mocks["reverify_target_disk"].assert_not_called()
        self.mocks["linux"].assert_not_called()
        self.mocks["mac"].assert_not_called()
        self.mocks["stage"].assert_not_called()
        self.assertFalse(any(a.startswith("DESTRUCTIVE") for a in self.audits))

    def test_bad_arguments_are_refused_first(self):
        cases = [
            ("unknown target", {"target": "gentoo"}, "Unknown seed target"),
            ("unknown profile", {"profile": "paranoid"}, "Unknown hardening profile"),
            ("device name", {"dev": "sdb; rm -rf /"}, ""),
            ("device name", {"dev": "../sdb"}, ""),
            ("tiny drive", {"expected_size": app.SEED_MIN_DRIVE_BYTES - 1}, "too small.*Nothing was changed"),
        ]
        for what, kw, pattern in cases:
            with self.subTest(what=what, kw=kw):
                with self.assertRaisesRegex(ValueError, pattern):
                    self.build(**kw)
                self.assertNothingTouched()

    def test_the_size_check_is_a_public_function_that_build_seed_usb_uses_too(self):
        with mock.patch.object(app, "check_seed_target_size", side_effect=ValueError("too small (stub)")) as check:
            with self.assertRaisesRegex(ValueError, "too small"):
                self.build(expected_size=10 * MIB)
        check.assert_called_once_with(10 * MIB)
        self.assertNothingTouched()

    def test_a_drive_of_exactly_64_mib_is_accepted_and_an_unknown_size_is_not_a_refusal(self):
        self.build(expected_size=64 * MIB)
        self.build(expected_size=None)
        self.build(expected_size=0)
        self.assertEqual(self.events.count("linux"), 3)

    def test_a_bad_label_is_refused(self):
        for label in ("cidata", "CI DATA", "A" * 12, "", "-X", "A;B"):
            with self.subTest(label=label):
                self.events.clear()
                self.seed = (label, dict(FILES))
                with self.assertRaisesRegex(ValueError, "Invalid seed drive label"):
                    self.build()
                self.assertNothingTouched()

    def test_bad_files_are_refused(self):
        for bad in ({"../x": b"1"}, {"/abs": b"1"}, {"a\\b": b"1"}, {"a\x00": b"1"}, {"A": b"1", "a": b"2"},
                    {"big": b"x" * (app.SEED_MAX_FILE_BYTES + 1)}, {}):
            with self.subTest(files=list(bad)[:1]):
                self.seed = (LABEL, bad)
                with self.assertRaises(ValueError):
                    self.build()
                self.assertNothingTouched()

    def test_missing_tools_are_refused_before_anything_happens(self):
        self.mocks["get_missing_dependencies"].return_value = ["parted", "wipefs"]
        with mock.patch.object(app, "IS_MAC", False), \
                mock.patch.object(app, "linux_detect_pkg_manager", return_value="apt-get"):
            with self.assertRaisesRegex(ValueError, "parted, wipefs.*Nothing was changed"):
                self.build()
        self.mocks["get_missing_dependencies"].assert_called_with(app.MODE_SEED)
        self.assertNothingTouched()

    def test_the_safety_recheck_failure_stops_everything(self):
        self.mocks["reverify_target_disk"].side_effect = RuntimeError("Aborted for safety: changed")
        with self.assertRaisesRegex(RuntimeError, "Aborted for safety"):
            self.build()
        self.mocks["linux"].assert_not_called()
        self.assertFalse(any(a.startswith("DESTRUCTIVE OPERATION START") for a in self.audits))

    def test_the_recheck_gets_the_device_and_the_expected_size(self):
        self.build(expected_size=2 * ONE_GIB)
        args = self.mocks["reverify_target_disk"].call_args[0]
        self.assertEqual(args[0], "sdb")
        self.assertEqual(args[1], 2 * ONE_GIB)

    # ----- cancel semantics -----
    def test_cancel_before_the_drive_is_touched(self):
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(app.OperationCanceled) as ctx:
            self.build(cancel_event=cancel)
        self.assertFalse(ctx.exception.drive_touched)
        self.assertFalse(ctx.exception.written)
        self.mocks["linux"].assert_not_called()
        self.assertTrue(any("before the drive was touched" in a for a in self.audits), self.audits)
        self.assertFalse(any(a.startswith("DESTRUCTIVE OPERATION START") for a in self.audits))

    def test_cancel_in_the_backend_before_the_erase(self):
        self.mocks["linux"].side_effect = app.OperationCanceled("c", drive_touched=False)
        with self.assertRaises(app.OperationCanceled) as ctx:
            self.build()
        self.assertFalse(ctx.exception.drive_touched)
        self.assertTrue(any("before the drive was touched" in a and "CANCELED" in a for a in self.audits))
        self.assertFalse(any("left unusable" in a for a in self.audits))

    def test_cancel_after_the_drive_was_touched(self):
        self.mocks["linux"].side_effect = app.OperationCanceled("c")
        with self.assertRaises(app.OperationCanceled) as ctx:
            self.build()
        self.assertTrue(ctx.exception.drive_touched)
        self.assertFalse(ctx.exception.written)
        self.assertTrue(any("left unusable" in a for a in self.audits), self.audits)

    def test_cancel_during_verification(self):
        self.mocks["linux"].side_effect = app.OperationCanceled("c", written=True)
        with self.assertRaises(app.OperationCanceled) as ctx:
            self.build()
        self.assertTrue(ctx.exception.written)
        self.assertTrue(any("NOT verified" in a for a in self.audits), self.audits)

    # ----- audit trail and failures -----
    def test_audit_lines_on_success(self):
        self.build()
        starts = [a for a in self.audits if a.startswith("DESTRUCTIVE OPERATION START")]
        self.assertEqual(len(starts), 1)
        self.assertIn("/dev/sdb", starts[0])
        self.assertIn(f"label={LABEL}", starts[0])
        self.assertIn("files=2", starts[0])
        self.assertRegex(starts[0], r"sha256=[0-9a-f]{64}")
        self.assertIn("DESTRUCTIVE OPERATION COMPLETED on /dev/sdb (ejected=True)", self.audits)
        self.assertTrue(self.audits.index(starts[0]) < len(self.audits) - 1)

    def test_audit_lines_never_contain_file_contents(self):
        self.seed = (LABEL, {"user-data": b"SUPERSECRETMARKER"})
        self.build()
        self.assertFalse(any("SUPERSECRETMARKER" in a for a in self.audits))

    def test_a_failure_is_audited_and_reraised(self):
        self.mocks["linux"].side_effect = RuntimeError("Verification FAILED: 1 file(s) differ")
        with self.assertRaisesRegex(RuntimeError, "Verification FAILED"):
            self.build()
        self.assertTrue(any("DESTRUCTIVE OPERATION FAILED on /dev/sdb: RuntimeError" in a for a in self.audits))
        self.assertFalse(any("COMPLETED" in a for a in self.audits))

    def test_sleep_is_prevented_while_the_drive_is_written(self):
        entered = []

        @contextlib.contextmanager
        def fake_sleep(log=None):
            entered.append("in")
            yield
            entered.append("out")

        self.mocks["linux"].side_effect = lambda *a, **k: entered.append("write") or True
        with mock.patch.object(app, "prevent_sleep", fake_sleep):
            self.build()
        self.assertEqual(entered, ["in", "write", "out"])


# ---------------------------------------------------------------------------
# 5. The Linux backend, with a fake privilege helper and a temp directory standing in for the mount
# ---------------------------------------------------------------------------
class FakeSeedPriv:
    """Records every script; the prep script "mounts" by doing nothing (the mount point is a temp dir)."""

    cached_password = None

    def __init__(self, on_prep=None, on_remount=None, fail_on=None, prep_lines=()):
        self.calls = []
        self.on_prep = on_prep
        self.on_remount = on_remount
        self.fail_on = fail_on
        self.prep_lines = prep_lines

    def run_script(self, script, log, args=None, **_kw):
        args = [str(a) for a in (args or [])]
        self.calls.append((script, args))
        if script is app.LINUX_SEED_PREP_SCRIPT:
            for line in self.prep_lines:
                log(line)
            if self.on_prep:
                self.on_prep(args)
        elif script is app.LINUX_SEED_REMOUNT_SCRIPT and self.on_remount:
            self.on_remount(args)
        if self.fail_on is script:
            raise RuntimeError("script failed (1)")

    def names(self):
        table = {id(app.LINUX_SEED_PREP_SCRIPT): "prep", id(app.LINUX_SEED_REMOUNT_SCRIPT): "remount",
                 id(app.LINUX_SEED_CLEANUP_SCRIPT): "cleanup"}
        return [table[id(s)] for s, _ in self.calls]


class LinuxSeedBackendTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.files = {"user-data": b"#cloud-config\nautoinstall: {}\n", "meta-data": b"",
                      "sub/dir/harden-linux.sh": os.urandom(5000)}
        self.stage = app.stage_seed_files(self.files)
        self.addCleanup(lambda: shutil.rmtree(self.stage, ignore_errors=True))
        self.mount = self.path("mnt")
        os.makedirs(self.mount)
        self.log = Collector()
        self.events = []
        patches = {
            "mkdtemp": mock.patch.object(app.tempfile, "mkdtemp", return_value=self.mount),
            "run_cmd": mock.patch.object(app, "run_cmd", return_value=0),
            "eject": mock.patch.object(app, "linux_eject", side_effect=lambda *a, **k: self.events.append("eject")
                                       or True),
            "rmdir": mock.patch.object(app, "_silent_rmdir"),
            "audit": mock.patch.object(app, "audit"),
        }
        self.mocks = {}
        for name, patch in patches.items():
            self.mocks[name] = patch.start()
            self.addCleanup(patch.stop)

    def run_backend(self, priv, **kw):
        return app.linux_build_seed_usb(LABEL, self.files, self.stage, "sdb", self.log, priv, **kw)

    def drive_files(self):
        found = {}
        for root, _dirs, names in os.walk(self.mount):
            for n in names:
                p = os.path.join(root, n)
                with open(p, "rb") as fh:
                    found[os.path.relpath(p, self.mount).replace(os.sep, "/")] = fh.read()
        return found

    def test_success_copies_verifies_unmounts_and_ejects_in_order(self):
        priv = FakeSeedPriv()
        progress = Collector()
        self.assertIs(self.run_backend(priv, progress=progress), True)
        self.assertEqual(priv.names(), ["prep", "remount", "cleanup"])
        self.assertEqual(self.drive_files(), self.files)
        self.mocks["eject"].assert_called_once()
        self.assertTrue(any("Verification passed" in line for line in self.log.lines))
        texts = [c[2] for c in progress.calls]
        self.assertIn("Copying files...", texts)
        self.assertIn("Verifying the copied files...", texts)
        self.mocks["run_cmd"].assert_any_call(["sync"], self.log, check=False)

    def test_values_travel_only_as_positional_arguments(self):
        priv = FakeSeedPriv()
        self.run_backend(priv)
        prep_script, prep_args = priv.calls[0]
        dev, part, label, mnt, owner, flag = prep_args
        self.assertEqual((dev, part, label, mnt), ("/dev/sdb", "/dev/sdb1", LABEL, self.mount))
        self.assertRegex(owner, r"^\d+:\d+$")
        self.assertTrue(flag.endswith("cancel"))
        for script, _args in priv.calls:
            for value in prep_args:
                self.assertNotIn(value, script)

    def test_nvme_style_names_get_the_p_suffix(self):
        priv = FakeSeedPriv()
        app.linux_build_seed_usb(LABEL, self.files, self.stage, "nvme0n1", self.log, priv)
        self.assertEqual(priv.calls[0][1][:2], ["/dev/nvme0n1", "/dev/nvme0n1p1"])

    def test_every_script_runs_once_and_a_failing_one_is_never_rerun(self):
        priv = FakeSeedPriv(fail_on=app.LINUX_SEED_PREP_SCRIPT)
        with self.assertRaisesRegex(RuntimeError, "script failed"):
            self.run_backend(priv)
        # No retry. The cleanup (`umount ... || true`, harmless when nothing is mounted) runs once because the
        # volume is marked as mounted BEFORE the prep script runs: its last command is the mount, and an
        # error or an interrupt right after it must not leave the volume mounted.
        self.assertEqual(priv.names(), ["prep", "cleanup"])
        self.mocks["eject"].assert_not_called()
        self.assertEqual(self.drive_files(), {})

    def test_an_interrupt_right_after_the_mount_still_unmounts(self):
        class Interrupted(FakeSeedPriv):
            def run_script(self, script, log, args=None, **kw):
                super().run_script(script, log, args, **kw)
                if script is app.LINUX_SEED_PREP_SCRIPT:
                    raise KeyboardInterrupt  # Ctrl-C arrives after the script's last command, the mount

        priv = Interrupted()
        with self.assertRaises(KeyboardInterrupt):
            self.run_backend(priv)
        self.assertEqual(priv.names(), ["prep", "cleanup"])
        self.mocks["eject"].assert_not_called()

    def test_verification_mismatch_blocks_the_eject_and_still_unmounts(self):
        def corrupt(args):
            path = os.path.join(args[1], "user-data")
            with open(path, "r+b") as fh:
                fh.seek(3)
                byte = fh.read(1)
                fh.seek(3)
                fh.write(bytes([byte[0] ^ 0xFF]))

        priv = FakeSeedPriv(on_remount=corrupt)
        with self.assertRaisesRegex(RuntimeError, r"(?s)Verification FAILED.*user-data \(content differs\).*NOT ejected"):
            self.run_backend(priv)
        self.assertEqual(priv.names(), ["prep", "remount", "cleanup"])
        self.mocks["eject"].assert_not_called()

    def test_a_missing_file_and_a_truncated_file_are_caught(self):
        for damage, text in ((lambda m: os.remove(os.path.join(m, "meta-data")), "meta-data \\(missing\\)"),
                             (lambda m: open(os.path.join(m, "user-data"), "wb").close(), "user-data \\(size differs\\)")):
            with self.subTest(text=text):
                self.mocks["eject"].reset_mock()
                priv = FakeSeedPriv(on_remount=lambda args, d=damage: d(args[1]))
                with self.assertRaisesRegex(RuntimeError, f"(?s)Verification FAILED.*{text}"):
                    self.run_backend(priv)
                self.mocks["eject"].assert_not_called()

    def test_extra_files_such_as_system_folders_do_not_fail_the_check(self):
        priv = FakeSeedPriv(on_remount=lambda args: open(os.path.join(args[1], "extra.dat"), "wb").close())
        self.assertIs(self.run_backend(priv), True)

    def test_cancel_before_the_script_touches_the_drive(self):
        priv = FakeSeedPriv(prep_lines=[app.SEED_UNTOUCHED_MARKER])
        with self.assertRaises(app.OperationCanceled) as ctx:
            self.run_backend(priv)
        self.assertFalse(ctx.exception.drive_touched)
        self.assertEqual(priv.names(), ["prep"])  # stopped before the mount: nothing to unmount
        self.mocks["eject"].assert_not_called()
        self.assertFalse(any("unusable" in line for line in self.log.lines))
        self.assertEqual(self.drive_files(), {})

    def test_cancel_before_the_backend_starts(self):
        cancel = threading.Event()
        cancel.set()
        priv = FakeSeedPriv()
        with self.assertRaises(app.OperationCanceled) as ctx:
            self.run_backend(priv, cancel_event=cancel)
        self.assertFalse(ctx.exception.drive_touched)
        self.assertEqual(priv.calls, [])

    def test_cancel_after_the_script_wiped_the_drive(self):
        priv = FakeSeedPriv(prep_lines=[app.SEED_CANCELED_MARKER])
        with self.assertRaises(app.OperationCanceled) as ctx:
            self.run_backend(priv)
        self.assertTrue(ctx.exception.drive_touched)
        self.assertFalse(ctx.exception.written)
        self.assertTrue(any("incomplete and unusable" in line for line in self.log.lines))
        self.assertEqual(priv.names(), ["prep"])  # stopped before mkfs and the mount
        self.mocks["eject"].assert_not_called()

    def test_cancel_while_copying_leaves_an_unusable_drive_and_unmounts(self):
        cancel = threading.Event()
        priv = FakeSeedPriv()
        progress = lambda done, total, text: cancel.set() if text == "Copying files..." else None  # noqa: E731
        with self.assertRaises(app.OperationCanceled) as ctx:
            self.run_backend(priv, progress=progress, cancel_event=cancel)
        self.assertTrue(ctx.exception.drive_touched)
        self.assertFalse(ctx.exception.written)
        self.assertEqual(priv.names(), ["prep", "cleanup"])
        self.mocks["eject"].assert_not_called()

    def test_cancel_during_verification_says_written_but_not_verified(self):
        cancel = threading.Event()
        priv = FakeSeedPriv(on_remount=lambda args: cancel.set())
        with self.assertRaises(app.OperationCanceled) as ctx:
            self.run_backend(priv, cancel_event=cancel)
        self.assertTrue(ctx.exception.written)
        self.assertEqual(priv.names(), ["prep", "remount", "cleanup"])
        self.assertTrue(any("NOT verified" in line for line in self.log.lines))
        self.mocks["eject"].assert_not_called()

    def test_no_eject_leaves_the_drive_connected(self):
        self.mocks["eject"].reset_mock()
        priv = FakeSeedPriv()
        result = self.run_backend(priv, eject=False)
        self.assertIsNone(result)
        self.mocks["eject"].assert_not_called()
        self.assertTrue(any("left connected" in line for line in self.log.lines))

    def test_a_failing_cleanup_is_only_a_warning(self):
        priv = FakeSeedPriv(fail_on=app.LINUX_SEED_CLEANUP_SCRIPT)
        self.assertIs(self.run_backend(priv), True)
        self.assertTrue(any(line.startswith("Warning: cleanup failed") for line in self.log.lines))

    def test_the_mount_directory_is_removed(self):
        self.run_backend(FakeSeedPriv())
        self.mocks["rmdir"].assert_called_with(self.mount)


# ---------------------------------------------------------------------------
# 6. The macOS backend
# ---------------------------------------------------------------------------
class MacSeedBackendTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.files = {"ks.cfg": b"# kickstart\n", "README.txt": b"read me\n"}
        self.stage = app.stage_seed_files(self.files)
        self.addCleanup(lambda: shutil.rmtree(self.stage, ignore_errors=True))
        self.mount = self.path("Volumes", LABEL)
        os.makedirs(self.mount)
        self.cmds = []
        self.log = Collector()

        def fake_run_cmd(args, log, check=True, timeout=None, cancel_event=None):
            self.cmds.append(list(args))
            return 0

        self.corrupt_on_unmount = None

        def fake_unmount(dev, log, check=True, force=False):
            self.cmds.append(["unmount", dev, check])
            if self.corrupt_on_unmount:
                self.corrupt_on_unmount()

        patches = {
            "run_cmd": mock.patch.object(app, "run_cmd", side_effect=fake_run_cmd),
            "find": mock.patch.object(app, "macos_find_mountpoint_by_volname", return_value=self.mount),
            "unmount": mock.patch.object(app, "macos_unmount", side_effect=fake_unmount),
            "eject": mock.patch.object(app, "macos_eject", side_effect=lambda *a, **k: self.cmds.append(["eject"])
                                       or True),
            "audit": mock.patch.object(app, "audit"),
        }
        self.mocks = {}
        for name, patch in patches.items():
            self.mocks[name] = patch.start()
            self.addCleanup(patch.stop)

    def run_backend(self, **kw):
        return app.macos_build_seed_usb(LABEL, self.files, self.stage, "disk9", self.log, **kw)

    def test_success_sequence(self):
        self.assertIs(self.run_backend(), True)
        erase = ["diskutil", "eraseDisk", "FAT32", LABEL, "GPT", "/dev/disk9"]
        self.assertEqual(self.cmds[0], erase)
        self.assertEqual(self.cmds[1], ["sync"])
        self.assertEqual(self.cmds[2], ["unmount", "disk9", True])
        self.assertEqual(self.cmds[3], ["diskutil", "mountDisk", "/dev/disk9"])
        self.assertEqual(self.cmds[-1], ["eject"])
        for rel, data in self.files.items():
            with open(os.path.join(self.mount, rel), "rb") as fh:
                self.assertEqual(fh.read(), data)
        self.mocks["find"].assert_called_with("disk9", LABEL)

    def test_the_label_is_a_single_argument_never_joined_into_text(self):
        self.run_backend()
        self.assertIn(LABEL, self.cmds[0])
        self.assertEqual(len([a for a in self.cmds[0] if LABEL in a]), 1)

    def test_verification_mismatch_does_not_eject(self):
        def corrupt():
            with open(os.path.join(self.mount, "ks.cfg"), "wb") as fh:
                fh.write(b"# tampered\n")

        self.corrupt_on_unmount = corrupt
        with self.assertRaisesRegex(RuntimeError, "Verification FAILED.*ks.cfg"):
            self.run_backend()
        self.assertNotIn(["eject"], self.cmds)

    def test_cancel_before_the_erase_runs_nothing(self):
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(app.OperationCanceled) as ctx:
            self.run_backend(cancel_event=cancel)
        self.assertFalse(ctx.exception.drive_touched)
        self.assertEqual(self.cmds, [])

    def test_cancel_while_copying_unmounts_and_does_not_eject(self):
        cancel = threading.Event()
        progress = lambda done, total, text: cancel.set() if text == "Copying files..." else None  # noqa: E731
        with self.assertRaises(app.OperationCanceled) as ctx:
            self.run_backend(progress=progress, cancel_event=cancel)
        self.assertTrue(ctx.exception.drive_touched)
        self.assertFalse(ctx.exception.written)
        self.assertEqual(self.cmds[-1], ["unmount", "disk9", False])
        self.assertNotIn(["eject"], self.cmds)

    def test_cancel_during_verification_is_marked_written(self):
        cancel = threading.Event()
        self.corrupt_on_unmount = cancel.set
        with self.assertRaises(app.OperationCanceled) as ctx:
            self.run_backend(cancel_event=cancel)
        self.assertTrue(ctx.exception.written)
        self.assertNotIn(["eject"], self.cmds)

    def test_no_eject(self):
        self.assertIsNone(self.run_backend(eject=False))
        self.assertNotIn(["eject"], self.cmds)

    def test_eject_failure_is_reported_not_raised(self):
        self.mocks["eject"].side_effect = lambda *a, **k: False
        self.assertIs(self.run_backend(), False)


# ---------------------------------------------------------------------------
# 7. Copy and verification helpers
# ---------------------------------------------------------------------------
class SeedCopyVerifyTests(TempDirTestCase):
    def test_staged_files_are_private_and_complete(self):
        files = {"a/b/c.txt": b"1", "d": b"2"}
        stage = app.stage_seed_files(files)
        self.addCleanup(lambda: shutil.rmtree(stage, ignore_errors=True))
        self.assertEqual(stat.S_IMODE(os.stat(stage).st_mode), 0o700)
        with open(os.path.join(stage, "a", "b", "c.txt"), "rb") as fh:
            self.assertEqual(fh.read(), b"1")
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(stage, "d")).st_mode), 0o600)

    def test_a_path_that_would_leave_the_directory_is_refused_even_if_validation_was_skipped(self):
        with self.assertRaises(ValueError):
            app.stage_seed_files({"../escape": b"x"})
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(self.tmp), "escape")))

    def test_staging_failure_leaves_no_directory_behind(self):
        before = set(os.listdir(tempfile.gettempdir()))
        with self.assertRaises(ValueError):
            app.stage_seed_files({"fine": b"x", "../escape": b"y"})
        leftovers = [d for d in set(os.listdir(tempfile.gettempdir())) - before if d.startswith("epmaseed_")]
        self.assertEqual(leftovers, [])

    def test_copy_then_verify_roundtrip_with_nested_folders(self):
        files = {"sources/$OEM$/$$/Setup/Scripts/SetupComplete.cmd": b"@echo off\r\n", "autounattend.xml": b"<x/>"}
        stage = app.stage_seed_files(files)
        self.addCleanup(lambda: shutil.rmtree(stage, ignore_errors=True))
        dst = self.path("drive")
        os.makedirs(dst)
        with mock.patch.object(app, "run_cmd", return_value=0):
            app.copy_seed_files(stage, dst, files, Collector())
        app.verify_seed_files(files, dst, Collector())
        with open(os.path.join(dst, "sources", "$OEM$", "$$", "Setup", "Scripts", "SetupComplete.cmd"), "rb") as fh:
            self.assertEqual(fh.read(), b"@echo off\r\n")

    def test_verify_reports_each_kind_of_difference(self):
        dst = self.path("drive")
        os.makedirs(dst)
        files = {"same": b"abc", "changed": b"abc", "short": b"abcd", "gone": b"x"}
        for name, data in (("same", b"abc"), ("changed", b"abd"), ("short", b"ab")):
            with open(os.path.join(dst, name), "wb") as fh:
                fh.write(data)
        with self.assertRaises(RuntimeError) as ctx:
            app.verify_seed_files(files, dst, Collector())
        text = str(ctx.exception)
        self.assertIn("3 file(s)", text)
        self.assertIn("NOT ejected", text)
        self.assertTrue(app._is_verification_failure(ctx.exception))

    def test_a_symlink_is_not_accepted_as_the_file(self):
        dst = self.path("drive")
        os.makedirs(dst)
        with open(self.path("real"), "wb") as fh:
            fh.write(b"abc")
        os.symlink(self.path("real"), os.path.join(dst, "link"))
        with self.assertRaisesRegex(RuntimeError, "link \\(missing\\)"):
            app.verify_seed_files({"link": b"abc"}, dst, Collector())

    def test_a_longer_file_on_the_drive_is_a_difference(self):
        dst = self.path("drive")
        os.makedirs(dst)
        with open(os.path.join(dst, "f"), "wb") as fh:
            fh.write(b"abcd")
        with self.assertRaisesRegex(RuntimeError, "size differs"):
            app.verify_seed_files({"f": b"abc"}, dst, Collector())

    def test_manifest_hash_depends_on_names_and_contents(self):
        a = app._seed_manifest_sha256({"x": b"1", "y": b"2"})
        self.assertEqual(a, app._seed_manifest_sha256({"y": b"2", "x": b"1"}))
        self.assertNotEqual(a, app._seed_manifest_sha256({"x": b"1", "y": b"3"}))
        self.assertNotEqual(a, app._seed_manifest_sha256({"x": b"1", "z": b"2"}))
        self.assertNotEqual(app._seed_manifest_sha256({"ab": b"c"}), app._seed_manifest_sha256({"a": b"bc"}))


# ---------------------------------------------------------------------------
# 8. The security guard knows about the seed drive (and notices when it is weakened)
# ---------------------------------------------------------------------------
class GuardTests(unittest.TestCase):
    def run_script(self, name):
        return subprocess.run([sys.executable, os.path.join(ROOT, "output", "auditoria", name)],
                              capture_output=True, text=True, timeout=600)

    def test_the_guard_passes_and_includes_the_seed_rules(self):
        proc = self.run_script("guard_seguranca.py")
        self.assertEqual(proc.returncode, 0, proc.stdout[-3000:])
        self.assertIn("G14", proc.stdout)
        self.assertNotIn("[FALHA]", proc.stdout)

    def test_the_guard_self_test_still_catches_every_regression(self):
        proc = self.run_script("teste_do_guarda.py")
        self.assertEqual(proc.returncode, 0, proc.stdout[-3000:])
        self.assertIn("pendrive de sementes", proc.stdout.lower())


if __name__ == "__main__":
    unittest.main()
