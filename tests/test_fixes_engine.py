"""Tests for the engine / download / extraction / privilege / CLI fixes of the review.

Hermetic: temp directories, fake objects, mocked subprocess. No network, no sudo, nothing under
/dev. The few tests that start a real `bash` do it with stub `dd`/`umount` programs on PATH.
"""
import errno
import json
import os
import signal
import stat
import subprocess
import sys
import threading
import time
import unittest
import zipfile
import zlib
from unittest import mock

from tests.helpers import FAKE_DISKS, MIB, Collector, TempDirTestCase, app, run_main


def wait_until(predicate, timeout=6.0, step=0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(step)
    return predicate()


# ---------------------------------------------------------------------------
# 1 + 8. Missing tools and capacity are refused before anything is touched
# ---------------------------------------------------------------------------
class PreflightTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.iso = self.make_iso("Win11.iso", size=2 * MIB, hybrid=False)

    def test_windows_mode_refuses_when_a_tool_is_missing_and_says_how_to_get_it_on_macos(self):
        with mock.patch.object(app, "IS_MAC", True), \
                mock.patch.object(app, "get_missing_dependencies", return_value=["wimlib-imagex"]):
            with self.assertRaises(ValueError) as ctx:
                app.validate_image_for_mode(self.iso, app.MODE_WINDOWS, 16 * 1024 ** 3)
        text = str(ctx.exception)
        self.assertIn("wimlib-imagex", text)
        self.assertIn("brew install wimlib", text)
        self.assertIn("Nothing was changed", text)

    def test_windows_mode_names_every_missing_linux_tool_and_the_install_command(self):
        missing = ["parted", "mkfs.vfat", "partprobe"]
        with mock.patch.object(app, "IS_MAC", False), \
                mock.patch.object(app, "get_missing_dependencies", return_value=missing), \
                mock.patch.object(app, "linux_detect_pkg_manager", return_value="apt-get"):
            with self.assertRaises(ValueError) as ctx:
                app.validate_image_for_mode(self.iso, app.MODE_WINDOWS, None)
        text = str(ctx.exception)
        for tool in missing:
            self.assertIn(tool, text)
        self.assertIn("apt-get install -y dosfstools parted", text)

    def test_unknown_package_manager_still_gives_a_hint(self):
        with mock.patch.object(app, "IS_MAC", False), \
                mock.patch.object(app, "linux_detect_pkg_manager", return_value=None):
            hint = app.missing_dependencies_hint(["parted"])
        self.assertIn("package manager", hint)

    def test_build_usb_stops_before_anything_is_touched(self):
        calls = {}
        patches = {
            name: mock.patch.object(app, name, **kw)
            for name, kw in (("get_missing_dependencies", {"return_value": ["wimlib-imagex"]}),
                             ("hash_iso_for_audit", {"return_value": "0" * 64}),
                             ("reverify_target_disk", {}),
                             ("macos_build_usb", {}), ("linux_build_usb", {}),
                             ("prevent_sleep", {"return_value": mock.MagicMock()}))
        }
        for name, patch in patches.items():
            calls[name] = patch.start()
            self.addCleanup(patch.stop)
        with self.assertRaisesRegex(ValueError, "wimlib-imagex"):
            app.build_usb(self.iso, "disk9", Collector(), None, expected_size=16 * 1024 ** 3,
                          mode=app.MODE_WINDOWS)
        for name in ("hash_iso_for_audit", "reverify_target_disk", "macos_build_usb", "linux_build_usb"):
            calls[name].assert_not_called()

    def test_windows_mode_refuses_an_iso_larger_than_the_drive(self):
        with mock.patch.object(app, "get_missing_dependencies", return_value=[]):
            with self.assertRaisesRegex(ValueError, "larger than the drive.*Nothing was changed"):
                app.validate_image_for_mode(self.iso, app.MODE_WINDOWS, 1 * MIB)
            # exactly as large as the drive is not "larger"
            self.assertEqual(app.validate_image_for_mode(self.iso, app.MODE_WINDOWS, 2 * MIB),
                             os.path.realpath(self.iso))

    def test_cli_refuses_a_windows_iso_larger_than_the_drive(self):
        disks = [{"id": "disk9", "size": 1 * MIB, "label": "tiny"}]
        with mock.patch.object(app, "get_external_disks", return_value=disks), \
                mock.patch.object(app, "get_missing_dependencies", return_value=[]), \
                mock.patch.object(app, "build_usb") as build:
            code, _out, err = run_main(["write", "--iso", self.iso, "--disk", "disk9", "--mode", "windows",
                                        "--yes"])
        self.assertEqual(code, 1)
        self.assertIn("larger than the drive", err)
        build.assert_not_called()

    def test_cli_missing_tools_message_includes_the_hint(self):
        with mock.patch.object(app, "get_external_disks", return_value=[dict(d) for d in FAKE_DISKS]), \
                mock.patch.object(app, "get_missing_dependencies", return_value=["wimlib-imagex"]), \
                mock.patch.object(app, "IS_MAC", True), mock.patch.object(app, "build_usb") as build:
            code, _out, err = run_main(["write", "--iso", self.iso, "--disk", "disk9", "--mode", "windows",
                                        "--yes"])
        self.assertEqual(code, 1)
        self.assertIn("brew install wimlib", err)
        build.assert_not_called()


# ---------------------------------------------------------------------------
# 2. The CLI pins the identity of the drive it listed
# ---------------------------------------------------------------------------
class CliPinsIdentityTests(TempDirTestCase):
    IDENTITY = (("model", "Fake Stick"), ("serial", "ABC123"))

    def setUp(self):
        super().setUp()
        disk = {"id": "disk9", "size": 16 * 1024 ** 3, "label": "stick", "identity": self.IDENTITY}
        for target, kw in (("get_external_disks", {"return_value": [disk]}),
                           ("get_missing_dependencies", {"return_value": []})):
            patch = mock.patch.object(app, target, **kw)
            patch.start()
            self.addCleanup(patch.stop)
        patch = mock.patch.object(app.CliPrivilege, "authenticate")
        patch.start()
        self.addCleanup(patch.stop)
        self.iso = self.make_iso("ubuntu.iso")
        app._pinned_identities.pop("disk9", None)

    def test_the_identity_is_pinned_when_the_engine_is_called_and_released_afterwards(self):
        seen = {}

        def engine(*_a, **_k):
            seen["pinned"] = app._pinned_identities.get("disk9")
            return True

        with mock.patch.object(app, "build_usb", side_effect=engine):
            code, _out, _err = run_main(["write", "--iso", self.iso, "--disk", "disk9", "--yes"])
        self.assertEqual(code, 0)
        self.assertEqual(seen["pinned"], self.IDENTITY)
        self.assertNotIn("disk9", app._pinned_identities)

    def test_a_different_drive_under_the_same_name_is_refused_by_the_real_recheck(self):
        impostor = {"id": "disk9", "size": 16 * 1024 ** 3, "label": "other",
                    "identity": (("model", "Fake Stick"), ("serial", "ZZZ999"))}
        real_build = app.build_usb
        calls = []

        def relist(*_a, **_k):
            calls.append(1)
            # first listing (the plan) shows the confirmed drive, the re-check sees an impostor
            return [{"id": "disk9", "size": 16 * 1024 ** 3, "label": "stick", "identity": self.IDENTITY}] \
                if len(calls) == 1 else [impostor]

        with mock.patch.object(app, "get_external_disks", side_effect=relist), \
                mock.patch.object(app, "hash_iso_for_audit", return_value="0" * 64), \
                mock.patch.object(app, "prevent_sleep", return_value=mock.MagicMock()), \
                mock.patch.object(app, "linux_write_raw") as lin, mock.patch.object(app, "macos_write_raw") as mac, \
                mock.patch.object(app, "build_usb", side_effect=real_build):
            code, _out, err = run_main(["write", "--iso", self.iso, "--disk", "disk9", "--yes"])
        self.assertEqual(code, 1)
        self.assertIn("no longer looks like the drive you confirmed", err)
        lin.assert_not_called()
        mac.assert_not_called()

    def test_dry_run_json_shows_the_identity_as_an_object(self):
        code, out, _err = run_main(["write", "--iso", self.iso, "--disk", "disk9", "--dry-run", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["identity"], {"model": "Fake Stick", "serial": "ABC123"})

    def test_a_listing_without_identity_pins_nothing(self):
        app.get_external_disks.return_value = [{"id": "disk9", "size": 16 * 1024 ** 3, "label": "stick"}]
        seen = {}

        def engine(*_a, **_k):
            seen["pinned"] = dict(app._pinned_identities)
            return True

        with mock.patch.object(app, "build_usb", side_effect=engine):
            code, _out, _err = run_main(["write", "--iso", self.iso, "--disk", "disk9", "--yes"])
        self.assertEqual(code, 0)
        self.assertNotIn("disk9", seen["pinned"])


# ---------------------------------------------------------------------------
# 3. Ctrl-C reaches the root script: it must ignore SIGINT and stop dd through the flag file
# ---------------------------------------------------------------------------
class RawScriptSigintTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.bin = self.path("bin")
        os.makedirs(self.bin)
        self.pidfile = self.path("dd.pid")
        self.flag = self.path("cancel-flag")
        # Stub dd: records its pid and just sleeps (exec keeps the pid, so SIGTERM stops it).
        self.stub("dd", f'#!/bin/sh\necho $$ > "{self.pidfile}"\nexec sleep 30\n')
        self.stub("umount", "#!/bin/sh\nexit 0\n")
        self.addCleanup(self.reap_stub)

    def stub(self, name, body):
        path = os.path.join(self.bin, name)
        with open(path, "w") as fh:
            fh.write(body)
        os.chmod(path, 0o700)

    def stub_pid(self):
        try:
            with open(self.pidfile) as fh:
                return int(fh.read().strip())
        except (OSError, ValueError):
            return None

    @staticmethod
    def alive(pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True

    def reap_stub(self):
        pid = self.stub_pid()
        if pid and self.alive(pid):
            os.kill(pid, signal.SIGTERM)  # our own stub, never anything else

    def start(self, script, args):
        env = dict(os.environ, PATH=self.bin + os.pathsep + os.environ["PATH"])
        # Own session = own process group, so the SIGINT below reaches only this script and its children.
        return subprocess.Popen(["bash", "-c", script, "win11_usb_creator"] + args, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                start_new_session=True)

    def interrupt_then_cancel(self, proc):
        self.assertTrue(wait_until(lambda: self.stub_pid() is not None), "the stub dd never started")
        os.killpg(proc.pid, signal.SIGINT)   # what a terminal Ctrl-C does
        time.sleep(0.4)
        return proc.poll() is None           # is the script still alive?

    def test_the_scripts_start_with_set_eu_then_ignore_sigint(self):
        for script in (app.MACOS_RAW_SCRIPT, app.LINUX_RAW_SCRIPT, app.VERIFY_RAW_SCRIPT):
            lines = script.splitlines()
            self.assertEqual(lines[0], "set -eu")
            self.assertEqual(lines[1], "trap '' INT")

    def check_raw_script(self, script, args):
        proc = self.start(script, args)
        try:
            self.assertTrue(self.interrupt_then_cancel(proc), "Ctrl-C killed the root script")
            dd_pid = self.stub_pid()
            self.assertTrue(self.alive(dd_pid), "dd died from the Ctrl-C itself (nobody stopped it)")
            open(self.flag, "w").close()     # the app's cancel flag
            out, _ = proc.communicate(timeout=8)
        finally:
            if proc.poll() is None:
                proc.kill()
        self.assertEqual(proc.returncode, 0)
        self.assertIn(app.RAW_CANCELED_MARKER, out)
        self.assertTrue(wait_until(lambda: not self.alive(dd_pid)), "the script left dd running")

    def test_macos_raw_script_survives_ctrl_c_and_stops_dd_through_the_flag(self):
        self.check_raw_script(app.MACOS_RAW_SCRIPT, [self.path("in.iso"), self.path("out.img"), "4m", self.flag])

    def test_linux_raw_script_survives_ctrl_c_and_stops_dd_through_the_flag(self):
        self.check_raw_script(app.LINUX_RAW_SCRIPT,
                              [self.path("in.iso"), self.path("out.img"), "4M", self.flag, "buffered"])

    def test_without_the_trap_ctrl_c_kills_the_script_and_orphans_dd(self):
        """Control experiment: this is the bug the trap fixes."""
        script = app.MACOS_RAW_SCRIPT.replace("trap '' INT\n", "")
        self.assertNotEqual(script, app.MACOS_RAW_SCRIPT)
        proc = self.start(script, [self.path("in.iso"), self.path("out.img"), "4m", self.flag])
        try:
            script_survived = self.interrupt_then_cancel(proc)
            dd_pid = self.stub_pid()
            self.assertFalse(script_survived)
            self.assertTrue(self.alive(dd_pid), "dd should be left behind as an orphan")
        finally:
            self.reap_stub()                  # the orphan holds the pipe open until it is stopped
            if proc.poll() is None:
                proc.kill()
            proc.communicate(timeout=10)

    def test_verify_script_survives_ctrl_c_and_reports_the_cancel(self):
        # A slow `dd` makes the first chunk last long enough to interrupt it.
        self.stub("dd", f'#!/bin/sh\necho $$ > "{self.pidfile}"\nsleep 1.5\n')
        proc = self.start(app.VERIFY_RAW_SCRIPT, [self.path("in.iso"), self.path("dev"), "20", "10", self.flag])
        try:
            self.assertTrue(self.interrupt_then_cancel(proc), "Ctrl-C killed the verification script")
            open(self.flag, "w").close()
            out, _ = proc.communicate(timeout=10)
        finally:
            if proc.poll() is None:
                proc.kill()
        self.assertEqual(proc.returncode, 0)
        self.assertIn("VERIFY_CANCELED", out)


# ---------------------------------------------------------------------------
# 4. Linux Windows-mode prep script mounts the ISO as UDF first
# ---------------------------------------------------------------------------
class LinuxMountTypeTests(TempDirTestCase):
    def prep_script(self):
        scripts = []

        class RecordingPriv:
            cached_password = None

            def run_script(self, script, log, args=None, **_kw):
                scripts.append(script)
                raise RuntimeError("stop here")

        iso = self.make_iso("Win11.iso", hybrid=False)
        with self.assertRaises(RuntimeError):
            app.linux_build_usb(iso, "sdb", Collector(), RecordingPriv())
        return scripts[0]

    def test_the_iso_is_mounted_with_an_explicit_udf_then_iso9660_type(self):
        script = self.prep_script()
        typed = 'mount -t udf,iso9660 -o loop,ro,uid="${OWNER%%:*}",gid="${OWNER##*:}" "$ISO" "$ISO_MNT"'
        untyped = 'mount -o loop,ro,uid="${OWNER%%:*}",gid="${OWNER##*:}" "$ISO" "$ISO_MNT"'
        self.assertIn(typed, script)
        self.assertIn(untyped, script)          # autodetection stays as the last resort (self-test anchor)
        self.assertLess(script.index(typed), script.index(untyped))
        self.assertTrue(script.startswith("set -eu\n"))

    def test_the_script_is_valid_shell(self):
        result = subprocess.run(["bash", "-n"], input=self.prep_script(), text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)


# ---------------------------------------------------------------------------
# 5. extract_disk_image turns every damaged-archive failure into a ValueError
# ---------------------------------------------------------------------------
class ExtractionErrorTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.dest = self.path("out")
        os.makedirs(self.dest)

    def make_zip(self, compression=zipfile.ZIP_STORED, data=None, name="flex.bin"):
        path = self.path("flex.zip")
        with zipfile.ZipFile(path, "w", compression) as zf:
            zf.writestr(name, data if data is not None else bytes(2 * MIB))
        return path

    def assert_clean_failure(self, zip_path, pattern):
        with self.assertRaisesRegex(ValueError, pattern):
            app.extract_disk_image(zip_path, self.dest)
        self.assertEqual(os.listdir(self.dest), [], "no half-written file may be left behind")

    def test_a_corrupt_deflate_stream(self):
        zip_path = self.make_zip(zipfile.ZIP_DEFLATED, os.urandom(300_000) + bytes(2 * MIB))
        with open(zip_path, "r+b") as fh:        # damage the middle of the compressed data
            fh.seek(150_000)
            fh.write(b"\xff" * 4096)
        self.assert_clean_failure(zip_path, "damaged")

    def test_zlib_error_from_the_reader(self):
        zip_path = self.make_zip()
        with mock.patch.object(zipfile.ZipExtFile, "read", side_effect=zlib.error("incorrect header check")):
            self.assert_clean_failure(zip_path, "damaged")

    def test_truncated_stream(self):
        zip_path = self.make_zip()
        with mock.patch.object(zipfile.ZipExtFile, "read", side_effect=EOFError("Truncated")):
            self.assert_clean_failure(zip_path, "damaged")

    def test_unsupported_compression(self):
        zip_path = self.make_zip()
        with mock.patch.object(zipfile.ZipFile, "open", side_effect=NotImplementedError("compression type 99")):
            self.assert_clean_failure(zip_path, "not supported")

    def test_encrypted_entry(self):
        zip_path = self.make_zip()
        with mock.patch.object(zipfile.ZipFile, "open", side_effect=RuntimeError("File is encrypted")):
            self.assert_clean_failure(zip_path, "not supported")

    def test_cancel_is_still_a_cancel(self):
        zip_path = self.make_zip()
        event = threading.Event()
        event.set()
        with self.assertRaises(app.OperationCanceled):
            app.extract_disk_image(zip_path, self.dest, cancel_event=event)
        self.assertEqual(os.listdir(self.dest), [])

    def test_a_good_archive_still_extracts(self):
        out = app.extract_disk_image(self.make_zip(), self.dest)
        self.assertEqual(os.path.getsize(out), 2 * MIB)

    # ---- 13: the temporary file is never written through a symlink ----
    def test_a_symlink_at_the_temp_name_is_replaced_not_followed(self):
        victim = self.write_file("victim.txt", b"precious")
        os.symlink(victim, os.path.join(self.dest, "flex.bin.part"))
        out = app.extract_disk_image(self.make_zip(), self.dest)
        with open(victim, "rb") as fh:
            self.assertEqual(fh.read(), b"precious")
        self.assertEqual(os.path.getsize(out), 2 * MIB)
        self.assertFalse(os.path.islink(out))

    def test_a_stale_part_file_is_removed_and_the_new_one_is_private(self):
        self.write_file("out/flex.bin.part", b"stale")
        out = app.extract_disk_image(self.make_zip(), self.dest)
        self.assertEqual(os.path.getsize(out), 2 * MIB)
        self.assertEqual(stat.S_IMODE(os.stat(out).st_mode) & 0o077, 0)


class FetchChromeosExistingZipTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.dest = self.path("dl")
        os.makedirs(self.dest)
        self.zip_path = os.path.join(self.dest, "chromeos_flex_latest.bin.zip")
        with zipfile.ZipFile(self.zip_path, "w") as zf:
            zf.writestr("chromeos_flex.bin", os.urandom(2 * MIB))

    def test_a_complete_zip_is_extracted_again_not_refused_and_not_downloaded(self):
        with mock.patch.object(app, "download_file_blocking") as download:
            code, out, err = run_main(["fetch-chromeos", "--dest", self.dest, "--json"])
        self.assertEqual(code, 0, err)
        download.assert_not_called()
        data = json.loads(out)
        self.assertTrue(os.path.isfile(data["image"]))
        self.assertTrue(data["kept_zip"])                      # a ZIP that was already there is not deleted
        self.assertTrue(os.path.exists(self.zip_path))
        self.assertIn("extracting it again", err)

    def test_a_failed_extraction_keeps_the_zip_and_says_what_to_do_next(self):
        with mock.patch.object(app, "extract_disk_image", side_effect=ValueError("Not enough free space in x")):
            code, _out, err = run_main(["fetch-chromeos", "--dest", self.dest])
        self.assertEqual(code, 1)
        self.assertIn("Not enough free space", err)
        self.assertIn("run 'epma-usb-creator fetch-chromeos' again to extract it", err)
        self.assertNotIn("Remove it", err)
        self.assertTrue(os.path.exists(self.zip_path))

    def test_an_unfinished_part_file_still_means_download(self):
        self.write_file("dl/chromeos_flex_latest.bin.zip.part", b"half")
        with mock.patch.object(app, "download_file_blocking", return_value="ab" * 32) as download:
            code, _out, _err = run_main(["fetch-chromeos", "--dest", self.dest])
        self.assertEqual(code, 0)
        download.assert_called_once()


# ---------------------------------------------------------------------------
# 6. Cancel: was the drive touched?
# ---------------------------------------------------------------------------
class CancelContractTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.iso = self.make_iso("ubuntu.iso", size=2 * MIB)
        self.audits = []
        self.mocks = {}
        for name, kw in (("audit", {"side_effect": lambda msg, level=None: self.audits.append(msg)}),
                         ("get_missing_dependencies", {"return_value": []}),
                         ("reverify_target_disk", {}),
                         ("prevent_sleep", {"return_value": mock.MagicMock()}),
                         ("macos_write_raw", {}), ("linux_write_raw", {}),
                         ("macos_build_usb", {}), ("linux_build_usb", {})):
            patch = mock.patch.object(app, name, **kw)
            self.mocks[name] = patch.start()
            self.addCleanup(patch.stop)

    def build(self, cancel_event=None, is_mac=True, mode=app.MODE_LINUX):
        with mock.patch.object(app, "IS_MAC", is_mac):
            return app.build_usb(self.iso, "disk9", Collector(), None, expected_size=16 * 1024 ** 3,
                                 mode=mode, cancel_event=cancel_event)

    def test_defaults(self):
        e = app.OperationCanceled("x")
        self.assertTrue(e.drive_touched)
        self.assertFalse(e.written)
        self.assertTrue(app.OperationCanceled().drive_touched)
        self.assertFalse(app.OperationCanceled("x", drive_touched=False).drive_touched)

    def test_canceled_while_hashing_leaves_the_drive_untouched(self):
        event = threading.Event()
        event.set()
        with self.assertRaises(app.OperationCanceled) as ctx:
            self.build(cancel_event=event)
        self.assertFalse(ctx.exception.drive_touched)
        self.assertTrue(any("before the drive was touched" in a for a in self.audits), self.audits)
        self.assertFalse(any("left unusable" in a for a in self.audits))
        self.mocks["macos_write_raw"].assert_not_called()

    def test_canceled_just_before_the_destructive_step(self):
        event = threading.Event()

        def hash_then_cancel(*_a, **_k):
            event.set()
            return "0" * 64

        with mock.patch.object(app, "hash_iso_for_audit", side_effect=hash_then_cancel):
            with self.assertRaises(app.OperationCanceled) as ctx:
                self.build(cancel_event=event)
        self.assertFalse(ctx.exception.drive_touched)
        self.assertFalse(any(a.startswith("DESTRUCTIVE OPERATION START") for a in self.audits))

    def test_canceled_during_the_write_means_an_unusable_drive(self):
        self.mocks["macos_write_raw"].side_effect = app.OperationCanceled("stopped")
        with self.assertRaises(app.OperationCanceled) as ctx:
            self.build()
        self.assertTrue(ctx.exception.drive_touched)
        self.assertTrue(any("left unusable" in a for a in self.audits))

    def test_canceled_during_verification_says_written_but_not_verified(self):
        self.mocks["macos_write_raw"].side_effect = app.OperationCanceled("stopped", written=True)
        with self.assertRaises(app.OperationCanceled) as ctx:
            self.build()
        self.assertTrue(ctx.exception.written)
        self.assertTrue(any("written but NOT verified" in a for a in self.audits), self.audits)
        self.assertFalse(any("left unusable" in a for a in self.audits))

    def test_verify_raw_write_cancel_is_marked_as_written(self):
        class CancelingPriv:
            def run_script(self, script, log, args=None, **_kw):
                log("VERIFY_CANCELED")

        log = Collector()
        with self.assertRaises(app.OperationCanceled) as ctx:
            app.verify_raw_write(self.iso, "/dev/null-test", log, CancelingPriv(), None)
        self.assertTrue(ctx.exception.written)
        self.assertTrue(ctx.exception.drive_touched)
        self.assertTrue(any("NOT verified" in line for line in log.lines))

    def test_verify_raw_write_cancel_before_start_is_marked_as_written(self):
        event = threading.Event()
        event.set()
        with self.assertRaises(app.OperationCanceled) as ctx:
            app.verify_raw_write(self.iso, "/dev/null-test", Collector(), mock.MagicMock(), None, event)
        self.assertTrue(ctx.exception.written)

    def test_check_canceled_passes_the_state_on(self):
        event = threading.Event()
        event.set()
        with self.assertRaises(app.OperationCanceled) as ctx:
            app.check_canceled(event, drive_touched=False)
        self.assertFalse(ctx.exception.drive_touched)
        app.check_canceled(None)
        app.check_canceled(threading.Event())


class BackendsCanceledEarlyTests(TempDirTestCase):
    def test_backends_cancelled_before_they_start_do_not_touch_the_drive(self):
        self.iso = self.make_iso("ubuntu.iso", size=2 * MIB)
        event = threading.Event()
        event.set()
        priv = mock.MagicMock()
        with mock.patch.object(app, "run_cmd") as run_cmd:
            for fn, args in ((app.macos_write_raw, (self.iso, "disk9", Collector(), priv)),
                             (app.linux_write_raw, (self.iso, "sdb", Collector(), priv)),
                             (app.macos_build_usb, (self.iso, "disk9", Collector())),
                             (app.linux_build_usb, (self.iso, "sdb", Collector(), priv))):
                with self.subTest(fn=fn.__name__):
                    with self.assertRaises(app.OperationCanceled) as ctx:
                        fn(*args, cancel_event=event)
                    self.assertFalse(ctx.exception.drive_touched)
        run_cmd.assert_not_called()
        priv.run_script.assert_not_called()


# ---------------------------------------------------------------------------
# 7. Sleep inhibitor
# ---------------------------------------------------------------------------
class PreventSleepTests(unittest.TestCase):
    class FakeProc:
        pid = 4242

        def __init__(self, running=True):
            self.running = running

        def wait(self, timeout=None):
            if self.running:
                raise subprocess.TimeoutExpired("systemd-inhibit", timeout)
            return 1

    def run_ctx(self, proc, after=None):
        log = Collector()
        popen = mock.MagicMock(return_value=proc)
        with mock.patch.object(app, "IS_MAC", False), mock.patch.object(app, "IS_LINUX", True), \
                mock.patch.object(app.shutil, "which", return_value="/usr/bin/systemd-inhibit"), \
                mock.patch.object(app.subprocess, "Popen", popen), \
                mock.patch.object(app, "_stop_process") as stop, \
                mock.patch.object(app.atexit, "register") as register, \
                mock.patch.object(app.atexit, "unregister") as unregister:
            with app.prevent_sleep(log):
                pass
            if after:
                after(stop, register)
        return log, popen, stop, register, unregister

    def test_the_sleep_is_bounded_and_cleaned_up_at_exit(self):
        log, popen, stop, register, unregister = self.run_ctx(self.FakeProc(running=True))
        cmd = popen.call_args.args[0]
        self.assertEqual(cmd[-2:], ["sleep", str(app.SLEEP_INHIBIT_SECONDS)])
        self.assertNotIn("infinity", cmd)
        self.assertEqual(app.SLEEP_INHIBIT_SECONDS, 12 * 3600)
        register.assert_called_once()
        unregister.assert_called_once_with(register.call_args.args[0])
        stop.assert_called_once()
        self.assertIn("Sleep is blocked while the drive is being written.", log.lines)

    def test_the_atexit_hook_stops_the_process_group(self):
        proc = self.FakeProc(running=True)

        def at_exit(stop, register):
            stop.reset_mock()
            register.call_args.args[0]()      # what the interpreter would call at exit
            stop.assert_called_once_with(proc, group=True)

        self.run_ctx(proc, after=at_exit)

    def test_an_inhibitor_that_exits_at_once_is_not_reported_as_blocking(self):
        log, _popen, stop, register, _unregister = self.run_ctx(self.FakeProc(running=False))
        self.assertNotIn("Sleep is blocked while the drive is being written.", log.lines)
        register.assert_not_called()
        stop.assert_not_called()


# ---------------------------------------------------------------------------
# 9. Case-insensitive "sources" lookup
# ---------------------------------------------------------------------------
class CaseInsensitiveSourcesTests(TempDirTestCase):
    def test_find_case_insensitive(self):
        self.write_file("iso/Sources/Install.WIM", b"x")
        self.assertEqual(app.find_case_insensitive(self.path("iso"), "sources"), self.path("iso", "Sources"))
        self.assertEqual(app.find_case_insensitive(self.path("iso", "Sources"), "install.wim"),
                         self.path("iso", "Sources", "Install.WIM"))
        self.assertIsNone(app.find_case_insensitive(self.path("iso"), "nothing"))
        self.assertIsNone(app.find_case_insensitive(self.path("missing-dir"), "sources"))

    def copy(self, rel):
        self.write_file(f"iso/{rel}", b"wim data" * 100)
        self.write_file("iso/BOOTMGR", b"boot")
        os.makedirs(self.path("usb"))
        commands = []

        def fake_run_cmd(args, log, check=True, timeout=None, cancel_event=None):
            commands.append(list(args))
            return 0

        with mock.patch.object(app, "run_cmd", fake_run_cmd):
            app.copy_windows_payload(self.path("iso"), self.path("usb"), Collector(), None, "no wimlib")
        return commands

    def test_mixed_case_directory_and_file_are_found(self):
        commands = self.copy("Sources/Install.wim")
        rsync = next(c for c in commands if c[:2] == ["rsync", "-rv"])
        self.assertIn("--exclude=Sources/Install.wim", rsync)    # the real spelling, not "sources/install.wim"
        copied = [n for n in os.listdir(self.path("usb")) if n.lower() == "sources"]
        self.assertEqual(len(copied), 1)
        self.assertTrue(os.path.isfile(self.path("usb", copied[0], "Install.wim")))

    def test_upper_case_esd(self):
        commands = self.copy("SOURCES/INSTALL.ESD")
        rsync = next(c for c in commands if c[:2] == ["rsync", "-rv"])
        self.assertIn("--exclude=SOURCES/INSTALL.ESD", rsync)

    def test_still_fails_clearly_without_an_install_image(self):
        self.write_file("iso/Sources/boot.wim", b"x")
        with self.assertRaisesRegex(RuntimeError, "Could not find sources/install.wim"):
            app.copy_windows_payload(self.path("iso"), self.path("usb"), Collector(), None, "h")


# ---------------------------------------------------------------------------
# 10, 11, 13. Download: redirects, local write errors, symlinks
# ---------------------------------------------------------------------------
class FakeResponse:
    def __init__(self, final_url, body, headers=None, fail_with=None):
        self._final, self._body, self._pos, self._fail = final_url, body, 0, fail_with
        self.status = 200
        self.headers = {"Content-Length": str(len(body)), "ETag": '"abc"', **(headers or {})}

    def geturl(self):
        return self._final

    def getcode(self):
        return self.status

    def read(self, n=-1):
        if self._fail is not None and self._pos > 0:
            raise self._fail
        size = min(n if n and n > 0 else len(self._body), 4 if self._fail is not None else len(self._body))
        chunk = self._body[self._pos:self._pos + size]
        self._pos += len(chunk)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class DownloadTestCase(TempDirTestCase):
    MS = "https://software.download.prss.microsoft.com/Win11.iso"

    def setUp(self):
        super().setUp()
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        for var in (app.ENV_ALLOW_ANY_HOST, app.ENV_TRUSTED_HOSTS):
            os.environ.pop(var, None)
        patch = mock.patch.object(app, "DOWNLOAD_BACKOFF_SECONDS", (0, 0))
        patch.start()
        self.addCleanup(patch.stop)
        self.dest = self.path("Win11.iso")

    def download(self, url, responses, allowed_hosts=None):
        """Run a DownloadThread whose connections return `responses` in turn. Returns (outcome, opens)."""
        outcome, opens = {}, []
        queue = list(responses)

        def fake_open(_self, offset, validator):
            opens.append((offset, validator))
            return queue.pop(0) if len(queue) > 1 else queue[0]

        thread = app.DownloadThread(
            url, self.dest, progress_cb=lambda *_a: None,
            done_cb=lambda path, sha, _v: outcome.update(done=(path, sha)),
            error_cb=lambda msg: outcome.update(error=msg), cancel_event=threading.Event(),
            allowed_hosts=allowed_hosts)
        with mock.patch.object(app.DownloadThread, "_open", fake_open):
            thread.start()
            thread.join(15)
        return outcome, opens


class RedirectTrustTests(DownloadTestCase):
    def test_trusted_origin_redirected_to_an_untrusted_host_is_refused_and_discarded(self):
        outcome, _ = self.download(self.MS, [FakeResponse("https://evil.example.com/Win11.iso", b"payload")])
        self.assertIn("not trusted", outcome["error"])
        self.assertIn("evil.example.com", outcome["error"])
        self.assertNotIn("done", outcome)
        self.assertFalse(os.path.exists(self.dest))
        self.assertFalse(os.path.exists(self.dest + ".part"))
        self.assertFalse(os.path.exists(self.dest + ".part.meta"))

    def test_look_alike_hosts_are_untrusted_too(self):
        for host in ("microsoft.com.evil.example", "notmicrosoft.com"):
            with self.subTest(host=host):
                outcome, _ = self.download(self.MS, [FakeResponse(f"https://{host}/x.iso", b"payload")])
                self.assertIn("not trusted", outcome["error"])

    def test_trusted_to_trusted_is_fine(self):
        outcome, _ = self.download(self.MS, [FakeResponse("https://download.microsoft.com/Win11.iso", b"payload")])
        self.assertNotIn("error", outcome)
        with open(self.dest, "rb") as fh:
            self.assertEqual(fh.read(), b"payload")

    def test_an_origin_the_user_already_accepted_as_untrusted_keeps_todays_behaviour(self):
        outcome, _ = self.download("https://downloads.example.org/a.iso",
                                   [FakeResponse("https://cdn.other.example/a.iso", b"payload")])
        self.assertNotIn("error", outcome)

    def test_the_allow_any_host_switch_disables_the_rule(self):
        os.environ[app.ENV_ALLOW_ANY_HOST] = "1"
        outcome, _ = self.download(self.MS, [FakeResponse("https://evil.example.com/Win11.iso", b"payload")])
        self.assertNotIn("error", outcome)

    def test_downgrade_to_http_is_still_refused(self):
        outcome, _ = self.download(self.MS, [FakeResponse("http://software.download.prss.microsoft.com/x", b"p")])
        self.assertIn("error", outcome)
        self.assertFalse(os.path.exists(self.dest))

    def test_flex_downloads_keep_using_their_own_host_list(self):
        outcome, _ = self.download(app.CHROMEOS_FLEX_URL,
                                   [FakeResponse("https://dl.google.com/dl/edgedl/x.bin.zip", b"flex")],
                                   allowed_hosts=app.CHROMEOS_FLEX_HOSTS)
        self.assertNotIn("error", outcome)


class LocalWriteErrorTests(DownloadTestCase):
    def test_a_full_disk_stops_at_once_and_deletes_the_partial_file(self):
        failing = FakeResponse(self.MS, b"x" * 64, fail_with=OSError(errno.ENOSPC, "No space left on device"))
        outcome, opens = self.download(self.MS, [failing])
        self.assertEqual(len(opens), 1, "a full disk must not be retried")
        self.assertIn("not enough free space", outcome["error"])
        self.assertIn("deleted", outcome["error"])
        self.assertNotIn("done", outcome)
        self.assertFalse(os.path.exists(self.dest + ".part"))
        self.assertFalse(os.path.exists(self.dest + ".part.meta"))

    def test_the_other_local_errors_are_not_retried_either(self):
        expected = {errno.EROFS: "read-only", errno.EACCES: "not allowed to write", errno.EPERM: "not allowed to write"}
        for code, text in expected.items():
            with self.subTest(errno=errno.errorcode[code]):
                failing = FakeResponse(self.MS, b"x" * 64, fail_with=OSError(code, "nope"))
                outcome, opens = self.download(self.MS, [failing])
                self.assertEqual(len(opens), 1)
                self.assertIn(text, outcome["error"])
                self.assertFalse(os.path.exists(self.dest + ".part"))

    def test_a_network_reset_is_still_retried_and_the_partial_file_kept(self):
        failing = FakeResponse(self.MS, b"x" * 64, fail_with=ConnectionResetError(errno.ECONNRESET, "reset"))
        outcome, opens = self.download(self.MS, [failing])
        self.assertEqual(len(opens), app.DOWNLOAD_MAX_ATTEMPTS)
        self.assertIn("interrupted", outcome["error"])
        self.assertTrue(os.path.exists(self.dest + ".part"))


class DownloadSymlinkTests(DownloadTestCase):
    def test_symlinked_part_and_meta_files_are_dropped_not_followed(self):
        victim = self.write_file("victim-part.txt", b"precious part")
        victim_meta = self.write_file("victim-meta.txt", b"precious meta")
        os.symlink(victim, self.dest + ".part")
        os.symlink(victim_meta, self.dest + ".part.meta")
        outcome, _ = self.download(self.MS, [FakeResponse(self.MS, b"fresh payload")])
        self.assertNotIn("error", outcome)
        with open(self.dest, "rb") as fh:
            self.assertEqual(fh.read(), b"fresh payload")
        for path, content in ((victim, b"precious part"), (victim_meta, b"precious meta")):
            with open(path, "rb") as fh:
                self.assertEqual(fh.read(), content)

    def test_the_validator_is_not_written_through_a_symlink(self):
        victim = self.write_file("victim-meta.txt", b"precious meta")
        thread = app.DownloadThread(self.MS, self.dest, lambda *_a: None, lambda *_a: None, lambda *_a: None,
                                    threading.Event())
        os.symlink(victim, thread._meta_path())
        thread._write_validator('"etag"')
        self.assertIsNone(thread._read_validator())
        with open(victim, "rb") as fh:
            self.assertEqual(fh.read(), b"precious meta")

    def test_resuming_a_regular_part_file_still_works(self):
        first = FakeResponse(self.MS, b"0123456789")
        thread_kwargs = {}
        outcome, opens = self.download(self.MS, [first])
        self.assertNotIn("error", outcome, thread_kwargs)
        # now a resume: a valid part + validator, server answers 206
        part = self.dest + ".part"
        with open(part, "wb") as fh:
            fh.write(b"01234")
        thread = app.DownloadThread(self.MS, self.dest, lambda *_a: None, lambda *_a: None, lambda *_a: None,
                                    threading.Event())
        thread._write_validator('"abc"')
        resume = FakeResponse(self.MS, b"56789", headers={"Content-Range": "bytes 5-9/10"})
        resume.status = 206
        outcome2, opens2 = {}, []

        def fake_open(_self, offset, validator):
            opens2.append((offset, validator))
            return resume

        t2 = app.DownloadThread(self.MS, self.dest, lambda *_a: None,
                                lambda path, sha, _v: outcome2.update(done=sha),
                                lambda msg: outcome2.update(error=msg), threading.Event())
        os.remove(self.dest)
        with mock.patch.object(app.DownloadThread, "_open", fake_open):
            t2.start()
            t2.join(10)
        self.assertNotIn("error", outcome2)
        self.assertEqual(opens2, [(5, '"abc"')])
        with open(self.dest, "rb") as fh:
            self.assertEqual(fh.read(), b"0123456789")


# ---------------------------------------------------------------------------
# 12. Output that is not UTF-8 must not abort a copy
# ---------------------------------------------------------------------------
class LenientDecodingTests(unittest.TestCase):
    BAD = "import sys; sys.stdout.buffer.write(b'caf\\xe9 file.txt\\n')"

    def test_run_cmd(self):
        log = Collector()
        app.run_cmd([sys.executable, "-c", self.BAD], log)
        self.assertIn("caf� file.txt", log.lines)

    def test_cli_privilege_run_script_as_root(self):
        log = Collector()
        priv = app.CliPrivilege()
        with mock.patch.object(app.CliPrivilege, "is_root", staticmethod(lambda: True)):
            priv.run_script("printf 'caf\\351 file.txt\\n'", log)
        self.assertIn("caf� file.txt", log.lines)

    def test_privilege_helper_run_script_as_root(self):
        log = Collector()
        helper = app.PrivilegeHelper(None)
        with mock.patch.object(app.os, "geteuid", return_value=0):
            helper.run_script("printf 'caf\\351 file.txt\\n'", log)
        self.assertIn("caf� file.txt", log.lines)


# ---------------------------------------------------------------------------
# 14 + 15. CLI details
# ---------------------------------------------------------------------------
class CliDetailsTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        for target, kw in (("get_external_disks", {"return_value": [dict(d) for d in FAKE_DISKS]}),
                           ("get_missing_dependencies", {"return_value": []})):
            patch = mock.patch.object(app, target, **kw)
            patch.start()
            self.addCleanup(patch.stop)

    def test_a_wrong_confirmation_exits_with_the_usage_code(self):
        iso = self.make_iso("ubuntu.iso")
        with mock.patch.object(app, "_is_interactive", return_value=True), \
                mock.patch.object(app, "build_usb") as build:
            code, _out, err = run_main(["write", "--iso", iso, "--disk", "disk9"], stdin_text="nope\n")
        self.assertEqual(code, 2)
        self.assertEqual(app.EXIT_USAGE, 2)
        self.assertIn("did not match", err)
        build.assert_not_called()

    def test_the_file_name_never_selects_the_windows_mode(self):
        for name in ("darwin-linux.img", "win11.iso", "Windows_install.iso"):
            with self.subTest(name=name):
                path = self.make_iso(name, hybrid=False)
                self.assertEqual(app.cli_detect_kind(path), (app.KIND_UNKNOWN, "none"))
                code, out, _err = run_main(["detect", path, "--json"])
                self.assertEqual(json.loads(out)["kind"], "unknown")

    def test_auto_mode_demands_an_explicit_mode_for_unknown_content(self):
        path = self.make_iso("darwin-linux.img", hybrid=False)
        with mock.patch.object(app, "build_usb") as build:
            code, _out, err = run_main(["write", "--iso", path, "--disk", "disk9", "--yes"])
        self.assertEqual(code, 2)
        self.assertIn("--mode", err)
        build.assert_not_called()

    def test_the_method_stays_accurate(self):
        hybrid = self.make_iso("windows.iso", hybrid=True)           # name says windows, content is hybrid
        self.assertEqual(app.cli_detect_kind(hybrid), (app.MODE_LINUX, "boot-signature"))
        with mock.patch.object(app, "detect_iso_kind", return_value="windows"):
            self.assertEqual(app.cli_detect_kind(hybrid), (app.MODE_WINDOWS, "content"))

    def test_plain_detect_prints_unknown(self):
        code, out, _err = run_main(["detect", self.make_iso("mystery.bin", hybrid=False)])
        self.assertEqual((code, out), (0, "unknown\n"))


if __name__ == "__main__":
    unittest.main()
