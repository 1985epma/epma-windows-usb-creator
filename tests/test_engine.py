import logging
import os
import shutil
import stat
import sys
import unittest
import warnings
from unittest import mock

from tests.helpers import MIB, Collector, LocalPriv, TempDirTestCase, app


class MakeProgressLogTests(unittest.TestCase):
    def test_non_dd_lines_always_pass(self):
        sink = Collector()
        wrapped = app.make_progress_log(sink, interval=5.0)
        for i in range(5):
            wrapped(f"message {i}")
        self.assertEqual(len(sink.lines), 5)

    def test_dd_lines_are_throttled(self):
        sink = Collector()
        wrapped = app.make_progress_log(sink, interval=5.0)
        with mock.patch.object(app.time, "time", side_effect=[100.0, 101.0, 104.9, 105.1, 106.0]):
            for n in range(5):
                wrapped(f"{n * 1000} bytes transferred")
        # kept: t=100 (first) and t=105.1 (>= 5s later)
        self.assertEqual(sink.lines, ["0 bytes transferred", "3000 bytes transferred"])


class MakeDdLogTests(unittest.TestCase):
    def test_bytes_lines_become_progress(self):
        log, progress = Collector(), Collector()
        wrapped = app.make_dd_log(log, 2000, progress)
        wrapped("1000 bytes (1.0 kB) copied, 1 s")
        self.assertEqual(progress.calls, [(1000, 2000, "Writing the image...")])
        self.assertEqual(len(log.lines), 1)

    def test_progress_is_clamped_to_total(self):
        progress = Collector()
        app.make_dd_log(Collector(), 2000, progress)("5000 bytes copied")
        self.assertEqual(progress.calls[0][:2], (2000, 2000))

    def test_other_lines_do_not_report_progress(self):
        log, progress = Collector(), Collector()
        app.make_dd_log(log, 2000, progress)("dd: some warning")
        self.assertEqual(progress.calls, [])
        self.assertEqual(log.lines, ["dd: some warning"])

    def test_no_progress_without_total_or_callback(self):
        log = Collector()
        app.make_dd_log(log, 0, Collector())("100 bytes copied")
        app.make_dd_log(log, 2000, None)("100 bytes copied")
        self.assertEqual(len(log.lines), 2)


class CopyFileWithProgressTests(TempDirTestCase):
    def test_copies_content_and_reports_bytes(self):
        src = self.make_iso("big.bin", size=int(2.5 * MIB))
        os.utime(src, (1_000_000_000, 1_000_000_000))
        dst_dir = self.path("dst")
        os.mkdir(dst_dir)
        seen = []
        app.copy_file_with_progress(src, dst_dir, seen.append)
        dst = os.path.join(dst_dir, "big.bin")
        with open(src, "rb") as a, open(dst, "rb") as b:
            self.assertEqual(a.read(), b.read())
        self.assertEqual(seen, sorted(seen))
        self.assertEqual(seen[-1], os.path.getsize(src))
        self.assertEqual(len(seen), 3)  # 1 MiB chunks: 1, 2, 2.5 MiB
        self.assertEqual(int(os.path.getmtime(dst)), 1_000_000_000)

    def test_empty_file(self):
        src = self.write_file("empty.bin", b"")
        os.mkdir(self.path("d"))
        seen = []
        app.copy_file_with_progress(src, self.path("d"), seen.append)
        self.assertEqual(seen, [])
        self.assertEqual(os.path.getsize(self.path("d", "empty.bin")), 0)


class VerifyRawWriteTests(TempDirTestCase):
    """verify_raw_write with the privileged script run locally against temp files."""

    def setUp(self):
        super().setUp()
        if not shutil.which("bash") or not shutil.which("cmp"):
            self.skipTest("bash/cmp not available")
        # Several chunks even for a small image.
        patcher = mock.patch.object(app, "VERIFY_CHUNK", MIB)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.iso = self.make_iso("image.iso", size=int(2.5 * MIB))
        with open(self.iso, "rb") as fh:
            self.data = fh.read()
        self.priv = LocalPriv()

    def device(self, data):
        return self.write_file("device.img", data)

    def verify(self, device, progress=None):
        log = Collector()
        app.verify_raw_write(self.iso, device, log, self.priv, progress)
        return log

    def test_identical_drive_passes_and_reports_progress(self):
        progress = Collector()
        log = self.verify(self.device(self.data), progress)
        self.assertTrue(any("Verification passed" in line for line in log.lines))
        self.assertTrue(progress.calls)
        done = [c[0] for c in progress.calls]
        self.assertEqual(done, sorted(done))
        self.assertEqual(progress.calls[-1][:2], (len(self.data), len(self.data)))

    def test_drive_larger_than_image_passes(self):
        self.verify(self.device(self.data + b"\0" * 4096))

    def test_script_receives_values_as_arguments(self):
        device = self.device(self.data)
        self.verify(device)
        script, args = self.priv.scripts[0]
        self.assertTrue(script.startswith("set -eu\n"))
        self.assertEqual(args[:3], [self.iso, device, str(len(self.data))])
        self.assertNotIn(self.iso, script)

    def test_corrupt_byte_in_second_chunk_fails(self):
        bad = bytearray(self.data)
        bad[MIB + 17] ^= 0xFF
        with self.assertRaisesRegex(RuntimeError, "Verification FAILED") as ctx:
            self.verify(self.device(bytes(bad)))
        self.assertIn(str(MIB), str(ctx.exception))  # first differing chunk starts at 1 MiB

    def test_corrupt_first_byte_fails(self):
        bad = bytearray(self.data)
        bad[0] ^= 0x01
        with self.assertRaisesRegex(RuntimeError, "NOT ejected"):
            self.verify(self.device(bytes(bad)))

    def test_truncated_drive_fails(self):
        with self.assertRaisesRegex(RuntimeError, "Verification FAILED"):
            self.verify(self.device(self.data[: int(1.5 * MIB)]))

    def test_truncated_in_the_last_chunk_fails(self):
        with self.assertRaisesRegex(RuntimeError, "Verification FAILED"):
            self.verify(self.device(self.data[:-1]))

    def test_empty_drive_fails(self):
        with self.assertRaisesRegex(RuntimeError, "Verification FAILED"):
            self.verify(self.device(b""))

    def test_no_result_marker_is_an_error(self):
        class SilentPriv:
            def run_script(self, script, log, args=None, **_kw):
                log("something unrelated")

        with self.assertRaisesRegex(RuntimeError, "Could not complete the verification"):
            app.verify_raw_write(self.iso, self.device(self.data), Collector(), SilentPriv(), None)


@unittest.skipUnless(shutil.which("rsync"), "rsync not installed")
class WindowsPayloadTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        # run_cmd leaves the child's stdout pipe to the garbage collector.
        warnings_ctx = warnings.catch_warnings()
        warnings_ctx.__enter__()
        self.addCleanup(warnings_ctx.__exit__, None, None, None)
        warnings.simplefilter("ignore", ResourceWarning)
        self.src = self.path("iso")
        self.dst = self.path("usb")
        os.makedirs(self.dst)
        self.files = {
            "bootmgr": b"boot manager",
            "efi/boot/bootx64.efi": os.urandom(5000),
            "sources/boot.wim": os.urandom(20000),
            "sources/install.wim": os.urandom(30000),
            "support/readme.txt": b"hello\n",
        }
        for rel, data in self.files.items():
            self.write_file(os.path.join("iso", rel), data)

    def copy(self, progress=None):
        log = Collector()
        app.copy_windows_payload(self.src, self.dst, log, progress, "wimlib missing hint")
        return log

    def read_dst(self, rel):
        with open(os.path.join(self.dst, rel), "rb") as fh:
            return fh.read()

    def test_copies_everything_verifies_and_reports_progress(self):
        progress = Collector()
        log = self.copy(progress)
        for rel, data in self.files.items():
            with self.subTest(rel=rel):
                self.assertEqual(self.read_dst(rel), data)
        self.assertTrue(any("Verification passed" in line for line in log.lines))
        measured = [c for c in progress.calls if c[1]]  # the verify stage reports (0, 0, text)
        done = [c[0] for c in measured]
        self.assertEqual(done, sorted(done))
        total = sum(len(d) for d in self.files.values())
        self.assertEqual({c[1] for c in measured}, {total})
        self.assertEqual(measured[-1][0], total)
        self.assertTrue(any(c[1] == 0 and "Verifying" in c[2] for c in progress.calls))

    def test_install_esd_is_supported(self):
        os.rename(os.path.join(self.src, "sources", "install.wim"),
                  os.path.join(self.src, "sources", "install.esd"))
        self.copy()
        self.assertEqual(self.read_dst("sources/install.esd"), self.files["sources/install.wim"])

    def test_missing_install_image(self):
        os.remove(os.path.join(self.src, "sources", "install.wim"))
        with self.assertRaisesRegex(RuntimeError, "install.wim or sources/install.esd"):
            self.copy()

    def test_oversized_image_needs_wimlib(self):
        with mock.patch.object(app, "FAT32_MAX_FILE_SIZE", 1000), \
                mock.patch.object(app.shutil, "which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "wimlib missing hint"):
                self.copy()

    def test_verify_detects_a_modified_file(self):
        self.copy()
        with open(os.path.join(self.dst, "efi", "boot", "bootx64.efi"), "r+b") as fh:
            fh.write(b"\xff\xff")
        with self.assertRaisesRegex(RuntimeError, "Verification FAILED"):
            self.verify()

    def test_verify_detects_a_missing_file(self):
        self.copy()
        os.remove(os.path.join(self.dst, "support", "readme.txt"))
        with self.assertRaisesRegex(RuntimeError, "Verification FAILED"):
            self.verify()

    def test_verify_detects_a_damaged_install_image(self):
        self.copy()
        with open(os.path.join(self.dst, "sources", "install.wim"), "r+b") as fh:
            fh.seek(100)
            fh.write(b"\x00\x01\x02")
        with self.assertRaisesRegex(RuntimeError, "install.wim on the drive differs"):
            self.verify()

    def test_verify_passes_on_an_exact_copy(self):
        self.copy()
        self.verify()

    def verify(self):
        big = os.path.join(self.src, "sources", "install.wim")
        app.verify_windows_payload(self.src, self.dst, os.path.join("sources", "install.wim"),
                                   big, Collector(), None)


class EjectTests(unittest.TestCase):
    def run_macos_eject(self, results):
        calls = []

        def fake_run_cmd(args, log, check=True):
            calls.append((list(args), check))
            return results[len(calls) - 1]

        log = Collector()
        with mock.patch.object(app, "run_cmd", fake_run_cmd), mock.patch.object(app.time, "sleep"):
            ok = app.macos_eject("disk4", log)
        return ok, calls

    def test_clean_eject(self):
        ok, calls = self.run_macos_eject([0])
        self.assertTrue(ok)
        self.assertEqual(calls, [(["diskutil", "eject", "/dev/disk4"], False)])

    def test_busy_drive_is_force_unmounted_then_ejected(self):
        ok, calls = self.run_macos_eject([1, 0, 0])
        self.assertTrue(ok)
        self.assertEqual([c[0] for c in calls], [
            ["diskutil", "eject", "/dev/disk4"],
            ["diskutil", "unmountDisk", "force", "/dev/disk4"],
            ["diskutil", "eject", "/dev/disk4"],
        ])

    def test_eject_that_keeps_failing_returns_false(self):
        ok, calls = self.run_macos_eject([1, 0, 1])
        self.assertFalse(ok)
        self.assertEqual(len(calls), 3)

    def test_report_eject_messages(self):
        done, failed = Collector(), Collector()
        app.report_eject(True, done)
        app.report_eject(False, failed)
        self.assertIn("unplug", done.lines[0])
        self.assertIn("Could not eject", failed.lines[0])

    def test_linux_eject_reads_the_marker_line(self):
        class Priv:
            def __init__(self, line):
                self.line = line
                self.args = None

            def run_script(self, script, log, args=None, **_kw):
                self.args = args
                log(self.line)

        yes, no = Priv("EJECTED"), Priv("NOT_EJECTED")
        self.assertTrue(app.linux_eject("sdb", Collector(), yes))
        self.assertFalse(app.linux_eject("sdb", Collector(), no))
        self.assertEqual(yes.args, ["/dev/sdb"])

    def test_linux_eject_failure_is_not_fatal(self):
        class Boom:
            def run_script(self, *_a, **_k):
                raise RuntimeError("no sudo")

        self.assertFalse(app.linux_eject("sdb", Collector(), Boom()))


class MacosAppNameTests(unittest.TestCase):
    def test_noop_off_macos(self):
        fake_ctypes = mock.MagicMock()
        with mock.patch.object(app, "IS_MAC", False), \
                mock.patch.dict(sys.modules, {"ctypes": fake_ctypes, "ctypes.util": fake_ctypes.util}):
            self.assertIsNone(app.set_macos_app_name("epma-usb-creator"))
        fake_ctypes.cdll.LoadLibrary.assert_not_called()

    def test_failures_are_swallowed_on_macos(self):
        fake_ctypes = mock.MagicMock()
        fake_ctypes.cdll.LoadLibrary.side_effect = OSError("no objc")
        with mock.patch.object(app, "IS_MAC", True), \
                mock.patch.dict(sys.modules, {"ctypes": fake_ctypes, "ctypes.util": fake_ctypes.util}):
            self.assertIsNone(app.set_macos_app_name("epma-usb-creator"))
        fake_ctypes.cdll.LoadLibrary.assert_called_once()


class AuditTests(TempDirTestCase):
    def fresh_logger(self, **env):
        """Run with a brand-new audit logger configured by `env`; restore everything after."""
        logger = logging.getLogger("epma.win11usb.audit")
        saved_handlers = list(logger.handlers)
        base = {k: v for k, v in os.environ.items() if k != app.ENV_DISABLE_AUDIT_LOG}
        base.update(env)
        env_patch = mock.patch.dict(os.environ, base, clear=True)
        env_patch.start()
        logger_patch = mock.patch.object(app, "_audit_logger", None)
        logger_patch.start()

        def restore():
            logger_patch.stop()
            env_patch.stop()
            for handler in list(logger.handlers):
                if handler not in saved_handlers:
                    handler.close()
                    logger.removeHandler(handler)

        self.addCleanup(restore)

    def test_never_raises(self):
        with mock.patch.object(app, "get_audit_logger", side_effect=RuntimeError("boom")):
            self.assertIsNone(app.audit("message"))
        broken = mock.MagicMock()
        broken.log.side_effect = OSError("disk full")
        with mock.patch.object(app, "get_audit_logger", return_value=broken):
            self.assertIsNone(app.audit("message", logging.ERROR))

    def test_disabled_by_environment(self):
        self.assertEqual(os.environ.get(app.ENV_DISABLE_AUDIT_LOG), "1")
        self.assertIsNone(app.audit("this goes nowhere"))

    def test_writes_owner_only_log(self):
        log_path = self.path("state", "audit.log")
        self.fresh_logger(**{app.ENV_AUDIT_LOG: log_path})
        app.audit("hello from the tests")
        with open(log_path, encoding="utf-8") as fh:
            self.assertIn("hello from the tests", fh.read())
        self.assertEqual(stat.S_IMODE(os.stat(log_path).st_mode), 0o600)

    def test_unwritable_location_degrades_silently(self):
        blocker = self.write_file("blocker", b"a file, not a directory")
        self.fresh_logger(**{app.ENV_AUDIT_LOG: os.path.join(blocker, "audit.log")})
        self.assertIsNone(app.audit("still fine"))

    def test_log_path_resolution(self):
        with mock.patch.dict(os.environ, {app.ENV_AUDIT_LOG: "~/custom.log"}):
            self.assertEqual(app.audit_log_path(), os.path.expanduser("~/custom.log"))
        env = {k: v for k, v in os.environ.items() if k != app.ENV_AUDIT_LOG}
        env["XDG_STATE_HOME"] = self.tmp
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(app.audit_log_path(),
                             os.path.join(self.tmp, "epma-win11-usb-creator", "audit.log"))


class ImportWithoutTkTests(unittest.TestCase):
    """The engine must import (and fail cleanly) when Tkinter is missing."""

    def run_python(self, code):
        import subprocess

        env = dict(os.environ, WIN11USB_DISABLE_AUDIT_LOG="1")
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return subprocess.run([sys.executable, "-c", code], cwd=root, env=env,
                              capture_output=True, text=True, timeout=60, check=False)

    def test_module_imports_and_gui_refuses_politely(self):
        proc = self.run_python(
            "import sys\n"
            "sys.modules['tkinter'] = None\n"  # makes 'import tkinter' raise ImportError
            "import win11_usb_creator as a\n"
            "assert a.tk is None and a.ttk is None and a.messagebox is None\n"
            "assert a.App.__mro__[1] is object\n"
            "assert 'Tkinter is not available' in a.TK_MISSING_MESSAGE\n"
            "try:\n"
            "    a.App()\n"
            "except RuntimeError as e:\n"
            "    assert str(e) == a.TK_MISSING_MESSAGE\n"
            "else:\n"
            "    raise SystemExit('App() should refuse without Tk')\n"
            "assert a.human_size(1024) == '1.0 KB'\n"
            "print('ok')\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "ok")

    def test_script_without_arguments_prints_hint_and_exits_1(self):
        proc = self.run_python(
            "import sys, runpy\n"
            "sys.modules['tkinter'] = None\n"
            "sys.argv = ['win11_usb_creator.py']\n"
            "runpy.run_path('win11_usb_creator.py', run_name='__main__')\n")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Tkinter is not available", proc.stderr)


if __name__ == "__main__":
    unittest.main()
