import hashlib
import io
import json
import os
import signal
import subprocess
import unittest
from unittest import mock

from tests.helpers import FAKE_DISKS, MIB, Collector, TempDirTestCase, app, run_main


class CliTestCase(TempDirTestCase):
    """Common fixtures: fake drives, no missing tools, no sudo, engine mocked."""

    def setUp(self):
        super().setUp()
        self.disks = mock.patch.object(app, "get_external_disks", return_value=[dict(d) for d in FAKE_DISKS])
        self.disks.start()
        self.addCleanup(self.disks.stop)
        missing = mock.patch.object(app, "get_missing_dependencies", return_value=[])
        missing.start()
        self.addCleanup(missing.stop)
        auth = mock.patch.object(app.CliPrivilege, "authenticate")
        self.authenticate = auth.start()
        self.addCleanup(auth.stop)
        build = mock.patch.object(app, "build_usb", return_value=True)
        self.build_usb = build.start()
        self.addCleanup(build.stop)
        env = mock.patch.dict(os.environ, {"NO_COLOR": "1"})
        env.start()
        self.addCleanup(env.stop)

    def write_args(self, iso, *extra, disk="disk9"):
        return ["write", "--iso", iso, "--disk", disk, *extra]


class VersionAndHelpTests(CliTestCase):
    def test_version(self):
        code, out, err = run_main(["--version"])
        # The version itself is pinned in tests/test_docs_consistency.py (one place to touch on a bump).
        self.assertEqual((code, out, err), (0, f"epma-usb-creator {app.__version__}\n", ""))

    def test_help_documents_commands_and_exit_codes(self):
        code, out, _err = run_main(["--help"])
        self.assertEqual(code, 0)
        for word in ("list", "detect", "sha256", "write", "gui", "exit codes", "130", "NO_COLOR"):
            self.assertIn(word, out)

    def test_help_lists_every_exit_code_and_environment_variable(self):
        # --help is generated from CLI_EXIT_CODE_HELP / CLI_ENV_HELP; this fails when a new
        # EXIT_* or ENV_* constant is added to the program but not to those lists.
        _code, out, _err = run_main(["--help"])
        for name in sorted(n for n in dir(app) if n.startswith("EXIT_")):
            with self.subTest(constant=name):
                self.assertRegex(out, r"(?m)^  " + str(getattr(app, name)) + r" ")
        for name in sorted(n for n in dir(app) if n.startswith("ENV_")):
            value = getattr(app, name)
            if not isinstance(value, str):
                continue
            with self.subTest(constant=name):
                self.assertRegex(out, r"(?m)^  " + value + r" ")
        self.assertRegex(out, r"(?m)^  NO_COLOR ")

    def test_write_help_documents_flags(self):
        code, out, _err = run_main(["write", "--help"])
        self.assertEqual(code, 0)
        for flag in ("--iso", "--disk", "--mode", "--yes", "--dry-run", "--no-eject", "--json"):
            self.assertIn(flag, out)

    def test_there_is_no_way_to_skip_verification(self):
        self.assertNotIn("verify", run_main(["write", "--help"])[1].replace("verify it", ""))
        iso = self.make_iso()
        for flag in ("--no-verify", "--skip-verify", "--no"):
            with self.subTest(flag=flag):
                code, _out, _err = run_main(self.write_args(iso, "--yes", flag))
                self.assertEqual(code, 2)
        self.build_usb.assert_not_called()

    def test_usage_errors_exit_2(self):
        for argv in (["bogus"], ["write"], ["write", "--iso", "x"], ["sha256"], ["list", "--nope"],
                     ["write", "--iso", "x", "--disk", "y", "--mode", "weird"]):
            with self.subTest(argv=argv):
                code, out, err = run_main(argv)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertIn("usage:", err)


class GuiDispatchTests(CliTestCase):
    def test_no_arguments_and_gui_open_the_window(self):
        for argv in ([], ["gui"], ["--debug"]):
            with self.subTest(argv=argv):
                fake_app = mock.MagicMock()
                with mock.patch.object(app, "tk", object()), mock.patch.object(app, "App", fake_app):
                    code, out, err = run_main(argv)
                self.assertEqual((code, out, err), (0, "", ""))
                fake_app.assert_called_once_with()
                fake_app.return_value.mainloop.assert_called_once_with()

    def test_main_reads_sys_argv_by_default(self):
        fake_app = mock.MagicMock()
        with mock.patch.object(app, "tk", object()), mock.patch.object(app, "App", fake_app), \
                mock.patch.object(app.sys, "argv", ["win11_usb_creator.py"]):
            self.assertEqual(app.main(), 0)
        fake_app.return_value.mainloop.assert_called_once_with()

    def test_missing_tk_prints_hint_and_fails(self):
        for argv in ([], ["gui"]):
            with self.subTest(argv=argv):
                with mock.patch.object(app, "tk", None):
                    code, out, err = run_main(argv)
                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertIn(app.TK_MISSING_MESSAGE, err)

    def test_cli_commands_do_not_need_tk(self):
        with mock.patch.object(app, "tk", None):
            self.assertEqual(run_main(["list"])[0], 0)


class ListTests(CliTestCase):
    def test_table(self):
        code, out, _err = run_main(["list"])
        self.assertEqual(code, 0)
        lines = out.splitlines()
        self.assertEqual(lines[0].split(), ["ID", "SIZE", "MODEL", "LABEL"])
        self.assertIn("disk9", lines[1])
        self.assertIn("16.0 GB", lines[1])
        self.assertIn("disk8", lines[2])
        self.assertIn("Fake Stick", lines[2])
        self.assertEqual(len(lines), 3)

    def test_json_shape(self):
        code, out, err = run_main(["list", "--json"])
        self.assertEqual((code, err), (0, ""))
        data = json.loads(out)
        self.assertEqual([d["id"] for d in data["disks"]], ["disk9", "disk8"])
        first = data["disks"][0]
        self.assertEqual(first["size"], 16 * 1024 ** 3)
        self.assertEqual(first["size_human"], "16.0 GB")
        self.assertIn("label", first)
        self.assertEqual(data["disks"][1]["model"], "Fake Stick")

    def test_no_drives(self):
        app.get_external_disks.return_value = []
        code, out, err = run_main(["list"])
        self.assertEqual((code, out), (0, ""))
        self.assertIn("No USB drives", err)
        self.assertEqual(json.loads(run_main(["list", "--json"])[1]), {"disks": []})

    def test_enumeration_failure(self):
        app.get_external_disks.side_effect = FileNotFoundError("diskutil")
        code, out, err = run_main(["list"])
        self.assertEqual((code, out), (1, ""))
        self.assertIn("Could not list the drives", err)
        self.assertNotIn("Traceback", err)

    def test_labels_survive_an_ascii_terminal(self):
        raw = io.BytesIO()
        stream = io.TextIOWrapper(raw, encoding="ascii", errors="strict", write_through=True)
        with mock.patch.object(app.sys, "stdout", stream):
            app._out("disk9 — 16 GB")
        self.assertEqual(raw.getvalue(), b"disk9 ? 16 GB\n")


class DetectTests(CliTestCase):
    def test_signature_heuristic_and_no_filename_guess(self):
        win_named = self.make_iso("Win11_English_x64.iso", hybrid=False)
        ubuntu = self.make_iso("ubuntu-24.04.iso", hybrid=True)
        other = self.make_iso("mystery.iso", hybrid=False)
        self.assertEqual(run_main(["detect", ubuntu])[1], "linux\n")
        self.assertEqual(run_main(["detect", other])[1], "unknown\n")
        # The name alone never selects the destructive Windows mode (see test_fixes_engine).
        self.assertEqual(run_main(["detect", win_named])[1], "unknown\n")

    def test_json(self):
        data = json.loads(run_main(["detect", self.make_iso("ubuntu.iso"), "--json"])[1])
        self.assertEqual(data["kind"], "linux")
        self.assertEqual(data["method"], "boot-signature")
        self.assertTrue(os.path.isabs(data["iso"]))

    def test_uses_the_content_detector(self):
        win_named = self.make_iso("win-looking.iso", hybrid=False)
        with mock.patch.object(app, "detect_iso_kind", return_value="linux") as detector:
            code, out, _err = run_main(["detect", win_named, "--json"])
        detector.assert_called_once_with(win_named)
        self.assertEqual(json.loads(out)["kind"], "linux")
        self.assertEqual(json.loads(out)["method"], "content")

    def test_an_unknown_content_result_falls_back_to_the_boot_signature(self):
        hybrid = self.make_iso("ubuntu.iso", hybrid=True)
        plain = self.make_iso("windows.iso", hybrid=False)
        with mock.patch.object(app, "detect_iso_kind", return_value="unknown"):
            self.assertEqual(run_main(["detect", hybrid])[1], "linux\n")
            self.assertEqual(run_main(["detect", plain])[1], "unknown\n")

    def test_missing_file(self):
        code, out, err = run_main(["detect", self.path("nope.iso")])
        self.assertEqual((code, out), (1, ""))
        self.assertIn("Not a file", err)


class Sha256Tests(CliTestCase):
    def setUp(self):
        super().setUp()
        self.iso = self.write_file("data.iso", b"epma" * 300_000)
        self.digest = hashlib.sha256(b"epma" * 300_000).hexdigest()

    def test_prints_digest_and_filename(self):
        code, out, err = run_main(["sha256", self.iso])
        self.assertEqual(code, 0)
        self.assertEqual(out, f"{self.digest}  {self.iso}\n")
        self.assertIn("%", err)  # progress goes to stderr

    def test_matching_expected_value(self):
        for expected in (self.digest, self.digest.upper(), f"sha256:{self.digest}", f"  {self.digest}\n"):
            with self.subTest(expected=expected):
                code, out, err = run_main(["sha256", self.iso, "--expected", expected])
                self.assertEqual(code, 0)
                self.assertIn(self.digest, out)
                self.assertIn("matches", err)

    def test_mismatch_exits_3_but_still_prints_digest(self):
        code, out, err = run_main(["sha256", self.iso, "--expected", "0" * 64])
        self.assertEqual(code, 3)
        self.assertIn(self.digest, out)
        self.assertIn("does not match", err)

    def test_malformed_expected_is_a_usage_error(self):
        for bad in ("abc", "z" * 64, "0" * 63):
            with self.subTest(bad=bad):
                code, out, err = run_main(["sha256", self.iso, "--expected", bad])
                self.assertEqual((code, out), (2, ""))
                self.assertIn("64-character", err)

    def test_json(self):
        data = json.loads(run_main(["sha256", self.iso, "--json", "--expected", self.digest])[1])
        self.assertEqual(data, {"file": self.iso, "sha256": self.digest, "expected": self.digest, "match": True})
        data = json.loads(run_main(["sha256", self.iso, "--json"])[1])
        self.assertIsNone(data["match"])
        self.assertIsNone(data["expected"])

    def test_missing_file(self):
        code, out, err = run_main(["sha256", self.path("nope")])
        self.assertEqual((code, out), (1, ""))
        self.assertIn("Not a file", err)

    def test_hashing_helper_is_chunked(self):
        seen = []
        digest = app.cli_sha256_file(self.iso, lambda d, t, s: seen.append((d, t)), chunk=500_000)
        self.assertEqual(digest, self.digest)
        self.assertEqual(seen[-1], (1_200_000, 1_200_000))
        self.assertEqual(len(seen), 3)


class WriteValidationTests(CliTestCase):
    def test_everything_is_validated_before_anything_runs(self):
        iso = self.make_iso()
        cases = {
            "not a valid disk identifier": self.write_args(iso, "--yes", disk="disk4; rm -rf /"),
            "not an eligible USB drive": self.write_args(iso, "--yes", disk="disk3"),
            "no longer exists": self.write_args(self.path("nope.iso"), "--yes"),
            "too small": self.write_args(self.write_file("tiny.iso", b"x"), "--yes"),
            "not a bootable hybrid": self.write_args(self.make_iso("plain.iso", hybrid=False),
                                                     "--yes", "--mode", "linux"),
        }
        for fragment, argv in cases.items():
            with self.subTest(fragment=fragment):
                code, out, err = run_main(argv)
                self.assertEqual((code, out), (1, ""))
                self.assertIn(fragment, err)
        self.build_usb.assert_not_called()
        self.authenticate.assert_not_called()

    def test_dev_prefix_is_accepted(self):
        code, out, _err = run_main(self.write_args(self.make_iso(), "--dry-run", disk="/dev/disk9"))
        self.assertEqual(code, 0)
        self.assertIn("/dev/disk9", out)

    def test_auto_mode_needs_a_recognisable_iso(self):
        code, _out, err = run_main(self.write_args(self.make_iso("mystery.iso", hybrid=False), "--yes"))
        self.assertEqual(code, 2)
        self.assertIn("--mode", err)
        self.build_usb.assert_not_called()

    def test_explicit_mode_overrides_detection_with_a_warning(self):
        win = self.make_iso("win11.iso", hybrid=True)
        with mock.patch.object(app, "detect_iso_kind", return_value="windows"):
            code, out, err = run_main(self.write_args(win, "--dry-run", "--mode", "linux"))
        self.assertEqual(code, 0)
        self.assertIn("looks like a windows image", err)
        self.assertIn("Mode : linux", out)

    def test_iso_larger_than_drive_is_refused_for_raw_writes(self):
        app.get_external_disks.return_value = [{"id": "disk9", "size": MIB, "label": "tiny"}]
        code, _out, err = run_main(self.write_args(self.make_iso(size=2 * MIB), "--yes"))
        self.assertEqual(code, 1)
        self.assertIn("larger than the drive", err)
        self.build_usb.assert_not_called()

    def test_missing_tools_are_reported(self):
        app.get_missing_dependencies.return_value = ["wimlib-imagex"]
        code, _out, err = run_main(self.write_args(self.make_iso("win11.iso", hybrid=False), "--yes",
                                                   "--mode", "windows"))
        self.assertEqual(code, 1)
        self.assertIn("wimlib-imagex", err)
        self.build_usb.assert_not_called()


class WriteDryRunTests(CliTestCase):
    def test_prints_plan_and_touches_nothing(self):
        iso = self.make_iso("ubuntu.iso")
        code, out, err = run_main(self.write_args(iso, "--dry-run"))
        self.assertEqual(code, 0)
        for text in ("Plan", "/dev/disk9", "16.0 GB", iso, "Mode : linux", "byte for byte", "Eject the drive"):
            self.assertIn(text, out)
        self.assertIn("Dry run", err)
        self.build_usb.assert_not_called()
        self.authenticate.assert_not_called()

    def test_windows_plan(self):
        iso = self.make_iso("Win11.iso", hybrid=False)
        code, out, _err = run_main(self.write_args(iso, "--dry-run", "--mode", "windows"))
        self.assertEqual(code, 0)
        self.assertIn("GPT + FAT32", out)
        self.assertIn("Mode : windows", out)
        self.assertIn("Verify the copied files", out)

    def test_dry_run_never_needs_confirmation(self):
        self.assertEqual(run_main(self.write_args(self.make_iso(), "--dry-run"))[0], 0)

    def test_json_plan(self):
        iso = self.make_iso("ubuntu.iso", size=2 * MIB)
        code, out, err = run_main(self.write_args(iso, "--dry-run", "--json", "--no-eject"))
        self.assertEqual((code, err), (0, ""))
        plan = json.loads(out)
        self.assertEqual(plan["mode"], "linux")
        self.assertEqual(plan["iso"], iso)
        self.assertEqual(plan["iso_size"], 2 * MIB)
        self.assertEqual(plan["disk"]["id"], "disk9")
        self.assertTrue(plan["dry_run"])
        self.assertFalse(plan["eject"])
        self.assertIn("Leave the drive connected (--no-eject)", plan["steps"][-1])


class WriteConfirmationTests(CliTestCase):
    def setUp(self):
        super().setUp()
        self.iso = self.make_iso()

    def test_non_interactive_without_yes_is_refused(self):
        code, out, err = run_main(self.write_args(self.iso))
        self.assertEqual((code, out), (2, ""))
        self.assertIn("--yes", err)
        self.assertIn("Plan", err)  # the plan was still shown
        self.build_usb.assert_not_called()
        self.authenticate.assert_not_called()

    def test_non_interactive_ignores_typed_input(self):
        code, _out, _err = run_main(self.write_args(self.iso), stdin_text="disk9\n")
        self.assertEqual(code, 2)
        self.build_usb.assert_not_called()

    def test_interactive_user_must_type_the_disk_id(self):
        with mock.patch.object(app, "_is_interactive", return_value=True):
            code, _out, err = run_main(self.write_args(self.iso), stdin_text="disk9\n")
        self.assertEqual(code, 0)
        self.assertIn("Type the disk id (disk9)", err)
        self.build_usb.assert_called_once()

    def test_interactive_wrong_or_empty_answer_aborts(self):
        for answer in ("yes\n", "disk8\n", "\n", "", "DISK9\n", "/dev/disk9\n"):
            with self.subTest(answer=answer):
                self.build_usb.reset_mock()
                with mock.patch.object(app, "_is_interactive", return_value=True):
                    code, _out, err = run_main(self.write_args(self.iso), stdin_text=answer)
                self.assertEqual(code, app.EXIT_USAGE)  # the documented code for a wrong confirmation
                self.assertIn("Nothing was changed", err)
                self.build_usb.assert_not_called()

    def test_yes_skips_the_prompt(self):
        with mock.patch.object(app, "_is_interactive", return_value=True):
            code, _out, err = run_main(self.write_args(self.iso, "--yes"), stdin_text="")
        self.assertEqual(code, 0)
        self.assertNotIn("Type the disk id", err)

    def test_privileges_are_requested_after_confirmation_and_before_the_write(self):
        order = []
        self.authenticate.side_effect = lambda *a, **k: order.append("auth")
        self.build_usb.side_effect = lambda *a, **k: order.append("build") or True
        with mock.patch.object(app, "_is_interactive", return_value=True):
            run_main(self.write_args(self.iso), stdin_text="disk9\n")
        self.assertEqual(order, ["auth", "build"])


class WriteRunTests(CliTestCase):
    def setUp(self):
        super().setUp()
        self.iso = self.make_iso("ubuntu.iso")

    def run_write(self, *extra, **kw):
        return run_main(self.write_args(self.iso, "--yes", *extra), **kw)

    def test_success_passes_the_right_arguments_to_the_engine(self):
        code, out, err = self.run_write()
        self.assertEqual((code, out), (0, ""))
        self.assertIn("ejected", err)
        args, kwargs = self.build_usb.call_args
        self.assertEqual(args[0], self.iso)
        self.assertEqual(args[1], "disk9")
        self.assertIsInstance(args[3], app.CliPrivilege)
        self.assertEqual(kwargs["mode"], app.MODE_LINUX)
        self.assertEqual(kwargs["expected_size"], 16 * 1024 ** 3)
        self.assertTrue(callable(kwargs["progress"]))
        self.assertTrue(callable(args[2]))
        self.authenticate.assert_called_once_with()

    def test_windows_mode_on_macos_needs_no_privileges(self):
        win = self.make_iso("Win11.iso", hybrid=False)
        # Simulate macOS completely: on a Linux machine IS_LINUX alone off would be "no supported system".
        with mock.patch.object(app, "IS_LINUX", False), mock.patch.object(app, "IS_MAC", True):
            code, _out, _err = run_main(self.write_args(win, "--yes", "--mode", "windows"))
        self.assertEqual(code, 0)
        self.authenticate.assert_not_called()
        self.assertEqual(self.build_usb.call_args[1]["mode"], app.MODE_WINDOWS)

    def test_cancel_event_is_passed_to_the_engine(self):
        def engine(iso, dev, log, priv, expected_size=None, mode="windows", progress=None, cancel_event=None,
                   eject=True):
            engine.seen = cancel_event
            return True

        with mock.patch.object(app, "build_usb", engine):
            self.assertEqual(self.run_write()[0], 0)
        self.assertTrue(hasattr(engine.seen, "set"))
        self.assertFalse(engine.seen.is_set())

    def test_json_result_on_success(self):
        code, out, err = self.run_write("--json")
        self.assertEqual(code, 0)
        result = json.loads(out)
        self.assertEqual({k: result[k] for k in ("ok", "mode", "iso", "disk", "verified", "ejected",
                                                 "error", "exit_code")},
                         {"ok": True, "mode": "linux", "iso": self.iso, "disk": "disk9", "verified": True,
                          "ejected": True, "error": None, "exit_code": 0})
        self.assertIn("elapsed_seconds", result)
        self.assertNotIn('"ok"', err)  # stdout carries the data, stderr the messages

    def test_eject_failure_exits_4(self):
        self.build_usb.return_value = False
        code, out, err = self.run_write("--json")
        self.assertEqual(code, 4)
        result = json.loads(out)
        self.assertTrue(result["verified"])
        self.assertFalse(result["ejected"])
        self.assertEqual(result["exit_code"], 4)
        self.assertIn("could not be ejected", err)

    def test_no_eject_is_passed_to_the_engine_and_is_not_a_failure(self):
        self.build_usb.return_value = False
        code, _out, err = self.run_write("--no-eject")
        self.assertEqual(code, 0)  # not ejecting on request is not a failure
        self.assertIs(self.build_usb.call_args.kwargs["eject"], False)
        self.assertIn("left connected", err)

    def test_eject_is_requested_by_default(self):
        self.build_usb.return_value = True
        code, _out, _err = self.run_write()
        self.assertEqual(code, 0)
        self.assertIs(self.build_usb.call_args.kwargs["eject"], True)

    def test_verification_failure_exits_3(self):
        self.build_usb.side_effect = RuntimeError("Verification FAILED: the data differs near byte 4096.")
        code, out, err = self.run_write("--json")
        self.assertEqual(code, 3)
        result = json.loads(out)
        self.assertFalse(result["ok"])
        self.assertFalse(result["verified"])
        self.assertIn("Verification FAILED", result["error"])
        self.assertEqual(result["exit_code"], 3)
        self.assertIn("Verification FAILED", err)

    def test_engine_errors_exit_1_without_traceback(self):
        for exc in (RuntimeError("Privileged command failed"), ValueError("bad value"), KeyError("oops"),
                    OSError("device vanished")):
            with self.subTest(exc=exc):
                self.build_usb.side_effect = exc
                code, out, err = self.run_write()
                self.assertEqual((code, out), (1, ""))
                self.assertNotIn("Traceback", err)

    def test_debug_shows_the_traceback(self):
        self.build_usb.side_effect = KeyError("oops")
        code, _out, err = run_main(["--debug"] + self.write_args(self.iso, "--yes"))
        self.assertEqual(code, 1)
        self.assertIn("Traceback", err)

    def test_recent_log_lines_are_shown_on_failure(self):
        def engine(iso, dev, log, priv, **_kw):
            log("$ diskutil eraseDisk")
            log("Error: could not unmount")
            raise RuntimeError("Command failed (exit code 1)")

        self.build_usb.side_effect = engine
        code, _out, err = self.run_write()
        self.assertEqual(code, 1)
        self.assertIn("Last log lines:", err)
        self.assertIn("$ diskutil eraseDisk", err)

    def test_keyboard_interrupt_exits_130(self):
        self.build_usb.side_effect = KeyboardInterrupt()
        code, out, err = self.run_write("--json")
        self.assertEqual(code, 130)
        self.assertEqual(json.loads(out)["error"], "interrupted")
        self.assertIn("must not be used", err)

    def test_sigint_sets_cancel_event_and_exits_130(self):
        seen = {}

        def engine(iso, dev, log, priv, cancel_event=None, **_kw):
            seen["event"] = cancel_event
            os.kill(os.getpid(), signal.SIGINT)
            seen["set_after_signal"] = cancel_event.is_set()
            raise RuntimeError("Canceled")

        self.build_usb.side_effect = engine
        before = signal.getsignal(signal.SIGINT)
        code, _out, err = self.run_write()
        self.assertEqual(code, 130)
        self.assertTrue(seen["set_after_signal"])
        self.assertTrue(seen["event"].is_set())
        self.assertIn("press Ctrl-C again", err)
        self.assertEqual(signal.getsignal(signal.SIGINT), before)

    def test_second_sigint_forces_quit(self):
        def engine(iso, dev, log, priv, cancel_event=None, **_kw):
            os.kill(os.getpid(), signal.SIGINT)
            os.kill(os.getpid(), signal.SIGINT)
            raise AssertionError("the second Ctrl-C should have interrupted the engine")

        self.build_usb.side_effect = engine
        self.assertEqual(self.run_write()[0], 130)

    def test_privilege_failure_stops_before_the_engine(self):
        self.authenticate.side_effect = RuntimeError("Could not obtain administrator privileges")
        code, _out, err = self.run_write()
        self.assertEqual(code, 1)
        self.assertIn("administrator privileges", err)
        self.build_usb.assert_not_called()

    def test_progress_and_log_reach_stderr_only(self):
        def engine(iso, dev, log, priv, progress=None, **_kw):
            log("Erasing /dev/disk9...")
            log("rsync noise line")
            progress(10, 100, "Copying files...")
            progress(100, 100, "Copying files...")
            return True

        self.build_usb.side_effect = engine
        code, out, err = self.run_write()
        self.assertEqual((code, out), (0, ""))
        self.assertIn("Erasing /dev/disk9...", err)
        self.assertNotIn("rsync noise line", err)
        self.assertIn("Copying files...", err)
        _code, _out, verbose_err = self.run_write("--verbose")
        self.assertIn("rsync noise line", verbose_err)


class _FakeStream(io.StringIO):
    def __init__(self, tty):
        super().__init__()
        self._tty = tty

    def isatty(self):
        return self._tty


class OutputHelpersTests(unittest.TestCase):
    def test_color_rules(self):
        tty, plain = _FakeStream(True), _FakeStream(False)
        with mock.patch.dict(os.environ, {"TERM": "xterm"}, clear=False):
            os.environ.pop("NO_COLOR", None)
            self.assertIn("\033[", app._style(tty, "x", "31"))
            self.assertEqual(app._style(plain, "x", "31"), "x")
            with mock.patch.dict(os.environ, {"NO_COLOR": "1"}):
                self.assertEqual(app._style(tty, "x", "31"), "x")
        with mock.patch.dict(os.environ, {"TERM": "dumb"}):
            os.environ.pop("NO_COLOR", None)
            self.assertEqual(app._style(tty, "x", "31"), "x")

    def test_progress_on_a_terminal_updates_one_line(self):
        stream = _FakeStream(True)
        now = [0.0]
        progress = app.CliProgress(stream, clock=lambda: now[0])
        progress(10, 100, "Writing...")
        now[0] = 0.1
        progress(20, 100, "Writing...")   # throttled
        now[0] = 0.5
        progress(50, 100, "Writing...")
        progress.clear()
        progress(60, 100, "Verifying...")  # new stage: shown at once
        progress.finish()
        text = stream.getvalue()
        self.assertEqual(text.count("\r"), 5)
        self.assertNotIn("20.0%", text)
        self.assertIn("50.0%", text)
        self.assertIn("Verifying...", text)
        self.assertTrue(text.endswith("\n"))

    def test_progress_without_a_terminal_prints_periodic_lines(self):
        stream = _FakeStream(False)
        now = [0.0]
        progress = app.CliProgress(stream, clock=lambda: now[0])
        progress(1, 100, "Copying...")
        now[0] = 3.0
        progress(2, 100, "Copying...")    # within 10 s: skipped
        now[0] = 11.0
        progress(3, 100, "Copying...")
        progress(100, 100, "Copying...")  # completion is always shown
        progress(0, 0, "Syncing...")
        lines = stream.getvalue().splitlines()
        self.assertEqual(len(lines), 4)
        self.assertNotIn("\r", stream.getvalue())
        self.assertIn("100.0%", lines[2])
        self.assertEqual(lines[3], "Syncing...")

    def test_progress_shows_speed_and_eta(self):
        stream = _FakeStream(False)
        now = [0.0]
        progress = app.CliProgress(stream, clock=lambda: now[0])
        progress(0, 100 * MIB, "Writing...")
        now[0] = 20.0
        progress(20 * MIB, 100 * MIB, "Writing...")
        last = stream.getvalue().splitlines()[-1]
        self.assertIn("20.0%", last)
        self.assertIn("1.0 MB/s", last)
        self.assertIn("~1m20s left", last)

    def test_logger_filters_noise_unless_verbose(self):
        stream = _FakeStream(False)
        with mock.patch.object(app.sys, "stderr", stream):
            quiet = app.CliLogger(app.CliProgress(stream))
            for line in ("$ diskutil eraseDisk FAT32", "sources/boot.wim", "Erasing and formatting /dev/disk9...",
                         "Verification passed: identical", "", "   "):
                quiet(line)
            loud = app.CliLogger(app.CliProgress(stream), verbose=True)
            loud("sources/boot.wim")
        shown = stream.getvalue().splitlines()
        self.assertEqual(shown, ["Erasing and formatting /dev/disk9...", "Verification passed: identical",
                                 "sources/boot.wim"])
        self.assertEqual(list(quiet.recent)[:2], ["$ diskutil eraseDisk FAT32", "sources/boot.wim"])


class CliPrivilegeTests(TempDirTestCase):
    def as_root(self):
        patcher = mock.patch.object(app.os, "geteuid", return_value=0)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_interface_matches_what_the_engine_uses(self):
        priv = app.CliPrivilege()
        self.assertIsNone(priv.cached_password)
        priv.clear_cached_password()
        self.assertIsNone(priv.cached_password)
        self.assertTrue(callable(priv.run_script))

    def test_root_runs_scripts_directly_with_positional_arguments(self):
        self.as_root()
        log = Collector()
        marker = self.path("marker with spaces; $(id)")
        app.CliPrivilege().run_script('set -eu\nprintf "%s|%s" "$1" "$2" > "$3"\necho done\n', log,
                                      args=["a b", "$(whoami)", marker])
        with open(marker, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "a b|$(whoami)")  # data, never code
        self.assertIn("done", log.lines)

    def test_failure_is_reported_and_never_retried(self):
        self.as_root()
        counter = self.path("runs")
        script = 'set -eu\necho x >> "$1"\nexit 7\n'
        with self.assertRaisesRegex(RuntimeError, "exit code 7"):
            app.CliPrivilege().run_script(script, Collector(), args=[counter])
        with open(counter, encoding="utf-8") as fh:
            self.assertEqual(fh.read().count("x"), 1)

    def test_non_root_goes_through_sudo_with_the_same_argv_shape(self):
        captured = {}

        class FakePopen:
            returncode = 0

            def __init__(self, argv, **kwargs):
                captured["argv"], captured["kwargs"] = argv, kwargs
                self.stdout = iter(["line one\n"])

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        log = Collector()
        with mock.patch.object(app.os, "geteuid", return_value=1000), \
                mock.patch.object(app.subprocess, "Popen", FakePopen):
            app.CliPrivilege().run_script("set -eu\ntrue\n", log, args=["/dev/sdb", 5])
        argv = captured["argv"]
        self.assertEqual(argv[:4], ["sudo", "bash", "-c", "set -eu\ntrue\n"])
        self.assertEqual(argv[4:], ["win11_usb_creator", "/dev/sdb", "5"])
        self.assertNotIn("stdin", captured["kwargs"])  # inherited: sudo prompts on the terminal
        self.assertIn("line one", log.lines)

    def test_authenticate_without_sudo(self):
        with mock.patch.object(app.os, "geteuid", return_value=1000), \
                mock.patch.object(app.shutil, "which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "sudo"):
                app.CliPrivilege().authenticate()

    def test_authenticate_refused_by_sudo(self):
        with mock.patch.object(app.os, "geteuid", return_value=1000), \
                mock.patch.object(app.shutil, "which", return_value="/usr/bin/sudo"), \
                mock.patch.object(app.subprocess, "call", return_value=1) as call:
            with self.assertRaisesRegex(RuntimeError, "administrator privileges"):
                app.CliPrivilege().authenticate()
        call.assert_called_once_with(["sudo", "-v"])

    def test_authenticate_as_root_does_nothing(self):
        self.as_root()
        with mock.patch.object(app.subprocess, "call") as call:
            app.CliPrivilege().authenticate()
        call.assert_not_called()

    def test_keepalive_starts_after_authentication_and_stops(self):
        priv = app.CliPrivilege()
        with mock.patch.object(app.os, "geteuid", return_value=1000), \
                mock.patch.object(app.shutil, "which", return_value="/usr/bin/sudo"), \
                mock.patch.object(app.subprocess, "call", return_value=0):
            priv.authenticate()
        self.assertTrue(priv._thread.is_alive())
        priv.clear_cached_password()
        priv._thread.join(timeout=5)
        self.assertFalse(priv._thread.is_alive())

    def test_privileged_script_runs_with_the_real_cli_engine_path(self):
        """CliPrivilege plugs into verify_raw_write like the GUI helper does."""
        self.as_root()
        iso = self.make_iso("image.iso", size=MIB + 123)
        with open(iso, "rb") as fh:
            data = fh.read()
        device = self.write_file("device.img", data)
        log = Collector()
        app.verify_raw_write(iso, device, log, app.CliPrivilege(), None)
        self.assertTrue(any("Verification passed" in line for line in log.lines))
        with open(device, "r+b") as fh:
            fh.seek(MIB)
            fh.write(bytes([data[MIB] ^ 0xFF]))   # always differs (the ISO bytes are random)
        with self.assertRaisesRegex(RuntimeError, "Verification FAILED"):
            app.verify_raw_write(iso, device, log, app.CliPrivilege(), None)


class ModuleEntryPointTests(unittest.TestCase):
    def test_script_version_flag(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        proc = subprocess.run(
            [os.sys.executable, "win11_usb_creator.py", "--version"], cwd=root, capture_output=True,
            text=True, timeout=60, check=False, env=dict(os.environ, WIN11USB_DISABLE_AUDIT_LOG="1"))
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, f"epma-usb-creator {app.__version__}\n")


if __name__ == "__main__":
    unittest.main()
