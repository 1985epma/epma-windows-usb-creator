"""The command line side of the hardened setup: `write --hardened`, `harden-seed` and `harden-files`.

The engine functions that build the files and the seed drive belong to other parts of the program, so they are
replaced here by small stand-ins: these tests are about what the command line does with them (arguments,
safety flow, exit codes, what it writes to a folder). Nothing touches a real drive.
"""
import json
import os
import signal
import stat
import unittest
from unittest import mock

from tests.helpers import FAKE_DISKS, TempDirTestCase, app, run_main

WIN_FILES = {
    "autounattend.xml": b"<unattend/>\n",
    "sources/$OEM$/$$/Setup/Scripts/SetupComplete.cmd": b"@echo off\r\n",
    "sources/$OEM$/$$/Setup/Scripts/harden.ps1": b"# harden\r\n",
}
SEED_FILES = {
    "ubuntu": ("CIDATA", {"user-data": b"#cloud-config\n", "meta-data": b"\n",
                          "harden-linux.sh": b"#!/bin/bash\n", "README.txt": b"hello\n"}),
    "fedora": ("OEMDRV", {"ks.cfg": b"# kickstart\n", "harden-linux.sh": b"#!/bin/bash\n",
                          "README.txt": b"hello\n"}),
    "debian": ("EPMA-SEED", {"preseed.cfg": b"# preseed\n", "harden-linux.sh": b"#!/bin/bash\n",
                             "README.txt": b"hello\n"}),
}


def fake_validate(files):
    return dict(files)


class HardeningCliCase(TempDirTestCase):
    """Fake drives, no missing tools, no sudo; the engine and the file builders are stand-ins."""

    def setUp(self):
        super().setUp()
        self.disks = [dict(d) for d in FAKE_DISKS]
        self.disks[0]["identity"] = (("serial", "ABC123"),)
        for name, patcher in {
            "get_external_disks": mock.patch.object(app, "get_external_disks", return_value=self.disks),
            "missing": mock.patch.object(app, "get_missing_dependencies", return_value=[]),
            "authenticate": mock.patch.object(app.CliPrivilege, "authenticate"),
            "build_usb": mock.patch.object(app, "build_usb", return_value=True),
            "build_seed_usb": mock.patch.object(app, "build_seed_usb", create=True, return_value=True),
            "files_windows": mock.patch.object(app, "hardening_files_windows", create=True,
                                               side_effect=lambda profile: dict(WIN_FILES)),
            "files_seed": mock.patch.object(app, "hardening_files_seed", create=True,
                                            side_effect=lambda target, profile: (
                                                SEED_FILES[target][0], dict(SEED_FILES[target][1]))),
            "validate": mock.patch.object(app, "validate_seed_files", create=True, side_effect=fake_validate),
            # added by the engine part of the feature (ValueError for a known size under 64 MiB)
            "size_check": mock.patch.object(app, "check_seed_target_size", create=True),
            "pin": mock.patch.object(app, "pin_target_identity"),
            "env": mock.patch.dict(os.environ, {"NO_COLOR": "1"}),
        }.items():
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)

    def write_args(self, iso, *extra, disk="disk9"):
        return ["write", "--iso", iso, "--disk", disk, *extra]

    def seed_args(self, *extra, target="ubuntu", disk="disk9"):
        return ["harden-seed", "--target", target, "--disk", disk, *extra]

    def interactive(self):
        patcher = mock.patch.object(app, "_is_interactive", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)


class ParserTests(unittest.TestCase):
    def parse(self, *argv):
        return app.build_cli_parser().parse_args(list(argv))

    def test_the_new_commands_and_flags_are_accepted(self):
        args = self.parse("write", "--iso", "a.iso", "--disk", "disk9", "--hardened")
        self.assertTrue(args.hardened)
        self.assertFalse(self.parse("write", "--iso", "a.iso", "--disk", "disk9").hardened)
        args = self.parse("harden-seed", "--target", "fedora", "--disk", "sdb", "--dry-run", "--yes", "--json",
                          "--no-eject")
        self.assertEqual((args.command, args.target, args.disk), ("harden-seed", "fedora", "sdb"))
        self.assertTrue(args.dry_run and args.yes and args.json and args.no_eject)
        args = self.parse("harden-files", "--target", "windows", "--out", "somewhere", "--json")
        self.assertEqual((args.target, args.out, args.json), ("windows", "somewhere", True))

    def test_every_target_is_accepted(self):
        for target in app.SEED_TARGETS:
            with self.subTest(target=target):
                self.assertEqual(self.parse("harden-seed", "--target", target, "--disk", "d").target, target)
                self.assertEqual(self.parse("harden-files", "--target", target, "--out", "x").target, target)
        self.assertEqual(self.parse("harden-files", "--target", "windows", "--out", "x").target, "windows")

    def test_bad_arguments_are_usage_errors(self):
        for argv in (["harden-seed"],
                     ["harden-seed", "--target", "ubuntu"],
                     ["harden-seed", "--disk", "disk9"],
                     ["harden-seed", "--target", "windows", "--disk", "disk9"],  # a seed drive is for Linux
                     ["harden-seed", "--target", "arch", "--disk", "disk9"],
                     ["harden-seed", "--target", "ubuntu", "--disk", "disk9", "--hardened"],
                     ["harden-seed", "--target", "ubuntu", "--disk", "disk9", "--no-verify"],
                     ["harden-files"],
                     ["harden-files", "--target", "windows"],
                     ["harden-files", "--out", "x"],
                     ["harden-files", "--target", "macos", "--out", "x"],
                     ["harden-files", "--target", "windows", "--out", "x", "--yes"],  # no drive, nothing to confirm
                     ["harden-files", "--target", "windows", "--out", "x", "--dry-run"]):
            with self.subTest(argv=argv):
                code, out, err = run_main(argv)
                self.assertEqual(code, app.EXIT_USAGE)
                self.assertEqual(out, "")
                self.assertIn("usage:", err)

    def test_the_commands_are_in_the_dispatch_table(self):
        self.assertIs(app.COMMANDS["harden-seed"], app.cmd_harden_seed)
        self.assertIs(app.COMMANDS["harden-files"], app.cmd_harden_files)

    def test_help_text_names_the_commands_and_flags(self):
        _code, out, _err = run_main(["--help"])
        self.assertIn("harden-seed", out)
        self.assertIn("harden-files", out)
        self.assertIn("--hardened", run_main(["write", "--help"])[1])
        text = run_main(["harden-seed", "--help"])[1]
        for flag in ("--target", "--disk", "--dry-run", "--yes", "--json", "--no-eject"):
            self.assertIn(flag, text)
        self.assertNotIn("--no-verify", text)  # verification of the seed drive cannot be switched off either
        for flag in ("--target", "--out", "--json"):
            self.assertIn(flag, run_main(["harden-files", "--help"])[1])


class WriteHardenedTests(HardeningCliCase):
    def setUp(self):
        super().setUp()
        self.win = self.make_iso("Win11.iso", hybrid=False)
        self.linux = self.make_iso("ubuntu.iso")

    def test_dry_run_lists_the_extra_files_by_name_only(self):
        code, out, err = run_main(self.write_args(self.win, "--dry-run", "--hardened", "--mode", "windows"))
        self.assertEqual(code, 0)
        for name in WIN_FILES:
            self.assertIn(name, out)
        self.assertIn("Hardened (recommended settings)", out)
        for content in (b"<unattend/>", b"@echo off", b"# harden"):
            self.assertNotIn(content.decode(), out)  # names, never contents
        self.assertIn("Dry run", err)
        self.build_usb.assert_not_called()
        self.authenticate.assert_not_called()

    def test_dry_run_json_shape(self):
        code, out, err = run_main(self.write_args(self.win, "--dry-run", "--hardened", "--mode", "windows",
                                                  "--json"))
        self.assertEqual((code, err), (0, ""))
        plan = json.loads(out)
        self.assertEqual(plan["hardening"], "baseline")
        self.assertEqual(plan["hardening_files"], sorted(WIN_FILES))
        self.assertTrue(any("Hardened (recommended settings)" in step for step in plan["steps"]))
        # and without the flag the plan says so, so a script can tell the two apart
        plain = json.loads(run_main(self.write_args(self.win, "--dry-run", "--mode", "windows", "--json"))[1])
        self.assertEqual((plain["hardening"], plain["hardening_files"]), ("none", []))

    def test_the_engine_gets_the_baseline_profile(self):
        code, _out, _err = run_main(self.write_args(self.win, "--yes", "--hardened", "--mode", "windows"))
        self.assertEqual(code, 0)
        self.assertEqual(self.build_usb.call_args.kwargs["hardening"], app.HARDENING_BASELINE)
        self.assertEqual(self.build_usb.call_args.kwargs["mode"], app.MODE_WINDOWS)

    def test_auto_mode_that_finds_a_windows_image_accepts_it(self):
        with mock.patch.object(app, "detect_iso_kind", return_value="windows"):
            code, _out, _err = run_main(self.write_args(self.win, "--yes", "--hardened"))
        self.assertEqual(code, 0)
        self.assertEqual(self.build_usb.call_args.kwargs["hardening"], app.HARDENING_BASELINE)

    def test_without_the_flag_the_engine_is_called_as_before(self):
        run_main(self.write_args(self.win, "--yes", "--mode", "windows"))
        self.assertNotIn("hardening", self.build_usb.call_args.kwargs)

    def test_a_linux_or_chromeos_mode_is_a_usage_error_before_anything_else(self):
        for mode in ("linux", "chromeos"):
            with self.subTest(mode=mode):
                code, out, err = run_main(self.write_args(self.linux, "--yes", "--hardened", "--mode", mode))
                self.assertEqual((code, out), (app.EXIT_USAGE, ""))
                self.assertIn("--hardened", err)
                self.assertIn("harden-seed", err)  # tells the user where to go instead
        self.get_external_disks.assert_not_called()
        self.build_usb.assert_not_called()
        self.authenticate.assert_not_called()

    def test_auto_mode_that_resolves_to_linux_is_a_usage_error(self):
        code, out, err = run_main(self.write_args(self.linux, "--yes", "--hardened"))
        self.assertEqual((code, out), (app.EXIT_USAGE, ""))
        self.assertIn("--hardened", err)
        self.build_usb.assert_not_called()
        self.authenticate.assert_not_called()

    def test_the_usage_error_is_in_the_json_result_too(self):
        code, out, _err = run_main(self.write_args(self.linux, "--yes", "--hardened", "--json"))
        self.assertEqual(code, app.EXIT_USAGE)
        result = json.loads(out)
        self.assertFalse(result["ok"])
        self.assertEqual(result["exit_code"], app.EXIT_USAGE)

    def test_the_typed_confirmation_is_still_required(self):
        code, _out, err = run_main(self.write_args(self.win, "--hardened", "--mode", "windows"))
        self.assertEqual(code, app.EXIT_USAGE)  # not a terminal and no --yes
        self.assertIn("--yes", err)
        self.interactive()
        for answer in ("", "yes\n", "disk8\n"):
            with self.subTest(answer=answer):
                code, _out, err = run_main(self.write_args(self.win, "--hardened", "--mode", "windows"),
                                           stdin_text=answer)
                self.assertEqual(code, app.EXIT_USAGE)
        code, _out, err = run_main(self.write_args(self.win, "--hardened", "--mode", "windows"),
                                   stdin_text="disk9\n")
        self.assertEqual(code, 0)
        self.assertIn("Type the disk id (disk9)", err)

    def test_files_the_validator_refuses_stop_the_plan(self):
        self.validate.side_effect = ValueError("path escapes the drive")
        code, out, err = run_main(self.write_args(self.win, "--yes", "--hardened", "--mode", "windows"))
        self.assertEqual((code, out), (app.EXIT_ERROR, ""))
        self.assertIn("path escapes the drive", err)
        self.build_usb.assert_not_called()


class HardenSeedTests(HardeningCliCase):
    def test_dry_run_prints_the_plan_and_touches_nothing(self):
        code, out, err = run_main(self.seed_args("--dry-run"))
        self.assertEqual(code, 0)
        for text in ("Plan", "/dev/disk9", "16.0 GB", "ubuntu", "CIDATA", "GPT + FAT32", "harden-linux.sh",
                     "user-data", "Mode : seed", "byte for byte", "Eject the drive"):
            self.assertIn(text, out)
        self.assertIn("Dry run", err)
        self.build_seed_usb.assert_not_called()
        self.authenticate.assert_not_called()
        self.pin.assert_not_called()

    def test_dry_run_json_shape(self):
        code, out, err = run_main(self.seed_args("--dry-run", "--json", "--no-eject", target="fedora"))
        self.assertEqual((code, err), (0, ""))
        plan = json.loads(out)
        self.assertEqual((plan["mode"], plan["target"], plan["volume_label"]), ("seed", "fedora", "OEMDRV"))
        self.assertEqual(plan["files"], sorted(SEED_FILES["fedora"][1]))
        self.assertEqual(plan["disk"]["id"], "disk9")
        self.assertEqual(plan["identity"], {"serial": "ABC123"})
        self.assertTrue(plan["dry_run"])
        self.assertFalse(plan["eject"])
        self.assertIn("--no-eject", plan["steps"][-1])

    def test_every_target_uses_its_own_files_and_label(self):
        for target, (label, files) in SEED_FILES.items():
            with self.subTest(target=target):
                self.build_seed_usb.reset_mock()
                code, out, _err = run_main(self.seed_args("--dry-run", target=target))
                self.assertEqual(code, 0)
                self.assertIn(label, out)
                for name in files:
                    self.assertIn(name, out)

    def test_validation_happens_before_anything_runs(self):
        cases = {
            "not a valid disk identifier": self.seed_args("--yes", disk="disk4; rm -rf /"),
            "not an eligible USB drive": self.seed_args("--yes", disk="disk3"),
        }
        for fragment, argv in cases.items():
            with self.subTest(fragment=fragment):
                code, out, err = run_main(argv)
                self.assertEqual((code, out), (1, ""))
                self.assertIn(fragment, err)
        self.build_seed_usb.assert_not_called()
        self.authenticate.assert_not_called()

    def test_dev_prefix_is_accepted(self):
        code, out, _err = run_main(self.seed_args("--dry-run", disk="/dev/disk9"))
        self.assertEqual(code, 0)
        self.assertIn("/dev/disk9", out)

    def test_missing_tools_are_reported(self):
        self.missing.return_value = ["parted"]
        code, _out, err = run_main(self.seed_args("--yes"))
        self.assertEqual(code, 1)
        self.assertIn("parted", err)
        self.missing.assert_called_with(app.MODE_SEED)
        self.build_seed_usb.assert_not_called()

    def test_files_the_validator_refuses_stop_the_command(self):
        self.validate.side_effect = ValueError("file too large")
        code, out, err = run_main(self.seed_args("--yes"))
        self.assertEqual((code, out), (1, ""))
        self.assertIn("file too large", err)
        self.build_seed_usb.assert_not_called()
        self.authenticate.assert_not_called()

    # -- the confirmation: the same as `write` --
    def test_non_interactive_without_yes_is_refused(self):
        code, out, err = run_main(self.seed_args())
        self.assertEqual((code, out), (app.EXIT_USAGE, ""))
        self.assertIn("--yes", err)
        self.assertIn("Plan", err)  # the plan was still shown
        self.build_seed_usb.assert_not_called()
        self.authenticate.assert_not_called()

    def test_non_interactive_ignores_typed_input(self):
        code, _out, _err = run_main(self.seed_args(), stdin_text="disk9\n")
        self.assertEqual(code, app.EXIT_USAGE)
        self.build_seed_usb.assert_not_called()

    def test_the_user_must_type_the_disk_id(self):
        self.interactive()
        for answer in ("yes\n", "disk8\n", "\n", "", "DISK9\n", "/dev/disk9\n"):
            with self.subTest(answer=answer):
                code, _out, err = run_main(self.seed_args(), stdin_text=answer)
                self.assertEqual(code, app.EXIT_USAGE)
                self.assertIn("Nothing was changed", err)
                self.build_seed_usb.assert_not_called()
        code, _out, err = run_main(self.seed_args(), stdin_text="disk9\n")
        self.assertEqual(code, 0)
        self.assertIn("Type the disk id (disk9)", err)
        self.assertIn("PERMANENTLY ERASE", err)
        self.build_seed_usb.assert_called_once()

    def test_yes_skips_the_prompt(self):
        self.interactive()
        code, _out, err = run_main(self.seed_args("--yes"), stdin_text="")
        self.assertEqual(code, 0)
        self.assertNotIn("Type the disk id", err)

    # -- the run --
    def test_success_passes_the_right_arguments_to_the_engine(self):
        code, out, err = run_main(self.seed_args("--yes", target="debian"))
        self.assertEqual((code, out), (0, ""))
        self.assertIn("ejected", err)
        args, kwargs = self.build_seed_usb.call_args
        self.assertEqual(args[0], "debian")
        self.assertEqual(args[1], "disk9")
        self.assertTrue(callable(args[2]))
        self.assertIsInstance(args[3], app.CliPrivilege)
        self.assertEqual(kwargs["expected_size"], 16 * 1024 ** 3)
        self.assertTrue(callable(kwargs["progress"]))
        self.assertIs(kwargs["eject"], True)
        self.assertEqual(kwargs["profile"], app.HARDENING_BASELINE)
        self.assertTrue(hasattr(kwargs["cancel_event"], "set"))
        self.assertFalse(kwargs["cancel_event"].is_set())
        self.build_usb.assert_not_called()  # an image writer is never involved

    def test_the_drive_identity_is_pinned_before_the_engine_and_released_after(self):
        order = []
        self.pin.side_effect = lambda dev, identity: order.append(("pin", dev, identity))
        self.build_seed_usb.side_effect = lambda *a, **k: order.append("build") or True
        run_main(self.seed_args("--yes"))
        self.assertEqual(order[0], ("pin", "disk9", (("serial", "ABC123"),)))
        self.assertEqual(order[1], "build")
        self.assertEqual(order[-1], ("pin", "disk9", None))

    def test_privileges_follow_needs_admin_and_come_after_the_confirmation(self):
        order = []
        self.authenticate.side_effect = lambda *a, **k: order.append("auth")
        self.build_seed_usb.side_effect = lambda *a, **k: order.append("build") or True
        self.interactive()
        with mock.patch.object(app, "IS_LINUX", True), mock.patch.object(app, "IS_MAC", False):
            run_main(self.seed_args(), stdin_text="disk9\n")
        self.assertEqual(order, ["auth", "build"])
        self.authenticate.reset_mock()
        with mock.patch.object(app, "IS_LINUX", False), mock.patch.object(app, "IS_MAC", True):
            self.assertEqual(run_main(self.seed_args("--yes"))[0], 0)
        self.authenticate.assert_not_called()  # macOS: like Windows mode, no administrator rights needed

    def test_privilege_failure_stops_before_the_engine(self):
        self.authenticate.side_effect = RuntimeError("Could not obtain administrator privileges")
        with mock.patch.object(app, "IS_LINUX", True):
            code, _out, err = run_main(self.seed_args("--yes"))
        self.assertEqual(code, 1)
        self.assertIn("administrator privileges", err)
        self.build_seed_usb.assert_not_called()

    def test_json_result_on_success(self):
        code, out, err = run_main(self.seed_args("--yes", "--json"))
        self.assertEqual(code, 0)
        result = json.loads(out)
        self.assertEqual({k: result[k] for k in ("ok", "mode", "target", "disk", "verified", "ejected", "error",
                                                 "exit_code")},
                         {"ok": True, "mode": "seed", "target": "ubuntu", "disk": "disk9", "verified": True,
                          "ejected": True, "error": None, "exit_code": 0})
        self.assertEqual(result["files"], sorted(SEED_FILES["ubuntu"][1]))
        self.assertIn("elapsed_seconds", result)
        self.assertNotIn('"ok"', err)  # stdout carries the data, stderr the messages

    def test_eject_failure_exits_4(self):
        self.build_seed_usb.return_value = False
        code, out, err = run_main(self.seed_args("--yes", "--json"))
        self.assertEqual(code, app.EXIT_EJECT_FAILED)
        result = json.loads(out)
        self.assertTrue(result["verified"])
        self.assertFalse(result["ejected"])
        self.assertEqual(result["exit_code"], 4)
        self.assertIn("could not be ejected", err)

    def test_no_eject_is_passed_to_the_engine_and_is_not_a_failure(self):
        self.build_seed_usb.return_value = False
        code, _out, err = run_main(self.seed_args("--yes", "--no-eject"))
        self.assertEqual(code, 0)
        self.assertIs(self.build_seed_usb.call_args.kwargs["eject"], False)
        self.assertIn("left connected", err)

    def test_verification_failure_exits_3(self):
        self.build_seed_usb.side_effect = RuntimeError("Verification FAILED: user-data differs.")
        code, out, err = run_main(self.seed_args("--yes", "--json"))
        self.assertEqual(code, app.EXIT_VERIFY_FAILED)
        result = json.loads(out)
        self.assertFalse(result["ok"])
        self.assertFalse(result["verified"])
        self.assertEqual(result["exit_code"], 3)
        self.assertIn("Verification FAILED", err)

    def test_engine_errors_exit_1_without_traceback(self):
        for exc in (RuntimeError("Privileged command failed"), ValueError("bad value"), KeyError("oops"),
                    OSError("device vanished")):
            with self.subTest(exc=exc):
                self.build_seed_usb.side_effect = exc
                code, out, err = run_main(self.seed_args("--yes"))
                self.assertEqual((code, out), (1, ""))
                self.assertNotIn("Traceback", err)

    def test_keyboard_interrupt_exits_130(self):
        self.build_seed_usb.side_effect = KeyboardInterrupt()
        code, out, err = run_main(self.seed_args("--yes", "--json"))
        self.assertEqual(code, app.EXIT_INTERRUPTED)
        self.assertEqual(json.loads(out)["error"], "interrupted")
        self.assertIn("must not be used", err)
        self.pin.assert_called_with("disk9", None)

    def test_ctrl_c_sets_the_cancel_event_and_exits_130(self):
        seen = {}

        def engine(target, dev, log, priv, cancel_event=None, **_kw):
            seen["event"] = cancel_event
            os.kill(os.getpid(), signal.SIGINT)
            seen["set_after_signal"] = cancel_event.is_set()
            raise RuntimeError("Canceled")

        self.build_seed_usb.side_effect = engine
        before = signal.getsignal(signal.SIGINT)
        code, _out, err = run_main(self.seed_args("--yes"))
        self.assertEqual(code, app.EXIT_INTERRUPTED)
        self.assertTrue(seen["set_after_signal"])
        self.assertTrue(seen["event"].is_set())
        self.assertIn("press Ctrl-C again", err)
        self.assertEqual(signal.getsignal(signal.SIGINT), before)

    def test_progress_and_log_reach_stderr_only(self):
        def engine(target, dev, log, priv, progress=None, **_kw):
            log("Erasing /dev/disk9...")
            progress(10, 100, "Copying files...")
            progress(100, 100, "Copying files...")
            return True

        self.build_seed_usb.side_effect = engine
        code, out, err = run_main(self.seed_args("--yes"))
        self.assertEqual((code, out), (0, ""))
        self.assertIn("Erasing /dev/disk9...", err)
        self.assertIn("Copying files...", err)

    def test_unsupported_system_is_refused(self):
        with mock.patch.object(app, "IS_MAC", False), mock.patch.object(app, "IS_LINUX", False):
            code, _out, err = run_main(self.seed_args("--yes"))
        self.assertEqual(code, 1)
        self.assertIn("macOS and Linux only", err)
        self.build_seed_usb.assert_not_called()


class HardenFilesTests(HardeningCliCase):
    def out_dir(self, name="seed-files"):
        return self.path(name)

    def tree(self, root):
        found = {}
        for folder, dirs, files in os.walk(root):
            for name in dirs + files:
                full = os.path.join(folder, name)
                found[os.path.relpath(full, root).replace(os.sep, "/")] = full
        return found

    def leftovers(self):
        """Anything the command may have left next to the destination (staging folders)."""
        return [n for n in os.listdir(self.tmp) if n.startswith(".epma-harden-")]

    def test_writes_every_target_into_a_new_folder(self):
        cases = {"windows": WIN_FILES, **{t: SEED_FILES[t][1] for t in app.SEED_TARGETS}}
        for target, files in cases.items():
            with self.subTest(target=target):
                out = self.out_dir(f"out-{target}")
                code, stdout, err = run_main(["harden-files", "--target", target, "--out", out])
                self.assertEqual(code, 0)
                self.assertEqual(stdout.split("\n")[:-1], sorted(files))  # data on stdout: the names
                self.assertIn("No drive was touched", err)
                for rel, data in files.items():
                    with open(os.path.join(out, *rel.split("/")), "rb") as fh:
                        self.assertEqual(fh.read(), data)
                self.assertEqual(self.leftovers(), [])

    def test_permissions_are_normal_and_do_not_depend_on_the_umask(self):
        old = os.umask(0o077)
        try:
            out = self.out_dir()
            self.assertEqual(run_main(["harden-files", "--target", "windows", "--out", out])[0], 0)
        finally:
            os.umask(old)
        for rel, full in self.tree(out).items():
            mode = stat.S_IMODE(os.stat(full).st_mode)
            expected = 0o700 if os.path.isdir(full) else 0o600
            self.assertEqual(mode, expected, f"{rel} is {oct(mode)}")
        self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o700)

    def test_an_existing_empty_folder_is_filled_and_keeps_its_identity(self):
        out = self.out_dir()
        os.mkdir(out)
        inode = os.stat(out).st_ino
        code, _stdout, _err = run_main(["harden-files", "--target", "ubuntu", "--out", out])
        self.assertEqual(code, 0)
        self.assertEqual(os.stat(out).st_ino, inode)
        self.assertEqual(sorted(os.listdir(out)), sorted(SEED_FILES["ubuntu"][1]))
        self.assertEqual(self.leftovers(), [])

    def test_a_folder_that_is_not_empty_is_refused_and_left_alone(self):
        out = self.out_dir()
        self.write_file("seed-files/notes.txt", b"mine")
        before = self.tree(out)
        for target in ("windows", "ubuntu"):
            with self.subTest(target=target):
                code, stdout, err = run_main(["harden-files", "--target", target, "--out", out])
                self.assertEqual((code, stdout), (app.EXIT_ERROR, ""))
                self.assertIn("not empty", err)
                self.assertEqual(self.tree(out), before)
                with open(os.path.join(out, "notes.txt"), "rb") as fh:
                    self.assertEqual(fh.read(), b"mine")
        self.assertEqual(self.leftovers(), [])

    def test_a_name_that_already_exists_is_never_overwritten(self):
        out = self.out_dir()
        self.write_file("seed-files/user-data", b"precious")
        code, _stdout, err = run_main(["harden-files", "--target", "ubuntu", "--out", out])
        self.assertEqual(code, app.EXIT_ERROR)
        with open(os.path.join(out, "user-data"), "rb") as fh:
            self.assertEqual(fh.read(), b"precious")
        self.assertEqual(os.listdir(out), ["user-data"])
        self.assertIn("not empty", err)

    def test_a_hidden_file_counts_as_content(self):
        out = self.out_dir()
        self.write_file("seed-files/.hidden", b"")
        self.assertEqual(run_main(["harden-files", "--target", "windows", "--out", out])[0], app.EXIT_ERROR)
        self.assertEqual(os.listdir(out), [".hidden"])

    def test_a_symbolic_link_is_refused_even_when_it_points_at_an_empty_folder(self):
        real = self.path("real-empty")
        os.mkdir(real)
        link = self.path("link")
        os.symlink(real, link)
        code, stdout, err = run_main(["harden-files", "--target", "windows", "--out", link])
        self.assertEqual((code, stdout), (app.EXIT_ERROR, ""))
        self.assertIn("symbolic link", err)
        self.assertEqual(os.listdir(real), [])
        # a dangling link too (it must not be "created through")
        dangling = self.path("dangling")
        os.symlink(self.path("nowhere"), dangling)
        self.assertEqual(run_main(["harden-files", "--target", "windows", "--out", dangling])[0], app.EXIT_ERROR)
        self.assertFalse(os.path.exists(self.path("nowhere")))
        self.assertEqual(self.leftovers(), [])

    def test_a_file_or_a_missing_parent_is_refused(self):
        a_file = self.write_file("plain.txt", b"x")
        code, _stdout, err = run_main(["harden-files", "--target", "windows", "--out", a_file])
        self.assertEqual(code, app.EXIT_ERROR)
        self.assertIn("Not a folder", err)
        code, _stdout, err = run_main(["harden-files", "--target", "windows", "--out", self.path("a", "b")])
        self.assertEqual(code, app.EXIT_ERROR)
        self.assertIn("parent folder does not exist", err)
        self.assertFalse(os.path.exists(self.path("a")))

    def test_invalid_files_write_nothing(self):
        self.validate.side_effect = ValueError("path is absolute")
        out = self.out_dir()
        code, stdout, err = run_main(["harden-files", "--target", "windows", "--out", out])
        self.assertEqual((code, stdout), (app.EXIT_ERROR, ""))
        self.assertIn("path is absolute", err)
        self.assertFalse(os.path.exists(out))
        self.assertEqual(self.leftovers(), [])

    def test_the_shared_validator_checks_what_gets_written(self):
        run_main(["harden-files", "--target", "debian", "--out", self.out_dir()])
        self.validate.assert_called_once_with(SEED_FILES["debian"][1])

    def test_a_failure_halfway_leaves_nothing_behind(self):
        real_open = os.open
        calls = {"n": 0}

        def flaky(path, *a, **k):
            calls["n"] += 1
            if calls["n"] == 3:
                raise OSError(28, "No space left on device")
            return real_open(path, *a, **k)

        out = self.out_dir()
        with mock.patch.object(app.os, "open", flaky):
            code, stdout, err = run_main(["harden-files", "--target", "windows", "--out", out])
        self.assertEqual((code, stdout), (app.EXIT_ERROR, ""))
        self.assertIn("No space left", err)
        self.assertFalse(os.path.exists(out))
        self.assertEqual(self.leftovers(), [])

    def test_a_failure_while_filling_an_empty_folder_puts_it_back_as_it_was(self):
        out = self.out_dir()
        os.mkdir(out)
        real_rename = os.rename
        calls = {"n": 0}

        def flaky(src, dst):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError(5, "Input/output error")
            return real_rename(src, dst)

        with mock.patch.object(app.os, "rename", flaky):
            code, _stdout, err = run_main(["harden-files", "--target", "ubuntu", "--out", out])
        self.assertEqual(code, app.EXIT_ERROR)
        self.assertIn("Input/output error", err)
        self.assertEqual(os.listdir(out), [])
        self.assertEqual(self.leftovers(), [])

    def test_paths_that_escape_the_folder_are_never_written(self):
        # Defence in depth: even a validator that let a bad path through cannot make the command write outside.
        self.files_seed.side_effect = lambda target, profile: ("CIDATA", {"../evil.txt": b"x"})
        out = self.out_dir()
        code, _stdout, _err = run_main(["harden-files", "--target", "ubuntu", "--out", out])
        self.assertEqual(code, app.EXIT_ERROR)
        self.assertFalse(os.path.exists(self.path("evil.txt")))
        self.assertFalse(os.path.exists(out))
        self.assertEqual(self.leftovers(), [])

    def test_json_shape(self):
        out = self.out_dir()
        code, stdout, err = run_main(["harden-files", "--target", "fedora", "--out", out, "--json"])
        self.assertEqual(code, 0)
        data = json.loads(stdout)
        self.assertEqual(data["target"], "fedora")
        self.assertEqual(data["out"], out)
        self.assertEqual(data["volume_label"], "OEMDRV")
        self.assertEqual(data["files"], [{"path": name, "bytes": len(SEED_FILES["fedora"][1][name])}
                                         for name in sorted(SEED_FILES["fedora"][1])])
        self.assertNotIn('"files"', err)
        windows = json.loads(run_main(["harden-files", "--target", "windows", "--out", self.out_dir("w"),
                                       "--json"])[1])
        self.assertIsNone(windows["volume_label"])

    def test_no_drive_and_no_privileges_are_involved(self):
        code, _stdout, _err = run_main(["harden-files", "--target", "windows", "--out", self.out_dir()])
        self.assertEqual(code, 0)
        for mocked in (self.get_external_disks, self.authenticate, self.build_usb, self.build_seed_usb, self.pin):
            mocked.assert_not_called()

    def test_it_works_where_no_drive_can_be_written(self):
        with mock.patch.object(app, "IS_MAC", False), mock.patch.object(app, "IS_LINUX", False):
            code, _stdout, _err = run_main(["harden-files", "--target", "ubuntu", "--out", self.out_dir()])
        self.assertEqual(code, 0)

    def test_the_tilde_is_expanded(self):
        with mock.patch.dict(os.environ, {"HOME": self.tmp}):
            code, _stdout, _err = run_main(["harden-files", "--target", "windows", "--out", "~/from-home"])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isfile(self.path("from-home", "autounattend.xml")))


class SeedSizeAndConflictTests(HardeningCliCase):
    """A too-small seed drive is refused first; the engine's refusal for an ISO that already has the files exits 2."""

    TOO_SMALL = "The drive (16.0 MB) is too small for a seed drive (at least 64.0 MB). Nothing was changed."

    def test_the_size_is_checked_with_the_size_of_the_listed_drive(self):
        code, _out, _err = run_main(self.seed_args("--dry-run"))
        self.assertEqual(code, 0)
        self.size_check.assert_called_once_with(self.disks[0]["size"])

    def test_a_dry_run_flags_a_too_small_drive(self):
        self.size_check.side_effect = ValueError(self.TOO_SMALL)
        code, out, err = run_main(self.seed_args("--dry-run"))
        self.assertEqual(code, app.EXIT_USAGE)
        self.assertEqual(out, "")                          # no plan was printed
        self.assertIn("too small for a seed drive", err)
        self.assertNotIn("Traceback", err)
        self.assertNotIn("Dry run: nothing was changed", err)
        self.build_seed_usb.assert_not_called()

    def test_the_refusal_comes_before_any_confirmation_or_password(self):
        self.size_check.side_effect = ValueError(self.TOO_SMALL)
        self.interactive()
        with mock.patch("sys.stdin") as stdin:
            code, out, err = run_main(self.seed_args())
        self.assertEqual(code, app.EXIT_USAGE)
        stdin.readline.assert_not_called()                 # the typed identifier was never asked for
        self.assertNotIn("PERMANENTLY ERASE", err)
        self.authenticate.assert_not_called()
        self.pin.assert_not_called()
        self.build_seed_usb.assert_not_called()

    def test_the_refusal_is_a_json_error_too(self):
        self.size_check.side_effect = ValueError(self.TOO_SMALL)
        code, out, _err = run_main(self.seed_args("--json", "--yes"))
        self.assertEqual(code, app.EXIT_USAGE)
        result = json.loads(out)
        self.assertFalse(result["ok"])
        self.assertEqual(result["exit_code"], 2)
        self.assertIn("too small", result["error"])

    def test_an_iso_that_already_holds_the_hardening_files_exits_2_with_the_message(self):
        iso = self.make_iso("Win11.iso", hybrid=False)
        text = "This ISO already contains the hardening files (autounattend.xml). Nothing was changed."
        self.build_usb.side_effect = ValueError(text)
        code, out, err = run_main(self.write_args(iso, "--yes", "--hardened", "--mode", "windows", "--json"))
        self.assertEqual(code, app.EXIT_USAGE)
        self.assertEqual(json.loads(out)["exit_code"], 2)
        self.assertIn("already contains the hardening files", err)
        self.assertNotIn("Traceback", err)
        self.assertNotIn("Unexpected failure", err)
        self.pin.assert_called_with("disk9", None)

    def test_other_engine_value_errors_keep_exit_1(self):
        iso = self.make_iso("Win11.iso", hybrid=False)
        self.build_usb.side_effect = ValueError("bad value")
        code, _out, _err = run_main(self.write_args(iso, "--yes", "--hardened", "--mode", "windows"))
        self.assertEqual(code, 1)


class EpilogTests(unittest.TestCase):
    def test_the_read_back_claim_is_true_for_every_write_command(self):
        text = app.cli_epilog()
        self.assertIn("compared with its source", text)
        self.assertNotIn("compared with the ISO", text)


class HelpAndDocsTests(unittest.TestCase):
    def test_the_command_line_help_section_documents_the_new_commands(self):
        text = dict(app.help_sections())["Command line"]
        for needle in ("• harden-seed ", "• harden-files ", "--hardened"):
            self.assertIn(needle, text)
        self.assertNotRegex(text, r"(?i)\b(CIS|STIG|NIST|certified|compliant|compliance)\b")

    def test_the_help_flags_exist_in_the_parser(self):
        parser = app.build_cli_parser()
        helps = {}
        for action in parser._actions:
            if isinstance(getattr(action, "choices", None), dict):
                helps = {name: sub.format_help() for name, sub in action.choices.items()}
        text = dict(app.help_sections())["Command line"]
        for command, flags in {"harden-seed": ("--target", "--disk", "--dry-run", "--yes", "--no-eject", "--json"),
                               "harden-files": ("--target", "--out", "--json"),
                               "write": ("--hardened",)}.items():
            for flag in flags:
                with self.subTest(command=command, flag=flag):
                    self.assertIn(flag, helps[command])
                    self.assertIn(flag, text)


if __name__ == "__main__":
    unittest.main()
