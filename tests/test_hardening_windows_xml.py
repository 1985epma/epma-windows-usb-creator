"""Tests for the autounattend.xml of the EXPERIMENTAL "during setup" Windows seed drive.

The Windows Assessment and Deployment Kit (and its schema) and Windows itself are not available where these tests
run, so the file is checked structurally: well-formed, the unattend namespace, the element order of the published
Microsoft samples, ONLY the specialize pass, two commands that only copy files (plain cmd, no PowerShell), nothing
that could make Setup non-interactive, and the command lines (escaping, length, markers). It was never run on a
real Windows Setup.
"""
import re
import unittest
import xml.etree.ElementTree as ET
from unittest import mock

from tests.helpers import app

NS = "urn:schemas-microsoft-com:unattend"
WCM = "http://schemas.microsoft.com/WMIConfig/2002/State"
Q = "{" + NS + "}"

# Words that must not appear anywhere in the file (case-insensitive): disk, licence, account, locale, hardware-check
# bypass, restart and other-pass settings. The specialize step runs no PowerShell, so "bypass" never appears either.
FORBIDDEN = (
    "DiskConfiguration", "ImageInstall", "ProductKey", "AcceptEula", "UserData", "AutoLogon", "LocalAccount",
    "LabConfig", "BypassTPMCheck", "BypassSecureBootCheck", "BypassRAMCheck", "BypassCPUCheck", "Reseal",
    "shutdown", "Restart", "reboot", "oobeSystem", "windowsPE", "SetupUILanguage", "InputLocale", "UILanguage",
    "SystemLocale", "UserLocale", "UserAccounts", "FirstLogonCommands", "OOBE", "Password", "Credentials",
    "PartitionID", "DiskID", "InstallTo", "WillReboot", "Format", "Wipe", "diskpart", "reg add", "TimeZone",
)


class XmlBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = app.windows_seed_autounattend(app.HARDENING_BASELINE)
        cls.text = cls.data.decode("utf-8")
        cls.root = ET.fromstring(cls.data)  # noqa: S314 - bytes built by our own code, not untrusted input
        cls.commands = [el.text for el in cls.root.findall(f".//{Q}Path")]
        cls.stage_ps1, cls.stage_cmd = cls.commands  # Order 1: harden.ps1, Order 2: SetupComplete.cmd


class StructureTests(XmlBase):
    def test_is_bytes_utf8_ascii_with_declaration(self):
        self.assertIsInstance(self.data, bytes)
        self.assertTrue(self.data.startswith(b'<?xml version="1.0" encoding="utf-8"?>'))
        self.assertFalse(self.data.startswith(b"\xef\xbb\xbf"))
        self.data.decode("ascii")

    def test_crlf_only(self):
        self.assertIn(b"\r\n", self.data)
        self.assertNotRegex(self.data, rb"(?<!\r)\n")

    def test_parses_and_uses_the_unattend_namespace(self):
        self.assertEqual(self.root.tag, Q + "unattend")
        for el in self.root.iter():
            self.assertTrue(el.tag.startswith(Q), el.tag)

    def test_only_the_specialize_pass(self):
        settings = self.root.findall(f"{Q}settings")
        self.assertEqual([s.get("pass") for s in settings], ["specialize"])
        self.assertEqual(len(list(self.root)), 1)  # nothing but <settings> under <unattend>

    def test_one_component_deployment_amd64(self):
        comps = self.root.findall(f"{Q}settings/{Q}component")
        self.assertEqual(len(comps), 1)
        comp = comps[0]
        self.assertEqual(comp.get("name"), "Microsoft-Windows-Deployment")
        self.assertEqual(comp.get("processorArchitecture"), "amd64")
        self.assertEqual(comp.get("publicKeyToken"), "31bf3856ad364e35")
        self.assertEqual(comp.get("language"), "neutral")
        self.assertEqual(comp.get("versionScope"), "nonSxS")
        self.assertEqual([c.tag for c in comp], [Q + "RunSynchronous"])  # nothing else inside the component
        self.assertNotIn("arm64", self.text)  # UNVERIFIED for Windows on ARM: left out on purpose

    def test_two_commands_with_the_published_element_order(self):
        cmds = self.root.findall(f".//{Q}RunSynchronousCommand")
        self.assertEqual(len(cmds), 2)
        for n, cmd in enumerate(cmds, 1):
            self.assertEqual(cmd.get(f"{{{WCM}}}action"), "add")
            self.assertEqual([c.tag for c in cmd], [Q + "Order", Q + "Path", Q + "Description"])
            self.assertEqual(int(cmd.find(f"{Q}Order").text), n)
        self.assertEqual(len(self.root.findall(f".//{Q}RunSynchronous")), 1)

    def test_descriptions_are_short_plain_text(self):
        descs = [el.text for el in self.root.findall(f".//{Q}Description")]
        self.assertEqual(tuple(descs), app.WINDOWS_SEED_STEP_TEXTS)
        for desc in descs:
            self.assertLessEqual(len(desc), 100)
            self.assertNotRegex(desc, r"[<>&\"']")

    def test_only_the_expected_element_names(self):
        names = {el.tag[len(Q):] for el in self.root.iter()}
        self.assertEqual(names, {"unattend", "settings", "component", "RunSynchronous", "RunSynchronousCommand",
                                 "Order", "Path", "Description"})

    def test_deterministic(self):
        self.assertEqual(app.windows_seed_autounattend(app.HARDENING_BASELINE), self.data)

    def test_none_profile_gives_nothing_and_unknown_profile_raises(self):
        self.assertEqual(app.windows_seed_autounattend(app.HARDENING_NONE), b"")
        with self.assertRaises(ValueError):
            app.windows_seed_autounattend("bogus")


class ForbiddenContentTests(XmlBase):
    def test_no_forbidden_element_or_word(self):
        low = self.text.lower()
        for word in FORBIDDEN:
            with self.subTest(word=word):
                self.assertNotIn(word.lower(), low)

    def test_no_powershell_at_all(self):
        # The specialize pass only stages files: PowerShell (DISM, Defender, firewall) belongs to SetupComplete.cmd.
        for word in ("powershell", "pwsh", "-ExecutionPolicy", "bypass", "-File", "-Mode", "-Command"):
            with self.subTest(word=word):
                self.assertNotIn(word.lower(), self.text.lower())

    def test_no_compliance_words(self):
        for word in ("CIS", "STIG", "NIST", "compliant", "compliance", "certified"):
            with self.subTest(word=word):
                self.assertIsNone(re.search(r"\b" + word + r"\b", self.text, re.IGNORECASE))

    def test_no_download_or_remote_code(self):
        for word in ("iex", "Invoke-Expression", "Invoke-WebRequest", "Invoke-RestMethod", "DownloadString",
                     "DownloadFile", "http://", "https://", "curl", "wget", "bitsadmin", "certutil", "Start-BitsTransfer",
                     "-EncodedCommand", "-enc "):
            with self.subTest(word=word):
                if word == "http://":
                    # the only URL allowed is the wcm schema namespace declaration
                    urls = re.findall(r"https?://[^\"' <>]+", self.text)
                    self.assertEqual(sorted(set(urls)), ["http://schemas.microsoft.com/WMIConfig/2002/State",
                                                         "http://www.w3.org/2001/XMLSchema-instance"])
                elif word == "https://":
                    self.assertNotIn(word, self.text)
                else:
                    self.assertIsNone(re.search(r"(?<![A-Za-z-])" + re.escape(word) + r"(?![A-Za-z])", self.text,
                                                re.IGNORECASE))


class CommandTests(XmlBase):
    def test_commands_are_the_constants_after_a_round_trip_through_xml(self):
        # The file holds `&amp;`; a parser hands back the plain `&`, and that is the command Windows runs.
        self.assertEqual(tuple(self.commands), app.WINDOWS_SEED_COMMANDS)
        self.assertEqual(self.text.count("&amp;"), sum(c.count("&") for c in self.commands))
        self.assertNotRegex(self.text, r"&(?!amp;)")
        for command in self.commands:
            self.assertNotIn("<", command)  # the only characters XML needs escaped are & and <
            self.assertNotIn(">", command)  # no redirection needed: a failing md only prints a line

    def test_length_is_below_the_documented_path_limit(self):
        self.assertEqual(app.WINDOWS_SEED_PATH_MAX, 259)
        for command in self.commands:
            with self.subTest(command=command[-40:]):
                self.assertLessEqual(len(command), app.WINDOWS_SEED_PATH_MAX)

    def test_too_long_command_is_refused(self):
        for i in range(len(app.WINDOWS_SEED_COMMANDS)):
            long = list(app.WINDOWS_SEED_COMMANDS)
            long[i] = "x" * 260
            with self.subTest(i=i), mock.patch.object(app, "WINDOWS_SEED_COMMANDS", tuple(long)):
                with self.assertRaises(ValueError):
                    app.windows_seed_autounattend(app.HARDENING_BASELINE)

    def test_run_through_cmd_and_do_not_start_with_a_quote(self):
        for command in self.commands:
            self.assertTrue(command.startswith("cmd /c ("))
            self.assertFalse(command.split("/c ", 1)[1].startswith('"'))  # cmd would strip a leading quote

    def test_look_for_the_marker_on_d_to_z(self):
        self.assertEqual(app.WINDOWS_SEED_MARKER, "EPMA-SEED.txt")
        for command in self.commands:
            with self.subTest(command=command[-40:]):
                self.assertIn("if exist %d\\EPMA-SEED.txt", command)
                m = re.search(r"for %d in \(([^)]*)\) do", command)
                self.assertIsNotNone(m)
                self.assertEqual(m.group(1).split(), [c + ":" for c in "DEFGHIJKLMNOPQRSTUVWXYZ"])
                self.assertNotIn("C:", m.group(1))

    def test_stage_the_script_into_setup_scripts(self):
        # Order 1: the folder is created (a message if it exists is harmless), then harden.ps1 is copied into it.
        cmd = self.stage_ps1
        self.assertIn("md %SystemRoot%\\Setup\\Scripts", cmd)
        self.assertIn("copy /y %d\\harden.ps1 %SystemRoot%\\Setup\\Scripts\\", cmd)
        self.assertLess(cmd.index("md "), cmd.index("copy "))
        self.assertNotIn("SetupComplete.cmd", cmd)

    def test_stage_setupcomplete_only_if_none_exists_there(self):
        # Order 2: an existing SetupComplete.cmd is never overwritten. The `if` is in parentheses: written
        # `if c a & b`, b would also depend on c.
        cmd = self.stage_cmd
        guard = ("(if not exist %SystemRoot%\\Setup\\Scripts\\SetupComplete.cmd "
                 "copy %d\\SetupComplete.cmd %SystemRoot%\\Setup\\Scripts\\)")
        self.assertIn(guard, cmd)
        self.assertEqual(cmd.count("copy"), 1)
        self.assertNotIn("/y", cmd)  # never the overwrite switch
        self.assertNotIn("harden.ps1", cmd)

    def test_only_md_and_copy_run_nothing_else(self):
        # No PowerShell, no script, no program from the seed drive: the commands only move two files.
        for command in self.commands:
            with self.subTest(command=command[-40:]):
                body = re.sub(r"^cmd /c \(for %d in \([^)]*\) do if exist %d\\EPMA-SEED\.txt ", "", command)
                body = body.replace("%SystemRoot%\\Setup\\Scripts", "").replace("%d\\", "")
                words = set(re.findall(r"[A-Za-z]+(?:\.[A-Za-z0-9]+)?", body))
                self.assertLessEqual(words, {"md", "copy", "y", "if", "not", "exist", "exit",
                                             "SetupComplete.cmd", "harden.ps1"})
                for bad in ("powershell", "start ", "call ", "wscript", "cscript", "rundll32", "msiexec", "*"):
                    self.assertNotIn(bad, command.lower())

    def test_single_percent_loop_variable_and_no_colon_right_after_it(self):
        # A command line (not a batch file) uses %d, never %%d; "%d:" could be read as the substring syntax.
        for command in self.commands:
            self.assertNotIn("%%", command)
            self.assertNotIn("%d:", command)
            self.assertEqual(set(re.findall(r"%[^ \\]*", command)), {"%d", "%SystemRoot%"})

    def test_stop_after_the_first_hit_and_always_exit_zero(self):
        for command in self.commands:
            with self.subTest(command=command[-40:]):
                self.assertEqual(command.count("exit 0"), 2)  # one after the staging (stops looking), one after the loop
                self.assertTrue(command.endswith("& exit 0"))
                self.assertNotIn("exit 1", command)
                self.assertIsNone(re.search(r"exit\s+/b\s+[1-9]", command))
                self.assertNotRegex(command, r"\bgoto\b")

    def test_parentheses_and_quotes_are_balanced(self):
        for command in self.commands:
            with self.subTest(command=command[-40:]):
                self.assertEqual(command.count("("), command.count(")"))
                depth = 0
                for ch in command:
                    depth += (ch == "(") - (ch == ")")
                    self.assertGreaterEqual(depth, 0)
                self.assertEqual(depth, 0)
                self.assertEqual(command.count('"') % 2, 0)

    def test_an_if_followed_by_more_commands_is_in_parentheses(self):
        # `if c a & b` would run b only when c is true: every `if` except the loop's own `if exist` is wrapped.
        for command in self.commands:
            for m in re.finditer(r"\bif\b", command):
                if command[:m.start()].endswith(") do "):
                    continue  # the loop's own `if exist`, whose action is the parenthesised block
                self.assertEqual(command[m.start() - 1], "(", command)

    def test_nothing_that_stops_or_restarts_the_machine(self):
        for command in self.commands:
            low = command.lower()
            for word in ("shutdown", "restart", "reboot", "logoff", "taskkill", "del ", "format", "diskpart", "reg ", "net "):
                with self.subTest(word=word):
                    self.assertNotIn(word, low)

    def test_ascii_only(self):
        for command in self.commands:
            command.encode("ascii")


class DescribeTests(unittest.TestCase):
    def setUp(self):
        self.lines = app.describe_windows_seed_during_setup()

    def test_plain_english_lines(self):
        self.assertGreaterEqual(len(self.lines), 5)
        self.assertEqual(len(set(self.lines)), len(self.lines))
        for line in self.lines:
            with self.subTest(line=line[:50]):
                self.assertIsInstance(line, str)
                line.encode("ascii")
                self.assertTrue(line.strip())
                self.assertNotIn("{", line)  # translated texts are plain, never format strings
                self.assertNotIn("\n", line)

    def test_says_experimental_and_what_it_does_not_do(self):
        blob = " ".join(self.lines)
        self.assertIn("EXPERIMENTAL", self.lines[0])
        for must in ("EPMA-SEED.txt", "harden.ps1", "SetupComplete.cmd", "autounattend.xml", "interactive", "plugged in"):
            with self.subTest(must=must):
                self.assertIn(must, blob)
        for denied in ("erase a disk", "product key", "accounts", "restart", "download"):
            with self.subTest(denied=denied):
                self.assertIn(denied, blob)

    def test_describes_the_staging_design_not_the_old_one(self):
        blob = " ".join(self.lines)
        for must in ("only copies files", "C:\\Windows\\Setup\\Scripts", "never overwritten", "very end of Setup",
                     "SHA-256", "C:\\Windows\\Temp\\epma-hardening.log", "before Setup starts", "first restart",
                     "can be unplugged", "does not authenticate", "first drive from D: to Z:", "made yourself",
                     "start the installation again from the beginning", "could not parse or process", "ARM64"):
            with self.subTest(must=must):
                self.assertIn(must, blob)
        for old in ("runs harden.ps1 from that drive", "Keep both drives plugged in"):
            self.assertNotIn(old, blob)

    def test_no_compliance_claims(self):
        blob = " ".join(self.lines)
        for word in ("CIS", "STIG", "NIST", "compliant", "compliance", "certified"):
            with self.subTest(word=word):
                self.assertIsNone(re.search(r"\b" + word + r"\b", blob, re.IGNORECASE))

    def test_every_line_has_a_portuguese_translation(self):
        for line in self.lines:
            with self.subTest(line=line[:60]):
                self.assertIn(line, app.PT_BR)
                pt = app.PT_BR[line]
                self.assertTrue(pt.strip())
                self.assertNotEqual(pt, line)
                for token in ("EPMA-SEED.txt", "harden.ps1", "SetupComplete.cmd", "autounattend.xml", "EXPERIMENTAL",
                              "C:\\Windows\\Setup\\Scripts", "C:\\Windows\\Temp\\epma-hardening.log", "SHA-256"):
                    self.assertEqual(token in line, token in pt, token)
                with mock.patch.object(app, "ACTIVE_LANGUAGE", "pt"):
                    self.assertEqual(app._(line), pt)

    def test_returns_a_fresh_list(self):
        self.lines.append("x")
        self.assertNotIn("x", app.describe_windows_seed_during_setup())


class ContractTests(unittest.TestCase):
    def test_seed_windows_is_a_seed_target(self):
        self.assertEqual(app.SEED_WINDOWS, "windows")
        self.assertIn(app.SEED_WINDOWS, app.SEED_TARGETS)
        self.assertEqual(app.SEED_TARGETS[:3], (app.SEED_UBUNTU, app.SEED_FEDORA, app.SEED_DEBIAN))


if __name__ == "__main__":
    unittest.main()
