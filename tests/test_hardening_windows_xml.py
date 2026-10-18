"""Tests for the autounattend.xml of the EXPERIMENTAL "during setup" Windows seed drive.

The Windows Assessment and Deployment Kit (and its schema) and Windows itself are not available where these tests
run, so the file is checked structurally: well-formed, the unattend namespace, the element order of the published
Microsoft samples, ONLY the specialize pass, ONE command, nothing that could make Setup non-interactive, and the
command line (escaping, length, markers). It was never run on a real Windows Setup.
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
# bypass, restart and other-pass settings. "Bypass" alone is allowed ONLY as the PowerShell execution policy.
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
        cls.path_elem = cls.root.find(f".//{Q}Path")
        cls.command = cls.path_elem.text


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

    def test_exactly_one_command_with_the_published_element_order(self):
        cmds = self.root.findall(f".//{Q}RunSynchronousCommand")
        self.assertEqual(len(cmds), 1)
        cmd = cmds[0]
        self.assertEqual(cmd.get(f"{{{WCM}}}action"), "add")
        self.assertEqual([c.tag for c in cmd], [Q + "Order", Q + "Path", Q + "Description"])
        self.assertEqual(cmd.find(f"{Q}Order").text, "1")
        self.assertEqual(self.root.findall(f".//{Q}RunSynchronous")[0].tag, Q + "RunSynchronous")
        self.assertEqual(len(self.root.findall(f".//{Q}RunSynchronous")), 1)

    def test_order_is_an_integer(self):
        self.assertEqual(int(self.root.find(f".//{Q}Order").text), 1)

    def test_description_is_short_plain_text(self):
        desc = self.root.find(f".//{Q}Description").text
        self.assertEqual(desc, app.WINDOWS_SEED_STEP_TEXT)
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

    def test_bypass_only_as_execution_policy(self):
        hits = [m.start() for m in re.finditer("bypass", self.text, re.IGNORECASE)]
        self.assertEqual(len(hits), 1)
        self.assertIn("-ExecutionPolicy Bypass", self.text)

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
    def test_command_is_the_constant_after_a_round_trip_through_xml(self):
        # The file holds `&amp;`; a parser hands back the plain `&`, and that is the command Windows runs.
        self.assertEqual(self.command, app.WINDOWS_SEED_COMMAND)
        self.assertIn("&amp;", self.text)
        self.assertNotRegex(self.text, r"&(?!amp;)")
        self.assertNotIn("<", self.command)
        self.assertNotIn(">", self.command)  # no redirection: nothing needs more escaping

    def test_length_is_below_the_documented_path_limit(self):
        self.assertEqual(app.WINDOWS_SEED_PATH_MAX, 259)
        self.assertLessEqual(len(self.command), app.WINDOWS_SEED_PATH_MAX)
        self.assertLess(len(self.command), 250)  # headroom

    def test_too_long_command_is_refused(self):
        with mock.patch.object(app, "WINDOWS_SEED_COMMAND", "x" * 260):
            with self.assertRaises(ValueError):
                app.windows_seed_autounattend(app.HARDENING_BASELINE)

    def test_runs_through_cmd_and_does_not_start_with_a_quote(self):
        self.assertTrue(self.command.startswith("cmd /c ("))
        self.assertFalse(self.command.split("/c ", 1)[1].startswith('"'))  # cmd would strip a leading quote

    def test_looks_for_the_marker_on_d_to_z(self):
        self.assertEqual(app.WINDOWS_SEED_MARKER, "EPMA-SEED.txt")
        self.assertIn("if exist %d\\EPMA-SEED.txt", self.command)
        m = re.search(r"for %d in \(([^)]*)\) do", self.command)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1).split(), [c + ":" for c in "DEFGHIJKLMNOPQRSTUVWXYZ"])
        self.assertNotIn("C:", m.group(1))

    def test_runs_the_script_from_the_found_drive_in_apply_mode(self):
        self.assertIn('powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%d\\harden.ps1" -Mode Apply', self.command)
        self.assertEqual(self.command.count("powershell.exe"), 1)
        self.assertEqual(self.command.count("-Mode"), 1)

    def test_single_percent_loop_variable_and_no_colon_right_after_it(self):
        # A command line (not a batch file) uses %d, never %%d; "%d:" could be read as the substring syntax.
        self.assertNotIn("%%", self.command)
        self.assertNotIn("%d:", self.command)
        self.assertEqual(set(re.findall(r"%[^ \\]*", self.command)), {"%d"})

    def test_stops_after_the_first_hit_and_always_exits_zero(self):
        self.assertEqual(self.command.count("exit 0"), 2)  # one after the script (stops looking), one after the loop
        self.assertTrue(self.command.endswith("& exit 0"))
        self.assertNotIn("exit 1", self.command)
        self.assertIsNone(re.search(r"exit\s+/b\s+[1-9]", self.command))
        self.assertNotRegex(self.command, r"\bgoto\b")

    def test_parentheses_and_quotes_are_balanced(self):
        self.assertEqual(self.command.count("("), self.command.count(")"))
        depth = 0
        for ch in self.command:
            depth += (ch == "(") - (ch == ")")
            self.assertGreaterEqual(depth, 0)
        self.assertEqual(depth, 0)
        self.assertEqual(self.command.count('"') % 2, 0)

    def test_nothing_that_stops_or_restarts_the_machine(self):
        low = self.command.lower()
        for word in ("shutdown", "restart", "reboot", "logoff", "taskkill", "del ", "format", "diskpart", "reg ", "net "):
            with self.subTest(word=word):
                self.assertNotIn(word, low)

    def test_ascii_only(self):
        self.command.encode("ascii")


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
        for must in ("EPMA-SEED.txt", "harden.ps1", "autounattend.xml", "interactive", "plugged in"):
            with self.subTest(must=must):
                self.assertIn(must, blob)
        for denied in ("erase a disk", "product key", "accounts", "restart", "download"):
            with self.subTest(denied=denied):
                self.assertIn(denied, blob)

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
                for token in ("EPMA-SEED.txt", "harden.ps1", "autounattend.xml", "EXPERIMENTAL"):
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
