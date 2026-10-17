"""Tests for the Windows 11 hardened-setup files (SetupComplete.cmd and harden.ps1, nothing else).

The content is pure text built in memory. PowerShell is not available where these tests run, so the script
is checked structurally (balanced blocks, markers, banned commands) and never executed.
"""
import re
import unittest
from unittest import mock

from tests.helpers import app

CMD_PATH = "sources/$OEM$/$$/Setup/Scripts/SetupComplete.cmd"
PS1_PATH = "sources/$OEM$/$$/Setup/Scripts/harden.ps1"
EXPECTED_PATHS = {CMD_PATH, PS1_PATH}

MAX_FILE = 256 * 1024
MAX_TOTAL = 2 * 1024 * 1024
MAX_PATH = 240

def _check_relative_path(path):
    """A simple relative-path check, mirroring the shared validator's rules (written out here on purpose)."""
    if not path or len(path) > MAX_PATH:
        return False
    if "\\" in path or "\x00" in path or path.startswith("/") or re.match(r"^[A-Za-z]:", path):
        return False
    parts = path.split("/")
    return all(p not in ("", ".", "..") for p in parts)


class HardeningWindowsBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = app.hardening_files_windows(app.HARDENING_BASELINE)
        cls.cmd_bytes = cls.files[CMD_PATH]
        cls.ps1_bytes = cls.files[PS1_PATH]
        cls.cmd_text = cls.cmd_bytes.decode("ascii")
        cls.ps1_text = cls.ps1_bytes.decode("utf-8-sig")


class ProfileTests(HardeningWindowsBase):
    def test_none_profile_returns_nothing(self):
        self.assertEqual(app.hardening_files_windows(app.HARDENING_NONE), {})
        self.assertEqual(app.describe_hardening_windows(app.HARDENING_NONE), [])

    def test_unknown_profile_is_refused(self):
        for bad in ("", "strict", "BASELINE", None, 1):
            with self.subTest(profile=bad):
                with self.assertRaises(ValueError):
                    app.hardening_files_windows(bad)
                with self.assertRaises(ValueError):
                    app.describe_hardening_windows(bad)

    def test_baseline_is_a_known_profile(self):
        self.assertIn(app.HARDENING_BASELINE, app.HARDENING_PROFILES)

    def test_contract_constants(self):
        self.assertEqual(app.MODE_SEED, "seed")
        self.assertEqual(app.HARDENING_PROFILES, (app.HARDENING_NONE, app.HARDENING_BASELINE))
        self.assertEqual(app.SEED_TARGETS, ("ubuntu", "fedora", "debian"))

    def test_deterministic(self):
        self.assertEqual(self.files, app.hardening_files_windows(app.HARDENING_BASELINE))


class FileSetTests(HardeningWindowsBase):
    def test_exact_paths(self):
        self.assertEqual(set(self.files), EXPECTED_PATHS)

    def test_no_answer_file_anywhere(self):
        # The $OEM$ mechanism needs no answer file, and Windows Setup must stay fully interactive.
        for path, data in self.files.items():
            with self.subTest(path=path):
                self.assertNotIn("unattend", path.lower())
                self.assertNotIn(b"unattend", data.lower())
        self.assertFalse(hasattr(app, "WINDOWS_HARDENING_AUTOUNATTEND"))
        self.assertFalse(hasattr(app, "_windows_autounattend_xml"))

    def test_oem_paths_are_literal(self):
        # `$OEM$` and `$$` are what Windows Setup looks for: they must reach the drive unchanged.
        self.assertEqual(CMD_PATH, "sources/$OEM$/$$/Setup/Scripts/SetupComplete.cmd")
        self.assertIn("sources/$OEM$/$$/Setup/Scripts/SetupComplete.cmd", self.files)
        self.assertIn("sources/$OEM$/$$/Setup/Scripts/harden.ps1", self.files)

    def test_values_are_bytes(self):
        for path, data in self.files.items():
            with self.subTest(path=path):
                self.assertIsInstance(data, bytes)
                self.assertTrue(data)

    def test_paths_are_safe_relative_posix(self):
        for path in self.files:
            with self.subTest(path=path):
                self.assertTrue(_check_relative_path(path))

    def test_path_check_itself(self):
        for bad in ("", "/etc/x", "../x", "a/../b", "a\\b", "a//b", "C:/x", "a\x00b", "x" * 241):
            self.assertFalse(_check_relative_path(bad), bad)

    def test_sizes_within_limits(self):
        for path, data in self.files.items():
            with self.subTest(path=path):
                self.assertLessEqual(len(data), MAX_FILE)
        self.assertLessEqual(sum(len(d) for d in self.files.values()), MAX_TOTAL)

    def test_shared_validator_accepts_the_files_when_present(self):
        validate = getattr(app, "validate_seed_files", None)
        if validate is None:
            self.skipTest("validate_seed_files is not merged into this branch yet")
        self.assertEqual(validate(self.files), self.files)

    def test_plain_ascii_everywhere(self):
        for path, data in self.files.items():
            with self.subTest(path=path):
                data.decode("ascii") if path != PS1_PATH else data[3:].decode("ascii")

    def test_never_claims_a_compliance_standard(self):
        blob = " ".join([self.cmd_text, self.ps1_text, *app.describe_hardening_windows(app.HARDENING_BASELINE)])
        for word in ("CIS", "STIG", "NIST", "compliant", "certified"):
            with self.subTest(word=word):
                self.assertIsNone(re.search(r"\b" + word + r"\b", blob, re.IGNORECASE))


class SetupCompleteTests(HardeningWindowsBase):
    def test_crlf_only_and_no_bom(self):
        self.assertFalse(self.cmd_bytes.startswith(b"\xef\xbb\xbf"))
        self.assertIn(b"\r\n", self.cmd_bytes)
        self.assertNotRegex(self.cmd_bytes, rb"(?<!\r)\n")

    def test_runs_the_script_the_documented_way(self):
        self.assertIn('powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0harden.ps1"', self.cmd_text)

    def test_logs_to_the_documented_file(self):
        self.assertIn("%windir%\\Temp\\epma-hardening.log", self.cmd_text)
        self.assertIn(">> \"%EPMA_LOG%\" 2>&1", self.cmd_text)

    def test_never_fails_the_setup(self):
        lines = [ln.strip().lower() for ln in self.cmd_text.splitlines() if ln.strip()]
        self.assertEqual(lines[-1], "exit /b 0")
        # Every exit of the batch file must be a success code.
        for ln in lines:
            if ln.startswith("exit"):
                self.assertEqual(ln, "exit /b 0")
        self.assertNotIn("shutdown", self.cmd_text.lower())
        self.assertNotIn("reboot", self.cmd_text.lower())

    def test_errorlevel_is_not_read_inside_a_block(self):
        # %errorlevel% inside a parenthesised block is expanded before the command runs.
        self.assertNotIn("(", self.cmd_text.replace("(ignored)", ""))

    def test_does_not_use_the_network(self):
        low = self.cmd_text.lower()
        for word in ("curl", "wget", "bitsadmin", "http://", "https://", "certutil"):
            self.assertNotIn(word, low)


class HardenScriptTests(HardeningWindowsBase):
    def test_bom_and_crlf(self):
        # PowerShell 5.1 reads a file without a BOM as ANSI; the BOM makes it UTF-8.
        self.assertTrue(self.ps1_bytes.startswith(b"\xef\xbb\xbf"))
        body = self.ps1_bytes[3:]
        self.assertIn(b"\r\n", body)
        self.assertNotRegex(body, rb"(?<!\r)\n")

    def test_blocks_are_balanced(self):
        text = self.ps1_text
        for open_c, close_c in (("{", "}"), ("(", ")"), ("[", "]")):
            with self.subTest(pair=open_c + close_c):
                self.assertEqual(text.count(open_c), text.count(close_c))
        # Never negative while scanning (a closer before its opener).
        depth = 0
        for ch in text:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                self.assertGreaterEqual(depth, 0)
        self.assertEqual(depth, 0)

    def test_quotes_are_balanced(self):
        # Single quotes: an even number per line once doubled quotes are removed (no multi-line strings used).
        for n, line in enumerate(self.ps1_text.splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            self.assertEqual(line.replace("''", "").count("'") % 2, 0, f"line {n}: {line}")

    def test_every_try_has_a_catch(self):
        tries = len(re.findall(r"\btry\s*\{", self.ps1_text))
        catches = len(re.findall(r"\bcatch\s*\{", self.ps1_text))
        self.assertEqual(tries, catches)
        self.assertGreaterEqual(tries, len(app.WINDOWS_HARDENING_SETTINGS))

    def test_every_setting_id_is_in_the_script_once(self):
        found = re.findall(r"^# setting: (\w+)\s*$", self.ps1_text, re.MULTILINE)
        self.assertEqual(found, [s[0] for s in app.WINDOWS_HARDENING_SETTINGS])
        for sid, _text, _risk in app.WINDOWS_HARDENING_SETTINGS:
            self.assertIn(sid, self.ps1_text)

    def test_every_setting_has_its_own_handler(self):
        # Split the script at the markers; each part must carry its own try and catch.
        parts = re.split(r"^# setting: \w+\s*$", self.ps1_text, flags=re.MULTILINE)[1:]
        self.assertEqual(len(parts), len(app.WINDOWS_HARDENING_SETTINGS))
        for (sid, _t, _r), part in zip(app.WINDOWS_HARDENING_SETTINGS, parts, strict=True):
            with self.subTest(setting=sid):
                self.assertRegex(part, r"\btry\s*\{")
                self.assertRegex(part, r"\bcatch\s*\{")
                self.assertIn("Write-Result 'FAIL'", part)

    def test_code_and_settings_match(self):
        self.assertEqual([s[0] for s in app.WINDOWS_HARDENING_SETTINGS], list(app._WINDOWS_PS_CODE))

    def test_every_setting_has_text_and_a_risk_note(self):
        ids = set()
        for row in app.WINDOWS_HARDENING_SETTINGS:
            self.assertEqual(len(row), 3)
            sid, text, risk = row
            with self.subTest(setting=sid):
                self.assertRegex(sid, r"^[a-z0-9_]+$")
                self.assertNotIn(sid, ids)
                ids.add(sid)
                self.assertGreater(len(text), 10)
                self.assertGreater(len(risk), 20)
                self.assertTrue(risk.endswith("."))
                # The risk note is in the script header too.
                self.assertIn(risk, self.ps1_text)

    def test_log_line_format(self):
        for tag in ("OK", "SKIP", "WARN", "FAIL"):
            self.assertIn(f"'{tag}'", self.ps1_text)
        self.assertIn("Write-Host ('[' + $Status + '] ' + $What + ' (' + $Why + ')')", self.ps1_text)
        # Every Write-Result call passes a status, what and why.
        for m in re.finditer(r"^\s*Write-Result (.*)$", self.ps1_text, re.MULTILINE):
            self.assertRegex(m.group(1), r"^'(OK|SKIP|WARN|FAIL)' ['(]", m.group(0))

    def test_exit_code_is_always_zero(self):
        self.assertTrue(self.ps1_text.rstrip().endswith("exit 0"))
        self.assertNotRegex(self.ps1_text, r"exit\s+[1-9]")

    def test_no_network_downloads_or_external_tools(self):
        banned = (
            "invoke-webrequest", "invoke-restmethod", "iwr ", "irm ", "downloadstring", "downloadfile",
            "start-bitstransfer", "net.webclient", "system.net", "http://", "https://", "curl", "wget",
            "choco", "winget", "scoop", "msiexec", "start-process", "invoke-expression", "iex ",
            "restart-computer", "stop-computer", "shutdown",
        )
        low = self.ps1_text.lower()
        for word in banned:
            with self.subTest(word=word):
                self.assertNotIn(word, low)

    def test_decisions_that_are_left_to_the_owner(self):
        low = self.ps1_text.lower()
        # BitLocker and NTLM are explained in comments but never touched.
        for call in ("enable-bitlocker", "manage-bde", "lmcompatibilitylevel", "restrictntlm", "restrictsendingntlm"):
            with self.subTest(call=call):
                self.assertNotIn(call, low)
        self.assertIn("bitlocker is not turned on automatically", low)
        self.assertIn("ntlm authentication levels are left as they are", low)

    def test_does_not_weaken_anything(self):
        low = self.ps1_text.lower()
        for bad in ("enablelua' -value 0", "-enabled false", "disableantispyware", "-disablerealtimemonitoring",
                    "-defaultinboundaction allow", "enablesmb1protocol $true", "-puaprotection disabled"):
            with self.subTest(bad=bad):
                self.assertNotIn(bad, low)

    def test_lsass_is_the_only_block_rule(self):
        self.assertIn("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", self.ps1_text)  # LSASS credential theft
        self.assertEqual(len(re.findall(r"-Action 'Enabled'", self.ps1_text)), 1)
        self.assertEqual(len(re.findall(r"-Action 'AuditMode'", self.ps1_text)), 1)  # one call inside the loop

    def test_audit_policy_uses_guids_not_translated_names(self):
        self.assertNotRegex(self.ps1_text, r"/subcategory:\"")
        self.assertEqual(len(re.findall(r"\{0CCE92[0-9A-F]{2}-69AE-11D9-BED3-505054503030\}", self.ps1_text)), 6)

    def _part(self, sid):
        parts = re.split(r"^# setting: (\w+)\s*$", self.ps1_text, flags=re.MULTILINE)
        return dict(zip(parts[1::2], parts[2::2], strict=True))[sid]

    def test_audit_uses_advanced_subcategories_and_says_so(self):
        text = {s[0]: s[1] for s in app.WINDOWS_HARDENING_SETTINGS}["audit"]
        self.assertIn("Advanced audit policy", text)
        self.assertNotIn("Basic audit policy", self.ps1_text)
        self.assertNotIn("basic audit", text.lower())

    def test_audit_raises_the_security_log_size_and_never_lowers_it(self):
        part = self._part("audit")
        self.assertIn("134217728", part)  # 128 MiB
        self.assertIn("wevtutil.exe sl Security", part)
        self.assertRegex(part, r"\$oldBytes -ge \$wantBytes")  # only raised, never lowered
        self.assertIn("Security log size raised from", part)  # old and new size are logged
        self.assertIn("MiB to", part)
        risk = {s[0]: s[2] for s in app.WINDOWS_HARDENING_SETTINGS}["audit"]
        self.assertIn("128 MiB", risk)
        self.assertIn("Retention is still limited", risk)
        self.assertEqual(134217728, 128 * 1024 * 1024)

    def test_audit_reports_each_rejected_subcategory_and_names_the_listing_command(self):
        part = self._part("audit")
        self.assertRegex(part, r"Write-Result 'FAIL' \('Audit subcategory '")
        self.assertIn("auditpol /list /subcategory:* /v", part)
        self.assertIn("$LASTEXITCODE -ne 0", part)

    def test_settings_are_read_back_before_saying_ok(self):
        for sid in ("firewall", "defender_cloud", "asr_lsass", "asr_audit"):
            with self.subTest(setting=sid):
                part = self._part(sid)
                self.assertRegex(part, r"Write-Result 'WARN' '[^']* not in effect'")
                self.assertIn("likely reason", part)
        self.assertEqual(self._part("firewall").count("Get-NetFirewallProfile"), 2)  # before and after setting
        self.assertEqual(self._part("defender_cloud").count("Get-MpPreference"), 2)
        self.assertIn("Get-AsrAction $ruleId", self._part("asr_lsass"))
        self.assertIn("Get-AsrAction $id", self._part("asr_audit"))
        self.assertIn("Tamper Protection", self.ps1_text)

    def test_warn_is_counted_and_reported_in_the_summary(self):
        self.assertIn("$script:CountWarn++", self.ps1_text)
        self.assertIn("not in effect, ' + $script:CountFail", self.ps1_text)

    def test_header_and_notes_say_it_runs_once_and_does_not_retry(self):
        head = self.ps1_text.split("function Write-Result")[0]
        self.assertIn("does NOT retry", head)
        by_id = {s[0]: s[2] for s in app.WINDOWS_HARDENING_SETTINGS}
        for sid in ("firewall", "defender_cloud", "asr_lsass", "asr_audit"):
            with self.subTest(setting=sid):
                self.assertIn("runs once at the end of Setup and does not retry", by_id[sid])

    def test_powershell_2_is_disabled_not_removed(self):
        text = {s[0]: s[1] for s in app.WINDOWS_HARDENING_SETTINGS}["ps2"]
        self.assertTrue(text.startswith("Disable"))
        for sid in ("ps2", "smb1"):
            part = self._part(sid)
            self.assertNotIn("removed", part)
            self.assertIn("disabled", part)
        self.assertNotIn("Remove the PowerShell", self.ps1_text)

    def test_optional_features_are_listed_only_once(self):
        # One slow Get-WindowsOptionalFeature call for the whole script, cached by Get-FeatureState.
        self.assertEqual(self.ps1_text.count("Get-WindowsOptionalFeature -Online"), 1)
        self.assertNotIn("Get-WindowsOptionalFeature", self._part("smb1"))
        self.assertNotIn("Get-WindowsOptionalFeature", self._part("ps2"))
        self.assertIn("Get-FeatureState", self._part("smb1"))
        self.assertIn("Get-FeatureState", self._part("ps2"))

    def test_autorun_note_mentions_phones_and_cameras(self):
        risk = {s[0]: s[2] for s in app.WINDOWS_HARDENING_SETTINGS}["autorun"]
        self.assertIn("phones", risk)
        self.assertIn("cameras", risk)

    def test_idempotence_helpers_exist(self):
        for name in ("Set-RegDword", "Set-AsrRule", "Get-AsrAction", "Get-FeatureState", "Write-Result"):
            self.assertIn(f"function {name}", self.ps1_text)

    def test_powershell_51_syntax_only(self):
        # Syntax that does not exist in Windows PowerShell 5.1.
        for token in ("?:", "&&", "||", "??", "?.", "-AsHashtable", "ForEach-Object -Parallel", "$IsWindows"):
            with self.subTest(token=token):
                self.assertNotIn(token, self.ps1_text)


class DescribeTests(HardeningWindowsBase):
    def test_one_line_per_setting(self):
        lines = app.describe_hardening_windows(app.HARDENING_BASELINE)
        self.assertEqual(len(lines), len(app.WINDOWS_HARDENING_SETTINGS))
        for line, (_sid, text, risk) in zip(lines, app.WINDOWS_HARDENING_SETTINGS, strict=True):
            self.assertIn(text, line)
            self.assertIn(risk, line)
            self.assertIsInstance(line, str)
            line.encode("ascii")

    def test_every_line_has_a_portuguese_translation(self):
        # The GUI shows these lines through _() in a Portuguese window: a line without an entry stays English.
        for line in app.describe_hardening_windows(app.HARDENING_BASELINE):
            with self.subTest(line=line[:60]):
                self.assertIn(line, app.PT_BR)
                pt = app.PT_BR[line]
                self.assertTrue(pt.strip())
                self.assertNotEqual(pt, line)
                self.assertIn(" -- risco: ", pt)
                self.assertEqual(line.count("[WARN]"), pt.count("[WARN]"))
                with mock.patch.object(app, "ACTIVE_LANGUAGE", "pt"):
                    self.assertEqual(app._(line), pt)
        self.assertEqual(app.PT_BR[app.describe_hardening_windows(app.HARDENING_BASELINE)[0]].count(" -- risco: "), 1)

    def test_returns_a_fresh_list(self):
        a = app.describe_hardening_windows(app.HARDENING_BASELINE)
        a.append("x")
        self.assertNotIn("x", app.describe_hardening_windows(app.HARDENING_BASELINE))

    def test_not_changed_notes_exist(self):
        ids = {row[0] for row in app.WINDOWS_HARDENING_NOT_CHANGED}
        self.assertTrue({"bitlocker", "ntlm"} <= ids)
        for _sid, text, why in app.WINDOWS_HARDENING_NOT_CHANGED:
            self.assertTrue(text and why)


if __name__ == "__main__":
    unittest.main()
