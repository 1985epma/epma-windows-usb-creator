"""Tests for the Windows 11 hardened-setup files (SetupComplete.cmd and harden.ps1, nothing else).

The content is pure text built in memory. PowerShell is not available where these tests run, so the script
is checked structurally (balanced blocks, markers, banned commands) and never executed.
"""
import hashlib
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
        self.assertEqual(app.SEED_WINDOWS, "windows")
        self.assertEqual(app.SEED_TARGETS, ("ubuntu", "fedora", "debian", "windows"))

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
    PS = "%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    def lines(self):
        return self.cmd_text.split("\r\n")[:-1]

    def want(self):
        m = re.search(r'^set "EPMA_WANT=([0-9a-f]+)"\r?$', self.cmd_text, re.MULTILINE)
        self.assertIsNotNone(m)
        return m.group(1)

    def test_crlf_only_and_no_bom(self):
        self.assertFalse(self.cmd_bytes.startswith(b"\xef\xbb\xbf"))
        self.assertIn(b"\r\n", self.cmd_bytes)
        self.assertNotRegex(self.cmd_bytes, rb"(?<!\r)\n")

    def test_runs_the_script_the_documented_way_by_full_path(self):
        self.assertIn(self.PS + ' -NoProfile -ExecutionPolicy Bypass -File "%~dp0harden.ps1"', self.cmd_text)
        for line in self.lines():
            self.assertFalse(line.lower().startswith("powershell"), line)  # never the bare name

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
        # %errorlevel% inside a parenthesised block is expanded before the command runs: the only parentheses
        # are the single-line `for /f` command and the words in two log lines.
        text = self.cmd_text.replace("(ignored)", "").replace("(certutil failed)", "")
        text = re.sub(r"in \('[^']*'\)", "", text)
        self.assertNotIn("(", text)
        self.assertNotIn(")", text)

    def test_does_not_use_the_network(self):
        low = self.cmd_text.lower()
        for word in ("curl", "wget", "bitsadmin", "http://", "https://", "invoke-webrequest", "downloadfile"):
            self.assertNotIn(word, low)
        # certutil is only used with -hashfile, which reads a local file and prints its hash
        self.assertEqual(re.findall(r"certutil\.exe\s+(\S+)", self.cmd_text), ["-hashfile"])

    # ---- the SHA-256 check of harden.ps1
    def test_embedded_hash_is_the_sha256_of_the_shipped_script(self):
        digest = hashlib.sha256(self.ps1_bytes).hexdigest()
        self.assertEqual(self.want(), digest)
        self.assertEqual(self.want(), hashlib.sha256(app.windows_hardening_ps1(app.HARDENING_BASELINE)).hexdigest())
        self.assertEqual(len(self.want()), 64)

    def test_the_hash_line_changes_when_the_script_changes(self):
        base = app.hardening_files_windows(app.HARDENING_BASELINE)[CMD_PATH]
        other = b"\xef\xbb\xbf# another harden.ps1\r\n"
        with mock.patch.object(app, "windows_hardening_ps1", return_value=other), \
                mock.patch.object(app, "_windows_harden_ps1", return_value=other):
            changed = app.hardening_files_windows(app.HARDENING_BASELINE)
        self.assertNotEqual(changed[CMD_PATH], base)
        self.assertIn(('set "EPMA_WANT=' + hashlib.sha256(other).hexdigest() + '"').encode(), changed[CMD_PATH])
        self.assertNotIn(self.want().encode(), changed[CMD_PATH])
        # same shape otherwise: only the hash line differs
        old = [ln for ln in base.split(b"\r\n") if not ln.startswith(b'set "EPMA_WANT=')]
        new = [ln for ln in changed[CMD_PATH].split(b"\r\n") if not ln.startswith(b'set "EPMA_WANT=')]
        self.assertEqual(old, new)

    def test_the_hash_matches_the_bytes_that_are_written_in_both_modes(self):
        # same-USB mode: the script and SetupComplete.cmd come out of one call
        script = self.files[PS1_PATH]
        self.assertEqual(self.want(), hashlib.sha256(script).hexdigest())
        # seed drive: the file next to it is the same text as the same-USB SetupComplete.cmd
        _label, seed = app.hardening_files_seed(app.SEED_WINDOWS, app.HARDENING_BASELINE, during_setup=True)
        self.assertEqual(seed["SetupComplete.cmd"], self.cmd_bytes)
        self.assertEqual(hashlib.sha256(seed["harden.ps1"]).hexdigest(), self.want())

    def test_none_profile_and_empty_script_are_refused(self):
        with self.assertRaises(ValueError):
            app._windows_setupcomplete_cmd(app.HARDENING_NONE)
        with self.assertRaises(ValueError):
            app._windows_setupcomplete_cmd(app.HARDENING_BASELINE, b"  \r\n")

    def test_hash_is_read_with_certutil_by_full_path_second_line(self):
        text = self.cmd_text
        self.assertIn('for /f "skip=1 delims=" %%H in (\'%SystemRoot%\\System32\\certutil.exe -hashfile '
                      '"%~dp0harden.ps1" SHA256 2^>nul\') do if not defined EPMA_GOT set "EPMA_GOT=%%H"', text)
        self.assertIn('set "EPMA_GOT=%EPMA_GOT: =%"', text)  # older Windows prints the bytes separated by spaces
        self.assertIn('if /i not "%EPMA_GOT%"=="%EPMA_WANT%" goto mismatch', text)  # /i: case-insensitive
        self.assertLess(text.index("certutil"), text.index("goto mismatch"))
        self.assertLess(text.index("goto mismatch"), text.index(self.PS))  # the check comes before the run
        self.assertEqual(text.count("-File"), 1)  # harden.ps1 is started in exactly one place

    def simulate(self, got, exists=True):
        """Walk the batch file's `goto`/`if ... goto` lines for one scenario; returns the lines that run."""
        want = self.want()
        lines = self.lines()
        labels = {ln[1:]: i for i, ln in enumerate(lines) if ln.startswith(":")}
        ran, i, steps = [], 0, 0
        env_got = None
        while i < len(lines):
            steps += 1
            self.assertLess(steps, 200, "loop")
            ln = lines[i]
            i += 1
            if ln.startswith(("@", "rem ", ":", 'set "EPMA_LOG', 'set "EPMA_WANT')):
                continue
            if ln == 'set "EPMA_GOT="':
                env_got = None
            elif ln.startswith("for /f"):
                env_got = got
            elif ln == 'set "EPMA_GOT=%EPMA_GOT: =%"':
                env_got = env_got.replace(" ", "")
            elif ln.startswith("if not exist"):
                if not exists:
                    i = labels[ln.rsplit("goto ", 1)[1]]
            elif ln.startswith("if not defined"):
                if env_got is None:
                    i = labels[ln.rsplit("goto ", 1)[1]]
            elif ln.startswith("if /i not"):
                if env_got.lower() != want.lower():
                    i = labels[ln.rsplit("goto ", 1)[1]]
            elif ln.startswith("goto "):
                i = labels[ln[5:]]
            elif ln == "exit /b 0":
                ran.append(ln)
                break
            else:
                ran.append(ln)
        return ran

    def test_only_a_matching_hash_runs_the_script(self):
        want = self.want()
        spaced = " ".join(want[i:i + 2] for i in range(0, 64, 2))
        for label, got in (("lower case", want), ("upper case", want.upper()), ("bytes separated by spaces", spaced)):
            with self.subTest(label):
                ran = self.simulate(got)
                self.assertTrue(any(self.PS in ln for ln in ran), ran)
        off_by_one = want[:-1] + ("0" if want[-1] != "0" else "1")
        for label, got, exists in (("other hash", "0" * 64, True), ("one digit off", off_by_one, True),
                                   ("certutil gave nothing", None, True), ("script missing", want, False)):
            with self.subTest(label):
                ran = self.simulate(got, exists)
                self.assertFalse(any(self.PS in ln for ln in ran), ran)
                self.assertEqual(ran[-1], "exit /b 0")
                self.assertTrue(any("[SKIP]" in ln for ln in ran), ran)  # the log says why

    def test_a_mismatch_is_written_to_the_log_with_both_values(self):
        ran = self.simulate("0" * 64)
        text = " ".join(ran)
        self.assertIn("does not match the SHA-256 recorded in SetupComplete.cmd", text)
        self.assertIn("harden.ps1 was NOT run", text)
        self.assertIn("expected %EPMA_WANT% but found %EPMA_GOT%", text)
        for ln in ran:
            if ln.startswith("echo"):
                self.assertTrue(ln.endswith('>> "%EPMA_LOG%"'), ln)


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
        # The line goes to the console (Write-Host, inside Write-Log) and, when allowed, to the log file.
        self.assertIn("Write-Log ('[' + $Status + '] ' + $What + ' (' + $Why + ')')", self.ps1_text)
        # Every Write-Result call passes a status, what and why.
        for m in re.finditer(r"^\s*Write-Result (.*)$", self.ps1_text, re.MULTILINE):
            self.assertRegex(m.group(1), r"^('(OK|SKIP|WARN|FAIL)'|\$Status) ['($]", m.group(0))

    def test_exit_code_is_zero_unless_it_refuses_to_start(self):
        self.assertTrue(self.ps1_text.rstrip().endswith("exit 0"))
        # The only non-zero exits are refusals to start, each right after the SYSTEM guard "exit 0": Windows Setup
        # (which runs as SYSTEM) therefore never sees a failing exit code.
        lines = [ln.strip() for ln in self.ps1_text.splitlines() if ln.strip()]
        nonzero = [i for i, ln in enumerate(lines) if re.match(r"exit\s+[1-9]", ln)]
        self.assertTrue(nonzero)
        for i in nonzero:
            self.assertEqual(lines[i - 1], "if ($isSystem) { exit 0 }")

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
        # One call inside each of the two audit-only loops (the original four rules and the three added later).
        self.assertEqual(len(re.findall(r"-Action 'AuditMode'", self.ps1_text)), 2)

    def test_audit_policy_uses_guids_not_translated_names(self):
        self.assertNotRegex(self.ps1_text, r"/subcategory:\"")
        guids = re.findall(r"\{0CCE92[0-9A-F]{2}-69AE-11D9-BED3-505054503030\}", self.ps1_text)
        self.assertEqual(set(guids), {g for g, _n, _s, _f in app.WINDOWS_AUDIT_SUBCATEGORIES})
        self.assertEqual(len(app.WINDOWS_AUDIT_SUBCATEGORIES), 6)
        self.assertEqual(len({g for g, _n, _s, _f in app.WINDOWS_AUDIT_SUBCATEGORIES}), 6)

    def _whole(self, sid):
        parts = re.split(r"^# setting: (\w+)\s*$", self.ps1_text.replace("\r\n", "\n"), flags=re.MULTILINE)
        return dict(zip(parts[1::2], parts[2::2], strict=True))[sid].split("\nif ($Mode -eq 'Audit') {\n")[0]

    def _branches(self, sid):
        """(Apply, Audit, Undo) code of one setting, split at the three top-level mode branches."""
        whole = self._whole(sid)
        m = re.fullmatch(r"(?s)\s*if \(\$Mode -eq 'Apply'\) \{\n(.*?)\n\} elseif \(\$Mode -eq 'Audit'\) \{\n(.*?)\n\} else \{\n(.*)\n\}\s*", whole)
        self.assertIsNotNone(m, sid)
        return m.group(1), m.group(2), m.group(3)

    def _part(self, sid):
        """The Apply branch (what the earlier tests looked at)."""
        return self._branches(sid)[0]

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
        # The exit code of auditpol is checked in the helper that calls it.
        self.assertIn("$LASTEXITCODE -ne 0", self.ps1_text.split("function Set-AuditSubcategory")[1])

    def test_settings_are_read_back_before_saying_ok(self):
        for sid in ("firewall", "defender_cloud", "asr_lsass", "asr_audit", "asr_audit_extra"):
            with self.subTest(setting=sid):
                part = self._part(sid)
                self.assertRegex(part, r"Write-Result 'WARN' '[^']* not in effect'")
                self.assertIn("likely reason", part)
        self.assertEqual(self._part("firewall").count("Get-NetFirewallProfile"), 2)  # before and after setting
        self.assertEqual(self._part("defender_cloud").count("Get-MpPreference"), 2)
        self.assertIn("Get-AsrAction $ruleId", self._part("asr_lsass"))
        self.assertIn("Get-AsrAction $id", self._part("asr_audit"))
        self.assertIn("Get-AsrAction $id", self._part("asr_audit_extra"))
        self.assertIn("Tamper Protection", self.ps1_text)

    def test_warn_is_counted_and_reported_in_the_summary(self):
        self.assertIn("$script:CountWarn++", self.ps1_text)
        self.assertIn("not in effect, ' + $script:CountFail", self.ps1_text)

    def test_header_and_notes_say_it_runs_once_and_does_not_retry(self):
        head = self.ps1_text.split("function Write-Result")[0]
        self.assertIn("does NOT retry", head)
        by_id = {s[0]: s[2] for s in app.WINDOWS_HARDENING_SETTINGS}
        for sid in ("firewall", "defender_cloud", "asr_lsass", "asr_audit", "asr_audit_extra"):
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


# ===== hardening2: WIN-SCRIPT tests =====
GUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
# Commands that change something. Nothing in the Audit branches or in the helpers they use may contain them.
MUTATORS = re.compile(
    r"\b(Set|New|Remove|Add|Enable|Disable|Save|Restore|Move|Rename|Clear|Import|Initialize|Out)-[A-Za-z]+"
    r"|auditpol\.exe /(set|backup|restore)|wevtutil\.exe sl")
ORIGINAL_ASR_RULES = (
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a", "5beb7efe-fd9a-4556-801d-275e5ffc04cc",
    "d3e037e1-3eb8-44c8-a917-57927947596d",
)


class Win2Base(HardeningWindowsBase):
    def _whole(self, sid):
        parts = re.split(r"^# setting: (\w+)\s*$", self.ps1_text.replace("\r\n", "\n"), flags=re.MULTILINE)
        return dict(zip(parts[1::2], parts[2::2], strict=True))[sid].split("\nif ($Mode -eq 'Audit') {\n")[0]

    def _branches(self, sid):
        m = re.fullmatch(r"(?s)\s*if \(\$Mode -eq 'Apply'\) \{\n(.*?)\n\} elseif \(\$Mode -eq 'Audit'\) \{\n(.*?)\n\} else \{\n(.*)\n\}\s*",
                         self._whole(sid))
        self.assertIsNotNone(m, sid)
        return m.group(1), m.group(2), m.group(3)

    def _function(self, name):
        text = self.ps1_text.replace("\r\n", "\n")
        m = re.search(r"^function " + re.escape(name) + r" \{\n(.*?)\n\}\n", text, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(m, name)
        return m.group(1)

    @property
    def ids(self):
        return [s[0] for s in app.WINDOWS_HARDENING_SETTINGS]


class ParameterTests(Win2Base):
    def test_param_block_comes_first_and_is_a_cmdlet_binding(self):
        code = [ln for ln in self.ps1_text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
        self.assertEqual(code[0], "[CmdletBinding()]")
        self.assertEqual(code[1], "param(")

    def test_parameters_and_safe_defaults(self):
        text = self.ps1_text
        self.assertIn("[ValidateSet('Apply', 'Audit', 'Undo')]", text)
        self.assertIn("[string]$Mode = 'Apply'", text)
        self.assertIn("[switch]$DisableLegacyNetwork", text)  # a switch is $false unless given
        self.assertIn("[string]$LogPath = (Join-Path $env:windir 'Temp\\epma-hardening.log')", text)
        self.assertTrue(app.WINDOWS_HARDENING_LOG.endswith("\\Temp\\epma-hardening.log"))
        self.assertEqual(app.WINDOWS_HARDENING_MODES, ("Apply", "Audit", "Undo"))

    def test_setupcomplete_is_unchanged_and_passes_no_arguments(self):
        self.assertIn('-File "%~dp0harden.ps1" >> "%EPMA_LOG%" 2>&1', self.cmd_text)
        self.assertNotIn("-Mode", self.cmd_text)
        self.assertNotIn("DisableLegacyNetwork", self.cmd_text)

    def test_refuses_without_administrator_with_a_clear_message(self):
        text = self.ps1_text
        self.assertIn("IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)", text)
        self.assertIn("$isSystem = $identity.IsSystem", text)
        self.assertIn("must run as administrator", text)
        self.assertIn("Nothing was changed.", text)
        i_check = text.index("if (-not $isAdmin)")
        # The refusal happens before the first setting, the state file and the log file are touched.
        self.assertLess(i_check, text.index("# setting: smb1"))
        self.assertLess(i_check, text.index("Import-State)"))
        self.assertLess(i_check, text.index("Write-Log ('[START]"))

    def test_console_and_log_file(self):
        body = self._function("Write-Log")
        self.assertIn("Write-Host $Line", body)
        self.assertIn("Add-Content -LiteralPath $LogPath", body)
        self.assertIn("catch", body)  # a log file that cannot be written never stops the script
        # SetupComplete.cmd appends the console output itself: as SYSTEM with the default path the file is not
        # written a second time. Audit mode writes a file only when -LogPath was given on purpose.
        self.assertIn("$PSBoundParameters.ContainsKey('LogPath')", self.ps1_text)
        self.assertIn("($isSystem -or ($Mode -eq 'Audit'))", self.ps1_text)

    def test_every_line_goes_through_write_log(self):
        # Only the refusal (before the log exists), the log writer itself and its failure notice use Write-Host.
        hosts = [ln.strip() for ln in self.ps1_text.splitlines() if re.match(r"\s*Write-Host\b", ln)]
        self.assertLessEqual(len(hosts), 4, hosts)

    def test_no_restart_no_iex_no_network_in_any_mode(self):
        low = self.ps1_text.lower()
        for word in ("restart-computer", "invoke-expression", "iex ", "invoke-webrequest", "downloadfile", "http://", "https://"):
            self.assertNotIn(word, low)


class ModeCoverageTests(Win2Base):
    def test_three_dicts_cover_the_same_settings_in_order(self):
        self.assertEqual(self.ids, list(app._WINDOWS_PS_CODE))
        self.assertEqual(self.ids, list(app._WINDOWS_PS_AUDIT))
        self.assertEqual(self.ids, list(app._WINDOWS_PS_UNDO))

    def test_every_setting_is_handled_in_all_three_modes(self):
        for sid in self.ids:
            with self.subTest(setting=sid):
                apply_code, audit_code, undo_code = self._branches(sid)
                for code in (apply_code, audit_code, undo_code):
                    self.assertRegex(code, r"\btry \{")
                    self.assertRegex(code, r"\bcatch \{")
                self.assertIn("Write-Result 'FAIL'", apply_code)
                self.assertIn("Write-Audit", audit_code)
                self.assertNotIn("Write-Result", audit_code)  # Audit prints [OK]/[DIFF]/[N/A] only
                self.assertIn("Write-Audit 'NA'", audit_code)  # a check that fails is reported, not fatal
                self.assertRegex(undo_code, r"Write-UndoSummary|Write-Result '(SKIP|WARN)'")
                self.assertNotIn("Write-Audit", undo_code)

    def test_marker_and_three_branches_once_per_setting(self):
        text = self.ps1_text
        for token in ("if ($Mode -eq 'Apply') {", "} elseif ($Mode -eq 'Audit') {", "} else {"):
            self.assertGreaterEqual(text.count(token), len(self.ids), token)
        self.assertEqual(len(re.findall(r"^# setting: ", text, re.MULTILINE)), len(self.ids))

    def test_one_log_line_per_setting_in_audit(self):
        # Audit prints a verdict tag: [OK] ... in effect, [DIFF] ... not in effect, [N/A].
        body = self._function("Write-Audit")
        for token in ("'[OK] '", "'[DIFF] '", "'[N/A] '", "-- in effect (", "-- not in effect ("):
            self.assertIn(token, body)

    def test_audit_branches_and_helpers_change_nothing(self):
        for sid, code in app._WINDOWS_PS_AUDIT.items():
            with self.subTest(setting=sid):
                self.assertIsNone(MUTATORS.search(code), MUTATORS.search(code))
        self.assertIsNone(MUTATORS.search(app._WINDOWS_PS_AUDIT_INFO))
        for name in ("Get-RegDword", "Format-Value", "Get-FeatureState", "Get-AsrAction", "Get-AsrActionName",
                     "Get-AuditSetting"):
            with self.subTest(helper=name):
                body = self._function(name)
                found = MUTATORS.search(body)
                self.assertIsNone(found, found)
        self.assertIn("auditpol.exe /get", self._function("Get-AuditSetting"))

    def test_audit_never_touches_the_state_file(self):
        text = self.ps1_text.replace("\r\n", "\n")
        # State is read and written only when the mode is not Audit.
        self.assertRegex(text, r"if \(\$Mode -ne 'Audit'\) \{\n    if \(-not \(Import-State\)\) \{")
        for sid, code in app._WINDOWS_PS_AUDIT.items():
            for token in ("Add-StateOnce", "Save-State", "Import-State", "Initialize-StateFolder", "$script:State"):
                self.assertNotIn(token, code, sid)
        self.assertNotIn("Save-State", app._WINDOWS_PS_AUDIT_INFO)

    def test_audit_ends_with_the_summary_line(self):
        self.assertIn("Write-Log ('[DONE] ' + $script:CountOk + ' in effect, ' + $script:CountDiff + ' not in effect')",
                      self.ps1_text)
        self.assertIn("$script:CountDiff++", self.ps1_text)

    def test_audit_reports_read_only_facts(self):
        info = app._WINDOWS_PS_AUDIT_INFO
        for token in ("Get-BitLockerVolume", "Get-Tpm", "Confirm-SecureBootUEFI", "Get-MpComputerStatus",
                      "IsTamperProtected", "AttackSurfaceReductionRules_Ids", "Win32_DeviceGuard",
                      "SecurityServicesRunning", "LsaCfgFlags", "HypervisorEnforcedCodeIntegrity"):
            with self.subTest(token=token):
                self.assertIn(token, info)
        # Secure Boot throws on legacy BIOS: it is inside its own try/catch.
        m = re.search(r"try \{\n\s*if \(Confirm-SecureBootUEFI\).*?\} catch \{", info, re.DOTALL)
        self.assertIsNotNone(m)
        # Facts are reported with [INFO] and never counted in the summary.
        self.assertNotIn("Write-Audit", info)
        self.assertIn("function Write-Info", self.ps1_text)
        self.assertIn("'[INFO] '", self.ps1_text)

    def test_credential_guard_hvci_bitlocker_exploit_protection_are_never_enabled(self):
        low = self.ps1_text.lower()
        for token in ("enable-bitlocker", "manage-bde", "set-processmitigation", "add-bitlockerkeyprotector",
                      "lsacfgflags' -value"):
            with self.subTest(token=token):
                self.assertNotIn(token, low)
        names = {row[0] for row in app.WINDOWS_HARDENING_NOT_CHANGED}
        self.assertIn("device_guard", names)
        self.assertNotIn("Set-RegDword -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'", self.ps1_text)


class StateAndUndoTests(Win2Base):
    def test_state_file_path_constant(self):
        self.assertEqual(app.WINDOWS_HARDENING_STATE, "%ProgramData%\\EPMA\\hardening-state.json")
        self.assertEqual((app.WINDOWS_HARDENING_STATE_DIR, app.WINDOWS_HARDENING_STATE_FILE), ("EPMA", "hardening-state.json"))
        self.assertIn("$script:StateDir = Join-Path $env:ProgramData 'EPMA'", self.ps1_text)
        self.assertIn("$script:StatePath = Join-Path $script:StateDir 'hardening-state.json'", self.ps1_text)
        self.assertIn(app.WINDOWS_HARDENING_STATE, self.ps1_text)  # said in the header too

    def test_state_folder_is_limited_to_administrators_and_system(self):
        body = self._function("Initialize-StateFolder")
        for token in ("New-Item -ItemType Directory", "Get-Acl", "SetAccessRuleProtection($true, $false)",
                      "'S-1-5-18'", "'S-1-5-32-544'", "FileSystemAccessRule", "Set-Acl"):
            self.assertIn(token, body)
        self.assertRegex(body, r"\} catch \{\n\s+Write-Log \('\[WARN\]")  # a failure is logged, never fatal
        # An existing folder is left alone.
        self.assertIn("if (Test-Path -LiteralPath $script:StateDir) { return }", body)

    def test_first_seen_value_is_never_overwritten(self):
        body = self._function("Add-StateOnce")
        self.assertIn("if ($script:State.ContainsKey($Key)) { return }", body)
        # If the record cannot be saved the change that follows is not made.
        self.assertIn("throw", body)
        self.assertIn("Save-State", body)

    def test_value_is_recorded_before_it_is_changed(self):
        for name, change in (("Set-RegDword", "New-ItemProperty"), ("Set-AsrRule", "Add-MpPreference"),
                             ("Set-AuditSubcategory", "auditpol.exe /set")):
            with self.subTest(function=name):
                body = self._function(name)
                self.assertIn("Add-StateOnce", body)
                self.assertLess(body.index("Add-StateOnce"), body.index(change))
        for sid in ("smb1", "ps2"):
            code = self._branches(sid)[0]
            self.assertLess(code.index("Save-FeatureState"), code.index("Disable-WindowsOptionalFeature"))
        firewall = self._branches("firewall")[0]
        self.assertLess(firewall.index("Save-FirewallState"), firewall.index("Set-NetFirewallProfile"))
        defender = self._branches("defender_cloud")[0]
        self.assertLess(defender.index("Save-DefenderValue 'PUAProtection'"), defender.index("Set-MpPreference -PUAProtection"))
        self.assertLess(defender.index("Save-DefenderValue 'MAPSReporting'"), defender.index("Set-MpPreference -MAPSReporting"))
        audit = self._branches("audit")[0]
        self.assertLess(audit.index("Save-EventLogState"), audit.index("wevtutil.exe sl"))

    def test_state_is_json_with_enough_depth(self):
        body = self._function("Save-State")
        self.assertIn("ConvertTo-Json -Depth 6", body)
        self.assertIn("Set-Content -LiteralPath $script:StatePath", body)
        self.assertIn("ConvertFrom-Json", self._function("Import-State"))

    def test_undo_handles_every_kind_of_change_that_apply_records(self):
        pairs = dict(app.WINDOWS_HARDENING_STATE_PAIRS)
        setter_re = re.compile(r"\b(" + "|".join(re.escape(k) for k in pairs) + r")\b")
        for sid in self.ids:
            with self.subTest(setting=sid):
                apply_code, _audit, undo_code = self._branches(sid)
                used = set(setter_re.findall(apply_code))
                for setter in used:
                    self.assertIn(pairs[setter], undo_code, f"{sid}: Apply uses {setter} but Undo never calls {pairs[setter]}")
        # Every setter and restorer exists as a function; every recorded kind has a restorer.
        for setter, restorer in pairs.items():
            self.assertIn(f"function {setter} ", self.ps1_text)
            self.assertIn(f"function {restorer} ", self.ps1_text)
        kinds = set(re.findall(r"kind = '(\w+)'", self.ps1_text))
        self.assertEqual(kinds, {"reg", "asr", "audit", "fw", "mp", "feature", "eventlog"})

    def test_apply_never_changes_without_a_recording_helper(self):
        # A raw change command may only appear inside the helpers (which record first) or after a Save-* call.
        for sid in self.ids:
            apply_code = self._branches(sid)[0]
            for raw in ("New-ItemProperty", "Set-ItemProperty", "Add-MpPreference", "Remove-MpPreference", "Remove-ItemProperty"):
                self.assertIsNone(re.search(r"(?<!Get-Command )" + raw, apply_code), sid)

    def test_undo_restores_removes_or_reports(self):
        reg = self._function("Restore-RegValue")
        for token in ("New-ItemProperty", "Remove-ItemProperty", "$rec.existed", "Remove-StateEntry $key", "'no record'"):
            self.assertIn(token, reg)
        asr = self._function("Restore-AsrRule")
        self.assertIn("Remove-MpPreference", asr)
        self.assertIn("Add-MpPreference", asr)
        self.assertIn("Get-AsrAction $Id", asr)  # read back
        audit = self._function("Restore-AuditSubcategory")
        self.assertIn("/success:disable", audit)
        self.assertIn("auditpol /restore /file:", audit)
        self.assertIn("-not $rec.known", audit)  # an unreadable earlier value is never guessed

    def test_undo_logs_ok_skip_warn_only(self):
        for sid in self.ids:
            undo_code = self._branches(sid)[2]
            self.assertNotIn("'FAIL'", undo_code, sid)
        self.assertIn("Write-Result 'SKIP' $What 'nothing recorded", self._function("Write-UndoSummary"))
        self.assertIn("Write-Result 'OK' $What", self._function("Write-UndoSummary"))

    def test_undo_states_what_it_cannot_undo(self):
        feature = self._function("Restore-FeatureState")
        self.assertIn("Enable-WindowsOptionalFeature -Online -FeatureName", feature)
        for sid in ("smb1", "ps2"):
            self.assertIn("Write-Result 'WARN'", self._branches(sid)[2])
        self.assertIn("not shrunk", self._function("Restore-EventLogState"))
        undo_end = app._WINDOWS_PS_END["Undo"]
        for token in ("Enable-WindowsOptionalFeature", "never shrinks", "auditpol /restore", "already in the wanted state"):
            self.assertIn(token, undo_end)

    def test_feature_is_never_turned_back_on_by_undo(self):
        # Turning SMBv1 or PowerShell 2.0 back on would weaken the PC: Undo only tells the owner how.
        self.assertNotRegex(self.ps1_text, r"(?m)^\s*Enable-WindowsOptionalFeature")
        self.assertNotRegex(self.ps1_text, r"(?m)^\s*& Enable-WindowsOptionalFeature")

    def test_audit_policy_is_saved_once_with_auditpol_backup(self):
        body = self._function("Save-AuditBackup")
        self.assertIn("auditpol.exe /backup", body)
        self.assertIn("if (Test-Path -LiteralPath $script:AuditBackupPath) { return }", body)

    def test_unreadable_state_never_leads_to_unrecorded_changes(self):
        text = self.ps1_text.replace("\r\n", "\n")
        self.assertIn("without a record there would be no way back", text)
        self.assertIn("'.unreadable-'", text)

    def test_empty_state_file_is_removed_after_undo(self):
        self.assertIn("Remove-Item -LiteralPath $script:StatePath -Force", app._WINDOWS_PS_END["Undo"])
        self.assertIn("$script:State.Count -eq 0", app._WINDOWS_PS_END["Undo"])


class NewSettingsTests(Win2Base):
    def test_asr_guids_are_well_formed_and_unique(self):
        groups = {
            "lsass": (app.WINDOWS_ASR_LSASS,), "audit": app.WINDOWS_ASR_AUDIT_RULES,
            "extra": app.WINDOWS_ASR_AUDIT_EXTRA_RULES,
        }
        every = [g for group in groups.values() for g in group]
        self.assertEqual(len(every), 8)
        self.assertEqual(len(set(every)), len(every))
        for guid in every:
            self.assertRegex(guid, GUID_RE)
        # The script mentions exactly these GUIDs (the audit-policy ones have braces and capital letters).
        in_script = set(re.findall(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", self.ps1_text))
        self.assertEqual(in_script, set(every))

    def test_the_original_five_rules_are_unchanged(self):
        self.assertEqual((app.WINDOWS_ASR_LSASS, *app.WINDOWS_ASR_AUDIT_RULES), ORIGINAL_ASR_RULES)

    def test_new_asr_rules_are_the_certain_ones(self):
        self.assertEqual(app.WINDOWS_ASR_AUDIT_EXTRA_RULES, (
            "56a863a9-875e-4185-98a7-b882c64b5ce5",  # abuse of exploited vulnerable signed drivers
            "d1e49aac-8f56-4280-b9ba-993a6d77406c",  # process creations from PSExec and WMI
            "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",  # untrusted processes from USB
        ))

    def test_new_asr_rules_are_audit_mode_only(self):
        apply_code = self._branches("asr_audit_extra")[0]
        self.assertIn("-Action 'AuditMode'", apply_code)
        self.assertNotIn("'Enabled'", apply_code)
        for guid in app.WINDOWS_ASR_AUDIT_EXTRA_RULES:
            self.assertIn(guid, apply_code)
            self.assertNotIn(guid, self._branches("asr_audit")[0])
        # Block mode (the only 'Enabled') stays reserved for the LSASS rule.
        self.assertEqual(self.ps1_text.count("-Action 'Enabled'"), 1)

    def test_opt_in_settings_are_listed_and_gated(self):
        self.assertEqual(app.WINDOWS_HARDENING_OPTIN, ("netbios", "wpad"))
        for sid in app.WINDOWS_HARDENING_OPTIN:
            with self.subTest(setting=sid):
                self.assertIn(sid, self.ids)
                apply_code, audit_code, _undo = self._branches(sid)
                self.assertIn("if (-not $DisableLegacyNetwork) {", apply_code)
                self.assertIn("Write-Result 'SKIP'", apply_code)
                self.assertLess(apply_code.index("-not $DisableLegacyNetwork"), apply_code.index("Set-RegDword"))
                self.assertIn("-OptIn $true", audit_code)
                text = {s[0]: s[1] for s in app.WINDOWS_HARDENING_SETTINGS}[sid]
                self.assertIn("-DisableLegacyNetwork", text)
        # Only the opt-in settings look at the switch.
        for sid in self.ids:
            if sid not in app.WINDOWS_HARDENING_OPTIN:
                self.assertNotIn("DisableLegacyNetwork", self._branches(sid)[0], sid)

    def test_opt_in_audit_does_not_count_a_setting_that_was_never_requested(self):
        body = self._function("Write-Audit")
        self.assertIn("-not $DisableLegacyNetwork", body)
        self.assertIn("$Verdict = 'NA'", body)
        self.assertIn("not counted", body)

    def test_netbios_and_wpad_do_only_what_is_certain(self):
        net = self._branches("netbios")
        self.assertIn(r"HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces", net[0])
        self.assertIn("'Tcpip_*'", net[0])
        self.assertIn("-Name 'NetbiosOptions' -Value 2", net[0])
        self.assertIn("NetBT", net[2])
        wpad = self._branches("wpad")
        self.assertIn(r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp", wpad[0])
        self.assertIn("-Name 'DisableWpad' -Value 1", wpad[0])
        # The WinHTTP auto-proxy service is not stopped or disabled, and no service is touched at all.
        low = self.ps1_text.lower()
        for token in ("stop-service", "set-service", "sc.exe", "winhttpautoproxysvc"):
            self.assertNotIn(token, low)

    def test_new_describe_lines_exist_and_mention_the_switch(self):
        lines = app.describe_hardening_windows(app.HARDENING_BASELINE)
        self.assertEqual(len(lines), len(self.ids))
        joined = "\n".join(lines)
        self.assertIn("more: abuse of exploited vulnerable signed drivers", joined)
        self.assertIn("NetBIOS over TCP/IP", joined)
        self.assertIn("WPAD", joined)
        self.assertEqual(sum("-DisableLegacyNetwork" in ln for ln in lines), 2)

    def test_new_describe_lines_have_portuguese_text(self):
        new = [ln for ln in app.describe_hardening_windows(app.HARDENING_BASELINE)
               if "more: abuse" in ln or "NetBIOS" in ln or "WPAD" in ln]
        self.assertEqual(len(new), 3)
        for line in new:
            with self.subTest(line=line[:50]):
                pt = app.PT_BR[line]
                self.assertNotEqual(pt, line)
                self.assertEqual(pt.count(" -- risco: "), 1)
                self.assertEqual(line.count("-DisableLegacyNetwork"), pt.count("-DisableLegacyNetwork"))
                self.assertEqual(line.count("[WARN]"), pt.count("[WARN]"))
                with mock.patch.object(app, "ACTIVE_LANGUAGE", "pt"):
                    self.assertEqual(app._(line), pt)


class PublicHelperTests(Win2Base):
    def test_bytes_equal_the_file_in_hardening_files_windows(self):
        self.assertEqual(app.windows_hardening_ps1(app.HARDENING_BASELINE), self.files[PS1_PATH])
        self.assertIsInstance(app.windows_hardening_ps1(app.HARDENING_BASELINE), bytes)

    def test_format(self):
        data = app.windows_hardening_ps1(app.HARDENING_BASELINE)
        self.assertTrue(data.startswith(b"\xef\xbb\xbf"))
        body = data[3:]
        body.decode("ascii")
        self.assertNotRegex(body, rb"(?<!\r)\n")
        self.assertLessEqual(len(data), MAX_FILE)

    def test_profiles(self):
        self.assertEqual(app.windows_hardening_ps1(app.HARDENING_NONE), b"")
        with self.assertRaises(ValueError):
            app.windows_hardening_ps1("strict")

    def test_deterministic(self):
        self.assertEqual(app.windows_hardening_ps1(app.HARDENING_BASELINE),
                         app.windows_hardening_ps1(app.HARDENING_BASELINE))

    def test_hardening_files_windows_uses_the_same_bytes(self):
        with mock.patch.object(app, "_windows_harden_ps1", return_value=b"marker"):
            self.assertEqual(app.hardening_files_windows(app.HARDENING_BASELINE)[PS1_PATH], b"marker")
            self.assertEqual(app.windows_hardening_ps1(app.HARDENING_BASELINE), b"marker")
# ===== end hardening2: WIN-SCRIPT tests =====


if __name__ == "__main__":
    unittest.main()
