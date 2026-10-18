"""Tests for the hardening seed files (hardening_files_seed): what goes on the second USB.

The point of these tests is SAFETY. A seed must never partition, format or choose a disk, never create
an account, and never carry a password, hash or key. The checks look at the parsed structure of every
file (there is no PyYAML in the standard library, so a tiny parser for the YAML subset the code emits
is included below), not just at a text search.

linux_hardening_script is written by another part of the feature: the tests patch it with a short fake
script (and, when it exists in this build, run the same checks on the real one too).
"""
import base64
import os
import re
import shutil
import subprocess
import unittest
from unittest import mock

from tests.helpers import TempDirTestCase, app

FAKE_SCRIPT = (
    "#!/usr/bin/env bash\n"
    "set -eu\n"
    "# fake hardening script used by the tests\n"
    'case "${1:-}" in --undo) echo "undo";; --dry-run) echo "dry run";; *) echo "apply \\"$HOME\\" $# \'x\'";; esac\n'
    "cat <<'EOF'\n"
    "  indented heredoc line with % and $ and `backticks`\n"
    "EOF\n"
)

LINUX_TARGETS = ("ubuntu", "fedora", "debian")  # the targets whose seed carries harden-linux.sh
ALLOWED_LABELS = {"ubuntu": "CIDATA", "fedora": "OEMDRV", "debian": "EPMA-SEED", "windows": "EPMA-SEED"}
EXPECTED_FILES = {
    "ubuntu": {"user-data", "meta-data", "harden-linux.sh", "README.txt"},
    "fedora": {"ks.cfg", "harden-linux.sh", "README.txt"},
    "debian": {"preseed.cfg", "harden-linux.sh", "README.txt"},
    # Windows, "run after install" mode (no answer file); WINDOWS_SETUP_FILES are added by during_setup=True
    "windows": {"harden.cmd", "audit.cmd", "undo.cmd", "harden.ps1", "README.txt"},
}
WINDOWS_SETUP_FILES = {"autounattend.xml", "EPMA-SEED.txt", "SetupComplete.cmd"}
WINDOWS_CMD_FILES = ("harden.cmd", "audit.cmd", "undo.cmd")
# The big script of each target (not checked as a plain ASCII config file).
SCRIPT_FILES = {"ubuntu": "harden-linux.sh", "fedora": "harden-linux.sh", "debian": "harden-linux.sh",
                "windows": "harden.ps1"}
CONFIG_FILES = {"ubuntu": "user-data", "fedora": "ks.cfg", "debian": "preseed.cfg", "windows": "harden.cmd"}

# Stand-ins for the two Windows pieces that other parts of the feature write (both are patched in the tests).
FAKE_PS1 = b"\xef\xbb\xbf# fake harden.ps1 used by the tests\r\nparam([string]$Mode = 'Apply')\r\nWrite-Host $Mode\r\n"
FAKE_XML = b'<?xml version="1.0" encoding="utf-8"?>\r\n<unattend xmlns="urn:schemas-microsoft-com:unattend" />\r\n'

MAX_FILE = 256 * 1024
MAX_TOTAL = 2 * 1024 * 1024

# Keys that must never appear (as a key, a kickstart command or a preseed key) in any seed.
FORBIDDEN_KEYS = (
    "storage", "clearpart", "autopart", "zerombr", "ignoredisk", "part", "volgroup", "logvol", "partman",
    "passwd", "rootpw", "user", "sshkey", "identity", "ssh_authorized_keys", "password", "hash",
    # also never in a cloud-init/autoinstall seed
    "users", "chpasswd", "user-data", "ssh", "reboot", "poweroff", "halt", "shutdown", "bootloader",
)
# Disk or account tools/commands that must not appear anywhere in executable seed text.
DANGEROUS_WORDS = re.compile(
    r"\b(mkfs\w*|wipefs|parted|fdisk|sfdisk|sgdisk|clearpart|autopart|zerombr|ignoredisk|volgroup|logvol|"
    r"partman\S*|rootpw|sshkey|poweroff|halt|shutdown|reboot|chpasswd|passwd|useradd|usermod|losetup)\b")
HASH_LIKE = re.compile(r"\$(?:1|2[abxy]?|5|6|7|y|gy|sha1|md5)\$")
CLAIMS = re.compile(r"\b(CIS|STIG|NIST)\b")


# --------------------------------------------------------------------------- tiny YAML subset parser
def _indent(line):
    return len(line) - len(line.lstrip(" "))


def _skip(lines, i):
    while i < len(lines) and (not lines[i].strip() or lines[i].lstrip().startswith("#")):
        i += 1
    return i


def _scalar(text):
    text = text.strip()
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        return [_scalar(p) for p in inner.split(",")] if inner else []
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def _parse_block(lines, i, indent):
    """Parse the mapping or sequence whose first line is at `indent`. Returns (value, next_index)."""
    i = _skip(lines, i)
    assert i < len(lines), "unexpected end of document"
    assert _indent(lines[i]) == indent, f"line {i + 1}: expected indent {indent}: {lines[i]!r}"
    if lines[i].lstrip().startswith("- "):
        seq = []
        while True:
            i = _skip(lines, i)
            if i >= len(lines) or _indent(lines[i]) < indent:
                return seq, i
            assert _indent(lines[i]) == indent, f"line {i + 1}: bad indent"
            item = lines[i][indent:]
            assert item.startswith("- "), f"line {i + 1}: sequence expected: {lines[i]!r}"
            item = item[2:]
            i += 1
            if item == "|":
                body, base = [], None
                while i < len(lines):
                    raw = lines[i]
                    if not raw.strip():
                        body.append("")
                        i += 1
                        continue
                    if _indent(raw) <= indent:
                        break
                    if base is None:
                        base = _indent(raw)
                        assert base == indent + 2, f"line {i + 1}: block scalar not indented by 2"
                    assert _indent(raw) >= base, f"line {i + 1}: block scalar under-indented"
                    body.append(raw[base:])
                    i += 1
                seq.append("\n".join(body).rstrip("\n") + "\n")
            else:
                seq.append(_scalar(item))
    mapping = {}
    while True:
        i = _skip(lines, i)
        if i >= len(lines) or _indent(lines[i]) < indent:
            return mapping, i
        assert _indent(lines[i]) == indent, f"line {i + 1}: bad indent"
        m = re.fullmatch(r"([A-Za-z0-9_-]+):(?: (.+))?", lines[i][indent:])
        assert m, f"line {i + 1}: not a 'key: value' line: {lines[i]!r}"
        key, value = m.group(1), m.group(2)
        assert key not in mapping, f"duplicate key {key}"
        i += 1
        if value is None:
            mapping[key], i = _parse_block(lines, i, indent + 2)
        else:
            mapping[key] = _scalar(value)


def parse_mini_yaml(text):
    """Parse the YAML subset the seed uses (maps, lists, `- |` block scalars, one-line [a, b] lists)."""
    assert "\t" not in text, "tab in YAML"
    assert "\r" not in text, "carriage return in YAML"
    lines = text.split("\n")
    for n, line in enumerate(lines, 1):
        assert line == line.rstrip(), f"line {n}: trailing whitespace"
    value, i = _parse_block(lines, 0, 0)
    assert _skip(lines, i) >= len(lines), f"line {i + 1}: could not parse the rest"
    return value


def walk_keys(node):
    """Every mapping key anywhere in a parsed tree."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield key
            yield from walk_keys(value)
    elif isinstance(node, list):
        for item in node:
            yield from walk_keys(item)


# --------------------------------------------------------------------------- helpers
def executable_text(text):
    """The config text without comment lines and without base64 payload lines."""
    keep = []
    for line in text.split("\n"):
        stripped = line.strip()
        if stripped.startswith("#") and not stripped.startswith("#cloud-config"):
            continue
        if re.fullmatch(r"[A-Za-z0-9+/=]{20,}", stripped):
            continue
        keep.append(line)
    return "\n".join(keep)


def heredoc_payload(text):
    """The base64 text between `<<'EPMA_B64'` and the EPMA_B64 line (lines may be indented)."""
    m = re.search(r"<<'EPMA_B64'\n(.*?)\n\s*EPMA_B64\n", text, re.S)
    assert m, "no EPMA_B64 heredoc"
    return [line.strip() for line in m.group(1).split("\n")]


def decode_b64(lines):
    return base64.b64decode("".join(lines), validate=True)


def preseed_logical_lines(text):
    """Preseed lines with backslash continuations joined; comments and blanks dropped."""
    out, current = [], ""
    for line in text.split("\n"):
        if not current and (not line.strip() or line.lstrip().startswith("#")):
            continue
        if line.endswith("\\"):
            current += line[:-1] + " "
            continue
        out.append((current + line).strip())
        current = ""
    assert not current, "preseed ends inside a continuation"
    return out


def kickstart_sections(text):
    """(commands outside any section, {section header: [body lines]}) of a kickstart file."""
    commands, sections, current, name = [], {}, None, None
    for line in text.split("\n"):
        stripped = line.strip()
        if current is None:
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("%"):
                assert stripped not in ("%end",), "stray %end"
                name = stripped
                assert name not in sections, f"section {name} twice"
                current = sections[name] = []
            else:
                commands.append(stripped)
        elif stripped == "%end":
            current = None
        else:
            current.append(line)
    assert current is None, "section without %end"
    return commands, sections


class SeedTestBase(unittest.TestCase):
    script = FAKE_SCRIPT
    ps1 = FAKE_PS1
    xml = FAKE_XML

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(app, "linux_hardening_script", create=True, side_effect=lambda p: self.script)
        self.script_mock = patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(app, "windows_hardening_ps1", create=True, side_effect=lambda p: self.ps1)
        self.ps1_mock = patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(app, "windows_seed_autounattend", create=True, side_effect=lambda p: self.xml)
        self.xml_mock = patcher.start()
        self.addCleanup(patcher.stop)

    def seed(self, target, profile=None, **kwargs):
        return app.hardening_files_seed(target, app.HARDENING_BASELINE if profile is None else profile, **kwargs)

    def text(self, target, name=None, **kwargs):
        """A file of the seed as text; Windows files use CRLF, shown here with plain newlines."""
        _label, files = self.seed(target, **kwargs)
        return files[name or CONFIG_FILES[target]].decode("ascii").replace("\r\n", "\n")


class ContractTests(unittest.TestCase):
    def test_constants(self):
        self.assertEqual(app.MODE_SEED, "seed")
        self.assertEqual(app.HARDENING_NONE, "none")
        self.assertEqual(app.HARDENING_BASELINE, "baseline")
        self.assertEqual(app.HARDENING_PROFILES, ("none", "baseline"))
        self.assertEqual((app.SEED_UBUNTU, app.SEED_FEDORA, app.SEED_DEBIAN), ("ubuntu", "fedora", "debian"))
        self.assertEqual(app.SEED_WINDOWS, "windows")
        self.assertEqual(app.SEED_TARGETS, ("ubuntu", "fedora", "debian", "windows"))


class ArgumentTests(SeedTestBase):
    def test_none_profile_is_refused(self):
        for target in app.SEED_TARGETS:
            with self.subTest(target=target), self.assertRaises(ValueError):
                app.hardening_files_seed(target, app.HARDENING_NONE)
        self.script_mock.assert_not_called()

    def test_unknown_profile_is_refused(self):
        for bad in ("strict", "", None, "BASELINE", 1, ["baseline"]):
            with self.subTest(profile=bad), self.assertRaises(ValueError):
                app.hardening_files_seed(app.SEED_UBUNTU, bad)

    def test_unknown_target_is_refused(self):
        for bad in ("arch", "windows-seed", "Windows", "", None, "UBUNTU", 3, ["ubuntu"]):
            with self.subTest(target=bad), self.assertRaises(ValueError):
                app.hardening_files_seed(bad, app.HARDENING_BASELINE)

    def test_empty_script_is_refused(self):
        for bad in ("", "  \n", None, b"#!/bin/sh\n"):
            self.script = bad
            for target in LINUX_TARGETS:
                with self.subTest(script=bad, target=target), self.assertRaises(ValueError):
                    self.seed(target)

    def test_script_comes_from_linux_hardening_script_at_call_time(self):
        self.seed(app.SEED_UBUNTU)
        self.script_mock.assert_called_once_with(app.HARDENING_BASELINE)
        self.script = "#!/bin/sh\necho second\n"
        _label, files = self.seed(app.SEED_FEDORA)
        self.assertEqual(files["harden-linux.sh"], b"#!/bin/sh\necho second\n")
        self.assertIn(base64.b64encode(b"#!/bin/sh\necho second\n").decode(), files["ks.cfg"].decode())


class CommonSafetyTests(SeedTestBase):
    def test_labels_are_valid_fat32_labels(self):
        for target in app.SEED_TARGETS:
            with self.subTest(target=target):
                label, _files = self.seed(target)
                self.assertEqual(label, ALLOWED_LABELS[target])
                self.assertLessEqual(len(label), 11)
                self.assertEqual(label, label.upper())
                self.assertRegex(label, r"^[A-Z0-9_-]{1,11}$")
                self.assertIn(label, {"CIDATA", "OEMDRV", "EPMA-SEED"})

    def test_file_set_and_types(self):
        for target in app.SEED_TARGETS:
            with self.subTest(target=target):
                _label, files = self.seed(target)
                self.assertEqual(set(files), EXPECTED_FILES[target])
                for name, data in files.items():
                    self.assertIsInstance(name, str)
                    self.assertIsInstance(data, bytes)
                    self.assertTrue(data, f"{name} is empty")

    def test_paths_are_plain_relative_names(self):
        for target in app.SEED_TARGETS:
            _label, files = self.seed(target)
            for name in files:
                with self.subTest(target=target, name=name):
                    self.assertNotIn("\\", name)
                    self.assertNotIn("\0", name)
                    self.assertFalse(name.startswith("/"))
                    self.assertNotIn("..", name.split("/"))
                    self.assertLessEqual(len(name), 240)
                    self.assertRegex(name, r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

    def test_script_file_is_exactly_the_script(self):
        for target in LINUX_TARGETS:
            with self.subTest(target=target):
                _label, files = self.seed(target)
                self.assertEqual(files["harden-linux.sh"], FAKE_SCRIPT.encode("utf-8"))
        _label, files = self.seed(app.SEED_WINDOWS)  # Windows: harden.ps1 comes from windows_hardening_ps1
        self.assertEqual(files["harden.ps1"], FAKE_PS1)
        self.assertNotIn("harden-linux.sh", files)

    def test_deterministic(self):
        for target in app.SEED_TARGETS:
            with self.subTest(target=target):
                self.assertEqual(self.seed(target), self.seed(target))

    def test_sizes_within_limits_even_for_a_big_script(self):
        big = "#!/usr/bin/env bash\nset -eu\n" + "".join(
            f"echo 'line {n} of a long hardening script ........................'\n" for n in range(1500))
        self.assertGreater(len(big), 80_000)
        for script in (FAKE_SCRIPT, big):
            self.script = script
            for target in app.SEED_TARGETS:
                with self.subTest(target=target, size=len(script)):
                    if target == app.SEED_DEBIAN and script is big:
                        with self.assertRaises(ValueError):  # too big for one late_command argument
                            self.seed(target)
                        continue
                    _label, files = self.seed(target)
                    self.assertTrue(all(len(data) <= MAX_FILE for data in files.values()),
                                    {k: len(v) for k, v in files.items()})
                    self.assertLessEqual(sum(len(d) for d in files.values()), MAX_TOTAL)
                    self.assertLessEqual(len(files), 8)

    def test_config_files_are_clean_ascii(self):
        for target in LINUX_TARGETS:
            for name in set(EXPECTED_FILES[target]) - {"harden-linux.sh"}:
                with self.subTest(target=target, name=name):
                    _label, files = self.seed(target)
                    text = files[name].decode("ascii")  # raises on any non-ASCII byte
                    self.assertNotIn("\t", text)
                    self.assertNotIn("\r", text)
                    self.assertTrue(text.endswith("\n") and not text.endswith("\n\n"))
                    for n, line in enumerate(text.split("\n"), 1):
                        self.assertEqual(line, line.rstrip(), f"{name}:{n} trailing whitespace")

    def test_no_password_hashes_keys_or_claims(self):
        for target in app.SEED_TARGETS:
            names = set(EXPECTED_FILES[target]) - {SCRIPT_FILES[target]}
            if target == app.SEED_WINDOWS:
                names |= WINDOWS_SETUP_FILES
            for name in names:
                with self.subTest(target=target, name=name):
                    _label, files = self.seed(target, during_setup=True)
                    text = files[name].decode("ascii")
                    self.assertIsNone(HASH_LIKE.search(text), "looks like a password hash")
                    self.assertNotIn("ssh-rsa", text)
                    self.assertNotIn("ssh-ed25519", text)
                    self.assertNotIn("ecdsa-sha2", text)
                    self.assertNotIn("BEGIN OPENSSH", text)
                    self.assertNotIn("BEGIN PRIVATE", text)
                    self.assertIsNone(CLAIMS.search(text), "compliance claim")
                    self.assertIsNone(re.search(r"\b(token|secret|api[_-]?key)\b", text, re.I))

    def test_no_disk_or_account_commands_in_executable_text(self):
        for target in app.SEED_TARGETS:
            with self.subTest(target=target):
                body = executable_text(self.text(target))
                found = DANGEROUS_WORDS.findall(body)
                self.assertEqual(found, [], f"dangerous words in {target}: {found}")

    def test_seed_text_never_embeds_the_forbidden_words_as_settings(self):
        # A line-oriented search on top of the parsers below: no `key:` / `key ` at the start of a line.
        for target in app.SEED_TARGETS:
            with self.subTest(target=target):
                for line in executable_text(self.text(target)).split("\n"):
                    if line.strip().startswith("- "):
                        continue  # list items: interactive-sections legitimately names storage and identity
                    first = re.split(r"[\s:=]", line.strip(), maxsplit=1)[0].lower()
                    self.assertNotIn(first, FORBIDDEN_KEYS, line)

    def test_nothing_in_readme_claims_compliance(self):
        for target in app.SEED_TARGETS:
            with self.subTest(target=target):
                readme = self.text(target, "README.txt")
                self.assertIsNone(CLAIMS.search(readme))
                self.assertIn("not a compliance claim", readme)
                self.assertIn("inspired by common security baselines", readme.replace("\n", " "))


class ReadmeTests(SeedTestBase):
    def test_ascii_and_width(self):
        for target in app.SEED_TARGETS:
            with self.subTest(target=target):
                _label, files = self.seed(target)
                text = files["README.txt"].decode("ascii")
                if target == app.SEED_WINDOWS:  # Notepad shows a file properly only with CRLF line ends
                    self.assertEqual(text.count("\n"), text.count("\r\n"), "bare LF in the Windows README")
                    self.assertEqual(text.count("\r"), text.count("\r\n"), "bare CR in the Windows README")
                    text = text.replace("\r\n", "\n")
                for n, line in enumerate(text.split("\n"), 1):
                    self.assertLessEqual(len(line), 80, f"README line {n}: {line!r}")
                    self.assertEqual(line, line.rstrip(), f"README line {n} has trailing spaces")
                self.assertNotIn("\t", text)
                self.assertNotIn("\r", text)
                self.assertTrue(text.endswith("\n"))

    def test_common_content(self):
        for target in LINUX_TARGETS:
            with self.subTest(target=target):
                text = " ".join(self.text(target, "README.txt").split())
                self.assertIn("SECOND USB", text)
                self.assertIn("Nothing here selects a disk", text)
                self.assertIn("creates an account", text)
                self.assertIn("--undo", text)
                self.assertIn("--dry-run", text)
                self.assertIn(".epma-bak", text)

    def test_ubuntu_readme_explains_the_autoinstall_parameter(self):
        text = " ".join(self.text(app.SEED_UBUNTU, "README.txt").split())
        self.assertIn("CIDATA", text)
        self.assertIn("press e", text)
        self.assertIn("add the word autoinstall before the ---", text)
        self.assertIn("F10", text)
        self.assertIn("asks you to confirm", text)

    def test_fedora_readme_mentions_automatic_detection(self):
        text = " ".join(self.text(app.SEED_FEDORA, "README.txt").split())
        self.assertIn("OEMDRV", text)
        self.assertIn("detects by itself", text)
        for family in ("Fedora", "RHEL", "Rocky", "Alma"):
            self.assertIn(family, text)

    def test_no_firewall_claim_on_fedora_and_no_login_promise(self):
        for target in LINUX_TARGETS:
            with self.subTest(target=target):
                text = " ".join(self.text(target, "README.txt").split())
                self.assertNotIn("keep your own login working", text)
                self.assertNotIn("keeps working", text.replace("cannot promise your login keeps working", ""))
                self.assertIn("tries not to lock you out", text)
                self.assertIn("cannot promise your login keeps working", text)
                self.assertIn("sudo (Debian/Ubuntu) or wheel (Fedora/RHEL)", text)
                self.assertIn("authorized_keys", text)
                self.assertIn("[WARN]", text)
                self.assertIn("50-cloud-init.conf", text)
        fedora = " ".join(self.text(app.SEED_FEDORA, "README.txt").split())
        self.assertNotIn("blocks unsolicited incoming", fedora)
        self.assertNotIn("blocks incoming connections", fedora)
        self.assertIn("default zone is left exactly as Fedora/RHEL set it", fedora)
        for target in (app.SEED_UBUNTU, app.SEED_DEBIAN):
            text = " ".join(self.text(target, "README.txt").split())
            self.assertIn("ufw firewall blocks incoming connections by default", text)
            self.assertIn("Docker, libvirt or LXD", text)

    def test_ubuntu_readme_says_every_screen_is_interactive_and_packages_come_later(self):
        text = " ".join(self.text(app.SEED_UBUNTU, "README.txt").split())
        self.assertIn("Every installer screen stays interactive", text)
        self.assertIn("installed by the hardening script on the first boot", text)
        self.assertNotIn("are fetched then", text)

    def test_debian_readme_mentions_su_without_sudo(self):
        text = " ".join(self.text(app.SEED_DEBIAN, "README.txt").split())
        self.assertIn("If sudo is not installed", text)
        self.assertIn("su -", text)
        self.assertIn("bash /path/to/harden-linux.sh", text)
        self.assertIn("sudo bash harden-linux.sh", text)
        other = " ".join(self.text(app.SEED_FEDORA, "README.txt").split())
        self.assertNotIn("If sudo is not installed", other)

    def test_debian_readme_is_honest_about_detection(self):
        text = " ".join(self.text(app.SEED_DEBIAN, "README.txt").split())
        self.assertIn("does NOT detect this drive by itself", text)
        self.assertIn("(a) Recommended", text)
        self.assertIn("sudo bash harden-linux.sh", text)
        self.assertIn("(b) Advanced", text)
        self.assertIn("auto=true priority=critical file=...", text)
        self.assertIn("official Debian installation guide", text)


class UbuntuSeedTests(SeedTestBase):
    def parsed(self):
        text = self.text(app.SEED_UBUNTU)
        self.assertTrue(text.startswith("#cloud-config\n"))
        return parse_mini_yaml(text)

    def test_structure(self):
        tree = self.parsed()
        self.assertEqual(set(tree), {"autoinstall"})
        auto = tree["autoinstall"]
        self.assertEqual(set(auto), {"version", "interactive-sections", "late-commands"})
        self.assertEqual(auto["version"], "1")

    def test_every_screen_stays_interactive(self):
        # "*" makes EVERY section interactive, storage and identity included: by construction the seed
        # cannot pick a disk or create an account, and a section nobody thought of cannot be skipped.
        auto = self.parsed()["autoinstall"]
        self.assertEqual(auto["interactive-sections"], ["*"])
        self.assertEqual(app.SEED_UBUNTU_INTERACTIVE, ("*",))
        self.assertNotIn("storage", auto)
        self.assertNotIn("identity", auto)
        self.assertIn('    - "*"\n', self.text(app.SEED_UBUNTU))

    def test_no_forbidden_keys_anywhere(self):
        keys = {str(k).lower() for k in walk_keys(self.parsed())}
        self.assertEqual(keys & set(FORBIDDEN_KEYS), set(), keys)

    def test_identity_and_storage_are_not_configured(self):
        auto = self.parsed()["autoinstall"]
        self.assertNotIn("storage", auto)
        self.assertNotIn("identity", auto)
        self.assertNotIn("user-data", auto)
        self.assertNotIn("ssh", auto)
        # only the names inside interactive-sections, never "storage:" / "identity:" lines
        for line in self.text(app.SEED_UBUNTU).split("\n"):
            self.assertIsNone(re.match(r"\s*(storage|identity|users?|ssh|chpasswd|password)\s*:", line), line)

    def test_no_packages_key(self):
        # A failing `packages:` entry is fatal in Subiquity; the script / first-boot unit installs what is missing.
        auto = self.parsed()["autoinstall"]
        self.assertNotIn("packages", auto)
        text = self.text(app.SEED_UBUNTU)
        self.assertNotIn("packages", text.replace("no packages", ""))
        for name in app.SEED_PACKAGES_DEB:
            self.assertNotIn("    - " + name, text)

    def test_late_commands_write_and_run_the_script(self):
        commands = self.parsed()["autoinstall"]["late-commands"]
        self.assertEqual(len(commands), 2)
        write, run = commands
        self.assertIn("/target/root/harden-linux.sh", write)
        self.assertIn("base64 -d", write)
        self.assertIn("chmod 700 /target/root/harden-linux.sh", write)
        self.assertIn("curtin in-target --target=/target -- /bin/bash /root/harden-linux.sh --yes --chroot", run)

    def test_embedded_base64_is_exactly_the_script(self):
        write = self.parsed()["autoinstall"]["late-commands"][0]
        payload = heredoc_payload(write)
        self.assertTrue(all(0 < len(line) <= 76 for line in payload))
        self.assertEqual(decode_b64(payload), FAKE_SCRIPT.encode("utf-8"))

    def test_script_output_is_not_appended_to_its_own_log(self):
        write, run = self.parsed()["autoinstall"]["late-commands"]
        invocation = next(line for line in run.split("\n") if "harden-linux.sh --yes --chroot" in line)
        self.assertNotIn(">>", invocation)
        self.assertNotIn("2>&1", invocation)
        # the script itself writes /var/log/epma-hardening.log; the seed only adds one status line
        self.assertEqual(run.count("epma-hardening.log"), 2)  # "finished" and "failed" lines

    def test_a_failing_script_never_fails_the_install(self):
        write, run = self.parsed()["autoinstall"]["late-commands"]
        for command in (write, run):
            # the block ends in `true`, so the exit status of the whole command is always 0
            self.assertEqual(command.rstrip("\n").split("\n")[-1].strip(), "true")
        self.assertIn("else", run)
        self.assertIn("failed", run)
        self.assertIn("/target/var/log/epma-hardening.log", run)
        self.assertNotIn("set -e", run)

    def test_meta_data(self):
        text = self.text(app.SEED_UBUNTU, "meta-data")
        tree = parse_mini_yaml(text)
        self.assertEqual(set(tree), {"instance-id", "local-hostname"})
        self.assertTrue(tree["instance-id"])
        self.assertTrue(tree["local-hostname"])
        self.assertRegex(tree["local-hostname"], r"^[a-z0-9-]+$")

    def test_yaml_indentation_is_two_spaces(self):
        previous = 0
        in_block = False
        block_base = 0
        for n, line in enumerate(self.text(app.SEED_UBUNTU).split("\n"), 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            ind = _indent(line)
            if in_block and ind >= block_base:
                continue  # shell text inside a `- |` block scalar
            in_block = False
            self.assertEqual(ind % 2, 0, f"line {n}: odd indentation")
            self.assertLessEqual(ind - previous, 2, f"line {n}: indentation jumps by more than 2")
            previous = ind
            if line.strip() == "- |":
                in_block, block_base = True, ind + 2
                previous = ind + 2


class FedoraSeedTests(SeedTestBase):
    def sections(self):
        return kickstart_sections(self.text(app.SEED_FEDORA))

    def test_no_commands_outside_sections(self):
        commands, _sections = self.sections()
        # No storage, account, bootloader or power command: nothing at all outside %packages/%post.
        self.assertEqual(commands, [])

    def test_only_packages_and_post_sections(self):
        _commands, sections = self.sections()
        self.assertEqual(set(sections), {"%packages --ignoremissing", "%post"})
        self.assertEqual([p.strip() for p in sections["%packages --ignoremissing"] if p.strip()],
                         list(app.SEED_PACKAGES_RPM))
        self.assertLessEqual(set(app.SEED_PACKAGES_RPM), {"firewalld", "audit", "dnf-automatic"})

    def test_post_runs_in_the_installed_system(self):
        text = self.text(app.SEED_FEDORA)
        self.assertNotIn("--nochroot", text)
        self.assertNotIn("--erroronfail", text)
        self.assertIn("/bin/bash /root/harden-linux.sh --yes --chroot", text)

    def test_embedded_base64_is_exactly_the_script(self):
        self.assertEqual(decode_b64(heredoc_payload(self.text(app.SEED_FEDORA))), FAKE_SCRIPT.encode("utf-8"))

    def test_script_output_is_not_appended_to_its_own_log(self):
        _commands, sections = self.sections()
        invocation = next(line for line in sections["%post"] if "harden-linux.sh --yes --chroot" in line)
        self.assertNotIn(">>", invocation)
        self.assertNotIn("2>&1", invocation)

    def test_post_never_fails_the_install(self):
        _commands, sections = self.sections()
        body = [line for line in sections["%post"] if line.strip()]
        self.assertEqual(body[-1].strip(), "exit 0")
        self.assertIn("else", [line.strip() for line in body])
        self.assertNotIn("set -e", "\n".join(body))

    def test_no_forbidden_kickstart_command_anywhere(self):
        for line in executable_text(self.text(app.SEED_FEDORA)).split("\n"):
            words = line.split()
            if words:
                self.assertNotIn(words[0].lstrip("%"), FORBIDDEN_KEYS, line)


class DebianSeedTests(SeedTestBase):
    def lines(self):
        return preseed_logical_lines(self.text(app.SEED_DEBIAN))

    def test_only_whitelisted_non_disk_keys(self):
        keys = []
        for line in self.lines():
            parts = line.split(None, 3)
            self.assertEqual(parts[0], "d-i", line)
            self.assertIn(parts[2], {"string", "select", "boolean"}, line)
            keys.append(parts[1])
        self.assertEqual(sorted(keys), ["pkgsel/include", "pkgsel/update-policy", "preseed/late_command"])

    def test_no_partman_passwd_or_bootdev(self):
        text = executable_text(self.text(app.SEED_DEBIAN))
        for needle in ("partman", "passwd/", "grub-installer", "bootdev", "user-fullname", "root-password"):
            self.assertNotIn(needle, text)

    def test_embedded_base64_is_exactly_the_script(self):
        text = self.text(app.SEED_DEBIAN)
        chunks = re.findall(r"echo ([A-Za-z0-9+/=]+) >> /target/root/harden-linux\.b64", text)
        self.assertTrue(chunks)
        self.assertTrue(all(len(c) <= app.SEED_DEBIAN_B64_WIDTH for c in chunks))
        self.assertEqual(decode_b64(chunks), FAKE_SCRIPT.encode("utf-8"))

    def test_late_command_uses_long_base64_lines(self):
        self.script = "#!/bin/sh\n" + "# padding padding padding padding padding\n" * 600
        text = self.text(app.SEED_DEBIAN)
        chunks = re.findall(r"echo ([A-Za-z0-9+/=]+) >> /target/root/harden-linux\.b64", text)
        self.assertGreaterEqual(app.SEED_DEBIAN_B64_WIDTH, 4096, "several KB per line")
        self.assertTrue(all(len(c) == app.SEED_DEBIAN_B64_WIDTH for c in chunks[:-1]))
        self.assertLess(len(chunks), 10)  # a 25 KB script: a handful of echo lines, not 450
        self.assertEqual(decode_b64(chunks), self.script.encode("utf-8"))

    def test_script_output_is_not_appended_to_its_own_log(self):
        late = next(line for line in self.lines() if line.startswith("d-i preseed/late_command"))
        invocation = late[late.index("in-target /bin/sh -c"):]
        self.assertIn("/bin/bash /root/harden-linux.sh --yes --chroot &&", invocation)
        self.assertNotIn("--chroot >>", invocation)
        self.assertNotIn("2>&1", invocation)

    def test_late_command_too_big_is_refused(self):
        # ~80 KB of script becomes ~107 KB of base64: above the 100,000 byte limit that keeps the
        # command far from MAX_ARG_STRLEN (131,072).
        self.script = "#!/bin/sh\n" + "".join(f"# line {n:05d} ............................................\n" for n in range(1500))
        self.assertGreater(len(self.script) * 4 // 3, app.SEED_DEBIAN_LATE_MAX)
        with self.assertRaises(ValueError) as ctx:
            self.seed(app.SEED_DEBIAN)
        self.assertIn("late_command", str(ctx.exception))
        # the other seeds carry the same script without a limit of this kind
        self.seed(app.SEED_UBUNTU)
        self.seed(app.SEED_FEDORA)

    def test_late_command_just_under_the_limit_is_accepted(self):
        # a script whose late_command is close to, but below, the limit
        per_line = len("# line 00000 ............................................\n")
        self.script = "#!/bin/sh\n" + "".join(f"# line {n:05d} ............................................\n"
                                                for n in range(int(app.SEED_DEBIAN_LATE_MAX * 0.70 / per_line)))
        late = next(line for line in preseed_logical_lines(self.text(app.SEED_DEBIAN))
                    if line.startswith("d-i preseed/late_command"))
        self.assertLess(len(late.split(" string ", 1)[1]), app.SEED_DEBIAN_LATE_MAX)

    def test_late_command_runs_the_script_and_tolerates_failure(self):
        late = [line for line in self.lines() if line.startswith("d-i preseed/late_command")]
        self.assertEqual(len(late), 1)
        command = late[0]
        self.assertIn("in-target /bin/sh -c", command)
        self.assertIn("/bin/bash /root/harden-linux.sh --yes --chroot", command)
        self.assertIn("||", command)  # failure is logged and swallowed
        self.assertTrue(command.rstrip().endswith("true"))

    def test_continuation_lines_are_well_formed(self):
        raw = self.text(app.SEED_DEBIAN).split("\n")
        start = next(n for n, line in enumerate(raw) if line.startswith("d-i preseed/late_command"))
        block = raw[start:]
        block.remove("")
        self.assertTrue(all(line.endswith("\\") for line in block[:-1]))
        self.assertFalse(block[-1].endswith("\\"))
        for line in block[1:]:
            self.assertTrue(line.startswith("    "))


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class ShellSyntaxTests(SeedTestBase):
    """The shell text inside each seed is syntactically valid (bash -n never runs anything)."""

    def check(self, snippet, label):
        done = subprocess.run(["bash", "-n"], input=snippet.encode("ascii"), capture_output=True, timeout=30)
        self.assertEqual(done.returncode, 0, f"{label}: {done.stderr.decode(errors='replace')}")

    def test_ubuntu_late_commands(self):
        for n, command in enumerate(parse_mini_yaml(self.text(app.SEED_UBUNTU))["autoinstall"]["late-commands"]):
            self.check(command, f"ubuntu late-command {n}")

    def test_fedora_post(self):
        _commands, sections = kickstart_sections(self.text(app.SEED_FEDORA))
        self.check("\n".join(sections["%post"]) + "\n", "fedora %post")

    def test_debian_late_command(self):
        late = next(line for line in preseed_logical_lines(self.text(app.SEED_DEBIAN))
                    if line.startswith("d-i preseed/late_command"))
        self.check(late.split(" string ", 1)[1], "debian late_command")


def _base64_decode_works():
    try:
        done = subprocess.run(["base64", "-d"], input=b"aGk=", capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    return done.returncode == 0 and done.stdout == b"hi"


@unittest.skipUnless(shutil.which("bash") and _base64_decode_works(), "needs bash and base64 -d")
class ShellRoundTripTests(SeedTestBase, TempDirTestCase):
    """Run only the harmless 'rebuild the script' part of each seed inside a temp directory."""

    def run_snippet(self, snippet):
        tmp = self.tmp
        done = subprocess.run(["bash", "-e"], input=snippet.encode("ascii"), capture_output=True, timeout=30, cwd=tmp)
        self.assertEqual(done.returncode, 0, done.stderr.decode(errors="replace"))
        return tmp

    def test_ubuntu_write_step_recreates_the_script(self):
        write = parse_mini_yaml(self.text(app.SEED_UBUNTU))["autoinstall"]["late-commands"][0]
        tmp = self.tmp
        snippet = write.replace("/target", tmp + "/target")
        self.assertEqual(snippet.count(tmp), snippet.count("/target"))
        self.run_snippet(snippet)
        path = os.path.join(tmp, "target", "root", "harden-linux.sh")
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), FAKE_SCRIPT.encode("utf-8"))
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o700)

    def test_fedora_post_step_recreates_the_script(self):
        _commands, sections = kickstart_sections(self.text(app.SEED_FEDORA))
        body = list(sections["%post"])
        end = next(n for n, line in enumerate(body) if line.startswith("chmod 700"))
        snippet = "\n".join(body[:end + 1]) + "\n"
        tmp = self.tmp
        snippet = snippet.replace("/root", tmp + "/root").replace("/var/log", tmp + "/var/log")
        self.run_snippet(snippet)
        with open(os.path.join(tmp, "root", "harden-linux.sh"), "rb") as fh:
            self.assertEqual(fh.read(), FAKE_SCRIPT.encode("utf-8"))

    def test_debian_chunks_recreate_the_script(self):
        late = next(line for line in preseed_logical_lines(self.text(app.SEED_DEBIAN))
                    if line.startswith("d-i preseed/late_command"))
        command = late.split(" string ", 1)[1]
        steps = [s.strip() for s in command.split(";") if s.strip()]
        keep = [s for s in steps if s.startswith(("mkdir", ": >", "echo"))]
        self.assertGreaterEqual(len(keep), 3)
        tmp = self.tmp
        self.run_snippet(";\n".join(keep).replace("/target", tmp + "/target") + "\n")
        with open(os.path.join(tmp, "target", "root", "harden-linux.b64"), encoding="ascii") as fh:
            encoded = fh.read().split()
        self.assertEqual(decode_b64(encoded), FAKE_SCRIPT.encode("utf-8"))


class WindowsSeedTests(SeedTestBase):
    """The Windows 11 seed drive: launchers, script, README and (experimental) answer file + marker."""

    def files(self, during_setup=False):
        return self.seed(app.SEED_WINDOWS, during_setup=during_setup)[1]

    def cmd(self, name, during_setup=False):
        return self.files(during_setup)[name].decode("ascii")

    # ---- the file set
    def test_label_is_a_valid_fat32_label(self):
        for during_setup in (False, True):
            label, _files = self.seed(app.SEED_WINDOWS, during_setup=during_setup)
            self.assertEqual(label, "EPMA-SEED")
            self.assertEqual(app.validate_seed_label(label), label)
            self.assertEqual(app.SEED_LABELS[app.SEED_WINDOWS], "EPMA-SEED")

    def test_exact_file_sets_for_both_modes(self):
        self.assertEqual(set(self.files(False)), EXPECTED_FILES["windows"])
        self.assertEqual(set(self.files(True)), EXPECTED_FILES["windows"] | WINDOWS_SETUP_FILES)
        self.assertEqual(set(self.files()), EXPECTED_FILES["windows"])  # the default is "run after install"
        self.assertFalse(WINDOWS_SETUP_FILES & set(self.files(False)))

    def test_during_setup_only_adds_files(self):
        before, after = self.files(False), self.files(True)
        for name, data in before.items():
            if name == "README.txt":
                continue  # the README gains the experimental section
            self.assertEqual(after[name], data, name)
        self.assertTrue(after["README.txt"].startswith(before["README.txt"].split(b"\r\nHONEST CAVEATS")[0]))

    def test_files_pass_the_drive_validator_in_both_modes(self):
        for during_setup in (False, True):
            files = self.files(during_setup)
            self.assertEqual(app.validate_seed_files(files), files)
            for name, data in files.items():
                self.assertRegex(name, r"^[A-Za-z0-9][A-Za-z0-9._-]*$")  # flat, ASCII
                self.assertTrue(data, name)
                self.assertLessEqual(len(data), MAX_FILE)
            self.assertLessEqual(sum(len(d) for d in files.values()), MAX_TOTAL)

    def test_script_and_answer_file_come_from_the_other_parts_at_call_time(self):
        files = self.files(True)
        self.assertEqual(files["harden.ps1"], FAKE_PS1)
        self.assertEqual(files["autounattend.xml"], FAKE_XML)
        self.ps1_mock.assert_called_with(app.HARDENING_BASELINE)
        self.xml_mock.assert_called_once_with(app.HARDENING_BASELINE)
        self.ps1 = b"\xef\xbb\xbf# second\r\n"
        self.xml = b"<unattend/>\r\n"
        files = self.files(True)
        self.assertEqual(files["harden.ps1"], b"\xef\xbb\xbf# second\r\n")
        self.assertEqual(files["autounattend.xml"], b"<unattend/>\r\n")

    def test_answer_file_is_not_even_requested_after_install_mode(self):
        self.files(False)
        self.ps1_mock.assert_called_once_with(app.HARDENING_BASELINE)
        self.xml_mock.assert_not_called()

    def test_linux_script_is_not_used(self):
        self.files(True)
        self.script_mock.assert_not_called()

    def test_empty_pieces_are_refused(self):
        for bad in (b"", b"  \r\n", "text", None):
            self.ps1 = bad
            with self.subTest(ps1=bad), self.assertRaises(ValueError):
                self.files(False)
        self.ps1 = FAKE_PS1
        for bad in (b"", b"\r\n", "<x/>", None):
            self.xml = bad
            with self.subTest(xml=bad), self.assertRaises(ValueError):
                self.files(True)
            self.files(False)  # the answer file is only needed in the experimental mode

    def test_profile_and_target_are_validated(self):
        for during_setup in (False, True):
            for bad in (app.HARDENING_NONE, "strict", "", None, "BASELINE"):
                with self.subTest(profile=bad, during_setup=during_setup), self.assertRaises(ValueError):
                    app.hardening_files_seed(app.SEED_WINDOWS, bad, during_setup=during_setup)
        self.ps1_mock.assert_not_called()

    def test_deterministic(self):
        for during_setup in (False, True):
            self.assertEqual(self.seed(app.SEED_WINDOWS, during_setup=during_setup),
                             self.seed(app.SEED_WINDOWS, during_setup=during_setup))

    def test_linux_targets_ignore_during_setup(self):
        for target in LINUX_TARGETS:
            with self.subTest(target=target):
                self.assertEqual(self.seed(target, during_setup=True), self.seed(target, during_setup=False))
                self.assertEqual(self.seed(target, during_setup=True), self.seed(target))
        self.ps1_mock.assert_not_called()
        self.xml_mock.assert_not_called()

    # ---- the launchers
    def test_launchers_are_crlf_ascii_without_bom(self):
        for during_setup in (False, True):
            for name in WINDOWS_CMD_FILES:
                with self.subTest(name=name, during_setup=during_setup):
                    data = self.files(during_setup)[name]
                    self.assertFalse(data.startswith(b"\xef\xbb\xbf"), "BOM")
                    text = data.decode("ascii")
                    self.assertNotIn("\0", text)
                    self.assertNotIn("\t", text)
                    self.assertTrue(text.endswith("\r\n"))
                    self.assertEqual(text.count("\n"), text.count("\r\n"), "bare LF")
                    self.assertEqual(text.count("\r"), text.count("\r\n"), "bare CR")
                    for n, line in enumerate(text.split("\r\n")[:-1], 1):
                        self.assertEqual(line, line.rstrip(), f"{name}:{n} trailing whitespace")
                        self.assertLessEqual(len(line), 200, f"{name}:{n}")
                    self.assertTrue(text.startswith("@echo off\r\n"))

    def test_launchers_say_what_they_do(self):
        for name in WINDOWS_CMD_FILES:
            with self.subTest(name=name):
                text = self.cmd(name)
                head = [line for line in text.split("\r\n") if line.startswith(("rem ", "echo "))][:12]
                joined = " ".join(head)
                self.assertIn("EPMA", joined)
                self.assertIn("EXPERIMENTAL", joined)
                self.assertIn("Nothing is installed and nothing is downloaded", " ".join(joined.split()).replace("echo ", ""))
                first_echo = next(line for line in text.split("\r\n") if line.startswith("echo ") and len(line) > 6)
                self.assertTrue(first_echo.startswith("echo EPMA USB CREATOR"), first_echo)

    def test_every_launcher_runs_the_script_from_its_own_folder_quoted(self):
        ps = '"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"'
        for name, mode in (("harden.cmd", "Apply"), ("audit.cmd", "Audit"), ("undo.cmd", "Undo")):
            with self.subTest(name=name):
                text = self.cmd(name)
                run = [line for line in text.split("\r\n") if line.startswith(ps) and '-File "' in line]
                self.assertEqual(run, [f'{ps} -NoProfile -ExecutionPolicy Bypass -File '
                                       f'"%~dp0harden.ps1" -Mode {mode}'])
                for m in re.finditer(r"%~dp0", text):  # always inside double quotes: paths with spaces work
                    self.assertEqual(text[m.start() - 1], '"', "unquoted %~dp0")
                    self.assertEqual(text[m.end():m.end() + 11], "harden.ps1\"")
                self.assertNotIn("%cd%", text.lower())  # never the current folder: it is System32 after elevation
                self.assertNotIn("%0", text)
                self.assertEqual(text.count("-Mode"), 1 + text.count("rem Runs harden.ps1 -Mode"))
                others = {"Apply", "Audit", "Undo"} - {mode}
                self.assertFalse([o for o in others if f"-Mode {o}" in text])

    def test_system_tools_are_called_by_full_path_and_the_current_folder_is_not_searched(self):
        for name in WINDOWS_CMD_FILES:
            with self.subTest(name=name):
                lines = self.cmd(name).split("\r\n")
                self.assertEqual(lines[:3], ["@echo off", "setlocal", 'set "NoDefaultCurrentDirectoryInExePath=1"'])
                for tool in ("net.exe session", "fltmc.exe"):
                    hits = [ln for ln in lines if tool in ln]
                    self.assertEqual(len(hits), 1, tool)
                    self.assertTrue(hits[0].startswith("%SystemRoot%\\System32\\"), hits[0])
                for ln in lines:  # no command is started by its bare name
                    self.assertNotRegex(ln, r"^(net|fltmc|powershell|choice|certutil|cmd|reg|sc|where|timeout)\b", ln)
                    self.assertNotRegex(ln, r"^\"?powershell", ln)
                self.assertEqual(self.cmd(name).lower().count("powershell.exe"),
                                 self.cmd(name).count("\\WindowsPowerShell\\v1.0\\powershell.exe"))

    def test_every_launcher_checks_for_admin_and_elevates_itself(self):
        for name in WINDOWS_CMD_FILES:
            with self.subTest(name=name):
                text = self.cmd(name)
                self.assertIn("%SystemRoot%\\System32\\net.exe session >nul 2>&1", text)
                self.assertIn("%SystemRoot%\\System32\\fltmc.exe >nul 2>&1", text)
                self.assertIn("Start-Process", text)
                self.assertIn("-Verb RunAs", text)
                self.assertIn("-ArgumentList 'elevated'", text)  # the elevated copy must not elevate again
                self.assertIn('if /i "%~1"=="elevated" goto :noadmin', text)
                self.assertLess(text.index("net.exe session"), text.index("Start-Process"))
                self.assertLess(text.index("Start-Process"), text.index('-File "'))
                self.assertIn("Administrator rights were not granted. Nothing was changed.", text)

    def test_the_launcher_path_reaches_powershell_through_the_environment_only(self):
        # A folder name with ' or a typographic apostrophe (U+2018/2019/201A/201B) must not be able to leave a
        # PowerShell string: the path is never put into the command text, only into an environment variable.
        for name in WINDOWS_CMD_FILES:
            with self.subTest(name=name):
                text = self.cmd(name)
                self.assertIn('set "EPMA_SELF=%~f0"', text)
                (start,) = [ln for ln in text.split("\r\n") if "Start-Process" in ln]
                self.assertIn("-FilePath $env:EPMA_SELF", start)
                self.assertNotIn("%~f0", start)
                self.assertNotIn("%EPMA_SELF%", start)
                self.assertEqual(re.findall(r"%[^%]*%", start), ["%SystemRoot%"])  # no other variable inside it
                self.assertEqual(start.count("'"), 2)  # only 'elevated', a constant
                self.assertNotIn("SELF_PS", text)
                self.assertNotIn("'=''", text)  # the old quote-doubling workaround is gone
                for quote in "‘’‚‛":
                    self.assertNotIn(quote, text)

    def test_harden_and_undo_ask_for_confirmation_audit_does_not(self):
        choice = '%SystemRoot%\\System32\\choice.exe /c yn /n /m "Continue? [y/N] "'
        for name in ("harden.cmd", "undo.cmd"):
            with self.subTest(name=name):
                text = self.cmd(name)
                self.assertIn(choice, text)
                self.assertLess(text.index("Continue? [y/N]"), text.index('-File "'))
                # only the answer "y" (errorlevel 1) leads to the run; 2 (n), 0 (Ctrl+C) and errors cancel
                self.assertIn("if errorlevel 2 goto :cancel\r\nif errorlevel 1 goto :run\r\n:cancel\r\n", text)
                self.assertIn("Cancelled. Nothing was changed.", text)
                cancel = text.index(":cancel")
                self.assertLess(cancel, text.index('-File "'))
                self.assertIn("exit /b 1", text[cancel:text.index("\r\n:run\r\n")])
                # nothing the user types is ever expanded by cmd: no set /p, no %ANSWER% in an if
                self.assertNotIn("set /p", text)
                self.assertNotIn("ANSWER", text)
        audit = self.cmd("audit.cmd")
        self.assertNotIn("Continue?", audit)
        self.assertNotIn("choice", audit)
        self.assertNotIn(":cancel", audit)
        self.assertIn("changes nothing", audit)

    def test_the_window_stays_open(self):
        flags = {"harden.cmd": "WARN", "audit.cmd": "DIFF", "undo.cmd": "WARN"}
        for name in WINDOWS_CMD_FILES:
            with self.subTest(name=name):
                text = self.cmd(name)
                tail = text.split('-File "')[1]
                self.assertIn("\r\npause\r\n", tail)
                self.assertIn("exit /b %RC%", tail)
                self.assertIn(f"a [{flags[name]}] line means a", tail)
                other = "DIFF" if flags[name] == "WARN" else "WARN"
                self.assertNotIn(other, text)
        self.assertIn("non-zero exit code", self.cmd("undo.cmd"))

    def test_launchers_have_no_destructive_or_download_commands(self):
        bad = re.compile(r"\b(del|erase|format|diskpart|rd|rmdir|reg|regedit|mountvol|bcdedit|cipher|shutdown|"
                         r"takeown|icacls|robocopy|xcopy|copy|move|ren|rename|mkdir|md|taskkill|sc|netsh|wmic|"
                         r"curl|wget|bitsadmin|certutil|Invoke-WebRequest|Invoke-Expression|iex|DownloadFile|"
                         r"DownloadString|msiexec|winget|choco)\b", re.I)
        for name in WINDOWS_CMD_FILES:
            with self.subTest(name=name):
                text = self.cmd(name)
                self.assertEqual(bad.findall(text), [])
                self.assertNotIn("reg delete", text.lower())
                self.assertNotIn("http", text.lower())
                self.assertIsNone(re.search(r"\\\\|[A-Za-z]:\\", text.replace("C:\\Windows\\Temp", "")), "absolute path")
                self.assertNotIn("-WindowStyle Hidden", text)  # nothing runs out of sight

    def test_percent_signs_are_only_the_known_safe_forms(self):
        allowed = re.compile(r"%~dp0|%~f0|%~1|%SystemRoot%|%RC%|%errorlevel%")
        for name in WINDOWS_CMD_FILES:
            with self.subTest(name=name):
                text = self.cmd(name)
                self.assertNotIn("%", allowed.sub("", text))
                self.assertNotIn("!", text)  # no delayed expansion surprises

    def test_labels_and_gotos_match(self):
        for name in WINDOWS_CMD_FILES:
            with self.subTest(name=name):
                lines = self.cmd(name).split("\r\n")
                labels = [line for line in lines if line.startswith(":")]
                self.assertEqual(len(labels), len(set(labels)))
                for target in re.findall(r"goto (:\w+)", "\r\n".join(lines)):
                    self.assertIn(target, labels)
                self.assertEqual(lines.count("@echo off"), 1)

    def test_echo_lines_use_no_special_characters(self):
        # & | < > ( ) ^ " and % in an echo line would run something or break the line
        for name in WINDOWS_CMD_FILES:
            with self.subTest(name=name):
                for line in self.cmd(name).split("\r\n"):
                    if line.startswith("echo "):
                        self.assertIsNone(re.search(r'[&|<>()^"%!]', line[5:].replace("%RC%", "")), line)

    def test_no_secrets_or_account_changes_in_the_launchers(self):
        for name in WINDOWS_CMD_FILES:
            with self.subTest(name=name):
                text = self.cmd(name)
                self.assertIsNone(HASH_LIKE.search(text))
                self.assertIsNone(CLAIMS.search(text))
                self.assertIsNone(re.search(r"\b(net user|net localgroup|password|secret|token|key)\b", text, re.I))

    # ---- the README
    def test_readme_is_crlf_ascii_and_at_most_80_columns(self):
        for during_setup in (False, True):
            data = self.files(during_setup)["README.txt"]
            text = data.decode("ascii")
            self.assertFalse(data.startswith(b"\xef\xbb\xbf"))
            self.assertTrue(text.endswith("\r\n"))
            self.assertEqual(text.count("\n"), text.count("\r\n"))
            for n, line in enumerate(text.split("\r\n")[:-1], 1):
                self.assertLessEqual(len(line), 80, f"README line {n}: {line!r}")
                self.assertEqual(line, line.rstrip())
            self.assertNotIn("\t", text)

    def test_readme_explains_what_the_drive_is_and_how_to_use_it(self):
        text = " ".join(self.text(app.SEED_WINDOWS, "README.txt").split())
        for needle in ("SECOND small USB", "NOT a Windows installer", "does not boot",
                       "Nothing is installed and nothing is downloaded",
                       "RUN IT AFTER WINDOWS IS INSTALLED",
                       "File Explorer", "audit.cmd", "harden.cmd", "undo.cmd", "FIRST", "User Account Control",
                       "choose Yes", "Continue? [y/N]", "C:\\Windows\\Temp\\epma-hardening.log",
                       "A restart may be needed", "A [WARN] line means that a setting is NOT in effect",
                       "plain text files", "Notepad"):
            self.assertIn(needle, text)
        self.assertLess(text.index("audit.cmd"), text.index("harden.cmd"), "audit comes first")

    def test_readme_lists_every_setting_and_what_is_left_alone(self):
        text = " ".join(self.text(app.SEED_WINDOWS, "README.txt").split())
        lines = app.describe_hardening_windows_applied(app.HARDENING_BASELINE)
        self.assertGreater(len(lines), 5)
        self.assertLess(len(lines), len(app.describe_hardening_windows(app.HARDENING_BASELINE)))
        for line in lines:
            summary = line.split(" -- risk:")[0]
            self.assertIn(" ".join(summary.split()), text)
        self.assertIn("-DisableLegacyNetwork", text)     # the opt-in settings are named as opt-in, not listed as applied
        self.assertNotIn("-- risk", text)
        for _sid, item, _why in app.WINDOWS_HARDENING_NOT_CHANGED:
            self.assertIn(item, text)
        self.assertIn("WHAT IT LEAVES ALONE", text)

    def test_readme_is_honest(self):
        for during_setup in (False, True):
            text = " ".join(self.text(app.SEED_WINDOWS, "README.txt", during_setup=during_setup).split())
            self.assertIn("EXPERIMENTAL", text.upper())
            self.assertIn("never executed by its authors on a real Windows", text)
            self.assertIn("not a compliance claim, certification or guarantee", text)
            self.assertIn("inspired by common security baselines", text)
            self.assertIn("spare PC", text)
            self.assertIn("virtual machine", text)
            self.assertIn("Tamper Protection", text)
            self.assertIn("another antivirus", text.lower())
            self.assertIn("[WARN]", text)
            self.assertIn("Nothing here selects a disk", text)
            self.assertIn("nothing creates an account", text)
            self.assertIsNone(CLAIMS.search(text), "compliance word")
            for word in ("CIS", "STIG", "NIST", "compliant", "certified", "guaranteed"):
                self.assertNotIn(word, text)

    def test_experimental_section_only_with_during_setup(self):
        plain = " ".join(self.text(app.SEED_WINDOWS, "README.txt", during_setup=False).split())
        setup = " ".join(self.text(app.SEED_WINDOWS, "README.txt", during_setup=True).split())
        for needle in ("autounattend.xml", "EPMA-SEED.txt", "specialize", "EXPERIMENTAL: APPLY IT WHILE",
                       "SetupComplete.cmd", "SHA-256", "Panther", "ARM64"):
            self.assertNotIn(needle, plain)
            self.assertIn(needle, setup)
        for needle in ("next to the Windows installer USB BEFORE you start Setup",
                       "It must still be plugged in at the first restart of Setup",
                       "you can unplug it: it is not needed at the end of Setup",
                       "Setup still asks for the language, the disk, the edition and your account",
                       "the answer file only copies harden.ps1 and SetupComplete.cmd from this drive into "
                       "C:\\Windows\\Setup\\Scripts",
                       "It does not run PowerShell and it never overwrites a SetupComplete.cmd that is already there",
                       "At the very end of Setup, Windows runs SetupComplete.cmd",
                       "It checks the SHA-256 of the harden.ps1 next to it and only then runs it in Apply mode",
                       "It appends to the log C:\\Windows\\Temp\\epma-hardening.log ([SKIP] lines say why nothing ran)",
                       "it is not defined which one Windows uses: use only one of them",
                       "already has its own autounattend.xml", "has not been tried by its authors on a real Windows"):
            self.assertIn(needle, setup)
        self.assertNotIn("Setup then runs harden.ps1 at the end of the specialize phase", setup)  # the old design
        self.assertLess(setup.index("HONEST CAVEATS"), setup.index("EXPERIMENTAL: APPLY IT WHILE"))

    def test_during_setup_readme_says_who_is_trusted_and_what_the_hash_does_not_do(self):
        setup = " ".join(self.text(app.SEED_WINDOWS, "README.txt", during_setup=True).split())
        for needle in ("the answer file and SetupComplete.cmd trust any drive that carries EPMA-SEED.txt on its root "
                       "(the first match from D: to Z:)",
                       "The SHA-256 check only protects against a harden.ps1 that does not match the "
                       "SetupComplete.cmd next to it",
                       "It does NOT protect against someone who controls the seed drive",
                       "Use only a seed drive that you made yourself"):
            self.assertIn(needle, setup)
        for claim in ("tamper-proof", "digitally signed", "verified drive", "trusted drive", "secure drive",
                      "authenticated drive", "protects the drive"):
            self.assertNotIn(claim, setup.lower())
        self.assertIn("This drive is not protected or authenticated in any way", setup)

    def test_during_setup_readme_explains_the_answer_file_error(self):
        setup = " ".join(self.text(app.SEED_WINDOWS, "README.txt", during_setup=True).split())
        for needle in ("Windows could not parse or process the unattended answer file",
                       "unplug this drive and RESTART the installation from the beginning",
                       "C:\\Windows\\Panther", "unplugging alone is not enough",
                       "Then use harden.cmd after installing",
                       "64-bit Intel/AMD PCs (amd64) only. On ARM64 PCs use Way 1"):
            self.assertIn(needle, setup)
        plain = " ".join(self.text(app.SEED_WINDOWS, "README.txt", during_setup=False).split())
        self.assertNotIn("Windows could not parse", plain)

    def test_readme_audit_and_launcher_sentences_are_accurate(self):
        for during_setup in (False, True):
            text = " ".join(self.text(app.SEED_WINDOWS, "README.txt", during_setup=during_setup).split())
            self.assertIn("audit.cmd does not ask you to confirm anything", text)
            self.assertIn("[DIFF] means NOT in effect", text)
            self.assertIn("harden.cmd and undo.cmd also ask you to confirm; audit.cmd does not", text)
            self.assertNotIn("Each launcher only asks for administrator rights, asks you to confirm", text)
            self.assertNotIn("audit.cmd prints a [WARN]", text)

    def test_readme_explains_the_opt_in_switch_and_the_undo_limits(self):
        for during_setup in (False, True):
            raw = self.text(app.SEED_WINDOWS, "README.txt", during_setup=during_setup)
            text = " ".join(raw.split())
            self.assertIn("powershell -ExecutionPolicy Bypass -File harden.ps1 -Mode Apply -DisableLegacyNetwork", text)
            self.assertIn("open PowerShell as administrator", text)
            self.assertIn("LIMITS OF UNDO.CMD", text)
            for needle in ("It does not turn SMBv1 or PowerShell 2.0 on again",
                           "does not lower the Security log size",
                           "already in the wanted state before harden.cmd ran is not recorded",
                           "undo.cmd can finish with a non-zero exit code when one of its steps failed"):
                self.assertIn(needle, text)

    def test_readme_logs_per_mode(self):
        plain = " ".join(self.text(app.SEED_WINDOWS, "README.txt", during_setup=False).split())
        setup = " ".join(self.text(app.SEED_WINDOWS, "README.txt", during_setup=True).split())
        for text in (plain, setup):
            self.assertIn("harden.cmd and undo.cmd write a log to C:\\Windows\\Temp\\epma-hardening.log. "
                          "audit.cmd only prints in its window", text)
        self.assertIn("It appends to the log C:\\Windows\\Temp\\epma-hardening.log", setup)
        self.assertNotIn("SetupComplete.cmd", plain)

    def test_seed_drive_no_longer_has_to_stay_until_the_end(self):
        setup = " ".join(self.text(app.SEED_WINDOWS, "README.txt", during_setup=True).split())
        self.assertNotIn("Keep both drives plugged in", setup)
        self.assertNotIn("until the first screens", setup)

    # ---- SetupComplete.cmd on the seed drive (during setup)
    def test_setupcomplete_is_on_the_drive_only_in_during_setup_and_holds_the_hash_of_harden_ps1(self):
        import hashlib
        self.assertNotIn("SetupComplete.cmd", self.files(False))
        files = self.files(True)
        text = files["SetupComplete.cmd"].decode("ascii")
        self.assertIn('set "EPMA_WANT=' + hashlib.sha256(FAKE_PS1).hexdigest() + '"', text)
        self.assertEqual(files["SetupComplete.cmd"], app._windows_setupcomplete_cmd(app.HARDENING_BASELINE, FAKE_PS1))
        # the hash line follows the script
        self.ps1 = b"\xef\xbb\xbf# second\r\n"
        other = self.files(True)["SetupComplete.cmd"].decode("ascii")
        self.assertIn('set "EPMA_WANT=' + hashlib.sha256(self.ps1).hexdigest() + '"', other)
        self.assertNotEqual(other, text)
        self.assertEqual([ln for ln in other.split("\r\n") if not ln.startswith('set "EPMA_WANT')],
                         [ln for ln in text.split("\r\n") if not ln.startswith('set "EPMA_WANT')])

    def test_setupcomplete_on_the_drive_checks_before_it_runs(self):
        text = self.cmd("SetupComplete.cmd", True)
        self.assertLess(text.index("-hashfile"), text.index("-File"))
        self.assertIn("harden.ps1 was NOT run", text)
        self.assertTrue(text.endswith("exit /b 0\r\n"))

    # ---- the marker and the answer file
    def test_marker_file_is_one_short_ascii_line(self):
        data = self.files(True)["EPMA-SEED.txt"]
        text = data.decode("ascii")
        self.assertTrue(text.endswith("\r\n"))
        self.assertEqual(text.count("\n"), 1)
        self.assertLessEqual(len(text), 120)
        self.assertIn("EPMA", text)
        self.assertIn("seed", text)
        self.assertIsNone(CLAIMS.search(text))

    # ---- the whole drive
    def test_no_secrets_or_hash_like_strings_anywhere(self):
        for during_setup in (False, True):
            for name, data in self.files(during_setup).items():
                if name in ("harden.ps1", "autounattend.xml"):
                    continue  # stand-ins here; the real ones are checked in RealWindowsSeedTests
                if name == "SetupComplete.cmd":
                    continue  # holds the public SHA-256 of harden.ps1 (checked in its own test)
                with self.subTest(name=name, during_setup=during_setup):
                    text = data.decode("ascii")
                    self.assertIsNone(HASH_LIKE.search(text))
                    self.assertIsNone(re.search(r"[A-Za-z0-9+/]{40,}={0,2}", text), "long base64-like string")
                    self.assertIsNone(re.search(r"\b[0-9a-f]{32,}\b", text, re.I), "hash-like string")
                    for needle in ("BEGIN PRIVATE", "BEGIN OPENSSH", "ssh-rsa", "ssh-ed25519"):
                        self.assertNotIn(needle, text)


@unittest.skipUnless(hasattr(app, "windows_hardening_ps1") and hasattr(app, "windows_seed_autounattend"),
                     "the Windows script and answer file are not in this build")
class RealWindowsSeedTests(unittest.TestCase):
    """The same drive with the real script and answer file (runs once the Windows parts are merged)."""

    def test_real_pieces_end_up_on_the_drive_unchanged(self):
        ps1 = app.windows_hardening_ps1(app.HARDENING_BASELINE)
        xml = app.windows_seed_autounattend(app.HARDENING_BASELINE)
        for during_setup in (False, True):
            label, files = app.hardening_files_seed(app.SEED_WINDOWS, app.HARDENING_BASELINE, during_setup=during_setup)
            self.assertEqual(label, "EPMA-SEED")
            self.assertEqual(set(files), EXPECTED_FILES["windows"] | (WINDOWS_SETUP_FILES if during_setup else set()))
            self.assertEqual(files["harden.ps1"], ps1)
            if during_setup:
                self.assertEqual(files["autounattend.xml"], xml)
            self.assertEqual(app.validate_seed_files(files), files)
            for name in ("harden.cmd", "audit.cmd", "undo.cmd", "README.txt"):
                self.assertTrue(files[name].decode("ascii"))
            self.assertEqual(app.hardening_files_seed(app.SEED_WINDOWS, app.HARDENING_BASELINE,
                                                      during_setup=during_setup), (label, files))

    def test_launchers_call_parameters_the_real_script_declares(self):
        ps1 = app.windows_hardening_ps1(app.HARDENING_BASELINE).decode("utf-8-sig")
        self.assertRegex(ps1, r"(?is)param\s*\(.*\$Mode")
        for mode in ("Apply", "Audit", "Undo"):
            self.assertIn(mode, ps1, f"the real harden.ps1 does not mention -Mode {mode}")

    def test_real_pieces_hold_no_secrets_or_claims(self):
        _label, files = app.hardening_files_seed(app.SEED_WINDOWS, app.HARDENING_BASELINE, during_setup=True)
        for name in ("harden.ps1", "autounattend.xml"):
            text = files[name].decode("utf-8-sig")
            with self.subTest(name=name):
                self.assertIsNone(HASH_LIKE.search(text))
                self.assertIsNone(CLAIMS.search(text))
                self.assertNotIn("BEGIN PRIVATE", text)


@unittest.skipUnless(hasattr(app, "linux_hardening_script"), "linux_hardening_script is not in this build")
class RealScriptTests(unittest.TestCase):
    """Same structural checks with the real script (this runs once the scripts part is merged)."""

    def test_real_script_round_trips_in_every_seed(self):
        script = app.linux_hardening_script(app.HARDENING_BASELINE).encode("utf-8")
        for target in LINUX_TARGETS:
            with self.subTest(target=target):
                label, files = app.hardening_files_seed(target, app.HARDENING_BASELINE)
                self.assertEqual(label, ALLOWED_LABELS[target])
                self.assertEqual(files["harden-linux.sh"], script)
                self.assertTrue(all(len(d) <= MAX_FILE for d in files.values()))
                self.assertLessEqual(sum(len(d) for d in files.values()), MAX_TOTAL)
                text = files[CONFIG_FILES[target]].decode("ascii")
                if target == app.SEED_DEBIAN:
                    chunks = re.findall(r"echo ([A-Za-z0-9+/=]+) >> /target/root/harden-linux\.b64", text)
                    self.assertEqual(decode_b64(chunks), script)
                    late = next(line for line in preseed_logical_lines(text) if line.startswith("d-i preseed/late_command"))
                    command = late.split(" string ", 1)[1]
                    self.assertLess(len(command), app.SEED_DEBIAN_LATE_MAX, "the real late_command must fit with room to spare")
                    self.assertLess(len(command), 131072)
                    self.assertLessEqual(len(chunks), 30, "long base64 lines, few echo commands")
                else:
                    self.assertEqual(decode_b64(heredoc_payload(text)), script)
                for name in set(files) - {"harden-linux.sh"}:
                    body = files[name].decode("ascii")
                    self.assertIsNone(HASH_LIKE.search(body))
                    self.assertIsNone(CLAIMS.search(body))
                self.assertEqual(app.hardening_files_seed(target, app.HARDENING_BASELINE), (label, files))


if __name__ == "__main__":
    unittest.main()
