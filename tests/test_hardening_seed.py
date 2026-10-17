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

ALLOWED_LABELS = {"ubuntu": "CIDATA", "fedora": "OEMDRV", "debian": "EPMA-SEED"}
EXPECTED_FILES = {
    "ubuntu": {"user-data", "meta-data", "harden-linux.sh", "README.txt"},
    "fedora": {"ks.cfg", "harden-linux.sh", "README.txt"},
    "debian": {"preseed.cfg", "harden-linux.sh", "README.txt"},
}
CONFIG_FILES = {"ubuntu": "user-data", "fedora": "ks.cfg", "debian": "preseed.cfg"}

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

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(app, "linux_hardening_script", create=True, side_effect=lambda p: self.script)
        self.script_mock = patcher.start()
        self.addCleanup(patcher.stop)

    def seed(self, target, profile=None):
        return app.hardening_files_seed(target, app.HARDENING_BASELINE if profile is None else profile)

    def text(self, target, name=None):
        _label, files = self.seed(target)
        return files[name or CONFIG_FILES[target]].decode("ascii")


class ContractTests(unittest.TestCase):
    def test_constants(self):
        self.assertEqual(app.MODE_SEED, "seed")
        self.assertEqual(app.HARDENING_NONE, "none")
        self.assertEqual(app.HARDENING_BASELINE, "baseline")
        self.assertEqual(app.HARDENING_PROFILES, ("none", "baseline"))
        self.assertEqual((app.SEED_UBUNTU, app.SEED_FEDORA, app.SEED_DEBIAN), ("ubuntu", "fedora", "debian"))
        self.assertEqual(app.SEED_TARGETS, ("ubuntu", "fedora", "debian"))


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
        for bad in ("arch", "windows", "", None, "UBUNTU", 3, ["ubuntu"]):
            with self.subTest(target=bad), self.assertRaises(ValueError):
                app.hardening_files_seed(bad, app.HARDENING_BASELINE)

    def test_empty_script_is_refused(self):
        for bad in ("", "  \n", None, b"#!/bin/sh\n"):
            self.script = bad
            for target in app.SEED_TARGETS:
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
        for target in app.SEED_TARGETS:
            with self.subTest(target=target):
                _label, files = self.seed(target)
                self.assertEqual(files["harden-linux.sh"], FAKE_SCRIPT.encode("utf-8"))

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
                    _label, files = self.seed(target)
                    self.assertTrue(all(len(data) <= MAX_FILE for data in files.values()),
                                    {k: len(v) for k, v in files.items()})
                    self.assertLessEqual(sum(len(d) for d in files.values()), MAX_TOTAL)
                    self.assertLessEqual(len(files), 8)

    def test_config_files_are_clean_ascii(self):
        for target in app.SEED_TARGETS:
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
            for name in set(EXPECTED_FILES[target]) - {"harden-linux.sh"}:
                with self.subTest(target=target, name=name):
                    _label, files = self.seed(target)
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
                for n, line in enumerate(text.split("\n"), 1):
                    self.assertLessEqual(len(line), 80, f"README line {n}: {line!r}")
                    self.assertEqual(line, line.rstrip(), f"README line {n} has trailing spaces")
                self.assertNotIn("\t", text)
                self.assertNotIn("\r", text)
                self.assertTrue(text.endswith("\n"))

    def test_common_content(self):
        for target in app.SEED_TARGETS:
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
        self.assertEqual(set(auto), {"version", "interactive-sections", "packages", "late-commands"})
        self.assertEqual(auto["version"], "1")

    def test_storage_and_identity_stay_interactive(self):
        auto = self.parsed()["autoinstall"]
        sections = auto["interactive-sections"]
        self.assertIsInstance(sections, list)
        self.assertIn("storage", sections)
        self.assertIn("identity", sections)
        self.assertEqual(len(sections), len(set(sections)))
        self.assertLessEqual(set(sections), {"locale", "keyboard", "network", "storage", "identity", "timezone"})
        self.assertNotIn("*", sections)

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

    def test_packages_are_only_what_the_script_needs(self):
        auto = self.parsed()["autoinstall"]
        self.assertEqual(auto["packages"], list(app.SEED_PACKAGES_DEB))
        self.assertLessEqual(set(auto["packages"]), {"ufw", "auditd", "unattended-upgrades"})

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
        self.assertTrue(all(len(c) <= 76 for c in chunks))
        self.assertEqual(decode_b64(chunks), FAKE_SCRIPT.encode("utf-8"))

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


@unittest.skipUnless(hasattr(app, "linux_hardening_script"), "linux_hardening_script is not in this build")
class RealScriptTests(unittest.TestCase):
    """Same structural checks with the real script (this runs once the scripts part is merged)."""

    def test_real_script_round_trips_in_every_seed(self):
        script = app.linux_hardening_script(app.HARDENING_BASELINE).encode("utf-8")
        for target in app.SEED_TARGETS:
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
                else:
                    self.assertEqual(decode_b64(heredoc_payload(text)), script)
                for name in set(files) - {"harden-linux.sh"}:
                    body = files[name].decode("ascii")
                    self.assertIsNone(HASH_LIKE.search(body))
                    self.assertIsNone(CLAIMS.search(body))
                self.assertEqual(app.hardening_files_seed(target, app.HARDENING_BASELINE), (label, files))


if __name__ == "__main__":
    unittest.main()
