"""The Linux hardening script (`harden-linux.sh`) written by `linux_hardening_script()`.

Nothing here touches the real system: the script has a hidden test mode (EPMA_HARDEN_TEST_ROOT) in
which every path lives below a temporary directory, "live" commands (apt-get, systemctl, ufw, sshd,
...) are looked up in <root>/stubs only, and EPMA_HARDEN_TEST_UID may pretend to be root. The tests
build a fake root, run the real script text against it and look at the files that result.
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest

from tests.helpers import app

BASH = shutil.which("bash") or "/bin/bash"
SHELLCHECK = shutil.which("shellcheck") or ("/opt/homebrew/bin/shellcheck" if os.path.exists("/opt/homebrew/bin/shellcheck") else None)

STUB_NAMES = ("apt-get", "dpkg", "rpm", "dnf", "systemctl", "sysctl", "ufw", "firewall-cmd", "sshd",
              "augenrules", "getenforce")

# One generic stub for every live command. It logs the call and keeps a little state in <root>/state
# so a second run can see what the first one did (installed packages, enabled services, ufw).
STUB = r"""#!/bin/sh
R="$EPMA_HARDEN_TEST_ROOT"
n="$(basename "$0")"
echo "$n $*" >> "$R/calls.log"
S="$R/state"
mkdir -p "$S"
last=""
for a in "$@"; do last="$a"; done
case "$n" in
sshd)
  case "$1" in
    -t) if [ -e "$S/sshd_t_fail" ]; then echo "Bad configuration option: Nonsense" >&2; exit 1; fi; exit 0 ;;
    -T) if [ -e "$S/sshd_T" ]; then cat "$S/sshd_T"; else
          printf 'port 22\npermitrootlogin no\nx11forwarding no\nmaxauthtries 4\nlogingracetime 30\npermitemptypasswords no\n'
        fi; exit 0 ;;
  esac ;;
dpkg) if [ -e "$S/pkg_$2" ]; then echo "Package: $2"; echo "Status: install ok installed"; exit 0; fi; exit 1 ;;
rpm) if [ -e "$S/pkg_$2" ]; then exit 0; fi; exit 1 ;;
apt-get) if [ "$1" = install ]; then touch "$S/pkg_$last"; fi; exit 0 ;;
dnf) if [ "$2" = install ]; then touch "$S/pkg_$last"; fi; exit 0 ;;
systemctl)
  case "$1" in
    is-active) if [ -e "$S/active_$last" ]; then exit 0; fi; exit 3 ;;
    is-enabled) if [ -e "$S/enabled_$last" ]; then exit 0; fi; exit 1 ;;
    enable) touch "$S/enabled_$last" "$S/active_$last"; exit 0 ;;
    disable) rm -f "$S/enabled_$last"; exit 0 ;;
    list-unit-files) printf 'dnf-automatic-install.timer disabled\n'; exit 0 ;;
  esac ;;
ufw)
  case "$1" in
    status) if [ -e "$S/ufw_active" ]; then printf 'Status: active\nDefault: deny (incoming), allow (outgoing)\n'; else echo "Status: inactive"; fi ;;
    --force) touch "$S/ufw_active" ;;
  esac ;;
firewall-cmd)
  case "$1" in --get-default-zone) echo public; exit 0 ;; esac
  for a in "$@"; do case "$a" in --query-*) exit 1 ;; esac; done ;;
getenforce) echo Enforcing ;;
esac
exit 0
"""

MUTATING_CALLS = re.compile(r"^(apt-get|dnf) |^systemctl (enable|disable|reload|start|stop)|^sysctl |^ufw (default|allow|--force)"
                            r"|^firewall-cmd .*--add-|^augenrules ")


def os_release(distro):
    if distro == "ubuntu":
        return 'PRETTY_NAME="Ubuntu 24.04 LTS"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="24.04"\n'
    if distro == "debian":
        return 'PRETTY_NAME="Debian GNU/Linux 12"\nID=debian\n'
    if distro == "fedora":
        return 'NAME="Fedora Linux"\nID=fedora\nPRETTY_NAME="Fedora Linux 42"\n'
    if distro == "rocky":
        return 'NAME="Rocky Linux"\nID="rocky"\nID_LIKE="rhel centos fedora"\nPRETTY_NAME="Rocky Linux 9"\n'
    if distro == "opensuse":
        return 'ID="opensuse-leap"\nID_LIKE="suse opensuse"\nPRETTY_NAME="openSUSE Leap"\n'
    raise ValueError(distro)


def sysctl_keys(text):
    return re.findall(r"^([a-z0-9_.]+)\|[^|]*\|(?:req|opt)\|", text, re.M)


class FakeRoot:
    """A throw-away root directory with the files the script reads, plus stubs for the live commands."""

    def __init__(self, tc, distro="ubuntu", sshd=True, regular_user=True, proc=True, login_defs=True):
        self.tc = tc
        self.distro = distro
        self.base = tempfile.mkdtemp(prefix="epma-harden-test-")
        tc.addCleanup(shutil.rmtree, self.base, True)
        self.root = os.path.join(self.base, "root")
        self.scripts = os.path.join(self.base, "scripts")
        self.sentinel = os.path.join(self.base, "sentinel")  # HOME and TMPDIR point here: it must stay empty
        for d in (self.root, self.scripts, self.sentinel):
            os.makedirs(d)
        self.script_path = os.path.join(self.scripts, "harden-linux.sh")
        self.script = app.linux_hardening_script(app.HARDENING_BASELINE)
        with open(self.script_path, "w", encoding="ascii", newline="") as fh:
            fh.write(self.script)
        self.write("etc/os-release", os_release(distro))
        accounts = "root:x:0:0:root:/root:/bin/bash\n"
        if regular_user:
            accounts += "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
        self.write("etc/passwd", accounts, 0o644)
        self.write("etc/group", "root:x:0:\n", 0o664)
        self.write("etc/shadow", "root:!:19000:0:99999:7:::\n", 0o644)
        self.write("etc/gshadow", "root:*::\n", 0o640)
        if login_defs:
            self.write("etc/login.defs", "# login.defs\nPASS_MAX_DAYS\t99999\nPASS_MIN_DAYS\t0\nPASS_WARN_AGE\t7\nUMASK\t022\n")
        self.write("etc/security/pwquality.conf", "# pwquality\n")
        self.write("etc/apt/apt.conf.d/20auto-upgrades", '// original\nAPT::Periodic::Update-Package-Lists "0";\n')
        self.makedirs("tmp")
        self.makedirs("state")
        os.makedirs(os.path.join(self.root, "stubs"))
        for name in STUB_NAMES:
            if name == "sshd" and not sshd:
                continue
            if distro in ("ubuntu", "debian") and name in ("rpm", "dnf", "firewall-cmd", "getenforce"):
                continue
            if distro in ("fedora", "rocky") and name in ("apt-get", "dpkg", "ufw"):
                continue
            self.write("stubs/" + name, STUB, 0o755)
        if sshd:
            self.write("etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n")
        if proc:
            for key in sysctl_keys(self.script):
                self.write("proc/sys/" + key.replace(".", "/"), "0\n")
        self.write("sys/module/apparmor/parameters/enabled", "Y\n")
        self.write("etc/selinux/config", "SELINUX=enforcing\n")
        self.makedirs("usr/lib/systemd")

    def path(self, rel):
        return os.path.join(self.root, rel)

    def makedirs(self, rel):
        os.makedirs(self.path(rel), exist_ok=True)

    def write(self, rel, text, mode=None):
        p = self.path(rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="ascii", newline="") as fh:
            fh.write(text)
        if mode is not None:
            os.chmod(p, mode)

    def read(self, rel):
        with open(self.path(rel), encoding="ascii") as fh:
            return fh.read()

    def exists(self, rel):
        return os.path.lexists(self.path(rel))

    def state(self, *names):
        for n in names:
            self.write("state/" + n, "")

    def calls(self):
        try:
            return self.read("calls.log").splitlines()
        except FileNotFoundError:
            return []

    def env(self, **extra):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C", "LC_ALL": "C",
               "HOME": self.sentinel, "TMPDIR": self.sentinel,
               "EPMA_HARDEN_TEST_ROOT": self.root, "EPMA_HARDEN_TEST_UID": "0"}
        env.update(extra)
        return {k: v for k, v in env.items() if v is not None}

    def run(self, *args, stdin_script=False, **extra_env):
        """Run the script; returns (exit status, stdout, stderr). No controlling terminal, so a prompt cannot hang."""
        if stdin_script:
            cmd, data = [BASH, "-s", "--", *args], self.script
        else:
            cmd, data = [BASH, self.script_path, *args], None
        p = subprocess.run(cmd, input=data, capture_output=True, text=True, env=self.env(**extra_env),
                           cwd=self.scripts, timeout=60, start_new_session=True)
        return p.returncode, p.stdout, p.stderr

    def snapshot(self, skip=("calls.log", "state", "tmp"), dirs=True, ignore=()):
        """{relative path: (kind, mode, content)} of everything below the root except `skip`."""
        out = {}
        for dirpath, dirnames, filenames in os.walk(self.root):
            rel_dir = os.path.relpath(dirpath, self.root)
            for name in list(dirnames) + filenames:
                rel = os.path.normpath(os.path.join(rel_dir, name))
                if rel.split(os.sep)[0] in skip or rel in ignore:
                    continue
                full = os.path.join(self.root, rel)
                st = os.lstat(full)
                if os.path.islink(full):
                    out[rel] = ("link", 0, os.readlink(full))
                elif os.path.isdir(full):
                    if dirs:
                        out[rel] = ("dir", st.st_mode & 0o7777, None)
                else:
                    with open(full, "rb") as fh:
                        out[rel] = ("file", st.st_mode & 0o7777, fh.read())
        return out


class TestCase(unittest.TestCase):
    def fake(self, **kw):
        return FakeRoot(self, **kw)

    def assertSentinelEmpty(self, fr):
        self.assertEqual(os.listdir(fr.sentinel), [], "the script wrote outside the test root")


class ScriptTextTests(TestCase):
    def test_profiles(self):
        with self.assertRaises(ValueError):
            app.linux_hardening_script(app.HARDENING_NONE)
        with self.assertRaises(ValueError):
            app.linux_hardening_script("paranoid")
        with self.assertRaises(ValueError):
            app.linux_hardening_script(None)
        text = app.linux_hardening_script(app.HARDENING_BASELINE)
        self.assertIsInstance(text, str)
        self.assertEqual(text, app.linux_hardening_script(app.HARDENING_BASELINE))

    def test_text_shape(self):
        text = app.linux_hardening_script(app.HARDENING_BASELINE)
        text.encode("ascii")  # pure ASCII
        self.assertNotIn("\r", text)
        self.assertTrue(text.startswith("#!/usr/bin/env bash\n"))
        self.assertIn("\nset -euo pipefail\n", text)
        self.assertTrue(text.endswith('main "$@"\n'))

    def test_forbidden_constructs(self):
        text = app.linux_hardening_script(app.HARDENING_BASELINE)
        code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        self.assertIsNone(re.search(r"\beval\b", code))
        for word in ("curl", "wget", "http://", "https://", "ftp://", "ssh-copy-id"):
            with self.subTest(word=word):
                self.assertNotIn(word, text)
        for pattern in (r"\bpip3?\b", r"\bnc\b", r"\bncat\b", r"\bscp\b", r"\bgit\b", r"\bfetch\b"):
            with self.subTest(pattern=pattern):
                self.assertIsNone(re.search(pattern, text), pattern)
        self.assertIsNone(re.search(r"\|\s*(ba|z)?sh\b", code), "never pipe into a shell")
        self.assertIsNone(re.search(r"^\s*(source|\.)\s", code, re.M))
        for line in code.splitlines():
            if "rm -rf" in line:
                self.assertRegex(line, r"\$\{[A-Za-z0-9_]+:\?\}", line)
            if re.search(r"\brm\b", line) and "rm -f" in line:
                self.assertRegex(line, r"\$\{[A-Za-z0-9_]+:\?\}", line)

    def test_no_compliance_claims(self):
        text = app.linux_hardening_script(app.HARDENING_BASELINE)
        for word in ("CIS", "STIG", "NIST"):
            with self.subTest(word=word):
                self.assertNotIn(word, text)
        for word in ("certif", "complian", "benchmark"):
            with self.subTest(word=word):
                self.assertNotIn(word, text.lower())

    def test_never_touches_storage_users_or_secrets(self):
        text = app.linux_hardening_script(app.HARDENING_BASELINE)
        code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        for word in ("mkfs", "parted", "fdisk", "wipefs", "dd if=", "useradd", "chpasswd", "passwd -", "usermod", "setenforce",
                     "aa-enforce", "aa-complain", "usb-storage", "BEGIN", "ssh-rsa", "ssh-ed25519"):
            with self.subTest(word=word):
                self.assertNotIn(word, code)

    def test_modprobe_list_keeps_media_filesystems(self):
        fr = self.fake()
        rc, out, err = fr.run("--yes")
        self.assertEqual(rc, 0, out + err)
        conf = fr.read("etc/modprobe.d/epma-hardening.conf")
        for mod in ("cramfs", "freevxfs", "hfs", "hfsplus", "jffs2", "dccp", "sctp", "rds", "tipc"):
            self.assertIn(f"install {mod} /bin/false", conf)
            self.assertIn(f"blacklist {mod}\n", conf)
        for mod in ("squashfs", "udf", "iso9660", "vfat", "exfat", "ntfs", "usb-storage", "usb_storage", "uas"):
            self.assertNotIn(mod, conf)

    @unittest.skipUnless(os.path.exists(BASH), "bash not found")
    def test_bash_syntax(self):
        fr = self.fake()
        p = subprocess.run([BASH, "-n", fr.script_path], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    @unittest.skipUnless(SHELLCHECK, "shellcheck is not installed")
    def test_shellcheck_clean(self):
        fr = self.fake()
        p = subprocess.run([SHELLCHECK, "--shell=bash", "--severity=style", fr.script_path], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)


class SafetyOfInvocationTests(TestCase):
    def run_plain(self, *args, **env):
        """The script as a normal user would start it: no test hooks (unless given)."""
        base = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C"}
        base.update(env)
        d = tempfile.mkdtemp(prefix="epma-harden-plain-")
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "harden-linux.sh")
        with open(path, "w", encoding="ascii") as fh:
            fh.write(app.linux_hardening_script(app.HARDENING_BASELINE))
        p = subprocess.run([BASH, path, *args], capture_output=True, text=True, env=base, cwd=d, timeout=60,
                           start_new_session=True)
        return p.returncode, p.stdout, p.stderr, d

    def test_help_needs_no_root(self):
        rc, out, err, _d = self.run_plain("--help")
        self.assertEqual(rc, 0, err)
        for opt in ("--dry-run", "--yes", "--undo", "--chroot", "--help"):
            self.assertIn(opt, out)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "must not run as root")
    def test_not_root_exits_2_and_touches_nothing(self):
        for args in (["--dry-run"], ["--yes"], ["--undo", "--yes"], ["--chroot", "--yes"], []):
            with self.subTest(args=args):
                rc, out, err, d = self.run_plain(*args)
                self.assertEqual(rc, 2, out + err)
                self.assertIn("root", err)
                self.assertEqual(os.listdir(d), ["harden-linux.sh"])

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "must not run as root")
    def test_test_uid_is_ignored_without_the_root_variable(self):
        rc, out, err, _d = self.run_plain("--dry-run", EPMA_HARDEN_TEST_UID="0")
        self.assertEqual(rc, 2, out + err)

    def test_bad_test_root_is_refused(self):
        for value in ("relative/dir", "/", "/nonexistent-epma-dir-xyz"):
            with self.subTest(value=value):
                rc, out, err, _d = self.run_plain("--dry-run", EPMA_HARDEN_TEST_ROOT=value, EPMA_HARDEN_TEST_UID="0")
                self.assertEqual(rc, 2, out + err)
                self.assertIn("EPMA_HARDEN_TEST_ROOT", err)

    def test_unknown_option(self):
        fr = self.fake()
        rc, out, err = fr.run("--frobnicate")
        self.assertEqual(rc, 2)
        self.assertIn("unknown option", err)
        self.assertEqual(fr.calls(), [])

    def test_unsupported_distribution(self):
        fr = self.fake(distro="opensuse")
        before = fr.snapshot()
        rc, out, err = fr.run("--yes")
        self.assertEqual(rc, 2, out + err)
        self.assertIn("unsupported", err)
        self.assertEqual(fr.snapshot(), before)

    def test_missing_os_release(self):
        fr = self.fake()
        os.remove(fr.path("etc/os-release"))
        rc, out, err = fr.run("--yes")
        self.assertEqual(rc, 2)
        self.assertIn("os-release", err)

    def test_distribution_detection(self):
        for distro, expect in (("ubuntu", "apt"), ("debian", "apt"), ("fedora", "dnf"), ("rocky", "dnf")):
            with self.subTest(distro=distro):
                fr = self.fake(distro=distro)
                rc, out, err = fr.run("--dry-run")
                self.assertEqual(rc, 0, out + err)
                self.assertIn(f"[package manager: {expect}]", out)

    def test_confirmation_needs_a_terminal_or_yes(self):
        fr = self.fake()
        before = fr.snapshot()
        rc, out, err = fr.run()
        self.assertEqual(rc, 2, out + err)
        self.assertIn("--yes", err)
        self.assertEqual(fr.snapshot(), before)


class DryRunTests(TestCase):
    def test_dry_run_changes_nothing(self):
        for distro in ("ubuntu", "fedora"):
            with self.subTest(distro=distro):
                fr = self.fake(distro=distro)
                fr.write("home/alice/.ssh/authorized_keys", "ssh-ed25519 AAAA alice@laptop\n")
                before = fr.snapshot(skip=("calls.log", "tmp"))
                rc, out, err = fr.run("--dry-run")
                self.assertEqual(rc, 0, out + err)
                self.assertEqual(fr.snapshot(skip=("calls.log", "tmp")), before)
                self.assertEqual(os.listdir(fr.path("tmp")), [], "scratch files must be removed")
                self.assertFalse(fr.exists("var/log/epma-hardening.log"))
                self.assertFalse(fr.exists("var/lib/epma-hardening"))
                self.assertEqual([c for c in fr.calls() if MUTATING_CALLS.search(c)], [])
                self.assertIn("[CHANGE] (dry-run)", out)
                self.assertIn("Dry run: nothing was changed", out)
                self.assertSentinelEmpty(fr)

    def test_dry_run_flavours_change_nothing(self):
        for flags in (["--dry-run", "--chroot"], ["--dry-run", "--undo"], ["--dry-run", "--yes"]):
            with self.subTest(flags=flags):
                fr = self.fake()
                before = fr.snapshot(skip=("calls.log", "tmp"))
                rc, out, err = fr.run(*flags)
                self.assertEqual(rc, 0, out + err)
                self.assertEqual(fr.snapshot(skip=("calls.log", "tmp")), before)
                self.assertEqual([c for c in fr.calls() if MUTATING_CALLS.search(c)], [])

    def test_dry_run_after_real_run_reports_nothing_to_do(self):
        fr = self.fake()
        self.assertEqual(fr.run("--yes")[0], 0)
        rc, out, err = fr.run("--dry-run")
        self.assertEqual(rc, 0, out + err)
        self.assertNotIn("[CHANGE]", out)


class ApplyTests(TestCase):
    def apply(self, **kw):
        fr = self.fake(**kw)
        rc, out, err = fr.run("--yes", **kw.get("env", {}))
        return fr, rc, out, err

    def test_output_lines_and_summary(self):
        fr, rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        for tag in ("[OK]", "[SKIP]", "[CHANGE]"):
            self.assertIn(tag, out)
        self.assertRegex(out, r"Summary: \d+ ok, \d+ changed, \d+ skipped, \d+ warnings, 0 errors")
        self.assertIn("To go back: sudo bash harden-linux.sh --undo", out)
        log = fr.read("var/log/epma-hardening.log")
        self.assertIn("[CHANGE]", log)
        self.assertIn("harden-linux.sh start", log)
        self.assertSentinelEmpty(fr)
        self.assertEqual(os.listdir(fr.path("tmp")), [])

    def test_files_written(self):
        fr, rc, out, err = self.apply()
        self.assertEqual(rc, 0, out + err)
        sysctl = fr.read("etc/sysctl.d/99-epma-hardening.conf")
        for key in ("kernel.kptr_restrict = 2", "kernel.dmesg_restrict = 1", "kernel.randomize_va_space = 2",
                    "kernel.yama.ptrace_scope = 1", "net.ipv4.tcp_syncookies = 1", "fs.suid_dumpable = 0",
                    "fs.protected_symlinks = 1", "fs.protected_hardlinks = 1", "fs.protected_fifos = 1",
                    "fs.protected_regular = 1", "net.ipv4.conf.all.rp_filter = 2",
                    "net.ipv4.conf.all.accept_redirects = 0", "net.ipv6.conf.all.accept_redirects = 0",
                    "net.ipv4.conf.all.accept_source_route = 0"):
            self.assertIn(key, sysctl)
        for block in sysctl.split("\n\n")[1:]:
            lines = block.strip().splitlines()
            self.assertEqual(len(lines), 2, block)
            self.assertTrue(lines[0].startswith("# ") and " = " in lines[1], "every setting has its own comment: " + block)
        self.assertIn("* ", fr.read("etc/security/limits.d/99-epma-hardening.conf"))
        self.assertIn("Storage=none", fr.read("etc/systemd/coredump.conf.d/99-epma-hardening.conf"))
        self.assertIn("minlen = 12", fr.read("etc/security/pwquality.conf.d/99-epma-hardening.conf"))
        rules = fr.read("etc/audit/rules.d/99-epma-hardening.rules")
        self.assertIn("-w /etc/passwd -p wa -k identity", rules)
        self.assertNotIn("-e 2", rules)
        auto = fr.read("etc/apt/apt.conf.d/20auto-upgrades")
        self.assertIn('Unattended-Upgrade "1"', auto)
        self.assertIn("security", fr.read("etc/apt/apt.conf.d/52epma-hardening-unattended").lower())
        defs = fr.read("etc/login.defs")
        self.assertRegex(defs, r"(?m)^PASS_MAX_DAYS\t365$")
        self.assertRegex(defs, r"(?m)^PASS_WARN_AGE\t14$")
        self.assertRegex(defs, r"(?m)^HOME_MODE\t0750$")
        self.assertRegex(defs, r"(?m)^UMASK\t022$", "UMASK is left alone")
        self.assertRegex(defs, r"(?m)^PASS_MIN_DAYS\t0$")

    def test_backups_once(self):
        fr = self.fake()
        original_defs = fr.read("etc/login.defs")
        original_auto = fr.read("etc/apt/apt.conf.d/20auto-upgrades")
        self.assertEqual(fr.run("--yes")[0], 0)
        self.assertEqual(fr.read("etc/login.defs.epma-bak"), original_defs)
        self.assertEqual(fr.read("etc/apt/apt.conf.d/20auto-upgrades.epma-bak"), original_auto)
        # The script modifies a file again later: the first backup must survive.
        fr.write("etc/login.defs", fr.read("etc/login.defs").replace("365", "400"))
        self.assertEqual(fr.run("--yes")[0], 0)
        self.assertEqual(fr.read("etc/login.defs.epma-bak"), original_defs)
        self.assertIn("PASS_MAX_DAYS\t365", fr.read("etc/login.defs"))
        for created in ("etc/sysctl.d/99-epma-hardening.conf", "etc/modprobe.d/epma-hardening.conf"):
            self.assertFalse(fr.exists(created + ".epma-bak"), "no backup of a file the script created itself")

    def test_second_run_changes_nothing(self):
        for distro in ("ubuntu", "fedora"):
            with self.subTest(distro=distro):
                fr = self.fake(distro=distro)
                fr.write("home/alice/.ssh/authorized_keys", "ssh-ed25519 AAAA alice@laptop\n")
                rc, out, err = fr.run("--yes")
                self.assertEqual(rc, 0, out + err)
                first_calls = len(fr.calls())
                snap = fr.snapshot(skip=("calls.log", "tmp", "state", "var"))
                rc, out, err = fr.run("--yes")
                self.assertEqual(rc, 0, out + err)
                self.assertNotIn("[CHANGE]", out)
                self.assertEqual(fr.snapshot(skip=("calls.log", "tmp", "state", "var")), snap)
                self.assertEqual([c for c in fr.calls()[first_calls:] if MUTATING_CALLS.search(c)], [])
                self.assertRegex(out, r"Summary: \d+ ok, 0 changed")

    def test_permissions_are_tightened_and_restored(self):
        fr = self.fake()
        self.assertEqual(fr.run("--yes")[0], 0)
        self.assertEqual(os.stat(fr.path("etc/shadow")).st_mode & 0o777, 0o640)
        self.assertEqual(os.stat(fr.path("etc/group")).st_mode & 0o777, 0o644)
        self.assertEqual(os.stat(fr.path("etc/passwd")).st_mode & 0o777, 0o644)
        self.assertEqual(os.stat(fr.path("etc/gshadow")).st_mode & 0o777, 0o640)
        rc, out, err = fr.run("--undo", "--yes")
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(os.stat(fr.path("etc/shadow")).st_mode & 0o777, 0o644)
        self.assertEqual(os.stat(fr.path("etc/group")).st_mode & 0o777, 0o664)

    def test_fedora_style_shadow_is_not_loosened(self):
        fr = self.fake()
        os.chmod(fr.path("etc/shadow"), 0)
        self.assertEqual(fr.run("--yes")[0], 0)
        self.assertEqual(os.stat(fr.path("etc/shadow")).st_mode & 0o777, 0)

    def test_sysctl_only_lists_keys_the_kernel_has(self):
        fr = self.fake()
        os.remove(fr.path("proc/sys/kernel/yama/ptrace_scope"))
        rc, out, err = fr.run("--yes")
        self.assertEqual(rc, 0, out + err)
        self.assertNotIn("ptrace_scope", fr.read("etc/sysctl.d/99-epma-hardening.conf"))
        self.assertIn("left out: kernel.yama.ptrace_scope", out)
        self.assertIn("kernel.kptr_restrict", fr.read("etc/sysctl.d/99-epma-hardening.conf"))

    def test_sysctl_without_proc_keeps_the_required_keys(self):
        fr = self.fake(proc=False)
        shutil.rmtree(fr.path("proc"), True)
        self.assertEqual(fr.run("--yes")[0], 0)
        conf = fr.read("etc/sysctl.d/99-epma-hardening.conf")
        self.assertIn("kernel.kptr_restrict = 2", conf)
        self.assertNotIn("ptrace_scope", conf)
        self.assertNotIn("protected_regular", conf)

    def test_sysctl_loaded_only_when_the_file_changed(self):
        fr = self.fake()
        self.assertEqual(fr.run("--yes")[0], 0)
        self.assertEqual([c for c in fr.calls() if c.startswith("sysctl ")], ["sysctl --system"])

    def test_missing_optional_files_are_skipped(self):
        fr = self.fake(login_defs=False)
        os.remove(fr.path("etc/security/pwquality.conf"))
        rc, out, err = fr.run("--yes")
        self.assertEqual(rc, 0, out + err)
        self.assertIn("[SKIP]   /etc/login.defs not found", out)
        self.assertIn("[SKIP]   password quality", out)
        self.assertFalse(fr.exists("etc/login.defs"))

    def test_audit_rules_only_for_existing_paths(self):
        fr = self.fake()
        self.assertEqual(fr.run("--yes")[0], 0)
        rules = fr.read("etc/audit/rules.d/99-epma-hardening.rules")
        self.assertNotIn("/etc/sudoers", rules)  # not present in the fake root
        fr2 = self.fake()
        fr2.write("etc/sudoers", "root ALL=(ALL) ALL\n")
        self.assertEqual(fr2.run("--yes")[0], 0)
        self.assertIn("-w /etc/sudoers -p wa -k sudoers", fr2.read("etc/audit/rules.d/99-epma-hardening.rules"))


class UndoTests(TestCase):
    def test_undo_restores_everything(self):
        for distro in ("ubuntu", "fedora"):
            with self.subTest(distro=distro):
                fr = self.fake(distro=distro)
                fr.write("etc/dnf/automatic.conf", "# original dnf-automatic\n")
                before = fr.snapshot(dirs=False)
                self.assertEqual(fr.run("--yes")[0], 0)
                self.assertNotEqual(fr.snapshot(dirs=False), before)
                rc, out, err = fr.run("--undo", "--yes")
                self.assertEqual(rc, 0, out + err)
                after = fr.snapshot(dirs=False, ignore=("var/log/epma-hardening.log",))
                self.assertEqual(after, before)
                self.assertFalse(fr.exists("var/lib/epma-hardening"))
                self.assertIn("restored from", out)
                self.assertIn("removed (created by this script)", out)
                self.assertSentinelEmpty(fr)

    def test_undo_without_a_previous_run(self):
        fr = self.fake()
        rc, out, err = fr.run("--undo", "--yes")
        self.assertEqual(rc, 0, out + err)
        self.assertIn("nothing to undo", out)

    def test_undo_dry_run_lists_but_does_nothing(self):
        fr = self.fake()
        self.assertEqual(fr.run("--yes")[0], 0)
        before = fr.snapshot(skip=("calls.log", "tmp"))
        rc, out, err = fr.run("--undo", "--dry-run")
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(fr.snapshot(skip=("calls.log", "tmp")), before)
        self.assertIn("would be removed", out)
        self.assertIn("would be restored", out)

    def test_undo_ignores_paths_outside_the_expected_places(self):
        fr = self.fake()
        self.assertEqual(fr.run("--yes")[0], 0)
        victim = os.path.join(fr.base, "victim.txt")
        with open(victim, "w") as fh:
            fh.write("keep me")
        with open(fr.path("var/lib/epma-hardening/created.list"), "a") as fh:
            fh.write(victim + "\n")
            fh.write(fr.root + "/etc/../../victim.txt\n")
        rc, out, err = fr.run("--undo", "--yes")
        self.assertEqual(rc, 0, out + err)
        self.assertTrue(os.path.exists(victim))
        self.assertIn("unexpected path", out)


class SshTests(TestCase):
    DROPIN = "etc/ssh/sshd_config.d/99-epma-hardening.conf"

    def test_dropin_contents_without_keys(self):
        fr = self.fake()
        rc, out, err = fr.run("--yes")
        self.assertEqual(rc, 0, out + err)
        conf = fr.read(self.DROPIN)
        for line in ("PermitRootLogin no", "X11Forwarding no", "MaxAuthTries 4", "LoginGraceTime 30",
                     "PermitEmptyPasswords no", "ClientAliveInterval 300"):
            self.assertIn("\n" + line + "\n", conf)
        self.assertNotIn("PasswordAuthentication", conf)
        self.assertIn(["sshd -t"], [[c] for c in fr.calls() if c == "sshd -t"])

    def test_password_authentication_untouched_without_keys(self):
        for content in (None, "", "\n   \n", "# a comment only\n"):
            with self.subTest(content=content):
                fr = self.fake()
                if content is not None:
                    fr.write("home/alice/.ssh/authorized_keys", content)
                self.assertEqual(fr.run("--yes")[0], 0)
                self.assertNotIn("PasswordAuthentication", fr.read(self.DROPIN))

    def test_password_authentication_off_when_a_key_exists(self):
        for where in ("home/alice/.ssh/authorized_keys", "root/.ssh/authorized_keys"):
            with self.subTest(where=where):
                fr = self.fake()
                fr.write(where, "# comment\nssh-ed25519 AAAAC3Nza alice@laptop\n")
                rc, out, err = fr.run("--yes")
                self.assertEqual(rc, 0, out + err)
                self.assertIn("\nPasswordAuthentication no\n", fr.read(self.DROPIN))
                self.assertIn("SSH PASSWORD LOGIN IS NOW OFF", out)
                self.assertIn("Please read:", out)

    def test_never_cuts_off_the_ssh_user_who_has_no_key(self):
        fr = self.fake()
        fr.write("root/.ssh/authorized_keys", "ssh-ed25519 AAAA root@x\n")
        rc, out, err = fr.run("--yes", SSH_CONNECTION="10.0.0.2 50000 10.0.0.9 22", SUDO_USER="alice")
        self.assertEqual(rc, 0, out + err)
        self.assertNotIn("PasswordAuthentication", fr.read(self.DROPIN))
        self.assertIn("password login left as it is", out)

    def test_keys_for_the_ssh_user_allow_it(self):
        fr = self.fake()
        fr.write("home/alice/.ssh/authorized_keys", "ssh-ed25519 AAAA alice@x\n")
        rc, out, err = fr.run("--yes", SSH_CONNECTION="10.0.0.2 50000 10.0.0.9 22", SUDO_USER="alice")
        self.assertEqual(rc, 0, out + err)
        self.assertIn("PasswordAuthentication no", fr.read(self.DROPIN))

    def test_revert_when_sshd_t_fails(self):
        fr = self.fake()
        fr.state("sshd_t_fail")
        rc, out, err = fr.run("--yes")
        self.assertEqual(rc, 1, out + err)
        self.assertFalse(fr.exists(self.DROPIN))
        self.assertIn("sshd -t rejected", out)
        self.assertIn("reverted", out)
        self.assertNotIn("systemctl reload", "\n".join(fr.calls()))
        created = fr.read("var/lib/epma-hardening/created.list")
        self.assertNotIn("sshd_config.d", created)

    def test_revert_inside_a_chroot_is_not_an_error_exit(self):
        fr = self.fake()
        fr.state("sshd_t_fail")
        rc, out, err = fr.run("--chroot", "--yes")
        self.assertEqual(rc, 0, out + err)
        self.assertFalse(fr.exists(self.DROPIN))
        self.assertIn("reverted", out)

    def test_revert_restores_the_previous_dropin(self):
        fr = self.fake()
        old = "# an older version\nX11Forwarding no\n"
        fr.write(self.DROPIN, old)
        fr.state("sshd_t_fail")
        rc, out, err = fr.run("--yes")
        self.assertEqual(rc, 1, out + err)
        self.assertEqual(fr.read(self.DROPIN), old)

    def test_reload_only_when_changed_and_running(self):
        fr = self.fake()
        fr.state("active_ssh")
        self.assertEqual(fr.run("--yes")[0], 0)
        self.assertEqual([c for c in fr.calls() if c.startswith("systemctl reload")], ["systemctl reload ssh"])
        n = len(fr.calls())
        self.assertEqual(fr.run("--yes")[0], 0)
        self.assertEqual([c for c in fr.calls()[n:] if c.startswith("systemctl reload")], [])

    def test_sshd_not_installed(self):
        fr = self.fake(sshd=False)
        rc, out, err = fr.run("--yes")
        self.assertEqual(rc, 0, out + err)
        self.assertFalse(fr.exists("etc/ssh"))
        self.assertIn("[SKIP]   SSH: the SSH server is not installed", out)

    def test_main_config_without_include_is_left_alone(self):
        fr = self.fake()
        fr.write("etc/ssh/sshd_config", "Port 22\nPermitRootLogin yes\n")
        rc, out, err = fr.run("--yes")
        self.assertEqual(rc, 0, out + err)
        self.assertFalse(fr.exists(self.DROPIN))
        self.assertEqual(fr.read("etc/ssh/sshd_config"), "Port 22\nPermitRootLogin yes\n")
        self.assertIn("does not include sshd_config.d", out)

    def test_root_login_stays_possible_when_there_is_no_normal_user(self):
        fr = self.fake(regular_user=False)
        rc, out, err = fr.run("--yes")
        self.assertEqual(rc, 0, out + err)
        self.assertIn("PermitRootLogin prohibit-password", fr.read(self.DROPIN))
        self.assertNotIn("PermitRootLogin no\n", fr.read(self.DROPIN))

    def test_warns_when_an_earlier_file_overrides_ours(self):
        fr = self.fake()
        fr.write("state/sshd_T", "port 22\npermitrootlogin yes\nx11forwarding no\nmaxauthtries 4\n")
        rc, out, err = fr.run("--yes")
        self.assertEqual(rc, 0, out + err)
        self.assertIn("permitrootlogin is yes, not no", out)


class FirewallTests(TestCase):
    def test_ufw_order_and_ssh_port(self):
        fr = self.fake()
        fr.state("active_ssh")
        rc, out, err = fr.run("--yes")
        self.assertEqual(rc, 0, out + err)
        calls = fr.calls()
        wanted = ["ufw default deny incoming", "ufw default allow outgoing", "ufw allow 22/tcp", "ufw --force enable"]
        idx = [calls.index(w) for w in wanted]
        self.assertEqual(idx, sorted(idx))
        self.assertTrue(fr.exists("state/ufw_active"))
        self.assertIn("apt-get install -y --no-install-recommends ufw", calls)

    def test_ufw_without_ssh_opens_nothing(self):
        fr = self.fake()
        rc, out, err = fr.run("--yes")
        self.assertEqual(rc, 0, out + err)
        self.assertEqual([c for c in fr.calls() if c.startswith("ufw allow")], [])
        self.assertIn("ufw default deny incoming", fr.calls())

    def test_active_ssh_session_port_is_always_allowed(self):
        fr = self.fake()
        rc, out, err = fr.run("--yes", SSH_CONNECTION="10.0.0.2 50000 10.0.0.9 2222")
        self.assertEqual(rc, 0, out + err)
        allows = [c for c in fr.calls() if c.startswith("ufw allow")]
        self.assertIn("ufw allow 2222/tcp", allows)
        self.assertIn("ufw allow 22/tcp", allows)
        calls = fr.calls()
        self.assertLess(calls.index("ufw allow 2222/tcp"), calls.index("ufw --force enable"))

    def test_garbage_ssh_connection_port_is_ignored(self):
        fr = self.fake()
        rc, out, err = fr.run("--yes", SSH_CONNECTION="a b c ;reboot")
        self.assertEqual(rc, 0, out + err)
        self.assertEqual([c for c in fr.calls() if c.startswith("ufw allow")], ["ufw allow 22/tcp"])

    def test_existing_active_ufw_is_left_alone(self):
        fr = self.fake()
        fr.state("pkg_ufw", "ufw_active")
        rc, out, err = fr.run("--yes")
        self.assertEqual(rc, 0, out + err)
        self.assertEqual([c for c in fr.calls() if c.startswith("ufw ") and not c.startswith("ufw status")], [])
        self.assertIn("ufw is already active", out)

    def test_ufw_failure_does_not_enable_the_firewall(self):
        fr = self.fake()
        fr.state("active_ssh")
        stub = fr.read("stubs/ufw").replace('--force) touch "$S/ufw_active" ;;', '--force) touch "$S/ufw_active" ;;\n    allow) exit 1 ;;')
        fr.write("stubs/ufw", stub, 0o755)
        rc, out, err = fr.run("--yes")
        self.assertEqual(rc, 1, out + err)
        self.assertNotIn("ufw --force enable", fr.calls())
        self.assertIn("NOT being enabled", out)

    def test_firewalld_on_fedora(self):
        fr = self.fake(distro="fedora")
        fr.state("active_sshd")
        rc, out, err = fr.run("--yes")
        self.assertEqual(rc, 0, out + err)
        calls = fr.calls()
        self.assertIn("dnf -y install firewalld", calls)
        self.assertIn("systemctl enable --now firewalld", calls)
        self.assertTrue(any(c.startswith("firewall-cmd --permanent --zone=public --add-service=ssh") for c in calls))
        self.assertFalse(any(c.startswith("firewall-cmd") and "set-default-zone" in c for c in calls), "the default zone is not touched")
        self.assertFalse(any(c.startswith("ufw") for c in calls))

    def test_firewalld_already_running_is_left_alone(self):
        fr = self.fake(distro="fedora")
        fr.state("pkg_firewalld", "enabled_firewalld", "active_firewalld")
        rc, out, err = fr.run("--yes")
        self.assertEqual(rc, 0, out + err)
        self.assertFalse(any(c.startswith("firewall-cmd --") and "--add" in c for c in fr.calls()))
        self.assertIn("its zones are left as they are", out)


class ServicesAndReportsTests(TestCase):
    def test_apt_packages_and_services(self):
        fr = self.fake()
        rc, out, err = fr.run("--yes")
        self.assertEqual(rc, 0, out + err)
        calls = fr.calls()
        for pkg in ("ufw", "unattended-upgrades", "auditd"):
            self.assertIn("apt-get install -y --no-install-recommends " + pkg, calls)
        self.assertIn("systemctl enable --now auditd", calls)
        self.assertIn("augenrules --load", calls)
        self.assertFalse(any("dnf" in c for c in calls))

    def test_dnf_packages_and_automatic_updates(self):
        fr = self.fake(distro="fedora")
        rc, out, err = fr.run("--yes")
        self.assertEqual(rc, 0, out + err)
        calls = fr.calls()
        for pkg in ("dnf-automatic", "audit", "firewalld"):
            self.assertIn("dnf -y install " + pkg, calls)
        self.assertIn("systemctl enable --now dnf-automatic-install.timer", calls)
        conf = fr.read("etc/dnf/automatic.conf")
        self.assertIn("upgrade_type = security", conf)
        self.assertIn("apply_updates = yes", conf)
        self.assertFalse(any(c.startswith("apt-get") for c in calls))

    def test_dnf5_uses_its_own_package_and_timer(self):
        fr = self.fake(distro="fedora")
        fr.state("pkg_dnf5")
        rc, out, err = fr.run("--yes")
        self.assertEqual(rc, 0, out + err)
        self.assertIn("dnf -y install dnf5-plugin-automatic", fr.calls())
        self.assertIn("systemctl enable --now dnf-automatic-install.timer", fr.calls())  # what the stub lists
        self.assertNotIn("dnf -y install dnf-automatic", fr.calls())

    def test_selinux_and_apparmor_are_only_reported(self):
        fr = self.fake(distro="fedora")
        fr.write("stubs/getenforce", "#!/bin/sh\necho Permissive\n", 0o755)
        rc, out, err = fr.run("--yes")
        self.assertEqual(rc, 0, out + err)
        self.assertIn("SELinux is not enforcing", out)
        self.assertIn("[SKIP]   AppArmor", out)
        self.assertEqual([c for c in fr.calls() if "setenforce" in c], [])
        self.assertEqual(fr.read("etc/selinux/config"), "SELINUX=enforcing\n")
        fr2 = self.fake()
        fr2.write("sys/module/apparmor/parameters/enabled", "N\n")
        rc, out, err = fr2.run("--yes")
        self.assertEqual(rc, 0, out + err)
        self.assertIn("AppArmor is built in but NOT enabled", out)
        self.assertIn("[SKIP]   SELinux", out)

    def test_package_failure_is_an_error_exit_but_the_rest_still_runs(self):
        fr = self.fake()
        fr.write("stubs/apt-get", "#!/bin/sh\necho \"apt-get $*\" >> \"$EPMA_HARDEN_TEST_ROOT/calls.log\"\nexit 100\n", 0o755)
        rc, out, err = fr.run("--yes")
        self.assertEqual(rc, 1, out + err)
        self.assertIn("FAILED: install package ufw", out)
        self.assertTrue(fr.exists("etc/sysctl.d/99-epma-hardening.conf"))
        self.assertFalse(fr.exists("state/ufw_active"))


class ChrootTests(TestCase):
    UNIT = "etc/systemd/system/epma-hardening-firstboot.service"
    WANTS = "etc/systemd/system/multi-user.target.wants/epma-hardening-firstboot.service"
    COPY = "usr/local/sbin/epma-harden-linux.sh"

    def test_chroot_writes_files_only(self):
        fr = self.fake()
        rc, out, err = fr.run("--chroot", "--yes")
        self.assertEqual(rc, 0, out + err)
        self.assertEqual([c for c in fr.calls() if MUTATING_CALLS.search(c)], [])
        self.assertFalse(any(c.startswith(("ufw", "augenrules")) for c in fr.calls()))
        for rel in ("etc/sysctl.d/99-epma-hardening.conf", "etc/modprobe.d/epma-hardening.conf",
                    "etc/ssh/sshd_config.d/99-epma-hardening.conf", "etc/security/limits.d/99-epma-hardening.conf"):
            self.assertTrue(fr.exists(rel), rel)
        self.assertIn("left to the first boot", out)
        self.assertIn("first boot", out)
        self.assertFalse(fr.exists("state/ufw_active"))

    def test_first_boot_service_files(self):
        fr = self.fake()
        self.assertEqual(fr.run("--chroot", "--yes")[0], 0)
        unit = fr.read(self.UNIT)
        self.assertIn("Type=oneshot", unit)
        self.assertIn("ExecStart=/usr/local/sbin/epma-harden-linux.sh --yes", unit)
        self.assertIn("ConditionPathExists=/var/lib/epma-hardening/firstboot.pending", unit)
        self.assertIn("WantedBy=multi-user.target", unit)
        self.assertTrue(os.path.islink(fr.path(self.WANTS)))
        self.assertEqual(os.readlink(fr.path(self.WANTS)), "../epma-hardening-firstboot.service")
        self.assertTrue(fr.exists("var/lib/epma-hardening/firstboot.pending"))
        self.assertTrue(os.access(fr.path(self.COPY), os.X_OK))
        # run from a file: the copy is the script itself
        self.assertEqual(fr.read(self.COPY), fr.script)

    def test_works_through_bash_dash_s(self):
        fr = self.fake()
        rc, out, err = fr.run("--chroot", "--yes", stdin_script=True)
        self.assertEqual(rc, 0, out + err)
        self.assertTrue(fr.exists(self.UNIT))
        copy = fr.path(self.COPY)
        self.assertTrue(os.path.exists(copy))
        self.assertEqual(subprocess.run([BASH, "-n", copy], capture_output=True).returncode, 0)
        p = subprocess.run([BASH, copy, "--help"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("--chroot", p.stdout)
        # the rebuilt copy behaves like the original: same dry-run report
        a = fr.run("--dry-run")
        os.replace(fr.path(self.COPY), fr.script_path + ".copy")
        p = subprocess.run([BASH, fr.script_path + ".copy", "--dry-run"], capture_output=True, text=True, env=fr.env(),
                           cwd=fr.scripts, start_new_session=True)
        self.assertEqual(p.returncode, a[0], p.stderr)
        self.assertEqual(p.stdout, a[1])

    def test_each_option_works_through_bash_dash_s(self):
        fr = self.fake()
        for flags in (["--dry-run"], ["--yes"], ["--undo", "--yes"], ["--help"]):
            with self.subTest(flags=flags):
                rc, out, err = fr.run(*flags, stdin_script=True)
                self.assertEqual(rc, 0, out + err)
        self.assertSentinelEmpty(fr)

    def test_chroot_run_is_idempotent(self):
        fr = self.fake()
        self.assertEqual(fr.run("--chroot", "--yes")[0], 0)
        snap = fr.snapshot(skip=("calls.log", "tmp", "state", "var"))
        rc, out, err = fr.run("--chroot", "--yes")
        self.assertEqual(rc, 0, out + err)
        self.assertNotIn("[CHANGE]", out)
        self.assertEqual(fr.snapshot(skip=("calls.log", "tmp", "state", "var")), snap)

    def test_first_boot_run_finishes_and_switches_the_service_off(self):
        fr = self.fake()
        self.assertEqual(fr.run("--chroot", "--yes")[0], 0)
        fr.state("enabled_epma-hardening-firstboot.service")
        rc, out, err = fr.run("--yes")
        self.assertEqual(rc, 0, out + err)
        self.assertFalse(fr.exists("var/lib/epma-hardening/firstboot.pending"))
        self.assertFalse(fr.exists(self.WANTS))
        self.assertIn("systemctl disable epma-hardening-firstboot.service", fr.calls())
        self.assertIn("auditd", " ".join(fr.calls()))
        self.assertIn("first-boot service switched off", out)

    def test_first_boot_run_stays_on_after_an_error(self):
        fr = self.fake()
        self.assertEqual(fr.run("--chroot", "--yes")[0], 0)
        fr.write("stubs/apt-get", "#!/bin/sh\nexit 100\n", 0o755)
        rc, out, err = fr.run("--yes")
        self.assertEqual(rc, 1, out + err)
        self.assertTrue(fr.exists("var/lib/epma-hardening/firstboot.pending"))
        self.assertTrue(os.path.islink(fr.path(self.WANTS)))

    def test_undo_removes_the_first_boot_service(self):
        fr = self.fake()
        self.assertEqual(fr.run("--chroot", "--yes")[0], 0)
        self.assertEqual(fr.run("--undo", "--yes")[0], 0)
        for rel in (self.UNIT, self.COPY, "var/lib/epma-hardening"):
            self.assertFalse(fr.exists(rel), rel)
        self.assertFalse(os.path.lexists(fr.path(self.WANTS)))


if __name__ == "__main__":
    unittest.main()
