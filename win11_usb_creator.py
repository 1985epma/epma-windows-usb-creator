#!/usr/bin/env python3
#
# EPMA Windows 11 Creator USB
# Copyright (C) 2026 EPMA
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
Cross-platform (macOS + any Linux distro) GUI to download the official
Windows 11 ISO and write a bootable USB drive (UEFI, GPT + FAT32).

macOS requirements:
  brew install python-tk@3.14 wimlib

Linux requirements (package names vary by distro; the app can install them
for you via apt/dnf/yum/pacman/zypper/apk):
  parted, dosfstools (mkfs.vfat), util-linux (wipefs/mount/umount/lsblk),
  rsync, wimlib (wimlib-imagex) and python3-tk for the GUI itself.

wimlib-imagex is required because the Windows 11 install.wim/install.esd
usually exceeds 4 GB, the FAT32 file size limit — the script splits the
file automatically when that happens.

On Linux, partitioning/formatting/mounting a raw block device requires
root, so the app will ask for your sudo password (or use pkexec if sudo
isn't available) once per operation. The password is only used locally to
run disk commands and is never stored to disk or sent anywhere.
"""

import hashlib
import json
import logging
import os
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import webbrowser

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, simpledialog
except ImportError:
    _msg = "Tkinter is not available for this Python installation.\n"
    if platform.system() == "Darwin":
        _msg += "Install it with: brew install python-tk@<version matching your python>"
    else:
        _msg += (
            "Install it with your package manager, e.g.:\n"
            "  Debian/Ubuntu: sudo apt install python3-tk\n"
            "  Fedora:        sudo dnf install python3-tkinter\n"
            "  Arch:          sudo pacman -S tk\n"
            "  openSUSE:      sudo zypper install python3-tk"
        )
    print(_msg)
    sys.exit(1)

IS_MAC = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"

MS_DOWNLOAD_PAGE = "https://www.microsoft.com/en-us/software-download/windows11"
FAT32_MAX_FILE_SIZE = 4_294_967_295  # 4GB - 1 byte
CHUNK_SIZE = 1024 * 1024
VOL_NAME = "WIN11USB"

# What kind of image is being written.
#   windows: format GPT + FAT32 and copy the ISO contents (splitting install.wim)
#   linux:   write the ISO byte-for-byte to the drive (hybrid ISO, like `dd`)
MODE_WINDOWS = "windows"
MODE_LINUX = "linux"
RAW_WRITE_BLOCK = {"mac": "4m", "linux": "4M"}  # BSD dd and GNU dd spell the unit differently

LINUX_REQUIRED_TOOLS = ["parted", "mkfs.vfat", "wipefs", "partprobe", "rsync", "wimlib-imagex"]
LINUX_PKG_MAP = {
    "apt-get": {"parted": "parted", "mkfs.vfat": "dosfstools", "wipefs": "util-linux",
                "partprobe": "parted", "rsync": "rsync", "wimlib-imagex": "wimtools"},
    "dnf":     {"parted": "parted", "mkfs.vfat": "dosfstools", "wipefs": "util-linux",
                "partprobe": "parted", "rsync": "rsync", "wimlib-imagex": "wimlib-utils"},
    "yum":     {"parted": "parted", "mkfs.vfat": "dosfstools", "wipefs": "util-linux",
                "partprobe": "parted", "rsync": "rsync", "wimlib-imagex": "wimlib-utils"},
    "pacman":  {"parted": "parted", "mkfs.vfat": "dosfstools", "wipefs": "util-linux",
                "partprobe": "parted", "rsync": "rsync", "wimlib-imagex": "wimlib"},
    "zypper":  {"parted": "parted", "mkfs.vfat": "dosfstools", "wipefs": "util-linux",
                "partprobe": "parted", "rsync": "rsync", "wimlib-imagex": "wimlib"},
    "apk":     {"parted": "parted", "mkfs.vfat": "dosfstools", "wipefs": "util-linux-misc",
                "partprobe": "parted", "rsync": "rsync", "wimlib-imagex": "wimlib"},
}
LINUX_INSTALL_CMD_TEMPLATE = {
    "apt-get": "apt-get update && apt-get install -y {pkgs}",
    "dnf": "dnf install -y {pkgs}",
    "yum": "yum install -y {pkgs}",
    # -Syu (not -Sy): a partial upgrade is explicitly unsupported on Arch and can
    # leave the user's system in a broken state.
    "pacman": "pacman -Syu --noconfirm {pkgs}",
    "zypper": "zypper --non-interactive install {pkgs}",
    "apk": "apk add {pkgs}",
}

# ---- Security configuration (overridable via environment variables) ----
# Download URLs must use HTTPS and, unless the user opts out, come from a
# Microsoft-controlled host. See SECURITY.md.
ALLOWED_URL_SCHEMES = ("https",)
DEFAULT_TRUSTED_ISO_HOSTS = (
    "microsoft.com",
    "www.microsoft.com",
    "software-download.microsoft.com",
    "software.download.prss.microsoft.com",
    "download.microsoft.com",
)
ENV_TRUSTED_HOSTS = "WIN11USB_TRUSTED_ISO_HOSTS"
ENV_AUDIT_LOG = "WIN11USB_AUDIT_LOG"
ENV_DISABLE_AUDIT_LOG = "WIN11USB_DISABLE_AUDIT_LOG"
ENV_ALLOW_ANY_HOST = "WIN11USB_ALLOW_ANY_DOWNLOAD_HOST"
ENV_EXPECTED_SHA256 = "WIN11USB_EXPECTED_SHA256"

DOWNLOAD_TIMEOUT_SECONDS = 60  # per network read; prevents an indefinite hang
PRIVATE_FILE_MODE = 0o600      # owner-only read/write for files we create

# Device identifiers we are willing to pass to privileged commands. Anything
# outside this shape is rejected rather than escaped: there is no legitimate
# disk name with spaces, quotes or shell metacharacters.
MAC_DEVICE_RE = re.compile(r"^disk[0-9]+$")
LINUX_DEVICE_RE = re.compile(r"^[a-zA-Z0-9_+-]{1,32}$")

# Mount points that must never live on a disk we are about to erase.
CRITICAL_MOUNTPOINTS = ("/", "/boot", "/boot/efi", "/home", "/usr", "/var", "/etc")

_audit_logger = None


def human_size(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


# ============================================================
# Audit trail
#
# Destructive, privileged operations should leave a record. The log is written
# with owner-only permissions and deliberately never receives passwords: the
# sudo password is passed on stdin and never appears in an argument list or in
# any string handed to audit()/log().
# ============================================================
def audit_log_path():
    override = os.environ.get(ENV_AUDIT_LOG)
    if override:
        return os.path.expanduser(override)
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return os.path.join(base, "epma-win11-usb-creator", "audit.log")


def get_audit_logger():
    """Lazily create the audit logger. Never raises: logging must not break the app."""
    global _audit_logger
    if _audit_logger is not None:
        return _audit_logger
    logger = logging.getLogger("epma.win11usb.audit")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if os.environ.get(ENV_DISABLE_AUDIT_LOG, "").strip().lower() in ("1", "true", "yes"):
        logger.addHandler(logging.NullHandler())
        _audit_logger = logger
        return logger
    try:
        path = audit_log_path()
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        # Create with restrictive permissions before the handler opens it.
        if not os.path.exists(path):
            os.close(os.open(path, os.O_CREAT | os.O_WRONLY, PRIVATE_FILE_MODE))
        else:
            os.chmod(path, PRIVATE_FILE_MODE)
        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
    except Exception:
        # A read-only or unwritable home must not stop the user from making a USB.
        logger.addHandler(logging.NullHandler())
    _audit_logger = logger
    return logger


def audit(msg, level=logging.INFO):
    """Record a security-relevant event. Callers must not pass secrets or personal data."""
    try:
        get_audit_logger().log(level, msg)
    except Exception:  # noqa: S110 - deliberate: logging must never break the app
        pass


# ============================================================
# Input validation
# ============================================================
def validate_device_name(dev):
    """Return dev if it is a plausible disk identifier, else raise.

    Rejecting is safer than escaping: this value reaches privileged commands.
    """
    if not isinstance(dev, str) or not dev:
        raise ValueError("No disk was selected.")
    pattern = MAC_DEVICE_RE if IS_MAC else LINUX_DEVICE_RE
    if not pattern.match(dev):
        audit(f"REJECTED invalid device identifier: {dev!r}", logging.WARNING)
        raise ValueError(
            f"Refusing to operate on {dev!r}: it is not a valid disk identifier. "
            "Expected something like 'disk4' (macOS) or 'sdb' (Linux)."
        )
    return dev


def validate_iso_path(path):
    """Return an absolute, existing, regular-file ISO path, or raise."""
    if not path:
        raise ValueError("No ISO file has been selected yet.")
    resolved = os.path.realpath(os.path.expanduser(path))
    if not os.path.exists(resolved):
        raise ValueError(f"The selected ISO file no longer exists: {resolved}")
    if not os.path.isfile(resolved):
        raise ValueError(f"The selected ISO path is not a regular file: {resolved}")
    if not os.access(resolved, os.R_OK):
        raise ValueError(f"The selected ISO file cannot be read: {resolved}")
    if os.path.getsize(resolved) < 1024 * 1024:
        raise ValueError(
            "The selected file is too small to be a Windows 11 ISO "
            f"({human_size(os.path.getsize(resolved))}). It may be an incomplete download."
        )
    return resolved


def validate_hybrid_iso(path):
    """Raise unless `path` carries an MBR boot signature (isohybrid).

    Writing a non-hybrid ISO byte-for-byte produces a drive that will not boot, so
    refuse up front instead of erasing the drive for nothing. Windows ISOs are not
    hybrid; they must use the Windows mode.
    """
    with open(path, "rb") as fh:
        head = fh.read(512)
    if len(head) < 512 or head[510:512] != b"\x55\xaa":
        raise ValueError(
            "This ISO is not a bootable hybrid image, so it cannot be written directly to a USB drive.\n\n"
            "If this is a Windows ISO, choose 'Windows 11' as the image type. Otherwise use an "
            "ISO that is provided as a hybrid/USB-ready image (all current Ubuntu, Debian, Fedora, "
            "Mint and Arch ISOs are)."
        )


def make_progress_log(log, interval=5.0):
    """Wrap `log` so dd's frequent progress lines are shown at most every `interval` seconds."""
    last = [0.0]

    def wrapped(line):
        if re.search(r"\d+ bytes", line):
            now = time.time()
            if now - last[0] < interval:
                return
            last[0] = now
        log(line)

    return wrapped


def make_dd_log(log, total, progress):
    """Log wrapper that turns dd's "N bytes ..." lines into progress updates.

    GNU dd (status=progress) and BSD dd (SIGINFO) both print the running byte count
    as "<N> bytes ...", so one pattern covers both.
    """
    throttled = make_progress_log(log)

    def wrapped(line):
        m = re.search(r"(\d+) bytes", line)
        if m and total and progress:
            progress(min(int(m.group(1)), total), total, "Writing the image...")
        throttled(line)

    return wrapped


def copy_file_with_progress(src, dst_dir, on_bytes):
    """Copy `src` into `dst_dir` in chunks, reporting the bytes copied so far."""
    dst = os.path.join(dst_dir, os.path.basename(src))
    copied = 0
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            fout.write(chunk)
            copied += len(chunk)
            on_bytes(copied)
    shutil.copystat(src, dst)


def copy_windows_payload(src_root, dst_root, log, progress, wimlib_hint):
    """Copy the contents of a mounted Windows ISO to the drive, reporting progress.

    Everything except sources/install.wim|esd is copied with rsync; that file is
    copied directly, or split into <4 GB parts when it exceeds the FAT32 limit.
    Progress is counted in bytes over the whole payload.
    """
    sources_dir = os.path.join(src_root, "sources")
    big_file = None
    for name in ("install.wim", "install.esd"):
        p = os.path.join(sources_dir, name)
        if os.path.exists(p):
            big_file = p
            break
    if not big_file:
        raise RuntimeError("Could not find sources/install.wim or sources/install.esd on the ISO.")

    rest_total = 0
    for root, _dirs, files in os.walk(src_root):
        for fname in files:
            path = os.path.join(root, fname)
            if path != big_file:
                try:
                    rest_total += os.path.getsize(path)
                except OSError:
                    pass
    size = os.path.getsize(big_file)
    total = rest_total + size
    state = {"done": 0}

    def report(done, text):
        if progress:
            progress(min(done, total), total, text)

    def rsync_log(line):
        log(line)
        name = line.strip()
        if not name or name.endswith("/"):
            return
        path = os.path.join(src_root, name)
        if os.path.isfile(path):  # header/summary lines never resolve to a file
            state["done"] += os.path.getsize(path)
            report(min(state["done"], rest_total), "Copying files...")

    rel_big = os.path.relpath(big_file, src_root)
    log("Copying files from the ISO to the USB drive (this can take several minutes)...")
    run_cmd(["rsync", "-rv", f"--exclude={rel_big}", src_root + "/", dst_root + "/"], rsync_log)
    report(rest_total, "Copying files...")

    target_sources = os.path.join(dst_root, "sources")
    os.makedirs(target_sources, exist_ok=True)

    if size > FAT32_MAX_FILE_SIZE:
        log(f"{os.path.basename(big_file)} is {human_size(size)} (over 4GB). Splitting with wimlib-imagex...")
        if not shutil.which("wimlib-imagex"):
            raise RuntimeError(wimlib_hint)
        out_swm = os.path.join(target_sources, os.path.splitext(os.path.basename(big_file))[0] + ".swm")

        def split_log(line):
            log(line)
            m = re.search(r"(\d{1,3})%", line)
            if m:
                report(rest_total + size * min(int(m.group(1)), 100) // 100, "Splitting the install image...")

        run_cmd(["wimlib-imagex", "split", big_file, out_swm, "3800"], split_log)
    else:
        log(f"Copying {os.path.basename(big_file)} ({human_size(size)})...")
        copy_file_with_progress(
            big_file, target_sources,
            lambda n: report(rest_total + n, "Copying the install image..."))

    report(total, "Flushing data to the drive...")
    log("Syncing writes to disk...")
    run_cmd(["sync"], log, check=False)


def validate_download_url(raw_url):
    """Return a normalised URL, or raise ValueError explaining why it was rejected."""
    url = (raw_url or "").strip()
    if not url:
        raise ValueError("Paste the direct ISO link before downloading.")
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        # 'from None': the parser's internal message would only confuse the user.
        raise ValueError("That does not look like a valid link.") from None
    if parsed.scheme.lower() not in ALLOWED_URL_SCHEMES:
        raise ValueError(
            f"Only {'/'.join(s.upper() for s in ALLOWED_URL_SCHEMES)} links are accepted "
            f"(this one starts with '{parsed.scheme or '?'}://').\n\n"
            "An unencrypted link can be modified in transit, which would let someone "
            "replace the Windows image with a tampered one."
        )
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("The link has no server address.")
    if os.environ.get(ENV_ALLOW_ANY_HOST, "").strip().lower() in ("1", "true", "yes"):
        return url, host, False
    trusted = os.environ.get(ENV_TRUSTED_HOSTS)
    trusted_hosts = tuple(h.strip().lower() for h in trusted.split(",") if h.strip()) if trusted \
        else DEFAULT_TRUSTED_ISO_HOSTS
    is_trusted = any(host == t or host.endswith("." + t) for t in trusted_hosts)
    return url, host, not is_trusted


def run_cmd(args, log, check=True):
    log(f"$ {' '.join(args)}")
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    for line in proc.stdout:
        log(line.rstrip())
    proc.wait()
    if check and proc.returncode != 0:
        raise RuntimeError(f"Command failed (exit code {proc.returncode}): {' '.join(args)}")
    return proc.returncode


def platform_display_name():
    if IS_MAC:
        return "macOS"
    if IS_LINUX:
        try:
            info = platform.freedesktop_os_release()
            return info.get("PRETTY_NAME", "Linux")
        except Exception:
            return "Linux"
    return platform.system()


# ============================================================
# Privilege escalation (Linux always; macOS only for raw writes —
# diskutil/hdiutil need no root, but writing /dev/rdiskN does)
# ============================================================
class PrivilegeHelper:
    def __init__(self, app):
        self.app = app
        self.cached_password = None

    def _ask_password_on_main_thread(self):
        result = {}
        done = threading.Event()

        def ask():
            pw = simpledialog.askstring(
                "Administrator password",
                "Enter your sudo/administrator password to partition and format the drive.\n"
                "It is used only to run local disk commands and is never stored or sent anywhere.",
                show="*",
                parent=self.app,
            )
            result["pw"] = pw
            done.set()

        self.app.after(0, ask)
        done.wait()
        return result.get("pw")

    def check_password(self, password):
        """True if `password` is accepted by sudo. Never raises, never logs the password.

        `-k` makes sudo ignore any cached credential, so a wrong password cannot slip
        through because a previous sudo session is still valid. The password goes to
        stdin only, as in run_script().
        """
        if not password:
            return False
        try:
            proc = subprocess.run(
                ["sudo", "-S", "-k", "-p", "", "true"],
                input=password + "\n", capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            return False
        return proc.returncode == 0

    def needs_password(self):
        """Whether a sudo password must be collected before running privileged commands."""
        return os.geteuid() != 0 and bool(shutil.which("sudo"))

    def authenticate(self, reason, max_attempts=3):
        """Ask for the administrator password up front and verify it. GUI thread only.

        Doing this before anything touches the drive means a wrong or missing password
        is caught while the drive is still untouched, instead of mid-operation.
        Returns True when privileges are available (password cached for this operation).
        """
        if not self.needs_password():
            return True  # already root, or pkexec will show its own prompt
        for attempt in range(max_attempts):
            pw = simpledialog.askstring(
                "Administrator password",
                f"{reason}\n\nEnter your administrator (sudo) password.\n"
                "It is used only to run local disk commands and is never stored or sent anywhere.",
                show="*",
                parent=self.app,
            )
            if pw is None:
                return False  # canceled
            if self.check_password(pw):
                self.cached_password = pw
                return True
            if attempt < max_attempts - 1:
                messagebox.showerror("Wrong password", "That password was not accepted. Please try again.",
                                     parent=self.app)
        messagebox.showerror("Wrong password", "Too many incorrect attempts. Nothing was changed.",
                             parent=self.app)
        return False

    def clear_cached_password(self):
        """Drop the in-memory copy of the password as soon as it is no longer needed."""
        self.cached_password = None

    def run_script(self, script, log, args=None, max_attempts=3):
        """Run `script` with root privileges.

        Values are NEVER interpolated into the script text. They are passed as
        positional shell parameters ("$1", "$2", ...) via `args`, so a filename
        containing quotes, semicolons or $(...) is treated as data, not as code.
        """
        args = [str(a) for a in (args or [])]
        # bash -c SCRIPT NAME ARG1 ARG2 ... -> inside SCRIPT: $0=NAME, $1=ARG1, ...
        bash_argv = ["bash", "-c", script, "win11_usb_creator"] + args

        if shutil.which("sudo"):
            attempts = 0
            while attempts < max_attempts:
                password = self.cached_password
                if password is None:
                    password = self._ask_password_on_main_thread()
                    if password is None:
                        raise RuntimeError("Administrator password entry canceled.")
                proc = subprocess.Popen(
                    ["sudo", "-S", "-p", ""] + bash_argv,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
                # The password goes only to stdin: it never appears in the process
                # argument list (visible to other users via `ps`) nor in any log.
                proc.stdin.write(password + "\n")
                proc.stdin.flush()
                proc.stdin.close()
                log("$ sudo bash -c '<privileged script>' " + " ".join(repr(a) for a in args))
                for line in proc.stdout:
                    log(line.rstrip())
                proc.wait()
                if proc.returncode == 0:
                    self.cached_password = password
                    return
                self.cached_password = None
                attempts += 1
                if attempts >= max_attempts:
                    audit(f"Privileged script failed after {max_attempts} attempts (exit {proc.returncode})",
                          logging.ERROR)
                    raise RuntimeError(
                        f"Privileged command failed (exit code {proc.returncode}). "
                        "This may be a wrong password or a real command error — check the log above."
                    )
                log("Command failed — this may be a wrong password. Please try again.")
            return
        if shutil.which("pkexec"):
            return run_cmd(["pkexec"] + bash_argv, log)
        raise RuntimeError(
            "Neither 'sudo' nor 'pkexec' was found. Install sudo (or run this app as root) "
            "so it can partition and format drives."
        )


# ============================================================
# macOS backend
# ============================================================
def macos_get_external_disks():
    """List only EXTERNAL physical disks attached over USB (never the Mac's internal disk)."""
    out = subprocess.check_output(["diskutil", "list", "-plist", "external", "physical"])
    data = plistlib.loads(out)
    disks = []
    for d in data.get("AllDisksAndPartitions", []):
        dev = d.get("DeviceIdentifier")
        if not dev or not MAC_DEVICE_RE.match(dev):
            continue
        size = d.get("Size", 0)
        try:
            info = plistlib.loads(subprocess.check_output(["diskutil", "info", "-plist", f"/dev/{dev}"]))
        except Exception as e:
            # Fail closed: if we cannot confirm the disk is external, do not offer
            # it for erasure. Previously this fell back to {} and the Internal
            # check silently passed, which could expose the system disk.
            audit(f"Hiding {dev}: could not verify it is external ({type(e).__name__})", logging.WARNING)
            continue
        if info.get("Internal", False):
            continue  # extra safety: never list the internal disk
        if not info.get("Removable", True) and not info.get("Ejectable", True):
            continue
        if str(info.get("BusProtocol", "")).upper() != "USB":
            continue  # only USB drives are offered (no SD cards, Thunderbolt/NVMe enclosures, disk images)
        label = f"/dev/{dev} — {human_size(size)}"
        disks.append({"id": dev, "size": size, "label": label})
    return disks


def macos_find_mountpoint_by_volname(dev, volname, retries=15):
    for _ in range(retries):
        out = subprocess.check_output(["diskutil", "list", "-plist", f"/dev/{dev}"])
        data = plistlib.loads(out)
        entries = data.get("AllDisksAndPartitions", [])
        parts = entries[0].get("Partitions", []) if entries else []
        for part in parts:
            if part.get("VolumeName", "").upper() == volname.upper():
                pid = part.get("DeviceIdentifier")
                info = plistlib.loads(subprocess.check_output(["diskutil", "info", "-plist", f"/dev/{pid}"]))
                mp = info.get("MountPoint")
                if mp:
                    return mp
        time.sleep(1)
    raise RuntimeError("Could not find the USB drive's mount point after formatting.")


def macos_build_usb(iso_path, dev, log, priv=None, progress=None):
    log(f"Erasing and formatting /dev/{dev} as GPT + FAT32 ('{VOL_NAME}')...")
    run_cmd(["diskutil", "eraseDisk", "FAT32", VOL_NAME, "GPT", f"/dev/{dev}"], log)

    target = macos_find_mountpoint_by_volname(dev, VOL_NAME)
    log(f"USB drive ready at: {target}")

    mount_dir = tempfile.mkdtemp(prefix="win11iso_")
    log(f"Mounting the ISO at {mount_dir}...")
    run_cmd(["hdiutil", "attach", iso_path, "-nobrowse", "-readonly", "-mountpoint", mount_dir], log)

    try:
        copy_windows_payload(
            mount_dir, target, log, progress,
            "wimlib-imagex not found. Install it with: brew install wimlib "
            "(or use the 'Install missing dependencies' button on tab 2).")
    finally:
        log("Unmounting the ISO...")
        run_cmd(["hdiutil", "detach", mount_dir, "-force"], log, check=False)
        try:
            os.rmdir(mount_dir)
        except OSError:
            pass

    log("Safely ejecting the USB drive...")
    run_cmd(["diskutil", "eject", f"/dev/{dev}"], log, check=False)
    log("Done! The USB drive is ready to install Windows 11.")


def macos_write_raw(iso_path, dev, log, priv, progress=None):
    """Write the ISO byte-for-byte to the whole disk (Linux and other hybrid ISOs)."""
    validate_hybrid_iso(iso_path)
    log(f"Unmounting /dev/{dev}...")
    run_cmd(["diskutil", "unmountDisk", f"/dev/{dev}"], log)
    log(f"Writing the ISO to /dev/{dev} (administrator privileges required). "
        "This can take several minutes.")
    # /dev/rdiskN (raw node) is several times faster than /dev/diskN.
    # BSD dd has no status=progress: it prints the byte count when it receives
    # SIGINFO, so ask for it once a second until the copy ends.
    script = (
        'set -eu\n'
        'dd if="$1" of="$2" bs="$3" &\n'
        'pid=$!\n'
        'while kill -0 "$pid" 2>/dev/null; do kill -INFO "$pid" 2>/dev/null || true; sleep 1; done\n'
        'wait "$pid"\n'
        'sync\n'
    )
    total = os.path.getsize(iso_path)
    priv.run_script(script, make_dd_log(log, total, progress),
                    args=[iso_path, f"/dev/r{dev}", RAW_WRITE_BLOCK["mac"]])
    if progress:
        progress(total, total, "Done")
    log("Safely ejecting the USB drive...")
    run_cmd(["diskutil", "eject", f"/dev/{dev}"], log, check=False)
    log("Done! The USB drive is ready to boot.")


# ============================================================
# Linux backend
# ============================================================
def linux_root_disk():
    try:
        src = subprocess.check_output(["findmnt", "-no", "SOURCE", "/"], text=True).strip()
        pk = subprocess.check_output(["lsblk", "-no", "PKNAME", src], text=True).strip()
        return pk or None
    except Exception as e:
        audit(f"Could not determine the system disk ({type(e).__name__}); "
              "falling back to mountpoint inspection", logging.WARNING)
        return None


def linux_disks_holding_critical_mounts():
    """Names of whole disks that currently host a critical system mountpoint.

    This is the safety net for machines that boot from a device flagged as
    removable (a Raspberry Pi booting from its SD card, a USB-booted system):
    there, the 'removable' flag alone would happily offer the system disk for
    erasure. Returns a set; an empty set means "could not determine".
    """
    unsafe = set()
    try:
        out = subprocess.check_output(
            ["lsblk", "-J", "-b", "-o", "NAME,TYPE,MOUNTPOINT,PKNAME"], text=True)
        data = json.loads(out)

        def walk(node, top):
            mp = node.get("mountpoint")
            if mp and (mp in CRITICAL_MOUNTPOINTS or mp.startswith("/boot")):
                unsafe.add(top)
            for child in node.get("children", []) or []:
                walk(child, top)

        for dev in data.get("blockdevices", []):
            if dev.get("type") != "disk":
                continue
            walk(dev, dev.get("name"))
    except Exception as e:
        audit(f"Critical-mountpoint scan unavailable ({type(e).__name__})", logging.WARNING)
    return unsafe


def linux_get_external_disks():
    root_disk = linux_root_disk()
    unsafe_disks = linux_disks_holding_critical_mounts()
    if root_disk:
        unsafe_disks.add(root_disk)
    disks = []
    if shutil.which("lsblk"):
        try:
            out = subprocess.check_output(["lsblk", "-J", "-b", "-o", "NAME,SIZE,TYPE,RM,TRAN"], text=True)
            data = json.loads(out)
            for dev in data.get("blockdevices", []):
                if dev.get("type") != "disk":
                    continue
                name = dev.get("name")
                if not name or not LINUX_DEVICE_RE.match(name):
                    continue
                if name in unsafe_disks:
                    audit(f"Hiding {name}: it hosts the system or a critical mountpoint")
                    continue
                if name.startswith(("loop", "zram", "dm-")):
                    continue
                if (dev.get("tran") or "").lower() != "usb":
                    continue  # only USB drives are offered
                size = int(dev.get("size") or 0)
                disks.append({"id": name, "size": size, "label": f"/dev/{name} — {human_size(size)}"})
            return disks
        except Exception as e:
            audit(f"lsblk enumeration failed ({type(e).__name__}); using /sys/block fallback",
                  logging.WARNING)

    # Fallback using /sys/block directly (works even without lsblk -J support)
    for name in sorted(os.listdir("/sys/block")):
        if name.startswith(("loop", "ram", "dm-", "sr", "zram")):
            continue
        if not LINUX_DEVICE_RE.match(name) or name in unsafe_disks:
            continue
        removable_path = f"/sys/block/{name}/removable"
        size_path = f"/sys/block/{name}/size"
        if not os.path.exists(removable_path):
            continue
        try:
            with open(removable_path) as fh:
                removable = fh.read().strip() == "1"
        except Exception:
            removable = False  # fail closed
        if not removable:
            continue
        # The sysfs device path of a USB drive passes through a "usb" bus node.
        if "/usb" not in os.path.realpath(f"/sys/block/{name}"):
            continue
        try:
            with open(size_path) as fh:
                sectors = int(fh.read().strip())
        except Exception:
            audit(f"Hiding {name}: could not read its size", logging.WARNING)
            continue  # fail closed: an unknown-size disk is not offered
        size = sectors * 512
        disks.append({"id": name, "size": size, "label": f"/dev/{name} — {human_size(size)}"})
    return disks


def linux_partition_path(dev_name, n):
    if dev_name[-1].isdigit():
        return f"/dev/{dev_name}p{n}"
    return f"/dev/{dev_name}{n}"


def linux_detect_pkg_manager():
    for mgr in ("apt-get", "dnf", "yum", "pacman", "zypper", "apk"):
        if shutil.which(mgr):
            return mgr
    return None


def linux_build_install_command(mgr, missing_tools):
    """Build the package-install command from the fixed allow-list only.

    Only tools declared in LINUX_REQUIRED_TOOLS may be installed, and only under
    the package name mapped in LINUX_PKG_MAP. Nothing from user input or from the
    network can influence what gets installed with root privileges.
    """
    if mgr not in LINUX_INSTALL_CMD_TEMPLATE:
        raise ValueError(f"Unsupported package manager: {mgr!r}")
    pkgmap = LINUX_PKG_MAP.get(mgr, {})
    allowed = set(LINUX_REQUIRED_TOOLS)
    pkgs = sorted({pkgmap[t] for t in missing_tools if t in allowed and t in pkgmap})
    if not pkgs:
        raise ValueError("Nothing to install: no recognised missing dependency.")
    for pkg in pkgs:
        if not re.fullmatch(r"[A-Za-z0-9._+-]{1,64}", pkg):
            raise ValueError(f"Refusing to install suspicious package name: {pkg!r}")
    return LINUX_INSTALL_CMD_TEMPLATE[mgr].format(pkgs=" ".join(pkgs))


def linux_write_raw(iso_path, dev_name, log, priv, progress=None):
    """Write the ISO byte-for-byte to the whole disk (Linux and other hybrid ISOs)."""
    validate_hybrid_iso(iso_path)
    dev = f"/dev/{dev_name}"
    log(f"Writing the ISO to {dev} (administrator privileges required)...")
    # Values arrive as "$1".."$3"; the glob expands only after the quoted device prefix.
    script = (
        'set -eu\n'
        'for p in "$2"*; do umount "$p" 2>/dev/null || true; done\n'
        'dd if="$1" of="$2" bs="$3" conv=fsync status=progress\n'
        'sync\n'
    )
    total = os.path.getsize(iso_path)
    priv.run_script(script, make_dd_log(log, total, progress),
                    args=[iso_path, dev, RAW_WRITE_BLOCK["linux"]])
    if progress:
        progress(total, total, "Done")
    log("Done! The USB drive is ready to boot. It's safe to unplug it now.")


def linux_build_usb(iso_path, dev_name, log, priv, progress=None):
    dev = f"/dev/{dev_name}"
    part = linux_partition_path(dev_name, 1)
    uid, gid = os.getuid(), os.getgid()
    iso_mount = tempfile.mkdtemp(prefix="win11iso_")
    usb_mount = tempfile.mkdtemp(prefix="win11usb_")

    log(f"Erasing and formatting {dev} as GPT + FAT32 (administrator privileges required)...")
    # Every value below arrives as a positional parameter ("$1".."$6"), never
    # pasted into the script text, so no filename can inject extra commands.
    prep_script = (
        'set -eu\n'
        'DEV="$1"; PART="$2"; ISO="$3"; ISO_MNT="$4"; USB_MNT="$5"; OWNER="$6"\n'
        'wipefs -a "$DEV"\n'
        'parted -s "$DEV" mklabel gpt\n'
        'parted -s "$DEV" mkpart primary fat32 1MiB 100%\n'
        'parted -s "$DEV" set 1 esp on\n'
        'partprobe "$DEV"\n'
        'sleep 2\n'
        f'mkfs.vfat -F 32 -n {VOL_NAME} "$PART"\n'
        'mount -o loop,ro,uid="${OWNER%%:*}",gid="${OWNER##*:}" "$ISO" "$ISO_MNT"\n'
        'mount -o uid="${OWNER%%:*}",gid="${OWNER##*:}" "$PART" "$USB_MNT"\n'
    )
    priv.run_script(prep_script, log,
                    args=[dev, part, iso_path, iso_mount, usb_mount, f"{uid}:{gid}"])

    try:
        copy_windows_payload(
            iso_mount, usb_mount, log, progress,
            "wimlib-imagex not found. Install it via your package manager "
            "(e.g. 'wimtools' on Debian/Ubuntu, 'wimlib-utils' on Fedora, 'wimlib' on "
            "Arch/openSUSE) or use the 'Install missing dependencies' button on tab 2.")
    finally:
        log("Unmounting...")
        cleanup_script = 'umount "$1" || true\numount "$2" || true\n'
        try:
            priv.run_script(cleanup_script, log, args=[usb_mount, iso_mount])
        except Exception as cleanup_err:
            log(f"Warning: cleanup failed: {cleanup_err}")
        for d in (iso_mount, usb_mount):
            try:
                os.rmdir(d)
            except OSError:
                pass

    log("Done! The USB drive is ready to install Windows 11. It's safe to unplug it now.")


# ============================================================
# Platform dispatch
# ============================================================
def get_external_disks():
    return macos_get_external_disks() if IS_MAC else linux_get_external_disks()


def reverify_target_disk(dev, expected_size, log):
    """Re-check, immediately before erasing, that `dev` is still the disk we listed.

    Device names are recycled by the operating system: if a drive is unplugged and
    another plugged in between listing and writing, '/dev/sdb' can point somewhere
    else entirely. Re-enumerating here closes that window.
    """
    validate_device_name(dev)
    current = {d["id"]: d for d in get_external_disks()}
    if dev not in current:
        audit(f"ABORTED: {dev} is no longer an eligible external disk", logging.ERROR)
        raise RuntimeError(
            f"Aborted for safety: /dev/{dev} is no longer listed as an external drive.\n\n"
            "It may have been unplugged, or the name may now refer to a different disk. "
            "Click 'Refresh USB drives list' and select the drive again."
        )
    actual_size = current[dev]["size"]
    if expected_size and actual_size != expected_size:
        audit(f"ABORTED: {dev} size changed {expected_size} -> {actual_size}", logging.ERROR)
        raise RuntimeError(
            f"Aborted for safety: /dev/{dev} now reports a different size "
            f"({human_size(actual_size)} instead of {human_size(expected_size)}).\n\n"
            "This means the name now points to a different device. Refresh the list "
            "and select the drive again."
        )
    log(f"Safety re-check passed: /dev/{dev} is still the same external drive "
        f"({human_size(actual_size)}).")


def build_usb(iso_path, dev, log, priv, expected_size=None, mode=MODE_WINDOWS, progress=None):
    if mode not in (MODE_WINDOWS, MODE_LINUX):
        raise ValueError(f"Unknown image type: {mode!r}")
    iso_path = validate_iso_path(iso_path)
    validate_device_name(dev)
    if mode == MODE_LINUX:
        validate_hybrid_iso(iso_path)  # fail before anything is touched
    reverify_target_disk(dev, expected_size, log)
    audit(f"DESTRUCTIVE OPERATION START: erasing /dev/{dev} and writing {mode} image")
    try:
        if mode == MODE_LINUX:
            if IS_MAC:
                macos_write_raw(iso_path, dev, log, priv, progress)
            else:
                linux_write_raw(iso_path, dev, log, priv, progress)
        elif IS_MAC:
            macos_build_usb(iso_path, dev, log, progress=progress)
        else:
            linux_build_usb(iso_path, dev, log, priv, progress)
    except Exception as e:
        audit(f"DESTRUCTIVE OPERATION FAILED on /dev/{dev}: {type(e).__name__}", logging.ERROR)
        raise
    audit(f"DESTRUCTIVE OPERATION COMPLETED on /dev/{dev}")


def get_missing_dependencies(mode=MODE_WINDOWS):
    if mode == MODE_LINUX:
        return [] if shutil.which("dd") else ["dd"]  # raw write needs nothing else
    if IS_MAC:
        return [] if shutil.which("wimlib-imagex") else ["wimlib-imagex"]
    return [t for t in LINUX_REQUIRED_TOOLS if not shutil.which(t)]


# ============================================================
# Download
# ============================================================
class DownloadThread(threading.Thread):
    def __init__(self, url, dest_path, progress_cb, done_cb, error_cb, cancel_event,
                 expected_sha256=None):
        super().__init__(daemon=True)
        self.url = url
        self.dest_path = dest_path
        self.progress_cb = progress_cb
        self.done_cb = done_cb
        self.error_cb = error_cb
        self.cancel_event = cancel_event
        self.expected_sha256 = expected_sha256

    def run(self):
        tmp_path = self.dest_path + ".part"
        try:
            # The URL was validated before this thread started; re-check here so
            # the guarantee holds even if this class is reused elsewhere.
            validate_download_url(self.url)
            # noqa S310 below: the scheme is restricted to HTTPS by the call above
            # and re-checked after redirects; file:// and friends cannot reach here.
            req = urllib.request.Request(self.url, headers={"User-Agent": "Mozilla/5.0"})  # noqa: S310
            digest = hashlib.sha256()
            with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT_SECONDS) as resp:  # noqa: S310
                # urlopen follows redirects; make sure we were not downgraded to
                # an unencrypted connection along the way.
                final_url = resp.geturl()
                if final_url != self.url:
                    validate_download_url(final_url)
                    audit(f"Download redirected to host: {urllib.parse.urlparse(final_url).hostname}")
                total = int(resp.headers.get("Content-Length", 0))
                downloaded = 0
                start = time.time()
                # Create the partial file readable only by its owner.
                fd = os.open(tmp_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, PRIVATE_FILE_MODE)
                with os.fdopen(fd, "wb") as f:
                    while True:
                        if self.cancel_event.is_set():
                            raise RuntimeError("Download canceled by user.")
                        chunk = resp.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        f.write(chunk)
                        digest.update(chunk)
                        downloaded += len(chunk)
                        elapsed = max(time.time() - start, 0.001)
                        self.progress_cb(downloaded, total, downloaded / elapsed)
                if total and downloaded != total:
                    raise RuntimeError(
                        f"Incomplete download: received {human_size(downloaded)} of "
                        f"{human_size(total)}. The file was discarded."
                    )
                sha256 = digest.hexdigest()
                expected = (self.expected_sha256 or "").strip().lower()
                if expected and expected != sha256:
                    audit("Downloaded ISO FAILED SHA-256 verification", logging.ERROR)
                    raise RuntimeError(
                        "SHA-256 verification FAILED — the downloaded file is NOT the one you "
                        "expected and was discarded.\n\n"
                        f"Expected: {expected}\nReceived: {sha256}\n\n"
                        "Do not use this file. Download it again from the official Microsoft page."
                    )
                os.replace(tmp_path, self.dest_path)
            audit(f"ISO downloaded ({human_size(downloaded)}) sha256={sha256}"
                  + (" [verified against expected value]" if expected else " [not verified]"))
            self.done_cb(self.dest_path, sha256, bool(expected))
        except Exception as e:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
            self.error_cb(str(e))


# ============================================================
# GUI
# ============================================================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("EPMA Windows 11 Creator USB")
        self.geometry("760x700")
        self.iso_path = tk.StringVar(value="")
        self.cancel_event = threading.Event()
        self.disks = []
        self.priv = PrivilegeHelper(self)
        self._build_ui()

    # ---------- UI ----------
    def _build_ui(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=10)
        self.tab1 = ttk.Frame(nb)
        self.tab2 = ttk.Frame(nb)
        nb.add(self.tab1, text="1. Download ISO")
        nb.add(self.tab2, text="2. Create USB drive")
        self._build_tab1()
        self._build_tab2()

    def _build_tab1(self):
        f = self.tab1
        instructions = (
            "Microsoft only releases the direct ISO link after you pick the edition and "
            "language on the official site. Steps:\n\n"
            "1. Click 'Open Microsoft's official page' below.\n"
            "2. Under 'Download Windows 11 Disk Image (ISO)', pick the\n"
            "   'Windows 11 (multi-edition ISO)' edition and click Download.\n"
            "3. Choose the language and confirm.\n"
            "4. Right-click the blue 64-bit download button and choose\n"
            "   'Copy Link Address' (do NOT click it to download directly in the browser).\n"
            "5. Paste the link below and click 'Download ISO'."
        )
        ttk.Label(f, text=instructions, justify="left").pack(anchor="w", padx=10, pady=(10, 10))
        ttk.Button(f, text="Open Microsoft's official page", command=self.open_ms_page).pack(anchor="w", padx=10)

        url_frame = ttk.Frame(f)
        url_frame.pack(fill="x", padx=10, pady=(15, 5))
        ttk.Label(url_frame, text="Direct ISO link (HTTPS only):").pack(anchor="w")
        self.url_entry = ttk.Entry(url_frame)
        self.url_entry.pack(fill="x", pady=(2, 0))

        sha_frame = ttk.Frame(f)
        sha_frame.pack(fill="x", padx=10, pady=(5, 0))
        ttk.Label(
            sha_frame,
            text="Expected SHA-256 checksum (optional — leave empty to skip verification):",
        ).pack(anchor="w")
        self.sha_entry = ttk.Entry(sha_frame)
        self.sha_entry.pack(fill="x", pady=(2, 0))
        self.sha_entry.insert(0, os.environ.get(ENV_EXPECTED_SHA256, ""))

        btn_frame = ttk.Frame(f)
        btn_frame.pack(fill="x", padx=10, pady=5)
        self.download_btn = ttk.Button(btn_frame, text="Download ISO", command=self.start_download)
        self.download_btn.pack(side="left")
        self.cancel_btn = ttk.Button(btn_frame, text="Cancel", command=self.cancel_download, state="disabled")
        self.cancel_btn.pack(side="left", padx=5)

        self.progress = ttk.Progressbar(f, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", padx=10, pady=(10, 2))
        self.progress_label = ttk.Label(f, text="")
        self.progress_label.pack(anchor="w", padx=10)

        ttk.Separator(f).pack(fill="x", padx=10, pady=15)
        ttk.Label(f, text="Already downloaded the ISO manually in your browser?").pack(anchor="w", padx=10)
        ttk.Button(f, text="Select existing ISO file...", command=self.pick_existing_iso).pack(
            anchor="w", padx=10, pady=(2, 10)
        )

        self.iso_label = ttk.Label(f, text="No ISO selected yet.", foreground="blue")
        self.iso_label.pack(anchor="w", padx=10, pady=(5, 10))

    def _build_tab2(self):
        f = self.tab2
        ttk.Label(f, text=f"Platform: {platform_display_name()}", foreground="gray").pack(anchor="w", padx=10, pady=(10, 0))
        self.iso_label2 = ttk.Label(f, text="ISO: (none selected)")
        self.iso_label2.pack(anchor="w", padx=10, pady=(0, 5))

        mode_frame = ttk.Frame(f)
        mode_frame.pack(fill="x", padx=10, pady=(0, 8))
        ttk.Label(mode_frame, text="Image type:").pack(side="left")
        self.mode_var = tk.StringVar(value=MODE_WINDOWS)
        ttk.Radiobutton(mode_frame, text="Windows 11 (GPT + FAT32, files copied)", value=MODE_WINDOWS,
                        variable=self.mode_var, command=self.on_mode_change).pack(side="left", padx=(8, 0))
        ttk.Radiobutton(mode_frame, text="Linux / other hybrid ISO (written directly)", value=MODE_LINUX,
                        variable=self.mode_var, command=self.on_mode_change).pack(side="left", padx=(8, 0))

        dep_frame = ttk.Frame(f)
        dep_frame.pack(fill="x", padx=10, pady=(0, 10))
        self.dep_label = ttk.Label(dep_frame, text="")
        self.dep_label.pack(side="left")
        self.install_deps_btn = ttk.Button(dep_frame, text="Install missing dependencies", command=self.install_dependencies)
        self.check_dependencies()

        ttk.Button(f, text="Refresh USB drives list", command=self.refresh_disks).pack(anchor="w", padx=10)
        self.disk_combo = ttk.Combobox(f, state="readonly", width=90)
        self.disk_combo.pack(fill="x", padx=10, pady=5)
        self.disk_combo.bind("<<ComboboxSelected>>", lambda e: self.update_create_button_state())

        warn_text = (
            "WARNING: ALL DATA on the selected drive will be PERMANENTLY erased.\n"
            "Double-check that this is really your USB drive before continuing. Only USB "
            "drives are listed — the system's internal disk is never shown."
        )
        if IS_LINUX:
            warn_text += "\nYou'll be asked for your administrator (sudo) password to format the drive."
        else:
            warn_text += "\nLinux mode on macOS asks for your administrator password to write the drive."
        ttk.Label(f, text=warn_text, foreground="red", justify="left", wraplength=720).pack(anchor="w", padx=10, pady=10)

        self.create_btn = ttk.Button(
            f, text="Create Bootable USB Drive", command=self.start_create_usb, state="disabled"
        )
        self.create_btn.pack(anchor="w", padx=10, pady=10)

        self.create_progress = ttk.Progressbar(f, orient="horizontal", mode="determinate")
        self.create_progress.pack(fill="x", padx=10, pady=(0, 2))
        self.create_progress_label = ttk.Label(f, text="")
        self.create_progress_label.pack(anchor="w", padx=10)
        self._create_started = None
        self._create_last_ui = 0.0

        self.log_text = tk.Text(f, height=15, state="disabled", bg="black", fg="lightgreen")
        self.log_text.pack(fill="both", expand=True, padx=10, pady=(5, 10))

    # ---------- dependencies ----------
    def on_mode_change(self):
        self.check_dependencies()
        self.update_create_button_state()

    def check_dependencies(self):
        missing = get_missing_dependencies(self.mode_var.get())
        if not missing:
            self.dep_label.config(text="All dependencies OK", foreground="green")
            self.install_deps_btn.pack_forget()
        else:
            self.dep_label.config(text="Missing: " + ", ".join(missing), foreground="orange")
            self.install_deps_btn.pack(side="left", padx=5)

    def install_dependencies(self):
        self.install_deps_btn.config(state="disabled")

        def worker():
            try:
                if IS_MAC:
                    if not shutil.which("brew"):
                        raise RuntimeError("Homebrew not found. Install it from https://brew.sh")
                    run_cmd(["brew", "install", "wimlib"], lambda m: self.after(0, self.log, m))
                else:
                    missing = get_missing_dependencies(MODE_WINDOWS)
                    mgr = linux_detect_pkg_manager()
                    if not mgr:
                        raise RuntimeError(
                            "No supported package manager found (apt/dnf/yum/pacman/zypper/apk). "
                            "Please install manually: " + ", ".join(missing)
                        )
                    script = linux_build_install_command(mgr, missing)
                    # Show exactly what will run as root before it runs.
                    self.after(0, self.log, f"About to run as administrator: {script}")
                    audit(f"Installing dependencies via {mgr}: {', '.join(missing)}")
                    self.priv.run_script(script, lambda m: self.after(0, self.log, m))
            except (ValueError, RuntimeError) as e:
                self.after(0, self._report_error, "Error", str(e))
            except Exception as e:
                self.after(0, self._report_error, "Unexpected error", None, e)
            finally:
                self.priv.clear_cached_password()
                self.after(0, self.check_dependencies)
                self.after(0, lambda: self.install_deps_btn.config(state="normal"))

        threading.Thread(target=worker, daemon=True).start()

    # ---------- download ----------
    def open_ms_page(self):
        webbrowser.open(MS_DOWNLOAD_PAGE)

    def pick_existing_iso(self):
        path = filedialog.askopenfilename(title="Select the Windows 11 ISO file", filetypes=[("ISO image", "*.iso")])
        if path:
            self.set_iso(path)

    def set_iso(self, path):
        self.iso_path.set(path)
        self.iso_label.config(text=f"Selected ISO: {path}")
        self.iso_label2.config(text=f"ISO: {path}")
        # Only a default: the user can still switch the image type by hand.
        self.mode_var.set(MODE_WINDOWS if "win" in os.path.basename(path).lower() else MODE_LINUX)
        self.on_mode_change()

    def start_download(self):
        try:
            url, host, untrusted_host = validate_download_url(self.url_entry.get())
        except ValueError as e:
            messagebox.showerror("Invalid link", str(e))
            return

        expected_sha = self.sha_entry.get().strip().lower()
        if expected_sha and not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
            messagebox.showerror(
                "Invalid checksum",
                "A SHA-256 checksum must be exactly 64 characters using only 0-9 and a-f.\n\n"
                "Leave the field empty if you do not have one.",
            )
            return

        if untrusted_host and not messagebox.askyesno(
            "Unrecognised download server",
            f"This link points to '{host}', which is not a known Microsoft download server.\n\n"
            "Downloading a Windows image from an unofficial source is a real risk: a tampered "
            "image would install a compromised Windows on the target computer, and you would "
            "have no way of noticing.\n\n"
            "Continue anyway?",
            icon="warning",
        ):
            audit(f"User declined download from untrusted host: {host}")
            return

        dest = filedialog.asksaveasfilename(
            title="Save ISO as", defaultextension=".iso", initialfile="Win11.iso", filetypes=[("ISO image", "*.iso")]
        )
        if not dest:
            return
        audit(f"Download started from host={host} trusted={not untrusted_host} "
              f"checksum_supplied={bool(expected_sha)}")
        self.cancel_event.clear()
        self.download_btn.config(state="disabled")
        self.cancel_btn.config(state="normal")
        self.progress.config(mode="determinate", value=0)
        t = DownloadThread(
            url,
            dest,
            progress_cb=lambda d, tt, s: self.after(0, self._on_progress, d, tt, s),
            done_cb=lambda p, h, v: self.after(0, self._on_download_done, p, h, v),
            error_cb=lambda e: self.after(0, self._on_download_error, e),
            cancel_event=self.cancel_event,
            expected_sha256=expected_sha,
        )
        t.start()

    def cancel_download(self):
        self.cancel_event.set()

    def _on_progress(self, downloaded, total, speed):
        if total:
            pct = downloaded / total * 100
            self.progress.config(mode="determinate", value=pct)
            eta = (total - downloaded) / speed if speed > 0 else 0
            self.progress_label.config(
                text=f"{human_size(downloaded)} / {human_size(total)} ({pct:.1f}%) — "
                f"{human_size(speed)}/s — ~{int(eta)}s left"
            )
        else:
            self.progress.config(mode="indeterminate")
            self.progress_label.config(text=f"{human_size(downloaded)} downloaded — {human_size(speed)}/s")

    def _on_download_done(self, path, sha256, verified):
        self.download_btn.config(state="normal")
        self.cancel_btn.config(state="disabled")
        self.progress_label.config(text="Download complete.")
        self.set_iso(path)
        self.log(f"SHA-256 of the downloaded file: {sha256}")
        if verified:
            detail = "\n\nThe SHA-256 checksum matches the value you supplied — the file is intact."
        else:
            detail = (
                "\n\nSHA-256 of this file:\n"
                f"{sha256}\n\n"
                "No checksum was supplied, so authenticity was NOT verified. If Microsoft "
                "publishes a checksum for this image, compare it with the value above before "
                "writing the USB drive."
            )
        messagebox.showinfo("Done", f"ISO downloaded to:\n{path}{detail}")

    def _on_download_error(self, msg):
        self.download_btn.config(state="normal")
        self.cancel_btn.config(state="disabled")
        self.progress_label.config(text="Download failed.")
        messagebox.showerror("Download error", msg)

    # ---------- USB drive ----------
    def refresh_disks(self):
        try:
            self.disks = get_external_disks()
        except Exception as e:
            messagebox.showerror("Error", f"Could not list disks: {e}")
            return
        labels = [d["label"] for d in self.disks]
        self.disk_combo["values"] = labels
        if labels:
            self.disk_combo.current(0)
        else:
            self.disk_combo.set("")
        self.update_create_button_state()

    def selected_disk(self):
        idx = self.disk_combo.current()
        if idx < 0 or idx >= len(self.disks):
            return None
        return self.disks[idx]

    def update_create_button_state(self):
        disk = self.selected_disk()
        ok = (
            bool(self.iso_path.get())
            and disk is not None
        )
        self.create_btn.config(state="normal" if ok else "disabled")

    def log(self, msg):
        self.log_text.config(state="normal")
        self.log_text.insert("end", msg + "\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def start_create_usb(self):
        disk = self.selected_disk()
        if not disk:
            return
        mode = self.mode_var.get()
        what = "Windows 11" if mode == MODE_WINDOWS else "the selected Linux image"
        if not messagebox.askyesno(
            "Final confirmation",
            f"This will PERMANENTLY ERASE all data on /dev/{disk['id']} "
            f"({disk['label']}) and write {what} to it.\n\nContinue?",
        ):
            return
        # Writing the drive needs administrator rights (always on Linux; on macOS only for
        # the direct-write mode). Collect and verify the password now, before touching
        # the drive.
        if (IS_LINUX or mode == MODE_LINUX) and not self.priv.authenticate(
                f"Administrator access is required to write /dev/{disk['id']}."):
            self.priv.clear_cached_password()
            self.log("Canceled: administrator password was not provided. The drive was not modified.")
            return
        self.create_btn.config(state="disabled")
        self._reset_create_progress()
        iso = self.iso_path.get()
        dev = disk["id"]
        expected_size = disk.get("size")

        def worker():
            try:
                build_usb(iso, dev, lambda m: self.after(0, self.log, m), self.priv,
                          expected_size=expected_size, mode=mode,
                          progress=lambda d, t, s: self.after(0, self._on_create_progress, d, t, s))
                self.after(0, self._finish_create_progress, True)
                self.after(0, lambda: messagebox.showinfo("Done", "Bootable USB drive created successfully!"))
            except (ValueError, RuntimeError) as e:
                # Expected, actionable failures: the message is written for the user.
                self.after(0, self._finish_create_progress, False)
                self.after(0, self._report_error, "Error", str(e))
            except Exception as e:
                # Unexpected failure: show a short message, keep the detail in the log
                # so internal paths and command lines are not surfaced in a dialog.
                self.after(0, self._finish_create_progress, False)
                self.after(0, self._report_error, "Unexpected error", None, e)
            finally:
                # The administrator password is no longer needed once the operation ends.
                self.priv.clear_cached_password()
                self.after(0, lambda: self.create_btn.config(state="normal"))

        threading.Thread(target=worker, daemon=True).start()

    # ---------- USB creation progress ----------
    def _reset_create_progress(self):
        self._create_started = None
        self._create_last_ui = 0.0
        self.create_progress.config(mode="indeterminate", value=0)
        self.create_progress.start(12)
        self.create_progress_label.config(text="Preparing the drive...")

    def _on_create_progress(self, done, total, text):
        now = time.time()
        finished = total and done >= total
        # Updates can arrive thousands of times (one per copied file); redraw ~5x/s.
        if not finished and now - self._create_last_ui < 0.2:
            return
        self._create_last_ui = now
        if not total:
            return
        if str(self.create_progress.cget("mode")) != "determinate":
            self.create_progress.stop()
            self.create_progress.config(mode="determinate")
        if self._create_started is None:
            self._create_started = now
        pct = done / total * 100
        self.create_progress.config(value=pct)
        elapsed = max(now - self._create_started, 0.001)
        speed = done / elapsed
        if finished:
            self.create_progress_label.config(text=f"{text}  100%")
            return
        eta = (total - done) / speed if speed > 0 and done > 0 else 0
        self.create_progress_label.config(
            text=f"{text}  {pct:.1f}% — {human_size(done)} / {human_size(total)} — "
                 f"{human_size(speed)}/s — ~{int(eta // 60)}m{int(eta % 60):02d}s left")

    def _finish_create_progress(self, ok):
        self.create_progress.stop()
        self.create_progress.config(mode="determinate", value=100 if ok else 0)
        self.create_progress_label.config(text="Done — 100%" if ok else "Failed.")

    def _report_error(self, title, message, exc=None):
        """Show a user-facing error without leaking internals into the dialog."""
        if exc is not None:
            self.log(f"ERROR [{type(exc).__name__}]: {exc}")
            audit(f"{title}: {type(exc).__name__}", logging.ERROR)
            message = (
                "The operation could not be completed.\n\n"
                f"Reason: {type(exc).__name__}\n\n"
                "The full technical detail was written to the log box below and to the "
                f"audit log at:\n{audit_log_path()}"
            )
        else:
            self.log(f"ERROR: {message}")
        messagebox.showerror(title, message)


if __name__ == "__main__":
    if not (IS_MAC or IS_LINUX):
        print("This script supports macOS and Linux only.")
        sys.exit(1)
    App().mainloop()
