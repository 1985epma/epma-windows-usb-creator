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

import argparse
import collections
import contextlib
import filecmp
import hashlib
import http.client
import inspect
import json
import logging
import logging.handlers
import os
import platform
import plistlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

# Tkinter is needed by the GUI only. The engine and the command line interface work
# without it, so a missing Tk is remembered here instead of ending the program at
# import time; main() prints the hint when the GUI is requested.
if platform.system() == "Darwin":
    TK_MISSING_MESSAGE = (
        "Tkinter is not available for this Python installation.\n"
        "Install it with: brew install python-tk@<version matching your python>"
    )
else:
    TK_MISSING_MESSAGE = (
        "Tkinter is not available for this Python installation.\n"
        "Install it with your package manager, e.g.:\n"
        "  Debian/Ubuntu: sudo apt install python3-tk\n"
        "  Fedora:        sudo dnf install python3-tkinter\n"
        "  Arch:          sudo pacman -S tk\n"
        "  openSUSE:      sudo zypper install python3-tk"
    )
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except ImportError:
    tk = ttk = filedialog = messagebox = None

__version__ = "1.1.0"

IS_MAC = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"

APP_NAME = "epma-usb-creator"  # shown in the macOS menu bar / Dock and used as the Linux window class

MS_DOWNLOAD_PAGE = "https://www.microsoft.com/en-us/software-download/windows11"
FAT32_MAX_FILE_SIZE = 4_294_967_295  # 4GB - 1 byte
CHUNK_SIZE = 1024 * 1024
VOL_NAME = "WIN11USB"

# What kind of image is being written.
#   windows: format GPT + FAT32 and copy the ISO contents (splitting install.wim)
#   linux:   write the ISO byte-for-byte to the drive (hybrid ISO, like `dd`)
MODE_WINDOWS = "windows"
MODE_LINUX = "linux"
LOG_MAX_LINES = 5000   # the on-screen log keeps only this many lines
LOG_FLUSH_MS = 100     # worker log lines are queued and written to the log box this often
VERIFY_CHUNK = 16 * 1024 * 1024  # bytes compared per step when reading a raw write back
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
DOWNLOAD_MAX_ATTEMPTS = 3      # transient network errors are retried (resuming where possible)
DOWNLOAD_BACKOFF_SECONDS = (2, 5)  # wait before retry 2 and 3
QUERY_TIMEOUT = 30             # seconds allowed for quick query commands (diskutil list, lsblk, ...)
SUDO_KEEPALIVE_SECONDS = 60    # how often the sudo timestamp is refreshed while an operation runs
SUDO_KEEPALIVE_MAX_SECONDS = 6 * 3600  # the keep-alive never outlives this, whatever happens
AUDIT_LOG_MAX_BYTES = 1_000_000
AUDIT_LOG_BACKUPS = 5
RAW_CANCELED_MARKER = "WRITE_CANCELED"  # printed by the root write scripts when they stop on request
DIRECT_IO_ALIGNMENT = 4096     # oflag=direct on Linux only when the image size is a multiple of this
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


class PrivateRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Rotating log file that stays owner-only (0600), live file and rotated copies alike."""

    def _open(self):
        fd = os.open(self.baseFilename, os.O_WRONLY | os.O_CREAT | os.O_APPEND, PRIVATE_FILE_MODE)
        return os.fdopen(fd, self.mode, encoding=self.encoding, errors=self.errors)

    def doRollover(self):
        super().doRollover()
        for i in range(0, self.backupCount + 1):
            path = self.baseFilename if i == 0 else f"{self.baseFilename}.{i}"
            try:
                os.chmod(path, PRIVATE_FILE_MODE)
            except OSError:
                pass


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
        handler = PrivateRotatingFileHandler(
            path, maxBytes=AUDIT_LOG_MAX_BYTES, backupCount=AUDIT_LOG_BACKUPS, encoding="utf-8")
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
    # fullmatch, not match: "$" also matches just before a trailing newline, so "sdb\n" would pass.
    if not pattern.fullmatch(dev):
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


# ============================================================
# ISO inspection (pure stdlib, never raises, reads a few MB at most)
# ============================================================
ISO_KIND_WINDOWS = "windows"
ISO_KIND_LINUX = "linux"
ISO_KIND_UNKNOWN = "unknown"
ISO_SECTOR = 2048
ISO_PVD_OFFSET = 16 * ISO_SECTOR        # Primary Volume Descriptor: sector 16 (0x8000)
ISO_DIR_MAX_BYTES = 256 * 1024          # never read more than this per directory
ISO_UDF_SCAN_BYTES = 4 * 1024 * 1024    # how much of a UDF image is searched for Windows names
# Volume ids that Microsoft's media tools produce, e.g. CCCOMA_X64FRE_EN-US_DV9.
WINDOWS_VOLUME_ID_RE = re.compile(
    r"^(?:[A-Z0-9]{2,8}_(?:X64|X86|A64|ARM64)F?REV?_|WIN(?:DOWS)?[ _-]?(?:SERVER|1[01]|[78])\b)")
WINDOWS_ROOT_FILES = {"BOOTMGR", "BOOTMGR.EFI", "SETUP.EXE"}
WINDOWS_SOURCES_FILES = {"INSTALL.WIM", "INSTALL.ESD", "INSTALL.SWM", "BOOT.WIM"}


def _iso_read_dir(fh, extent, length, block, file_size):
    """Parse one ISO 9660 directory into [(NAME, is_dir, extent, length)]. Names lose their ';1'."""
    offset = extent * block
    if length <= 0 or offset <= 0 or offset >= file_size:
        return []
    fh.seek(offset)
    data = fh.read(min(length, ISO_DIR_MAX_BYTES))
    entries = []
    pos = 0
    while pos < len(data):
        rec_len = data[pos]
        if rec_len == 0:  # records never span sectors; padding means "continue in the next one"
            pos = (pos // ISO_SECTOR + 1) * ISO_SECTOR
            continue
        if rec_len < 34 or pos + rec_len > len(data):
            break
        name_len = data[pos + 32]
        raw = data[pos + 33:pos + 33 + name_len]
        if raw not in (b"\x00", b"\x01"):  # skip the '.' and '..' entries
            name = raw.decode("latin-1").split(";")[0].rstrip(".").upper()
            entries.append((
                name,
                bool(data[pos + 25] & 0x02),
                int.from_bytes(data[pos + 2:pos + 6], "little"),
                int.from_bytes(data[pos + 10:pos + 14], "little"),
            ))
        pos += rec_len
    return entries


def _iso_has_udf(fh):
    """True if the volume recognition area (sectors 17-19) announces UDF (ECMA-167)."""
    fh.seek(ISO_PVD_OFFSET + ISO_SECTOR)
    area = fh.read(3 * ISO_SECTOR)
    return any(area[i * ISO_SECTOR + 1:i * ISO_SECTOR + 6] in (b"BEA01", b"NSR02", b"NSR03")
               for i in range(len(area) // ISO_SECTOR))


def _detect_iso_kind(path):
    file_size = os.path.getsize(path)
    with open(path, "rb") as fh:
        head = fh.read(ISO_PVD_OFFSET + ISO_SECTOR)
        pvd = head[ISO_PVD_OFFSET:]
        if len(pvd) < ISO_SECTOR or pvd[0] != 1 or pvd[1:6] != b"CD001":
            return ISO_KIND_UNKNOWN  # not an ISO 9660 image
        volume_id = pvd[40:72].decode("latin-1").strip().upper()
        block = int.from_bytes(pvd[128:130], "little")
        if block < 512 or block > 65536:
            block = ISO_SECTOR
        root = pvd[156:190]
        root_extent = int.from_bytes(root[2:6], "little")
        root_length = int.from_bytes(root[10:14], "little")

        # 1. Walk the ISO 9660 tree: root files, then \SOURCES\.
        entries = _iso_read_dir(fh, root_extent, root_length, block, file_size)
        for name, is_dir, extent, length in entries:
            if not is_dir and name in WINDOWS_ROOT_FILES:
                return ISO_KIND_WINDOWS
            if is_dir and name == "SOURCES":
                for sub, sub_is_dir, _e, _l in _iso_read_dir(fh, extent, length, block, file_size):
                    if not sub_is_dir and sub in WINDOWS_SOURCES_FILES:
                        return ISO_KIND_WINDOWS

        # 2. Microsoft's own ISOs are UDF images whose ISO 9660 side is just a stub, so the
        #    names above are invisible. UDF stores them near the start of the file.
        if _iso_has_udf(fh):
            fh.seek(0)
            blob = fh.read(ISO_UDF_SCAN_BYTES).lower()
            for needle in (b"bootmgr", "bootmgr".encode("utf-16-be")):
                if needle in blob and (b"sources" in blob or "sources".encode("utf-16-be") in blob):
                    return ISO_KIND_WINDOWS
        if WINDOWS_VOLUME_ID_RE.match(volume_id):
            return ISO_KIND_WINDOWS

        # 3. Everything else that boots from a USB drive as-is is a hybrid image (Linux & co).
        if head[510:512] == b"\x55\xaa":
            return ISO_KIND_LINUX
    return ISO_KIND_UNKNOWN


def detect_iso_kind(path):
    """Classify an ISO by its content: 'windows', 'linux' (hybrid) or 'unknown'.

    Never raises and reads at most a few MB, so it is safe to call on any file the user
    picks. 'unknown' means "could not tell" and callers should fall back to the file name.
    """
    try:
        return _detect_iso_kind(path)
    except Exception:  # noqa: BLE001 - any malformed/unreadable file simply means "unknown"
        return ISO_KIND_UNKNOWN


# ---- SHA-256 of a local file ----
SHA256_CHUNK = 4 * 1024 * 1024
_HEX64_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")


def parse_expected_sha256(text, filename=None):
    """Extract a SHA-256 from what the user pasted. Returns lowercase hex, or None if empty.

    Accepts a bare hash, a `sha256sum` line (`<hash> *file.iso` / `<hash>  file.iso`), the BSD
    form (`SHA256 (file.iso) = <hash>`), or a whole SHA256SUMS file (then `filename` picks the
    line). Raises ValueError with a user-facing message when nothing valid can be found.
    """
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    if not lines:
        return None
    found = [(m.group(0).lower(), ln) for ln in lines for m in [_HEX64_RE.search(ln)] if m]
    if not found:
        raise ValueError("That is not a SHA-256 checksum: it must be 64 characters using only 0-9 and a-f.")
    if len(found) == 1 or len({h for h, _ in found}) == 1:
        return found[0][0]
    if filename:
        named = {h for h, ln in found if filename in ln}
        if len(named) == 1:
            return named.pop()
    raise ValueError("The pasted text contains several checksums. Paste only the line for your ISO file.")


def compute_sha256(path, progress=None, chunk=SHA256_CHUNK):
    """SHA-256 of a file by chunked reads. `progress(done, total)` is called after each chunk."""
    digest = hashlib.sha256()
    total = os.path.getsize(path)
    done = 0
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            digest.update(block)
            done += len(block)
            if progress:
                progress(done, total)
    return digest.hexdigest()


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


def copy_file_with_progress(src, dst_dir, on_bytes, cancel_event=None):
    """Copy `src` into `dst_dir` in chunks, reporting the bytes copied so far."""
    dst = os.path.join(dst_dir, os.path.basename(src))
    copied = 0
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        while True:
            check_canceled(cancel_event)
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            fout.write(chunk)
            copied += len(chunk)
            on_bytes(copied)
    shutil.copystat(src, dst)


# Reads the whole image back from the drive and compares it with the ISO, chunk by
# chunk. It exits 0 and reports the result as a VERIFY_OK / VERIFY_FAIL marker line
# (so a mismatch is told apart from a script error). Values arrive as "$1".."$5",
# never pasted into the text; "$5" is the cancel flag file (VERIFY_CANCELED when it appears).
VERIFY_RAW_SCRIPT = (
    'set -eu\n'
    'ISO="$1"; DEV="$2"; SIZE="$3"; BS="$4"; STOP="$5"\n'
    # Linux: make sure we read the device, not the page cache (harmless elsewhere).
    '{ blockdev --flushbufs "$DEV"; echo 3 > /proc/sys/vm/drop_caches; } >/dev/null 2>&1 || true\n'
    'off=0; i=0\n'
    'while [ "$off" -lt "$SIZE" ]; do\n'
    '  if [ -e "$STOP" ]; then echo "VERIFY_CANCELED"; exit 0; fi\n'
    '  len=$(( SIZE - off ))\n'
    '  if [ "$len" -gt "$BS" ]; then len=$BS; fi\n'
    '  if ! cmp -s <(dd if="$ISO" bs="$BS" skip="$i" count=1 2>/dev/null | head -c "$len") \\\n'
    '              <(dd if="$DEV" bs="$BS" skip="$i" count=1 2>/dev/null | head -c "$len"); then\n'
    '    echo "VERIFY_FAIL $off"; exit 0\n'
    '  fi\n'
    '  off=$((off + len)); i=$((i + 1))\n'
    '  echo "VERIFY_PROGRESS $off"\n'
    'done\n'
    'echo "VERIFY_OK"\n'
    'exit 0\n'
)


def verify_raw_write(iso_path, device_path, log, priv, progress, cancel_event=None):
    """Read the drive back and compare it byte-for-byte with the ISO. Raises on any mismatch."""
    total = os.path.getsize(iso_path)
    log("Verifying the written image: reading the drive back and comparing it with the ISO...")
    result = {}
    last = [0.0]

    def watch(line):
        line = line.strip()
        m = re.fullmatch(r"VERIFY_PROGRESS (\d+)", line)
        if m:
            now = time.time()
            if progress and (now - last[0] >= 0.5 or int(m.group(1)) >= total):
                last[0] = now
                progress(min(int(m.group(1)), total), total, "Verifying the written image...")
            return
        if line == "VERIFY_OK":
            result["ok"] = True
        elif line == "VERIFY_CANCELED":
            result["canceled"] = True
        elif line.startswith("VERIFY_FAIL"):
            result["ok"] = False
            result["offset"] = line.split()[-1]
        else:
            log(line)

    check_canceled(cancel_event)
    with cancel_flag(cancel_event) as flag:
        priv.run_script(VERIFY_RAW_SCRIPT, watch,
                        args=[iso_path, device_path, str(total), str(VERIFY_CHUNK), flag])
    if result.get("canceled"):
        raise OperationCanceled("Canceled by the user.")
    if result.get("ok") is None:
        raise RuntimeError("Could not complete the verification of the written drive. "
                           "Do not trust this drive; run the creation again.")
    if not result["ok"]:
        audit(f"VERIFICATION FAILED at byte {result['offset']}", logging.ERROR)
        raise RuntimeError(
            f"Verification FAILED: the data on the drive differs from the ISO (first difference "
            f"near byte {result['offset']}).\n\nThe drive was NOT ejected and should not be used. "
            "Try again, and if it fails again, the USB drive or its port may be faulty.")
    audit("Verification passed (raw write matches the ISO)")
    log("Verification passed: the drive content is identical to the ISO.")


def verify_windows_payload(src_root, dst_root, rel_big, big_file, log, progress, cancel_event=None):
    """Compare what is on the drive with the ISO. Raises on any mismatch.

    Every file is compared by checksum (rsync dry run), and the install image is
    either compared directly or checked with `wimlib-imagex verify` when it was split.
    """
    log("Verifying the copied files (reading them back from the drive)...")
    if progress:
        progress(0, 0, "Verifying the copied files...")
    bad = []

    def watch(line):
        log(line)
        if re.match(r"^(>f|cd|\*deleting)", line):
            bad.append(line.strip())

    run_cmd(["rsync", "-rcn", "-i", f"--exclude={rel_big}", src_root + "/", dst_root + "/"], watch,
            cancel_event=cancel_event)
    if bad:
        audit(f"VERIFICATION FAILED: {len(bad)} file(s) differ", logging.ERROR)
        raise RuntimeError(
            f"Verification FAILED: {len(bad)} item(s) on the drive are missing or differ from the "
            f"ISO (for example: {bad[0]}).\n\nThe drive was NOT ejected and should not be used.")

    name = os.path.basename(big_file)
    sources = os.path.join(dst_root, "sources")
    if progress:
        progress(0, 0, "Verifying the install image...")
    swm = os.path.join(sources, os.path.splitext(name)[0] + ".swm")
    if os.path.exists(swm):
        try:
            run_cmd(["wimlib-imagex", "verify", swm, f"--ref={sources}/{os.path.splitext(name)[0]}*.swm"], log,
                    cancel_event=cancel_event)
        except RuntimeError:
            raise RuntimeError(
                "Verification FAILED: the split install image on the drive is damaged.\n\n"
                "The drive was NOT ejected and should not be used.") from None
    elif check_canceled(cancel_event) or not filecmp.cmp(big_file, os.path.join(sources, name), shallow=False):
        raise RuntimeError(
            f"Verification FAILED: {name} on the drive differs from the ISO.\n\n"
            "The drive was NOT ejected and should not be used.")
    audit("Verification passed (copied files match the ISO)")
    log("Verification passed: the files on the drive match the ISO.")


def copy_windows_payload(src_root, dst_root, log, progress, wimlib_hint, reopen=None, cancel_event=None):
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
    run_cmd(["rsync", "-rv", f"--exclude={rel_big}", src_root + "/", dst_root + "/"], rsync_log,
            cancel_event=cancel_event)
    report(rest_total, "Copying files...")
    check_canceled(cancel_event)

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

        run_cmd(["wimlib-imagex", "split", big_file, out_swm, "3800"], split_log, cancel_event=cancel_event)
    else:
        log(f"Copying {os.path.basename(big_file)} ({human_size(size)})...")
        copy_file_with_progress(
            big_file, target_sources,
            lambda n: report(rest_total + n, "Copying the install image..."),
            cancel_event=cancel_event)

    report(total, "Flushing data to the drive...")
    check_canceled(cancel_event)
    log("Syncing writes to disk...")
    run_cmd(["sync"], log, check=False)
    # Remount so the check reads from the device itself and not from the system cache.
    if reopen:
        dst_root = reopen()
    verify_windows_payload(src_root, dst_root, rel_big, big_file, log, progress, cancel_event=cancel_event)


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


class OperationCanceled(RuntimeError):
    """The user canceled the USB creation. A RuntimeError so older handlers still cope."""


def check_canceled(cancel_event):
    """Raise OperationCanceled if the user asked to stop. Cheap; call between steps."""
    if cancel_event is not None and cancel_event.is_set():
        raise OperationCanceled("Canceled by the user.")


def sha256_file(path, cancel_event=None, chunk=4 * 1024 * 1024):
    """SHA-256 of a file, read in chunks (constant memory). Cancel-aware."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            check_canceled(cancel_event)
            block = fh.read(chunk)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _stop_process(proc, group=False):
    """Ask a child (or, with group=True, its whole process group) to stop; kill it if it does not."""
    def send(sig):
        if group:
            os.killpg(os.getpgid(proc.pid), sig)
        elif sig == signal.SIGTERM:
            proc.terminate()
        else:
            proc.kill()

    try:
        send(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            send(signal.SIGKILL)
    except (OSError, ProcessLookupError):
        pass


def run_cmd(args, log, check=True, timeout=None, cancel_event=None):
    """Run a command as the current user, streaming its output to `log`.

    `timeout` (seconds) kills a command that hangs. `cancel_event` makes it stop
    promptly when the user cancels: the process is terminated and OperationCanceled
    is raised. Passing neither keeps the original behaviour.
    """
    log(f"$ {' '.join(args)}")
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    state = {"timed_out": False, "canceled": False}
    finished = threading.Event()

    def watchdog():
        deadline = None if timeout is None else time.monotonic() + timeout
        while not finished.wait(0.2):
            if cancel_event is not None and cancel_event.is_set():
                state["canceled"] = True
            elif deadline is not None and time.monotonic() >= deadline:
                state["timed_out"] = True
            else:
                continue
            _stop_process(proc)
            return

    watcher = None
    if timeout is not None or cancel_event is not None:
        watcher = threading.Thread(target=watchdog, daemon=True)
        watcher.start()
    try:
        for line in proc.stdout:
            log(line.rstrip())
        proc.wait()
    finally:
        finished.set()
        if watcher is not None:
            watcher.join(10)
        if proc.stdout:
            proc.stdout.close()
    if state["canceled"]:
        raise OperationCanceled("Canceled by the user.")
    if state["timed_out"]:
        log(f"Command timed out after {timeout}s and was stopped: {args[0]}")
        if check:
            raise RuntimeError(f"Command timed out after {timeout}s: {' '.join(args)}")
        return proc.returncode if proc.returncode else -1
    if check and proc.returncode != 0:
        raise RuntimeError(f"Command failed (exit code {proc.returncode}): {' '.join(args)}")
    return proc.returncode


@contextlib.contextmanager
def cancel_flag(cancel_event):
    """Yield the path of a private flag file that appears when `cancel_event` is set.

    The privileged write script runs as root, so the app cannot signal it. Instead the
    script polls for this file and stops dd itself. The file lives in a fresh 0700
    directory owned by the user; the script only tests whether the path exists.
    """
    flag_dir = tempfile.mkdtemp(prefix="win11cancel_")
    path = os.path.join(flag_dir, "cancel")
    stop = threading.Event()

    def watch():
        while not stop.is_set():
            if cancel_event is None:
                return
            if cancel_event.wait(0.25):
                try:
                    open(path, "w").close()
                except OSError:
                    pass
                return

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    try:
        yield path
    finally:
        stop.set()
        watcher.join(2)
        try:
            os.remove(path)
        except OSError:
            pass
        try:
            os.rmdir(flag_dir)
        except OSError:
            pass


@contextlib.contextmanager
def prevent_sleep(log=None):
    """Keep the computer awake while a write runs. Best effort: failures are ignored."""
    proc = None
    try:
        if IS_MAC and shutil.which("caffeinate"):
            # -i: no idle sleep; -w: stop by itself when our process exits.
            cmd = ["caffeinate", "-i", "-w", str(os.getpid())]
        elif IS_LINUX and shutil.which("systemd-inhibit"):
            cmd = ["systemd-inhibit", "--what=sleep:idle", f"--who={APP_NAME}",
                   "--why=Writing a USB drive", "sleep", "infinity"]
        else:
            cmd = None
        if cmd:
            # Own process group, so stopping it also stops systemd-inhibit's `sleep infinity`.
            proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, start_new_session=True)
            if log:
                log("Sleep is blocked while the drive is being written.")
    except (OSError, subprocess.SubprocessError):
        proc = None
    try:
        yield
    finally:
        if proc is not None:
            _stop_process(proc, group=True)


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


def ask_password(parent, title, prompt):
    """Modal password prompt. Returns the text, or None if canceled. GUI thread only.

    Built by hand instead of tkinter.simpledialog: on Tk 9 (current Homebrew Python on
    macOS) simpledialog raises TclError because it calls a removed Tcl command, which
    made the whole "Create" button fail silently.
    """
    top = tk.Toplevel(parent)
    top.title(title)
    top.resizable(False, False)
    result = {"pw": None}

    ttk.Label(top, text=prompt, justify="left", wraplength=420).pack(padx=16, pady=(16, 8), anchor="w")
    entry = ttk.Entry(top, show="*", width=44)
    entry.pack(padx=16, fill="x")

    def accept(_event=None):
        result["pw"] = entry.get()
        top.destroy()

    def cancel(_event=None):
        top.destroy()

    row = ttk.Frame(top)
    row.pack(padx=16, pady=14, anchor="e")
    ttk.Button(row, text="Cancel", command=cancel).pack(side="left", padx=(0, 8))
    ttk.Button(row, text="OK", command=accept).pack(side="left")
    top.bind("<Return>", accept)
    top.bind("<Escape>", cancel)
    top.protocol("WM_DELETE_WINDOW", cancel)

    top.update_idletasks()
    x = parent.winfo_rootx() + max((parent.winfo_width() - top.winfo_reqwidth()) // 2, 0)
    y = parent.winfo_rooty() + 80
    top.geometry(f"+{x}+{y}")
    top.transient(parent)
    top.attributes("-topmost", True)  # a prompt hidden behind the main window looks like a freeze
    top.lift()
    try:
        top.wait_visibility()
        top.grab_set()
    except tk.TclError:
        pass  # grab is a nicety; the dialog still works without it
    entry.focus_force()
    parent.wait_window(top)
    return result["pw"]


def normalize_typed_identifier(text):
    """What the user typed as a disk identifier, with whitespace and a '/dev/' prefix removed."""
    text = (text or "").strip()
    return text[5:] if text.startswith("/dev/") else text


def ask_typed_confirmation(parent, title, message, expected, reasons=()):
    """Modal "type the drive identifier to continue" dialog. Returns True only on an exact match.

    Used for high-risk drives. Built by hand (see ask_password): no simpledialog on Tk 9. The
    confirm button stays disabled until the text matches, so Enter cannot slip through.
    """
    top = tk.Toplevel(parent)
    top.title(title)
    top.resizable(False, False)
    result = {"ok": False}

    ttk.Label(top, text=message, justify="left", wraplength=520).pack(padx=16, pady=(16, 8), anchor="w")
    if reasons:
        ttk.Label(top, text="This drive does not look like a spare USB stick:", foreground="#c62828",
                  justify="left").pack(padx=16, anchor="w")
        for reason in reasons:
            ttk.Label(top, text="\u2022 " + reason, foreground="#c62828", justify="left",
                      wraplength=500).pack(padx=(28, 16), anchor="w")
    ttk.Label(top, text=f"To confirm, type the drive identifier exactly as shown ({expected}):",
              justify="left", wraplength=520).pack(padx=16, pady=(12, 4), anchor="w")
    entry = ttk.Entry(top, width=30)
    entry.pack(padx=16, anchor="w")

    def matches():
        return normalize_typed_identifier(entry.get()) == expected

    def accept(_event=None):
        if matches():
            result["ok"] = True
            top.destroy()

    def cancel(_event=None):
        top.destroy()

    row = ttk.Frame(top)
    row.pack(padx=16, pady=14, anchor="e")
    ttk.Button(row, text="Cancel", command=cancel).pack(side="left", padx=(0, 8))
    erase_btn = ttk.Button(row, text="Erase this drive", command=accept, state="disabled")
    erase_btn.pack(side="left")
    entry.bind("<KeyRelease>", lambda _e: erase_btn.config(state="normal" if matches() else "disabled"))
    top.bind("<Return>", accept)
    top.bind("<Escape>", cancel)
    top.protocol("WM_DELETE_WINDOW", cancel)

    top.update_idletasks()
    x = parent.winfo_rootx() + max((parent.winfo_width() - top.winfo_reqwidth()) // 2, 0)
    y = parent.winfo_rooty() + 60
    top.geometry(f"+{x}+{y}")
    top.transient(parent)
    top.attributes("-topmost", True)
    top.lift()
    try:
        top.wait_visibility()
        top.grab_set()
    except tk.TclError:
        pass  # grab is a nicety; the dialog still works without it
    entry.focus_force()
    parent.wait_window(top)
    return result["ok"]


# ============================================================
# Privilege escalation (Linux always; macOS only for raw writes —
# diskutil/hdiutil need no root, but writing /dev/rdiskN does)
# ============================================================
class PrivilegeHelper:
    """Runs privileged scripts through sudo (or pkexec), asking for the password once.

    After the password is validated, sudo's own timestamp carries the authorization:
    scripts run with `sudo -n` (nothing on stdin) and a small keep-alive refreshes the
    timestamp while an operation runs, so the password is not held in memory for the
    whole write. If that does not work on this machine (for example `timestamp_timeout=0`
    or per-process tickets), the helper falls back to keeping the validated password
    and passing it on stdin. In every mode a script that fails is NEVER run again.
    """

    def __init__(self, app):
        self.app = app
        self.cached_password = None   # only set in the stdin fallback mode
        self._use_timestamp = False   # True: sudo's timestamp is armed, no password held
        self._keepalive_stop = None

    def _ask_password_on_main_thread(self, retry=False):
        result = {}
        done = threading.Event()
        prefix = "That password was not accepted. Try again.\n\n" if retry else ""

        def ask():
            try:
                result["pw"] = ask_password(
                    self.app,
                    "Administrator password",
                    prefix +
                    "Enter your sudo/administrator password to partition and format the drive.\n"
                    "It is used only to run local disk commands and is never stored or sent anywhere.",
                )
            finally:
                done.set()  # never leave the worker thread waiting forever

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

    # ---------- sudo timestamp (no password kept in memory) ----------
    def _sudo_probe(self):
        """True if sudo currently accepts us without a password (and refreshes its timestamp)."""
        try:
            proc = subprocess.run(["sudo", "-n", "-v"], stdin=subprocess.DEVNULL,
                                  capture_output=True, timeout=QUERY_TIMEOUT)
        except (OSError, subprocess.SubprocessError):
            return False
        return proc.returncode == 0

    def _arm_timestamp(self, password):
        """Validate with `sudo -S -v`, then confirm a fresh `sudo -n` process is accepted.

        The second step is what proves the timestamp is shared between our sudo calls on
        this machine; if it is not, the caller falls back to the stdin mode.
        """
        try:
            proc = subprocess.run(["sudo", "-S", "-v", "-p", ""], input=password + "\n",
                                  capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            return False
        return proc.returncode == 0 and self._sudo_probe()

    def _start_keepalive(self):
        self._stop_keepalive()
        stop = threading.Event()
        self._keepalive_stop = stop

        def loop():
            deadline = time.monotonic() + SUDO_KEEPALIVE_MAX_SECONDS
            while not stop.wait(SUDO_KEEPALIVE_SECONDS) and time.monotonic() < deadline:
                self._sudo_probe()

        threading.Thread(target=loop, daemon=True).start()

    def _stop_keepalive(self):
        stop, self._keepalive_stop = self._keepalive_stop, None
        if stop is not None:
            stop.set()

    def _adopt(self, secret):
        """Take a validated password: arm sudo's timestamp and drop the string if that works."""
        if self._arm_timestamp(secret):
            self._use_timestamp = True
            self.cached_password = None
            self._start_keepalive()
        else:
            self._use_timestamp = False
            self.cached_password = secret

    def _ensure_auth(self, max_attempts=3):
        """Make sure scripts can run. Returns "ts" (sudo timestamp) or "pw" (stdin fallback).

        Passwords are validated here, BEFORE any script runs, so a wrong password is
        never discovered by re-running a script. Asks at most `max_attempts` times.
        """
        if self._use_timestamp:
            if self._sudo_probe():
                return "ts"
            self._use_timestamp = False  # expired or revoked: ask again
            self._stop_keepalive()
        if self.cached_password is not None:
            return "pw"
        for attempt in range(max_attempts):
            entered = self._ask_password_on_main_thread(retry=attempt > 0)
            if entered is None:
                raise RuntimeError("Administrator password entry canceled.")
            if self.check_password(entered):
                self._adopt(entered)
                entered = None
                return "ts" if self._use_timestamp else "pw"
        raise RuntimeError("The administrator password was not accepted after "
                           f"{max_attempts} attempts. Nothing was changed.")

    def authenticate(self, reason, max_attempts=3):
        """Ask for the administrator password up front and verify it. GUI thread only.

        Doing this before anything touches the drive means a wrong or missing password
        is caught while the drive is still untouched, instead of mid-operation.
        Returns True when privileges are available (sudo's timestamp is armed, or as a
        fallback the password is kept in memory for this operation).
        """
        if not self.needs_password():
            return True  # already root, or pkexec will show its own prompt
        for attempt in range(max_attempts):
            pw = ask_password(
                self.app,
                "Administrator password",
                f"{reason}\n\nEnter your administrator (sudo) password.\n"
                "It is used only to run local disk commands and is never stored or sent anywhere.",
            )
            if pw is None:
                return False  # canceled
            if self.check_password(pw):
                self._adopt(pw)
                pw = None  # the string is not needed any more
                return True
            if attempt < max_attempts - 1:
                messagebox.showerror("Wrong password", "That password was not accepted. Please try again.",
                                     parent=self.app)
        messagebox.showerror("Wrong password", "Too many incorrect attempts. Nothing was changed.",
                             parent=self.app)
        return False

    def clear_cached_password(self):
        """Forget the password and end the sudo session as soon as it is no longer needed."""
        self.cached_password = None
        self._stop_keepalive()
        if self._use_timestamp:
            self._use_timestamp = False
            try:
                subprocess.run(["sudo", "-k"], stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
            except (OSError, subprocess.SubprocessError):
                pass

    def run_script(self, script, log, args=None, max_attempts=3):
        """Run `script` with root privileges, exactly once.

        Values are NEVER interpolated into the script text. They are passed as
        positional shell parameters ("$1", "$2", ...) via `args`, so a filename
        containing quotes, semicolons or $(...) is treated as data, not as code.

        A script that exits non-zero raises RuntimeError and is never re-run: a failed
        mkfs or dd must not be repeated behind the user's back. Password problems are
        handled before the script starts (_ensure_auth). `max_attempts` is accepted for
        backward compatibility and limits only the password prompts.
        """
        args = [str(a) for a in (args or [])]
        # bash -c SCRIPT NAME ARG1 ARG2 ... -> inside SCRIPT: $0=NAME, $1=ARG1, ...
        bash_argv = ["bash", "-c", script, "win11_usb_creator"] + args

        sudo_prefix, use_stdin = [], False   # already root: no sudo
        if os.geteuid() == 0:
            pass
        elif shutil.which("sudo"):
            use_stdin = self._ensure_auth(max_attempts) != "ts"
            sudo_prefix = ["sudo", "-n"]   # used unless the stdin fallback is needed
        elif shutil.which("pkexec"):
            return run_cmd(["pkexec"] + bash_argv, log)
        else:
            raise RuntimeError(
                "Neither 'sudo' nor 'pkexec' was found. Install sudo (or run this app as root) "
                "so it can partition and format drives."
            )

        if use_stdin and self.cached_password is None:
            raise RuntimeError("The administrator session ended before the command started. "
                               "Nothing was changed; start the operation again.")
        popen_kw = {"stdout": subprocess.PIPE, "stderr": subprocess.STDOUT, "text": True, "bufsize": 1}
        if use_stdin:
            proc = subprocess.Popen(["sudo", "-S", "-p", ""] + bash_argv, stdin=subprocess.PIPE, **popen_kw)
        else:
            proc = subprocess.Popen(sudo_prefix + bash_argv, stdin=subprocess.DEVNULL, **popen_kw)
        if use_stdin:
            # The password goes only to stdin: it never appears in the process
            # argument list (visible to other users via `ps`) nor in any log.
            password = self.cached_password
            proc.stdin.write(password + "\n")
            proc.stdin.flush()
            proc.stdin.close()
        log("$ sudo bash -c '<privileged script>' " + " ".join(repr(a) for a in args))
        refused = False
        for line in proc.stdout:
            line = line.rstrip()
            if "a password is required" in line and line.startswith("sudo:"):
                refused = True
            log(line)
        proc.wait()
        if proc.returncode == 0:
            return None
        audit(f"Privileged script failed (exit {proc.returncode}); not retried", logging.ERROR)
        if refused:
            self._use_timestamp = False
            raise RuntimeError(
                "The administrator session expired before the command started, so it did not "
                "run and nothing was changed. Start the operation again.")
        raise RuntimeError(
            f"Privileged command failed (exit code {proc.returncode}). It was not run again; "
            "check the log above for the reason.")


# ============================================================
# Disk description and risk assessment (pure functions: no I/O, unit-testable)
#
# A disk dict always has `id`, `size`, `label`. The listing code adds, when it can:
#   model     str                 vendor + product name, e.g. "SanDisk Ultra"
#   volumes   list[dict] | None   what is on the drive (None = could not be inspected)
#             each: name, filesystem, size, used (bytes or None), mountpoint (or None)
#   identity  tuple of (key, value) pairs, stable identifiers (serial, WWN, DiskUUID, model)
# ============================================================
LARGE_DISK_BYTES = 256 * 1024 ** 3        # bigger than this is more likely a backup disk than a stick
SUBSTANTIAL_USED_BYTES = 16 * 1024 ** 3   # an old installer stick holds ~6 GB; more means real data
MANY_VOLUMES = 4
DATA_VOLUME_NAME_RE = re.compile(
    r"back\s*-?up|bkp|time\s*machine|archive|arquivo|photos?|fotos?|document|dados|\bdata\b|"
    r"storage|media|movies|music|clone|vault|\bhd\b|\bfiles\b", re.IGNORECASE)
DATA_DRIVE_MODEL_RE = re.compile(
    r"passport|elements|expansion|backup\s*plus|my\s*book|canvio|portable|\bssd\b|\bhdd\b|external|rugged",
    re.IGNORECASE)
MAX_VOLUMES_SHOWN = 8


def make_identity(**parts):
    """Normalise stable identifiers into a sorted tuple of (key, value); empty values are dropped."""
    return tuple(sorted((k, str(v).strip()) for k, v in parts.items() if v is not None and str(v).strip()))


def identity_mismatch(expected, actual):
    """Describe how `actual` differs from `expected`, or return None when it is the same drive.

    Every identifier recorded at listing time must still be present and equal. Identifiers
    that only show up now are ignored. With no recorded identity there is nothing to compare.
    """
    if not expected:
        return None
    now = dict(actual or ())
    for key, value in expected:
        if now.get(key) != value:
            return f"{key} changed"
    return None


def format_volume_line(vol):
    """One human-readable line describing a volume, e.g. 'Untitled (FAT32, 58.0 GB, 12.3 GB used)'."""
    bits = []
    if vol.get("filesystem"):
        bits.append(str(vol["filesystem"]))
    if vol.get("size"):
        bits.append(human_size(vol["size"]))
    if vol.get("used") is not None:
        bits.append(f"{human_size(vol['used'])} used")
    elif vol.get("mountpoint") is None:
        bits.append("not mounted, usage unknown")
    name = vol.get("name") or "(unnamed)"
    return f"{name} ({', '.join(bits)})" if bits else name


def build_disk_label(dev_path, model, size, volumes):
    """The text shown in the drive list: '/dev/disk4 — SanDisk Ultra — 58.6 GB — 2 volumes (...)'."""
    parts = [dev_path]
    if model:
        parts.append(model)
    parts.append(human_size(size))
    if volumes is None:
        parts.append("contents unknown")
    elif not volumes:
        parts.append("no volumes")
    else:
        names = [repr(v.get("name") or v.get("filesystem") or "unnamed") for v in volumes[:3]]
        if len(volumes) > 3:
            names.append("…")
        noun = "volume" if len(volumes) == 1 else "volumes"
        parts.append(f"{len(volumes)} {noun} ({', '.join(names)})")
    return " — ".join(parts)


def assess_disk_risk(disk):
    """Return (level, reasons): level is 'high' or 'normal'; reasons explain every 'high'.

    High means "this does not look like a spare USB stick": it is large, holds a lot of data,
    has a name that suggests backups/personal data, looks like an external HDD/SSD, has many
    partitions, or its contents could not be read. High-risk drives need the identifier typed
    before they can be erased. A disk dict without a 'volumes' key (not inspected at all) is not
    penalised for that; a 'volumes' of None (inspection failed) is.
    """
    reasons = []
    size = disk.get("size") or 0
    if size > LARGE_DISK_BYTES:
        reasons.append(f"It is large ({human_size(size)}); installer sticks are usually much smaller. "
                       "This may be an external hard disk or SSD.")
    model = disk.get("model") or ""
    if model and DATA_DRIVE_MODEL_RE.search(model):
        reasons.append(f"Its model name ({model}) suggests an external hard disk or SSD.")
    if "volumes" in disk:
        volumes = disk["volumes"]
        if volumes is None:
            reasons.append("What is stored on it could not be read, so there is no way to tell what would be lost.")
        else:
            used = sum(v.get("used") or 0 for v in volumes)
            if used >= SUBSTANTIAL_USED_BYTES:
                reasons.append(f"It holds a lot of data ({human_size(used)} in use).")
            named = [v.get("name") for v in volumes if v.get("name") and DATA_VOLUME_NAME_RE.search(v["name"])]
            if named:
                reasons.append("Volume name(s) suggest personal data or backups: "
                               + ", ".join(repr(n) for n in named[:3]) + ".")
            if len(volumes) >= MANY_VOLUMES:
                reasons.append(f"It has {len(volumes)} volumes, which is unusual for a USB stick.")
    return ("high" if reasons else "normal"), reasons


def describe_disk_for_confirmation(disk):
    """Multi-line summary (model, size, every volume with its used space) for the final confirmation."""
    lines = [f"Drive: /dev/{disk.get('id')}"]
    if disk.get("model"):
        lines.append(f"Model: {disk['model']}")
    lines.append(f"Size: {human_size(disk.get('size') or 0)}")
    volumes = disk.get("volumes")
    if volumes is None:
        lines.append("Contents: could not be read")
    elif not volumes:
        lines.append("Contents: no volumes found (the drive looks empty)")
    else:
        lines.append("Contents that will be DESTROYED:")
        lines.extend("  - " + format_volume_line(v) for v in volumes[:MAX_VOLUMES_SHOWN])
        if len(volumes) > MAX_VOLUMES_SHOWN:
            lines.append(f"  - ... and {len(volumes) - MAX_VOLUMES_SHOWN} more")
    return "\n".join(lines)


# Identity recorded for the drive the user selected; checked again right before erasing.
# (Kept here, not in build_usb's signature, so the check cannot be forgotten by a caller.)
_pinned_identities = {}


def pin_target_identity(dev, identity):
    """Remember the identity of the drive the user confirmed; reverify_target_disk() enforces it."""
    if identity:
        _pinned_identities[dev] = tuple(identity)
    else:
        _pinned_identities.pop(dev, None)


# ============================================================
# macOS backend
# ============================================================
def macos_usb_device_map():
    """Map BSD names ('disk4', 'disk4s1', ...) to the USB device that carries them.

    Parses `ioreg` (the only place macOS exposes the USB serial number). Best effort: returns
    {} on any failure, since this only enriches the description of a drive.
    """
    try:
        out = subprocess.check_output(["ioreg", "-a", "-r", "-c", "IOUSBHostDevice", "-l"],
                                      stderr=subprocess.DEVNULL, timeout=15)
        roots = plistlib.loads(out)
    except Exception as e:
        audit(f"USB serial lookup unavailable ({type(e).__name__})", logging.WARNING)
        return {}
    found = {}

    def walk(node, usb):
        if not isinstance(node, dict):
            return
        if node.get("IOObjectClass") == "IOUSBHostDevice":
            usb = {
                "serial": node.get("kUSBSerialNumberString") or node.get("USB Serial Number") or "",
                "vendor": node.get("USB Vendor Name") or "",
                "product": node.get("USB Product Name") or "",
            }
        bsd = node.get("BSD Name")
        if usb is not None and isinstance(bsd, str):
            found[bsd] = usb
        for child in node.get("IORegistryEntryChildren", []) or []:
            walk(child, usb)

    for root in roots if isinstance(roots, list) else []:
        walk(root, None)
    return found


def macos_apfs_volumes_by_store():
    """Map the partition holding an APFS container ('disk4s2') to that container's volumes."""
    try:
        data = plistlib.loads(subprocess.check_output(["diskutil", "list", "-plist"], timeout=30))
    except Exception:
        return {}
    by_store = {}
    for entry in data.get("AllDisksAndPartitions", []):
        for store in entry.get("APFSPhysicalStores", []) or []:
            vols = []
            for v in entry.get("APFSVolumes", []) or []:
                vols.append({
                    "name": v.get("VolumeName") or "",
                    "filesystem": "APFS",
                    "size": entry.get("Size") or 0,
                    "used": v.get("CapacityInUse"),
                    "mountpoint": v.get("MountPoint") or None,
                })
            by_store[store.get("DeviceIdentifier")] = vols
    return by_store


def _used_bytes(mountpoint):
    """Bytes in use on a mounted filesystem, or None."""
    if not mountpoint:
        return None
    try:
        usage = shutil.disk_usage(mountpoint)
        return usage.total - usage.free
    except Exception:
        return None


def macos_describe_disk(entry, info, usb_map, apfs_map):
    """(model, volumes, identity) for one external disk. `volumes` is None if it cannot be read."""
    dev = entry.get("DeviceIdentifier")
    usb = usb_map.get(dev) or {}
    media = str(info.get("MediaName") or "").strip()
    vendor = str(usb.get("vendor") or "").strip()
    model = media or str(usb.get("product") or "").strip()
    if vendor and vendor.lower() not in model.lower():
        model = f"{vendor} {model}".strip()
    identity = make_identity(serial=usb.get("serial"), model=media or usb.get("product"),
                             diskuuid=info.get("DiskUUID"))
    volumes = []
    try:
        for part in entry.get("Partitions", []) or []:
            pid = part.get("DeviceIdentifier")
            if str(part.get("Content", "")).startswith("Apple_APFS") and apfs_map.get(pid):
                volumes.extend(apfs_map[pid])
                continue
            pinfo = plistlib.loads(subprocess.check_output(
                ["diskutil", "info", "-plist", f"/dev/{pid}"], timeout=30))
            mountpoint = pinfo.get("MountPoint") or part.get("MountPoint") or None
            volumes.append({
                "name": part.get("VolumeName") or pinfo.get("VolumeName") or "",
                "filesystem": pinfo.get("FilesystemUserVisibleName") or pinfo.get("FilesystemName")
                              or str(part.get("Content") or ""),
                "size": part.get("Size") or 0,
                "used": _used_bytes(mountpoint),
                "mountpoint": mountpoint,
            })
    except Exception as e:
        audit(f"Could not inspect the volumes of {dev} ({type(e).__name__})", logging.WARNING)
        volumes = None
    return model, volumes, identity


def macos_get_external_disks():
    """List only EXTERNAL physical disks attached over USB (never the Mac's internal disk)."""
    out = subprocess.check_output(["diskutil", "list", "-plist", "external", "physical"])
    data = plistlib.loads(out)
    usb_map = None  # looked up lazily: only needed when at least one disk qualifies
    apfs_map = None
    disks = []
    for d in data.get("AllDisksAndPartitions", []):
        dev = d.get("DeviceIdentifier")
        if not dev or not MAC_DEVICE_RE.fullmatch(dev):
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
        # Descriptive extras (model, volumes, identity). Failing to gather them never hides
        # or exposes a disk: the safety filters above have already decided that.
        if usb_map is None:
            usb_map = macos_usb_device_map()
            apfs_map = macos_apfs_volumes_by_store()
        model, volumes, identity = macos_describe_disk(d, info, usb_map, apfs_map)
        label = build_disk_label(f"/dev/{dev}", model, size, volumes)
        disks.append({"id": dev, "size": size, "label": label,
                      "model": model, "volumes": volumes, "identity": identity})
    return disks


def macos_find_mountpoint_by_volname(dev, volname, retries=15):
    for _ in range(retries):
        out = subprocess.check_output(["diskutil", "list", "-plist", f"/dev/{dev}"], timeout=QUERY_TIMEOUT)
        data = plistlib.loads(out)
        entries = data.get("AllDisksAndPartitions", [])
        parts = entries[0].get("Partitions", []) if entries else []
        for part in parts:
            if part.get("VolumeName", "").upper() == volname.upper():
                pid = part.get("DeviceIdentifier")
                info = plistlib.loads(subprocess.check_output(
                    ["diskutil", "info", "-plist", f"/dev/{pid}"], timeout=QUERY_TIMEOUT))
                mp = info.get("MountPoint")
                if mp:
                    return mp
        time.sleep(1)
    raise RuntimeError("Could not find the USB drive's mount point after formatting.")


def macos_build_usb(iso_path, dev, log, priv=None, progress=None, cancel_event=None, eject=True):
    check_canceled(cancel_event)
    log(f"Erasing and formatting /dev/{dev} as GPT + FAT32 ('{VOL_NAME}')...")
    run_cmd(["diskutil", "eraseDisk", "FAT32", VOL_NAME, "GPT", f"/dev/{dev}"], log, timeout=600)

    target = macos_find_mountpoint_by_volname(dev, VOL_NAME)
    log(f"USB drive ready at: {target}")
    check_canceled(cancel_event)

    mount_dir = tempfile.mkdtemp(prefix="win11iso_")
    log(f"Mounting the ISO at {mount_dir}...")
    try:
        run_cmd(["hdiutil", "attach", iso_path, "-nobrowse", "-readonly", "-mountpoint", mount_dir], log,
                timeout=300)
    except Exception:
        try:
            os.rmdir(mount_dir)
        except OSError:
            pass
        raise

    try:
        def reopen():
            log("Remounting the drive to read it back from the device...")
            run_cmd(["diskutil", "unmountDisk", f"/dev/{dev}"], log, timeout=120)
            run_cmd(["diskutil", "mountDisk", f"/dev/{dev}"], log, timeout=120)
            return macos_find_mountpoint_by_volname(dev, VOL_NAME)

        copy_windows_payload(
            mount_dir, target, log, progress,
            "wimlib-imagex not found. Install it with: brew install wimlib "
            "(or use the 'Install missing dependencies' button on tab 2).",
            reopen=reopen, cancel_event=cancel_event)
    except OperationCanceled:
        log("Canceled. Unmounting the drive; it is left incomplete and unusable.")
        run_cmd(["diskutil", "unmountDisk", f"/dev/{dev}"], log, check=False, timeout=120)
        raise
    finally:
        log("Unmounting the ISO...")
        run_cmd(["hdiutil", "detach", mount_dir, "-force"], log, check=False, timeout=120)
        try:
            os.rmdir(mount_dir)
        except OSError:
            pass

    ejected = macos_eject(dev, log) if eject else None
    log("Done! The USB drive is ready to install Windows 11.")
    report_eject(ejected, log, skipped=not eject)
    return ejected


def macos_eject(dev, log):
    """Eject the whole disk; if something holds it, force-unmount and retry. Returns True on success."""
    log("Ejecting the USB drive...")
    if run_cmd(["diskutil", "eject", f"/dev/{dev}"], log, check=False, timeout=120) == 0:
        return True
    log("The drive is busy — forcing the unmount and trying again...")
    run_cmd(["diskutil", "unmountDisk", "force", f"/dev/{dev}"], log, check=False, timeout=120)
    time.sleep(1)
    return run_cmd(["diskutil", "eject", f"/dev/{dev}"], log, check=False, timeout=120) == 0


def linux_eject(dev_name, log, priv):
    """Flush, unmount and power the drive off. Best effort: returns True if it was ejected."""
    log("Ejecting the USB drive (administrator privileges required)...")
    # Always exits 0 so a drive that cannot be powered off is not reported as a failure;
    # the outcome is reported through the EJECTED / NOT_EJECTED marker line.
    script = (
        'set -eu\n'
        'sync\n'
        'for p in "$1"[0-9]* "$1"p[0-9]*; do umount "$p" 2>/dev/null || true; done\n'
        'if command -v eject >/dev/null 2>&1 && eject "$1" 2>/dev/null; then echo EJECTED; exit 0; fi\n'
        'if command -v udisksctl >/dev/null 2>&1 && udisksctl power-off -b "$1" 2>/dev/null; '
        'then echo EJECTED; exit 0; fi\n'
        'echo NOT_EJECTED\n'
        'exit 0\n'
    )
    seen = []

    def watch(line):
        seen.append(line.strip())
        log(line)

    try:
        priv.run_script(script, watch, args=[f"/dev/{dev_name}"])
    except Exception as e:
        log(f"Warning: could not run the eject step: {e}")
        return False
    return "EJECTED" in seen


def report_eject(ejected, log, skipped=False):
    if skipped:
        log("The drive was left connected, as requested. Eject it before unplugging.")
    elif ejected:
        log("Drive ejected — you can unplug it now.")
    else:
        log("Could not eject automatically. Eject the drive from the file manager before unplugging it.")


# Root scripts that write the image. Values arrive as "$1".."$n" (never pasted into the
# text). "$4" is a flag file: the app creates it to ask for a cancel, and the loop below
# (which polls it once a second) then stops dd and prints WRITE_CANCELED.
MACOS_RAW_SCRIPT = (
    'set -eu\n'
    'dd if="$1" of="$2" bs="$3" &\n'
    'pid=$!\n'
    'canceled=0\n'
    # BSD dd has no status=progress: it prints the byte count when it receives
    # SIGINFO, so ask for it once a second until the copy ends.
    'while kill -0 "$pid" 2>/dev/null; do\n'
    '  if [ -e "$4" ]; then kill "$pid" 2>/dev/null || true; canceled=1; break; fi\n'
    '  kill -INFO "$pid" 2>/dev/null || true\n'
    '  sleep 1\n'
    'done\n'
    'if [ "$canceled" = 1 ]; then wait "$pid" 2>/dev/null || true; echo WRITE_CANCELED; exit 0; fi\n'
    'wait "$pid"\n'
    'sync\n'
)

# "$5" is "direct" (add oflag=direct) or "buffered"; the caller decides, the text never changes.
LINUX_RAW_SCRIPT = (
    'set -eu\n'
    'for p in "$2"[0-9]* "$2"p[0-9]*; do umount "$p" 2>/dev/null || true; done\n'
    'if [ "$5" = direct ]; then\n'
    '  dd if="$1" of="$2" bs="$3" conv=fsync status=progress oflag=direct &\n'
    'else\n'
    '  dd if="$1" of="$2" bs="$3" conv=fsync status=progress &\n'
    'fi\n'
    'pid=$!\n'
    'canceled=0\n'
    'while kill -0 "$pid" 2>/dev/null; do\n'
    '  if [ -e "$4" ]; then kill "$pid" 2>/dev/null || true; canceled=1; break; fi\n'
    '  sleep 1\n'
    'done\n'
    'if [ "$canceled" = 1 ]; then wait "$pid" 2>/dev/null || true; echo WRITE_CANCELED; exit 0; fi\n'
    'wait "$pid"\n'
    'sync\n'
)


def write_raw_image(priv, script, base_args, log, total, progress, cancel_event, extra_args=()):
    """Run a root write script (MACOS_RAW_SCRIPT / LINUX_RAW_SCRIPT). True if it stopped on request.

    The script runs as root, so the app cannot signal it; `cancel_flag` gives it a file to
    watch instead. `base_args` are "$1".."$3", the flag path becomes "$4", then `extra_args`.
    """
    state = {"canceled": False}
    dd_log = make_dd_log(log, total, progress)

    def watch(line):
        if line.strip() == RAW_CANCELED_MARKER:
            state["canceled"] = True
            log("The write was stopped at your request.")
            return
        dd_log(line)

    with cancel_flag(cancel_event) as flag:
        priv.run_script(script, watch, args=list(base_args) + [flag] + list(extra_args))
    return state["canceled"]


def macos_write_raw(iso_path, dev, log, priv, progress=None, cancel_event=None, eject=True):
    """Write the ISO byte-for-byte to the whole disk (Linux and other hybrid ISOs)."""
    validate_hybrid_iso(iso_path)
    check_canceled(cancel_event)
    log(f"Unmounting /dev/{dev}...")
    run_cmd(["diskutil", "unmountDisk", f"/dev/{dev}"], log, timeout=120)
    log(f"Writing the ISO to /dev/{dev} (administrator privileges required). "
        "This can take several minutes.")
    total = os.path.getsize(iso_path)
    # /dev/rdiskN (raw node) is several times faster than /dev/diskN.
    canceled = write_raw_image(priv, MACOS_RAW_SCRIPT,
                               [iso_path, f"/dev/r{dev}", RAW_WRITE_BLOCK["mac"]],
                               log, total, progress, cancel_event)
    if canceled:
        log("Canceled. The drive holds a partial image and is unusable until written again.")
        run_cmd(["diskutil", "unmountDisk", f"/dev/{dev}"], log, check=False, timeout=120)
        raise OperationCanceled("Canceled by the user.")
    if progress:
        progress(total, total, "Written")
    verify_raw_write(iso_path, f"/dev/r{dev}", log, priv, progress, cancel_event)
    log("Note: macOS cannot read Linux (ISO 9660/ext) images, so this drive will not show up in "
        "Finder, and macOS may say the disk is 'not readable' — click Ignore, never Initialize. "
        "That is normal; the content was just verified byte-for-byte.")
    ejected = macos_eject(dev, log) if eject else None
    log("Done! The USB drive is ready to boot.")
    report_eject(ejected, log, skipped=not eject)
    return ejected


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


LSBLK_COLUMN_SETS = (
    # Richest first; older util-linux rejects unknown columns, so fall back step by step.
    "NAME,SIZE,TYPE,RM,TRAN,SERIAL,WWN,MODEL,VENDOR,FSTYPE,LABEL,MOUNTPOINT,FSUSED",
    "NAME,SIZE,TYPE,RM,TRAN,SERIAL,WWN,MODEL,VENDOR,FSTYPE,LABEL,MOUNTPOINT",
    "NAME,SIZE,TYPE,RM,TRAN",
)


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def linux_lsblk_disks():
    """`lsblk -J` as a list of top-level devices, using the richest column set this lsblk supports."""
    last_error = None
    for columns in LSBLK_COLUMN_SETS:
        try:
            out = subprocess.check_output(["lsblk", "-J", "-b", "-o", columns], text=True,
                                          stderr=subprocess.DEVNULL, timeout=30)
            return json.loads(out).get("blockdevices", [])
        except Exception as e:
            last_error = e
    raise last_error


def linux_describe_disk(dev):
    """(model, volumes, identity) from one lsblk disk node. volumes is None without partition info."""
    try:
        return _linux_describe_disk(dev)
    except Exception as e:  # descriptive only: never let it change which disks are offered
        audit(f"Could not describe {dev.get('name')} ({type(e).__name__})", logging.WARNING)
        return "", None, ()


def _linux_describe_disk(dev):
    vendor = (dev.get("vendor") or "").strip()
    product = (dev.get("model") or "").strip()
    model = f"{vendor} {product}".strip() if vendor.lower() not in product.lower() else product
    identity = make_identity(serial=dev.get("serial"), wwn=dev.get("wwn"), model=model)
    if "fstype" not in dev:
        return model, None, identity  # this lsblk is too old to report filesystems
    nodes = [c for c in dev.get("children") or [] if c.get("type") == "part"]
    if dev.get("fstype"):
        nodes.append(dev)  # a filesystem written straight onto the disk, with no partition table
    volumes = []
    for node in nodes:
        mountpoint = node.get("mountpoint") or None
        used = _as_int(node.get("fsused"))
        if used is None:
            used = _used_bytes(mountpoint)
        volumes.append({
            "name": node.get("label") or node.get("name") or "",
            "filesystem": node.get("fstype") or "",
            "size": _as_int(node.get("size")) or 0,
            "used": used,
            "mountpoint": mountpoint,
        })
    return model, volumes, identity


def linux_get_external_disks():
    root_disk = linux_root_disk()
    unsafe_disks = linux_disks_holding_critical_mounts()
    if root_disk:
        unsafe_disks.add(root_disk)
    disks = []
    if shutil.which("lsblk"):
        try:
            for dev in linux_lsblk_disks():
                if dev.get("type") != "disk":
                    continue
                name = dev.get("name")
                if not name or not LINUX_DEVICE_RE.fullmatch(name):
                    continue
                if name in unsafe_disks:
                    audit(f"Hiding {name}: it hosts the system or a critical mountpoint")
                    continue
                if name.startswith(("loop", "zram", "dm-")):
                    continue
                if (dev.get("tran") or "").lower() != "usb":
                    continue  # only USB drives are offered
                size = int(dev.get("size") or 0)
                model, volumes, identity = linux_describe_disk(dev)
                disks.append({"id": name, "size": size, "model": model, "volumes": volumes,
                              "identity": identity,
                              "label": build_disk_label(f"/dev/{name}", model, size, volumes)})
            return disks
        except Exception as e:
            audit(f"lsblk enumeration failed ({type(e).__name__}); using /sys/block fallback",
                  logging.WARNING)

    # Fallback using /sys/block directly (works even without lsblk -J support)
    for name in sorted(os.listdir("/sys/block")):
        if name.startswith(("loop", "ram", "dm-", "sr", "zram")):
            continue
        if not LINUX_DEVICE_RE.fullmatch(name) or name in unsafe_disks:
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
        model = ""
        try:
            parts = []
            for attr in ("vendor", "model"):
                with open(f"/sys/block/{name}/device/{attr}") as fh:
                    parts.append(fh.read().strip())
            model = " ".join(p for p in parts if p)
        except Exception:  # noqa: S110 - purely descriptive, the disk is listed either way
            pass
        # No partition information here (volumes=None): the confirmation says so and treats it as high risk.
        disks.append({"id": name, "size": size, "model": model, "volumes": None,
                      "identity": make_identity(model=model),
                      "label": build_disk_label(f"/dev/{name}", model, size, None)})
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


def linux_unmount_partitions(dev, log, priv):
    """Best effort: unmount every partition of `dev` (used after a cancel)."""
    script = (
        'set -eu\n'
        'for p in "$1"[0-9]* "$1"p[0-9]*; do umount "$p" 2>/dev/null || true; done\n'
    )
    try:
        priv.run_script(script, log, args=[dev])
    except Exception as e:
        log(f"Warning: could not unmount the drive: {e}")


def linux_write_raw(iso_path, dev_name, log, priv, progress=None, cancel_event=None, eject=True):
    """Write the ISO byte-for-byte to the whole disk (Linux and other hybrid ISOs)."""
    validate_hybrid_iso(iso_path)
    check_canceled(cancel_event)
    dev = f"/dev/{dev_name}"
    total = os.path.getsize(iso_path)
    # O_DIRECT bypasses the page cache (steadier speed, honest progress), but needs every
    # write block aligned; only use it when the image size is a multiple of the alignment.
    direct = "direct" if total % DIRECT_IO_ALIGNMENT == 0 else "buffered"
    log(f"Writing the ISO to {dev} (administrator privileges required)...")
    # Values arrive as "$1".."$5"; the glob expands only after the quoted device prefix.
    canceled = write_raw_image(priv, LINUX_RAW_SCRIPT,
                               [iso_path, dev, RAW_WRITE_BLOCK["linux"]],
                               log, total, progress, cancel_event, extra_args=[direct])
    if canceled:
        log("Canceled. The drive holds a partial image and is unusable until written again.")
        linux_unmount_partitions(dev, log, priv)
        raise OperationCanceled("Canceled by the user.")
    if progress:
        progress(total, total, "Written")
    verify_raw_write(iso_path, dev, log, priv, progress, cancel_event)
    ejected = linux_eject(dev_name, log, priv) if eject else None
    log("Done! The USB drive is ready to boot.")
    report_eject(ejected, log, skipped=not eject)
    return ejected


def linux_build_usb(iso_path, dev_name, log, priv, progress=None, cancel_event=None, eject=True):
    check_canceled(cancel_event)
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
        # A desktop session may auto-mount partitions of the drive (before and after
        # we change them); unmount them so wipefs/mkfs/mount are not blocked.
        'umount_parts() { for p in "$DEV"[0-9]* "$DEV"p[0-9]*; do umount "$p" 2>/dev/null || true; done; }\n'
        'umount_parts\n'
        'wipefs -a "$DEV"\n'
        'parted -s "$DEV" mklabel gpt\n'
        'parted -s "$DEV" mkpart primary fat32 1MiB 100%\n'
        'parted -s "$DEV" set 1 esp on\n'
        'partprobe "$DEV"\n'
        # Wait for udev to create the new partition node instead of sleeping blindly.
        'udevadm settle --timeout=15 2>/dev/null || sleep 2\n'
        'i=0\n'
        'while [ ! -b "$PART" ] && [ "$i" -lt 20 ]; do sleep 1; i=$((i + 1)); done\n'
        '[ -b "$PART" ] || { echo "The new partition $PART did not appear." >&2; exit 1; }\n'
        'umount_parts\n'
        f'mkfs.vfat -F 32 -n {VOL_NAME} "$PART"\n'
        'udevadm settle --timeout=15 2>/dev/null || true\n'
        'umount_parts\n'
        'mount -o loop,ro,uid="${OWNER%%:*}",gid="${OWNER##*:}" "$ISO" "$ISO_MNT"\n'
        'mount -o uid="${OWNER%%:*}",gid="${OWNER##*:}" "$PART" "$USB_MNT"\n'
    )

    try:
        priv.run_script(prep_script, log,
                        args=[dev, part, iso_path, iso_mount, usb_mount, f"{uid}:{gid}"])
        check_canceled(cancel_event)

        def reopen():
            log("Remounting the drive read-only to read it back from the device...")
            remount = (
                'set -eu\n'
                'sync\n'
                'umount "$2"\n'
                '{ echo 3 > /proc/sys/vm/drop_caches; } 2>/dev/null || true\n'
                'mount -o ro,uid="${3%%:*}",gid="${3##*:}" "$1" "$2"\n'
            )
            priv.run_script(remount, log, args=[part, usb_mount, f"{uid}:{gid}"])
            return usb_mount

        copy_windows_payload(
            iso_mount, usb_mount, log, progress,
            "wimlib-imagex not found. Install it via your package manager "
            "(e.g. 'wimtools' on Debian/Ubuntu, 'wimlib-utils' on Fedora, 'wimlib' on "
            "Arch/openSUSE) or use the 'Install missing dependencies' button on tab 2.",
            reopen=reopen, cancel_event=cancel_event)
    except OperationCanceled:
        log("Canceled. The drive is left incomplete and unusable.")
        raise
    finally:
        log("Unmounting...")
        cleanup_script = 'set -eu\numount "$1" || true\numount "$2" || true\n'
        try:
            priv.run_script(cleanup_script, log, args=[usb_mount, iso_mount])
        except Exception as cleanup_err:
            log(f"Warning: cleanup failed: {cleanup_err}")
        for d in (iso_mount, usb_mount):
            try:
                os.rmdir(d)
            except OSError:
                pass

    ejected = linux_eject(dev_name, log, priv) if eject else None
    log("Done! The USB drive is ready to install Windows 11.")
    report_eject(ejected, log, skipped=not eject)
    return ejected


# ============================================================
# Platform dispatch
# ============================================================
def get_external_disks():
    return macos_get_external_disks() if IS_MAC else linux_get_external_disks()


def reverify_target_disk(dev, expected_size, log, expected_identity=None):
    """Re-check, immediately before erasing, that `dev` is still the disk we listed.

    Device names are recycled by the operating system: if a drive is unplugged and
    another plugged in between listing and writing, '/dev/sdb' can point somewhere
    else entirely. Re-enumerating here closes that window.
    """
    validate_device_name(dev)
    # The identity the user confirmed: passed explicitly or pinned by the UI (see pin_target_identity).
    expected_identity = expected_identity or _pinned_identities.pop(dev, None)
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
    changed = identity_mismatch(expected_identity, current[dev].get("identity"))
    if changed:
        audit(f"ABORTED: {dev} identity changed ({changed})", logging.ERROR)
        raise RuntimeError(
            f"Aborted for safety: /dev/{dev} no longer looks like the drive you confirmed "
            f"({changed}).\n\n"
            "This means the name now points to a different device. Refresh the list "
            "and select the drive again."
        )
    log(f"Safety re-check passed: /dev/{dev} is still the same external drive "
        f"({human_size(actual_size)}).")


def hash_iso_for_audit(iso_path, log, progress, cancel_event):
    """SHA-256 of the ISO for the audit trail. Runs in the worker thread, before the drive is touched."""
    log("Hashing the ISO (recorded in the audit log)...")
    if progress:
        progress(0, 0, "Hashing the ISO...")
    try:
        digest = sha256_file(iso_path, cancel_event)
    except OSError as e:
        raise RuntimeError(f"Could not read the ISO file: {e.strerror or type(e).__name__}. "
                           "The drive was not modified.") from None
    log(f"ISO SHA-256: {digest}")
    return digest


def build_usb(iso_path, dev, log, priv, expected_size=None, mode=MODE_WINDOWS, progress=None,
              cancel_event=None, eject=True):
    if mode not in (MODE_WINDOWS, MODE_LINUX):
        raise ValueError(f"Unknown image type: {mode!r}")
    iso_path = validate_iso_path(iso_path)
    validate_device_name(dev)
    if mode == MODE_LINUX:
        validate_hybrid_iso(iso_path)  # fail before anything is touched
    iso_sha = hash_iso_for_audit(iso_path, log, progress, cancel_event)
    reverify_target_disk(dev, expected_size, log)
    audit(f"DESTRUCTIVE OPERATION START: erasing /dev/{dev} and writing {mode} image "
          f"(iso sha256={iso_sha}, size={os.path.getsize(iso_path)})")
    try:
        with prevent_sleep(log):
            if mode == MODE_LINUX:
                if IS_MAC:
                    ejected = macos_write_raw(iso_path, dev, log, priv, progress, cancel_event, eject)
                else:
                    ejected = linux_write_raw(iso_path, dev, log, priv, progress, cancel_event, eject)
            elif IS_MAC:
                ejected = macos_build_usb(iso_path, dev, log, progress=progress, cancel_event=cancel_event,
                                         eject=eject)
            else:
                ejected = linux_build_usb(iso_path, dev, log, priv, progress, cancel_event, eject)
    except OperationCanceled:
        audit(f"DESTRUCTIVE OPERATION CANCELED by the user on /dev/{dev}; the drive was left unusable",
              logging.WARNING)
        raise
    except Exception as e:
        audit(f"DESTRUCTIVE OPERATION FAILED on /dev/{dev}: {type(e).__name__}", logging.ERROR)
        raise
    audit(f"DESTRUCTIVE OPERATION COMPLETED on /dev/{dev} (ejected={bool(ejected)})")
    return bool(ejected)


def get_missing_dependencies(mode=MODE_WINDOWS):
    if mode == MODE_LINUX:
        return [] if shutil.which("dd") else ["dd"]  # raw write needs nothing else
    if IS_MAC:
        return [] if shutil.which("wimlib-imagex") else ["wimlib-imagex"]
    return [t for t in LINUX_REQUIRED_TOOLS if not shutil.which(t)]


# ============================================================
# Download
# ============================================================
class _DownloadCanceled(RuntimeError):
    """The user canceled; the partial file is kept so the download can be resumed."""


class _DownloadInterrupted(RuntimeError):
    """The connection kept failing; the partial file is kept so the download can be resumed."""


class _RestartDownload(Exception):  # noqa: N818 - internal control flow, not an error
    """The server's answer cannot extend the partial file; it was discarded, start from zero."""


class DownloadThread(threading.Thread):
    """Downloads one file over HTTPS, resuming and retrying where that is safe.

    * The data goes to `<dest>.part` (owner-only). On cancel or a network error the part
      file is KEPT; the next run resumes it with a Range request. The SHA-256 always
      covers the whole file (the bytes already on disk are hashed first).
    * A resume is only attempted when the first response carried a strong ETag or a
      Last-Modified date (saved beside the part file) and is sent with If-Range, so a file
      that changed on the server is downloaded again from scratch instead of being
      stitched together. A server that ignores Range also leads to a clean restart.
    * Transient errors are retried (DOWNLOAD_MAX_ATTEMPTS, with backoff).
    * A checksum mismatch or an unexpected failure deletes the part file.
    """

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

    # ---------- partial-file bookkeeping ----------
    def _meta_path(self):
        return self.dest_path + ".part.meta"

    def _read_validator(self):
        try:
            with open(self._meta_path(), encoding="utf-8") as fh:
                value = json.load(fh).get("validator")
        except (OSError, ValueError, AttributeError):
            return None
        return value if isinstance(value, str) and value else None

    def _write_validator(self, validator):
        try:
            fd = os.open(self._meta_path(), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, PRIVATE_FILE_MODE)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"validator": validator}, fh)
        except OSError:
            pass  # without it the next run simply restarts instead of resuming

    def _discard_partial(self, tmp_path):
        for path in (tmp_path, self._meta_path()):
            try:
                os.remove(path)
            except OSError:
                pass

    @staticmethod
    def _strong_validator(headers):
        etag = headers.get("ETag")
        if etag and not etag.startswith("W/"):
            return etag
        return headers.get("Last-Modified") or None

    def _check_cancel(self):
        if self.cancel_event.is_set():
            raise _DownloadCanceled(
                "Download canceled by user. The partial file was kept, so downloading the same "
                "file again to the same location resumes where it stopped.")

    def _hash_part(self, tmp_path, digest, size):
        remaining = size
        with open(tmp_path, "rb") as fh:
            while remaining > 0:
                self._check_cancel()
                chunk = fh.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    raise OSError("the partial file is shorter than expected")
                digest.update(chunk)
                remaining -= len(chunk)

    def _open(self, offset, validator):
        headers = {"User-Agent": "Mozilla/5.0"}
        if offset:
            headers["Range"] = f"bytes={offset}-"
            headers["If-Range"] = validator
        # noqa S310 below: the scheme is restricted to HTTPS by validate_download_url()
        # and re-checked after redirects; file:// and friends cannot reach here.
        req = urllib.request.Request(self.url, headers=headers)  # noqa: S310
        return urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT_SECONDS)  # noqa: S310

    # ---------- one connection ----------
    def _attempt(self, tmp_path):
        """Download (or resume) once. Returns (bytes, sha256, expected). Raises on any problem."""
        offset = os.path.getsize(tmp_path) if os.path.isfile(tmp_path) else 0
        validator = self._read_validator() if offset else None
        if offset and not validator:
            self._discard_partial(tmp_path)  # nothing proves it belongs to this file
            offset = 0
        digest = hashlib.sha256()
        if offset:
            self._hash_part(tmp_path, digest, offset)
        try:
            resp = self._open(offset, validator)
        except urllib.error.HTTPError as e:
            if e.code != 416 or not offset:
                raise
            # Range not satisfiable: the part file does not fit the file on the server.
            self._discard_partial(tmp_path)
            offset, digest = 0, hashlib.sha256()
            resp = self._open(0, None)

        with resp:
            # urlopen follows redirects; make sure we were not downgraded to
            # an unencrypted connection along the way.
            final_url = resp.geturl()
            if final_url != self.url:
                validate_download_url(final_url)
                audit(f"Download redirected to host: {urllib.parse.urlparse(final_url).hostname}")
            status = getattr(resp, "status", None) or resp.getcode()
            length = int(resp.headers.get("Content-Length", 0) or 0)
            if offset and status == 206:
                m = re.match(r"bytes (\d+)-\d+/(\d+|\*)", resp.headers.get("Content-Range", ""))
                if not m or int(m.group(1)) != offset:
                    self._discard_partial(tmp_path)
                    raise _RestartDownload()
                total = int(m.group(2)) if m.group(2).isdigit() else offset + length
                audit(f"Download resumed at {human_size(offset)}")
            else:
                if offset:  # the server ignored Range (or the file changed): start over cleanly
                    audit("Server did not honour the resume request; restarting the download")
                    offset, digest = 0, hashlib.sha256()
                    self._discard_partial(tmp_path)
                total = length
                fresh_validator = self._strong_validator(resp.headers)
                if fresh_validator:
                    self._write_validator(fresh_validator)
                else:
                    try:
                        os.remove(self._meta_path())  # never leave a stale validator behind
                    except OSError:
                        pass

            downloaded = offset
            start = time.time()
            # Create the partial file readable only by its owner.
            flags = os.O_CREAT | os.O_WRONLY | (os.O_APPEND if offset else os.O_TRUNC)
            fd = os.open(tmp_path, flags, PRIVATE_FILE_MODE)
            with os.fdopen(fd, "ab" if offset else "wb") as f:
                while True:
                    self._check_cancel()
                    chunk = resp.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    f.write(chunk)
                    digest.update(chunk)
                    downloaded += len(chunk)
                    elapsed = max(time.time() - start, 0.001)
                    self.progress_cb(downloaded, total, (downloaded - offset) / elapsed)
        if total and downloaded < total:
            raise _DownloadInterrupted(
                f"Incomplete download: received {human_size(downloaded)} of {human_size(total)}.")
        if total and downloaded > total:
            self._discard_partial(tmp_path)
            raise RuntimeError("The server sent more data than announced. The file was discarded.")
        sha256 = digest.hexdigest()
        expected = (self.expected_sha256 or "").strip().lower()
        if expected and expected != sha256:
            audit("Downloaded ISO FAILED SHA-256 verification", logging.ERROR)
            self._discard_partial(tmp_path)
            raise RuntimeError(
                "SHA-256 verification FAILED — the downloaded file is NOT the one you "
                "expected and was discarded.\n\n"
                f"Expected: {expected}\nReceived: {sha256}\n\n"
                "Do not use this file. Download it again from the official Microsoft page."
            )
        os.replace(tmp_path, self.dest_path)
        try:
            os.remove(self._meta_path())
        except OSError:
            pass
        return downloaded, sha256, expected

    # ---------- retry loop ----------
    def run(self):
        tmp_path = self.dest_path + ".part"
        try:
            # The URL was validated before this thread started; re-check here so
            # the guarantee holds even if this class is reused elsewhere.
            validate_download_url(self.url)
            attempt = 0
            restarts = 0
            while True:
                attempt += 1
                try:
                    downloaded, sha256, expected = self._attempt(tmp_path)
                    break
                except _RestartDownload:
                    restarts += 1
                    if restarts > 2:
                        raise RuntimeError("The server keeps answering the resume request with "
                                           "unusable data. Try the download again.") from None
                    attempt -= 1
                    continue
                except urllib.error.HTTPError as e:
                    if e.code < 500 and e.code not in (408, 429):
                        raise _DownloadInterrupted(
                            f"The server refused the download (HTTP {e.code}). If the link has "
                            "expired, copy a fresh one from the Microsoft page; the partial file "
                            "is kept and will be resumed if it is the same file.") from None
                    problem = f"HTTP {e.code}"
                except (urllib.error.URLError, OSError, http.client.HTTPException,
                        _DownloadInterrupted) as e:
                    if isinstance(e, urllib.error.URLError) and e.reason is not None:
                        problem = str(e.reason)
                    else:
                        problem = str(e) or type(e).__name__
                if attempt >= DOWNLOAD_MAX_ATTEMPTS:
                    raise _DownloadInterrupted(
                        f"The download was interrupted ({problem}) and could not be continued after "
                        f"{attempt} attempts. The partial file was kept; start the download again "
                        "to resume it.")
                delay = DOWNLOAD_BACKOFF_SECONDS[min(attempt - 1, len(DOWNLOAD_BACKOFF_SECONDS) - 1)]
                audit(f"Download attempt {attempt} failed; retrying in {delay}s")
                if self.cancel_event.wait(delay):
                    self._check_cancel()
            audit(f"ISO downloaded ({human_size(downloaded)}) sha256={sha256}"
                  + (" [verified against expected value]" if expected else " [not verified]"))
            self.done_cb(self.dest_path, sha256, bool(expected))
        except (_DownloadCanceled, _DownloadInterrupted) as e:
            self.error_cb(str(e))  # the partial file stays on disk for a later resume
        except Exception as e:
            self._discard_partial(tmp_path)
            self.error_cb(str(e))


# ============================================================
# GUI
# ============================================================
def set_macos_app_name(name):
    """Make the macOS menu bar and Dock say `name` instead of "Python".

    The name comes from the running bundle's Info.plist (CFBundleName), which for a
    script is Python.app's. Overriding it in memory before the first window is created
    needs no extra packages (plain ctypes into the Objective-C runtime) and changes
    nothing on disk. Purely cosmetic, so any failure is ignored.
    """
    if not IS_MAC:
        return
    try:
        import ctypes
        import ctypes.util

        objc = ctypes.cdll.LoadLibrary(ctypes.util.find_library("objc"))
        objc.objc_getClass.restype = ctypes.c_void_p
        objc.objc_getClass.argtypes = [ctypes.c_char_p]
        objc.sel_registerName.restype = ctypes.c_void_p
        objc.sel_registerName.argtypes = [ctypes.c_char_p]

        def send(obj, selector, *args):
            fn = objc.objc_msgSend
            fn.restype = ctypes.c_void_p
            fn.argtypes = [ctypes.c_void_p, ctypes.c_void_p] + [ctypes.c_void_p] * len(args)
            return fn(obj, objc.sel_registerName(selector.encode()), *args)

        def nsstring(text):
            return send(objc.objc_getClass(b"NSString"), "stringWithUTF8String:", text.encode())

        bundle = send(objc.objc_getClass(b"NSBundle"), "mainBundle")
        info = send(bundle, "infoDictionary")
        if info:
            for key in ("CFBundleName", "CFBundleDisplayName"):
                send(info, "setObject:forKey:", nsstring(name), nsstring(key))
        send(send(objc.objc_getClass(b"NSProcessInfo"), "processInfo"), "setProcessName:", nsstring(name))
    except Exception:  # noqa: S110 - cosmetic only; never block the app over a label
        pass


_TkBase = tk.Tk if tk else object  # lets the module import (engine, CLI) without Tk


class App(_TkBase):
    def __init__(self):
        if tk is None:
            raise RuntimeError(TK_MISSING_MESSAGE)
        set_macos_app_name(APP_NAME)  # must run before the first window exists
        super().__init__(className=APP_NAME)
        self.title("EPMA Windows 11 Creator USB")
        self.geometry("760x700")
        self.iso_path = tk.StringVar(value="")
        self.cancel_event = threading.Event()
        self.create_cancel_event = threading.Event()  # cancels the USB creation (not the download)
        self.disks = []
        self.priv = PrivilegeHelper(self)
        self._log_lock = threading.Lock()
        self._log_pending = []
        self._sha_job = 0  # identifies the running SHA-256 calculation, so stale results are ignored
        self._build_ui()
        self.after(LOG_FLUSH_MS, self._log_tick)

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

        # Integrity check of the selected ISO; shown once an ISO is selected (see set_iso).
        self.iso_check_frame = ttk.LabelFrame(f, text="Verify the selected ISO (SHA-256)")
        ttk.Label(
            self.iso_check_frame,
            text="Expected checksum (optional) — paste the hash or the whole line from SHA256SUMS:",
        ).pack(anchor="w", padx=8, pady=(6, 0))
        self.iso_sha_entry = ttk.Entry(self.iso_check_frame)
        self.iso_sha_entry.pack(fill="x", padx=8, pady=(2, 4))
        sha_row = ttk.Frame(self.iso_check_frame)
        sha_row.pack(fill="x", padx=8)
        self.iso_sha_btn = ttk.Button(sha_row, text="Calculate SHA-256", command=self.calculate_iso_sha256)
        self.iso_sha_btn.pack(side="left")
        self.iso_sha_progress = ttk.Progressbar(sha_row, orient="horizontal", mode="determinate")
        self.iso_sha_progress.pack(side="left", fill="x", expand=True, padx=(8, 0))
        self.iso_sha_label = ttk.Label(self.iso_check_frame, text="", wraplength=680, justify="left")
        self.iso_sha_label.pack(anchor="w", padx=8)
        self.iso_sha_result = ttk.Label(self.iso_check_frame, text="", wraplength=680, justify="left")
        self.iso_sha_result.pack(anchor="w", padx=8, pady=(0, 6))

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

        create_row = ttk.Frame(f)
        create_row.pack(anchor="w", padx=10, pady=10)
        self.create_btn = ttk.Button(
            create_row, text="Create Bootable USB Drive", command=self.start_create_usb, state="disabled"
        )
        self.create_btn.pack(side="left")
        self.cancel_create_btn = ttk.Button(
            create_row, text="Cancel", command=self.cancel_create_usb, state="disabled"
        )
        self.cancel_create_btn.pack(side="left", padx=(8, 0))

        self.create_progress = ttk.Progressbar(f, orient="horizontal", mode="determinate")
        self.create_progress.pack(fill="x", padx=10, pady=(0, 2))
        self.create_progress_label = ttk.Label(f, text="")
        self.create_progress_label.pack(anchor="w", padx=10)
        self._create_started = None
        self._create_last_ui = 0.0
        self._create_stage = None
        self._create_stage_base = 0

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
                    run_cmd(["brew", "install", "wimlib"], self.log_threadsafe)
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
                    self.log_threadsafe(f"About to run as administrator: {script}")
                    audit(f"Installing dependencies via {mgr}: {', '.join(missing)}")
                    self.priv.run_script("set -eu\n" + script, self.log_threadsafe)
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
        # Only a default: the user can still switch the image type by hand. The content of
        # the ISO decides; the file name is only the fallback when it cannot be read.
        kind = detect_iso_kind(path)
        if kind == ISO_KIND_UNKNOWN:
            kind = MODE_WINDOWS if "win" in os.path.basename(path).lower() else MODE_LINUX
            how = "from the file name (the content could not be identified)"
        else:
            how = "from the content of the ISO"
        self.mode_var.set(MODE_WINDOWS if kind == ISO_KIND_WINDOWS else MODE_LINUX)
        self.log(f"Image type preselected {how}: "
                 f"{'Windows 11' if kind == ISO_KIND_WINDOWS else 'Linux / other hybrid ISO'}.")
        self.on_mode_change()
        self._reset_iso_sha()
        self.iso_check_frame.pack(fill="x", padx=10, pady=(0, 10))

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

    # ---------- log box ----------
    # Workers can emit thousands of lines (rsync -v); inserting each one through after(0)
    # floods the Tk event loop. They append to a queue instead, drained in one insert every
    # LOG_FLUSH_MS. log() (main thread) appends and drains at once, so order is preserved.
    def log_threadsafe(self, msg):
        """Queue a log line from ANY thread; it appears within LOG_FLUSH_MS."""
        with self._log_lock:
            self._log_pending.append(str(msg))
            if len(self._log_pending) > 4 * LOG_MAX_LINES:  # nobody can read more than the box keeps
                del self._log_pending[:2 * LOG_MAX_LINES]

    def log(self, msg):
        """Write a log line. Main thread only; use log_threadsafe() from workers."""
        self.log_threadsafe(msg)
        self._flush_log()

    def _flush_log(self):
        with self._log_lock:
            lines, self._log_pending = self._log_pending, []
        if not lines:
            return
        lines = lines[-LOG_MAX_LINES:]
        self.log_text.config(state="normal")
        self.log_text.insert("end", "\n".join(lines) + "\n")
        total = int(self.log_text.index("end-1c").split(".")[0])
        if total > LOG_MAX_LINES:
            self.log_text.delete("1.0", f"{total - LOG_MAX_LINES + 1}.0")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def _log_tick(self):
        try:
            self._flush_log()
        except tk.TclError:
            return  # the window is gone
        self.after(LOG_FLUSH_MS, self._log_tick)

    # ---------- SHA-256 of the selected ISO ----------
    def _reset_iso_sha(self):
        self._sha_job += 1  # invalidates any calculation still running for the previous file
        self.iso_sha_btn.config(state="normal")
        self.iso_sha_progress.config(value=0)
        self.iso_sha_label.config(text="")
        self.iso_sha_result.config(text="", foreground="")

    def calculate_iso_sha256(self):
        path = self.iso_path.get()
        if not path or not os.path.isfile(path):
            self.iso_sha_result.config(text="Select an ISO file first.", foreground="#c62828")
            return
        try:
            expected = parse_expected_sha256(self.iso_sha_entry.get(), os.path.basename(path))
        except ValueError as e:
            self.iso_sha_result.config(text=str(e), foreground="#c62828")
            return
        self._sha_job += 1
        job = self._sha_job
        self.iso_sha_btn.config(state="disabled")
        self.iso_sha_progress.config(value=0)
        self.iso_sha_result.config(text="", foreground="")
        self.iso_sha_label.config(text="Calculating...")
        self.log(f"Calculating SHA-256 of {os.path.basename(path)}...")
        last = [0.0]

        def progress(done, total):
            now = time.time()
            if done < total and now - last[0] < 0.1:
                return  # ~10 UI updates per second is plenty
            last[0] = now
            self.after(0, self._on_iso_sha_progress, job, done, total)

        def worker():
            try:
                digest = compute_sha256(path, progress)
                self.after(0, self._on_iso_sha_done, job, path, digest, expected)
            except Exception as e:  # noqa: BLE001 - reported in the UI, never lost in the thread
                self.after(0, self._on_iso_sha_error, job, e)

        threading.Thread(target=worker, daemon=True).start()

    def _on_iso_sha_progress(self, job, done, total):
        if job != self._sha_job:
            return
        pct = done / total * 100 if total else 0
        self.iso_sha_progress.config(value=pct)
        self.iso_sha_label.config(text=f"Calculating... {pct:.0f}% ({human_size(done)} / {human_size(total)})")

    def _on_iso_sha_done(self, job, path, digest, expected):
        if job != self._sha_job:
            return
        self.iso_sha_btn.config(state="normal")
        self.iso_sha_progress.config(value=100)
        self.iso_sha_label.config(text=f"SHA-256: {digest}")
        if expected is None:
            outcome, text, color = "unverified", "No expected checksum given: compare the value above yourself.", ""
        elif digest == expected:
            outcome, text, color = "match", "MATCH — the file is intact and identical to the published one.", "#1a7f37"
        else:
            outcome, text, color = "mismatch", "MISMATCH — this is NOT the published file. Do not use it.", "#c62828"
            self.log(f"Expected SHA-256: {expected}")
        self.iso_sha_result.config(text=text, foreground=color)
        self.log(f"SHA-256 of {os.path.basename(path)}: {digest}")
        self.log(f"Checksum comparison: {outcome.upper()}")
        audit(f"ISO SHA-256 check result={outcome}", logging.WARNING if outcome == "mismatch" else logging.INFO)

    def _on_iso_sha_error(self, job, exc):
        if job != self._sha_job:
            return
        self.iso_sha_btn.config(state="normal")
        self.iso_sha_label.config(text="")
        self.iso_sha_result.config(text=f"Could not read the file ({type(exc).__name__}).", foreground="#c62828")

    def confirm_erase(self, disk, what):
        """Final confirmation: always shows model, size and contents; high-risk drives also need
        their identifier typed. Returns True to go ahead."""
        level, reasons = assess_disk_risk(disk)
        text = (f"This will PERMANENTLY ERASE all data on /dev/{disk['id']} and write {what} to it.\n\n"
                + describe_disk_for_confirmation(disk))
        audit(f"Erase confirmation shown for /dev/{disk['id']} risk={level}")
        if level == "high":
            ok = ask_typed_confirmation(self, "Confirm erasing this drive", text, disk["id"], reasons)
        else:
            ok = messagebox.askyesno("Final confirmation", text + "\n\nContinue?")
        if not ok:
            audit(f"Erase of /dev/{disk['id']} declined by the user")
        return ok

    def start_create_usb(self):
        disk = self.selected_disk()
        if not disk:
            return
        mode = self.mode_var.get()
        what = "Windows 11" if mode == MODE_WINDOWS else "the selected Linux image"
        if not self.confirm_erase(disk, what):
            return
        # Bind the safety re-check (right before erasing) to exactly the drive that was confirmed.
        pin_target_identity(disk["id"], disk.get("identity"))
        # Writing the drive needs administrator rights (always on Linux; on macOS only for
        # the direct-write mode). Collect and verify the password now, before touching
        # the drive.
        if (IS_LINUX or mode == MODE_LINUX) and not self.priv.authenticate(
                f"Administrator access is required to write /dev/{disk['id']}."):
            self.priv.clear_cached_password()
            self.log("Canceled: administrator password was not provided. The drive was not modified.")
            return
        self.create_btn.config(state="disabled")
        self.create_cancel_event.clear()
        self.cancel_create_btn.config(state="normal")
        self._reset_create_progress()
        iso = self.iso_path.get()
        dev = disk["id"]
        expected_size = disk.get("size")

        def worker():
            try:
                ejected = build_usb(iso, dev, self.log_threadsafe, self.priv,
                          expected_size=expected_size, mode=mode,
                          progress=lambda d, t, s: self.after(0, self._on_create_progress, d, t, s),
                          cancel_event=self.create_cancel_event)
                self.after(0, self._finish_create_progress, True)
                note = ("It was verified against the ISO and ejected — you can unplug it now." if ejected else
                        "It was verified against the ISO, but could not be ejected automatically. "
                        "Eject it from the file manager before unplugging.")
                self.after(0, lambda: messagebox.showinfo(
                    "Done", f"Bootable USB drive created successfully!\n\n{note}"))
            except OperationCanceled:
                # Not an error: the user asked for it. Say clearly what state the drive is in.
                self.after(0, self._finish_create_progress, False, True)
                self.after(0, self.log, "Canceled. The drive was left unusable; create it again before use.")
                self.after(0, lambda: messagebox.showinfo(
                    "Canceled", "The operation was canceled.\n\nThe USB drive was left incomplete and "
                    "unusable. Create it again before using it."))
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
                self.after(0, lambda: self.cancel_create_btn.config(state="disabled"))

        threading.Thread(target=worker, daemon=True).start()

    def cancel_create_usb(self):
        """Ask the running USB creation to stop (after a warning). Safe to call at any time."""
        if self.create_cancel_event.is_set() or str(self.cancel_create_btn.cget("state")) == "disabled":
            return
        if not messagebox.askyesno(
            "Cancel the operation?",
            "Canceling now will leave the USB drive incomplete and UNUSABLE until it is created "
            "again.\n\nDo you really want to cancel?",
            icon="warning",
        ):
            return
        self.create_cancel_event.set()
        self.cancel_create_btn.config(state="disabled")
        self.log("Cancel requested: stopping safely...")
        audit("User requested cancel of the USB creation")

    # ---------- USB creation progress ----------
    def _reset_create_progress(self):
        self._create_started = None
        self._create_last_ui = 0.0
        self._create_stage = None
        self._create_stage_base = 0
        self.create_progress.config(mode="indeterminate", value=0)
        self.create_progress.start(12)
        self.create_progress_label.config(text="Preparing the drive...")

    def _on_create_progress(self, done, total, text):
        now = time.time()
        if not total:
            # Length unknown (e.g. comparing files): show a busy bar with what is going on.
            if str(self.create_progress.cget("mode")) != "indeterminate":
                self.create_progress.config(mode="indeterminate", value=0)
                self.create_progress.start(12)
            self.create_progress_label.config(text=f"{text} (this can take a few minutes)")
            self._create_stage = None
            return
        finished = done >= total
        # Updates can arrive thousands of times (one per copied file); redraw ~5x/s.
        if not finished and now - self._create_last_ui < 0.2:
            return
        self._create_last_ui = now
        if str(self.create_progress.cget("mode")) != "determinate":
            self.create_progress.stop()
            self.create_progress.config(mode="determinate")
        if text != self._create_stage:
            # New stage: measure speed and time left from where this stage began.
            self._create_stage = text
            self._create_started = now
            self._create_stage_base = done
        pct = done / total * 100
        self.create_progress.config(value=pct)
        if finished:
            self.create_progress_label.config(text=f"{text}  100%")
            return
        elapsed = max(now - self._create_started, 0.001)
        speed = (done - self._create_stage_base) / elapsed
        if speed > 0:
            eta = (total - done) / speed
            tail = f" — {human_size(speed)}/s — ~{int(eta // 60)}m{int(eta % 60):02d}s left"
        else:
            tail = " — calculating..."
        self.create_progress_label.config(
            text=f"{text}  {pct:.1f}% — {human_size(done)} / {human_size(total)}{tail}")

    def _finish_create_progress(self, ok, canceled=False):
        self._flush_log()  # show the worker's last lines before the result dialog appears
        self.create_progress.stop()
        self.create_progress.config(mode="determinate", value=100 if ok else 0)
        self.create_progress_label.config(text="Done — 100%" if ok else ("Canceled." if canceled else "Failed."))

    def report_callback_exception(self, exc, val, tb):
        """Tk swallows exceptions raised in button handlers (they only reach stderr).
        Show them, so a broken button never looks like "nothing happened"."""
        self._report_error("Unexpected error", None, val)

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


# ============================================================
# ===== Command line interface =====
#
#   epma-usb-creator                 open the GUI (same as `epma-usb-creator gui`)
#   epma-usb-creator list            list the USB drives that can be written
#   epma-usb-creator detect ISO      windows / linux / unknown
#   epma-usb-creator sha256 ISO      checksum, optionally compared with --expected
#   epma-usb-creator write ...       create the bootable drive
#
# Data goes to stdout; messages, errors and progress go to stderr. Verification
# of the written drive is part of `write` and cannot be switched off.
# ============================================================
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_VERIFY_FAILED = 3     # the drive does not match the ISO, or the checksum differs
EXIT_EJECT_FAILED = 4      # written and verified, but the drive could not be ejected
EXIT_INTERRUPTED = 130     # Ctrl-C

CLI_PROG = "epma-usb-creator"
MODE_AUTO = "auto"
KIND_UNKNOWN = "unknown"
SHA256_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")
# Engine log lines worth showing without --verbose (everything else is command output).
CLI_MILESTONE_RE = re.compile(
    r"warning|error|fail|verif|eject|done!|safety re-check|erasing|writing the iso|copying|"
    r"splitting|mounting|syncing|note:|could not|aborted", re.IGNORECASE)


class CliError(Exception):
    """A failure the command line reports as a plain message with an exit code."""

    def __init__(self, message, code=EXIT_ERROR):
        super().__init__(message)
        self.message = message
        self.code = code


def _emit(stream, text, end="\n"):
    try:
        stream.write(text + end)
    except UnicodeEncodeError:  # e.g. LANG=C: the "—" in disk labels cannot be encoded
        enc = getattr(stream, "encoding", None) or "ascii"
        stream.write((text + end).encode(enc, "replace").decode(enc, "replace"))
    with contextlib.suppress(OSError, ValueError):
        stream.flush()


def _out(text=""):
    _emit(sys.stdout, text)


def _err(text=""):
    _emit(sys.stderr, text)


def _use_color(stream):
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


def _style(stream, text, code):
    return f"\033[{code}m{text}\033[0m" if _use_color(stream) else text


def _error(message):
    _err(f"{_style(sys.stderr, 'error:', '1;31')} {message}")


def _warn(message):
    _err(f"{_style(sys.stderr, 'warning:', '33')} {message}")


class CliProgress:
    """Progress sink for the engine: one updating line on a terminal, periodic lines otherwise."""

    def __init__(self, stream=None, clock=time.monotonic):
        self.stream = stream if stream is not None else sys.stderr
        isatty = getattr(self.stream, "isatty", None)
        self.tty = bool(isatty and isatty())
        self.interval = 0.25 if self.tty else 10.0
        self.clock = clock
        self._text = None
        self._base = 0
        self._stage_start = 0.0
        self._last = None
        self._width = 0
        self._open = False

    def _format(self, done, total, text, now):
        if not total:
            return text
        pct = min(done / total * 100, 100.0)
        line = f"{text}  {pct:5.1f}%  {human_size(done)} / {human_size(total)}"
        elapsed = now - self._stage_start
        if elapsed >= 1.0 and done > self._base:
            speed = (done - self._base) / elapsed
            eta = int((total - done) / speed) if speed > 0 else 0
            line += f"  {human_size(speed)}/s  ~{eta // 60}m{eta % 60:02d}s left"
        return line

    def __call__(self, done, total, text):
        now = self.clock()
        changed = text != self._text
        if changed:
            self._text, self._base, self._stage_start = text, done, now
        final = bool(total) and done >= total
        if not (changed or final) and self._last is not None and now - self._last < self.interval:
            return
        self._last = now
        line = self._format(done, total, text, now)
        if self.tty:
            self._width = max(self._width, len(line))
            _emit(self.stream, "\r" + line.ljust(self._width), end="")
            self._open = True
        else:
            _emit(self.stream, line)

    def clear(self):
        """Wipe the progress line so a log message can be printed in its place."""
        if self._open:
            _emit(self.stream, "\r" + " " * self._width + "\r", end="")
            self._open = False

    def finish(self):
        if self._open:
            _emit(self.stream, "")
            self._open = False


class CliLogger:
    """Log sink for the engine: milestones always, everything with --verbose."""

    def __init__(self, progress, verbose=False):
        self.progress = progress
        self.verbose = verbose
        self.recent = collections.deque(maxlen=20)

    def __call__(self, line):
        line = str(line).rstrip()
        if not line:
            return
        self.recent.append(line)
        if self.verbose or (CLI_MILESTONE_RE.search(line) and not line.startswith("$ ")):
            self.progress.clear()
            _err(line)

    def dump_recent(self):
        if self.verbose or not self.recent:
            return
        _err("Last log lines:")
        for line in self.recent:
            _err("  " + line)


class CliPrivilege:
    """Privilege helper for the command line, duck-typed to what the engine uses.

    Unlike the GUI's PrivilegeHelper it never handles the administrator credential
    itself: sudo asks on the controlling terminal. Scripts are run once and never
    retried; a failure is reported as it is.
    """

    SUDO_REFRESH_SECONDS = 60

    def __init__(self):
        self.cached_password = None  # always None: sudo owns the credential
        self._stop = threading.Event()
        self._thread = None

    @staticmethod
    def is_root():
        return os.geteuid() == 0

    def authenticate(self):
        """Ask sudo for credentials up front, before anything touches the drive."""
        if self.is_root():
            return
        if not shutil.which("sudo"):
            raise RuntimeError("Administrator privileges are required but 'sudo' was not found. "
                               "Run this command as root or install sudo.")
        # stdin/stdout/stderr are inherited, so sudo prompts on the terminal.
        if subprocess.call(["sudo", "-v"]) != 0:
            raise RuntimeError("Could not obtain administrator privileges (sudo refused). "
                               "Nothing was changed.")
        self._start_keepalive()

    def _start_keepalive(self):
        # Writing and verifying a large image can outlast sudo's credential cache.
        if self._thread is not None:
            return

        def refresh():
            while not self._stop.wait(self.SUDO_REFRESH_SECONDS):
                with contextlib.suppress(OSError, subprocess.SubprocessError):
                    subprocess.run(["sudo", "-n", "-v"], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   timeout=30, check=False)

        self._thread = threading.Thread(target=refresh, daemon=True)
        self._thread.start()

    def clear_cached_password(self):
        self.cached_password = None
        self._stop.set()

    def run_script(self, script, log, args=None, **_kw):
        """Run `script` as root once. Values arrive only as "$1".. arguments."""
        args = [str(a) for a in (args or [])]
        argv = ["bash", "-c", script, "win11_usb_creator"] + args
        if not self.is_root():
            argv = ["sudo"] + argv
        log(("$ sudo " if not self.is_root() else "$ ") + "bash -c '<privileged script>' "
            + " ".join(repr(a) for a in args))
        with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, bufsize=1) as proc:
            try:
                for line in proc.stdout:
                    log(line.rstrip())
            except BaseException:
                with contextlib.suppress(OSError):
                    proc.terminate()
                raise
        if proc.returncode != 0:
            audit(f"Privileged script failed (exit {proc.returncode})", logging.ERROR)
            raise RuntimeError(f"Privileged command failed (exit code {proc.returncode}). "
                               "Check the messages above.")


def cli_sha256_file(path, progress=None, chunk=4 * CHUNK_SIZE):
    """SHA-256 of a file, read in chunks; reports (done, total, text) to `progress`."""
    total = os.path.getsize(path)
    digest = hashlib.sha256()
    done = 0
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            digest.update(block)
            done += len(block)
            if progress:
                progress(done, total, "Computing SHA-256...")
    return digest.hexdigest()


def cli_detect_kind(iso_path):
    """Return (kind, method): kind is windows, linux or unknown.

    Uses detect_iso_kind() when the engine provides it (reads the ISO); otherwise a
    filename heuristic (the same one the GUI uses) backed by the hybrid-image signature.
    """
    detector = globals().get("detect_iso_kind")
    if callable(detector):
        try:
            kind = detector(iso_path)
        except Exception:
            kind = None
        if isinstance(kind, str) and kind.lower() in (MODE_WINDOWS, MODE_LINUX):
            return kind.lower(), "content"
    if "win" in os.path.basename(iso_path).lower():
        return MODE_WINDOWS, "filename"
    try:
        validate_hybrid_iso(iso_path)
        return MODE_LINUX, "boot-signature"
    except (ValueError, OSError):
        return KIND_UNKNOWN, "none"


def _is_interactive():
    return bool(sys.stdin and sys.stdin.isatty() and sys.stderr.isatty())


def _is_verification_failure(exc):
    cls = globals().get("VerificationError")
    if isinstance(cls, type) and isinstance(exc, cls):
        return True
    text = str(exc).lower()
    return "verification failed" in text or "could not complete the verification" in text


def _disk_summary(disk):
    info = {k: v for k, v in disk.items() if v is None or isinstance(v, (str, int, float, bool))}
    info["size_human"] = human_size(disk.get("size") or 0)
    return info


def _write_steps(mode, disk_id, eject):
    steps = [f"Re-check that /dev/{disk_id} is still the listed USB drive"]
    if mode == MODE_LINUX:
        steps += [f"Unmount /dev/{disk_id} and write the ISO to it byte for byte",
                  "Read the drive back and compare it with the ISO"]
    else:
        steps += [f"Erase /dev/{disk_id} and format it as GPT + FAT32 ('{VOL_NAME}')",
                  "Copy the ISO contents (install.wim is split when it exceeds 4 GB)",
                  "Verify the copied files against the ISO"]
    steps.append("Eject the drive" if eject else "Leave the drive connected (--no-eject)")
    return steps


def _print_plan(plan, to_stdout):
    disk = plan["disk"]
    emit = _out if to_stdout else _err
    emit("Plan")
    emit(f"  Disk : /dev/{disk['id']}  {disk.get('size_human', '')}  {disk.get('label', '')}".rstrip())
    if disk.get("model"):
        emit(f"  Model: {disk['model']}")
    emit(f"  ISO  : {plan['iso']} ({human_size(plan['iso_size'])})")
    emit(f"  Mode : {plan['mode']}")
    emit("  Steps:")
    for i, step in enumerate(plan["steps"], 1):
        emit(f"    {i}. {step}")


def _engine_kwargs(cancel_event):
    """Pass cancel_event to build_usb only when the engine accepts it."""
    try:
        params = list(inspect.signature(build_usb).parameters.values())
    except (TypeError, ValueError):
        return {}, False
    if any(p.name == "cancel_event" or p.kind is p.VAR_KEYWORD for p in params):
        return {"cancel_event": cancel_event}, True
    return {}, False


def _normalize_disk_id(value):
    value = (value or "").strip()
    return value[len("/dev/"):] if value.startswith("/dev/") else value


# ---------- commands ----------
def cmd_list(args):
    try:
        disks = get_external_disks()
    except Exception as e:
        raise CliError(f"Could not list the drives: {e}") from None
    if args.json:
        _out(json.dumps({"disks": [_disk_summary(d) for d in disks]}, indent=2, default=str))
        return EXIT_OK
    if not disks:
        _err("No USB drives found. Plug one in and try again.")
        return EXIT_OK
    has_model = any(d.get("model") for d in disks)
    header = ["ID", "SIZE"] + (["MODEL"] if has_model else []) + ["LABEL"]
    rows = [[d["id"], human_size(d.get("size") or 0)] + ([str(d.get("model") or "")] if has_model else [])
            + [str(d.get("label", ""))] for d in disks]
    widths = [max(len(r[i]) for r in [header] + rows) for i in range(len(header))]
    for row in [header] + rows:
        _out("  ".join(c.ljust(widths[i]) for i, c in enumerate(row)).rstrip())
    return EXIT_OK


def cmd_detect(args):
    iso = os.path.realpath(os.path.expanduser(args.iso))
    if not os.path.isfile(iso):
        raise CliError(f"Not a file: {iso}")
    kind, method = cli_detect_kind(iso)
    if args.json:
        _out(json.dumps({"iso": iso, "kind": kind, "method": method}, indent=2))
    else:
        _out(kind)
    return EXIT_OK


def cmd_sha256(args):
    expected = None
    if args.expected:
        expected = args.expected.strip().lower()
        if expected.startswith("sha256:"):
            expected = expected[len("sha256:"):]
        if not SHA256_HEX_RE.match(expected):
            raise CliError("--expected must be a 64-character hexadecimal SHA-256 value.", EXIT_USAGE)
    iso = os.path.realpath(os.path.expanduser(args.iso))
    if not os.path.isfile(iso):
        raise CliError(f"Not a file: {iso}")
    progress = CliProgress()
    try:
        digest = cli_sha256_file(iso, progress)
    except OSError as e:
        progress.finish()
        raise CliError(f"Could not read {iso}: {e.strerror or e}") from None
    progress.finish()
    match = None if expected is None else (digest == expected)
    if args.json:
        _out(json.dumps({"file": iso, "sha256": digest, "expected": expected, "match": match}, indent=2))
    else:
        _out(f"{digest}  {iso}")
    if match is False:
        _error(f"The checksum does not match.\n  expected: {expected}\n  actual:   {digest}")
        return EXIT_VERIFY_FAILED
    if match:
        _err("Checksum matches.")
    return EXIT_OK


def _prepare_write(args):
    """Validate everything and build the plan. Raises CliError; touches nothing."""
    try:
        iso = validate_iso_path(args.iso)
        disk_id = validate_device_name(_normalize_disk_id(args.disk))
    except ValueError as e:
        raise CliError(str(e)) from None
    try:
        disks = get_external_disks()
    except Exception as e:
        raise CliError(f"Could not list the drives: {e}") from None
    disk = next((d for d in disks if d.get("id") == disk_id), None)
    if disk is None:
        raise CliError(f"/dev/{disk_id} is not an eligible USB drive. "
                       f"Run '{CLI_PROG} list' to see the drives that can be written.")
    mode = args.mode
    detected, _method = cli_detect_kind(iso)
    if mode == MODE_AUTO:
        if detected == KIND_UNKNOWN:
            raise CliError("Could not tell whether this is a Windows or a Linux ISO. "
                           "Pass --mode windows or --mode linux.", EXIT_USAGE)
        mode = detected
    elif detected in (MODE_WINDOWS, MODE_LINUX) and detected != mode:
        _warn(f"This ISO looks like a {detected} image but --mode {mode} was requested.")
    iso_size = os.path.getsize(iso)
    size = disk.get("size") or 0
    if mode == MODE_LINUX:
        try:
            validate_hybrid_iso(iso)
        except ValueError as e:
            raise CliError(str(e)) from None
        if size and iso_size > size:
            raise CliError(f"The ISO ({human_size(iso_size)}) is larger than the drive ({human_size(size)}).")
    elif size and iso_size > size:
        _warn(f"The ISO ({human_size(iso_size)}) is larger than the drive ({human_size(size)}); "
              "the copy may not fit.")
    missing = get_missing_dependencies(mode)
    if missing:
        raise CliError("Missing required tools: " + ", ".join(missing) + ". Install them and try again.")
    eject = not args.no_eject
    return {"iso": iso, "iso_size": iso_size, "mode": mode, "disk": _disk_summary(disk),
            "steps": _write_steps(mode, disk_id, eject), "eject": eject, "dry_run": bool(args.dry_run)}


def _confirm_write(args, plan):
    """Return normally only when the user has agreed to erase the drive."""
    if args.yes:
        return
    disk_id = plan["disk"]["id"]
    if not _is_interactive():
        raise CliError("Refusing to erase a drive without confirmation: this is not an interactive "
                       "terminal. Review the plan with --dry-run, then pass --yes.", EXIT_USAGE)
    _err(f"\nThis will PERMANENTLY ERASE all data on /dev/{disk_id}.")
    _emit(sys.stderr, f"Type the disk id ({disk_id}) to confirm: ", end="")
    answer = sys.stdin.readline().strip()
    if answer != disk_id:
        raise CliError("The confirmation did not match. Nothing was changed.")


def _run_write(args, plan, result):
    needs_priv = IS_LINUX or plan["mode"] == MODE_LINUX
    priv = CliPrivilege()
    progress = CliProgress()
    log = CliLogger(progress, verbose=args.verbose)
    cancel = threading.Event()
    kwargs, supports_cancel = _engine_kwargs(cancel)
    state = {"interrupted": False}

    def on_sigint(_signum, _frame):
        if state["interrupted"] or not supports_cancel:
            raise KeyboardInterrupt
        state["interrupted"] = True
        cancel.set()
        _err("\nInterrupted: finishing safely (unmounting) - press Ctrl-C again to force quit.")

    try:
        previous = signal.signal(signal.SIGINT, on_sigint)
    except ValueError:  # not the main thread
        previous = None
    started = time.time()
    audit(f"CLI write requested: /dev/{plan['disk']['id']} mode={plan['mode']}")
    ejected, failure = None, None
    try:
        if needs_priv:
            priv.authenticate()
        ejected = build_usb(plan["iso"], plan["disk"]["id"], log, priv,
                            expected_size=plan["disk"].get("size"), mode=plan["mode"],
                            progress=progress, eject=plan["eject"], **kwargs)
    except KeyboardInterrupt as e:
        state["interrupted"] = True
        failure = e
    except Exception as e:
        failure = e
        if args.debug:
            progress.clear()
            traceback.print_exc()
    finally:
        progress.finish()
        priv.clear_cached_password()
        if previous is not None:
            signal.signal(signal.SIGINT, previous)
    result["elapsed_seconds"] = round(time.time() - started, 1)

    if failure is None:
        result.update(ok=True, verified=True, ejected=bool(ejected))
        if not plan["eject"]:
            _err("Done. The drive was written and verified; it was left connected (--no-eject).")
            return EXIT_OK
        if ejected:
            _err("Done. The drive was written, verified and ejected - you can unplug it now.")
            return EXIT_OK
        _error("The drive was written and verified, but it could not be ejected. "
               "Eject it from the file manager before unplugging.")
        result["error"] = "eject failed"
        return EXIT_EJECT_FAILED

    if state["interrupted"]:
        result["error"] = "interrupted"
        _error("Interrupted. The drive may be partially written and must not be used.")
        return EXIT_INTERRUPTED
    result["error"] = str(failure)
    if _is_verification_failure(failure):
        _error(str(failure))
        return EXIT_VERIFY_FAILED
    if isinstance(failure, (ValueError, RuntimeError)):
        _error(str(failure))
    else:
        _error(f"Unexpected failure ({type(failure).__name__}): {failure}")
    log.dump_recent()
    return EXIT_ERROR


def cmd_write(args):
    result = {"ok": False, "mode": None, "iso": None, "disk": None, "verified": False,
              "ejected": False, "error": None, "exit_code": EXIT_ERROR}
    try:
        plan = _prepare_write(args)
        result.update(mode=plan["mode"], iso=plan["iso"], disk=plan["disk"]["id"])
        if args.dry_run:
            if args.json:
                _out(json.dumps(plan, indent=2, default=str))
            else:
                _print_plan(plan, to_stdout=True)
                _err("Dry run: nothing was changed.")
            return EXIT_OK
        _print_plan(plan, to_stdout=False)
        _confirm_write(args, plan)
        code = _run_write(args, plan, result)
    except CliError as e:
        result.update(error=e.message, exit_code=e.code)
        if args.json:
            _out(json.dumps(result, indent=2))
        raise
    result["exit_code"] = code
    if args.json:
        _out(json.dumps(result, indent=2))
    return code


COMMANDS = {"list": cmd_list, "detect": cmd_detect, "sha256": cmd_sha256, "write": cmd_write}


def build_cli_parser():
    common = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    common.add_argument("--debug", action="store_true", default=argparse.SUPPRESS,
                        help="show Python tracebacks for unexpected errors")
    parser = argparse.ArgumentParser(
        prog=CLI_PROG, allow_abbrev=False,
        description="Create bootable USB drives from Windows 11 or hybrid Linux ISOs. "
                    "Run without arguments to open the graphical interface.",
        epilog=(
            "exit codes:\n"
            "  0    success\n"
            "  1    error\n"
            "  2    usage error (also: confirmation missing, ISO kind unknown)\n"
            "  3    verification failed / checksum mismatch\n"
            "  4    written and verified, but the drive could not be ejected\n"
            "  130  interrupted (Ctrl-C)\n\n"
            "environment:\n"
            "  NO_COLOR                       disable colored messages\n"
            "  WIN11USB_DISABLE_AUDIT_LOG=1   do not write the audit log\n\n"
            "Data is written to stdout; messages, errors and progress to stderr.\n"
            "The written drive is always read back and compared with the ISO."),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"{CLI_PROG} {__version__}")
    parser.add_argument("--debug", action="store_true", help="show Python tracebacks for unexpected errors")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    def add(name, help_text, **kw):
        return sub.add_parser(name, help=help_text, description=help_text, parents=[common],
                              allow_abbrev=False, **kw)

    add("gui", "open the graphical interface (the default with no arguments)")
    p = add("list", "list the USB drives that can be written")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p = add("detect", "tell whether an ISO is a windows or linux image (or unknown)")
    p.add_argument("iso", metavar="ISO")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p = add("sha256", "compute the SHA-256 of a file, optionally comparing it with a known value")
    p.add_argument("iso", metavar="ISO")
    p.add_argument("--expected", metavar="HASH", help="expected SHA-256; exit code 3 if it differs")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p = add("write", "write an ISO to a USB drive, verify it and eject",
            epilog="The drive is ERASED. Use --dry-run first to see the plan without changing anything.")
    p.add_argument("--iso", required=True, metavar="ISO", help="path of the ISO image")
    p.add_argument("--disk", required=True, metavar="DISKID",
                   help="drive id as shown by 'list' (disk4 on macOS, sdb on Linux)")
    p.add_argument("--mode", choices=[MODE_AUTO, MODE_WINDOWS, MODE_LINUX], default=MODE_AUTO,
                   help="windows: GPT+FAT32 file copy; linux: raw write of a hybrid ISO; "
                        "auto: detect (default)")
    p.add_argument("--yes", action="store_true",
                   help="do not ask for confirmation (required when not in an interactive terminal)")
    p.add_argument("--dry-run", action="store_true", help="print the plan and exit without touching anything")
    p.add_argument("--no-eject", action="store_true", help="leave the drive connected when done")
    p.add_argument("--json", action="store_true", help="machine-readable result on stdout")
    p.add_argument("-v", "--verbose", action="store_true", help="show every engine log line")
    return parser


def _run_gui():
    if tk is None:
        _err(TK_MISSING_MESSAGE)
        return EXIT_ERROR
    App().mainloop()
    return EXIT_OK


def main(argv=None):
    """Entry point. Returns the process exit code (see the exit codes in --help)."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        command, args = "gui", None
    else:
        try:
            args = build_cli_parser().parse_args(argv)
        except SystemExit as e:  # --help / --version (0) or a usage error (2)
            return e.code if isinstance(e.code, int) else (EXIT_OK if e.code is None else EXIT_USAGE)
        command = args.command or "gui"
    if command in ("gui", "list", "write") and not (IS_MAC or IS_LINUX):
        _err("This script supports macOS and Linux only.")
        return EXIT_ERROR
    debug = bool(getattr(args, "debug", False))
    try:
        if command == "gui":
            return _run_gui()
        return COMMANDS[command](args)
    except CliError as e:
        _error(e.message)
        return e.code
    except KeyboardInterrupt:
        _err("Interrupted.")
        return EXIT_INTERRUPTED
    except BrokenPipeError:
        with contextlib.suppress(Exception):
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return EXIT_OK
    except Exception as e:
        if debug:
            traceback.print_exc()
        _error(str(e) if isinstance(e, (ValueError, RuntimeError, OSError))
               else f"Unexpected failure ({type(e).__name__}): {e}")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
