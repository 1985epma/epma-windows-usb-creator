#!/usr/bin/env python3
"""End-to-end test of the REAL privileged code paths, against loop devices.

!!  FOR GITHUB ACTIONS LINUX RUNNERS (or a throw-away VM).  DO NOT RUN ON A MACHINE  !!
!!  YOU CARE ABOUT: it uses `sudo -n`, losetup, mount and mkfs.                       !!

Everything runs against loop devices that this script creates itself from sparse
files (`truncate -s 512M disk.img; losetup -fP --show disk.img`), so no real disk is
ever touched; the script refuses to hand any path that is not /dev/loopN to the
application. It still needs passwordless sudo, so it will not start unless it is
running under GitHub Actions (GITHUB_ACTIONS=true) or E2E_ALLOW_LOOPBACK=1 is set.

Scenarios (each with its own loop device, always detached in `finally`):

  raw-write     linux_write_raw + verify_raw_write: the loop device must equal the ISO;
                a deliberately flipped byte must make verify_raw_write raise, and the
                reported offset must point at the right chunk; a non-hybrid ISO must be
                refused before the device is touched.
  windows-copy  linux_build_usb on a real ISO9660 image: GPT + FAT32, volume label,
                every file present and identical, install.wim copied whole.
  windows-split linux_build_usb with FAT32_MAX_FILE_SIZE patched tiny and a real WIM,
                exercising `wimlib-imagex split` + `wimlib-imagex verify`.
  windows-hardening
                linux_build_usb with hardening files (written by plain file I/O, as the user, onto the
                FAT32 volume that the real prep script mounts with the user's uid/gid): every extra file
                is present with the exact bytes, including the literal sources/$OEM$/$$/... path, next to
                the ISO's files; a byte flipped on the drive after the copy must fail the verification;
                and an image that already ships one of the files (spelled with other letter case) is
                refused by refuse_hardening_clash (a real read-only loop mount) before any drive is touched.
  verify-diff   verify_windows_payload (no loop device needed) must reject a missing
                file, a changed file and a changed install image.
  seed-drive    build_seed_usb (the hardening seed drive) on a 128 MiB loop device: refused when
                too small and when canceled before the start (device untouched), then GPT + ONE
                FAT32 partition (not an EFI system partition) with the label from the seed, every
                file byte for byte (nested folder, '$' in a name), and verify_seed_files must
                reject a changed and a missing file. Only the USB-only safety re-check is stood in
                for (a loop device is not a USB drive); everything else is the real code.

Environment:
  E2E_REQUIRE=1   a missing prerequisite is a FAILURE instead of a skip (CI sets this).
  E2E_VERBOSE=1   print the application log of every scenario, not only of failed ones.

The application module is imported with the real Tkinter when present and a stub
otherwise (see _appimport.py); no window is ever created.
"""

import contextlib
import hashlib
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _appimport import import_app  # noqa: E402

REQUIRE = os.environ.get("E2E_REQUIRE") == "1"
VERBOSE = os.environ.get("E2E_VERBOSE") == "1"
MIB = 1024 * 1024

NEEDED_TOOLS = ["sudo", "losetup", "truncate", "parted", "mkfs.vfat", "wipefs", "partprobe",
                "rsync", "wimlib-imagex", "xorriso", "blkid", "cmp", "dd", "mount", "umount"]


class Skip(Exception):
    pass


# --------------------------------------------------------------------------- helpers
def sudo(*cmd, check=True, input_bytes=None, text=True):
    return subprocess.run(["sudo", "-n", *cmd], capture_output=True, text=text, check=check,
                          input=input_bytes)


class FakePriv:
    """Stands in for PrivilegeHelper: same run_script contract, but through `sudo -n`."""

    cached_password = None

    def run_script(self, script, log, args=None, **_kw):
        argv = ["sudo", "-n", "bash", "-c", script, "win11_usb_creator"] + [str(a) for a in (args or [])]
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        for line in proc.stdout:
            log(line.rstrip("\n"))
        proc.wait()
        if proc.returncode != 0:
            raise RuntimeError(f"privileged script failed (exit {proc.returncode})")

    def clear_cached_password(self):
        pass


def make_hybrid_iso(path, size, seed=1):
    """A file that passes validate_hybrid_iso: random content with the 0x55AA signature."""
    data = bytearray(random.Random(seed).randbytes(size))
    data[510:512] = b"\x55\xaa"
    with open(path, "wb") as fh:
        fh.write(data)


def write_random(path, size, seed):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(random.Random(seed).randbytes(size))


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(MIB), b""):
            h.update(chunk)
    return h.hexdigest()


def mounted_under(prefix):
    """Mount points (and their sources) at or below `prefix`, deepest first."""
    found = []
    with open("/proc/mounts", encoding="utf-8") as fh:
        for line in fh:
            src, mnt = line.split()[:2]
            if mnt == prefix or mnt.startswith(prefix.rstrip("/") + "/"):
                found.append((src, mnt))
    return sorted(found, key=lambda m: len(m[1]), reverse=True)


def cleanup_workdir_devices(workdir):
    """Unmount everything mounted below `workdir` and detach every loop device backed by it."""
    for _src, mnt in mounted_under(workdir):
        sudo("umount", "-l", mnt, check=False)
    for _attempt in range(5):
        out = sudo("losetup", "-a", check=False).stdout
        loops = [line.split(":")[0] for line in out.splitlines() if workdir in line]
        if not loops:
            return
        for dev in loops:
            sudo("losetup", "-d", dev, check=False)
        time.sleep(1)
    print(f"WARNING: could not detach every loop device backed by {workdir}")


@contextlib.contextmanager
def loop_device(workdir, name, size="512M"):
    """Create a sparse image, attach it with partition scanning, always detach afterwards."""
    img = os.path.join(workdir, f"{name}.img")
    subprocess.run(["truncate", "-s", size, img], check=True)
    dev = sudo("losetup", "-fP", "--show", img).stdout.strip()
    if not re.fullmatch(r"/dev/loop[0-9]+", dev):  # safety net: never hand anything else on
        sudo("losetup", "-d", dev, check=False)
        raise RuntimeError(f"unexpected losetup output: {dev!r}")
    try:
        yield dev
    finally:
        cleanup_workdir_devices(workdir)


class Recorder:
    """Collects the application log (and progress calls) of one scenario."""

    def __init__(self):
        self.lines = []
        self.progress_calls = []

    def log(self, line):
        self.lines.append(str(line))

    def progress(self, *args, **_kw):
        self.progress_calls.append(args)


def expect_raises(exc_type, fn, *args, contains=None, **kwargs):
    try:
        fn(*args, **kwargs)
    except exc_type as e:
        if contains and contains not in str(e):
            raise AssertionError(f"{exc_type.__name__} raised, but without {contains!r}: {e}") from None
        return e
    raise AssertionError(f"expected {exc_type.__name__} from {fn.__name__}, nothing was raised")


def device_equals_file(dev, path, size):
    return sudo("cmp", "-n", str(size), path, dev, check=False).returncode == 0


def flip_byte(dev, offset):
    """Invert one byte of the device; returns a function that puts it back."""
    orig = sudo("dd", f"if={dev}", "bs=1", f"skip={offset}", "count=1", "status=none", text=False).stdout
    assert len(orig) == 1, "could not read the byte to corrupt"

    def write(value):
        sudo("dd", f"of={dev}", "bs=1", f"seek={offset}", "count=1", "conv=notrunc", "status=none",
             input_bytes=value, text=False)
        sudo("sync")

    write(bytes([orig[0] ^ 0xFF]))
    return lambda: write(orig)


# --------------------------------------------------------------------------- scenarios
def scenario_raw_write(app, workdir, priv, rec):
    size = 6 * MIB + 12345  # not a multiple of the chunk size on purpose
    iso = os.path.join(workdir, "hybrid.iso")
    make_hybrid_iso(iso, size)

    with loop_device(workdir, "raw") as dev:
        name = os.path.basename(dev)

        # A non-hybrid image must be refused BEFORE anything is written.
        plain = os.path.join(workdir, "not-hybrid.iso")
        write_random(plain, MIB, 99)
        with open(plain, "r+b") as fh:
            fh.seek(510)
            fh.write(b"\x00\x00")
        expect_raises(ValueError, app.linux_write_raw, plain, name, rec.log, priv)
        assert sudo("cmp", "-n", str(MIB), "/dev/zero", dev, check=False).returncode == 0, \
            "the device was modified even though the ISO was refused"

        # The real write, read-back verification and eject step.
        app.linux_write_raw(iso, name, rec.log, priv, rec.progress)
        assert device_equals_file(dev, iso, size), "device content differs from the ISO after linux_write_raw"
        assert rec.progress_calls, "no progress was reported during the write"
        assert any("Verification passed" in line for line in rec.lines), "no 'Verification passed' log line"

        # verify_raw_write must pass on good data...
        app.verify_raw_write(iso, dev, rec.log, priv, rec.progress)

        # ...and fail on a single flipped byte, in the right chunk (multi-chunk path).
        old_chunk = app.VERIFY_CHUNK
        app.VERIFY_CHUNK = MIB
        try:
            restore = flip_byte(dev, size - 1)  # last byte of the last (partial) chunk
            e = expect_raises(RuntimeError, app.verify_raw_write, iso, dev, rec.log, priv, rec.progress,
                              contains="Verification FAILED")
            assert str(6 * MIB) in str(e), f"wrong failing offset reported: {e}"
            restore()
            app.verify_raw_write(iso, dev, rec.log, priv, rec.progress)

            restore = flip_byte(dev, 4096)  # first chunk
            e = expect_raises(RuntimeError, app.verify_raw_write, iso, dev, rec.log, priv, rec.progress,
                              contains="Verification FAILED")
            assert "near byte 0)" in str(e), f"wrong failing offset reported: {e}"
            restore()
        finally:
            app.VERIFY_CHUNK = old_chunk


def build_windows_tree(root, wim_path=None, wim_bytes=3 * MIB):
    """Lay out a miniature Windows installer; returns {relative path: sha256} for the small files."""
    files = {
        "setup.exe": (200_000, 11),
        "bootmgr": (50_000, 12),
        "boot/bcd": (30_000, 13),
        "boot/fonts/segoe_slboot.ttf": (70_000, 14),
        "efi/boot/bootx64.efi": (120_000, 15),
        "efi/microsoft/boot/bcd": (30_000, 16),
        "sources/boot.wim": (MIB, 17),
        "sources/lang.ini": (1_000, 18),
    }
    for rel, (size, seed) in files.items():
        write_random(os.path.join(root, rel), size, seed)
    if wim_path:
        shutil.copyfile(wim_path, os.path.join(root, "sources", "install.wim"))
    else:
        write_random(os.path.join(root, "sources", "install.wim"), wim_bytes, 19)
    return {rel: sha256(os.path.join(root, rel)) for rel in files}


def make_iso(tree, out):
    subprocess.run(["xorriso", "-as", "mkisofs", "-iso-level", "3", "-R", "-J", "-V", "WIN11TEST",
                    "-o", out, tree], check=True, capture_output=True)


def check_windows_drive(app, dev, expect_small, expect_install, split):
    """Mount the first partition read-only and check label, layout and contents."""
    part = f"{dev}p1"
    assert os.path.exists(part), f"{part} does not exist: the partition table was not created"
    assert sudo("blkid", "-p", "-s", "PTTYPE", "-o", "value", dev).stdout.strip() == "gpt", "not a GPT disk"
    assert sudo("blkid", "-p", "-s", "TYPE", "-o", "value", part).stdout.strip() == "vfat", "not FAT"
    label = sudo("blkid", "-p", "-s", "LABEL", "-o", "value", part).stdout.strip()
    assert label == app.VOL_NAME, f"volume label is {label!r}, expected {app.VOL_NAME!r}"
    assert not [m for m in mounted_under("/") if m[0] == part], "the partition is still mounted after linux_build_usb"

    mnt = tempfile.mkdtemp(prefix="check_")
    sudo("mount", "-o", "ro", part, mnt)
    try:
        for rel, digest in expect_small.items():
            path = os.path.join(mnt, rel)
            assert os.path.isfile(path), f"missing on the drive: {rel}"
            assert sha256(path) == digest, f"content differs on the drive: {rel}"
        sources = os.path.join(mnt, "sources")
        if split:
            swm = os.path.join(sources, "install.swm")
            assert os.path.isfile(swm), "sources/install.swm missing"
            assert not os.path.exists(os.path.join(sources, "install.wim")), "unsplit install.wim left behind"
            subprocess.run(["wimlib-imagex", "verify", swm, f"--ref={sources}/install*.swm"],
                           check=True, capture_output=True)
        else:
            assert sha256(os.path.join(sources, "install.wim")) == expect_install, "install.wim differs"
    finally:
        sudo("umount", mnt, check=False)
        with contextlib.suppress(OSError):
            os.rmdir(mnt)


def scenario_windows_copy(app, workdir, priv, rec):
    tree = os.path.join(workdir, "tree-copy")
    small = build_windows_tree(tree)
    install_digest = sha256(os.path.join(tree, "sources", "install.wim"))
    iso = os.path.join(workdir, "win-copy.iso")
    make_iso(tree, iso)

    with loop_device(workdir, "wincopy") as dev:
        app.linux_build_usb(iso, os.path.basename(dev), rec.log, priv, rec.progress)
        assert any("Verification passed" in line for line in rec.lines), "verification did not pass"
        check_windows_drive(app, dev, small, install_digest, split=False)


def scenario_windows_split(app, workdir, priv, rec):
    # A real (tiny) WIM, so that `wimlib-imagex split` and `verify` have something to chew on.
    wim_src = os.path.join(workdir, "wim-src")
    for i in range(3):
        write_random(os.path.join(wim_src, f"f{i}.bin"), MIB, 30 + i)
    wim = os.path.join(workdir, "install-real.wim")
    subprocess.run(["wimlib-imagex", "capture", wim_src, wim, "E2E image"], check=True, capture_output=True)

    probe = os.path.join(workdir, "split-probe")
    os.makedirs(probe)
    if subprocess.run(["wimlib-imagex", "split", wim, os.path.join(probe, "p.swm"), "3800"],
                      capture_output=True).returncode != 0:
        raise Skip("this wimlib-imagex refuses to split a WIM smaller than one part")

    tree = os.path.join(workdir, "tree-split")
    small = build_windows_tree(tree, wim_path=wim)
    iso = os.path.join(workdir, "win-split.iso")
    make_iso(tree, iso)

    old_limit = app.FAT32_MAX_FILE_SIZE
    app.FAT32_MAX_FILE_SIZE = MIB  # the 3 MiB WIM now counts as "over 4 GB"
    try:
        with loop_device(workdir, "winsplit") as dev:
            app.linux_build_usb(iso, os.path.basename(dev), rec.log, priv, rec.progress)
            assert any("Splitting" in line for line in rec.lines), "the split branch was not taken"
            assert any("Verification passed" in line for line in rec.lines), "verification did not pass"
            check_windows_drive(app, dev, small, None, split=True)
    finally:
        app.FAT32_MAX_FILE_SIZE = old_limit


HARDENING_FILES = {
    "autounattend.xml": b"<?xml version='1.0' encoding='utf-8'?><unattend/>\n",
    "sources/$OEM$/$$/Setup/Scripts/SetupComplete.cmd": b"@echo off\r\npowershell -File harden.ps1\r\n",
    "sources/$OEM$/$$/Setup/Scripts/harden.ps1": random.Random(41).randbytes(5000),
}


def scenario_windows_hardening(app, workdir, priv, rec):
    tree = os.path.join(workdir, "tree-hard")
    small = build_windows_tree(tree)
    install_digest = sha256(os.path.join(tree, "sources", "install.wim"))
    iso = os.path.join(workdir, "win-hard.iso")
    make_iso(tree, iso)

    with loop_device(workdir, "winhard") as dev:
        app.linux_build_usb(iso, os.path.basename(dev), rec.log, priv, rec.progress,
                            hardening_files=HARDENING_FILES)
        assert any(line == "Adding hardening files..." for line in rec.lines), "no 'Adding hardening files...' log line"
        assert any("Hardening files verified" in line for line in rec.lines), "extra files were not verified"
        assert any("Verification passed" in line for line in rec.lines), "verification did not pass"
        check_windows_drive(app, dev, small, install_digest, split=False)

        part = f"{dev}p1"
        mnt = tempfile.mkdtemp(prefix="check_")
        sudo("mount", "-o", "ro", part, mnt)
        try:
            for rel, data in HARDENING_FILES.items():
                with open(os.path.join(mnt, *rel.split("/")), "rb") as fh:
                    assert fh.read() == data, f"hardening file differs on the drive: {rel}"
            assert os.path.isdir(os.path.join(mnt, "sources", "$OEM$", "$$")), "the $OEM$/$$ folders are missing"
        finally:
            sudo("umount", mnt, check=False)
            with contextlib.suppress(OSError):
                os.rmdir(mnt)

    # A byte that changes on the drive after the copy must be caught by the read-back.
    original = app.write_hardening_files

    def write_then_corrupt(root, files, cancel_event=None):
        original(root, files, cancel_event)
        victim = os.path.join(root, "sources", "$OEM$", "$$", "Setup", "Scripts", "harden.ps1")
        with open(victim, "r+b") as fh:
            fh.seek(10)
            first = fh.read(1)
            fh.seek(10)
            fh.write(bytes([first[0] ^ 0xFF]))

    rec2 = Recorder()
    app.write_hardening_files = write_then_corrupt
    try:
        with loop_device(workdir, "winhard2") as dev:
            expect_raises(RuntimeError, app.linux_build_usb, iso, os.path.basename(dev), rec2.log, priv,
                          rec2.progress, hardening_files=HARDENING_FILES, contains="Verification FAILED")
    finally:
        app.write_hardening_files = original
    rec.lines.extend(rec2.lines)

    # An image that already ships one of the files (any letter case) is refused before the drive is touched.
    oem_tree = os.path.join(workdir, "tree-oem")
    build_windows_tree(oem_tree)
    write_random(os.path.join(oem_tree, "sources", "$oem$", "$$", "Setup", "Scripts", "SETUPCOMPLETE.CMD"), 300, 77)
    oem_iso = os.path.join(workdir, "win-oem.iso")
    make_iso(oem_tree, oem_iso)
    err = expect_raises(ValueError, app.refuse_hardening_clash, oem_iso, HARDENING_FILES, rec.log, priv,
                        contains="already contains")
    assert "SetupComplete.cmd" in str(err), f"the refusal does not name the file: {err}"
    app.refuse_hardening_clash(iso, HARDENING_FILES, rec.log, priv)  # the clean image passes


def scenario_verify_diff(app, workdir, priv, rec):
    """verify_windows_payload on plain directories: no loop device, no root."""
    def fresh(name):
        src, dst = os.path.join(workdir, f"{name}-src"), os.path.join(workdir, f"{name}-dst")
        for root in (src, dst):
            write_random(os.path.join(root, "setup.exe"), 5000, 1)
            write_random(os.path.join(root, "boot", "bcd"), 3000, 2)
            write_random(os.path.join(root, "sources", "install.wim"), 20_000, 3)
        return src, dst

    def run(src, dst):
        big = os.path.join(src, "sources", "install.wim")
        app.verify_windows_payload(src, dst, "sources/install.wim", big, rec.log, rec.progress)

    src, dst = fresh("ok")
    run(src, dst)  # identical trees pass

    src, dst = fresh("missing")
    os.remove(os.path.join(dst, "boot", "bcd"))
    expect_raises(RuntimeError, run, src, dst, contains="Verification FAILED")

    src, dst = fresh("changed")
    write_random(os.path.join(dst, "setup.exe"), 5000, 777)  # same size, other content
    expect_raises(RuntimeError, run, src, dst, contains="Verification FAILED")

    src, dst = fresh("image")
    write_random(os.path.join(dst, "sources", "install.wim"), 20_000, 778)
    expect_raises(RuntimeError, run, src, dst, contains="Verification FAILED")


# ===== hardening: engine-seed =====
EFI_SYSTEM_PARTITION_GUID = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"


def seed_test_files():
    """A small seed set with a nested folder and a name containing '$' (like the real ones)."""
    return {
        "user-data": b"#cloud-config\nautoinstall:\n  version: 1\n",
        "meta-data": b"",
        "README.txt": b"seed drive e2e\n",
        "scripts/$setup$/harden-linux.sh": random.Random(41).randbytes(60_000),
    }


@contextlib.contextmanager
def seed_engine_patches(app, loop_name, label, files):
    """Point build_seed_usb at the loop device: the real USB-only listing would (rightly) not list it.

    Only the safety re-check is replaced, and only to insist that it is asked about THIS loop device;
    every other step (validation, scripts, copy, read-back) is the real code. hardening_files_seed is
    replaced too, so this scenario does not depend on the wording of the real seed files.
    """
    def recheck(dev, expected_size, log, expected_identity=None):
        assert dev == loop_name, f"build_seed_usb re-checked {dev!r}, expected {loop_name!r}"
        log(f"(e2e) safety re-check stands in for the USB listing: {dev}")

    with mock.patch.object(app, "hardening_files_seed", create=True,
                           side_effect=lambda target, profile: (label, dict(files))), \
            mock.patch.object(app, "reverify_target_disk", side_effect=recheck):
        yield


def check_seed_drive(app, dev, label, files):
    part = f"{dev}p1"
    assert os.path.exists(part), f"{part} does not exist: the partition table was not created"
    assert not os.path.exists(f"{dev}p2"), "the seed drive must have exactly one partition"
    assert sudo("blkid", "-p", "-s", "PTTYPE", "-o", "value", dev).stdout.strip() == "gpt", "not a GPT disk"
    assert sudo("blkid", "-p", "-s", "TYPE", "-o", "value", part).stdout.strip() == "vfat", "not FAT"
    got = sudo("blkid", "-p", "-s", "LABEL", "-o", "value", part).stdout.strip()
    assert got == label, f"volume label is {got!r}, expected {label!r}"
    entry = sudo("blkid", "-p", "-s", "PART_ENTRY_TYPE", "-o", "value", part).stdout.strip().lower()
    assert entry != EFI_SYSTEM_PARTITION_GUID, "a data drive must not be an EFI system partition"
    assert not [m for m in mounted_under("/") if m[0] == part], "the partition is still mounted after the build"

    mnt = tempfile.mkdtemp(prefix="check_")
    sudo("mount", "-o", "ro", part, mnt)
    try:
        for rel, data in files.items():
            path = os.path.join(mnt, *rel.split("/"))
            assert os.path.isfile(path), f"missing on the drive: {rel}"
            with open(path, "rb") as fh:
                assert fh.read() == data, f"content differs on the drive: {rel}"
    finally:
        sudo("umount", mnt, check=False)
        with contextlib.suppress(OSError):
            os.rmdir(mnt)


def scenario_seed_drive(app, workdir, priv, rec):
    files = seed_test_files()
    label = "CIDATA"

    with loop_device(workdir, "seed", size="128M") as dev:
        name = os.path.basename(dev)
        size = 128 * MIB
        with seed_engine_patches(app, name, label, files):
            # Refused before the device is touched: too small a drive, and a cancel before the start.
            expect_raises(ValueError, app.build_seed_usb, "ubuntu", name, rec.log, priv,
                          expected_size=32 * MIB, contains="too small")
            cancel = threading.Event()
            cancel.set()
            e = expect_raises(app.OperationCanceled, app.build_seed_usb, "ubuntu", name, rec.log, priv,
                              expected_size=size, cancel_event=cancel)
            assert e.drive_touched is False, "a cancel before the start must not claim the drive was touched"
            assert sudo("cmp", "-n", str(MIB), "/dev/zero", dev, check=False).returncode == 0, \
                "the device was modified although the build was refused or canceled"

            # The real thing: erase, GPT + FAT32, label, copy, read-back, unmount, eject step.
            ejected = app.build_seed_usb("ubuntu", name, rec.log, priv, expected_size=size, progress=rec.progress)
            assert isinstance(ejected, bool), "build_seed_usb must return a bool"
            assert any("Verification passed" in line for line in rec.lines), "verification did not pass"
            assert rec.progress_calls, "no progress was reported"
            check_seed_drive(app, dev, label, files)

            # The read-back must notice a changed file (same size, other content) and a missing one.
            part = f"{dev}p1"
            mnt = tempfile.mkdtemp(prefix="seedverify_")
            try:
                sudo("mount", part, mnt)
                sudo("sh", "-c", 'head -c "$1" /dev/zero > "$2"', "sh", str(len(files["README.txt"])),
                     os.path.join(mnt, "README.txt"))
                sudo("umount", mnt)
                sudo("mount", "-o", "ro", part, mnt)
                expect_raises(RuntimeError, app.verify_seed_files, files, mnt, rec.log, rec.progress,
                              contains="README.txt (content differs)")
                sudo("umount", mnt)
                sudo("mount", part, mnt)
                sudo("rm", "-f", os.path.join(mnt, "meta-data"))
                sudo("umount", mnt)
                sudo("mount", "-o", "ro", part, mnt)
                expect_raises(RuntimeError, app.verify_seed_files, files, mnt, rec.log, rec.progress,
                              contains="Verification FAILED")
            finally:
                sudo("umount", mnt, check=False)
                with contextlib.suppress(OSError):
                    os.rmdir(mnt)

        # The same drive again with another label: the label really comes from the seed.
        with seed_engine_patches(app, name, "EPMA-SEED", files):
            app.build_seed_usb("debian", name, Recorder().log, priv, expected_size=size)
        check_seed_drive(app, dev, "EPMA-SEED", files)
# ===== end hardening: engine-seed =====


SCENARIOS = [
    ("raw-write", scenario_raw_write),
    ("windows-copy", scenario_windows_copy),
    ("windows-split", scenario_windows_split),
    ("windows-hardening", scenario_windows_hardening),
    ("verify-diff", scenario_verify_diff),
    ("seed-drive", scenario_seed_drive),
]


# --------------------------------------------------------------------------- driver
def prerequisites_problem():
    if sys.platform != "linux":
        return "not running on Linux"
    if not (os.environ.get("GITHUB_ACTIONS") == "true" or os.environ.get("E2E_ALLOW_LOOPBACK") == "1"):
        return "refusing to run outside GitHub Actions (set E2E_ALLOW_LOOPBACK=1 to override on a throw-away VM)"
    missing = [t for t in NEEDED_TOOLS if not shutil.which(t)]
    if missing:
        return "missing tools: " + ", ".join(missing)
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        return "passwordless sudo is not available"
    probe = subprocess.run(["sudo", "-n", "losetup", "-f"], capture_output=True)
    if probe.returncode != 0:
        return "loop devices are not available"
    return None


def main():
    problem = prerequisites_problem()
    if problem:
        print(f"{'FAIL' if REQUIRE else 'SKIP'}: loopback e2e cannot run: {problem}")
        return 1 if REQUIRE else 0

    app = import_app()
    workdir = tempfile.mkdtemp(prefix="epma-e2e-")
    tempfile.tempdir = workdir  # the app's mount-point directories land here too, so cleanup finds them
    priv = FakePriv()
    results = []
    try:
        for name, fn in SCENARIOS:
            rec = Recorder()
            print(f"\n=== {name}")
            try:
                fn(app, workdir, priv, rec)
                results.append((name, "PASS", ""))
                print(f"[PASS] {name}")
                if VERBOSE:
                    print("\n".join("    " + line for line in rec.lines))
            except Skip as e:
                results.append((name, "SKIP", str(e)))
                print(f"[SKIP] {name}: {e}")
            except Exception as e:
                results.append((name, "FAIL", f"{type(e).__name__}: {e}"))
                print(f"[FAIL] {name}: {type(e).__name__}: {e}")
                traceback.print_exc()
                print("--- application log (last 60 lines) ---")
                print("\n".join("    " + line for line in rec.lines[-60:]))
            finally:
                cleanup_workdir_devices(workdir)
    finally:
        cleanup_workdir_devices(workdir)
        shutil.rmtree(workdir, ignore_errors=True)

    print("\n=== summary")
    for name, status, detail in results:
        print(f"  {status:5} {name} {detail}")
    failed = [r for r in results if r[1] == "FAIL"]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
