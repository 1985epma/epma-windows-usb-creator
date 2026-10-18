#!/usr/bin/env python3
"""End-to-end test of the REAL Windows code paths, against a virtual disk (VHD).

!!  FOR GITHUB ACTIONS WINDOWS RUNNERS (or a throw-away VM).  DO NOT RUN ON A MACHINE  !!
!!  YOU CARE ABOUT: it uses diskpart, Clear-Disk, Format-Volume and raw disk writes.     !!

Everything runs against a VHD that this script creates itself (`diskpart: create vdisk`, `attach vdisk`), so no
physical disk is touched; the script refuses to hand any disk to the application that it did not create (it checks
that the disk number belongs to its own VHD). It needs an elevated process, so it will not start unless it is
running under GitHub Actions (GITHUB_ACTIONS=true) or E2E_ALLOW_VHD=1 is set.

A VHD is not a USB drive, so two things are stood in for - and only these two:
  * the drive list (`get_external_disks`) offers the VHD, because the real one only offers BusType USB;
  * the "is it USB?" test inside the PowerShell scripts is removed from the script text.
Everything else (Clear-Disk, GPT, Format-Volume, Mount-DiskImage, the copy, DISM, the raw write and its read-back)
is the real code.

Scenarios (each with its own VHD, always detached in `finally`):

  raw-write     windows_write_raw + windows_raw_verify: the disk must equal the image; a deliberately flipped
                byte must make the verification raise.
  windows-copy  windows_build_usb on a real UDF ISO (built with IMAPI2): GPT + FAT32, label, every file present
                and identical.
  windows-split windows_build_usb with FAT32_MAX_FILE_SIZE patched tiny and a real WIM (DISM /Capture-Image),
                exercising DISM /Split-Image and the part check.
  seed-drive    windows_build_seed_usb with a small file set: label, every file byte for byte.

Environment:
  E2E_REQUIRE=1   a missing prerequisite is a FAILURE instead of a skip (CI sets this).
  E2E_VERBOSE=1   print the application log of every scenario, not only of failed ones.
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
import time
import traceback
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _appimport import import_app  # noqa: E402

REQUIRE = os.environ.get("E2E_REQUIRE") == "1"
VERBOSE = os.environ.get("E2E_VERBOSE") == "1"
MIB = 1024 * 1024
POWERSHELL = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0",
                          "powershell.exe")
DISKPART = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "diskpart.exe")
DISM = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "dism.exe")


class Skip(Exception):
    pass


# --------------------------------------------------------------------------- helpers
def ps(script, check=True):
    proc = subprocess.run([POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                           "-Command", script], capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise RuntimeError(f"PowerShell failed ({proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}")
    return proc.stdout.strip()


def diskpart(lines):
    path = tempfile.mktemp(suffix=".txt")
    with open(path, "w", encoding="ascii") as fh:
        fh.write("\n".join(lines) + "\n")
    try:
        return subprocess.run([DISKPART, "/s", path], capture_output=True, text=True, check=True).stdout
    finally:
        os.remove(path)


@contextlib.contextmanager
def vhd(workdir, name, size_mb=512):
    """Create and attach a VHD; yield (disk number, vhd path); always detach it afterwards."""
    path = os.path.join(workdir, f"{name}.vhd")
    diskpart([f'create vdisk file="{path}" maximum={size_mb} type=expandable', f'select vdisk file="{path}"',
              "attach vdisk"])
    try:
        number = int(ps(f"(Get-DiskImage -ImagePath '{path}' | Get-Disk).Number"))
        yield number, path
    finally:
        with contextlib.suppress(Exception):
            diskpart([f'select vdisk file="{path}"', "detach vdisk"])


def make_hybrid_iso(path, size, seed=1):
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


MAKE_ISO = r"""
param([string]$Dir, [string]$Out, [string]$Label)
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
public static class EpmaIsoWriter {
  public static void Write(object stream, string path, int blockSize, int blocks) {
    IStream s = (IStream)stream;
    byte[] buf = new byte[blockSize];
    IntPtr read = Marshal.AllocHGlobal(4);
    try {
      using (FileStream fs = File.Create(path)) {
        for (int i = 0; i < blocks; i++) {
          s.Read(buf, blockSize, read);
          fs.Write(buf, 0, blockSize);
        }
      }
    } finally { Marshal.FreeHGlobal(read); }
  }
}
'@
$fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
$fsi.FileSystemsToCreate = 5
$fsi.VolumeName = $Label
$fsi.Root.AddTree($Dir, $false)
$result = $fsi.CreateResultImage()
[EpmaIsoWriter]::Write($result.ImageStream, $Out, $result.BlockSize, $result.TotalBlocks)
"""


def build_iso(workdir, tree, name):
    """An ISO (ISO 9660 + UDF) of the folder `tree`, made with IMAPI2."""
    out = os.path.join(workdir, name)
    script = os.path.join(workdir, "make_iso.ps1")
    with open(script, "w", encoding="utf-8-sig") as fh:
        fh.write(MAKE_ISO)
    proc = subprocess.run([POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                           "-File", script, tree, out, "E2EWIN"], capture_output=True, text=True)
    if proc.returncode != 0 or not os.path.isfile(out):
        raise Skip("could not build an ISO with IMAPI2: " + (proc.stderr.strip() or proc.stdout.strip())[:300])
    return out


class Recorder:
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


def disk_entry(app, number, size):
    return app._disk_entry(f"PhysicalDrive{number}", size, "E2E virtual disk", [], ())


@contextlib.contextmanager
def engine_patches(app, number, size):
    """Offer the VHD as the only drive and drop the 'is it USB' test from the scripts (and nothing else)."""
    own = {f"PhysicalDrive{number}"}

    def listing():
        return [disk_entry(app, number, size)]

    def strip_usb_test(script):
        return script.replace("$disk.BusType -ne 'USB'", "$false")

    patched = {name: strip_usb_test(getattr(app, name))
               for name in ("WINDOWS_PREPARE_SCRIPT", "WINDOWS_PREPARE_RAW_SCRIPT")}
    assert all(patched[n] != getattr(app, n) for n in patched), "the USB test was not found in the scripts"
    real_disk_number = app.windows_disk_number

    def guarded_number(dev):  # safety net: never operate on a disk this script did not create
        assert dev in own, f"refusing {dev}: not the e2e VHD"
        return real_disk_number(dev)

    with mock.patch.object(app, "get_external_disks", listing), \
            mock.patch.object(app, "windows_get_external_disks", listing), \
            mock.patch.object(app, "windows_disk_number", guarded_number), \
            mock.patch.multiple(app, **patched):
        yield


def volume_letter(number):
    letter = ps(f"(Get-Partition -DiskNumber {number} | Where-Object DriveLetter | "
                "Select-Object -First 1).DriveLetter")
    assert re.fullmatch(r"[A-Za-z]", letter), f"no volume with a letter on disk {number}: {letter!r}"
    return letter.upper()


def volume_label(letter):
    return ps(f"(Get-Volume -DriveLetter {letter}).FileSystemLabel")


def files_equal(root_a, root_b, rels):
    for rel in rels:
        a, b = os.path.join(root_a, rel), os.path.join(root_b, rel)
        assert os.path.isfile(b), f"{rel} is missing on the drive"
        assert sha256(a) == sha256(b), f"{rel} differs"


# --------------------------------------------------------------------------- scenarios
def scenario_raw_write(app, workdir, rec):
    iso = os.path.join(workdir, "raw.iso")
    make_hybrid_iso(iso, 24 * MIB + 1234)
    with vhd(workdir, "raw", 256) as (number, _path), engine_patches(app, number, 256 * MIB):
        app.windows_write_raw(iso, f"PhysicalDrive{number}", rec.log, rec.progress, None, eject=False)
        total = os.path.getsize(iso)
        with app.open_windows_raw_disk(number) as disk:
            app.windows_raw_verify(iso, disk, rec.log)
        with app.open_windows_raw_disk(number, write=True) as disk:  # corrupt one byte past the head
            offset = 8 * MIB
            good = disk.read_at(offset, app.WINDOWS_RAW_ALIGN)
            bad = bytes([good[0] ^ 0xFF]) + good[1:]
            disk.write_at(offset, bad)
        with app.open_windows_raw_disk(number) as disk:
            expect_raises(RuntimeError, app.windows_raw_verify, iso, disk, rec.log, contains="Verification FAILED")
        assert total > 24 * MIB
        # a non-hybrid image is refused before the disk is touched
        plain = os.path.join(workdir, "plain.iso")
        write_random(plain, 4 * MIB, 3)
        expect_raises(ValueError, app.windows_write_raw, plain, f"PhysicalDrive{number}", rec.log)


def make_windows_tree(workdir, name, wim=None):
    tree = os.path.join(workdir, name)
    write_random(os.path.join(tree, "bootmgr"), 40_000, 1)
    write_random(os.path.join(tree, "efi", "boot", "bootx64.efi"), 120_000, 2)
    write_random(os.path.join(tree, "sources", "boot.wim"), 300_000, 3)
    if wim is None:
        write_random(os.path.join(tree, "sources", "install.wim"), 2 * MIB, 4)
    else:
        os.makedirs(os.path.join(tree, "sources"), exist_ok=True)
        shutil.copy(wim, os.path.join(tree, "sources", "install.wim"))
    return tree


def scenario_windows_copy(app, workdir, rec):
    tree = make_windows_tree(workdir, "tree-copy")
    iso = build_iso(workdir, tree, "copy.iso")
    with vhd(workdir, "copy", 512) as (number, _path), engine_patches(app, number, 512 * MIB):
        app.windows_build_usb(iso, f"PhysicalDrive{number}", rec.log, None, rec.progress, None, eject=False)
        letter = volume_letter(number)
        assert volume_label(letter) == app.VOL_NAME, "wrong volume label"
        style = ps(f"(Get-Disk -Number {number}).PartitionStyle")
        assert style == "GPT", f"partition style is {style}"
        fs = ps(f"(Get-Volume -DriveLetter {letter}).FileSystem")
        assert fs == "FAT32", f"file system is {fs}"
        files_equal(tree, f"{letter}:\\", ["bootmgr", os.path.join("efi", "boot", "bootx64.efi"),
                                           os.path.join("sources", "boot.wim"),
                                           os.path.join("sources", "install.wim")])
    assert any("Verification passed" in line for line in rec.lines), "no verification line in the log"


def scenario_windows_split(app, workdir, rec):
    capture = os.path.join(workdir, "capture")
    write_random(os.path.join(capture, "data.bin"), 3 * MIB, 9)
    wim = os.path.join(workdir, "real.wim")
    subprocess.run([DISM, "/Capture-Image", f"/ImageFile:{wim}", f"/CaptureDir:{capture}", "/Name:e2e"],
                   capture_output=True, check=True)
    tree = make_windows_tree(workdir, "tree-split", wim=wim)
    iso = build_iso(workdir, tree, "split.iso")
    with vhd(workdir, "split", 512) as (number, _path), engine_patches(app, number, 512 * MIB), \
            mock.patch.object(app, "FAT32_MAX_FILE_SIZE", 1 * MIB):
        app.windows_build_usb(iso, f"PhysicalDrive{number}", rec.log, None, rec.progress, None, eject=False)
        letter = volume_letter(number)
        sources = f"{letter}:\\sources"
        names = sorted(n.lower() for n in os.listdir(sources))
        assert "install.swm" in names, f"no install.swm on the drive: {names}"
        assert "install.wim" not in names, "the unsplit install.wim must not be on the drive"
    assert any("DISM" in line for line in rec.lines), "DISM was not used"
    assert any("Verification passed" in line for line in rec.lines)


def scenario_seed_drive(app, workdir, rec):
    files = {"harden.cmd": b"@echo off\r\necho hi\r\n", "harden.ps1": b"\xef\xbb\xbfWrite-Output 'x'\r\n" * 200,
             "README.txt": b"seed\r\n"}
    stage = app.stage_seed_files(files)
    try:
        with vhd(workdir, "seed", 256) as (number, _path), engine_patches(app, number, 256 * MIB):
            app.windows_build_seed_usb("EPMA-SEED", files, stage, f"PhysicalDrive{number}", rec.log,
                                       rec.progress, None, eject=False)
            letter = volume_letter(number)
            assert volume_label(letter) == "EPMA-SEED", "wrong seed label"
            for rel, data in files.items():
                with open(os.path.join(f"{letter}:\\", rel), "rb") as fh:
                    assert fh.read() == data, f"{rel} differs"
    finally:
        shutil.rmtree(stage, ignore_errors=True)


SCENARIOS = [
    ("raw-write", scenario_raw_write),
    ("windows-copy", scenario_windows_copy),
    ("windows-split", scenario_windows_split),
    ("seed-drive", scenario_seed_drive),
]


# --------------------------------------------------------------------------- driver
def prerequisites_problem():
    if sys.platform != "win32":
        return "not running on Windows"
    if not (os.environ.get("GITHUB_ACTIONS") == "true" or os.environ.get("E2E_ALLOW_VHD") == "1"):
        return "refusing to run outside GitHub Actions (set E2E_ALLOW_VHD=1 to override on a throw-away VM)"
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        return "the process is not elevated"
    for tool in (POWERSHELL, DISKPART, DISM):
        if not os.path.isfile(tool):
            return f"missing {tool}"
    return None


def main():
    problem = prerequisites_problem()
    if problem:
        print(f"{'FAIL' if REQUIRE else 'SKIP'}: Windows e2e cannot run: {problem}")
        return 1 if REQUIRE else 0

    app = import_app()
    workdir = tempfile.mkdtemp(prefix="epma-e2e-")
    results = []
    try:
        for name, fn in SCENARIOS:
            rec = Recorder()
            print(f"\n=== {name}")
            try:
                fn(app, workdir, rec)
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
            time.sleep(1)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    print("\n=== summary")
    for name, status, detail in results:
        print(f"  {status:5} {name} {detail}")
    skipped_required = REQUIRE and any(r[1] == "SKIP" for r in results)
    failed = [r for r in results if r[1] == "FAIL"]
    return 1 if failed or skipped_required else 0


if __name__ == "__main__":
    sys.exit(main())
