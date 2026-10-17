#!/usr/bin/env python3
"""Headless per-distribution probe, run inside a bare distro container by CI.

It checks the Linux package-manager logic of the application against a real distro:

  1. linux_detect_pkg_manager() finds the manager this distro ships (--expect);
  2. linux_build_install_command() builds the exact, expected command for EVERY
     manager and rejects bad input;
  3. with --install, the command built for this distro is actually executed (the
     container runs as root) and every tool in LINUX_REQUIRED_TOOLS must then be on
     PATH. That proves the package names in LINUX_PKG_MAP exist in that distro.

Only Python's standard library is needed. When Tkinter is not installed in the
container, the module is imported against a stub (see _appimport.py); nothing here
opens a window.

Usage: python3 tests/e2e/distro_probe.py --expect apt-get [--install]
"""

import argparse
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _appimport import import_app, uses_tk_stub  # noqa: E402

ALL_TOOLS = ["parted", "mkfs.vfat", "wipefs", "partprobe", "rsync", "wimlib-imagex"]

# Independent restatement of what each manager must be told to install for ALL tools.
EXPECTED_ALL = {
    "apt-get": "apt-get update && apt-get install -y dosfstools parted rsync util-linux wimtools",
    "dnf": "dnf install -y dosfstools parted rsync util-linux wimlib-utils",
    "yum": "yum install -y dosfstools parted rsync util-linux wimlib-utils",
    "pacman": "pacman -Syu --noconfirm dosfstools parted rsync util-linux wimlib",
    "zypper": "zypper --non-interactive install dosfstools parted rsync util-linux wimlib",
    "apk": "apk add dosfstools parted rsync util-linux-misc wimlib",
}
# A single missing tool must pull in only its own package.
EXPECTED_ONE = {
    "apt-get": "apt-get update && apt-get install -y wimtools",
    "dnf": "dnf install -y wimlib-utils",
    "yum": "yum install -y wimlib-utils",
    "pacman": "pacman -Syu --noconfirm wimlib",
    "zypper": "zypper --non-interactive install wimlib",
    "apk": "apk add wimlib",
}


def check(condition, message):
    if not condition:
        print(f"FAIL: {message}")
        sys.exit(1)
    print(f"ok: {message}")


def raises(exc_type, fn, *args):
    try:
        fn(*args)
    except exc_type:
        return True
    return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect", required=True, choices=sorted(EXPECTED_ALL),
                        help="package manager this container must report")
    parser.add_argument("--install", action="store_true",
                        help="run the install command for real and check the tools afterwards")
    args = parser.parse_args()

    app = import_app()
    print(f"python {sys.version.split()[0]}, tkinter {'STUB' if uses_tk_stub() else 'real'}")

    # 1. detection
    detected = app.linux_detect_pkg_manager()
    check(detected == args.expect, f"linux_detect_pkg_manager() -> {detected!r} (expected {args.expect!r})")

    # 2. command construction, every manager
    check(sorted(app.LINUX_INSTALL_CMD_TEMPLATE) == sorted(EXPECTED_ALL),
          "the application supports exactly the managers this probe knows")
    for mgr, expected in EXPECTED_ALL.items():
        got = app.linux_build_install_command(mgr, ALL_TOOLS)
        check(got == expected, f"{mgr}: full install command\n      got      {got}\n      expected {expected}")
        one = app.linux_build_install_command(mgr, ["wimlib-imagex"])
        check(one == EXPECTED_ONE[mgr], f"{mgr}: single-tool command -> {one}")
        check(raises(ValueError, app.linux_build_install_command, mgr, []), f"{mgr}: nothing missing is rejected")
        check(raises(ValueError, app.linux_build_install_command, mgr, ["not-a-required-tool; rm -rf /"]),
              f"{mgr}: unknown tool names are rejected")
    check(raises(ValueError, app.linux_build_install_command, "brew", ["rsync"]), "unsupported manager is rejected")
    check(raises(ValueError, app.linux_build_install_command, None, ["rsync"]), "missing manager is rejected")

    # every required tool is mapped for every manager (a gap would silently skip an install)
    for mgr in EXPECTED_ALL:
        unmapped = [t for t in app.LINUX_REQUIRED_TOOLS if t not in app.LINUX_PKG_MAP.get(mgr, {})]
        check(not unmapped, f"{mgr}: every required tool has a package name (unmapped: {unmapped})")

    # 3. optional: really install, then make sure the tools exist
    if args.install:
        missing = [t for t in app.LINUX_REQUIRED_TOOLS if not shutil.which(t)]
        command = app.linux_build_install_command(detected, missing or ALL_TOOLS)
        print(f"running: {command}")
        rc = subprocess.run(["sh", "-c", command]).returncode  # noqa: S603 - fixed allow-list command, container only
        check(rc == 0, f"the install command exits 0 (got {rc})")
        still_missing = [t for t in app.LINUX_REQUIRED_TOOLS if not shutil.which(t)]
        check(not still_missing, f"all required tools are on PATH after install (missing: {still_missing})")

    print("PROBE PASSED")


if __name__ == "__main__":
    main()
