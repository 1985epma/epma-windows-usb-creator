#!/usr/bin/env python3
"""Regenerate tests/golden/ from the Python reference implementation (byte-exact expected outputs for Rust tests).

Layout:
  tests/golden/linux/harden-linux.sh                       linux_hardening_script("baseline")
  tests/golden/windows/harden.ps1                          windows_hardening_ps1("baseline") (bytes)
  tests/golden/windows-files/<relpath>                     hardening_files_windows("baseline")
  tests/golden/seed-<target>/<relpath> + LABEL             hardening_files_seed(<target>, "baseline")
  tests/golden/help_sections.json                          help_sections() as [[title, body], ...] (platform text varies)
  tests/golden/windows_describe.json                       describe_hardening_windows / _applied rows
"""
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import py_dump  # noqa: E402

ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "tests", "golden")


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data if isinstance(data, bytes) else data.encode("utf-8"))


def main():
    m = py_dump.load()
    if os.path.isdir(OUT):
        shutil.rmtree(OUT)
    write(os.path.join(OUT, "linux", "harden-linux.sh"), m.linux_hardening_script("baseline"))
    write(os.path.join(OUT, "windows", "harden.ps1"), m.windows_hardening_ps1("baseline"))
    for rel, data in m.hardening_files_windows("baseline").items():
        write(os.path.join(OUT, "windows-files", rel), data)
    for target in m.SEED_TARGETS:
        label, files = m.hardening_files_seed(target, "baseline")
        write(os.path.join(OUT, "seed-" + target, "LABEL"), label)
        for rel, data in files.items():
            write(os.path.join(OUT, "seed-" + target, rel), data)
    write(os.path.join(OUT, "help_sections.json"),
          json.dumps([[t, b] for t, b in m.help_sections()], indent=1, ensure_ascii=False))
    write(os.path.join(OUT, "windows_describe.json"), json.dumps({
        "describe": list(m.describe_hardening_windows("baseline")),
        "applied": list(m.describe_hardening_windows_applied("baseline")),
    }, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
