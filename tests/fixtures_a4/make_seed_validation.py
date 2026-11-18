"""Regenerates seed_validation.json: what the Python seed validators answer (or the exact error message) for a set of
inputs (python3 tests/fixtures_a4/make_seed_validation.py tests/fixtures_a4/seed_validation.json)."""
import json
import os
import sys

os.environ["WIN11USB_DISABLE_AUDIT_LOG"] = "1"
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
import py_dump

m = py_dump.load()
MIB = 1024 * 1024

PATHS = [
    "user-data", "a/b/c.txt", "sources/$OEM$/$$/Setup/Scripts/SetupComplete.cmd", "l\u00e9ame-a\u00e7\u00e3o.txt",
    "..", "../etc/passwd", "a/../../b", "a/..", "a/../b", "/etc/passwd", "/user-data", "//server/share",
    "C:/Windows/x", "a:b", "a\\b", "..\\x", "\\abs", "a\x00b", "a\nb", "a\tb", "a\x7fb", "a\x1fb", "a" * 240, "a" * 241,
    "d/" * 120 + "ab", "", "a//b", "a/", "./a", "a/./b", ".", "a?", "a*b", "a<b", 'a"b', "a|b", "name.", "name ",
    "dir /x", "CON", "nul.txt", "COM1", "lpt9.cfg", "a?*|", "x" * 5000 + "\\", "it's", 'it\'s "quoted"', "tab\there",
    "\u00e9\u00a0x", "zero\u200bwidth", "caf\u00e9/\u4e2d\u6587.txt", "a b/c d", "name.with.dots", "aux.txt.bak",
    "Nul .txt", "com0", "COM10",
]

cases = []
for path in PATHS:
    files = {path: b"x"}
    try:
        m.validate_seed_files(files)
        cases.append({"files": [[path, 1]], "ok": True})
    except ValueError as e:
        cases.append({"files": [[path, 1]], "error": str(e)})

MULTI = [
    [["README.txt", 1], ["readme.TXT", 1]],
    [["A/b", 1], ["a/B", 1]],
    [["a", 1], ["a/b", 1]],
    [["A", 1], ["a/b", 1]],
    [["a/b", 1], ["a", 1]],
    [["a/b/c", 1], ["A/B", 1]],
    [["a/x", 1], ["b/x", 1]],
    [["ok", 1], ["../bad", 1], ["a\\b", 1]],
    [["big", 256 * 1024]],
    [["big", 256 * 1024 + 1]],
    [["f%d" % i, 256 * 1024] for i in range(8)],
    [["f%d" % i, 256 * 1024] for i in range(9)],
    [["f%d" % i, 0] for i in range(128)],
    [["f%d" % i, 0] for i in range(129)],
    [["stra\u00dfe", 1], ["STRASSE", 1]],
    [["\u00c9", 1], ["\u00e9", 1]],
]
for spec in MULTI:
    files = {name: b"x" * size for name, size in spec}
    try:
        m.validate_seed_files(files)
        cases.append({"files": spec, "ok": True})
    except ValueError as e:
        cases.append({"files": spec, "error": str(e)})
try:
    m.validate_seed_files({})
except ValueError as e:
    cases.append({"files": [], "error": str(e)})

labels = []
for label in ["CIDATA", "OEMDRV", "EPMA-SEED", "A", "A" * 11, "_X", "0-9_", "", "A" * 12, "cidata", "CI DATA", "CI.DATA",
              "CIDATA\n", "-X", "A;B", "$(id)", "A/B", "\u00c1", "A\x00", "CIDATA ", " CIDATA", "'", 'a"b', "x" * 200]:
    try:
        m.validate_seed_label(label)
        labels.append({"label": label, "ok": True})
    except ValueError as e:
        labels.append({"label": label, "error": str(e)})

sizes = []
for size in [None, 0, 1, 10 * MIB, 64 * MIB - 1, 64 * MIB, 16 * 1024 * MIB]:
    try:
        m.check_seed_target_size(size)
        sizes.append({"size": size, "ok": True})
    except ValueError as e:
        sizes.append({"size": size, "error": str(e)})

manifests = []
for spec in [[["x", b"1"], ["y", b"2"]], [["ab", b"c"]], [["a", b"bc"]], [["b", b"2"], ["a", b"1"]],
             [["l\u00e9", b"\x00\xff"], ["Z", b""]]]:
    files = {name: data for name, data in spec}
    manifests.append({"files": [[n, list(d)] for n, d in spec], "sha256": m._seed_manifest_sha256(files)})

with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump({"files": cases, "labels": labels, "sizes": sizes, "manifests": manifests}, fh, indent=1,
              ensure_ascii=True)
print(len(cases), "file cases,", len(labels), "labels,", len(sizes), "sizes,", len(manifests), "manifests")
