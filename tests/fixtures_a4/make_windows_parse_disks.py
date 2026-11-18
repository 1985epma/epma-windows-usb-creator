"""Regenerates windows_parse_disks.json: the Python windows_parse_disks() on a set of inputs (python3 tests/fixtures_a4/make_windows_parse_disks.py tests/fixtures_a4/windows_parse_disks.json)."""
import json
import os
import sys

os.environ["WIN11USB_DISABLE_AUDIT_LOG"] = "1"
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
import py_dump

m = py_dump.load()
GIB = 1024 ** 3


def rec(number=3, **over):
    r = {"Number": number, "Model": "SanDisk Ultra", "Serial": "ABC123", "UniqueId": "USBSTOR\\X", "BusType": "USB",
         "Size": 16 * GIB, "SectorSize": 512, "HoldsSystem": False,
         "Volumes": [{"Letter": "E", "Label": "OLD", "FileSystem": "FAT32", "Size": 8 * GIB, "Free": 6 * GIB}]}
    r.update(over)
    return r


texts = []
texts.append(json.dumps([rec()]))
texts.append(json.dumps(rec()))
texts.append("")
texts.append("  \n")
texts.append("[]")
texts.append(json.dumps([rec(BusType="SATA"), rec(BusType="usb", Number=4), rec(BusType=None, Number=5)]))
texts.append(json.dumps([rec(HoldsSystem=True), rec(HoldsSystem=None, Number=4), rec(HoldsSystem=0, Number=5)]))
texts.append(json.dumps([rec(Size=0), {"Number": "x"}, {"BusType": "USB"}, rec(Size=-5, Number=6)]))
texts.append(json.dumps([rec(Number="7", Size="1000", Model="")]))
texts.append(json.dumps([rec(Number=12345), rec(Number=-1), rec(Number=7.9), rec(Number=True)]))
texts.append(json.dumps([rec(Volumes=[{"Letter": "", "Label": "", "FileSystem": "", "Size": 100, "Free": -1}])]))
texts.append(json.dumps([rec(Volumes=[{"Letter": "F", "Label": "", "FileSystem": "NTFS", "Size": 100, "Free": 200},
                                      {"Letter": "G", "Label": "DATA", "FileSystem": "exFAT", "Size": 100, "Free": 100},
                                      {"Letter": None, "Label": None, "FileSystem": None, "Size": None, "Free": None}])]))
texts.append(json.dumps([rec(Volumes=[]), rec(Volumes=None, Number=8)]))
texts.append(json.dumps([rec(Serial=None, UniqueId="", Model="  Spaces  "), rec(Serial=12345, Number=9)]))
texts.append(json.dumps([rec(Number=1), rec(Number=2, Model="B"), rec(Number=10, Model="C")]))

cases = []
for text in texts:
    try:
        disks = m.windows_parse_disks(text)
        out = [{"id": d["id"], "size": d["size"], "model": d["model"] or None, "volumes": d["volumes"],
                "identity": [list(p) for p in d["identity"]]} for d in disks]
        cases.append({"text": text, "disks": out})
    except Exception as e:  # noqa: BLE001
        cases.append({"text": text, "error": type(e).__name__})
path = sys.argv[1]
with open(path, "w", encoding="utf-8") as fh:
    json.dump({"cases": cases}, fh, indent=1)
print(len(cases), "cases ->", path)
