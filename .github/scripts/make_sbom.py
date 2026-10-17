#!/usr/bin/env python3
"""Generate a CycloneDX 1.5 (JSON) SBOM for epma-usb-creator, standard library only.

The project has ZERO Python dependencies (see requirements.txt), so the interesting
part of its bill of materials is what the program asks the operating system for at
run time: the disk and file tools it launches (parted, mkfs.vfat, wipefs, rsync,
wimlib-imagex, ...). Those are listed as components flagged with
`epma:runtime-system-dependency = true`. They are resolved from the host at run time,
so they carry no version here.

The tool list is cross-checked against LINUX_REQUIRED_TOOLS in win11_usb_creator.py
(read with `ast`, never imported): if the program starts requiring a tool that is not
described below, this script FAILS, so the SBOM cannot silently go stale.

Usage:
    python .github/scripts/make_sbom.py --version v1.1.0 --out sbom.cdx.json \
        [--source win11_usb_creator.py] [--artifact pacote/win11_usb_creator.py] \
        [--repo 1985epma/epma-windows-usb-creator] [--commit SHA]

Environment: SOURCE_DATE_EPOCH, when set, fixes the timestamp (reproducible output).
"""

import argparse
import ast
import datetime
import hashlib
import json
import os
import sys
import uuid

DEFAULT_REPO = "1985epma/epma-windows-usb-creator"
LICENSE_ID = "GPL-3.0-or-later"
SPEC_VERSION = "1.5"

# name -> (description, tools it provides, platforms where it is needed)
SYSTEM_DEPENDENCIES = {
    "rsync": ("File copy and checksum comparison of the ISO contents", ["rsync"], "linux"),
    "wimlib": ("Splits and verifies install.wim/install.esd (FAT32 4 GB limit)", ["wimlib-imagex"],
               "linux, macos"),
    "parted": ("Creates the GPT partition table", ["parted", "partprobe"], "linux"),
    "dosfstools": ("Formats the FAT32 volume", ["mkfs.vfat"], "linux"),
    "util-linux": ("wipefs, mount, umount, blockdev, eject and loop-device handling",
                   ["wipefs", "mount", "umount", "blockdev", "eject"], "linux"),
    "coreutils": ("dd (raw write and read-back), head, sync", ["dd", "head", "sync"], "linux, macos"),
    "diffutils": ("cmp (byte-for-byte verification of raw writes)", ["cmp"], "linux, macos"),
    "sudo": ("Privilege escalation for disk commands (pkexec is the fallback)", ["sudo", "pkexec"],
             "linux, macos"),
    "macos-disk-tools": ("diskutil and hdiutil, shipped with macOS", ["diskutil", "hdiutil"], "macos"),
}

PYTHON_RUNTIME = {
    "name": "python",
    "description": "Python interpreter with Tkinter (graphical interface); standard library only",
    "min": "3.10",
}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def required_tools_from_source(path):
    """LINUX_REQUIRED_TOOLS as written in the program, without importing it."""
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=path)
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "LINUX_REQUIRED_TOOLS"
                                                for t in node.targets):
            return list(ast.literal_eval(node.value))
    raise SystemExit(f"ERROR: LINUX_REQUIRED_TOOLS not found in {path}")


def prop(name, value):
    return {"name": name, "value": value}


def build_bom(version, repo, source, artifact, commit, now):
    clean = version[1:] if version.startswith("v") else version
    covered = {tool for _d, tools, _p in SYSTEM_DEPENDENCIES.values() for tool in tools}
    uncovered = [t for t in required_tools_from_source(source) if t not in covered]
    if uncovered:
        raise SystemExit(
            "ERROR: win11_usb_creator.py requires tools that SYSTEM_DEPENDENCIES in "
            f"{os.path.basename(__file__)} does not describe: {', '.join(uncovered)}. Add them.")

    base = f"https://github.com/{repo}"
    main_ref = f"pkg:github/{repo.lower()}@{version}"
    main = {
        "type": "application",
        "bom-ref": main_ref,
        "name": "epma-usb-creator",
        "version": clean,
        "description": "Create verified bootable USB drives from Windows 11, Linux and other ISOs, and Google's ChromeOS Flex, on macOS or Linux",
        "licenses": [{"license": {"id": LICENSE_ID}}],
        "purl": main_ref,
        "externalReferences": [
            {"type": "website", "url": base},
            {"type": "vcs", "url": f"{base}.git"},
            {"type": "issue-tracker", "url": f"{base}/issues"},
            {"type": "distribution", "url": f"{base}/releases/tag/{version}"},
            {"type": "documentation", "url": f"{base}/blob/{version}/SECURITY.md"},
        ],
        "properties": [prop("epma:python-dependencies", "none (standard library only)")],
    }
    if artifact:
        main["hashes"] = [{"alg": "SHA-256", "content": sha256_file(artifact)}]
        main["properties"].append(prop("epma:artifact", os.path.basename(artifact)))

    components = []
    refs = []

    def add(name, description, props):
        ref = f"system-dependency:{name}"
        refs.append(ref)
        components.append({
            "type": "application",
            "bom-ref": ref,
            "name": name,
            "description": description,
            "scope": "required",
            "purl": f"pkg:generic/{name}",
            "properties": [prop("epma:runtime-system-dependency", "true"),
                           prop("epma:version-resolution", "host operating system, at run time")] + props,
        })

    add(PYTHON_RUNTIME["name"], PYTHON_RUNTIME["description"],
        [prop("epma:minimum-version", PYTHON_RUNTIME["min"]), prop("epma:platforms", "linux, macos")])
    for name, (description, tools, platforms) in SYSTEM_DEPENDENCIES.items():
        add(name, description, [prop("epma:provides", ", ".join(tools)), prop("epma:platforms", platforms)])

    metadata_props = [
        prop("epma:sbom-scope", "Python packages: none. System tools are listed without versions because "
                                "they are resolved from the host at run time."),
    ]
    if commit:
        metadata_props.append(prop("epma:source-commit", commit))

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"{main_ref}#{commit or ''}")),
        "version": 1,
        "metadata": {
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "lifecycles": [{"phase": "build"}],
            "tools": {"components": [{"type": "application", "name": "make_sbom.py",
                                      "description": "stdlib-only CycloneDX generator of this repository"}]},
            "component": main,
            "properties": metadata_props,
        },
        "components": components,
        "dependencies": [{"ref": main_ref, "dependsOn": refs}] + [{"ref": r, "dependsOn": []} for r in refs],
    }
    validate(bom)
    return bom


def validate(bom):
    """Cheap structural checks (the full JSON schema is not available offline)."""
    problems = []
    if bom["bomFormat"] != "CycloneDX" or bom["specVersion"] != SPEC_VERSION:
        problems.append("wrong bomFormat/specVersion")
    refs = [bom["metadata"]["component"]["bom-ref"]] + [c["bom-ref"] for c in bom["components"]]
    if len(refs) != len(set(refs)):
        problems.append("duplicate bom-ref")
    for dep in bom["dependencies"]:
        if dep["ref"] not in refs or any(r not in refs for r in dep["dependsOn"]):
            problems.append(f"dangling dependency reference in {dep['ref']}")
    for comp in [bom["metadata"]["component"]] + bom["components"]:
        if not comp.get("type") or not comp.get("name"):
            problems.append("component without type/name")
    if problems:
        raise SystemExit("ERROR: invalid SBOM: " + "; ".join(problems))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--version", required=True, help="release tag, e.g. v1.1.0")
    parser.add_argument("--out", required=True, help="output file")
    parser.add_argument("--source", default="win11_usb_creator.py", help="program source (for the tool cross-check)")
    parser.add_argument("--artifact", help="file whose SHA-256 is recorded on the main component")
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY") or DEFAULT_REPO)
    parser.add_argument("--commit", default=os.environ.get("GITHUB_SHA", ""))
    args = parser.parse_args(argv)

    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    now = (datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc) if epoch
           else datetime.datetime.now(datetime.timezone.utc))
    bom = build_bom(args.version, args.repo, args.source, args.artifact, args.commit, now)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(bom, fh, indent=2, sort_keys=False)
        fh.write("\n")
    print(f"wrote {args.out}: CycloneDX {SPEC_VERSION}, {len(bom['components'])} components")
    return 0


if __name__ == "__main__":
    sys.exit(main())
