#!/usr/bin/env python3
"""Print the CHANGELOG.md section of one release (standard library only).

    python .github/scripts/changelog_section.py v1.1.0 [--file CHANGELOG.md]

Looks for a heading `## [1.1.0]` (an optional leading "v" on the argument is ignored)
and prints everything up to the next `## ` heading, without the heading itself.
Exit status 0 with the text on stdout; exit status 1 and nothing on stdout when the
section is missing or empty, so a workflow can fall back to generic notes.
"""

import argparse
import re
import sys


def extract(text, version):
    version = version[1:] if version.startswith("v") else version
    heading = re.compile(r"^##\s+\[" + re.escape(version) + r"\](?:\s.*)?$")
    lines, inside, body = text.splitlines(), False, []
    for line in lines:
        if inside:
            if line.startswith("## ") or re.match(r"^\[[^\]]+\]:\s", line):
                break
            body.append(line)
        elif heading.match(line):
            inside = True
    return "\n".join(body).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("version")
    parser.add_argument("--file", default="CHANGELOG.md")
    args = parser.parse_args()
    try:
        with open(args.file, encoding="utf-8") as fh:
            section = extract(fh.read(), args.version)
    except OSError:
        return 1
    if not section:
        return 1
    print(section)
    return 0


if __name__ == "__main__":
    sys.exit(main())
