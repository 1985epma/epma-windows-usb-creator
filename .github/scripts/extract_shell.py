#!/usr/bin/env python3
"""Extract the shell scripts embedded in win11_usb_creator.py so shellcheck can lint them.

The application runs privileged shell snippets through `PrivilegeHelper.run_script`
(`sudo bash -c SCRIPT win11_usb_creator ARG1 ARG2 ...`) and builds a package-install
one-liner from `LINUX_INSTALL_CMD_TEMPLATE`. Those snippets live inside Python string
literals, where no shell linter can see them, yet they run as ROOT. This tool finds
them with `ast` (no regexes over source text, nothing is executed or imported) and
writes each one to its own `.sh` file.

What counts as an embedded script:
  * a string expression assigned to a name containing "script" (VERIFY_RAW_SCRIPT,
    prep_script, cleanup_script, ...) or containing "install_cmd" (the per-package-
    manager command templates, whose values are dict entries);
  * any string expression that starts with `set -eu` (e.g. the `remount` snippet);
  * the first argument of any `.run_script(...)` call when it is a string expression.

f-string placeholders are replaced by the value of the module-level string constant
of the same name when there is one (VOL_NAME), else by a harmless token; the
`{pkgs}` placeholder of the install templates becomes `pkg`.

Usage:
    python .github/scripts/extract_shell.py OUT_DIR [--source win11_usb_creator.py] [--min 5]

Each script is written to OUT_DIR/<NN>_<name>_L<line>.sh (the line is where the string
starts in the Python source), and the list of generated files is printed one per line.
Exit status: 0 on success, 2 when fewer than --min scripts were found (the extractor
itself broke, or the scripts were moved somewhere it cannot see).

INTENTIONAL SHELLCHECK DISABLES live in DISABLES below, keyed by script name. Each one
needs a written reason; they are injected into the generated file as
`# shellcheck disable=...` directives so they show up in the CI log. There are none
today -- keep it that way unless a finding is a verified false positive.
"""

import argparse
import ast
import os
import re
import sys

# {script_name: [(shellcheck_code, "why this is a false positive"), ...]}
DISABLES = {}

NAME_RE = re.compile(r"script|install_cmd", re.IGNORECASE)
PLACEHOLDER = "x"


def module_string_constants(tree):
    """Module-level NAME = "literal" assignments, used to expand f-string placeholders."""
    consts = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    consts[target.id] = node.value.value
    return consts


def render(node, consts):
    """Return the text of a string expression, or None when it is not statically known."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.JoinedStr):
        parts = []
        for piece in node.values:
            if isinstance(piece, ast.Constant):
                parts.append(str(piece.value))
            elif isinstance(piece, ast.FormattedValue):
                if isinstance(piece.value, ast.Name) and piece.value.id in consts:
                    parts.append(consts[piece.value.id])
                else:
                    parts.append(PLACEHOLDER)
            else:
                return None
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = render(node.left, consts), render(node.right, consts)
        return None if left is None or right is None else left + right
    return None


def is_string_expr(node):
    return isinstance(node, (ast.Constant, ast.JoinedStr, ast.BinOp)) and (
        not isinstance(node, ast.Constant) or isinstance(node.value, str)
    )


def target_names(node):
    names = []
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    for target in targets:
        if isinstance(target, ast.Name):
            names.append(target.id)
    return names


def find_scripts(tree, consts):
    """Return a list of (name, lineno, text), deduplicated by source position."""
    found = {}  # (lineno, col) -> (name, text)
    # value node -> the variable it is assigned to, so even a snippet that matched only
    # by content (e.g. `remount = 'set -eu...'`) gets a meaningful file name.
    assigned = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            names = target_names(node)
            if names:
                assigned[id(node.value)] = names[0]

    def add(name, node, text):
        if text is None or not text.strip():
            return
        found.setdefault((node.lineno, node.col_offset), (name, text))

    for node in ast.walk(tree):
        # 1. Assignments to *script* / *install_cmd* names (plain strings or dicts of strings).
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            for name in target_names(node):
                if not NAME_RE.search(name):
                    continue
                if isinstance(node.value, ast.Dict):
                    for key, value in zip(node.value.keys, node.value.values, strict=True):
                        if is_string_expr(value):
                            text = render(value, consts)
                            if text is not None:
                                text = text.replace("{pkgs}", "pkg")
                            label = key.value if isinstance(key, ast.Constant) else "item"
                            add(f"{name}_{label}", value, text)
                elif is_string_expr(node.value):
                    add(name, node.value, render(node.value, consts))
        # 2. Anything that starts like a strict-mode script.
        if is_string_expr(node):
            text = render(node, consts)
            if text is not None and text.lstrip().startswith("set -eu"):
                add(assigned.get(id(node), "inline"), node, text)
        # 3. First argument of run_script(...).
        if isinstance(node, ast.Call):
            func = node.func
            fname = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if fname == "run_script" and node.args and is_string_expr(node.args[0]):
                add(assigned.get(id(node.args[0]), "run_script_arg"), node.args[0], render(node.args[0], consts))

    return [(name, line, text) for (line, _col), (name, text) in sorted(found.items())]


def safe_name(name):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("_") or "script"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("out_dir", help="directory that will receive the .sh files")
    parser.add_argument("--source", default="win11_usb_creator.py", help="Python file to scan")
    parser.add_argument("--min", type=int, default=5, dest="minimum",
                        help="fail if fewer scripts than this are found (default: 5)")
    args = parser.parse_args(argv)

    with open(args.source, encoding="utf-8") as fh:
        source = fh.read()
    tree = ast.parse(source, filename=args.source)
    scripts = find_scripts(tree, module_string_constants(tree))

    if len(scripts) < args.minimum:
        print(f"ERROR: found only {len(scripts)} embedded script(s) in {args.source}, expected at least "
              f"{args.minimum}. The extractor no longer recognises the code layout.", file=sys.stderr)
        return 2

    os.makedirs(args.out_dir, exist_ok=True)
    for index, (name, line, text) in enumerate(scripts, 1):
        path = os.path.join(args.out_dir, f"{index:02d}_{safe_name(name)}_L{line}.sh")
        header = ["#!/usr/bin/env bash", f"# extracted from {args.source}:{line} ({name})"]
        # Mirrors how the app runs it: bash -c SCRIPT win11_usb_creator ARG1 ARG2 ...
        for key, entries in DISABLES.items():
            if name == key or name.startswith(key + "_"):
                for code, reason in entries:
                    header.append(f"# shellcheck disable={code} # {reason}")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(header) + "\n" + text.rstrip("\n") + "\n")
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
