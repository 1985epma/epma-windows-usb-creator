#!/usr/bin/env python3
"""Dump module-level values of win11_usb_creator.py so big texts need not be retyped.

  python3 tools/py_dump.py text NAME OUTFILE        write a str constant (or the str returned by a call) as is
  python3 tools/py_dump.py call 'EXPR' OUTFILE      evaluate EXPR (in the module namespace) and write the str result
  python3 tools/py_dump.py rust NAME [--const RSNAME]  print a Rust literal for a constant (str/int/float/bool/bytes/
                                                    tuple/list/dict of those); dict -> &[(&str, &str)] when flat
  python3 tools/py_dump.py json EXPR OUTFILE        evaluate EXPR and write it as JSON (bytes -> latin-1 text)

Nothing here is part of the product; it only reads the Python reference implementation.
"""
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def load():
    spec = importlib.util.spec_from_file_location("win11_usb_creator", os.path.join(ROOT, "win11_usb_creator.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["win11_usb_creator"] = mod
    spec.loader.exec_module(mod)
    return mod


def rs_str(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20 or o == 0x7F:
            out.append("\\u{%x}" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def rs_val(v, indent=0):
    pad = "    " * indent
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, str):
        return rs_str(v)
    if isinstance(v, bytes):
        return 'b"' + "".join("\\x%02x" % b for b in v) + '"'
    if isinstance(v, (tuple, list)):
        inner = ",\n".join(pad + "    " + rs_val(x, indent + 1) for x in v)
        return "&[\n" + inner + ",\n" + pad + "]"
    if isinstance(v, dict):
        inner = ",\n".join(pad + "    (" + rs_val(k, indent + 1) + ", " + rs_val(x, indent + 1) + ")"
                           for k, x in v.items())
        return "&[\n" + inner + ",\n" + pad + "]"
    raise TypeError(type(v))


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    mod = load()
    cmd = argv[1]
    if cmd == "text":
        value = getattr(mod, argv[2])
        with open(argv[3], "w", encoding="utf-8", newline="") as fh:
            fh.write(value)
    elif cmd == "call":
        value = eval(argv[2], vars(mod))
        with open(argv[3], "w", encoding="utf-8", newline="") as fh:
            fh.write(value)
    elif cmd == "json":
        value = eval(argv[2], vars(mod))

        def enc(o):
            if isinstance(o, bytes):
                return o.decode("latin-1")
            raise TypeError(type(o))
        with open(argv[3], "w", encoding="utf-8") as fh:
            json.dump(value, fh, indent=1, ensure_ascii=False, default=enc)
    elif cmd == "rust":
        value = getattr(mod, argv[2])
        name = argv[argv.index("--const") + 1] if "--const" in argv else argv[2]
        print(f"pub static {name}: &[(&str, &str)] = {rs_val(value)};" if isinstance(value, dict)
              else f"pub const {name}: _ = {rs_val(value)};")
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
