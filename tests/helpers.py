"""Shared helpers for the unit tests.

Nothing here (or in the tests) touches a real device, uses sudo or the network:
privileged scripts are run locally on temp files, subprocess calls are mocked and the
audit log is disabled.
"""
import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest

os.environ["WIN11USB_DISABLE_AUDIT_LOG"] = "1"

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import win11_usb_creator as app  # noqa: E402

MIB = 1024 * 1024

FAKE_DISKS = [
    {"id": "disk9", "size": 16 * 1024 ** 3, "label": "/dev/disk9 — 16.0 GB"},
    {"id": "disk8", "size": 8 * 1024 ** 3, "label": "/dev/disk8 — 8.0 GB", "model": "Fake Stick"},
]


class TempDirTestCase(unittest.TestCase):
    """A test case with a private temp directory, removed afterwards."""

    def setUp(self):
        super().setUp()
        self._tmp = tempfile.TemporaryDirectory(prefix="epma-test-")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = os.path.realpath(self._tmp.name)

    def path(self, *parts):
        return os.path.join(self.tmp, *parts)

    def write_file(self, name, data):
        path = self.path(name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def make_iso(self, name="ubuntu.iso", size=2 * MIB, hybrid=True):
        """An ISO-sized file; `hybrid` adds the 0x55AA MBR boot signature."""
        data = bytearray(os.urandom(size))
        data[510:512] = b"\x55\xaa" if hybrid else b"\x00\x00"
        return self.write_file(name, bytes(data))


class Collector:
    """Callable that records everything it is called with (a stand-in for log/progress)."""

    def __init__(self):
        self.calls = []

    def __call__(self, *args):
        self.calls.append(args)

    @property
    def lines(self):
        return [c[0] for c in self.calls if len(c) == 1]


class LocalPriv:
    """Privilege helper that runs the engine's scripts as the current user, with bash.

    Same interface as PrivilegeHelper.run_script, but without sudo: the scripts are
    pointed at temp files standing in for the device.
    """

    cached_password = None

    def __init__(self):
        self.scripts = []

    def run_script(self, script, log, args=None, **_kw):
        args = [str(a) for a in (args or [])]
        self.scripts.append((script, args))
        with subprocess.Popen(["bash", "-c", script, "win11_usb_creator"] + args,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as proc:
            for line in proc.stdout:
                log(line.rstrip())
        if proc.returncode != 0:
            raise RuntimeError(f"script failed ({proc.returncode})")

    def clear_cached_password(self):
        pass


def run_main(argv, stdin_text=None):
    """Run app.main(argv) capturing stdout/stderr. Returns (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    stdin = io.StringIO(stdin_text if stdin_text is not None else "")
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        old_stdin, sys.stdin = sys.stdin, stdin
        try:
            code = app.main(argv)
        finally:
            sys.stdin = old_stdin
    return code, out.getvalue(), err.getvalue()
