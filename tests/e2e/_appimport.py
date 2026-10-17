"""Import helper shared by the end-to-end scripts.

`win11_usb_creator` may insist on Tkinter at import time (it exits with status 1 when
Tkinter is missing). The e2e scripts never open a window, so when the real Tkinter is
unavailable (a bare container, a headless server) they import the module against a
throw-away stub instead. When Tkinter IS installed it is used as is.
"""

import importlib
import os
import sys
import types

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MODULE_NAME = "win11_usb_creator"


class _StubModule(types.ModuleType):
    """A module whose every missing attribute is a distinct, empty class."""

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        cls = type(name, (), {})
        setattr(self, name, cls)
        return cls


def _install_tk_stub():
    tk = _StubModule("tkinter")
    tk.__path__ = []  # lets "import tkinter.ttk" style imports resolve to the entries below
    for sub in ("ttk", "filedialog", "messagebox"):
        mod = _StubModule(f"tkinter.{sub}")
        setattr(tk, sub, mod)
        sys.modules[f"tkinter.{sub}"] = mod
    sys.modules["tkinter"] = tk


def import_app(allow_tk_stub=True):
    """Return the imported application module. Never opens a window."""
    # Never write the audit log into the real home directory from a test run.
    os.environ.setdefault("WIN11USB_DISABLE_AUDIT_LOG", "1")
    if REPO_ROOT not in sys.path:
        sys.path.insert(0, REPO_ROOT)
    try:
        return importlib.import_module(MODULE_NAME)
    except (ImportError, SystemExit):
        if not allow_tk_stub:
            raise
    # Tkinter is missing: drop the half-imported module and retry against a stub.
    sys.modules.pop(MODULE_NAME, None)
    _install_tk_stub()
    return importlib.import_module(MODULE_NAME)


def uses_tk_stub():
    return isinstance(sys.modules.get("tkinter"), _StubModule)
