"""Tests for the small helpers that replaced duplicated code (see CHANGELOG / refactor commits).

Like the rest of the suite nothing here touches a real device, uses sudo or the network.
"""
import os
import unittest
from unittest import mock

from tests.helpers import TempDirTestCase, app


class SilentRemoveTests(TempDirTestCase):
    def test_removes_files_and_ignores_missing_ones(self):
        a = self.write_file("a.txt", b"x")
        b = self.write_file("b.txt", b"y")
        app._silent_remove(a, self.path("missing.txt"), b)
        self.assertFalse(os.path.exists(a))
        self.assertFalse(os.path.exists(b))

    def test_swallows_os_errors_from_remove(self):
        with mock.patch.object(app.os, "remove", side_effect=PermissionError("denied")):
            app._silent_remove("/nonexistent/whatever")  # must not raise

    def test_rmdir_removes_empty_dirs_and_ignores_the_rest(self):
        empty = self.path("empty")
        os.mkdir(empty)
        full = self.path("full")
        os.mkdir(full)
        self.write_file("full/file", b"x")
        app._silent_rmdir(empty, full, self.path("missing"))
        self.assertFalse(os.path.exists(empty))
        self.assertTrue(os.path.isdir(full))  # not empty: left alone, no exception


if __name__ == "__main__":
    unittest.main()
