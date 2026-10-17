import os
import unittest
from unittest import mock

from tests.helpers import MIB, TempDirTestCase, app


class HumanSizeTests(unittest.TestCase):
    def test_units(self):
        self.assertEqual(app.human_size(0), "0.0 B")
        self.assertEqual(app.human_size(1023), "1023.0 B")
        self.assertEqual(app.human_size(1024), "1.0 KB")
        self.assertEqual(app.human_size(1536), "1.5 KB")
        self.assertEqual(app.human_size(5 * 1024 ** 2), "5.0 MB")
        self.assertEqual(app.human_size(16 * 1024 ** 3), "16.0 GB")
        self.assertEqual(app.human_size(2 * 1024 ** 4), "2.0 TB")

    def test_beyond_terabytes(self):
        self.assertEqual(app.human_size(3 * 1024 ** 5), "3.0 PB")

    def test_accepts_floats(self):
        self.assertEqual(app.human_size(1536.0), "1.5 KB")


class ValidateDeviceNameTests(unittest.TestCase):
    def check(self, is_mac, good, bad):
        with mock.patch.object(app, "IS_MAC", is_mac):
            for name in good:
                with self.subTest(good=name):
                    self.assertEqual(app.validate_device_name(name), name)
            for name in bad:
                with self.subTest(bad=name):
                    with self.assertRaises(ValueError):
                        app.validate_device_name(name)

    def test_macos_pattern(self):
        self.check(True, ["disk0", "disk4", "disk12"],
                   ["", None, 4, "disk", "diskX", "disk4s1", "rdisk4", "/dev/disk4", "sdb",
                    "disk4;rm", "disk4 ", " disk4", "../disk4"])

    def test_linux_pattern(self):
        self.check(False, ["sdb", "nvme0n1", "mmcblk0", "vda", "a", "x" * 32],
                   ["", None, "x" * 33, "sd b", "sdb;reboot", "../sda", "/dev/sdb",
                    "sd$(id)", "sdb'", 'sdb"', "sd`id`", "sd*"])

    def test_error_message_mentions_the_value(self):
        with mock.patch.object(app, "IS_MAC", True):
            with self.assertRaises(ValueError) as ctx:
                app.validate_device_name("sdb")
        self.assertIn("'sdb'", str(ctx.exception))

    def test_no_selection_message(self):
        with self.assertRaises(ValueError) as ctx:
            app.validate_device_name("")
        self.assertIn("No disk", str(ctx.exception))


class ValidateIsoPathTests(TempDirTestCase):
    def test_returns_real_absolute_path(self):
        iso = self.make_iso("a.iso")
        link = self.path("link.iso")
        os.symlink(iso, link)
        self.assertEqual(app.validate_iso_path(link), os.path.realpath(iso))

    def test_expands_user(self):
        iso = self.make_iso("home.iso")
        with mock.patch.dict(os.environ, {"HOME": self.tmp}):
            self.assertEqual(app.validate_iso_path("~/home.iso"), os.path.realpath(iso))

    def test_rejects_empty(self):
        for value in ("", None):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    app.validate_iso_path(value)

    def test_rejects_missing_file(self):
        with self.assertRaisesRegex(ValueError, "no longer exists"):
            app.validate_iso_path(self.path("nope.iso"))

    def test_rejects_directory(self):
        os.mkdir(self.path("dir.iso"))
        with self.assertRaisesRegex(ValueError, "not a regular file"):
            app.validate_iso_path(self.path("dir.iso"))

    def test_rejects_tiny_file(self):
        small = self.write_file("small.iso", b"x" * 1000)
        with self.assertRaisesRegex(ValueError, "too small"):
            app.validate_iso_path(small)

    def test_one_mebibyte_is_enough(self):
        exact = self.write_file("exact.iso", b"\0" * MIB)
        self.assertEqual(app.validate_iso_path(exact), exact)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root can read anything")
    def test_rejects_unreadable_file(self):
        iso = self.make_iso("secret.iso")
        os.chmod(iso, 0)
        self.addCleanup(os.chmod, iso, 0o600)
        with self.assertRaisesRegex(ValueError, "cannot be read"):
            app.validate_iso_path(iso)


class ValidateHybridIsoTests(TempDirTestCase):
    def test_accepts_boot_signature(self):
        app.validate_hybrid_iso(self.make_iso(hybrid=True))

    def test_rejects_missing_signature(self):
        with self.assertRaisesRegex(ValueError, "not a bootable hybrid"):
            app.validate_hybrid_iso(self.make_iso(hybrid=False))

    def test_rejects_short_file(self):
        with self.assertRaises(ValueError):
            app.validate_hybrid_iso(self.write_file("short.iso", b"\x55\xaa"))

    def test_signature_must_be_at_offset_510(self):
        data = bytearray(2048)
        data[1022:1024] = b"\x55\xaa"
        with self.assertRaises(ValueError):
            app.validate_hybrid_iso(self.write_file("late.iso", bytes(data)))


class ValidateDownloadUrlTests(unittest.TestCase):
    def setUp(self):
        env = {k: v for k, v in os.environ.items()
               if k not in (app.ENV_TRUSTED_HOSTS, app.ENV_ALLOW_ANY_HOST)}
        patcher = mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_trusted_microsoft_hosts(self):
        for url in ("https://www.microsoft.com/a", "https://microsoft.com/a",
                    "https://software.download.prss.microsoft.com/x.iso",
                    "https://HOST.download.microsoft.com/x.iso"):
            with self.subTest(url=url):
                _url, _host, untrusted = app.validate_download_url(url)
                self.assertFalse(untrusted)

    def test_untrusted_host_is_flagged_not_rejected(self):
        url, host, untrusted = app.validate_download_url("https://example.com/win.iso")
        self.assertEqual((url, host, untrusted), ("https://example.com/win.iso", "example.com", True))

    def test_lookalike_hosts_are_untrusted(self):
        for url in ("https://microsoft.com.evil.example/x", "https://evilmicrosoft.com/x",
                    "https://microsoft.com@evil.example/x"):
            with self.subTest(url=url):
                self.assertTrue(app.validate_download_url(url)[2])

    def test_only_https(self):
        for url in ("http://www.microsoft.com/x", "ftp://www.microsoft.com/x",
                    "file:///etc/passwd", "javascript:alert(1)", "www.microsoft.com/x"):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    app.validate_download_url(url)

    def test_empty_and_hostless(self):
        for url in ("", "   ", None, "https://", "https:///path"):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    app.validate_download_url(url)

    def test_strips_whitespace(self):
        self.assertEqual(app.validate_download_url("  https://www.microsoft.com/x \n")[0],
                         "https://www.microsoft.com/x")

    def test_trusted_hosts_env_override(self):
        with mock.patch.dict(os.environ, {app.ENV_TRUSTED_HOSTS: "example.org, mirror.test"}):
            self.assertFalse(app.validate_download_url("https://example.org/x")[2])
            self.assertFalse(app.validate_download_url("https://cdn.mirror.test/x")[2])
            self.assertTrue(app.validate_download_url("https://www.microsoft.com/x")[2])

    def test_allow_any_host_env_still_requires_https(self):
        with mock.patch.dict(os.environ, {app.ENV_ALLOW_ANY_HOST: "1"}):
            self.assertFalse(app.validate_download_url("https://whatever.example/x")[2])
            with self.assertRaises(ValueError):
                app.validate_download_url("http://whatever.example/x")


class LinuxPartitionPathTests(unittest.TestCase):
    def test_plain_and_numbered_devices(self):
        self.assertEqual(app.linux_partition_path("sdb", 1), "/dev/sdb1")
        self.assertEqual(app.linux_partition_path("nvme0n1", 2), "/dev/nvme0n1p2")
        self.assertEqual(app.linux_partition_path("mmcblk0", 1), "/dev/mmcblk0p1")


class LinuxInstallCommandTests(unittest.TestCase):
    def test_apt(self):
        cmd = app.linux_build_install_command("apt-get", ["wimlib-imagex", "parted"])
        self.assertEqual(cmd, "apt-get update && apt-get install -y parted wimtools")

    def test_packages_are_deduplicated_and_sorted(self):
        # parted and partprobe both come from the "parted" package
        cmd = app.linux_build_install_command("dnf", ["partprobe", "parted", "rsync"])
        self.assertEqual(cmd, "dnf install -y parted rsync")

    def test_pacman_uses_full_upgrade(self):
        self.assertIn("-Syu", app.linux_build_install_command("pacman", ["rsync"]))

    def test_every_manager_covers_every_required_tool(self):
        for mgr in app.LINUX_INSTALL_CMD_TEMPLATE:
            with self.subTest(mgr=mgr):
                self.assertTrue(app.linux_build_install_command(mgr, app.LINUX_REQUIRED_TOOLS))

    def test_unknown_manager(self):
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            app.linux_build_install_command("brew", ["rsync"])

    def test_names_outside_the_allow_list_are_ignored(self):
        with self.assertRaisesRegex(ValueError, "Nothing to install"):
            app.linux_build_install_command("apt-get", ["rsync; rm -rf /", "$(id)", "nc"])
        cmd = app.linux_build_install_command("apt-get", ["rsync", "evil; reboot"])
        self.assertEqual(cmd, "apt-get update && apt-get install -y rsync")

    def test_nothing_missing(self):
        with self.assertRaises(ValueError):
            app.linux_build_install_command("apt-get", [])

    def test_rejects_suspicious_package_names(self):
        for bad in ("parted; rm -rf /", "a b", "$(id)", "x" * 65, "", "p`id`"):
            with self.subTest(pkg=bad):
                with mock.patch.dict(app.LINUX_PKG_MAP["apt-get"], {"parted": bad}):
                    with self.assertRaises(ValueError):
                        app.linux_build_install_command("apt-get", ["parted"])


if __name__ == "__main__":
    unittest.main()
