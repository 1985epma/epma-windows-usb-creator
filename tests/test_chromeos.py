"""ChromeOS Flex support: image checks, content detection, safe extraction, the official
download address, the write path and the command line.

Everything runs on temp files; no network, no sudo and no device is touched.
"""
import json
import os
import threading
import unittest
import zipfile
from unittest import mock

from tests.helpers import FAKE_DISKS, MIB, Collector, TempDirTestCase, app, run_main

CHROMEOS_NAMES = ("KERN-A", "ROOT-A", "KERN-B", "ROOT-B", "STATE", "EFI-SYSTEM")


def gpt_image(names, size=2 * MIB, signature=True):
    """A disk image with a protective MBR and a GPT whose partitions carry `names`."""
    data = bytearray(os.urandom(size))
    data[0:1024] = bytes(1024)
    if signature:
        data[510:512] = b"\x55\xaa"
    data[512:520] = b"EFI PART"
    for i, name in enumerate(names):
        entry = bytearray(128)
        entry[0:16] = b"\x11" * 16                        # partition type GUID (non-zero = used)
        entry[16:32] = bytes([i + 1]) * 16                # unique GUID
        entry[56:56 + 72] = name.encode("utf-16-le").ljust(72, b"\x00")[:72]
        data[1024 + i * 128:1024 + (i + 1) * 128] = entry
    return bytes(data)


class ChromeTestCase(TempDirTestCase):
    def make_zip(self, members, name="latest.bin.zip", compression=zipfile.ZIP_DEFLATED):
        path = self.path(name)
        with zipfile.ZipFile(path, "w", compression) as zf:
            for member, data in members.items():
                zf.writestr(member, data)
        return path


class CardTests(unittest.TestCase):
    """The four cards at the top of the window and how each one writes the drive."""

    def test_every_card_has_a_mode_and_an_order(self):
        self.assertEqual(set(app.CARD_ORDER), set(app.CARD_MODE))
        self.assertEqual(len(app.CARD_ORDER), 4)
        self.assertEqual(app.CARD_ORDER[0], app.CARD_CHROME)  # Google Chrome first, as designed

    def test_how_each_card_writes(self):
        self.assertEqual(app.CARD_MODE[app.CARD_CHROME], app.MODE_CHROMEOS)
        self.assertEqual(app.CARD_MODE[app.CARD_WINDOWS], app.MODE_WINDOWS)
        self.assertEqual(app.CARD_MODE[app.CARD_LINUX], app.MODE_LINUX)
        self.assertEqual(app.CARD_MODE[app.CARD_OTHER], app.MODE_LINUX)

    def test_only_windows_copies_files(self):
        raw = [card for card, mode in app.CARD_MODE.items() if mode in app.RAW_MODES]
        self.assertEqual(sorted(raw), sorted([app.CARD_CHROME, app.CARD_LINUX, app.CARD_OTHER]))

    def test_the_module_imports_without_tkinter(self):
        # OptionCard inherits from a Tk class; it must not make the engine/CLI need Tk
        self.assertTrue(hasattr(app, "OptionCard"))
        self.assertTrue(hasattr(app, "_CanvasBase"))


class ConstantsTests(unittest.TestCase):
    def test_the_official_address_is_https_on_dl_google_com(self):
        self.assertEqual(app.CHROMEOS_FLEX_URL, "https://dl.google.com/chromeos-flex/images/latest.bin.zip")

    def test_raw_modes(self):
        self.assertEqual(set(app.RAW_MODES), {app.MODE_LINUX, app.MODE_CHROMEOS})
        self.assertNotIn(app.MODE_WINDOWS, app.RAW_MODES)

    def test_minimum_drive_is_a_16gb_stick(self):
        # a stick sold as "16 GB" holds about 15.5e9 bytes and must not be warned about
        self.assertLess(app.CHROMEOS_MIN_USB_BYTES, 15_500_000_000)
        self.assertGreater(app.CHROMEOS_MIN_USB_BYTES, 8_000_000_000)


class ValidateDiskImageTests(ChromeTestCase):
    def test_accepts_an_image_with_the_boot_signature(self):
        app.validate_disk_image(self.write_file("a.bin", gpt_image(CHROMEOS_NAMES)))

    def test_refuses_a_file_without_the_boot_signature(self):
        path = self.write_file("a.bin", gpt_image(CHROMEOS_NAMES, signature=False))
        with self.assertRaisesRegex(ValueError, "not a bootable disk image"):
            app.validate_disk_image(path)

    def test_refuses_the_zip_and_says_what_to_do(self):
        zip_path = self.make_zip({"x.bin": os.urandom(MIB)})
        with self.assertRaisesRegex(ValueError, "ZIP archive, not the disk image"):
            app.validate_disk_image(zip_path)


class DetectionTests(ChromeTestCase):
    def test_a_chromeos_gpt_is_recognised_by_its_partition_names(self):
        path = self.write_file("a.bin", gpt_image(CHROMEOS_NAMES))
        self.assertEqual(app.detect_iso_kind(path), "chromeos")

    def test_the_minimum_set_of_names_is_enough(self):
        path = self.write_file("a.bin", gpt_image(("KERN-A", "ROOT-A", "STATE")))
        self.assertEqual(app.detect_iso_kind(path), "chromeos")

    def test_other_gpt_disks_are_not_chromeos(self):
        for names in (("EFI System Partition", "Basic data partition"), ("ROOT-A",), ("KERN-A", "STATE"),
                      ("root", "boot", "home")):
            with self.subTest(names=names):
                path = self.write_file("b.bin", gpt_image(names))
                self.assertNotEqual(app.detect_iso_kind(path), "chromeos")

    def test_a_hybrid_iso_is_still_linux(self):
        # the smallest thing the detector accepts as a hybrid ISO: a primary volume descriptor
        # ("CD001") and the MBR boot signature
        data = bytearray(os.urandom(2 * MIB))
        data[510:512] = b"\x55\xaa"
        data[16 * 2048:16 * 2048 + 8] = b"\x01CD001\x01\x00"
        data[16 * 2048 + 156:16 * 2048 + 190] = bytes(34)  # empty root directory record
        self.assertEqual(app.detect_iso_kind(self.write_file("u2.iso", bytes(data))), "linux")

    def test_garbage_and_missing_files_never_raise(self):
        self.assertEqual(app.detect_iso_kind(self.write_file("g.bin", os.urandom(4096))), "unknown")
        self.assertEqual(app.detect_iso_kind(self.path("missing.bin")), "unknown")

    def test_an_empty_gpt_slot_is_ignored(self):
        data = bytearray(gpt_image(CHROMEOS_NAMES))
        data[1024 + 6 * 128:1024 + 7 * 128] = bytes(128)
        path = self.write_file("c.bin", bytes(data))
        self.assertEqual(app.detect_iso_kind(path), "chromeos")


class ExtractionTests(ChromeTestCase):
    def setUp(self):
        super().setUp()
        self.dest = self.path("out")
        os.makedirs(self.dest)
        self.image = gpt_image(CHROMEOS_NAMES, size=3 * MIB)

    def test_extracts_the_image_and_reports_progress(self):
        zip_path = self.make_zip({"chromeos_flex.bin": self.image})
        seen = []
        out = app.extract_disk_image(zip_path, self.dest, progress=lambda d, t: seen.append((d, t)))
        self.assertEqual(out, os.path.join(self.dest, "chromeos_flex.bin"))
        with open(out, "rb") as fh:
            self.assertEqual(fh.read(), self.image)
        self.assertEqual(seen[-1], (len(self.image), len(self.image)))
        self.assertEqual([d for d, _t in seen], sorted(d for d, _t in seen))
        self.assertEqual(os.listdir(self.dest), ["chromeos_flex.bin"])  # no .part left behind

    def test_the_extracted_file_is_private(self):
        out = app.extract_disk_image(self.make_zip({"a.bin": self.image}), self.dest)
        self.assertEqual(os.stat(out).st_mode & 0o077, 0)

    def test_a_path_in_the_zip_cannot_escape_the_folder(self):
        zip_path = self.make_zip({"../../evil.bin": self.image})
        out = app.extract_disk_image(zip_path, self.dest)
        self.assertEqual(os.path.dirname(out), self.dest)
        self.assertEqual(os.path.basename(out), "evil.bin")
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(self.dest), "evil.bin")))

    def test_an_odd_member_name_is_replaced_by_a_safe_one(self):
        out = app.extract_disk_image(self.make_zip({"we ird$name;.bin": self.image}), self.dest)
        self.assertEqual(os.path.basename(out), "chromeos_flex.bin")

    def test_picks_the_largest_bin_when_there_are_several(self):
        zip_path = self.make_zip({"small.bin": os.urandom(2 * MIB), "big.bin": self.image, "readme.txt": b"x"})
        self.assertEqual(os.path.basename(app.extract_disk_image(zip_path, self.dest)), "big.bin")

    def test_never_overwrites_an_existing_file(self):
        self.write_file("out/chromeos_flex.bin", b"precious")
        out = app.extract_disk_image(self.make_zip({"chromeos_flex.bin": self.image}), self.dest)
        self.assertEqual(os.path.basename(out), "chromeos_flex-1.bin")
        with open(os.path.join(self.dest, "chromeos_flex.bin"), "rb") as fh:
            self.assertEqual(fh.read(), b"precious")

    def test_refuses_a_zip_without_a_bin(self):
        with self.assertRaisesRegex(ValueError, "does not contain a .bin"):
            app.extract_disk_image(self.make_zip({"readme.txt": b"hello"}), self.dest)

    def test_refuses_an_implausibly_small_image(self):
        with self.assertRaisesRegex(ValueError, "implausible size"):
            app.extract_disk_image(self.make_zip({"a.bin": b"tiny"}), self.dest)

    def test_refuses_an_implausibly_large_image(self):
        zip_path = self.make_zip({"a.bin": self.image})
        with mock.patch.object(app, "DISK_IMAGE_MAX_BYTES", MIB):
            with self.assertRaisesRegex(ValueError, "implausible size"):
                app.extract_disk_image(zip_path, self.dest)

    def test_refuses_when_there_is_not_enough_free_space(self):
        zip_path = self.make_zip({"a.bin": self.image})
        usage = mock.Mock(free=1024)
        with mock.patch.object(app.shutil, "disk_usage", return_value=usage):
            with self.assertRaisesRegex(ValueError, "Not enough free space"):
                app.extract_disk_image(zip_path, self.dest)
        self.assertEqual(os.listdir(self.dest), [])

    def test_not_a_zip(self):
        with self.assertRaisesRegex(ValueError, "not a valid ZIP"):
            app.extract_disk_image(self.write_file("x.zip", b"this is not a zip"), self.dest)

    def test_a_missing_destination_folder(self):
        with self.assertRaisesRegex(ValueError, "does not exist"):
            app.extract_disk_image(self.make_zip({"a.bin": self.image}), self.path("nope"))

    def test_a_damaged_zip_is_detected_and_leaves_nothing_behind(self):
        zip_path = self.make_zip({"a.bin": self.image}, compression=zipfile.ZIP_STORED)
        with open(zip_path, "rb") as fh:
            data = bytearray(fh.read())
        data[len(data) // 2] ^= 0xFF  # flip a byte inside the stored image: the CRC no longer matches
        with open(zip_path, "wb") as fh:
            fh.write(bytes(data))
        with self.assertRaisesRegex(ValueError, "damaged"):
            app.extract_disk_image(zip_path, self.dest)
        self.assertEqual(os.listdir(self.dest), [])

    def test_cancel_stops_and_cleans_up(self):
        zip_path = self.make_zip({"a.bin": self.image})
        event = threading.Event()

        def progress(done, _total):
            event.set()  # cancel as soon as the first chunk is written

        with self.assertRaises(app.OperationCanceled):
            app.extract_disk_image(zip_path, self.dest, progress=progress, cancel_event=event)
        self.assertEqual(os.listdir(self.dest), [])


class DownloadAddressTests(unittest.TestCase):
    def test_the_official_link_is_trusted(self):
        url, host, untrusted = app.validate_download_url(app.CHROMEOS_FLEX_URL)
        self.assertEqual((url, host, untrusted), (app.CHROMEOS_FLEX_URL, "dl.google.com", False))

    def test_any_other_google_address_is_still_unknown(self):
        for other in ("https://dl.google.com/other/file.zip", app.CHROMEOS_FLEX_URL + "?x=1",
                      "https://dl.google.com/chromeos-flex/images/latest.bin.zip/..", "https://google.com/x.zip"):
            with self.subTest(url=other):
                self.assertTrue(app.validate_download_url(other)[2])

    def test_plain_http_is_still_refused(self):
        with self.assertRaises(ValueError):
            app.validate_download_url(app.CHROMEOS_FLEX_URL.replace("https://", "http://"))


class FakeResponse:
    """What urlopen returns, as far as DownloadThread uses it."""

    def __init__(self, final_url, body, headers=None):
        self._final, self._body, self._pos = final_url, body, 0
        self.status = 200
        self.headers = {"Content-Length": str(len(body)), "ETag": '"abc"', **(headers or {})}

    def geturl(self):
        return self._final

    def getcode(self):
        return self.status

    def read(self, n=-1):
        chunk = self._body[self._pos:self._pos + (n if n and n > 0 else len(self._body))]
        self._pos += len(chunk)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class FlexRedirectTests(ChromeTestCase):
    VERSIONED = ("https://dl.google.com/dl/edgedl/chromeos/recovery/"
                 "chromeos_16765.41.0_reven_recovery_stable-channel_RevenMPKeys-v11.bin.zip")

    def download(self, final_url, body=b"payload", allowed=app.CHROMEOS_FLEX_HOSTS):
        dest = self.path("latest.bin.zip")
        outcome = {}
        thread = app.DownloadThread(
            app.CHROMEOS_FLEX_URL, dest, progress_cb=lambda *_a: None,
            done_cb=lambda path, sha, _v: outcome.update(done=(path, sha)),
            error_cb=lambda msg: outcome.update(error=msg), cancel_event=threading.Event(),
            allowed_hosts=allowed)
        with mock.patch.object(app.DownloadThread, "_open", return_value=FakeResponse(final_url, body)):
            thread.start()
            thread.join(10)
        return dest, outcome

    def test_the_versioned_file_on_the_same_google_host_is_accepted(self):
        dest, outcome = self.download(self.VERSIONED, b"hello flex")
        self.assertNotIn("error", outcome)
        with open(dest, "rb") as fh:
            self.assertEqual(fh.read(), b"hello flex")
        import hashlib
        self.assertEqual(outcome["done"][1], hashlib.sha256(b"hello flex").hexdigest())

    def test_a_redirect_to_another_host_is_refused_and_nothing_is_kept(self):
        dest, outcome = self.download("https://evil.example.com/latest.bin.zip")
        self.assertIn("unexpected address (evil.example.com)", outcome["error"])
        self.assertNotIn("done", outcome)
        self.assertFalse(os.path.exists(dest))
        self.assertFalse(os.path.exists(dest + ".part"))

    def test_a_look_alike_host_is_refused(self):
        for host in ("dl.google.com.evil.example", "xdl.google.com", "google.com"):
            with self.subTest(host=host):
                _dest, outcome = self.download(f"https://{host}/x.zip")
                self.assertIn("unexpected address", outcome["error"])

    def test_other_downloads_are_not_restricted(self):
        # the Windows ISO download keeps its previous behaviour (HTTPS only)
        _dest, outcome = self.download("https://software.download.prss.microsoft.com/x.iso", allowed=None)
        self.assertNotIn("error", outcome)

    def test_the_blocking_helper_restricts_only_the_flex_address(self):
        captured = {}

        class Spy:
            def __init__(self, *args, **kw):
                captured.update(kw)
                self.cb = kw["done_cb"]

            def start(self):
                self.cb("/x", "00" * 32, False)

            def join(self):
                pass

        with mock.patch.object(app, "DownloadThread", Spy):
            app.download_file_blocking(app.CHROMEOS_FLEX_URL, "/x")
            self.assertEqual(captured["allowed_hosts"], app.CHROMEOS_FLEX_HOSTS)
            app.download_file_blocking("https://example.com/x", "/x")
            self.assertIsNone(captured["allowed_hosts"])


class BuildUsbTests(ChromeTestCase):
    def setUp(self):
        super().setUp()
        self.image = self.write_file("flex.bin", gpt_image(CHROMEOS_NAMES, size=4 * MIB))
        patches = {
            "hash": mock.patch.object(app, "hash_iso_for_audit", return_value="0" * 64),
            "reverify": mock.patch.object(app, "reverify_target_disk"),
            "sleep": mock.patch.object(app, "prevent_sleep", return_value=mock.MagicMock()),
            "mac": mock.patch.object(app, "macos_write_raw", return_value=True),
            "linux": mock.patch.object(app, "linux_write_raw", return_value=True),
            "mac_build": mock.patch.object(app, "macos_build_usb", return_value=True),
            "linux_build": mock.patch.object(app, "linux_build_usb", return_value=True),
        }
        self.m = {}
        for name, patch in patches.items():
            self.m[name] = patch.start()
            self.addCleanup(patch.stop)

    def run_build(self, mode=app.MODE_CHROMEOS, expected_size=None, image=None, is_mac=True):
        # No tool is "missing" on a CI machine: the dependency check itself is tested in test_fixes_engine.
        with mock.patch.object(app, "IS_MAC", is_mac), \
                mock.patch.object(app, "get_missing_dependencies", return_value=[]):
            return app.build_usb(image or self.image, "disk9", Collector(), None, expected_size=expected_size,
                                 mode=mode)

    def test_chromeos_uses_the_raw_write_on_macos(self):
        self.assertTrue(self.run_build(is_mac=True))
        self.m["mac"].assert_called_once()
        self.m["linux"].assert_not_called()
        self.m["mac_build"].assert_not_called()

    def test_chromeos_uses_the_raw_write_on_linux(self):
        self.assertTrue(self.run_build(is_mac=False))
        self.m["linux"].assert_called_once()
        self.m["mac"].assert_not_called()
        self.m["linux_build"].assert_not_called()

    def test_windows_still_copies_files(self):
        self.run_build(mode=app.MODE_WINDOWS, is_mac=True)
        self.m["mac_build"].assert_called_once()
        self.m["mac"].assert_not_called()

    def test_the_drive_is_rechecked_before_writing(self):
        self.run_build()
        self.m["reverify"].assert_called_once()

    def test_refuses_an_image_larger_than_the_drive_before_anything_happens(self):
        with self.assertRaisesRegex(ValueError, "larger than the drive"):
            self.run_build(expected_size=2 * MIB)
        self.m["reverify"].assert_not_called()
        self.m["mac"].assert_not_called()

    def test_refuses_the_zip(self):
        zip_path = self.make_zip({"a.bin": os.urandom(2 * MIB)})
        with self.assertRaisesRegex(ValueError, "ZIP archive"):
            self.run_build(image=zip_path)
        self.m["mac"].assert_not_called()

    def test_refuses_a_non_bootable_image(self):
        bad = self.write_file("bad.bin", gpt_image(CHROMEOS_NAMES, signature=False))
        with self.assertRaisesRegex(ValueError, "not a bootable disk image"):
            self.run_build(image=bad)

    def test_unknown_mode(self):
        with self.assertRaisesRegex(ValueError, "Unknown image type"):
            self.run_build(mode="plan9")

    def test_linux_mode_also_checks_the_size(self):
        with self.assertRaisesRegex(ValueError, "larger than the drive"):
            self.run_build(mode=app.MODE_LINUX, expected_size=1 * MIB, image=self.make_iso("u.iso", 4 * MIB))

    def test_dependencies_for_the_raw_modes_are_just_dd(self):
        with mock.patch.object(app.shutil, "which", return_value="/bin/dd"):
            self.assertEqual(app.get_missing_dependencies(app.MODE_CHROMEOS), [])
        with mock.patch.object(app.shutil, "which", return_value=None):
            self.assertEqual(app.get_missing_dependencies(app.MODE_CHROMEOS), ["dd"])


class CliTests(ChromeTestCase):
    def setUp(self):
        super().setUp()
        for target, kw in (("get_external_disks", {"return_value": [dict(d) for d in FAKE_DISKS]}),
                           ("get_missing_dependencies", {"return_value": []}),
                           ("build_usb", {"return_value": True})):
            patch = mock.patch.object(app, target, **kw)
            setattr(self, target, patch.start())
            self.addCleanup(patch.stop)
        patch = mock.patch.object(app.CliPrivilege, "authenticate")
        patch.start()
        self.addCleanup(patch.stop)
        env = mock.patch.dict(os.environ, {"NO_COLOR": "1"})
        env.start()
        self.addCleanup(env.stop)
        self.image = self.write_file("flex.bin", gpt_image(CHROMEOS_NAMES, size=4 * MIB))

    def test_detect_prints_chromeos(self):
        code, out, _err = run_main(["detect", self.image])
        self.assertEqual((code, out.strip()), (0, "chromeos"))
        code, out, _err = run_main(["detect", self.image, "--json"])
        self.assertEqual(json.loads(out)["kind"], "chromeos")

    def test_write_auto_selects_chromeos(self):
        code, out, _err = run_main(["write", "--iso", self.image, "--disk", "disk9", "--dry-run", "--json"])
        self.assertEqual(code, 0)
        plan = json.loads(out)
        self.assertEqual(plan["mode"], "chromeos")
        self.assertTrue(any("byte for byte" in step for step in plan["steps"]))

    def test_write_chromeos_passes_the_mode_to_the_engine(self):
        code, _out, _err = run_main(["write", "--iso", self.image, "--disk", "disk9", "--yes"])
        self.assertEqual(code, 0)
        self.assertEqual(self.build_usb.call_args.kwargs["mode"], "chromeos")

    def test_a_small_drive_gets_a_warning_but_is_allowed(self):
        code, _out, err = run_main(["write", "--iso", self.image, "--disk", "disk8", "--dry-run"])
        self.assertEqual(code, 0)
        self.assertIn("16 GB or larger", err)

    def test_an_image_bigger_than_the_drive_is_refused(self):
        small = [dict(FAKE_DISKS[0], size=2 * MIB)]
        self.get_external_disks.return_value = small
        code, _out, err = run_main(["write", "--iso", self.image, "--disk", "disk9", "--dry-run"])
        self.assertEqual(code, 1)
        self.assertIn("larger than the drive", err)

    def test_the_zip_is_refused_with_a_hint(self):
        zip_path = self.make_zip({"a.bin": os.urandom(2 * MIB)})
        code, _out, err = run_main(["write", "--iso", zip_path, "--disk", "disk9", "--mode", "chromeos",
                                    "--dry-run"])
        self.assertEqual(code, 1)
        self.assertIn("ZIP archive", err)

    def test_mode_choices_include_chromeos(self):
        code, out, _err = run_main(["write", "--help"])
        self.assertEqual(code, 0)
        self.assertIn("chromeos", out)

    # ---- fetch-chromeos ----
    def fake_download(self, payload):
        def download(url, dest, progress=None, cancel_event=None):
            self.assertEqual(url, app.CHROMEOS_FLEX_URL)
            with open(dest, "wb") as fh:
                fh.write(payload)
            return "ab" * 32
        return download

    def make_flex_zip_bytes(self):
        path = self.make_zip({"chromeos_flex_1.bin": gpt_image(CHROMEOS_NAMES, size=2 * MIB)}, name="src.zip")
        with open(path, "rb") as fh:
            return fh.read()

    def test_fetch_downloads_extracts_and_removes_the_zip(self):
        out_dir = self.path("dl")
        os.makedirs(out_dir)
        with mock.patch.object(app, "download_file_blocking", self.fake_download(self.make_flex_zip_bytes())):
            code, out, err = run_main(["fetch-chromeos", "--dest", out_dir, "--json"])
        self.assertEqual(code, 0, err)
        info = json.loads(out)
        self.assertEqual(os.path.dirname(info["image"]), os.path.realpath(out_dir))
        self.assertEqual(app.detect_iso_kind(info["image"]), "chromeos")
        self.assertEqual(info["zip_sha256"], "ab" * 32)
        self.assertEqual(sorted(os.listdir(out_dir)), ["chromeos_flex_1.bin"])  # the zip is gone
        self.assertIn("Google's own terms", err)

    def test_fetch_keep_zip(self):
        out_dir = self.path("dl")
        os.makedirs(out_dir)
        with mock.patch.object(app, "download_file_blocking", self.fake_download(self.make_flex_zip_bytes())):
            code, _out, _err = run_main(["fetch-chromeos", "--dest", out_dir, "--keep-zip"])
        self.assertEqual(code, 0)
        self.assertIn("chromeos_flex_latest.bin.zip", os.listdir(out_dir))

    def test_fetch_reports_a_download_failure(self):
        out_dir = self.path("dl")
        os.makedirs(out_dir)

        def failing(url, dest, progress=None, cancel_event=None):
            raise RuntimeError("Could not reach the server.")

        with mock.patch.object(app, "download_file_blocking", failing):
            code, _out, err = run_main(["fetch-chromeos", "--dest", out_dir])
        self.assertEqual(code, 1)
        self.assertIn("Could not reach the server", err)

    def test_fetch_refuses_a_missing_folder_and_an_existing_zip(self):
        code, _out, err = run_main(["fetch-chromeos", "--dest", self.path("nope")])
        self.assertEqual(code, 1)
        self.assertIn("Not a folder", err)
        out_dir = self.path("dl")
        os.makedirs(out_dir)
        self.write_file("dl/chromeos_flex_latest.bin.zip", b"old")
        # An existing ZIP is no longer refused: it is extracted again (here it is not a ZIP at all,
        # so the reason is shown together with how to continue).
        code, _out, err = run_main(["fetch-chromeos", "--dest", out_dir])
        self.assertEqual(code, 1)
        self.assertIn("not a valid ZIP", err)
        self.assertIn("remove the file", err)
        self.assertTrue(os.path.exists(os.path.join(out_dir, "chromeos_flex_latest.bin.zip")))


class DownloadBlockingTests(unittest.TestCase):
    def test_returns_the_hash_or_raises_the_reason(self):
        class FakeThread:
            outcome = None

            def __init__(self, url, dest, progress_cb, done_cb, error_cb, cancel_event, **_kw):
                self.done_cb, self.error_cb, self.dest = done_cb, error_cb, dest

            def start(self):
                kind, value = FakeThread.outcome
                (self.done_cb(self.dest, value, False) if kind == "ok" else self.error_cb(value))

            def join(self):
                pass

        with mock.patch.object(app, "DownloadThread", FakeThread):
            FakeThread.outcome = ("ok", "cd" * 32)
            self.assertEqual(app.download_file_blocking("https://x/y", "/tmp/z"), "cd" * 32)
            FakeThread.outcome = ("err", "Download canceled by user.")
            with self.assertRaisesRegex(RuntimeError, "canceled"):
                app.download_file_blocking("https://x/y", "/tmp/z")


if __name__ == "__main__":
    unittest.main()
