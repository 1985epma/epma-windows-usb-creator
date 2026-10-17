# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The release workflow (`.github/workflows/release.yml`) publishes the section whose
heading matches the pushed tag as the GitHub release notes: tag `v1.1.0` uses the
`## [1.1.0]` section below. Keep the heading format `## [X.Y.Z] - date`.

## [Unreleased]

## [1.1.0] - unreleased

### Added

- **Linux / hybrid ISO image type.** A second image type writes the ISO byte-for-byte to
  the drive (like `dd`). ISOs without an MBR boot signature (`0x55AA`) are refused before
  anything is touched, because the resulting drive would not boot.
- **Write progress bar** with percentage, speed and estimated time remaining, for both the
  Windows copy (rsync, install image copy or split) and the raw write (`dd status=progress`
  on Linux, `SIGINFO` polling on macOS). Stages of unknown length show a busy indicator.
- **Administrator password dialog up front.** The sudo password is collected and verified
  (`sudo -k`) before the drive is unmounted or written, so a wrong or canceled password
  leaves the drive untouched.
- **Post-write verification.** Raw writes are read back and compared byte-for-byte with the
  ISO. Windows drives are remounted and compared by checksum (`rsync -c`), and a split
  install image is checked with `wimlib-imagex verify`. A failed check aborts without
  ejecting the drive.
- **Reliable eject.** The drive is ejected when the work is done (macOS with a force-unmount
  retry; Linux through `eject` or `udisksctl power-off`) and the outcome is reported.
- **Cancel button** for the whole operation (privileged raw writes are stopped through a
  private flag file the root script polls), and the machine is kept awake while writing
  (`caffeinate` / `systemd-inhibit`).
- **Drive details before erasing.** The drive list and the final dialog show the model, size
  and volumes with used space. **High-risk drives** (over 256 GB, lots of data, backup-like
  names, unreadable contents) additionally require typing the disk identifier.
- **Stronger target re-check:** the serial number / model / UUID must match, not only the size.
- **SHA-256 of an existing ISO** (a panel under the selected file; accepts a bare hash or a `SHA256SUMS` line).
- **ISO type detected from its contents** (ISO 9660 / UDF markers) instead of the file name.
- **Command line mode:** `list`, `detect`, `sha256`, `write` (`--dry-run`, `--yes`, `--json`,
  `--no-eject`), `--version`, documented exit codes. The engine now imports without Tkinter.
- The interface is always US English. A Portuguese (pt-BR) translation is available only when `EPMA_LANG=pt` is set explicitly; the system locale is never consulted.
- **Resumable downloads** with `Range`/`If-Range` and automatic retries; the partial file is
  kept when the network drops.
- **Audit log:** rotation (1 MB × 5, files stay `0600`) and the SHA-256 of the ISO that was
  written.
- **ChromeOS Flex** (Google's free ChromeOS for PCs and Macs): the *Google Chrome* card downloads the official image from `dl.google.com` (HTTPS, resumable) and extracts it from the ZIP with a hardened routine. It is then written byte for byte to the USB drive, like a Linux ISO, with the same read-back verification and eject (a real 9.5 GB write was verified end to end). The image is recognised by its GPT partition names. `fetch-chromeos` and `write --mode chromeos` on the command line. Google asks for a USB drive of 16 GB or larger, which is checked and warned about.
- **One-page window:** four cards (*Google Chrome*, *Windows 11*, *Linux*, *Other ISO*) replace the three tabs; below them the source panel of the chosen card, the USB drive list, the image file (with the SHA-256 check), and a large Create button with progress and log. The card is picked from the image contents, a mismatching file is questioned before anything is erased, and the window keeps one height whichever card is chosen.
- **Help menu** with built-in documentation (F1): quick starts for Windows and Linux ISOs, both tabs, safety, verification and eject, command line, troubleshooting, files and settings, plus About, the audit log folder and the project page. Tests check it against the code (commands, exit codes, thresholds, messages).
- Unit test suite (`tests/`, standard library only) and a per-distribution package probe.
- Release engineering: end-to-end tests against loop devices (Linux CI), ShellCheck over the
  embedded privileged scripts, a per-distribution package-manager probe, a CycloneDX SBOM and
  provenance attestation for every release, OpenSSF Scorecard, and automatic Homebrew tap
  updates.

### Changed

- **Only USB drives are listed** (macOS `BusProtocol=USB`, Linux `tran=usb`); internal and
  other external disks never appear.
- **The confirmation checkbox was removed, and the typed disk identifier is now required only
  for high-risk drives.** For an ordinary USB stick the final dialog (which names the drive,
  its size and volumes) is the single confirmation.
- **A failing privileged script is never run again.** Previously any failure was treated as a
  wrong password and the whole script, including `mkfs`/`dd`, could be re-run.
- The sudo password is checked once and then dropped from memory; the operation continues on
  sudo's credential timestamp (with an automatic fallback that asks again).
- Linux partitioning waits for `udevadm settle` instead of a fixed `sleep 2`, unmounts
  partitions the desktop auto-mounted, and uses `oflag=direct` when the image size allows it.
- The product and window title is now **EPMA USB CREATOR** (it was "EPMA Windows 11 Creator USB"; the tool also writes Linux images).
- The application name shown in the macOS menu bar and Dock is now `epma-usb-creator`
  instead of `Python`; the Linux window class matches.
- Minimum supported Python is now 3.10 (CI covers 3.10 through 3.14).
- GitHub Actions are pinned by full commit SHA and run on Node 24; CI runs on a pinned
  `ubuntu-24.04` image.
- The Homebrew caveats now describe the current safeguards (USB-only listing, final
  confirmation, verification and eject).

### Fixed

- Disk identifiers are matched with `fullmatch`: `"sdb\n"` used to pass the `$`-anchored
  pattern.
- Unnamed volumes are labelled with their file system instead of `?`.
- The password dialog no longer fails on Tk 9 / macOS. `tkinter.simpledialog` raised a
  `TclError` there, which made the *Create* button appear to do nothing. Errors raised in
  button callbacks are now shown in a dialog instead of disappearing.

## [1.0.0] - 2026-07-27

### Added

- First public release: create a bootable Windows 11 USB drive from macOS or Linux (GPT +
  FAT32, `install.wim`/`install.esd` split with `wimlib` when larger than 4 GB).
- Security hardening from the audit: HTTPS-only downloads from trusted hosts with optional
  SHA-256 verification, no shell interpolation in privileged commands, target re-verification
  before erasing, and an audit log. See `SECURITY.md`.
- CI, security pipeline (regression guard, Bandit, Semgrep, CodeQL, Gitleaks) and a release
  workflow producing SHA256SUMS and a build-provenance attestation.
- Homebrew formula (`1985epma/homebrew-tap`).

[Unreleased]: https://github.com/1985epma/epma-windows-usb-creator/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/1985epma/epma-windows-usb-creator/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/1985epma/epma-windows-usb-creator/releases/tag/v1.0.0
