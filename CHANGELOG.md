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
- Release engineering: end-to-end tests against loop devices (Linux CI), ShellCheck over the
  embedded privileged scripts, a per-distribution package-manager probe, a CycloneDX SBOM and
  provenance attestation for every release, OpenSSF Scorecard, and automatic Homebrew tap
  updates.

### Changed

- **Only USB drives are listed** (macOS `BusProtocol=USB`, Linux `tran=usb`); internal and
  other external disks never appear.
- **The typed disk identifier and the confirmation checkbox were removed.** The final
  confirmation dialog, which names the drive and its size, is the single confirmation.
- The application name shown in the macOS menu bar and Dock is now `epma-usb-creator`
  instead of `Python`; the Linux window class matches.
- Minimum supported Python is now 3.10 (CI covers 3.10 through 3.14).
- GitHub Actions are pinned by full commit SHA and run on Node 24; CI runs on a pinned
  `ubuntu-24.04` image.
- The Homebrew caveats now describe the current safeguards (USB-only listing, final
  confirmation, verification and eject).

### Fixed

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
