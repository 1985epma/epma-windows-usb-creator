# EPMA USB CREATOR

**English** · [Português](README.pt-BR.md)

Cross-platform application (**macOS** and **any Linux distribution**) that downloads the official Windows 11 ISO and writes a bootable USB drive in **UEFI (GPT + FAT32)** format. It can also write **any hybrid ISO** (Ubuntu, Debian, Fedora, Mint, Arch…) directly to a USB drive, and every write is **read back and verified** before the drive is ejected.

It has a graphical interface (US English) and a [command line mode](#command-line).

Written in pure Python with Tkinter — **zero third-party Python dependencies**.

![License](https://img.shields.io/badge/license-GPLv3-blue)
![Platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Linux-lightgrey)
![Python](https://img.shields.io/badge/python-3.10%2B-green)

---

## Table of contents

- [Features](#features)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Security](#security)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [License](#license)

---

## Features

- **Download the ISO** from within the application, with a progress bar, transfer speed, time remaining and a cancel button.
- **Use an existing ISO** if you already downloaded the file in your browser.
- **Automatic formatting** of the USB drive as GPT + FAT32 with the label `WIN11USB` (UEFI-bootable, no need to disable Secure Boot).
- **Automatic splitting of `install.wim` / `install.esd`**: these files usually exceed 4 GB, the FAT32 size limit. The application detects this and splits the file into `.swm` parts using `wimlib-imagex`.
- **Automatic dependency installation**: detects your package manager (`apt-get`, `dnf`, `yum`, `pacman`, `zypper`, `apk`) or Homebrew on macOS and installs whatever is missing.
- **Two image types**: *Windows 11* (GPT + FAT32, files copied) or *Linux / other hybrid ISO* (written byte-for-byte, like `dd`). The type is detected from the ISO's **contents**, not its file name, and you can always change it.
- **Verified writes**: after writing, the drive is read back and compared with the ISO (byte for byte for Linux images; checksum comparison and `wimlib-imagex verify` for Windows). If anything differs the drive is **not** ejected and you are told not to use it.
- **Reliable eject** once the drive has been verified, with a clear message if the operating system refuses.
- **Progress bar** with percentage, speed and time remaining for writing and verifying; a **Cancel** button for the whole operation.
- **Protection against erasing the wrong disk**: only USB drives are listed with their model and volumes, the system disk is never shown, risky drives (large, holding data, looking like a backup disk) require you to **type the disk identifier**, and a final confirmation is always required.
- **SHA-256 check for an ISO you already have** (paste the expected value or a `SHA256SUMS` line).
- **Resumable downloads** with automatic retries.
- **Command line mode** (`list`, `write`, `detect`, `sha256`, `--dry-run`, JSON output, exit codes) for scripts.
- **Built-in documentation**: open **Help → EPMA USB CREATOR Help** (or press **F1**) for quick starts, a reference for both tabs, safety, verification and eject, the command line, troubleshooting and the files/settings the program uses.
- **Integrity verification**: HTTPS-only downloads, warnings for unrecognised servers, and a SHA-256 checksum of the downloaded image.
- **Real-time log** of every command executed, inside the application window.

## How it works

1. The ISO is mounted read-only (`hdiutil` on macOS, `mount -o loop,ro` on Linux).
2. The USB drive is wiped and repartitioned as GPT with a single FAT32 partition flagged as ESP.
3. All files from the ISO are copied with `rsync`, **except** `install.wim`/`install.esd`.
4. That large file is handled separately: if it fits within the FAT32 limit it is copied directly; if it exceeds 4 GB it is split into ~3.8 GB parts with `wimlib-imagex split`.
5. Writes are flushed to disk, the drive is remounted and **read back to verify** that every file matches the ISO (in Linux mode the ISO is written directly and the whole drive content is compared with it).
6. Only then is the USB drive safely unmounted and ejected.

## Requirements

### macOS

```bash
brew install python-tk@3.14 wimlib
```

> Python **3.10 or newer** is required. Adjust `python-tk@<version>` to match your Python version. In Windows mode macOS needs no `sudo` (disk operations go through `diskutil` and `hdiutil`); Linux mode, which writes the raw device, asks for your administrator password.

### Linux

Package names vary by distribution. Required tools:

| Tool | Debian/Ubuntu | Fedora/RHEL | Arch | openSUSE |
|---|---|---|---|---|
| `parted`, `partprobe` | `parted` | `parted` | `parted` | `parted` |
| `mkfs.vfat` | `dosfstools` | `dosfstools` | `dosfstools` | `dosfstools` |
| `wipefs` | `util-linux` | `util-linux` | `util-linux` | `util-linux` |
| `rsync` | `rsync` | `rsync` | `rsync` | `rsync` |
| `wimlib-imagex` | `wimtools` | `wimlib-utils` | `wimlib` | `wimlib` |
| GUI (Tkinter) | `python3-tk` | `python3-tkinter` | `tk` | `python3-tk` |

Example on Debian/Ubuntu:

```bash
sudo apt install python3-tk parted dosfstools util-linux rsync wimtools
```

Alternatively, just launch the application and use the **"Install missing dependencies"** button on tab 2 — it builds and runs the correct command for your package manager.

On Linux, partitioning/formatting/mounting a raw block device requires root, so the application will ask for your administrator password (via `sudo`, or `pkexec` if `sudo` is unavailable).

## Installation

### Homebrew (macOS — recommended)

```bash
brew tap 1985epma/tap
brew trust 1985epma/tap
brew install epma-windows-usb-creator
```

Then run it with `epma-windows-usb-creator`.

Homebrew pulls in `wimlib` and a Python build with Tkinter automatically, so
there is nothing else to install. `brew trust` is required by Homebrew for any
third-party tap — it is a one-time confirmation that you accept code from this
tap.

### From source

```bash
git clone https://github.com/1985epma/epma-windows-usb-creator.git
cd epma-windows-usb-creator
chmod +x win11_usb_creator.py
```

**Verify the file before running it.** This application asks for your administrator password, which makes a tampered copy a worthwhile target for an attacker:

```bash
shasum -a 256 win11_usb_creator.py
```

For files downloaded from a [release](https://github.com/1985epma/epma-windows-usb-creator/releases), compare the result against the published `SHA256SUMS.txt`, or verify the build provenance attestation issued by GitHub:

```bash
gh attestation verify win11_usb_creator.py --repo 1985epma/epma-windows-usb-creator
```

## Usage

```bash
python3 win11_usb_creator.py
```

### Tab 1 — Download the ISO

Microsoft only exposes the direct ISO link after you select an edition and language on their official site, so:

1. Click **"Open Microsoft's official page"**.
2. Under *Download Windows 11 Disk Image (ISO)*, select **Windows 11 (multi-edition ISO)** and click Download.
3. Choose your language and confirm.
4. **Right-click** the blue 64-bit download button and choose **"Copy Link Address"** (do not click it to download in the browser).
5. Paste the link into the field and click **"Download ISO"**.

Optionally, paste Microsoft's published SHA-256 checksum into the *Expected SHA-256* field. If the downloaded file does not match, it is discarded automatically.

If you already downloaded the ISO manually, use **"Select existing ISO file..."** and skip to tab 2.

### Tab 2 — Create the USB drive

1. Check the dependency status at the top (install anything missing, if needed).
2. Plug in the USB drive (**8 GB minimum**) and click **"Refresh USB drives list"**.
3. Select your drive from the list.
4. Choose the **image type** (it is suggested from the ISO file name):
   - **Windows 11** — GPT + FAT32, ISO files copied (`install.wim` split when over 4 GB).
   - **Linux / other hybrid ISO** — the ISO is written byte-for-byte to the drive (like `dd`). Use this for Ubuntu, Debian, Fedora, Mint, Arch, etc. Select the ISO with *Select existing ISO file...* on tab 1. ISOs without a boot signature are refused before anything is erased.
5. Click **"Create Bootable USB Drive"**. The final dialog shows the drive's model, size and volumes. For a **high-risk drive** (larger than 256 GB, with lots of data, or that looks like a backup/external disk) you must also type its identifier (for example `disk4`). Then the drive is erased and the image is written to it, verified and ejected.
6. Use **Cancel** to stop an operation in progress. The drive is then left unusable until written again.

> Administrator rights are needed on Linux, and on macOS in Linux (direct-write) mode. The password is asked and verified right after you confirm, **before** the drive is touched (a wrong or canceled password changes nothing). A progress bar shows the percentage, speed and time remaining.
>
> **macOS and Linux images:** macOS cannot read Linux (ISO 9660/ext) images, so the finished drive will **not appear in Finder**, and macOS may say the disk is "not readable". Click **Ignore** — never *Initialize*. The content was already verified against the ISO.

The interface is always in US English. A Brazilian Portuguese translation exists and can be switched on explicitly with `EPMA_LANG=pt`; the system language is never used.

The process takes several minutes depending on the speed of your USB drive. Follow along in the log at the bottom of the window.

### Command line

The same engine is available without the window (no Tkinter needed):

```bash
epma-usb-creator --help                 # Homebrew: epma-windows-usb-creator
python3 win11_usb_creator.py list                       # USB drives that can be used (--json available)
python3 win11_usb_creator.py detect ubuntu.iso          # windows | linux | unknown
python3 win11_usb_creator.py sha256 ubuntu.iso --expected <hash>
python3 win11_usb_creator.py write --iso ubuntu.iso --disk disk4 --dry-run   # show the plan, change nothing
python3 win11_usb_creator.py write --iso ubuntu.iso --disk disk4             # asks you to type the disk id
```

`write` always verifies the drive and requires you to type the disk identifier (or pass `--yes` when there is no terminal). It never offers a way to skip verification. Run with no arguments to open the window.

| Exit code | Meaning |
|---|---|
| 0 | success |
| 1 | generic error |
| 2 | wrong usage or missing confirmation |
| 3 | verification failed / checksum mismatch |
| 4 | written and verified, but the drive could not be ejected |
| 130 | interrupted (Ctrl-C) |

Data goes to stdout; messages, progress and errors go to stderr. `NO_COLOR` is honored.

## Security

This application **completely erases** the selected disk and executes privileged commands. The implemented protections are:

### Preventing the wrong disk from being erased

- Only **USB** drives are listed. On macOS the internal disk is filtered twice (`diskutil list external physical` plus an explicit `Internal` flag check) and the bus protocol must be `USB`; on Linux the disk holding the root filesystem is excluded and only devices with USB transport are shown (SD cards and internal disks are not).
- **Fail closed:** if the application cannot *confirm* that a disk is external, it hides the disk instead of listing it. Disks holding `/`, `/boot`, `/home`, `/usr`, `/var` or `/etc` are never listed, even when the system reports them as removable — this protects machines that boot from an SD card or USB stick, such as a Raspberry Pi.
- **You see what you are erasing:** the list and the final dialog show the model, size and volumes (with used space). Drives that are large, hold a lot of data or look like a backup disk require typing the disk identifier.
- **Re-verification before erasing:** immediately before writing, the application re-enumerates the disks and confirms the selected identifier still points to the same device with the same size **and the same serial/model**. Names such as `/dev/sdb` are recycled by the operating system — if a drive is swapped in between, the operation is aborted.
- A final confirmation dialog appears before any write occurs.
- **Nothing is retried blindly:** a privileged script that fails is never run a second time.
- **Verified before eject:** a mismatch aborts without ejecting and the drive is reported as unusable.

> Even so: **double-check the selected disk before confirming.**

### Handling of the administrator password

The password is used solely to run local disk commands via `sudo`. It is checked once, over **`stdin` only** — never on the command line, where other users on the machine could see it with `ps` — and then dropped from memory: the operation continues on sudo's own credential timestamp, which is refreshed while it runs and invalidated (`sudo -k`) at the end. If the system does not keep that timestamp, the application asks again instead of keeping the password. It is **never written to disk or transmitted anywhere**. Every run is recorded in an owner-only audit log, including the SHA-256 of the ISO that was written.

### Integrity of the downloaded image

The application accepts **HTTPS links only** and warns you if the server is not a recognised Microsoft download host. After the download completes it displays the **SHA-256 checksum** of the file. If you supply an expected value, a mismatch causes the file to be discarded.

> **Always download from Microsoft's official website.** Never use a "faster mirror" link suggested in a forum or video — a tampered image would install a compromised Windows without you noticing.

### Security documentation

The threat model, implemented controls and optional environment variables are documented in [SECURITY.md](SECURITY.md).

Full audit reports (SCA, SAST, STRIDE, OWASP Top 10 and DAST) are in [output/](output/). Start with the [consolidated report](output/relatorio-consolidado-seguranca.md). *Note: the audit reports are written in Portuguese.*

## Development

### Running the checks locally

Before submitting a change, run the same checks the CI pipeline runs:

```bash
python3 verificar.py
```

This is safe: nothing touches a disk, formats anything, or requires administrator privileges. The unit tests run on their own with `python3 -m unittest discover -s tests -t .` (no Tkinter needed).

### Continuous integration

Every change is automatically checked by GitHub Actions (all actions are pinned by commit SHA):

| Workflow | Purpose |
|---|---|
| [`ci.yml`](.github/workflows/ci.yml) | Linting, unit tests (Python 3.10–3.14, Linux and macOS), ShellCheck of the embedded scripts, end-to-end tests on loop devices, Linux distribution probes |
| [`security.yml`](.github/workflows/security.yml) | Security regression guard, Bandit, Semgrep, CodeQL, secret scanning |
| [`release.yml`](.github/workflows/release.yml) | Publishes releases with SHA-256 checksums, build provenance and an SBOM; updates the Homebrew tap |
| [`scorecard.yml`](.github/workflows/scorecard.yml) | OpenSSF Scorecard supply-chain assessment |

The security pipeline is built in two layers: a dependency-free regression guard that verifies all 27 audit fixes remain in place, plus external analysers as a second opinion. Each workflow file is extensively commented, explaining what every step does and why.

### Contributing

Third-party dependencies are deliberately avoided — this eliminates the most common supply-chain attack surface in modern software, and CI enforces it. If a dependency becomes genuinely necessary, the failing check explains the process to follow.

## Troubleshooting

**"Tkinter is not available for this Python installation"**
Install Tkinter for your Python version (see [Requirements](#requirements)).

**"wimlib-imagex not found"**
Install `wimlib` (macOS: `brew install wimlib`; Linux: see the table above) or use the dependency installation button.

**"Could not find sources/install.wim or sources/install.esd on the ISO"**
The selected image is not a Windows installation ISO. Download the official *multi-edition* ISO from Microsoft.

**"Only HTTPS links are accepted"**
The download link must start with `https://`. An unencrypted link can be modified in transit, which would let someone replace the Windows image with a tampered one.

**"Neither 'sudo' nor 'pkexec' was found"**
Install `sudo` or run the application as root.

**"Aborted for safety: /dev/sdX is no longer listed as an external drive"**
The device changed between selection and writing. Click *Refresh USB drives list* and select the drive again — this check exists precisely to prevent the wrong disk from being erased.

**No drives appear in the list**
Only drives attached over **USB** are listed (SD cards, internal disks and the system disk never are). Check that the drive is plugged in and click *Refresh*.

**The drive does not show up in Finder after a Linux ISO write (macOS)**
This is expected: macOS cannot read Linux images. If macOS says "the disk is not readable", click **Ignore**, never *Initialize*. The content was verified against the ISO before ejecting.

**"Verification FAILED"**
The data on the drive differs from the ISO. The drive was not ejected and must not be used. Write it again; if it keeps failing, try another USB port or drive.

**The USB drive does not appear in the boot menu**
Make sure the machine is in **UEFI** mode (not Legacy/CSM). The generated drive is UEFI + GPT and will not boot on legacy BIOS.

## Limitations

- Does not run on Windows (the script exits with an error on that platform).
- Produces **UEFI/GPT** media only — no legacy BIOS boot support.
- Does not bypass Windows 11 requirements (TPM 2.0 / Secure Boot).
- A cancelled or interrupted download keeps its partial file and resumes when the server supports it; a failed integrity check discards it.
- Formatting does not overwrite the previous contents of the USB drive. If it held sensitive data, wipe it first with `shred` (Linux) or "Erase securely" in Disk Utility (macOS).

## License

Copyright (C) 2026 EPMA

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU General Public License, version 3**, as published by the Free Software Foundation, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but **WITHOUT ANY WARRANTY**; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

The full license text is in [LICENSE](LICENSE) and is also available at <https://www.gnu.org/licenses/gpl-3.0.html>.

---

> **Disclaimer:** Windows and Windows 11 are registered trademarks of Microsoft Corporation. This project is not affiliated with Microsoft. The ISO is downloaded exclusively from Microsoft's official servers, and its use is subject to Microsoft's licensing terms.
