# EPMA Windows 11 Creator USB

**English** · [Português](README.pt-BR.md)

Cross-platform GUI application (**macOS** and **any Linux distribution**) that downloads the official Windows 11 ISO and writes a bootable USB drive in **UEFI (GPT + FAT32)** format.

Written in pure Python with Tkinter — **zero third-party Python dependencies**.

![License](https://img.shields.io/badge/license-GPLv3-blue)
![Platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Linux-lightgrey)
![Python](https://img.shields.io/badge/python-3.9%2B-green)

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
- **Protection against erasing the wrong disk**: only external/removable drives are listed, the system disk is never shown, and three separate confirmations are required before writing.
- **Integrity verification**: HTTPS-only downloads, warnings for unrecognised servers, and a SHA-256 checksum of the downloaded image.
- **Real-time log** of every command executed, inside the application window.

## How it works

1. The ISO is mounted read-only (`hdiutil` on macOS, `mount -o loop,ro` on Linux).
2. The USB drive is wiped and repartitioned as GPT with a single FAT32 partition flagged as ESP.
3. All files from the ISO are copied with `rsync`, **except** `install.wim`/`install.esd`.
4. That large file is handled separately: if it fits within the FAT32 limit it is copied directly; if it exceeds 4 GB it is split into ~3.8 GB parts with `wimlib-imagex split`.
5. Writes are flushed to disk and the USB drive is safely unmounted/ejected.

## Requirements

### macOS

```bash
brew install python-tk@3.14 wimlib
```

> Adjust `python-tk@<version>` to match your Python version. On macOS no `sudo` is required: disk operations on external drives go through `diskutil` and `hdiutil`.

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
2. Plug in the USB drive (**8 GB minimum**) and click **"Refresh external drives list"**.
3. Select your drive from the list.
4. Tick the checkbox confirming that all data will be erased.
5. **Type the disk identifier** (e.g. `disk4` on macOS, `sdb` on Linux) into the confirmation field.
6. Click **"Create Bootable USB Drive"** and confirm in the final dialog.

The process takes several minutes depending on the speed of your USB drive. Follow along in the log at the bottom of the window.

## Security

This application **completely erases** the selected disk and executes privileged commands. The implemented protections are:

### Preventing the wrong disk from being erased

- Only **external/removable** drives are listed. On macOS the internal disk is filtered twice (`diskutil list external physical` plus an explicit `Internal` flag check); on Linux the disk holding the root filesystem is excluded and only removable or USB/MMC-attached devices are shown.
- **Fail closed:** if the application cannot *confirm* that a disk is external, it hides the disk instead of listing it. Disks holding `/`, `/boot`, `/home`, `/usr`, `/var` or `/etc` are never listed, even when the system reports them as removable — this protects machines that boot from an SD card or USB stick, such as a Raspberry Pi.
- **Re-verification before erasing:** immediately before writing, the application re-enumerates the disks and confirms the selected identifier still points to the same device with the same size. Names such as `/dev/sdb` are recycled by the operating system — if a drive is swapped in between, the operation is aborted.
- You must explicitly tick the confirmation checkbox.
- You must **manually type** the exact disk identifier.
- A final confirmation dialog appears before any write occurs.

> Even so: **double-check the selected disk before confirming.**

### Handling of the administrator password (Linux)

The password is used solely to run local disk commands via `sudo -S`. It is passed **exclusively over `stdin`** — never on the command line, where other users on the machine could see it with `ps` — is **never written to disk or transmitted anywhere**, and is cleared from memory as soon as the operation completes.

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

This is safe: nothing touches a disk, formats anything, or requires administrator privileges.

### Continuous integration

Every change is automatically checked by GitHub Actions:

| Workflow | Purpose |
|---|---|
| [`ci.yml`](.github/workflows/ci.yml) | Linting and tests across Python 3.9–3.13 on Linux and macOS |
| [`security.yml`](.github/workflows/security.yml) | Security regression guard, Bandit, Semgrep, CodeQL, secret scanning |
| [`release.yml`](.github/workflows/release.yml) | Publishes releases with SHA-256 checksums and build provenance |

The security pipeline is built in two layers: a dependency-free regression guard that verifies all 24 audit fixes remain in place, plus external analysers as a second opinion. See [.github/README-CICD.md](.github/README-CICD.md) for details. *Note: written in Portuguese.*

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
The device changed between selection and writing. Click *Refresh external drives list* and select the drive again — this check exists precisely to prevent the wrong disk from being erased.

**No drives appear in the list**
Check that the USB drive is plugged in and click *Refresh*. On Linux, some USB-SATA adapters report as non-removable and are deliberately hidden for safety.

**The USB drive does not appear in the boot menu**
Make sure the machine is in **UEFI** mode (not Legacy/CSM). The generated drive is UEFI + GPT and will not boot on legacy BIOS.

## Limitations

- Does not run on Windows (the script exits with an error on that platform).
- Produces **UEFI/GPT** media only — no legacy BIOS boot support.
- Does not bypass Windows 11 requirements (TPM 2.0 / Secure Boot).
- Downloads cannot be resumed: cancelling discards the partial file.
- Formatting does not overwrite the previous contents of the USB drive. If it held sensitive data, wipe it first with `shred` (Linux) or "Erase securely" in Disk Utility (macOS).

## License

Copyright (C) 2026 EPMA

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU General Public License, version 3**, as published by the Free Software Foundation, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but **WITHOUT ANY WARRANTY**; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

The full license text is in [LICENSE](LICENSE) and is also available at <https://www.gnu.org/licenses/gpl-3.0.html>.

---

> **Disclaimer:** Windows and Windows 11 are registered trademarks of Microsoft Corporation. This project is not affiliated with Microsoft. The ISO is downloaded exclusively from Microsoft's official servers, and its use is subject to Microsoft's licensing terms.
