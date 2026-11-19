//! Built-in documentation (the Help window). Port of win11_usb_creator.py lines 9195-9530.
//!
//! The text lives here, as data, so tests can check it against the code: every command line command, exit code,
//! environment variable and risk threshold it mentions comes from the same constants the program uses. The
//! documentation is in English only. Lines starting with "## " are sub-headings and "• " are bullets.
//!
//! Deliberate differences from the Python text (it described a Python/Tkinter program):
//! * About: the last sentence ("The program has no third-party dependencies: it uses only the Python standard
//!   library.") is now "The program is written in Rust and bundles its libraries."
//! * Command line: "(no Tkinter needed)" is now "(no window is needed)".
//! * Troubleshooting: the entry about "Tkinter is not available for this Python installation" (with its Tk install
//!   instructions) is gone, because the program no longer depends on Tk or Python.
//! * macOS: the Rust build has a sixth card (the image type "macOS") that the Python program does not have, so the
//!   sections that list the image types (Overview, Getting the image, The drive and the Create button,
//!   Verification and eject, Command line) name it too. `tests/test_help_a5.rs` lists these changes one by one.
//! * macOS seed: the same, for the hardening seed's fifth target (Hardened setup, Command line).

use crate::cli::{EXIT_EJECT_FAILED, EXIT_ERROR, EXIT_INTERRUPTED, EXIT_OK, EXIT_USAGE, EXIT_VERIFY_FAILED};
use crate::constants::{
    APP_TAGLINE, AUDIT_LOG_BACKUPS, AUDIT_LOG_MAX_BYTES, CHROMEOS_FLEX_GUIDE_URL, CHROMEOS_FLEX_REQUIREMENTS_URL,
    CHROMEOS_FLEX_URL, CRITICAL_MOUNTPOINTS, DEFAULT_TRUSTED_ISO_HOSTS, DOWNLOAD_MAX_ATTEMPTS, ENV_ALLOW_ANY_HOST,
    ENV_AUDIT_LOG, ENV_DISABLE_AUDIT_LOG, ENV_EXPECTED_SHA256, ENV_LANG, ENV_TRUSTED_HOSTS, PROJECT_URL, VERSION,
    VOL_NAME,
};
use crate::diskrisk::{LARGE_DISK_BYTES, MANY_VOLUMES, SUBSTANTIAL_USED_BYTES};
use crate::harden_windows::{describe_hardening_windows_applied, WINDOWS_HARDENING_NOT_CHANGED};
use crate::types::Hardening;

const GIB: u64 = 1024 * 1024 * 1024;

/// `help_sections()`: `(title, body)` pairs. The text embeds constants (risk thresholds, env vars, exit codes...) so
/// it can never drift from the code. The audit log path comes from `audit::audit_log_path()` and the platform name
/// (About) from `proc::platform_display_name()`; see [`help_sections_with`].
pub fn help_sections() -> Vec<(String, String)> {
    let audit_path = crate::audit::audit_log_path().display().to_string();
    let platform = crate::proc::platform_display_name();
    let applied = describe_hardening_windows_applied(Hardening::Baseline);
    help_sections_with(&audit_path, &platform, &applied, WINDOWS_HARDENING_NOT_CHANGED)
}

/// The sections with the machine-dependent pieces given: the audit log path, the platform name (About), the lines of
/// `describe_hardening_windows_applied(baseline)` and `WINDOWS_HARDENING_NOT_CHANGED` (the "What the Windows option
/// changes" section). Split out so the text can be produced and tested without those modules.
pub fn help_sections_with(
    audit_path: &str,
    platform: &str,
    windows_applied: &[String],
    windows_not_changed: &[(&str, &str, &str)],
) -> Vec<(String, String)> {
    let large_gb = LARGE_DISK_BYTES / GIB;
    let used_gb = SUBSTANTIAL_USED_BYTES / GIB;
    let hosts = DEFAULT_TRUSTED_ISO_HOSTS.join(", ");
    let critical_mounts = CRITICAL_MOUNTPOINTS.join(", ");
    let retries = DOWNLOAD_MAX_ATTEMPTS - 1;
    // Python's `f"{x:g}"`: 1.0 is "1" (Rust's Display does the same)
    let audit_mb = AUDIT_LOG_MAX_BYTES as f64 / 1_000_000.0;
    let windows_settings = windows_applied
        .iter()
        .map(|line| format!("• {}", line.split(" -- risk:").next().unwrap_or("")))
        .collect::<Vec<_>>()
        .join("\n");
    let windows_not_changed =
        windows_not_changed.iter().map(|(_id, text, why)| format!("• {text}: {why}")).collect::<Vec<_>>().join("\n");
    vec![
        (
            "Overview".to_string(),
            format!(r#"EPMA USB CREATOR {VERSION} writes a bootable USB drive from an ISO image on Windows 11, macOS and Linux.

## Five image types and the hardening seed (six cards)
• Google Chrome — ChromeOS Flex, Google's free ChromeOS for PCs and Macs. The disk image is written byte for byte, like a Linux ISO. The program can download Google's official image for you.
• Windows 11 — erases the drive, creates a GPT partition table with one FAT32 partition (label {VOL_NAME}) and copies the files of the ISO. The result boots on UEFI computers. Windows' install.wim / install.esd is usually larger than the 4 GB FAT32 limit, so it is split into .swm parts with wimlib-imagex.
• Linux and Other ISO — both write the ISO byte for byte to the whole drive (like dd). Use Linux for Ubuntu, Debian, Fedora, Mint, Arch and other "hybrid" images, and Other ISO for any other bootable image. An ISO that cannot boot from a USB drive is refused before anything is erased.
• macOS — writes a ready-made whole-disk macOS image (.img, or a .dmg converted to a whole-disk image, for example an OpenCore installer) byte for byte to the whole drive. A compressed .dmg or a single volume is refused before anything is erased. For Apple's own installer use 'createinstallmedia' on a Mac.
• Hardening seed (optional, the sixth card) — needs no image. It erases a second, small USB drive and writes hardening files on it for Ubuntu, Fedora/RHEL, Debian, Windows 11 or macOS. See "Hardened setup (optional)".

## What always happens
• Only drives attached over USB are offered. The system disk and internal disks are never listed.
• Everything on the selected drive is erased. Nothing is kept.
• After writing, the drive is read back and compared with the ISO (a hardening seed drive: every file compared byte for byte). Only a drive that passes is ejected.

## The window, from top to bottom
• The top row shows the program name and version, a status chip for the tools it needs ("Ready" in green, "Missing tools" in amber with "Install missing dependencies" next to it) and "Help", which opens this documentation (F1 does the same).
• The page has three numbered steps. 1 Image type: six equal cards. Five choose the type of image (Google Chrome (ChromeOS Flex), Windows 11, Linux, macOS and Other ISO); the sixth, "Hardening seed", makes a separate drive and needs no image file.
• 2 Image: the panel under the cards changes with the card and shows where to get that kind of image. "Select existing ISO file..." picks the image you already have; the chosen file is shown with its name, folder, size and the type the program recognised (Windows 11, Linux, ChromeOS Flex, macOS or Unknown), with an optional SHA-256 check behind a link.
• 3 USB drive: the list of USB drives (read when the program starts and whenever you return to the window) and "Refresh USB drives list".
• "Create Bootable USB Drive" (the blue button), the one "Cancel" button for whatever is running (a download, an extraction or the write), its progress bar, and "Show details", which opens the log.
• Results appear under the Create button instead of in pop-up windows: a red box for a failed download, extraction, drive listing or tool installation (with "Try again" where it makes sense, and "Dismiss"), and a green box when the drive was written, verified and ejected, with "Make another" to start over. A failed or canceled write also keeps its pop-up, because the state of the drive matters.
• Help menu: this documentation, the audit log folder, the project page and About."#),
        ),
        (
            "Quick start: Windows 11".to_string(),
            r#"## 1. Get the ISO (card "Windows 11")
• Click "Open Microsoft's official page". Under "Download Windows 11 Disk Image (ISO)" choose "Windows 11 (multi-edition ISO)", pick the language and confirm.
• Right-click the blue 64-bit button and choose "Copy Link Address". Do not click it to download in the browser.
• Paste the link into "Direct ISO link". If Microsoft shows a SHA-256 checksum, paste it into "Expected SHA-256" so the download is checked automatically.
• Click "Download ISO" and choose where to save it.
• Already have the ISO? Click "Select existing ISO file..." instead.

## 2. Write the drive
• The chip at the top right must say "Ready". If it says "Missing tools", click "Install missing dependencies" next to it.
• Plug in the USB drive (8 GB or more) and click "Refresh USB drives list". Select your drive.
• The "Windows 11" card is chosen for you when the ISO is a Windows installer.
• Click "Create Bootable USB Drive", read the confirmation (model, size, volumes) and confirm.
• Wait for the progress bar. When the green box says the drive was verified and ejected, unplug it.

## Optional: hardened settings
• On the "Windows 11" card, tick "Add hardening settings to the Windows installation (optional)" before you click Create. Click "What does it change?" to read the list. See "Hardened setup (optional)" for what it does and does not do.

## 3. Boot from it
• The computer must start in UEFI mode (not Legacy/CSM). The drive is UEFI + GPT only.
• This tool does not bypass the Windows 11 requirements (TPM 2.0, Secure Boot)."#.to_string(),
        ),
        (
            "Quick start: Linux and other ISOs".to_string(),
            r#"## 1. Choose the ISO (card "Linux" or "Other ISO")
• Download the ISO from your distribution's website, then click "Select existing ISO file...". "Linux" and "Other ISO" write the image the same way; "Other ISO" is for any other bootable image.
• Optional but recommended: click "Verify the selected ISO (SHA-256)" under the file name, paste the checksum published by the distribution (or the whole line from its SHA256SUMS file) and click "Calculate SHA-256". Continue only on MATCH.

## 2. Write the drive
• The "Linux" card is chosen for you when the contents are a bootable ISO that is not a Windows installer.
• Plug in the drive, click "Refresh USB drives list", select it, and click "Create Bootable USB Drive".
• Confirm. The administrator password is requested before the drive is touched.
• The ISO is written, then read back and compared, then the drive is ejected.

## Optional: a hardened install
• Linux ISOs cannot take extra files after they are written, so the hardening settings go on a SECOND, small USB drive made with the "Hardening seed" card. See "Hardened setup (optional)".

## 3. On macOS: the drive will not appear in Finder
• macOS cannot read Linux (ISO 9660 / ext) images, so Finder shows nothing and macOS may say "The disk you attached was not readable".
• Click "Ignore". Never click "Initialize" — it would erase what was just written.
• This is normal. The content was already verified byte for byte."#.to_string(),
        ),
        (
            "Hardened setup (optional)".to_string(),
            r#"## What it is
• Optional files that make a fresh install start from safer settings ("Hardened (recommended settings)"). The settings are inspired by common security baselines. This program does NOT claim that the result complies with, or is certified by, any standard.
• Nothing here chooses a disk, creates an account or sets a password or key. Windows Setup and the Linux installers stay interactive: you still pick the disk, the language and your own account.
• Every hardening script prints each change, keeps a backup of anything it modifies and can be undone. They were checked with simulated systems and automated tests only, so try them on a spare computer or a virtual machine before relying on them.
• Want to read the files first? The command line "harden-files" writes them into a folder without touching any drive.

## Windows 11 (same USB drive)
• Tick "Add hardening settings to the Windows installation (optional)" on the "Windows 11" card. The files are copied onto the same USB drive and checked byte for byte with the rest.
• Windows Setup runs a script at the END of the installation. Its log will be C:\Windows\Temp\epma-hardening.log. The script runs once and does not retry: a line marked [WARN] means a setting was not in effect (for example another antivirus or Tamper Protection got in the way).
• If the image already contains one of these files, the program stops BEFORE erasing the drive and tells you, because the files would replace the image's own.

## What the Windows option changes
@WINDOWS_SETTINGS@

## What it deliberately leaves alone
@NOT_CHANGED@

## Linux and others (a second USB drive)
• Choose the "Hardening seed" card, pick the target system, select a small USB drive (64 MiB or more) and click "Create Seed Drive". The drive is erased and checked like any other; it is NOT an installer.
• Keep your normal installer USB and plug the seed drive in next to it before you start the installer.
• Ubuntu (autoinstall): the drive is named CIDATA. At the boot menu add the word autoinstall to the boot line (the README.txt on the drive shows the exact steps). Every installer screen stays interactive.
• Fedora / RHEL (kickstart): the drive is named OEMDRV and the installer finds it by itself. Disk, accounts and the summary stay interactive.
• Debian (script + preseed): the installer does NOT find this drive by itself. After installing, mount the drive and run the script as administrator (sudo bash harden-linux.sh, or su - if there is no sudo).
• The script harden-linux.sh is a plain text file on the drive: read it before you use it. It supports --dry-run (changes nothing), --yes, --undo and --help, and it appends to /var/log/epma-hardening.log.
• It tries not to lock you out of SSH: it only turns off root login or password login when an administrator account with a key exists, and it says so. It does not enable a firewall on a computer that runs Docker, libvirt or LXD unless you pass --yes. Test a second SSH session before you close the first.

## Windows 11 (a second USB drive)
• Choose the "Hardening seed" card and "Windows 11 (run after install)", select a small USB drive and click "Create Seed Drive". The drive is erased and checked like any other; it is NOT an installer.
• It works on a Windows 11 that is already installed (it does not take part in the installation). Open the drive in File Explorer and double-click audit.cmd first: it only reports what is in effect (lines marked [DIFF] are not). Then double-click harden.cmd, answer y and accept the administrator prompt. A restart may be needed for a few settings.
• The files on the drive are not authenticated: run only a seed drive you made yourself and keep it with you. The log is C:\Windows\Temp\epma-hardening.log.
• Extra, opt-in: in an elevated PowerShell run harden.ps1 with -DisableLegacyNetwork to also turn off NetBIOS over TCP/IP and WPAD proxy auto-discovery (it can break very old networks).

## macOS (a second USB drive)
• Choose the "Hardening seed" card and "macOS (run after install)", select a small USB drive and click "Create Seed Drive". The drive is erased and checked like any other; it is NOT an installer.
• It works on a Mac that is already installed (it does not take part in the installation). Open the drive in Finder and double-click audit.command first: it only reports what is in effect and needs no password (lines marked [CHANGE] would be changed, lines marked [WARN] need a look). Then double-click harden.command, answer y and type your password in the Terminal window. If a .command file does not open, run: sudo bash /Volumes/EPMA-SEED/harden-macos.sh
• It turns on the Application Firewall, stealth mode and Gatekeeper, enables automatic update checks and turns off the guest account and automatic login. It only reports FileVault, System Integrity Protection and Remote Login, and never changes them. Major macOS upgrades are not installed.
• The files on the drive are not authenticated: run only a seed drive you made yourself and keep it with you. The log is /var/log/epma-hardening.log. Applying and undoing were tested against stand-in commands only, never on a real Mac.

## Undo
• Linux: run the script again with --undo. It restores the files it backed up and removes the ones it created. It does not uninstall packages or turn services off.
• Windows: double-click undo.cmd on the seed drive (or run harden.ps1 -Mode Undo as administrator). It restores the values it recorded before changing them. It does not turn SMBv1 or the PowerShell 2.0 feature back on, does not shrink the Security log, and cannot restore a setting that was already in the wanted state before. It may report a non-zero exit code when a step failed: read its lines.
• macOS: double-click undo.command on the seed drive (or run sudo bash harden-macos.sh --undo). It puts back the values it remembered before changing them; a setting that was already in the wanted state is not remembered and stays as it is."#.to_string()
            .replace("@WINDOWS_SETTINGS@", &windows_settings)
            .replace("@NOT_CHANGED@", &windows_not_changed),
        ),
        (
            "ChromeOS Flex".to_string(),
            r#"## What it is
• ChromeOS Flex is Google's free version of ChromeOS for PCs and Macs. It is the official way to run ChromeOS on a computer you already own: Google does not publish regular ChromeOS for ordinary computers, so this program does not offer it.
• ChromeOS Flex is provided by Google under Google's own terms. This program only downloads Google's official image and writes it to your drive.

## What you need
• A USB drive of 16 GB or larger. Everything on it is erased. Google notes that some drives (certain Sandisk models, for example) may not work as installers.
• On the computer you will install it on: an Intel or AMD 64-bit processor, 4 GB of RAM, 16 GB of internal storage, and the ability to boot from USB. Google only guarantees ChromeOS Flex on certified models; other computers may work without guarantees.
• Google's guide: @GUIDE@
• Google's requirements: @REQUIREMENTS@

## Steps
• Choose the "Google Chrome" card and click "Download ChromeOS Flex from Google". Choose where to save the file. The download is resumable. The ZIP is extracted automatically; the ZIP that this program downloaded is deleted afterwards (a ZIP you selected yourself is kept).
• Already have latest.bin.zip, or the .bin inside it? Use "Select existing image..." (a ZIP is extracted for you).
• Then plug in the USB drive, click "Refresh USB drives list", select the drive and click "Create Bootable USB Drive". The confirmation, the administrator password, the progress bar and the Cancel button work as for any other image.
• The image is written, read back and compared with the file, and the drive is ejected.
• Boot the computer from the USB drive and follow Google's guide for the next steps.

## Notes
• The image is about 9.5 GB once extracted and the download about 1.4 GB: keep roughly 12 GB free on the computer while preparing it (a warning appears when there is less). The drive must be at least as large as the image, otherwise nothing is touched; a drive below 16 GB shows a warning first.
• The official address redirects to a versioned file on dl.google.com. A redirect to any other server is refused and what arrived is discarded.
• The administrator password is asked on macOS as well, because the whole drive is written directly.
• On Windows the finished drive may make Windows offer to format it (it cannot read Linux or ChromeOS partitions): click Cancel, never Format.
• On macOS the finished drive does not appear in Finder, as with Linux images (see "Quick start: Linux and other ISOs").
• The download link is only accepted when it is Google's official address (@URL@).
• Command line: fetch-chromeos downloads and extracts the image; write --mode chromeos writes it."#.to_string()
            .replace("@GUIDE@", CHROMEOS_FLEX_GUIDE_URL)
            .replace("@REQUIREMENTS@", CHROMEOS_FLEX_REQUIREMENTS_URL)
            .replace("@URL@", CHROMEOS_FLEX_URL),
        ),
        (
            "Getting the image".to_string(),
            r#"## Windows 11: direct ISO link
• Only https:// links are accepted: an unencrypted link could be altered on the way.
• Links to servers outside Microsoft's known download hosts (@HOSTS@) show a warning. Download Windows only from Microsoft.

## Expected SHA-256 (optional)
• 64 hexadecimal characters. If the downloaded file does not match, it is discarded.

## Download controls
• The bar shows percentage, speed and time left.
• "Cancel" keeps the partial file. Downloading to the same file again resumes where it stopped when the server supports it, and temporary network errors are retried automatically (up to @RETRIES@ retries, @ATTEMPTS@ attempts in all).
• A file that fails the checksum is deleted.

## Select existing ISO file...
• Picks an image you already have (.iso, .bin or .img; a ChromeOS Flex .zip is extracted for you). The card (Windows, Linux, macOS or Google Chrome) is chosen from the contents of the image, not from its name. You can still click another card.
• If the file clearly does not match the card (for example a Linux ISO under "Windows 11"), the program asks before erasing anything; a file that is not a ChromeOS Flex image under "Google Chrome" is refused. A file that does not look like a macOS disk image under "macOS" is asked about in the same way.

## Verify the selected ISO (SHA-256)
• A link under the file name, shown once an image is selected; click it to open the panel. Paste the expected hash, or the whole line from a SHA256SUMS file (the file name picks the right line), and click "Calculate SHA-256".
• MATCH (green): the file is identical to the published one. MISMATCH (red): do not use it.
• With no expected value it only shows the hash so you can compare it yourself."#.to_string()
            .replace("@HOSTS@", &hosts)
            .replace("@RETRIES@", &retries.to_string())
            .replace("@ATTEMPTS@", &DOWNLOAD_MAX_ATTEMPTS.to_string()),
        ),
        (
            "The drive and the Create button".to_string(),
            format!(r#"## The cards
• Google Chrome (ChromeOS Flex, disk image written directly), Windows 11 (GPT + FAT32, files copied), Linux, macOS and Other ISO (the image is written directly). The card is chosen from the image contents when you select a file; you can change it.
• Hardening seed: a separate small drive (GPT + FAT32) with auto-install files; no image file is needed, so the image step is hidden and the button reads "Create Seed Drive".

## Dependencies
• Windows mode needs wimlib (macOS: brew install wimlib). On Linux it also needs parted, mkfs.vfat (dosfstools), wipefs, partprobe, rsync and wimlib-imagex. On Windows 11 it needs nothing extra: PowerShell and DISM come with Windows (DISM splits install.wim when it is over 4 GB). On Windows a FAT32 volume is at most 30 GiB, so a bigger drive keeps the rest unallocated.
• The Google Chrome, Linux, macOS and Other ISO cards need nothing extra. The Hardening seed card needs only parted, mkfs.vfat, wipefs and partprobe on Linux and nothing extra on macOS.
• The dependencies are checked before anything is erased. When one is missing, the Create button stays disabled and a hint says what to install.
• "Install missing dependencies" uses your package manager (apt-get, dnf, yum, pacman, zypper, apk or Homebrew) and asks for the administrator password on Linux.

## The drive list
• Each drive is a row with a USB badge, its model, size, device and volumes, for example "SanDisk Ultra — 58.6 GB — /dev/disk4 · 2 volumes (Untitled, EFI)". The chosen row is highlighted; click a row, or use the Up and Down arrow keys, to choose another. While the drives are being read, two grey rows stand in; when there are none, the list says "No USB drive found". The list is read when the program starts and whenever you return to the window; click "Refresh USB drives list" if a drive you just plugged in is missing. While "Create Bootable USB Drive" is disabled, a line under it says what is missing.

## The confirmation
• The dialog shows model, size and every volume with its used space, so you can recognise the drive.
• Drives that do not look like a spare stick need you to type their identifier (for example disk4). That applies to drives larger than {large_gb} GB, with {used_gb} GB or more in use, with a name that suggests backups or personal data, that look like an external hard disk or SSD, with {MANY_VOLUMES} or more volumes, or whose contents could not be read.

## Administrator password
• Needed on Linux, and on macOS for the direct-write cards (Google Chrome, Linux, macOS and Other ISO). It is asked right after you confirm and checked before the drive is touched: a wrong or canceled password changes nothing.
• On Windows there is no password: the program itself must run as Administrator (the installed shortcut asks Windows for it with the UAC prompt; from a terminal, open it with Run as administrator). Without it nothing is changed.
• It is checked once. Normally it is then dropped and sudo's own credential timestamp carries the operation; only if this computer does not keep that timestamp does the password stay in memory, until the operation ends. It is used only to run local disk commands and is never logged, written to disk or sent anywhere.

## Progress, Cancel and the log
• The bar shows the percentage, speed and time left while writing and while verifying. Some steps (comparing files) show a moving bar without a percentage.
• "Cancel" stops the running operation (a download, an extraction or the write). If it is pressed during the write before the drive is touched, the log says so and nothing changed; otherwise the drive is left unusable until it is written again.
• Closing the window while a drive is being written asks you first, because stopping halfway leaves the drive unusable.
• "Show details" opens a box with every command that runs; it opens by itself when a write fails. Keep its text if you need to report a problem."#),
        ),
        (
            "Safety".to_string(),
            format!(r#"## What protects you
• Only USB drives are listed. If the program cannot confirm that a disk is external and safe, it hides the disk instead of offering it. On Linux, disks that hold the system ({critical_mounts}, or anything under /boot) are never listed; on Windows the disk that holds the running Windows is never listed.
• You see the model, size and contents before erasing. Large or data-filled drives need the identifier typed.
• Right before erasing, the drive is looked up again and must still be the same device (size, serial number, model). If it was swapped, the operation stops.
• A privileged command that fails is never run a second time on its own.
• The result is verified before the drive is ejected.
• The administrator password is checked up front, before the drive is touched. Normally it is then dropped and sudo's own credential timestamp is used; only if this computer does not keep that timestamp does the password stay in memory, until the operation ends. It is never logged or written to disk.
• Missing dependencies are detected before anything is erased, and a Windows ISO that is larger than the drive is refused up front.
• Closing the window during a write asks for confirmation first.

## What it cannot do for you
• It cannot tell which of your USB drives you meant. Read the model, size and volumes in the confirmation every time.
• It erases the whole drive, including partitions Windows, macOS or Linux may not show.
• A drive that was canceled or interrupted mid-write is not usable until written again."#),
        ),
        (
            "Verification and eject".to_string(),
            r#"## Verification
• Linux, ChromeOS Flex and macOS modes: the whole image is read back from the drive and compared byte for byte with the file.
• Windows mode: the drive is unmounted and mounted again so it is read from the device, then every file is compared by checksum with the ISO. A split install image is also checked with wimlib-imagex verify.
• Verification cannot be skipped. If anything differs, the drive is NOT ejected, the message says so, and the drive must not be used. Write it again; if it keeps failing, try another USB port or another drive.

## Eject
• After a successful verification the drive is ejected. If it is busy, the program unmounts it by force and tries again.
• The green box under the Create button says the drive was verified and ejected. If the eject failed the box is amber and tells you to eject the drive from Finder or your file manager before unplugging.
• The log ends with "Drive ejected — you can unplug it now." When it says the drive could not be ejected, eject it from Finder or your file manager before unplugging.
• Always wait for that message before pulling the drive out."#.to_string(),
        ),
        (
            "Command line".to_string(),
            format!(r#"The same engine works without the window. Run the program with a command (no window is needed):

## Commands
• list [--json] — USB drives that can be used.
• detect ISO [--json] — prints windows, linux, chromeos, macos or unknown.
• fetch-chromeos [--dest DIR] [--keep-zip] [--json] — downloads ChromeOS Flex from Google and extracts the disk image. It does not write a drive.
• sha256 ISO [--expected HASH] [--json] — checksum of an ISO; exits {EXIT_VERIFY_FAILED} when it differs from --expected.
• write --iso ISO --disk DISK [--mode auto|windows|linux|chromeos|macos] [--hardened] [--dry-run] [--yes] [--no-eject] [--json] [-v] — write a drive.
• harden-seed --target ubuntu|fedora|debian|windows|macos --disk DISK [--dry-run] [--yes] [--no-eject] [--json] [-v] — erase a small separate USB drive and write the hardening seed files on it.
• harden-files --target windows|windows-seed|ubuntu|fedora|debian|macos --out DIR [--json] — write the hardening files into a new or empty folder. "windows" is the set for the same USB drive as Windows; "windows-seed" is the set for the Windows seed drive; "macos" is the set for the macOS seed drive. No drive is involved and no administrator rights are needed.
• gui, or no command — open this window.
• --version, --help — program version and the full help.

## write
• --dry-run shows the plan and changes nothing. It is the safest way to try a command.
• Without --yes you are asked to type the disk identifier. When there is no terminal, --yes is required.
• Verification is always performed. There is no option to skip it.
• --hardened (Windows mode only; anything else is a usage error) adds the optional Hardened (recommended settings) files to the same USB drive. --dry-run lists their names.

## harden-seed and harden-files
• harden-seed asks for the same confirmation as write (type the disk identifier, or pass --yes), checks the drive the same way, verifies what it wrote and ejects. The seed drive is erased like any other target.
• The seed files never choose a disk, never partition or format anything and never create accounts or set passwords: storage and the user account stay interactive in the installer.
• harden-seed --target windows makes the Windows 11 seed drive (label EPMA-SEED): harden.cmd, audit.cmd, undo.cmd, harden.ps1 and a README to run as administrator on an installed Windows.
• harden-seed --target macos makes the macOS seed drive (label EPMA-SEED): harden.command, audit.command, undo.command, harden-macos.sh and a README to run on a Mac that is already installed.
• harden-files refuses a folder that is not empty and never overwrites anything.

## Exit codes
• {EXIT_OK} success
• {EXIT_ERROR} generic error
• {EXIT_USAGE} wrong usage or missing confirmation
• {EXIT_VERIFY_FAILED} verification failed or checksum mismatch
• {EXIT_EJECT_FAILED} written and verified, but the drive could not be ejected
• {EXIT_INTERRUPTED} interrupted (Ctrl-C)

Data goes to stdout; messages, progress and errors go to stderr. NO_COLOR is honored."#),
        ),
        (
            "Troubleshooting".to_string(),
            r#"## No drive appears in the list
• Only USB drives are listed (SD cards, internal disks and the system disk never are). Check the connection and click "Refresh USB drives list".

## The drive does not show in Finder after a Linux ISO (macOS)
• Expected. See "Quick start: Linux and other ISOs". Click Ignore, never Initialize.

## "Verification FAILED"
• The drive does not match the ISO. It was not ejected and must not be used. Write it again; try another port or drive if it repeats.

## "Aborted for safety: /dev/... is no longer listed as an external drive"
• The drive changed between choosing it and writing. Refresh the list and select it again.

## "Could not find sources/install.wim or sources/install.esd on the ISO"
• The ISO is not a Windows installation image. Download the official multi-edition ISO from Microsoft, or use the Linux mode for a Linux ISO.

## "This ISO is not a bootable hybrid image"
• Linux mode needs a hybrid image. Current Ubuntu, Debian, Fedora, Mint and Arch ISOs are. A Windows ISO needs the Windows mode.

## "This is the ZIP archive, not the disk image inside it"
• You selected latest.bin.zip in a place that expects the .bin. With the "Google Chrome" card (or "Select existing ISO file...") choose the ZIP and the program extracts the .bin for you.

## "This file is not a bootable disk image"
• ChromeOS Flex mode needs the .bin from Google's official latest.bin.zip. Download it again with the "Google Chrome" card.

## "The image is larger than the drive"
• Choose a bigger USB drive. Nothing was changed. For ChromeOS Flex Google asks for 16 GB or larger.

## The ChromeOS Flex download fails or is very slow
• Cancel and start it again: the partial file is kept and the download resumes. Google's server is the only source this program accepts for it.

## "wimlib-imagex not found"
• Install wimlib (macOS: brew install wimlib) or use "Install missing dependencies".

## "Neither 'sudo' nor 'pkexec' was found"
• Install sudo, or run the program as root.

## The computer does not boot from the drive
• Windows drives are UEFI + GPT only: choose the UEFI entry in the boot menu and make sure Legacy/CSM is off.

## A cancel or crash during writing
• The drive is unusable until it is written again. Nothing else is affected."#.to_string(),
        ),
        (
            "Files, logs and settings".to_string(),
            format!(r#"## Audit log
• Every destructive operation is recorded with its start, result and the SHA-256 of the ISO, together with security events such as hidden disks and rejected identifiers. Passwords are never logged.
• Location: {audit_path}
• It rotates at {audit_mb} MB ({AUDIT_LOG_BACKUPS} older files are kept) and is readable only by you. "Help > Open the audit log folder" opens it.

## Environment variables (all optional)
• {ENV_AUDIT_LOG} — another path for the audit log.
• {ENV_DISABLE_AUDIT_LOG} — set to 1 to turn the audit log off.
• {ENV_TRUSTED_HOSTS} — comma-separated list of trusted download hosts (replaces the Microsoft list).
• {ENV_ALLOW_ANY_HOST} — set to 1 to silence the unrecognised-server warning. This lowers security.
• {ENV_EXPECTED_SHA256} — pre-fills the expected checksum field of the Windows 11 card.
• {ENV_LANG} — set to pt for a Brazilian Portuguese window. The default is US English whatever the system language.

## Privacy
• No telemetry, no accounts, no data leaves your computer. The only network traffic is the ISO or ChromeOS Flex download you ask for."#),
        ),
        (
            "About".to_string(),
            format!(r#"EPMA USB CREATOR {VERSION}
{APP_TAGLINE}, on Windows 11, macOS and Linux.

Platform: {platform}
License: GNU General Public License v3 or later
Copyright (C) 2026 EPMA
Project: {PROJECT_URL}

The program is written in Rust and bundles its libraries."#),
        ),
    ]
}
