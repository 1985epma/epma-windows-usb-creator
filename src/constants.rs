//! Global constants (port of win11_usb_creator.py lines 112-267). OWNER: lead (frozen: other agents only read this).
//!
//! Typing rules used everywhere in the port: byte sizes are `u64`; whole seconds are `u64`; fractional seconds are
//! `f64`; strings are `&str`; tuples of strings are `&[&str]`; regexes are `LazyLock<Regex>` statics.
//! Module-local constants (ISO/GPT offsets, Windows backend, seed limits, hardening tables) live with their module.

use regex::Regex;
use std::sync::LazyLock;

pub const IS_MAC: bool = cfg!(target_os = "macos");
pub const IS_LINUX: bool = cfg!(target_os = "linux");
pub const IS_WINDOWS: bool = cfg!(windows);

/// Crate version (the Python `__version__`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Shown in the macOS menu bar / Dock and used as the Linux window class.
pub const APP_NAME: &str = "epma-usb-creator";
/// The one-sentence description of the product (README, About text, `--help`, Cargo.toml and the SBOM repeat it).
pub const APP_TAGLINE: &str =
    "Create verified bootable USB drives from Windows 11, Linux and other ISOs, and Google's ChromeOS Flex";

pub const MS_DOWNLOAD_PAGE: &str = "https://www.microsoft.com/en-us/software-download/windows11";
pub const PROJECT_URL: &str = "https://github.com/1985epma/epma-windows-usb-creator";

pub const CHROMEOS_FLEX_URL: &str = "https://dl.google.com/chromeos-flex/images/latest.bin.zip";
/// The official address redirects to a versioned file on the same host; any other host is refused.
pub const CHROMEOS_FLEX_HOSTS: &[&str] = &["dl.google.com"];
/// The ZIP is about 1.4 GB and the image inside it about 9.5 GB; warn below this much free space.
pub const CHROMEOS_FLEX_FREE_BYTES: u64 = 12_000_000_000;
pub const CHROMEOS_FLEX_GUIDE_URL: &str = "https://support.google.com/chromeosflex/answer/11541904";
pub const CHROMEOS_FLEX_REQUIREMENTS_URL: &str = "https://support.google.com/chromeosflex/answer/11552529";
/// Google asks for "16 GB or larger"; drives sold as 16 GB hold about 15.5e9 bytes.
pub const CHROMEOS_MIN_USB_BYTES: u64 = 15_000_000_000;
/// An image larger than this is not a plausible ChromeOS image.
pub const DISK_IMAGE_MAX_BYTES: u64 = 64 * 1024 * 1024 * 1024;
/// 4 GB - 1 byte.
pub const FAT32_MAX_FILE_SIZE: u64 = 4_294_967_295;
pub const CHUNK_SIZE: usize = 1024 * 1024;
/// A file smaller than this cannot be a disk image or an ISO.
pub const MIN_IMAGE_BYTES: u64 = 1024 * 1024;
pub const VOL_NAME: &str = "WIN11USB";

// Mode / Hardening / SeedTarget / IsoKind / Card are enums in `types.rs` (their string forms are the Python constants).

pub const LOG_MAX_LINES: usize = 5000;
pub const LOG_FLUSH_MS: u64 = 100;
/// The drive list is not re-read more often than this when the window regains focus.
pub const AUTO_REFRESH_MIN_SECONDS: f64 = 3.0;
pub const PROGRESS_UI_INTERVAL: f64 = 0.2;
pub const SHA_UI_INTERVAL: f64 = 0.1;
/// Seconds between the progress updates of the read-back verification.
pub const VERIFY_PROGRESS_INTERVAL: f64 = 0.5;
/// dd's frequent byte-count lines reach the log at most this often (seconds).
pub const DD_LOG_INTERVAL: f64 = 5.0;
/// Wrap width (pixels) of the explanatory texts in the window.
pub const PANEL_WRAP: u32 = 720;
/// The last two bytes of the first sector of an image that can boot from USB.
pub const MBR_SIGNATURE: [u8; 2] = [0x55, 0xaa];
pub const MBR_SIGNATURE_OFFSET: usize = 510;
/// Bytes compared per step when reading a raw write back.
pub const VERIFY_CHUNK: u64 = 16 * 1024 * 1024;
/// BSD dd and GNU dd spell the unit differently.
pub const RAW_WRITE_BLOCK_MAC: &str = "4m";
pub const RAW_WRITE_BLOCK_LINUX: &str = "4M";

pub const LINUX_REQUIRED_TOOLS: &[&str] = &["parted", "mkfs.vfat", "wipefs", "partprobe", "rsync", "wimlib-imagex"];

/// Package that provides each tool, per package manager: `(manager, [(tool, package)])`.
pub const LINUX_PKG_MAP: &[(&str, &[(&str, &str)])] = &[
    (
        "apt-get",
        &[
            ("parted", "parted"),
            ("mkfs.vfat", "dosfstools"),
            ("wipefs", "util-linux"),
            ("partprobe", "parted"),
            ("rsync", "rsync"),
            ("wimlib-imagex", "wimtools"),
        ],
    ),
    (
        "dnf",
        &[
            ("parted", "parted"),
            ("mkfs.vfat", "dosfstools"),
            ("wipefs", "util-linux"),
            ("partprobe", "parted"),
            ("rsync", "rsync"),
            ("wimlib-imagex", "wimlib-utils"),
        ],
    ),
    (
        "yum",
        &[
            ("parted", "parted"),
            ("mkfs.vfat", "dosfstools"),
            ("wipefs", "util-linux"),
            ("partprobe", "parted"),
            ("rsync", "rsync"),
            ("wimlib-imagex", "wimlib-utils"),
        ],
    ),
    (
        "pacman",
        &[
            ("parted", "parted"),
            ("mkfs.vfat", "dosfstools"),
            ("wipefs", "util-linux"),
            ("partprobe", "parted"),
            ("rsync", "rsync"),
            ("wimlib-imagex", "wimlib"),
        ],
    ),
    (
        "zypper",
        &[
            ("parted", "parted"),
            ("mkfs.vfat", "dosfstools"),
            ("wipefs", "util-linux"),
            ("partprobe", "parted"),
            ("rsync", "rsync"),
            ("wimlib-imagex", "wimlib"),
        ],
    ),
    (
        "apk",
        &[
            ("parted", "parted"),
            ("mkfs.vfat", "dosfstools"),
            ("wipefs", "util-linux-misc"),
            ("partprobe", "parted"),
            ("rsync", "rsync"),
            ("wimlib-imagex", "wimlib"),
        ],
    ),
];
/// `{pkgs}` is replaced by the space-separated package list.
pub const LINUX_INSTALL_CMD_TEMPLATE: &[(&str, &str)] = &[
    ("apt-get", "apt-get update && apt-get install -y {pkgs}"),
    ("dnf", "dnf install -y {pkgs}"),
    ("yum", "yum install -y {pkgs}"),
    // -Syu (not -Sy): a partial upgrade is explicitly unsupported on Arch.
    ("pacman", "pacman -Syu --noconfirm {pkgs}"),
    ("zypper", "zypper --non-interactive install {pkgs}"),
    ("apk", "apk add {pkgs}"),
];

// ---- Security configuration (overridable via environment variables) ----
pub const ALLOWED_URL_SCHEMES: &[&str] = &["https"];
pub const DEFAULT_TRUSTED_ISO_HOSTS: &[&str] = &[
    "microsoft.com",
    "www.microsoft.com",
    "software-download.microsoft.com",
    "software.download.prss.microsoft.com",
    "download.microsoft.com",
];
pub const ENV_TRUSTED_HOSTS: &str = "WIN11USB_TRUSTED_ISO_HOSTS";
pub const ENV_AUDIT_LOG: &str = "WIN11USB_AUDIT_LOG";
pub const ENV_DISABLE_AUDIT_LOG: &str = "WIN11USB_DISABLE_AUDIT_LOG";
pub const ENV_ALLOW_ANY_HOST: &str = "WIN11USB_ALLOW_ANY_DOWNLOAD_HOST";
pub const ENV_EXPECTED_SHA256: &str = "WIN11USB_EXPECTED_SHA256";

/// Per network read; prevents an indefinite hang.
pub const DOWNLOAD_TIMEOUT_SECONDS: u64 = 60;
/// Transient network errors are retried (resuming where possible).
pub const DOWNLOAD_MAX_ATTEMPTS: u32 = 3;
/// Wait before retry 2 and 3.
pub const DOWNLOAD_BACKOFF_SECONDS: &[u64] = &[2, 5];
/// Seconds allowed for quick query commands (diskutil list, lsblk, ...).
pub const QUERY_TIMEOUT: u64 = 30;
/// Seconds allowed for macOS unmount, mount, eject and detach commands.
pub const DISKUTIL_TIMEOUT: u64 = 120;
/// Seconds for `ioreg`: it only adds the USB serial number, so it must not stall the list.
pub const IOREG_TIMEOUT: u64 = 10;
/// How often the sudo timestamp is refreshed while an operation runs.
pub const SUDO_KEEPALIVE_SECONDS: u64 = 60;
pub const SUDO_TIMEOUT: u64 = QUERY_TIMEOUT;
/// The keep-alive never outlives this, whatever happens.
pub const SUDO_KEEPALIVE_MAX_SECONDS: u64 = 6 * 3600;
pub const AUDIT_LOG_MAX_BYTES: u64 = 1_000_000;
pub const AUDIT_LOG_BACKUPS: u32 = 5;
/// Printed by the root write scripts when they stop on request.
pub const RAW_CANCELED_MARKER: &str = "WRITE_CANCELED";
/// `oflag=direct` on Linux only when the image size is a multiple of this.
pub const DIRECT_IO_ALIGNMENT: u64 = 4096;
/// Owner-only read/write for files we create (unix mode bits).
pub const PRIVATE_FILE_MODE: u32 = 0o600;
/// The Linux sleep inhibitor is bounded, so it can never leak for good.
pub const SLEEP_INHIBIT_SECONDS: u64 = 12 * 3600;
/// How long to wait (seconds) to see that the inhibitor really started.
pub const SLEEP_INHIBIT_CHECK_SECONDS: f64 = 0.3;

/// Device identifiers we are willing to pass to privileged commands. Anything outside this shape is rejected
/// rather than escaped.
pub static MAC_DEVICE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^disk[0-9]+$").unwrap());
pub static LINUX_DEVICE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_+-]{1,32}$").unwrap());
pub static WINDOWS_DEVICE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^PhysicalDrive[0-9]{1,4}$").unwrap());

/// Mount points that must never live on a disk we are about to erase.
pub const CRITICAL_MOUNTPOINTS: &[&str] = &["/", "/boot", "/boot/efi", "/home", "/usr", "/var", "/etc"];

pub const ENV_LANG: &str = "EPMA_LANG";
pub const LANG_EN: &str = "en";
pub const LANG_PT: &str = "pt";
