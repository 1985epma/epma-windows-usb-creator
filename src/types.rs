//! Shared types of the port. OWNER: lead (frozen: other agents only read and use this file).
//!
//! * `Log` / `Progress` replace the Python `log(line)` / `progress(done, total, text)` callables.
//! * `CancelToken` is the `threading.Event` (`cancel_event`).
//! * `Error` replaces RuntimeError / ValueError / OperationCanceled / OSError.
//! * `Mode`, `Hardening`, `SeedTarget`, `IsoKind`, `Card` are the string constants of the Python code as enums;
//!   `as_str()` gives back the exact Python string (what the command line prints and accepts).
//! * `Disk` / `Volume` / `Identity` are the "disk dict" of the Python code.
//! * `Privilege` is what the backends call to run a script as root (duck-typed in Python).

use indexmap::IndexMap;
use std::fmt;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

// ---------------------------------------------------------------------------------------------------------------
// Callbacks
// ---------------------------------------------------------------------------------------------------------------

/// `log(line)`: one line of the log (no trailing newline).
pub type Log<'a> = &'a (dyn Fn(&str) + Send + Sync);
/// `progress(done, total, text)`. `total == 0` means "unknown / indeterminate".
pub type Progress<'a> = &'a (dyn Fn(u64, u64, &str) + Send + Sync);
/// `progress(done, total)` where the Python code takes two arguments (sha256_file, extract_disk_image).
pub type Progress2<'a> = &'a (dyn Fn(u64, u64) + Send + Sync);

/// A log that discards everything (tests, quiet callers).
pub fn null_log(_line: &str) {}

// ---------------------------------------------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------------------------------------------

/// A cancel flag shared between threads (`threading.Event`): clone it freely, every clone is the same flag.
#[derive(Clone, Default)]
pub struct CancelToken {
    inner: Arc<(Mutex<bool>, Condvar)>,
}

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(&self) {
        let (lock, cv) = &*self.inner;
        *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
        cv.notify_all();
    }
    pub fn clear(&self) {
        let (lock, _) = &*self.inner;
        *lock.lock().unwrap_or_else(|e| e.into_inner()) = false;
    }
    pub fn is_set(&self) -> bool {
        let (lock, _) = &*self.inner;
        *lock.lock().unwrap_or_else(|e| e.into_inner())
    }
    /// Block until the flag is set or `timeout` passes; true if it is set (`Event.wait(timeout)`).
    pub fn wait(&self, timeout: Duration) -> bool {
        let (lock, cv) = &*self.inner;
        let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        let (guard, _) = cv.wait_timeout_while(guard, timeout, |set| !*set).unwrap_or_else(|e| e.into_inner());
        *guard
    }
}

impl fmt::Debug for CancelToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CancelToken(set={})", self.is_set())
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------------------------

/// The failure kinds of the Python code. The text of `Runtime` / `Value` is the message the user reads, so it must
/// match the Python message (tests and the window match on substrings).
#[derive(Debug)]
pub enum Error {
    /// `RuntimeError`: an operation failed (a command, a verification, a safety abort...).
    Runtime(String),
    /// `ValueError`: a bad input or a precondition that fails before anything is touched.
    Value(String),
    /// `OperationCanceled`. `drive_touched`: false when nothing on the drive was changed. `written`: true when the
    /// whole image was written and the cancel came during the final verification.
    Canceled { message: String, drive_touched: bool, written: bool },
    /// An `OSError`.
    Io(std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn runtime(msg: impl Into<String>) -> Self {
        Error::Runtime(msg.into())
    }
    pub fn value(msg: impl Into<String>) -> Self {
        Error::Value(msg.into())
    }
    /// `OperationCanceled("Canceled by the user.")` with the Python defaults (drive_touched=True, written=False).
    pub fn canceled() -> Self {
        Error::Canceled { message: "Canceled by the user.".into(), drive_touched: true, written: false }
    }
    pub fn canceled_with(message: impl Into<String>, drive_touched: bool, written: bool) -> Self {
        Error::Canceled { message: message.into(), drive_touched, written }
    }
    pub fn is_canceled(&self) -> bool {
        matches!(self, Error::Canceled { .. })
    }
    /// The Python `getattr(e, "drive_touched", True)`.
    pub fn drive_touched(&self) -> bool {
        match self {
            Error::Canceled { drive_touched, .. } => *drive_touched,
            _ => true,
        }
    }
    /// The Python `getattr(e, "written", False)`.
    pub fn written(&self) -> bool {
        match self {
            Error::Canceled { written, .. } => *written,
            _ => false,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Runtime(m) | Error::Value(m) => f.write_str(m),
            Error::Canceled { message, .. } => f.write_str(message),
            Error::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Context bundle (log + progress + cancel), passed to every long operation
// ---------------------------------------------------------------------------------------------------------------

/// What nearly every long operation takes: where to log, where to report progress, and the cancel flag.
#[derive(Clone, Copy)]
pub struct Ctx<'a> {
    pub log: Log<'a>,
    pub progress: Option<Progress<'a>>,
    pub cancel: Option<&'a CancelToken>,
}

impl<'a> Ctx<'a> {
    pub fn new(log: Log<'a>, progress: Option<Progress<'a>>, cancel: Option<&'a CancelToken>) -> Self {
        Ctx { log, progress, cancel }
    }
    /// A context that logs nowhere and never cancels (tests).
    pub fn quiet() -> Ctx<'static> {
        Ctx { log: &null_log, progress: None, cancel: None }
    }
    pub fn log(&self, line: &str) {
        (self.log)(line)
    }
    /// `progress(done, total, text)` if a progress callback was given.
    pub fn report(&self, done: u64, total: u64, text: &str) {
        if let Some(p) = self.progress {
            p(done, total, text)
        }
    }
    pub fn is_canceled(&self) -> bool {
        self.cancel.map(|c| c.is_set()).unwrap_or(false)
    }
    /// The Python `check_canceled(cancel_event, drive_touched, written)`.
    pub fn check_canceled(&self, drive_touched: bool, written: bool) -> Result<()> {
        if self.is_canceled() {
            Err(Error::canceled_with("Canceled by the user.", drive_touched, written))
        } else {
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Enumerations (the Python string constants)
// ---------------------------------------------------------------------------------------------------------------

/// What kind of image is being written (MODE_*). `Seed` is the pseudo-mode of a drive that carries only the
/// hardening seed files (used by the dependency check). `Auto` is the command line's "take it from the image".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    Windows,
    Linux,
    ChromeOs,
    Seed,
    Auto,
}

impl Mode {
    /// ALL_MODES: the three real image types.
    pub const ALL: [Mode; 3] = [Mode::Windows, Mode::Linux, Mode::ChromeOs];
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Windows => "windows",
            Mode::Linux => "linux",
            Mode::ChromeOs => "chromeos",
            Mode::Seed => "seed",
            Mode::Auto => "auto",
        }
    }
    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "windows" => Some(Mode::Windows),
            "linux" => Some(Mode::Linux),
            "chromeos" => Some(Mode::ChromeOs),
            "seed" => Some(Mode::Seed),
            "auto" => Some(Mode::Auto),
            _ => None,
        }
    }
    /// `mode in ALL_MODES`.
    pub fn is_image_mode(self) -> bool {
        Mode::ALL.contains(&self)
    }
    /// `mode in RAW_MODES`: written byte for byte to the whole drive.
    pub fn is_raw(self) -> bool {
        matches!(self, Mode::Linux | Mode::ChromeOs)
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// HARDENING_* profiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Hardening {
    None,
    Baseline,
}

impl Hardening {
    /// HARDENING_PROFILES
    pub const ALL: [Hardening; 2] = [Hardening::None, Hardening::Baseline];
    pub fn as_str(self) -> &'static str {
        match self {
            Hardening::None => "none",
            Hardening::Baseline => "baseline",
        }
    }
    pub fn parse(s: &str) -> Option<Hardening> {
        match s {
            "none" => Some(Hardening::None),
            "baseline" => Some(Hardening::Baseline),
            _ => None,
        }
    }
}

impl fmt::Display for Hardening {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// SEED_* targets of the hardening seed drive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SeedTarget {
    Ubuntu,
    Fedora,
    Debian,
    Windows,
}

impl SeedTarget {
    /// SEED_TARGETS
    pub const ALL: [SeedTarget; 4] = [SeedTarget::Ubuntu, SeedTarget::Fedora, SeedTarget::Debian, SeedTarget::Windows];
    pub fn as_str(self) -> &'static str {
        match self {
            SeedTarget::Ubuntu => "ubuntu",
            SeedTarget::Fedora => "fedora",
            SeedTarget::Debian => "debian",
            SeedTarget::Windows => "windows",
        }
    }
    pub fn parse(s: &str) -> Option<SeedTarget> {
        SeedTarget::ALL.into_iter().find(|t| t.as_str() == s)
    }
}

impl fmt::Display for SeedTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What `detect_iso_kind()` finds in an image (ISO_KIND_*).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IsoKind {
    Windows,
    Linux,
    ChromeOs,
    Unknown,
}

impl IsoKind {
    pub fn as_str(self) -> &'static str {
        match self {
            IsoKind::Windows => "windows",
            IsoKind::Linux => "linux",
            IsoKind::ChromeOs => "chromeos",
            IsoKind::Unknown => "unknown",
        }
    }
    /// KIND_MODE: the mode that writes this kind (None for Unknown).
    pub fn mode(self) -> Option<Mode> {
        match self {
            IsoKind::Windows => Some(Mode::Windows),
            IsoKind::Linux => Some(Mode::Linux),
            IsoKind::ChromeOs => Some(Mode::ChromeOs),
            IsoKind::Unknown => None,
        }
    }
    /// KIND_CARD: the card a detected image selects (None for Unknown).
    pub fn card(self) -> Option<Card> {
        match self {
            IsoKind::Windows => Some(Card::Windows),
            IsoKind::Linux => Some(Card::Linux),
            IsoKind::ChromeOs => Some(Card::Chrome),
            IsoKind::Unknown => None,
        }
    }
}

impl fmt::Display for IsoKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The choices at the top of the window (CARD_*).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Card {
    Chrome,
    Windows,
    Linux,
    Other,
    Seed,
}

impl Card {
    /// CARD_ORDER
    pub const ORDER: [Card; 5] = [Card::Chrome, Card::Windows, Card::Linux, Card::Other, Card::Seed];
    pub fn as_str(self) -> &'static str {
        match self {
            Card::Chrome => "chrome",
            Card::Windows => "windows",
            Card::Linux => "linux",
            Card::Other => "other",
            Card::Seed => "seed",
        }
    }
    /// CARD_MODE
    pub fn mode(self) -> Mode {
        match self {
            Card::Chrome => Mode::ChromeOs,
            Card::Windows => Mode::Windows,
            Card::Linux | Card::Other => Mode::Linux,
            Card::Seed => Mode::Seed,
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Disks
// ---------------------------------------------------------------------------------------------------------------

/// Stable identifiers of a drive (serial, WWN, DiskUUID, model...): sorted `(key, value)` pairs, empty values dropped.
pub type Identity = Vec<(String, String)>;

/// One volume on a drive (`name`, `filesystem`, `size`, `used`, `mountpoint` of the Python volume dict).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Volume {
    pub name: Option<String>,
    pub filesystem: Option<String>,
    pub size: Option<u64>,
    /// Bytes in use; `None` when unknown.
    pub used: Option<u64>,
    /// `None` when the volume is not mounted.
    pub mountpoint: Option<String>,
}

/// The `volumes` entry of a disk dict: it may be absent, `None`, or a list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Volumes {
    /// The key is absent from the dict: the disk was not inspected at all (not penalised by the risk check).
    #[default]
    NotInspected,
    /// `volumes: None`: the inspection failed (penalised by the risk check).
    Unknown,
    List(Vec<Volume>),
}

/// A disk record (the "disk dict"): `id` is the device id (`disk4`, `sdb`, `PhysicalDrive3`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Disk {
    pub id: String,
    pub size: u64,
    /// The text shown in the drive list.
    pub label: String,
    pub model: Option<String>,
    pub volumes: Volumes,
    pub identity: Identity,
}

/// A set of files to write on a drive: `{relative posix path: bytes}`, in insertion order (the Python dict).
pub type Files = IndexMap<String, Vec<u8>>;

// ---------------------------------------------------------------------------------------------------------------
// Privilege
// ---------------------------------------------------------------------------------------------------------------

/// What the backends need to run a script as root. The window implements it with a password dialog
/// (`PrivilegeHelper`), the command line with the terminal's sudo (`CliPrivilege`); on Windows nothing is asked
/// (`WindowsPrivilege`). Implementations live in `privilege.rs`.
pub trait Privilege: Send + Sync {
    /// Run the bash `script` as root, exactly once (never retried). Values arrive only as positional parameters
    /// (`"$1"`, `"$2"`...) through `args`, never pasted into the script text. Streams the output to `log`.
    fn run_script(&self, script: &str, log: Log, args: &[String]) -> Result<()>;
    /// Whether a sudo password must be collected before running privileged commands.
    fn needs_password(&self) -> bool {
        false
    }
    /// Ask for the credentials up front, before anything touches the drive. `Ok(true)`: privileges are available;
    /// `Ok(false)`: the user canceled or refused (the window explains); `Err`: a failure to report as is.
    fn authenticate(&self, reason: &str) -> Result<bool>;
    /// Forget any held credential (end of the operation).
    fn clear_cached_password(&self) {}
}

/// Asks the user for the administrator password; implemented by the window (the worker thread blocks on it).
pub trait PasswordPrompt: Send + Sync {
    /// `None` when the user canceled.
    fn ask_password(&self, title: &str, prompt: &str) -> Option<String>;
    /// An error message box (e.g. "Wrong password").
    fn show_error(&self, title: &str, message: &str);
}

// ---------------------------------------------------------------------------------------------------------------
// Options of a write
// ---------------------------------------------------------------------------------------------------------------

/// The settings of `engine::build_usb` besides the image, the drive and the context.
#[derive(Clone, Copy, Debug)]
pub struct BuildOptions {
    /// The size the drive had when it was listed; re-checked right before erasing.
    pub expected_size: Option<u64>,
    pub mode: Mode,
    pub eject: bool,
    /// Windows mode only.
    pub hardening: Hardening,
}

impl Default for BuildOptions {
    fn default() -> Self {
        BuildOptions { expected_size: None, mode: Mode::Windows, eject: true, hardening: Hardening::None }
    }
}
