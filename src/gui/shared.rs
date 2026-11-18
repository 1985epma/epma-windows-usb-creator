//! What the window's threads share: the messages the workers post to the UI thread (the Python `self.after(0, ...)` and
//! `self._post(...)` calls), the log queue (`log_threadsafe`), the dependencies handle and a few small helpers.

use super::backend::Backend;
use super::dialogs::{DialogRequest, Dialogs};
use super::widgets::Retry;
use crate::constants::LOG_MAX_LINES;
use crate::types::{CancelToken, Disk, Hardening, Mode, Privilege, SeedTarget};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

/// A failure to show without leaking internals: the Python exception's class name and text (`type(exc).__name__`,
/// `str(exc)`).
#[derive(Clone, Debug, PartialEq)]
pub struct ExcInfo {
    pub type_name: String,
    pub text: String,
}

impl ExcInfo {
    pub fn of(error: &crate::types::Error) -> ExcInfo {
        ExcInfo { type_name: error_type_name(error).to_string(), text: error.to_string() }
    }
}

/// The Python exception class an `Error` stands for.
pub fn error_type_name(error: &crate::types::Error) -> &'static str {
    use crate::types::Error;
    match error {
        Error::Runtime(_) => "RuntimeError",
        Error::Value(_) => "ValueError",
        Error::Canceled { .. } => "OperationCanceled",
        Error::Io(_) => "OSError",
    }
}

/// The dialog flows that run on their own thread; at most one of each kind is open at a time (a Tk dialog is modal,
/// so a second click could never start a second one).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowKind {
    Download,
    FlexDownload,
    PickImage,
    CancelWrite,
    CloseWindow,
}

/// Everything a worker thread can ask the UI thread to do. The window applies them in order, once per frame.
pub enum UiMsg {
    /// A dialog to show (a notification, a question, a file dialog...).
    Dialog(DialogRequest),

    // ---- the drive list ----
    ListingFinished { job: u64, result: std::result::Result<Vec<Disk>, String>, quiet: bool },

    // ---- Windows ISO download ----
    DownloadApproved { url: String, dest: PathBuf, expected_sha: String },
    DownloadProgress { done: u64, total: u64, speed: f64 },
    DownloadDone { path: PathBuf, sha256: String, verified: bool },
    DownloadError(String),

    // ---- ChromeOS Flex ----
    FlexApproved { dest: PathBuf },
    FlexProgress { done: u64, total: u64, speed: f64, stage: String },
    FlexDownloaded { path: PathBuf, sha256: String },
    FlexExtracted { image: PathBuf, zip: PathBuf, delete_zip: bool },
    FlexError(String),
    /// The file dialog of "Select existing ISO file..." returned a file.
    ImagePicked(PathBuf),

    // ---- SHA-256 of the selected image ----
    ShaProgress { job: u64, done: u64, total: u64 },
    ShaDone { job: u64, path: PathBuf, digest: String, expected: Option<String> },
    ShaError { job: u64, reason: String },

    // ---- writing a drive ----
    /// The confirmations were declined or refused: nothing was started.
    CreateRefused,
    /// Everything was confirmed: the write begins (the UI shows the bar, Cancel...).
    CreateGo,
    CreateProgress { done: u64, total: u64, text: String },
    CreateFinish { ok: bool, canceled: bool },
    CreateSuccess { ejected: bool, mode: Mode, hardening: Hardening, target: Option<SeedTarget> },
    CreationEnded,
    /// The user (or closing the window) asked the write to stop: update the window (`audit` goes to the audit log).
    CancelRequested { audit: String },
    /// The user confirmed quitting: close the window now.
    CloseConfirmed,
    /// A dialog flow ended (whatever the user answered): a new one of that kind may start.
    FlowEnded(FlowKind),

    // ---- results ----
    Log(String),
    Notify { info: bool, title: String, body: String },
    ShowError { title: String, message: String },
    ReportError { title: String, message: Option<String>, exc: Option<ExcInfo>, modal: bool, retry: Option<Retry> },
    InstallEnded,
}

/// Where worker threads run: on their own threads, or (tests) on the calling thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spawner {
    Threads,
    Inline,
}

impl Spawner {
    pub fn spawn(self, work: impl FnOnce() + Send + 'static) {
        match self {
            Spawner::Inline => work(),
            Spawner::Threads => {
                // A detached, daemon-like thread: the process does not wait for it when the window closes.
                let slot = Arc::new(Mutex::new(Some(work)));
                let for_thread = slot.clone();
                let spawned = std::thread::Builder::new().name("epma-worker".into()).spawn(move || {
                    let job = for_thread.lock().unwrap_or_else(|e| e.into_inner()).take();
                    if let Some(job) = job {
                        job();
                    }
                });
                if spawned.is_err() {
                    // Could not create a thread: do the work here rather than silently dropping it.
                    let job = slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                    if let Some(job) = job {
                        job();
                    }
                }
            }
        }
    }
}

/// `log_threadsafe`: lines queued from any thread, drained by the window in one insert per frame.
#[derive(Clone)]
pub struct LogSink {
    pending: Arc<Mutex<Vec<String>>>,
    notify: Arc<dyn Fn() + Send + Sync>,
}

impl LogSink {
    pub fn new(notify: Arc<dyn Fn() + Send + Sync>) -> Self {
        LogSink { pending: Arc::default(), notify }
    }
    /// Queue a log line from ANY thread; it appears within `LOG_FLUSH_MS`.
    pub fn push(&self, msg: &str) {
        {
            let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            pending.push(msg.to_string());
            if pending.len() > 4 * LOG_MAX_LINES {
                // nobody can read more than the box keeps
                pending.drain(..2 * LOG_MAX_LINES);
            }
        }
        (self.notify)();
    }
    /// Take everything queued so far.
    pub fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.pending.lock().unwrap_or_else(|e| e.into_inner()))
    }
    pub fn pending_len(&self) -> usize {
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// Cheap-to-clone handle given to every worker thread.
#[derive(Clone)]
pub struct Shared {
    pub backend: Arc<dyn Backend>,
    pub dialogs: Arc<dyn Dialogs>,
    pub priv_: Arc<dyn Privilege>,
    pub tx: Sender<UiMsg>,
    pub notify: Arc<dyn Fn() + Send + Sync>,
    /// Seconds (monotonic); tests drive it.
    pub clock: Arc<dyn Fn() -> f64 + Send + Sync>,
    pub log: LogSink,
    /// The window is being closed: no more dialogs, no more listings.
    pub closing: Arc<AtomicBool>,
    /// A write worker exists and has not ended (`self._create_thread.is_alive()`).
    pub write_alive: Arc<AtomicBool>,
    pub spawner: Spawner,
    /// Cancels a Windows ISO download (`cancel_event`).
    pub cancel_download: CancelToken,
    /// Cancels the write of the drive (`create_cancel_event`).
    pub cancel_create: CancelToken,
    /// Cancels a ChromeOS Flex download or extraction (`flex_cancel_event`).
    pub cancel_flex: CancelToken,
}

impl Shared {
    /// `self._post(func, *args)` / `self.after(0, ...)`: run on the UI thread; silently dropped once the window is
    /// gone.
    pub fn post(&self, msg: UiMsg) {
        let _ = self.tx.send(msg);
        (self.notify)();
    }
    pub fn is_closing(&self) -> bool {
        self.closing.load(Ordering::SeqCst)
    }
    pub fn now(&self) -> f64 {
        (self.clock)()
    }
}

/// Run `f`, turning a panic into an `Err` with its message (a panicking worker must still report back).
pub fn guarded<T>(f: impl FnOnce() -> T) -> std::result::Result<T, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(|payload| {
        if let Some(s) = payload.downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            "panic".to_string()
        }
    })
}

/// Python's `str(bool)`, for audit lines that print a flag.
pub fn py_bool(value: bool) -> &'static str {
    if value {
        "True"
    } else {
        "False"
    }
}
