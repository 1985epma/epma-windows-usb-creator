#![allow(unused)] // STUB: delete this line when the module is implemented
//! HTTPS download with resume. OWNER: A7. Port of win11_usb_creator.py lines 8872-9146 (DownloadThread).

use crate::types::CancelToken;
use std::path::PathBuf;
use std::thread::JoinHandle;

pub type ProgressCb = Box<dyn Fn(u64, u64, f64) + Send + Sync>;
pub type DoneCb = Box<dyn Fn(&std::path::Path, &str, bool) + Send + Sync>;
pub type ErrorCb = Box<dyn Fn(&str) + Send + Sync>;

/// Downloads one file over HTTPS, resuming and retrying where that is safe (see the Python docstring).
/// Callbacks run on the download thread: `progress(done, total, speed)`, `done(path, sha256, verified)`, `error(message)`.
pub struct DownloadThread {
    pub url: String,
    pub dest_path: PathBuf,
    pub progress_cb: ProgressCb,
    pub done_cb: DoneCb,
    pub error_cb: ErrorCb,
    pub cancel: CancelToken,
    pub expected_sha256: Option<String>,
    pub allowed_hosts: Option<Vec<String>>,
}
impl DownloadThread {
    /// Start it on its own (daemon-like) thread.
    pub fn start(self) -> JoinHandle<()> {
        todo!()
    }
}
