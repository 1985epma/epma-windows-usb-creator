//! Test doubles for the window's logic tests: a fake `Backend`, scripted `Dialogs`, a fake `Privilege` and a harness
//! that builds an `AppState` around them (the Python `GuiTestCase` with its fake message box and patched engine).

use super::backend::{Backend, DownloadRequest, Platform};
use super::dialogs::{Dialogs, FileFilter};
use super::model::{AppState, Deps};
use super::shared::Spawner;
use crate::audit::AuditLevel;
use crate::diskrisk::RiskLevel;
use crate::types::{
    BuildOptions, CancelToken, Ctx, Disk, Error, Hardening, Identity, IsoKind, Log, Mode, Privilege, Progress2, Result,
    SeedTarget,
};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::ThreadId;
use std::time::Duration;

pub const GB: u64 = 1000 * 1000 * 1000;

/// `USB_DISK` of the Python tests.
pub fn usb_disk() -> Disk {
    Disk { id: "disk9".into(), size: 32 * GB, label: "/dev/disk9 - Test".into(), ..Default::default() }
}

/// A thread-safe one-shot gate a fake engine waits on (`threading.Event`).
#[derive(Default)]
pub struct Gate {
    open: Mutex<bool>,
    cv: Condvar,
}

impl Gate {
    pub fn new() -> Arc<Gate> {
        Arc::new(Gate::default())
    }
    pub fn set(&self) {
        *self.open.lock().unwrap() = true;
        self.cv.notify_all();
    }
    pub fn is_set(&self) -> bool {
        *self.open.lock().unwrap()
    }
    pub fn wait(&self, secs: f64) -> bool {
        let guard = self.open.lock().unwrap();
        let (guard, _) = self.cv.wait_timeout_while(guard, Duration::from_secs_f64(secs), |o| !*o).unwrap();
        *guard
    }
}

/// An ordered record of what happened across the fakes (`self.events` of the Python tests).
pub type Events = Arc<Mutex<Vec<String>>>;

type BuildFn = Arc<dyn Fn(&BuildCall, &Ctx) -> Result<bool> + Send + Sync>;
type SeedFn = Arc<dyn Fn(&SeedCall, &Ctx) -> Result<bool> + Send + Sync>;
type ExtractFn = Arc<dyn Fn(&Path, Option<Progress2>, Option<&CancelToken>) -> Result<PathBuf> + Send + Sync>;
type ListFn = Arc<dyn Fn() -> Result<Vec<Disk>> + Send + Sync>;
type UrlCheck = std::result::Result<(String, String, bool), String>;
/// `(title, message, expected, reasons)` of a typed-confirmation dialog.
pub type TypedCall = (String, String, String, Vec<String>);

#[derive(Clone, Debug)]
pub struct BuildCall {
    pub iso: PathBuf,
    pub dev: String,
    pub opts: BuildOptions,
}

#[derive(Clone, Debug)]
pub struct SeedCall {
    pub target: SeedTarget,
    pub dev: String,
    pub expected_size: Option<u64>,
    pub eject: bool,
    pub profile: Hardening,
}

/// A stand-in for the rest of the program.
pub struct FakeBackend {
    pub events: Events,
    pub platform: Mutex<Platform>,
    pub listed: Mutex<Vec<Disk>>,
    pub list_threads: Mutex<Vec<ThreadId>>,
    pub list_fn: Mutex<Option<ListFn>>,
    pub missing: Mutex<Vec<String>>,
    pub missing_modes: Mutex<Vec<Mode>>,
    pub iso_kind: Mutex<IsoKind>,
    pub risk: Mutex<(RiskLevel, Vec<String>)>,
    pub needs_admin: AtomicBool,
    pub admin_modes: Mutex<Vec<Mode>>,
    pub build_fn: Mutex<Option<BuildFn>>,
    pub build_calls: Mutex<Vec<BuildCall>>,
    pub seed_fn: Mutex<Option<SeedFn>>,
    pub seed_calls: Mutex<Vec<SeedCall>>,
    pub seed_size_error: Mutex<Option<String>>,
    pub seed_size_checks: Mutex<Vec<Option<u64>>>,
    pub downloads: Mutex<Vec<DownloadRequest>>,
    pub extract_fn: Mutex<Option<ExtractFn>>,
    pub extract_calls: AtomicUsize,
    pub sha_result: Mutex<Option<Result<String>>>,
    pub audits: Mutex<Vec<(String, AuditLevel)>>,
    pub urls: Mutex<Vec<String>>,
    pub has_brew: AtomicBool,
    pub pkg_manager: Mutex<Option<String>>,
    pub free_bytes: Mutex<Option<u64>>,
    pub hardening_lines: Mutex<Vec<String>>,
    pub hardening_describe_calls: AtomicUsize,
    pub validate_url: Mutex<Option<UrlCheck>>,
    pub run_cmd_calls: Mutex<Vec<Vec<String>>>,
    pub audit_dir: Mutex<PathBuf>,
    /// The next `get_missing_dependencies` call panics (a failure inside a flow).
    pub panic_next_missing: AtomicBool,
}

impl FakeBackend {
    pub fn new(events: Events) -> Arc<FakeBackend> {
        Arc::new(FakeBackend {
            events,
            platform: Mutex::new(Platform::Mac),
            listed: Mutex::new(Vec::new()),
            list_threads: Mutex::new(Vec::new()),
            list_fn: Mutex::new(None),
            missing: Mutex::new(Vec::new()),
            missing_modes: Mutex::new(Vec::new()),
            iso_kind: Mutex::new(IsoKind::Unknown),
            risk: Mutex::new((RiskLevel::Normal, Vec::new())),
            needs_admin: AtomicBool::new(false),
            admin_modes: Mutex::new(Vec::new()),
            build_fn: Mutex::new(None),
            build_calls: Mutex::new(Vec::new()),
            seed_fn: Mutex::new(None),
            seed_calls: Mutex::new(Vec::new()),
            seed_size_error: Mutex::new(None),
            seed_size_checks: Mutex::new(Vec::new()),
            downloads: Mutex::new(Vec::new()),
            extract_fn: Mutex::new(None),
            extract_calls: AtomicUsize::new(0),
            sha_result: Mutex::new(None),
            audits: Mutex::new(Vec::new()),
            urls: Mutex::new(Vec::new()),
            has_brew: AtomicBool::new(true),
            pkg_manager: Mutex::new(None),
            free_bytes: Mutex::new(None),
            hardening_lines: Mutex::new(vec!["Turns thing A on".into()]),
            hardening_describe_calls: AtomicUsize::new(0),
            validate_url: Mutex::new(None),
            run_cmd_calls: Mutex::new(Vec::new()),
            audit_dir: Mutex::new(std::env::temp_dir().join("epma-gui-test-audit")),
            panic_next_missing: AtomicBool::new(false),
        })
    }
    pub fn set_listed(&self, disks: Vec<Disk>) {
        *self.listed.lock().unwrap() = disks;
    }
    pub fn set_missing(&self, tools: &[&str]) {
        *self.missing.lock().unwrap() = tools.iter().map(|t| t.to_string()).collect();
    }
    pub fn set_build(&self, f: impl Fn(&BuildCall, &Ctx) -> Result<bool> + Send + Sync + 'static) {
        *self.build_fn.lock().unwrap() = Some(Arc::new(f));
    }
    pub fn set_seed(&self, f: impl Fn(&SeedCall, &Ctx) -> Result<bool> + Send + Sync + 'static) {
        *self.seed_fn.lock().unwrap() = Some(Arc::new(f));
    }
    pub fn set_list(&self, f: impl Fn() -> Result<Vec<Disk>> + Send + Sync + 'static) {
        *self.list_fn.lock().unwrap() = Some(Arc::new(f));
    }
    pub fn set_extract(
        &self,
        f: impl Fn(&Path, Option<Progress2>, Option<&CancelToken>) -> Result<PathBuf> + Send + Sync + 'static,
    ) {
        *self.extract_fn.lock().unwrap() = Some(Arc::new(f));
    }
    pub fn event(&self, name: &str) {
        self.events.lock().unwrap().push(name.to_string());
    }
    pub fn last_download(&self) -> Option<DownloadRequest> {
        self.downloads.lock().unwrap().pop()
    }
}

impl Backend for FakeBackend {
    fn platform(&self) -> Platform {
        *self.platform.lock().unwrap()
    }
    fn get_external_disks(&self) -> Result<Vec<Disk>> {
        self.list_threads.lock().unwrap().push(std::thread::current().id());
        let f = self.list_fn.lock().unwrap().clone();
        if let Some(f) = f {
            return f();
        }
        Ok(self.listed.lock().unwrap().clone())
    }
    fn get_missing_dependencies(&self, mode: Mode) -> Vec<String> {
        if self.panic_next_missing.swap(false, Ordering::SeqCst) {
            panic!("boom");
        }
        self.missing_modes.lock().unwrap().push(mode);
        self.missing.lock().unwrap().clone()
    }
    fn missing_dependencies_hint(&self, _missing: &[String]) -> String {
        "On Windows there is nothing to install.".to_string()
    }
    fn needs_admin(&self, mode: Mode) -> bool {
        self.admin_modes.lock().unwrap().push(mode);
        self.needs_admin.load(Ordering::SeqCst)
    }
    fn pin_target_identity(&self, dev: &str, _identity: Option<Identity>) {
        self.event(&format!("pin:{dev}"));
    }
    fn image_exceeds_drive(&self, image_size: u64, drive_size: u64) -> bool {
        image_size > 0 && drive_size > 0 && image_size > drive_size
    }
    fn chromeos_drive_too_small(&self, mode: Mode, drive_size: u64) -> bool {
        mode == Mode::ChromeOs && drive_size > 0 && drive_size < crate::constants::CHROMEOS_MIN_USB_BYTES
    }
    fn check_seed_target_size(&self, size: Option<u64>) -> Result<()> {
        self.seed_size_checks.lock().unwrap().push(size);
        match self.seed_size_error.lock().unwrap().clone() {
            Some(m) => Err(Error::value(m)),
            None => Ok(()),
        }
    }
    fn assess_disk_risk(&self, _disk: &Disk) -> (RiskLevel, Vec<String>) {
        self.risk.lock().unwrap().clone()
    }
    fn describe_disk_for_confirmation(&self, disk: &Disk) -> String {
        format!("Disk {} ({} bytes)", disk.id, disk.size)
    }
    fn build_usb(&self, iso: &Path, dev: &str, ctx: &Ctx, _priv_: &dyn Privilege, opts: &BuildOptions) -> Result<bool> {
        let call = BuildCall { iso: iso.to_path_buf(), dev: dev.to_string(), opts: *opts };
        self.build_calls.lock().unwrap().push(call.clone());
        self.event("engine");
        let f = self.build_fn.lock().unwrap().clone();
        match f {
            Some(f) => f(&call, ctx),
            None => Ok(true),
        }
    }
    fn build_seed_usb(
        &self,
        target: SeedTarget,
        dev: &str,
        ctx: &Ctx,
        _priv_: &dyn Privilege,
        expected_size: Option<u64>,
        eject: bool,
        profile: Hardening,
    ) -> Result<bool> {
        let call = SeedCall { target, dev: dev.to_string(), expected_size, eject, profile };
        self.seed_calls.lock().unwrap().push(call.clone());
        self.event("seed");
        let f = self.seed_fn.lock().unwrap().clone();
        match f {
            Some(f) => f(&call, ctx),
            None => Ok(true),
        }
    }
    fn detect_iso_kind(&self, _path: &Path) -> IsoKind {
        *self.iso_kind.lock().unwrap()
    }
    fn extract_disk_image(
        &self,
        zip: &Path,
        _dest_dir: &Path,
        progress: Option<Progress2>,
        cancel: Option<&CancelToken>,
    ) -> Result<PathBuf> {
        self.extract_calls.fetch_add(1, Ordering::SeqCst);
        let f = self.extract_fn.lock().unwrap().clone();
        match f {
            Some(f) => f(zip, progress, cancel),
            None => Ok(zip.with_extension("")),
        }
    }
    fn sha256_file(&self, _path: &Path, _cancel: Option<&CancelToken>, progress: Option<Progress2>) -> Result<String> {
        if let Some(p) = progress {
            p(5, 10);
            p(10, 10);
        }
        match self.sha_result.lock().unwrap().take() {
            Some(r) => r,
            None => Ok("ab".repeat(32)),
        }
    }
    fn validate_download_url(&self, raw: &str) -> Result<(String, String, bool)> {
        if let Some(r) = self.validate_url.lock().unwrap().clone() {
            return r.map_err(Error::Value);
        }
        if raw.starts_with("https://") {
            let host = raw.trim_start_matches("https://").split('/').next().unwrap_or("").to_string();
            let trusted = host.ends_with("microsoft.com");
            Ok((raw.to_string(), host, !trusted))
        } else {
            Err(Error::value("Only HTTPS links are accepted."))
        }
    }
    fn is_sha256_hex(&self, text: &str) -> bool {
        text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit())
    }
    fn parse_expected_sha256(&self, text: &str, _filename: Option<&str>) -> Result<Option<String>> {
        let t = text.trim().to_lowercase();
        if t.is_empty() {
            return Ok(None);
        }
        if self.is_sha256_hex(&t) {
            Ok(Some(t))
        } else {
            Err(Error::value("That is not a SHA-256 checksum."))
        }
    }
    fn start_download(&self, request: DownloadRequest) {
        self.downloads.lock().unwrap().push(request);
    }
    fn detect_pkg_manager(&self) -> Option<String> {
        self.pkg_manager.lock().unwrap().clone()
    }
    fn build_install_command(&self, mgr: Option<&str>, missing: &[String]) -> Result<String> {
        Ok(format!("{} install {}", mgr.unwrap_or("?"), missing.join(" ")))
    }
    fn run_cmd(&self, args: &[String], _log: Log) -> Result<i32> {
        self.run_cmd_calls.lock().unwrap().push(args.to_vec());
        Ok(0)
    }
    fn which(&self, _name: &str) -> bool {
        self.has_brew.load(Ordering::SeqCst)
    }
    fn describe_hardening_applied(&self) -> Vec<String> {
        self.hardening_describe_calls.fetch_add(1, Ordering::SeqCst);
        self.hardening_lines.lock().unwrap().clone()
    }
    fn help_sections(&self) -> Vec<(String, String)> {
        vec![
            ("Overview".into(), "## Heading\n• a bullet\nplain".into()),
            ("About".into(), "EPMA USB CREATOR about text".into()),
        ]
    }
    fn audit(&self, msg: &str, level: AuditLevel) {
        self.audits.lock().unwrap().push((msg.to_string(), level));
    }
    fn audit_log_path(&self) -> PathBuf {
        self.audit_dir.lock().unwrap().join("audit.log")
    }
    fn disk_free(&self, _dir: &Path) -> Option<u64> {
        *self.free_bytes.lock().unwrap()
    }
    fn open_url(&self, url: &str) {
        self.urls.lock().unwrap().push(url.to_string());
    }
}

/// One dialog the fake recorded: `(kind, title, message)`.
pub type DialogCall = (String, String, String);

/// A scripted message box: records every dialog and answers the questions with `yes`.
pub struct FakeDialogs {
    pub events: Events,
    pub yes: AtomicBool,
    pub calls: Mutex<Vec<DialogCall>>,
    /// Answers consumed first by the yes / no questions (then `yes`).
    pub answers: Mutex<VecDeque<bool>>,
    pub typed_ok: AtomicBool,
    pub typed_calls: Mutex<Vec<TypedCall>>,
    pub save_path: Mutex<Option<PathBuf>>,
    pub open_path: Mutex<Option<PathBuf>>,
    pub password: Mutex<Option<String>>,
}

impl FakeDialogs {
    pub fn new(events: Events) -> Arc<FakeDialogs> {
        Arc::new(FakeDialogs {
            events,
            yes: AtomicBool::new(false),
            calls: Mutex::new(Vec::new()),
            answers: Mutex::new(VecDeque::new()),
            typed_ok: AtomicBool::new(false),
            typed_calls: Mutex::new(Vec::new()),
            save_path: Mutex::new(None),
            open_path: Mutex::new(None),
            password: Mutex::new(None),
        })
    }
    pub fn set_yes(&self, yes: bool) {
        self.yes.store(yes, Ordering::SeqCst);
    }
    fn record(&self, kind: &str, title: &str, message: &str) {
        self.calls.lock().unwrap().push((kind.to_string(), title.to_string(), message.to_string()));
    }
    /// The titles of the dialogs of one kind (`box.titles(kind)`); `None` for all.
    pub fn titles(&self, kind: Option<&str>) -> Vec<String> {
        self.calls.lock().unwrap().iter().filter(|c| kind.is_none_or(|k| c.0 == k)).map(|c| c.1.clone()).collect()
    }
    pub fn count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
    pub fn clear(&self) {
        self.calls.lock().unwrap().clear();
    }
    pub fn last(&self) -> Option<DialogCall> {
        self.calls.lock().unwrap().last().cloned()
    }
}

impl Dialogs for FakeDialogs {
    fn show_info(&self, title: &str, message: &str) {
        self.record("info", title, message);
    }
    fn show_error(&self, title: &str, message: &str) {
        self.record("error", title, message);
    }
    fn ask_yes_no(&self, title: &str, message: &str, _warning: bool) -> bool {
        self.record("question", title, message);
        let answer = match self.answers.lock().unwrap().pop_front() {
            Some(a) => a,
            None => self.yes.load(Ordering::SeqCst),
        };
        if title == "Final confirmation" {
            self.events.lock().unwrap().push("confirm".to_string());
        }
        answer
    }
    fn ask_typed_confirmation(&self, title: &str, message: &str, expected: &str, reasons: &[String]) -> bool {
        self.record("typed", title, message);
        self.typed_calls.lock().unwrap().push((
            title.to_string(),
            message.to_string(),
            expected.to_string(),
            reasons.to_vec(),
        ));
        self.events.lock().unwrap().push("confirm".to_string());
        self.typed_ok.load(Ordering::SeqCst)
    }
    fn ask_password(&self, title: &str, prompt: &str) -> Option<String> {
        self.record("password", title, prompt);
        self.password.lock().unwrap().clone()
    }
    fn pick_open_file(&self, title: &str, _filters: &[FileFilter]) -> Option<PathBuf> {
        self.record("open", title, "");
        self.open_path.lock().unwrap().clone()
    }
    fn pick_save_file(&self, title: &str, initial: &str, _ext: &str, _filters: &[FileFilter]) -> Option<PathBuf> {
        self.record("save", title, initial);
        self.save_path.lock().unwrap().clone()
    }
}

/// A fake privilege helper (`win.priv.authenticate = Mock(...)`).
pub struct FakePriv {
    pub events: Events,
    pub authenticate_result: AtomicBool,
    pub authenticate_calls: AtomicUsize,
    pub cleared: AtomicUsize,
    pub scripts: Mutex<Vec<String>>,
}

impl FakePriv {
    pub fn new(events: Events) -> Arc<FakePriv> {
        Arc::new(FakePriv {
            events,
            authenticate_result: AtomicBool::new(true),
            authenticate_calls: AtomicUsize::new(0),
            cleared: AtomicUsize::new(0),
            scripts: Mutex::new(Vec::new()),
        })
    }
}

impl Privilege for FakePriv {
    fn run_script(&self, script: &str, _log: Log, _args: &[String]) -> Result<()> {
        self.scripts.lock().unwrap().push(script.to_string());
        Ok(())
    }
    fn authenticate(&self, _reason: &str) -> Result<bool> {
        self.authenticate_calls.fetch_add(1, Ordering::SeqCst);
        self.events.lock().unwrap().push("auth".to_string());
        Ok(self.authenticate_result.load(Ordering::SeqCst))
    }
    fn clear_cached_password(&self) {
        self.cleared.fetch_add(1, Ordering::SeqCst);
    }
}

/// The window state around the fakes (the `GuiTestCase` of the Python tests).
pub struct Harness {
    pub state: AppState,
    pub be: Arc<FakeBackend>,
    pub dialogs: Arc<FakeDialogs>,
    pub priv_: Arc<FakePriv>,
    pub events: Events,
    pub clock: Arc<Mutex<f64>>,
}

impl Harness {
    /// Worker flows run on their own threads (like the real window).
    pub fn new() -> Harness {
        Harness::with(Spawner::Threads)
    }
    /// Worker flows run on the calling thread (deterministic; the fakes must not block).
    pub fn inline() -> Harness {
        Harness::with(Spawner::Inline)
    }
    fn with(spawner: Spawner) -> Harness {
        let events: Events = Arc::default();
        let be = FakeBackend::new(events.clone());
        let dialogs = FakeDialogs::new(events.clone());
        let priv_ = FakePriv::new(events.clone());
        let clock = Arc::new(Mutex::new(1000.0));
        let c = clock.clone();
        let deps = Deps {
            backend: be.clone(),
            dialogs: dialogs.clone(),
            priv_: priv_.clone(),
            notify: Arc::new(|| {}),
            clock: Arc::new(move || *c.lock().unwrap()),
            spawner,
        };
        let mut state = AppState::new(deps);
        state.last_disk_refresh = Some(*clock.lock().unwrap()); // no automatic listing while a test runs
        Harness { state, be, dialogs, priv_, events, clock }
    }
    pub fn advance(&self, secs: f64) {
        *self.clock.lock().unwrap() += secs;
    }
    pub fn now(&self) -> f64 {
        *self.clock.lock().unwrap()
    }
    /// `with_disk(iso)`: one drive listed and selected, an image chosen.
    pub fn with_disk(&mut self, iso: &str) {
        self.be.set_listed(vec![usb_disk()]);
        self.state.iso_path = iso.to_string();
        self.state.refresh_disks(false, true);
        assert!(self.state.selected_disk().is_some());
    }
    /// `pump(condition)`: run the message pump until the condition holds (10 s at most).
    pub fn pump(&mut self, condition: impl Fn(&AppState) -> bool) -> bool {
        self.state.pump_until(10.0, condition)
    }
    /// `write()`: click Create and wait for the write to end.
    pub fn write(&mut self) {
        self.state.start_create_usb();
        assert!(self.pump(|s| !s.creating), "the write did not end");
        self.state.pump();
    }
    pub fn event_list(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
    pub fn clear_events(&self) {
        self.events.lock().unwrap().clear();
    }
    pub fn log(&mut self) -> String {
        self.state.flush_log();
        self.state.log_text()
    }
}
