//! The window's state and logic (port of the `App` class, win11_usb_creator.py lines 10326-12034), without any
//! drawing: card and mode selection, when "Create" is enabled and the hint under it, the drive list, the image card,
//! the SHA-256 panel, downloads, the write with its progress and result banners, the log, hardening and seed choices,
//! the close protection. `view.rs` draws from this; the tests drive it with a fake `Backend`.
//!
//! Threads: everything here runs on the UI thread. Workers (listing, downloads, extraction, SHA-256, the write, the
//! dialog flows of `flows.rs`) post `UiMsg`s that `pump` applies in order.

use super::backend::{Backend, Platform};
use super::dialogs::{DialogReply, DialogRequest, Dialogs};
use super::flows::{self, CreateInputs};
use super::shared::{guarded, ExcInfo, FlowKind, LogSink, Shared, Spawner, UiMsg};
use super::texts::{self, seed_step_heading, seed_target_note};
use super::tx::{human_size, rate_tail, tr, trf};
use super::widgets::{
    card_texts, fit_window_height, image_label, Banner, BannerKind, Bar, BarMode, Disclosure, DownloadWidgets, DriveList,
    FileCard, LinkAction, Retry, ShaPanel, Tone, START_WINDOW_SIZE,
};
use crate::audit::AuditLevel;
use crate::constants::{
    AUTO_REFRESH_MIN_SECONDS, ENV_EXPECTED_SHA256, LOG_MAX_LINES, MS_DOWNLOAD_PAGE, PROJECT_URL, PROGRESS_UI_INTERVAL,
};
use crate::types::{Card, Disk, Hardening, IsoKind, Mode, Privilege, SeedTarget};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;

/// Which banner a link belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BannerId {
    Error,
    Success,
}

/// The enabled state of the controls that must not be used while something is running (`_sync_controls`).
#[derive(Clone, Copy, Debug)]
pub struct Controls {
    pub cards_enabled: bool,
    pub refresh_enabled: bool,
    pub pick_enabled: bool,
    pub hardening_enabled: bool,
    pub seed_radios_enabled: bool,
    pub install_enabled: bool,
    /// The window's single Cancel button.
    pub cancel_enabled: bool,
    /// The Create button (`update_create_button_state`).
    pub create_enabled: bool,
}

impl Default for Controls {
    fn default() -> Self {
        Controls {
            cards_enabled: true,
            refresh_enabled: true,
            pick_enabled: true,
            hardening_enabled: true,
            seed_radios_enabled: true,
            install_enabled: true,
            cancel_enabled: false,
            create_enabled: false,
        }
    }
}

/// The documentation window.
#[derive(Clone, Debug, Default)]
pub struct HelpState {
    pub open: bool,
    pub section: usize,
    pub sections: Vec<(String, String)>,
}

/// What the window is built from.
#[derive(Clone)]
pub struct Deps {
    pub backend: Arc<dyn Backend>,
    pub dialogs: Arc<dyn Dialogs>,
    pub priv_: Arc<dyn Privilege>,
    /// Wakes the UI thread (`egui::Context::request_repaint`); a no-op in tests.
    pub notify: Arc<dyn Fn() + Send + Sync>,
    pub clock: Arc<dyn Fn() -> f64 + Send + Sync>,
    pub spawner: Spawner,
}

/// The state of the window.
pub struct AppState {
    pub sh: Shared,
    rx: Receiver<UiMsg>,

    // ---- the choices ----
    pub card: Card,
    pub mode: Mode,
    pub iso_path: String,
    pub disks: Vec<Disk>,
    pub drives: DriveList,
    pub iso_card: FileCard,
    /// The Windows card's link and expected checksum fields.
    pub url_entry: String,
    pub sha_entry: String,
    /// The Windows hardening checkbox (off by default, remembered while the program runs).
    pub hardening: bool,
    pub hardening_toggle: Disclosure,
    pub hardening_details: String,
    /// The value of the seed radio buttons (a key of `SEED_CHOICES`).
    pub seed_choice: String,
    pub sha_toggle: Disclosure,
    pub sha: ShaPanel,
    /// The tools the chosen mode lacks (the chip and the install button).
    pub dep_missing: Vec<String>,

    // ---- feedback ----
    pub controls: Controls,
    pub windows_dl: DownloadWidgets,
    pub flex_dl: DownloadWidgets,
    pub create_progress: Bar,
    pub create_progress_label: String,
    pub create_hint: String,
    pub error_banner: Banner,
    pub success_panel: Banner,
    pub details_toggle: Disclosure,
    pub log_lines: VecDeque<String>,
    /// Set when lines were added: the log box scrolls to its end.
    pub log_scroll_to_end: bool,
    pub help: HelpState,

    // ---- running operations ----
    /// True from the click on "Create" until the write has ended.
    pub creating: bool,
    /// The write worker has started (`self._create_thread is not None`).
    pub create_started: bool,
    pub installing: bool,
    pub download_running: bool,
    pub flex_busy: bool,
    pub flex_extracting: bool,
    pub destroy_requested: bool,
    pub close_wait_seconds: f64,
    open_flows: Vec<FlowKind>,

    // ---- the drive listing ----
    pub last_disk_refresh: Option<f64>,
    pub disk_job: u64,
    pub disk_listing: bool,
    /// A refresh asked for while one was running: the `quiet` of the request.
    pub disk_pending: Option<bool>,
    sha_job: u64,

    // ---- progress of the write ----
    pub create_started_at: Option<f64>,
    pub create_last_ui: f64,
    pub create_stage: Option<String>,
    pub create_stage_base: u64,

    // ---- dialogs and window ----
    pub dialog_queue: VecDeque<DialogRequest>,
    /// The text of the dialog on top (typed identifier or password).
    pub dialog_text: String,
    pub window_size: (f32, f32),
}

impl AppState {
    /// A window state with its own message channel.
    pub fn new(deps: Deps) -> AppState {
        let (tx, rx) = channel();
        AppState::with_channel(deps, tx, rx)
    }

    /// A window state on an existing channel (the real dialogs post to the same one).
    pub fn with_channel(deps: Deps, tx: Sender<UiMsg>, rx: Receiver<UiMsg>) -> AppState {
        let notify = deps.notify.clone();
        let sh = Shared {
            backend: deps.backend,
            dialogs: deps.dialogs,
            priv_: deps.priv_,
            tx,
            notify: deps.notify,
            clock: deps.clock,
            log: LogSink::new(notify),
            closing: Arc::default(),
            write_alive: Arc::default(),
            spawner: deps.spawner,
            cancel_download: Default::default(),
            cancel_create: Default::default(),
            cancel_flex: Default::default(),
        };
        let mut state = AppState {
            sh,
            rx,
            card: Card::Windows,
            mode: Mode::Windows,
            iso_path: String::new(),
            disks: Vec::new(),
            drives: DriveList::default(),
            iso_card: FileCard::new(&tr("No ISO selected yet.")),
            url_entry: String::new(),
            sha_entry: std::env::var(ENV_EXPECTED_SHA256).unwrap_or_default(),
            hardening: false,
            hardening_toggle: Disclosure::new(&tr("What does it change?"), &tr("Hide the list")),
            hardening_details: String::new(),
            seed_choice: "ubuntu".to_string(),
            sha_toggle: Disclosure::new(&tr("Verify the selected ISO (SHA-256)"), &tr("Verify the selected ISO (SHA-256)")),
            sha: ShaPanel::default(),
            dep_missing: Vec::new(),
            controls: Controls::default(),
            windows_dl: DownloadWidgets::default(),
            flex_dl: DownloadWidgets::default(),
            create_progress: Bar::default(),
            create_progress_label: String::new(),
            create_hint: String::new(),
            error_banner: Banner::new(BannerKind::Error),
            success_panel: Banner::new(BannerKind::Success),
            details_toggle: Disclosure::new(&tr("Show details"), &tr("Hide details")),
            log_lines: VecDeque::new(),
            log_scroll_to_end: false,
            help: HelpState::default(),
            creating: false,
            create_started: false,
            installing: false,
            download_running: false,
            flex_busy: false,
            flex_extracting: false,
            destroy_requested: false,
            close_wait_seconds: flows::CLOSE_WAIT_SECONDS,
            open_flows: Vec::new(),
            last_disk_refresh: None,
            disk_job: 0,
            disk_listing: false,
            disk_pending: None,
            sha_job: 0,
            create_started_at: None,
            create_last_ui: f64::NEG_INFINITY,
            create_stage: None,
            create_stage_base: 0,
            dialog_queue: VecDeque::new(),
            dialog_text: String::new(),
            window_size: START_WINDOW_SIZE,
        };
        state.select_card(Card::Windows);
        state
    }

    // ------------------------------------------------------------------------------------------------------
    // Small accessors
    // ------------------------------------------------------------------------------------------------------
    pub fn backend(&self) -> &dyn Backend {
        &*self.sh.backend
    }
    pub fn closing(&self) -> bool {
        self.sh.is_closing()
    }
    pub fn now(&self) -> f64 {
        self.sh.now()
    }
    /// `_write_running()`: a write worker is alive.
    pub fn write_running(&self) -> bool {
        self.sh.write_alive.load(Ordering::SeqCst)
    }
    pub fn selected_disk(&self) -> Option<&Disk> {
        let idx = self.drives.selected_index();
        if idx < 0 {
            return None;
        }
        self.disks.get(idx as usize)
    }
    /// `card_titles[card]`: the translated title of a card.
    pub fn card_title(&self, card: Card) -> String {
        card_texts(card).0
    }
    /// The Create button's text (the seed card writes a seed drive).
    pub fn create_btn_text(&self) -> String {
        if self.mode == Mode::Seed {
            tr("Create Seed Drive")
        } else {
            tr("Create Bootable USB Drive")
        }
    }
    /// The title of step `number` (1 Image type, 2 Image / what the seed drive carries, 3 USB drive).
    pub fn step_title(&self, number: u8) -> String {
        match number {
            1 => tr("Image type"),
            2 if self.card == Card::Seed => seed_step_heading(&self.seed_choice),
            2 => tr("Image"),
            _ => tr("USB drive"),
        }
    }
    /// The seed card takes the file row, the chosen-file card and the SHA-256 link off the page.
    pub fn image_block_hidden(&self) -> bool {
        self.card == Card::Seed
    }
    pub fn sha_toggle_visible(&self) -> bool {
        !self.image_block_hidden() && self.iso_card.has_file
    }
    pub fn sha_panel_visible(&self) -> bool {
        self.sha_toggle_visible() && self.sha_toggle.is_open
    }
    /// The note under the seed radio buttons.
    pub fn seed_note(&self) -> String {
        seed_target_note(&self.seed_choice)
    }
    /// The chip: `(text, ready)`.
    pub fn dep_chip(&self) -> (String, bool) {
        if self.dep_missing.is_empty() {
            (tr("● Ready"), true)
        } else {
            (tr("● Missing tools"), false)
        }
    }

    // ------------------------------------------------------------------------------------------------------
    // The message pump
    // ------------------------------------------------------------------------------------------------------

    /// Apply every message the workers posted, flush the log. Called once per frame.
    pub fn pump(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            self.apply(msg);
        }
        self.flush_log();
    }

    /// Pump until `condition` holds or `timeout_secs` pass (tests: workers deliver their results through the pump).
    pub fn pump_until(&mut self, timeout_secs: f64, condition: impl Fn(&AppState) -> bool) -> bool {
        let start = std::time::Instant::now();
        loop {
            self.pump();
            if condition(self) {
                return true;
            }
            if start.elapsed().as_secs_f64() > timeout_secs {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }

    /// One message from a worker.
    pub fn apply(&mut self, msg: UiMsg) {
        match msg {
            UiMsg::Dialog(request) => self.dialog_queue.push_back(request),
            UiMsg::ListingFinished { job, result, quiet } => self.listing_finished(job, result, quiet),
            UiMsg::DownloadApproved { url, dest, expected_sha } => self.download_approved(url, dest, expected_sha),
            UiMsg::DownloadProgress { done, total, speed } => self.on_progress(done, total, speed),
            UiMsg::DownloadDone { path, sha256, verified } => self.on_download_done(&path, &sha256, verified),
            UiMsg::DownloadError(msg) => self.on_download_error(&msg),
            UiMsg::FlexApproved { dest } => self.flex_approved(dest),
            UiMsg::FlexProgress { done, total, speed, stage } => self.on_flex_progress(done, total, speed, &stage),
            UiMsg::FlexDownloaded { path, sha256 } => self.on_flex_downloaded(&path, &sha256),
            UiMsg::FlexExtracted { image, zip, delete_zip } => self.on_flex_extracted(&image, &zip, delete_zip),
            UiMsg::FlexError(msg) => self.on_flex_error(&msg),
            UiMsg::ImagePicked(path) => self.image_picked(&path),
            UiMsg::ShaProgress { job, done, total } => self.on_iso_sha_progress(job, done, total),
            UiMsg::ShaDone { job, path, digest, expected } => self.on_iso_sha_done(job, &path, &digest, expected.as_deref()),
            UiMsg::ShaError { job, reason } => self.on_iso_sha_error(job, &reason),
            UiMsg::CreateRefused => self.create_refused(),
            UiMsg::CreateGo => self.create_go(),
            UiMsg::CreateProgress { done, total, text } => self.on_create_progress(done, total, &text),
            UiMsg::CreateFinish { ok, canceled } => self.finish_create_progress(ok, canceled),
            UiMsg::CreateSuccess { ejected, mode, hardening, target } => {
                self.show_create_success(ejected, mode, hardening, target)
            }
            UiMsg::CreationEnded => self.creation_ended(),
            UiMsg::CancelRequested { audit } => self.cancel_requested(&audit),
            UiMsg::CloseConfirmed => self.finish_close(),
            UiMsg::FlowEnded(kind) => self.open_flows.retain(|k| *k != kind),
            UiMsg::Log(line) => self.log(&line),
            UiMsg::Notify { info, title, body } => self.notify(info, &title, &body),
            UiMsg::ShowError { title, message } => self.show_error(&title, &message, None),
            UiMsg::ReportError { title, message, exc, modal, retry } => {
                self.report_error(&title, message.as_deref(), exc.as_ref(), modal, retry)
            }
            UiMsg::InstallEnded => self.installation_ended(),
        }
    }

    /// A dialog flow of this kind is open (a question is waiting for the user).
    pub fn flow_open(&self, kind: FlowKind) -> bool {
        self.open_flows.contains(&kind)
    }

    /// Start a dialog flow on its own thread (a flow of that kind already open: ignored). A panicking flow is caught.
    fn spawn_flow(&mut self, kind: FlowKind, flow: impl FnOnce(&Shared) + Send + 'static) -> bool {
        if self.open_flows.contains(&kind) {
            return false;
        }
        self.open_flows.push(kind);
        let sh = self.sh.clone();
        self.sh.spawner.spawn(move || {
            let _ = guarded(|| flow(&sh));
            sh.post(UiMsg::FlowEnded(kind));
        });
        true
    }

    // ------------------------------------------------------------------------------------------------------
    // Dialogs shown by the window
    // ------------------------------------------------------------------------------------------------------

    /// The user answered the dialog on top (or closed it): the flow waiting for it continues.
    pub fn answer_dialog(&mut self, reply: DialogReply) {
        if let Some(request) = self.dialog_queue.pop_front() {
            request.answer(reply);
        }
        self.dialog_text.clear();
    }

    /// `_notify(kind, title, message)`: an information dialog from a worker's result; skipped while closing.
    fn notify(&mut self, info: bool, title: &str, message: &str) {
        if self.closing() {
            return;
        }
        if info {
            self.sh.dialogs.show_info(title, message);
        } else {
            self.sh.dialogs.show_error(title, message);
        }
    }

    // ------------------------------------------------------------------------------------------------------
    // Inline messages
    // ------------------------------------------------------------------------------------------------------

    /// `show_error(title, message, retry)`: the red banner under the Create row ("Try again" when `retry` is given).
    pub fn show_error(&mut self, title: &str, message: &str, retry: Option<Retry>) {
        let actions = retry.map(|r| vec![(tr("Try again"), LinkAction::Retry(r))]).unwrap_or_default();
        self.error_banner.show(title, message, actions, true, None);
    }
    pub fn clear_error(&mut self) {
        self.error_banner.clear();
    }
    /// The finished-write panel (green; amber when the drive still has to be ejected by hand).
    pub fn show_success(&mut self, title: &str, message: &str, verified_and_ejected: bool) {
        let kind = if verified_and_ejected { BannerKind::Success } else { BannerKind::Warning };
        self.success_panel.show(title, message, vec![(tr("Make another"), LinkAction::MakeAnother)], false, Some(kind));
    }
    pub fn clear_success(&mut self) {
        self.success_panel.clear();
    }
    /// Back to the start of the flow after a finished write: the panel and the old result go away.
    pub fn make_another(&mut self) {
        self.clear_success();
        self.create_progress.visible = false;
        self.create_progress_label.clear();
        self.refresh_disks(true, false); // the drive that was ejected is no longer there
        self.update_create_button_state();
    }
    /// A click on a link of a banner: the banner closes, then the action runs.
    pub fn banner_link_clicked(&mut self, banner: BannerId, index: usize) {
        let action = match banner {
            BannerId::Error => self.error_banner.click(index),
            BannerId::Success => self.success_panel.click(index),
        };
        match action {
            Some(LinkAction::MakeAnother) => self.make_another(),
            Some(LinkAction::Retry(Retry::Download)) => self.start_download(),
            Some(LinkAction::Retry(Retry::FlexDownload)) => self.start_flex_download(),
            Some(LinkAction::Retry(Retry::RefreshDisks)) => self.refresh_disks(false, false),
            Some(LinkAction::Retry(Retry::InstallDependencies)) => self.install_dependencies(),
            None => {}
        }
    }

    /// `_report_error(title, message, exc, modal, retry)`: show a user-facing error without leaking internals into the
    /// dialog. `title` is the English text (it also goes to the audit log); the dialog shows it translated. A
    /// `message` given by the caller (an engine error) is shown as it is. The red banner always shows it (with "Try
    /// again" when `retry` is given); the modal dialog too unless `modal` is false.
    pub fn report_error(&mut self, title: &str, message: Option<&str>, exc: Option<&ExcInfo>, modal: bool, retry: Option<Retry>) {
        if self.closing() {
            // no dialog while the window is going away; the log and the audit trail keep it
            let line = match exc {
                None => format!("ERROR: {}", message.unwrap_or("")),
                Some(e) => format!("ERROR [{}]: {}", e.type_name, e.text),
            };
            self.log(&line);
            return;
        }
        let shown: String = match exc {
            Some(e) => {
                self.log(&format!("ERROR [{}]: {}", e.type_name, e.text));
                self.sh.backend.audit(&format!("{title}: {}", e.type_name), AuditLevel::Error);
                trf(
                    "The operation could not be completed.\n\n\
                     Reason: {reason}\n\n\
                     The full technical detail was written to the log box below and to the \
                     audit log at:\n{path}",
                    &[("reason", e.type_name.clone().into()), ("path", self.sh.backend.audit_log_path().into())],
                )
            }
            None => {
                let message = message.unwrap_or("");
                self.log(&format!("ERROR: {message}"));
                message.to_string()
            }
        };
        self.show_error(&tr(title), &shown, retry);
        if modal {
            self.sh.dialogs.show_error(&tr(title), &shown);
        }
    }

    // ------------------------------------------------------------------------------------------------------
    // The log box
    // ------------------------------------------------------------------------------------------------------

    /// `log_threadsafe(msg)`: queue a log line from ANY thread; it appears within `LOG_FLUSH_MS`.
    pub fn log_threadsafe(&self, msg: &str) {
        self.sh.log.push(msg);
    }
    /// `log(msg)`: write a log line (UI thread); order is preserved.
    pub fn log(&mut self, msg: &str) {
        self.sh.log.push(msg);
        self.flush_log();
    }
    /// `_flush_log`: move the queued lines into the box, keeping at most `LOG_MAX_LINES`.
    pub fn flush_log(&mut self) {
        let lines = self.sh.log.take();
        if lines.is_empty() {
            return;
        }
        let skip = lines.len().saturating_sub(LOG_MAX_LINES);
        self.log_lines.extend(lines.into_iter().skip(skip));
        while self.log_lines.len() > LOG_MAX_LINES {
            self.log_lines.pop_front();
        }
        self.log_scroll_to_end = true;
    }
    /// The text of the log box (`log_text.get("1.0", "end")` without the trailing newline).
    pub fn log_text(&self) -> String {
        self.log_lines.iter().map(String::as_str).collect::<Vec<_>>().join("\n")
    }

    // ------------------------------------------------------------------------------------------------------
    // Cards, mode and dependencies
    // ------------------------------------------------------------------------------------------------------

    /// `select_card(key)`: choose the image type: it sets how the image will be written.
    pub fn select_card(&mut self, card: Card) {
        self.card = card;
        self.mode = card.mode();
        self.on_mode_change();
    }
    pub fn on_mode_change(&mut self) {
        self.check_dependencies();
        self.update_create_button_state();
    }
    /// `check_dependencies()`: the chip ("Ready" or "Missing tools" with the install button).
    pub fn check_dependencies(&mut self) {
        self.dep_missing = self.sh.backend.get_missing_dependencies(self.mode);
    }
    /// The seed radio buttons.
    pub fn set_seed_choice(&mut self, choice: &str) {
        self.seed_choice = choice.to_string();
    }
    /// `hardening_selected(mode)`: the baseline profile when the Windows option is ticked and Windows is what is
    /// written, else none. The tick is ignored on every other card (it is only shown on the Windows one).
    pub fn hardening_selected(&self, mode: Option<Mode>) -> Hardening {
        let mode = mode.unwrap_or(self.mode);
        if mode == Mode::Windows && self.hardening {
            Hardening::Baseline
        } else {
            Hardening::None
        }
    }
    /// The "What does it change?" link: the list is built from the engine's description when it opens.
    pub fn set_hardening_details_open(&mut self, open: bool) {
        if self.hardening_toggle.set_open(open) && open {
            let lines = self.sh.backend.describe_hardening_applied();
            self.hardening_details = texts::hardening_details_text(&lines);
        }
    }
    pub fn set_sha_toggle_open(&mut self, open: bool) {
        self.sha_toggle.set_open(open);
    }
    pub fn set_details_open(&mut self, open: bool) {
        if self.details_toggle.set_open(open) && open {
            self.log_scroll_to_end = true;
        }
    }

    /// `install_dependencies()`.
    pub fn install_dependencies(&mut self) {
        if self.creating || self.installing {
            return; // installing clears the cached administrator password the running write may be using
        }
        self.installing = true;
        self.clear_error();
        self.sync_controls();
        self.update_create_button_state();
        let sh = self.sh.clone();
        self.sh.spawner.spawn(move || flows::worker_install(&sh));
    }
    pub fn installation_ended(&mut self) {
        self.installing = false;
        self.check_dependencies();
        self.sync_controls();
        self.update_create_button_state(); // the Create button depends on the tools being there
    }

    // ------------------------------------------------------------------------------------------------------
    // Menu and documentation
    // ------------------------------------------------------------------------------------------------------

    /// `show_help(section)`: open the documentation window (or bring it to the front) on the given section.
    pub fn show_help(&mut self, section: usize) {
        if self.help.sections.is_empty() || !self.help.open {
            self.help.sections = self.sh.backend.help_sections();
        }
        self.help.open = true;
        self.help.section = section.min(self.help.sections.len().saturating_sub(1));
    }
    /// `show_about()`: the "About" section in a message box.
    pub fn show_about(&mut self) {
        let sections = self.sh.backend.help_sections();
        let about = sections.iter().find(|(t, _)| t == "About").map(|(_, b)| b.clone()).unwrap_or_default();
        self.sh.dialogs.show_info(&tr("About EPMA USB CREATOR"), &about);
    }
    pub fn open_audit_log_folder(&mut self) {
        let log_path = self.sh.backend.audit_log_path();
        let folder = log_path.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
        match create_private_dir(&folder) {
            Ok(()) => self.sh.backend.open_url(&path_to_file_uri(&folder)),
            Err(e) => self.sh.dialogs.show_error(
                &tr("Audit log"),
                &trf("Could not open the folder: {reason}", &[("reason", e.to_string().into())]),
            ),
        }
    }
    pub fn open_project_page(&self) {
        self.sh.backend.open_url(PROJECT_URL);
    }
    pub fn open_ms_page(&self) {
        self.sh.backend.open_url(MS_DOWNLOAD_PAGE);
    }
    pub fn open_url(&self, url: &str) {
        self.sh.backend.open_url(url);
    }

    // ------------------------------------------------------------------------------------------------------
    // The image
    // ------------------------------------------------------------------------------------------------------

    /// `pick_existing_iso()`: the button "Select existing ISO file...".
    pub fn pick_existing_iso(&mut self) {
        if self.creating || self.flex_busy {
            return; // the button is disabled meanwhile; this is the safety net for other callers
        }
        self.spawn_flow(FlowKind::PickImage, |sh| flows::flow_pick_image(sh));
    }
    /// The file dialog returned a file.
    fn image_picked(&mut self, path: &Path) {
        if self.creating || self.flex_busy {
            return; // something started while the file dialog was open
        }
        let is_zip = path.to_string_lossy().to_lowercase().ends_with(".zip");
        if is_zip {
            // Google distributes ChromeOS Flex as latest.bin.zip: extract the .bin next to it.
            self.select_card(Card::Chrome); // the extraction progress is shown in that card
            self.sh.cancel_flex.clear(); // a new operation: only here, so a running one never loses its cancel
            self.extract_flex_image(path.to_path_buf(), false);
        } else {
            self.set_iso(&path.to_string_lossy());
        }
    }

    /// `set_iso(path)`: the image was chosen or downloaded.
    pub fn set_iso(&mut self, path: &str) {
        self.iso_path = path.to_string();
        // Only a default: the user can still switch the image type by hand. The CONTENT of the ISO decides. When it
        // cannot be identified the card is left as it is: guessing from the file name could pick the card that
        // erases the drive first ("darwin-linux.img" contains "win").
        let kind = self.sh.backend.detect_iso_kind(Path::new(path));
        let size = std::fs::metadata(path).ok().map(|m| m.len());
        self.iso_card.show(path, kind, size);
        let basename = Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if self.card == Card::Seed {
            // The Hardening seed card needs no image and the user chose it on purpose, so a finished download does
            // not pull them to another card: the image is only remembered for when they choose one.
            self.log(&trf(
                "Image remembered: {name}. The Hardening seed card does not use it; choose the matching \
                 card to write it.",
                &[("name", basename.into())],
            ));
            self.reset_iso_sha();
            return;
        }
        let card = if kind == IsoKind::Unknown {
            let card = self.card;
            let title = self.card_title(card);
            self.log(&trf(
                "The content of this image could not be identified, so the image type was not changed. \
                 Check that the selected card ({card}) is the right one.",
                &[("card", title.into())],
            ));
            card
        } else {
            let mut card = kind.card().unwrap_or(self.card);
            if kind == IsoKind::Linux && self.card == Card::Other {
                card = Card::Other; // a hybrid image keeps "Other ISO" if that is what was chosen, otherwise "Linux"
            }
            let image = image_label(kind.mode().unwrap_or(Mode::Linux), &tr("Linux / other hybrid ISO"));
            self.log(&trf(
                "Image type preselected {how}: {image}.",
                &[("how", tr("from the content of the ISO").into()), ("image", image.into())],
            ));
            card
        };
        self.select_card(card);
        self.reset_iso_sha();
    }

    // ------------------------------------------------------------------------------------------------------
    // SHA-256 of the selected image
    // ------------------------------------------------------------------------------------------------------

    pub fn reset_iso_sha(&mut self) {
        self.sha_job += 1; // invalidates any calculation still running for the previous file
        self.sha.btn_enabled = true;
        self.sha.bar.value = 0.0;
        self.sha.bar.visible = false;
        self.sha.label.clear();
        self.sha.result.clear();
        self.sha.result_tone = Tone::Normal;
    }

    pub fn calculate_iso_sha256(&mut self) {
        let path = self.iso_path.clone();
        if path.is_empty() || !Path::new(&path).is_file() {
            self.sha.result = tr("Select an ISO file first.");
            self.sha.result_tone = Tone::Red;
            return;
        }
        let name = Path::new(&path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let expected = match self.sh.backend.parse_expected_sha256(&self.sha.entry, Some(&name)) {
            Ok(expected) => expected,
            Err(e) => {
                self.sha.result = e.to_string();
                self.sha.result_tone = Tone::Red;
                return;
            }
        };
        self.sha_job += 1;
        let job = self.sha_job;
        self.sha.btn_enabled = false;
        self.sha.bar.value = 0.0;
        self.sha.result.clear();
        self.sha.result_tone = Tone::Normal;
        self.sha.label = tr("Calculating...");
        self.sha.bar.visible = true;
        self.log(&trf("Calculating SHA-256 of {name}...", &[("name", name.into())]));
        let sh = self.sh.clone();
        self.sh.spawner.spawn(move || flows::worker_sha(&sh, job, PathBuf::from(path), expected));
    }

    fn on_iso_sha_progress(&mut self, job: u64, done: u64, total: u64) {
        if job != self.sha_job {
            return;
        }
        let pct = if total > 0 { done as f64 / total as f64 * 100.0 } else { 0.0 };
        self.sha.bar.value = pct;
        self.sha.label = trf(
            "Calculating... {pct:.0f}% ({done} / {total})",
            &[("pct", pct.into()), ("done", human_size(done).into()), ("total", human_size(total).into())],
        );
    }

    fn on_iso_sha_done(&mut self, job: u64, path: &Path, digest: &str, expected: Option<&str>) {
        if job != self.sha_job {
            return;
        }
        self.sha.btn_enabled = true;
        self.sha.bar.value = 100.0;
        self.sha.label = trf("SHA-256: {digest}", &[("digest", digest.into())]);
        let (outcome, text, tone, outcome_label);
        match expected {
            None => {
                outcome = "unverified";
                text = tr("No expected checksum given: compare the value above yourself.");
                tone = Tone::Normal;
                outcome_label = tr("UNVERIFIED");
            }
            Some(exp) if exp == digest => {
                outcome = "match";
                tone = Tone::Green;
                text = tr("MATCH — the file is intact and identical to the published one.");
                outcome_label = tr("MATCH");
            }
            Some(exp) => {
                outcome = "mismatch";
                tone = Tone::Red;
                text = tr("MISMATCH — this is NOT the published file. Do not use it.");
                outcome_label = tr("MISMATCH");
                self.log(&trf("Expected SHA-256: {expected}", &[("expected", exp.into())]));
            }
        }
        self.sha.result = text;
        self.sha.result_tone = tone;
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        self.log(&trf("SHA-256 of {name}: {digest}", &[("name", name.into()), ("digest", digest.into())]));
        self.log(&trf("Checksum comparison: {outcome}", &[("outcome", outcome_label.into())]));
        let level = if outcome == "mismatch" { AuditLevel::Warning } else { AuditLevel::Info };
        self.sh.backend.audit(&format!("ISO SHA-256 check result={outcome}"), level);
    }

    fn on_iso_sha_error(&mut self, job: u64, reason: &str) {
        if job != self.sha_job {
            return;
        }
        self.sha.btn_enabled = true;
        self.sha.label.clear();
        self.sha.result = trf("Could not read the file ({reason}).", &[("reason", reason.into())]);
        self.sha.result_tone = Tone::Red;
    }

    // ------------------------------------------------------------------------------------------------------
    // Windows ISO download
    // ------------------------------------------------------------------------------------------------------

    pub fn start_download(&mut self) {
        if self.creating || self.download_running {
            return;
        }
        let url_text = self.url_entry.clone();
        let expected_sha = self.sha_entry.trim().to_lowercase();
        self.spawn_flow(FlowKind::Download, move |sh| flows::flow_download(sh, url_text, expected_sha));
    }

    fn download_approved(&mut self, url: String, dest: PathBuf, expected_sha: String) {
        if self.creating || self.download_running {
            return; // something started while the dialogs were open
        }
        self.sh.cancel_download.clear();
        self.download_running = true;
        self.clear_error();
        self.sync_controls();
        self.windows_dl.start(None);
        let expected = if expected_sha.is_empty() { None } else { Some(expected_sha) };
        flows::launch_windows_download(&self.sh, url, dest, expected);
    }

    pub fn cancel_download(&self) {
        self.sh.cancel_download.set();
    }

    pub fn on_progress(&mut self, downloaded: u64, total: u64, speed: f64) {
        if total > 0 {
            let pct = downloaded as f64 / total as f64 * 100.0;
            let eta = super::tx::eta_remaining(downloaded, total, speed);
            let text = trf(
                "{done} / {total} ({pct:.1f}%) — {speed}/s — {eta}",
                &[
                    ("done", human_size(downloaded).into()),
                    ("total", human_size(total).into()),
                    ("pct", pct.into()),
                    ("speed", super::tx::human_size_f(speed).into()),
                    ("eta", if eta.is_empty() { tr("calculating...") } else { eta }.into()),
                ],
            );
            self.windows_dl.show(Some(pct), &text);
        } else {
            let text = trf(
                "{done} downloaded — {speed}/s",
                &[("done", human_size(downloaded).into()), ("speed", super::tx::human_size_f(speed).into())],
            );
            self.windows_dl.show(None, &text);
        }
    }

    pub fn on_download_done(&mut self, path: &Path, sha256: &str, verified: bool) {
        self.download_running = false;
        self.sync_controls();
        if self.closing() {
            return;
        }
        self.windows_dl.finish(&tr("Download complete."), None);
        self.set_iso(&path.to_string_lossy());
        self.log(&trf("SHA-256 of the downloaded file: {sha256}", &[("sha256", sha256.into())]));
        let detail = if verified {
            format!("\n\n{}", tr("The SHA-256 checksum matches the value you supplied — the file is intact."))
        } else {
            format!(
                "\n\n{}",
                trf(
                    "SHA-256 of this file:\n{sha256}\n\n\
                     No checksum was supplied, so authenticity was NOT verified. If Microsoft \
                     publishes a checksum for this image, compare it with the value above before \
                     writing the USB drive.",
                    &[("sha256", sha256.into())],
                )
            )
        };
        let text = trf("ISO downloaded to:\n{path}", &[("path", path.into())]) + &detail;
        self.sh.dialogs.show_info(&tr("Done"), &text);
    }

    pub fn on_download_error(&mut self, msg: &str) {
        self.download_running = false;
        self.sync_controls();
        if self.closing() {
            return;
        }
        self.windows_dl.finish(&tr("Download failed."), Some(0.0));
        self.report_error("Download error", Some(msg), None, false, Some(Retry::Download));
    }

    // ------------------------------------------------------------------------------------------------------
    // ChromeOS Flex
    // ------------------------------------------------------------------------------------------------------

    pub fn start_flex_download(&mut self) {
        if self.creating || self.flex_busy {
            return;
        }
        self.spawn_flow(FlowKind::FlexDownload, |sh| flows::flow_flex_download(sh));
    }

    fn flex_approved(&mut self, dest: PathBuf) {
        if self.creating || self.flex_busy {
            return; // something started while the dialogs were open
        }
        self.sh.backend.audit("ChromeOS Flex download started (dl.google.com)", AuditLevel::Info);
        self.sh.cancel_flex.clear();
        self.flex_busy = true;
        self.clear_error();
        self.sync_controls();
        self.flex_dl.start(None);
        flows::launch_flex_download(&self.sh, dest);
    }

    pub fn cancel_flex(&self) {
        self.sh.cancel_flex.set();
    }

    pub fn on_flex_progress(&mut self, done: u64, total: u64, speed: f64, stage: &str) {
        if total > 0 {
            let pct = done as f64 / total as f64 * 100.0;
            let text = format!(
                "{stage}  {pct:.1}% — {} / {}{}",
                human_size(done),
                human_size(total),
                rate_tail(done, total, speed)
            );
            self.flex_dl.show(Some(pct), &text);
        } else {
            self.flex_dl.show(None, &format!("{stage}  {}", human_size(done)));
        }
    }

    pub fn on_flex_downloaded(&mut self, path: &Path, sha256: &str) {
        self.log(&trf("SHA-256 of the downloaded file: {sha256}", &[("sha256", sha256.into())]));
        if self.sh.cancel_flex.is_set() {
            // canceled just as the download ended: keep the cancel
            self.on_flex_error(&tr("Canceled."));
            return;
        }
        self.extract_flex_image(path.to_path_buf(), true);
    }

    /// `_extract_flex_image(zip, delete_zip)`: extract the .bin from `zip` in a worker thread, then select it for
    /// writing. The caller starts the operation; this never clears the cancel flag, so a cancel that is already
    /// pending is honoured. A second extraction cannot start while one is running.
    pub fn extract_flex_image(&mut self, zip: PathBuf, delete_zip: bool) {
        if self.flex_extracting {
            return;
        }
        self.flex_extracting = true;
        self.flex_busy = true;
        self.clear_error();
        self.sync_controls();
        self.flex_dl.start(Some(&tr("Extracting...")));
        let sh = self.sh.clone();
        self.sh.spawner.spawn(move || flows::worker_extract(&sh, zip, delete_zip));
    }

    pub fn on_flex_extracted(&mut self, image: &Path, zip: &Path, delete_zip: bool) {
        self.flex_busy = false;
        self.flex_extracting = false;
        self.sync_controls();
        if self.closing() {
            return;
        }
        self.flex_dl.finish(&tr("Ready."), Some(100.0));
        if delete_zip {
            let _ = std::fs::remove_file(zip); // only the archive this program downloaded itself (_silent_remove)
        }
        self.set_iso(&image.to_string_lossy());
        self.refresh_disks(false, false); // so a drive that is already plugged in shows up right away
        let text = trf(
            "The disk image is ready:\n{path}\n\nNext: plug in a USB drive of 16 GB or larger, click \
             \"Refresh USB drives list\", select the drive and click \
             \"Create Bootable USB Drive\".",
            &[("path", image.into())],
        );
        self.sh.dialogs.show_info(&tr("ChromeOS Flex is ready"), &text);
    }

    pub fn on_flex_error(&mut self, msg: &str) {
        let was_extracting = self.flex_extracting;
        self.flex_busy = false;
        self.flex_extracting = false;
        self.sync_controls();
        if self.closing() {
            return;
        }
        self.flex_dl.finish(&tr("Failed."), Some(0.0));
        // "Try again" repeats the download; a failed extraction of a file the user chose has nothing to repeat.
        let retry = if was_extracting { None } else { Some(Retry::FlexDownload) };
        self.report_error("ChromeOS Flex", Some(msg), None, false, retry);
    }

    // ------------------------------------------------------------------------------------------------------
    // The drive list
    // ------------------------------------------------------------------------------------------------------

    /// `refresh_disks(quiet, sync)`: read the list of USB drives. `quiet` (automatic refreshes) logs a failure instead
    /// of opening a message. The drive that was selected stays selected if it is still there. The listing runs in a
    /// worker (diskutil/lsblk can take long or hang with a faulty drive); two listings never overlap: a request made
    /// while one runs is remembered and served right after. `sync` lists on the calling thread (tests).
    pub fn refresh_disks(&mut self, quiet: bool, sync: bool) {
        if self.closing() {
            return;
        }
        if !quiet {
            self.clear_error(); // an explicit refresh starts over; automatic ones never hide a message
        }
        if sync {
            self.disk_job += 1;
            let job = self.disk_job;
            match guarded(|| self.sh.backend.get_external_disks()) {
                Ok(Ok(disks)) => self.on_disks(job, disks),
                Ok(Err(e)) => self.on_disks_error(job, &e.to_string(), quiet),
                Err(panic) => self.on_disks_error(job, &panic, quiet),
            }
            return;
        }
        if self.disk_listing {
            // Keep the strongest request: an explicit click (not quiet) must still report a failure.
            self.disk_pending = Some(match self.disk_pending {
                None => quiet,
                Some(pending) => pending && quiet,
            });
            return;
        }
        self.disk_listing = true;
        self.drives.set_loading(true);
        self.disk_job += 1;
        let job = self.disk_job;
        let sh = self.sh.clone();
        self.sh.spawner.spawn(move || {
            let result = match guarded(|| sh.backend.get_external_disks()) {
                Ok(Ok(disks)) => Ok(disks),
                Ok(Err(e)) => Err(e.to_string()),
                Err(panic) => Err(panic),
            };
            sh.post(UiMsg::ListingFinished { job, result, quiet });
        });
    }

    /// The listing worker delivered its result; then serve the request made meanwhile.
    fn listing_finished(&mut self, job: u64, result: Result<Vec<Disk>, String>, quiet: bool) {
        self.disk_listing = false;
        self.drives.set_loading(false);
        match result {
            Err(error) => self.on_disks_error(job, &error, quiet),
            Ok(disks) => self.on_disks(job, disks),
        }
        if let Some(pending) = self.disk_pending.take() {
            if !self.closing() {
                self.refresh_disks(pending, false);
            }
        }
    }

    fn on_disks_error(&mut self, job: u64, error: &str, quiet: bool) {
        if job != self.disk_job || self.closing() {
            return; // an older listing, or the window is closing
        }
        if self.drives.view_state() == super::widgets::ListView::Loading {
            let disks = self.disks.clone();
            self.drives.set_items(&disks); // the listing failed: stop showing the placeholder rows
        }
        let text = trf("Could not list disks: {error}", &[("error", error.into())]);
        if quiet {
            self.log(&text);
        } else {
            self.report_error("Error", Some(&text), None, false, Some(Retry::RefreshDisks));
        }
    }

    fn on_disks(&mut self, job: u64, disks: Vec<Disk>) {
        if job != self.disk_job || self.closing() || self.creating {
            return; // an older listing, or the write is running: creation_ended lists again
        }
        self.disks = disks;
        self.last_disk_refresh = Some(self.now());
        self.drives.set_items(&self.disks); // keeps the selection on the same drive (by id), else the first
        self.update_create_button_state();
    }

    /// Look for newly plugged drives when the program starts and whenever its window gets focus again, so the user
    /// does not have to remember to click "Refresh".
    pub fn auto_refresh_disks(&mut self) {
        if self.creating {
            return;
        }
        if let Some(last) = self.last_disk_refresh {
            if self.now() - last < AUTO_REFRESH_MIN_SECONDS {
                return;
            }
        }
        self.refresh_disks(true, false);
    }

    /// A click on a row of the drive list.
    pub fn select_drive(&mut self, index: usize) {
        if self.drives.row_pressed(index) {
            self.update_create_button_state();
        }
    }
    /// Up / Down on a row of the drive list.
    pub fn drive_arrow(&mut self, row: usize, step: i64) {
        if self.drives.row_arrow(row, step) {
            self.update_create_button_state();
        }
    }

    // ------------------------------------------------------------------------------------------------------
    // Enabled states and the Create button
    // ------------------------------------------------------------------------------------------------------

    /// `_sync_controls()`: enable or disable the controls that must not be used while something is running. While a
    /// write runs nothing that changes the image type, the drive or the image may be touched. A download or an
    /// extraction only locks its own button and the image picker.
    pub fn sync_controls(&mut self) {
        let creating = self.creating;
        self.controls.cards_enabled = !creating;
        self.drives.set_enabled(!creating);
        self.controls.refresh_enabled = !creating;
        self.windows_dl.sync(self.download_running, creating);
        self.flex_dl.sync(self.flex_busy, creating);
        if !creating {
            // during a write the Cancel button follows the write itself (see create_go)
            self.controls.cancel_enabled = self.download_running || self.flex_busy;
        }
        self.controls.pick_enabled = !(creating || self.flex_busy);
        self.controls.hardening_enabled = !creating; // the choices are read when Create is clicked
        self.controls.seed_radios_enabled = !creating;
        self.controls.install_enabled = !(creating || self.installing);
        self.update_create_button_state(); // Create also waits for a running download or extraction
    }

    /// `update_create_button_state()`: when Create is enabled and the hint under it.
    pub fn update_create_button_state(&mut self) {
        let disk_present = self.selected_disk().is_some();
        let has_image = !self.iso_path.is_empty() || self.mode == Mode::Seed; // the seed card needs no image
        // The tools the chosen mode needs: without them the drive would be erased and the copy would then fail.
        let missing = if self.creating { Vec::new() } else { self.sh.backend.get_missing_dependencies(self.mode) };
        let downloading = self.download_running || self.flex_busy; // the image (and the card) may still change
        let ok = has_image
            && disk_present
            && missing.is_empty()
            && !self.creating
            && !self.installing
            && !self.closing()
            && !downloading;
        self.controls.create_enabled = ok;
        self.create_hint = if self.creating {
            String::new()
        } else if downloading {
            tr("Wait for the download to finish or cancel it first.")
        } else if !has_image {
            tr("Choose the image file first (\"Select existing ISO file...\" or the download above).")
        } else if !disk_present && self.disks.is_empty() {
            tr("No USB drive found. Plug it in and click \"Refresh USB drives list\".")
        } else if !disk_present {
            tr("Select a USB drive in the list.")
        } else if !missing.is_empty() {
            trf(
                "Missing tools: {tools}. Click \"Install missing dependencies\" first.",
                &[("tools", missing.join(", ").into())],
            )
        } else if self.installing {
            tr("Installing the missing tools...")
        } else {
            String::new()
        };
    }

    // ------------------------------------------------------------------------------------------------------
    // Writing the drive
    // ------------------------------------------------------------------------------------------------------

    /// `start_create_usb()`: the click on Create. Everything the write depends on is read ONCE, here, before any
    /// dialog opens.
    pub fn start_create_usb(&mut self) {
        if self.creating {
            return; // a write (or its confirmation) is already in progress: never start a second one
        }
        self.creating = true;
        self.sync_controls();
        let inputs = CreateInputs {
            disk: self.selected_disk().cloned(),
            mode: self.mode,
            iso: self.iso_path.clone(),
            seed_choice: self.seed_choice.clone(),
            hardening: self.hardening_selected(None),
            downloading: self.download_running || self.flex_busy,
        };
        let sh = self.sh.clone();
        self.sh.spawner.spawn(move || flows::run_create_flow(sh, inputs));
    }

    /// Canceled or refused before the worker began: unlock again.
    fn create_refused(&mut self) {
        self.creating = false;
        self.sync_controls();
        self.update_create_button_state();
    }

    /// Everything was confirmed and the worker began.
    fn create_go(&mut self) {
        self.create_started = true;
        self.update_create_button_state();
        self.controls.cancel_enabled = true;
        self.clear_error();
        self.clear_success();
        self.reset_create_progress();
    }

    /// The write finished (or failed or was canceled): unlock the window and look at the drives again, because a
    /// drive that was ejected is no longer there.
    pub fn creation_ended(&mut self) {
        self.creating = false;
        self.create_started = false;
        self.controls.cancel_enabled = false;
        self.sync_controls();
        self.update_create_button_state();
        self.refresh_disks(true, false);
    }

    /// The single Cancel button: stop whatever is running (the write, else a download or extraction).
    pub fn cancel_current(&mut self) {
        if self.creating {
            self.cancel_create_usb();
        } else if self.download_running {
            self.cancel_download();
        } else if self.flex_busy {
            self.cancel_flex();
        }
    }

    /// Ask the running USB creation to stop (after a warning). Safe to call at any time.
    pub fn cancel_create_usb(&mut self) {
        if self.sh.cancel_create.is_set() || !self.controls.cancel_enabled {
            return;
        }
        self.spawn_flow(FlowKind::CancelWrite, |sh| flows::flow_cancel_write(sh));
    }

    /// The cancel was confirmed (the token is already set).
    fn cancel_requested(&mut self, audit: &str) {
        self.controls.cancel_enabled = false;
        self.log(&tr("Cancel requested: stopping safely..."));
        self.sh.backend.audit(audit, AuditLevel::Info);
    }

    // ------------------------------------------------------------------------------------------------------
    // Progress of the write
    // ------------------------------------------------------------------------------------------------------

    pub fn reset_create_progress(&mut self) {
        self.create_started_at = None;
        self.create_last_ui = f64::NEG_INFINITY;
        self.create_stage = None;
        self.create_stage_base = 0;
        self.create_progress.visible = true;
        self.create_progress.config(Some(BarMode::Indeterminate), Some(0.0));
        self.create_progress.start();
        self.create_progress_label = tr("Preparing the drive...");
    }

    pub fn on_create_progress(&mut self, done: u64, total: u64, text: &str) {
        let text = tr(text); // the stage names come from the engine in English; same input, same output
        let now = self.now();
        if total == 0 {
            // Length unknown (e.g. comparing files): show a busy bar with what is going on.
            if self.create_progress.mode != BarMode::Indeterminate {
                self.create_progress.config(Some(BarMode::Indeterminate), Some(0.0));
                self.create_progress.start();
            }
            self.create_progress_label = trf("{stage} (this can take a few minutes)", &[("stage", text.into())]);
            self.create_stage = None;
            return;
        }
        let finished = done >= total;
        // Updates can arrive thousands of times (one per copied file); redraw ~5x/s.
        if !finished && now - self.create_last_ui < PROGRESS_UI_INTERVAL {
            return;
        }
        self.create_last_ui = now;
        if self.create_progress.mode != BarMode::Determinate {
            self.create_progress.stop();
            self.create_progress.config(Some(BarMode::Determinate), None);
        }
        if self.create_stage.as_deref() != Some(text.as_str()) {
            // New stage: measure speed and time left from where this stage began.
            self.create_stage = Some(text.clone());
            self.create_started_at = Some(now);
            self.create_stage_base = done;
        }
        let pct = done as f64 / total as f64 * 100.0;
        self.create_progress.value = pct;
        if finished {
            self.create_progress_label = format!("{text}  100%");
            return;
        }
        let elapsed = (now - self.create_started_at.unwrap_or(now)).max(0.001);
        let speed = done.saturating_sub(self.create_stage_base) as f64 / elapsed;
        let mut tail = rate_tail(done, total, speed);
        if tail.is_empty() {
            tail = tr(" — calculating...");
        }
        self.create_progress_label =
            format!("{text}  {pct:.1}% — {} / {}{tail}", human_size(done), human_size(total));
    }

    pub fn finish_create_progress(&mut self, ok: bool, canceled: bool) {
        self.flush_log(); // show the worker's last lines before the result dialog appears
        self.create_progress.stop();
        self.create_progress.config(Some(BarMode::Determinate), Some(if ok { 100.0 } else { 0.0 }));
        if !ok {
            self.create_progress.visible = false; // an empty bar says nothing; the label below says what happened
            if !canceled {
                self.set_details_open(true); // a failure: the log is what the user will want to read
            }
        }
        self.create_progress_label = if ok {
            tr("Done — 100%")
        } else if canceled {
            tr("Canceled.")
        } else {
            tr("Failed.")
        };
    }

    /// `_show_create_success(ejected, mode, hardening, target)`: the write was verified: the inline panel. Without the
    /// eject the panel is amber and says the drive must be ejected by hand before it is unplugged.
    pub fn show_create_success(&mut self, ejected: bool, mode: Mode, hardening: Hardening, target: Option<SeedTarget>) {
        if self.closing() {
            return;
        }
        if mode == Mode::Seed && target == Some(SeedTarget::Windows) {
            let (title, note) = texts::windows_seed_success_texts(ejected);
            self.show_success(&title, &note, ejected);
            return;
        }
        if mode == Mode::Seed {
            let (title, note) = texts::seed_success_texts(ejected);
            self.show_success(&title, &note, ejected);
            return;
        }
        let (title, note) = texts::create_success_texts(ejected, hardening != Hardening::None);
        self.show_success(&title, &note, ejected);
    }

    // ------------------------------------------------------------------------------------------------------
    // Closing the window
    // ------------------------------------------------------------------------------------------------------

    /// The window's close button (and Cmd-Q). A running write is never abandoned silently: closing asks first, then
    /// cancels it and waits (bounded, the window stays alive) for the worker to stop.
    pub fn request_close(&mut self) {
        if self.closing() {
            return;
        }
        if self.creating && !self.create_started && !self.write_running() {
            return; // a confirmation or password dialog is waiting for an answer: finish that first
        }
        if self.write_running() {
            let wait = self.close_wait_seconds;
            self.spawn_flow(FlowKind::CloseWindow, move |sh| flows::flow_close_while_writing(sh, wait));
            return;
        }
        self.finish_close();
    }

    /// Close for good: stop the downloads and tell the window to go.
    fn finish_close(&mut self) {
        self.sh.closing.store(true, Ordering::SeqCst);
        self.sh.cancel_download.set(); // a Windows ISO download
        self.sh.cancel_flex.set(); // a ChromeOS Flex download or extraction
        self.destroy_requested = true;
    }

    // ------------------------------------------------------------------------------------------------------
    // The window's size
    // ------------------------------------------------------------------------------------------------------

    /// `_fit_window()`: the height the window should have now, or None to leave it alone (see `fit_window_height`).
    pub fn fit_window(&mut self, shown_height: f32, required_height: f32, screen_height: f32) -> Option<f32> {
        let height = fit_window_height(self.window_size.1, shown_height, required_height, screen_height)?;
        self.window_size.1 = height;
        Some(height)
    }

    /// `Platform` of the running system.
    pub fn platform(&self) -> Platform {
        self.sh.backend.platform()
    }
}

/// `os.makedirs(folder, mode=0o700, exist_ok=True)`.
fn create_private_dir(folder: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(folder)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(folder)
    }
}

/// `pathlib.Path(folder).as_uri()`: `file:///home/me/.local/state/epma` (non-ASCII and special characters are
/// percent-encoded; a Windows drive keeps its colon).
pub fn path_to_file_uri(path: &Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    let mut out = String::from("file://");
    if !text.starts_with('/') {
        out.push('/'); // a Windows drive path: file:///C:/...
    }
    let bytes = text.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        let keep = b.is_ascii_alphanumeric()
            || matches!(b, b'/' | b'_' | b'.' | b'-' | b'~')
            || (b == b':' && i == 1 && bytes[0].is_ascii_alphabetic());
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `set_macos_app_name(name)`: make the macOS menu bar and Dock say `name` instead of the program's file name.
///
/// The Python reached into the Objective-C runtime through ctypes. This port does not add an Objective-C dependency
/// for a cosmetic label: the window's title and `ViewportBuilder::with_app_id` (the Linux window class and the macOS
/// application name winit derives from it) carry the name instead. Never fails; does nothing off macOS.
pub fn set_macos_app_name(_name: &str) {}
