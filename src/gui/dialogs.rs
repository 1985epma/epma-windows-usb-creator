//! The window's dialogs (port of win11_usb_creator.py lines 1747-1880 and the `messagebox` / `filedialog` calls of the
//! `App` class).
//!
//! The Python window blocks inside `messagebox.askyesno(...)`. An immediate-mode window cannot, so every flow that
//! asks something runs on a worker thread and talks to the user through the [`Dialogs`] trait: `ask_*` block that
//! worker until the window has shown the dialog and the user has answered (a reply channel); `show_*` never block.
//! The window drains the queue of [`DialogRequest`]s on its own thread. Tests use a scripted fake instead.

use crate::types::PasswordPrompt;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;

/// `("ISO and disk images", ["iso", "bin", ...])`: a file type filter of a file dialog.
pub type FileFilter = (String, Vec<String>);

#[derive(Clone, Debug, PartialEq)]
pub enum DialogKind {
    Info,
    Error,
    /// A yes / no question (`warning`: the exclamation icon).
    Question {
        warning: bool,
    },
    /// "Type the drive identifier": Erase stays disabled until the text matches `expected`.
    Typed {
        expected: String,
        reasons: Vec<String>,
    },
    Password,
    OpenFile {
        filters: Vec<FileFilter>,
    },
    SaveFile {
        initial_name: String,
        extension: String,
        filters: Vec<FileFilter>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum DialogReply {
    Yes(bool),
    Text(Option<String>),
    Path(Option<PathBuf>),
}

/// One dialog waiting to be shown.
pub struct DialogRequest {
    pub kind: DialogKind,
    pub title: String,
    pub message: String,
    /// `None` for the notifications (`show_info` / `show_error`).
    pub reply: Option<Sender<DialogReply>>,
}

impl DialogRequest {
    /// What a dialog answers when the window goes away (or the user closes it): "no", nothing.
    pub fn default_reply(&self) -> DialogReply {
        match self.kind {
            DialogKind::Password => DialogReply::Text(None),
            DialogKind::OpenFile { .. } | DialogKind::SaveFile { .. } => DialogReply::Path(None),
            _ => DialogReply::Yes(false),
        }
    }
    /// Send the answer to the flow that is waiting for it (no-op for notifications).
    pub fn answer(self, reply: DialogReply) {
        if let Some(tx) = self.reply {
            let _ = tx.send(reply);
        }
    }
}

/// What the flows ask the user. `ask_*` and `pick_*` block until the user answered (from a worker thread only).
pub trait Dialogs: Send + Sync {
    /// An information box (`messagebox.showinfo`); does not wait.
    fn show_info(&self, title: &str, message: &str);
    /// An error box (`messagebox.showerror`); does not wait.
    fn show_error(&self, title: &str, message: &str);
    /// `messagebox.askyesno`.
    fn ask_yes_no(&self, title: &str, message: &str, warning: bool) -> bool;
    /// `ask_typed_confirmation`: true only on an exact match of the identifier.
    fn ask_typed_confirmation(&self, title: &str, message: &str, expected: &str, reasons: &[String]) -> bool;
    /// `ask_password`: the text, or None if canceled.
    fn ask_password(&self, title: &str, prompt: &str) -> Option<String>;
    /// `filedialog.askopenfilename`.
    fn pick_open_file(&self, title: &str, filters: &[FileFilter]) -> Option<PathBuf>;
    /// `filedialog.asksaveasfilename`.
    fn pick_save_file(
        &self,
        title: &str,
        initial_name: &str,
        extension: &str,
        filters: &[FileFilter],
    ) -> Option<PathBuf>;
}

/// The real dialogs: requests go to the window (through `post`, which queues them for the UI thread and wakes it).
#[derive(Clone)]
pub struct HubDialogs {
    post: Arc<dyn Fn(DialogRequest) + Send + Sync>,
}

impl HubDialogs {
    pub fn new(post: Arc<dyn Fn(DialogRequest) + Send + Sync>) -> Self {
        HubDialogs { post }
    }

    fn ask(&self, kind: DialogKind, title: &str, message: &str) -> DialogReply {
        let (tx, rx) = channel();
        let request = DialogRequest { kind, title: title.to_string(), message: message.to_string(), reply: Some(tx) };
        let fallback = request.default_reply();
        (self.post)(request);
        // The window dropping the request (it is closing) answers like a canceled dialog.
        rx.recv().unwrap_or(fallback)
    }

    fn notify(&self, kind: DialogKind, title: &str, message: &str) {
        (self.post)(DialogRequest { kind, title: title.to_string(), message: message.to_string(), reply: None });
    }
}

impl Dialogs for HubDialogs {
    fn show_info(&self, title: &str, message: &str) {
        self.notify(DialogKind::Info, title, message);
    }
    fn show_error(&self, title: &str, message: &str) {
        self.notify(DialogKind::Error, title, message);
    }
    fn ask_yes_no(&self, title: &str, message: &str, warning: bool) -> bool {
        matches!(self.ask(DialogKind::Question { warning }, title, message), DialogReply::Yes(true))
    }
    fn ask_typed_confirmation(&self, title: &str, message: &str, expected: &str, reasons: &[String]) -> bool {
        let kind = DialogKind::Typed { expected: expected.to_string(), reasons: reasons.to_vec() };
        matches!(self.ask(kind, title, message), DialogReply::Yes(true))
    }
    fn ask_password(&self, title: &str, prompt: &str) -> Option<String> {
        match self.ask(DialogKind::Password, title, prompt) {
            DialogReply::Text(t) => t,
            _ => None,
        }
    }
    fn pick_open_file(&self, title: &str, filters: &[FileFilter]) -> Option<PathBuf> {
        match self.ask(DialogKind::OpenFile { filters: filters.to_vec() }, title, "") {
            DialogReply::Path(p) => p,
            _ => None,
        }
    }
    fn pick_save_file(
        &self,
        title: &str,
        initial_name: &str,
        extension: &str,
        filters: &[FileFilter],
    ) -> Option<PathBuf> {
        let kind = DialogKind::SaveFile {
            initial_name: initial_name.to_string(),
            extension: extension.to_string(),
            filters: filters.to_vec(),
        };
        match self.ask(kind, title, "") {
            DialogReply::Path(p) => p,
            _ => None,
        }
    }
}

/// The privileged helpers ask for the administrator password through this: the worker thread blocks until the user
/// answered the window's password dialog.
impl PasswordPrompt for HubDialogs {
    fn ask_password(&self, title: &str, prompt: &str) -> Option<String> {
        Dialogs::ask_password(self, title, prompt)
    }
    fn show_error(&self, title: &str, message: &str) {
        Dialogs::show_error(self, title, message)
    }
}

/// `normalize_typed_identifier(text)` for the given platform: what the user typed as a disk identifier, with
/// whitespace and a `/dev/` prefix removed (on Windows: `3`, `disk 3` and `\\.\PhysicalDrive3` all become
/// `PhysicalDrive3`).
pub fn normalize_typed_identifier_for(text: &str, windows: bool) -> String {
    let mut text = text.trim().to_string();
    if windows {
        // Windows people say "disk 3" (Disk Management, diskpart): accept it, "3" and the device path.
        if let Some(rest) = text.strip_prefix("\\\\.\\") {
            text = rest.to_string();
        }
        let lower = text.to_lowercase();
        let digits = lower.strip_prefix("disk").map(str::trim_start).unwrap_or(&lower);
        if (1..=4).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_digit()) {
            let n: u64 = digits.parse().unwrap_or(0);
            return format!("PhysicalDrive{n}");
        }
        return text;
    }
    text.strip_prefix("/dev/").map(str::to_string).unwrap_or(text)
}

/// `normalize_typed_identifier(text)` on this platform.
pub fn normalize_typed_identifier(text: &str) -> String {
    normalize_typed_identifier_for(text, crate::constants::IS_WINDOWS)
}

/// The typed-confirmation dialog's logic (`build_typed_confirmation_dialog`): the Erase button follows the text, so
/// every way of changing it counts (typing, a paste, drag and drop), and Enter cannot slip through.
#[derive(Clone, Debug, Default)]
pub struct TypedConfirm {
    pub typed: String,
    pub expected: String,
    pub windows: bool,
    pub ok: bool,
}

impl TypedConfirm {
    pub fn new(expected: &str) -> Self {
        TypedConfirm {
            typed: String::new(),
            expected: expected.to_string(),
            windows: crate::constants::IS_WINDOWS,
            ok: false,
        }
    }
    pub fn matches(&self) -> bool {
        normalize_typed_identifier_for(&self.typed, self.windows) == self.expected
    }
    /// The state of the Erase button.
    pub fn erase_enabled(&self) -> bool {
        self.matches()
    }
    /// Return (or the Erase button): accepts only an exact match.
    pub fn accept(&mut self) -> bool {
        if self.matches() {
            self.ok = true;
        }
        self.ok
    }
}

/// The password dialog's logic (`ask_password`): OK returns the text (an empty password is allowed), Cancel,
/// Escape and the close button return None.
#[derive(Clone, Debug, Default)]
pub struct PasswordEntry {
    pub text: String,
}

impl PasswordEntry {
    pub fn accept(&self) -> Option<String> {
        Some(self.text.clone())
    }
    pub fn cancel(&self) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // ---- tests/test_refactor_helpers.py: test_normalize_typed_identifier ----
    #[test]
    fn normalize_on_unix() {
        for (text, expected) in
            [("disk4", "disk4"), ("  /dev/disk4 \n", "disk4"), ("/dev/sdb", "sdb"), ("", ""), ("dev/sdb", "dev/sdb")]
        {
            assert_eq!(normalize_typed_identifier_for(text, false), expected, "{text:?}");
        }
    }

    // ---- tests/test_windows_backend.py: the typed identifier on Windows ----
    #[test]
    fn normalize_on_windows() {
        for typed in
            ["3", "disk 3", "Disk3", "DISK  3", "\\\\.\\PhysicalDrive3", " 3 ", "03", "\\\\.\\3", "PhysicalDrive3"]
        {
            assert_eq!(normalize_typed_identifier_for(typed, true), "PhysicalDrive3", "{typed:?}");
        }
        assert_eq!(normalize_typed_identifier_for("/dev/sdb", true), "/dev/sdb");
        assert_eq!(normalize_typed_identifier_for("PhysicalDrive3", true), "PhysicalDrive3");
        assert_eq!(normalize_typed_identifier_for("12345", true), "12345"); // more than 4 digits: not a drive number
    }

    // ---- tests/test_fixes_gui.py: TypedConfirmationTests ----
    #[test]
    fn typed_button_follows_every_kind_of_edit() {
        let mut dialog = TypedConfirm::new("disk9");
        dialog.windows = false;
        assert!(!dialog.erase_enabled());
        for (typed, enabled) in
            [("disk9", true), ("", false), ("/dev/disk9", true), ("disk90", false), ("  disk9  ", true)]
        {
            dialog.typed = typed.to_string();
            assert_eq!(dialog.erase_enabled(), enabled, "{typed:?}");
        }
        assert!(!dialog.ok);
    }

    #[test]
    fn typed_enter_cannot_slip_through() {
        let mut dialog = TypedConfirm::new("disk9");
        dialog.windows = false;
        dialog.typed = "disk8".into();
        assert!(!dialog.accept());
        assert!(!dialog.ok);
        dialog.typed = " /dev/disk9 ".into();
        assert!(dialog.accept());
        assert!(dialog.ok);
    }

    // ---- tests/test_refactor_helpers.py: ModalDialogTests ----
    #[test]
    fn password_ok_returns_the_text_and_cancel_returns_none() {
        let entry = PasswordEntry { text: "s3cret".into() };
        assert_eq!(entry.accept().as_deref(), Some("s3cret"));
        assert_eq!(entry.cancel(), None);
        assert_eq!(PasswordEntry::default().accept().as_deref(), Some(""));
    }

    // ---- the hub: a blocking ask is answered through the channel ----
    #[test]
    fn the_hub_blocks_until_the_window_answers_and_survives_a_dropped_request() {
        let queue: Arc<Mutex<Vec<DialogRequest>>> = Arc::default();
        let q = queue.clone();
        let hub = HubDialogs::new(Arc::new(move |r| q.lock().unwrap().push(r)));
        let h2 = hub.clone();
        let worker = std::thread::spawn(move || h2.ask_yes_no("Title", "Question?", true));
        loop {
            if let Some(request) = queue.lock().unwrap().pop() {
                assert_eq!(request.kind, DialogKind::Question { warning: true });
                assert_eq!(request.title, "Title");
                request.answer(DialogReply::Yes(true));
                break;
            }
            std::thread::yield_now();
        }
        assert!(worker.join().unwrap());

        // a request dropped without an answer (the window closed) is a "no"
        let q = queue.clone();
        let h3 = hub.clone();
        let worker = std::thread::spawn(move || Dialogs::ask_password(&h3, "T", "P"));
        loop {
            if let Some(request) = q.lock().unwrap().pop() {
                drop(request);
                break;
            }
            std::thread::yield_now();
        }
        assert_eq!(worker.join().unwrap(), None);
    }

    #[test]
    fn notifications_do_not_wait_and_carry_no_reply() {
        let queue: Arc<Mutex<Vec<DialogRequest>>> = Arc::default();
        let q = queue.clone();
        let hub = HubDialogs::new(Arc::new(move |r| q.lock().unwrap().push(r)));
        hub.show_info("Done", "ok");
        PasswordPrompt::show_error(&hub, "Wrong password", "x");
        let got = queue.lock().unwrap();
        assert_eq!(got.len(), 2);
        assert!(got.iter().all(|r| r.reply.is_none()));
        assert_eq!(got[0].kind, DialogKind::Info);
        assert_eq!(got[1].kind, DialogKind::Error);
    }
}
