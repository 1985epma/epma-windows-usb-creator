//! The state of the window's widgets, without any drawing (port of the logic of OptionCard, AccentButton, _Disclosure,
//! DriveList and its rows, _StepHeading, _FileCard, _Banner, _DownloadWidgets and friends, win11_usb_creator.py lines
//! 9187-10308). The egui layer (`view.rs`) draws from these, the tests drive them directly.

use super::tx::{dev_path, human_size, tr};
use crate::types::{Card, Disk, IsoKind, Mode, Volumes};

// ---------------------------------------------------------------------------------------------------------------
// Small pure helpers
// ---------------------------------------------------------------------------------------------------------------

/// `_image_label(mode, other)`: the window's name for what `mode` writes; `other` (already translated) names a
/// Linux or other ISO.
pub fn image_label(mode: Mode, other: &str) -> String {
    match mode {
        Mode::Windows => tr("Windows 11"),
        Mode::ChromeOs => tr("ChromeOS Flex"),
        _ => other.to_string(),
    }
}

/// `_shorten_middle(text, limit)`: `text` cut to at most `limit` characters by replacing the middle with an
/// ellipsis (the start and the end of a path or file name are the parts that identify it).
pub fn shorten_middle(text: &str, limit: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if limit < 5 || chars.len() <= limit {
        return text.to_string();
    }
    let keep = limit - 1;
    let head = keep / 2 + keep % 2;
    let tail = keep - head;
    let mut out: String = chars[..head].iter().collect();
    out.push('…');
    out.extend(chars[chars.len() - tail..].iter());
    out
}

/// `_DriveRow._fit`: `text` cut with an ellipsis so that it is at most `room` wide (`measure` gives the width).
pub fn fit_with_ellipsis(measure: &dyn Fn(&str) -> f32, text: &str, room: f32) -> String {
    if measure(text) <= room {
        return text.to_string();
    }
    let mut chars: Vec<char> = text.chars().collect();
    while !chars.is_empty() {
        let candidate: String = chars.iter().collect::<String>() + "…";
        if measure(&candidate) <= room {
            break;
        }
        chars.pop();
    }
    let kept: String = chars.iter().collect();
    format!("{}…", kept.trim_end())
}

/// `OptionCard._fit`: `(font size, text)` that fit inside `room`: the size shrinks down to 8 pt and, when the text
/// is still too wide at 8 pt, it is cut and ends with an ellipsis (it is never clipped silently by the card edge).
/// `measure(size, text)` is the width of `text` at that size.
pub fn fit_title(measure: &dyn Fn(f32, &str) -> f32, size: f32, text: &str, room: f32) -> (f32, String) {
    let mut size = size;
    while size > 8.0 && measure(size, text) > room {
        size -= 1.0;
    }
    if measure(size, text) <= room {
        return (size, text.to_string());
    }
    let chars: Vec<char> = text.chars().collect();
    let mut cut = chars.len();
    while cut > 0 {
        let candidate: String = chars[..cut].iter().collect::<String>().trim_end().to_string() + "…";
        if measure(size, &candidate) <= room {
            break;
        }
        cut -= 1;
    }
    let kept: String = chars[..cut].iter().collect();
    (size, format!("{}…", kept.trim_end()))
}

/// The height the window starts with and settles back to.
pub const MIN_WINDOW_HEIGHT: f32 = 700.0;
/// The size the window starts with.
pub const START_WINDOW_SIZE: (f32, f32) = (780.0, 700.0);

/// `App._fit_window`: the new window height, or `None` to leave it alone.
///
/// It grows when something appears (the checksum panel, the log, a result) and returns toward `MIN_WINDOW_HEIGHT`
/// when that goes away again, but only while the user has not resized the window by hand. Capped to the screen.
/// `last` is the height the program set last, `shown` the height the window has now (<= 1: not on screen yet),
/// `required` the height the content asks for.
pub fn fit_window_height(last: f32, shown: f32, required: f32, screen_height: f32) -> Option<f32> {
    let shown = if shown <= 1.0 { last } else { shown };
    let needed = MIN_WINDOW_HEIGHT.max(required).min((screen_height - 120.0).max(MIN_WINDOW_HEIGHT));
    let height = if needed > shown {
        needed
    } else if (shown - last).abs() <= 2.0 && needed < last {
        needed // still the size we set: settle back
    } else {
        return None; // the user made it taller than needed: leave it alone
    };
    if (height - last).abs() > f32::EPSILON {
        Some(height)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The drive list
// ---------------------------------------------------------------------------------------------------------------

/// `drive_row_texts(disk)`: the three texts of one row of the drive list: `(name, size, detail)`.
///
/// The name is the model (or the device path when the model is unknown), the size is human readable and the detail
/// is the device path plus a summary of the volumes on the drive. A record without a model, size or volume list (an
/// older one) still gives sensible text.
pub fn drive_row_texts(disk: &Disk) -> (String, String, String) {
    let dev = dev_path(&disk.id);
    let model = disk.model.as_deref().unwrap_or("").trim().to_string();
    let size = if disk.size > 0 { human_size(disk.size) } else { String::new() };
    let summary = match &disk.volumes {
        Volumes::NotInspected => String::new(),
        Volumes::Unknown => tr("contents unknown"),
        Volumes::List(list) if list.is_empty() => tr("no volumes"),
        Volumes::List(list) => {
            let mut names: Vec<String> = list
                .iter()
                .take(3)
                .map(|v| {
                    v.name
                        .as_deref()
                        .filter(|s| !s.is_empty())
                        .or(v.filesystem.as_deref().filter(|s| !s.is_empty()))
                        .map(str::to_string)
                        .unwrap_or_else(|| tr("(unnamed)"))
                })
                .collect();
            if list.len() > 3 {
                names.push("…".to_string());
            }
            let template = if list.len() == 1 { tr("1 volume ({names})") } else { tr("{count} volumes ({names})") };
            super::tx::format_template(
                &template,
                &[("count", list.len().into()), ("names", names.join(", ").into())],
            )
        }
    };
    let parts: Vec<String> = [if model.is_empty() { String::new() } else { dev.clone() }, summary]
        .into_iter()
        .filter(|p| !p.is_empty())
        .collect();
    let name = if model.is_empty() { dev } else { model };
    (name, size, parts.join(" · "))
}

/// What the drive list shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListView {
    Items,
    /// Two grey placeholder rows while the drives are being listed.
    Loading,
    /// The "No USB drive found" message.
    Empty,
}

/// The list of USB drives: one selectable row per drive (`DriveList`). `select` and the arrow keys report whether
/// the selection changed; `set_items` never counts as a choice of the user.
#[derive(Clone, Debug)]
pub struct DriveList {
    items: Vec<Disk>,
    selected: i64,
    enabled: bool,
    loading: bool,
    loaded: bool,
}

impl Default for DriveList {
    fn default() -> Self {
        DriveList { items: Vec::new(), selected: -1, enabled: true, loading: false, loaded: false }
    }
}

impl DriveList {
    pub const SKELETON_ROWS: usize = 2;

    /// Replace the drives; the selection stays on the drive with the same id, otherwise it moves to the first one.
    pub fn set_items(&mut self, items: &[Disk]) {
        let previous = self.selected_item().map(|d| d.id.clone());
        self.items = items.to_vec();
        self.loaded = true;
        self.selected = if self.items.is_empty() {
            -1
        } else {
            previous.and_then(|id| self.items.iter().position(|d| d.id == id)).unwrap_or(0) as i64
        };
    }
    pub fn items(&self) -> &[Disk] {
        &self.items
    }
    /// -1 for none.
    pub fn selected_index(&self) -> i64 {
        self.selected
    }
    pub fn selected_item(&self) -> Option<&Disk> {
        usize::try_from(self.selected).ok().and_then(|i| self.items.get(i))
    }
    /// Select row `index` (out of range clears the selection); true when the selection changed.
    pub fn select(&mut self, index: i64) -> bool {
        let index = if index >= 0 && (index as usize) < self.items.len() { index } else { -1 };
        if index == self.selected {
            return false;
        }
        self.selected = index;
        true
    }
    /// A click (or Space/Return) on row `row`: ignored while the list is locked.
    pub fn row_pressed(&mut self, row: usize) -> bool {
        if !self.enabled || row >= self.items.len() {
            return false;
        }
        self.select(row as i64)
    }
    /// Up/Down on row `row` (`step` is -1 or 1): moves the selection; true when it changed.
    pub fn row_arrow(&mut self, row: usize, step: i64) -> bool {
        if !self.enabled || row >= self.items.len() {
            return false;
        }
        let target = row as i64 + step;
        if target >= 0 && (target as usize) < self.items.len() {
            return self.select(target);
        }
        false
    }
    /// A disabled list greys out and ignores the mouse and the keyboard.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
    pub fn set_loading(&mut self, loading: bool) {
        self.loading = loading;
    }
    pub fn is_loading(&self) -> bool {
        self.loading
    }
    /// What is on screen: the rows, the placeholder rows or the "no drive" message.
    pub fn view_state(&self) -> ListView {
        if !self.items.is_empty() {
            ListView::Items
        } else if self.loading || !self.loaded {
            ListView::Loading
        } else {
            ListView::Empty
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The chosen image
// ---------------------------------------------------------------------------------------------------------------

/// `os.path.expanduser("~")`.
pub fn home_dir() -> Option<String> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var(var).ok().filter(|s| !s.is_empty())
}

/// The chosen image as a compact card (`_FileCard`): the file name, its folder (shortened in the middle), its size
/// and a badge with the kind that was detected. Until a file is chosen it shows only `empty_text`.
#[derive(Clone, Debug)]
pub struct FileCard {
    pub has_file: bool,
    /// The name label: the file name, or the empty text.
    pub label: String,
    pub folder: String,
    pub size: String,
    pub badge: String,
    pub kind: IsoKind,
    empty_text: String,
}

impl FileCard {
    pub fn new(empty_text: &str) -> Self {
        FileCard {
            has_file: false,
            label: empty_text.to_string(),
            folder: String::new(),
            size: String::new(),
            badge: String::new(),
            kind: IsoKind::Unknown,
            empty_text: empty_text.to_string(),
        }
    }
    pub fn clear(&mut self) {
        self.has_file = false;
        self.label = self.empty_text.clone();
        self.folder.clear();
        self.size.clear();
        self.badge.clear();
        self.kind = IsoKind::Unknown;
    }
    /// The name of a kind in the window (`kind_names`).
    pub fn kind_name(kind: IsoKind) -> String {
        match kind {
            IsoKind::Windows => tr("Windows 11"),
            IsoKind::Linux => tr("Linux"),
            IsoKind::ChromeOs => tr("ChromeOS Flex"),
            IsoKind::Unknown => tr("Unknown"),
        }
    }
    /// Show `path`; `size` is in bytes (None when it cannot be read).
    pub fn show(&mut self, path: &str, kind: IsoKind, size: Option<u64>) {
        self.has_file = true;
        let p = std::path::Path::new(path);
        let mut folder = p.parent().map(|d| d.to_string_lossy().into_owned()).unwrap_or_default();
        if let Some(home) = home_dir() {
            let sep = std::path::MAIN_SEPARATOR;
            if home != sep.to_string() && (folder == home || folder.starts_with(&format!("{home}{sep}"))) {
                folder = format!("~{}", &folder[home.len()..]);
            }
        }
        let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).filter(|n| !n.is_empty());
        self.label = shorten_middle(&name.unwrap_or_else(|| path.to_string()), 56);
        self.folder = shorten_middle(&folder, 64);
        self.size = size.map(human_size).unwrap_or_default();
        self.badge = Self::kind_name(kind);
        self.kind = kind;
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Progress bars, download cards, disclosure links, banners
// ---------------------------------------------------------------------------------------------------------------

/// What "Try again" repeats (the Python `retry` callbacks).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retry {
    Download,
    FlexDownload,
    RefreshDisks,
    InstallDependencies,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BarMode {
    Determinate,
    Indeterminate,
}

/// A progress bar (`ttk.Progressbar`): on screen only while `visible`.
#[derive(Clone, Copy, Debug)]
pub struct Bar {
    pub visible: bool,
    pub mode: BarMode,
    /// Percent, 0..=100 (determinate mode).
    pub value: f64,
    /// `start(12)` was called: the indeterminate bar moves.
    pub running: bool,
}

impl Default for Bar {
    fn default() -> Self {
        Bar { visible: false, mode: BarMode::Determinate, value: 0.0, running: false }
    }
}

impl Bar {
    pub fn config(&mut self, mode: Option<BarMode>, value: Option<f64>) {
        if let Some(m) = mode {
            self.mode = m;
        }
        if let Some(v) = value {
            self.value = v;
        }
    }
    pub fn start(&mut self) {
        self.running = true;
    }
    pub fn stop(&mut self) {
        self.running = false;
    }
}

/// The widgets of a download card (button, bar and its label) and the state changes the Windows ISO card and the
/// ChromeOS Flex card share (`_DownloadWidgets`). The bar is on screen only while it has something to show.
#[derive(Clone, Debug)]
pub struct DownloadWidgets {
    pub btn_enabled: bool,
    pub bar: Bar,
    pub label: String,
}

impl Default for DownloadWidgets {
    fn default() -> Self {
        DownloadWidgets { btn_enabled: true, bar: Bar::default(), label: String::new() }
    }
}

impl DownloadWidgets {
    /// Download off while a write (`creating`) or this card's own operation (`running`) is going.
    pub fn sync(&mut self, running: bool, creating: bool) {
        self.btn_enabled = !(creating || running);
    }
    pub fn hide_bar(&mut self) {
        self.bar.visible = false;
    }
    /// A new operation: an empty determinate bar (and `text` in the label, if given).
    pub fn start(&mut self, text: Option<&str>) {
        self.bar.visible = true;
        self.bar.config(Some(BarMode::Determinate), Some(0.0));
        if let Some(t) = text {
            self.label = t.to_string();
        }
    }
    /// Progress: `pct` percent on the bar, or None when the length is unknown (a moving bar).
    pub fn show(&mut self, pct: Option<f64>, text: &str) {
        self.bar.visible = true;
        match pct {
            None => self.bar.config(Some(BarMode::Indeterminate), None),
            Some(p) => self.bar.config(Some(BarMode::Determinate), Some(p)),
        }
        self.label = text.to_string();
    }
    /// The operation ended (done or failed): the final `text`, and the bar set to `bar_value` if given (a bar left
    /// empty is hidden).
    pub fn finish(&mut self, text: &str, bar_value: Option<f64>) {
        if let Some(v) = bar_value {
            self.bar.config(Some(BarMode::Determinate), Some(v));
            self.bar.visible = v != 0.0;
        }
        self.label = text.to_string();
    }
}

/// A link-like row that opens and closes a section: "▸ Show details" / "▾ Hide details" (`_Disclosure`).
#[derive(Clone, Debug)]
pub struct Disclosure {
    closed_text: String,
    open_text: String,
    pub is_open: bool,
}

impl Disclosure {
    pub fn new(closed_text: &str, open_text: &str) -> Self {
        Disclosure { closed_text: closed_text.to_string(), open_text: open_text.to_string(), is_open: false }
    }
    /// The text of the link now.
    pub fn text(&self) -> String {
        if self.is_open {
            format!("▾ {}", self.open_text)
        } else {
            format!("▸ {}", self.closed_text)
        }
    }
    /// Set the state; true when it changed (the owner reacts to the change).
    pub fn set_open(&mut self, value: bool) -> bool {
        if value != self.is_open {
            self.is_open = value;
            return true;
        }
        false
    }
    pub fn toggle(&mut self) -> bool {
        let v = !self.is_open;
        self.set_open(v)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BannerKind {
    Error,
    Success,
    Warning,
}

impl BannerKind {
    /// The border and title colour (RGB).
    pub fn color(self) -> (u8, u8, u8) {
        match self {
            BannerKind::Error => (0xe5, 0x53, 0x4b),
            BannerKind::Success => (0x2e, 0xa0, 0x43),
            BannerKind::Warning => (0xff, 0x9f, 0x0a),
        }
    }
}

/// What a link of a banner does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkAction {
    Retry(Retry),
    MakeAnother,
}

#[derive(Clone, Debug)]
pub struct BannerLink {
    pub text: String,
    /// `None` for "Dismiss".
    pub action: Option<LinkAction>,
}

/// An inline message box with a soft coloured border: a failure ("error"), a finished write ("success") or something
/// that needs attention ("warning"). It holds a title, the message and links, and takes no space until shown.
#[derive(Clone, Debug)]
pub struct Banner {
    pub kind: BannerKind,
    pub shown: bool,
    pub title_text: String,
    pub message_text: String,
    pub links: Vec<BannerLink>,
}

impl Banner {
    pub fn new(kind: BannerKind) -> Self {
        Banner { kind, shown: false, title_text: String::new(), message_text: String::new(), links: Vec::new() }
    }
    /// Show the box. `actions` are `(text, action)` links; each one closes the box first. `dismiss` adds the
    /// "Dismiss" link. `kind` changes the colour (default: the one it was made with).
    pub fn show(
        &mut self,
        title: &str,
        message: &str,
        actions: Vec<(String, LinkAction)>,
        dismiss: bool,
        kind: Option<BannerKind>,
    ) {
        self.kind = kind.unwrap_or(self.kind);
        self.title_text = title.to_string();
        self.message_text = message.to_string();
        self.links = actions.into_iter().map(|(text, a)| BannerLink { text, action: Some(a) }).collect();
        if dismiss {
            self.links.push(BannerLink { text: tr("Dismiss"), action: None });
        }
        self.shown = true;
    }
    pub fn clear(&mut self) {
        self.shown = false;
        self.title_text.clear();
        self.message_text.clear();
    }
    pub fn link_texts(&self) -> Vec<String> {
        self.links.iter().map(|l| l.text.clone()).collect()
    }
    /// A click on link `index`: the box closes first; the action (if any) is returned for the caller to run.
    pub fn click(&mut self, index: usize) -> Option<LinkAction> {
        let action = self.links.get(index).and_then(|l| l.action);
        self.clear();
        action
    }
}

/// The colour of a result line of the checksum panel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Normal,
    Red,
    Green,
}

/// The "Verify the selected ISO (SHA-256)" panel (`iso_check_frame` and its children).
#[derive(Clone, Debug)]
pub struct ShaPanel {
    pub entry: String,
    pub btn_enabled: bool,
    pub bar: Bar,
    pub label: String,
    pub result: String,
    pub result_tone: Tone,
}

impl Default for ShaPanel {
    fn default() -> Self {
        ShaPanel {
            entry: String::new(),
            btn_enabled: true,
            bar: Bar::default(),
            label: String::new(),
            result: String::new(),
            result_tone: Tone::Normal,
        }
    }
}

/// The five cards, with the strings of their titles and subtitles (the order of `Card::ORDER`).
pub fn card_texts(card: Card) -> (String, String) {
    match card {
        Card::Chrome => (tr("Google Chrome"), tr("ChromeOS Flex")),
        Card::Windows => (tr("Windows 11"), tr("Copies the files")),
        Card::Linux => (tr("Linux"), tr("Ubuntu, Fedora...")),
        Card::Other => (tr("Other ISO"), tr("Any bootable image")),
        Card::Seed => (tr("Hardening seed"), tr("Second USB drive")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Volume, Volumes};

    const GB: u64 = 1000 * 1000 * 1000;

    fn drive(id: &str, model: &str, size: u64, volumes: Vec<Volume>) -> Disk {
        Disk {
            id: id.into(),
            size,
            label: format!("/dev/{id}"),
            model: Some(model.into()),
            volumes: Volumes::List(volumes),
            identity: vec![],
        }
    }
    fn vol(name: &str, fs: Option<&str>) -> Volume {
        Volume {
            name: if name.is_empty() { None } else { Some(name.into()) },
            filesystem: fs.map(String::from),
            ..Default::default()
        }
    }

    // ---- tests/test_drive_list.py: RowTextTests ----
    #[test]
    fn row_model_size_device_and_volumes() {
        let d = drive("disk4", "SanDisk Ultra", 32 * GB, vec![vol("Untitled", Some("FAT32"))]);
        let (name, size, detail) = drive_row_texts(&d);
        assert_eq!(name, "SanDisk Ultra");
        assert_eq!(size, "29.8 GB");
        assert_eq!(detail, "/dev/disk4 · 1 volume (Untitled)");
    }

    #[test]
    fn row_several_volumes_are_summarised() {
        let vols: Vec<Volume> = ["A", "B", "C", "D"].iter().map(|n| vol(n, None)).collect();
        assert_eq!(drive_row_texts(&drive("sdb", "SanDisk Ultra", 32 * GB, vols)).2, "/dev/sdb · 4 volumes (A, B, C, …)");
    }

    #[test]
    fn row_no_volumes_and_unknown_contents() {
        assert_eq!(drive_row_texts(&drive("sdb", "SanDisk Ultra", 32 * GB, vec![])).2, "/dev/sdb · no volumes");
        let mut d = drive("sdb", "SanDisk Ultra", 32 * GB, vec![]);
        d.volumes = Volumes::Unknown;
        assert_eq!(drive_row_texts(&d).2, "/dev/sdb · contents unknown");
    }

    #[test]
    fn row_without_a_model_the_device_is_the_name() {
        let (name, _size, detail) = drive_row_texts(&drive("sdb", "", 32 * GB, vec![]));
        assert_eq!(name, "/dev/sdb");
        assert_eq!(detail, "no volumes");
    }

    #[test]
    fn row_an_old_record_without_model_size_or_volumes_still_works() {
        let d = Disk { id: "disk9".into(), label: "x".into(), ..Default::default() };
        assert_eq!(drive_row_texts(&d), ("/dev/disk9".to_string(), String::new(), String::new()));
    }

    #[test]
    fn row_unnamed_volume_falls_back_to_the_filesystem_then_the_placeholder() {
        let d = drive("sdb", "M", 32 * GB, vec![vol("", Some("ext4")), vol("", None)]);
        assert_eq!(drive_row_texts(&d).2, "/dev/sdb · 2 volumes (ext4, (unnamed))");
    }

    #[test]
    fn row_texts_are_translated() {
        crate::gui::tx::set_test_language("pt");
        let text = drive_row_texts(&drive("sdb", "SanDisk Ultra", 32 * GB, vec![])).2;
        crate::gui::tx::set_test_language("en");
        assert_eq!(text, "/dev/sdb · sem volumes");
    }

    // ---- DriveList (tests/test_drive_list.py: ModelTests, WriteLockTests, PlaceholderTests, KeyboardTests) ----
    fn first() -> Disk {
        drive("disk4", "SanDisk Ultra", 32 * GB, vec![vol("Untitled", Some("FAT32"))])
    }
    fn second() -> Disk {
        drive("disk5", "Kingston", 64 * GB, vec![])
    }

    #[test]
    fn list_one_row_per_drive_and_the_first_is_selected() {
        let mut list = DriveList::default();
        list.set_items(&[first(), second()]);
        assert_eq!(list.view_state(), ListView::Items);
        assert_eq!(list.items().len(), 2);
        assert_eq!(list.selected_index(), 0);
        assert_eq!(list.selected_item().map(|d| d.id.as_str()), Some("disk4"));
    }

    #[test]
    fn list_select_reports_only_changes_and_out_of_range_clears() {
        let mut list = DriveList::default();
        list.set_items(&[first(), second()]);
        assert!(!list.select(0));
        assert!(list.select(1));
        assert!(list.select(99));
        assert_eq!(list.selected_index(), -1);
        assert!(list.selected_item().is_none());
    }

    #[test]
    fn list_the_selection_stays_on_the_same_drive_by_id() {
        let mut list = DriveList::default();
        list.set_items(&[first(), second()]);
        list.select(1);
        list.set_items(&[second(), first()]);
        assert_eq!(list.selected_item().map(|d| d.id.as_str()), Some("disk5"));
        assert_eq!(list.selected_index(), 0);
        let mut renamed = second();
        renamed.model = Some("Kingston DataTraveler".into());
        list.set_items(&[renamed, first()]);
        assert_eq!(list.selected_item().map(|d| d.id.as_str()), Some("disk5"));
    }

    #[test]
    fn list_goes_to_the_first_drive_when_the_chosen_one_is_gone_and_clears_when_empty() {
        let mut list = DriveList::default();
        list.set_items(&[first(), second()]);
        list.select(1);
        list.set_items(&[first()]);
        assert_eq!(list.selected_item().map(|d| d.id.as_str()), Some("disk4"));
        list.set_items(&[]);
        assert!(list.selected_item().is_none());
        assert_eq!(list.selected_index(), -1);
        assert!(list.items().is_empty());
    }

    #[test]
    fn list_a_locked_list_ignores_clicks_and_the_keyboard() {
        let mut list = DriveList::default();
        list.set_items(&[first(), second()]);
        list.set_enabled(false);
        assert!(!list.row_pressed(1));
        assert!(!list.row_arrow(0, 1));
        assert_eq!(list.selected_index(), 0);
        list.set_enabled(true);
        assert!(list.row_pressed(1));
        assert_eq!(list.selected_index(), 1);
    }

    #[test]
    fn list_arrows_move_the_selection_and_stop_at_the_ends() {
        let mut list = DriveList::default();
        list.set_items(&[first(), second()]);
        assert!(list.row_arrow(0, 1));
        assert_eq!(list.selected_index(), 1);
        assert!(!list.row_arrow(1, 1));
        assert_eq!(list.selected_index(), 1);
        assert!(list.row_arrow(1, -1));
        assert_eq!(list.selected_index(), 0);
    }

    #[test]
    fn list_view_states() {
        let mut list = DriveList::default();
        assert_eq!(list.view_state(), ListView::Loading); // nothing listed yet
        list.set_items(&[]);
        assert_eq!(list.view_state(), ListView::Empty);
        list.set_loading(true);
        assert_eq!(list.view_state(), ListView::Loading);
        assert!(list.is_loading());
        list.set_items(&[first()]);
        assert_eq!(list.view_state(), ListView::Items); // rows stay while a refresh runs
        list.set_loading(false);
        list.set_items(&[]);
        assert_eq!(list.view_state(), ListView::Empty);
        assert_eq!(DriveList::SKELETON_ROWS, 2);
    }

    // ---- tests/test_fixes_gui.py: ShortenMiddleTests ----
    #[test]
    fn shorten_middle_short_text_is_unchanged() {
        assert_eq!(shorten_middle("abc", 10), "abc");
        assert_eq!(shorten_middle(&"a".repeat(10), 10), "a".repeat(10));
    }

    #[test]
    fn shorten_middle_keeps_both_ends_and_the_limit() {
        for limit in [5usize, 6, 11, 20, 64] {
            let text = format!("/Users/someone/{}/Downloads/ubuntu.iso", "x".repeat(100));
            let short = shorten_middle(&text, limit);
            assert_eq!(short.chars().count(), limit, "limit {limit}");
            assert!(short.contains('…'));
            assert!(short.starts_with(&text[..2]) && short.ends_with(&text[text.len() - 2..]));
        }
    }

    // ---- the file card (tests/test_fixes_gui.py: StepLayoutTests) ----
    #[test]
    fn file_card_empty_state_then_chosen_then_cleared() {
        let mut card = FileCard::new("No ISO selected yet.");
        assert!(!card.has_file);
        assert_eq!(card.label, "No ISO selected yet.");
        card.show("/tmp/some/dir/ubuntu-24.04.iso", IsoKind::Linux, Some(2 * 1024 * 1024));
        assert!(card.has_file);
        assert_eq!(card.label, "ubuntu-24.04.iso");
        assert_eq!(card.folder, "/tmp/some/dir");
        assert_eq!(card.size, "2.0 MB");
        assert_eq!(card.badge, "Linux");
        card.show("/tmp/missing.iso", IsoKind::Unknown, None);
        assert_eq!(card.size, "");
        assert_eq!(card.badge, "Unknown");
        card.show("/tmp/flex.bin", IsoKind::ChromeOs, Some(1));
        assert_eq!(card.badge, "ChromeOS Flex");
        card.show("/tmp/w.iso", IsoKind::Windows, Some(1));
        assert_eq!(card.badge, "Windows 11");
        card.clear();
        assert!(!card.has_file);
        assert_eq!(card.label, "No ISO selected yet.");
        assert!(card.badge.is_empty());
    }

    // ---- _DownloadWidgets (tests/test_refactor_helpers.py: DownloadWidgetsTests, QuietLayoutTests) ----
    #[test]
    fn download_widgets_sync_locks_the_button_while_something_runs() {
        let mut w = DownloadWidgets::default();
        for (running, creating, enabled) in [(false, false, true), (true, false, false), (false, true, false), (true, true, false)] {
            w.sync(running, creating);
            assert_eq!(w.btn_enabled, enabled);
        }
    }

    #[test]
    fn download_widgets_start_show_finish() {
        let mut w = DownloadWidgets::default();
        w.start(None);
        assert!(w.bar.visible && w.bar.mode == BarMode::Determinate && w.bar.value == 0.0);
        assert_eq!(w.label, "");
        w.start(Some("Extracting..."));
        assert_eq!(w.label, "Extracting...");
        w.show(Some(42.5), "42%");
        assert_eq!((w.bar.mode, w.bar.value, w.label.as_str()), (BarMode::Determinate, 42.5, "42%"));
        w.show(None, "12 MB");
        assert_eq!((w.bar.mode, w.label.as_str()), (BarMode::Indeterminate, "12 MB"));
        let before = w.bar;
        w.finish("Download failed.", None);
        assert_eq!((w.bar.visible, w.bar.mode, w.bar.value), (before.visible, before.mode, before.value));
        assert_eq!(w.label, "Download failed.");
        w.finish("Ready.", Some(100.0));
        assert_eq!((w.bar.mode, w.bar.value, w.label.as_str()), (BarMode::Determinate, 100.0, "Ready."));
    }

    #[test]
    fn download_widgets_the_bar_is_on_screen_only_while_it_has_something_to_show() {
        let mut w = DownloadWidgets::default();
        assert!(!w.bar.visible);
        w.start(None);
        assert!(w.bar.visible);
        w.finish("Failed.", Some(0.0));
        assert!(!w.bar.visible);
        w.finish("Ready.", Some(100.0));
        assert!(w.bar.visible);
        w.hide_bar();
        assert!(!w.bar.visible);
    }

    // ---- disclosure ----
    #[test]
    fn disclosure_text_and_toggle() {
        let mut d = Disclosure::new("Show details", "Hide details");
        assert_eq!(d.text(), "▸ Show details");
        assert!(d.toggle());
        assert_eq!(d.text(), "▾ Hide details");
        assert!(!d.set_open(true)); // no change, no reaction
        assert!(d.set_open(false));
        assert!(!d.is_open);
    }

    // ---- banner ----
    #[test]
    fn banner_is_lazy_has_links_and_runs_the_action_after_closing() {
        let mut b = Banner::new(BannerKind::Error);
        assert!(!b.shown);
        b.show("Error", "x", vec![("Try again".into(), LinkAction::Retry(Retry::Download))], true, None);
        assert!(b.shown);
        assert_eq!(b.link_texts(), vec!["Try again", "Dismiss"]);
        assert_eq!(b.click(0), Some(LinkAction::Retry(Retry::Download)));
        assert!(!b.shown);
        assert_eq!(b.message_text, "");
        b.show("Error", "no retry here", vec![], true, None);
        assert_eq!(b.link_texts(), vec!["Dismiss"]);
        assert_eq!(b.click(0), None);
        assert!(!b.shown);
    }

    #[test]
    fn banner_kind_can_change_when_shown() {
        let mut b = Banner::new(BannerKind::Success);
        b.show("t", "m", vec![("Make another".into(), LinkAction::MakeAnother)], false, Some(BannerKind::Warning));
        assert_eq!(b.kind, BannerKind::Warning);
        assert_eq!(b.link_texts(), vec!["Make another"]);
    }

    // ---- window growth (tests/test_fixes_gui.py: test_the_window_grows_and_settles_back) ----
    #[test]
    fn the_window_grows_and_settles_back() {
        let min = MIN_WINDOW_HEIGHT;
        let screen = 4000.0;
        // a small page: the usual height, not smaller
        let mut last = min;
        assert_eq!(fit_window_height(last, last, min - 100.0, screen), None);
        // content grows
        let grown = fit_window_height(last, last, min + 150.0, screen);
        assert_eq!(grown, Some(min + 150.0));
        last = min + 150.0;
        // and shrinks back to the usual height, not smaller
        assert_eq!(fit_window_height(last, last, min - 100.0, screen), Some(min));
        last = min;
        // the user made it taller by hand: the content shrinking must not take that away
        let last2 = min + 150.0;
        assert_eq!(fit_window_height(last2, min + 400.0, min, screen), None);
        // capped to the screen
        assert_eq!(fit_window_height(min, min, 5000.0, 900.0), Some(780.0));
        // not on screen yet: the size that was asked for is all there is
        assert_eq!(fit_window_height(min, 0.0, min, screen), None);
        let _ = last;
    }

    // ---- fitting texts ----
    fn mono(size: f32, text: &str) -> f32 {
        text.chars().count() as f32 * size * 0.6
    }

    #[test]
    fn a_long_title_shrinks_to_fit_then_is_cut_with_an_ellipsis() {
        let m: &dyn Fn(f32, &str) -> f32 = &mono;
        let (size, shown) = fit_title(m, 14.0, "Hardening seed", 96.0 - 16.0);
        assert!(size < 14.0 && size >= 8.0, "{size}");
        assert_eq!(shown, "Hardening seed");
        let (size, shown) = fit_title(m, 14.0, "Hardening seed", 300.0);
        assert_eq!(size, 14.0);
        assert_eq!(shown, "Hardening seed");
        let long = "Härtungsunterstützungsdatenträger-Erstellungsassistent";
        let (size, shown) = fit_title(m, 14.0, long, 780.0 / 5.0 - 12.0 - 16.0);
        assert_eq!(size, 8.0);
        assert!(shown.ends_with('…'));
        assert!(shown.chars().count() < long.chars().count());
        assert!(long.starts_with(&shown[..shown.len() - '…'.len_utf8()]));
        assert!(mono(size, &shown) <= 780.0 / 5.0 - 12.0 - 16.0);
    }

    #[test]
    fn ellipsis_fit_for_the_drive_rows() {
        let m = |t: &str| t.chars().count() as f32 * 7.0;
        assert_eq!(fit_with_ellipsis(&m, "short", 100.0), "short");
        let cut = fit_with_ellipsis(&m, "a very long drive name indeed", 100.0);
        assert!(cut.ends_with('…') && m(&cut) <= 100.0, "{cut}");
    }

    #[test]
    fn image_label_names_what_is_written() {
        assert_eq!(image_label(Mode::Windows, "x"), "Windows 11");
        assert_eq!(image_label(Mode::ChromeOs, "x"), "ChromeOS Flex");
        assert_eq!(image_label(Mode::Linux, "the selected Linux image"), "the selected Linux image");
    }

    #[test]
    fn card_texts_match_the_design() {
        assert_eq!(card_texts(Card::Seed), ("Hardening seed".to_string(), "Second USB drive".to_string()));
        assert_eq!(card_texts(Card::Chrome).0, "Google Chrome");
    }
}
