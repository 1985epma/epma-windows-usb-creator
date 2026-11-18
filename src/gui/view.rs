//! The egui drawing of the window (feature `gui`): the five cards, the three numbered steps, the Create button, the
//! banners, the log, the dialogs and the help window. It only draws `AppState` and forwards clicks to it; every rule
//! lives in `model.rs`. Port of the widget classes and `_build_*` methods of win11_usb_creator.py (lines 9532-10325,
//! 10369-10793).

use super::backend::RealBackend;
use super::dialogs::{DialogKind, DialogReply, DialogRequest, HubDialogs, TypedConfirm};
use super::model::{AppState, BannerId, Deps};
use super::shared::{Spawner, UiMsg};
use super::texts;
use super::tx::{tr, trf};
use super::widgets::{
    card_texts, drive_row_texts, fit_title, fit_with_ellipsis, Banner, Bar, BarMode, Disclosure, ListView, Tone,
};
use crate::constants::{
    APP_NAME, CHROMEOS_FLEX_GUIDE_URL, CHROMEOS_FLEX_REQUIREMENTS_URL, LOG_FLUSH_MS, PANEL_WRAP, VERSION,
};
use crate::types::{Card, Privilege};
use eframe::egui::{
    self, pos2, vec2, Align, Align2, Color32, CornerRadius, CursorIcon, FontId, Key, Layout, Margin, Modifiers, Rect,
    RichText, Sense, Stroke, StrokeKind, Ui,
};
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::time::Duration;

const ACCENT: Color32 = Color32::from_rgb(0x0a, 0x84, 0xff);
const ACCENT_HOVER: Color32 = Color32::from_rgb(0x40, 0x9c, 0xff);
const MUTED: Color32 = Color32::from_rgb(0x8e, 0x8e, 0x93);
const LINK: Color32 = Color32::from_rgb(0x4d, 0xa3, 0xff);
const GREEN: Color32 = Color32::from_rgb(0x2e, 0xa0, 0x43);
const AMBER: Color32 = Color32::from_rgb(0xff, 0x9f, 0x0a);
const RED: Color32 = Color32::from_rgb(0xc6, 0x28, 0x28);
const OK_GREEN: Color32 = Color32::from_rgb(0x1a, 0x7f, 0x37);
const BORDER: Color32 = Color32::from_rgb(0x6e, 0x6e, 0x73);
const BORDER_HOT: Color32 = Color32::from_rgb(0xa0, 0xa0, 0xa8);
const CARD_HEIGHT: f32 = 124.0;
const CARD_GAP: f32 = 12.0;
const ROW_HEIGHT: f32 = 58.0;

/// Open the window and block until it closes. Returns the process exit code.
pub fn run() -> i32 {
    super::set_macos_app_name(APP_NAME);
    let (w, h) = super::widgets::START_WINDOW_SIZE;
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("EPMA USB CREATOR")
            .with_app_id(APP_NAME)
            .with_inner_size([w, h])
            .with_min_inner_size([520.0, 420.0]),
        ..Default::default()
    };
    let result = eframe::run_native(
        "EPMA USB CREATOR",
        options,
        Box::new(|cc| Ok(Box::new(EpmaApp::new(&cc.egui_ctx)) as Box<dyn eframe::App>)),
    );
    match result {
        Ok(()) => crate::cli::EXIT_OK,
        Err(e) => {
            eprintln!("The window could not be opened: {e}");
            crate::cli::EXIT_ERROR
        }
    }
}

/// The application: the state plus what only the drawing needs.
pub struct EpmaApp {
    pub state: AppState,
    allowed_to_close: bool,
    was_focused: bool,
    started: bool,
    startup_refresh_at: Option<f64>,
    dialog_focused: bool,
}

impl EpmaApp {
    /// The real window: real backend, real privilege helper, dialogs through the window's own queue.
    pub fn new(ctx: &egui::Context) -> EpmaApp {
        let (tx, rx) = channel::<UiMsg>();
        let wake = ctx.clone();
        let notify: Arc<dyn Fn() + Send + Sync> = Arc::new(move || wake.request_repaint());
        let hub = {
            let tx = tx.clone();
            let notify = notify.clone();
            HubDialogs::new(Arc::new(move |request: DialogRequest| {
                let _ = tx.send(UiMsg::Dialog(request));
                notify();
            }))
        };
        let priv_: Arc<dyn Privilege> = if cfg!(windows) {
            Arc::new(crate::privilege::WindowsPrivilege)
        } else {
            Arc::new(crate::privilege::PrivilegeHelper::new(Arc::new(hub.clone())))
        };
        let start = std::time::Instant::now();
        let deps = Deps {
            backend: Arc::new(RealBackend),
            dialogs: Arc::new(hub),
            priv_,
            notify,
            clock: Arc::new(move || 1000.0 + start.elapsed().as_secs_f64()),
            spawner: Spawner::Threads,
        };
        EpmaApp::with_state(AppState::with_channel(deps, tx, rx))
    }

    /// A window around an existing state (tests).
    pub fn with_state(state: AppState) -> EpmaApp {
        EpmaApp {
            state,
            allowed_to_close: false,
            was_focused: false,
            started: false,
            startup_refresh_at: None,
            dialog_focused: false,
        }
    }

    // ------------------------------------------------------------------------------------------------------
    // One frame
    // ------------------------------------------------------------------------------------------------------
    pub fn draw(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        self.state.pump();
        self.viewport_events(&ctx);
        if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::F1)) {
            self.state.show_help(0);
        }
        egui::Panel::top("epma_menu").show(ui, |ui| self.menu_bar(ui));
        egui::CentralPanel::default().show(ui, |ui| {
            let output = egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                egui::Frame::new().inner_margin(Margin::symmetric(14, 12)).show(ui, |ui| self.page(ui));
            });
            self.fit_window(&ctx, output.content_size.y, output.inner_rect.height());
        });
        self.show_dialogs(&ctx);
        self.help_window(&ctx);
        self.schedule_repaints(&ctx);
    }

    /// The close button, the first automatic refresh and the one on regaining focus.
    fn viewport_events(&mut self, ctx: &egui::Context) {
        if ctx.input(|i| i.viewport().close_requested()) && !self.allowed_to_close {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.state.request_close();
        }
        if self.state.destroy_requested && !self.allowed_to_close {
            self.allowed_to_close = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        if !self.started {
            self.started = true;
            self.startup_refresh_at = Some(self.state.now() + 0.3);
        }
        if let Some(at) = self.startup_refresh_at {
            if self.state.now() >= at {
                self.startup_refresh_at = None;
                self.state.auto_refresh_disks();
            } else {
                ctx.request_repaint_after(Duration::from_millis(300));
            }
        }
        let focused = ctx.input(|i| i.viewport().focused).unwrap_or(false);
        if focused && !self.was_focused && self.startup_refresh_at.is_none() {
            self.state.auto_refresh_disks(); // the window got focus again: look for newly plugged drives
        }
        self.was_focused = focused;
    }

    /// `_fit_window`: grow the window when the content needs more room, settle back when it goes away.
    fn fit_window(&mut self, ctx: &egui::Context, content_height: f32, visible_height: f32) {
        let (shown, monitor) = ctx.input(|i| {
            let v = i.viewport();
            (v.inner_rect.map(|r| r.height()), v.monitor_size.map(|s| s.y))
        });
        let (Some(shown), Some(screen)) = (shown, monitor) else { return };
        let chrome = (shown - visible_height).max(0.0);
        if let Some(height) = self.state.fit_window(shown, content_height + chrome, screen) {
            let width = ctx.input(|i| i.viewport().inner_rect.map(|r| r.width())).unwrap_or(self.state.window_size.0);
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(vec2(width, height)));
        }
    }

    fn schedule_repaints(&self, ctx: &egui::Context) {
        let s = &self.state;
        let animating = [&s.windows_dl.bar, &s.flex_dl.bar, &s.create_progress, &s.sha.bar]
            .iter()
            .any(|b| b.visible && (b.mode == BarMode::Indeterminate || b.running));
        let busy = s.creating || s.download_running || s.flex_busy || s.installing || s.disk_listing;
        if animating {
            ctx.request_repaint_after(Duration::from_millis(33));
        } else if busy {
            ctx.request_repaint_after(Duration::from_millis(LOG_FLUSH_MS));
        }
    }

    // ------------------------------------------------------------------------------------------------------
    // Menu
    // ------------------------------------------------------------------------------------------------------
    fn menu_bar(&mut self, ui: &mut Ui) {
        egui::MenuBar::new().ui(ui, |ui| {
            ui.menu_button(tr("Help"), |ui| {
                if ui.add(egui::Button::new(tr("EPMA USB CREATOR Help")).shortcut_text("F1")).clicked() {
                    self.state.show_help(0);
                }
                ui.separator();
                if ui.button(tr("Open the audit log folder")).clicked() {
                    self.state.open_audit_log_folder();
                }
                if ui.button(tr("Project page (GitHub)")).clicked() {
                    self.state.open_project_page();
                }
                // On macOS Tk put "About" in the application menu; eframe has no native menu, so it lives here too.
                ui.separator();
                if ui.button(tr("About EPMA USB CREATOR")).clicked() {
                    self.state.show_about();
                }
            });
        });
    }

    // ------------------------------------------------------------------------------------------------------
    // The page: header, 1 Image type, 2 Image, 3 USB drive, Create
    // ------------------------------------------------------------------------------------------------------
    fn page(&mut self, ui: &mut Ui) {
        self.header(ui);
        step_heading(ui, 1, &self.state.step_title(1));
        ui.add_space(6.0);
        self.cards(ui);
        ui.add_space(10.0);
        step_heading(ui, 2, &self.state.step_title(2));
        ui.add_space(6.0);
        self.source_panel(ui);
        if !self.state.image_block_hidden() {
            self.image_block(ui);
        }
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(4.0);
        step_heading(ui, 3, &self.state.step_title(3));
        ui.add_space(6.0);
        self.drive_section(ui);
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);
        self.create_section(ui);
    }

    fn header(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("EPMA USB CREATOR").strong().size(15.0));
            ui.label(RichText::new(format!("v{VERSION}")).color(MUTED));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if link(ui, &tr("Help")).clicked() {
                    self.state.show_help(0);
                }
                let (text, ready) = self.state.dep_chip();
                ui.add_space(8.0);
                ui.label(RichText::new(text).color(if ready { GREEN } else { AMBER }));
                if !self.state.dep_missing.is_empty() {
                    let enabled = self.state.controls.install_enabled;
                    if ui.add_enabled(enabled, egui::Button::new(tr("Install missing dependencies"))).clicked() {
                        self.state.install_dependencies();
                    }
                }
            });
        });
        ui.add_space(8.0);
    }

    fn cards(&mut self, ui: &mut Ui) {
        let available = ui.available_width();
        let width = ((available - 4.0 * CARD_GAP) / 5.0).max(40.0);
        let enabled = self.state.controls.cards_enabled;
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = CARD_GAP;
            for card in Card::ORDER {
                let response = option_card(ui, card, width, card == self.state.card, enabled);
                if response.clicked() {
                    self.state.select_card(card);
                }
            }
        });
    }

    // ------------------------------------------------------------------------------------------------------
    // The source panel of the chosen card
    // ------------------------------------------------------------------------------------------------------
    fn source_panel(&mut self, ui: &mut Ui) {
        let card = self.state.card;
        wrapped(ui, &texts::panel_text(card), PANEL_WRAP as f32, None);
        match card {
            Card::Chrome => self.chrome_panel(ui),
            Card::Windows => self.windows_panel(ui),
            Card::Seed => self.seed_panel(ui),
            Card::Linux | Card::Other => {}
        }
    }

    fn chrome_panel(&mut self, ui: &mut Ui) {
        ui.add_space(6.0);
        let enabled = self.state.flex_dl.btn_enabled;
        if ui.add_enabled(enabled, egui::Button::new(tr("Download ChromeOS Flex from Google"))).clicked() {
            self.state.start_flex_download();
        }
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui.button(tr("Google's installation guide")).clicked() {
                self.state.open_url(CHROMEOS_FLEX_GUIDE_URL);
            }
            if ui.button(tr("Google's requirements page")).clicked() {
                self.state.open_url(CHROMEOS_FLEX_REQUIREMENTS_URL);
            }
        });
        download_progress(ui, &self.state.flex_dl.bar, &self.state.flex_dl.label);
    }

    fn windows_panel(&mut self, ui: &mut Ui) {
        ui.add_space(6.0);
        let entry_width = (ui.available_width() - 210.0).max(120.0);
        egui::Grid::new("epma_windows_grid").num_columns(2).min_col_width(190.0).spacing([8.0, 4.0]).show(ui, |ui| {
            ui.label(tr("Direct ISO link (HTTPS only):"));
            ui.add(egui::TextEdit::singleline(&mut self.state.url_entry).desired_width(entry_width));
            ui.end_row();
            ui.label(tr("Expected SHA-256 (optional):"));
            ui.add(egui::TextEdit::singleline(&mut self.state.sha_entry).desired_width(entry_width));
            ui.end_row();
        });
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui.button(tr("Open Microsoft's official page")).clicked() {
                self.state.open_ms_page();
            }
            ui.add_space(8.0);
            let enabled = self.state.windows_dl.btn_enabled;
            if ui.add_enabled(enabled, egui::Button::new(tr("Download ISO"))).clicked() {
                self.state.start_download();
            }
        });
        self.hardening_option(ui);
        download_progress(ui, &self.state.windows_dl.bar, &self.state.windows_dl.label);
    }

    /// The optional hardening checkbox of the Windows 11 card.
    fn hardening_option(&mut self, ui: &mut Ui) {
        ui.add_space(10.0);
        let enabled = self.state.controls.hardening_enabled;
        ui.add_enabled_ui(enabled, |ui| {
            ui.checkbox(&mut self.state.hardening, tr("Add hardening settings to the Windows installation (optional)"));
        });
        ui.indent("epma_hardening_note", |ui| {
            wrapped(ui, &texts::hardening_explanation(), PANEL_WRAP as f32 - 24.0, Some(MUTED));
            let toggled = disclosure(ui, &self.state.hardening_toggle);
            if let Some(open) = toggled {
                self.state.set_hardening_details_open(open);
            }
            if self.state.hardening_toggle.is_open {
                wrapped(ui, &self.state.hardening_details, PANEL_WRAP as f32 - 40.0, None);
            }
        });
    }

    fn seed_panel(&mut self, ui: &mut Ui) {
        ui.add_space(6.0);
        ui.label(tr("Install target:"));
        let enabled = self.state.controls.seed_radios_enabled;
        let radios = texts::seed_target_texts();
        let mut choice = self.state.seed_choice.clone();
        ui.add_enabled_ui(enabled, |ui| {
            // Four radio buttons do not fit one row of a 780 px window (the texts are long, more so in Portuguese):
            // two rows of two.
            for pair in radios.chunks(2) {
                ui.horizontal(|ui| {
                    for (key, text) in pair {
                        ui.radio_value(&mut choice, (*key).to_string(), text.as_str());
                        ui.add_space(8.0);
                    }
                });
            }
        });
        if choice != self.state.seed_choice {
            self.state.set_seed_choice(&choice);
        }
        ui.add_space(6.0);
        wrapped(ui, &self.state.seed_note(), PANEL_WRAP as f32, Some(MUTED));
    }

    // ------------------------------------------------------------------------------------------------------
    // The image: file row, chosen-file card, SHA-256 panel
    // ------------------------------------------------------------------------------------------------------
    fn image_block(&mut self, ui: &mut Ui) {
        ui.add_space(10.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(tr("Already downloaded the image (ISO, or ChromeOS Flex .zip/.bin)?"));
            let enabled = self.state.controls.pick_enabled;
            if ui.add_enabled(enabled, egui::Button::new(tr("Select existing ISO file..."))).clicked() {
                self.state.pick_existing_iso();
            }
        });
        ui.add_space(6.0);
        self.file_card(ui);
        if self.state.sha_toggle_visible() {
            ui.add_space(4.0);
            if let Some(open) = disclosure(ui, &self.state.sha_toggle) {
                self.state.set_sha_toggle_open(open);
            }
        }
        if self.state.sha_panel_visible() {
            ui.add_space(4.0);
            self.sha_panel(ui);
        }
    }

    fn file_card(&mut self, ui: &mut Ui) {
        let card = self.state.iso_card.clone();
        egui::Frame::new().inner_margin(Margin::symmetric(0, 2)).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    if card.has_file {
                        ui.label(RichText::new(&card.label).strong());
                        ui.label(RichText::new(&card.folder).small().color(MUTED));
                    } else {
                        ui.label(RichText::new(&card.label).color(MUTED));
                    }
                });
                if card.has_file {
                    ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
                        let color = match card.kind {
                            crate::types::IsoKind::Windows => ACCENT,
                            crate::types::IsoKind::Linux => Color32::from_rgb(0xbf, 0x5a, 0xf2),
                            crate::types::IsoKind::ChromeOs => Color32::from_rgb(0x30, 0xa4, 0x6c),
                            crate::types::IsoKind::Unknown => MUTED,
                        };
                        egui::Frame::new().fill(color).corner_radius(4).inner_margin(Margin::symmetric(7, 1)).show(
                            ui,
                            |ui| {
                                ui.label(RichText::new(&card.badge).small().strong().color(Color32::WHITE));
                            },
                        );
                        if !card.size.is_empty() {
                            ui.label(RichText::new(&card.size).small().color(MUTED));
                        }
                    });
                }
            });
        });
    }

    fn sha_panel(&mut self, ui: &mut Ui) {
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            ui.label(
                RichText::new(tr("Paste the published hash or SHA256SUMS line, then calculate")).small().color(MUTED),
            );
            ui.horizontal(|ui| {
                let width = (ui.available_width() - 160.0).max(80.0);
                ui.add(egui::TextEdit::singleline(&mut self.state.sha.entry).desired_width(width));
                let enabled = self.state.sha.btn_enabled;
                if ui.add_enabled(enabled, egui::Button::new(tr("Calculate SHA-256"))).clicked() {
                    self.state.calculate_iso_sha256();
                }
            });
            if self.state.sha.bar.visible {
                bar(ui, &self.state.sha.bar);
            }
            if !self.state.sha.label.is_empty() {
                ui.label(&self.state.sha.label);
            }
            if !self.state.sha.result.is_empty() {
                let color = match self.state.sha.result_tone {
                    Tone::Normal => ui.visuals().text_color(),
                    Tone::Red => RED,
                    Tone::Green => OK_GREEN,
                };
                ui.label(RichText::new(&self.state.sha.result).color(color));
            }
        });
    }

    // ------------------------------------------------------------------------------------------------------
    // The drive list
    // ------------------------------------------------------------------------------------------------------
    fn drive_section(&mut self, ui: &mut Ui) {
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let enabled = self.state.controls.refresh_enabled;
            if ui.add_enabled(enabled, egui::Button::new(format!("⟳ {}", tr("Refresh USB drives list")))).clicked() {
                self.state.refresh_disks(false, false);
            }
        });
        ui.add_space(4.0);
        let dark = ui.visuals().dark_mode;
        match self.state.drives.view_state() {
            ListView::Items => {
                let enabled = self.state.drives.is_enabled();
                let selected = self.state.drives.selected_index();
                let count = self.state.drives.items().len();
                let mut pressed = None;
                let mut arrow = None;
                for index in 0..count {
                    let texts = drive_row_texts(&self.state.drives.items()[index]);
                    let id = egui::Id::unique(("epma_drive_row", index));
                    let response = drive_row(ui, id, Some(&texts), selected == index as i64, enabled, dark);
                    if enabled && response.clicked() {
                        pressed = Some(index);
                    }
                    if enabled && response.has_focus() {
                        let (up, down) = ui.input(|i| (i.key_pressed(Key::ArrowUp), i.key_pressed(Key::ArrowDown)));
                        if up {
                            arrow = Some((index, -1));
                        } else if down {
                            arrow = Some((index, 1));
                        }
                    }
                    ui.add_space(2.0);
                }
                if let Some(index) = pressed {
                    self.state.select_drive(index);
                }
                if let Some((row, step)) = arrow {
                    self.state.drive_arrow(row, step);
                    let target = row as i64 + step;
                    if target >= 0 && (target as usize) < count {
                        ui.memory_mut(|m| m.request_focus(egui::Id::unique(("epma_drive_row", target as usize))));
                    }
                }
            }
            ListView::Loading => {
                for index in 0..super::widgets::DriveList::SKELETON_ROWS {
                    drive_row(ui, egui::Id::unique(("epma_drive_skeleton", index)), None, false, false, dark);
                    ui.add_space(2.0);
                }
            }
            ListView::Empty => {
                ui.vertical_centered(|ui| {
                    ui.add_space(8.0);
                    ui.label(RichText::new(tr("No USB drive found")).strong());
                    ui.label(
                        RichText::new(tr("Plug in a USB drive (8 GB or more) and it will appear here.")).color(MUTED),
                    );
                    ui.add_space(8.0);
                });
            }
        }
    }

    // ------------------------------------------------------------------------------------------------------
    // Create, progress, results, log
    // ------------------------------------------------------------------------------------------------------
    fn create_section(&mut self, ui: &mut Ui) {
        // One short warning right above the button that does the damage, in the warning colour.
        wrapped(
            ui,
            &tr("WARNING: ALL DATA on the selected drive will be PERMANENTLY erased."),
            PANEL_WRAP as f32,
            Some(AMBER),
        );
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let enabled = self.state.controls.create_enabled;
            if accent_button(ui, &self.state.create_btn_text(), enabled).clicked() {
                self.state.start_create_usb();
            }
            ui.add_space(10.0);
            // The window's single Cancel: it stops whatever is running (a download, an extraction or the write).
            let enabled = self.state.controls.cancel_enabled;
            if ui.add_enabled(enabled, egui::Button::new(tr("Cancel"))).clicked() {
                self.state.cancel_current();
            }
        });
        // Inline results under the Create row, above the hint and the bar.
        if let Some(index) = banner(ui, &self.state.error_banner) {
            self.state.banner_link_clicked(BannerId::Error, index);
        }
        if let Some(index) = banner(ui, &self.state.success_panel) {
            self.state.banner_link_clicked(BannerId::Success, index);
        }
        if !self.state.create_hint.is_empty() {
            ui.add_space(6.0);
            wrapped(ui, &self.state.create_hint, 680.0, Some(MUTED));
        }
        if self.state.create_progress.visible {
            ui.add_space(10.0);
            bar(ui, &self.state.create_progress);
        }
        if !self.state.create_progress_label.is_empty() {
            ui.label(&self.state.create_progress_label);
        }
        ui.add_space(6.0);
        // The log is behind a link: it is for problems, not for everyone.
        if let Some(open) = disclosure(ui, &self.state.details_toggle) {
            self.state.set_details_open(open);
        }
        if self.state.details_toggle.is_open {
            self.log_box(ui);
        }
    }

    fn log_box(&mut self, ui: &mut Ui) {
        ui.add_space(6.0);
        let scroll_to_end = std::mem::take(&mut self.state.log_scroll_to_end);
        egui::Frame::new().fill(Color32::BLACK).corner_radius(3).inner_margin(Margin::same(4)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + 2.0;
            let total = self.state.log_lines.len();
            let mut area = egui::ScrollArea::vertical()
                .id_salt("epma_log")
                .max_height(row_height * 8.0)
                .auto_shrink([false, true]);
            if scroll_to_end {
                area = area.stick_to_bottom(true);
            }
            area.show_rows(ui, row_height, total, |ui, range| {
                for i in range {
                    if let Some(line) = self.state.log_lines.get(i) {
                        ui.label(RichText::new(line).monospace().color(Color32::LIGHT_GREEN));
                    }
                }
            });
        });
    }

    // ------------------------------------------------------------------------------------------------------
    // Dialogs
    // ------------------------------------------------------------------------------------------------------
    fn show_dialogs(&mut self, ctx: &egui::Context) {
        let Some(front) = self.state.dialog_queue.front() else {
            self.dialog_focused = false;
            return;
        };
        // File dialogs are the operating system's own and block this frame, like Tk's did.
        if matches!(front.kind, DialogKind::OpenFile { .. } | DialogKind::SaveFile { .. }) {
            if let Some(request) = self.state.dialog_queue.pop_front() {
                let reply = DialogReply::Path(run_file_dialog(&request));
                request.answer(reply);
                ctx.request_repaint();
            }
            return;
        }
        let kind = front.kind.clone();
        let title = front.title.clone();
        let message = front.message.clone();
        let pt = super::tx::is_portuguese();
        let (yes_text, no_text) = if pt { ("Sim", "Não") } else { ("Yes", "No") };
        let mut reply: Option<DialogReply> = None;
        let escape = ctx.input(|i| i.key_pressed(Key::Escape));
        let enter = ctx.input(|i| i.key_pressed(Key::Enter));
        let mut text = std::mem::take(&mut self.state.dialog_text);
        let mut first_focus = !self.dialog_focused;
        egui::Modal::new(egui::Id::unique("epma_dialog")).show(ctx, |ui| {
            ui.set_max_width(520.0);
            ui.label(RichText::new(&title).strong().size(16.0));
            ui.add_space(6.0);
            if !message.is_empty() {
                ui.label(&message);
            }
            ui.add_space(8.0);
            match &kind {
                DialogKind::Info | DialogKind::Error => {
                    if ui.button(tr("OK")).clicked() || escape || enter {
                        reply = Some(DialogReply::Yes(true));
                    }
                }
                DialogKind::Question { .. } => {
                    ui.horizontal(|ui| {
                        if ui.button(yes_text).clicked() {
                            reply = Some(DialogReply::Yes(true));
                        }
                        if ui.button(no_text).clicked() || escape {
                            reply = Some(DialogReply::Yes(false));
                        }
                    });
                }
                DialogKind::Typed { expected, reasons } => {
                    if !reasons.is_empty() {
                        ui.label(RichText::new(tr("This drive does not look like a spare USB stick:")).color(RED));
                        for reason in reasons {
                            ui.label(RichText::new(format!("\u{2022} {reason}")).color(RED));
                        }
                        ui.add_space(6.0);
                    }
                    ui.label(trf(
                        "To confirm, type the drive identifier exactly as shown ({expected}):",
                        &[("expected", expected.clone().into())],
                    ));
                    let edit = ui.add(egui::TextEdit::singleline(&mut text).desired_width(240.0));
                    if first_focus {
                        edit.request_focus();
                        first_focus = false;
                    }
                    let mut confirm = TypedConfirm::new(expected);
                    confirm.typed = text.clone();
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button(tr("Cancel")).clicked() || escape {
                            reply = Some(DialogReply::Yes(false));
                        }
                        // The Erase button follows the text; Enter cannot slip through.
                        let ready = confirm.erase_enabled();
                        if ui.add_enabled(ready, egui::Button::new(tr("Erase this drive"))).clicked()
                            || (enter && ready)
                        {
                            reply = Some(DialogReply::Yes(true));
                        }
                    });
                }
                DialogKind::Password => {
                    let edit = ui.add(egui::TextEdit::singleline(&mut text).password(true).desired_width(320.0));
                    if first_focus {
                        edit.request_focus();
                        first_focus = false;
                    }
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button(tr("Cancel")).clicked() || escape {
                            reply = Some(DialogReply::Text(None));
                        }
                        if ui.button(tr("OK")).clicked() || enter {
                            reply = Some(DialogReply::Text(Some(text.clone())));
                        }
                    });
                }
                DialogKind::OpenFile { .. } | DialogKind::SaveFile { .. } => {}
            }
        });
        self.dialog_focused = !first_focus || self.dialog_focused;
        self.state.dialog_text = text;
        if let Some(reply) = reply {
            self.dialog_focused = false;
            self.state.answer_dialog(reply);
            ctx.request_repaint();
        }
    }

    // ------------------------------------------------------------------------------------------------------
    // The documentation window
    // ------------------------------------------------------------------------------------------------------
    fn help_window(&mut self, ctx: &egui::Context) {
        if !self.state.help.open {
            return;
        }
        let mut open = true;
        let sections = self.state.help.sections.clone();
        let mut selected = self.state.help.section;
        let screen = ctx.content_rect().size();
        let mut close = ctx.input(|i| i.key_pressed(Key::Escape));
        egui::Window::new(tr("EPMA USB CREATOR Help"))
            .open(&mut open)
            .default_size(vec2(880.0_f32.min(screen.x * 0.95), 640.0_f32.min(screen.y * 0.9)))
            .min_size(vec2(260.0, 200.0))
            .max_size(vec2(screen.x.max(300.0), screen.y.max(240.0)))
            .resizable(true)
            .show(ctx, |ui| {
                let height = (ui.available_height() - 40.0).max(120.0);
                ui.horizontal_top(|ui| {
                    ui.allocate_ui(vec2(210.0, height), |ui| {
                        egui::ScrollArea::vertical().id_salt("epma_help_nav").max_height(height).show(ui, |ui| {
                            ui.set_width(200.0);
                            for (index, (title, _)) in sections.iter().enumerate() {
                                if ui.selectable_label(selected == index, title).clicked() {
                                    selected = index;
                                }
                            }
                        });
                    });
                    ui.separator();
                    ui.vertical(|ui| {
                        egui::ScrollArea::vertical().id_salt(("epma_help_body", selected)).max_height(height).show(
                            ui,
                            |ui| {
                                if let Some((title, body)) = sections.get(selected) {
                                    render_help(ui, title, body);
                                }
                            },
                        );
                    });
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button(tr("Close")).clicked() {
                        close = true;
                    }
                });
            });
        self.state.help.section = selected;
        if !open || close {
            self.state.help.open = false;
        }
    }
}

impl eframe::App for EpmaApp {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        // Tk swallowed the exceptions of its handlers (they only reached stderr); `report_callback_exception` showed
        // them instead, so a broken button never looks like "nothing happened". Same here: a failure while the
        // window is drawn or a click is handled becomes an "Unexpected error" message, not a crash.
        if let Err(panic) = super::shared::guarded(|| self.draw(ui)) {
            let exc = super::shared::ExcInfo { type_name: "InternalError".into(), text: panic };
            self.state.report_error("Unexpected error", None, Some(&exc), true, None);
        }
    }
}

// =================================================================================================================
// Drawing helpers
// =================================================================================================================

/// `run the file dialog` (rfd) for a `pick_*` request; `defaultextension` of Tk is applied when none was typed.
fn run_file_dialog(request: &DialogRequest) -> Option<std::path::PathBuf> {
    let mut dialog = rfd::FileDialog::new().set_title(request.title.clone());
    let add_filters = |mut d: rfd::FileDialog, filters: &[(String, Vec<String>)]| {
        for (name, extensions) in filters {
            if extensions.iter().any(|e| e == "*") {
                continue; // "All files" is what a dialog without a filter already shows
            }
            d = d.add_filter(name.clone(), extensions);
        }
        d
    };
    match &request.kind {
        DialogKind::OpenFile { filters } => {
            dialog = add_filters(dialog, filters);
            dialog.pick_file()
        }
        DialogKind::SaveFile { initial_name, extension, filters } => {
            dialog = add_filters(dialog, filters).set_file_name(initial_name.clone());
            let mut path = dialog.save_file()?;
            let wanted = extension.trim_start_matches('.');
            if path.extension().is_none() && !wanted.is_empty() {
                path.set_extension(wanted);
            }
            Some(path)
        }
        _ => None,
    }
}

/// A link-like label that is clicked.
fn link(ui: &mut Ui, text: &str) -> egui::Response {
    ui.add(egui::Label::new(RichText::new(text).color(LINK)).sense(Sense::click()))
        .on_hover_cursor(CursorIcon::PointingHand)
}

/// A "▸ Show details" / "▾ Hide details" row; returns the new state when it was toggled.
fn disclosure(ui: &mut Ui, d: &Disclosure) -> Option<bool> {
    if link(ui, &d.text()).clicked() {
        return Some(!d.is_open);
    }
    None
}

/// A label wrapped at `wrap` pixels (the Python `wraplength`), optionally coloured.
fn wrapped(ui: &mut Ui, text: &str, wrap: f32, color: Option<Color32>) {
    if text.is_empty() {
        return;
    }
    ui.scope(|ui| {
        let width = wrap.min(ui.available_width()).max(60.0);
        ui.set_max_width(width);
        let mut rich = RichText::new(text);
        if let Some(c) = color {
            rich = rich.color(c);
        }
        ui.label(rich);
    });
}

/// A numbered pill and a bold title ("1  Image type").
fn step_heading(ui: &mut Ui, number: u8, title: &str) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(vec2(20.0, 20.0), Sense::hover());
        let painter = ui.painter();
        painter.circle_stroke(rect.center(), 9.0, Stroke::new(1.0, MUTED));
        painter.text(rect.center(), Align2::CENTER_CENTER, number.to_string(), FontId::proportional(11.0), MUTED);
        ui.add_space(4.0);
        ui.label(RichText::new(title).strong().size(14.0));
    });
}

/// A progress bar: determinate, or a moving segment when the length is unknown.
fn bar(ui: &mut Ui, bar: &Bar) {
    let width = ui.available_width().max(20.0);
    let (rect, _) = ui.allocate_exact_size(vec2(width, 10.0), Sense::hover());
    let painter = ui.painter();
    let dark = ui.visuals().dark_mode;
    let track = if dark { Color32::from_rgb(0x3a, 0x3a, 0x3c) } else { Color32::from_rgb(0xd8, 0xd8, 0xdc) };
    painter.rect_filled(rect, CornerRadius::same(5), track);
    if bar.mode == BarMode::Indeterminate {
        let t = ui.input(|i| i.time) as f32;
        let phase = (t * 0.7).fract();
        let pos = if phase < 0.5 { phase * 2.0 } else { (1.0 - phase) * 2.0 };
        let seg = rect.width() * 0.3;
        let x0 = rect.left() + (rect.width() - seg) * pos;
        let seg_rect = Rect::from_min_size(pos2(x0, rect.top()), vec2(seg, rect.height()));
        painter.rect_filled(seg_rect, CornerRadius::same(5), ACCENT);
    } else {
        let fraction = (bar.value / 100.0).clamp(0.0, 1.0) as f32;
        if fraction > 0.0 {
            let fill = Rect::from_min_size(rect.min, vec2((rect.width() * fraction).max(10.0), rect.height()));
            painter.rect_filled(fill.intersect(rect), CornerRadius::same(5), ACCENT);
        }
    }
}

/// The bar and the label of a download card; both take no room while idle.
fn download_progress(ui: &mut Ui, progress: &Bar, label: &str) {
    if progress.visible {
        ui.add_space(8.0);
        bar(ui, progress);
    }
    if !label.is_empty() {
        ui.label(label);
    }
}

/// An inline message box; returns the index of the link that was clicked.
fn banner(ui: &mut Ui, b: &Banner) -> Option<usize> {
    if !b.shown {
        return None;
    }
    let (r, g, bl) = b.kind.color();
    let color = Color32::from_rgb(r, g, bl);
    let mut clicked = None;
    ui.add_space(8.0);
    egui::Frame::new().stroke(Stroke::new(1.0, color)).corner_radius(4).inner_margin(Margin::symmetric(10, 6)).show(
        ui,
        |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new(&b.title_text).strong().color(color));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    for (index, l) in b.links.iter().enumerate().rev() {
                        ui.add_space(6.0);
                        if link(ui, &l.text).clicked() {
                            clicked = Some(index);
                        }
                    }
                });
            });
            wrapped(ui, &b.message_text, PANEL_WRAP as f32 - 60.0, None);
        },
    );
    clicked
}

/// The one primary action of the window: a filled, rounded button in the accent colour.
fn accent_button(ui: &mut Ui, text: &str, enabled: bool) -> egui::Response {
    let font = FontId::proportional(17.0);
    let galley = ui.painter().layout_no_wrap(text.to_string(), font, Color32::WHITE);
    let width = (galley.size().x + 64.0).max(260.0);
    let sense = if enabled { Sense::click() } else { Sense::hover() };
    let (rect, response) = ui.allocate_exact_size(vec2(width, 46.0), sense);
    let dark = ui.visuals().dark_mode;
    let (fill, text_color) = if enabled {
        (if response.hovered() { ACCENT_HOVER } else { ACCENT }, Color32::WHITE)
    } else {
        (if dark { Color32::from_rgb(0x3a, 0x3a, 0x3c) } else { Color32::from_rgb(0xd8, 0xd8, 0xdc) }, MUTED)
    };
    let painter = ui.painter();
    painter.rect_filled(rect.shrink(2.0), CornerRadius::same(10), fill);
    if enabled && response.has_focus() {
        let ring = if dark { Color32::WHITE } else { Color32::from_rgb(0x00, 0x3d, 0x99) };
        painter.rect_stroke(rect.shrink(2.0), CornerRadius::same(10), Stroke::new(2.0, ring), StrokeKind::Inside);
    }
    painter.text(rect.center(), Align2::CENTER_CENTER, text, FontId::proportional(17.0), text_color);
    if enabled {
        response.on_hover_cursor(CursorIcon::PointingHand)
    } else {
        response
    }
}

/// One of the square, clickable choices at the top of the window (`OptionCard`).
fn option_card(ui: &mut Ui, card: Card, width: f32, selected: bool, enabled: bool) -> egui::Response {
    let sense = if enabled { Sense::click() } else { Sense::hover() };
    let (rect, response) = ui.allocate_exact_size(vec2(width, CARD_HEIGHT), sense);
    let hover = enabled && response.hovered();
    let focused = enabled && response.has_focus();
    let mut color = if selected {
        ACCENT
    } else if hover || focused {
        BORDER_HOT
    } else {
        BORDER
    };
    let line = if selected {
        3.0
    } else if focused {
        2.0
    } else {
        1.0
    };
    let mut text_color = ui.visuals().text_color();
    if !enabled {
        // locked while a write runs: the chosen card stays visible, the rest greys out
        text_color = MUTED;
        if !selected {
            color = MUTED;
        }
    }
    let painter = ui.painter_at(rect);
    painter.rect_stroke(rect.shrink(3.0), CornerRadius::same(14), Stroke::new(line, color), StrokeKind::Inside);
    let c = pos2(rect.center().x, rect.top() + 40.0);
    let glyph = if selected { ACCENT } else { text_color };
    match card {
        Card::Windows => {
            for (ox, oy) in [(-17.0, -17.0), (2.0, -17.0), (-17.0, 2.0), (2.0, 2.0)] {
                painter.rect_filled(Rect::from_min_size(pos2(c.x + ox, c.y + oy), vec2(15.0, 15.0)), 0.0, glyph);
            }
        }
        Card::Chrome => {
            painter.circle_stroke(c, 18.5, Stroke::new(3.0, glyph));
            painter.circle_filled(c, 8.0, glyph);
        }
        Card::Linux => {
            painter.text(c, Align2::CENTER_CENTER, ">_", FontId::monospace(26.0), glyph);
        }
        Card::Seed => {
            let shield = vec![
                pos2(c.x, c.y - 21.0),
                pos2(c.x + 17.0, c.y - 14.0),
                pos2(c.x + 17.0, c.y + 2.0),
                pos2(c.x + 10.0, c.y + 14.0),
                pos2(c.x, c.y + 21.0),
                pos2(c.x - 10.0, c.y + 14.0),
                pos2(c.x - 17.0, c.y + 2.0),
                pos2(c.x - 17.0, c.y - 14.0),
            ];
            painter.add(egui::Shape::closed_line(shield, Stroke::new(3.0, glyph)));
            painter.add(egui::Shape::line(
                vec![pos2(c.x - 8.0, c.y), pos2(c.x - 2.0, c.y + 7.0), pos2(c.x + 8.0, c.y - 6.0)],
                Stroke::new(3.0, glyph),
            ));
        }
        Card::Other => {
            painter.circle_stroke(c, 18.5, Stroke::new(3.0, glyph));
            painter.circle_stroke(c, 4.5, Stroke::new(3.0, glyph));
        }
    }
    let (title, subtitle) = card_texts(card);
    let room = (rect.width() - 16.0).max(10.0);
    // five cards share the width of the window: a longer title or a translation shrinks (down to 8 pt), then is cut
    let measure_size = |size: f32, text: &str| {
        painter.layout_no_wrap(text.to_string(), FontId::proportional(size), Color32::WHITE).size().x
    };
    let (size, shown) = fit_title(&measure_size, 15.0, &title, room);
    painter.text(pos2(c.x, rect.top() + 82.0), Align2::CENTER_CENTER, shown, FontId::proportional(size), text_color);
    let (size, shown) = fit_title(&measure_size, 11.0, &subtitle, room);
    painter.text(pos2(c.x, rect.top() + 103.0), Align2::CENTER_CENTER, shown, FontId::proportional(size), MUTED);
    if enabled {
        response.on_hover_cursor(CursorIcon::PointingHand)
    } else {
        response
    }
}

/// One row of the drive list; `texts` is `None` for the grey placeholder shown while the drives are listed.
fn drive_row(
    ui: &mut Ui,
    id: egui::Id,
    texts: Option<&(String, String, String)>,
    selected: bool,
    enabled: bool,
    dark: bool,
) -> egui::Response {
    let usable = texts.is_some() && enabled;
    let sense = if usable { Sense::click() } else { Sense::hover() };
    let width = ui.available_width().max(80.0);
    let (_, rect) = ui.allocate_space(vec2(width, ROW_HEIGHT));
    // a stable id so the keyboard focus survives the frame
    let response = ui.interact(rect, id, sense);
    let painter = ui.painter_at(rect);
    let cy = rect.center().y;
    let corner = CornerRadius::same(10);
    let Some((name, size, detail)) = texts else {
        let base = if dark { Color32::from_rgb(0x2c, 0x2c, 0x2e) } else { Color32::from_rgb(0xe9, 0xe9, 0xee) };
        let bar = if dark { Color32::from_rgb(0x3a, 0x3a, 0x3c) } else { Color32::from_rgb(0xd1, 0xd1, 0xd6) };
        painter.rect_filled(rect.shrink(3.0), corner, base);
        painter.circle_filled(pos2(rect.left() + 24.0, cy), 8.0, bar);
        painter.rect_filled(
            Rect::from_min_size(pos2(rect.left() + 44.0, cy - 14.0), vec2(rect.width() * 0.34, 10.0)),
            2.0,
            bar,
        );
        painter.rect_filled(
            Rect::from_min_size(pos2(rect.left() + 44.0, cy + 5.0), vec2(rect.width() * 0.2, 8.0)),
            2.0,
            bar,
        );
        return response;
    };
    let hover = usable && response.hovered();
    let focused = usable && response.has_focus();
    let text_color = if enabled { ui.visuals().text_color() } else { MUTED };
    let mut border = if enabled { BORDER } else { MUTED };
    let mut line = 1.0;
    let mut fill = Color32::TRANSPARENT;
    if selected {
        border = ACCENT;
        line = 2.0;
        fill = if dark { Color32::from_rgb(0x10, 0x26, 0x3d) } else { Color32::from_rgb(0xe6, 0xf1, 0xff) };
    } else if hover || focused {
        border = BORDER_HOT;
        line = 2.0;
    }
    painter.rect(rect.shrink(3.0), corner, fill, Stroke::new(line, border), StrokeKind::Inside);
    if focused {
        let ring = if dark { Color32::WHITE } else { Color32::from_rgb(0x00, 0x3d, 0x99) };
        painter.rect_stroke(rect.shrink(1.0), CornerRadius::same(12), Stroke::new(1.0, ring), StrokeKind::Inside);
    }
    let marker = if selected { ACCENT } else { MUTED };
    let center = pos2(rect.left() + 24.0, cy);
    painter.circle_stroke(center, 7.0, Stroke::new(2.0, marker));
    if selected {
        painter.circle_filled(center, 4.0, marker);
    }
    let measure = |font: FontId| {
        let painter = painter.clone();
        move |t: &str| painter.layout_no_wrap(t.to_string(), font.clone(), Color32::WHITE).size().x
    };
    let name_font = FontId::proportional(14.0);
    let detail_font = FontId::proportional(12.0);
    let badge_font = FontId::proportional(10.0);
    let mut right = rect.right() - 16.0;
    if !size.is_empty() {
        painter.text(pos2(right, rect.top() + 21.0), Align2::RIGHT_CENTER, size, name_font.clone(), text_color);
        right -= measure(name_font.clone())(size) + 12.0;
    }
    let accented = selected && enabled;
    let badge = tr("USB");
    let badge_w = measure(badge_font.clone())(&badge) + 14.0;
    let badge_fill = if accented {
        ACCENT
    } else if dark {
        Color32::from_rgb(0x3a, 0x3a, 0x3c)
    } else {
        Color32::from_rgb(0xe5, 0xe5, 0xea)
    };
    let badge_rect = Rect::from_min_max(pos2(right - badge_w, rect.top() + 12.0), pos2(right, rect.top() + 30.0));
    painter.rect_filled(badge_rect, CornerRadius::same(8), badge_fill);
    painter.text(
        badge_rect.center(),
        Align2::CENTER_CENTER,
        &badge,
        badge_font,
        if accented { Color32::WHITE } else { text_color },
    );
    let name_room = (right - badge_w - 54.0 - rect.left()).max(20.0);
    let shown = fit_with_ellipsis(&measure(name_font.clone()), name, name_room);
    painter.text(pos2(rect.left() + 44.0, rect.top() + 21.0), Align2::LEFT_CENTER, shown, name_font, text_color);
    if !detail.is_empty() {
        let room = (rect.width() - 44.0 - 16.0).max(20.0);
        let shown = fit_with_ellipsis(&measure(detail_font.clone()), detail, room);
        painter.text(pos2(rect.left() + 44.0, rect.top() + 41.0), Align2::LEFT_CENTER, shown, detail_font, MUTED);
    }
    if usable {
        response.on_hover_cursor(CursorIcon::PointingHand)
    } else {
        response
    }
}

/// One documentation section: the title, "## " sub-headings, "• " bullets and plain lines.
fn render_help(ui: &mut Ui, title: &str, body: &str) {
    ui.label(RichText::new(title).strong().size(19.0));
    ui.add_space(6.0);
    for line in body.split('\n') {
        if let Some(heading) = line.strip_prefix("## ") {
            ui.add_space(8.0);
            ui.label(RichText::new(heading).strong().size(15.0));
            ui.add_space(2.0);
        } else if line.starts_with("• ") {
            ui.horizontal_top(|ui| {
                ui.add_space(12.0);
                ui.label(line);
            });
        } else if line.is_empty() {
            ui.add_space(6.0);
        } else {
            ui.label(line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gui::testkit::{usb_disk, Harness};
    use crate::gui::tx::set_test_language;
    use crate::types::Card;

    fn input(width: f32, height: f32) -> egui::RawInput {
        egui::RawInput {
            screen_rect: Some(Rect::from_min_size(pos2(0.0, 0.0), vec2(width, height))),
            ..Default::default()
        }
    }

    /// Run `frames` frames of the whole window against a headless context.
    fn frames(app: &mut EpmaApp, ctx: &egui::Context, width: f32, height: f32, frames: usize) -> usize {
        let mut shapes = 0;
        for _ in 0..frames {
            let out = ctx.run_ui(input(width, height), |ui| app.draw(ui));
            shapes += out.shapes.len();
            out.drop_without_applying_deltas();
        }
        shapes
    }

    fn app() -> (EpmaApp, Harness) {
        // the state of a harness is moved into the app; the harness keeps the fakes
        let mut h = Harness::inline();
        h.be.set_listed(vec![usb_disk()]);
        let state = std::mem::replace(&mut h.state, Harness::inline().state);
        (EpmaApp::with_state(state), h)
    }

    #[test]
    fn one_frame_of_the_window_draws_without_panicking() {
        let (mut app, _h) = app();
        let ctx = egui::Context::default();
        let drawn = frames(&mut app, &ctx, 780.0, 700.0, 3);
        assert!(drawn > 50, "the window drew almost nothing: {drawn} shapes");
    }

    #[test]
    fn every_card_and_every_state_draws() {
        let (mut app, _h) = app();
        let ctx = egui::Context::default();
        for card in Card::ORDER {
            app.state.select_card(card);
            frames(&mut app, &ctx, 780.0, 700.0, 2);
        }
        app.state.select_card(Card::Windows);
        app.state.hardening_toggle.is_open = true;
        app.state.set_hardening_details_open(false);
        app.state.set_hardening_details_open(true);
        app.state.set_details_open(true);
        app.state.log("a line of the log");
        app.state.set_iso("/tmp/ubuntu-24.04.iso");
        app.state.set_sha_toggle_open(true);
        app.state.sha.result = "MATCH".into();
        app.state.sha.bar.visible = true;
        app.state.refresh_disks(false, true);
        app.state.show_error("Error", "something failed", Some(crate::gui::widgets::Retry::Download));
        app.state.show_success("Done", "all good", true);
        app.state.reset_create_progress();
        app.state.windows_dl.show(None, "downloading");
        app.state.flex_dl.show(Some(40.0), "40%");
        app.state.show_help(0);
        frames(&mut app, &ctx, 780.0, 700.0, 3);
        app.state.creating = true;
        app.state.sync_controls();
        frames(&mut app, &ctx, 780.0, 700.0, 2);
    }

    #[test]
    fn small_windows_do_not_panic() {
        let (mut app, _h) = app();
        let ctx = egui::Context::default();
        app.state.refresh_disks(false, true);
        app.state.show_help(0);
        app.state.set_details_open(true);
        for (w, h) in [(200.0, 120.0), (330.0, 200.0), (520.0, 420.0), (1920.0, 1080.0), (40.0, 40.0)] {
            frames(&mut app, &ctx, w, h, 2);
        }
    }

    #[test]
    fn the_portuguese_window_draws() {
        set_test_language("pt");
        let (mut app, _h) = app();
        let ctx = egui::Context::default();
        for card in Card::ORDER {
            app.state.select_card(card);
            frames(&mut app, &ctx, 780.0, 700.0, 1);
        }
        set_test_language("en");
    }

    #[test]
    fn a_dialog_in_the_queue_is_shown_and_answered() {
        let (mut app, _h) = app();
        let ctx = egui::Context::default();
        let (tx, rx) = std::sync::mpsc::channel();
        app.state.apply(UiMsg::Dialog(DialogRequest {
            kind: DialogKind::Typed { expected: "disk9".into(), reasons: vec!["big".into()] },
            title: "Confirm".into(),
            message: "Erase?".into(),
            reply: Some(tx),
        }));
        frames(&mut app, &ctx, 780.0, 700.0, 2);
        assert_eq!(app.state.dialog_queue.len(), 1, "the dialog waits for the user");
        assert!(rx.try_recv().is_err());
        app.state.answer_dialog(DialogReply::Yes(false));
        assert_eq!(rx.recv().unwrap(), DialogReply::Yes(false));
        frames(&mut app, &ctx, 780.0, 700.0, 1);
    }
}
