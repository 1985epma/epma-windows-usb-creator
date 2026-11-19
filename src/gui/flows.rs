//! The window's flows that run off the UI thread (port of the dialog sequences and the worker functions of the `App`
//! class, win11_usb_creator.py lines 10885-12034): the confirmations and the write, the downloads, the extraction,
//! the SHA-256 calculation, the dependency installer, the quit and cancel questions.
//!
//! Each flow reads what it needs from a snapshot taken on the UI thread (so what is confirmed is what is written),
//! asks the user through `Dialogs` (blocking this worker, not the window) and reports back by posting `UiMsg`s.

use super::backend::{Backend, DownloadRequest, Platform};
use super::dialogs::{Dialogs, FileFilter};
use super::shared::{error_type_name, guarded, py_bool, ExcInfo, Shared, UiMsg};
use super::texts::{canceled_texts, seed_target};
use super::tx::{dev_path, human_size, tr, trf};
use super::widgets::{image_label, Retry};
use crate::audit::AuditLevel;
use crate::constants::{
    CHROMEOS_FLEX_FREE_BYTES, CHROMEOS_FLEX_GUIDE_URL, CHROMEOS_FLEX_HOSTS, CHROMEOS_FLEX_URL, SHA_UI_INTERVAL,
};
use crate::diskrisk::RiskLevel;
use crate::types::{BuildOptions, Ctx, Disk, Error, Hardening, IsoKind, Mode, SeedTarget};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::time::Duration;

// ---------------------------------------------------------------------------------------------------------------
// Confirmations
// ---------------------------------------------------------------------------------------------------------------

/// `App.confirm_erase(disk, what)`: the final confirmation. It always shows model, size and contents; high-risk
/// drives also need their identifier typed. True to go ahead.
pub fn confirm_erase(be: &dyn Backend, dialogs: &dyn Dialogs, disk: &Disk, what: &str) -> bool {
    let (level, reasons) = be.assess_disk_risk(disk); // the level never depends on the language
    let path = dev_path(&disk.id);
    let text = trf(
        "This will PERMANENTLY ERASE all data on {path} and write {what} to it.",
        &[("path", path.clone().into()), ("what", what.into())],
    ) + "\n\n"
        + &be.describe_disk_for_confirmation(disk);
    let level_name = match level {
        RiskLevel::High => "high",
        RiskLevel::Normal => "normal",
    };
    be.audit(&format!("Erase confirmation shown for {path} risk={level_name}"), AuditLevel::Info);
    let ok = if level == RiskLevel::High {
        dialogs.ask_typed_confirmation(&tr("Confirm erasing this drive"), &text, &disk.id, &reasons)
    } else {
        dialogs.ask_yes_no(&tr("Final confirmation"), &(text + "\n\n" + &tr("Continue?")), false)
    };
    if !ok {
        be.audit(&format!("Erase of {path} declined by the user"), AuditLevel::Info);
    }
    ok
}

/// `App._image_matches_choice(mode, image)`: stop (or ask) when the selected file is clearly not what the chosen card
/// writes. A Linux image under "Windows 11" would otherwise be discovered only after the drive was erased ("could not
/// find install.wim"); a non-ChromeOS file under "Google Chrome" is refused outright.
pub fn image_matches_choice(be: &dyn Backend, dialogs: &dyn Dialogs, mode: Mode, image: &str) -> bool {
    if mode == Mode::Seed {
        return true; // the seed drive carries no image: there is nothing to compare
    }
    let kind = be.detect_iso_kind(Path::new(image));
    if mode == Mode::ChromeOs && kind != IsoKind::ChromeOs {
        dialogs.show_error(
            &tr("ChromeOS Flex"),
            &trf(
                "The selected image is not a ChromeOS Flex disk image:\n{path}\n\n\
                 Download it with the button above, or select the .bin file from Google's \
                 latest.bin.zip.",
                &[("path", image.into())],
            ),
        );
        return false;
    }
    if mode == Mode::MacOs && kind != IsoKind::MacOs {
        // The engine refuses an image without a partition table before anything is erased; this asks earlier, when
        // the file is clearly something else (a Windows or Linux ISO under the macOS card).
        return dialogs.ask_yes_no(
            &tr("This does not look like a macOS disk image"),
            &trf(
                "The selected file does not look like a macOS disk image:\n{path}\n\n\
                 The macOS card writes a whole-disk image (a partition table with Apple partitions) as it is. \
                 Choose the matching card instead, or continue only if you are sure.\n\n\
                 Continue anyway?",
                &[("path", image.into())],
            ),
            true,
        );
    }
    if mode == Mode::Windows && matches!(kind, IsoKind::Linux | IsoKind::ChromeOs | IsoKind::MacOs) {
        let name = match kind {
            IsoKind::Linux => tr("a Linux image"),
            IsoKind::MacOs => tr("a macOS image"),
            _ => tr("a ChromeOS image"),
        };
        return dialogs.ask_yes_no(
            &tr("This does not look like Windows"),
            &trf(
                "The selected file looks like {name}, but \"Windows 11\" is chosen. Windows mode would \
                 erase the drive and then fail to find the Windows installer.\n\n\
                 Choose the matching card instead, or continue only if you are sure.\n\n\
                 Continue anyway?",
                &[("name", name.into())],
            ),
            true,
        );
    }
    if mode == Mode::Windows && kind == IsoKind::Unknown {
        // Nothing says this is a Windows installer, and Windows mode erases the drive BEFORE it looks for
        // install.wim. The file name is no evidence, so ask.
        return dialogs.ask_yes_no(
            &tr("Image type not recognised"),
            &tr("The program could not identify the selected file, but \"Windows 11\" is chosen. Windows mode \
                 would erase the drive and then fail if this is not a Windows installer.\n\n\
                 Continue only if you are sure this is a Windows 11 ISO.\n\n\
                 Continue anyway?"),
            true,
        );
    }
    true
}

// ---------------------------------------------------------------------------------------------------------------
// Writing a drive
// ---------------------------------------------------------------------------------------------------------------

/// Everything the write depends on, read ONCE on the UI thread before any dialog opens: the confirmation, the password
/// prompt and the worker all use these values, so what is confirmed is what is written even if something else (a
/// finishing download) changes the window's image or card meanwhile.
#[derive(Clone, Debug)]
pub struct CreateInputs {
    pub disk: Option<Disk>,
    pub mode: Mode,
    pub iso: String,
    /// The value of the seed radio buttons' variable (a key of `SEED_CHOICES`, or anything the variable holds).
    pub seed_choice: String,
    pub hardening: Hardening,
    /// A download or an extraction is running.
    pub downloading: bool,
}

/// What the confirmations approved.
#[derive(Clone, Debug)]
pub struct CreatePlan {
    pub disk: Disk,
    pub mode: Mode,
    pub iso: String,
    pub seed: bool,
    pub target: Option<SeedTarget>,
    pub hardening: Hardening,
    pub expected_size: u64,
}

/// `App._start_create_usb` up to (not including) the worker: every check, question and the password prompt, in the
/// order of the Python. `None` when something refused or the user declined (nothing was touched).
pub fn create_preflight(sh: &Shared, inputs: &CreateInputs) -> Option<CreatePlan> {
    let be: &dyn Backend = &*sh.backend;
    let dialogs: &dyn Dialogs = &*sh.dialogs;
    let log = |line: &str| sh.log.push(line);
    let disk = inputs.disk.clone()?;
    let mode = inputs.mode;
    let iso = inputs.iso.clone();
    let seed = mode == Mode::Seed;
    let choice = if seed { Some(inputs.seed_choice.as_str()) } else { None };
    let target = choice.and_then(seed_target); // read ONCE, like the rest
    let hardening = inputs.hardening;
    if inputs.downloading {
        // the button is disabled in this case; this covers a stale one
        dialogs.show_error(&tr("Download in progress"), &tr("Wait for the download to finish or cancel it first."));
        return None;
    }
    let missing = be.get_missing_dependencies(mode);
    if !missing.is_empty() {
        // the Create button is disabled in this case; this covers a stale button
        dialogs.show_error(
            &tr("Missing tools"),
            &trf(
                "These tools are missing: {tools}. Click \"Install missing dependencies\" first. \
                 Nothing was changed.",
                &[("tools", missing.join(", ").into())],
            ),
        );
        return None;
    }
    let disk_size = disk.size;
    if disk_size == 0 {
        // An empty card reader reports 0 bytes. Never skip the size checks for it: refuse.
        dialogs.show_error(
            &tr("Unknown drive size"),
            &tr("The size of this drive could not be read (it reports 0 bytes). It may be an empty card \
                 reader or a drive that is not ready. Nothing was changed."),
        );
        return None;
    }
    if seed && target.is_none() {
        // the radio buttons only give valid values; never trust the variable
        dialogs
            .show_error(&tr("Hardening seed"), &tr("Choose which system the seed drive is for. Nothing was changed."));
        return None;
    }
    if seed {
        // a drive known to be too small is refused now, before the confirmation, not after it
        if let Err(e) = be.check_seed_target_size(Some(disk_size)) {
            dialogs.show_error(&tr("Drive too small"), &e.to_string());
            return None;
        }
    }
    if !seed && !image_matches_choice(be, dialogs, mode, &iso) {
        return None;
    }
    let what = if seed {
        tr("the hardening seed files")
    } else if hardening != Hardening::None {
        tr("Windows 11 and add the hardening files")
    } else {
        image_label(mode, &tr("the selected Linux image"))
    };
    if mode.is_raw() {
        let image_size = std::fs::metadata(&iso).map(|m| m.len()).unwrap_or(0);
        if be.image_exceeds_drive(image_size, disk_size) {
            dialogs.show_error(
                &tr("Drive too small"),
                &trf(
                    "The image ({image}) is larger than this drive ({drive}). Choose a bigger drive. \
                     Nothing was changed.",
                    &[("image", human_size(image_size).into()), ("drive", human_size(disk_size).into())],
                ),
            );
            return None;
        }
    }
    if be.chromeos_drive_too_small(mode, disk_size)
        && !dialogs.ask_yes_no(
            &tr("Small USB drive"),
            &trf(
                "Google asks for a USB drive of 16 GB or larger for ChromeOS Flex, and this one is {size}. \
                 It may not work as an installer.\n\nContinue anyway?",
                &[("size", human_size(disk_size).into())],
            ),
            true,
        )
    {
        return None;
    }
    if !confirm_erase(be, dialogs, &disk, &what) {
        return None;
    }
    // Bind the safety re-check (right before erasing) to exactly the drive that was confirmed.
    be.pin_target_identity(&disk.id, Some(disk.identity.clone()));
    // Writing the drive needs administrator rights (always on Linux; on macOS only for the direct-write mode).
    // Collect and verify the password now, before touching the drive.
    if be.needs_admin(mode) {
        let reason = trf("Administrator access is required to write {path}.", &[("path", dev_path(&disk.id).into())]);
        match sh.priv_.authenticate(&reason) {
            Ok(true) => {}
            Ok(false) => {
                sh.priv_.clear_cached_password();
                if be.platform() == Platform::Windows {
                    dialogs.show_error(
                        &tr("Administrator required"),
                        &tr("EPMA USB Creator must run as Administrator to erase and write a USB drive.\n\n\
                             Close it and open it again with right-click > Run as administrator (the Start menu \
                             shortcut of the installed program does this by itself). Nothing was changed."),
                    );
                    log(&tr("Canceled: the program is not running as Administrator. The drive was not modified."));
                } else {
                    log(&tr("Canceled: administrator password was not provided. The drive was not modified."));
                }
                return None;
            }
            Err(e) => {
                sh.priv_.clear_cached_password();
                sh.post(UiMsg::ReportError {
                    title: "Error".into(),
                    message: Some(e.to_string()),
                    exc: None,
                    modal: true,
                    retry: None,
                });
                return None;
            }
        }
    }
    Some(CreatePlan { disk, mode, iso, seed, target, hardening, expected_size: disk_size })
}

/// The engine call of the write worker.
fn run_write(sh: &Shared, plan: &CreatePlan) -> crate::types::Result<bool> {
    let log = |line: &str| sh.log.push(line);
    let progress = |done: u64, total: u64, text: &str| {
        sh.post(UiMsg::CreateProgress { done, total, text: text.to_string() });
    };
    let ctx = Ctx::new(&log, Some(&progress), Some(&sh.cancel_create));
    let be: &dyn Backend = &*sh.backend;
    if plan.seed {
        // the same flow as every other write; only the engine call differs (no image)
        let Some(target) = plan.target else {
            return Err(Error::value("Choose which system the seed drive is for."));
        };
        be.build_seed_usb(target, &plan.disk.id, &ctx, &*sh.priv_, Some(plan.expected_size), true, Hardening::Baseline)
    } else {
        let opts = BuildOptions {
            expected_size: Some(plan.expected_size),
            mode: plan.mode,
            eject: true,
            hardening: plan.hardening,
        };
        be.build_usb(Path::new(&plan.iso), &plan.disk.id, &ctx, &*sh.priv_, &opts)
    }
}

/// The whole of `start_create_usb` after the click: confirmations, then the write, on one worker thread. The UI thread
/// has already locked the window (`creating`). Always ends with `CreateRefused` (nothing started) or `CreationEnded`.
pub fn run_create_flow(sh: Shared, inputs: CreateInputs) {
    let plan = match guarded(|| create_preflight(&sh, &inputs)) {
        Ok(Some(plan)) => plan,
        Ok(None) => {
            sh.post(UiMsg::CreateRefused);
            return;
        }
        Err(panic) => {
            sh.post(UiMsg::ReportError {
                title: "Unexpected error".into(),
                message: None,
                exc: Some(ExcInfo { type_name: "InternalError".into(), text: panic }),
                modal: true,
                retry: None,
            });
            sh.post(UiMsg::CreateRefused);
            return;
        }
    };
    // From here the write is running: closing the window must ask first.
    sh.write_alive.store(true, Ordering::SeqCst);
    sh.cancel_create.clear();
    sh.post(UiMsg::CreateGo);
    let seed = plan.seed;
    match guarded(|| run_write(&sh, &plan)) {
        Ok(Ok(ejected)) => {
            sh.post(UiMsg::CreateFinish { ok: true, canceled: false });
            sh.post(UiMsg::CreateSuccess { ejected, mode: plan.mode, hardening: plan.hardening, target: plan.target });
        }
        Ok(Err(e @ Error::Canceled { .. })) => {
            // Not an error: the user asked for it. Say clearly what state the drive is in.
            let (log_text, title, body) = canceled_texts(e.drive_touched(), e.written(), seed);
            sh.post(UiMsg::CreateFinish { ok: false, canceled: true });
            sh.post(UiMsg::Log(log_text));
            sh.post(UiMsg::Notify { info: true, title: title.clone(), body: body.clone() });
            if e.drive_touched() {
                // the warning that the drive is not usable stays on screen
                sh.post(UiMsg::ShowError { title, message: body });
            }
        }
        Ok(Err(e @ (Error::Value(_) | Error::Runtime(_)))) => {
            // Expected, actionable failures: the message is written for the user.
            sh.post(UiMsg::CreateFinish { ok: false, canceled: false });
            sh.post(UiMsg::ReportError {
                title: "Error".into(),
                message: Some(e.to_string()),
                exc: None,
                modal: true,
                retry: None,
            });
        }
        Ok(Err(e)) => {
            // Unexpected failure: a short message in the dialog, the detail in the log.
            sh.post(UiMsg::CreateFinish { ok: false, canceled: false });
            sh.post(UiMsg::ReportError {
                title: "Unexpected error".into(),
                message: None,
                exc: Some(ExcInfo::of(&e)),
                modal: true,
                retry: None,
            });
        }
        Err(panic) => {
            sh.post(UiMsg::CreateFinish { ok: false, canceled: false });
            sh.post(UiMsg::ReportError {
                title: "Unexpected error".into(),
                message: None,
                exc: Some(ExcInfo { type_name: "InternalError".into(), text: panic }),
                modal: true,
                retry: None,
            });
        }
    }
    // The administrator password is no longer needed once the operation ends.
    sh.priv_.clear_cached_password();
    sh.post(UiMsg::CreationEnded);
    sh.write_alive.store(false, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------------------------------------------
// Downloads
// ---------------------------------------------------------------------------------------------------------------

fn iso_filter(name: &str, ext: &str) -> Vec<FileFilter> {
    vec![(name.to_string(), vec![ext.to_string()])]
}

/// `start_download` up to the file dialog: validate the link and the checksum, warn about an unknown server, ask where
/// to save. Posts `DownloadApproved` (the UI thread starts the download) or nothing.
pub fn flow_download(sh: &Shared, url_text: String, expected_sha: String) {
    let be: &dyn Backend = &*sh.backend;
    let dialogs: &dyn Dialogs = &*sh.dialogs;
    let (url, host, untrusted_host) = match be.validate_download_url(&url_text) {
        Ok(t) => t,
        Err(e) => {
            dialogs.show_error(&tr("Invalid link"), &e.to_string());
            return;
        }
    };
    if !expected_sha.is_empty() && !be.is_sha256_hex(&expected_sha) {
        dialogs.show_error(
            &tr("Invalid checksum"),
            &tr("A SHA-256 checksum must be exactly 64 characters using only 0-9 and a-f.\n\n\
                 Leave the field empty if you do not have one."),
        );
        return;
    }
    if untrusted_host
        && !dialogs.ask_yes_no(
            &tr("Unrecognised download server"),
            &trf(
                "This link points to '{host}', which is not a known Microsoft download server.\n\n\
                 Downloading a Windows image from an unofficial source is a real risk: a tampered \
                 image would install a compromised Windows on the target computer, and you would \
                 have no way of noticing.\n\n\
                 Continue anyway?",
                &[("host", host.clone().into())],
            ),
            true,
        )
    {
        be.audit(&format!("User declined download from untrusted host: {host}"), AuditLevel::Info);
        return;
    }
    let Some(dest) =
        dialogs.pick_save_file(&tr("Save ISO as"), "Win11.iso", ".iso", &iso_filter(&tr("ISO image"), "iso"))
    else {
        return;
    };
    be.audit(
        &format!(
            "Download started from host={host} trusted={} checksum_supplied={}",
            py_bool(!untrusted_host),
            py_bool(!expected_sha.is_empty())
        ),
        AuditLevel::Info,
    );
    sh.post(UiMsg::DownloadApproved { url, dest, expected_sha });
}

/// `start_flex_download` up to the file dialog: the terms, where to save, the free-space warning.
pub fn flow_flex_download(sh: &Shared) {
    let be: &dyn Backend = &*sh.backend;
    let dialogs: &dyn Dialogs = &*sh.dialogs;
    if !dialogs.ask_yes_no(
        &tr("Download ChromeOS Flex"),
        &trf(
            "ChromeOS Flex is provided by Google and is subject to Google's own terms.\n\n\
             This program only downloads Google's official image from its servers \
             (dl.google.com) over HTTPS and prepares it for your USB drive. Google's installation \
             guide: {url}\n\nDownload it now?",
            &[("url", CHROMEOS_FLEX_GUIDE_URL.into())],
        ),
        false,
    ) {
        return;
    }
    let Some(dest) = dialogs.pick_save_file(
        &tr("Save ChromeOS Flex as"),
        "chromeos_flex_latest.bin.zip",
        ".zip",
        &iso_filter(&tr("ZIP archive"), "zip"),
    ) else {
        return;
    };
    let folder = parent_or_here(&dest);
    if let Some(free) = be.disk_free(&folder) {
        if free < CHROMEOS_FLEX_FREE_BYTES
            && !dialogs.ask_yes_no(
                &tr("Not much free space"),
                &trf(
                    "The download (about 1.4 GB) and the extracted image (about 9.5 GB) need roughly \
                     {need} free in this folder, and only {free} is available. It may fail part-way.\n\n\
                     Continue anyway?",
                    &[("need", human_size(CHROMEOS_FLEX_FREE_BYTES).into()), ("free", human_size(free).into())],
                ),
                true,
            )
        {
            return;
        }
    }
    sh.post(UiMsg::FlexApproved { dest });
}

/// The folder of `path` (the current folder for a bare file name).
pub fn parent_or_here(path: &Path) -> PathBuf {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// `pick_existing_iso` up to the file dialog.
pub fn flow_pick_image(sh: &Shared) {
    let filters: Vec<FileFilter> = vec![
        (tr("ISO and disk images"), vec!["iso".into(), "bin".into(), "img".into(), "zip".into()]),
        (tr("All files"), vec!["*".into()]),
    ];
    if let Some(path) = sh.dialogs.pick_open_file(&tr("Select an ISO or disk image"), &filters) {
        sh.post(UiMsg::ImagePicked(path));
    }
}

/// Start the HTTPS download of a Windows ISO (the three callbacks only post messages to the window).
pub fn launch_windows_download(sh: &Shared, url: String, dest: PathBuf, expected_sha256: Option<String>) {
    let (p, d, e) = (sh.clone(), sh.clone(), sh.clone());
    sh.backend.start_download(DownloadRequest {
        url,
        dest,
        cancel: sh.cancel_download.clone(),
        expected_sha256,
        allowed_hosts: None,
        progress: Box::new(move |done, total, speed| p.post(UiMsg::DownloadProgress { done, total, speed })),
        done: Box::new(move |path, sha256, verified| {
            d.post(UiMsg::DownloadDone { path: path.to_path_buf(), sha256: sha256.to_string(), verified })
        }),
        error: Box::new(move |msg| e.post(UiMsg::DownloadError(msg.to_string()))),
    });
}

/// Start the HTTPS download of ChromeOS Flex (only Google's host is allowed).
pub fn launch_flex_download(sh: &Shared, dest: PathBuf) {
    let (p, d, e) = (sh.clone(), sh.clone(), sh.clone());
    let stage = tr("Downloading...");
    sh.backend.start_download(DownloadRequest {
        url: CHROMEOS_FLEX_URL.to_string(),
        dest,
        cancel: sh.cancel_flex.clone(),
        expected_sha256: None,
        allowed_hosts: Some(CHROMEOS_FLEX_HOSTS.iter().map(|h| (*h).to_string()).collect()),
        progress: Box::new(move |done, total, speed| {
            p.post(UiMsg::FlexProgress { done, total, speed, stage: stage.clone() })
        }),
        done: Box::new(move |path, sha256, _verified| {
            d.post(UiMsg::FlexDownloaded { path: path.to_path_buf(), sha256: sha256.to_string() })
        }),
        error: Box::new(move |msg| e.post(UiMsg::FlexError(msg.to_string()))),
    });
}

/// `_extract_flex_image`'s worker: extract the .bin from `zip` next to it.
pub fn worker_extract(sh: &Shared, zip: PathBuf, delete_zip: bool) {
    let folder = parent_or_here(&zip);
    let stage = tr("Extracting...");
    let progress = |done: u64, total: u64| {
        sh.post(UiMsg::FlexProgress { done, total, speed: 0.0, stage: stage.clone() });
    };
    let result = guarded(|| sh.backend.extract_disk_image(&zip, &folder, Some(&progress), Some(&sh.cancel_flex)));
    match result {
        Ok(Ok(image)) => sh.post(UiMsg::FlexExtracted { image, zip, delete_zip }),
        Ok(Err(Error::Canceled { .. })) => sh.post(UiMsg::FlexError(tr("Canceled."))),
        Ok(Err(e)) => sh.post(UiMsg::FlexError(e.to_string())),
        Err(panic) => sh.post(UiMsg::FlexError(format!("Exception: {panic}"))),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// SHA-256, dependencies, quit and cancel
// ---------------------------------------------------------------------------------------------------------------

/// `calculate_iso_sha256`'s worker.
pub fn worker_sha(sh: &Shared, job: u64, path: PathBuf, expected: Option<String>) {
    let last = Mutex::new(f64::NEG_INFINITY);
    let progress = |done: u64, total: u64| {
        let now = sh.now();
        let mut last = last.lock().unwrap_or_else(|e| e.into_inner());
        if done < total && now - *last < SHA_UI_INTERVAL {
            return; // ~10 UI updates per second is plenty
        }
        *last = now;
        sh.post(UiMsg::ShaProgress { job, done, total });
    };
    match guarded(|| sh.backend.sha256_file(&path, None, Some(&progress))) {
        Ok(Ok(digest)) => sh.post(UiMsg::ShaDone { job, path, digest, expected }),
        Ok(Err(e)) => sh.post(UiMsg::ShaError { job, reason: error_type_name(&e).to_string() }),
        Err(_) => sh.post(UiMsg::ShaError { job, reason: "Exception".into() }),
    }
}

/// `install_dependencies`'s worker: the install itself, then `InstallEnded`.
pub fn worker_install(sh: &Shared) {
    let be: &dyn Backend = &*sh.backend;
    let log = |line: &str| sh.log.push(line);
    let outcome = guarded(|| -> crate::types::Result<()> {
        match be.platform() {
            Platform::Windows => Err(Error::runtime(be.missing_dependencies_hint(&[]))),
            Platform::Mac => {
                if !be.which("brew") {
                    return Err(Error::runtime("Homebrew not found. Install it from https://brew.sh"));
                }
                let args = ["brew", "install", "wimlib"].map(String::from);
                be.run_cmd(&args, &log).map(|_| ())
            }
            Platform::Linux => {
                let missing = be.get_missing_dependencies(Mode::Windows);
                let Some(mgr) = be.detect_pkg_manager() else {
                    return Err(Error::runtime(format!(
                        "No supported package manager found (apt/dnf/yum/pacman/zypper/apk). \
                         Please install manually: {}",
                        missing.join(", ")
                    )));
                };
                let install_command = be.build_install_command(Some(&mgr), &missing)?;
                // Show exactly what will run as root before it runs.
                log(&format!("About to run as administrator: {install_command}"));
                be.audit(&format!("Installing dependencies via {mgr}: {}", missing.join(", ")), AuditLevel::Info);
                // A fixed prefix (so a failing step stops the script) in front of a command that
                // build_install_command() builds only from the fixed package allow-list.
                let script = format!("set -eu\n{install_command}");
                sh.priv_.run_script(&script, &log, &[])
            }
        }
    });
    let retry = Some(Retry::InstallDependencies);
    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(e @ (Error::Value(_) | Error::Runtime(_)))) => {
            // shown as a banner (not a dialog), with "Try again"
            sh.post(UiMsg::ReportError {
                title: "Error".into(),
                message: Some(e.to_string()),
                exc: None,
                modal: false,
                retry,
            });
        }
        Ok(Err(e)) => sh.post(UiMsg::ReportError {
            title: "Unexpected error".into(),
            message: None,
            exc: Some(ExcInfo::of(&e)),
            modal: false,
            retry,
        }),
        Err(panic) => sh.post(UiMsg::ReportError {
            title: "Unexpected error".into(),
            message: None,
            exc: Some(ExcInfo { type_name: "InternalError".into(), text: panic }),
            modal: false,
            retry,
        }),
    }
    sh.priv_.clear_cached_password();
    sh.post(UiMsg::InstallEnded);
}

/// `cancel_create_usb` after the guard: ask first (canceling leaves the drive unusable), then stop the write.
pub fn flow_cancel_write(sh: &Shared) {
    if !sh.dialogs.ask_yes_no(
        &tr("Cancel the operation?"),
        &tr("Canceling now will leave the USB drive incomplete and UNUSABLE until it is created \
             again.\n\nDo you really want to cancel?"),
        true,
    ) {
        return;
    }
    sh.cancel_create.set();
    sh.post(UiMsg::CancelRequested { audit: "User requested cancel of the USB creation".into() });
}

/// How long a close waits for a canceled write to stop.
pub const CLOSE_WAIT_SECONDS: f64 = 20.0;

/// `_on_close` while a write runs: a running write is never abandoned silently. Ask first, then cancel it and wait
/// (bounded, the window stays alive) for the worker to stop. Posts `CloseConfirmed` when the window may close.
pub fn flow_close_while_writing(sh: &Shared, wait_seconds: f64) {
    let dialogs: &dyn Dialogs = &*sh.dialogs;
    if !dialogs.ask_yes_no(
        &tr("Quit while writing?"),
        &tr("A USB drive is being written right now. Quitting cancels the operation and leaves \
             the drive incomplete and UNUSABLE until it is created again.\n\n\
             Cancel the operation and quit?"),
        true,
    ) {
        return;
    }
    if sh.write_alive.load(Ordering::SeqCst) {
        // it may have finished while the question was open
        sh.cancel_create.set();
        sh.post(UiMsg::CancelRequested {
            audit: "User closed the window during the USB creation: canceling it".into(),
        });
        if !wait_for_write(sh, wait_seconds)
            && !dialogs.ask_yes_no(
                &tr("Still stopping"),
                &tr("The operation is taking a while to stop. Quit anyway? The drive stays unusable \
                     until it is created again."),
                true,
            )
        {
            return;
        }
    }
    sh.post(UiMsg::CloseConfirmed);
}

/// `_wait_for_write(seconds)`: wait until the write worker ends or `seconds` pass; true if it ended. Dialogs from the
/// worker are suppressed meanwhile (`closing`), so nothing can block the wait.
pub fn wait_for_write(sh: &Shared, seconds: f64) -> bool {
    sh.closing.store(true, Ordering::SeqCst);
    let start = std::time::Instant::now();
    while sh.write_alive.load(Ordering::SeqCst) && start.elapsed().as_secs_f64() < seconds {
        std::thread::sleep(Duration::from_millis(50));
    }
    sh.closing.store(false, Ordering::SeqCst);
    !sh.write_alive.load(Ordering::SeqCst)
}
