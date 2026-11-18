//! Tests of the command line. The Python tests monkeypatch the engine (`mock.patch.object(app, ...)`) and call
//! `run_main(argv)`; here the whole command line runs against a [`FakeEngine`] (the `Engine` trait), in-memory
//! streams, a scripted environment and a manual Ctrl-C. Everything the fake does not override goes to the real
//! validators of `crate::validate` / `crate::util` on temp files, like the Python tests.
//!
//! * `basic`: tests/test_cli.py
//! * `hardening`: tests/test_cli_hardening.py
//! * `misc`: the command line parts of tests/test_fixes_engine.py, tests/test_chromeos.py and tests/test_help.py

mod basic;
mod hardening;
mod misc;

use super::{run, Engine, Env, Interrupts, OutStream};
use crate::audit::AuditLevel;
use crate::types::{
    BuildOptions, CancelToken, Ctx, Disk, Error, Files, Hardening, Identity, IsoKind, Mode, Privilege, Progress,
    Progress2, Result, SeedTarget,
};
use std::io::{self, BufRead, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

pub const MIB: u64 = 1024 * 1024;
pub const GIB: u64 = 1024 * 1024 * 1024;

pub fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// `FAKE_DISKS` of tests/helpers.py.
pub fn fake_disks() -> Vec<Disk> {
    vec![
        Disk { id: "disk9".into(), size: 16 * GIB, label: "/dev/disk9 \u{2014} 16.0 GB".into(), ..Disk::default() },
        Disk {
            id: "disk8".into(),
            size: 8 * GIB,
            label: "/dev/disk8 \u{2014} 8.0 GB".into(),
            model: Some("Fake Stick".into()),
            ..Disk::default()
        },
    ]
}

pub fn files_of(pairs: &[(&str, &[u8])]) -> Files {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_vec())).collect()
}

/// WIN_FILES of tests/test_cli_hardening.py.
pub fn win_files() -> Files {
    files_of(&[
        ("answer-standin.xml", b"<unattend/>\n"),
        ("sources/$OEM$/$$/Setup/Scripts/SetupComplete.cmd", b"@echo off\r\n"),
        ("sources/$OEM$/$$/Setup/Scripts/harden.ps1", b"# harden\r\n"),
    ])
}

/// SEED_FILES of tests/test_cli_hardening.py: `(volume label, files)` per seed target.
pub fn seed_files(target: SeedTarget) -> (String, Files) {
    match target {
        SeedTarget::Ubuntu => (
            "CIDATA".into(),
            files_of(&[
                ("user-data", b"#cloud-config\n"),
                ("meta-data", b"\n"),
                ("harden-linux.sh", b"#!/bin/bash\n"),
                ("README.txt", b"hello\n"),
            ]),
        ),
        SeedTarget::Fedora => (
            "OEMDRV".into(),
            files_of(&[
                ("ks.cfg", b"# kickstart\n"),
                ("harden-linux.sh", b"#!/bin/bash\n"),
                ("README.txt", b"hello\n"),
            ]),
        ),
        SeedTarget::Debian => (
            "EPMA-SEED".into(),
            files_of(&[
                ("preseed.cfg", b"# preseed\n"),
                ("harden-linux.sh", b"#!/bin/bash\n"),
                ("README.txt", b"hello\n"),
            ]),
        ),
        SeedTarget::Windows => (
            "EPMA-SEED".into(),
            files_of(&[
                ("harden.cmd", b"@echo off\r\n"),
                ("audit.cmd", b"@echo off\r\n"),
                ("undo.cmd", b"@echo off\r\n"),
                ("harden.ps1", b"\xef\xbb\xbf# harden\r\n"),
                ("README.txt", b"hello\r\n"),
            ]),
        ),
    }
}

pub fn sorted_names(files: &Files) -> Vec<String> {
    let mut names: Vec<String> = files.keys().cloned().collect();
    names.sort();
    names
}

// ---------------------------------------------------------------------------------------------------------------
// The fake engine
// ---------------------------------------------------------------------------------------------------------------

/// What `Engine::build_usb` was called with.
#[derive(Clone, Debug)]
pub struct BuildCall {
    pub iso: PathBuf,
    pub dev: String,
    pub expected_size: Option<u64>,
    pub mode: Mode,
    pub eject: bool,
    pub hardening: Hardening,
    /// Address of the privilege helper the engine received (compare with `FakeEngine::priv_addr`).
    pub priv_addr: usize,
}

#[derive(Clone, Debug)]
pub struct SeedCall {
    pub target: SeedTarget,
    pub dev: String,
    pub expected_size: Option<u64>,
    pub eject: bool,
    pub profile: Hardening,
    pub priv_addr: usize,
}

/// `needs_admin(mode)`: always on Linux and Windows, only for the byte-for-byte modes on macOS.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Admin {
    Always,
    RawOnly,
}

pub type BuildFn = Box<dyn Fn(&BuildCall, &Ctx) -> Result<bool> + Send + Sync>;
pub type SeedFn = Box<dyn Fn(&SeedCall, &Ctx) -> Result<bool> + Send + Sync>;
pub type DownloadFn = Box<dyn Fn(&str, &Path, Option<&CancelToken>) -> Result<String> + Send + Sync>;
pub type FilesSeedFn = Box<dyn Fn(SeedTarget) -> Result<(String, Files)> + Send + Sync>;
pub type ValidateFn = Box<dyn Fn(&Files) -> Result<Files> + Send + Sync>;
pub type SizeFn = Box<dyn Fn(Option<u64>) -> Result<()> + Send + Sync>;
pub type ShaFn = Box<dyn Fn(&Path, Option<&CancelToken>) -> Result<String> + Send + Sync>;
pub type ExtractFn = Box<dyn Fn(&Path, &Path) -> Result<PathBuf> + Send + Sync>;

/// The privilege helper the fake hands to the command line.
pub struct FakePriv {
    pub events: Arc<Mutex<Vec<String>>>,
    pub auth_calls: AtomicUsize,
    pub auth_error: Mutex<Option<String>>,
    pub cleared: AtomicUsize,
}

impl Privilege for FakePriv {
    fn run_script(&self, _script: &str, _log: crate::types::Log, _args: &[String]) -> Result<()> {
        Ok(())
    }
    fn authenticate(&self, _reason: &str) -> Result<bool> {
        self.auth_calls.fetch_add(1, Ordering::SeqCst);
        lock(&self.events).push("auth".into());
        match lock(&self.auth_error).clone() {
            Some(message) => Err(Error::Runtime(message)),
            None => Ok(true),
        }
    }
    fn clear_cached_password(&self) {
        self.cleared.fetch_add(1, Ordering::SeqCst);
    }
}

pub struct FakeEngine {
    pub events: Arc<Mutex<Vec<String>>>,
    pub disks: Mutex<Vec<Disk>>,
    pub disks_error: Mutex<Option<String>>,
    pub list_calls: AtomicUsize,
    /// Make `get_external_disks` panic (a bug in the engine).
    pub disks_panic: AtomicBool,
    pub missing: Mutex<Vec<String>>,
    pub missing_calls: Mutex<Vec<Mode>>,
    pub admin: Mutex<Admin>,
    pub detect: Mutex<Option<IsoKind>>,
    pub detect_calls: Mutex<Vec<PathBuf>>,
    pub build: Mutex<BuildFn>,
    pub build_calls: Mutex<Vec<BuildCall>>,
    pub seed: Mutex<SeedFn>,
    pub seed_calls: Mutex<Vec<SeedCall>>,
    pub pins: Mutex<Vec<(String, Option<Identity>)>>,
    pub priv_: Arc<FakePriv>,
    pub download: Mutex<DownloadFn>,
    /// Replaces the real `sha256_file` when set.
    pub sha: Mutex<Option<ShaFn>>,
    pub download_calls: Mutex<Vec<(String, PathBuf)>>,
    pub extract: Mutex<ExtractFn>,
    pub extract_calls: Mutex<Vec<(PathBuf, PathBuf)>>,
    pub files_windows_calls: Mutex<Vec<Hardening>>,
    pub files_windows: Mutex<Box<dyn Fn() -> Result<Files> + Send + Sync>>,
    pub files_seed_calls: Mutex<Vec<(SeedTarget, Hardening)>>,
    pub files_seed: Mutex<FilesSeedFn>,
    pub validate_calls: Mutex<Vec<Files>>,
    pub validate_files: Mutex<ValidateFn>,
    pub size_calls: Mutex<Vec<Option<u64>>>,
    pub size_check: Mutex<SizeFn>,
    pub free: Mutex<Option<u64>>,
    pub audits: Mutex<Vec<String>>,
    pub gui_calls: AtomicUsize,
    pub gui_code: AtomicI32,
    pub supported: AtomicBool,
    pub hint: Mutex<String>,
}

impl FakeEngine {
    pub fn new(events: Arc<Mutex<Vec<String>>>) -> FakeEngine {
        let build_events = events.clone();
        let seed_events = events.clone();
        FakeEngine {
            priv_: Arc::new(FakePriv {
                events: events.clone(),
                auth_calls: AtomicUsize::new(0),
                auth_error: Mutex::new(None),
                cleared: AtomicUsize::new(0),
            }),
            events,
            disks: Mutex::new(fake_disks()),
            disks_error: Mutex::new(None),
            list_calls: AtomicUsize::new(0),
            disks_panic: AtomicBool::new(false),
            missing: Mutex::new(Vec::new()),
            missing_calls: Mutex::new(Vec::new()),
            admin: Mutex::new(Admin::Always),
            detect: Mutex::new(None),
            detect_calls: Mutex::new(Vec::new()),
            build: Mutex::new(Box::new(move |_, _| {
                lock(&build_events).push("build".into());
                Ok(true)
            })),
            build_calls: Mutex::new(Vec::new()),
            seed: Mutex::new(Box::new(move |_, _| {
                lock(&seed_events).push("build".into());
                Ok(true)
            })),
            seed_calls: Mutex::new(Vec::new()),
            pins: Mutex::new(Vec::new()),
            download: Mutex::new(Box::new(|_, _, _| Err(Error::runtime("no download was scripted")))),
            sha: Mutex::new(None),
            download_calls: Mutex::new(Vec::new()),
            extract: Mutex::new(Box::new(|_, _| Err(Error::runtime("no extraction was scripted")))),
            extract_calls: Mutex::new(Vec::new()),
            files_windows_calls: Mutex::new(Vec::new()),
            files_windows: Mutex::new(Box::new(|| Ok(win_files()))),
            files_seed_calls: Mutex::new(Vec::new()),
            files_seed: Mutex::new(Box::new(|target| Ok(seed_files(target)))),
            validate_calls: Mutex::new(Vec::new()),
            validate_files: Mutex::new(Box::new(|files| Ok(files.clone()))),
            size_calls: Mutex::new(Vec::new()),
            size_check: Mutex::new(Box::new(|_| Ok(()))),
            free: Mutex::new(Some(100 * GIB)),
            audits: Mutex::new(Vec::new()),
            gui_calls: AtomicUsize::new(0),
            gui_code: AtomicI32::new(0),
            supported: AtomicBool::new(true),
            hint: Mutex::new("Install them with your package manager.".into()),
        }
    }

    pub fn priv_addr(&self) -> usize {
        Arc::as_ptr(&self.priv_) as *const () as usize
    }

    pub fn set_disks(&self, disks: Vec<Disk>) {
        *lock(&self.disks) = disks;
    }
    pub fn on_build(&self, f: impl Fn(&BuildCall, &Ctx) -> Result<bool> + Send + Sync + 'static) {
        *lock(&self.build) = Box::new(f);
    }
    pub fn on_seed(&self, f: impl Fn(&SeedCall, &Ctx) -> Result<bool> + Send + Sync + 'static) {
        *lock(&self.seed) = Box::new(f);
    }
    pub fn builds(&self) -> Vec<BuildCall> {
        lock(&self.build_calls).clone()
    }
    pub fn seeds(&self) -> Vec<SeedCall> {
        lock(&self.seed_calls).clone()
    }
    pub fn events(&self) -> Vec<String> {
        lock(&self.events).clone()
    }
    pub fn pin_log(&self) -> Vec<(String, Option<Identity>)> {
        lock(&self.pins).clone()
    }
    pub fn auth_calls(&self) -> usize {
        self.priv_.auth_calls.load(Ordering::SeqCst)
    }
}

impl Engine for FakeEngine {
    fn supported_platform(&self) -> bool {
        self.supported.load(Ordering::SeqCst)
    }
    fn get_external_disks(&self) -> Result<Vec<Disk>> {
        self.list_calls.fetch_add(1, Ordering::SeqCst);
        if self.disks_panic.load(Ordering::SeqCst) {
            panic!("the drive list exploded");
        }
        if let Some(message) = lock(&self.disks_error).clone() {
            return Err(Error::Io(io::Error::new(io::ErrorKind::NotFound, message)));
        }
        Ok(lock(&self.disks).clone())
    }
    fn get_missing_dependencies(&self, mode: Mode) -> Vec<String> {
        lock(&self.missing_calls).push(mode);
        lock(&self.missing).clone()
    }
    fn missing_dependencies_hint(&self, _missing: &[String]) -> String {
        lock(&self.hint).clone()
    }
    fn needs_admin(&self, mode: Mode) -> bool {
        *lock(&self.admin) == Admin::Always || mode.is_raw()
    }
    fn image_exceeds_drive(&self, image_size: u64, drive_size: u64) -> bool {
        image_size > 0 && drive_size > 0 && image_size > drive_size
    }
    fn chromeos_drive_too_small(&self, mode: Mode, drive_size: u64) -> bool {
        mode == Mode::ChromeOs && drive_size > 0 && drive_size < crate::constants::CHROMEOS_MIN_USB_BYTES
    }
    fn pin_target_identity(&self, dev: &str, identity: Option<Identity>) {
        lock(&self.events).push("pin".into());
        lock(&self.pins).push((dev.to_string(), identity));
    }
    fn free_space(&self, _dir: &Path) -> Option<u64> {
        *lock(&self.free)
    }
    fn detect_iso_kind(&self, path: &Path) -> IsoKind {
        lock(&self.detect_calls).push(path.to_path_buf());
        lock(&self.detect).unwrap_or(IsoKind::Unknown)
    }
    fn privilege(&self) -> Arc<dyn Privilege> {
        self.priv_.clone()
    }
    fn build_usb(
        &self,
        iso_path: &Path,
        dev: &str,
        ctx: &Ctx,
        priv_: &dyn Privilege,
        opts: &BuildOptions,
    ) -> Result<bool> {
        let call = BuildCall {
            iso: iso_path.to_path_buf(),
            dev: dev.to_string(),
            expected_size: opts.expected_size,
            mode: opts.mode,
            eject: opts.eject,
            hardening: opts.hardening,
            priv_addr: priv_ as *const dyn Privilege as *const () as usize,
        };
        lock(&self.build_calls).push(call.clone());
        (lock(&self.build))(&call, ctx)
    }
    fn build_seed_usb(
        &self,
        target: SeedTarget,
        dev: &str,
        ctx: &Ctx,
        priv_: &dyn Privilege,
        expected_size: Option<u64>,
        eject: bool,
        profile: Hardening,
    ) -> Result<bool> {
        let call = SeedCall {
            target,
            dev: dev.to_string(),
            expected_size,
            eject,
            profile,
            priv_addr: priv_ as *const dyn Privilege as *const () as usize,
        };
        lock(&self.seed_calls).push(call.clone());
        (lock(&self.seed))(&call, ctx)
    }
    fn download(
        &self,
        url: &str,
        dest: &Path,
        progress: Option<Progress>,
        cancel: Option<&CancelToken>,
    ) -> Result<String> {
        lock(&self.download_calls).push((url.to_string(), dest.to_path_buf()));
        if let Some(p) = progress {
            p(1, 2, "ignored");
        }
        (lock(&self.download))(url, dest, cancel)
    }
    fn sha256_file(&self, path: &Path, cancel: Option<&CancelToken>, progress: Option<Progress2>) -> Result<String> {
        match &*lock(&self.sha) {
            Some(hook) => hook(path, cancel),
            None => crate::hash::sha256_file(path, cancel, progress),
        }
    }
    fn extract_disk_image(
        &self,
        zip_path: &Path,
        dest_dir: &Path,
        progress: Option<Progress2>,
        _cancel: Option<&CancelToken>,
    ) -> Result<PathBuf> {
        lock(&self.extract_calls).push((zip_path.to_path_buf(), dest_dir.to_path_buf()));
        if let Some(p) = progress {
            p(1, 2);
        }
        (lock(&self.extract))(zip_path, dest_dir)
    }
    fn hardening_files_windows(&self, profile: Hardening) -> Result<Files> {
        lock(&self.files_windows_calls).push(profile);
        (lock(&self.files_windows))()
    }
    fn hardening_files_seed(&self, target: SeedTarget, profile: Hardening) -> Result<(String, Files)> {
        lock(&self.files_seed_calls).push((target, profile));
        (lock(&self.files_seed))(target)
    }
    fn validate_seed_files(&self, files: &Files) -> Result<Files> {
        lock(&self.validate_calls).push(files.clone());
        (lock(&self.validate_files))(files)
    }
    fn check_seed_target_size(&self, size: Option<u64>) -> Result<()> {
        lock(&self.size_calls).push(size);
        (lock(&self.size_check))(size)
    }
    fn audit(&self, msg: &str, _level: AuditLevel) {
        lock(&self.audits).push(msg.to_string());
    }
    fn run_gui(&self) -> i32 {
        self.gui_calls.fetch_add(1, Ordering::SeqCst);
        self.gui_code.load(Ordering::SeqCst)
    }
    fn prepare_gui(&self, _err: &dyn Fn(&str)) -> Option<i32> {
        None
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The harness (`TempDirTestCase` + `run_main` of tests/helpers.py)
// ---------------------------------------------------------------------------------------------------------------

/// An in-memory stream.
#[derive(Clone, Default)]
pub struct Buf(pub Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        lock(&self.0).extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Buf {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&lock(&self.0)).to_string()
    }
}

/// A scripted stdin that remembers whether anything tried to read it.
pub struct Stdin {
    data: Cursor<Vec<u8>>,
    touched: Arc<AtomicBool>,
}

impl Read for Stdin {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.touched.store(true, Ordering::SeqCst);
        self.data.read(buf)
    }
}

impl BufRead for Stdin {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.touched.store(true, Ordering::SeqCst);
        self.data.fill_buf()
    }
    fn consume(&mut self, amount: usize) {
        self.data.consume(amount)
    }
}

pub struct T {
    _dir: tempfile::TempDir,
    pub tmp: PathBuf,
    pub engine: Arc<FakeEngine>,
    pub events: Arc<Mutex<Vec<String>>>,
    pub interrupts: Arc<Interrupts>,
    /// `_is_interactive()`.
    pub interactive: bool,
    pub env_vars: Vec<(String, String)>,
    pub stdin_touched: Arc<AtomicBool>,
}

impl T {
    pub fn new() -> T {
        let dir = tempfile::Builder::new().prefix("epma-test-").tempdir().unwrap();
        let tmp = std::fs::canonicalize(dir.path()).unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        T {
            _dir: dir,
            tmp,
            engine: Arc::new(FakeEngine::new(events.clone())),
            events,
            interrupts: Arc::new(Interrupts::manual()),
            interactive: false,
            env_vars: vec![("NO_COLOR".into(), "1".into())],
            stdin_touched: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn path(&self, name: &str) -> String {
        self.tmp.join(name).display().to_string()
    }

    pub fn write_file(&self, name: &str, data: &[u8]) -> String {
        let path = self.tmp.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, data).unwrap();
        path.display().to_string()
    }

    /// An ISO-sized file; `hybrid` adds the 0x55AA MBR boot signature.
    pub fn make_iso(&self, name: &str, size: u64, hybrid: bool) -> String {
        let mut data: Vec<u8> = (0..size).map(|i| (i.wrapping_mul(31) % 251) as u8).collect();
        data[510] = if hybrid { 0x55 } else { 0 };
        data[511] = if hybrid { 0xaa } else { 0 };
        self.write_file(name, &data)
    }

    /// The default ISO: "ubuntu.iso", 2 MiB, hybrid.
    pub fn iso(&self) -> String {
        self.make_iso("ubuntu.iso", 2 * MIB, true)
    }

    pub fn env(&self, stdin_text: &str, out: &Buf, err: &Buf) -> Env {
        let vars = self.env_vars.clone();
        Env {
            engine: self.engine.clone(),
            out: OutStream::new(Box::new(out.clone()), false),
            err: OutStream::new(Box::new(err.clone()), false),
            stdin: Mutex::new(Box::new(Stdin {
                data: Cursor::new(stdin_text.as_bytes().to_vec()),
                touched: self.stdin_touched.clone(),
            })),
            interactive: self.interactive,
            getenv: Box::new(move |name| vars.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())),
            clock: Arc::new(|| 0.0),
            interrupts: self.interrupts.clone(),
        }
    }

    /// `run_main(argv, stdin_text)`: `(exit code, stdout, stderr)`.
    pub fn run_in(&self, argv: &[&str], stdin_text: &str) -> (i32, String, String) {
        let (out, err) = (Buf::default(), Buf::default());
        let env = self.env(stdin_text, &out, &err);
        let argv: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
        let code = run(&argv, &env);
        (code, out.text(), err.text())
    }

    pub fn run(&self, argv: &[&str]) -> (i32, String, String) {
        self.run_in(argv, "")
    }

    /// `["write", "--iso", iso, "--disk", disk, *extra]` with disk9.
    pub fn write_args<'a>(&self, iso: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
        let mut argv = vec!["write", "--iso", iso, "--disk", "disk9"];
        argv.extend_from_slice(extra);
        argv
    }

    pub fn seed_args<'a>(&self, extra: &[&'a str], target: &'a str, disk: &'a str) -> Vec<&'a str> {
        let mut argv = vec!["harden-seed", "--target", target, "--disk", disk];
        argv.extend_from_slice(extra);
        argv
    }
}

pub fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("not JSON ({e}): {text:?}"))
}

pub fn first_lines(text: &str) -> Vec<String> {
    text.lines().map(|l| l.to_string()).collect()
}
