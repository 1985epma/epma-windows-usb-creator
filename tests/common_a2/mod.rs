//! Helpers shared by the A2 tests (engine, copy / verify, privilege, disk risk). Nothing here touches a real device,
//! uses sudo or the network: privileged scripts are run locally on temp files, and the engine's dispatch is replaced
//! through `EngineOps` / `CopyHost` / `SudoSys`.
#![allow(dead_code)]

use epma_usb_creator::types::{CancelToken, Ctx, Error, Log, Privilege, Progress, Result};
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

pub const MIB: usize = 1024 * 1024;
pub const GIB: u64 = 1024 * 1024 * 1024;

/// A device identifier the real `validate_device_name` accepts on this OS.
pub fn dev() -> &'static str {
    if cfg!(windows) {
        "PhysicalDrive3"
    } else {
        "disk9"
    }
}

/// Whether `tool` is on PATH (tests that need rsync, bash... skip themselves without it).
pub fn have(tool: &str) -> bool {
    epma_usb_creator::engine::which_tool(tool).is_some()
}

/// Deterministic pseudo-random bytes (the Python tests use os.urandom; nothing here needs real entropy).
pub fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

// ---------------------------------------------------------------------------------------------------------------
// log / progress recorder
// ---------------------------------------------------------------------------------------------------------------

type ProgressCall = (u64, u64, String);
type ProgressFn = Box<dyn Fn(u64, u64, &str) + Send + Sync>;
type QuietFn = Box<dyn Fn(&[String], Option<&str>) -> Option<i32> + Send + Sync>;
type WhichFn = Box<dyn Fn(&str) -> bool + Send + Sync>;
type IsFileFn = Box<dyn Fn(&std::path::Path) -> bool + Send + Sync>;
pub type RunFn = Box<dyn Fn(&[String]) -> Result<i32> + Send + Sync>;

/// The `Collector` of the Python tests: records every log line and every progress call.
pub struct Sink {
    lines: Arc<Mutex<Vec<String>>>,
    calls: Arc<Mutex<Vec<ProgressCall>>>,
    log_fn: Box<dyn Fn(&str) + Send + Sync>,
    progress_fn: ProgressFn,
}

impl Default for Sink {
    fn default() -> Self {
        Self::new()
    }
}

impl Sink {
    pub fn new() -> Self {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let l = lines.clone();
        let c = calls.clone();
        Sink {
            lines,
            calls,
            log_fn: Box::new(move |line| l.lock().unwrap().push(line.to_string())),
            progress_fn: Box::new(move |done, total, text| c.lock().unwrap().push((done, total, text.to_string()))),
        }
    }
    pub fn log(&self) -> Log<'_> {
        &*self.log_fn
    }
    pub fn progress(&self) -> Progress<'_> {
        &*self.progress_fn
    }
    /// A context that logs here and reports progress here.
    pub fn ctx<'a>(&'a self, cancel: Option<&'a CancelToken>) -> Ctx<'a> {
        Ctx::new(&*self.log_fn, Some(&*self.progress_fn), cancel)
    }
    /// A context that logs here and has no progress callback.
    pub fn ctx_no_progress<'a>(&'a self, cancel: Option<&'a CancelToken>) -> Ctx<'a> {
        Ctx::new(&*self.log_fn, None, cancel)
    }
    pub fn lines(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }
    pub fn text(&self) -> String {
        self.lines().join("\n")
    }
    pub fn calls(&self) -> Vec<ProgressCall> {
        self.calls.lock().unwrap().clone()
    }
    pub fn has_line_containing(&self, needle: &str) -> bool {
        self.lines().iter().any(|l| l.contains(needle))
    }
}

// ---------------------------------------------------------------------------------------------------------------
// temp files
// ---------------------------------------------------------------------------------------------------------------

/// A private temp directory (`TempDirTestCase`), removed on drop.
pub struct Tmp {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Default for Tmp {
    fn default() -> Self {
        Self::new()
    }
}

impl Tmp {
    pub fn new() -> Self {
        let dir = tempfile::Builder::new().prefix("epma-test-").tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        Tmp { _dir: dir, root }
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn path(&self, rel: &str) -> PathBuf {
        let mut p = self.root.clone();
        for part in rel.split('/').filter(|s| !s.is_empty()) {
            p.push(part);
        }
        p
    }
    pub fn write(&self, rel: &str, data: &[u8]) -> PathBuf {
        let p = self.path(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, data).unwrap();
        p
    }
    pub fn read(&self, rel: &str) -> Vec<u8> {
        fs::read(self.path(rel)).unwrap()
    }
    pub fn mkdir(&self, rel: &str) -> PathBuf {
        let p = self.path(rel);
        fs::create_dir_all(&p).unwrap();
        p
    }
    /// An ISO-sized file; `hybrid` adds the 0x55AA MBR boot signature.
    pub fn make_iso(&self, name: &str, size: usize, hybrid: bool) -> PathBuf {
        let mut data = pseudo_random(size, name.len() as u64 + size as u64);
        let sig: [u8; 2] = if hybrid { [0x55, 0xaa] } else { [0, 0] };
        data[510..512].copy_from_slice(&sig);
        self.write(name, &data)
    }
}

/// `{rel: bytes}` of a directory tree (files only), for comparing two trees.
pub fn read_tree(root: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        let mut entries: Vec<_> = fs::read_dir(dir).unwrap().flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let p = e.path();
            if p.is_dir() {
                walk(&p, root, out);
            } else {
                let rel = p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
                out.push((rel, fs::read(&p).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out
}

// ---------------------------------------------------------------------------------------------------------------
// privilege fakes
// ---------------------------------------------------------------------------------------------------------------

/// `LocalPriv` of the Python tests: runs the engine's scripts as the current user, with bash, no sudo.
#[derive(Default)]
pub struct LocalPriv {
    pub scripts: Mutex<Vec<(String, Vec<String>)>>,
}

impl LocalPriv {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn recorded(&self) -> Vec<(String, Vec<String>)> {
        self.scripts.lock().unwrap().clone()
    }
}

impl Privilege for LocalPriv {
    fn run_script(&self, script: &str, log: Log, args: &[String]) -> Result<()> {
        self.scripts.lock().unwrap().push((script.to_string(), args.to_vec()));
        let output = Command::new("bash")
            .arg("-c")
            .arg(script)
            .arg("win11_usb_creator")
            .args(args)
            .stdin(Stdio::null())
            .output()
            .map_err(Error::Io)?;
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        for line in text.lines() {
            log(line.trim_end());
        }
        if !output.status.success() {
            return Err(Error::runtime(format!("script failed ({})", output.status.code().unwrap_or(-1))));
        }
        Ok(())
    }
    fn authenticate(&self, _reason: &str) -> Result<bool> {
        Ok(true)
    }
}

/// A privilege that must never be used.
pub struct NoPriv;
impl Privilege for NoPriv {
    fn run_script(&self, _script: &str, _log: Log, _args: &[String]) -> Result<()> {
        panic!("no privileged script may run here");
    }
    fn authenticate(&self, _reason: &str) -> Result<bool> {
        Ok(true)
    }
}

/// Scripted answers of a `PasswordPrompt` (the window's dialog).
#[derive(Default)]
pub struct FakePrompt {
    pub answers: Mutex<VecDeque<Option<String>>>,
    pub asked: Mutex<Vec<(String, String)>>,
    pub errors: Mutex<Vec<(String, String)>>,
}

impl FakePrompt {
    pub fn with_answers(answers: &[Option<&str>]) -> Arc<Self> {
        let p = FakePrompt::default();
        *p.answers.lock().unwrap() = answers.iter().map(|a| a.map(String::from)).collect();
        Arc::new(p)
    }
}

impl epma_usb_creator::types::PasswordPrompt for FakePrompt {
    fn ask_password(&self, title: &str, prompt: &str) -> Option<String> {
        self.asked.lock().unwrap().push((title.to_string(), prompt.to_string()));
        self.answers.lock().unwrap().pop_front().unwrap_or(None)
    }
    fn show_error(&self, title: &str, message: &str) {
        self.errors.lock().unwrap().push((title.to_string(), message.to_string()));
    }
}

// ---------------------------------------------------------------------------------------------------------------
// sudo, faked
// ---------------------------------------------------------------------------------------------------------------

use epma_usb_creator::privilege::{RealSys, StdinMode, SudoSys};
use std::time::Duration;

/// "We are root" (`mock.patch.object(app.os, "geteuid", return_value=0)`): scripts really run, through bash.
pub struct RootSys;

impl SudoSys for RootSys {
    fn is_root(&self) -> bool {
        true
    }
    fn which(&self, _tool: &str) -> bool {
        false
    }
    fn run_quiet(&self, _argv: &[&str], _input: Option<&str>, _timeout: Duration) -> Option<i32> {
        None
    }
    fn call_inherit(&self, _argv: &[&str]) -> Result<i32> {
        Ok(0)
    }
    fn run_streaming(
        &self,
        argv: &[String],
        stdin: StdinMode,
        on_start: &mut dyn FnMut(),
        on_line: &mut dyn FnMut(&str),
    ) -> Result<i32> {
        RealSys.run_streaming(argv, stdin, on_start, on_line)
    }
    fn run_logged(&self, _argv: &[String], _log: Log) -> Result<()> {
        unreachable!("pkexec is never used as root")
    }
}

/// One call a `FakeSys` saw.
#[derive(Clone, Debug, PartialEq)]
pub enum SysCall {
    Quiet { argv: Vec<String>, input: Option<String>, timeout: Duration },
    Inherit { argv: Vec<String> },
    Streaming { argv: Vec<String>, stdin: String },
    Logged { argv: Vec<String> },
}

/// A scripted `SudoSys`: records every call; the answers come from the closures.
pub struct FakeSys {
    pub root: bool,
    pub tools: Vec<&'static str>,
    pub calls: Mutex<Vec<SysCall>>,
    /// Exit code of `run_quiet` for an argv (None: could not run). Receives the argv and the input text.
    pub quiet: QuietFn,
    /// `call_inherit` exit code.
    pub inherit: i32,
    /// `run_streaming`: the lines the command prints and its exit code.
    pub stream_lines: Vec<String>,
    pub stream_exit: i32,
}

impl FakeSys {
    pub fn new() -> Self {
        FakeSys {
            root: false,
            tools: vec!["sudo"],
            calls: Mutex::new(Vec::new()),
            quiet: Box::new(|_, _| Some(0)),
            inherit: 0,
            stream_lines: Vec::new(),
            stream_exit: 0,
        }
    }
    pub fn calls(&self) -> Vec<SysCall> {
        self.calls.lock().unwrap().clone()
    }
    pub fn quiet_argvs(&self) -> Vec<Vec<String>> {
        self.calls()
            .into_iter()
            .filter_map(|c| if let SysCall::Quiet { argv, .. } = c { Some(argv) } else { None })
            .collect()
    }
    pub fn streaming(&self) -> Vec<(Vec<String>, String)> {
        self.calls()
            .into_iter()
            .filter_map(|c| if let SysCall::Streaming { argv, stdin } = c { Some((argv, stdin)) } else { None })
            .collect()
    }
}

impl Default for FakeSys {
    fn default() -> Self {
        Self::new()
    }
}

impl SudoSys for FakeSys {
    fn is_root(&self) -> bool {
        self.root
    }
    fn which(&self, tool: &str) -> bool {
        self.tools.contains(&tool)
    }
    fn run_quiet(&self, argv: &[&str], input: Option<&str>, timeout: Duration) -> Option<i32> {
        let argv: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
        self.calls.lock().unwrap().push(SysCall::Quiet { argv: argv.clone(), input: input.map(String::from), timeout });
        (self.quiet)(&argv, input)
    }
    fn call_inherit(&self, argv: &[&str]) -> Result<i32> {
        self.calls.lock().unwrap().push(SysCall::Inherit { argv: argv.iter().map(|a| a.to_string()).collect() });
        Ok(self.inherit)
    }
    fn run_streaming(
        &self,
        argv: &[String],
        stdin: StdinMode,
        on_start: &mut dyn FnMut(),
        on_line: &mut dyn FnMut(&str),
    ) -> Result<i32> {
        let stdin = match stdin {
            StdinMode::Null => "null".to_string(),
            StdinMode::Inherit => "inherit".to_string(),
            StdinMode::Text(t) => format!("text:{t}"),
        };
        self.calls.lock().unwrap().push(SysCall::Streaming { argv: argv.to_vec(), stdin });
        on_start();
        for line in &self.stream_lines {
            on_line(line);
        }
        Ok(self.stream_exit)
    }
    fn run_logged(&self, argv: &[String], _log: Log) -> Result<()> {
        self.calls.lock().unwrap().push(SysCall::Logged { argv: argv.to_vec() });
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The engine's dispatch, faked
// ---------------------------------------------------------------------------------------------------------------

use epma_usb_creator::engine::{
    get_missing_dependencies_on, hash_iso_for_audit, refuse_hardening_clash_on, reverify_target_disk_on,
    validate_image_for_mode_on, EngineOps, Os,
};
use epma_usb_creator::types::{Disk, Files, Hardening, Identity, Mode};
use std::any::Any;

pub type Hook<T> = Box<dyn Fn() -> T + Send + Sync>;

/// `mock.patch.object(app, ...)` for the engine: every field replaces one step of the dispatch, the rest is the real
/// engine code. `calls` records which steps ran, in order.
pub struct FakeOps {
    pub os: Os,
    pub calls: Mutex<Vec<String>>,
    /// `get_missing_dependencies` (None: the real function against this fake's `which` / `is_file`).
    pub missing: Option<Vec<String>>,
    /// `linux_build_install_command(...)`: Some(Ok(cmd)) / Some(Err(())) = ValueError.
    pub install_cmd: Option<std::result::Result<String, ()>>,
    /// `validate_image_for_mode` (None: the real one).
    pub image: Option<PathBuf>,
    /// `hash_iso_for_audit` (None: the real one).
    pub hash: Option<Hook<Result<String>>>,
    /// `reverify_target_disk`: when true it only records "reverify" (otherwise the real one runs on `listings`).
    pub fake_reverify: bool,
    /// Successive answers of `get_external_disks()`; the last one repeats.
    pub listings: Mutex<VecDeque<Vec<Disk>>>,
    /// `refuse_hardening_clash`: when Some, replaces it (None: the real one).
    pub clash: Option<Hook<Result<()>>>,
    /// `hardening_files_windows(profile)`.
    pub hardening: Option<Files>,
    /// `validate_seed_files` raises ValueError("bad seed").
    pub seed_invalid: bool,
    pub raw: Mutex<Option<Result<bool>>>,
    pub windows: Mutex<Option<Result<bool>>>,
    pub last_hardening_files: Mutex<Option<Files>>,
    pub clash_args: Mutex<Option<(PathBuf, Files)>>,
    pub which_fn: Option<WhichFn>,
    pub is_file_fn: Option<IsFileFn>,
    /// `run_cmd` (hdiutil...): every command is recorded; `run` answers it.
    pub commands: Mutex<Vec<Vec<String>>>,
    pub run: Option<RunFn>,
}

impl FakeOps {
    pub fn new(os: Os) -> Self {
        FakeOps {
            os,
            calls: Mutex::new(Vec::new()),
            missing: Some(Vec::new()),
            install_cmd: None,
            image: None,
            hash: Some(Box::new(|| Ok("0".repeat(64)))),
            fake_reverify: true,
            listings: Mutex::new(VecDeque::new()),
            clash: Some(Box::new(|| Ok(()))),
            hardening: None,
            seed_invalid: false,
            raw: Mutex::new(None),
            windows: Mutex::new(None),
            last_hardening_files: Mutex::new(None),
            clash_args: Mutex::new(None),
            which_fn: None,
            is_file_fn: None,
            commands: Mutex::new(Vec::new()),
            run: None,
        }
    }
    pub fn commands(&self) -> Vec<Vec<String>> {
        self.commands.lock().unwrap().clone()
    }
    pub fn note(&self, what: &str) {
        self.calls.lock().unwrap().push(what.to_string());
    }
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
    pub fn called(&self, what: &str) -> bool {
        self.calls().iter().any(|c| c == what)
    }
}

impl EngineOps for FakeOps {
    fn os(&self) -> Os {
        self.os
    }
    fn which(&self, tool: &str) -> bool {
        match &self.which_fn {
            Some(f) => f(tool),
            None => panic!("which({tool}) was not faked"),
        }
    }
    fn is_file(&self, path: &Path) -> bool {
        match &self.is_file_fn {
            Some(f) => f(path),
            None => panic!("is_file was not faked"),
        }
    }
    fn powershell_exe(&self) -> PathBuf {
        PathBuf::from("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
    }
    fn dism_exe(&self) -> PathBuf {
        PathBuf::from("C:\\Windows\\System32\\dism.exe")
    }
    fn list_disks(&self) -> Result<Vec<Disk>> {
        let mut q = self.listings.lock().unwrap();
        match q.len() {
            0 => panic!("get_external_disks was not faked"),
            1 => Ok(q[0].clone()),
            _ => Ok(q.pop_front().unwrap()),
        }
    }
    fn install_command(&self, _missing: &[String]) -> Result<String> {
        match &self.install_cmd {
            Some(Ok(cmd)) => Ok(cmd.clone()),
            Some(Err(())) => Err(Error::value("no package manager")),
            None => panic!("install_command was not faked"),
        }
    }
    fn missing_dependencies(&self, mode: Mode) -> Vec<String> {
        match &self.missing {
            Some(m) => m.clone(),
            None => get_missing_dependencies_on(self, mode),
        }
    }
    fn validate_image(&self, iso_path: &Path, mode: Mode, expected_size: Option<u64>) -> Result<PathBuf> {
        match &self.image {
            Some(p) => Ok(p.clone()),
            None => validate_image_for_mode_on(self, iso_path, mode, expected_size),
        }
    }
    fn hash_iso(&self, iso_path: &Path, ctx: &Ctx) -> Result<String> {
        self.note("hash");
        match &self.hash {
            Some(f) => f(),
            None => hash_iso_for_audit(iso_path, ctx),
        }
    }
    fn reverify(&self, dev: &str, size: Option<u64>, log: Log, identity: Option<&Identity>) -> Result<()> {
        self.note("reverify");
        if self.fake_reverify {
            Ok(())
        } else {
            reverify_target_disk_on(self, dev, size, log, identity)
        }
    }
    fn refuse_clash(&self, iso: &Path, files: &Files, ctx: &Ctx, priv_: &dyn Privilege) -> Result<()> {
        match &self.clash {
            Some(f) => {
                self.note("clash");
                *self.clash_args.lock().unwrap() = Some((iso.to_path_buf(), files.clone()));
                f()
            }
            None => refuse_hardening_clash_on(self, iso, files, ctx, priv_),
        }
    }
    fn hardening_files(&self, _profile: Hardening) -> Result<Files> {
        self.note("hardening_files");
        Ok(self.hardening.clone().expect("hardening_files_windows was not faked"))
    }
    fn validate_files(&self, files: &Files) -> Result<Files> {
        self.note("validate_files");
        if self.seed_invalid {
            return Err(Error::value("bad seed"));
        }
        Ok(files.clone())
    }
    fn prevent_sleep(&self, _log: Log) -> Box<dyn Any> {
        self.note("sleep");
        Box::new(())
    }
    fn run_cmd(
        &self,
        args: &[String],
        _log: Log,
        _check: bool,
        _timeout: Option<Duration>,
        _cancel: Option<&CancelToken>,
    ) -> Result<i32> {
        self.commands.lock().unwrap().push(args.to_vec());
        match &self.run {
            Some(f) => f(args),
            None => Ok(0),
        }
    }
    fn write_raw(&self, _iso: &Path, _dev: &str, _ctx: &Ctx, _priv: &dyn Privilege, _eject: bool) -> Result<bool> {
        self.note("raw");
        self.raw.lock().unwrap().take().unwrap_or(Ok(true))
    }
    fn build_windows_usb(
        &self,
        _iso: &Path,
        _dev: &str,
        _ctx: &Ctx,
        _priv: &dyn Privilege,
        _eject: bool,
        files: Option<&Files>,
    ) -> Result<bool> {
        self.note("win");
        *self.last_hardening_files.lock().unwrap() = files.cloned();
        self.windows.lock().unwrap().take().unwrap_or(Ok(true))
    }
}

/// `shutil.copytree(src, dst, dirs_exist_ok=True)`.
pub fn copy_tree(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap().flatten() {
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            copy_tree(&from, &to);
        } else {
            fs::copy(&from, &to).unwrap();
        }
    }
}
