//! Tests of the Windows backend that run on any system (port of tests/test_windows_backend.py, the parts that
//! exercise this module).
//!
//! Nothing here needs Windows, PowerShell or a drive: the pieces that talk to Windows (PowerShell scripts, the raw
//! disk handle, the other modules) are stood in for by `FakeEnv`, and the pure parts (parsing the drive list, the
//! raw write order, identifier handling) run for real on temp files.

use super::*;
use crate::types::Volumes;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Write;
use std::rc::Rc;
use std::sync::Mutex;

const MIB: u64 = 1024 * 1024;

fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------------------------------------------

/// Which script a fake PowerShell run is about.
fn script_name(script: &str) -> &'static str {
    for (name, text) in [
        ("list", WINDOWS_LIST_SCRIPT),
        ("prepare", WINDOWS_PREPARE_SCRIPT),
        ("prepare_raw", WINDOWS_PREPARE_RAW_SCRIPT),
        ("detach", WINDOWS_DETACH_SCRIPT),
        ("iso_mount", WINDOWS_ISO_MOUNT_SCRIPT),
        ("iso_dismount", WINDOWS_ISO_DISMOUNT_SCRIPT),
    ] {
        if script == text {
            return name;
        }
    }
    "unknown"
}

fn aligned(n: u64) -> bool {
    n.rem_euclid(WINDOWS_RAW_ALIGN) == 0
}

/// A regular file standing in for `\\.\PhysicalDriveN`: same read_at / write_at / flush surface.
struct FileDisk {
    file: File,
    writes: Vec<(u64, usize)>,
    flushed: bool,
}

impl FileDisk {
    fn new(path: &Path, size: u64) -> Self {
        let file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(path).unwrap();
        file.set_len(size).unwrap();
        FileDisk { file, writes: Vec::new(), flushed: false }
    }
}

impl RawDisk for FileDisk {
    fn write_at(&mut self, offset: u64, data: &[u8]) -> std::result::Result<(), DriveIoError> {
        assert!(aligned(offset) && aligned(data.len() as u64));
        self.writes.push((offset, data.len()));
        self.file.seek(SeekFrom::Start(offset)).unwrap();
        self.file.write_all(data).unwrap();
        Ok(())
    }
    fn read_at(&mut self, offset: u64, length: usize) -> std::result::Result<Vec<u8>, DriveIoError> {
        assert!(aligned(offset) && aligned(length as u64));
        self.file.seek(SeekFrom::Start(offset)).unwrap();
        let mut buf = vec![0u8; length];
        let n = read_fill(&mut self.file, &mut buf).unwrap();
        buf.truncate(n);
        Ok(buf)
    }
    fn flush(&mut self) {
        self.flushed = true;
    }
}

/// The same drive opened twice (once to write, once to read back), like the Python test's shared object. With a
/// hook, the cancel flag is set after that many writes.
struct SharedDisk(Rc<RefCell<FileDisk>>, Option<(CancelToken, usize)>);

impl RawDisk for SharedDisk {
    fn write_at(&mut self, offset: u64, data: &[u8]) -> std::result::Result<(), DriveIoError> {
        self.0.borrow_mut().write_at(offset, data)?;
        if let Some((token, after)) = &self.1 {
            if self.0.borrow().writes.len() == *after {
                token.set();
            }
        }
        Ok(())
    }
    fn read_at(&mut self, offset: u64, length: usize) -> std::result::Result<Vec<u8>, DriveIoError> {
        self.0.borrow_mut().read_at(offset, length)
    }
    fn flush(&mut self) {
        self.0.borrow_mut().flush()
    }
}

/// Sets the cancel flag after its `after`-th write (the Python test's `write_then_cancel`).
struct CancelingDisk {
    inner: FileDisk,
    token: CancelToken,
    after: usize,
}

impl RawDisk for CancelingDisk {
    fn write_at(&mut self, offset: u64, data: &[u8]) -> std::result::Result<(), DriveIoError> {
        self.inner.write_at(offset, data)?;
        if self.inner.writes.len() == self.after {
            self.token.set();
        }
        Ok(())
    }
    fn read_at(&mut self, offset: u64, length: usize) -> std::result::Result<Vec<u8>, DriveIoError> {
        self.inner.read_at(offset, length)
    }
    fn flush(&mut self) {
        self.inner.flush()
    }
}

/// A drive that fails every write.
struct BrokenDisk;

impl RawDisk for BrokenDisk {
    fn write_at(&mut self, offset: u64, _data: &[u8]) -> std::result::Result<(), DriveIoError> {
        Err(DriveIoError { code: 5, strerror: format!("Could not write to the drive at offset {offset}") })
    }
    fn read_at(&mut self, _offset: u64, _length: usize) -> std::result::Result<Vec<u8>, DriveIoError> {
        Err(DriveIoError { code: 5, strerror: "Could not read".to_string() })
    }
    fn flush(&mut self) {}
}

type Responder = Box<dyn FnMut(&str, &[String]) -> Result<Vec<String>>>;
type PayloadFn = Box<dyn FnMut(&Path, &Path, Option<&Files>, Option<&dyn Fn() -> Result<PathBuf>>) -> Result<()>>;
/// `(script, check, timeout, a cancel flag was given)` of a PowerShell run.
type RunOpts = (&'static str, bool, Option<Duration>, bool);
/// What the runner of a script saw: the command, check, timeout, the script text and whether the file existed.
type RunnerSeen = (Vec<String>, bool, Option<Duration>, String, bool);

/// The fake outside world: records every call as an event and answers PowerShell with canned marker lines.
struct FakeEnv {
    events: RefCell<Vec<String>>,
    audits: RefCell<Vec<(String, AuditLevel)>>,
    /// The `(script name, args)` of every PowerShell run.
    runs: RefCell<Vec<(&'static str, Vec<String>)>>,
    /// The options of every PowerShell run (check flag, timeout).
    opts: RefCell<Vec<RunOpts>>,
    respond: RefCell<Responder>,
    disk: RefCell<Option<Rc<RefCell<FileDisk>>>>,
    /// Set the cancel flag after this many writes to the raw disk.
    cancel_after: RefCell<Option<(CancelToken, usize)>>,
    open_error: RefCell<Option<DriveIoError>>,
    payload: RefCell<PayloadFn>,
    seed_copy: RefCell<Option<Error>>,
    seed_verify: RefCell<Option<Error>>,
}

impl FakeEnv {
    fn new() -> Self {
        FakeEnv {
            events: RefCell::new(Vec::new()),
            audits: RefCell::new(Vec::new()),
            runs: RefCell::new(Vec::new()),
            opts: RefCell::new(Vec::new()),
            respond: RefCell::new(Box::new(|_, _| Ok(Vec::new()))),
            disk: RefCell::new(None),
            cancel_after: RefCell::new(None),
            open_error: RefCell::new(None),
            payload: RefCell::new(Box::new(|_, _, _, _| Ok(()))),
            seed_copy: RefCell::new(None),
            seed_verify: RefCell::new(None),
        }
    }

    /// Answer every PowerShell run with the lines `f(script_name, args)` returns.
    fn answer(&self, f: impl FnMut(&str, &[String]) -> Result<Vec<String>> + 'static) {
        *self.respond.borrow_mut() = Box::new(f);
    }

    /// The usual happy-path answers: a volume letter for the format and the re-attach, EJECTED for the eject.
    fn answer_normally(&self) {
        self.answer(|name, args| {
            Ok(match name {
                "prepare" => vec!["EPMA_VOLUME e 2".to_string()],
                "iso_mount" => vec!["EPMA_ISO f 0".to_string()],
                "detach" if args.get(1).map(String::as_str) == Some("1") => vec!["EPMA_VOLUME e 2".to_string()],
                "detach" => vec!["EJECTED".to_string()],
                _ => Vec::new(),
            })
        });
    }

    fn events(&self) -> Vec<String> {
        self.events.borrow().clone()
    }

    fn event(&self, text: impl Into<String>) {
        self.events.borrow_mut().push(text.into());
    }

    fn audit_texts(&self) -> Vec<String> {
        self.audits.borrow().iter().map(|(m, _)| m.clone()).collect()
    }
}

impl WinEnv for FakeEnv {
    fn audit(&self, msg: &str, level: AuditLevel) {
        self.audits.borrow_mut().push((msg.to_string(), level));
    }
    fn make_identity(&self, parts: &[(&str, Option<String>)]) -> Identity {
        let mut out: Identity = parts
            .iter()
            .filter_map(|(k, v)| {
                let v = v.as_deref()?.trim().to_string();
                (!v.is_empty()).then(|| (k.to_string(), v))
            })
            .collect();
        out.sort();
        out
    }
    fn disk_entry(
        &self,
        id: &str,
        size: u64,
        model: Option<&str>,
        volumes: Option<Vec<Volume>>,
        identity: Identity,
    ) -> Disk {
        Disk {
            id: id.to_string(),
            size,
            label: format!("{id} {size}"),
            model: model.map(str::to_string),
            volumes: volumes.map(Volumes::List).unwrap_or(Volumes::Unknown),
            identity,
        }
    }
    fn disk_number(&self, dev: &str) -> Result<u32> {
        parse_disk_number(dev)
    }
    fn dev_path(&self, dev: &str) -> String {
        format!("\\\\.\\{dev}")
    }
    fn validate_hybrid_iso(&self, _path: &Path) -> Result<()> {
        self.event("validate_iso");
        Ok(())
    }
    fn run_ps(&self, script: &str, log: Log, args: &[String], opts: &PsOptions) -> Result<i32> {
        let name = script_name(script);
        self.event(name);
        self.runs.borrow_mut().push((name, args.to_vec()));
        self.opts.borrow_mut().push((name, opts.check, opts.timeout, opts.cancel.is_some()));
        let mut respond = self.respond.borrow_mut();
        let lines = (**respond)(name, args)?;
        for line in lines {
            log(&line);
        }
        Ok(0)
    }
    fn wait_for_root(&self, letter: char, _log: Log) -> Result<PathBuf> {
        self.event(format!("root {letter}"));
        Ok(PathBuf::from(format!("{letter}:\\")))
    }
    fn open_raw_disk(&self, _number: u32, write: bool) -> std::result::Result<Box<dyn RawDisk>, RawError> {
        self.event(if write { "open_write" } else { "open_read" });
        if let Some(e) = self.open_error.borrow().clone() {
            return Err(RawError::Drive(e));
        }
        let disk = self.disk.borrow().clone().expect("the test gave no disk");
        Ok(Box::new(SharedDisk(disk, self.cancel_after.borrow().clone())))
    }
    fn copy_windows_payload(
        &self,
        src_root: &Path,
        dst_root: &Path,
        _ctx: &Ctx,
        wimlib_hint: &str,
        reopen: Option<&dyn Fn() -> Result<PathBuf>>,
        extra_files: Option<&Files>,
    ) -> Result<()> {
        self.event("payload");
        assert!(wimlib_hint.contains("install.esd is over 4 GB"));
        let mut payload = self.payload.borrow_mut();
        (**payload)(src_root, dst_root, extra_files, reopen)
    }
    fn copy_seed_files(&self, _stage_dir: &Path, _dst_root: &Path, _files: &Files, _ctx: &Ctx) -> Result<()> {
        self.event("copy_seed");
        match self.seed_copy.borrow_mut().take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
    fn verify_seed_files(&self, _files: &Files, _dst_root: &Path, _ctx: &Ctx) -> Result<()> {
        self.event("verify_seed");
        match self.seed_verify.borrow_mut().take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

/// A log that remembers its lines.
#[derive(Default)]
struct Lines(Mutex<Vec<String>>);

impl Lines {
    fn log(&self) -> impl Fn(&str) + Send + Sync + '_ {
        |line: &str| self.0.lock().unwrap().push(line.to_string())
    }
    fn all(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
    fn text(&self) -> String {
        self.all().join("\n")
    }
}

/// An ISO-sized file of pseudo-random bytes; `hybrid` adds the 0x55AA MBR boot signature.
fn make_iso(dir: &Path, name: &str, size: usize) -> PathBuf {
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    let mut data: Vec<u8> = (0..size)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect();
    data[510] = 0x55;
    data[511] = 0xaa;
    let path = dir.join(name);
    std::fs::write(&path, data).unwrap();
    path
}

fn usb_record() -> Value {
    json!({
        "Number": 3, "Model": "SanDisk Ultra", "Serial": "ABC123", "UniqueId": "USBSTOR\\X", "BusType": "USB",
        "Size": 16u64 * 1024 * 1024 * 1024, "SectorSize": 512, "HoldsSystem": false,
        "Volumes": [{"Letter": "E", "Label": "OLD", "FileSystem": "FAT32", "Size": 8u64 * 1024 * 1024 * 1024,
                     "Free": 6u64 * 1024 * 1024 * 1024}]
    })
}

/// `usb_record()` with some keys replaced.
fn usb_with(over: Value) -> Value {
    let mut rec = usb_record();
    for (k, v) in over.as_object().unwrap() {
        rec[k] = v.clone();
    }
    rec
}

fn parse(records: &[Value]) -> Vec<Disk> {
    parse_disks_with(&FakeEnv::new(), &Value::Array(records.to_vec()).to_string()).unwrap()
}

// ---------------------------------------------------------------------------------------------------------------
// ParseDisksTests
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn a_usb_drive_is_listed_with_model_volumes_and_identity() {
    let disks = parse(&[usb_record()]);
    assert_eq!(disks.len(), 1);
    let disk = &disks[0];
    assert_eq!(disk.id, "PhysicalDrive3");
    assert_eq!(disk.size, 16 * 1024 * 1024 * 1024);
    assert_eq!(disk.model.as_deref(), Some("SanDisk Ultra"));
    let gib = 1024u64 * 1024 * 1024;
    assert_eq!(
        disk.volumes,
        Volumes::List(vec![Volume {
            name: Some("OLD".into()),
            filesystem: Some("FAT32".into()),
            size: Some(8 * gib),
            used: Some(2 * gib),
            mountpoint: Some("E:\\".into()),
        }])
    );
    assert!(disk.identity.contains(&("serial".to_string(), "ABC123".to_string())));
    assert!(disk.identity.contains(&("uniqueid".to_string(), "USBSTOR\\X".to_string())));
    assert!(disk.identity.contains(&("model".to_string(), "SanDisk Ultra".to_string())));
}

#[test]
fn only_usb_drives_are_offered() {
    let records = [
        usb_with(json!({"BusType": "SATA"})),
        usb_with(json!({"BusType": "NVMe"})),
        usb_with(json!({"BusType": "File Backed Virtual"})),
    ];
    assert!(parse(&records).is_empty());
    // the bus type is compared without regard to case
    assert_eq!(parse(&[usb_with(json!({"BusType": "usb"}))]).len(), 1);
}

#[test]
fn the_disk_holding_windows_is_never_offered() {
    let env = FakeEnv::new();
    let text = Value::Array(vec![usb_with(json!({"HoldsSystem": true}))]).to_string();
    assert!(parse_disks_with(&env, &text).unwrap().is_empty());
    assert!(env.audit_texts().iter().any(|m| m.starts_with("Hiding PhysicalDrive3: it holds the running Windows")));
}

#[test]
fn an_unknown_system_flag_fails_closed() {
    let mut rec = usb_record();
    rec.as_object_mut().unwrap().remove("HoldsSystem");
    assert!(parse(&[rec]).is_empty());
    assert!(parse(&[usb_with(json!({"HoldsSystem": null}))]).is_empty());
    // only the exact JSON false lets a drive through: 0 and "False" do not
    assert!(parse(&[usb_with(json!({"HoldsSystem": 0}))]).is_empty());
    assert!(parse(&[usb_with(json!({"HoldsSystem": "False"}))]).is_empty());
}

#[test]
fn empty_card_reader_and_broken_records_are_hidden() {
    let env = FakeEnv::new();
    let records = [usb_with(json!({"Size": 0})), json!({"Number": "x"}), json!({"BusType": "USB"})];
    let text = Value::Array(records.to_vec()).to_string();
    assert!(parse_disks_with(&env, &text).unwrap().is_empty());
    let audits = env.audits.borrow().clone();
    assert!(
        audits.contains(&("Hiding PhysicalDrive3: its size is zero or unreadable".to_string(), AuditLevel::Warning))
    );
    assert!(audits
        .contains(&("Hiding a drive whose record could not be read (ValueError)".to_string(), AuditLevel::Warning)));
    assert!(
        audits.contains(&("Hiding a drive whose record could not be read (KeyError)".to_string(), AuditLevel::Warning))
    );
}

#[test]
fn a_single_object_and_empty_output_are_accepted() {
    let env = FakeEnv::new();
    assert_eq!(parse_disks_with(&env, &usb_record().to_string()).unwrap().len(), 1);
    assert!(parse_disks_with(&env, "").unwrap().is_empty());
    assert!(parse_disks_with(&env, "  \r\n").unwrap().is_empty());
    assert!(parse_disks_with(&env, "[]").unwrap().is_empty());
}

#[test]
fn a_volume_without_a_letter_has_no_mountpoint() {
    let rec = usb_with(json!({"Volumes": [{"Letter": "", "Label": "", "FileSystem": "", "Size": 100, "Free": -1}]}));
    let disks = parse(&[rec]);
    let Volumes::List(volumes) = &disks[0].volumes else { panic!("no volume list") };
    assert_eq!(volumes[0].mountpoint, None);
    assert_eq!(volumes[0].used, None);
    assert_eq!(volumes[0].name.as_deref(), Some(""));
}

#[test]
fn an_empty_volume_list_is_no_volumes() {
    let disks = parse(&[usb_with(json!({"Volumes": []}))]);
    assert_eq!(disks[0].volumes, Volumes::List(Vec::new()));
}

#[test]
fn an_unlabelled_volume_is_named_by_its_letter_and_free_space_beyond_the_size_is_unknown() {
    let rec =
        usb_with(json!({"Volumes": [{"Letter": "F", "Label": "", "FileSystem": "NTFS", "Size": 100, "Free": 200}]}));
    let disks = parse(&[rec]);
    let Volumes::List(volumes) = &disks[0].volumes else { panic!("no volume list") };
    assert_eq!(volumes[0].name.as_deref(), Some("F:"));
    assert_eq!(volumes[0].used, None);
    assert_eq!(volumes[0].mountpoint.as_deref(), Some("F:\\"));
}

#[test]
fn a_missing_model_is_none_and_numbers_may_arrive_as_text() {
    let rec = usb_with(json!({"Model": "", "Number": "7", "Size": "1000"}));
    let disks = parse(&[rec]);
    assert_eq!(disks[0].id, "PhysicalDrive7");
    assert_eq!(disks[0].size, 1000);
    assert_eq!(disks[0].model, None);
}

#[test]
fn out_of_range_disk_numbers_are_hidden() {
    assert!(parse(&[usb_with(json!({"Number": 12345}))]).is_empty());
    assert!(parse(&[usb_with(json!({"Number": -1}))]).is_empty());
}

#[test]
fn an_unreadable_listing_is_an_error() {
    let env = FakeEnv::new();
    assert!(matches!(parse_disks_with(&env, "not json"), Err(Error::Value(_))));
    assert!(matches!(parse_disks_with(&env, "42"), Err(Error::Value(_))));
}

/// The drive list of every input in tests/fixtures_a4/windows_parse_disks.json is what the Python
/// `windows_parse_disks` returned for it (the file is generated by make_windows_parse_disks.py).
#[test]
fn the_parser_agrees_with_the_python_one_on_every_recorded_input() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures_a4/windows_parse_disks.json");
    let cases: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let cases = cases["cases"].as_array().unwrap();
    assert!(cases.len() >= 10);
    for (i, case) in cases.iter().enumerate() {
        let input = case["text"].as_str().unwrap();
        let got = parse_disks_with(&FakeEnv::new(), input);
        if let Some(kind) = case.get("error") {
            assert!(got.is_err(), "case {i}: Python raised {kind}, Rust gave {got:?}");
            continue;
        }
        let got: Vec<Value> = got.unwrap().iter().map(disk_as_json).collect();
        assert_eq!(Value::Array(got), case["disks"], "case {i}: {input}");
    }
}

/// A disk as the Python dict (model "" is `None`).
fn disk_as_json(d: &Disk) -> Value {
    let Volumes::List(list) = &d.volumes else { panic!("no volume list") };
    let volumes: Vec<Value> = list
        .iter()
        .map(|v| json!({"name": v.name, "filesystem": v.filesystem, "size": v.size, "used": v.used, "mountpoint": v.mountpoint}))
        .collect();
    let identity: Vec<Value> = d.identity.iter().map(|(k, v)| json!([k, v])).collect();
    json!({"id": d.id, "size": d.size, "model": d.model, "volumes": volumes, "identity": identity})
}

// ---------------------------------------------------------------------------------------------------------------
// Identifiers (the shape check; the name validation itself belongs to validate.rs)
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn the_disk_number() {
    assert_eq!(parse_disk_number("PhysicalDrive12").unwrap(), 12);
    assert_eq!(parse_disk_number("PhysicalDrive3").unwrap(), 3);
    for bad in ["disk3", "PhysicalDrive", "PhysicalDrive3\n", "PhysicalDrive3; rm", "../PhysicalDrive3", ""] {
        assert!(matches!(parse_disk_number(bad), Err(Error::Value(_))), "{bad:?}");
    }
}

// ---------------------------------------------------------------------------------------------------------------
// ScriptShapeTests
// ---------------------------------------------------------------------------------------------------------------

const SCRIPTS: [(&str, &str); 6] = [
    ("WINDOWS_LIST_SCRIPT", WINDOWS_LIST_SCRIPT),
    ("WINDOWS_PREPARE_SCRIPT", WINDOWS_PREPARE_SCRIPT),
    ("WINDOWS_PREPARE_RAW_SCRIPT", WINDOWS_PREPARE_RAW_SCRIPT),
    ("WINDOWS_DETACH_SCRIPT", WINDOWS_DETACH_SCRIPT),
    ("WINDOWS_ISO_MOUNT_SCRIPT", WINDOWS_ISO_MOUNT_SCRIPT),
    ("WINDOWS_ISO_DISMOUNT_SCRIPT", WINDOWS_ISO_DISMOUNT_SCRIPT),
];

/// Text with the line ends of a Windows checkout (autocrlf) undone.
fn lf(text: &str) -> String {
    text.replace("\r\n", "\n")
}

#[test]
fn scripts_are_the_python_texts_byte_for_byte() {
    // SHA-256 of the six WINDOWS_*_SCRIPT constants of win11_usb_creator.py (UTF-8, LF line ends).
    let expected = [
        "5d002203c048655395e1a7e688e9a8a2b8347dd0b94ccfbac9bad81c13a31ade",
        "cb90c3b1f2d0fd041333a25d5ca3aea05d6fd8948f197087aeeeeb011620b204",
        "3af382e2c071be1b00482efb097a8f57da2591d2076a73c8dfc646566d14b966",
        "4d7f9957d8cb77e2c447d5c22bb5368d75e420230bf607d72caf7eabc2931507",
        "839c8f57946c8d36e03d74cf64aa3cbceae6c838daef9b9f1341cef1b0819786",
        "647dbfaf9b03d60c1087395a824f78d0b99db331d167cbe001896d8dcf1b47ca",
    ];
    for ((name, text), want) in SCRIPTS.iter().zip(expected) {
        assert_eq!(sha256_hex(&lf(text)), want, "{name}");
    }
    assert_eq!(
        WINDOWS_PS_PREAMBLE,
        "$ErrorActionPreference = 'Stop'\n$ProgressPreference = 'SilentlyContinue'\n\
         try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }\n"
    );
}

#[test]
fn scripts_that_take_values_declare_typed_parameters() {
    let typed = regex::Regex::new(r"^param\(\[(int|string|long)\]").unwrap();
    for (name, text) in &SCRIPTS[1..] {
        assert!(typed.is_match(text.trim()), "{name}");
    }
}

#[test]
fn destructive_scripts_check_the_disk_again_before_the_wipe() {
    for text in [WINDOWS_PREPARE_SCRIPT, WINDOWS_PREPARE_RAW_SCRIPT] {
        assert!(text.contains("-ne 'USB'"));
        let boot = text.find("IsBoot").expect("IsBoot");
        assert!(boot < text.find("Clear-Disk").expect("Clear-Disk"));
    }
}

#[test]
fn scripts_are_ascii() {
    for (name, text) in SCRIPTS {
        assert!(text.is_ascii(), "{name}");
    }
}

#[test]
fn the_temporary_script_has_a_bom_crlf_and_the_preamble() {
    let bytes = script_bytes("param([int]$N)\nGet-Disk -Number $N\n");
    assert_eq!(&bytes[..3], b"\xef\xbb\xbf");
    let text = String::from_utf8(bytes[3..].to_vec()).unwrap();
    assert!(text.starts_with("$ErrorActionPreference = 'Stop'\r\n"));
    assert!(text.ends_with("Get-Disk -Number $N\r\n"));
    assert!(!text.replace("\r\n", "").contains('\n'), "no bare LF");
    // a script that already has CRLF (a checkout with autocrlf) comes out the same
    assert_eq!(
        script_bytes("param([int]$N)\r\nGet-Disk -Number $N\r\n"),
        script_bytes("param([int]$N)\nGet-Disk -Number $N\n")
    );
}

#[test]
fn an_argument_that_looks_like_a_parameter_is_refused() {
    let log = |_: &str| {};
    let err = run_ps_with(
        Path::new("powershell.exe"),
        &|_, _, _, _, _| -> Result<i32> { panic!("must not run") },
        "param([string]$A)",
        &log,
        &["-Command".to_string()],
        &PsOptions::default(),
    )
    .unwrap_err();
    assert!(matches!(err, Error::Value(_)));
}

#[test]
fn run_ps_uses_the_absolute_powershell_and_file_mode() {
    let seen: RefCell<Vec<RunnerSeen>> = RefCell::new(Vec::new());
    let log = |_: &str| {};
    let powershell = system32_under(Path::new("C:\\Windows"), &["WindowsPowerShell", "v1.0", "powershell.exe"]);
    run_ps_with(
        &powershell,
        &|cmd, _log, check, timeout, _cancel| {
            let file = cmd[cmd.iter().position(|a| a == "-File").unwrap() + 1].clone();
            let bytes = std::fs::read(&file).unwrap();
            let exists = Path::new(&file).exists();
            seen.borrow_mut().push((cmd.to_vec(), check, timeout, String::from_utf8(bytes).unwrap(), exists));
            Ok(0)
        },
        "param([int]$N)\nGet-Disk -Number $N",
        &log,
        &["3".to_string()],
        &PsOptions::default(),
    )
    .unwrap();
    let seen = seen.borrow();
    let (cmd, check, timeout, text, existed) = &seen[0];
    assert!(cmd[0].to_lowercase().ends_with("powershell.exe"));
    assert!(cmd[0].contains("C:\\Windows"));
    assert_eq!(cmd.last().unwrap(), "3");
    assert!(cmd.iter().any(|a| a == "-NonInteractive"));
    assert!(*check);
    assert_eq!(*timeout, Some(Duration::from_secs(POWERSHELL_TIMEOUT)));
    assert!(text.starts_with("\u{feff}$ErrorActionPreference = 'Stop'"));
    assert!(text.contains("Get-Disk -Number $N"));
    assert!(*existed);
    let file = cmd[cmd.iter().position(|a| a == "-File").unwrap() + 1].clone();
    assert!(!Path::new(&file).exists(), "the temporary script is removed");
}

#[test]
fn the_temporary_script_is_removed_after_a_failure_too() {
    let files: RefCell<Vec<String>> = RefCell::new(Vec::new());
    let log = |_: &str| {};
    let result = run_ps_with(
        Path::new("p"),
        &|cmd, _, _, _, _| -> Result<i32> {
            files.borrow_mut().push(cmd[cmd.iter().position(|a| a == "-File").unwrap() + 1].clone());
            Err(Error::runtime("boom"))
        },
        "param([int]$N)",
        &log,
        &[],
        &PsOptions::default(),
    );
    assert!(result.is_err());
    assert!(!Path::new(&files.borrow()[0]).exists());
}

#[test]
fn the_command_line_keeps_values_as_separate_arguments() {
    let cmd = powershell_command(
        Path::new("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
        Path::new("C:\\Temp\\x\\script.ps1"),
        &["3".to_string(), "MY LABEL; rm".to_string(), "32212254720".to_string()],
    );
    assert_eq!(&cmd[1..7], ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"]);
    assert_eq!(&cmd[8..], ["3", "MY LABEL; rm", "32212254720"]);
}

#[test]
fn run_collect_returns_the_stripped_output_lines_and_still_logs_them() {
    let env = FakeEnv::new();
    env.answer(|_, _| Ok(vec!["  EPMA_VOLUME e 2  ".to_string(), "noise".to_string()]));
    let lines = Lines::default();
    let log = lines.log();
    let seen = env.run_collect(WINDOWS_PREPARE_SCRIPT, &log, &[], &PsOptions::default()).unwrap();
    assert_eq!(seen, ["EPMA_VOLUME e 2", "noise"]);
    assert_eq!(lines.all(), ["  EPMA_VOLUME e 2  ", "noise"]);
}

// ---------------------------------------------------------------------------------------------------------------
// System32 paths, elevation helpers
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn the_windows_folder_comes_from_the_environment_with_a_default() {
    let os = |s: &str| Some(OsString::from(s));
    assert_eq!(pick_system_root(os("D:\\Win"), os("E:\\Other")), PathBuf::from("D:\\Win"));
    assert_eq!(pick_system_root(None, os("E:\\Other")), PathBuf::from("E:\\Other"));
    assert_eq!(pick_system_root(os(""), os("E:\\Other")), PathBuf::from("E:\\Other"));
    assert_eq!(pick_system_root(None, None), PathBuf::from("C:\\Windows"));
    assert_eq!(pick_system_root(os(""), os("")), PathBuf::from("C:\\Windows"));
}

#[test]
fn tools_are_found_under_system32() {
    let root = Path::new("C:\\Windows");
    assert_eq!(system32_under(root, &["dism.exe"]), root.join("System32").join("dism.exe"));
    let ps = system32_under(root, &["WindowsPowerShell", "v1.0", "powershell.exe"]);
    assert!(ps.to_string_lossy().ends_with("powershell.exe"));
    assert!(ps.to_string_lossy().contains("System32"));
    assert!(dism_exe().to_string_lossy().to_lowercase().ends_with("dism.exe"));
    assert!(powershell_exe().to_string_lossy().to_lowercase().ends_with("powershell.exe"));
    assert!(system32("x.exe").to_string_lossy().contains("System32"));
}

#[test]
fn command_lines_are_quoted_like_the_c_runtime_wants() {
    let args: Vec<String> =
        ["a b", "c\"d", "e\\", "", "f g\\\\", "h\\\"i", "plain", "x\\ y\\"].map(String::from).to_vec();
    // the output of Python's subprocess.list2cmdline for the same list
    assert_eq!(list2cmdline(&args), r#""a b" c\"d e\ "" "f g\\\\" h\\\"i plain "x\ y\\""#);
    assert_eq!(list2cmdline(&[]), "");
    assert_eq!(list2cmdline(&["--debug".to_string()]), "--debug");
}

#[cfg(not(windows))]
#[test]
fn not_windows_means_not_admin_and_no_raw_drive() {
    assert!(!is_admin());
    assert!(!relaunch_elevated());
    enable_dpi_awareness(); // does nothing, and must not panic
    let err = RealWinEnv.open_raw_disk(3, false).err().expect("an error");
    assert!(matches!(err, RawError::Other(Error::Runtime(m)) if m.contains("only available on Windows")));
}

// ---------------------------------------------------------------------------------------------------------------
// FormatAndMountTests
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn prepare_fat32_reads_the_drive_letter_and_waits_for_the_root() {
    let env = FakeEnv::new();
    env.answer(|_, _| Ok(vec!["...".into(), "EPMA_VOLUME e 2".into()]));
    let log = |_: &str| {};
    let (root, part) = prepare_fat32(&env, 3, "WIN11USB", &log, None).unwrap();
    assert_eq!((root, part), (PathBuf::from("E:\\"), 2));
    let runs = env.runs.borrow();
    assert_eq!(runs[0].0, "prepare");
    let cap = WINDOWS_FAT32_MAX_PARTITION.to_string();
    assert_eq!(runs[0].1, ["3", "WIN11USB", cap.as_str()]);
    assert_eq!(env.events(), ["prepare", "root E"]);
}

#[test]
fn prepare_fat32_without_a_marker_is_an_error() {
    let env = FakeEnv::new();
    env.answer(|_, _| Ok(vec!["nothing useful".into()]));
    let log = |_: &str| {};
    let err = prepare_fat32(&env, 3, "WIN11USB", &log, None).unwrap_err();
    assert!(matches!(&err, Error::Runtime(m) if m.contains("did not report its drive letter")));
    assert!(!env.events().iter().any(|e| e.starts_with("root")), "nothing is waited for");
}

#[test]
fn a_marker_with_a_bad_letter_or_partition_is_refused() {
    for line in [
        "EPMA_VOLUME ../ 2",
        "EPMA_VOLUME ee 2",
        "EPMA_VOLUME 1 2",
        "EPMA_VOLUME e",
        "EPMA_VOLUME e x",
        "EPMA_VOLUME",
        "EPMA_VOLUME e 99999999999",
    ] {
        let env = FakeEnv::new();
        env.answer(move |_, _| Ok(vec![line.to_string()]));
        let log = |_: &str| {};
        assert!(matches!(prepare_fat32(&env, 3, "WIN11USB", &log, None), Err(Error::Runtime(_))), "{line}");
    }
}

#[test]
fn prepare_fat32_hands_the_cancel_flag_to_the_script_runner() {
    let env = FakeEnv::new();
    env.answer(|_, _| Ok(vec!["EPMA_VOLUME e 2".into()]));
    let token = CancelToken::new();
    let log = |_: &str| {};
    prepare_fat32(&env, 3, "WIN11USB", &log, Some(&token)).unwrap();
    assert!(env.opts.borrow()[0].3);
}

#[test]
fn the_fat32_cap_is_below_the_windows_limit() {
    const { assert!(WINDOWS_FAT32_MAX_PARTITION < 32 * 1024 * 1024 * 1024) };
}

#[test]
fn eject_reports_the_marker() {
    let log = |_: &str| {};
    let env = FakeEnv::new();
    env.answer(|_, _| Ok(vec!["EJECTED".into()]));
    assert!(eject_disk(&env, 3, &log));
    env.answer(|_, _| Ok(vec!["NOT_EJECTED".into()]));
    assert!(!eject_disk(&env, 3, &log));
    env.answer(|_, _| Err(Error::runtime("boom")));
    let lines = Lines::default();
    let note = lines.log();
    assert!(!eject_disk(&env, 3, &note));
    assert!(lines.text().contains("Warning: could not run the eject step: boom"));
    // the eject script gets the disk number, 0 for "do not re-attach", a two minute limit and must succeed
    assert_eq!(env.runs.borrow()[0].1, ["3", "0"]);
    assert_eq!(env.opts.borrow()[0], ("detach", true, Some(Duration::from_secs(120)), false));
}

#[test]
fn reopen_attaches_the_volume_again_and_returns_its_root() {
    let env = FakeEnv::new();
    env.answer(|_, _| Ok(vec!["EPMA_VOLUME g 1".into()]));
    let log = |_: &str| {};
    assert_eq!(reopen_volume(&env, 3, &log).unwrap(), PathBuf::from("G:\\"));
    assert_eq!(env.runs.borrow()[0].1, ["3", "1"]);
    env.answer(|_, _| Ok(vec!["EJECTED".into()]));
    assert!(
        matches!(reopen_volume(&env, 3, &log), Err(Error::Runtime(m)) if m.contains("Could not mount the drive again"))
    );
}

#[test]
fn mounted_iso_dismounts_only_what_it_mounted() {
    let log = |_: &str| {};
    let env = FakeEnv::new();
    env.answer(|_, _| Ok(vec!["EPMA_ISO f 0".into()]));
    let root = with_mounted_iso_env(&env, Path::new("C:\\x.iso"), &log, |root| Ok(root.to_path_buf())).unwrap();
    assert_eq!(root, PathBuf::from("F:\\"));
    assert_eq!(env.events(), ["iso_mount", "iso_dismount"]);
    // the ISO path and nothing else is the argument of both scripts, and a failed dismount is not an error
    assert_eq!(env.runs.borrow()[0].1, ["C:\\x.iso"]);
    assert_eq!(env.runs.borrow()[1].1, ["C:\\x.iso"]);
    assert_eq!(env.opts.borrow()[1], ("iso_dismount", false, Some(Duration::from_secs(120)), false));

    let env = FakeEnv::new();
    env.answer(|_, _| Ok(vec!["EPMA_ISO g 1".into()]));
    with_mounted_iso_env(&env, Path::new("C:\\x.iso"), &log, |_| Ok(())).unwrap();
    assert_eq!(env.events(), ["iso_mount"], "it was mounted before: leave it mounted");
}

#[test]
fn mounted_iso_dismounts_after_an_error_in_the_block() {
    let log = |_: &str| {};
    let env = FakeEnv::new();
    env.answer(|_, _| Ok(vec!["EPMA_ISO f 0".into()]));
    let result: Result<()> = with_mounted_iso_env(&env, Path::new("C:\\x.iso"), &log, |_| Err(Error::runtime("x")));
    assert!(matches!(result, Err(Error::Runtime(m)) if m == "x"));
    assert_eq!(env.events(), ["iso_mount", "iso_dismount"]);
}

#[test]
fn a_failing_dismount_does_not_hide_the_result() {
    let log = |_: &str| {};
    let env = FakeEnv::new();
    env.answer(|name, _| if name == "iso_mount" { Ok(vec!["EPMA_ISO f 0".into()]) } else { Err(Error::runtime("no")) });
    assert_eq!(with_mounted_iso_env(&env, Path::new("C:\\x.iso"), &log, |_| Ok(7)).unwrap(), 7);
}

#[test]
fn mounted_iso_without_a_marker_is_an_error_and_never_runs_the_block() {
    let log = |_: &str| {};
    let env = FakeEnv::new();
    env.answer(|_, _| Ok(vec!["EPMA_ISO ../ 0".into()]));
    let result: Result<()> = with_mounted_iso_env(&env, Path::new("C:\\x.iso"), &log, |_| panic!("must not run"));
    assert!(matches!(result, Err(Error::Runtime(m)) if m == "Could not mount the ISO."));
    assert_eq!(env.events(), ["iso_mount"]);
}

#[test]
fn the_wait_for_the_drive_root_gives_up_after_the_retries() {
    let looks = RefCell::new(0u32);
    let pauses = RefCell::new(0u32);
    let found = wait_for_root_with(
        'E',
        30,
        &|_| {
            *looks.borrow_mut() += 1;
            *looks.borrow() >= 3
        },
        &|| *pauses.borrow_mut() += 1,
    )
    .unwrap();
    assert_eq!(found, PathBuf::from("E:\\"));
    assert_eq!((*looks.borrow(), *pauses.borrow()), (3, 2));

    let looks = RefCell::new(0u32);
    let err = wait_for_root_with(
        'E',
        WINDOWS_MOUNT_RETRIES,
        &|_| {
            *looks.borrow_mut() += 1;
            false
        },
        &|| {},
    )
    .unwrap_err();
    assert_eq!(*looks.borrow(), WINDOWS_MOUNT_RETRIES);
    assert!(
        matches!(err, Error::Runtime(m) if m == "Windows did not make the drive E: available after formatting it.")
    );
}

// ---------------------------------------------------------------------------------------------------------------
// RawWriteTests
// ---------------------------------------------------------------------------------------------------------------

fn quiet_audit(_: &str, _: AuditLevel) {}

#[test]
fn the_head_is_written_last_and_the_content_matches() {
    let dir = tempfile::tempdir().unwrap();
    let iso = make_iso(dir.path(), "img.iso", (3 * MIB + 1000) as usize); // not a multiple of the sector size: padded
    let mut disk = FileDisk::new(&dir.path().join("disk.bin"), 8 * MIB);
    raw_write(&iso, &mut disk, &Ctx::quiet(), MIB).unwrap();
    let offsets: Vec<u64> = disk.writes.iter().map(|w| w.0).collect();
    assert_eq!(*offsets.last().unwrap(), 0, "the partition tables are written last");
    let before_head = &offsets[..offsets.len() - 1];
    assert!(before_head.windows(2).all(|w| w[0] < w[1]), "the rest is written in order");
    assert!(disk.flushed);
    let image = std::fs::read(&iso).unwrap();
    let on_disk = std::fs::read(dir.path().join("disk.bin")).unwrap();
    assert_eq!(&on_disk[..image.len()], &image[..]);
    // the padding after the end of the image is zeros
    assert!(on_disk[image.len()..(3 * MIB as usize + 4096)].iter().all(|b| *b == 0));
}

#[test]
fn a_cancel_before_the_head_leaves_it_unwritten() {
    let dir = tempfile::tempdir().unwrap();
    let iso = make_iso(dir.path(), "img.iso", (4 * MIB) as usize);
    let token = CancelToken::new();
    let mut disk =
        CancelingDisk { inner: FileDisk::new(&dir.path().join("disk.bin"), 8 * MIB), token: token.clone(), after: 2 };
    let log = |_: &str| {};
    let ctx = Ctx::new(&log, None, Some(&token));
    let err = raw_write(&iso, &mut disk, &ctx, MIB).unwrap_err();
    assert!(matches!(err, RawError::Other(Error::Canceled { drive_touched: true, written: false, .. })));
    let on_disk = std::fs::read(dir.path().join("disk.bin")).unwrap();
    assert!(on_disk[..WINDOWS_RAW_HEAD as usize].iter().all(|b| *b == 0));
}

#[test]
fn a_small_image_is_written_in_one_piece() {
    let dir = tempfile::tempdir().unwrap();
    let iso = make_iso(dir.path(), "img.iso", 64 * 1024);
    let mut disk = FileDisk::new(&dir.path().join("disk.bin"), MIB);
    raw_write(&iso, &mut disk, &Ctx::quiet(), WINDOWS_RAW_BLOCK).unwrap();
    assert_eq!(disk.writes, [(0, 64 * 1024)]);
}

#[test]
fn raw_write_reports_progress_up_to_the_total() {
    let dir = tempfile::tempdir().unwrap();
    let iso = make_iso(dir.path(), "img.iso", (3 * MIB) as usize);
    let mut disk = FileDisk::new(&dir.path().join("disk.bin"), 4 * MIB);
    let seen: Mutex<Vec<(u64, u64, String)>> = Mutex::new(Vec::new());
    let progress = |done: u64, total: u64, text: &str| seen.lock().unwrap().push((done, total, text.to_string()));
    let log = |_: &str| {};
    let ctx = Ctx::new(&log, Some(&progress), None);
    assert_eq!(raw_write(&iso, &mut disk, &ctx, MIB).unwrap(), 3 * MIB);
    let seen = seen.lock().unwrap();
    assert_eq!(seen.last().unwrap(), &(3 * MIB, 3 * MIB, "Writing the image...".to_string()));
    assert!(seen.iter().all(|(done, total, _)| done <= total));
}

#[test]
fn a_truncated_image_stops_the_write() {
    let dir = tempfile::tempdir().unwrap();
    let iso = make_iso(dir.path(), "img.iso", (2 * MIB) as usize);
    // a "disk" that shrinks the image while it is being written
    struct Shrinking(FileDisk, PathBuf);
    impl RawDisk for Shrinking {
        fn write_at(&mut self, o: u64, d: &[u8]) -> std::result::Result<(), DriveIoError> {
            std::fs::OpenOptions::new().write(true).open(&self.1).unwrap().set_len(MIB + 100).unwrap();
            self.0.write_at(o, d)
        }
        fn read_at(&mut self, o: u64, l: usize) -> std::result::Result<Vec<u8>, DriveIoError> {
            self.0.read_at(o, l)
        }
        fn flush(&mut self) {}
    }
    let mut disk = Shrinking(FileDisk::new(&dir.path().join("disk.bin"), 4 * MIB), iso.clone());
    let err = raw_write(&iso, &mut disk, &Ctx::quiet(), 4096 * 64).unwrap_err().into_error();
    assert!(matches!(err, Error::Runtime(m) if m.contains("The image ended earlier than its size said")));
}

#[test]
fn a_drive_that_refuses_a_write_is_a_drive_error() {
    let dir = tempfile::tempdir().unwrap();
    let iso = make_iso(dir.path(), "img.iso", (2 * MIB) as usize);
    let err = raw_write(&iso, &mut BrokenDisk, &Ctx::quiet(), MIB).unwrap_err();
    assert!(matches!(err, RawError::Drive(DriveIoError { code: 5, .. })));
}

#[test]
fn verify_passes_on_a_good_write_and_fails_on_a_flipped_byte() {
    let dir = tempfile::tempdir().unwrap();
    let iso = make_iso(dir.path(), "img.iso", (3 * MIB + 700) as usize);
    let mut disk = FileDisk::new(&dir.path().join("disk.bin"), 8 * MIB);
    raw_write(&iso, &mut disk, &Ctx::quiet(), MIB).unwrap();
    let lines = Lines::default();
    let log = lines.log();
    let ctx = Ctx::new(&log, None, None);
    let audits: RefCell<Vec<(String, AuditLevel)>> = RefCell::new(Vec::new());
    let audit = |m: &str, l: AuditLevel| audits.borrow_mut().push((m.to_string(), l));
    raw_verify(&iso, &mut disk, &ctx, MIB, &audit).unwrap();
    assert!(lines.text().contains("Verification passed"));
    assert_eq!(audits.borrow()[0].0, "Verification passed (raw write matches the ISO)");

    disk.file.seek(SeekFrom::Start(2 * MIB + 5)).unwrap();
    disk.file.write_all(&[0xff, 0xfe]).unwrap();
    let err = raw_verify(&iso, &mut disk, &Ctx::quiet(), MIB, &audit).unwrap_err().into_error();
    let Error::Runtime(message) = err else { panic!("not a runtime error") };
    assert!(message.contains("Verification FAILED"));
    assert!(message.contains(&(2 * MIB + 5).to_string()));
    assert!(message.contains("The drive was NOT ejected and should not be used."));
    assert!(audits
        .borrow()
        .iter()
        .any(|(m, l)| m == &format!("VERIFICATION FAILED at byte {}", 2 * MIB + 5) && *l == AuditLevel::Error));
}

#[test]
fn a_cancel_while_verifying_says_the_image_was_written() {
    let dir = tempfile::tempdir().unwrap();
    let iso = make_iso(dir.path(), "img.iso", (2 * MIB) as usize);
    let mut disk = FileDisk::new(&dir.path().join("disk.bin"), 4 * MIB);
    raw_write(&iso, &mut disk, &Ctx::quiet(), MIB).unwrap();
    let token = CancelToken::new();
    token.set();
    let log = |_: &str| {};
    let ctx = Ctx::new(&log, None, Some(&token));
    let err = raw_verify(&iso, &mut disk, &ctx, MIB, &quiet_audit).unwrap_err().into_error();
    assert!(matches!(err, Error::Canceled { drive_touched: true, written: true, .. }));
}

fn raw_env(dir: &Path, disk_size: u64) -> FakeEnv {
    let env = FakeEnv::new();
    *env.disk.borrow_mut() = Some(Rc::new(RefCell::new(FileDisk::new(&dir.join("disk.bin"), disk_size))));
    env.answer_normally();
    env
}

#[test]
fn write_raw_end_to_end_with_a_file_for_a_drive() {
    let dir = tempfile::tempdir().unwrap();
    let iso = make_iso(dir.path(), "img.iso", (2 * MIB) as usize);
    let env = raw_env(dir.path(), 4 * MIB);
    let lines = Lines::default();
    let log = lines.log();
    let ctx = Ctx::new(&log, None, None);
    let ejected = write_raw_env(&env, &iso, "PhysicalDrive3", &ctx, true).unwrap();
    assert!(ejected);
    assert_eq!(env.events(), ["validate_iso", "prepare_raw", "open_write", "open_read", "detach"]);
    assert_eq!(env.runs.borrow()[0], ("prepare_raw", vec!["3".to_string()]));
    let text = lines.text();
    assert!(text.contains("Erasing \\\\.\\PhysicalDrive3 (administrator privileges required)..."));
    assert!(text.contains("Writing the ISO to \\\\.\\PhysicalDrive3. This can take several minutes."));
    assert!(text.contains("Verification passed"));
    assert!(text.contains("click Cancel, never Format"));
    assert!(text.contains("Done! The USB drive is ready to boot."));
    assert!(text.contains("Drive ejected"));
    assert!(env.audit_texts().iter().any(|m| m.starts_with("Verification passed")));
    // and the "drive" holds the image
    assert_eq!(
        &std::fs::read(dir.path().join("disk.bin")).unwrap()[..(2 * MIB) as usize],
        &std::fs::read(&iso).unwrap()[..]
    );
}

#[test]
fn write_raw_without_eject_leaves_the_drive_connected() {
    let dir = tempfile::tempdir().unwrap();
    let iso = make_iso(dir.path(), "img.iso", (2 * MIB) as usize);
    let env = raw_env(dir.path(), 4 * MIB);
    let lines = Lines::default();
    let log = lines.log();
    let ctx = Ctx::new(&log, None, None);
    assert!(!write_raw_env(&env, &iso, "PhysicalDrive3", &ctx, false).unwrap());
    assert!(!env.events().contains(&"detach".to_string()));
    assert!(lines.text().contains("The drive was left connected, as requested."));
}

#[test]
fn write_raw_refused_by_the_drive_explains_what_to_do() {
    let dir = tempfile::tempdir().unwrap();
    let iso = make_iso(dir.path(), "img.iso", (2 * MIB) as usize);
    let env = raw_env(dir.path(), 4 * MIB);
    *env.open_error.borrow_mut() =
        Some(DriveIoError { code: 5, strerror: "Could not open \\\\.\\PhysicalDrive3".into() });
    let err = write_raw_env(&env, &iso, "PhysicalDrive3", &Ctx::quiet(), true).unwrap_err();
    let Error::Runtime(message) = err else { panic!("not a runtime error") };
    assert!(message
        .starts_with("Windows refused the write to \\\\.\\PhysicalDrive3 (Could not open \\\\.\\PhysicalDrive3)."));
    assert!(message.contains("Close any program that is using the drive"));
    assert!(!env.events().contains(&"open_read".to_string()));
}

#[test]
fn a_cancel_before_the_erase_touches_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let iso = make_iso(dir.path(), "img.iso", (2 * MIB) as usize);
    let env = raw_env(dir.path(), 4 * MIB);
    let token = CancelToken::new();
    token.set();
    let log = |_: &str| {};
    let ctx = Ctx::new(&log, None, Some(&token));
    let err = write_raw_env(&env, &iso, "PhysicalDrive3", &ctx, true).unwrap_err();
    assert!(matches!(err, Error::Canceled { drive_touched: false, written: false, .. }));
    assert_eq!(env.events(), ["validate_iso"], "no PowerShell ran");
}

#[test]
fn a_cancel_while_the_partition_table_is_cleared_changes_nothing_on_the_drive() {
    let dir = tempfile::tempdir().unwrap();
    let iso = make_iso(dir.path(), "img.iso", (4 * MIB) as usize);
    let env = raw_env(dir.path(), 8 * MIB);
    let token = CancelToken::new();
    // the erase script "runs" and then the user cancels
    let t = token.clone();
    env.answer(move |name, _| {
        if name == "prepare_raw" {
            t.set();
        }
        Ok(Vec::new())
    });
    let log = |_: &str| {};
    let ctx = Ctx::new(&log, None, Some(&token));
    let err = write_raw_env(&env, &iso, "PhysicalDrive3", &ctx, true).unwrap_err();
    // clearing the partition table is not a write of the image
    assert!(matches!(err, Error::Canceled { drive_touched: false, written: false, .. }));
    assert!(!env.events().contains(&"open_write".to_string()));
}

#[test]
fn a_cancel_during_the_write_says_the_drive_is_unusable_and_never_writes_the_head() {
    let dir = tempfile::tempdir().unwrap();
    let iso = make_iso(dir.path(), "img.iso", (4 * MIB) as usize);
    let env = raw_env(dir.path(), 8 * MIB);
    let token = CancelToken::new();
    *env.cancel_after.borrow_mut() = Some((token.clone(), 1)); // after the body, before the partition tables
    let lines = Lines::default();
    let log = lines.log();
    let ctx = Ctx::new(&log, None, Some(&token));
    let err = write_raw_env(&env, &iso, "PhysicalDrive3", &ctx, true).unwrap_err();
    assert!(matches!(err, Error::Canceled { drive_touched: true, written: false, .. }));
    assert!(lines.text().contains("Canceled. The drive holds a partial image and is unusable until written again."));
    assert!(!env.events().contains(&"open_read".to_string()), "nothing is verified or ejected");
    let on_disk = std::fs::read(dir.path().join("disk.bin")).unwrap();
    assert!(on_disk[..WINDOWS_RAW_HEAD as usize].iter().all(|b| *b == 0), "no partition table");
}

// ---------------------------------------------------------------------------------------------------------------
// build_usb / build_seed_usb flows
// ---------------------------------------------------------------------------------------------------------------

fn files_of(names: &[&str]) -> Files {
    let mut files = Files::new();
    for name in names {
        files.insert(name.to_string(), name.as_bytes().to_vec());
    }
    files
}

#[test]
fn build_usb_runs_the_steps_in_order() {
    let env = FakeEnv::new();
    env.answer_normally();
    let reopened = Rc::new(RefCell::new(None));
    let r = reopened.clone();
    *env.payload.borrow_mut() = Box::new(move |src, dst, extra, reopen| {
        assert_eq!(src, Path::new("F:\\"));
        assert_eq!(dst, Path::new("E:\\"));
        assert!(extra.is_none(), "no hardening files");
        *r.borrow_mut() = Some(reopen.expect("a reopen callback")()?);
        Ok(())
    });
    let lines = Lines::default();
    let log = lines.log();
    let ctx = Ctx::new(&log, None, None);
    assert!(build_usb_env(&env, Path::new("C:\\x.iso"), "PhysicalDrive3", &ctx, true, None).unwrap());
    assert_eq!(
        env.events(),
        // (the eject comes after the ISO is dismounted, like the Python: it is outside the `with` block)
        ["iso_mount", "prepare", "root E", "payload", "detach", "root E", "iso_dismount", "detach"]
    );
    assert_eq!(*reopened.borrow(), Some(PathBuf::from("E:\\")));
    let text = lines.text();
    assert!(text.contains("Erasing and formatting \\\\.\\PhysicalDrive3 as GPT + FAT32 ('WIN11USB')..."));
    assert!(text.contains("USB drive ready at: E:\\"));
    assert!(text.contains("Detaching and attaching the drive again to read it back from the device..."));
    assert!(text.contains("Done! The USB drive is ready to install Windows 11."));
    assert!(text.contains("Drive ejected"));
    // the drive is formatted only after the ISO mounted fine
    let events = env.events();
    assert!(events.iter().position(|e| e == "iso_mount") < events.iter().position(|e| e == "prepare"));
}

#[test]
fn build_usb_only_passes_non_empty_hardening_files() {
    for (files, expect_some) in [(Some(files_of(&["a"])), true), (Some(files_of(&[])), false), (None, false)] {
        let env = FakeEnv::new();
        env.answer_normally();
        let got = Rc::new(RefCell::new(None));
        let g = got.clone();
        *env.payload.borrow_mut() = Box::new(move |_, _, extra, _| {
            *g.borrow_mut() = Some(extra.is_some());
            Ok(())
        });
        build_usb_env(&env, Path::new("C:\\x.iso"), "PhysicalDrive3", &Ctx::quiet(), false, files.as_ref()).unwrap();
        assert_eq!(*got.borrow(), Some(expect_some));
    }
}

#[test]
fn build_usb_without_eject_leaves_the_drive_connected() {
    let env = FakeEnv::new();
    env.answer_normally();
    let lines = Lines::default();
    let log = lines.log();
    let ctx = Ctx::new(&log, None, None);
    assert!(!build_usb_env(&env, Path::new("C:\\x.iso"), "PhysicalDrive3", &ctx, false, None).unwrap());
    assert!(lines.text().contains("The drive was left connected, as requested."));
    assert_eq!(env.runs.borrow().iter().filter(|r| r.0 == "detach" && r.1[1] == "0").count(), 0);
}

#[test]
fn build_usb_cancel_before_the_erase_touches_nothing() {
    let env = FakeEnv::new();
    env.answer_normally();
    let token = CancelToken::new();
    token.set();
    let log = |_: &str| {};
    let ctx = Ctx::new(&log, None, Some(&token));
    let err = build_usb_env(&env, Path::new("C:\\x.iso"), "PhysicalDrive3", &ctx, true, None).unwrap_err();
    assert!(matches!(err, Error::Canceled { drive_touched: false, .. }));
    assert!(env.events().is_empty(), "not even the ISO was mounted");
}

#[test]
fn build_usb_cancel_during_the_copy_ejects_and_still_dismounts_the_iso() {
    for written in [false, true] {
        let env = FakeEnv::new();
        env.answer_normally();
        *env.payload.borrow_mut() =
            Box::new(move |_, _, _, _| Err(Error::canceled_with("Canceled by the user.", true, written)));
        let lines = Lines::default();
        let log = lines.log();
        let ctx = Ctx::new(&log, None, None);
        let err = build_usb_env(&env, Path::new("C:\\x.iso"), "PhysicalDrive3", &ctx, true, None).unwrap_err();
        assert!(matches!(err, Error::Canceled { written: w, .. } if w == written));
        let text = lines.text();
        if written {
            assert!(text.contains("Canceled during verification. The files were copied completely but NOT verified."));
        } else {
            assert!(text.contains("Canceled. The drive is left incomplete and unusable."));
        }
        assert_eq!(env.events(), ["iso_mount", "prepare", "root E", "payload", "detach", "iso_dismount"]);
        assert!(!text.contains("Done!"));
    }
}

#[test]
fn build_usb_other_errors_do_not_eject() {
    let env = FakeEnv::new();
    env.answer_normally();
    *env.payload.borrow_mut() = Box::new(|_, _, _, _| Err(Error::runtime("Verification FAILED: something")));
    let err = build_usb_env(&env, Path::new("C:\\x.iso"), "PhysicalDrive3", &Ctx::quiet(), true, None).unwrap_err();
    assert!(matches!(err, Error::Runtime(m) if m.contains("Verification FAILED")));
    assert_eq!(env.events(), ["iso_mount", "prepare", "root E", "payload", "iso_dismount"]);
}

#[test]
fn build_seed_usb_runs_the_steps_in_order() {
    let env = FakeEnv::new();
    env.answer_normally();
    let files = files_of(&["harden.cmd", "README.txt"]);
    let lines = Lines::default();
    let log = lines.log();
    let ctx = Ctx::new(&log, None, None);
    assert!(build_seed_usb_env(&env, "EPMA-SEED", &files, Path::new("stage"), "PhysicalDrive3", &ctx, true).unwrap());
    assert_eq!(env.events(), ["prepare", "root E", "copy_seed", "detach", "root E", "verify_seed", "detach"]);
    // the label travels as a script argument, never as script text
    assert_eq!(env.runs.borrow()[0].1[1], "EPMA-SEED");
    let text = lines.text();
    assert!(text.contains("Erasing and formatting \\\\.\\PhysicalDrive3 as GPT + FAT32 ('EPMA-SEED')..."));
    assert!(text.contains("Done! The seed drive is ready: plug it in next to the installer USB drive."));
}

#[test]
fn build_seed_usb_without_eject() {
    let env = FakeEnv::new();
    env.answer_normally();
    let lines = Lines::default();
    let log = lines.log();
    let ctx = Ctx::new(&log, None, None);
    let files = files_of(&["a"]);
    assert!(!build_seed_usb_env(&env, "EPMA-SEED", &files, Path::new("stage"), "PhysicalDrive3", &ctx, false).unwrap());
    assert!(lines.text().contains("The drive was left connected, as requested."));
}

#[test]
fn build_seed_usb_cancel_cases() {
    // before anything is touched: nothing runs
    let env = FakeEnv::new();
    let token = CancelToken::new();
    token.set();
    let log = |_: &str| {};
    let ctx = Ctx::new(&log, None, Some(&token));
    let files = files_of(&["a"]);
    let err = build_seed_usb_env(&env, "EPMA-SEED", &files, Path::new("s"), "PhysicalDrive3", &ctx, true).unwrap_err();
    assert!(matches!(err, Error::Canceled { drive_touched: false, .. }));
    assert!(env.events().is_empty());

    // while copying: the drive is left unusable and is ejected
    let env = FakeEnv::new();
    env.answer_normally();
    *env.seed_copy.borrow_mut() = Some(Error::canceled());
    let lines = Lines::default();
    let log = lines.log();
    let ctx = Ctx::new(&log, None, None);
    let err = build_seed_usb_env(&env, "EPMA-SEED", &files, Path::new("s"), "PhysicalDrive3", &ctx, true).unwrap_err();
    assert!(matches!(err, Error::Canceled { written: false, .. }));
    assert!(lines.text().contains("Canceled. The drive is left incomplete and unusable."));
    assert_eq!(env.events(), ["prepare", "root E", "copy_seed", "detach"]);

    // while verifying: written but not verified
    let env = FakeEnv::new();
    env.answer_normally();
    *env.seed_verify.borrow_mut() = Some(Error::canceled_with("Canceled by the user.", true, true));
    let lines = Lines::default();
    let log = lines.log();
    let ctx = Ctx::new(&log, None, None);
    let err = build_seed_usb_env(&env, "EPMA-SEED", &files, Path::new("s"), "PhysicalDrive3", &ctx, true).unwrap_err();
    assert!(matches!(err, Error::Canceled { written: true, .. }));
    assert!(lines.text().contains("Canceled during verification. The files were copied completely but NOT verified."));
    assert_eq!(env.events().last().unwrap(), "detach");
}

#[test]
fn build_seed_usb_verification_failure_does_not_eject() {
    let env = FakeEnv::new();
    env.answer_normally();
    *env.seed_verify.borrow_mut() = Some(Error::runtime("Verification FAILED: 1 file(s) differ"));
    let files = files_of(&["a"]);
    let err = build_seed_usb_env(&env, "EPMA-SEED", &files, Path::new("s"), "PhysicalDrive3", &Ctx::quiet(), true)
        .unwrap_err();
    assert!(matches!(err, Error::Runtime(m) if m.contains("Verification FAILED")));
    assert_eq!(env.events().iter().filter(|e| *e == "detach").count(), 1, "only the re-attach, never the eject");
}

#[test]
fn the_script_name_map_is_unique() {
    let mut seen: HashMap<&str, usize> = HashMap::new();
    for (name, text) in SCRIPTS {
        *seen.entry(script_name(text)).or_default() += 1;
        assert_ne!(script_name(text), "unknown", "{name}");
    }
    assert!(seen.values().all(|n| *n == 1));
}

// ---------------------------------------------------------------------------------------------------------------
// The capture helper behind `ps_output` (checked with the shell on unix: nothing here needs PowerShell)
// ---------------------------------------------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn a_command_is_captured_with_its_exit_status() {
    let mut cmd = Command::new("sh");
    cmd.args(["-c", "echo out; echo err >&2; exit 3"]);
    quiet(&mut cmd);
    let (ok, out, err) = capture_with_timeout(&mut cmd, Duration::from_secs(20)).unwrap();
    assert!(!ok);
    assert_eq!(out, b"out\n");
    assert_eq!(err, b"err\n");
    let mut cmd = Command::new("sh");
    cmd.args(["-c", "head -c 200000 /dev/zero"]); // more than a pipe buffer holds: nothing may block
    let (ok, out, _) = capture_with_timeout(&mut cmd, Duration::from_secs(20)).unwrap();
    assert!(ok);
    assert_eq!(out.len(), 200_000);
}

#[cfg(unix)]
#[test]
fn a_command_that_takes_too_long_is_killed_and_a_missing_one_is_named() {
    let mut cmd = Command::new("sh");
    cmd.args(["-c", "exec sleep 30"]);
    let started = Instant::now();
    assert_eq!(capture_with_timeout(&mut cmd, Duration::from_millis(200)).unwrap_err(), "TimeoutExpired");
    assert!(started.elapsed() < Duration::from_secs(20), "the child was not killed");
    let mut cmd = Command::new("/nonexistent/powershell.exe");
    assert_eq!(capture_with_timeout(&mut cmd, Duration::from_secs(5)).unwrap_err(), "FileNotFoundError");
}

#[cfg(unix)]
#[test]
fn ps_output_without_powershell_says_so() {
    // (the PowerShell path points into C:\Windows, which does not exist here)
    let err = ps_output(WINDOWS_LIST_SCRIPT, &[], Duration::from_secs(5)).unwrap_err();
    assert!(matches!(&err, Error::Runtime(m) if m == "Could not run PowerShell (FileNotFoundError)."), "{err}");
}
