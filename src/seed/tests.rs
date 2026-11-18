//! Tests of the seed drive engine (port of tests/test_hardening_engine_seed.py: validate_seed_files,
//! validate_seed_label, check_seed_target_size, build_seed_usb, stage/copy/verify; the parts of
//! tests/test_hardening_seed.py that hand the generated content to the validators live in
//! tests/test_hardening_seed_a4.rs).
//!
//! Nothing here touches a real device or uses sudo: every outside effect goes through `FakeEnv` or runs against temp
//! directories.

use super::*;
use crate::types::CancelToken;
use std::cell::RefCell;
use std::sync::Mutex;

const MIB: u64 = 1024 * 1024;
const ONE_GIB: u64 = 1024 * 1024 * 1024;
const LABEL: &str = "CIDATA";
const WIN_LABEL: &str = "EPMA-SEED";

fn files_of(pairs: &[(&str, &[u8])]) -> Files {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_vec())).collect()
}

fn plain_files() -> Files {
    files_of(&[("user-data", b"#cloud-config\n"), ("README.txt", b"hello\n")])
}

/// A stand-in for what `hardening_files_seed(windows, ...)` returns: flat ASCII names with Windows extensions, CRLF
/// line endings, a UTF-8 BOM on the PowerShell file.
fn win_files() -> Files {
    files_of(&[
        ("harden.cmd", b"@echo off\r\nnet session >nul 2>&1\r\nif errorlevel 1 goto elevate\r\n:elevate\r\n"),
        ("audit.cmd", b"@echo off\r\npowershell -File harden.ps1 -Audit\r\n"),
        ("undo.cmd", b"@echo off\r\npowershell -File harden.ps1 -Undo\r\n"),
        ("harden.ps1", b"\xef\xbb\xbf# fake\r\nWrite-Output 'x'\r\n"),
        ("README.txt", b"Run harden.cmd as administrator.\r\n"),
    ])
}

fn message(e: Error) -> String {
    e.to_string()
}

fn rejected(files: &Files) -> String {
    validate_seed_files(files).expect_err("the files must be refused").to_string()
}

fn one(path: &str) -> Files {
    files_of(&[(path, b"x")])
}

// ---------------------------------------------------------------------------------------------------------------
// 1. validate_seed_files
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn a_plain_set_is_returned_as_a_copy() {
    let files = files_of(&[("user-data", b"a"), ("meta-data", b"b"), ("README.txt", b"c")]);
    let clean = validate_seed_files(&files).unwrap();
    assert_eq!(clean, files);
    assert_eq!(clean.keys().collect::<Vec<_>>(), files.keys().collect::<Vec<_>>(), "the order is kept");
}

#[test]
fn dollar_signs_and_nested_folders_are_ordinary() {
    let files = files_of(&[
        ("sources/$OEM$/$$/Setup/Scripts/SetupComplete.cmd", b"x"),
        ("sources/$OEM$/$$/Setup/Scripts/harden.ps1", b"y"),
        ("answer-standin.xml", b"<z/>"),
    ]);
    assert_eq!(validate_seed_files(&files).unwrap(), files);
}

#[test]
fn an_empty_file_is_allowed() {
    let files = files_of(&[("empty", b"")]);
    assert_eq!(validate_seed_files(&files).unwrap(), files);
}

#[test]
fn limits_are_inclusive() {
    let big = vec![b'x'; SEED_MAX_FILE_BYTES as usize];
    assert_eq!(SEED_MAX_FILE_BYTES, 256 * 1024);
    assert_eq!(SEED_MAX_TOTAL_BYTES, 2 * MIB);
    let mut files = Files::new();
    files.insert("one".to_string(), big.clone());
    validate_seed_files(&files).unwrap(); // exactly 256 KiB
    let eight: Files = (0..8).map(|i| (format!("f{i}"), big.clone())).collect();
    validate_seed_files(&eight).unwrap(); // exactly 2 MiB together
    let name = format!("{}a", "d/".repeat(119)); // 239 characters
    validate_seed_files(&one(&name)).unwrap();
    validate_seed_files(&one(&"a".repeat(SEED_MAX_PATH_CHARS))).unwrap(); // exactly 240 characters
}

#[test]
fn non_ascii_names_are_fine() {
    validate_seed_files(&one("l\u{e9}ame-a\u{e7}\u{e3}o.txt")).unwrap();
}

#[test]
fn same_name_in_different_folders_is_not_a_duplicate() {
    validate_seed_files(&files_of(&[("a/x", b"1"), ("b/x", b"2")])).unwrap();
}

#[test]
fn parent_directory_components() {
    for path in ["..", "../etc/passwd", "a/../../b", "a/..", "a/../b"] {
        let text = rejected(&one(path));
        assert!(text.contains(".."), "{path}: {text}");
    }
}

#[test]
fn absolute_paths() {
    for path in ["/etc/passwd", "/user-data", "//server/share"] {
        let text = rejected(&one(path));
        assert!(text.contains("is absolute"), "{path}: {text}");
    }
}

#[test]
fn drive_letters_and_colons() {
    assert!(rejected(&one("C:/Windows/x")).contains("FAT32"));
    assert!(rejected(&one("a:b")).contains("FAT32"));
}

#[test]
fn backslashes() {
    for path in ["a\\b", "..\\x", "\\abs"] {
        assert!(rejected(&one(path)).contains("backslash"), "{path}");
    }
}

#[test]
fn nul_and_control_characters() {
    assert!(rejected(&one("a\0b")).contains("NUL"));
    for path in ["a\nb", "a\tb", "a\x7fb", "a\x1fb"] {
        assert!(rejected(&one(path)).contains("control"), "{path:?}");
    }
}

#[test]
fn long_names() {
    assert!(rejected(&one(&"a".repeat(241))).contains("longer than 240"));
    assert!(rejected(&one(&format!("{}ab", "d/".repeat(120)))).contains("longer than 240"));
}

#[test]
fn empty_and_dot_components() {
    for path in ["", "a//b", "a/", "./a", "a/./b", "."] {
        rejected(&one(path));
    }
    assert!(rejected(&one("")).contains("empty path"));
    assert!(rejected(&one("a//b")).contains("empty or '.' component"));
}

#[test]
fn names_fat32_cannot_store() {
    for path in ["a?", "a*b", "a<b", "a\"b", "a|b", "name.", "name ", "dir /x", "CON", "nul.txt", "COM1", "lpt9.cfg"] {
        rejected(&one(path));
    }
    assert!(rejected(&one("a?")).contains("'?', which FAT32 cannot store"));
    assert!(rejected(&one("a?*")).contains("'*?', which FAT32 cannot store"), "the characters are sorted");
    assert!(rejected(&one("nul.txt")).contains("reserved device name"));
    assert!(rejected(&one("name.")).contains("ending in a space or a dot"));
}

#[test]
fn size_limits() {
    let mut big = Files::new();
    big.insert("big".to_string(), vec![b'x'; SEED_MAX_FILE_BYTES as usize + 1]);
    let text = rejected(&big);
    assert!(text.contains("256"), "{text}");
    assert!(text.contains("per file"));
    let nine: Files = (0..9).map(|i| (format!("f{i}"), vec![b'x'; SEED_MAX_FILE_BYTES as usize])).collect();
    assert!(rejected(&nine).contains("together"));
}

#[test]
fn names_that_differ_only_by_case() {
    assert!(rejected(&files_of(&[("README.txt", b"1"), ("readme.TXT", b"2")])).contains("letter case"));
    assert!(rejected(&files_of(&[("A/b", b"1"), ("a/B", b"2")])).contains("letter case"));
}

#[test]
fn a_file_cannot_also_be_a_folder() {
    assert!(rejected(&files_of(&[("a", b"1"), ("a/b", b"2")])).contains("is a file"));
    assert!(rejected(&files_of(&[("A", b"1"), ("a/b", b"2")])).contains("is a file"));
}

#[test]
fn no_files_and_too_many_files() {
    assert!(rejected(&Files::new()).contains("no seed files"));
    let many: Files = (0..=SEED_MAX_FILES).map(|i| (format!("f{i}"), Vec::new())).collect();
    assert!(rejected(&many).contains("Too many"));
    let exact: Files = (0..SEED_MAX_FILES).map(|i| (format!("f{i}"), Vec::new())).collect();
    validate_seed_files(&exact).unwrap();
}

#[test]
fn the_message_names_the_path_and_stays_short() {
    let text = rejected(&one(&format!("{}\\", "x".repeat(5000))));
    assert!(text.len() < 400, "{}", text.len());
    assert!(text.contains("..."), "the long path is shortened");
}

#[test]
fn nothing_is_changed_on_failure() {
    let files = files_of(&[("ok", b"1"), ("../bad", b"2")]);
    let before = files.clone();
    validate_seed_files(&files).unwrap_err();
    assert_eq!(files, before);
}

#[test]
fn the_first_offending_path_is_named() {
    let text = rejected(&files_of(&[("ok", b"1"), ("../bad", b"2"), ("a\\b", b"3")]));
    assert!(text.contains("'../bad'"), "{text}");
}

// ---------------------------------------------------------------------------------------------------------------
// 2. validate_seed_label
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn labels_of_the_targets_are_valid() {
    let eleven = "A".repeat(11);
    for label in ["CIDATA", "OEMDRV", "EPMA-SEED", "A", eleven.as_str(), "_X", "0-9_"] {
        assert_eq!(validate_seed_label(label).unwrap(), label);
    }
}

#[test]
fn invalid_labels() {
    let twelve = "A".repeat(12);
    let bad = [
        "",
        twelve.as_str(),
        "cidata",
        "CI DATA",
        "CI.DATA",
        "CIDATA\n",
        "-X",
        "A;B",
        "$(id)",
        "A/B",
        "\u{c1}",
        "A\0",
        "CIDATA ",
        " CIDATA",
        "'",
    ];
    for label in bad {
        let text = validate_seed_label(label).expect_err(label).to_string();
        assert!(text.starts_with("Invalid seed drive label"), "{label:?}: {text}");
    }
}

#[test]
fn the_label_message_says_what_is_allowed() {
    let text = message(validate_seed_label("cidata").unwrap_err());
    assert_eq!(
        text,
        "Invalid seed drive label 'cidata': use 1 to 11 characters from A-Z, 0-9, '_' and '-' (not starting with '-')."
    );
}

// ---------------------------------------------------------------------------------------------------------------
// 3. check_seed_target_size
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn a_known_size_under_64_mib_is_refused_with_a_friendly_message() {
    let re = regex::Regex::new(
        r"^The drive \(.*\) is too small for a seed drive \(at least 64.*\)\. Nothing was changed\.$",
    )
    .unwrap();
    for size in [1, 10 * MIB, SEED_MIN_DRIVE_BYTES - 1] {
        let text = check_seed_target_size(Some(size)).expect_err("too small").to_string();
        assert!(re.is_match(&text), "{text}");
    }
    assert!(matches!(check_seed_target_size(Some(1)), Err(Error::Value(_))));
}

#[test]
fn sixty_four_mib_and_more_pass() {
    for size in [SEED_MIN_DRIVE_BYTES, 16 * 1024 * MIB] {
        check_seed_target_size(Some(size)).unwrap();
    }
}

#[test]
fn an_unknown_size_passes() {
    check_seed_target_size(None).unwrap();
    check_seed_target_size(Some(0)).unwrap();
}

// ---------------------------------------------------------------------------------------------------------------
// 4. build_seed_usb: order of operations, validation, cancel, audit, eject
// ---------------------------------------------------------------------------------------------------------------

/// `(label, files, stage dir, dev, eject)` of a backend call.
type BackendCall = (String, Files, PathBuf, String, bool);
type BackendHook = Box<dyn FnMut(&Ctx)>;

/// What the fake backend saw of the stage directory when it was called.
#[derive(Default, Clone)]
struct StageInfo {
    stage: Option<PathBuf>,
    #[cfg(unix)]
    dir_mode: u32,
    files: Vec<(String, Vec<u8>, u32)>,
}

struct FakeEnv {
    events: RefCell<Vec<String>>,
    audits: RefCell<Vec<(String, AuditLevel)>>,
    seed: RefCell<(String, Files)>,
    /// What `hardening_files_seed` was asked for.
    seed_args: RefCell<Vec<(SeedTarget, Hardening)>>,
    missing: RefCell<Vec<String>>,
    reverify: RefCell<Option<Error>>,
    reverify_args: RefCell<Vec<(String, Option<u64>)>>,
    platform: RefCell<Platform>,
    /// What the backend answers (`Err` is taken once).
    backend: RefCell<Option<Result<bool>>>,
    backend_args: RefCell<Vec<BackendCall>>,
    stage_seen: RefCell<StageInfo>,
    on_backend: RefCell<Option<BackendHook>>,
}

impl FakeEnv {
    fn new() -> Self {
        FakeEnv {
            events: RefCell::new(Vec::new()),
            audits: RefCell::new(Vec::new()),
            seed: RefCell::new((LABEL.to_string(), plain_files())),
            seed_args: RefCell::new(Vec::new()),
            missing: RefCell::new(Vec::new()),
            reverify: RefCell::new(None),
            reverify_args: RefCell::new(Vec::new()),
            platform: RefCell::new(Platform::Linux),
            backend: RefCell::new(None),
            backend_args: RefCell::new(Vec::new()),
            stage_seen: RefCell::new(StageInfo::default()),
            on_backend: RefCell::new(None),
        }
    }
    fn events(&self) -> Vec<String> {
        self.events.borrow().clone()
    }
    fn audits(&self) -> Vec<String> {
        self.audits.borrow().iter().map(|(m, _)| m.clone()).collect()
    }
    fn set_seed(&self, label: &str, files: Files) {
        *self.seed.borrow_mut() = (label.to_string(), files);
    }
    fn backend_called(
        &self,
        name: &str,
        label: &str,
        files: &Files,
        stage: &Path,
        dev: &str,
        ctx: &Ctx,
        eject: bool,
    ) -> Result<bool> {
        self.events.borrow_mut().push(name.to_string());
        self.inspect_stage(stage);
        self.backend_args.borrow_mut().push((
            label.to_string(),
            files.clone(),
            stage.to_path_buf(),
            dev.to_string(),
            eject,
        ));
        if let Some(hook) = self.on_backend.borrow_mut().as_mut() {
            hook(ctx);
        }
        self.backend.borrow_mut().take().unwrap_or(Ok(true))
    }
    fn inspect_stage(&self, stage: &Path) {
        let mut info = StageInfo { stage: Some(stage.to_path_buf()), ..Default::default() };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            info.dir_mode = fs::metadata(stage).unwrap().permissions().mode() & 0o7777;
        }
        let mut stack = vec![stage.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                #[cfg(unix)]
                let mode = {
                    use std::os::unix::fs::PermissionsExt;
                    fs::metadata(&path).unwrap().permissions().mode() & 0o7777
                };
                #[cfg(not(unix))]
                let mode = 0o600;
                let rel = path.strip_prefix(stage).unwrap().to_string_lossy().replace('\\', "/");
                info.files.push((rel, fs::read(&path).unwrap(), mode));
            }
        }
        *self.stage_seen.borrow_mut() = info;
    }
}

impl SeedEnv for FakeEnv {
    fn validate_device_name(&self, dev: &str) -> Result<String> {
        // the shape check of the real function, for every platform
        if !crate::constants::LINUX_DEVICE_RE.is_match(dev) {
            return Err(Error::value(format!("Refusing to operate on {dev:?}")));
        }
        Ok(dev.to_string())
    }
    fn dev_path(&self, dev: &str) -> String {
        format!("/dev/{dev}")
    }
    fn hardening_files_seed(&self, target: SeedTarget, profile: Hardening) -> Result<(String, Files)> {
        self.events.borrow_mut().push("seed".to_string());
        self.seed_args.borrow_mut().push((target, profile));
        let (label, files) = self.seed.borrow().clone();
        if target == SeedTarget::Windows && label == LABEL && files == plain_files() {
            return Ok((WIN_LABEL.to_string(), win_files()));
        }
        Ok((label, files))
    }
    fn missing_dependencies(&self) -> Vec<String> {
        self.missing.borrow().clone()
    }
    fn missing_dependencies_hint(&self, _missing: &[String]) -> String {
        "Install them with your package manager.".to_string()
    }
    fn reverify_target_disk(&self, dev: &str, expected_size: Option<u64>, _log: Log) -> Result<()> {
        self.events.borrow_mut().push("reverify".to_string());
        self.reverify_args.borrow_mut().push((dev.to_string(), expected_size));
        match self.reverify.borrow_mut().take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
    fn audit(&self, msg: &str, level: AuditLevel) {
        self.audits.borrow_mut().push((msg.to_string(), level));
    }
    fn with_sleep_prevented(&self, _log: Log, run: &mut dyn FnMut() -> Result<bool>) -> Result<bool> {
        self.events.borrow_mut().push("sleep_in".to_string());
        let result = run();
        self.events.borrow_mut().push("sleep_out".to_string());
        result
    }
    fn platform(&self) -> Platform {
        *self.platform.borrow()
    }
    fn build_mac(&self, label: &str, files: &Files, stage: &Path, dev: &str, ctx: &Ctx, eject: bool) -> Result<bool> {
        self.backend_called("mac", label, files, stage, dev, ctx, eject)
    }
    fn build_windows(
        &self,
        label: &str,
        files: &Files,
        stage: &Path,
        dev: &str,
        ctx: &Ctx,
        eject: bool,
    ) -> Result<bool> {
        self.backend_called("windows", label, files, stage, dev, ctx, eject)
    }
    fn build_linux(&self, label: &str, files: &Files, stage: &Path, dev: &str, ctx: &Ctx, eject: bool) -> Result<bool> {
        self.backend_called("linux", label, files, stage, dev, ctx, eject)
    }
}

fn build(env: &FakeEnv, target: SeedTarget, dev: &str, expected_size: Option<u64>, eject: bool) -> Result<bool> {
    build_seed_usb_with(env, target, dev, &Ctx::quiet(), expected_size, eject, Hardening::Baseline)
}

fn build_ok(env: &FakeEnv) -> Result<bool> {
    build(env, SeedTarget::Ubuntu, "sdb", Some(ONE_GIB), true)
}

fn nothing_touched(env: &FakeEnv) {
    let events = env.events();
    for forbidden in ["reverify", "linux", "mac", "windows"] {
        assert!(!events.iter().any(|e| e == forbidden), "{forbidden} ran: {events:?}");
    }
    assert!(!env.audits().iter().any(|a| a.starts_with("DESTRUCTIVE")), "{:?}", env.audits());
    assert!(env.stage_seen.borrow().stage.is_none(), "a stage directory was made");
}

#[test]
fn order_of_operations_on_linux() {
    let env = FakeEnv::new();
    assert!(build_ok(&env).unwrap());
    assert_eq!(env.events(), ["seed", "reverify", "sleep_in", "linux", "sleep_out"]);
    assert_eq!(*env.seed_args.borrow(), [(SeedTarget::Ubuntu, Hardening::Baseline)]);
    let args = env.backend_args.borrow();
    assert_eq!(args[0].0, LABEL);
    assert_eq!(args[0].1, plain_files());
    assert_eq!(args[0].3, "sdb");
}

#[test]
fn order_of_operations_on_macos() {
    let env = FakeEnv::new();
    *env.platform.borrow_mut() = Platform::Mac;
    assert!(build(&env, SeedTarget::Ubuntu, "disk9", Some(ONE_GIB), true).unwrap());
    assert_eq!(env.events(), ["seed", "reverify", "sleep_in", "mac", "sleep_out"]);
    let args = env.backend_args.borrow();
    assert_eq!(args[0].0, LABEL);
    assert_eq!(args[0].3, "disk9");
}

#[test]
fn order_of_operations_on_windows() {
    let env = FakeEnv::new();
    *env.platform.borrow_mut() = Platform::Windows;
    assert!(build(&env, SeedTarget::Ubuntu, "PhysicalDrive3", Some(ONE_GIB), true).unwrap());
    assert_eq!(env.events(), ["seed", "reverify", "sleep_in", "windows", "sleep_out"]);
    assert_eq!(env.backend_args.borrow()[0].3, "PhysicalDrive3");
}

#[test]
fn the_target_and_profile_reach_hardening_files_seed() {
    for target in SeedTarget::ALL {
        for profile in Hardening::ALL {
            let env = FakeEnv::new();
            build_seed_usb_with(&env, target, "sdb", &Ctx::quiet(), Some(ONE_GIB), true, profile).unwrap();
            assert_eq!(*env.seed_args.borrow(), [(target, profile)]);
        }
    }
}

#[test]
fn the_files_are_staged_privately_and_removed_afterwards() {
    let env = FakeEnv::new();
    build_ok(&env).unwrap();
    let info = env.stage_seen.borrow().clone();
    #[cfg(unix)]
    assert_eq!(info.dir_mode, 0o700);
    let staged: Files = info.files.iter().map(|(k, v, _)| (k.clone(), v.clone())).collect();
    let mut want: Vec<_> = plain_files().into_iter().collect();
    want.sort();
    let mut got: Vec<_> = staged.into_iter().collect();
    got.sort();
    assert_eq!(got, want);
    assert!(info.files.iter().all(|(_, _, mode)| *mode == 0o600));
    assert!(!info.stage.unwrap().exists(), "the staging directory was left behind");
}

#[test]
fn the_staging_directory_is_removed_after_a_failure_too() {
    let env = FakeEnv::new();
    *env.backend.borrow_mut() = Some(Err(Error::runtime("boom")));
    assert!(matches!(build_ok(&env), Err(Error::Runtime(m)) if m == "boom"));
    let stage = env.stage_seen.borrow().stage.clone().unwrap();
    assert!(!stage.exists(), "the staging directory was left behind");
}

#[test]
fn files_are_cleaned_by_the_shared_validator() {
    let env = FakeEnv::new();
    env.set_seed(LABEL, files_of(&[("a", b"1")]));
    build_ok(&env).unwrap();
    assert_eq!(env.backend_args.borrow()[0].1, files_of(&[("a", b"1")]));
}

#[test]
fn eject_result_is_passed_through() {
    for expected in [true, false] {
        let env = FakeEnv::new();
        *env.backend.borrow_mut() = Some(Ok(expected));
        assert_eq!(build_ok(&env).unwrap(), expected);
        let shown = if expected { "True" } else { "False" };
        assert!(env.audits().last().unwrap().contains(&format!("(ejected={shown})")), "{:?}", env.audits());
    }
}

#[test]
fn no_eject_is_forwarded_to_the_backend() {
    let env = FakeEnv::new();
    *env.backend.borrow_mut() = Some(Ok(false));
    assert!(!build(&env, SeedTarget::Ubuntu, "sdb", Some(ONE_GIB), false).unwrap());
    assert!(!env.backend_args.borrow()[0].4);
}

#[test]
fn progress_and_cancel_flag_are_forwarded() {
    let env = FakeEnv::new();
    let reports = Mutex::new(Vec::<String>::new());
    let progress = |_: u64, _: u64, text: &str| reports.lock().unwrap().push(text.to_string());
    let token = CancelToken::new();
    let log = |_: &str| {};
    let ctx = Ctx::new(&log, Some(&progress), Some(&token));
    *env.on_backend.borrow_mut() = Some(Box::new(|ctx: &Ctx| {
        ctx.report(1, 2, "seen by the backend");
        assert!(!ctx.is_canceled());
    }));
    build_seed_usb_with(&env, SeedTarget::Ubuntu, "sdb", &ctx, Some(ONE_GIB), true, Hardening::Baseline).unwrap();
    assert_eq!(*reports.lock().unwrap(), ["seen by the backend"]);
}

#[test]
fn bad_arguments_are_refused_first() {
    let cases: [(&str, &str, Option<u64>, &str); 3] = [
        ("device name", "sdb; rm -rf /", Some(ONE_GIB), "Refusing to operate"),
        ("device name", "../sdb", Some(ONE_GIB), "Refusing to operate"),
        ("tiny drive", "sdb", Some(SEED_MIN_DRIVE_BYTES - 1), "too small"),
    ];
    for (what, dev, size, needle) in cases {
        let env = FakeEnv::new();
        let err = build(&env, SeedTarget::Ubuntu, dev, size, true).expect_err(what);
        assert!(matches!(&err, Error::Value(m) if m.contains(needle)), "{what}: {err}");
        nothing_touched(&env);
    }
    let env = FakeEnv::new();
    let err = build(&env, SeedTarget::Ubuntu, "sdb", Some(SEED_MIN_DRIVE_BYTES - 1), true).unwrap_err();
    assert!(message(err).ends_with("Nothing was changed."));
}

#[test]
fn a_drive_of_exactly_64_mib_is_accepted_and_an_unknown_size_is_not_a_refusal() {
    let env = FakeEnv::new();
    for size in [Some(64 * MIB), None, Some(0)] {
        build(&env, SeedTarget::Ubuntu, "sdb", size, true).unwrap();
    }
    assert_eq!(env.events().iter().filter(|e| *e == "linux").count(), 3);
}

#[test]
fn a_bad_label_is_refused() {
    let twelve = "A".repeat(12);
    for label in ["cidata", "CI DATA", twelve.as_str(), "", "-X", "A;B"] {
        let env = FakeEnv::new();
        env.set_seed(label, plain_files());
        let err = build_ok(&env).expect_err(label);
        assert!(matches!(&err, Error::Value(m) if m.contains("Invalid seed drive label")), "{label}");
        nothing_touched(&env);
    }
}

#[test]
fn bad_files_are_refused() {
    let mut big = Files::new();
    big.insert("big".to_string(), vec![b'x'; SEED_MAX_FILE_BYTES as usize + 1]);
    let bad =
        [one("../x"), one("/abs"), one("a\\b"), one("a\0"), files_of(&[("A", b"1"), ("a", b"2")]), big, Files::new()];
    for files in bad {
        let env = FakeEnv::new();
        env.set_seed(LABEL, files);
        assert!(matches!(build_ok(&env), Err(Error::Value(_))));
        nothing_touched(&env);
    }
}

#[test]
fn missing_tools_are_refused_before_anything_happens() {
    let env = FakeEnv::new();
    *env.missing.borrow_mut() = vec!["parted".to_string(), "wipefs".to_string()];
    let err = build_ok(&env).unwrap_err();
    let text = message(err);
    assert!(text.starts_with("Cannot continue: required tool(s) not found: parted, wipefs. "), "{text}");
    assert!(text.ends_with("Nothing was changed."));
    nothing_touched(&env);
}

#[test]
fn the_safety_recheck_failure_stops_everything() {
    let env = FakeEnv::new();
    *env.reverify.borrow_mut() = Some(Error::runtime("Aborted for safety: changed"));
    let err = build_ok(&env).unwrap_err();
    assert!(matches!(&err, Error::Runtime(m) if m.contains("Aborted for safety")));
    assert!(!env.events().contains(&"linux".to_string()));
    assert!(!env.audits().iter().any(|a| a.starts_with("DESTRUCTIVE OPERATION START")));
}

#[test]
fn the_recheck_gets_the_device_and_the_expected_size() {
    let env = FakeEnv::new();
    build(&env, SeedTarget::Ubuntu, "sdb", Some(2 * ONE_GIB), true).unwrap();
    assert_eq!(*env.reverify_args.borrow(), [("sdb".to_string(), Some(2 * ONE_GIB))]);
}

#[test]
fn cancel_before_the_drive_is_touched() {
    let env = FakeEnv::new();
    let token = CancelToken::new();
    token.set();
    let log = |_: &str| {};
    let ctx = Ctx::new(&log, None, Some(&token));
    let err = build_seed_usb_with(&env, SeedTarget::Ubuntu, "sdb", &ctx, Some(ONE_GIB), true, Hardening::Baseline)
        .unwrap_err();
    assert!(matches!(&err, Error::Canceled { drive_touched: false, written: false, .. }));
    assert_eq!(err.to_string(), "Canceled by the user before the drive was touched.");
    assert!(!env.events().contains(&"linux".to_string()));
    assert!(env.audits().iter().any(|a| a.contains("before the drive was touched")), "{:?}", env.audits());
    assert!(!env.audits().iter().any(|a| a.starts_with("DESTRUCTIVE OPERATION START")));
    assert!(env
        .audits()
        .iter()
        .any(|a| a.starts_with("OPERATION CANCELED by the user before the drive was touched (/dev/sdb)")));
}

#[test]
fn cancel_in_the_backend_before_the_erase() {
    let env = FakeEnv::new();
    *env.backend.borrow_mut() = Some(Err(Error::canceled_with("c", false, false)));
    let err = build_ok(&env).unwrap_err();
    assert!(matches!(&err, Error::Canceled { drive_touched: false, .. }));
    let audits = env.audits();
    assert!(audits.iter().any(|a| a.contains("before the drive was touched") && a.contains("CANCELED")));
    assert!(!audits.iter().any(|a| a.contains("left unusable")));
}

#[test]
fn cancel_after_the_drive_was_touched() {
    let env = FakeEnv::new();
    *env.backend.borrow_mut() = Some(Err(Error::canceled_with("c", true, false)));
    let err = build_ok(&env).unwrap_err();
    assert!(matches!(&err, Error::Canceled { drive_touched: true, written: false, .. }));
    assert!(env.audits().iter().any(|a| a.contains("left unusable")), "{:?}", env.audits());
}

#[test]
fn cancel_during_verification() {
    let env = FakeEnv::new();
    *env.backend.borrow_mut() = Some(Err(Error::canceled_with("c", true, true)));
    let err = build_ok(&env).unwrap_err();
    assert!(matches!(&err, Error::Canceled { written: true, .. }));
    assert!(env.audits().iter().any(|a| a.contains("NOT verified")), "{:?}", env.audits());
}

#[test]
fn audit_lines_on_success() {
    let env = FakeEnv::new();
    build_ok(&env).unwrap();
    let audits = env.audits();
    let starts: Vec<_> = audits.iter().filter(|a| a.starts_with("DESTRUCTIVE OPERATION START")).collect();
    assert_eq!(starts.len(), 1);
    let start = starts[0];
    assert!(start.starts_with("DESTRUCTIVE OPERATION START: erasing /dev/sdb and writing the ubuntu hardening seed (profile=baseline, label=CIDATA, files=2, bytes="));
    assert!(regex::Regex::new(r"sha256=[0-9a-f]{64}\)$").unwrap().is_match(start));
    assert!(audits.contains(&"DESTRUCTIVE OPERATION COMPLETED on /dev/sdb (ejected=True)".to_string()));
    assert!(audits.iter().position(|a| a == start).unwrap() < audits.len() - 1);
    assert!(start.contains(&format!("bytes={}", b"#cloud-config\n".len() + b"hello\n".len())));
}

#[test]
fn audit_lines_never_contain_file_contents() {
    let env = FakeEnv::new();
    env.set_seed(LABEL, files_of(&[("user-data", b"SUPERSECRETMARKER")]));
    build_ok(&env).unwrap();
    assert!(!env.audits().iter().any(|a| a.contains("SUPERSECRETMARKER")));
}

#[test]
fn a_failure_is_audited_and_reraised() {
    let env = FakeEnv::new();
    *env.backend.borrow_mut() = Some(Err(Error::runtime("Verification FAILED: 1 file(s) differ")));
    let err = build_ok(&env).unwrap_err();
    assert!(matches!(&err, Error::Runtime(m) if m.contains("Verification FAILED")));
    let audits = env.audits();
    assert!(audits.iter().any(|a| a == "DESTRUCTIVE OPERATION FAILED on /dev/sdb: RuntimeError"), "{audits:?}");
    assert!(!audits.iter().any(|a| a.contains("COMPLETED")));
    // an I/O error is an OSError in the Python
    let env = FakeEnv::new();
    *env.backend.borrow_mut() = Some(Err(Error::Io(std::io::Error::other("disk"))));
    build_ok(&env).unwrap_err();
    assert!(env.audits().iter().any(|a| a.ends_with(": OSError")));
}

#[test]
fn sleep_is_prevented_while_the_drive_is_written() {
    let env = FakeEnv::new();
    build_ok(&env).unwrap();
    assert_eq!(env.events()[2..], ["sleep_in", "linux", "sleep_out"]);
}

// ----- the Windows seed drive -----

#[test]
fn windows_runs_the_same_steps_in_the_same_order() {
    let env = FakeEnv::new();
    assert!(build(&env, SeedTarget::Windows, "sdb", Some(ONE_GIB), true).unwrap());
    assert_eq!(env.events(), ["seed", "reverify", "sleep_in", "linux", "sleep_out"]);
    let args = env.backend_args.borrow();
    assert_eq!(args[0].0, WIN_LABEL);
    assert_eq!(args[0].1, win_files());
}

#[test]
fn every_target_is_accepted_without_extra_options() {
    for target in SeedTarget::ALL {
        let env = FakeEnv::new();
        assert!(build(&env, target, "sdb", Some(ONE_GIB), true).unwrap());
    }
}

#[test]
fn a_windows_seed_is_checked_by_the_shared_validators() {
    let env = FakeEnv::new();
    env.set_seed("epma-seed", win_files());
    let err = build(&env, SeedTarget::Windows, "sdb", Some(ONE_GIB), true).unwrap_err();
    assert!(matches!(&err, Error::Value(m) if m.contains("Invalid seed drive label")));
    nothing_touched(&env);
    let too_long = "x".repeat(241);
    let extras: [(&str, &str); 5] = [
        ("Harden.CMD", "same name as harden.cmd (FAT32 ignores case)"),
        ("sub\\harden.cmd", "a backslash"),
        ("con.cmd", "a reserved device name"),
        ("harden.cmd.", "ends with a dot"),
        (too_long.as_str(), "too long"),
    ];
    for (name, _why) in extras {
        let mut files = win_files();
        files.insert(name.to_string(), b"x".to_vec());
        let env = FakeEnv::new();
        env.set_seed(WIN_LABEL, files);
        assert!(matches!(build(&env, SeedTarget::Windows, "sdb", Some(ONE_GIB), true), Err(Error::Value(_))), "{name}");
        nothing_touched(&env);
    }
}

#[test]
fn file_names_and_crlf_survive_staging_exactly() {
    let env = FakeEnv::new();
    build(&env, SeedTarget::Windows, "sdb", Some(ONE_GIB), true).unwrap();
    let info = env.stage_seen.borrow().clone();
    let mut staged: Vec<_> = info.files.iter().map(|(k, v, _)| (k.clone(), v.clone())).collect();
    staged.sort();
    let mut want: Vec<_> = win_files().into_iter().collect();
    want.sort();
    assert_eq!(staged, want);
    // every line ends with CRLF: no bare LF anywhere
    for (name, data) in &staged {
        let text = String::from_utf8_lossy(data);
        assert!(text.contains("\r\n"), "{name}");
        assert!(!text.replace("\r\n", "").contains('\n'), "{name}");
    }
    assert!(staged.iter().all(|(name, _)| !name.contains('/')), "flat");
    assert!(info.files.iter().all(|(_, _, mode)| *mode == 0o600));
}

#[test]
fn audit_lines_of_the_windows_seed_have_the_plain_shape() {
    let env = FakeEnv::new();
    build(&env, SeedTarget::Windows, "sdb", Some(ONE_GIB), true).unwrap();
    let audits = env.audits();
    assert!(!audits.join(" | ").contains("during_setup"));
    assert!(audits.contains(&"DESTRUCTIVE OPERATION COMPLETED on /dev/sdb (ejected=True)".to_string()));
    let starts: Vec<_> = audits.iter().filter(|a| a.starts_with("DESTRUCTIVE OPERATION START")).collect();
    assert_eq!(starts.len(), 1);
    assert!(starts[0].contains("the windows hardening seed"));
    assert!(starts[0].contains(&format!("label={WIN_LABEL}")));
    assert!(starts[0].contains(&format!("files={}", win_files().len())));
    assert!(regex::Regex::new(r"sha256=[0-9a-f]{64}").unwrap().is_match(starts[0]));
}

#[test]
fn the_audit_never_carries_the_file_contents_of_the_windows_files_either() {
    let env = FakeEnv::new();
    let mut files = win_files();
    files.insert("harden.ps1".to_string(), b"SUPERSECRETMARKER\r\n".to_vec());
    env.set_seed(WIN_LABEL, files);
    build(&env, SeedTarget::Windows, "sdb", Some(ONE_GIB), true).unwrap();
    assert!(!env.audits().iter().any(|a| a.contains("SUPERSECRETMARKER")));
}

#[test]
fn windows_on_macos_uses_the_mac_backend() {
    let env = FakeEnv::new();
    *env.platform.borrow_mut() = Platform::Mac;
    assert!(build(&env, SeedTarget::Windows, "disk9", Some(ONE_GIB), true).unwrap());
    assert_eq!(env.events(), ["seed", "reverify", "sleep_in", "mac", "sleep_out"]);
    let args = env.backend_args.borrow();
    assert_eq!((args[0].0.as_str(), &args[0].1), (WIN_LABEL, &win_files()));
}

// ---------------------------------------------------------------------------------------------------------------
// 5. Staging, copy and verification helpers
// ---------------------------------------------------------------------------------------------------------------

fn no_sync(_: Log) {}

#[test]
fn staged_files_are_private_and_complete() {
    let files = files_of(&[("a/b/c.txt", b"1"), ("d", b"2")]);
    let stage = stage_seed_files(&files).unwrap();
    let _guard = StageGuard(stage.clone());
    assert_eq!(fs::read(stage.join("a").join("b").join("c.txt")).unwrap(), b"1");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&stage).unwrap().permissions().mode() & 0o7777, 0o700);
        assert_eq!(fs::metadata(stage.join("d")).unwrap().permissions().mode() & 0o7777, 0o600);
        assert_eq!(fs::metadata(stage.join("a")).unwrap().permissions().mode() & 0o7777, 0o700);
    }
}

#[test]
fn a_path_that_would_leave_the_directory_is_refused_even_if_validation_was_skipped() {
    let err = stage_seed_files(&one("../escape")).unwrap_err();
    assert!(matches!(&err, Error::Value(m) if m.contains("would leave the drive")), "{err}");
    let outside = std::env::temp_dir().join("escape");
    assert!(!outside.exists());
}

#[test]
fn staging_failure_leaves_no_directory_behind() {
    let parent = tempfile::tempdir().unwrap();
    let err = stage_seed_files_in(parent.path(), &files_of(&[("fine", b"x"), ("../escape", b"y")])).unwrap_err();
    assert!(matches!(err, Error::Value(_)));
    let left: Vec<_> = fs::read_dir(parent.path()).unwrap().collect();
    assert!(left.is_empty(), "{left:?}");
    assert!(!parent.path().parent().unwrap().join("escape").exists());
    // and a good staging leaves exactly one private directory
    let stage = stage_seed_files_in(parent.path(), &files_of(&[("fine", b"x")])).unwrap();
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 1);
    assert!(stage.starts_with(parent.path()));
    assert!(stage.file_name().unwrap().to_string_lossy().starts_with("epmaseed_"));
}

#[test]
fn staging_never_overwrites_or_follows_a_planted_name() {
    // two entries cannot map to one staged file: the second create fails instead of overwriting
    let stage = tempfile::tempdir().unwrap();
    let path = stage.path().join("f");
    create_private_file(&path).unwrap().write_all(b"1").unwrap();
    assert!(create_private_file(&path).is_err());
    #[cfg(unix)]
    {
        let target = stage.path().join("real");
        fs::write(&target, b"real").unwrap();
        std::os::unix::fs::symlink(&target, stage.path().join("link")).unwrap();
        assert!(create_private_file(&stage.path().join("link")).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"real");
    }
}

fn round_trip(files: &Files) -> (tempfile::TempDir, PathBuf) {
    let stage = stage_seed_files(files).unwrap();
    let _guard = StageGuard(stage.clone());
    let drive = tempfile::tempdir().unwrap();
    let dst = drive.path().join("drive");
    fs::create_dir_all(&dst).unwrap();
    let synced = Mutex::new(0);
    let sync = |_: Log| *synced.lock().unwrap() += 1;
    copy_seed_files_with(&stage, &dst, files, &Ctx::quiet(), &sync).unwrap();
    assert_eq!(*synced.lock().unwrap(), 1, "the writes are synced once");
    (drive, dst)
}

fn audits_into(sink: &RefCell<Vec<(String, AuditLevel)>>) -> impl Fn(&str, AuditLevel) + '_ {
    |m, l| sink.borrow_mut().push((m.to_string(), l))
}

#[test]
fn copy_then_verify_roundtrip_with_nested_folders() {
    let files = files_of(&[
        ("sources/$OEM$/$$/Setup/Scripts/SetupComplete.cmd", b"@echo off\r\n"),
        ("answer-standin.xml", b"<x/>"),
    ]);
    let (_drive, dst) = round_trip(&files);
    let sink = RefCell::new(Vec::new());
    verify_seed_files_with(&files, &dst, &Ctx::quiet(), &audits_into(&sink)).unwrap();
    assert_eq!(
        fs::read(dst.join("sources").join("$OEM$").join("$$").join("Setup").join("Scripts").join("SetupComplete.cmd"))
            .unwrap(),
        b"@echo off\r\n"
    );
    assert_eq!(sink.borrow()[0].0, "Verification passed (seed files match)");
}

#[test]
fn the_windows_set_passes_the_validator_and_round_trips_with_crlf() {
    let files = win_files();
    let clean = validate_seed_files(&files).unwrap();
    assert_eq!(clean, files);
    assert_eq!(validate_seed_label(WIN_LABEL).unwrap(), WIN_LABEL);
    let (_drive, dst) = round_trip(&clean);
    verify_seed_files_with(&clean, &dst, &Ctx::quiet(), &|_, _| {}).unwrap();
    assert_eq!(fs::read(dst.join("harden.cmd")).unwrap(), files["harden.cmd"]);
    assert!(fs::read(dst.join("harden.ps1")).unwrap().starts_with(b"\xef\xbb\xbf"), "the BOM is not dropped");
}

#[test]
fn a_line_ending_change_on_the_drive_is_a_verification_failure() {
    let files = win_files();
    let (_drive, dst) = round_trip(&files);
    let path = dst.join("harden.cmd");
    let lf_only = String::from_utf8(fs::read(&path).unwrap()).unwrap().replace("\r\n", "\n");
    fs::write(&path, lf_only).unwrap(); // what a "text mode" copy would do
    let err = verify_seed_files_with(&files, &dst, &Ctx::quiet(), &|_, _| {}).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("Verification FAILED"));
    assert!(text.contains("harden.cmd (size differs)"));
    assert!(text.contains("NOT ejected"));
}

#[test]
fn a_same_size_content_change_is_caught() {
    let files = win_files();
    let (_drive, dst) = round_trip(&files);
    let path = dst.join("harden.ps1");
    let swapped = fs::read(&path).unwrap().iter().map(|b| if *b == b'x' { b'y' } else { *b }).collect::<Vec<_>>();
    fs::write(&path, swapped).unwrap();
    let err = verify_seed_files_with(&files, &dst, &Ctx::quiet(), &|_, _| {}).unwrap_err();
    assert!(err.to_string().contains("harden.ps1 (content differs)"), "{err}");
}

#[test]
fn verify_reports_each_kind_of_difference() {
    let drive = tempfile::tempdir().unwrap();
    let dst = drive.path();
    let files = files_of(&[("same", b"abc"), ("changed", b"abc"), ("short", b"abcd"), ("gone", b"x")]);
    for (name, data) in [("same", &b"abc"[..]), ("changed", b"abd"), ("short", b"ab")] {
        fs::write(dst.join(name), data).unwrap();
    }
    let sink = RefCell::new(Vec::new());
    let err = verify_seed_files_with(&files, dst, &Ctx::quiet(), &audits_into(&sink)).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("3 file(s)"), "{text}");
    assert!(text.contains("NOT ejected"));
    assert!(text.contains("(for example: changed (content differs))"), "{text}");
    assert!(text.contains("Verification FAILED"));
    assert_eq!(sink.borrow()[0], ("VERIFICATION FAILED: 3 seed file(s) differ".to_string(), AuditLevel::Error));
}

#[test]
fn a_symlink_is_not_accepted_as_the_file() {
    #[cfg(unix)]
    {
        let drive = tempfile::tempdir().unwrap();
        let real = tempfile::NamedTempFile::new().unwrap();
        fs::write(real.path(), b"abc").unwrap();
        std::os::unix::fs::symlink(real.path(), drive.path().join("link")).unwrap();
        let err = verify_seed_files_with(&files_of(&[("link", b"abc")]), drive.path(), &Ctx::quiet(), &|_, _| {})
            .unwrap_err();
        assert!(err.to_string().contains("link (missing)"), "{err}");
    }
}

#[test]
fn a_folder_is_not_accepted_as_the_file() {
    let drive = tempfile::tempdir().unwrap();
    fs::create_dir(drive.path().join("d")).unwrap();
    let err = verify_seed_files_with(&files_of(&[("d", b"abc")]), drive.path(), &Ctx::quiet(), &|_, _| {}).unwrap_err();
    assert!(err.to_string().contains("d (missing)"));
}

#[test]
fn a_longer_file_on_the_drive_is_a_difference() {
    let drive = tempfile::tempdir().unwrap();
    fs::write(drive.path().join("f"), b"abcd").unwrap();
    let err = verify_seed_files_with(&files_of(&[("f", b"abc")]), drive.path(), &Ctx::quiet(), &|_, _| {}).unwrap_err();
    assert!(err.to_string().contains("size differs"));
}

#[test]
fn verify_is_cancelable_and_says_the_files_were_written() {
    let drive = tempfile::tempdir().unwrap();
    let token = CancelToken::new();
    token.set();
    let log = |_: &str| {};
    let ctx = Ctx::new(&log, None, Some(&token));
    let err = verify_seed_files_with(&files_of(&[("f", b"abc")]), drive.path(), &ctx, &|_, _| {}).unwrap_err();
    assert!(matches!(err, Error::Canceled { drive_touched: true, written: true, .. }));
}

#[test]
fn copy_is_cancelable_between_files_and_reports_progress() {
    let files = files_of(&[("a", b"12"), ("b", b"345")]);
    let stage = stage_seed_files(&files).unwrap();
    let _guard = StageGuard(stage.clone());
    let drive = tempfile::tempdir().unwrap();

    let token = CancelToken::new();
    let reports = Mutex::new(Vec::<(u64, u64, String)>::new());
    let t = token.clone();
    let progress = |done: u64, total: u64, text: &str| {
        reports.lock().unwrap().push((done, total, text.to_string()));
        if text == "Copying files..." {
            t.set(); // cancel right after the first file
        }
    };
    let log = |_: &str| {};
    let ctx = Ctx::new(&log, Some(&progress), Some(&token));
    let err = copy_seed_files_with(&stage, drive.path(), &files, &ctx, &no_sync).unwrap_err();
    assert!(matches!(err, Error::Canceled { drive_touched: true, written: false, .. }));
    assert!(drive.path().join("a").exists());
    assert!(!drive.path().join("b").exists(), "the second file was not copied");
    assert_eq!(reports.lock().unwrap()[0], (2, 5, "Copying files...".to_string()));
}

#[test]
fn copy_logs_each_file_and_flushes_at_the_end() {
    let files = files_of(&[("a", b"12"), ("b/c", b"345")]);
    let stage = stage_seed_files(&files).unwrap();
    let _guard = StageGuard(stage.clone());
    let drive = tempfile::tempdir().unwrap();
    let lines = Mutex::new(Vec::<String>::new());
    let log = |l: &str| lines.lock().unwrap().push(l.to_string());
    let reports = Mutex::new(Vec::<(u64, u64, String)>::new());
    let progress = |d: u64, t: u64, s: &str| reports.lock().unwrap().push((d, t, s.to_string()));
    let ctx = Ctx::new(&log, Some(&progress), None);
    copy_seed_files_with(&stage, drive.path(), &files, &ctx, &no_sync).unwrap();
    assert_eq!(
        *lines.lock().unwrap(),
        ["Copying 2 seed file(s) to the USB drive...", "a", "b/c", "Syncing writes to disk..."]
    );
    assert_eq!(reports.lock().unwrap().last().unwrap(), &(5, 5, "Flushing data to the drive...".to_string()));
    assert_eq!(fs::read(drive.path().join("b").join("c")).unwrap(), b"345");
}

#[test]
fn the_local_path_helper_refuses_anything_outside_the_root() {
    let root = tempfile::tempdir().unwrap();
    assert!(seed_local_path(root.path(), "a/b").unwrap().starts_with(root.path()));
    for bad in ["..", "../x", "a/../../x"] {
        assert!(matches!(seed_local_path(root.path(), bad), Err(Error::Value(_))), "{bad}");
    }
    assert!(seed_local_path(root.path(), "a/../b").is_ok(), "staying inside is fine");
}

#[test]
fn manifest_hash_depends_on_names_and_contents() {
    let a = seed_manifest_sha256(&files_of(&[("x", b"1"), ("y", b"2")]));
    assert_eq!(a, seed_manifest_sha256(&files_of(&[("y", b"2"), ("x", b"1")])));
    assert_ne!(a, seed_manifest_sha256(&files_of(&[("x", b"1"), ("y", b"3")])));
    assert_ne!(a, seed_manifest_sha256(&files_of(&[("x", b"1"), ("z", b"2")])));
    assert_ne!(seed_manifest_sha256(&files_of(&[("ab", b"c")])), seed_manifest_sha256(&files_of(&[("a", b"bc")])));
    // the value the Python gives for the same files
    assert_eq!(a, "71e077ee36a15aae0b492b6b3f05e40dd0e3efd16ab6575e4abfdaaa114ba6fe");
}

#[test]
fn names_in_messages_are_quoted_like_python_repr() {
    assert_eq!(seed_name("a\0b"), "'a\\x00b'");
    assert_eq!(seed_name("a'b"), "\"a'b\"");
    assert_eq!(seed_name("a'b\"c"), "'a\\'b\"c'");
    assert_eq!(seed_name("\u{e9}\u{a0}x"), "'\u{e9}\\xa0x'");
    assert_eq!(seed_name("plain"), "'plain'");
    assert_eq!(seed_name("back\\slash"), "'back\\\\slash'");
    let long = seed_name(&"y".repeat(200));
    assert_eq!(long.chars().count(), 77 + 3 + 2);
}

#[test]
fn the_constants_match_the_contract() {
    assert_eq!(SEED_MIN_DRIVE_BYTES, 64 * 1024 * 1024);
    assert_eq!(SEED_MAX_FILES, 128);
    assert_eq!(SEED_LABEL_MAX, 11);
    assert_eq!(LINUX_SEED_TOOLS, ["parted", "mkfs.vfat", "wipefs", "partprobe"]);
    assert_eq!(SEED_UNTOUCHED_MARKER, "SEED_NOT_TOUCHED");
    assert_eq!(SEED_CANCELED_MARKER, "SEED_CANCELED");
    assert_eq!(SEED_RESERVED_NAMES.len(), 22);
    for tool in LINUX_SEED_TOOLS {
        assert!(crate::constants::LINUX_REQUIRED_TOOLS.contains(tool), "{tool} must be installable by the allow list");
    }
}

// ---------------------------------------------------------------------------------------------------------------
// 6. The Python validators' answers (tests/fixtures_a4/seed_validation.json, made by make_seed_validation.py)
// ---------------------------------------------------------------------------------------------------------------

fn fixture() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures_a4/seed_validation.json");
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

/// `Ok` or the exact error message, like the fixture.
fn answer(result: Result<impl Sized>) -> std::result::Result<(), String> {
    result.map(|_| ()).map_err(|e| e.to_string())
}

fn expected(case: &serde_json::Value) -> std::result::Result<(), String> {
    match case.get("error") {
        Some(message) => Err(message.as_str().unwrap().to_string()),
        None => Ok(()),
    }
}

#[test]
fn the_file_validator_says_what_the_python_one_says() {
    let fixture = fixture();
    let cases = fixture["files"].as_array().unwrap();
    assert!(cases.len() > 60);
    for case in cases {
        let files: Files = case["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| (pair[0].as_str().unwrap().to_string(), vec![b'x'; pair[1].as_u64().unwrap() as usize]))
            .collect();
        assert_eq!(answer(validate_seed_files(&files)), expected(case), "{}", case["files"]);
    }
}

#[test]
fn the_label_validator_says_what_the_python_one_says() {
    let fixture = fixture();
    for case in fixture["labels"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        assert_eq!(answer(validate_seed_label(label)), expected(case), "{label:?}");
    }
}

#[test]
fn the_size_check_says_what_the_python_one_says() {
    let fixture = fixture();
    for case in fixture["sizes"].as_array().unwrap() {
        let size = case["size"].as_u64();
        assert_eq!(answer(check_seed_target_size(size)), expected(case), "{size:?}");
    }
}

#[test]
fn the_manifest_hash_is_the_python_one() {
    let fixture = fixture();
    for case in fixture["manifests"].as_array().unwrap() {
        let files: Files = case["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| {
                let bytes = pair[1].as_array().unwrap().iter().map(|b| b.as_u64().unwrap() as u8).collect();
                (pair[0].as_str().unwrap().to_string(), bytes)
            })
            .collect();
        assert_eq!(seed_manifest_sha256(&files), case["sha256"].as_str().unwrap(), "{}", case["files"]);
    }
}
