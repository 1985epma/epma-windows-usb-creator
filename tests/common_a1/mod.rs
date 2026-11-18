//! Shared helpers of the A1 integration tests (the Python `tests/helpers.py`, reduced to what they need).
//!
//! Nothing here touches a real device, uses sudo or the network; the audit log is disabled for the whole test
//! process, exactly as `tests/helpers.py` does with `WIN11USB_DISABLE_AUDIT_LOG`.
#![allow(dead_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, Once};

pub const MIB: usize = 1024 * 1024;

/// Serialises the tests of one binary that change the process environment.
pub static ENV_LOCK: Mutex<()> = Mutex::new(());

static INIT: Once = Once::new();

/// Call first in every test: no test may write the user's real audit log.
pub fn init() {
    INIT.call_once(|| {
        std::env::set_var("WIN11USB_DISABLE_AUDIT_LOG", "1");
    });
}

/// Deterministic pseudo-random bytes (the Python tests use `os.urandom`).
pub fn random_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut x: u64 = seed ^ 0x9E37_79B9_7F4A_7C15;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// A private temp directory (`TempDirTestCase`).
pub struct Tmp {
    dir: tempfile::TempDir,
    pub root: PathBuf,
}

impl Tmp {
    pub fn new() -> Tmp {
        init();
        let dir = tempfile::Builder::new().prefix("epma-test-").tempdir().expect("a temp dir");
        let root = std::fs::canonicalize(dir.path()).expect("canonical temp dir");
        Tmp { dir, root }
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    pub fn write_file(&self, rel: &str, data: &[u8]) -> PathBuf {
        let path = self.path(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("parent dir");
        }
        std::fs::File::create(&path).expect("create").write_all(data).expect("write");
        path
    }

    /// An ISO-sized file; `hybrid` adds the 0x55AA MBR boot signature.
    pub fn make_iso(&self, name: &str, size: usize, hybrid: bool) -> PathBuf {
        let mut data = random_bytes(size, 7);
        if hybrid {
            data[510..512].copy_from_slice(&[0x55, 0xaa]);
        } else {
            data[510..512].copy_from_slice(&[0, 0]);
        }
        self.write_file(name, &data)
    }

    /// A ZIP archive holding `members` (name, data), deflated or stored.
    pub fn make_zip(&self, name: &str, members: &[(&str, &[u8])], deflate: bool) -> PathBuf {
        let path = self.path(name);
        let file = std::fs::File::create(&path).expect("zip file");
        let mut zip = zip::ZipWriter::new(file);
        let method = if deflate { zip::CompressionMethod::Deflated } else { zip::CompressionMethod::Stored };
        let options = zip::write::SimpleFileOptions::default().compression_method(method);
        for (member, data) in members {
            zip.start_file(*member, options).expect("start file");
            zip.write_all(data).expect("write member");
        }
        zip.finish().expect("finish zip");
        path
    }

    pub fn keep_alive(&self) -> &Path {
        self.dir.path()
    }
}

/// A disk image with a protective MBR and a GPT whose partitions carry `names`.
pub fn gpt_image(names: &[&str], size: usize, signature: bool) -> Vec<u8> {
    let mut data = random_bytes(size, 99);
    data[0..1024].fill(0);
    if signature {
        data[510..512].copy_from_slice(&[0x55, 0xaa]);
    }
    data[512..520].copy_from_slice(b"EFI PART");
    for (i, name) in names.iter().enumerate() {
        let at = 1024 + i * 128;
        let mut entry = [0u8; 128];
        entry[0..16].copy_from_slice(&[0x11; 16]); // partition type GUID (non-zero = used)
        entry[16..32].copy_from_slice(&[(i + 1) as u8; 16]); // unique GUID
        let units: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        entry[56..56 + units.len()].copy_from_slice(&units);
        data[at..at + 128].copy_from_slice(&entry);
    }
    data
}

pub const CHROMEOS_NAMES: [&str; 6] = ["KERN-A", "ROOT-A", "KERN-B", "ROOT-B", "STATE", "EFI-SYSTEM"];

/// Everything handed to a `log` callback (the Python `Collector`).
#[derive(Default)]
pub struct Collector {
    lines: Mutex<Vec<String>>,
}

impl Collector {
    pub fn new() -> Collector {
        Collector::default()
    }
    pub fn log(&self) -> impl Fn(&str) + Send + Sync + '_ {
        move |line: &str| self.lines.lock().unwrap().push(line.to_string())
    }
    pub fn lines(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }
}
