//! Port of the parts of tests/test_engine.py that exercise copyverify.rs: the dd progress log, copy_file_with_progress,
//! verify_raw_write (the privileged script run locally against temp files) and the Windows payload copy / verify.
//! (EjectTests, MacosAppNameTests, AuditTests, ImportWithoutTkTests, EjectOptionTests and DeviceNameTests belong to
//! the backends / A1.)

mod common_a2;

use common_a2::*;
use epma_usb_creator::copyverify::{
    copy_file_with_progress, copy_windows_payload_on, make_dd_log, make_progress_log, make_progress_log_with,
    verify_raw_write_chunked, verify_windows_payload_on, CopyHost, SystemHost,
};
use epma_usb_creator::types::{Error, Files, Log, Result};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

// ---------------------------------------------------------------------------------------------------------------
// MakeProgressLogTests
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn non_dd_lines_always_pass() {
    let sink = Sink::new();
    let wrapped = make_progress_log(sink.log(), 5.0);
    for i in 0..5 {
        wrapped(&format!("message {i}"));
    }
    assert_eq!(sink.lines().len(), 5);
}

#[test]
fn dd_lines_are_throttled() {
    let sink = Sink::new();
    let ticks = Mutex::new(vec![100.0, 101.0, 104.9, 105.1, 106.0].into_iter());
    let wrapped = make_progress_log_with(sink.log(), 5.0, move || ticks.lock().unwrap().next().unwrap());
    for n in 0..5 {
        wrapped(&format!("{} bytes transferred", n * 1000));
    }
    // kept: t=100 (first) and t=105.1 (>= 5s later)
    assert_eq!(sink.lines(), vec!["0 bytes transferred", "3000 bytes transferred"]);
}

// ---------------------------------------------------------------------------------------------------------------
// MakeDdLogTests
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn bytes_lines_become_progress() {
    let sink = Sink::new();
    let wrapped = make_dd_log(sink.log(), 2000, Some(sink.progress()));
    wrapped("1000 bytes (1.0 kB) copied, 1 s");
    assert_eq!(sink.calls(), vec![(1000, 2000, "Writing the image...".to_string())]);
    assert_eq!(sink.lines().len(), 1);
}

#[test]
fn dd_progress_is_clamped_to_total() {
    let sink = Sink::new();
    make_dd_log(sink.log(), 2000, Some(sink.progress()))("5000 bytes copied");
    assert_eq!(sink.calls()[0].0, 2000);
    assert_eq!(sink.calls()[0].1, 2000);
}

#[test]
fn other_lines_do_not_report_progress() {
    let sink = Sink::new();
    make_dd_log(sink.log(), 2000, Some(sink.progress()))("dd: some warning");
    assert!(sink.calls().is_empty());
    assert_eq!(sink.lines(), vec!["dd: some warning"]);
}

#[test]
fn no_progress_without_total_or_callback() {
    let sink = Sink::new();
    make_dd_log(sink.log(), 0, Some(sink.progress()))("100 bytes copied");
    make_dd_log(sink.log(), 2000, None)("100 bytes copied");
    assert_eq!(sink.lines().len(), 2);
    assert!(sink.calls().is_empty());
}

// ---------------------------------------------------------------------------------------------------------------
// CopyFileWithProgressTests
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn copies_content_and_reports_bytes() {
    let tmp = Tmp::new();
    let src = tmp.make_iso("big.bin", MIB * 5 / 2, true);
    let stamp = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
    fs::File::options().write(true).open(&src).unwrap().set_modified(stamp).unwrap();
    let dst_dir = tmp.mkdir("dst");
    let seen = Mutex::new(Vec::new());
    copy_file_with_progress(&src, &dst_dir, &|n| seen.lock().unwrap().push(n), None).unwrap();
    let dst = dst_dir.join("big.bin");
    assert_eq!(fs::read(&src).unwrap(), fs::read(&dst).unwrap());
    let seen = seen.into_inner().unwrap();
    let mut sorted = seen.clone();
    sorted.sort();
    assert_eq!(seen, sorted);
    assert_eq!(*seen.last().unwrap(), fs::metadata(&src).unwrap().len());
    assert_eq!(seen.len(), 3); // 1 MiB chunks: 1, 2, 2.5 MiB
    assert_eq!(fs::metadata(&dst).unwrap().modified().unwrap(), stamp);
}

#[test]
fn empty_file_is_copied_without_progress() {
    let tmp = Tmp::new();
    let src = tmp.write("empty.bin", b"");
    let dir = tmp.mkdir("d");
    let seen = Mutex::new(Vec::new());
    copy_file_with_progress(&src, &dir, &|n| seen.lock().unwrap().push(n), None).unwrap();
    assert!(seen.into_inner().unwrap().is_empty());
    assert_eq!(fs::metadata(dir.join("empty.bin")).unwrap().len(), 0);
}

// ---------------------------------------------------------------------------------------------------------------
// VerifyRawWriteTests: verify_raw_write with the privileged script run locally against temp files
// ---------------------------------------------------------------------------------------------------------------

struct RawVerify {
    tmp: Tmp,
    iso: PathBuf,
    data: Vec<u8>,
    priv_: LocalPriv,
}

impl RawVerify {
    fn new() -> Option<Self> {
        if !have("bash") || !have("cmp") {
            eprintln!("skipped: bash/cmp not available");
            return None;
        }
        let tmp = Tmp::new();
        let iso = tmp.make_iso("image.iso", MIB * 5 / 2, true);
        let data = fs::read(&iso).unwrap();
        Some(RawVerify { tmp, iso, data, priv_: LocalPriv::new() })
    }
    fn device(&self, data: &[u8]) -> String {
        self.tmp.write("device.img", data).to_string_lossy().into_owned()
    }
    /// The Python tests patch VERIFY_CHUNK to 1 MiB so that even a small image has several chunks.
    fn verify(&self, device: &str, sink: &Sink, with_progress: bool) -> Result<()> {
        let ctx = if with_progress { sink.ctx(None) } else { sink.ctx_no_progress(None) };
        verify_raw_write_chunked(&self.iso, device, &ctx, &self.priv_, MIB as u64, &|| 0.0)
    }
}

#[test]
fn identical_drive_passes_and_reports_progress() {
    let Some(t) = RawVerify::new() else { return };
    let sink = Sink::new();
    t.verify(&t.device(&t.data), &sink, true).unwrap();
    assert!(sink.has_line_containing("Verification passed"));
    let calls = sink.calls();
    assert!(!calls.is_empty());
    let done: Vec<u64> = calls.iter().map(|c| c.0).collect();
    let mut sorted = done.clone();
    sorted.sort();
    assert_eq!(done, sorted);
    let last = calls.last().unwrap();
    assert_eq!((last.0, last.1), (t.data.len() as u64, t.data.len() as u64));
    assert_eq!(last.2, "Verifying the written image...");
}

#[test]
fn drive_larger_than_image_passes() {
    let Some(t) = RawVerify::new() else { return };
    let mut bigger = t.data.clone();
    bigger.extend(vec![0u8; 4096]);
    t.verify(&t.device(&bigger), &Sink::new(), false).unwrap();
}

#[test]
fn script_receives_values_as_arguments() {
    let Some(t) = RawVerify::new() else { return };
    let device = t.device(&t.data);
    t.verify(&device, &Sink::new(), false).unwrap();
    let (script, args) = t.priv_.recorded().remove(0);
    assert!(script.starts_with("set -eu\n"));
    assert_eq!(args[..3], [t.iso.to_string_lossy().into_owned(), device, t.data.len().to_string()]);
    assert!(!script.contains(&*t.iso.to_string_lossy()));
}

#[test]
fn corrupt_byte_in_second_chunk_fails() {
    let Some(t) = RawVerify::new() else { return };
    let mut bad = t.data.clone();
    bad[MIB + 17] ^= 0xFF;
    let err = t.verify(&t.device(&bad), &Sink::new(), false).unwrap_err();
    assert!(matches!(err, Error::Runtime(_)));
    let text = err.to_string();
    assert!(text.contains("Verification FAILED"), "{text}");
    assert!(text.contains(&MIB.to_string()), "{text}"); // the first differing chunk starts at 1 MiB
}

#[test]
fn corrupt_first_byte_fails() {
    let Some(t) = RawVerify::new() else { return };
    let mut bad = t.data.clone();
    bad[0] ^= 0x01;
    let err = t.verify(&t.device(&bad), &Sink::new(), false).unwrap_err();
    assert!(err.to_string().contains("NOT ejected"));
}

#[test]
fn truncated_drive_fails() {
    let Some(t) = RawVerify::new() else { return };
    let err = t.verify(&t.device(&t.data[..MIB * 3 / 2]), &Sink::new(), false).unwrap_err();
    assert!(err.to_string().contains("Verification FAILED"));
}

#[test]
fn truncated_in_the_last_chunk_fails() {
    let Some(t) = RawVerify::new() else { return };
    let err = t.verify(&t.device(&t.data[..t.data.len() - 1]), &Sink::new(), false).unwrap_err();
    assert!(err.to_string().contains("Verification FAILED"));
}

#[test]
fn empty_drive_fails() {
    let Some(t) = RawVerify::new() else { return };
    let err = t.verify(&t.device(b""), &Sink::new(), false).unwrap_err();
    assert!(err.to_string().contains("Verification FAILED"));
}

#[test]
fn no_result_marker_is_an_error() {
    struct SilentPriv;
    impl epma_usb_creator::types::Privilege for SilentPriv {
        fn run_script(&self, _script: &str, log: Log, _args: &[String]) -> Result<()> {
            log("something unrelated");
            Ok(())
        }
        fn authenticate(&self, _reason: &str) -> Result<bool> {
            Ok(true)
        }
    }
    let Some(t) = RawVerify::new() else { return };
    let sink = Sink::new();
    let err = verify_raw_write_chunked(&t.iso, &t.device(&t.data), &sink.ctx(None), &SilentPriv, MIB as u64, &|| 0.0)
        .unwrap_err();
    assert!(err.to_string().contains("Could not complete the verification"));
    assert!(sink.has_line_containing("something unrelated"), "other lines of the script still reach the log");
}

// ---------------------------------------------------------------------------------------------------------------
// WindowsPayloadTests (rsync required, like the Python)
// ---------------------------------------------------------------------------------------------------------------

struct Payload {
    tmp: Tmp,
    src: PathBuf,
    dst: PathBuf,
    files: Vec<(&'static str, Vec<u8>)>,
}

impl Payload {
    fn new() -> Option<Self> {
        if !have("rsync") {
            eprintln!("skipped: rsync not installed");
            return None;
        }
        let tmp = Tmp::new();
        let files = vec![
            ("bootmgr", b"boot manager".to_vec()),
            ("efi/boot/bootx64.efi", pseudo_random(5000, 1)),
            ("sources/boot.wim", pseudo_random(20000, 2)),
            ("sources/install.wim", pseudo_random(30000, 3)),
            ("support/readme.txt", b"hello\n".to_vec()),
        ];
        for (rel, data) in &files {
            tmp.write(&format!("iso/{rel}"), data);
        }
        let src = tmp.path("iso");
        let dst = tmp.mkdir("usb");
        Some(Payload { tmp, src, dst, files })
    }
    fn copy(&self, sink: &Sink) -> Result<()> {
        epma_usb_creator::copyverify::copy_windows_payload(
            &self.src,
            &self.dst,
            &sink.ctx(None),
            "wimlib missing hint",
            None,
            None,
        )
    }
    fn verify(&self) -> Result<()> {
        let big = self.src.join("sources").join("install.wim");
        let sink = Sink::new();
        epma_usb_creator::copyverify::verify_windows_payload(
            &self.src,
            &self.dst,
            &format!("sources{}install.wim", std::path::MAIN_SEPARATOR),
            &big,
            &sink.ctx_no_progress(None),
            None,
            None,
        )
    }
    fn read_dst(&self, rel: &str) -> Vec<u8> {
        fs::read(self.dst.join(rel)).unwrap()
    }
}

#[test]
fn copies_everything_verifies_and_reports_progress() {
    let Some(t) = Payload::new() else { return };
    let sink = Sink::new();
    t.copy(&sink).unwrap();
    for (rel, data) in &t.files {
        assert_eq!(&t.read_dst(rel), data, "{rel}");
    }
    assert!(sink.has_line_containing("Verification passed"));
    let calls = sink.calls();
    let measured: Vec<_> = calls.iter().filter(|c| c.1 != 0).collect(); // the verify stage reports (0, 0, text)
    let done: Vec<u64> = measured.iter().map(|c| c.0).collect();
    let mut sorted = done.clone();
    sorted.sort();
    assert_eq!(done, sorted);
    let total: u64 = t.files.iter().map(|(_, d)| d.len() as u64).sum();
    assert!(measured.iter().all(|c| c.1 == total));
    assert_eq!(measured.last().unwrap().0, total);
    assert!(calls.iter().any(|c| c.1 == 0 && c.2.contains("Verifying")));
}

#[test]
fn install_esd_is_supported() {
    let Some(t) = Payload::new() else { return };
    fs::rename(t.src.join("sources/install.wim"), t.src.join("sources/install.esd")).unwrap();
    t.copy(&Sink::new()).unwrap();
    assert_eq!(t.read_dst("sources/install.esd"), t.files[3].1);
}

#[test]
fn missing_install_image() {
    let Some(t) = Payload::new() else { return };
    fs::remove_file(t.src.join("sources/install.wim")).unwrap();
    let err = t.copy(&Sink::new()).unwrap_err();
    assert!(err.to_string().contains("install.wim or sources/install.esd"), "{err}");
}

/// The real system, except that the FAT32 limit is tiny and no tool is on PATH.
struct TinyLimitNoTools;
impl CopyHost for TinyLimitNoTools {
    fn fat32_max_file_size(&self) -> u64 {
        1000
    }
    fn which(&self, _tool: &str) -> bool {
        false
    }
    fn run_cmd(&self, args: &[String], log: Log, cancel: Option<&epma_usb_creator::types::CancelToken>) -> Result<i32> {
        SystemHost.run_cmd(args, log, cancel)
    }
}

#[test]
fn oversized_image_needs_wimlib() {
    let Some(t) = Payload::new() else { return };
    let sink = Sink::new();
    let err =
        copy_windows_payload_on(&TinyLimitNoTools, &t.src, &t.dst, &sink.ctx(None), "wimlib missing hint", None, None)
            .unwrap_err();
    assert!(err.to_string().contains("wimlib missing hint"), "{err}");
    assert!(sink.has_line_containing("Splitting with wimlib-imagex"));
}

#[test]
fn verify_detects_a_modified_file() {
    let Some(t) = Payload::new() else { return };
    t.copy(&Sink::new()).unwrap();
    let mut data = t.read_dst("efi/boot/bootx64.efi");
    data[0] = 0xff;
    data[1] = 0xff;
    fs::write(t.dst.join("efi/boot/bootx64.efi"), data).unwrap();
    let err = t.verify().unwrap_err();
    assert!(err.to_string().contains("Verification FAILED"), "{err}");
}

#[test]
fn verify_detects_a_missing_file() {
    let Some(t) = Payload::new() else { return };
    t.copy(&Sink::new()).unwrap();
    fs::remove_file(t.dst.join("support/readme.txt")).unwrap();
    let err = t.verify().unwrap_err();
    assert!(err.to_string().contains("Verification FAILED"), "{err}");
}

#[test]
fn verify_detects_a_damaged_install_image() {
    let Some(t) = Payload::new() else { return };
    t.copy(&Sink::new()).unwrap();
    let mut data = t.read_dst("sources/install.wim");
    data[100] ^= 0xFF;
    fs::write(t.dst.join("sources/install.wim"), data).unwrap();
    let err = t.verify().unwrap_err();
    assert!(err.to_string().contains("install.wim on the drive differs"), "{err}");
}

#[test]
fn verify_passes_on_an_exact_copy() {
    let Some(t) = Payload::new() else { return };
    t.copy(&Sink::new()).unwrap();
    t.verify().unwrap();
    // the same through the host-generic entry point
    let sink = Sink::new();
    let big = t.src.join("sources").join("install.wim");
    let extra: Option<&Files> = None;
    verify_windows_payload_on(&SystemHost, &t.src, &t.dst, "sources/install.wim", &big, &sink.ctx(None), extra, None)
        .unwrap();
    let _ = &t.tmp;
}
