//! ISO / disk image inspection and the ChromeOS ZIP extraction. OWNER: A1.
//! Port of win11_usb_creator.py lines 856-1058 (+ has_mbr_signature users).
//!
//! The detection is pure std, never fails and reads a few MB at most; every offset taken from the file is checked
//! against the data actually read before it is used.

use crate::audit::audit;
use crate::constants::{CHUNK_SIZE, DISK_IMAGE_MAX_BYTES, MIN_IMAGE_BYTES, PRIVATE_FILE_MODE};
use crate::hash::read_full;
use crate::proc::check_canceled;
use crate::types::{CancelToken, Error, IsoKind, Progress2, Result};
use crate::util::{free_disk_space, human_size, py_strip, silent_remove};
use crate::validate::has_mbr_signature;
use regex::Regex;
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

const GPT_HEADER_OFFSET: usize = 512; // LBA 1: "EFI PART"
const GPT_ENTRIES_OFFSET: usize = 1024; // LBA 2: the partition entries (128 bytes each)
const GPT_ENTRY_SIZE: usize = 128;
/// ChromeOS disks always carry these partition names (kernel and root slots, user state).
const CHROMEOS_PARTITION_NAMES: [&str; 6] = ["KERN-A", "ROOT-A", "KERN-B", "ROOT-B", "STATE", "EFI-SYSTEM"];
const ISO_SECTOR: usize = 2048;
/// Primary Volume Descriptor: sector 16 (0x8000).
const ISO_PVD_OFFSET: usize = 16 * ISO_SECTOR;
/// Never read more than this per directory.
const ISO_DIR_MAX_BYTES: usize = 256 * 1024;
/// How much of a UDF image is searched for Windows names.
const ISO_UDF_SCAN_BYTES: usize = 4 * 1024 * 1024;

/// Volume ids that Microsoft's media tools produce, e.g. CCCOMA_X64FRE_EN-US_DV9.
/// The version must not run into another digit; "_" may follow it ("WIN11_23H2"), which is why there is no word
/// boundary here ("_" is a word character, so it would stop WIN11_23H2 matching). The Python writes the digit
/// condition as a look-ahead `(?![0-9])`; the regex crate has none, so the pattern consumes one non-digit (or the end)
/// instead, which is equivalent for a match test.
static WINDOWS_VOLUME_ID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^(?:[A-Z0-9]{2,8}_(?:X64|X86|A64|ARM64)F?REV?_|WIN(?:DOWS)?[ _-]?(?:SERVER|1[01]|[78])(?:[^0-9]|$))",
    )
    .expect("a valid pattern")
});
/// Does this volume id look like one Microsoft's media tools produce (`WINDOWS_VOLUME_ID_RE.match`)?
pub fn is_windows_volume_id(volume_id: &str) -> bool {
    WINDOWS_VOLUME_ID_RE.is_match(volume_id)
}
const WINDOWS_ROOT_FILES: [&str; 3] = ["BOOTMGR", "BOOTMGR.EFI", "SETUP.EXE"];
const WINDOWS_SOURCES_FILES: [&str; 4] = ["INSTALL.WIM", "INSTALL.ESD", "INSTALL.SWM", "BOOT.WIM"];

// ---------------------------------------------------------------------------------------------------------------
// Bounds-checked readers
// ---------------------------------------------------------------------------------------------------------------

/// Up to `n` bytes from the reader's current position (fewer at the end of the data).
fn read_up_to<R: Read>(reader: &mut R, n: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    let got = read_full(reader, &mut buf)?;
    buf.truncate(got);
    Ok(buf)
}

/// `data[at..at + n]`, or an empty slice when it does not fit.
fn slice(data: &[u8], at: usize, n: usize) -> &[u8] {
    at.checked_add(n).and_then(|end| data.get(at..end)).unwrap_or(&[])
}

fn byte(data: &[u8], at: usize) -> u8 {
    data.get(at).copied().unwrap_or(0)
}

/// A little-endian u16 at `at` (0 when it does not fit).
fn le_u16(data: &[u8], at: usize) -> u16 {
    <[u8; 2]>::try_from(slice(data, at, 2)).map(u16::from_le_bytes).unwrap_or(0)
}

/// A little-endian u32 at `at` (0 when it does not fit).
fn le_u32(data: &[u8], at: usize) -> u32 {
    <[u8; 4]>::try_from(slice(data, at, 4)).map(u32::from_le_bytes).unwrap_or(0)
}

/// `bytes.decode("latin-1")`.
fn latin1(raw: &[u8]) -> String {
    raw.iter().map(|&b| b as char).collect()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    let first = needle[0];
    let mut from = 0;
    while let Some(rel) = haystack.get(from..).and_then(|h| h.iter().position(|&b| b == first)) {
        let at = from + rel;
        if haystack.get(at..at + needle.len()) == Some(needle) {
            return true;
        }
        from = at + 1;
    }
    false
}

/// `"text".encode("utf-16-be")` for an ASCII needle.
fn utf16_be(ascii: &str) -> Vec<u8> {
    ascii.bytes().flat_map(|b| [0u8, b]).collect()
}

// ---------------------------------------------------------------------------------------------------------------
// ISO 9660 / UDF / GPT
// ---------------------------------------------------------------------------------------------------------------

/// One record of an ISO 9660 directory.
#[derive(Debug, PartialEq, Eq)]
struct DirEntry {
    name: String,
    is_dir: bool,
    extent: u32,
    length: u32,
}

/// Parse one ISO 9660 directory into entries. Names lose their ";1".
fn iso_read_dir<R: Read + Seek>(
    fh: &mut R,
    extent: u32,
    length: u32,
    block: u64,
    file_size: u64,
) -> io::Result<Vec<DirEntry>> {
    let offset = u64::from(extent) * block;
    if length == 0 || offset == 0 || offset >= file_size {
        return Ok(Vec::new());
    }
    fh.seek(SeekFrom::Start(offset))?;
    let data = read_up_to(fh, (length as usize).min(ISO_DIR_MAX_BYTES))?;
    Ok(parse_dir_records(&data))
}

/// The records inside a directory extent that was read into `data`.
fn parse_dir_records(data: &[u8]) -> Vec<DirEntry> {
    let mut entries = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let rec_len = usize::from(byte(data, pos));
        if rec_len == 0 {
            // records never span sectors; padding means "continue in the next one"
            pos = (pos / ISO_SECTOR + 1) * ISO_SECTOR;
            continue;
        }
        if rec_len < 34 || pos + rec_len > data.len() {
            break;
        }
        let name_len = usize::from(byte(data, pos + 32));
        let raw = slice(data, pos + 33, name_len.min(data.len().saturating_sub(pos + 33)));
        if raw != [0u8] && raw != [1u8] {
            // skip the '.' and '..' entries
            let name = latin1(raw).split(';').next().unwrap_or("").trim_end_matches('.').to_uppercase();
            entries.push(DirEntry {
                name,
                is_dir: byte(data, pos + 25) & 0x02 != 0,
                extent: le_u32(data, pos + 2),
                length: le_u32(data, pos + 10),
            });
        }
        pos += rec_len;
    }
    entries
}

/// True if the volume recognition area (sectors 17-19) announces UDF (ECMA-167).
fn iso_has_udf<R: Read + Seek>(fh: &mut R) -> io::Result<bool> {
    fh.seek(SeekFrom::Start((ISO_PVD_OFFSET + ISO_SECTOR) as u64))?;
    let area = read_up_to(fh, 3 * ISO_SECTOR)?;
    Ok((0..area.len() / ISO_SECTOR).any(|i| {
        let id = slice(&area, i * ISO_SECTOR + 1, 5);
        id == b"BEA01" || id == b"NSR02" || id == b"NSR03"
    }))
}

/// True if `head` (the first sectors of a file) is a GPT disk with ChromeOS partition names.
fn is_chromeos_disk_image(head: &[u8]) -> bool {
    if head.len() < GPT_ENTRIES_OFFSET + GPT_ENTRY_SIZE || slice(head, GPT_HEADER_OFFSET, 8) != b"EFI PART" {
        return false;
    }
    let mut names: HashSet<String> = HashSet::new();
    let end = head.len().min(GPT_ENTRIES_OFFSET + 128 * GPT_ENTRY_SIZE);
    for pos in (GPT_ENTRIES_OFFSET..end).step_by(GPT_ENTRY_SIZE) {
        let entry = slice(head, pos, GPT_ENTRY_SIZE);
        if entry.len() < GPT_ENTRY_SIZE || entry[..16].iter().all(|&b| b == 0) {
            continue; // unused slot (its partition type GUID is all zeros)
        }
        // The name: UTF-16LE in bytes 56..128, ended by a NUL; undecodable units are dropped ("ignore").
        let units: Vec<u16> = slice(entry, 56, 72).chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let name: String = char::decode_utf16(units).filter_map(|r| r.ok()).collect();
        names.insert(name.split('\0').next().unwrap_or("").to_uppercase());
    }
    // ROOT-A and KERN-A are in every ChromeOS image (installer, recovery and installed disks).
    let known = CHROMEOS_PARTITION_NAMES.iter().filter(|n| names.contains(**n)).count();
    names.contains("ROOT-A") && names.contains("KERN-A") && known >= 3
}

/// The detection itself, on any seekable source (`file_size` bounds the directory extents).
fn detect<R: Read + Seek>(fh: &mut R, file_size: u64) -> io::Result<IsoKind> {
    let head = read_up_to(fh, ISO_PVD_OFFSET + ISO_SECTOR)?;
    if is_chromeos_disk_image(&head) {
        return Ok(IsoKind::ChromeOs);
    }
    let pvd = head.get(ISO_PVD_OFFSET..).unwrap_or(&[]);
    if pvd.len() < ISO_SECTOR || byte(pvd, 0) != 1 || slice(pvd, 1, 5) != b"CD001" {
        return Ok(IsoKind::Unknown); // not an ISO 9660 image
    }
    let volume_id = py_strip(&latin1(slice(pvd, 40, 32))).to_uppercase();
    let mut block = u64::from(le_u16(pvd, 128));
    if !(512..=65536).contains(&block) {
        block = ISO_SECTOR as u64;
    }
    // The root directory record sits at 156..190 of the descriptor.
    let root_extent = le_u32(pvd, 156 + 2);
    let root_length = le_u32(pvd, 156 + 10);

    // 1. Walk the ISO 9660 tree: root files, then \SOURCES\.
    for entry in iso_read_dir(fh, root_extent, root_length, block, file_size)? {
        if !entry.is_dir && WINDOWS_ROOT_FILES.contains(&entry.name.as_str()) {
            return Ok(IsoKind::Windows);
        }
        if entry.is_dir && entry.name == "SOURCES" {
            for sub in iso_read_dir(fh, entry.extent, entry.length, block, file_size)? {
                if !sub.is_dir && WINDOWS_SOURCES_FILES.contains(&sub.name.as_str()) {
                    return Ok(IsoKind::Windows);
                }
            }
        }
    }

    // 2. Microsoft's own ISOs are UDF images whose ISO 9660 side is just a stub, so the names above are
    //    invisible. UDF stores them near the start of the file.
    if iso_has_udf(fh)? {
        fh.seek(SeekFrom::Start(0))?;
        let blob = read_up_to(fh, ISO_UDF_SCAN_BYTES)?.to_ascii_lowercase();
        let has_sources = contains_bytes(&blob, b"sources") || contains_bytes(&blob, &utf16_be("sources"));
        for needle in [b"bootmgr".to_vec(), utf16_be("bootmgr")] {
            if contains_bytes(&blob, &needle) && has_sources {
                return Ok(IsoKind::Windows);
            }
        }
    }
    if is_windows_volume_id(&volume_id) {
        return Ok(IsoKind::Windows);
    }

    // 3. Everything else that boots from a USB drive as-is is a hybrid image (Linux & co).
    if has_mbr_signature(&head) {
        return Ok(IsoKind::Linux);
    }
    Ok(IsoKind::Unknown)
}

/// Classify an image by its content: Windows, Linux (hybrid), ChromeOS or Unknown. Never fails; reads a few MB at most.
///
/// Safe to call on any file the user picks. `Unknown` means "could not tell"; callers must ask the user, not guess
/// from the file name.
pub fn detect_iso_kind(path: impl AsRef<Path>) -> IsoKind {
    let path = path.as_ref();
    let run = || -> io::Result<IsoKind> {
        let file_size = std::fs::metadata(path)?.len();
        let mut file = File::open(path)?;
        detect(&mut file, file_size)
    };
    // Any malformed/unreadable file simply means "unknown". The catch_unwind is a last line of defence for the
    // "never raises" promise: the parsing above is bounds-checked and has no known way to panic.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)).ok().and_then(|r| r.ok()).unwrap_or(IsoKind::Unknown)
}

// ---------------------------------------------------------------------------------------------------------------
// Extracting the disk image from Google's ZIP
// ---------------------------------------------------------------------------------------------------------------

const MSG_NOT_A_ZIP: &str = "That is not a valid ZIP file. If the download was interrupted, download it again.";
const MSG_DAMAGED: &str = "The ZIP file is damaged (checksum or compression error). Download it again.";
const MSG_UNSUPPORTED: &str = "This ZIP file uses a compression method or encryption that is not supported. \
                               Download latest.bin.zip again from Google.";

/// A zip error met while opening an entry: unsupported method / encryption, or a damaged archive. A real OS error
/// (the disk failing) is kept as an `OSError`.
fn map_zip_error(e: zip::result::ZipError) -> Error {
    use zip::result::ZipError;
    match e {
        // NotImplementedError / RuntimeError of Python's zipfile: unsupported compression, or an encrypted entry.
        ZipError::UnsupportedArchive(_) | ZipError::CompressionMethodNotSupported(_) | ZipError::InvalidPassword => {
            Error::value(MSG_UNSUPPORTED)
        }
        ZipError::Io(io) if io.raw_os_error().is_some() => Error::Io(io),
        // BadZipFile / zlib.error / EOFError
        _ => Error::value(MSG_DAMAGED),
    }
}

/// An error met while reading an entry's data: bad CRC, bad compressed data and a truncated archive are "damaged";
/// an error that carries an OS error code is a real I/O failure.
fn map_read_error(e: io::Error) -> Error {
    // The zip crate starts the decompressor on the first read, so an unknown compression method (or an encrypted
    // entry) can also surface here, as an io::Error wrapping the ZipError.
    use zip::result::ZipError;
    let unsupported = match e.get_ref().and_then(|inner| inner.downcast_ref::<ZipError>()) {
        Some(
            ZipError::UnsupportedArchive(_) | ZipError::CompressionMethodNotSupported(_) | ZipError::InvalidPassword,
        ) => true,
        _ => e.kind() == io::ErrorKind::Unsupported,
    };
    if unsupported {
        Error::value(MSG_UNSUPPORTED)
    } else if e.raw_os_error().is_some() {
        Error::Io(e)
    } else {
        Error::value(MSG_DAMAGED)
    }
}

/// `os.path.splitext(name)`: the extension is the part from the last dot, unless only dots come before it.
fn splitext(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(dot) if name[..dot].chars().any(|c| c != '.') => (&name[..dot], &name[dot..]),
        _ => (name, ""),
    }
}

/// `re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", name)`.
fn is_safe_image_name(name: &str) -> bool {
    (1..=128).contains(&name.len())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
}

/// Create `tmp` for writing: never through a symlink, never reusing a path, owner-only.
fn create_new_private(tmp: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(PRIVATE_FILE_MODE).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    {
        let _ = PRIVATE_FILE_MODE; // Windows: the folder's ACL is inherited
    }
    opts.open(tmp)
}

/// Extract the single .bin disk image from Google's ZIP into `dest_dir`; returns its path.
///
/// Only the file's base name is used (an entry such as "../../x.bin" cannot escape the folder), it never overwrites
/// an existing file, it refuses implausible sizes and checks the free space first, and the data goes to a temporary
/// file that is renamed only when the whole archive entry was read and its CRC verified. `progress(done, total)` is
/// called while copying. A damaged or unsupported archive always ends as a `ValueError` with a user-facing message
/// (never a raw decoder error). The temporary file is created without following symlinks and never reuses an
/// existing path.
pub fn extract_disk_image(
    zip_path: impl AsRef<Path>,
    dest_dir: impl AsRef<Path>,
    progress: Option<Progress2>,
    cancel: Option<&CancelToken>,
) -> Result<PathBuf> {
    let probe = |dir: &Path| free_disk_space(dir);
    extract_disk_image_with(zip_path.as_ref(), dest_dir.as_ref(), progress, cancel, DISK_IMAGE_MAX_BYTES, &probe)
}

/// `extract_disk_image` with the plausibility limit and the free-space probe passed in (the Python tests patch
/// `DISK_IMAGE_MAX_BYTES` and `shutil.disk_usage`).
pub fn extract_disk_image_with(
    zip_path: &Path,
    dest_dir: &Path,
    progress: Option<Progress2>,
    cancel: Option<&CancelToken>,
    max_image_bytes: u64,
    free_space: &dyn Fn(&Path) -> io::Result<u64>,
) -> Result<PathBuf> {
    let not_a_zip = || Error::value(MSG_NOT_A_ZIP);
    let file = File::open(zip_path).map_err(|_| not_a_zip())?;
    let mut archive = zip::ZipArchive::new(file).map_err(|_| not_a_zip())?;

    // The largest .bin entry (the first one when two are equally large).
    let mut best: Option<(usize, u64, String)> = None;
    for index in 0..archive.len() {
        let entry = archive.by_index_data(index).map_err(|_| not_a_zip())?;
        let Ok(name) = entry.name() else { continue };
        if name.ends_with('/') || !name.to_lowercase().ends_with(".bin") {
            continue;
        }
        let size = entry.size();
        if best.as_ref().is_none_or(|(_, best_size, _)| size > *best_size) {
            best = Some((index, size, name.into_owned()));
        }
    }
    let Some((index, size, entry_name)) = best else {
        return Err(Error::value("The ZIP file does not contain a .bin disk image."));
    };
    if !(MIN_IMAGE_BYTES..=max_image_bytes).contains(&size) {
        return Err(Error::value(format!(
            "The disk image inside the ZIP has an implausible size ({}), so it was not extracted.",
            human_size(size)
        )));
    }
    if !dest_dir.is_dir() {
        return Err(Error::value(format!("The folder does not exist: {}", dest_dir.display())));
    }
    if free_space(dest_dir)? < size + 256 * 1024 * 1024 {
        return Err(Error::value(format!(
            "Not enough free space in {}: the disk image needs {}.",
            dest_dir.display(),
            human_size(size)
        )));
    }

    let normalized = entry_name.replace('\\', "/");
    let base = normalized.rsplit('/').next().unwrap_or("");
    let name = if is_safe_image_name(base) { base } else { "chromeos_flex.bin" };
    let (stem, ext) = splitext(name);
    let mut dest = dest_dir.join(name);
    let mut n = 1;
    // lexists, not exists: even a dangling symlink at the name counts as taken, so it is never replaced.
    while dest.symlink_metadata().is_ok() {
        dest = dest_dir.join(format!("{stem}-{n}{ext}"));
        n += 1;
    }
    let tmp = {
        let mut t = dest.clone().into_os_string();
        t.push(".part");
        PathBuf::from(t)
    };

    let mut created = false;
    let outcome = (|| -> Result<u64> {
        let mut src = archive.by_index(index).map_err(map_zip_error)?;
        // A stale ".part" (or a symlink planted at that name) is removed, never written through.
        if tmp.symlink_metadata().is_ok() {
            std::fs::remove_file(&tmp)?;
        }
        let mut out = create_new_private(&tmp)?;
        created = true;
        let mut buf = vec![0u8; CHUNK_SIZE];
        let mut done: u64 = 0;
        loop {
            check_canceled(cancel, true, false)?;
            let got = read_full(&mut src, &mut buf).map_err(map_read_error)?;
            if got == 0 {
                break;
            }
            out.write_all(&buf[..got])?;
            done += got as u64;
            if let Some(progress) = progress {
                progress(done, size);
            }
        }
        out.flush()?;
        drop(out); // closed before the rename (Windows cannot rename an open file)
        if done != size {
            return Err(Error::value("The disk image in the ZIP is incomplete. Download the file again."));
        }
        std::fs::rename(&tmp, &dest)?;
        created = false;
        Ok(done)
    })();
    if created {
        silent_remove(&tmp);
    }
    let done = outcome?;
    audit(&format!("Extracted a disk image from a ZIP ({})", human_size(done)));
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ---- a tiny ISO 9660 builder ----
    const WIN_NAMES: [&str; 3] = ["BOOTMGR", "BOOTMGR.EFI", "SETUP.EXE"];

    /// One directory record.
    fn record(name: &[u8], is_dir: bool, extent: u32, length: u32) -> Vec<u8> {
        let mut len = 33 + name.len();
        if len % 2 == 1 {
            len += 1;
        }
        let mut r = vec![0u8; len];
        r[0] = len as u8;
        r[2..6].copy_from_slice(&extent.to_le_bytes());
        r[6..10].copy_from_slice(&extent.to_be_bytes());
        r[10..14].copy_from_slice(&length.to_le_bytes());
        r[14..18].copy_from_slice(&length.to_be_bytes());
        r[25] = if is_dir { 2 } else { 0 };
        r[32] = name.len() as u8;
        r[33..33 + name.len()].copy_from_slice(name);
        r
    }

    struct IsoBuilder {
        data: Vec<u8>,
    }

    impl IsoBuilder {
        /// A volume with a primary descriptor whose root directory is at sector 20 (length one sector).
        fn new(volume_id: &str, total_sectors: usize) -> IsoBuilder {
            let mut data = vec![0u8; total_sectors * ISO_SECTOR];
            let pvd = ISO_PVD_OFFSET;
            data[pvd] = 1;
            data[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
            data[pvd + 6] = 1;
            let mut vid = [b' '; 32];
            vid[..volume_id.len()].copy_from_slice(volume_id.as_bytes());
            data[pvd + 40..pvd + 72].copy_from_slice(&vid);
            data[pvd + 128..pvd + 130].copy_from_slice(&2048u16.to_le_bytes());
            let root = record(&[0], true, 20, 2048);
            data[pvd + 156..pvd + 156 + 34].copy_from_slice(&root[..34]);
            IsoBuilder { data }
        }
        fn hybrid(mut self) -> Self {
            self.data[510] = 0x55;
            self.data[511] = 0xaa;
            self
        }
        fn dir(mut self, sector: usize, records: &[Vec<u8>]) -> Self {
            let mut at = sector * ISO_SECTOR;
            // the "." and ".." entries come first, as on a real disc
            for r in [record(&[0], true, sector as u32, 2048), record(&[1], true, 20, 2048)].iter().chain(records) {
                self.data[at..at + r.len()].copy_from_slice(r);
                at += r.len();
            }
            self
        }
        fn put(mut self, at: usize, bytes: &[u8]) -> Self {
            self.data[at..at + bytes.len()].copy_from_slice(bytes);
            self
        }
        fn kind(&self) -> IsoKind {
            detect(&mut Cursor::new(&self.data), self.data.len() as u64).unwrap()
        }
    }

    #[test]
    fn a_windows_iso_is_found_by_its_root_files() {
        for name in WIN_NAMES {
            let iso =
                IsoBuilder::new("SOMETHING", 40).dir(20, &[record(format!("{name};1").as_bytes(), false, 30, 100)]);
            assert_eq!(iso.kind(), IsoKind::Windows, "{name}");
        }
        // lower case and the trailing dot some tools leave
        let iso = IsoBuilder::new("X", 40).dir(20, &[record(b"bootmgr.", false, 30, 100)]);
        assert_eq!(iso.kind(), IsoKind::Windows);
    }

    #[test]
    fn a_windows_iso_is_found_by_sources_install_wim() {
        let iso = IsoBuilder::new("X", 60)
            .dir(20, &[record(b"SOURCES", true, 30, 2048)])
            .dir(30, &[record(b"INSTALL.WIM;1", false, 50, 4096)]);
        assert_eq!(iso.kind(), IsoKind::Windows);
        for name in ["INSTALL.ESD", "INSTALL.SWM", "BOOT.WIM"] {
            let iso = IsoBuilder::new("X", 60)
                .dir(20, &[record(b"SOURCES", true, 30, 2048)])
                .dir(30, &[record(name.as_bytes(), false, 50, 4096)]);
            assert_eq!(iso.kind(), IsoKind::Windows, "{name}");
        }
        // a file called SOURCES is not the folder; an unrelated file in \SOURCES\ is not a Windows marker
        let iso = IsoBuilder::new("X", 60).dir(20, &[record(b"SOURCES", false, 30, 2048)]);
        assert_eq!(iso.kind(), IsoKind::Unknown);
        let iso = IsoBuilder::new("X", 60)
            .dir(20, &[record(b"SOURCES", true, 30, 2048)])
            .dir(30, &[record(b"README.TXT", false, 50, 10)]);
        assert_eq!(iso.kind(), IsoKind::Unknown);
    }

    #[test]
    fn a_udf_stub_with_bootmgr_and_sources_is_windows() {
        // sector 17: UDF announcement, and the names somewhere early in the file (ASCII here, UTF-16BE below)
        let iso = IsoBuilder::new("X", 80)
            .put(ISO_PVD_OFFSET + ISO_SECTOR, b"\x00BEA01\x01")
            .put(40 * ISO_SECTOR, b"bootmgr and sources");
        assert_eq!(iso.kind(), IsoKind::Windows);
        let iso = IsoBuilder::new("X", 80)
            .put(ISO_PVD_OFFSET + 2 * ISO_SECTOR, b"\x00NSR02\x01")
            .put(40 * ISO_SECTOR, &utf16_be("BOOTMGR"))
            .put(41 * ISO_SECTOR, &utf16_be("Sources"));
        assert_eq!(iso.kind(), IsoKind::Windows);
        // UDF announced but no Windows names: not Windows
        let iso = IsoBuilder::new("X", 80).put(ISO_PVD_OFFSET + ISO_SECTOR, b"\x00NSR03\x01");
        assert_eq!(iso.kind(), IsoKind::Unknown);
        // names without the UDF announcement do not count
        let iso = IsoBuilder::new("X", 80).put(40 * ISO_SECTOR, b"bootmgr sources");
        assert_eq!(iso.kind(), IsoKind::Unknown);
    }

    #[test]
    fn microsoft_volume_ids_are_windows() {
        for id in [
            "CCCOMA_X64FRE_EN-US_DV9",
            "CCSA_X64FRE_EN-US_DV5",
            "WIN11_23H2",
            "WIN10_22H2",
            "WINDOWS 11",
            "WIN_SERVER_2022",
            "Windows_Server",
            "WIN7",
            "WIN8",
            "ESD2_A64FRE_X",
        ] {
            assert_eq!(IsoBuilder::new(id, 40).kind(), IsoKind::Windows, "{id}");
        }
        for id in
            ["WIN110", "WIN7X", "UBUNTU 24.04", "Fedora-WS-Live-41", "DEBIAN_12", "ARCH_202501", "WINE", "WIN9", ""]
        {
            let expect = if id == "WIN7X" { IsoKind::Windows } else { IsoKind::Unknown };
            assert_eq!(IsoBuilder::new(id, 40).kind(), expect, "{id}");
        }
    }

    #[test]
    fn a_hybrid_iso_is_linux_and_a_plain_one_unknown() {
        assert_eq!(IsoBuilder::new("UBUNTU 24.04", 40).hybrid().kind(), IsoKind::Linux);
        assert_eq!(IsoBuilder::new("UBUNTU 24.04", 40).kind(), IsoKind::Unknown);
        // the smallest thing accepted: a primary descriptor and an empty root directory record
        let mut data = vec![0u8; 2 * 1024 * 1024];
        data[510..512].copy_from_slice(&[0x55, 0xaa]);
        data[ISO_PVD_OFFSET..ISO_PVD_OFFSET + 8].copy_from_slice(b"\x01CD001\x01\x00");
        assert_eq!(detect(&mut Cursor::new(&data), data.len() as u64).unwrap(), IsoKind::Linux);
    }

    #[test]
    fn a_windows_marker_beats_the_hybrid_signature() {
        let iso = IsoBuilder::new("X", 40).hybrid().dir(20, &[record(b"BOOTMGR", false, 30, 100)]);
        assert_eq!(iso.kind(), IsoKind::Windows);
    }

    fn gpt(names: &[&str]) -> Vec<u8> {
        let mut data = vec![0u8; ISO_PVD_OFFSET + ISO_SECTOR];
        data[510..512].copy_from_slice(&[0x55, 0xaa]);
        data[512..520].copy_from_slice(b"EFI PART");
        for (i, name) in names.iter().enumerate() {
            let at = GPT_ENTRIES_OFFSET + i * GPT_ENTRY_SIZE;
            data[at..at + 16].copy_from_slice(&[0x11; 16]);
            data[at + 16..at + 32].copy_from_slice(&[(i + 1) as u8; 16]);
            let units: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            data[at + 56..at + 56 + units.len()].copy_from_slice(&units);
        }
        data
    }

    fn kind_of(data: &[u8]) -> IsoKind {
        detect(&mut Cursor::new(data), data.len() as u64).unwrap()
    }

    #[test]
    fn a_chromeos_gpt_is_recognised_by_its_partition_names() {
        assert_eq!(kind_of(&gpt(&["KERN-A", "ROOT-A", "KERN-B", "ROOT-B", "STATE", "EFI-SYSTEM"])), IsoKind::ChromeOs);
        assert_eq!(kind_of(&gpt(&["KERN-A", "ROOT-A", "STATE"])), IsoKind::ChromeOs); // the minimum set
        assert_eq!(kind_of(&gpt(&["kern-a", "root-a", "state"])), IsoKind::ChromeOs);
        // case does not matter
    }

    #[test]
    fn other_gpt_disks_are_not_chromeos() {
        for names in [
            &["EFI System Partition", "Basic data partition"][..],
            &["ROOT-A"],
            &["KERN-A", "STATE"],
            &["root", "boot", "home"],
            &["KERN-B", "ROOT-B", "STATE"],
        ] {
            assert_ne!(kind_of(&gpt(names)), IsoKind::ChromeOs, "{names:?}");
        }
    }

    #[test]
    fn an_empty_gpt_slot_is_ignored() {
        let mut data = gpt(&["KERN-A", "ROOT-A", "KERN-B", "ROOT-B", "STATE", "EFI-SYSTEM"]);
        let at = GPT_ENTRIES_OFFSET + 6 * GPT_ENTRY_SIZE;
        data[at..at + GPT_ENTRY_SIZE].fill(0);
        assert_eq!(kind_of(&data), IsoKind::ChromeOs);
        // a slot with an all-zero type GUID is unused even when a name is left in it
        let mut data = gpt(&["KERN-A", "ROOT-A"]);
        let at = GPT_ENTRIES_OFFSET + 2 * GPT_ENTRY_SIZE;
        let units: Vec<u8> = "STATE".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        data[at + 56..at + 56 + units.len()].copy_from_slice(&units);
        assert_ne!(kind_of(&data), IsoKind::ChromeOs);
    }

    #[test]
    fn a_name_with_a_lone_surrogate_does_not_break_the_decoding() {
        let mut data = gpt(&["KERN-A", "ROOT-A", "STATE"]);
        let at = GPT_ENTRIES_OFFSET + 3 * GPT_ENTRY_SIZE;
        data[at..at + 16].copy_from_slice(&[0x11; 16]);
        data[at + 56..at + 60].copy_from_slice(&[0x00, 0xd8, 0x41, 0x00]); // a lone high surrogate, then "A"
        assert_eq!(kind_of(&data), IsoKind::ChromeOs);
    }

    #[test]
    fn hostile_and_truncated_input_never_panics() {
        // every prefix of a valid-looking image, and images whose pointers point nowhere
        let good = IsoBuilder::new("X", 60)
            .hybrid()
            .dir(20, &[record(b"SOURCES", true, 30, 2048)])
            .dir(30, &[record(b"INSTALL.WIM", false, 50, 4096)])
            .put(ISO_PVD_OFFSET + ISO_SECTOR, b"\x00BEA01\x01")
            .data;
        for cut in (0..good.len())
            .step_by(997)
            .chain([0, 1, 511, 512, 513, 1023, 1024, 1151, 1152, 32767, 32768, 34815, 34816, 34817])
        {
            let part = &good[..cut.min(good.len())];
            let _ = detect(&mut Cursor::new(part), part.len() as u64);
            let _ = detect(&mut Cursor::new(part), u64::MAX);
        }
        // a directory record whose lengths are nonsense
        let mut bad = good.clone();
        let pvd = ISO_PVD_OFFSET;
        bad[pvd + 156 + 2..pvd + 156 + 6].copy_from_slice(&u32::MAX.to_le_bytes()); // extent
        bad[pvd + 156 + 10..pvd + 156 + 14].copy_from_slice(&u32::MAX.to_le_bytes()); // length
        let _ = detect(&mut Cursor::new(&bad), bad.len() as u64);
        let _ = detect(&mut Cursor::new(&bad), u64::MAX);
        // records that claim to extend past the data, zero-length records forever, name lengths past the end
        let mut dirdata = vec![0u8; 5000];
        dirdata[0] = 200;
        dirdata[32] = 255;
        let _ = parse_dir_records(&dirdata);
        let _ = parse_dir_records(&vec![0u8; 100_000]);
        let _ = parse_dir_records(&[34u8; 40]);
        let _ = parse_dir_records(&[255u8; 3]);
        // a block size field outside the sane range falls back to 2048
        let mut odd = IsoBuilder::new("X", 40).hybrid().data;
        odd[pvd + 128..pvd + 130].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(kind_of(&odd), IsoKind::Linux);
        // pseudo-random garbage of several sizes
        let mut x: u64 = 88172645463325252;
        for len in [0usize, 1, 100, 4096, 40_000, 70_000] {
            let junk: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    x as u8
                })
                .collect();
            let _ = detect(&mut Cursor::new(&junk), junk.len() as u64);
        }
    }

    #[test]
    fn detect_iso_kind_on_files() {
        let dir = tempfile::tempdir().unwrap();
        let hybrid = dir.path().join("u.iso");
        std::fs::write(&hybrid, IsoBuilder::new("UBUNTU", 40).hybrid().data).unwrap();
        assert_eq!(detect_iso_kind(&hybrid), IsoKind::Linux);
        assert_eq!(detect_iso_kind(dir.path().join("missing.bin")), IsoKind::Unknown);
        assert_eq!(detect_iso_kind(dir.path()), IsoKind::Unknown); // a directory
        let junk = dir.path().join("g.bin");
        std::fs::write(&junk, (0..4096u32).map(|i| (i * 31 % 251) as u8).collect::<Vec<u8>>()).unwrap();
        assert_eq!(detect_iso_kind(&junk), IsoKind::Unknown);
        let empty = dir.path().join("empty");
        std::fs::write(&empty, b"").unwrap();
        assert_eq!(detect_iso_kind(&empty), IsoKind::Unknown);
    }

    #[test]
    fn the_directory_parser_handles_padding_and_stops_at_bad_records() {
        let mut data = vec![0u8; 3 * ISO_SECTOR];
        let a = record(b"A.TXT;1", false, 1, 1);
        data[..a.len()].copy_from_slice(&a);
        // padding up to the next sector, then another record
        let b = record(b"B.TXT;1", false, 2, 2);
        data[ISO_SECTOR..ISO_SECTOR + b.len()].copy_from_slice(&b);
        let names: Vec<String> = parse_dir_records(&data).into_iter().map(|e| e.name).collect();
        assert_eq!(names, vec!["A.TXT", "B.TXT"]);
        // a record shorter than the 34-byte minimum ends the parse
        let mut short = vec![0u8; 100];
        short[0] = 20;
        assert!(parse_dir_records(&short).is_empty());
    }

    #[test]
    fn splitext_like_python() {
        assert_eq!(splitext("a.bin"), ("a", ".bin"));
        assert_eq!(splitext("a.b.bin"), ("a.b", ".bin"));
        assert_eq!(splitext(".bin"), (".bin", ""));
        assert_eq!(splitext("..bin"), ("..bin", ""));
        assert_eq!(splitext("noext"), ("noext", ""));
        assert_eq!(splitext("chromeos_flex.bin"), ("chromeos_flex", ".bin"));
    }

    #[test]
    fn safe_names() {
        assert!(is_safe_image_name("chromeos_flex-1.bin"));
        assert!(is_safe_image_name("a+b.bin"));
        assert!(!is_safe_image_name("we ird$name;.bin"));
        assert!(!is_safe_image_name(""));
        assert!(!is_safe_image_name(&"a".repeat(129)));
        assert!(is_safe_image_name(&"a".repeat(128)));
        assert!(!is_safe_image_name("café.bin"));
    }
}
