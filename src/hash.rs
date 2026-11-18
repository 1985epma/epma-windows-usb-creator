//! SHA-256 of files. OWNER: A1. Port of win11_usb_creator.py lines 1059-1063, 1496-1528.

use crate::proc::check_canceled;
use crate::types::{CancelToken, Progress2, Result};
use sha2::{Digest, Sha256};
use std::io::{ErrorKind, Read};
use std::path::Path;

pub const SHA256_CHUNK: usize = 4 * 1024 * 1024;

/// Fill `buf` from `reader` until it is full or the stream ends (what Python's buffered `read(n)` does: a short
/// count only ever means the end). Returns the bytes read.
pub(crate) fn read_full(reader: &mut dyn Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Feed `digest` from `reader` in chunks (constant memory); returns the bytes read (`_hash_stream`).
/// `check` runs before every read and may return Err to stop; `on_chunk(done)` runs after every chunk.
///
/// `limit` stops after that many bytes (`None`: read to the end). The one place where a file is read in blocks for
/// hashing: `sha256_file` and the resume of a partial download both use it.
pub fn hash_stream(
    reader: &mut dyn std::io::Read,
    digest: &mut Sha256,
    limit: Option<u64>,
    check: Option<&dyn Fn() -> Result<()>>,
    on_chunk: Option<&dyn Fn(u64)>,
    chunk: usize,
) -> Result<u64> {
    let chunk = chunk.max(1);
    let mut buf = vec![0u8; limit.map_or(chunk as u64, |l| l.min(chunk as u64)) as usize];
    let mut done: u64 = 0;
    while limit.is_none_or(|l| done < l) {
        if let Some(check) = check {
            check()?;
        }
        let want = match limit {
            None => chunk,
            Some(l) => (chunk as u64).min(l - done) as usize,
        };
        let n = read_full(reader, &mut buf[..want])?;
        if n == 0 {
            break;
        }
        digest.update(&buf[..n]);
        done += n as u64;
        if let Some(on_chunk) = on_chunk {
            on_chunk(done);
        }
    }
    Ok(done)
}

/// SHA-256 of a file as lowercase hex; `cancel` is checked between chunks (Error::Canceled); `progress(done, total)`
/// is called after each chunk. The one SHA-256-of-a-file routine: the GUI, the command line and the audit trail use
/// it.
pub fn sha256_file(
    path: impl AsRef<Path>,
    cancel: Option<&CancelToken>,
    progress: Option<Progress2>,
) -> Result<String> {
    sha256_file_chunked(path, cancel, progress, SHA256_CHUNK)
}

/// `sha256_file` with the chunk size given (the Python `chunk` parameter; tests use small chunks to see the
/// progress steps).
pub fn sha256_file_chunked(
    path: impl AsRef<Path>,
    cancel: Option<&CancelToken>,
    progress: Option<Progress2>,
    chunk: usize,
) -> Result<String> {
    let path = path.as_ref();
    let mut digest = Sha256::new();
    // `total = os.path.getsize(path) if progress else 0`: a missing file is an OSError here or at open.
    let total = if progress.is_some() { std::fs::metadata(path)?.len() } else { 0 };
    let mut file = std::fs::File::open(path)?;
    let check = || check_canceled(cancel, true, false);
    let report = |done: u64| {
        if let Some(p) = progress {
            p(done, total)
        }
    };
    hash_stream(&mut file, &mut digest, None, Some(&check), progress.map(|_| &report as &dyn Fn(u64)), chunk)?;
    Ok(hex(&digest.finalize()))
}

/// Lowercase hex of a digest.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Error;
    use std::cell::RefCell;
    use std::io::{Cursor, Write};

    fn blob(len: usize) -> Vec<u8> {
        // deterministic pseudo-random bytes (xorshift)
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    fn expected(data: &[u8]) -> String {
        hex(&Sha256::digest(data))
    }

    fn temp_file(data: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob.bin");
        std::fs::File::create(&path).unwrap().write_all(data).unwrap();
        (dir, path)
    }

    // ---- Sha256FileTests ----
    #[test]
    fn matches_a_reference() {
        let data = blob(1_300_000);
        let (_d, path) = temp_file(&data);
        assert_eq!(sha256_file(&path, None, None).unwrap(), expected(&data));
        // the empty-string digest everybody knows
        let (_d2, empty) = temp_file(b"");
        assert_eq!(
            sha256_file(&empty, None, None).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn progress_reports_done_and_total_per_chunk() {
        let data = blob(1_300_000);
        let (_d, path) = temp_file(&data);
        let seen = std::sync::Mutex::new(Vec::new());
        let progress = |d: u64, t: u64| seen.lock().unwrap().push((d, t));
        let digest = sha256_file_chunked(&path, None, Some(&progress), 500_000).unwrap();
        assert_eq!(digest, expected(&data));
        assert_eq!(*seen.lock().unwrap(), vec![(500_000, 1_300_000), (1_000_000, 1_300_000), (1_300_000, 1_300_000)]);
    }

    #[test]
    fn cancel_stops_with_canceled_and_not_written() {
        let (_d, path) = temp_file(&blob(1000));
        let token = CancelToken::new();
        token.set();
        let err = sha256_file(&path, Some(&token), None).unwrap_err();
        assert!(err.is_canceled());
        assert!(!err.written());
    }

    #[test]
    fn a_cancel_between_chunks_is_noticed() {
        let data = blob(1_300_000);
        let (_d, path) = temp_file(&data);
        let token = CancelToken::new();
        let progress = |_d: u64, _t: u64| token.set(); // cancel after the first chunk
        let err = sha256_file_chunked(&path, Some(&token), Some(&progress), 500_000).unwrap_err();
        assert!(err.is_canceled());
    }

    #[test]
    fn missing_file_is_an_io_error() {
        let (_d, path) = temp_file(b"x");
        let gone = path.with_extension("nope");
        assert!(matches!(sha256_file(&gone, None, None), Err(Error::Io(_))));
        let progress = |_d: u64, _t: u64| {};
        assert!(matches!(sha256_file(&gone, None, Some(&progress)), Err(Error::Io(_))));
    }

    // ---- HashStreamTests ----
    #[test]
    fn limit_reads_only_that_many_bytes() {
        let mut digest = Sha256::new();
        let mut fh = Cursor::new(vec![b'a'; 100]);
        assert_eq!(hash_stream(&mut fh, &mut digest, Some(40), None, None, 16).unwrap(), 40);
        assert_eq!(hex(&digest.finalize()), expected(&[b'a'; 40]));
        assert_eq!(fh.position(), 40);
    }

    #[test]
    fn a_short_stream_returns_fewer_bytes_than_the_limit() {
        let mut digest = Sha256::new();
        let n =
            hash_stream(&mut Cursor::new(b"abc".to_vec()), &mut digest, Some(10), None, None, SHA256_CHUNK).unwrap();
        assert_eq!(n, 3);
    }

    #[test]
    fn check_runs_before_every_read_and_can_stop_it() {
        let calls = RefCell::new(0);
        let check = || {
            *calls.borrow_mut() += 1;
            if *calls.borrow() == 3 {
                Err(Error::runtime("stop"))
            } else {
                Ok(())
            }
        };
        let mut digest = Sha256::new();
        let err =
            hash_stream(&mut Cursor::new(vec![b'x'; 100]), &mut digest, None, Some(&check), None, 10).unwrap_err();
        assert_eq!(err.to_string(), "stop");
        assert_eq!(*calls.borrow(), 3);
    }

    #[test]
    fn on_chunk_sees_a_running_total() {
        let seen = RefCell::new(Vec::new());
        let on_chunk = |d: u64| seen.borrow_mut().push(d);
        let mut digest = Sha256::new();
        hash_stream(&mut Cursor::new(vec![0u8; 25]), &mut digest, None, None, Some(&on_chunk), 10).unwrap();
        assert_eq!(*seen.borrow(), vec![10, 20, 25]);
    }

    #[test]
    fn a_reader_that_returns_small_pieces_still_fills_the_chunks() {
        struct Dribble(Cursor<Vec<u8>>);
        impl Read for Dribble {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = buf.len().min(3);
                self.0.read(&mut buf[..n])
            }
        }
        let data = blob(100);
        let seen = RefCell::new(Vec::new());
        let on_chunk = |d: u64| seen.borrow_mut().push(d);
        let mut digest = Sha256::new();
        let n =
            hash_stream(&mut Dribble(Cursor::new(data.clone())), &mut digest, None, None, Some(&on_chunk), 40).unwrap();
        assert_eq!(n, 100);
        assert_eq!(*seen.borrow(), vec![40, 80, 100]);
        assert_eq!(hex(&digest.finalize()), expected(&data));
    }
}
