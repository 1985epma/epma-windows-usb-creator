#![allow(unused)] // STUB: delete this line when the module is implemented
//! SHA-256 of files. OWNER: A1. Port of win11_usb_creator.py lines 1059-1063, 1496-1528.

use crate::types::{CancelToken, Progress2, Result};
use sha2::Sha256;
use std::path::Path;

pub const SHA256_CHUNK: usize = 4 * 1024 * 1024;

/// Feed `digest` from `reader` in chunks (constant memory); returns the bytes read (`_hash_stream`).
/// `check` runs before every read and may return Err to stop; `on_chunk(done)` runs after every chunk.
pub fn hash_stream(
    reader: &mut dyn std::io::Read,
    digest: &mut Sha256,
    limit: Option<u64>,
    check: Option<&dyn Fn() -> Result<()>>,
    on_chunk: Option<&dyn Fn(u64)>,
    chunk: usize,
) -> Result<u64> {
    todo!()
}
/// SHA-256 of a file as lowercase hex; `cancel` is checked between chunks (Error::Canceled); `progress(done, total)`
/// is called after each chunk.
pub fn sha256_file(
    path: impl AsRef<Path>,
    cancel: Option<&CancelToken>,
    progress: Option<Progress2>,
) -> Result<String> {
    todo!()
}
