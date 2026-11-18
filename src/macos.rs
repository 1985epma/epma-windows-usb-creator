//! macOS backend. OWNER: A3. Port of win11_usb_creator.py lines 2302-2683 (diskutil/hdiutil/ioreg listing, build,
//! eject, raw write, MACOS_RAW_SCRIPT, write_raw_image) and 8703-8730 (macos_build_seed_usb). Compiles on every OS
//! (the listing parsers are pure and unit-testable); it only *runs* commands on macOS.
//!
//! Layout: the pure parsers (`parse_usb_device_map`, `parse_apfs_volumes_by_store`, `describe_disk`...) take the
//! text/plist a command printed and return structs; the thin functions run the commands through a [`Host`] (see
//! `macos/host.rs`). Every public function has a `*_with(host, ...)` twin for tests.

use crate::audit::AuditLevel;
use crate::constants::{DISKUTIL_TIMEOUT, IOREG_TIMEOUT, MAC_DEVICE_RE, QUERY_TIMEOUT, RAW_WRITE_BLOCK_MAC, VOL_NAME};
use crate::types::{Ctx, Disk, Error, Files, Identity, Log, Privilege, Result, Volume};
use plist::{Dictionary, Value};
use std::collections::HashMap;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub mod host;
#[cfg(test)]
pub(crate) mod testkit;
#[cfg(test)]
mod tests;

use host::error_kind;
pub use host::{report_eject, write_raw_image, write_raw_image_with, Host, SystemHost};

/// Root script that writes the image with `dd`. Values arrive as "$1".."$n" (never pasted into the text). "$4" is a
/// flag file: the app creates it to ask for a cancel, and the loop (which polls it once a second) then stops dd and
/// prints WRITE_CANCELED. A terminal Ctrl-C also reaches the script (same process group): ignoring it keeps the
/// script alive to stop dd itself through the flag file; otherwise dd would be orphaned. BSD dd has no
/// status=progress: it prints the byte count when it receives SIGINFO, so the loop asks for it once a second.
pub const MACOS_RAW_SCRIPT: &str = include_str!("../assets/macos_raw_write.sh");

const ERASE_TIMEOUT: Duration = Duration::from_secs(600);
const ATTACH_TIMEOUT: Duration = Duration::from_secs(300);
const WIMLIB_HINT_MAC: &str =
    "wimlib-imagex not found. Install it with: brew install wimlib (or use the 'Install missing dependencies' button).";

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

// ---------------------------------------------------------------------------------------------------------------
// Python-flavoured access to property lists
// ---------------------------------------------------------------------------------------------------------------

/// Python truthiness of a plist value.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Boolean(b) => *b,
        Value::Integer(i) => i.as_signed().is_none_or(|n| n != 0),
        Value::Real(f) => *f != 0.0,
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Dictionary(d) => !d.is_empty(),
        Value::Data(d) => !d.is_empty(),
        _ => true,
    }
}

/// `str(value)`.
fn py_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Boolean(true) => "True".to_string(),
        Value::Boolean(false) => "False".to_string(),
        Value::Integer(i) => i.to_string(),
        Value::Real(f) => f.to_string(),
        other => format!("{other:?}"),
    }
}

/// `str(d.get(key) or "")`: the text of a field, empty when it is absent or falsy.
fn text(d: &Dictionary, key: &str) -> String {
    match d.get(key) {
        Some(v) if truthy(v) => py_str(v),
        _ => String::new(),
    }
}

/// `d.get(key) or None` for a field that holds text.
fn text_opt(d: &Dictionary, key: &str) -> Option<String> {
    let s = text(d, key);
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// `d.get(key) or 0` for a size.
fn number(d: &Dictionary, key: &str) -> u64 {
    d.get(key).and_then(Value::as_unsigned_integer).unwrap_or(0)
}

fn plist_error(e: plist::Error) -> Error {
    Error::runtime(format!("Could not read the property list: {e}"))
}

fn parse_plist(bytes: &[u8]) -> Result<Value> {
    Value::from_reader(Cursor::new(bytes)).map_err(plist_error)
}

fn into_dictionary(v: Value) -> Result<Dictionary> {
    match v {
        Value::Dictionary(d) => Ok(d),
        _ => Err(Error::runtime("Unexpected property list (a dictionary was expected).")),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// diskutil / ioreg
// ---------------------------------------------------------------------------------------------------------------

/// `_diskutil_plist(*args, timeout)`: run `diskutil <args>` (a -plist query) and return the parsed property list.
///
/// The error is returned as it is: the callers decide what a failure means (the drive listing fails closed: a disk
/// that cannot be queried is hidden, never offered).
pub fn diskutil_plist(host: &dyn Host, args: &[&str], timeout: Duration) -> Result<Value> {
    let mut cmd = vec!["diskutil"];
    cmd.extend_from_slice(args);
    let out = host.check_output(&cmd, timeout, false)?;
    parse_plist(&out)
}

/// `_diskutil_info(node)`: `diskutil info -plist /dev/<node>` for a disk or partition identifier ('disk4', 'disk4s1').
pub fn diskutil_info(host: &dyn Host, node: &str) -> Result<Dictionary> {
    let value = diskutil_plist(host, &["info", "-plist", &format!("/dev/{node}")], secs(QUERY_TIMEOUT))?;
    into_dictionary(value)
}

/// The USB device that carries a BSD name ('disk4', 'disk4s1'...), as `ioreg` reports it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UsbDevice {
    pub serial: String,
    pub vendor: String,
    pub product: String,
}

/// The two lookups `describe_disk` needs, built once and only when a disk qualifies.
type DescribeMaps = (HashMap<String, UsbDevice>, HashMap<String, Vec<Volume>>);

/// Deeper than any real I/O Registry tree; stops a hostile or corrupt dump from recursing without end.
const MAX_REGISTRY_DEPTH: usize = 200;

/// Pure core of `macos_usb_device_map`: `ioreg -a -r -c IOUSBHostDevice -l` output -> BSD name -> USB device.
pub fn parse_usb_device_map(ioreg_output: &[u8]) -> Result<HashMap<String, UsbDevice>> {
    let roots = parse_plist(ioreg_output)?;
    let mut found = HashMap::new();
    if let Some(list) = roots.as_array() {
        for root in list {
            walk_registry(root, None, &mut found, 0);
        }
    }
    Ok(found)
}

fn walk_registry(node: &Value, usb: Option<&UsbDevice>, found: &mut HashMap<String, UsbDevice>, depth: usize) {
    let Some(dict) = node.as_dictionary() else {
        return;
    };
    if depth > MAX_REGISTRY_DEPTH {
        return;
    }
    let own;
    let mut usb = usb;
    if dict.get("IOObjectClass").and_then(Value::as_string) == Some("IOUSBHostDevice") {
        let serial = match text(dict, "kUSBSerialNumberString") {
            s if !s.is_empty() => s,
            _ => text(dict, "USB Serial Number"),
        };
        own = UsbDevice { serial, vendor: text(dict, "USB Vendor Name"), product: text(dict, "USB Product Name") };
        usb = Some(&own);
    }
    if let (Some(device), Some(bsd)) = (usb, dict.get("BSD Name").and_then(Value::as_string)) {
        found.insert(bsd.to_string(), device.clone());
    }
    if let Some(children) = dict.get("IORegistryEntryChildren").and_then(Value::as_array) {
        for child in children {
            walk_registry(child, usb, found, depth + 1);
        }
    }
}

/// `macos_usb_device_map()`: map BSD names to the USB device that carries them. Parses `ioreg` (the only place
/// macOS exposes the USB serial number). Best effort: an empty map on any failure, since this only enriches the
/// description of a drive.
pub fn usb_device_map(host: &dyn Host) -> HashMap<String, UsbDevice> {
    let result = host
        .check_output(&["ioreg", "-a", "-r", "-c", "IOUSBHostDevice", "-l"], secs(IOREG_TIMEOUT), true)
        .and_then(|out| parse_usb_device_map(&out));
    match result {
        Ok(map) => map,
        Err(e) => {
            host.audit(&format!("USB serial lookup unavailable ({})", error_kind(&e)), AuditLevel::Warning);
            HashMap::new()
        }
    }
}

/// Pure core of `macos_apfs_volumes_by_store`: `diskutil list -plist` -> the partition that holds an APFS container
/// ('disk4s2') -> that container's volumes.
pub fn parse_apfs_volumes_by_store(listing: &Value) -> HashMap<String, Vec<Volume>> {
    let mut by_store = HashMap::new();
    let entries = listing.as_dictionary().and_then(|d| d.get("AllDisksAndPartitions")).and_then(Value::as_array);
    for entry in entries.into_iter().flatten() {
        let Some(entry) = entry.as_dictionary() else {
            continue;
        };
        let stores = entry.get("APFSPhysicalStores").and_then(Value::as_array);
        for store in stores.into_iter().flatten() {
            let mut vols = Vec::new();
            for v in entry.get("APFSVolumes").and_then(Value::as_array).into_iter().flatten() {
                let Some(v) = v.as_dictionary() else {
                    continue;
                };
                vols.push(Volume {
                    name: Some(text(v, "VolumeName")),
                    filesystem: Some("APFS".to_string()),
                    size: Some(number(entry, "Size")),
                    used: v.get("CapacityInUse").and_then(Value::as_unsigned_integer),
                    mountpoint: text_opt(v, "MountPoint"),
                });
            }
            if let Some(id) = store.as_dictionary().and_then(|s| s.get("DeviceIdentifier")).and_then(Value::as_string) {
                by_store.insert(id.to_string(), vols);
            }
        }
    }
    by_store
}

/// `macos_apfs_volumes_by_store()`: `{}` when `diskutil list` fails.
pub fn apfs_volumes_by_store(host: &dyn Host) -> HashMap<String, Vec<Volume>> {
    match diskutil_plist(host, &["list", "-plist"], secs(QUERY_TIMEOUT)) {
        Ok(listing) => parse_apfs_volumes_by_store(&listing),
        Err(_) => HashMap::new(),
    }
}

/// `macos_describe_disk(entry, info, usb_map, apfs_map)`: `(model, volumes, identity)` for one external disk.
/// `volumes` is None if it cannot be read.
pub fn describe_disk(
    host: &dyn Host,
    entry: &Dictionary,
    info: &Dictionary,
    usb_map: &HashMap<String, UsbDevice>,
    apfs_map: &HashMap<String, Vec<Volume>>,
) -> (String, Option<Vec<Volume>>, Identity) {
    let dev = entry.get("DeviceIdentifier").and_then(Value::as_string).unwrap_or("");
    let usb = usb_map.get(dev).cloned().unwrap_or_default();
    let media = text(info, "MediaName").trim().to_string();
    let vendor = usb.vendor.trim().to_string();
    let mut model = if media.is_empty() { usb.product.trim().to_string() } else { media.clone() };
    if !vendor.is_empty() && !model.to_lowercase().contains(&vendor.to_lowercase()) {
        model = format!("{vendor} {model}").trim().to_string();
    }
    let identity = host.make_identity(&[
        ("serial", Some(usb.serial.clone())),
        ("model", Some(if media.is_empty() { usb.product.clone() } else { media })),
        ("diskuuid", info.get("DiskUUID").filter(|v| truthy(v)).map(py_str)),
    ]);
    let volumes = match partition_volumes(host, entry, apfs_map) {
        Ok(volumes) => Some(volumes),
        Err(e) => {
            host.audit(&format!("Could not inspect the volumes of {dev} ({})", error_kind(&e)), AuditLevel::Warning);
            None
        }
    };
    (model, volumes, identity)
}

/// The volumes of one disk: its partitions, with an APFS container's volumes in place of the container itself.
fn partition_volumes(
    host: &dyn Host,
    entry: &Dictionary,
    apfs_map: &HashMap<String, Vec<Volume>>,
) -> Result<Vec<Volume>> {
    let mut volumes = Vec::new();
    let parts = entry.get("Partitions").and_then(Value::as_array);
    for part in parts.into_iter().flatten() {
        let Some(part) = part.as_dictionary() else {
            return Err(Error::runtime("Unexpected partition entry."));
        };
        let pid = part
            .get("DeviceIdentifier")
            .and_then(Value::as_string)
            .ok_or_else(|| Error::runtime("A partition has no identifier."))?;
        if text(part, "Content").starts_with("Apple_APFS") {
            if let Some(apfs) = apfs_map.get(pid).filter(|v| !v.is_empty()) {
                volumes.extend(apfs.iter().cloned());
                continue;
            }
        }
        let pinfo = diskutil_info(host, pid)?;
        let mountpoint = text_opt(&pinfo, "MountPoint").or_else(|| text_opt(part, "MountPoint"));
        let name = text_opt(part, "VolumeName").or_else(|| text_opt(&pinfo, "VolumeName")).unwrap_or_default();
        let filesystem = text_opt(&pinfo, "FilesystemUserVisibleName")
            .or_else(|| text_opt(&pinfo, "FilesystemName"))
            .unwrap_or_else(|| text(part, "Content"));
        let used = mountpoint.as_deref().and_then(|mp| host.used_bytes(mp));
        volumes.push(Volume {
            name: Some(name),
            filesystem: Some(filesystem),
            size: Some(number(part, "Size")),
            used,
            mountpoint,
        });
    }
    Ok(volumes)
}

/// `macos_get_external_disks()`: list only EXTERNAL physical disks attached over USB (never the Mac's internal disk).
pub fn get_external_disks() -> Result<Vec<Disk>> {
    get_external_disks_with(&SystemHost)
}

pub fn get_external_disks_with(host: &dyn Host) -> Result<Vec<Disk>> {
    let data =
        into_dictionary(diskutil_plist(host, &["list", "-plist", "external", "physical"], secs(QUERY_TIMEOUT))?)?;
    // Looked up lazily: only needed when at least one disk qualifies.
    let mut maps: Option<DescribeMaps> = None;
    let mut disks = Vec::new();
    let entries = data.get("AllDisksAndPartitions").and_then(Value::as_array);
    for d in entries.into_iter().flatten() {
        let Some(d) = d.as_dictionary() else {
            continue;
        };
        let dev = match d.get("DeviceIdentifier").and_then(Value::as_string) {
            Some(dev) if !dev.is_empty() && MAC_DEVICE_RE.is_match(dev) => dev,
            _ => continue,
        };
        let size = match d.get("Size").and_then(Value::as_unsigned_integer) {
            Some(size) if size > 0 => size,
            _ => {
                // An empty card reader reports no media (0 bytes): there is nothing to write to.
                host.audit(&format!("Hiding {dev}: its size is zero or unreadable"), AuditLevel::Warning);
                continue;
            }
        };
        let info = match diskutil_info(host, dev) {
            Ok(info) => info,
            Err(e) => {
                // Fail closed: if we cannot confirm the disk is external, do not offer it for erasure. (A fallback
                // to an empty answer would let the Internal check pass silently and could expose the system disk.)
                host.audit(
                    &format!("Hiding {dev}: could not verify it is external ({})", error_kind(&e)),
                    AuditLevel::Warning,
                );
                continue;
            }
        };
        if info.get("Internal").is_some_and(truthy) {
            continue; // extra safety: never list the internal disk
        }
        if !info.get("Removable").is_none_or(truthy) && !info.get("Ejectable").is_none_or(truthy) {
            continue;
        }
        if text(&info, "BusProtocol").to_uppercase() != "USB" {
            continue; // only USB drives are offered (no SD cards, Thunderbolt/NVMe enclosures, disk images)
        }
        // Descriptive extras (model, volumes, identity). Failing to gather them never hides or exposes a disk: the
        // safety filters above have already decided that.
        let (usb_map, apfs_map) = maps.get_or_insert_with(|| (usb_device_map(host), apfs_volumes_by_store(host)));
        let (model, volumes, identity) = describe_disk(host, d, &info, usb_map, apfs_map);
        disks.push(host.disk_entry(dev, size, Some(&model), volumes, identity));
    }
    Ok(disks)
}

/// `macos_find_mountpoint_by_volname(dev, volname, retries=15)`: where the volume called `volname` on `/dev/<dev>` is
/// mounted, waiting up to 15 seconds for it to appear.
pub fn find_mountpoint_by_volname(dev: &str, volname: &str) -> Result<String> {
    find_mountpoint_by_volname_with(&SystemHost, dev, volname, 15)
}

pub fn find_mountpoint_by_volname_with(host: &dyn Host, dev: &str, volname: &str, retries: u32) -> Result<String> {
    for _ in 0..retries {
        let data =
            into_dictionary(diskutil_plist(host, &["list", "-plist", &format!("/dev/{dev}")], secs(QUERY_TIMEOUT))?)?;
        let entries = data.get("AllDisksAndPartitions").and_then(Value::as_array);
        let parts = entries
            .and_then(|e| e.first())
            .and_then(Value::as_dictionary)
            .and_then(|e| e.get("Partitions"))
            .and_then(Value::as_array);
        for part in parts.into_iter().flatten() {
            let Some(part) = part.as_dictionary() else {
                continue;
            };
            if text(part, "VolumeName").to_uppercase() == volname.to_uppercase() {
                let pid = part
                    .get("DeviceIdentifier")
                    .and_then(Value::as_string)
                    .ok_or_else(|| Error::runtime("A partition has no identifier."))?;
                let info = diskutil_info(host, pid)?;
                if let Some(mp) = text_opt(&info, "MountPoint") {
                    return Ok(mp);
                }
            }
        }
        host.sleep(1.0);
    }
    Err(Error::runtime("Could not find the USB drive's mount point after formatting."))
}

/// `macos_unmount(dev, log, check=True, force=False)`: unmount every volume of the whole disk
/// (`diskutil unmountDisk`); `force` also takes busy ones. Returns run_cmd's exit code; with `check` a failure is an
/// error, without it the code is only returned.
pub fn unmount(dev: &str, log: Log, check: bool, force: bool) -> Result<i32> {
    unmount_with(&SystemHost, dev, log, check, force)
}

pub fn unmount_with(host: &dyn Host, dev: &str, log: Log, check: bool, force: bool) -> Result<i32> {
    let target = format!("/dev/{dev}");
    let mut cmd = vec!["diskutil", "unmountDisk"];
    if force {
        cmd.push("force");
    }
    cmd.push(&target);
    host.run_cmd(&cmd, log, check, Some(secs(DISKUTIL_TIMEOUT)), None)
}

/// `macos_eject(dev, log)`: eject the whole disk; if something holds it, force-unmount and retry. True on success.
pub fn eject(dev: &str, log: Log) -> bool {
    eject_with(&SystemHost, dev, log)
}

pub fn eject_with(host: &dyn Host, dev: &str, log: Log) -> bool {
    let target = format!("/dev/{dev}");
    log("Ejecting the USB drive...");
    let try_eject = || {
        // A command that cannot even run counts as "not ejected" (the drive is left as it is).
        matches!(host.run_cmd(&["diskutil", "eject", &target], log, false, Some(secs(DISKUTIL_TIMEOUT)), None), Ok(0))
    };
    if try_eject() {
        return true;
    }
    log("The drive is busy — forcing the unmount and trying again...");
    let _ = unmount_with(host, dev, log, false, true);
    host.sleep(1.0);
    try_eject()
}

// ---------------------------------------------------------------------------------------------------------------
// Windows-mode build
// ---------------------------------------------------------------------------------------------------------------

/// `macos_build_usb`: erase, GPT + FAT32 (label WIN11USB), copy, verify, eject. `Ok(ejected)` (false when `eject`
/// is off: the drive was left connected).
pub fn build_usb(iso_path: &Path, dev: &str, ctx: &Ctx, eject: bool, hardening_files: Option<&Files>) -> Result<bool> {
    build_usb_with(&SystemHost, iso_path, dev, ctx, eject, hardening_files)
}

pub fn build_usb_with(
    host: &dyn Host,
    iso_path: &Path,
    dev: &str,
    ctx: &Ctx,
    eject: bool,
    hardening_files: Option<&Files>,
) -> Result<bool> {
    let log = ctx.log;
    ctx.check_canceled(false, false)?; // nothing has been changed yet
    let target_dev = format!("/dev/{dev}");
    ctx.log(&format!("Erasing and formatting {target_dev} as GPT + FAT32 ('{VOL_NAME}')..."));
    host.run_cmd(
        &["diskutil", "eraseDisk", "FAT32", VOL_NAME, "GPT", &target_dev],
        log,
        true,
        Some(ERASE_TIMEOUT),
        None,
    )?;

    let target = find_mountpoint_by_volname_with(host, dev, VOL_NAME, 15)?;
    ctx.log(&format!("USB drive ready at: {target}"));
    ctx.check_canceled(true, false)?;

    let mount_dir = host.mkdtemp("win11iso_")?;
    let mount_arg = mount_dir.to_string_lossy().into_owned();
    ctx.log(&format!("Mounting the ISO at {mount_arg}..."));
    let iso = iso_path.to_string_lossy().into_owned();
    let attach = host.run_cmd(
        &["hdiutil", "attach", &iso, "-nobrowse", "-readonly", "-mountpoint", &mount_arg],
        log,
        true,
        Some(ATTACH_TIMEOUT),
        None,
    );
    if let Err(e) = attach {
        host.silent_rmdir(&mount_dir);
        return Err(e);
    }

    let body = || -> Result<()> {
        let reopen = || -> Result<PathBuf> {
            ctx.log("Remounting the drive to read it back from the device...");
            unmount_with(host, dev, log, true, false)?;
            host.run_cmd(&["diskutil", "mountDisk", &target_dev], log, true, Some(secs(DISKUTIL_TIMEOUT)), None)?;
            Ok(PathBuf::from(find_mountpoint_by_volname_with(host, dev, VOL_NAME, 15)?))
        };
        let extra = hardening_files.filter(|f| !f.is_empty());
        let result =
            host.copy_windows_payload(&mount_dir, Path::new(&target), ctx, WIMLIB_HINT_MAC, Some(&reopen), extra);
        if let Err(e) = &result {
            if e.is_canceled() {
                if e.written() {
                    ctx.log(
                        "Canceled during verification. Unmounting the drive; the files were copied completely but NOT verified.",
                    );
                } else {
                    ctx.log("Canceled. Unmounting the drive; it is left incomplete and unusable.");
                }
                unmount_with(host, dev, log, false, false)?;
            }
        }
        result
    };
    let result = body();
    // finally:
    ctx.log("Unmounting the ISO...");
    let detach =
        host.run_cmd(&["hdiutil", "detach", &mount_arg, "-force"], log, false, Some(secs(DISKUTIL_TIMEOUT)), None);
    host.silent_rmdir(&mount_dir);
    detach?;
    result?;

    let ejected = if eject { eject_with(host, dev, log) } else { false };
    ctx.log("Done! The USB drive is ready to install Windows 11.");
    report_eject(ejected, log, !eject);
    Ok(ejected)
}

// ---------------------------------------------------------------------------------------------------------------
// Raw write (Linux and other hybrid ISOs, ChromeOS Flex)
// ---------------------------------------------------------------------------------------------------------------

/// `macos_write_raw`: write the image byte-for-byte to the whole disk, then read it back and compare. `Ok(ejected)`.
pub fn write_raw(iso_path: &Path, dev: &str, ctx: &Ctx, priv_: &dyn Privilege, eject: bool) -> Result<bool> {
    write_raw_with(&SystemHost, iso_path, dev, ctx, priv_, eject)
}

pub fn write_raw_with(
    host: &dyn Host,
    iso_path: &Path,
    dev: &str,
    ctx: &Ctx,
    priv_: &dyn Privilege,
    eject: bool,
) -> Result<bool> {
    let log = ctx.log;
    host.validate_hybrid_iso(iso_path)?;
    ctx.check_canceled(false, false)?;
    ctx.log(&format!("Unmounting /dev/{dev}..."));
    unmount_with(host, dev, log, true, false)?;
    ctx.check_canceled(false, false)?; // unmounting changes no data
    ctx.log(&format!(
        "Writing the ISO to /dev/{dev} (administrator privileges required). This can take several minutes."
    ));
    let total = std::fs::metadata(iso_path)?.len();
    // /dev/rdiskN (raw node) is several times faster than /dev/diskN.
    let raw_dev = format!("/dev/r{dev}");
    let base_args = [iso_path.to_string_lossy().into_owned(), raw_dev.clone(), RAW_WRITE_BLOCK_MAC.to_string()];
    let canceled = write_raw_image_with(host, priv_, MACOS_RAW_SCRIPT, &base_args, ctx, total, &[])?;
    if canceled {
        ctx.log("Canceled. The drive holds a partial image and is unusable until written again.");
        unmount_with(host, dev, log, false, false)?;
        return Err(Error::canceled());
    }
    ctx.report(total, total, "Written");
    host.verify_raw_write(iso_path, &raw_dev, ctx, priv_)?;
    ctx.log(
        "Note: macOS cannot read Linux or ChromeOS (ISO 9660/ext) images, so this drive will not show up in Finder, \
         and macOS may say the disk is 'not readable' — click Ignore, never Initialize. That is normal; the content \
         was just verified byte-for-byte.",
    );
    let ejected = if eject { eject_with(host, dev, log) } else { false };
    ctx.log("Done! The USB drive is ready to boot.");
    report_eject(ejected, log, !eject);
    Ok(ejected)
}

// ---------------------------------------------------------------------------------------------------------------
// The hardening seed drive
// ---------------------------------------------------------------------------------------------------------------

/// `macos_build_seed_usb`: the hardening seed drive (GPT + FAT32 with `label`, `files` copied from `stage_dir`,
/// verified). `Ok(ejected)`.
pub fn build_seed_usb(label: &str, files: &Files, stage_dir: &Path, dev: &str, ctx: &Ctx, eject: bool) -> Result<bool> {
    build_seed_usb_with(&SystemHost, label, files, stage_dir, dev, ctx, eject)
}

pub fn build_seed_usb_with(
    host: &dyn Host,
    label: &str,
    files: &Files,
    stage_dir: &Path,
    dev: &str,
    ctx: &Ctx,
    eject: bool,
) -> Result<bool> {
    let log = ctx.log;
    ctx.check_canceled(false, false)?; // nothing has been changed yet
    let target_dev = format!("/dev/{dev}");
    ctx.log(&format!("Erasing and formatting {target_dev} as GPT + FAT32 ('{label}')..."));
    host.run_cmd(&["diskutil", "eraseDisk", "FAT32", label, "GPT", &target_dev], log, true, Some(ERASE_TIMEOUT), None)?;
    let body = || -> Result<()> {
        let target = find_mountpoint_by_volname_with(host, dev, label, 15)?;
        ctx.log(&format!("USB drive ready at: {target}"));
        ctx.check_canceled(true, false)?;
        host.copy_seed_files(stage_dir, Path::new(&target), files, ctx)?;
        ctx.log("Remounting the drive to read it back from the device...");
        unmount_with(host, dev, log, true, false)?;
        host.run_cmd(&["diskutil", "mountDisk", &target_dev], log, true, Some(secs(DISKUTIL_TIMEOUT)), None)?;
        let target = find_mountpoint_by_volname_with(host, dev, label, 15)?;
        host.verify_seed_files(files, Path::new(&target), ctx)
    };
    if let Err(e) = body() {
        if e.is_canceled() {
            if e.written() {
                ctx.log(
                    "Canceled during verification. Unmounting the drive; the files were copied completely but NOT verified.",
                );
            } else {
                ctx.log("Canceled. Unmounting the drive; it is left incomplete and unusable.");
            }
            unmount_with(host, dev, log, false, false)?;
        }
        return Err(e);
    }
    let ejected = if eject { eject_with(host, dev, log) } else { false };
    ctx.log("Done! The seed drive is ready: plug it in next to the installer USB drive.");
    report_eject(ejected, log, !eject);
    Ok(ejected)
}
