//! Linux backend. OWNER: A3. Port of win11_usb_creator.py lines 2547-2574 (linux_eject) and 2684-3022 (lsblk listing,
//! package manager, LINUX_RAW_SCRIPT, linux_write_raw, linux_build_usb) and 8662-8702 + 8731-8789 (LINUX_SEED_*
//! scripts, linux_build_seed_usb). Compiles on every OS; it only *runs* commands on Linux.
//!
//! Layout: pure parsers/builders (`parse_lsblk`, `parse_critical_mounts`, `describe_disk`, `disks_from_lsblk`,
//! `build_install_command`...) and thin functions that run commands through a [`Host`] (`macos/host.rs`). Every
//! public function has a `*_with(host, ...)` twin for tests. Every root script is data (`assets/linux_*.sh`): values
//! reach them only as "$1".."$n" positional parameters through `Privilege::run_script`, never pasted into the text.

use crate::audit::AuditLevel;
use crate::constants::{
    CRITICAL_MOUNTPOINTS, DIRECT_IO_ALIGNMENT, LINUX_DEVICE_RE, LINUX_INSTALL_CMD_TEMPLATE, LINUX_PKG_MAP,
    LINUX_REQUIRED_TOOLS, QUERY_TIMEOUT, RAW_WRITE_BLOCK_LINUX,
};
use crate::macos::host::error_kind;
pub use crate::macos::host::{report_eject, write_raw_image, write_raw_image_with, Host, SystemHost};
use crate::types::{Ctx, Disk, Error, Files, Identity, Log, Privilege, Result, Volume};
use regex::Regex;
use serde_json::Value;
use std::cell::Cell;
use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

/// Root script that writes the image with `dd` (see `MACOS_RAW_SCRIPT` for the arguments). "$5" is "direct" (add
/// oflag=direct) or "buffered"; the caller decides, the text never changes.
pub const LINUX_RAW_SCRIPT: &str = include_str!("../assets/linux_raw_write.sh");
/// Root script of the Linux seed drive: unmount, wipe, GPT + one FAT32 partition, label, mount for the user. Values
/// arrive as "$1".."$6". "$6" is the cancel flag file (see `proc::cancel_flag`): the script looks at it between its
/// steps. Nothing is printed on success.
pub const LINUX_SEED_PREP_SCRIPT: &str = include_str!("../assets/linux_seed_prep.sh");
/// Remount the partition read-only so the check reads from the device and not from the cache.
pub const LINUX_SEED_REMOUNT_SCRIPT: &str = include_str!("../assets/linux_seed_remount.sh");
pub const LINUX_SEED_CLEANUP_SCRIPT: &str = include_str!("../assets/linux_seed_cleanup.sh");
/// Printed by `LINUX_SEED_PREP_SCRIPT` when it stops on request before touching the drive / after wiping it.
pub const SEED_UNTOUCHED_MARKER: &str = "SEED_NOT_TOUCHED";
pub const SEED_CANCELED_MARKER: &str = "SEED_CANCELED";

/// The Windows-mode prep script (erase, GPT + FAT32 labelled WIN11USB, mount the ISO and the drive).
const WINDOWS_PREP_SCRIPT: &str = include_str!("../assets/linux_win_prep.sh");
/// Read-only remount before the read-back.
const WINDOWS_REMOUNT_SCRIPT: &str = include_str!("../assets/linux_win_remount.sh");
const WINDOWS_CLEANUP_SCRIPT: &str = include_str!("../assets/linux_win_cleanup.sh");
/// Always exits 0 so a drive that cannot be powered off is not reported as a failure; the outcome is reported
/// through the EJECTED / NOT_EJECTED marker line.
const EJECT_SCRIPT: &str = include_str!("../assets/linux_eject.sh");
const UNMOUNT_PARTITIONS_SCRIPT: &str = include_str!("../assets/linux_unmount_parts.sh");

const WIMLIB_HINT_LINUX: &str = "wimlib-imagex not found. Install it via your package manager (e.g. 'wimtools' on \
Debian/Ubuntu, 'wimlib-utils' on Fedora, 'wimlib' on Arch/openSUSE) or use the 'Install missing dependencies' button.";

/// Richest first; older util-linux rejects unknown columns, so fall back step by step.
pub const LSBLK_COLUMN_SETS: [&str; 3] = [
    "NAME,SIZE,TYPE,RM,TRAN,SERIAL,WWN,MODEL,VENDOR,FSTYPE,LABEL,MOUNTPOINT,FSUSED",
    "NAME,SIZE,TYPE,RM,TRAN,SERIAL,WWN,MODEL,VENDOR,FSTYPE,LABEL,MOUNTPOINT",
    "NAME,SIZE,TYPE,RM,TRAN",
];

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

// ---------------------------------------------------------------------------------------------------------------
// Python-flavoured access to JSON
// ---------------------------------------------------------------------------------------------------------------

/// Python truthiness of a JSON value.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_none_or(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `str(value)` for the scalar types lsblk prints.
fn py_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Null => "None".to_string(),
        other => other.to_string(),
    }
}

/// `_as_int(value)`: `int(value)` or None when it is not a number (or a numeric string).
pub fn as_int(value: &Value) -> Option<i64> {
    match value {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().filter(|f| f.is_finite()).map(|f| f as i64)),
        Value::String(s) => s.trim().parse::<i64>().ok(),
        Value::Bool(b) => Some(i64::from(*b)),
        _ => None,
    }
}

/// `str(dev.get(key) or "")` for a field that must be text: `Err` where Python would raise on `.strip()`.
fn text_field(dev: &Value, key: &str) -> std::result::Result<String, &'static str> {
    match dev.get(key) {
        None => Ok(String::new()),
        Some(v) if !truthy(v) => Ok(String::new()),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(_) => Err("AttributeError"),
    }
}

/// `node.get(key) or None` for text.
fn text_opt(node: &Value, key: &str) -> Option<String> {
    node.get(key).filter(|v| truthy(v)).map(py_str)
}

// ---------------------------------------------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------------------------------------------

/// `linux_root_disk()`: the whole disk that holds `/`, or None when it cannot be determined.
pub fn root_disk(host: &dyn Host) -> Option<String> {
    let result = (|| -> Result<String> {
        let src = host.check_output(&["findmnt", "-no", "SOURCE", "/"], secs(QUERY_TIMEOUT), false)?;
        let src = String::from_utf8_lossy(&src).trim().to_string();
        let pk = host.check_output(&["lsblk", "-no", "PKNAME", &src], secs(QUERY_TIMEOUT), false)?;
        Ok(String::from_utf8_lossy(&pk).trim().to_string())
    })();
    match result {
        Ok(pk) if !pk.is_empty() => Some(pk),
        Ok(_) => None,
        Err(e) => {
            host.audit(
                &format!(
                    "Could not determine the system disk ({}); falling back to mountpoint inspection",
                    error_kind(&e)
                ),
                AuditLevel::Warning,
            );
            None
        }
    }
}

/// Pure core of `linux_disks_holding_critical_mounts`: `lsblk -J -b -o NAME,TYPE,MOUNTPOINT,PKNAME` output -> the
/// names of the whole disks that host a critical system mountpoint (anywhere in their tree of partitions).
pub fn parse_critical_mounts(lsblk_output: &[u8]) -> Result<HashSet<String>> {
    let data: Value = serde_json::from_slice(lsblk_output)
        .map_err(|e| Error::runtime(format!("Could not read the lsblk output: {e}")))?;
    let mut unsafe_disks = HashSet::new();
    let devices = data.get("blockdevices").and_then(Value::as_array).cloned().unwrap_or_default();
    for dev in &devices {
        if dev.get("type").and_then(Value::as_str) != Some("disk") {
            continue;
        }
        if let Some(name) = dev.get("name").and_then(Value::as_str) {
            if holds_critical_mount(dev, 0) {
                unsafe_disks.insert(name.to_string());
            }
        }
    }
    Ok(unsafe_disks)
}

/// Is a critical mountpoint (or anything under /boot) mounted from this node or one of its children?
fn holds_critical_mount(node: &Value, depth: usize) -> bool {
    if depth > 64 {
        return false;
    }
    if let Some(mp) = node.get("mountpoint").and_then(Value::as_str) {
        if CRITICAL_MOUNTPOINTS.contains(&mp) || mp.starts_with("/boot") {
            return true;
        }
    }
    node.get("children")
        .and_then(Value::as_array)
        .is_some_and(|children| children.iter().any(|child| holds_critical_mount(child, depth + 1)))
}

/// `linux_disks_holding_critical_mounts()`: names of whole disks that currently host a critical system mountpoint.
///
/// This is the safety net for machines that boot from a device flagged as removable (a Raspberry Pi booting from
/// its SD card, a USB-booted system): there, the 'removable' flag alone would happily offer the system disk for
/// erasure. An empty set means "could not determine".
pub fn disks_holding_critical_mounts(host: &dyn Host) -> HashSet<String> {
    let result = host
        .check_output(&["lsblk", "-J", "-b", "-o", "NAME,TYPE,MOUNTPOINT,PKNAME"], secs(QUERY_TIMEOUT), false)
        .and_then(|out| parse_critical_mounts(&out));
    match result {
        Ok(set) => set,
        Err(e) => {
            host.audit(&format!("Critical-mountpoint scan unavailable ({})", error_kind(&e)), AuditLevel::Warning);
            HashSet::new()
        }
    }
}

/// Pure core of `linux_lsblk_disks`: the top-level devices of `lsblk -J` output.
pub fn parse_lsblk(lsblk_output: &[u8]) -> Result<Vec<Value>> {
    let data: Value = serde_json::from_slice(lsblk_output)
        .map_err(|e| Error::runtime(format!("Could not read the lsblk output: {e}")))?;
    match data.get("blockdevices") {
        None => Ok(Vec::new()),
        Some(Value::Array(devices)) => Ok(devices.clone()),
        Some(_) => Err(Error::runtime("Unexpected lsblk output (blockdevices is not a list).")),
    }
}

/// `linux_lsblk_disks()`: `lsblk -J` as a list of top-level devices, using the richest column set this lsblk
/// supports. The last failure is returned when none works.
pub fn lsblk_disks(host: &dyn Host) -> Result<Vec<Value>> {
    let mut last_error = None;
    for columns in LSBLK_COLUMN_SETS {
        let result = host
            .check_output(&["lsblk", "-J", "-b", "-o", columns], secs(QUERY_TIMEOUT), true)
            .and_then(|out| parse_lsblk(&out));
        match result {
            Ok(devices) => return Ok(devices),
            Err(e) => last_error = Some(e),
        }
    }
    Err(last_error.unwrap_or_else(|| Error::runtime("lsblk failed.")))
}

/// `linux_describe_disk(dev)`: `(model, volumes, identity)` from one lsblk disk node. `volumes` is None without
/// partition info. Descriptive only: it never changes which disks are offered.
pub fn describe_disk(host: &dyn Host, dev: &Value) -> (String, Option<Vec<Volume>>, Identity) {
    match describe_disk_inner(host, dev) {
        Ok(description) => description,
        Err(kind) => {
            let name = dev.get("name").map_or_else(|| "None".to_string(), py_str);
            host.audit(&format!("Could not describe {name} ({kind})"), AuditLevel::Warning);
            (String::new(), None, Vec::new())
        }
    }
}

fn describe_disk_inner(
    host: &dyn Host,
    dev: &Value,
) -> std::result::Result<(String, Option<Vec<Volume>>, Identity), &'static str> {
    let vendor = text_field(dev, "vendor")?.trim().to_string();
    let product = text_field(dev, "model")?.trim().to_string();
    // `vendor.lower() not in product.lower()`: the vendor is added unless the product name already holds it.
    let model = if product.to_lowercase().contains(&vendor.to_lowercase()) {
        product.clone()
    } else {
        format!("{vendor} {product}").trim().to_string()
    };
    let identity = host.make_identity(&[
        ("serial", text_opt(dev, "serial")),
        ("wwn", text_opt(dev, "wwn")),
        ("model", Some(model.clone())),
    ]);
    if dev.as_object().is_none_or(|o| !o.contains_key("fstype")) {
        return Ok((model, None, identity)); // this lsblk is too old to report filesystems
    }
    let mut nodes: Vec<&Value> = Vec::new();
    match dev.get("children") {
        None => {}
        Some(v) if !truthy(v) => {}
        Some(Value::Array(children)) => {
            for child in children {
                if !child.is_object() {
                    return Err("AttributeError");
                }
                if child.get("type").and_then(Value::as_str) == Some("part") {
                    nodes.push(child);
                }
            }
        }
        Some(_) => return Err("AttributeError"),
    }
    if dev.get("fstype").is_some_and(truthy) {
        nodes.push(dev); // a filesystem written straight onto the disk, with no partition table
    }
    let mut volumes = Vec::new();
    for node in nodes {
        let mountpoint = text_opt(node, "mountpoint");
        let used = match node.get("fsused").and_then(as_int) {
            Some(n) => u64::try_from(n).ok(),
            None => mountpoint.as_deref().and_then(|mp| host.used_bytes(mp)),
        };
        volumes.push(Volume {
            name: Some(text_opt(node, "label").or_else(|| text_opt(node, "name")).unwrap_or_default()),
            filesystem: Some(text_opt(node, "fstype").unwrap_or_default()),
            size: Some(node.get("size").and_then(as_int).and_then(|n| u64::try_from(n).ok()).unwrap_or(0)),
            used,
            mountpoint,
        });
    }
    Ok((model, Some(volumes), identity))
}

/// The disks `lsblk` offers: USB only, never the system disk or one that hosts a critical mountpoint, never an
/// empty reader (size 0). `devices` are the top-level nodes of `lsblk -J`.
pub fn disks_from_lsblk(host: &dyn Host, devices: &[Value], unsafe_disks: &HashSet<String>) -> Vec<Disk> {
    let mut disks = Vec::new();
    for dev in devices {
        if dev.get("type").and_then(Value::as_str) != Some("disk") {
            continue;
        }
        let name = match dev.get("name").and_then(Value::as_str) {
            Some(name) if !name.is_empty() && LINUX_DEVICE_RE.is_match(name) => name,
            _ => continue,
        };
        if unsafe_disks.contains(name) {
            host.audit(&format!("Hiding {name}: it hosts the system or a critical mountpoint"), AuditLevel::Info);
            continue;
        }
        if name.starts_with("loop") || name.starts_with("zram") || name.starts_with("dm-") {
            continue;
        }
        let transport = dev.get("tran").and_then(Value::as_str).unwrap_or("");
        if transport.to_lowercase() != "usb" {
            continue; // only USB drives are offered
        }
        let size = dev.get("size").and_then(as_int).unwrap_or(0);
        if size <= 0 {
            // An empty card reader (transport "usb", no media) reports 0 bytes.
            host.audit(&format!("Hiding {name}: its size is zero or unreadable"), AuditLevel::Warning);
            continue;
        }
        let size = size as u64;
        let (model, volumes, identity) = describe_disk(host, dev);
        disks.push(host.disk_entry(name, size, Some(&model), volumes, identity));
    }
    disks
}

fn read_trimmed(path: &Path) -> std::io::Result<String> {
    Ok(std::fs::read_to_string(path)?.trim().to_string())
}

/// The fallback that reads `/sys/block` directly (works even without `lsblk -J` support).
pub fn disks_from_sysfs(host: &dyn Host, unsafe_disks: &HashSet<String>) -> Result<Vec<Disk>> {
    let root = host.sys_block_root();
    let mut names: Vec<String> = std::fs::read_dir(&root)?
        .filter_map(|entry| entry.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    let mut disks = Vec::new();
    for name in names {
        if ["loop", "ram", "dm-", "sr", "zram"].iter().any(|p| name.starts_with(p)) {
            continue;
        }
        if !LINUX_DEVICE_RE.is_match(&name) || unsafe_disks.contains(&name) {
            continue;
        }
        let disk_dir = root.join(&name);
        let removable_path = disk_dir.join("removable");
        if !removable_path.exists() {
            continue;
        }
        // Fail closed: a flag that cannot be read means "not removable".
        if !read_trimmed(&removable_path).is_ok_and(|s| s == "1") {
            continue;
        }
        // The sysfs device path of a USB drive passes through a "usb" bus node.
        let real = std::fs::canonicalize(&disk_dir).unwrap_or_else(|_| disk_dir.clone());
        if !real.to_string_lossy().contains("/usb") {
            continue;
        }
        let sectors = match read_trimmed(&disk_dir.join("size")).ok().and_then(|s| s.parse::<i64>().ok()) {
            Some(n) => n,
            None => {
                host.audit(&format!("Hiding {name}: could not read its size"), AuditLevel::Warning);
                continue; // fail closed: an unknown-size disk is not offered
            }
        };
        let size = sectors.saturating_mul(512);
        if size <= 0 {
            host.audit(&format!("Hiding {name}: its size is zero"), AuditLevel::Warning);
            continue; // fail closed: a drive without media is not offered
        }
        // Purely descriptive: the disk is listed either way.
        let model = ["vendor", "model"]
            .iter()
            .map(|attr| read_trimmed(&disk_dir.join("device").join(attr)))
            .collect::<std::io::Result<Vec<String>>>()
            .map(|parts| parts.into_iter().filter(|p| !p.is_empty()).collect::<Vec<_>>().join(" "))
            .unwrap_or_default();
        // No partition information here (volumes=None): the confirmation says so and treats it as high risk.
        let identity = host.make_identity(&[("model", Some(model.clone()))]);
        disks.push(host.disk_entry(&name, size as u64, Some(&model), None, identity));
    }
    Ok(disks)
}

/// `linux_get_external_disks()`: the USB drives that are safe to offer.
pub fn get_external_disks() -> Result<Vec<Disk>> {
    get_external_disks_with(&SystemHost)
}

pub fn get_external_disks_with(host: &dyn Host) -> Result<Vec<Disk>> {
    let root = root_disk(host);
    let mut unsafe_disks = disks_holding_critical_mounts(host);
    if let Some(root) = root {
        unsafe_disks.insert(root);
    }
    if host.which("lsblk") {
        match lsblk_disks(host) {
            Ok(devices) => return Ok(disks_from_lsblk(host, &devices, &unsafe_disks)),
            Err(e) => host.audit(
                &format!("lsblk enumeration failed ({}); using /sys/block fallback", error_kind(&e)),
                AuditLevel::Warning,
            ),
        }
    }
    disks_from_sysfs(host, &unsafe_disks)
}

// ---------------------------------------------------------------------------------------------------------------
// Partition paths, package manager
// ---------------------------------------------------------------------------------------------------------------

/// `linux_partition_path(dev_name, n)`: `/dev/sdb1`, but `/dev/nvme0n1p2` (a name that ends in a digit gets a "p").
pub fn partition_path(dev_name: &str, n: u32) -> String {
    if dev_name.chars().last().is_some_and(|c| c.is_ascii_digit()) {
        format!("/dev/{dev_name}p{n}")
    } else {
        format!("/dev/{dev_name}{n}")
    }
}

/// `linux_detect_pkg_manager()`: apt-get, dnf, yum, pacman, zypper or apk (None when none is found), in the order
/// the managers are listed in `LINUX_INSTALL_CMD_TEMPLATE`.
pub fn detect_pkg_manager() -> Option<String> {
    detect_pkg_manager_with(&SystemHost)
}

pub fn detect_pkg_manager_with(host: &dyn Host) -> Option<String> {
    LINUX_INSTALL_CMD_TEMPLATE.iter().map(|(mgr, _)| *mgr).find(|mgr| host.which(mgr)).map(str::to_string)
}

static PACKAGE_NAME_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9._+-]{1,64}$").unwrap());

/// Python's `repr()` of a short string (what the messages quote with `!r`).
fn py_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// The install command (without sudo) for the missing tools; `Error::Value` for an unknown/absent manager.
///
/// Built from the fixed allow-list only: only tools declared in `LINUX_REQUIRED_TOOLS` may be installed, and only
/// under the package name mapped in `LINUX_PKG_MAP`. Nothing from user input or from the network can influence what
/// gets installed with root privileges.
pub fn build_install_command(mgr: Option<&str>, missing_tools: &[String]) -> Result<String> {
    build_install_command_from(LINUX_PKG_MAP, mgr, missing_tools)
}

/// `build_install_command` over an explicit package table (the tests pass a damaged one).
pub fn build_install_command_from(
    pkg_map: &[(&str, &[(&str, &str)])],
    mgr: Option<&str>,
    missing_tools: &[String],
) -> Result<String> {
    let template = mgr.and_then(|m| LINUX_INSTALL_CMD_TEMPLATE.iter().find(|(name, _)| *name == m)).map(|(_, t)| *t);
    let (Some(mgr), Some(template)) = (mgr, template) else {
        let shown = mgr.map_or_else(|| "None".to_string(), py_repr);
        return Err(Error::value(format!("Unsupported package manager: {shown}")));
    };
    let table: &[(&str, &str)] = pkg_map.iter().find(|(name, _)| *name == mgr).map_or(&[], |(_, t)| *t);
    let pkgs: BTreeSet<&str> = missing_tools
        .iter()
        .filter(|tool| LINUX_REQUIRED_TOOLS.contains(&tool.as_str()))
        .filter_map(|tool| table.iter().find(|(name, _)| *name == tool.as_str()).map(|(_, pkg)| *pkg))
        .collect();
    if pkgs.is_empty() {
        return Err(Error::value("Nothing to install: no recognised missing dependency."));
    }
    for pkg in &pkgs {
        if !PACKAGE_NAME_RE.is_match(pkg) {
            return Err(Error::value(format!("Refusing to install suspicious package name: {}", py_repr(pkg))));
        }
    }
    Ok(template.replace("{pkgs}", &pkgs.into_iter().collect::<Vec<_>>().join(" ")))
}

// ---------------------------------------------------------------------------------------------------------------
// Unmount, eject
// ---------------------------------------------------------------------------------------------------------------

/// `linux_unmount_partitions(dev, log, priv)`: best effort, unmount every partition of `dev` (used after a cancel).
pub fn unmount_partitions(dev: &str, log: Log, priv_: &dyn Privilege) {
    if let Err(e) = priv_.run_script(UNMOUNT_PARTITIONS_SCRIPT, log, &[dev.to_string()]) {
        log(&format!("Warning: could not unmount the drive: {e}"));
    }
}

/// `linux_eject(dev_name, log, priv)`: flush, unmount and power the drive off. Best effort: true if it was ejected.
pub fn eject(dev_name: &str, log: Log, priv_: &dyn Privilege) -> bool {
    log("Ejecting the USB drive (administrator privileges required)...");
    let seen: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let watch = |line: &str| {
        seen.lock().unwrap_or_else(|e| e.into_inner()).push(line.trim().to_string());
        log(line);
    };
    if let Err(e) = priv_.run_script(EJECT_SCRIPT, &watch, &[format!("/dev/{dev_name}")]) {
        log(&format!("Warning: could not run the eject step: {e}"));
        return false;
    }
    let seen = seen.lock().unwrap_or_else(|e| e.into_inner());
    seen.iter().any(|line| line == "EJECTED")
}

// ---------------------------------------------------------------------------------------------------------------
// Raw write
// ---------------------------------------------------------------------------------------------------------------

/// `linux_write_raw`: write the image byte-for-byte to the whole disk, then read it back and compare. `Ok(ejected)`.
pub fn write_raw(iso_path: &Path, dev: &str, ctx: &Ctx, priv_: &dyn Privilege, eject: bool) -> Result<bool> {
    write_raw_with(&SystemHost, iso_path, dev, ctx, priv_, eject)
}

pub fn write_raw_with(
    host: &dyn Host,
    iso_path: &Path,
    dev_name: &str,
    ctx: &Ctx,
    priv_: &dyn Privilege,
    do_eject: bool,
) -> Result<bool> {
    let log = ctx.log;
    host.validate_hybrid_iso(iso_path)?;
    ctx.check_canceled(false, false)?;
    let dev = format!("/dev/{dev_name}");
    let total = std::fs::metadata(iso_path)?.len();
    // O_DIRECT bypasses the page cache (steadier speed, honest progress), but needs every write block aligned; only
    // use it when the image size is a multiple of the alignment.
    let direct = if total % DIRECT_IO_ALIGNMENT == 0 { "direct" } else { "buffered" };
    ctx.log(&format!("Writing the ISO to {dev} (administrator privileges required)..."));
    // Values arrive as "$1".."$5"; the glob expands only after the quoted device prefix.
    let base_args = [iso_path.to_string_lossy().into_owned(), dev.clone(), RAW_WRITE_BLOCK_LINUX.to_string()];
    let canceled = write_raw_image_with(host, priv_, LINUX_RAW_SCRIPT, &base_args, ctx, total, &[direct.to_string()])?;
    if canceled {
        ctx.log("Canceled. The drive holds a partial image and is unusable until written again.");
        unmount_partitions(&dev, log, priv_);
        return Err(Error::canceled());
    }
    ctx.report(total, total, "Written");
    host.verify_raw_write(iso_path, &dev, ctx, priv_)?;
    let ejected = if do_eject { eject(dev_name, log, priv_) } else { false };
    ctx.log("Done! The USB drive is ready to boot.");
    report_eject(ejected, log, !do_eject);
    Ok(ejected)
}

// ---------------------------------------------------------------------------------------------------------------
// Windows-mode build
// ---------------------------------------------------------------------------------------------------------------

/// `linux_build_usb`: erase, GPT + FAT32 (label WIN11USB), copy, verify, eject. `Ok(ejected)`.
pub fn build_usb(
    iso_path: &Path,
    dev: &str,
    ctx: &Ctx,
    priv_: &dyn Privilege,
    eject: bool,
    hardening_files: Option<&Files>,
) -> Result<bool> {
    build_usb_with(&SystemHost, iso_path, dev, ctx, priv_, eject, hardening_files)
}

pub fn build_usb_with(
    host: &dyn Host,
    iso_path: &Path,
    dev_name: &str,
    ctx: &Ctx,
    priv_: &dyn Privilege,
    do_eject: bool,
    hardening_files: Option<&Files>,
) -> Result<bool> {
    let log = ctx.log;
    ctx.check_canceled(false, false)?; // nothing has been changed yet
    let dev = format!("/dev/{dev_name}");
    let part = partition_path(dev_name, 1);
    let owner = host.owner();
    let iso_mount = host.mkdtemp("win11iso_")?;
    let usb_mount = match host.mkdtemp("win11usb_") {
        Ok(dir) => dir,
        Err(e) => {
            host.silent_rmdir(&iso_mount);
            return Err(e);
        }
    };
    let iso_mount_arg = iso_mount.to_string_lossy().into_owned();
    let usb_mount_arg = usb_mount.to_string_lossy().into_owned();

    ctx.log(&format!("Erasing and formatting {dev} as GPT + FAT32 (administrator privileges required)..."));
    // Every value below arrives as a positional parameter ("$1".."$6"), never pasted into the script text, so no
    // filename can inject extra commands.
    let body = || -> Result<()> {
        priv_.run_script(
            WINDOWS_PREP_SCRIPT,
            log,
            &[
                dev.clone(),
                part.clone(),
                iso_path.to_string_lossy().into_owned(),
                iso_mount_arg.clone(),
                usb_mount_arg.clone(),
                owner.clone(),
            ],
        )?;
        ctx.check_canceled(true, false)?;
        let reopen = || -> Result<PathBuf> {
            ctx.log("Remounting the drive read-only to read it back from the device...");
            priv_.run_script(WINDOWS_REMOUNT_SCRIPT, log, &[part.clone(), usb_mount_arg.clone(), owner.clone()])?;
            Ok(usb_mount.clone())
        };
        let extra = hardening_files.filter(|f| !f.is_empty());
        let result = host.copy_windows_payload(&iso_mount, &usb_mount, ctx, WIMLIB_HINT_LINUX, Some(&reopen), extra);
        if let Err(e) = &result {
            if e.is_canceled() {
                if e.written() {
                    ctx.log("Canceled during verification. The files were copied completely but NOT verified.");
                } else {
                    ctx.log("Canceled. The drive is left incomplete and unusable.");
                }
            }
        }
        result
    };
    let result = body();
    // finally:
    ctx.log("Unmounting...");
    if let Err(cleanup_err) =
        priv_.run_script(WINDOWS_CLEANUP_SCRIPT, log, &[usb_mount_arg.clone(), iso_mount_arg.clone()])
    {
        ctx.log(&format!("Warning: cleanup failed: {cleanup_err}"));
    }
    host.silent_rmdir(&iso_mount);
    host.silent_rmdir(&usb_mount);
    result?;

    let ejected = if do_eject { eject(dev_name, log, priv_) } else { false };
    ctx.log("Done! The USB drive is ready to install Windows 11.");
    report_eject(ejected, log, !do_eject);
    Ok(ejected)
}

// ---------------------------------------------------------------------------------------------------------------
// The hardening seed drive
// ---------------------------------------------------------------------------------------------------------------

/// `linux_build_seed_usb`: the hardening seed drive (GPT + FAT32 with `label`, `files` copied from `stage_dir`,
/// verified). `Ok(ejected)`.
pub fn build_seed_usb(
    label: &str,
    files: &Files,
    stage_dir: &Path,
    dev: &str,
    ctx: &Ctx,
    priv_: &dyn Privilege,
    eject: bool,
) -> Result<bool> {
    build_seed_usb_with(&SystemHost, label, files, stage_dir, dev, ctx, priv_, eject)
}

pub fn build_seed_usb_with(
    host: &dyn Host,
    label: &str,
    files: &Files,
    stage_dir: &Path,
    dev_name: &str,
    ctx: &Ctx,
    priv_: &dyn Privilege,
    do_eject: bool,
) -> Result<bool> {
    let log = ctx.log;
    ctx.check_canceled(false, false)?; // nothing has been changed yet
    let dev = format!("/dev/{dev_name}");
    let part = partition_path(dev_name, 1);
    let owner = host.owner();
    let usb_mount = host.mkdtemp("epmaseed_usb_")?;
    let usb_mount_arg = usb_mount.to_string_lossy().into_owned();
    let untouched = AtomicBool::new(false);
    let canceled = AtomicBool::new(false);
    let mounted = Cell::new(false);
    let watch = |line: &str| {
        let text = line.trim();
        if text == SEED_UNTOUCHED_MARKER {
            untouched.store(true, Ordering::SeqCst);
        } else if text == SEED_CANCELED_MARKER {
            canceled.store(true, Ordering::SeqCst);
        } else {
            log(line);
        }
    };

    ctx.log(&format!("Erasing and formatting {dev} as GPT + FAT32 ('{label}') (administrator privileges required)..."));
    let body = || -> Result<()> {
        // Marked BEFORE the script runs: its last command is the mount, and an interrupt (or an error) that arrives
        // right after it must still reach the unmount below. Unmounting a volume that was never mounted is harmless
        // (`umount ... || true`).
        mounted.set(true);
        host.with_cancel_flag(ctx.cancel, &mut |flag| {
            // Every value arrives as a positional parameter ("$1".."$6"), never pasted into the script.
            priv_.run_script(
                LINUX_SEED_PREP_SCRIPT,
                &watch,
                &[
                    dev.clone(),
                    part.clone(),
                    label.to_string(),
                    usb_mount_arg.clone(),
                    owner.clone(),
                    flag.to_string_lossy().into_owned(),
                ],
            )
        })?;
        if untouched.load(Ordering::SeqCst) {
            mounted.set(false); // the script stopped on request before the mount
            ctx.log("Canceled before the drive was touched; nothing was changed.");
            return Err(Error::canceled_with("Canceled by the user before the drive was touched.", false, false));
        }
        if canceled.load(Ordering::SeqCst) {
            mounted.set(false); // stopped between the wipe and the format: nothing is mounted
            return Err(Error::canceled());
        }
        ctx.check_canceled(true, false)?;
        host.copy_seed_files(stage_dir, &usb_mount, files, ctx)?;
        ctx.log("Remounting the drive read-only to read it back from the device...");
        priv_.run_script(LINUX_SEED_REMOUNT_SCRIPT, log, &[part.clone(), usb_mount_arg.clone(), owner.clone()])?;
        host.verify_seed_files(files, &usb_mount, ctx)
    };
    let result = body();
    if let Err(e) = &result {
        if e.is_canceled() {
            if e.written() {
                ctx.log("Canceled during verification. The files were copied completely but NOT verified.");
            } else if e.drive_touched() {
                ctx.log("Canceled. The drive is left incomplete and unusable.");
            }
        }
    }
    // finally:
    if mounted.get() {
        ctx.log("Unmounting...");
        if let Err(cleanup_err) = priv_.run_script(LINUX_SEED_CLEANUP_SCRIPT, log, std::slice::from_ref(&usb_mount_arg))
        {
            ctx.log(&format!("Warning: cleanup failed: {cleanup_err}"));
        }
    }
    host.silent_rmdir(&usb_mount);
    result?;

    let ejected = if do_eject { eject(dev_name, log, priv_) } else { false };
    ctx.log("Done! The seed drive is ready: plug it in next to the installer USB drive.");
    report_eject(ejected, log, !do_eject);
    Ok(ejected)
}

#[cfg(test)]
mod tests;
