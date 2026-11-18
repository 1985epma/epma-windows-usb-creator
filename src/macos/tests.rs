//! Unit tests of the macOS backend (ports of the Python tests listed in the module header of `macos.rs`):
//! tests/test_fixes_gui.py (EnumerationTests), tests/test_refactor_helpers.py (DiskutilHelperTests),
//! tests/test_engine.py (EjectTests, EjectOptionTests), tests/test_fixes_engine.py (RawScriptSigintTests,
//! CancelContract, BackendsCanceledEarly), tests/test_hardening_engine_windows.py (MacosBuildUsbTests, script
//! digests), tests/test_hardening_engine_seed.py (MacSeedBackendTests).

use super::testkit::*;
use super::*;
use crate::constants::{IOREG_TIMEOUT, MAC_DEVICE_RE};
use crate::types::{Error, Volumes};
use indexmap::IndexMap;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------------------------------------------
// plist builders
// ---------------------------------------------------------------------------------------------------------------

fn dict(pairs: Vec<(&str, Value)>) -> Value {
    let mut d = Dictionary::new();
    for (k, v) in pairs {
        d.insert(k.to_string(), v);
    }
    Value::Dictionary(d)
}
fn s(text: &str) -> Value {
    Value::String(text.to_string())
}
fn n(value: u64) -> Value {
    Value::Integer(value.into())
}
fn b(value: bool) -> Value {
    Value::Boolean(value)
}
fn arr(items: Vec<Value>) -> Value {
    Value::Array(items)
}
fn xml(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    v.to_writer_xml(&mut out).expect("plist");
    out
}
fn listing(entries: Vec<Value>) -> Value {
    dict(vec![("AllDisksAndPartitions", arr(entries))])
}
fn usb_info(media: &str) -> Value {
    dict(vec![
        ("Internal", b(false)),
        ("Removable", b(true)),
        ("Ejectable", b(true)),
        ("BusProtocol", s("USB")),
        ("MediaName", s(media)),
    ])
}
fn args_of(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}
fn os_error(what: &str) -> Error {
    Error::Io(std::io::Error::other(what.to_string()))
}

/// A `diskutil`/`ioreg` fake: the external listing, the full listing, ioreg, and `diskutil info` per node.
struct Disks {
    external: Value,
    all: Value,
    ioreg: Value,
    infos: Vec<(String, Value)>,
}

impl Disks {
    fn new(external: Value) -> Disks {
        Disks { external, all: listing(vec![]), ioreg: arr(vec![]), infos: Vec::new() }
    }
    fn info(mut self, node: &str, value: Value) -> Disks {
        self.infos.push((node.to_string(), value));
        self
    }
    fn host(self) -> FakeHost {
        FakeHost::new().with_output(move |args| {
            let a = args_of(args);
            match a.as_slice() {
                ["ioreg", ..] => Ok(xml(&self.ioreg)),
                ["diskutil", "list", rest @ ..] if rest.contains(&"external") => Ok(xml(&self.external)),
                ["diskutil", "list", ..] => Ok(xml(&self.all)),
                ["diskutil", "info", "-plist", target] => {
                    let node = target.trim_start_matches("/dev/");
                    match self.infos.iter().find(|(k, _)| k == node) {
                        Some((_, v)) => Ok(xml(v)),
                        None => Err(os_error(&format!("diskutil info {node} failed"))),
                    }
                }
                _ => panic!("unexpected command {a:?}"),
            }
        })
    }
}

// ---------------------------------------------------------------------------------------------------------------
// diskutil helpers (DiskutilHelperTests)
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn plist_runs_diskutil_with_the_default_query_timeout() {
    let host = FakeHost::new().with_output(|_| Ok(xml(&dict(vec![("Internal", b(false))]))));
    let value = diskutil_plist(&host, &["list", "-plist", "external", "physical"], secs(QUERY_TIMEOUT)).unwrap();
    assert_eq!(value.as_dictionary().and_then(|d| d.get("Internal")).and_then(Value::as_boolean), Some(false));
    diskutil_plist(&host, &["list", "-plist"], secs(7)).unwrap();
    diskutil_info(&host, "disk4s1").unwrap();
    let outs = host.outputs();
    assert_eq!(outs[0].0, ["diskutil", "list", "-plist", "external", "physical"]);
    assert_eq!(outs[0].1, secs(QUERY_TIMEOUT));
    assert_eq!(outs[1].1, secs(7));
    assert_eq!(outs[2].0, ["diskutil", "info", "-plist", "/dev/disk4s1"]);
}

#[test]
fn plist_failures_reach_the_caller() {
    let host = FakeHost::new().with_output(|_| Err(os_error("no diskutil")));
    assert!(matches!(diskutil_plist(&host, &["list", "-plist"], secs(30)), Err(Error::Io(_))));
    let host = FakeHost::new().with_output(|_| Ok(b"not a plist".to_vec()));
    assert!(diskutil_plist(&host, &["list", "-plist"], secs(30)).is_err());
}

#[test]
fn a_disk_whose_info_cannot_be_read_is_hidden() {
    let ext = listing(vec![dict(vec![("DeviceIdentifier", s("disk4")), ("Size", n(8 * GIB))])]);
    let host = Disks::new(ext).host(); // no `info` registered: every info query fails
    assert!(get_external_disks_with(&host).unwrap().is_empty()); // fail closed
    assert!(host.audit_texts().iter().any(|m| m.contains("Hiding disk4: could not verify it is external")));
}

#[test]
fn unmount_builds_the_expected_commands() {
    let host = FakeHost::new();
    let fx = Fx::new();
    unmount_with(&host, "disk4", fx.ctx().log, true, false).unwrap();
    unmount_with(&host, "disk4", fx.ctx().log, false, false).unwrap();
    unmount_with(&host, "disk4", fx.ctx().log, false, true).unwrap();
    let timeout = Some(secs(DISKUTIL_TIMEOUT));
    assert_eq!(DISKUTIL_TIMEOUT, 120);
    let strs = |a: &[&str]| a.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    assert_eq!(
        host.cmds(),
        vec![
            (strs(&["diskutil", "unmountDisk", "/dev/disk4"]), true, timeout),
            (strs(&["diskutil", "unmountDisk", "/dev/disk4"]), false, timeout),
            (strs(&["diskutil", "unmountDisk", "force", "/dev/disk4"]), false, timeout),
        ]
    );
}

// ---------------------------------------------------------------------------------------------------------------
// Listing (EnumerationTests and the describe helpers)
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn macos_listing_has_timeouts_and_skips_zero_size() {
    let ext = listing(vec![
        dict(vec![("DeviceIdentifier", s("disk4")), ("Size", n(0)), ("Partitions", arr(vec![]))]),
        dict(vec![("DeviceIdentifier", s("disk5")), ("Size", n(8 * GIB)), ("Partitions", arr(vec![]))]),
    ]);
    let host = Disks::new(ext).info("disk5", usb_info("Fake Stick")).host();
    let disks = get_external_disks_with(&host).unwrap();
    assert_eq!(disks.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(), ["disk5"]);
    let outs = host.outputs();
    assert!(!outs.is_empty());
    for (args, timeout, _) in &outs {
        assert!(*timeout > Duration::ZERO, "no timeout for {args:?}");
        let limit = if args[0] == "ioreg" { secs(IOREG_TIMEOUT) } else { secs(QUERY_TIMEOUT) };
        assert!(*timeout <= limit, "{args:?}");
    }
    const { assert!(IOREG_TIMEOUT < QUERY_TIMEOUT) };
    // `diskutil info` was never run for the 0-byte drive
    assert!(!outs.iter().any(|(a, _, _)| a[..2] == ["diskutil", "info"] && a.last().unwrap() == "/dev/disk4"));
    assert!(host.audit_texts().iter().any(|m| m == "Hiding disk4: its size is zero or unreadable"));
}

#[test]
fn a_hung_command_hides_the_disk_instead_of_hanging() {
    let ext = listing(vec![dict(vec![("DeviceIdentifier", s("disk5")), ("Size", n(8 * GIB))])]);
    let ext_bytes = xml(&ext);
    let host = FakeHost::new().with_output(move |args| {
        if args[..2] == ["diskutil", "list"] && args.iter().any(|a| a == "external") {
            Ok(ext_bytes.clone())
        } else {
            Err(Error::runtime("Command timed out after 30 seconds."))
        }
    });
    assert!(get_external_disks_with(&host).unwrap().is_empty()); // cannot verify it is external: hidden
}

#[test]
fn only_usb_external_whole_disks_are_listed() {
    let entry = |id: &str| dict(vec![("DeviceIdentifier", s(id)), ("Size", n(4 * GIB)), ("Partitions", arr(vec![]))]);
    let ext = listing(vec![
        entry("disk2"),   // internal
        entry("disk3"),   // neither removable nor ejectable
        entry("disk4"),   // not USB
        entry("disk5"),   // USB, lower case protocol
        entry("disk6s1"), // a partition identifier is not a disk
        entry("sdb"),
        dict(vec![("DeviceIdentifier", s("")), ("Size", n(4 * GIB))]),
        dict(vec![("Size", n(4 * GIB))]),
        s("junk"),
    ]);
    let info = |internal: bool, rem: bool, ej: bool, bus: &str| {
        dict(vec![
            ("Internal", b(internal)),
            ("Removable", b(rem)),
            ("Ejectable", b(ej)),
            ("BusProtocol", s(bus)),
            ("MediaName", s("M")),
        ])
    };
    let host = Disks::new(ext)
        .info("disk2", info(true, true, true, "USB"))
        .info("disk3", info(false, false, false, "USB"))
        .info("disk4", info(false, true, true, "SATA"))
        .info("disk5", info(false, true, false, "usb"))
        .host();
    let disks = get_external_disks_with(&host).unwrap();
    assert_eq!(disks.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(), ["disk5"]);
    // the safety rules never even queried the identifiers that are not whole disks
    assert!(!host.outputs().iter().any(|(a, _, _)| a.iter().any(|x| x == "/dev/disk6s1" || x == "/dev/sdb")));
}

#[test]
fn the_device_pattern_accepts_only_whole_disks() {
    for ok in ["disk0", "disk12"] {
        assert!(MAC_DEVICE_RE.is_match(ok));
    }
    for bad in ["disk", "disk1s1", "rdisk1", "disk1\n", "sdb"] {
        assert!(!MAC_DEVICE_RE.is_match(bad), "{bad:?}");
    }
}

#[test]
fn a_disk_gets_model_identity_and_volumes() {
    let ext = listing(vec![dict(vec![
        ("DeviceIdentifier", s("disk4")),
        ("Size", n(32 * GIB)),
        (
            "Partitions",
            arr(vec![
                dict(vec![
                    ("DeviceIdentifier", s("disk4s1")),
                    ("Content", s("Microsoft Basic Data")),
                    ("VolumeName", s("STICK")),
                    ("Size", n(GIB)),
                    ("MountPoint", s("/Volumes/STICK")),
                ]),
                dict(vec![("DeviceIdentifier", s("disk4s2")), ("Content", s("Apple_APFS")), ("Size", n(5 * GIB))]),
                dict(vec![("DeviceIdentifier", s("disk4s3")), ("Content", s("Apple_HFS")), ("Size", n(7))]),
            ]),
        ),
    ])]);
    let all = listing(vec![dict(vec![
        ("DeviceIdentifier", s("disk5")),
        ("Size", n(5 * GIB)),
        ("APFSPhysicalStores", arr(vec![dict(vec![("DeviceIdentifier", s("disk4s2"))])])),
        (
            "APFSVolumes",
            arr(vec![
                dict(vec![("VolumeName", s("Data")), ("CapacityInUse", n(123)), ("MountPoint", s("/Volumes/Data"))]),
                dict(vec![("VolumeName", s(""))]),
            ]),
        ),
    ])]);
    let usb = dict(vec![
        ("IOObjectClass", s("IOUSBHostDevice")),
        ("USB Vendor Name", s("SanDisk")),
        ("USB Product Name", s("Ultra Fit")),
        ("kUSBSerialNumberString", s("SER123")),
        (
            "IORegistryEntryChildren",
            arr(vec![dict(vec![
                ("BSD Name", s("disk4")),
                ("IORegistryEntryChildren", arr(vec![dict(vec![("BSD Name", s("disk4s1"))])])),
            ])]),
        ),
    ]);
    let mut disks_fake = Disks::new(ext)
        .info("disk4", {
            let mut d = usb_info("Ultra");
            if let Value::Dictionary(m) = &mut d {
                m.insert("DiskUUID".into(), s("UUID-1"));
            }
            d
        })
        .info(
            "disk4s1",
            dict(vec![("FilesystemUserVisibleName", s("MS-DOS FAT32")), ("MountPoint", s("/Volumes/STICK"))]),
        )
        .info("disk4s3", dict(vec![("FilesystemName", s("hfs"))]));
    disks_fake.all = all;
    disks_fake.ioreg = arr(vec![usb]);
    let mut host = disks_fake.host();
    host.used = vec![("/Volumes/STICK".to_string(), 1234)];
    let disks = get_external_disks_with(&host).unwrap();
    assert_eq!(disks.len(), 1);
    let d = &disks[0];
    assert_eq!((d.id.as_str(), d.size), ("disk4", 32 * GIB));
    assert_eq!(d.model.as_deref(), Some("SanDisk Ultra"));
    assert_eq!(
        d.identity,
        vec![
            ("diskuuid".to_string(), "UUID-1".to_string()),
            ("model".to_string(), "Ultra".to_string()),
            ("serial".to_string(), "SER123".to_string()),
        ]
    );
    let Volumes::List(vols) = &d.volumes else { panic!("volumes were not read: {:?}", d.volumes) };
    assert_eq!(
        vols,
        &vec![
            Volume {
                name: Some("STICK".into()),
                filesystem: Some("MS-DOS FAT32".into()),
                size: Some(GIB),
                used: Some(1234),
                mountpoint: Some("/Volumes/STICK".into()),
            },
            // the APFS container is replaced by its volumes
            Volume {
                name: Some("Data".into()),
                filesystem: Some("APFS".into()),
                size: Some(5 * GIB),
                used: Some(123),
                mountpoint: Some("/Volumes/Data".into()),
            },
            Volume {
                name: Some("".into()),
                filesystem: Some("APFS".into()),
                size: Some(5 * GIB),
                used: None,
                mountpoint: None,
            },
            // an unmounted partition: nothing is known about its use; the filesystem name comes from `info`
            Volume {
                name: Some("".into()),
                filesystem: Some("hfs".into()),
                size: Some(7),
                used: None,
                mountpoint: None
            },
        ]
    );
}

#[test]
fn the_vendor_is_not_repeated_when_the_media_name_has_it() {
    let host = Disks::new(listing(vec![dict(vec![("DeviceIdentifier", s("disk4")), ("Size", n(GIB))])]))
        .info("disk4", usb_info("SANDISK Ultra"))
        .host();
    let entry = dict(vec![("DeviceIdentifier", s("disk4"))]);
    let usb_map = HashMap::from([(
        "disk4".to_string(),
        UsbDevice { serial: "S".into(), vendor: "SanDisk".into(), product: "P".into() },
    )]);
    let info = diskutil_info(&host, "disk4").unwrap();
    let (model, volumes, identity) =
        describe_disk(&host, entry.as_dictionary().unwrap(), &info, &usb_map, &HashMap::new());
    assert_eq!(model, "SANDISK Ultra");
    assert_eq!(volumes, Some(vec![])); // no partitions at all
    assert_eq!(
        identity,
        vec![("model".to_string(), "SANDISK Ultra".to_string()), ("serial".to_string(), "S".to_string())]
    );
}

#[test]
fn without_a_media_name_the_usb_product_is_the_model() {
    let host = FakeHost::new();
    let entry = dict(vec![("DeviceIdentifier", s("disk4"))]);
    let usb_map = HashMap::from([(
        "disk4".to_string(),
        UsbDevice { serial: "".into(), vendor: " Kingston ".into(), product: " DT 100 ".into() },
    )]);
    let info = dict(vec![("MediaName", s("  "))]);
    let (model, _, identity) =
        describe_disk(&host, entry.as_dictionary().unwrap(), info.as_dictionary().unwrap(), &usb_map, &HashMap::new());
    assert_eq!(model, "Kingston DT 100");
    assert_eq!(identity, vec![("model".to_string(), " DT 100 ".trim().to_string())]);
}

#[test]
fn volumes_are_unknown_when_a_partition_cannot_be_inspected() {
    let ext = listing(vec![dict(vec![
        ("DeviceIdentifier", s("disk4")),
        ("Size", n(GIB)),
        (
            "Partitions",
            arr(vec![dict(vec![("DeviceIdentifier", s("disk4s1")), ("Content", s("Microsoft Basic Data"))])]),
        ),
    ])]);
    let host = Disks::new(ext).info("disk4", usb_info("Stick")).host(); // no info for disk4s1
    let disks = get_external_disks_with(&host).unwrap();
    assert_eq!(disks.len(), 1, "a disk whose volumes cannot be read is still listed");
    assert_eq!(disks[0].volumes, Volumes::Unknown);
    assert!(host.audit_texts().iter().any(|m| m == "Could not inspect the volumes of disk4 (OSError)"));
}

#[test]
fn a_failed_ioreg_only_loses_the_serial() {
    let ext = listing(vec![dict(vec![("DeviceIdentifier", s("disk4")), ("Size", n(GIB))])]);
    let ext_bytes = xml(&ext);
    let info_bytes = xml(&usb_info("Stick"));
    let all_bytes = xml(&listing(vec![]));
    let host = FakeHost::new().with_output(move |args| match args[0].as_str() {
        "ioreg" => Ok(b"garbage".to_vec()),
        _ if args.iter().any(|a| a == "external") => Ok(ext_bytes.clone()),
        _ if args[1] == "info" => Ok(info_bytes.clone()),
        _ => Ok(all_bytes.clone()),
    });
    let disks = get_external_disks_with(&host).unwrap();
    assert_eq!(disks.len(), 1);
    assert!(host.audit_texts().iter().any(|m| m == "USB serial lookup unavailable (RuntimeError)"));
}

#[test]
fn the_ioreg_tree_maps_bsd_names_to_the_nearest_usb_device() {
    let media = |bsd: &str| dict(vec![("BSD Name", s(bsd)), ("IOObjectClass", s("IOMedia"))]);
    let device = dict(vec![
        ("IOObjectClass", s("IOUSBHostDevice")),
        ("USB Serial Number", s("S1")),
        ("USB Vendor Name", s("V")),
        ("USB Product Name", s("P")),
        ("IORegistryEntryChildren", arr(vec![media("disk4"), media("disk4s1")])),
    ]);
    let hub = dict(vec![
        ("IOObjectClass", s("IOUSBHostDevice")),
        ("kUSBSerialNumberString", s("HUB")),
        ("IORegistryEntryChildren", arr(vec![device, media("disk9")])),
    ]);
    let map = parse_usb_device_map(&xml(&arr(vec![hub, s("junk"), media("disk7")]))).unwrap();
    assert_eq!(map["disk4"], UsbDevice { serial: "S1".into(), vendor: "V".into(), product: "P".into() });
    assert_eq!(map["disk4s1"].serial, "S1");
    assert_eq!(map["disk9"].serial, "HUB"); // carried by the hub, not by the device below it
    assert!(!map.contains_key("disk7")); // not under any USB device
    assert!(parse_usb_device_map(b"nope").is_err());
}

#[test]
fn apfs_volumes_are_indexed_by_the_partition_that_holds_the_container() {
    let all = listing(vec![
        dict(vec![("DeviceIdentifier", s("disk0")), ("Size", n(1))]),
        dict(vec![
            ("DeviceIdentifier", s("disk5")),
            ("Size", n(10)),
            ("APFSPhysicalStores", arr(vec![dict(vec![("DeviceIdentifier", s("disk4s2"))])])),
            ("APFSVolumes", arr(vec![dict(vec![("VolumeName", s("V")), ("CapacityInUse", n(3))])])),
        ]),
    ]);
    let map = parse_apfs_volumes_by_store(&all);
    assert_eq!(map.len(), 1);
    assert_eq!(
        map["disk4s2"],
        vec![Volume {
            name: Some("V".into()),
            filesystem: Some("APFS".into()),
            size: Some(10),
            used: Some(3),
            mountpoint: None
        }]
    );
    let host = FakeHost::new().with_output(|_| Err(os_error("boom")));
    assert!(apfs_volumes_by_store(&host).is_empty());
}

// ---------------------------------------------------------------------------------------------------------------
// find_mountpoint_by_volname
// ---------------------------------------------------------------------------------------------------------------

/// `diskutil list /dev/disk9` shows a volume called `label` once `appears_at` queries have been made.
fn mount_host(label: &str, mountpoint: Option<&str>, appears_at: usize) -> FakeHost {
    let label = label.to_string();
    let mp = mountpoint.map(str::to_string);
    let seen = AtomicUsize::new(0);
    FakeHost::new().with_output(move |args| match args[1].as_str() {
        "list" => {
            let count = seen.fetch_add(1, Ordering::SeqCst) + 1;
            let parts = if count >= appears_at {
                vec![dict(vec![("DeviceIdentifier", s("disk9s1")), ("VolumeName", s(&label))])]
            } else {
                vec![dict(vec![("DeviceIdentifier", s("disk9s2")), ("VolumeName", s("OTHER"))])]
            };
            Ok(xml(&listing(vec![dict(vec![("DeviceIdentifier", s("disk9")), ("Partitions", arr(parts))])])))
        }
        "info" => {
            let mut info = Dictionary::new();
            if let Some(mp) = &mp {
                info.insert("MountPoint".into(), s(mp));
            }
            Ok(xml(&Value::Dictionary(info)))
        }
        other => panic!("unexpected diskutil {other}"),
    })
}
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn the_mountpoint_is_found_ignoring_case() {
    let host = mount_host("win11usb", Some("/Volumes/WIN11USB"), 1);
    assert_eq!(find_mountpoint_by_volname_with(&host, "disk9", "WIN11USB", 15).unwrap(), "/Volumes/WIN11USB");
    assert_eq!(host.sleeps(), 0);
    assert_eq!(host.outputs()[0].0, ["diskutil", "list", "-plist", "/dev/disk9"]);
}

#[test]
fn the_mountpoint_is_waited_for() {
    let host = mount_host("WIN11USB", Some("/Volumes/WIN11USB"), 3);
    assert_eq!(find_mountpoint_by_volname_with(&host, "disk9", "WIN11USB", 15).unwrap(), "/Volumes/WIN11USB");
    assert_eq!(host.sleeps(), 2);
}

#[test]
fn a_volume_that_never_mounts_is_an_error() {
    let host = mount_host("WIN11USB", None, 1);
    let err = find_mountpoint_by_volname_with(&host, "disk9", "WIN11USB", 3).unwrap_err();
    assert_eq!(err.to_string(), "Could not find the USB drive's mount point after formatting.");
    assert_eq!(host.sleeps(), 3);
    let host = FakeHost::new().with_output(|_| Err(os_error("diskutil hung")));
    assert!(matches!(find_mountpoint_by_volname_with(&host, "disk9", "X", 3), Err(Error::Io(_))));
}

// ---------------------------------------------------------------------------------------------------------------
// eject and report_eject (EjectTests, EjectOptionTests)
// ---------------------------------------------------------------------------------------------------------------

fn eject_results(results: &'static [i32]) -> (bool, Vec<(Vec<String>, bool)>) {
    let n = Arc::new(AtomicUsize::new(0));
    let host = FakeHost::new().with_cmd(move |_| Ok(results[n.fetch_add(1, Ordering::SeqCst)]));
    let fx = Fx::new();
    let ok = eject_with(&host, "disk4", fx.ctx().log);
    (ok, host.cmds().into_iter().map(|(a, c, _)| (a, c)).collect())
}

#[test]
fn a_clean_eject() {
    let (ok, calls) = eject_results(&[0]);
    assert!(ok);
    assert_eq!(calls, vec![(vec!["diskutil".to_string(), "eject".into(), "/dev/disk4".into()], false)]);
}

#[test]
fn a_busy_drive_is_force_unmounted_then_ejected() {
    let (ok, calls) = eject_results(&[1, 0, 0]);
    assert!(ok);
    let expect: Vec<Vec<&str>> = vec![
        vec!["diskutil", "eject", "/dev/disk4"],
        vec!["diskutil", "unmountDisk", "force", "/dev/disk4"],
        vec!["diskutil", "eject", "/dev/disk4"],
    ];
    assert_eq!(calls.iter().map(|(a, _)| args_of(a)).collect::<Vec<_>>(), expect);
    assert!(calls.iter().all(|(_, check)| !check));
}

#[test]
fn an_eject_that_keeps_failing_returns_false() {
    let (ok, calls) = eject_results(&[1, 0, 1]);
    assert!(!ok);
    assert_eq!(calls.len(), 3);
}

#[test]
fn eject_sleeps_a_second_between_the_attempts() {
    let host = FakeHost::new().with_cmd(|_| Ok(1));
    eject_with(&host, "disk4", &quiet);
    assert_eq!(host.calls().iter().filter(|c| matches!(c, Call::Sleep(s) if *s == 1.0)).count(), 1);
}

#[test]
fn report_eject_messages() {
    let fx = Fx::new();
    report_eject(true, fx.ctx().log, false);
    report_eject(false, fx.ctx().log, false);
    report_eject(false, fx.ctx().log, true);
    let lines = fx.lines();
    assert!(lines[0].contains("unplug") && lines[0].to_lowercase().contains("ejected"));
    assert!(lines[1].contains("Could not eject"));
    assert!(lines[2].contains("left connected"));
    assert!(!lines[2].to_lowercase().contains("could not eject"));
}

// ---------------------------------------------------------------------------------------------------------------
// build_usb
// ---------------------------------------------------------------------------------------------------------------

/// A host that mounts the volume called `label` at `mountpoint` and runs every command successfully.
fn build_host(label: &str, mountpoint: &Path) -> FakeHost {
    mount_host(label, Some(&mountpoint.to_string_lossy()), 1)
}

fn files_of(pairs: &[(&str, &[u8])]) -> Files {
    let mut files: Files = IndexMap::new();
    for (k, v) in pairs {
        files.insert(k.to_string(), v.to_vec());
    }
    files
}

fn strs(a: &[&str]) -> Vec<String> {
    a.iter().map(|x| x.to_string()).collect()
}

#[test]
fn build_usb_runs_every_step_in_order() {
    let scratch = tempfile::tempdir().unwrap();
    let usb = scratch.path().join("Volumes").join("WIN11USB");
    std::fs::create_dir_all(&usb).unwrap();
    let remounted = Arc::new(Mutex::new(None));
    let r = Arc::clone(&remounted);
    let host = build_host("WIN11USB", &usb).with_payload(move |_, _, _, reopen, _| {
        *r.lock().unwrap() = Some(reopen.expect("a reopen callback")()?);
        Ok(())
    });
    let fx = Fx::new();
    let ejected = build_usb_with(&host, Path::new("/x/Win11.iso"), "disk9", &fx.ctx(), true, None).unwrap();
    assert!(ejected);
    let cmds = host.cmds();
    let mnt = host.calls().iter().find_map(|c| if let Call::Rmdir(p) = c { Some(p.clone()) } else { None }).unwrap();
    assert!(mnt.file_name().unwrap().to_string_lossy().starts_with("win11iso_"));
    let mnt = mnt.to_string_lossy().into_owned();
    assert_eq!(
        cmds.iter().map(|(a, c, t)| (a.clone(), *c, *t)).collect::<Vec<_>>(),
        vec![
            (strs(&["diskutil", "eraseDisk", "FAT32", "WIN11USB", "GPT", "/dev/disk9"]), true, Some(secs(600))),
            (
                strs(&["hdiutil", "attach", "/x/Win11.iso", "-nobrowse", "-readonly", "-mountpoint", &mnt]),
                true,
                Some(secs(300))
            ),
            (strs(&["diskutil", "unmountDisk", "/dev/disk9"]), true, Some(secs(120))),
            (strs(&["diskutil", "mountDisk", "/dev/disk9"]), true, Some(secs(120))),
            (strs(&["hdiutil", "detach", &mnt, "-force"]), false, Some(secs(120))),
            (strs(&["diskutil", "eject", "/dev/disk9"]), false, Some(secs(120))),
        ]
    );
    assert_eq!(remounted.lock().unwrap().as_deref(), Some(usb.as_path()));
    let payload = host.calls().into_iter().find_map(|c| if let Call::Payload { .. } = &c { Some(c) } else { None });
    let Some(Call::Payload { src, dst, hint, reopen, extra }) = payload else { panic!("no payload call") };
    assert_eq!((src.to_string_lossy().into_owned(), dst), (mnt.clone(), usb.clone()));
    assert!(hint.contains("brew install wimlib") && reopen && extra.is_none());
    // the log tells the story in order
    let text = fx.text();
    let order = [
        "Erasing and formatting /dev/disk9 as GPT + FAT32 ('WIN11USB')...",
        "USB drive ready at: ",
        "Mounting the ISO at ",
        "Remounting the drive to read it back from the device...",
        "Unmounting the ISO...",
        "Ejecting the USB drive...",
        "Done! The USB drive is ready to install Windows 11.",
        "Drive ejected — you can unplug it now.",
    ];
    let mut at = 0;
    for needle in order {
        let found = text[at..].find(needle).unwrap_or_else(|| panic!("{needle:?} missing or out of order in:\n{text}"));
        at += found;
    }
}

#[test]
fn a_cancel_before_the_backend_starts_touches_nothing() {
    let host = FakeHost::new();
    let fx = Fx::new();
    fx.cancel.set();
    let err = build_usb_with(&host, Path::new("/x/Win11.iso"), "disk9", &fx.ctx(), true, None).unwrap_err();
    assert!(matches!(err, Error::Canceled { drive_touched: false, .. }));
    assert!(host.calls().is_empty());
}

#[test]
fn a_cancel_while_copying_unmounts_and_does_not_eject() {
    let usb = tempfile::tempdir().unwrap();
    let host = build_host("WIN11USB", usb.path()).with_payload(|_, _, _, _, _| Err(Error::canceled()));
    let fx = Fx::new();
    let err = build_usb_with(&host, Path::new("/x/Win11.iso"), "disk9", &fx.ctx(), true, None).unwrap_err();
    assert!(err.drive_touched() && !err.written());
    let cmds = host.cmd_args();
    assert!(fx.has("Canceled. Unmounting the drive; it is left incomplete and unusable."));
    // attach, then the unmount that leaves the drive alone, then the ISO is detached; never an eject
    let i = cmds.iter().position(|c| c[..2] == ["diskutil", "unmountDisk"]).expect("unmounted");
    assert!(!host.cmds()[i].1);
    assert!(cmds.iter().position(|c| c[..2] == ["hdiutil", "detach"]).unwrap() > i);
    assert!(!cmds.iter().any(|c| c[..2] == ["diskutil", "eject"]));
}

#[test]
fn a_cancel_during_verification_says_the_files_were_not_verified() {
    let usb = tempfile::tempdir().unwrap();
    let host = build_host("WIN11USB", usb.path())
        .with_payload(|_, _, _, _, _| Err(Error::canceled_with("Canceled by the user.", true, true)));
    let fx = Fx::new();
    let err = build_usb_with(&host, Path::new("/x/Win11.iso"), "disk9", &fx.ctx(), true, None).unwrap_err();
    assert!(err.written());
    assert!(fx
        .has("Canceled during verification. Unmounting the drive; the files were copied completely but NOT verified."));
}

#[test]
fn a_write_error_does_not_eject_and_still_detaches_the_iso() {
    let usb = tempfile::tempdir().unwrap();
    let host = build_host("WIN11USB", usb.path()).with_payload(|_, _, _, _, _| Err(os_error("disk full")));
    let fx = Fx::new();
    let err = build_usb_with(&host, Path::new("/x/Win11.iso"), "disk9", &fx.ctx(), true, None).unwrap_err();
    assert!(matches!(err, Error::Io(_)));
    let cmds = host.cmd_args();
    assert!(!cmds.iter().any(|c| c[..2] == ["diskutil", "eject"]));
    assert!(!cmds.iter().any(|c| c[..2] == ["diskutil", "unmountDisk"])); // only a cancel unmounts
    assert!(cmds.iter().any(|c| c[..2] == ["hdiutil", "detach"]));
    assert!(host.calls().iter().any(|c| matches!(c, Call::Rmdir(_))));
}

#[test]
fn a_failed_attach_removes_the_mount_directory_and_stops() {
    let usb = tempfile::tempdir().unwrap();
    let inner = build_host("WIN11USB", usb.path());
    let host = FakeHost {
        cmd: Box::new(
            |args| if args[0] == "hdiutil" { Err(Error::runtime("Command failed (exit code 1)")) } else { Ok(0) },
        ),
        ..inner
    };
    let fx = Fx::new();
    let err = build_usb_with(&host, Path::new("/x/Win11.iso"), "disk9", &fx.ctx(), true, None).unwrap_err();
    assert!(err.to_string().contains("Command failed"));
    assert!(!host.calls().iter().any(|c| matches!(c, Call::Payload { .. })));
    assert!(host.calls().iter().any(|c| matches!(c, Call::Rmdir(_))));
    assert!(!host.cmd_args().iter().any(|c| c[..2] == ["hdiutil", "detach"]));
}

#[test]
fn hardening_files_are_handed_to_the_copy_and_an_empty_set_is_not() {
    let usb = tempfile::tempdir().unwrap();
    let host = build_host("WIN11USB", usb.path());
    let files = files_of(&[
        ("answer-standin.xml", b"<x/>"),
        ("sources/$OEM$/$$/Setup/Scripts/SetupComplete.cmd", b"@echo off\r\n"),
    ]);
    let fx = Fx::new();
    build_usb_with(&host, Path::new("/x/Win11.iso"), "disk9", &fx.ctx(), true, Some(&files)).unwrap();
    let extra =
        host.calls().into_iter().find_map(|c| if let Call::Payload { extra, .. } = c { Some(extra) } else { None });
    assert_eq!(
        extra,
        Some(Some(vec![
            "answer-standin.xml".to_string(),
            "sources/$OEM$/$$/Setup/Scripts/SetupComplete.cmd".to_string()
        ]))
    );
    let host = build_host("WIN11USB", usb.path());
    build_usb_with(&host, Path::new("/x/Win11.iso"), "disk9", &fx.ctx(), true, Some(&IndexMap::new())).unwrap();
    let extra =
        host.calls().into_iter().find_map(|c| if let Call::Payload { extra, .. } = c { Some(extra) } else { None });
    assert_eq!(extra, Some(None));
}

#[test]
fn no_eject_leaves_the_drive_connected_and_a_failed_eject_is_reported() {
    let usb = tempfile::tempdir().unwrap();
    let host = build_host("WIN11USB", usb.path());
    let fx = Fx::new();
    assert!(!build_usb_with(&host, Path::new("/x/Win11.iso"), "disk9", &fx.ctx(), false, None).unwrap());
    assert!(!host.cmd_args().iter().any(|c| c[..2] == ["diskutil", "eject"]));
    assert!(fx.has("left connected"));

    let inner = build_host("WIN11USB", usb.path());
    let host = FakeHost {
        cmd: Box::new(|a| Ok(i32::from(a[..2] == ["diskutil", "eject"] || a[..2] == ["diskutil", "unmountDisk"]))),
        ..inner
    };
    let fx = Fx::new();
    assert!(!build_usb_with(&host, Path::new("/x/Win11.iso"), "disk9", &fx.ctx(), true, None).unwrap());
    assert!(fx.has("Could not eject automatically"));
}

// ---------------------------------------------------------------------------------------------------------------
// write_raw
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn write_raw_unmounts_writes_verifies_and_ejects() {
    let dir = tempfile::tempdir().unwrap();
    let iso = make_image(dir.path(), "ubuntu.iso", 2 * 1024 * 1024);
    let host = FakeHost::new();
    let priv_ = RecPriv::new();
    let fx = Fx::new();
    assert!(write_raw_with(&host, &iso, "disk9", &fx.ctx(), &priv_, true).unwrap());
    // Unmount (checked), then the root script with the raw node and BSD's block size, then the eject.
    assert_eq!(host.cmd_args()[0], ["diskutil", "unmountDisk", "/dev/disk9"]);
    assert!(host.cmds()[0].1);
    let scripts = priv_.recorded();
    assert_eq!(scripts.len(), 1);
    assert_eq!(scripts[0].0, MACOS_RAW_SCRIPT);
    let args = &scripts[0].1;
    assert_eq!(&args[..3], [iso.to_string_lossy().into_owned(), "/dev/rdisk9".to_string(), "4m".to_string()]);
    assert_eq!(args.len(), 4, "the cancel flag is the fourth value");
    assert!(host.calls().iter().any(|c| matches!(c, Call::Hybrid(p) if p == &iso)));
    assert!(host.calls().contains(&Call::VerifyRaw { device: "/dev/rdisk9".to_string() }));
    assert!(fx.progress_texts().contains(&"Written".to_string()));
    assert!(fx.has("Unmounting /dev/disk9..."));
    assert!(fx.has("Writing the ISO to /dev/disk9 (administrator privileges required). This can take several minutes."));
    assert!(fx.has("macOS cannot read Linux or ChromeOS (ISO 9660/ext) images"));
    assert!(fx.has("click Ignore, never Initialize"));
    assert!(host.cmd_args().last().unwrap()[..2] == ["diskutil", "eject"]);
    assert!(fx.has("Done! The USB drive is ready to boot."));
    assert!(fx.has("Drive ejected"));
}

#[test]
fn write_raw_forwards_the_dd_progress_lines() {
    let dir = tempfile::tempdir().unwrap();
    let iso = make_image(dir.path(), "ubuntu.iso", 4096);
    let priv_ = RecPriv::with(|_, _, _, log| {
        log("1048576 bytes transferred in 0.1 secs");
        Ok(())
    });
    let fx = Fx::new();
    write_raw_with(&FakeHost::new(), &iso, "disk9", &fx.ctx(), &priv_, false).unwrap();
    assert!(fx.has("1048576 bytes transferred"));
}

#[test]
fn a_stop_request_unmounts_and_is_a_cancel() {
    let dir = tempfile::tempdir().unwrap();
    let iso = make_image(dir.path(), "ubuntu.iso", 4096);
    let priv_ = RecPriv::with(|_, _, _, log| {
        log("WRITE_CANCELED");
        Ok(())
    });
    let host = FakeHost::new();
    let fx = Fx::new();
    let err = write_raw_with(&host, &iso, "disk9", &fx.ctx(), &priv_, true).unwrap_err();
    assert!(err.is_canceled() && err.drive_touched() && !err.written());
    assert_eq!(err.to_string(), "Canceled by the user.");
    assert!(fx.has("The write was stopped at your request."));
    assert!(fx.has("Canceled. The drive holds a partial image and is unusable until written again."));
    assert!(!fx.has("WRITE_CANCELED"), "the marker is not echoed to the log");
    let cmds = host.cmds();
    assert_eq!(cmds.last().unwrap().0, ["diskutil", "unmountDisk", "/dev/disk9"]);
    assert!(!cmds.last().unwrap().1, "the unmount after a cancel is best effort");
    assert!(!host.calls().iter().any(|c| matches!(c, Call::VerifyRaw { .. })));
    assert!(!host.cmd_args().iter().any(|c| c[..2] == ["diskutil", "eject"]));
}

#[test]
fn write_raw_cancelled_before_it_starts_does_not_touch_the_drive() {
    let dir = tempfile::tempdir().unwrap();
    let iso = make_image(dir.path(), "ubuntu.iso", 4096);
    let host = FakeHost::new();
    let priv_ = RecPriv::new();
    let fx = Fx::new();
    fx.cancel.set();
    let err = write_raw_with(&host, &iso, "disk9", &fx.ctx(), &priv_, true).unwrap_err();
    assert!(matches!(err, Error::Canceled { drive_touched: false, .. }));
    assert!(host.cmds().is_empty());
    assert_eq!(priv_.count(), 0);
}

#[test]
fn write_raw_cancelled_after_the_unmount_still_leaves_the_drive_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let iso = make_image(dir.path(), "ubuntu.iso", 4096);
    let fx = Fx::new();
    let cancel = fx.cancel.clone();
    let host = FakeHost::new().with_cmd(move |_| {
        cancel.set(); // the user clicks Cancel while the disk is being unmounted
        Ok(0)
    });
    let priv_ = RecPriv::new();
    let err = write_raw_with(&host, &iso, "disk9", &fx.ctx(), &priv_, true).unwrap_err();
    assert!(matches!(err, Error::Canceled { drive_touched: false, .. })); // unmounting changes no data
    assert_eq!(priv_.count(), 0);
}

#[test]
fn write_raw_refuses_a_non_hybrid_image_first() {
    let mut host = FakeHost::new();
    host.hybrid_ok = false;
    let priv_ = RecPriv::new();
    let fx = Fx::new();
    let err = write_raw_with(&host, Path::new("/x/windows.iso"), "disk9", &fx.ctx(), &priv_, true).unwrap_err();
    assert!(matches!(err, Error::Value(_)));
    assert!(host.cmds().is_empty() && priv_.count() == 0);
}

#[test]
fn a_failed_verification_blocks_the_eject() {
    let dir = tempfile::tempdir().unwrap();
    let iso = make_image(dir.path(), "ubuntu.iso", 4096);
    let mut host = FakeHost::new();
    host.verify_raw = Box::new(|_, _| Err(Error::runtime("Verification FAILED: the drive differs")));
    let fx = Fx::new();
    let err = write_raw_with(&host, &iso, "disk9", &fx.ctx(), &RecPriv::new(), true).unwrap_err();
    assert!(err.to_string().contains("Verification FAILED"));
    assert!(!host.cmd_args().iter().any(|c| c[..2] == ["diskutil", "eject"]));
}

// ---------------------------------------------------------------------------------------------------------------
// The seed drive (MacSeedBackendTests)
// ---------------------------------------------------------------------------------------------------------------

const LABEL: &str = "EPMA-SEED";

struct Seed {
    host: FakeHost,
    mount: PathBuf,
    files: Files,
    _dir: tempfile::TempDir,
}

fn seed_fixture() -> Seed {
    let dir = tempfile::tempdir().unwrap();
    let mount = dir.path().join("Volumes").join(LABEL);
    std::fs::create_dir_all(&mount).unwrap();
    let mut host = mount_host(LABEL, Some(&mount.to_string_lossy()), 1);
    host.copy_seed = Box::new(|dst, files, _| write_files(dst, files));
    host.verify_seed = Box::new(|dst, files, _| compare_files(dst, files));
    Seed { host, mount, files: files_of(&[("ks.cfg", b"# kickstart\n"), ("README.txt", b"read me\n")]), _dir: dir }
}

#[test]
fn the_seed_success_sequence() {
    let seed = seed_fixture();
    let fx = Fx::new();
    let stage = Path::new("/stage");
    assert!(build_seed_usb_with(&seed.host, LABEL, &seed.files, stage, "disk9", &fx.ctx(), true).unwrap());
    let cmds = seed.host.cmd_args();
    assert_eq!(cmds[0], ["diskutil", "eraseDisk", "FAT32", LABEL, "GPT", "/dev/disk9"]);
    assert_eq!(seed.host.cmds()[0].2, Some(secs(600)));
    assert_eq!(cmds[1], ["diskutil", "unmountDisk", "/dev/disk9"]);
    assert!(seed.host.cmds()[1].1);
    assert_eq!(cmds[2], ["diskutil", "mountDisk", "/dev/disk9"]);
    assert_eq!(cmds.last().unwrap(), &["diskutil", "eject", "/dev/disk9"]);
    for (rel, data) in &seed.files {
        assert_eq!(&std::fs::read(seed.mount.join(rel)).unwrap(), data);
    }
    assert!(fx.has("Erasing and formatting /dev/disk9 as GPT + FAT32 ('EPMA-SEED')..."));
    assert!(fx.has("Done! The seed drive is ready: plug it in next to the installer USB drive."));
    // the volume is looked up by the seed label, not by WIN11USB
    assert!(seed.host.outputs().iter().all(|(a, _, _)| !a.iter().any(|x| x.contains("WIN11USB"))));
}

#[test]
fn the_label_is_a_single_argument_never_joined_into_text() {
    let seed = seed_fixture();
    let fx = Fx::new();
    build_seed_usb_with(&seed.host, LABEL, &seed.files, Path::new("/stage"), "disk9", &fx.ctx(), true).unwrap();
    let erase = &seed.host.cmd_args()[0];
    assert_eq!(erase.iter().filter(|a| a.contains(LABEL)).count(), 1);
}

#[test]
fn a_verification_mismatch_does_not_eject() {
    let mut seed = seed_fixture();
    let mount = seed.mount.clone();
    // the remount (mountDisk) is when the drive "changes under us"
    let host = std::mem::take(&mut seed.host);
    let inner_cmd = host.cmd;
    let host = FakeHost {
        cmd: Box::new(move |args| {
            if args[1] == "mountDisk" {
                std::fs::write(mount.join("ks.cfg"), b"# tampered\n").unwrap();
            }
            inner_cmd(args)
        }),
        ..host
    };
    let fx = Fx::new();
    let err =
        build_seed_usb_with(&host, LABEL, &seed.files, Path::new("/stage"), "disk9", &fx.ctx(), true).unwrap_err();
    assert!(err.to_string().contains("Verification FAILED") && err.to_string().contains("ks.cfg"));
    assert!(!host.cmd_args().iter().any(|c| c[1] == "eject"));
}

#[test]
fn a_seed_cancel_before_the_erase_runs_nothing() {
    let seed = seed_fixture();
    let fx = Fx::new();
    fx.cancel.set();
    let err =
        build_seed_usb_with(&seed.host, LABEL, &seed.files, Path::new("/stage"), "disk9", &fx.ctx(), true).unwrap_err();
    assert!(matches!(err, Error::Canceled { drive_touched: false, .. }));
    assert!(seed.host.calls().is_empty());
}

#[test]
fn a_seed_cancel_while_copying_unmounts_and_does_not_eject() {
    let mut seed = seed_fixture();
    let fx = Fx::new();
    let cancel = fx.cancel.clone();
    seed.host.copy_seed = Box::new(move |_, _, _| {
        cancel.set();
        Err(Error::canceled()) // what copy_seed_files does when it sees the flag
    });
    let err =
        build_seed_usb_with(&seed.host, LABEL, &seed.files, Path::new("/stage"), "disk9", &fx.ctx(), true).unwrap_err();
    assert!(err.drive_touched() && !err.written());
    let cmds = seed.host.cmds();
    assert_eq!(cmds.last().unwrap().0, ["diskutil", "unmountDisk", "/dev/disk9"]);
    assert!(!cmds.last().unwrap().1);
    assert!(!cmds.iter().any(|(a, _, _)| a[1] == "eject"));
    assert!(fx.has("Canceled. Unmounting the drive; it is left incomplete and unusable."));
}

#[test]
fn a_seed_cancel_during_verification_is_marked_written() {
    let mut seed = seed_fixture();
    seed.host.verify_seed = Box::new(|_, _, _| Err(Error::canceled_with("Canceled by the user.", true, true)));
    let fx = Fx::new();
    let err =
        build_seed_usb_with(&seed.host, LABEL, &seed.files, Path::new("/stage"), "disk9", &fx.ctx(), true).unwrap_err();
    assert!(err.written());
    assert!(fx
        .has("Canceled during verification. Unmounting the drive; the files were copied completely but NOT verified."));
    assert!(!seed.host.cmd_args().iter().any(|c| c[1] == "eject"));
}

#[test]
fn the_seed_drive_can_be_left_connected_and_an_eject_failure_is_reported() {
    let seed = seed_fixture();
    let fx = Fx::new();
    assert!(
        !build_seed_usb_with(&seed.host, LABEL, &seed.files, Path::new("/stage"), "disk9", &fx.ctx(), false).unwrap()
    );
    assert!(!seed.host.cmd_args().iter().any(|c| c[1] == "eject"));
    assert!(fx.has("left connected"));

    let seed = seed_fixture();
    let host = FakeHost {
        cmd: Box::new(|a| Ok(i32::from(a[1] == "eject" || a[1] == "unmountDisk" && a[2] == "force"))),
        ..seed.host
    };
    assert!(!build_seed_usb_with(&host, LABEL, &seed.files, Path::new("/stage"), "disk9", &fx.ctx(), true).unwrap());
}

// ---------------------------------------------------------------------------------------------------------------
// The raw script is data
// ---------------------------------------------------------------------------------------------------------------

fn sha(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

#[test]
fn the_macos_raw_script_is_byte_identical_to_the_python_one() {
    // The digest recorded in tests/test_hardening_engine_windows.py (EXPECTED["macos_raw"]).
    assert_eq!(sha(MACOS_RAW_SCRIPT), "ed23ca677a6af8e6a30adbb326ce4a4018206f36044ad1fa0dbb2e491a6283f7");
}

#[test]
fn the_script_starts_with_set_eu_then_ignores_sigint() {
    let lines: Vec<&str> = MACOS_RAW_SCRIPT.lines().collect();
    assert_eq!(lines[0], "set -eu");
    assert_eq!(lines[1], "trap '' INT");
    assert!(MACOS_RAW_SCRIPT.contains("WRITE_CANCELED"));
    assert!(MACOS_RAW_SCRIPT.contains(crate::constants::RAW_CANCELED_MARKER));
}

#[cfg(unix)]
mod script_runs {
    use super::*;
    use crate::macos::testkit::script::*;

    #[test]
    fn the_macos_raw_script_survives_ctrl_c_and_stops_dd_through_the_flag() {
        if !have_bash() {
            return;
        }
        let stubs = Stubs::new();
        let args = vec![
            stubs.path("in.iso"),
            stubs.path("out.img"),
            "4m".to_string(),
            stubs.flag.to_string_lossy().into_owned(),
        ];
        stubs.check_raw_script(MACOS_RAW_SCRIPT, &args);
    }

    #[test]
    fn without_the_trap_ctrl_c_kills_the_script_and_orphans_dd() {
        // Control experiment: this is the bug the trap fixes.
        if !have_bash() {
            return;
        }
        let script = MACOS_RAW_SCRIPT.replace("trap '' INT\n", "");
        assert_ne!(script, MACOS_RAW_SCRIPT);
        let stubs = Stubs::new();
        let args = vec![
            stubs.path("in.iso"),
            stubs.path("out.img"),
            "4m".to_string(),
            stubs.flag.to_string_lossy().into_owned(),
        ];
        stubs.check_script_dies_and_orphans_dd(&script, &args);
    }
}
