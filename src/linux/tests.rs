//! Unit tests of the Linux backend (ports of the Python tests listed in the module header of `linux.rs`):
//! tests/test_fixes_gui.py (EnumerationTests), tests/test_refactor_helpers.py (detection order),
//! tests/test_validation.py (partition path, install command), tests/test_engine.py (linux_eject, report_eject),
//! tests/test_fixes_engine.py (RawScriptSigintTests, LinuxMountTypeTests, BackendsCanceledEarly),
//! tests/test_hardening_engine_windows.py (LinuxBuildUsbTests, script digests), tests/test_hardening_engine_seed.py
//! (SeedScriptTests, LinuxSeedBackendTests).

use super::*;
use crate::constants::{LINUX_DEVICE_RE, QUERY_TIMEOUT};
use crate::macos::testkit::*;
use crate::types::Volumes;
use indexmap::IndexMap;
use serde_json::json;
use sha2::{Digest, Sha256};

fn strs(a: &[&str]) -> Vec<String> {
    a.iter().map(|x| x.to_string()).collect()
}
fn io_error(what: &str) -> Error {
    Error::Io(std::io::Error::other(what.to_string()))
}
fn files_of(pairs: &[(&str, &[u8])]) -> Files {
    let mut files: Files = IndexMap::new();
    for (k, v) in pairs {
        files.insert(k.to_string(), v.to_vec());
    }
    files
}
fn sha(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

// ---------------------------------------------------------------------------------------------------------------
// Partition paths and the package manager
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn plain_and_numbered_devices() {
    assert_eq!(partition_path("sdb", 1), "/dev/sdb1");
    assert_eq!(partition_path("nvme0n1", 2), "/dev/nvme0n1p2");
    assert_eq!(partition_path("mmcblk0", 1), "/dev/mmcblk0p1");
    assert_eq!(partition_path("", 1), "/dev/1"); // never panics
}

fn cmd(mgr: &str, tools: &[&str]) -> Result<String> {
    build_install_command(Some(mgr), &strs(tools))
}

#[test]
fn apt_install_command() {
    assert_eq!(
        cmd("apt-get", &["wimlib-imagex", "parted"]).unwrap(),
        "apt-get update && apt-get install -y parted wimtools"
    );
}

#[test]
fn packages_are_deduplicated_and_sorted() {
    // parted and partprobe both come from the "parted" package
    assert_eq!(cmd("dnf", &["partprobe", "parted", "rsync"]).unwrap(), "dnf install -y parted rsync");
}

#[test]
fn pacman_uses_full_upgrade() {
    assert!(cmd("pacman", &["rsync"]).unwrap().contains("-Syu"));
}

#[test]
fn every_manager_covers_every_required_tool() {
    for (mgr, _) in LINUX_INSTALL_CMD_TEMPLATE {
        assert!(!cmd(mgr, LINUX_REQUIRED_TOOLS).unwrap().is_empty(), "{mgr}");
    }
}

#[test]
fn an_unknown_or_absent_manager_is_a_value_error() {
    let err = cmd("brew", &["rsync"]).unwrap_err();
    assert!(matches!(err, Error::Value(_)));
    assert_eq!(err.to_string(), "Unsupported package manager: 'brew'");
    assert_eq!(
        build_install_command(None, &strs(&["rsync"])).unwrap_err().to_string(),
        "Unsupported package manager: None"
    );
}

#[test]
fn names_outside_the_allow_list_are_ignored() {
    let err = cmd("apt-get", &["rsync; rm -rf /", "$(id)", "nc"]).unwrap_err();
    assert!(err.to_string().contains("Nothing to install"));
    assert_eq!(cmd("apt-get", &["rsync", "evil; reboot"]).unwrap(), "apt-get update && apt-get install -y rsync");
}

#[test]
fn python_reprs_are_quoted_like_python() {
    assert_eq!(py_repr("brew"), r#"'brew'"#);
    assert_eq!(py_repr("it's"), r#""it's""#);
    assert_eq!(py_repr("a\nb"), r#"'a\nb'"#);
    assert_eq!(py_repr(r"back\slash"), r#"'back\\slash'"#);
    assert_eq!(py_repr("tab\there"), r#"'tab\there'"#);
}

#[test]
fn nothing_missing_is_an_error() {
    assert!(matches!(cmd("apt-get", &[]), Err(Error::Value(_))));
}

#[test]
fn suspicious_package_names_are_refused() {
    let long = "x".repeat(65);
    for bad in ["parted; rm -rf /", "a b", "$(id)", long.as_str(), "", "p`id`", "parted\n"] {
        let table: &[(&str, &[(&str, &str)])] = &[("apt-get", &[("parted", bad)])];
        let err = build_install_command_from(table, Some("apt-get"), &strs(&["parted"])).unwrap_err();
        assert!(matches!(err, Error::Value(_)), "{bad:?}");
    }
    let table: &[(&str, &[(&str, &str)])] = &[("apt-get", &[("parted", "a b")])];
    let err = build_install_command_from(table, Some("apt-get"), &strs(&["parted"])).unwrap_err();
    assert_eq!(err.to_string(), "Refusing to install suspicious package name: 'a b'");
}

#[test]
fn the_package_map_covers_the_same_tools_for_every_manager() {
    for (mgr, table) in LINUX_PKG_MAP {
        let mut names: Vec<&str> = table.iter().map(|(t, _)| *t).collect();
        let mut required: Vec<&str> = LINUX_REQUIRED_TOOLS.to_vec();
        names.sort_unstable();
        required.sort_unstable();
        assert_eq!(names, required, "{mgr}");
    }
}

#[test]
fn detection_follows_the_template_order() {
    let order: Vec<&str> = LINUX_INSTALL_CMD_TEMPLATE.iter().map(|(m, _)| *m).collect();
    assert_eq!(order, ["apt-get", "dnf", "yum", "pacman", "zypper", "apk"]);
    let map: Vec<&str> = LINUX_PKG_MAP.iter().map(|(m, _)| *m).collect();
    assert_eq!(map, order);
    let host = FakeHost::new().with_binaries(&["dnf", "apk"]);
    assert_eq!(detect_pkg_manager_with(&host).as_deref(), Some("dnf"));
    assert_eq!(detect_pkg_manager_with(&FakeHost::new()), None);
}

// ---------------------------------------------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn the_linux_queries_have_timeouts() {
    let host = FakeHost::new().with_output(|_| Err(Error::runtime("Command failed")));
    assert_eq!(root_disk(&host), None);
    assert!(disks_holding_critical_mounts(&host).is_empty());
    assert!(lsblk_disks(&host).is_err());
    let outs = host.outputs();
    assert!(outs.len() >= 4);
    for (args, timeout, _) in &outs {
        assert!(*timeout > Duration::ZERO && *timeout <= secs(QUERY_TIMEOUT), "{args:?}");
    }
    // the three lsblk column sets are tried, richest first, until one works
    let sets: Vec<&String> =
        outs.iter().filter(|(a, _, _)| a.iter().any(|x| x == "-b")).map(|(a, _, _)| a.last().unwrap()).collect();
    assert!(sets.iter().any(|s| s.ends_with("FSUSED")) && sets.iter().any(|s| s.as_str() == "NAME,SIZE,TYPE,RM,TRAN"));
}

#[test]
fn the_lsblk_column_sets_fall_back_step_by_step() {
    let host = FakeHost::new().with_output(move |args| {
        // an old util-linux: only the shortest column set is accepted
        if args.last().map(String::as_str) == Some("NAME,SIZE,TYPE,RM,TRAN") {
            Ok(br#"{"blockdevices": [{"name": "sdb", "type": "disk"}]}"#.to_vec())
        } else {
            Err(Error::runtime("lsblk: unknown column"))
        }
    });
    let devices = lsblk_disks(&host).unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(host.outputs().len(), 3);
    assert!(host.outputs().iter().all(|(a, _, quiet)| a[0] == "lsblk" && *quiet));
}

#[test]
fn lsblk_output_parsing() {
    assert!(parse_lsblk(b"{}").unwrap().is_empty());
    assert!(parse_lsblk(b"not json").is_err());
    assert!(parse_lsblk(br#"{"blockdevices": 5}"#).is_err());
    assert_eq!(parse_lsblk(br#"{"blockdevices": [{"name": "a"}, {"name": "b"}]}"#).unwrap().len(), 2);
}

#[test]
fn as_int_accepts_numbers_and_numeric_text_only() {
    assert_eq!(as_int(&json!(5)), Some(5));
    assert_eq!(as_int(&json!("42")), Some(42));
    assert_eq!(as_int(&json!(" 7 ")), Some(7));
    assert_eq!(as_int(&json!(3.9)), Some(3));
    assert_eq!(as_int(&json!("abc")), None);
    assert_eq!(as_int(&json!(null)), None);
    assert_eq!(as_int(&json!([1])), None);
}

#[test]
fn lsblk_skips_zero_and_unreadable_sizes() {
    let devices = vec![
        json!({"name": "sdb", "type": "disk", "tran": "usb", "size": 0}),
        json!({"name": "sdc", "type": "disk", "tran": "usb", "size": 8 * GIB}),
        json!({"name": "sdd", "type": "disk", "tran": "usb", "size": "abc"}),
        json!({"name": "sde", "type": "disk", "tran": "usb", "size": null}),
        json!({"name": "sdf", "type": "disk", "tran": "usb", "size": (4 * GIB).to_string()}),
        json!({"name": "sdg", "type": "disk", "tran": "usb", "size": -5}),
    ];
    let host = FakeHost::new();
    let disks = disks_from_lsblk(&host, &devices, &HashSet::new());
    assert_eq!(disks.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(), ["sdc", "sdf"]);
    assert!(disks.iter().all(|d| d.size > 0));
    assert_eq!(host.audit_texts().iter().filter(|m| m.ends_with("its size is zero or unreadable")).count(), 4);
}

#[test]
fn only_usb_whole_disks_with_a_safe_name_are_offered() {
    let disk = |name: &str, tran: &str| json!({"name": name, "type": "disk", "tran": tran, "size": GIB});
    let devices = vec![
        disk("sda", "sata"),
        disk("sdb", "USB"), // the transport is compared case-insensitively
        disk("nvme0n1", "nvme"),
        disk("loop0", "usb"),
        disk("zram0", "usb"),
        disk("dm-0", "usb"),
        disk("sdc;rm -rf", "usb"), // not a plausible device name
        json!({"name": "sdd", "type": "part", "tran": "usb", "size": GIB}),
        json!({"name": "sde", "type": "disk", "size": GIB}), // no transport at all
        json!({"type": "disk", "tran": "usb", "size": GIB}),
        json!("junk"),
    ];
    let host = FakeHost::new();
    let disks = disks_from_lsblk(&host, &devices, &HashSet::new());
    assert_eq!(disks.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(), ["sdb"]);
}

#[test]
fn a_disk_that_hosts_the_system_is_never_offered_even_over_usb() {
    let devices = vec![json!({"name": "sdb", "type": "disk", "tran": "usb", "size": GIB})];
    let host = FakeHost::new();
    let unsafe_disks: HashSet<String> = ["sdb".to_string()].into();
    assert!(disks_from_lsblk(&host, &devices, &unsafe_disks).is_empty());
    assert_eq!(host.audit_texts(), ["Hiding sdb: it hosts the system or a critical mountpoint"]);
    assert_eq!(host.audits.lock().unwrap()[0].1, AuditLevel::Info);
}

#[test]
fn the_device_pattern_is_the_validators() {
    for ok in ["sdb", "nvme0n1", "mmcblk0", "a_b+c-d"] {
        assert!(LINUX_DEVICE_RE.is_match(ok));
    }
    for bad in ["", "sd b", "sdb\n", "sd/b", &"x".repeat(33)] {
        assert!(!LINUX_DEVICE_RE.is_match(bad), "{bad:?}");
    }
}

#[test]
fn critical_mounts_are_found_anywhere_in_the_tree_of_a_disk() {
    let out = json!({"blockdevices": [
        {"name": "sda", "type": "disk", "mountpoint": null, "children": [
            {"name": "sda1", "type": "part", "mountpoint": "/boot/efi"},
            {"name": "sda2", "type": "part", "mountpoint": null, "children": [
                {"name": "vg-root", "type": "lvm", "mountpoint": "/"}]}]},
        {"name": "sdb", "type": "disk", "children": [
            {"name": "sdb1", "type": "part", "mountpoint": "/media/user/STICK"}]},
        {"name": "mmcblk0", "type": "disk", "children": [
            {"name": "mmcblk0p1", "type": "part", "mountpoint": "/boot/firmware"}]},
        {"name": "sdc", "type": "disk", "children": [
            {"name": "sdc1", "type": "part", "mountpoint": "/home"}]},
        {"name": "loop0", "type": "loop", "mountpoint": "/"}, // not a disk: ignored
    ]});
    let set = parse_critical_mounts(out.to_string().as_bytes()).unwrap();
    let mut names: Vec<&str> = set.iter().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(names, ["mmcblk0", "sda", "sdc"]);
    assert!(parse_critical_mounts(b"garbage").is_err());
}

#[test]
fn the_root_disk_comes_from_findmnt_and_lsblk() {
    let host = FakeHost::new().with_output(|args| match args[0].as_str() {
        "findmnt" => Ok(b"/dev/sda2\n".to_vec()),
        "lsblk" => {
            assert_eq!(args, ["lsblk", "-no", "PKNAME", "/dev/sda2"]);
            Ok(b"sda\n".to_vec())
        }
        other => panic!("unexpected {other}"),
    });
    assert_eq!(root_disk(&host).as_deref(), Some("sda"));
    assert_eq!(host.outputs()[0].0, ["findmnt", "-no", "SOURCE", "/"]);
    // an empty answer (the root is not on a partition we can see) means "unknown"
    let host = FakeHost::new()
        .with_output(|args| Ok(if args[0] == "findmnt" { b"overlay\n".to_vec() } else { b"\n".to_vec() }));
    assert_eq!(root_disk(&host), None);
    assert!(host.audit_texts().is_empty());
    // a failure is audited
    let host = FakeHost::new().with_output(|_| Err(io_error("no findmnt")));
    assert_eq!(root_disk(&host), None);
    assert_eq!(
        host.audit_texts(),
        ["Could not determine the system disk (OSError); falling back to mountpoint inspection"]
    );
}

fn lsblk_host(rich: serde_json::Value, critical: serde_json::Value) -> FakeHost {
    FakeHost::new()
        .with_output(move |args| match args[0].as_str() {
            "findmnt" => Ok(b"/dev/sda2\n".to_vec()),
            "lsblk" if args[1] == "-no" => Ok(b"sda\n".to_vec()),
            "lsblk" if args.last().map(String::as_str) == Some("NAME,TYPE,MOUNTPOINT,PKNAME") => {
                Ok(critical.to_string().into_bytes())
            }
            "lsblk" => Ok(rich.to_string().into_bytes()),
            other => panic!("unexpected {other}"),
        })
        .with_binaries(&["lsblk"])
}

#[test]
fn the_listing_offers_only_the_usb_stick() {
    let rich = json!({"blockdevices": [
        {"name": "sda", "size": 500 * GIB, "type": "disk", "rm": false, "tran": "sata", "serial": "S0",
         "model": "Samsung SSD", "vendor": "ATA", "fstype": null, "mountpoint": null, "children": [
            {"name": "sda1", "size": GIB, "type": "part", "fstype": "vfat", "mountpoint": "/boot/efi"}]},
        {"name": "sdb", "size": 16 * GIB, "type": "disk", "rm": true, "tran": "usb", "serial": "SER1", "wwn": "0x5000",
         "model": " Ultra ", "vendor": "SanDisk ", "fstype": null, "label": null, "mountpoint": null, "children": [
            {"name": "sdb1", "size": 15 * GIB, "type": "part", "fstype": "vfat", "label": "STICK",
             "mountpoint": "/media/user/STICK", "fsused": "1048576"},
            {"name": "sdb2", "size": GIB, "type": "part", "fstype": null, "mountpoint": null}]},
        {"name": "sdc", "size": 0, "type": "disk", "rm": true, "tran": "usb"},
        {"name": "loop0", "size": 1000, "type": "loop", "tran": null},
    ]});
    let critical = json!({"blockdevices": [
        {"name": "sda", "type": "disk", "children": [{"name": "sda1", "type": "part", "mountpoint": "/boot/efi"}]},
        {"name": "sdb", "type": "disk", "children": [{"name": "sdb1", "type": "part", "mountpoint": "/media/user/STICK"}]},
    ]});
    let host = lsblk_host(rich, critical);
    let disks = get_external_disks_with(&host).unwrap();
    assert_eq!(disks.len(), 1);
    let d = &disks[0];
    assert_eq!((d.id.as_str(), d.size), ("sdb", 16 * GIB));
    assert_eq!(d.model.as_deref(), Some("SanDisk Ultra"));
    assert_eq!(
        d.identity,
        vec![
            ("model".to_string(), "SanDisk Ultra".to_string()),
            ("serial".to_string(), "SER1".to_string()),
            ("wwn".to_string(), "0x5000".to_string()),
        ]
    );
    // the unformatted second partition is a volume too; its filesystem is empty
    assert_eq!(
        d.volumes,
        Volumes::List(vec![
            Volume {
                name: Some("STICK".into()),
                filesystem: Some("vfat".into()),
                size: Some(15 * GIB),
                used: Some(1_048_576),
                mountpoint: Some("/media/user/STICK".into()),
            },
            Volume {
                name: Some("sdb2".into()),
                filesystem: Some("".into()),
                size: Some(GIB),
                used: None,
                mountpoint: None
            },
        ])
    );
    assert!(host.audit_texts().iter().any(|m| m == "Hiding sda: it hosts the system or a critical mountpoint"));
}

#[test]
fn the_critical_mount_scan_is_a_net_under_the_root_disk_lookup() {
    // `findmnt` fails (a container, a chroot): the removable-flagged boot disk is still caught by its mounts.
    let rich = json!({"blockdevices": [
        {"name": "mmcblk0", "size": 32 * GIB, "type": "disk", "tran": "usb"},
        {"name": "sdb", "size": 8 * GIB, "type": "disk", "tran": "usb"}]});
    let critical = json!({"blockdevices": [
        {"name": "mmcblk0", "type": "disk", "children": [{"name": "p1", "type": "part", "mountpoint": "/"}]}]});
    let rich_s = rich.to_string();
    let critical_s = critical.to_string();
    let host = FakeHost::new()
        .with_output(move |args| match args[0].as_str() {
            "findmnt" => Err(Error::runtime("findmnt: not found")),
            "lsblk" if args.last().map(String::as_str) == Some("NAME,TYPE,MOUNTPOINT,PKNAME") => {
                Ok(critical_s.clone().into_bytes())
            }
            _ => Ok(rich_s.clone().into_bytes()),
        })
        .with_binaries(&["lsblk"]);
    let disks = get_external_disks_with(&host).unwrap();
    assert_eq!(disks.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(), ["sdb"]);
}

#[test]
fn an_lsblk_that_is_too_old_gives_a_disk_without_volumes() {
    let host = FakeHost::new();
    let dev = json!({"name": "sdb", "size": GIB, "type": "disk", "tran": "usb", "model": "Stick", "vendor": "", "serial": "X"});
    let (model, volumes, identity) = describe_disk(&host, &dev);
    assert_eq!(model, "Stick");
    assert_eq!(volumes, None);
    assert_eq!(identity, vec![("model".to_string(), "Stick".to_string()), ("serial".to_string(), "X".to_string())]);
}

#[test]
fn a_filesystem_written_straight_onto_the_disk_is_a_volume_and_used_bytes_fall_back_to_the_mountpoint() {
    let mut host = FakeHost::new();
    host.used = vec![("/mnt/x".to_string(), 99)];
    let dev =
        json!({"name": "sdb", "size": GIB, "type": "disk", "fstype": "ext4", "label": null, "mountpoint": "/mnt/x"});
    let (_, volumes, _) = describe_disk(&host, &dev);
    assert_eq!(
        volumes,
        Some(vec![Volume {
            name: Some("sdb".into()),
            filesystem: Some("ext4".into()),
            size: Some(GIB),
            used: Some(99),
            mountpoint: Some("/mnt/x".into())
        }])
    );
    // a disk with no partitions and no filesystem has no volumes (and is not "unknown")
    let (_, volumes, _) = describe_disk(&host, &json!({"name": "sdc", "type": "disk", "fstype": null}));
    assert_eq!(volumes, Some(vec![]));
}

#[test]
fn a_node_that_cannot_be_described_never_changes_the_listing() {
    let host = FakeHost::new();
    let dev =
        json!({"name": "sdb", "type": "disk", "size": GIB, "tran": "usb", "vendor": 5, "model": "x", "fstype": null});
    let (model, volumes, identity) = describe_disk(&host, &dev);
    assert_eq!((model.as_str(), volumes, identity), ("", None, vec![]));
    assert_eq!(host.audit_texts(), ["Could not describe sdb (AttributeError)"]);
    // and the disk is still listed
    let listed = disks_from_lsblk(&host, &[dev], &HashSet::new());
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].model.as_deref(), Some(""));
    let bad_children = json!({"name": "sdc", "type": "disk", "fstype": null, "children": {"a": 1}});
    assert_eq!(describe_disk(&host, &bad_children).1, None);
}

/// A fake `/sys/block` with one disk `sdz` that sits under a USB bus node.
#[cfg(unix)]
fn sysfs(removable: &str, sectors: &str, under_usb: bool) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let real = if under_usb {
        dir.path().join("devices/pci0000:00/0000:00:14.0/usb1/1-1/host6/target6:0:0/6:0:0:0/block/sdz")
    } else {
        dir.path().join("devices/pci0000:00/0000:00:17.0/ata1/host0/target0:0:0/0:0:0:0/block/sdz")
    };
    std::fs::create_dir_all(real.join("device")).unwrap();
    std::fs::write(real.join("removable"), removable).unwrap();
    std::fs::write(real.join("size"), sectors).unwrap();
    std::fs::write(real.join("device/vendor"), "SanDisk \n").unwrap();
    std::fs::write(real.join("device/model"), "Cruzer Blade \n").unwrap();
    let block = dir.path().join("block");
    std::fs::create_dir_all(&block).unwrap();
    std::os::unix::fs::symlink(&real, block.join("sdz")).unwrap();
    (dir, block)
}

#[cfg(unix)]
#[test]
fn the_sys_block_fallback_skips_zero_size() {
    let (dir, block) = sysfs("1\n", "0\n", true);
    let mut host = FakeHost::new();
    host.sys_root = block;
    assert!(disks_from_sysfs(&host, &HashSet::new()).unwrap().is_empty());
    assert!(host.audit_texts().iter().any(|m| m == "Hiding sdz: its size is zero"));
    // 16777216 sectors of 512 bytes
    std::fs::write(
        dir.path().join("devices/pci0000:00/0000:00:14.0/usb1/1-1/host6/target6:0:0/6:0:0:0/block/sdz/size"),
        "16777216\n",
    )
    .unwrap();
    let disks = disks_from_sysfs(&host, &HashSet::new()).unwrap();
    assert_eq!(disks.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(), ["sdz"]);
    assert_eq!(disks[0].size, 8 * GIB);
    assert_eq!(disks[0].model.as_deref(), Some("SanDisk Cruzer Blade"));
    assert_eq!(disks[0].volumes, Volumes::Unknown, "no partition information from sysfs");
    assert_eq!(disks[0].identity, vec![("model".to_string(), "SanDisk Cruzer Blade".to_string())]);
}

#[cfg(unix)]
#[test]
fn the_sys_block_fallback_is_fail_closed() {
    let mut host = FakeHost::new();
    // not removable
    let (_d1, block) = sysfs("0\n", "1000\n", true);
    host.sys_root = block;
    assert!(disks_from_sysfs(&host, &HashSet::new()).unwrap().is_empty());
    // removable but not on a USB bus (an SD reader on PCI, say)
    let (_d2, block) = sysfs("1\n", "1000\n", false);
    host.sys_root = block;
    assert!(disks_from_sysfs(&host, &HashSet::new()).unwrap().is_empty());
    // an unreadable size
    let (_d3, block) = sysfs("1\n", "lots\n", true);
    host.sys_root = block;
    assert!(disks_from_sysfs(&host, &HashSet::new()).unwrap().is_empty());
    assert!(host.audit_texts().iter().any(|m| m == "Hiding sdz: could not read its size"));
    // a disk that hosts a critical mountpoint
    let (_d4, block) = sysfs("1\n", "1000\n", true);
    host.sys_root = block;
    let unsafe_disks: HashSet<String> = ["sdz".to_string()].into();
    assert!(disks_from_sysfs(&host, &unsafe_disks).unwrap().is_empty());
    assert_eq!(disks_from_sysfs(&host, &HashSet::new()).unwrap().len(), 1);
    // no /sys/block at all
    host.sys_root = PathBuf::from("/nonexistent-sys-block");
    assert!(matches!(disks_from_sysfs(&host, &HashSet::new()), Err(Error::Io(_))));
}

#[cfg(unix)]
#[test]
fn without_lsblk_the_listing_uses_sys_block_and_a_failing_lsblk_falls_back_too() {
    let (_dir, block) = sysfs("1\n", "16777216\n", true);
    // no lsblk binary
    let mut host = FakeHost::new().with_output(|_| Err(Error::runtime("no")));
    host.sys_root = block.clone();
    assert_eq!(get_external_disks_with(&host).unwrap().iter().map(|d| d.id.as_str()).collect::<Vec<_>>(), ["sdz"]);
    assert!(!host.audit_texts().iter().any(|m| m.contains("lsblk enumeration failed")));
    // lsblk present but every column set fails
    let mut host = FakeHost::new().with_output(|_| Err(Error::runtime("Command failed"))).with_binaries(&["lsblk"]);
    host.sys_root = block;
    assert_eq!(get_external_disks_with(&host).unwrap().iter().map(|d| d.id.as_str()).collect::<Vec<_>>(), ["sdz"]);
    assert!(host
        .audit_texts()
        .iter()
        .any(|m| m == "lsblk enumeration failed (RuntimeError); using /sys/block fallback"));
}

// ---------------------------------------------------------------------------------------------------------------
// eject (EjectTests)
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn eject_reads_the_marker_line() {
    let marker = |line: &'static str| {
        RecPriv::with(move |_, _, _, log| {
            log(line);
            Ok(())
        })
    };
    let (yes, no) = (marker("EJECTED"), marker("NOT_EJECTED"));
    assert!(eject("sdb", &quiet, &yes));
    assert!(!eject("sdb", &quiet, &no));
    assert_eq!(yes.recorded()[0].1, ["/dev/sdb"]);
    assert_eq!(yes.recorded()[0].0, EJECT_SCRIPT);
    // the marker may carry surrounding whitespace
    assert!(eject("sdb", &quiet, &marker("  EJECTED \n")));
}

#[test]
fn an_eject_failure_is_not_fatal() {
    let boom = RecPriv::with(|_, _, _, _| Err(Error::runtime("no sudo")));
    let fx = Fx::new();
    assert!(!eject("sdb", fx.ctx().log, &boom));
    assert!(fx.has("Warning: could not run the eject step: no sudo"));
}

#[test]
fn unmounting_partitions_is_best_effort() {
    let boom = RecPriv::with(|_, _, _, _| Err(Error::runtime("no sudo")));
    let fx = Fx::new();
    unmount_partitions("/dev/sdb", fx.ctx().log, &boom);
    assert!(fx.has("Warning: could not unmount the drive: no sudo"));
    assert_eq!(boom.recorded()[0], (UNMOUNT_PARTITIONS_SCRIPT.to_string(), vec!["/dev/sdb".to_string()]));
}

// ---------------------------------------------------------------------------------------------------------------
// write_raw
// ---------------------------------------------------------------------------------------------------------------

/// Which of the known scripts is this?
fn kind(script: &str) -> &'static str {
    match script {
        s if s == WINDOWS_PREP_SCRIPT => "prep",
        s if s == WINDOWS_REMOUNT_SCRIPT => "remount",
        s if s == WINDOWS_CLEANUP_SCRIPT => "cleanup",
        s if s == LINUX_RAW_SCRIPT => "raw",
        s if s == EJECT_SCRIPT => "eject",
        s if s == UNMOUNT_PARTITIONS_SCRIPT => "unmount",
        s if s == LINUX_SEED_PREP_SCRIPT => "seed-prep",
        s if s == LINUX_SEED_REMOUNT_SCRIPT => "seed-remount",
        s if s == LINUX_SEED_CLEANUP_SCRIPT => "seed-cleanup",
        _ => "other",
    }
}
fn kinds(priv_: &RecPriv) -> Vec<&'static str> {
    priv_.texts().iter().map(|t| kind(t)).collect()
}
/// A privilege that answers the eject script with `EJECTED`.
fn ejecting_priv() -> RecPriv {
    RecPriv::with(|_, script, _, log| {
        if script == EJECT_SCRIPT {
            log("EJECTED");
        }
        Ok(())
    })
}

#[test]
fn write_raw_writes_verifies_and_ejects() {
    let dir = tempfile::tempdir().unwrap();
    let iso = make_image(dir.path(), "ubuntu.iso", 2 * 1024 * 1024);
    let host = FakeHost::new();
    let priv_ = ejecting_priv();
    let fx = Fx::new();
    assert!(write_raw_with(&host, &iso, "sdb", &fx.ctx(), &priv_, true).unwrap());
    assert_eq!(kinds(&priv_), ["raw", "eject"]);
    let args = &priv_.recorded()[0].1;
    // "$1".."$5": image, device, block size, cancel flag, direct/buffered
    assert_eq!(&args[..3], [iso.to_string_lossy().into_owned(), "/dev/sdb".to_string(), "4M".to_string()]);
    assert_eq!(args.len(), 5);
    assert_eq!(args[4], "direct"); // 2 MiB is a multiple of 4096
    assert!(host.calls().contains(&Call::VerifyRaw { device: "/dev/sdb".to_string() }));
    assert!(fx.progress_texts().contains(&"Written".to_string()));
    assert!(fx.has("Writing the ISO to /dev/sdb (administrator privileges required)..."));
    assert!(fx.has("Done! The USB drive is ready to boot."));
    assert!(fx.has("Drive ejected"));
    assert!(host.cmds().is_empty(), "the Linux backend runs nothing as the user");
}

#[test]
fn direct_io_is_used_only_for_an_aligned_image() {
    let dir = tempfile::tempdir().unwrap();
    for (size, expect) in [(4096usize, "direct"), (4096 + 512, "buffered"), (1, "buffered"), (8192, "direct")] {
        let iso = dir.path().join(format!("i{size}.iso"));
        std::fs::write(&iso, vec![0u8; size]).unwrap();
        let priv_ = RecPriv::new();
        write_raw_with(&FakeHost::new(), &iso, "sdb", &Fx::new().ctx(), &priv_, false).unwrap();
        assert_eq!(priv_.recorded()[0].1[4], expect, "{size}");
    }
}

#[test]
fn a_stop_request_unmounts_the_partitions_and_is_a_cancel() {
    let dir = tempfile::tempdir().unwrap();
    let iso = make_image(dir.path(), "ubuntu.iso", 4096);
    let priv_ = RecPriv::with(|_, script, _, log| {
        if script == LINUX_RAW_SCRIPT {
            log("WRITE_CANCELED");
        }
        Ok(())
    });
    let host = FakeHost::new();
    let fx = Fx::new();
    let err = write_raw_with(&host, &iso, "sdb", &fx.ctx(), &priv_, true).unwrap_err();
    assert!(err.is_canceled() && err.drive_touched() && !err.written());
    assert_eq!(kinds(&priv_), ["raw", "unmount"]);
    assert_eq!(priv_.recorded()[1].1, ["/dev/sdb"]);
    assert!(fx.has("The write was stopped at your request."));
    assert!(fx.has("Canceled. The drive holds a partial image and is unusable until written again."));
    assert!(!host.calls().iter().any(|c| matches!(c, Call::VerifyRaw { .. })));
}

#[test]
fn write_raw_cancelled_before_it_starts_does_not_touch_the_drive() {
    let dir = tempfile::tempdir().unwrap();
    let iso = make_image(dir.path(), "ubuntu.iso", 4096);
    let priv_ = RecPriv::new();
    let fx = Fx::new();
    fx.cancel.set();
    let err = write_raw_with(&FakeHost::new(), &iso, "sdb", &fx.ctx(), &priv_, true).unwrap_err();
    assert!(matches!(err, Error::Canceled { drive_touched: false, .. }));
    assert_eq!(priv_.count(), 0);
}

#[test]
fn write_raw_refuses_a_non_hybrid_image_and_a_missing_file() {
    let mut host = FakeHost::new();
    host.hybrid_ok = false;
    let priv_ = RecPriv::new();
    let err = write_raw_with(&host, Path::new("/x/windows.iso"), "sdb", &Fx::new().ctx(), &priv_, true).unwrap_err();
    assert!(matches!(err, Error::Value(_)));
    let err = write_raw_with(&FakeHost::new(), Path::new("/nonexistent/x.iso"), "sdb", &Fx::new().ctx(), &priv_, true)
        .unwrap_err();
    assert!(matches!(err, Error::Io(_)));
    assert_eq!(priv_.count(), 0);
}

#[test]
fn a_failed_verification_blocks_the_eject() {
    let dir = tempfile::tempdir().unwrap();
    let iso = make_image(dir.path(), "ubuntu.iso", 4096);
    let mut host = FakeHost::new();
    host.verify_raw = Box::new(|_, _| Err(Error::runtime("Verification FAILED: the drive differs")));
    let priv_ = ejecting_priv();
    let err = write_raw_with(&host, &iso, "sdb", &Fx::new().ctx(), &priv_, true).unwrap_err();
    assert!(err.to_string().contains("Verification FAILED"));
    assert_eq!(kinds(&priv_), ["raw"]);
}

#[test]
fn no_eject_leaves_the_drive_connected() {
    let dir = tempfile::tempdir().unwrap();
    let iso = make_image(dir.path(), "ubuntu.iso", 4096);
    let priv_ = ejecting_priv();
    let fx = Fx::new();
    assert!(!write_raw_with(&FakeHost::new(), &iso, "sdb", &fx.ctx(), &priv_, false).unwrap());
    assert_eq!(kinds(&priv_), ["raw"]);
    assert!(fx.has("left connected"));
}

// ---------------------------------------------------------------------------------------------------------------
// build_usb (LinuxBuildUsbTests, LinuxMountTypeTests)
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn build_usb_runs_prep_then_the_copy_then_remount_and_cleanup() {
    let host = FakeHost::new().with_payload(|src, dst, _, reopen, extra| {
        assert!(src.to_string_lossy().contains("win11iso_") && dst.to_string_lossy().contains("win11usb_"));
        assert!(extra.is_none());
        // the copy reads the drive back through the callback
        assert_eq!(reopen.expect("reopen")()?, dst);
        Ok(())
    });
    let priv_ = ejecting_priv();
    let fx = Fx::new();
    assert!(build_usb_with(&host, Path::new("/x/Win11.iso"), "sdb", &fx.ctx(), &priv_, true, None).unwrap());
    assert_eq!(kinds(&priv_), ["prep", "remount", "cleanup", "eject"]);
    let recorded = priv_.recorded();
    let payload = host.calls().into_iter().find(|c| matches!(c, Call::Payload { .. }));
    let Some(Call::Payload { src, dst, .. }) = payload else { panic!("no payload call") };
    let (iso_mnt, usb_mnt) = (src.to_string_lossy().into_owned(), dst.to_string_lossy().into_owned());
    // "$1".."$6": device, partition, image, ISO mount, drive mount, uid:gid
    assert_eq!(recorded[0].1, ["/dev/sdb", "/dev/sdb1", "/x/Win11.iso", &iso_mnt, &usb_mnt, "1000:1000"]);
    assert_eq!(recorded[1].1, ["/dev/sdb1", &usb_mnt, "1000:1000"]);
    assert_eq!(recorded[2].1, [usb_mnt.as_str(), iso_mnt.as_str()]);
    assert_eq!(recorded[3].1, ["/dev/sdb"]);
    // values travel as arguments only: none of them is pasted into any script
    for (script, _) in &recorded {
        for value in ["/dev/sdb", "/x/Win11.iso", iso_mnt.as_str(), usb_mnt.as_str()] {
            assert!(!script.contains(value), "{value} is in a script");
        }
    }
    assert!(recorded[0].0.contains(r#"uid="${OWNER%%:*}",gid="${OWNER##*:}" "$PART" "$USB_MNT""#));
    for needle in [
        "Erasing and formatting /dev/sdb as GPT + FAT32 (administrator privileges required)...",
        "Remounting the drive read-only to read it back from the device...",
        "Unmounting...",
        "Done! The USB drive is ready to install Windows 11.",
    ] {
        assert!(fx.has(needle), "{needle}");
    }
    // both mount directories are removed at the end
    let rmdirs: Vec<PathBuf> =
        host.calls().into_iter().filter_map(|c| if let Call::Rmdir(p) = c { Some(p) } else { None }).collect();
    assert_eq!(rmdirs, [PathBuf::from(&iso_mnt), PathBuf::from(&usb_mnt)]);
}

#[test]
fn the_wimlib_hint_names_every_distribution() {
    let host = FakeHost::new();
    build_usb_with(&host, Path::new("/x/Win11.iso"), "sdb", &Fx::new().ctx(), &RecPriv::new(), false, None).unwrap();
    let Some(Call::Payload { hint, reopen, .. }) = host.calls().into_iter().find(|c| matches!(c, Call::Payload { .. }))
    else {
        panic!("no payload call")
    };
    assert!(reopen);
    for needle in [
        "'wimtools' on Debian/Ubuntu",
        "'wimlib-utils' on Fedora",
        "'wimlib' on Arch/openSUSE",
        "'Install missing dependencies' button",
    ] {
        assert!(hint.contains(needle), "{needle}: {hint}");
    }
}

#[test]
fn nvme_names_get_the_p_suffix() {
    let host = FakeHost::new();
    let priv_ = RecPriv::new();
    build_usb_with(&host, Path::new("/x/Win11.iso"), "nvme0n1", &Fx::new().ctx(), &priv_, false, None).unwrap();
    assert_eq!(priv_.recorded()[0].1[..2], ["/dev/nvme0n1", "/dev/nvme0n1p1"]);
}

#[test]
fn the_remount_script_is_the_read_only_one() {
    // The read-back must read from the device: unmount, drop the caches, remount read-only.
    assert!(WINDOWS_REMOUNT_SCRIPT.starts_with("set -eu\nsync\numount"));
    assert!(WINDOWS_REMOUNT_SCRIPT.contains("mount -o ro,"));
    assert!(WINDOWS_CLEANUP_SCRIPT.starts_with("set -eu\numount"));
}

#[test]
fn a_cancel_before_the_backend_starts_touches_nothing() {
    let host = FakeHost::new();
    let priv_ = RecPriv::new();
    let fx = Fx::new();
    fx.cancel.set();
    let err = build_usb_with(&host, Path::new("/x/Win11.iso"), "sdb", &fx.ctx(), &priv_, true, None).unwrap_err();
    assert!(matches!(err, Error::Canceled { drive_touched: false, .. }));
    assert_eq!(priv_.count(), 0);
    assert!(host.calls().is_empty(), "no directory was even created");
}

#[test]
fn a_cancel_while_formatting_is_a_cancel_and_cleans_up() {
    let fx = Fx::new();
    let cancel = fx.cancel.clone();
    let priv_ = RecPriv::with(move |_, script, _, _| {
        if script == WINDOWS_PREP_SCRIPT {
            cancel.set(); // the user clicks Cancel while the drive is being formatted
        }
        Ok(())
    });
    let host = FakeHost::new();
    let err = build_usb_with(&host, Path::new("/x/Win11.iso"), "sdb", &fx.ctx(), &priv_, true, None).unwrap_err();
    assert!(err.is_canceled() && err.drive_touched());
    assert_eq!(kinds(&priv_), ["prep", "cleanup"]);
    assert!(!host.calls().iter().any(|c| matches!(c, Call::Payload { .. })));
}

#[test]
fn a_cancel_during_the_copy_says_so_and_never_ejects() {
    for (written, line) in [
        (false, "Canceled. The drive is left incomplete and unusable."),
        (true, "Canceled during verification. The files were copied completely but NOT verified."),
    ] {
        let host = FakeHost::new()
            .with_payload(move |_, _, _, _, _| Err(Error::canceled_with("Canceled by the user.", true, written)));
        let priv_ = ejecting_priv();
        let fx = Fx::new();
        let err = build_usb_with(&host, Path::new("/x/Win11.iso"), "sdb", &fx.ctx(), &priv_, true, None).unwrap_err();
        assert_eq!(err.written(), written);
        assert!(fx.has(line), "{line}");
        assert_eq!(kinds(&priv_), ["prep", "cleanup"]);
    }
}

#[test]
fn a_failing_script_is_never_rerun_and_the_cleanup_still_runs_once() {
    let priv_ = RecPriv::with(|_, script, _, _| {
        if script == WINDOWS_PREP_SCRIPT {
            Err(Error::runtime("Privileged command failed"))
        } else {
            Ok(())
        }
    });
    let host = FakeHost::new();
    let err =
        build_usb_with(&host, Path::new("/x/Win11.iso"), "sdb", &Fx::new().ctx(), &priv_, true, None).unwrap_err();
    assert_eq!(err.to_string(), "Privileged command failed");
    assert_eq!(kinds(&priv_), ["prep", "cleanup"]);
    assert!(!host.calls().iter().any(|c| matches!(c, Call::Payload { .. })));
    assert_eq!(host.calls().iter().filter(|c| matches!(c, Call::Rmdir(_))).count(), 2);
}

#[test]
fn a_copy_error_cleans_up_and_does_not_eject() {
    let host = FakeHost::new().with_payload(|_, _, _, _, _| Err(Error::runtime("Verification FAILED: x differs")));
    let priv_ = ejecting_priv();
    let err =
        build_usb_with(&host, Path::new("/x/Win11.iso"), "sdb", &Fx::new().ctx(), &priv_, true, None).unwrap_err();
    assert!(err.to_string().contains("Verification FAILED"));
    assert_eq!(kinds(&priv_), ["prep", "cleanup"]);
}

#[test]
fn a_failing_cleanup_is_only_a_warning() {
    let priv_ = RecPriv::with(|_, script, _, log| {
        if script == WINDOWS_CLEANUP_SCRIPT {
            return Err(Error::runtime("script failed (1)"));
        }
        if script == EJECT_SCRIPT {
            log("EJECTED");
        }
        Ok(())
    });
    let fx = Fx::new();
    assert!(build_usb_with(&FakeHost::new(), Path::new("/x/Win11.iso"), "sdb", &fx.ctx(), &priv_, true, None).unwrap());
    assert!(fx.lines().iter().any(|l| l.starts_with("Warning: cleanup failed")));
}

#[test]
fn the_hardening_files_reach_the_copy_only_when_there_are_some() {
    let files = files_of(&[("answer-standin.xml", b"<x/>")]);
    let host = FakeHost::new();
    build_usb_with(&host, Path::new("/x/Win11.iso"), "sdb", &Fx::new().ctx(), &RecPriv::new(), false, Some(&files))
        .unwrap();
    let Some(Call::Payload { extra, .. }) = host.calls().into_iter().find(|c| matches!(c, Call::Payload { .. })) else {
        panic!("no payload call")
    };
    assert_eq!(extra, Some(vec!["answer-standin.xml".to_string()]));
    let host = FakeHost::new();
    build_usb_with(
        &host,
        Path::new("/x/Win11.iso"),
        "sdb",
        &Fx::new().ctx(),
        &RecPriv::new(),
        false,
        Some(&IndexMap::new()),
    )
    .unwrap();
    let Some(Call::Payload { extra, .. }) = host.calls().into_iter().find(|c| matches!(c, Call::Payload { .. })) else {
        panic!("no payload call")
    };
    assert_eq!(extra, None);
}

#[test]
fn no_eject_leaves_the_windows_drive_connected() {
    let priv_ = RecPriv::new();
    let fx = Fx::new();
    assert!(
        !build_usb_with(&FakeHost::new(), Path::new("/x/Win11.iso"), "sdb", &fx.ctx(), &priv_, false, None).unwrap()
    );
    assert_eq!(kinds(&priv_), ["prep", "cleanup"]);
    assert!(fx.has("left connected"));
}

// ---------------------------------------------------------------------------------------------------------------
// The seed drive (LinuxSeedBackendTests)
// ---------------------------------------------------------------------------------------------------------------

const LABEL: &str = "EPMA-SEED";

struct Seed {
    host: FakeHost,
    files: Files,
}

fn seed_fixture() -> Seed {
    let mut host = FakeHost::new();
    host.copy_seed = Box::new(|dst, files, _| write_files(dst, files));
    host.verify_seed = Box::new(|dst, files, _| compare_files(dst, files));
    let files = files_of(&[
        ("user-data", b"#cloud-config\nautoinstall: {}\n"),
        ("meta-data", b""),
        ("sub/dir/harden-linux.sh", &[7u8; 5000]),
    ]);
    Seed { host, files }
}

fn run_seed(seed: &Seed, priv_: &RecPriv, fx: &Fx, eject: bool) -> Result<bool> {
    build_seed_usb_with(&seed.host, LABEL, &seed.files, Path::new("/stage"), "sdb", &fx.ctx(), priv_, eject)
}

/// A privilege for the seed flow: the eject script answers `EJECTED`; `prep_lines` are what the prep script prints;
/// `on_remount(args)` runs when the drive is remounted; `fail_on` makes that script fail.
fn seed_priv(
    prep_lines: &'static [&'static str],
    on_remount: impl Fn(&[String]) + Send + Sync + 'static,
    fail_on: &'static str,
) -> RecPriv {
    RecPriv::with(move |_, script, args, log| {
        if script == LINUX_SEED_PREP_SCRIPT {
            for line in prep_lines {
                log(line);
            }
        } else if script == LINUX_SEED_REMOUNT_SCRIPT {
            on_remount(args);
        } else if script == EJECT_SCRIPT {
            log("EJECTED");
        }
        if kind(script) == fail_on {
            return Err(Error::runtime("script failed (1)"));
        }
        Ok(())
    })
}

fn plain_seed_priv() -> RecPriv {
    seed_priv(&[], |_| {}, "")
}

fn drive_files(mount: &Path) -> IndexMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut IndexMap<String, Vec<u8>>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let rel = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
                out.insert(rel, std::fs::read(&path).unwrap());
            }
        }
    }
    let mut out = IndexMap::new();
    walk(mount, mount, &mut out);
    out
}

/// The mount directory the backend asked the host for.
fn seed_mount(seed: &Seed) -> PathBuf {
    seed.host
        .calls()
        .into_iter()
        .find_map(|c| match c {
            Call::CopySeed { dst } | Call::Rmdir(dst) => Some(dst),
            _ => None,
        })
        .expect("a mount directory")
}

#[test]
fn the_seed_success_copies_verifies_unmounts_and_ejects_in_order() {
    let seed = seed_fixture();
    let priv_ = plain_seed_priv();
    let fx = Fx::new();
    assert!(run_seed(&seed, &priv_, &fx, true).unwrap());
    assert_eq!(kinds(&priv_), ["seed-prep", "seed-remount", "seed-cleanup", "eject"]);
    let mount = seed_mount(&seed);
    assert!(mount.file_name().unwrap().to_string_lossy().starts_with("epmaseed_usb_"));
    assert_eq!(drive_files(&mount), seed.files);
    // copy, then the read-only remount, then the verification
    let order: Vec<&str> = seed
        .host
        .calls()
        .iter()
        .map(|c| match c {
            Call::CopySeed { .. } => "copy",
            Call::VerifySeed { .. } => "verify",
            Call::Rmdir(_) => "rmdir",
            _ => "other",
        })
        .collect();
    assert_eq!(order, ["copy", "verify", "rmdir"]);
    assert!(fx.has("Done! The seed drive is ready: plug it in next to the installer USB drive."));
    assert!(fx.has("Remounting the drive read-only to read it back from the device..."));
}

#[test]
fn the_seed_values_travel_only_as_positional_arguments() {
    let seed = seed_fixture();
    let priv_ = plain_seed_priv();
    run_seed(&seed, &priv_, &Fx::new(), true).unwrap();
    let recorded = priv_.recorded();
    let mnt = seed_mount(&seed).to_string_lossy().into_owned();
    let prep = &recorded[0].1;
    assert_eq!(&prep[..5], ["/dev/sdb", "/dev/sdb1", LABEL, &mnt, "1000:1000"]);
    assert!(prep[5].ends_with("cancel"), "the cancel flag is the sixth value");
    assert_eq!(recorded[1].1, ["/dev/sdb1", &mnt, "1000:1000"]);
    assert_eq!(recorded[2].1, [mnt.as_str()]);
    for (script, _) in &recorded {
        for value in prep {
            assert!(!script.contains(value.as_str()), "{value} is in a script");
        }
    }
}

#[test]
fn nvme_style_names_get_the_p_suffix_on_the_seed_drive() {
    let seed = seed_fixture();
    let priv_ = plain_seed_priv();
    build_seed_usb_with(&seed.host, LABEL, &seed.files, Path::new("/stage"), "nvme0n1", &Fx::new().ctx(), &priv_, true)
        .unwrap();
    assert_eq!(priv_.recorded()[0].1[..2], ["/dev/nvme0n1", "/dev/nvme0n1p1"]);
}

#[test]
fn every_script_runs_once_and_a_failing_one_is_never_rerun() {
    let seed = seed_fixture();
    let priv_ = seed_priv(&[], |_| {}, "seed-prep");
    let err = run_seed(&seed, &priv_, &Fx::new(), true).unwrap_err();
    assert!(err.to_string().contains("script failed"));
    // No retry. The cleanup (`umount ... || true`, harmless when nothing is mounted) runs once because the volume
    // is marked as mounted BEFORE the prep script runs: its last command is the mount, and an error or an
    // interrupt right after it must not leave the volume mounted.
    assert_eq!(kinds(&priv_), ["seed-prep", "seed-cleanup"]);
    assert!(!seed.host.calls().iter().any(|c| matches!(c, Call::CopySeed { .. })));
}

#[test]
fn a_verification_mismatch_blocks_the_eject_and_still_unmounts() {
    let seed = seed_fixture();
    let corrupt = |args: &[String]| {
        let path = Path::new(&args[1]).join("user-data");
        let mut data = std::fs::read(&path).unwrap();
        data[3] ^= 0xff;
        std::fs::write(path, data).unwrap();
    };
    let priv_ = seed_priv(&[], corrupt, "");
    let err = run_seed(&seed, &priv_, &Fx::new(), true).unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("Verification FAILED")
            && text.contains("user-data (content differs)")
            && text.contains("NOT ejected")
    );
    assert_eq!(kinds(&priv_), ["seed-prep", "seed-remount", "seed-cleanup"]);
}

#[test]
fn a_missing_file_and_a_truncated_file_are_caught_and_extra_files_are_not() {
    for (damage, text) in [
        (
            Box::new(|m: &Path| std::fs::remove_file(m.join("meta-data")).unwrap()) as Box<dyn Fn(&Path) + Send + Sync>,
            "meta-data (missing)",
        ),
        (Box::new(|m: &Path| std::fs::write(m.join("user-data"), b"").unwrap()), "user-data (size differs)"),
    ] {
        let seed = seed_fixture();
        let priv_ = seed_priv(&[], move |args| damage(Path::new(&args[1])), "");
        let err = run_seed(&seed, &priv_, &Fx::new(), true).unwrap_err();
        assert!(err.to_string().contains(text), "{err}");
        assert!(!kinds(&priv_).contains(&"eject"));
    }
    // system folders and other files the OS adds do not fail the check
    let seed = seed_fixture();
    let priv_ = seed_priv(&[], |args| std::fs::write(Path::new(&args[1]).join("extra.dat"), b"").unwrap(), "");
    assert!(run_seed(&seed, &priv_, &Fx::new(), true).unwrap());
}

#[test]
fn a_cancel_before_the_script_touches_the_drive() {
    let seed = seed_fixture();
    let priv_ = seed_priv(&[SEED_UNTOUCHED_MARKER], |_| {}, "");
    let fx = Fx::new();
    let err = run_seed(&seed, &priv_, &fx, true).unwrap_err();
    assert!(matches!(err, Error::Canceled { drive_touched: false, written: false, .. }));
    assert_eq!(err.to_string(), "Canceled by the user before the drive was touched.");
    assert_eq!(kinds(&priv_), ["seed-prep"]); // stopped before the mount: nothing to unmount
    assert!(fx.has("Canceled before the drive was touched; nothing was changed."));
    assert!(!fx.lines().iter().any(|l| l.contains("unusable")));
    assert!(!fx.has(SEED_UNTOUCHED_MARKER), "the marker is not echoed to the log");
}

#[test]
fn a_cancel_before_the_seed_backend_starts() {
    let seed = seed_fixture();
    let priv_ = plain_seed_priv();
    let fx = Fx::new();
    fx.cancel.set();
    let err = run_seed(&seed, &priv_, &fx, true).unwrap_err();
    assert!(matches!(err, Error::Canceled { drive_touched: false, .. }));
    assert_eq!(priv_.count(), 0);
    assert!(seed.host.calls().is_empty());
}

#[test]
fn a_cancel_after_the_script_wiped_the_drive() {
    let seed = seed_fixture();
    let priv_ = seed_priv(&[SEED_CANCELED_MARKER], |_| {}, "");
    let fx = Fx::new();
    let err = run_seed(&seed, &priv_, &fx, true).unwrap_err();
    assert!(err.drive_touched() && !err.written());
    assert!(fx.has("Canceled. The drive is left incomplete and unusable."));
    assert_eq!(kinds(&priv_), ["seed-prep"]); // stopped before mkfs and the mount
}

#[test]
fn a_cancel_while_copying_leaves_an_unusable_drive_and_unmounts() {
    let mut seed = seed_fixture();
    seed.host.copy_seed = Box::new(|_, _, _| Err(Error::canceled()));
    let priv_ = plain_seed_priv();
    let err = run_seed(&seed, &priv_, &Fx::new(), true).unwrap_err();
    assert!(err.drive_touched() && !err.written());
    assert_eq!(kinds(&priv_), ["seed-prep", "seed-cleanup"]);
}

#[test]
fn a_cancel_noticed_between_the_script_and_the_copy_is_a_cancel() {
    let seed = seed_fixture();
    let fx = Fx::new();
    let cancel = fx.cancel.clone();
    let priv_ = RecPriv::with(move |_, script, _, _| {
        if script == LINUX_SEED_PREP_SCRIPT {
            cancel.set();
        }
        Ok(())
    });
    let err = run_seed(&seed, &priv_, &fx, true).unwrap_err();
    assert!(err.drive_touched() && !err.written());
    assert_eq!(kinds(&priv_), ["seed-prep", "seed-cleanup"]);
    assert!(!seed.host.calls().iter().any(|c| matches!(c, Call::CopySeed { .. })));
}

#[test]
fn a_cancel_during_verification_says_written_but_not_verified() {
    let mut seed = seed_fixture();
    seed.host.verify_seed = Box::new(|_, _, _| Err(Error::canceled_with("Canceled by the user.", true, true)));
    let priv_ = plain_seed_priv();
    let fx = Fx::new();
    let err = run_seed(&seed, &priv_, &fx, true).unwrap_err();
    assert!(err.written());
    assert_eq!(kinds(&priv_), ["seed-prep", "seed-remount", "seed-cleanup"]);
    assert!(fx.has("NOT verified"));
}

#[test]
fn no_eject_leaves_the_seed_drive_connected() {
    let seed = seed_fixture();
    let priv_ = plain_seed_priv();
    let fx = Fx::new();
    assert!(!run_seed(&seed, &priv_, &fx, false).unwrap());
    assert!(!kinds(&priv_).contains(&"eject"));
    assert!(fx.has("left connected"));
}

#[test]
fn a_failing_seed_cleanup_is_only_a_warning() {
    let seed = seed_fixture();
    let priv_ = seed_priv(&[], |_| {}, "seed-cleanup");
    let fx = Fx::new();
    assert!(run_seed(&seed, &priv_, &fx, true).unwrap());
    assert!(fx.lines().iter().any(|l| l.starts_with("Warning: cleanup failed")));
}

#[test]
fn the_seed_mount_directory_is_removed() {
    let seed = seed_fixture();
    run_seed(&seed, &plain_seed_priv(), &Fx::new(), true).unwrap();
    let mount = seed_mount(&seed);
    assert!(seed.host.calls().contains(&Call::Rmdir(mount)));
}

#[test]
fn the_seed_progress_goes_to_the_copy_and_the_verification() {
    // The backend hands its own context (log, progress, cancel) to copy_seed_files and verify_seed_files.
    let mut seed = seed_fixture();
    seed.host.copy_seed = Box::new(|_, _, ctx| {
        ctx.report(0, 10, "Copying files...");
        Ok(())
    });
    seed.host.verify_seed = Box::new(|_, _, ctx| {
        ctx.report(10, 10, "Verifying the copied files...");
        Ok(())
    });
    let fx = Fx::new();
    run_seed(&seed, &plain_seed_priv(), &fx, false).unwrap();
    assert_eq!(fx.progress_texts(), ["Copying files...", "Verifying the copied files..."]);
}

// ---------------------------------------------------------------------------------------------------------------
// The scripts are data
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn the_scripts_are_byte_identical_to_the_python_ones() {
    // The digests recorded in tests/test_hardening_engine_windows.py (EXPECTED).
    assert_eq!(sha(WINDOWS_PREP_SCRIPT), "2fe84953fae7ab72da1faac2dd1ecd5a2c4ab6e43e081e92cc00e8301cc978e1");
    assert_eq!(sha(WINDOWS_REMOUNT_SCRIPT), "8b1af16122857c13763d3ffc45d0eb3090b8011491cc0d74cf04ee5210b89fef");
    assert_eq!(sha(WINDOWS_CLEANUP_SCRIPT), "19e8a5a771a7c18a04ce5b2169643d4dde6bb55c452fadd74af409d5035d6935");
    assert_eq!(sha(LINUX_RAW_SCRIPT), "c2bb23050148228cc18ed4433f162e49870cdc0640ecf7629dc53833f9ac9750");
}

#[test]
fn every_script_is_strict_and_the_cancel_aware_ones_ignore_ctrl_c() {
    for (name, script) in [
        ("raw", LINUX_RAW_SCRIPT),
        ("seed-prep", LINUX_SEED_PREP_SCRIPT),
        ("seed-remount", LINUX_SEED_REMOUNT_SCRIPT),
        ("seed-cleanup", LINUX_SEED_CLEANUP_SCRIPT),
    ] {
        assert!(script.starts_with("set -eu\ntrap '' INT\n"), "{name}");
    }
    for script in
        [WINDOWS_PREP_SCRIPT, WINDOWS_REMOUNT_SCRIPT, WINDOWS_CLEANUP_SCRIPT, EJECT_SCRIPT, UNMOUNT_PARTITIONS_SCRIPT]
    {
        assert!(script.starts_with("set -eu\n"));
    }
    assert!(!LINUX_RAW_SCRIPT.contains("SEED"));
}

#[test]
fn the_iso_is_mounted_with_an_explicit_udf_then_iso9660_type() {
    let typed = r#"mount -t udf,iso9660 -o loop,ro,uid="${OWNER%%:*}",gid="${OWNER##*:}" "$ISO" "$ISO_MNT""#;
    let untyped = r#"mount -o loop,ro,uid="${OWNER%%:*}",gid="${OWNER##*:}" "$ISO" "$ISO_MNT""#;
    let (a, b) = (
        WINDOWS_PREP_SCRIPT.find(typed).expect("typed mount"),
        WINDOWS_PREP_SCRIPT.find(untyped).expect("untyped mount"),
    );
    assert!(a < b, "autodetection stays as the last resort");
    // the volume label is a constant of the program, not a value: it is in the text exactly once
    assert_eq!(WINDOWS_PREP_SCRIPT.matches(crate::constants::VOL_NAME).count(), 1);
}

#[test]
fn the_seed_label_reaches_mkfs_as_a_positional_argument() {
    assert!(LINUX_SEED_PREP_SCRIPT.contains(r#"LABEL="$3""#));
    assert!(LINUX_SEED_PREP_SCRIPT.contains(r#"mkfs.vfat -F 32 -n "$LABEL" "$PART""#));
    for label in ["CIDATA", "OEMDRV", "EPMA-SEED"] {
        assert!(!LINUX_SEED_PREP_SCRIPT.contains(label));
    }
    assert!(!LINUX_SEED_PREP_SCRIPT.contains(" esp "), "no EFI system partition flag on a data drive");
}

#[test]
fn the_cancel_flag_is_checked_before_anything_destructive() {
    let script = LINUX_SEED_PREP_SCRIPT;
    let at = |needle: &str| script.find(needle).unwrap_or_else(|| panic!("{needle} missing"));
    assert!(at(r#"[ -e "$FLAG" ]"#) < at("wipefs"));
    assert!(at("SEED_CANCELED") < at("mkfs.vfat"));
    assert!(at("wipefs") < at("SEED_CANCELED"));
}

#[test]
fn the_markers_match_the_prep_script() {
    assert_eq!(SEED_UNTOUCHED_MARKER, "SEED_NOT_TOUCHED");
    assert_eq!(SEED_CANCELED_MARKER, "SEED_CANCELED");
    assert!(LINUX_SEED_PREP_SCRIPT.contains(&format!("echo {SEED_UNTOUCHED_MARKER};")));
    assert!(LINUX_SEED_PREP_SCRIPT.contains(&format!("echo {SEED_CANCELED_MARKER};")));
}

#[cfg(unix)]
mod script_runs {
    use super::*;
    use crate::macos::testkit::script::*;

    #[test]
    fn every_script_is_valid_shell() {
        if !have_bash() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        for (i, script) in [
            LINUX_RAW_SCRIPT,
            LINUX_SEED_PREP_SCRIPT,
            LINUX_SEED_REMOUNT_SCRIPT,
            LINUX_SEED_CLEANUP_SCRIPT,
            WINDOWS_PREP_SCRIPT,
            WINDOWS_REMOUNT_SCRIPT,
            WINDOWS_CLEANUP_SCRIPT,
            EJECT_SCRIPT,
            UNMOUNT_PARTITIONS_SCRIPT,
        ]
        .into_iter()
        .enumerate()
        {
            let path = dir.path().join(format!("s{i}.sh"));
            std::fs::write(&path, script).unwrap();
            let out = std::process::Command::new("bash").arg("-n").arg(&path).output().unwrap();
            assert!(out.status.success(), "script {i}: {}", String::from_utf8_lossy(&out.stderr));
        }
    }

    #[test]
    fn the_linux_raw_script_survives_ctrl_c_and_stops_dd_through_the_flag() {
        if !have_bash() {
            return;
        }
        let stubs = Stubs::new();
        let args = vec![
            stubs.path("in.iso"),
            stubs.path("out.img"),
            "4M".to_string(),
            stubs.flag.to_string_lossy().into_owned(),
            "buffered".to_string(),
        ];
        stubs.check_raw_script(LINUX_RAW_SCRIPT, &args);
    }

    fn trace_stubs(dir: &Path, tools: &[&str], trace: &Path) -> PathBuf {
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        for tool in tools {
            write_stub(&bin, tool, &format!("#!/bin/sh\necho \"{tool} $*\" >> \"{}\"\n", trace.display()));
        }
        bin
    }

    #[test]
    fn a_requested_cancel_stops_the_real_prep_script_before_any_tool_runs() {
        if !have_bash() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let trace = dir.path().join("trace");
        let bin = trace_stubs(
            dir.path(),
            &["wipefs", "parted", "partprobe", "mkfs.vfat", "mount", "umount", "udevadm"],
            &trace,
        );
        let flag = dir.path().join("cancel");
        std::fs::File::create(&flag).unwrap();
        let args = strs(&[
            &dir.path().join("fakedev").to_string_lossy(),
            &dir.path().join("fakedev1").to_string_lossy(),
            "CIDATA",
            &dir.path().join("mnt").to_string_lossy(),
            "0:0",
            &flag.to_string_lossy(),
        ]);
        let (code, stdout, stderr) = run_script(LINUX_SEED_PREP_SCRIPT, &args, &bin);
        assert_eq!(code, Some(0), "{stderr}");
        assert_eq!(stdout.trim(), SEED_UNTOUCHED_MARKER);
        assert!(!trace.exists(), "a tool ran although the cancel flag was already set");
    }

    #[test]
    fn the_prep_script_runs_the_tools_in_order_when_not_canceled() {
        if !have_bash() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let trace = dir.path().join("trace");
        let bin = trace_stubs(
            dir.path(),
            &["wipefs", "parted", "partprobe", "mkfs.vfat", "mount", "umount", "udevadm", "sleep"],
            &trace,
        );
        // `[ -b "$PART" ]` needs a block device. /dev/null is a character device, so the partition check fails: the
        // script must stop there (exit 1) AFTER wipefs/parted/partprobe, BEFORE mkfs.vfat.
        let args = strs(&[
            &dir.path().join("fakedev").to_string_lossy(),
            "/dev/null",
            "CIDATA",
            &dir.path().join("mnt").to_string_lossy(),
            "0:0",
            &dir.path().join("no-such-flag").to_string_lossy(),
        ]);
        let (code, stdout, stderr) = run_script(LINUX_SEED_PREP_SCRIPT, &args, &bin);
        assert_eq!(code, Some(1));
        assert!(format!("{stdout}{stderr}").contains("did not appear"));
        let tools: Vec<String> = std::fs::read_to_string(&trace)
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.split_whitespace().next().unwrap().to_string())
            .collect();
        let pos = |t: &str| tools.iter().position(|x| x == t).unwrap_or_else(|| panic!("{t} did not run: {tools:?}"));
        assert!(pos("wipefs") < pos("parted") && pos("parted") < pos("partprobe"));
        assert!(!tools.contains(&"mkfs.vfat".to_string()) && !tools.contains(&"mount".to_string()));
    }

    #[test]
    fn the_windows_prep_script_stops_when_the_partition_never_appears() {
        if !have_bash() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let trace = dir.path().join("trace");
        let bin = trace_stubs(
            dir.path(),
            &["wipefs", "parted", "partprobe", "mkfs.vfat", "mount", "umount", "udevadm", "sleep"],
            &trace,
        );
        let args = strs(&[
            &dir.path().join("fakedev").to_string_lossy(),
            "/dev/null",
            "/x/Win11.iso",
            &dir.path().join("iso").to_string_lossy(),
            &dir.path().join("usb").to_string_lossy(),
            "0:0",
        ]);
        let (code, stdout, stderr) = run_script(WINDOWS_PREP_SCRIPT, &args, &bin);
        assert_eq!(code, Some(1));
        assert!(format!("{stdout}{stderr}").contains("did not appear"));
        let log = std::fs::read_to_string(&trace).unwrap();
        assert!(log.contains("wipefs -a") && log.contains("mklabel gpt") && log.contains("set 1 esp on"));
        assert!(!log.contains("mkfs.vfat"), "the format must not run on a missing partition");
    }
}
