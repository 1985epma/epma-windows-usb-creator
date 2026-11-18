//! Port of CliPrivilegeTests of tests/test_cli.py (the command line's privilege helper). The rest of test_cli.py is
//! the command line itself (A7). The Python tests patch `os.geteuid`, `shutil.which` and `subprocess`; here the same
//! system calls are replaced through `SudoSys` (see tests/common_a2).

mod common_a2;

use common_a2::*;
use epma_usb_creator::copyverify::verify_raw_write_chunked;
use epma_usb_creator::privilege::CliPrivilege;
use epma_usb_creator::types::{Error, Privilege};
use std::fs;
use std::sync::Arc;
use std::time::Duration;

fn as_root() -> CliPrivilege {
    CliPrivilege::with_sys(Arc::new(RootSys))
}

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn interface_matches_what_the_engine_uses() {
    let priv_ = CliPrivilege::new();
    assert!(!priv_.needs_password(), "sudo owns the credential: nothing to collect");
    priv_.clear_cached_password();
    priv_.clear_cached_password();
}

#[test]
fn root_runs_scripts_directly_with_positional_arguments() {
    if !have("bash") {
        return;
    }
    let tmp = Tmp::new();
    let sink = Sink::new();
    let marker = tmp.path("marker with spaces; $(id)");
    as_root()
        .run_script(
            "set -eu\nprintf \"%s|%s\" \"$1\" \"$2\" > \"$3\"\necho done\n",
            sink.log(),
            &args(&["a b", "$(whoami)", &marker.to_string_lossy()]),
        )
        .unwrap();
    assert_eq!(fs::read_to_string(&marker).unwrap(), "a b|$(whoami)"); // data, never code
    assert!(sink.lines().contains(&"done".to_string()));
    // the log line shows the arguments with Python's repr and never the script
    let first = &sink.lines()[0];
    assert!(first.starts_with("$ bash -c '<privileged script>' 'a b' '$(whoami)' '"), "{first}");
    assert!(!first.contains("printf"));
}

#[test]
fn failure_is_reported_and_never_retried() {
    if !have("bash") {
        return;
    }
    let tmp = Tmp::new();
    let counter = tmp.path("runs");
    let script = "set -eu\necho x >> \"$1\"\nexit 7\n";
    let err = as_root().run_script(script, &|_| {}, &args(&[&counter.to_string_lossy()])).unwrap_err();
    assert!(matches!(err, Error::Runtime(_)));
    assert_eq!(err.to_string(), "Privileged command failed (exit code 7). Check the messages above.");
    assert_eq!(fs::read_to_string(&counter).unwrap().matches('x').count(), 1);
}

#[test]
fn non_root_goes_through_sudo_with_the_same_argv_shape() {
    let mut sys = FakeSys::new();
    sys.stream_lines = vec!["line one".to_string()];
    let sys = Arc::new(sys);
    let priv_ = CliPrivilege::with_sys(sys.clone());
    let sink = Sink::new();
    priv_.run_script("set -eu\ntrue\n", sink.log(), &args(&["/dev/sdb", "5"])).unwrap();
    let streaming = sys.streaming();
    assert_eq!(streaming.len(), 1);
    let (argv, stdin) = &streaming[0];
    assert_eq!(argv[..4], ["sudo", "bash", "-c", "set -eu\ntrue\n"]);
    assert_eq!(argv[4..], ["win11_usb_creator", "/dev/sdb", "5"]);
    assert_eq!(stdin, "inherit"); // inherited: sudo prompts on the terminal
    assert!(sink.lines().contains(&"line one".to_string()));
    assert_eq!(sink.lines()[0], "$ sudo bash -c '<privileged script>' '/dev/sdb' '5'");
}

#[test]
fn authenticate_without_sudo() {
    let mut sys = FakeSys::new();
    sys.tools = vec![];
    let err = CliPrivilege::with_sys(Arc::new(sys)).authenticate("x").unwrap_err();
    assert!(matches!(err, Error::Runtime(_)));
    assert!(err.to_string().contains("sudo"), "{err}");
    assert_eq!(
        err.to_string(),
        "Administrator privileges are required but 'sudo' was not found. Run this command as root or install sudo."
    );
}

#[test]
fn authenticate_refused_by_sudo() {
    let mut sys = FakeSys::new();
    sys.inherit = 1;
    let sys = Arc::new(sys);
    let err = CliPrivilege::with_sys(sys.clone()).authenticate("x").unwrap_err();
    assert!(err.to_string().contains("administrator privileges"), "{err}");
    assert_eq!(err.to_string(), "Could not obtain administrator privileges (sudo refused). Nothing was changed.");
    assert_eq!(sys.calls(), vec![SysCall::Inherit { argv: args(&["sudo", "-v"]) }]);
}

#[test]
fn authenticate_as_root_does_nothing() {
    // as_root's fake would answer 0 to everything; the point is that nothing is asked at all
    let priv_ = as_root();
    assert!(priv_.authenticate("x").unwrap());
    assert!(!priv_.keepalive_running());
}

#[test]
fn keepalive_starts_after_authentication_and_stops() {
    let sys = Arc::new(FakeSys::new());
    let priv_ = CliPrivilege::with_sys(sys.clone());
    assert!(priv_.authenticate("x").unwrap());
    assert!(priv_.keepalive_running());
    // a second authentication does not start a second thread
    assert!(priv_.authenticate("x").unwrap());
    priv_.clear_cached_password();
    assert!(priv_.join_keepalive(Duration::from_secs(5)), "the keep-alive thread must end");
    assert!(!priv_.keepalive_running());
}

#[test]
fn privileged_script_runs_with_the_real_cli_engine_path() {
    // CliPrivilege plugs into verify_raw_write like the window's helper does
    if !have("bash") || !have("cmp") {
        return;
    }
    let tmp = Tmp::new();
    let iso = tmp.make_iso("image.iso", MIB + 123, true);
    let data = fs::read(&iso).unwrap();
    let device = tmp.write("device.img", &data);
    let sink = Sink::new();
    let priv_ = as_root();
    let device_arg = device.to_string_lossy().into_owned();
    verify_raw_write_chunked(&iso, &device_arg, &sink.ctx_no_progress(None), &priv_, 16 * MIB as u64, &|| 0.0).unwrap();
    assert!(sink.has_line_containing("Verification passed"));
    let mut flipped = data.clone();
    flipped[MIB] ^= 0xFF; // always differs
    fs::write(&device, flipped).unwrap();
    let err =
        verify_raw_write_chunked(&iso, &device_arg, &sink.ctx_no_progress(None), &priv_, 16 * MIB as u64, &|| 0.0)
            .unwrap_err();
    assert!(err.to_string().contains("Verification FAILED"), "{err}");
}
