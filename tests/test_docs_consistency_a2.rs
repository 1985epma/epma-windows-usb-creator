//! Port of `test_the_code_really_behaves_that_way` of tests/test_docs_consistency.py (what the documents say about
//! the sudo password is what PrivilegeHelper does: dropped in timestamp mode, kept only until clear_cached_password in
//! the stdin fallback, never on a command line or in a log), plus the flows of PrivilegeHelper the Python suite
//! exercises only indirectly (the password prompts, the retry rules, `sudo -n` / `sudo -S` argv shapes, pkexec).
//! The system is faked through `SudoSys`; the prompt through `PasswordPrompt` (the window's dialog).

mod common_a2;

use common_a2::*;
use epma_usb_creator::audit::AuditLevel;
use epma_usb_creator::engine::capture_audit;
use epma_usb_creator::privilege::PrivilegeHelper;
use epma_usb_creator::types::{Error, Privilege};
use std::sync::Arc;

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// sudo as the tests need it: `accept` is the one password it takes; `timestamp_works` says whether a fresh `sudo -n`
/// is accepted after `sudo -S -v` (false: the stdin fallback mode).
fn sudo(accept: &'static str, timestamp_works: bool) -> FakeSys {
    let mut sys = FakeSys::new();
    sys.quiet = Box::new(move |argv, input| {
        let has = |flag: &str| argv.iter().any(|a| a == flag);
        if has("-k") && !has("-S") {
            return Some(0); // `sudo -k`
        }
        if has("-S") {
            // `sudo -S -k -p "" true` (validate) or `sudo -S -v -p ""` (arm): the password is on stdin
            return Some(if input == Some(&format!("{accept}\n")) { 0 } else { 1 });
        }
        if has("-n") {
            return Some(if timestamp_works { 0 } else { 1 }); // `sudo -n -v`: is the timestamp shared?
        }
        Some(1)
    });
    sys
}

fn helper(sys: &Arc<FakeSys>, prompt: &Arc<FakePrompt>) -> PrivilegeHelper {
    PrivilegeHelper::with_sys(prompt.clone(), sys.clone())
}

#[test]
fn timestamp_mode_drops_the_password() {
    let sys = Arc::new(sudo("secret", true));
    let prompt = FakePrompt::with_answers(&[Some("secret")]);
    let h = helper(&sys, &prompt);
    assert!(h.authenticate("Why not").unwrap());
    assert!(h.uses_timestamp());
    assert!(!h.has_cached_password(), "the password string is dropped once sudo's timestamp is armed");
    h.clear_cached_password();
    assert!(!h.uses_timestamp());
}

#[test]
fn fallback_mode_keeps_the_password_until_it_is_cleared() {
    let sys = Arc::new(sudo("secret", false));
    let prompt = FakePrompt::with_answers(&[Some("secret")]);
    let h = helper(&sys, &prompt);
    assert!(h.authenticate("Why not").unwrap());
    assert!(!h.uses_timestamp());
    assert!(h.has_cached_password());
    h.clear_cached_password();
    assert!(!h.has_cached_password());
    // there was no timestamp to end: no `sudo -k`
    assert!(!sys.quiet_argvs().iter().any(|a| a == &strings(&["sudo", "-k"])));
}

#[test]
fn the_password_goes_to_stdin_only_never_to_argv_or_the_log() {
    let sys = Arc::new(sudo("secret", false));
    let prompt = FakePrompt::with_answers(&[Some("secret")]);
    let h = helper(&sys, &prompt);
    assert!(h.authenticate("x").unwrap());
    let sink = Sink::new();
    h.run_script("set -eu\ntrue\n", sink.log(), &strings(&["/dev/sdb", "5"])).unwrap();

    for argv in sys.quiet_argvs() {
        assert!(!argv.iter().any(|a| a.contains("secret")), "{argv:?}");
    }
    let streaming = sys.streaming();
    let (argv, stdin) = &streaming[0];
    assert_eq!(argv[..4], ["sudo", "-S", "-p", ""], "the fallback reads the password from stdin");
    assert_eq!(argv[4..8], ["bash", "-c", "set -eu\ntrue\n", "win11_usb_creator"]);
    assert_eq!(argv[8..], ["/dev/sdb", "5"]);
    assert!(!argv.iter().any(|a| a.contains("secret")));
    assert_eq!(stdin, "text:secret\n");
    assert!(!sink.text().contains("secret"));
    // and the checks only ever saw it on stdin
    let inputs: Vec<Option<String>> = sys
        .calls()
        .into_iter()
        .filter_map(|c| if let SysCall::Quiet { input, .. } = c { Some(input) } else { None })
        .collect();
    assert!(inputs.contains(&Some("secret\n".to_string())));
}

#[test]
fn the_checks_use_the_documented_commands() {
    let sys = Arc::new(sudo("secret", true));
    let prompt = FakePrompt::with_answers(&[Some("secret")]);
    helper(&sys, &prompt).authenticate("x").unwrap();
    assert_eq!(
        sys.quiet_argvs(),
        vec![
            // -k: a cached credential must not make a wrong password look right
            strings(&["sudo", "-S", "-k", "-p", "", "true"]),
            // arm the timestamp, then prove a fresh `sudo -n` shares it
            strings(&["sudo", "-S", "-v", "-p", ""]),
            strings(&["sudo", "-n", "-v"]),
        ]
    );
}

#[test]
fn an_empty_password_is_never_sent_to_sudo() {
    let sys = Arc::new(sudo("secret", true));
    let h = helper(&sys, &FakePrompt::with_answers(&[]));
    assert!(!h.check_password(""));
    assert!(sys.calls().is_empty());
    assert!(h.check_password("secret"));
    assert!(!h.check_password("other"));
}

// ---------------------------------------------------------------------------------------------------------------
// authenticate (up front, GUI thread)
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn a_wrong_password_is_reported_and_asked_again() {
    let sys = Arc::new(sudo("good", true));
    let prompt = FakePrompt::with_answers(&[Some("bad"), Some("good")]);
    let h = helper(&sys, &prompt);
    assert!(h.authenticate("To partition the drive").unwrap());
    assert_eq!(
        *prompt.errors.lock().unwrap(),
        [("Wrong password".to_string(), "That password was not accepted. Please try again.".to_string())]
    );
    let asked = prompt.asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 2);
    assert_eq!(asked[0].0, "Administrator password");
    assert_eq!(
        asked[0].1,
        "To partition the drive\n\nEnter your administrator (sudo) password.\nIt is used only to run local disk commands and is never stored or sent anywhere."
    );
}

#[test]
fn three_wrong_passwords_give_up_with_nothing_changed() {
    let sys = Arc::new(sudo("good", true));
    let prompt = FakePrompt::with_answers(&[Some("a"), Some("b"), Some("c"), Some("good")]);
    let h = helper(&sys, &prompt);
    assert!(!h.authenticate("x").unwrap());
    assert_eq!(prompt.asked.lock().unwrap().len(), 3, "the fourth answer is never asked for");
    let errors = prompt.errors.lock().unwrap().clone();
    assert_eq!(
        errors,
        [
            ("Wrong password".to_string(), "That password was not accepted. Please try again.".to_string()),
            ("Wrong password".to_string(), "That password was not accepted. Please try again.".to_string()),
            ("Wrong password".to_string(), "Too many incorrect attempts. Nothing was changed.".to_string()),
        ]
    );
    assert!(!h.uses_timestamp() && !h.has_cached_password());
}

#[test]
fn a_canceled_prompt_returns_false_and_shows_nothing() {
    let sys = Arc::new(sudo("good", true));
    let prompt = FakePrompt::with_answers(&[None]);
    let h = helper(&sys, &prompt);
    assert!(!h.authenticate("x").unwrap());
    assert!(prompt.errors.lock().unwrap().is_empty());
    assert!(sys.calls().is_empty(), "sudo was never asked");
}

#[test]
fn nothing_is_asked_when_no_password_is_needed() {
    // root: scripts run directly
    let mut sys = FakeSys::new();
    sys.root = true;
    let prompt = FakePrompt::with_answers(&[]);
    let h = PrivilegeHelper::with_sys(prompt.clone(), Arc::new(sys));
    assert!(!h.needs_password());
    assert!(h.authenticate("x").unwrap());
    // no sudo installed: pkexec will show its own prompt
    let mut sys = FakeSys::new();
    sys.tools = vec!["pkexec"];
    let h = PrivilegeHelper::with_sys(prompt.clone(), Arc::new(sys));
    assert!(!h.needs_password());
    assert!(h.authenticate("x").unwrap());
    assert!(prompt.asked.lock().unwrap().is_empty());
    // sudo installed and not root: a password is needed
    let h = PrivilegeHelper::with_sys(prompt.clone(), Arc::new(FakeSys::new()));
    assert!(h.needs_password());
}

// ---------------------------------------------------------------------------------------------------------------
// run_script
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn a_script_runs_with_sudo_n_in_timestamp_mode_and_asks_only_once() {
    let sys = Arc::new(sudo("secret", true));
    let prompt = FakePrompt::with_answers(&[Some("secret")]);
    let h = helper(&sys, &prompt);
    let sink = Sink::new();
    h.run_script("set -eu\ntrue\n", sink.log(), &strings(&["a b", "it's"])).unwrap(); // asks (nobody authenticated yet)
    h.run_script("set -eu\ntrue\n", sink.log(), &[]).unwrap(); // the timestamp carries it
    assert_eq!(prompt.asked.lock().unwrap().len(), 1);
    let streaming = sys.streaming();
    assert_eq!(streaming.len(), 2);
    assert_eq!(streaming[0].0[..2], ["sudo", "-n"]);
    assert_eq!(streaming[0].0[2..6], ["bash", "-c", "set -eu\ntrue\n", "win11_usb_creator"]);
    assert_eq!(streaming[0].0[6..], ["a b", "it's"]);
    assert_eq!(streaming[0].1, "null", "nothing on stdin");
    assert_eq!(sink.lines()[0], "$ sudo bash -c '<privileged script>' 'a b' \"it's\"");
    h.clear_cached_password();
}

#[test]
fn an_expired_timestamp_asks_again() {
    let mut sys = sudo("secret", true);
    // the timestamp is valid for the arming probe, then it "expires"
    let probes = std::sync::atomic::AtomicUsize::new(0);
    let inner = sys.quiet;
    sys.quiet = Box::new(move |argv, input| {
        if argv.iter().any(|a| a == "-n") && probes.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 1 {
            return Some(1);
        }
        inner(argv, input)
    });
    let sys = Arc::new(sys);
    let prompt = FakePrompt::with_answers(&[Some("secret"), Some("secret")]);
    let h = helper(&sys, &prompt);
    assert!(h.authenticate("x").unwrap());
    h.run_script("true", &|_| {}, &[]).unwrap();
    assert_eq!(prompt.asked.lock().unwrap().len(), 2, "the second prompt is the one of run_script");
    h.clear_cached_password();
}

#[test]
fn a_failed_script_is_never_run_again() {
    let mut sys = sudo("secret", true);
    sys.stream_exit = 7;
    let sys = Arc::new(sys);
    let prompt = FakePrompt::with_answers(&[Some("secret")]);
    let h = helper(&sys, &prompt);
    let (result, audits) = capture_audit(|| h.run_script("exit 7", &|_| {}, &[]));
    let err = result.unwrap_err();
    assert!(matches!(err, Error::Runtime(_)));
    assert_eq!(
        err.to_string(),
        "Privileged command failed (exit code 7). It was not run again; check the log above for the reason."
    );
    assert_eq!(sys.streaming().len(), 1);
    assert!(audits
        .iter()
        .any(|(m, l)| m == "Privileged script failed (exit 7); not retried" && *l == AuditLevel::Error));
    h.clear_cached_password();
}

#[test]
fn an_expired_session_is_reported_as_such_and_forgotten() {
    let mut sys = sudo("secret", true);
    sys.stream_exit = 1;
    sys.stream_lines = vec!["sudo: a password is required".to_string()];
    let sys = Arc::new(sys);
    let prompt = FakePrompt::with_answers(&[Some("secret")]);
    let h = helper(&sys, &prompt);
    let err = h.run_script("true", &|_| {}, &[]).unwrap_err();
    assert!(err.to_string().contains("The administrator session expired before the command started"), "{err}");
    assert!(!h.uses_timestamp());
    assert_eq!(sys.streaming().len(), 1, "not retried");
    h.clear_cached_password();
}

#[test]
fn password_entry_can_be_canceled_while_a_script_waits() {
    let sys = Arc::new(sudo("secret", true));
    let prompt = FakePrompt::with_answers(&[None]);
    let h = helper(&sys, &prompt);
    let err = h.run_script("true", &|_| {}, &[]).unwrap_err();
    assert_eq!(err.to_string(), "Administrator password entry canceled.");
    assert!(sys.streaming().is_empty());
}

#[test]
fn a_script_gives_up_after_three_wrong_passwords() {
    let sys = Arc::new(sudo("secret", true));
    let prompt = FakePrompt::with_answers(&[Some("a"), Some("b"), Some("c")]);
    let h = helper(&sys, &prompt);
    let err = h.run_script("true", &|_| {}, &[]).unwrap_err();
    assert_eq!(err.to_string(), "The administrator password was not accepted after 3 attempts. Nothing was changed.");
    let asked = prompt.asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 3);
    assert!(!asked[0].1.starts_with("That password was not accepted."));
    assert!(asked[1]
        .1
        .starts_with("That password was not accepted. Try again.\n\nEnter your sudo/administrator password"));
    assert!(sys.streaming().is_empty());
}

#[test]
fn without_sudo_pkexec_is_used_and_without_either_it_is_an_error() {
    // pkexec shows its own prompt
    let mut sys = FakeSys::new();
    sys.tools = vec!["pkexec"];
    let sys = Arc::new(sys);
    let h = PrivilegeHelper::with_sys(FakePrompt::with_answers(&[]), sys.clone());
    h.run_script("set -eu\ntrue\n", &|_| {}, &strings(&["x"])).unwrap();
    assert_eq!(
        sys.calls(),
        vec![SysCall::Logged { argv: strings(&["pkexec", "bash", "-c", "set -eu\ntrue\n", "win11_usb_creator", "x"]) }]
    );
    // neither
    let mut sys = FakeSys::new();
    sys.tools = vec![];
    let h = PrivilegeHelper::with_sys(FakePrompt::with_answers(&[]), Arc::new(sys));
    let err = h.run_script("true", &|_| {}, &[]).unwrap_err();
    assert!(err.to_string().starts_with("Neither 'sudo' nor 'pkexec' was found."), "{err}");
}

#[test]
fn as_root_the_script_runs_without_sudo() {
    let mut sys = FakeSys::new();
    sys.root = true;
    let sys = Arc::new(sys);
    let h = PrivilegeHelper::with_sys(FakePrompt::with_answers(&[]), sys.clone());
    h.run_script("set -eu\ntrue\n", &|_| {}, &strings(&["x"])).unwrap();
    let streaming = sys.streaming();
    assert_eq!(streaming[0].0, strings(&["bash", "-c", "set -eu\ntrue\n", "win11_usb_creator", "x"]));
    assert_eq!(streaming[0].1, "null");
}
