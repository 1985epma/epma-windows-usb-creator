//! `write` and `harden-seed`: validate everything and build the plan (touching nothing), print it, ask for the typed
//! confirmation, then run the destructive engine call with Ctrl-C, privileges and exit codes handled the way the
//! Python `_prepare_write`, `_prepare_seed`, `_confirm_write`, `_run_write`, `cmd_write` and `cmd_harden_seed` do.

use super::commands::{cli_detect_kind, list_disks};
use super::harden::{hardening_file_names, hardening_files};
use super::io::{json_dumps, obj, CliLogger, Env, J};
use super::parser::{FilesKind, SeedArgs, WriteArgs, WriteFlags, HARDENED_WINDOWS_ONLY};
use super::plan::{print_plan, seed_steps, write_steps, DiskSummary, Plan};
use super::{
    normalize_typed_identifier, CliError, Failure, EXIT_EJECT_FAILED, EXIT_ERROR, EXIT_INTERRUPTED, EXIT_OK,
    EXIT_USAGE, EXIT_VERIFY_FAILED,
};
use crate::audit::AuditLevel;
use crate::constants::IS_WINDOWS;
use crate::types::{BuildOptions, CancelToken, Ctx, Disk, Error, Hardening, Mode, Privilege};
use crate::util::human_size;
use crate::validate::dev_path;
use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Message of the engine's "Verification FAILED" / "could not complete the verification" errors.
fn is_verification_failure(text: &str) -> bool {
    let text = text.to_lowercase();
    text.contains("verification failed") || text.contains("could not complete the verification")
}

/// True for the engine's refusal when the ISO already holds one of the hardening files (nothing was touched).
fn is_hardening_conflict(err: &Error) -> bool {
    matches!(err, Error::Value(m) if m.to_lowercase().contains("already contain"))
}

fn not_eligible(disk_id: &str) -> CliError {
    CliError::new(format!(
        "{} is not an eligible USB drive. Run '{} list' to see the drives that can be written.",
        dev_path(disk_id),
        super::CLI_PROG
    ))
}

fn value_to_cli(err: Error) -> CliError {
    CliError::new(err.to_string())
}

fn missing_tools(env: &Env, mode: Mode) -> Option<CliError> {
    let missing = env.engine.get_missing_dependencies(mode);
    (!missing.is_empty()).then(|| {
        CliError::new(format!(
            "Missing required tools: {}. {}",
            missing.join(", "),
            env.engine.missing_dependencies_hint(&missing)
        ))
    })
}

fn find_disk(disks: Vec<Disk>, disk_id: &str) -> Result<Disk, CliError> {
    disks.into_iter().find(|d| d.id == disk_id).ok_or_else(|| not_eligible(disk_id))
}

/// Validate everything for `write` and build the plan. Touches nothing.
pub fn prepare_write(env: &Env, args: &WriteArgs) -> Result<Plan, CliError> {
    let engine = &*env.engine;
    if args.hardened && !matches!(args.mode, Mode::Auto | Mode::Windows) {
        return Err(CliError::with_code(HARDENED_WINDOWS_ONLY, EXIT_USAGE));
    }
    let iso = engine.validate_iso_path(&args.iso).map_err(value_to_cli)?;
    let disk_id = engine.validate_device_name(&normalize_typed_identifier(&args.disk)).map_err(value_to_cli)?;
    let disk = find_disk(list_disks(env)?, &disk_id)?;
    let mut mode = args.mode;
    let (detected, _method) = cli_detect_kind(env, &iso);
    let detected_mode = detected.mode();
    if mode == Mode::Auto {
        mode = detected_mode.ok_or_else(|| {
            CliError::with_code(
                "Could not tell what kind of image this is. Pass --mode windows, --mode linux or --mode chromeos.",
                EXIT_USAGE,
            )
        })?;
    } else if detected_mode.is_some_and(|m| m != mode) {
        env.warn(&format!("This ISO looks like a {detected} image but --mode {mode} was requested."));
    }
    let mut hardening_names = Vec::new();
    if args.hardened {
        if mode != Mode::Windows {
            // --mode auto resolved to a Linux or ChromeOS image
            return Err(CliError::with_code(HARDENED_WINDOWS_ONLY, EXIT_USAGE));
        }
        hardening_names = hardening_file_names(env, FilesKind::Windows)?;
    }
    let iso_size = std::fs::metadata(&iso).map_err(|e| CliError::new(e.to_string()))?.len();
    let size = disk.size;
    if mode.is_raw() {
        let checked =
            if mode == Mode::ChromeOs { engine.validate_disk_image(&iso) } else { engine.validate_hybrid_iso(&iso) };
        checked.map_err(value_to_cli)?;
        if engine.chromeos_drive_too_small(mode, size) {
            env.warn(&format!(
                "Google asks for a USB drive of 16 GB or larger for ChromeOS Flex; this one is {}.",
                human_size(size)
            ));
        }
    }
    if engine.image_exceeds_drive(iso_size, size) {
        // A raw write needs the whole image; the copy of a Windows ISO holds at least its contents.
        return Err(CliError::new(format!(
            "The ISO ({}) is larger than the drive ({}).",
            human_size(iso_size),
            human_size(size)
        )));
    }
    if let Some(error) = missing_tools(env, mode) {
        return Err(error);
    }
    let eject = !args.flags.no_eject;
    Ok(Plan {
        iso: Some(iso.display().to_string()),
        iso_size,
        mode,
        target: None,
        volume_label: None,
        files: Vec::new(),
        disk: DiskSummary::of(&disk),
        // The identity (serial, WWN, ...) is kept so the safety re-check can compare the drive that is erased with
        // the one that was listed.
        identity: disk.identity.clone(),
        steps: write_steps(mode, &disk_id, eject, &hardening_names),
        eject,
        dry_run: args.flags.dry_run,
        hardening: if hardening_names.is_empty() { Hardening::None } else { Hardening::Baseline },
        hardening_files: hardening_names,
    })
}

/// Validate everything for `harden-seed` and build the plan. Touches nothing.
pub fn prepare_seed(env: &Env, args: &SeedArgs) -> Result<Plan, CliError> {
    let engine = &*env.engine;
    let disk_id = engine.validate_device_name(&normalize_typed_identifier(&args.disk)).map_err(value_to_cli)?;
    let disk = find_disk(list_disks(env)?, &disk_id)?;
    // A drive known to be too small is refused first: before the plan, the dry run and any confirmation.
    engine
        .check_seed_target_size((disk.size > 0).then_some(disk.size))
        .map_err(|e| CliError::with_code(e.to_string(), EXIT_USAGE))?;
    let (label, files) = hardening_files(env, FilesKind::of_seed_target(args.target))?;
    let mut names: Vec<String> = files.keys().cloned().collect();
    names.sort();
    if let Some(error) = missing_tools(env, Mode::Seed) {
        return Err(error);
    }
    let eject = !args.flags.no_eject;
    let label = label.unwrap_or_default();
    Ok(Plan {
        iso: None,
        iso_size: 0,
        mode: Mode::Seed,
        target: Some(args.target),
        steps: seed_steps(&disk_id, &label, &names, eject),
        volume_label: Some(label),
        files: names,
        disk: DiskSummary::of(&disk),
        identity: disk.identity.clone(),
        eject,
        dry_run: args.flags.dry_run,
        hardening: Hardening::Baseline,
        hardening_files: Vec::new(),
    })
}

/// Return normally only when the user has agreed to erase the drive.
fn confirm_write(env: &Env, flags: &WriteFlags, plan: &Plan) -> Result<(), CliError> {
    if flags.yes {
        return Ok(());
    }
    let disk_id = &plan.disk.id;
    if !env.interactive {
        return Err(CliError::with_code(
            "Refusing to erase a drive without confirmation: this is not an interactive terminal. Review the plan \
             with --dry-run, then pass --yes.",
            EXIT_USAGE,
        ));
    }
    env.err(&format!("\nThis will PERMANENTLY ERASE all data on {}.", dev_path(disk_id)));
    env.err.emit(&format!("Type the disk id ({disk_id}) to confirm: "), "");
    let answer = env.read_line().trim().to_string();
    let answer = if IS_WINDOWS { normalize_typed_identifier(&answer) } else { answer };
    if answer != *disk_id {
        return Err(CliError::with_code("The confirmation did not match. Nothing was changed.", EXIT_USAGE));
    }
    Ok(())
}

/// How the engine call ended, when it did not return a result.
enum Aborted {
    /// The engine returned an error.
    Error(Error),
    /// The engine panicked (a bug): the Python "unexpected exception".
    Panic(String),
    /// The second Ctrl-C: the engine call is abandoned (`KeyboardInterrupt`).
    Forced,
}

fn panic_text(payload: Box<dyn Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(text) => *text,
        Err(payload) => match payload.downcast::<&'static str>() {
            Ok(text) => (*text).to_string(),
            Err(_) => "the engine stopped unexpectedly".to_string(),
        },
    }
}

/// `_call_engine(plan, ...)`: the destructive engine call for `plan` (an image write, or the hardening seed drive).
fn call_engine(
    engine: &dyn super::api::Engine,
    plan: &Plan,
    log: &CliLogger,
    progress: &super::io::CliProgress,
    priv_: &dyn Privilege,
    cancel: &CancelToken,
) -> crate::types::Result<bool> {
    let log_line = |line: &str| log.call(line);
    let report = |done: u64, total: u64, text: &str| progress.call(done, total, text);
    let ctx = Ctx::new(&log_line, Some(&report), Some(cancel));
    let expected_size = (plan.disk.size > 0).then_some(plan.disk.size);
    if plan.mode == Mode::Seed {
        let Some(target) = plan.target else {
            return Err(Error::value("No seed target was chosen."));
        };
        return engine.build_seed_usb(
            target,
            &plan.disk.id,
            &ctx,
            priv_,
            expected_size,
            plan.eject,
            Hardening::Baseline,
        );
    }
    let opts = BuildOptions { expected_size, mode: plan.mode, eject: plan.eject, hardening: plan.hardening };
    engine.build_usb(Path::new(plan.iso.as_deref().unwrap_or("")), &plan.disk.id, &ctx, priv_, &opts)
}

fn round1(seconds: f64) -> f64 {
    (seconds * 10.0).round() / 10.0
}

/// Run the destructive engine call for `plan`. Returns the exit code and fills `result`.
fn run_write(env: &Env, flags: &WriteFlags, plan: &Plan, result: &mut J) -> i32 {
    let engine = env.engine.clone();
    let needs_priv = engine.needs_admin(plan.mode);
    let priv_: Arc<dyn Privilege> = engine.privilege();
    let progress = env.new_progress();
    let log = Arc::new(CliLogger::new(progress.clone(), env.err.clone(), flags.verbose));
    let cancel = CancelToken::new();
    let guard = env.interrupts.install();
    let started = Instant::now();
    engine.audit(
        &format!(
            "CLI write requested: {} mode={}{}{}",
            dev_path(&plan.disk.id),
            plan.mode,
            if plan.mode == Mode::Seed {
                format!(" target={}", plan.target.map(|t| t.as_str()).unwrap_or(""))
            } else {
                String::new()
            },
            if plan.hardening != Hardening::None { format!(" hardening={}", plan.hardening) } else { String::new() },
        ),
        AuditLevel::Info,
    );

    let mut announced = false; // the first Ctrl-C message was printed
    let mut announce = |cancel: &CancelToken| {
        if !announced {
            announced = true;
            cancel.set();
            env.err("\nInterrupted: finishing safely (unmounting) - press Ctrl-C again to force quit.");
        }
    };

    let mut ejected = false;
    let mut failure: Option<Aborted> = None;
    let authenticated = if needs_priv {
        // Ask sudo for credentials up front, before anything touches the drive.
        match priv_.authenticate("write a USB drive") {
            Ok(true) => Ok(()),
            Ok(false) => Err(Error::runtime("Could not obtain administrator privileges. Nothing was changed.")),
            Err(e) => Err(e),
        }
    } else {
        Ok(())
    };
    match authenticated {
        Err(e) => failure = Some(Aborted::Error(e)),
        Ok(()) => {
            // Bind the safety re-check (right before erasing) to exactly the drive that was planned.
            engine.pin_target_identity(&plan.disk.id, (!plan.identity.is_empty()).then(|| plan.identity.clone()));
            let (tx, rx) = mpsc::channel();
            let worker = {
                let (engine, priv_, log, progress, cancel, plan) =
                    (engine.clone(), priv_.clone(), log.clone(), progress.clone(), cancel.clone(), plan.clone());
                std::thread::Builder::new().name("write".into()).spawn(move || {
                    let outcome = catch_unwind(AssertUnwindSafe(|| {
                        call_engine(&*engine, &plan, &log, &progress, &*priv_, &cancel)
                    }));
                    let _ = tx.send(outcome);
                })
            };
            match worker {
                Err(e) => failure = Some(Aborted::Error(Error::Io(e))),
                Ok(_handle) => loop {
                    let presses = env.interrupts.count();
                    if presses >= 1 {
                        announce(&cancel);
                    }
                    if presses >= 2 {
                        failure = Some(Aborted::Forced);
                        break;
                    }
                    match rx.recv_timeout(Duration::from_millis(20)) {
                        Ok(outcome) => {
                            match outcome {
                                Ok(Ok(done)) => ejected = done,
                                Ok(Err(e)) => failure = Some(Aborted::Error(e)),
                                Err(payload) => failure = Some(Aborted::Panic(panic_text(payload))),
                            }
                            break;
                        }
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => {
                            failure = Some(Aborted::Panic("the engine stopped unexpectedly".into()));
                            break;
                        }
                    }
                },
            }
        }
    }
    let interrupted = env.interrupts.count() >= 1;
    if interrupted {
        announce(&cancel);
    }
    progress.finish();
    priv_.clear_cached_password();
    engine.pin_target_identity(&plan.disk.id, None); // never leave a pin behind (build_usb normally consumes it)
    drop(guard);
    result.set("elapsed_seconds", J::Float(round1(started.elapsed().as_secs_f64())));

    let Some(failure) = failure else {
        result.set("ok", J::Bool(true));
        result.set("verified", J::Bool(true));
        result.set("ejected", J::Bool(ejected));
        if !plan.eject {
            env.err("Done. The drive was written and verified; it was left connected (--no-eject).");
            return EXIT_OK;
        }
        if ejected {
            env.err("Done. The drive was written, verified and ejected - you can unplug it now.");
            return EXIT_OK;
        }
        env.error(
            "The drive was written and verified, but it could not be ejected. Eject it from the file manager before \
             unplugging.",
        );
        result.set("error", J::str("eject failed"));
        return EXIT_EJECT_FAILED;
    };

    if flags.debug {
        progress.clear();
        match &failure {
            Aborted::Error(e) => env.err(&format!("Traceback (debug output):\n{e:#?}")),
            Aborted::Panic(m) => env.err(&format!("Traceback (debug output):\npanic: {m}")),
            Aborted::Forced => {}
        }
    }
    if interrupted || matches!(failure, Aborted::Forced) {
        result.set("error", J::str("interrupted"));
        env.error("Interrupted. The drive may be partially written and must not be used.");
        return EXIT_INTERRUPTED;
    }
    let text = match &failure {
        Aborted::Error(e) => e.to_string(),
        Aborted::Panic(m) => m.clone(),
        Aborted::Forced => String::new(),
    };
    result.set("error", J::str(&text));
    if is_verification_failure(&text) {
        env.error(&text);
        return EXIT_VERIFY_FAILED;
    }
    match &failure {
        Aborted::Error(e @ (Error::Value(_) | Error::Runtime(_) | Error::Canceled { .. })) => {
            env.error(&text);
            if is_hardening_conflict(e) {
                // refused before the drive was touched: a usage problem, not a failure
                return EXIT_USAGE;
            }
        }
        Aborted::Error(Error::Io(_)) => env.error(&format!("Unexpected failure (OSError): {text}")),
        Aborted::Panic(_) | Aborted::Forced => env.error(&format!("Unexpected failure (panic): {text}")),
    }
    log.dump_recent();
    EXIT_ERROR
}

/// What a drive-writing command did, for `cmd_write` / `cmd_harden_seed`.
enum Outcome {
    /// `--dry-run`: the plan was printed, nothing else happened.
    DryRun,
    Code(i32),
}

fn drive_steps(env: &Env, flags: &WriteFlags, plan: &Plan, result: &mut J) -> Result<Outcome, CliError> {
    if flags.dry_run {
        if flags.json {
            env.out(&json_dumps(&plan.json()));
        } else {
            print_plan(env, plan, true);
            env.err("Dry run: nothing was changed.");
        }
        return Ok(Outcome::DryRun);
    }
    print_plan(env, plan, false);
    confirm_write(env, flags, plan)?;
    Ok(Outcome::Code(run_write(env, flags, plan, result)))
}

/// The part of `cmd_write` and `cmd_harden_seed` they share: prepare, dry run or confirm and write, and the
/// `--json` result (also printed when a `CliError` ends the command).
fn drive_command(
    env: &Env,
    flags: &WriteFlags,
    mut result: J,
    prepare: impl FnOnce() -> Result<Plan, CliError>,
    describe: impl FnOnce(&mut J, &Plan),
) -> Result<i32, Failure> {
    let outcome = prepare().and_then(|plan| {
        describe(&mut result, &plan);
        drive_steps(env, flags, &plan, &mut result)
    });
    match outcome {
        Err(e) => {
            result.set("error", J::str(&e.message));
            result.set("exit_code", J::Int(i64::from(e.code)));
            if flags.json {
                env.out(&json_dumps(&result));
            }
            Err(e.into())
        }
        Ok(Outcome::DryRun) => Ok(EXIT_OK),
        Ok(Outcome::Code(code)) => {
            result.set("exit_code", J::Int(i64::from(code)));
            if flags.json {
                env.out(&json_dumps(&result));
            }
            Ok(code)
        }
    }
}

pub fn cmd_write(env: &Env, args: &WriteArgs) -> Result<i32, Failure> {
    let result = obj(vec![
        ("ok", J::Bool(false)),
        ("mode", J::Null),
        ("iso", J::Null),
        ("disk", J::Null),
        ("verified", J::Bool(false)),
        ("ejected", J::Bool(false)),
        ("error", J::Null),
        ("exit_code", J::Int(i64::from(EXIT_ERROR))),
    ]);
    drive_command(
        env,
        &args.flags,
        result,
        || prepare_write(env, args),
        |result, plan| {
            result.set("mode", J::str(plan.mode.as_str()));
            result.set("iso", J::opt_str(plan.iso.as_deref()));
            result.set("disk", J::str(&plan.disk.id));
        },
    )
}

/// Erase a small separate USB drive and write the hardening seed files on it (never an OS image).
pub fn cmd_harden_seed(env: &Env, args: &SeedArgs) -> Result<i32, Failure> {
    let result = obj(vec![
        ("ok", J::Bool(false)),
        ("mode", J::str(Mode::Seed.as_str())),
        ("target", J::str(args.target.as_str())),
        ("disk", J::Null),
        ("verified", J::Bool(false)),
        ("ejected", J::Bool(false)),
        ("error", J::Null),
        ("exit_code", J::Int(i64::from(EXIT_ERROR))),
    ]);
    drive_command(
        env,
        &args.flags,
        result,
        || prepare_seed(env, args),
        |result, plan| {
            result.set("disk", J::str(&plan.disk.id));
            result.set("volume_label", J::opt_str(plan.volume_label.as_deref()));
            result.set("files", J::strings(&plan.files));
        },
    )
}
