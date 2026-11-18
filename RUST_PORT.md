# Rust port — conventions (read this first)

The product is being ported from `win11_usb_creator.py` (13,039 lines; the **reference**, do not edit it) to a Rust
crate `epma-usb-creator` (library `epma_usb_creator` + binary). The Python tests (`tests/*.py`, 1,309 tests) are the
specification: port the behaviour they check.

The skeleton compiles: every module exists with `todo!()` stubs carrying the **seam signatures** (the functions other
modules call). Eight agents (A1..A8) each own a disjoint set of files and replace the stubs with the real port.
Everything outside your files is a stub in your worktree: you can call it (it compiles) but it will `todo!()`-panic at
runtime, so test your module in isolation (unit tests with fakes / temp files / injected inputs).

## Ownership (never edit a file you do not own)

| Agent | Owns (src/ unless noted) | Python lines |
|---|---|---|
| A1 | `util.rs` `i18n.rs` `audit.rs` `validate.rs` `hash.rs` `isoinfo.rs` `proc.rs` | 284-1108, 1436-1745 (not 1467-1486: that is `types::Error::Canceled`) |
| A2 | `copyverify.rs` `privilege.rs` `diskrisk.rs` `engine.rs` | 1109-1435, 1886-2299, 3422-3505, 3768-3947, 3948-4127, 5919-5948, 12191-12264 |
| A3 | `macos.rs` `linux.rs` | 2302-3030, 8662-8791 |
| A4 | `windows.rs` `seed.rs` | 3030-3766, 3739-3766, 8462-8661, 8792-8868 |
| A5 | `harden_linux.rs` `seed_files.rs` `help.rs` (+ `assets/harden-linux.sh` wiring) | 4124-5917, 7940-8461, 9195-9530 |
| A6 | `harden_windows.rs` (+ `assets/` files it needs) | 5950-7940 |
| A7 | `download.rs` `cli.rs` `main.rs` | 8872-9146, 12040-13039 |
| A8 | `gui/` (any files under `src/gui/`) | 1747-1885, 9148-12040 |
| lead | `Cargo.toml` `lib.rs` `types.rs` `constants.rs` `i18n_table.rs` `RUST_PORT.md` `tools/` CI/docs | — |

`types.rs` and `constants.rs` are **frozen**. If you believe one needs a change, do not edit it: work around it and
describe the need in your report ("SEAM NOTES").

You may change the **signature** of a function in a file you own when the stub is inadequate, but every such change
must be listed in your final report (the lead reconciles the call sites at merge time). Prefer keeping the stubs.

## Fidelity rules (this is a port, not a redesign)

1. **Same behaviour, same messages.** User-facing and error message texts are copied verbatim from the Python
   (tests and the window match on substrings: "Verification FAILED", "already contain", "Nothing was changed"...).
2. **Shell and PowerShell scripts are data: copy them byte for byte.** Never retype a big text. Use
   `python3 tools/py_dump.py text NAME OUT` (or `call 'EXPR' OUT`) to write a Python constant to `assets/...`, then
   `include_str!("../assets/...")`. Short scripts may be Rust raw strings (`r#"..."#`) copied from the source. Values
   are passed to privileged scripts only as positional parameters (`"$1"`...), **never interpolated** into script text.
3. **Security properties are part of the spec**: validate device names with `validate::validate_device_name` before
   they reach a command; open temp/part files with no-follow semantics (`O_NOFOLLOW` via `OpenOptionsExt::custom_flags`
   on unix); files we create are owner-only (0o600) and directories 0o700; the sudo password never reaches argv, a
   log, or disk; a failed privileged script is **never re-run**; destructive steps are preceded by the safety
   re-check and followed by read-back verification exactly as in the Python.
4. **Output goldens.** `tests/golden/` holds byte-exact outputs of the Python generators (see `tools/make_goldens.py`).
   Generated content must be byte-identical (tests compare with `include_bytes!`/`include_str!`). You can also run
   Python on the fly: `python3 tools/py_dump.py json 'EXPR' out.json` evaluates an expression in the Python module.
5. **Do not "improve" or drop** checks, timeouts, retries, markers (`WRITE_CANCELED`, `VERIFY_OK`...) or ordering of
   steps. Comments explaining *why* in the Python should be carried over (shortened is fine).

## Rust conventions

* Edition 2021, `rustfmt.toml` (width 120). Format **only your own files**: `rustfmt --edition 2021 src/yours.rs`
  (never `cargo fmt`: it would touch other agents' files and cause merge conflicts).
* Remove the `#![allow(unused)] // STUB` line at the top of every file you implement, and leave your files free of
  compiler and `cargo clippy` warnings.
* Python names map to snake_case; a leading underscore means `pub(crate)` or private. `UPPER_CASE` constants keep
  their name. When a module is named after a platform (`macos`, `linux`, `windows`) the platform prefix is dropped
  (`macos_get_external_disks` -> `macos::get_external_disks`). Constants listed in `constants.rs` live there.
* Types: see `types.rs` (`Log`, `Progress`, `Progress2`, `CancelToken`, `Ctx`, `Error`, `Mode`, `Hardening`,
  `SeedTarget`, `IsoKind`, `Card`, `Disk`, `Volume`, `Volumes`, `Identity`, `Files`, `Privilege`, `PasswordPrompt`,
  `BuildOptions`). Paths: parameters `impl AsRef<Path>` (or `&Path`), returns `PathBuf`; device ids and labels `&str`.
  Byte sizes `u64`, whole seconds `u64`, fractional seconds `f64`.
* Errors: `RuntimeError` -> `Error::Runtime`, `ValueError` -> `Error::Value`, `OperationCanceled` ->
  `Error::Canceled{..}` (`Error::canceled()`, `Error::canceled_with(msg, drive_touched, written)`), `OSError` ->
  `Error::Io` (via `?`). Messages of the Python exceptions are kept. No `unwrap()`/`expect()`/indexing panics on
  anything derived from user input, files, or command output. Lock poisoning: `unwrap_or_else(|e| e.into_inner())`.
* Callbacks are `Fn + Send + Sync` (shared across threads). Interior mutability (`Mutex`, atomics) for state.
* Translation: GUI texts go through `i18n::tr` / `i18n::tr_fmt` exactly where the Python uses `_()`; engine / CLI /
  audit / script text stays English and untranslated.
* Platform code: every module compiles on every OS. Decide at runtime with `constants::{IS_MAC, IS_LINUX, IS_WINDOWS}`;
  use `#[cfg(unix)]` / `#[cfg(windows)]` only around APIs that do not exist elsewhere (libc, windows-sys), with a
  working stub or a clear `Error` on the other side. Windows code cannot be compiled here: keep `#[cfg(windows)]`
  blocks small, careful and well commented; put every pure part (script texts, parsers, argument building) outside.
* Dependencies are in `Cargo.toml`. If you need another crate, add ONE line in the "extra dependencies" block at the
  end of `[dependencies]` (comment which agent) and list it in your report. Prefer std.
* Processes: use `proc::run_cmd` for commands; read untrusted output defensively; use timeouts from `constants`.

## Tests

* Port the Python tests that exercise **your** modules (grep `tests/*.py` for the functions you port; the biggest files
  are test_hardening_*.py, test_fixes_gui.py, test_cli*.py, test_windows_backend.py, test_chromeos.py). Python tests
  rely on monkeypatching; in Rust, inject the dependency (a function parameter, a `&dyn Fn`, a trait object) or test the
  pure core. If a Python test cannot be ported 1:1, port its intent and note it in the report.
* Put unit tests in `#[cfg(test)] mod tests` at the bottom of your own module files, or integration tests in
  `tests/<python_test_stem>_<your_module>.rs` (e.g. `tests/test_validation.rs`). Shared helpers: inline them or use
  `tests/common_a<N>/mod.rs`. Never touch another agent's test file.
* Tests must be hermetic: temp dirs (`tempfile`), no network, never touch a real disk, no `sudo`, no global env
  changes without a lock (use a `static Mutex` when a test sets an env var).
* Count: your report must say "ported N of M Python tests" for the Python test files you worked from.

## Building and checking (per agent, in your worktree)

```bash
export CARGO_TARGET_DIR=<the directory the lead gave you>        # pre-warmed; never share it with another agent
cargo build --no-default-features                                 # engine + CLI only (fast); A8 also builds the default features
cargo test  --no-default-features --lib --tests <filter>
cargo clippy --no-default-features --all-targets 2>&1 | grep -A5 'src/<yourfile>'   # your files must be clean
```

Commit your work on your branch (the worktree is yours): `git add -A && git commit -m "A<N>: <module(s)>"`.
Do not push, do not touch `main`/`rust-port`, do not delete the Python files.

## Final report (your last message, keep it factual and compact)

1. Files written/changed, with line counts.
2. **Signature changes** vs the stubs (exact old -> new), and new public items other modules may want.
3. **SEAM NOTES**: what you needed from other modules / `types.rs` / `Cargo.toml`, and anything you stubbed.
4. Tests: "ported N of M" per Python test file; those you could not port and why.
5. Python behaviours you could not reproduce, deviations, or doubts (be honest; the lead merges and verifies).
6. Extra crates added to `Cargo.toml`.
