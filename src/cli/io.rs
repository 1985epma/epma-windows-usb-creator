//! What the command line prints and reads: the streams (Python `_emit`, `_out`, `_err`, `_use_color`, `_style`,
//! `_error`, `_warn`), the progress line (`CliProgress`), the log filter (`CliLogger`) and the ordered JSON the
//! `--json` outputs are written in (`json.dumps(indent=2)`).
//!
//! Data goes to stdout; messages, errors and progress go to stderr. Everything goes through an [`Env`], so the tests
//! can run the whole command line against in-memory streams, a scripted clock and a fake engine.

use super::api::Engine;
use super::signals::Interrupts;
use crate::util::{eta_remaining, human_size};
use regex::Regex;
use std::collections::VecDeque;
use std::io::{self, BufRead, IsTerminal, Write};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Instant;

/// Engine log lines worth showing without `--verbose` (everything else is command output).
pub static CLI_MILESTONE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)warning|error|fail|verif|eject|done!|safety re-check|erasing|writing the iso|copying|splitting|mounting|syncing|note:|could not|aborted",
    )
    .unwrap()
});

// ---------------------------------------------------------------------------------------------------------------
// Streams
// ---------------------------------------------------------------------------------------------------------------

/// One output stream (stdout or stderr): the writer and whether it is a terminal.
pub struct OutStream {
    writer: Mutex<Box<dyn Write + Send>>,
    tty: bool,
}

impl OutStream {
    pub fn new(writer: Box<dyn Write + Send>, tty: bool) -> Arc<OutStream> {
        Arc::new(OutStream { writer: Mutex::new(writer), tty })
    }
    pub fn is_tty(&self) -> bool {
        self.tty
    }
    /// `_emit(stream, text, end)`: write and flush. A stream that cannot be written (a closed pipe) is ignored.
    pub fn emit(&self, text: &str, end: &str) {
        let mut writer = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        let _ = writer.write_all(text.as_bytes());
        let _ = writer.write_all(end.as_bytes());
        let _ = writer.flush();
    }
}

/// `os.environ.get`.
pub type GetEnv = Box<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// Everything the command line touches in its surroundings.
pub struct Env {
    pub engine: Arc<dyn Engine>,
    pub out: Arc<OutStream>,
    pub err: Arc<OutStream>,
    pub stdin: Mutex<Box<dyn BufRead + Send>>,
    /// `_is_interactive()`: stdin and stderr are terminals.
    pub interactive: bool,
    pub getenv: GetEnv,
    /// A monotonic clock in seconds (`time.monotonic`).
    pub clock: Arc<dyn Fn() -> f64 + Send + Sync>,
    pub interrupts: Arc<Interrupts>,
}

impl Env {
    /// The real process: stdout, stderr, stdin, the environment, the monotonic clock and Ctrl-C.
    pub fn real(engine: Arc<dyn Engine>) -> Env {
        let started = Instant::now();
        Env {
            engine,
            out: OutStream::new(Box::new(io::stdout()), io::stdout().is_terminal()),
            err: OutStream::new(Box::new(io::stderr()), io::stderr().is_terminal()),
            stdin: Mutex::new(Box::new(io::BufReader::new(io::stdin()))),
            interactive: io::stdin().is_terminal() && io::stderr().is_terminal(),
            getenv: Box::new(|name| std::env::var(name).ok()),
            clock: Arc::new(move || started.elapsed().as_secs_f64()),
            interrupts: Arc::new(Interrupts::os()),
        }
    }

    pub fn env_var(&self, name: &str) -> Option<String> {
        (self.getenv)(name)
    }

    /// `_out(text)`.
    pub fn out(&self, text: &str) {
        self.out.emit(text, "\n");
    }

    /// `_err(text)`.
    pub fn err(&self, text: &str) {
        self.err.emit(text, "\n");
    }

    /// `_use_color(stream)`: never with NO_COLOR or TERM=dumb, and only on a terminal.
    pub fn use_color(&self, stream: &OutStream) -> bool {
        if self.env_var("NO_COLOR").is_some_and(|v| !v.is_empty()) || self.env_var("TERM").as_deref() == Some("dumb") {
            return false;
        }
        stream.is_tty()
    }

    /// `_style(stream, text, code)`.
    pub fn style(&self, stream: &OutStream, text: &str, code: &str) -> String {
        if self.use_color(stream) {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    /// `_error(message)`.
    pub fn error(&self, message: &str) {
        self.err(&format!("{} {message}", self.style(&self.err, "error:", "1;31")));
    }

    /// `_warn(message)`.
    pub fn warn(&self, message: &str) {
        self.err(&format!("{} {message}", self.style(&self.err, "warning:", "33")));
    }

    /// `sys.stdin.readline()`: one line including its newline, or "" at the end of the input.
    pub fn read_line(&self) -> String {
        let mut line = String::new();
        let mut stdin = self.stdin.lock().unwrap_or_else(|e| e.into_inner());
        let _ = stdin.read_line(&mut line);
        line
    }

    /// A new progress line on stderr.
    pub fn new_progress(&self) -> Arc<CliProgress> {
        Arc::new(CliProgress::new(self.err.clone(), self.clock.clone()))
    }
}

// ---------------------------------------------------------------------------------------------------------------
// CliProgress / CliLogger
// ---------------------------------------------------------------------------------------------------------------

#[derive(Default)]
struct ProgressState {
    text: Option<String>,
    base: u64,
    stage_start: f64,
    last: Option<f64>,
    width: usize,
    open: bool,
}

/// Progress sink for the engine: one updating line on a terminal, periodic lines otherwise.
pub struct CliProgress {
    stream: Arc<OutStream>,
    tty: bool,
    interval: f64,
    clock: Arc<dyn Fn() -> f64 + Send + Sync>,
    state: Mutex<ProgressState>,
}

impl CliProgress {
    pub fn new(stream: Arc<OutStream>, clock: Arc<dyn Fn() -> f64 + Send + Sync>) -> CliProgress {
        let tty = stream.is_tty();
        CliProgress {
            stream,
            tty,
            interval: if tty { 0.25 } else { 10.0 },
            clock,
            state: Mutex::new(ProgressState::default()),
        }
    }

    fn format(state: &ProgressState, done: u64, total: u64, text: &str, now: f64) -> String {
        if total == 0 {
            return text.to_string();
        }
        let pct = (done as f64 / total as f64 * 100.0).min(100.0);
        let mut line = format!("{text}  {pct:5.1}%  {} / {}", human_size(done), human_size(total));
        let elapsed = now - state.stage_start;
        if elapsed >= 1.0 && done > state.base {
            let speed = (done - state.base) as f64 / elapsed;
            line.push_str(&format!("  {}/s  {}", human_size(speed as u64), eta_remaining(done, total, speed, false)));
        }
        line
    }

    /// `__call__(done, total, text)`.
    pub fn call(&self, done: u64, total: u64, text: &str) {
        let now = (self.clock)();
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let changed = st.text.as_deref() != Some(text);
        if changed {
            st.text = Some(text.to_string());
            st.base = done;
            st.stage_start = now;
        }
        let is_final = total > 0 && done >= total;
        if !(changed || is_final) {
            if let Some(last) = st.last {
                if now - last < self.interval {
                    return;
                }
            }
        }
        st.last = Some(now);
        let line = Self::format(&st, done, total, text, now);
        if self.tty {
            st.width = st.width.max(line.chars().count());
            let pad = st.width.saturating_sub(line.chars().count());
            self.stream.emit(&format!("\r{line}{}", " ".repeat(pad)), "");
            st.open = true;
        } else {
            self.stream.emit(&line, "\n");
        }
    }

    /// Wipe the progress line so a log message can be printed in its place.
    pub fn clear(&self) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.open {
            self.stream.emit(&format!("\r{}\r", " ".repeat(st.width)), "");
            st.open = false;
        }
    }

    pub fn finish(&self) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.open {
            self.stream.emit("", "\n");
            st.open = false;
        }
    }
}

/// Log sink for the engine: milestones always, everything with `--verbose`.
pub struct CliLogger {
    progress: Arc<CliProgress>,
    stream: Arc<OutStream>,
    verbose: bool,
    recent: Mutex<VecDeque<String>>,
}

impl CliLogger {
    pub fn new(progress: Arc<CliProgress>, stream: Arc<OutStream>, verbose: bool) -> CliLogger {
        CliLogger { progress, stream, verbose, recent: Mutex::new(VecDeque::new()) }
    }

    /// `__call__(line)`.
    pub fn call(&self, line: &str) {
        let line = line.trim_end();
        if line.is_empty() {
            return;
        }
        {
            let mut recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
            if recent.len() == 20 {
                recent.pop_front();
            }
            recent.push_back(line.to_string());
        }
        if self.verbose || (CLI_MILESTONE_RE.is_match(line) && !line.starts_with("$ ")) {
            self.progress.clear();
            self.stream.emit(line, "\n");
        }
    }

    /// The last (up to 20) lines the engine logged, oldest first.
    pub fn recent(&self) -> Vec<String> {
        self.recent.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect()
    }

    pub fn dump_recent(&self) {
        let recent = self.recent();
        if self.verbose || recent.is_empty() {
            return;
        }
        self.stream.emit("Last log lines:", "\n");
        for line in recent {
            self.stream.emit(&format!("  {line}"), "\n");
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Ordered JSON (`json.dumps(value, indent=2)`)
// ---------------------------------------------------------------------------------------------------------------

/// A JSON value whose objects keep their insertion order, like the Python dicts the outputs were built from.
#[derive(Clone, Debug, PartialEq)]
pub enum J {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<J>),
    Map(Vec<(String, J)>),
}

impl J {
    pub fn str(text: impl Into<String>) -> J {
        J::Str(text.into())
    }
    pub fn opt_str(text: Option<impl Into<String>>) -> J {
        text.map(|t| J::Str(t.into())).unwrap_or(J::Null)
    }
    pub fn strings<S: AsRef<str>>(items: &[S]) -> J {
        J::List(items.iter().map(|s| J::Str(s.as_ref().to_string())).collect())
    }
    pub fn int(n: u64) -> J {
        J::Int(i64::try_from(n).unwrap_or(i64::MAX))
    }
    /// `dict[key] = value`: replace in place or append (a Python dict keeps the first position of a key).
    pub fn set(&mut self, key: &str, value: J) {
        if let J::Map(items) = self {
            match items.iter_mut().find(|(k, _)| k == key) {
                Some(slot) => slot.1 = value,
                None => items.push((key.to_string(), value)),
            }
        }
    }
}

fn dump_string(text: &str, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                // ensure_ascii: everything outside printable ASCII is written as \uXXXX (surrogate pairs above U+FFFF)
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn dump(value: &J, depth: usize, out: &mut String) {
    let pad = |n: usize| " ".repeat(2 * n);
    match value {
        J::Null => out.push_str("null"),
        J::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        J::Int(n) => out.push_str(&n.to_string()),
        J::Float(f) => out.push_str(&format!("{f:?}")),
        J::Str(s) => dump_string(s, out),
        J::List(items) if items.is_empty() => out.push_str("[]"),
        J::List(items) => {
            out.push_str("[\n");
            for (i, item) in items.iter().enumerate() {
                out.push_str(&pad(depth + 1));
                dump(item, depth + 1, out);
                out.push_str(if i + 1 < items.len() { ",\n" } else { "\n" });
            }
            out.push_str(&pad(depth));
            out.push(']');
        }
        J::Map(items) if items.is_empty() => out.push_str("{}"),
        J::Map(items) => {
            out.push_str("{\n");
            for (i, (key, item)) in items.iter().enumerate() {
                out.push_str(&pad(depth + 1));
                dump_string(key, out);
                out.push_str(": ");
                dump(item, depth + 1, out);
                out.push_str(if i + 1 < items.len() { ",\n" } else { "\n" });
            }
            out.push_str(&pad(depth));
            out.push('}');
        }
    }
}

/// `json.dumps(value, indent=2)`.
pub fn json_dumps(value: &J) -> String {
    let mut out = String::new();
    dump(value, 0, &mut out);
    out
}

/// `{"k": v, ...}` from a list of pairs.
pub fn obj(pairs: Vec<(&str, J)>) -> J {
    J::Map(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}
