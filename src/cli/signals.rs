//! Ctrl-C. The Python installs a SIGINT handler while a write runs: the first Ctrl-C asks the engine to stop safely
//! (the cancel event), the second one raises `KeyboardInterrupt`. A signal handler may only touch an atomic, so here
//! the handler counts the presses and the main thread polls the count ([`Interrupts::count`]); tests press Ctrl-C by
//! calling [`Interrupts::press`] on an [`Interrupts::manual`] instance, never by signalling the test process.

use std::sync::atomic::{AtomicU32, Ordering};

/// Presses of Ctrl-C seen by the real signal handler.
static SIGINT_COUNT: AtomicU32 = AtomicU32::new(0);

/// Counts Ctrl-C presses: from the operating system (the real command line) or by hand (tests).
pub struct Interrupts {
    manual: AtomicU32,
    os_signal: bool,
}

impl Interrupts {
    /// The real thing: [`Interrupts::install`] hooks Ctrl-C.
    pub fn os() -> Interrupts {
        Interrupts { manual: AtomicU32::new(0), os_signal: true }
    }

    /// Only [`Interrupts::press`] counts (tests).
    pub fn manual() -> Interrupts {
        Interrupts { manual: AtomicU32::new(0), os_signal: false }
    }

    /// One Ctrl-C, as if the user pressed it.
    pub fn press(&self) {
        self.manual.fetch_add(1, Ordering::SeqCst);
    }

    /// How many times Ctrl-C was pressed since the last [`Interrupts::install`].
    pub fn count(&self) -> u32 {
        self.manual.load(Ordering::SeqCst) + if self.os_signal { SIGINT_COUNT.load(Ordering::SeqCst) } else { 0 }
    }

    /// Start counting from zero and, for the real thing, hook Ctrl-C until the guard is dropped (which puts the
    /// previous handler back).
    pub fn install(&self) -> SigintGuard {
        self.manual.store(0, Ordering::SeqCst);
        if self.os_signal {
            SIGINT_COUNT.store(0, Ordering::SeqCst);
            SigintGuard::hook()
        } else {
            SigintGuard { previous: Previous::None }
        }
    }
}

enum Previous {
    None,
    #[cfg(unix)]
    Unix(libc::sighandler_t),
    #[cfg(windows)]
    Windows,
}

/// Puts the previous Ctrl-C behaviour back when dropped.
pub struct SigintGuard {
    previous: Previous,
}

#[cfg(unix)]
extern "C" fn on_sigint(_signal: libc::c_int) {
    SIGINT_COUNT.fetch_add(1, Ordering::SeqCst);
}

#[cfg(unix)]
impl SigintGuard {
    fn hook() -> SigintGuard {
        // SAFETY: the handler only touches an atomic, which is async-signal-safe; `signal` is called with a valid
        // signal number and a handler that has the right C signature.
        let previous =
            unsafe { libc::signal(libc::SIGINT, on_sigint as extern "C" fn(libc::c_int) as libc::sighandler_t) };
        if previous == libc::SIG_ERR {
            SigintGuard { previous: Previous::None }
        } else {
            SigintGuard { previous: Previous::Unix(previous) }
        }
    }
}

#[cfg(unix)]
impl Drop for SigintGuard {
    fn drop(&mut self) {
        if let Previous::Unix(previous) = self.previous {
            // SAFETY: restores the handler `signal` returned for SIGINT.
            unsafe {
                libc::signal(libc::SIGINT, previous);
            }
        }
    }
}

// Windows: Ctrl-C reaches a console control handler (kernel32, always linked by std); the three declarations below
// are the whole of the Win32 surface needed, kept here because the crate's windows-sys features do not include the
// console API. CTRL_C_EVENT = 0, CTRL_BREAK_EVENT = 1.
#[cfg(windows)]
mod console {
    pub type Handler = unsafe extern "system" fn(u32) -> i32;
    extern "system" {
        pub fn SetConsoleCtrlHandler(handler: Option<Handler>, add: i32) -> i32;
    }
    pub unsafe extern "system" fn on_ctrl(kind: u32) -> i32 {
        if kind == 0 || kind == 1 {
            super::SIGINT_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            1 // handled: do not end the process
        } else {
            0
        }
    }
}

#[cfg(windows)]
impl SigintGuard {
    fn hook() -> SigintGuard {
        // SAFETY: registers a handler with the C ABI that only touches an atomic.
        let ok = unsafe { console::SetConsoleCtrlHandler(Some(console::on_ctrl), 1) };
        SigintGuard { previous: if ok != 0 { Previous::Windows } else { Previous::None } }
    }
}

#[cfg(windows)]
impl Drop for SigintGuard {
    fn drop(&mut self) {
        if let Previous::Windows = self.previous {
            // SAFETY: removes the handler added by `hook`.
            unsafe {
                console::SetConsoleCtrlHandler(Some(console::on_ctrl), 0);
            }
        }
    }
}

#[cfg(not(any(unix, windows)))]
impl SigintGuard {
    fn hook() -> SigintGuard {
        SigintGuard { previous: Previous::None }
    }
}
