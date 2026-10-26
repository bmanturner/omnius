//! Process-wide panic redaction shared by applications and libraries.
use std::{
    cell::Cell,
    panic::{self, PanicHookInfo},
    sync::{
        Once,
        atomic::{AtomicBool, Ordering},
    },
};

thread_local! {
    static REDACTION_ACTIVE: Cell<bool> = const { Cell::new(false) };
}

static INSTALL_HOOK: Once = Once::new();
static REDACT_ALL: AtomicBool = AtomicBool::new(false);

/// Installs the process panic hook once; later calls are no-ops.
///
/// Precedence on each panic: while a [`RedactionScope`] is active on the
/// panicking thread the hook prints nothing (the panic is caught and reported
/// as a handler failure); otherwise, after [`redact_all_panics`], it prints only
/// the panic location, never the payload; otherwise it delegates to the hook
/// installed before it, so library consumers keep their normal panic output.
pub fn install_redacting_panic_hook() {
    INSTALL_HOOK.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |information| {
            let scoped = REDACTION_ACTIVE.try_with(Cell::get).unwrap_or(false);
            if scoped {
                return;
            }
            if REDACT_ALL.load(Ordering::Relaxed) {
                report_location(information);
            } else {
                previous(information);
            }
        }));
    });
}

/// Application entry point: installs the hook and redacts every panic in the process.
///
/// Panic output is limited to the location line, never the payload.
pub fn redact_all_panics() {
    install_redacting_panic_hook();
    REDACT_ALL.store(true, Ordering::Relaxed);
}

fn report_location(information: &PanicHookInfo<'_>) {
    #[cfg(test)]
    tests::REDACTED_REPORTS.with(|count| count.set(count.get() + 1));
    if let Some(location) = information.location() {
        eprintln!(
            "process panic captured at {}:{}:{}",
            location.file(),
            location.line(),
            location.column()
        );
    } else {
        eprintln!("process panic captured at unknown location");
    }
}

/// Redacts panics raised on this thread while alive, even without [`redact_all_panics`].
///
/// Scopes nest; dropping a scope restores the state it replaced.
#[derive(Debug)]
pub struct RedactionScope {
    previous: bool,
    // Thread-local state: the guard must drop on the thread that created it.
    _not_send: std::marker::PhantomData<*const ()>,
}

impl RedactionScope {
    /// Enters a redaction scope for the current thread.
    #[must_use = "the scope ends as soon as the guard is dropped"]
    pub fn enter() -> Self {
        Self {
            previous: REDACTION_ACTIVE.with(|active| active.replace(true)),
            _not_send: std::marker::PhantomData,
        }
    }
}

impl Drop for RedactionScope {
    fn drop(&mut self) {
        REDACTION_ACTIVE.with(|active| active.set(self.previous));
    }
}

/// Runs `run` inside a [`RedactionScope`].
pub fn with_redacted_panic<T>(run: impl FnOnce() -> T) -> T {
    let _scope = RedactionScope::enter();
    run()
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        pub(super) static REDACTED_REPORTS: Cell<usize> = const { Cell::new(0) };
        static PREVIOUS_CALLS: Cell<usize> = const { Cell::new(0) };
    }

    fn panic_quietly() {
        let _ = panic::catch_unwind(|| panic!("sensitive payload"));
    }

    // Hook state is process-global, so the three cases run sequentially in one test.
    #[test]
    fn scope_silences_redact_all_locates_otherwise_delegates() {
        panic::set_hook(Box::new(|_| PREVIOUS_CALLS.with(|c| c.set(c.get() + 1))));
        install_redacting_panic_hook();
        let counts = || {
            (
                REDACTED_REPORTS.with(Cell::get),
                PREVIOUS_CALLS.with(Cell::get),
            )
        };

        with_redacted_panic(panic_quietly);
        assert_eq!(counts(), (0, 0), "scoped panic must be silent");

        panic_quietly();
        assert_eq!(counts(), (0, 1), "unscoped panic must reach previous hook");

        REDACT_ALL.store(true, Ordering::Relaxed);
        panic_quietly();
        assert_eq!(
            counts(),
            (1, 1),
            "redact-all panic must print location only"
        );
        with_redacted_panic(panic_quietly);
        REDACT_ALL.store(false, Ordering::Relaxed);
        assert_eq!(counts(), (1, 1), "scope wins over redact-all");
    }
}
