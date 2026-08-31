pub mod app;
pub mod bip32;
pub mod chains;
pub mod gpu;
pub mod matcher;
pub mod pbkdf2_lanes;
pub mod seed;
pub mod slip10;
pub mod ui;
pub mod verify;

use self::app::App;
use crossterm::{
    event::{self, Event},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::Terminal;
use std::{
    io::{self, stdout},
    sync::atomic::Ordering,
    time::Duration,
};

/// Restore the terminal on ANY panic, then chain to whatever hook was already
/// installed so the message and backtrace still print.
///
/// The GPU path adds panic sites — `pack_key_block`'s hard assert, every Metal
/// `Result` unwrap — to a binary that previously had none inside the alternate
/// screen. Without this, a panic leaves the user in raw mode on the alternate
/// screen with a shell that echoes nothing.
fn install_terminal_restoring_panic_hook() {
    install_panic_hook_with(|| {
        // Best-effort and deliberately independent: inside a panic hook there
        // is nowhere to report an error, so both restores are attempted even
        // if one fails, rather than short-circuiting on the first `Result`.
        let _ = disable_raw_mode();
        let _ = stdout().execute(LeaveAlternateScreen);
    });
}

/// Split out so the test can observe that the restore ran, and that it ran
/// BEFORE the previous hook. Asserting only "the previous hook ran" passes for
/// an empty installer — measured; see the Step 1 test's doc comment.
fn install_panic_hook_with(restore: impl Fn() + Send + Sync + 'static) {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore();
        prev(info);
    }));
}

fn main() -> io::Result<()> {
    // Probe BEFORE enable_raw_mode(). Device creation is the one Metal call that
    // can print to stderr or panic on a machine we have not seen, and neither
    // must land inside the alternate screen. catch_unwind because a Rust unwind
    // here would otherwise take the process down before the hook below exists.
    // (An Objective-C exception is NOT catchable — that is why the backend never
    // calls setMathMode and always clamps the threadgroup size.)
    let gpu_status = std::panic::catch_unwind(gpu::GpuEngine::probe)
        .unwrap_or_else(|_| gpu::GpuStatus::Unavailable("Metal probe panicked".to_string()));

    install_terminal_restoring_panic_hook();

    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::with_gpu_status(gpu_status);
    let tick_rate = Duration::from_millis(100);

    loop {
        terminal.draw(|f| ui::ui(f, &app))?;

        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                app::handle_key_event(&mut app, key);
            }
        }

        app.drain_matches();

        if app.should_quit {
            app.stop.store(true, Ordering::Relaxed);
            break;
        }
    }

    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;

    let total = app.counter.load(Ordering::Relaxed);
    let matches = app.matches.len();
    if total > 0 {
        println!("\n==========================================================");
        println!("  Wallets checked : {}", total);
        println!("  Matches found   : {}", matches);
        if let Some(start) = app.start_time {
            println!("  Elapsed time    : {:.2?}", start.elapsed());
        }
        if matches > 0 {
            println!("  Saved to        : vanity_wallets.csv");
            println!("  SECURITY WARNING: CSV contains plaintext seed phrases.");
            println!("                    File is chmod 0600 (owner-only). Move to");
            println!("                    an encrypted location and delete the original.");
        }
        println!("==========================================================\n");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::install_panic_hook_with;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// NOTE: this test manipulates the PROCESS-WIDE panic hook, and `cargo test`
    /// runs tests as threads in one process. It installs, exercises, and then
    /// restores the default hook. Keep it short.
    ///
    /// It records an ORDER, not merely "the previous hook ran". Measured: with
    /// an EMPTY `fn install_terminal_restoring_panic_hook() {}` body this test's
    /// earlier form still printed `test result: ok. 1 passed`, because the
    /// stand-in hook below is then the installed one and latches anyway. So the
    /// restore action is injected here and its ORDER asserted: it must run
    /// BEFORE the previous hook, which prints the message and backtrace that are
    /// unreadable in raw mode on the alternate screen.
    ///
    /// Panic hooks are PROCESS-GLOBAL, so this test's stand-in hook must be
    /// undone unconditionally — including if an assertion below fails and
    /// panics before reaching the end of the function. Without that, a
    /// failed assertion would leave the silent stand-in hook installed as
    /// the process-global hook for the rest of the `cargo test` binary, and
    /// every later panic in the process — including other threads' — would
    /// print nothing.
    ///
    /// This is NOT done with an RAII guard whose `Drop` calls
    /// `std::panic::set_hook`. Measured: `set_hook` panics if the calling
    /// thread is already unwinding, so a `Drop` reached while THIS test's
    /// own assertion is unwinding double-panics on the same thread, which
    /// Rust always turns into an immediate process abort (SIGABRT) —
    /// `thread caused non-unwinding panic. aborting.` — regardless of
    /// `panic = "unwind"`. That is strictly worse than the bug it would fix:
    /// one broken test becomes one aborted `cargo test` run. Instead, the
    /// exercise-and-assert body runs inside its own `catch_unwind`, which
    /// returns this thread to a non-panicking state before the hook is
    /// restored; a failed assertion is then re-raised with
    /// `resume_unwind` so the test still reports FAILED.
    #[test]
    fn panic_hook_restores_terminal_and_still_calls_the_previous_hook() {
        static SEQ: AtomicUsize = AtomicUsize::new(1);
        static RESTORE_AT: AtomicUsize = AtomicUsize::new(0);
        static PREV_AT: AtomicUsize = AtomicUsize::new(0);

        let original_hook = std::panic::take_hook();

        let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // Stand in a hook of our own so we can prove the chain is intact.
            // The classic bug is forgetting `prev(info)`, which silently
            // deletes every panic message and backtrace in the binary.
            std::panic::set_hook(Box::new(|_| {
                PREV_AT.store(SEQ.fetch_add(1, Ordering::SeqCst), Ordering::SeqCst);
            }));

            // The SAME wiring main() installs, with a restore action this
            // test can observe.
            install_panic_hook_with(|| {
                RESTORE_AT.store(SEQ.fetch_add(1, Ordering::SeqCst), Ordering::SeqCst);
            });

            let result = std::panic::catch_unwind(|| panic!("deliberate test panic"));
            assert!(result.is_err(), "the panic must still unwind");

            let restore_at = RESTORE_AT.load(Ordering::SeqCst);
            let prev_at = PREV_AT.load(Ordering::SeqCst);
            assert_ne!(restore_at, 0, "the terminal restore never ran");
            assert_ne!(
                prev_at, 0,
                "the installed hook must call the previous hook, or all panic output is lost"
            );
            assert!(
                restore_at < prev_at,
                "the terminal must be restored BEFORE the previous hook prints: {restore_at} vs {prev_at}"
            );
        }));

        // This thread is no longer unwinding at this point (the body's own
        // catch_unwind above already caught any assertion panic), so
        // set_hook is safe to call here on every path.
        std::panic::set_hook(original_hook);

        if let Err(payload) = body {
            std::panic::resume_unwind(payload);
        }
    }

    #[test]
    fn probe_result_reaches_the_app() {
        // Whatever the machine reports, App must carry it verbatim — main() is
        // the only place a probe happens, and a dropped result would silently
        // mean "no GPU, forever". The single licensed exception is the env veto,
        // which deliberately rewrites a `Ready` probe into `Disabled(UserOff)` so
        // the config row can show the reason.
        let status = crate::gpu::GpuEngine::probe();
        let app = crate::app::App::with_gpu_status(status.clone());
        let vetoed = crate::app::gpu_env_off(
            std::env::var("VANADDY_GPU").ok().as_deref(),
            std::env::var("VANADDY_NO_GPU").ok().as_deref(),
        ) && matches!(status, crate::gpu::GpuStatus::Ready { .. });
        if vetoed {
            assert_eq!(
                app.gpu_status,
                crate::gpu::GpuStatus::Disabled(crate::gpu::GpuDisableReason::UserOff)
            );
        } else {
            assert_eq!(app.gpu_status, status);
        }
    }
}
