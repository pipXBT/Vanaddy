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
use crossterm::event::{self, Event};
use std::{io, sync::atomic::Ordering, time::Duration};

fn main() -> io::Result<()> {
    // Probe BEFORE try_init(). Device creation is the one Metal call that can
    // print to stderr or panic on a machine we have not seen, and neither must
    // land inside the alternate screen. catch_unwind because a Rust unwind here
    // would otherwise take the process down before try_init's panic hook exists.
    // (An Objective-C exception is NOT catchable — that is why the backend never
    // calls setMathMode and always clamps the threadgroup size.)
    let gpu_status = std::panic::catch_unwind(gpu::GpuEngine::probe)
        .unwrap_or_else(|_| gpu::GpuStatus::Unavailable("Metal probe panicked".to_string()));

    // Raw mode + alternate screen, plus a panic hook that restores the terminal
    // and then chains to the previous hook so the message and backtrace print.
    let mut terminal = ratatui::try_init()?;

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

    // Deliberately infallible (`restore` only logs). Everything below this point
    // is loss-bearing: two drains that write found wallets to the CSV, and the
    // GPU wind-down. A failure restoring the terminal must not skip them.
    ratatui::restore();

    // A quit taken straight out of Searching leaves verified matches in the
    // mpsc queue. This is the last chance to write them: `stop_search` was
    // never called on this path, so without this drain they are found wallets
    // destroyed at exit, and the summary below under-reports the run.
    app.drain_matches();

    // Restore the terminal FIRST, then wind the GPU down. Worst case in steady
    // state is ~135 ms (one command buffer + the in-flight ring + one
    // send_timeout); ~400 ms during startup. 600 ms covers both. Anything still
    // running past that is abandoned rather than hanging the exit.
    app.shutdown_gpu(Duration::from_millis(600));

    // Second drain, and not redundant: a worker that had not yet seen
    // `app.stop` when the first drain ran can enqueue a verified match
    // microseconds later, and `shutdown_gpu` may then burn up to 600 ms before
    // `main` returns and drops the receiver. Inert with respect to the GPU --
    // `gpu_rx` is None and `gpu_engines` is empty by now, so sections 1-3 of
    // `drain_matches` do nothing.
    app.drain_matches();

    let total = app.counter.load(Ordering::Relaxed);
    let matches = app.total_matches;
    if total > 0 {
        println!("\n==========================================================");
        println!("  Wallets checked : {}", total);
        println!("  Matches found   : {}", matches);
        if let Some(start) = app.start_time {
            println!("  Elapsed time    : {:.2?}", start.elapsed());
        }
        if matches > 0 && app.csv_write_failures == 0 {
            println!("  Saved to        : {}", app.csv_path.display());
            println!("  SECURITY WARNING: CSV contains plaintext seed phrases.");
            println!("                    File is chmod 0600 (owner-only). Move to");
            println!("                    an encrypted location and delete the original.");
        } else if app.csv_write_failures > 0 {
            println!(
                "  NOT SAVED       : {} matches could not be written to {}",
                app.csv_write_failures,
                app.csv_path.display()
            );
        }
        println!("==========================================================\n");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
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
