> Generated: 2026-10-19 | Token-lean format for LLM context | Source: update-codemaps

# TUI

`src/main.rs` runs the event loop. `src/app.rs` owns the state machine. `src/ui.rs` renders. Ratatui 0.29 + Crossterm 0.28, `EnterAlternateScreen`, raw mode.

`GpuEngine::probe()` runs before `enable_raw_mode`. A panic hook restores the terminal, then calls the previous hook.
## Event Loop

```rust
loop {
    terminal.draw(|f| ui::ui(f, &app))?;
    if event::poll(100ms)? {
        if let Event::Key(key) = event::read()? {
            app::handle_key_event(&mut app, key);
        }
    }
    app.drain_matches();
    if app.should_quit { app.stop.store(true, Relaxed); break; }
}
// leave alt screen FIRST (errors ignored)
app.drain_matches();
app.shutdown_gpu(600ms);   // poll, never a blocking join
app.drain_matches();       // workers may enqueue during the wind-down
// print checked / total_matches / CSV warning
```

Tick is `Duration::from_millis(100)`. Summary uses `total_matches`, not `matches.len()`. A `csv_write_failures > 0` line replaces the "saved" line.

## State Machine

```
AppState::Configuring  ─── Enter (validate OK, CSV opens) ───►  Searching
        ▲                                                         │
        └──────── Ctrl+C / stop_search ───────────────────────────┘
q (any state) ── should_quit ──► loop break (Searching q also stop_search)
```

A CSV open or header failure stays in `Configuring`. No pool and no GPU thread start.

## App Struct (`src/app.rs:42`)

| Field | Type | Purpose |
|-------|------|---------|
| `state` | `AppState` | `Configuring \| Searching` |
| `should_quit` | `bool` | event-loop exit |
| `active_field` | `usize` | focused field |
| `chain` | `ChainKind` | default `Solana` |
| `match_position` | `MatchPosition` | Starts / Ends / Both |
| `vanity_prefix`, `vanity_suffix` | `String` | user input |
| `case_sensitive` | `bool` | EVM = EIP-55; Solana/Monero/TON fold; Bitcoin no-op |
| `thread_count` | `String` | parsed into `validated_thread_count` |
| `error_message` | `Option<String>` | red text in the config panel |
| `show_help` | `bool` | help overlay |
| `matches` | `VecDeque<Match>` | window, cap `MATCH_CAP` (500) |
| `total_matches` | `u64` | every drained row, including evicted ones |
| `selected_match` | `usize` | index into the window |
| `csv_path` / `csv_file` | `PathBuf` / `Option<File>` | held open for the search |
| `csv_write_failures` | `u64` | failed row writes; search stops |
| `counter` | `Arc<AtomicU64>` | candidates (advances by `BATCH` or GPU chunk) |
| `start_time` | `Option<Instant>` | rate + ETA |
| `stop` | `Arc<AtomicBool>` | worker cancel. Not the GPU flag |
| `rx` | `Option<mpsc::Receiver<Match>>` | drained each tick |
| `thread_pool` | `Option<rayon::ThreadPool>` | `None` when idle. Drop joins |
| `gpu_status` | `GpuStatus` | what the TUI renders |
| `gpu_requested` | `bool` | form toggle. On only if probe is `Ready` and env allows |
| `gpu_env_off` | `bool` | `VANADDY_GPU=0` or `VANADDY_NO_GPU` set |
| `validated_gpu` | `bool` | frozen by `validate` |
| `gpu_health` | `Arc<GpuHealth>` | fault cell. Fresh one each `start_search` |
| `gpu_rx` | `Option<GpuRx>` | this run's seed channel |
| `gpu_engines` | `Vec<GpuEngine>` | parked. Never joined here |

`App::new()` is `Unavailable("not probed")` so tests cannot spawn a GPU by accident. `main` uses `with_gpu_status`.

## Field Layout

`field_count()` (`app.rs:192`): 6 normally, 7 when `StartsAndEndsWith`. GPU is `field_count() - 2`, between Case and Threads.

| Index | Starts / Ends | Starts & Ends |
|-------|---------------|---------------|
| 0 | Chain | Chain |
| 1 | Match | Match |
| 2 | Prefix or Suffix | Prefix |
| 3 | Case | Suffix |
| 4 | GPU | Case |
| 5 | Threads | GPU |
| 6 | — | Threads |

`is_text_field()` (`app.rs:216`): field 2, field 3 when both, and the last field (threads). GPU is not a text field.

## Key Handling (`app.rs:901`)

`key.kind != Press` is ignored. Help dismisses on any key. `Ctrl+C` stops a search or quits config. `h` opens help unless a text field is focused.

| Field | Keys |
|-------|------|
| Chain (0) | `Left/Right` cycle, `1`–`5` Solana/EVM/Bitcoin/TON/Monero |
| Match (1) | `Left/Right` cycle, `1/2/3` |
| Vanity (2) | charset push, `Backspace`, else red error |
| Suffix (3 if both) | same |
| Case (3 or 4) | `y/n`, `Left/Right` |
| GPU (`field_count()-2`) | `y/n`, `Left/Right`. Off always works. On is refused (no device, disabled, or not EVM) |
| Threads (last) | digits, max 3, `Backspace` |
| Any | `Tab/Down`, `BackTab/Up`, `Enter` validate+start, `q` quit (non-text) |

Searching: `Up/Down` move `selected_match`, `q` stops and quits, `Ctrl+C` returns to config. `gpu_requested` is not cleared when the chain changes.

## Validation (`app.rs:369`)

1. EndsWith uses the suffix; otherwise the prefix.
2. Empty → `"Vanity string cannot be empty"`.
3. Longer than `max_vanity()` → `"Must be 1-N characters"`.
4. Char outside `charset()` → `"'X' is not valid for this chain"`.
5. `StartsAndEndsWith` repeats 2–4 on the suffix.
6. Threads: `usize` in `1..=2*num_cpus`. `detect_optimal_threads` (`app.rs:884`) picks physical cores when logical > physical, else logical.

GPU never fails validation. `validated_gpu = gpu_effective()`: requested, status is `Ready|Initializing|Running`, chain is EVM. Env off rewrites a `Ready` probe to `Disabled(UserOff)` at construction. `VANADDY_GPU` matches `0|off|false|no`. `VANADDY_NO_GPU` is presence-based.

## Search Lifecycle (`app.rs:417`)

```
start_search:
    reap finished engines (non-blocking). spawn only if
        validated_gpu && gpu_engines.is_empty()
        else, if the user wanted GPU: error "winding down — CPU only"
    reset matches, total_matches, counter, stop, start_time
    state = Searching
    Matcher::new(prefix, suffix, case_sensitive, chain)
    open_csv_secure → header if empty → hold csv_file
        failure: back to Configuring, no workers
    new GpuHealth
    if spawn: crossbeam bounded(32), GpuEngine::start, status = Initializing
    Rayon pool.spawn: N workers call
        chain.search(&matcher, &stop, &counter, &tx, gpu_rx, &health)

stop_search:                         // app.rs:554
    stop = true
    thread_pool = None               // joins CPU workers
    drain_matches                    // queued matches still hit the CSV
    rx = None; gpu_rx = None
    signal_stop each engine          // no join
    inode check vs csv_path          // replaced or deleted → error_message
    csv_file = None
    state = Configuring
```

`shutdown_gpu` (`app.rs:624`) is the exit reaper: signal, poll `is_finished` until the deadline, then detach. A wedged `waitUntilCompleted` is abandoned.

`drain_matches` (`app.rs:655`), every tick:

1. If `gpu_health.disable` and status is not already `Disabled`: sticky `Disabled`, clear `gpu_requested` / `validated_gpu`, drop `gpu_rx`. CPU search continues.
2. While `gpu_rx` is live, copy `engine.status()` (`Initializing` → `Running`).
3. Engine finished with no reason, while searching and the channel is live → `Disabled(Panicked)`.
4. `try_recv` matches. Write through `csv_file` (`write_match_row`) or `append_match_row` if no handle. A write error increments `csv_write_failures`, sets `stop`, and still records the row. Push back, evict past 500, follow the end unless the user scrolled up.

## CSV Output

Path: `vanity_wallets.csv` (`CSV_PATH`). `open_csv_secure` (`app.rs:767`): create+append, Unix mode `0o600`, then `set_permissions` `0o600`. Header only when the file length is 0. Row writer is `write_match_row` (`app.rs:795`): `chain, address, secret_hex, mnemonic`. It takes `&Match`, so the `Verified` token is required. 0600 is re-asserted on open, not on each row.

## Stats / ETA (`ui.rs:326`, `app.rs:281`)

| Stat | Source |
|------|--------|
| Checked | `counter` via `format_count` |
| Rate | `count / elapsed_secs` (integer seconds) |
| GPU rate | `gpu_measured_rate`: seeds/s and % of `counter`, only while `gpu_rx` is live. Label is `GPU rate:`, not `GPU:`. `Disabled` replaces that row with `OFF — reason (CPU cont.)` |
| Matches | `total_matches` |
| Elapsed | `start.elapsed().as_secs()` |
| Expected | `effective_alphabet_size().pow(total_vanity_chars)` |
| ETA | `expected / rate`. Live rate once `start_time` is set; else `estimated_rate` |

`effective_alphabet_size`: Solana/Monero 58 or 33; EVM 16 or 32; Bitcoin 32; TON 64 or 38.

`single_thread_rate`: Solana 3470, EVM 3115, Bitcoin 3115, TON 38.4, Monero 28600. `estimated_rate` adds 13600 GPU seeds/s only when `gpu_effective()`, minus `gpu_tail_cores` (`13600 * 50.5µs`, clamped to the thread count). Pre-search only. `single_thread_rate × threads` is already ~1.6× optimistic on 4P+4E — do not call that jump the GPU.

`format_duration`: `< 1s`, `Ns`, `Nm Ns`, `Nh Nm`, `Nd Nh`, `N.Ny`, `>100y`.

## Render Layout (`ui.rs:14`)

```
20% banner (logo + "v0.6")
25% left: config (Chain…GPU, Threads, bc1q/UQ/4 hint) + dynamic stats
75% right: placeholder, or 60% match table + 40% detail
1-line key hints
```

Config GPU row label is ` GPU:`. Value: `[On]`, `[Off]`, `[n/a — EVM only]`, `[n/a — …]`, or `[disabled — reason]`. Compiler text is flattened and truncated (`sanitize_status_text`).

Match table (`ui.rs:484`) columns `#`, Chain, Address. The `#` is `total_matches - window_len + i + 1`, not the window index. Detail (`ui.rs:534`) shows chain, address, key, phrase by field name. `verified` is not rendered.

Help popup (`ui.rs:440`): 56×29, includes "GPU offload  Metal PBKDF2, EVM only". Any key dismisses it.

## Tests

- `app::tests::start_stop_restart_does_not_leak_threads` — pool is `None`, `stop` is true.
- `app::tests::stop_search_releases_everything_and_never_blocks_the_ui_thread` — no GPU join.
- `app::tests::gpu_spawn_is_skipped_while_a_previous_engine_is_still_winding_down`.
- `ui::tests::config_form_puts_the_gpu_row_between_case_and_threads` and `one_gpu_row_per_frame_never_two` (`GPU:` vs `GPU rate:`).
- `ui::tests::*` — `format_count` and `format_duration`.
