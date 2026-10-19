> Generated: 2026-10-19 | Token-lean format for LLM context

# TUI

`src/main.rs` runs the event loop, `src/app.rs` owns the state machine, `src/ui.rs` renders. Ratatui 0.29 + Crossterm 0.28. `main` probes the GPU with `catch_unwind(gpu::probe)` (panic → `Unavailable("Metal probe panicked")`) BEFORE `ratatui::try_init()`, which installs a panic hook (`restore()` then the previous hook), enables raw mode, enters the alternate screen.

## Event Loop (`main.rs:16`)

```rust
let mut terminal = ratatui::try_init()?;
let mut app = App::with_gpu_status(gpu_status);
loop {
    terminal.draw(|f| ui::ui(f, &app))?;
    if event::poll(100ms)? {
        if let Event::Key(key) = event::read()? { app::handle_key_event(&mut app, key); }
    }
    app.drain_matches();
    if app.should_quit { app.stop.store(true, Relaxed); break; }
}
ratatui::restore();        // infallible (logs); FIRST, so the drains below always run.
                           // ponytail: stops at first error — failed disable_raw_mode skips LeaveAlternateScreen
app.drain_matches();       // quit straight out of Searching never called stop_search
app.shutdown_gpu(600ms);   // poll, never a blocking join
app.drain_matches();       // workers may enqueue during the wind-down
```

Summary (only if `counter > 0`): checked (`counter`), matches (`total_matches`, not `matches.len()`), elapsed. `Saved to` + plaintext-seed SECURITY WARNING when `matches > 0 && csv_write_failures == 0`; `NOT SAVED : N matches could not be written to <path>` when failures > 0.

## State Machine

```
AppState::Configuring ─── Enter (validate Ok, CSV opens) ───► Searching
        ▲                                                       │
        └──────────── Ctrl+C → stop_search ─────────────────────┘
Configuring: q (non-text field) / Ctrl+C → should_quit
Searching:   q → stop_search + should_quit
CSV open/header failure → stays Configuring: no Rayon pool, no GPU thread
```

## App Struct (`app.rs:42`)

| Field | Type | Purpose |
|-------|------|---------|
| `state` / `should_quit` | `AppState` / `bool` | `Configuring \| Searching`; loop exit |
| `active_field` | `usize` | focused form row |
| `chain` / `match_position` | `ChainKind` / `MatchPosition` | default `Solana` / `StartsWith` |
| `vanity_prefix`, `vanity_suffix` | `String` | typed buffers |
| `case_sensitive` | `bool` | default `false` |
| `thread_count` / `validated_thread_count` | `String` / `usize` | default `detect_optimal_threads()`; frozen by `validate` |
| `error_message` / `show_help` | `Option<String>` / `bool` | red Config line; help overlay |
| `matches` | `VecDeque<Match>` | window, cap `MATCH_CAP` = 500 |
| `total_matches` | `u64` | every drained row, incl. evicted |
| `csv_path` / `csv_file` (private) | `PathBuf` / `Option<File>` | `CSV_PATH` (tests: temp dir); held open for the search |
| `csv_write_failures` | `u64` | failed row writes this run |
| `selected_match` | `usize` | index into the window |
| `counter` / `stop` | `Arc<AtomicU64>` / `Arc<AtomicBool>` | fresh `Arc`s per `start_search` |
| `start_time` | `Option<Instant>` | rate, ETA, elapsed |
| `rx` / `thread_pool` | `Option<mpsc::Receiver<Match>>` / `Option<rayon::ThreadPool>` | drained each tick; drop signals workers to exit (rayon does not join) |
| `gpu_status` | `GpuStatus` | single source the TUI renders |
| `gpu_requested` / `validated_gpu` | `bool` | form toggle / frozen by `validate` |
| `gpu_health` | `Arc<GpuHealth>` | fault cell + `seeds_delivered`; fresh per `start_search` |
| `gpu_rx` / `gpu_engines` | `Option<GpuRx>` / `Vec<GpuEngine>` | this run's seed channel clone; parked engines, never joined on UI thread |

`App::new()` = `with_gpu_status(Unavailable("not probed"))`, so tests cannot spawn a GPU. `with_gpu_status` (`app.rs:121`) reads env once: `env_off = gpu_env_off(VANADDY_GPU, VANADDY_NO_GPU)`; `gpu_requested = !env_off && Ready`; env-off rewrites ONLY a `Ready` probe to `Disabled(UserOff)`. `gpu_env_off` (`app.rs:766`, pure): `VANADDY_NO_GPU` present, or `VANADDY_GPU` trimmed+lowercased in `0|off|false|no`.

## Field Layout

`field_count()` (`app.rs:181`): 6, or 7 when `StartsAndEndsWith`. GPU = `field_count() - 2`, Threads = `field_count() - 1`. Form row index == field index.

| Index | StartsWith | EndsWith | StartsAndEndsWith |
|-------|-----------|----------|-------------------|
| 0 / 1 | Chain / Match | Chain / Match | Chain / Match |
| 2 | Prefix | Suffix | Prefix |
| 3 | Case | Case | Suffix |
| 4 | GPU | GPU | Case |
| 5 | Threads | Threads | GPU |
| 6 | — | — | Threads |

`is_text_field()` (`app.rs:205`): 2; 3 when both; last. `patterns()` (`app.rs:216`) → `(prefix, suffix)`: StartsWith `(prefix,"")`, EndsWith `("",suffix)`, both `(prefix,suffix)`; feeds `total_vanity_chars`, `validate`, `start_search`.

## Key Handling (`app.rs:785`)

Order: non-`Press` ignored → help open: any key closes → `Ctrl+C` (Searching: `stop_search`; else quit) → `h` opens help if Searching or not a text field → dispatch by state.

| Field | Keys |
|-------|------|
| Chain (0) | `Left/Right` cycle `CHAINS`, `1`–`5` Solana/EVM/Bitcoin/TON/Monero |
| Match (1) | `Left/Right` cycle `POSITIONS`, `1/2/3` |
| Vanity (2, 3 if both) | `edit_vanity`: charset char push (`Max N chars` at limit), other char → `'c' not valid for X — allowed: …`, `Backspace` |
| Case (`both ? 4 : 3`) | `y/n` (any case), `Left/Right` toggle |
| GPU (`field_count()-2`) | `y/n`, `Left/Right`. Off always works + clears error. On refused, precedence: `Unavailable` → `GPU unavailable: r`; `Disabled(Backend(e))` → `GPU disabled this session: {e:?}`; other `Disabled` → `GPU disabled this session: {r:?}`; non-EVM → `GPU offload is EVM-only — X runs on CPU` |
| Threads (last) | ASCII digits, max 3 chars, `Backspace` |
| Any (Configuring) | `Tab/Down` next, `BackTab/Up` prev (both clear error), `Enter` validate → `start_search` or error, `q` quit (non-text) |

Searching (`app.rs:1001`): `Up/Down` move `selected_match` (clamped), `q` stop + quit. `gpu_requested` survives chain changes.

## Validation (`app.rs:344`)

1. Each active pattern: empty → `Vanity string cannot be empty`; `s.len() > max_vanity()` → `Must be 1-N characters`; char outside `charset()` → `'X' is not valid for this chain`. Suffix in both mode: `Suffix cannot be empty` / `Suffix must be …`.
2. Threads: parse fail → `Invalid thread count`; outside `1..=2*num_cpus::get()` → `Threads must be 1-N`. Then `validated_gpu = gpu_effective()` — advisory, never an `Err`.

`gpu_effective()` (`app.rs:196`): `gpu_requested && status ∈ {Ready, Initializing, Running} && chain == Evm`. `detect_optimal_threads` (`app.rs:781`): `get_physical().min(get())`.

## Search Lifecycle

```
start_search (app.rs:388):
    reap finished engines: extract_if(is_finished).for_each(reap)   // non-blocking
    spawn_gpu = validated_gpu && gpu_engines.is_empty()
        validated_gpu && !spawn_gpu → error "GPU: previous session winding down — this run is CPU only"
    reset matches, total_matches, csv_write_failures, selected_match, counter, stop, start_time
    state = Searching
    Matcher::new(prefix, suffix, case_sensitive, chain); mpsc::channel → rx
    open_csv_secure → header via write_row if len == 0 → hold csv_file
        open Err → "Cannot open <path>: e"; header Err → "Failed to write CSV header (…)"
        either: rx = None, csv_file = None, state = Configuring, return
    gpu_health = fresh Arc (unconditional)
    if spawn_gpu: crossbeam bounded(CHANNEL_CAPACITY = 32), GpuEngine::start(tx, health),
                  gpu_status = engine.status(), push engine, gpu_rx = Some(rx.clone())
    else gpu_rx = None
    Rayon pool(N).spawn: (0..N).into_par_iter → chain.search(&matcher,&stop,&counter,&tx,gpu_rx,&health); drop(tx)

stop_search (app.rs:512):
    stop = true; thread_pool = None (code comment says "join"; rayon-core 1.12 ThreadPool::drop only signals, never blocks)
    drain_matches                    // queued matches still hit the CSV
    rx = None; gpu_rx = None         // producer wake-path #2
    signal_stop each engine          // no join
    dev+ino of held csv_file vs csv_path → "The CSV file was replaced|deleted during the search; …"
    csv_file = None; state = Configuring
```

`shutdown_gpu(deadline)` (`app.rs:571`): signal all, `gpu_rx = None`, reap finished every 5 ms until empty or deadline, then `clear()` (abandon; `GpuEngine::drop` must not join). `disable_gpu(reason)` (`app.rs:599`): `Disabled(reason)`, `gpu_requested = validated_gpu = false`, `gpu_rx = None` — sticky for the process.

`drain_matches` (`app.rs:606`), every tick:

1. Fault: `gpu_health.disable` set, status not `Disabled` → `disable_gpu(take_reason() or Panicked)`.
2. Refresh: `gpu_rx` live, not `Disabled` → `gpu_status = gpu_engines.last().status()` (`Initializing` → `Running`). Quiet exit: Searching, `gpu_rx` live, no fault, any engine finished → `disable_gpu(Panicked)`.
3. `try_recv` loop: write via `csv_file` (`write_match_row`) or `append_match_row(csv_path)` if no handle. `Err` → `csv_write_failures += 1`, error `CSV write failed (e); matches are NOT being saved`, `stop = true`; row still recorded. `total_matches += 1`, push back, evict past `MATCH_CAP` (decrement `selected_match`), follow the end unless scrolled up.

## CSV Output

| Item | Detail |
|------|--------|
| `CSV_PATH` (`app.rs:698`) | `"vanity_wallets.csv"` |
| `open_csv_secure(path)` (`app.rs:709`) | create+append; `#[cfg(unix)]` `.mode(0o600)`, then `set_permissions(path, 0o600)` |
| Header | `Chain, Address, Private Key (hex), Seed Phrase`; only when file len is 0 |
| `write_match_row(file, &Match)` (`app.rs:736`) | `[chain, address, secret_hex, mnemonic]` → `write_row` (`app.rs:741`: `csv::WriterBuilder` `has_headers(false)`, one record, flush) |
| `append_match_row(path, &Match)` (`app.rs:750`) | `open_csv_secure` + `write_match_row`; the no-handle fallback |

0600 re-asserted per open, not per row. Trust boundary is upstream: a GPU candidate becomes a `Match` only after `verify::verify_gpu`.

## Stats / ETA (`ui.rs:295`, `app.rs:234`–`342`)

| Row | Source |
|-----|--------|
| `Checked:` / `Rate:` | `counter` via `format_count` / `count / elapsed.as_secs()` (0 before start or at 0 s) |
| `GPU rate:` (inserted at index 2) | `gpu_stats_line`, see Render Layout |
| `Matches:` / `Elapsed:` | `total_matches` (green if > 0) / `{secs}s` |
| `Expected:` | `1 in effective_alphabet_size().powi(total_vanity_chars)`; absent when no vanity |
| `ETA:` | `projected_seconds`: live `count / max(secs, 0.5)` (≥ 1) once started; else `estimated_rate` |

`stats_height` = 4 + Expected? + ETA? + GPU row? + 2 borders. `effective_alphabet_size` (sensitive / insensitive): Solana/Monero 58/33, EVM 32/16, Bitcoin 32, TON 64/38.

`single_thread_rate`: Solana 3470, EVM 3115, Bitcoin 3115, TON 38.4, Monero 28600. `estimated_rate`: `threads = thread_count.parse::<f64>().unwrap_or(1).max(1)`; with `gpu_effective()`: `13_600 + (threads - min(13_600 × 50.5e-6, threads)) × per_thread` (`EVM_GPU_SEEDS_PER_SEC`, `EVM_GPU_TAIL_SECS`). Pre-search only; `per_thread × threads` is already ~1.6× optimistic on 4P+4E. `gpu_measured_rate` (`app.rs:327`): `(seeds_delivered / max(secs, 0.5), round(min(gpu,total)/total × 100))`; `(0,0)` before start. Measured, never modelled. `format_count`: raw < 1000, then `.1` K/M/B/T. `format_duration`: `—` (non-finite/negative), `< 1s`, `Ns`, `Nm Ns`, `Nh Nm`, `Nd Nh`, `N.Ny`, `>100y`.

## Render Layout (`ui.rs:14`)

```
┌ 20% banner: panel " Vanaddy ", 6-line logo + "v0.6 — Multi-Chain Vanity Address Generator" (cyan) ┐
├ Min(0) body ── 25% left ─────────────┬── 75% right ───────────────────────────────────────────────┤
│  Min(10) " Config "                  │ Configuring && no matches: " Results " placeholder         │
│  Length(stats_height) " Stats "      │ else 60% " Matches " table / 40% " Detail "                │
└ Length(1) key hints ─────────────────┴────────────────────────────────────────────────────────────┘
show_help → help popup overlay
```

`panel(title)` (`ui.rs:42`): `Block` all borders, DarkGray border, title; every pane except the help popup.

Config (`ui.rs:81`): ` Chain:`, ` Match:` (`[Starts with|Ends with|Starts & Ends]`), ` Prefix:` (unless EndsWith), ` Suffix:` (unless StartsWith), ` Case:` (`[Yes|No]`), ` GPU:`, ` Threads:`; empty buffers show `_`. Focused row Yellow bold, others White, all DarkGray while Searching. Chain hint (DarkGray): Bitcoin after `bc1q`, TON after `UQ` (W5, Tonkeeper), Monero after `4`. `error_message` red, last.

| `gpu_status` | Config ` GPU:` value (`gpu_form_value`) | Stats `gpu_stats_line` |
|--------------|-----------------------------------------|------------------------|
| `Unavailable(r)` | `[n/a — sanitize(r, 24)]` dim | none |
| `Disabled(r)` | `[disabled — gpu_reason_label(r)]` red | ` GPU rate: OFF — label (CPU cont.)` red |
| non-EVM chain | `[n/a — EVM only]` dim | — |
| `Ready` | `[On]` green / `[Off]` white | none |
| `Initializing` | as Ready | ` GPU rate: initialising…` yellow; none if `gpu_rx` is `None` |
| `Running` | as Ready | ` GPU rate: N/s (P%)` green; none if `gpu_rx` is `None` |

`gpu_reason_label`: bare variant name (`Backend(e)` → the `GpuError` variant). `sanitize_status_text(s, max)`: control chars → space, char-boundary truncate with `…`. Label keeps focus styling; value carries the state style.

Match table (`ui.rs:447`): `#`, `Chain`, `Address` (cyan bold); widths 4 / 10 / Min(20). Address > 30 chars → first 14 + `...` + last 10. `#` = `total_matches - matches.len() + i + 1`. Highlight DarkGray bg bold on `selected_match`. Detail (`ui.rs:492`): `  No matches yet` when empty; else ` Chain:`, ` Address:`, ` Key:` (`secret_hex`), ` Phrase:` (`mnemonic`), wrapped. Key hints (`ui.rs:353`): ` h:Help  Enter:Start  q:Quit` / ` h:Help  Ctrl+C:Stop  q:Quit`. Help popup (`ui.rs:406`): `HELP_POPUP_WIDTH` 56 × `HELP_POPUP_HEIGHT` 29, clamped to area − 4, centred, black bg, cyan border; `help_lines()` = 27 lines (height − 2): Navigation, Field Input (incl. `GPU offload  Metal PBKDF2, EVM only (Apple Silicon)`), Actions, Supported Chains.

## Tests

- `app::tests` lifecycle: `start_stop_restart_does_not_leak_threads`, `stop_search_releases_everything_and_never_blocks_the_ui_thread`, `start_search_spawns_no_second_engine_while_one_winds_down`, `stop_search_drains_matches_still_queued_at_stop_time`, `stop_search_flags_a_replaced_or_deleted_csv_and_nothing_else`.
- CSV: `open_csv_secure_reasserts_0600_on_preexisting_0644`, `held_open_csv_file_takes_every_row_and_stays_0600`, `drain_falls_back_to_the_path_when_no_file_is_held`, `a_failed_csv_write_is_counted_and_never_evicts_the_only_copy`, `match_cap_evicts_oldest_and_total_keeps_counting`.
- GPU: `gpu_field_*`, `gpu_effective_requires_user_device_and_evm`, `validate_never_returns_err_for_a_gpu_reason`, `mismatch_disables_gpu_and_leaves_app_running`, `drain_matches_flags_a_quiet_gpu_exit_only_on_a_live_faultless_run`, `gpu_env_off_*`; `main::tests::probe_result_reaches_the_app`. `ui::tests`: `one_gpu_row_per_frame_never_two`, `stats_height_counts_the_gpu_row_exactly_once`, `every_pane_survives_an_80_by_24_terminal`, `help_popup_documents_gpu_offload_and_nothing_is_clipped`, `format_count_cases`, `format_duration_cases`.
