> Generated: 2026-08-24 | Token-lean format for LLM context

# TUI

`src/main.rs` runs the event loop directly; `src/app.rs` owns the state machine; `src/ui.rs` renders. The TUI uses Ratatui 0.29 + Crossterm 0.28 with `EnterAlternateScreen` and raw mode.

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
```

Tick rate is `Duration::from_millis(100)` — UI redraws ~10 fps. On exit, alt-screen is left, raw mode disabled, and a summary printed (counts + CSV warning if matches were found).

## State Machine

```
AppState::Configuring  ─── Enter (validate OK) ───►  AppState::Searching
        ▲                                                    │
        └────── Ctrl+C / stop_search ────────────────────────┘
                                                             │
        q (any state) ── should_quit = true ─► main loop break
```

## App Struct (`src/app.rs:21`)

| Field | Type | Purpose |
|-------|------|---------|
| `state` | `AppState` | `Configuring \| Searching` |
| `should_quit` | `bool` | Top-level event-loop exit flag |
| `active_field` | `usize` | Currently focused config field (0..field_count) |
| `chain` | `ChainKind` | Selected chain |
| `match_position` | `MatchPosition` | StartsWith / EndsWith / StartsAndEndsWith |
| `vanity_prefix`, `vanity_suffix` | `String` | User input |
| `case_sensitive` | `bool` | EVM = EIP-55 check, Solana/Monero/TON = case-folded compare, Bitcoin = no-op |
| `thread_count` | `String` | User-typed; validated into `validated_thread_count: usize` |
| `error_message` | `Option<String>` | Inline form error (red text in config panel) |
| `show_help` | `bool` | Help popup overlay |
| `matches` | `Vec<Match>` | Found vanity addresses |
| `selected_match` | `usize` | Highlighted row in match table / detail view source |
| `counter` | `Arc<AtomicU64>` | Shared with workers — total candidates checked (advances by `Chain::BATCH`) |
| `start_time` | `Option<Instant>` | Wall-clock start, for rate + ETA |
| `stop` | `Arc<AtomicBool>` | Worker cancellation |
| `rx` | `Option<mpsc::Receiver<Match>>` | Drained each tick |
| `thread_pool` | `Option<rayon::ThreadPool>` | Owns worker threads; `None` when not searching |

`Match` is a struct (not a tuple) with fields `{ chain, address, secret_hex, mnemonic: String }`.

## Field Layout

`field_count()` (`app.rs:76`) returns 5 normally, 6 when match_position is `StartsAndEndsWith`.

| Position | StartsWith / EndsWith | StartsAndEndsWith |
|----------|----------------------|-------------------|
| 0 | Chain | Chain |
| 1 | Match position | Match position |
| 2 | Vanity (prefix or suffix per match position) | Prefix |
| 3 | Case | Suffix |
| 4 | Threads | Case |
| 5 | — | Threads |

`is_text_field()` (`app.rs:84`): fields 2, 3 (when both), and the last field (threads).

## Key Handling (`app.rs:336`)

Top-level: `key.kind != Press` → ignored. Help popup dismissed by any key. `Ctrl+C` either stops search (Searching) or quits (Configuring). `h` toggles help unless typing in a text field.

| Field | Keys |
|-------|------|
| Chain (0) | `Left/Right` cycle, `1/2/3/4/5` direct (Solana/EVM/Bitcoin/TON/Monero) |
| Match (1) | `Left/Right` cycle, `1/2/3` direct |
| Vanity prefix (2) | Charset chars push, `Backspace` pop, invalid chars set red error |
| Suffix (3 if both) | Same as prefix |
| Case (3 or 4) | `y/Y` → true, `n/N` → false, `Left/Right` toggle |
| Threads (last) | digits push (max 3 chars), `Backspace` pop |
| Any | `Tab/Down`/`BackTab/Up` cycle fields, `Enter` validate+start, `q` quit (non-text) |

In `AppState::Searching`: `Up/Down` browse `selected_match`, `q` stops & quits, `Ctrl+C` stops to config.

## Validation (`app.rs:174`)

1. Pick `input_str` per `match_position` (suffix when `EndsWith`, otherwise prefix).
2. Empty → `"Vanity string cannot be empty"`.
3. Length > `chain.max_vanity()` → `"Must be 1-N characters"`.
4. Any char not in `chain.charset()` → `"'X' is not valid for this chain"`.
5. If `StartsAndEndsWith`, repeat 2-4 for suffix.
6. Threads: parse `usize`, must be `1..=2*num_cpus`.

`validated_thread_count` is populated for `start_search()` to consume.

## Search Lifecycle (`app.rs:214`)

```rust
start_search:
    reset counters, atomics, matches, time
    state = Searching
    matcher = Matcher::new(prefix, suffix, case_sensitive, chain)   // 4 args
    open_csv_secure() → write header if file is empty
    pool = rayon::ThreadPoolBuilder::num_threads(N).build()
    pool.spawn(move || (0..N).par_iter().for_each(|_| chain.search(&matcher, &stop, &counter, &tx)))

stop_search:                                    // app.rs:264
    stop.store(true)
    rx = None       (drops sender side eventually)
    thread_pool = None  (drops pool — workers exit after their current batch)
    state = Configuring
```

Workers check `stop` once per `generate_batch` (4 candidates; ~1 ms for BIP-39 chains, ~100 ms for TON).

`detect_optimal_threads()` (line 319): if `logical > physical` (x86 hyperthreaded) → physical; otherwise (Apple Silicon) → logical. Validation still allows up to `2 × num_cpus`, which measures slower than `num_cpus` on M1.

`drain_matches` (line 272): non-blocking `try_recv` loop. For each `Match`, opens CSV via `open_csv_secure()`, appends a row using `payload.chain / address / secret_hex / mnemonic`, pushes to `matches`, advances `selected_match`.

## CSV Output

Path: `vanity_wallets.csv` in CWD. Single chokepoint: `open_csv_secure()` (`src/app.rs:297`) — every open goes through it. The function:
1. `OpenOptions::create(true).append(true)`, with `mode(0o600)` on Unix.
2. After open, re-asserts `0o600` via `set_permissions` in case the file pre-existed with looser perms.

Header (`Chain, Address, Private Key (hex), Seed Phrase`) is written by `start_search` only when the file is empty. Rows appended one per match by `drain_matches`.

## Stats / ETA (`ui.rs:201`, `app.rs:116-172`)

| Stat | Source |
|------|--------|
| Checked | `counter.load(Relaxed)`, formatted via `format_count` (K/M/B/T) |
| Rate | `count / elapsed_secs` |
| Matches | `app.matches.len()`, green if > 0 |
| Elapsed | `start.elapsed().as_secs()` |
| Expected | `effective_alphabet_size().pow(total_vanity_chars)` (geometric mean) |
| ETA | `expected / rate` — uses live rate when searching, otherwise `single_thread_rate(chain) × thread_count` |

`effective_alphabet_size`: 33/58 (Solana, Monero), 16/32 (EVM, where 32 = case-sensitive EIP-55), 32 (Bitcoin, lowercase only), 38/64 (TON).

`single_thread_rate` (`app.rs:149`) holds per-chain throughput measured on an M1 P-core with the 4-lane PBKDF2 path: Solana 3470/s, EVM 3115/s, Bitcoin 3115/s, TON 38.4/s, Monero 28600/s — used for ETA estimation when no live rate is yet available.

`format_duration`: `< 1s`, `Ns`, `Nm Ns`, `Nh Nm`, `Nd Nh`, `N.Ny`, `>100y`.

## Render Layout (`ui.rs:13`)

```
┌── 20% banner (vanaddy logo + version) ──────────────────────┐
├── 25% left panel ───┬── 75% right panel ───────────────────┤
│ Config form         │ (Configuring + 0 matches: placeholder)│
│ Stats (9 lines)     │ Match table (60%)                    │
│ Key hints (3 lines) │ Detail view (40%)                    │
└─────────────────────┴───────────────────────────────────────┘
```

Match table (`ui.rs:340`) & detail view (`ui.rs:384`) access `Match` fields by name (`.chain`, `.address`, `.secret_hex`, `.mnemonic`).

Help popup (`render_help_popup`, line 266): centered 56×26 `Block` with key bindings, dismissed by any key.

## Tests

- `app::tests::start_stop_restart_does_not_leak_threads` — start/stop/restart cycle leaves `thread_pool == None`, `stop == true`.
- `chains::tests::search_counts_whole_batches_and_honours_stop` — worker loop stops on the flag and counts in multiples of `BATCH`.
- `ui::tests::*` — `format_count` and `format_duration` units.
