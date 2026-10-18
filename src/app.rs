use super::chains::{ChainKind, Match};
use super::matcher::{Matcher, MatchPosition};
use crossterm::event::{self, KeyCode, KeyEventKind, KeyModifiers};
use csv::WriterBuilder;
use rayon::prelude::*;
use std::{
    fs::{File, OpenOptions},
    io,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc,
    },
    time::Instant,
};

use crate::gpu::{GpuEngine, GpuHealth, GpuRx, GpuStatus};
use std::collections::VecDeque;
use std::path::PathBuf;

/// Cap on the in-memory match list.
///
/// `render_match_table` (src/ui.rs:352-370) rebuilds EVERY row — three `String`
/// allocations each — on every 100 ms frame. At a 1-character EVM vanity the
/// match rate is ~1 in 16, which the GPU roughly doubles to ~1,700/s; an
/// uncapped `Vec` therefore reaches ~300,000 allocations per frame within a
/// minute and the TUI hard-freezes. The cap bounds render cost. `total_matches`
/// carries the honest count and the CSV carries every row, so nothing is lost.
pub const MATCH_CAP: usize = 500;

/// Measured CPU cost of turning ONE GPU-supplied seed into an EVM candidate:
/// BIP-32 + kG + Keccak, everything PBKDF2 does not cover. This is the tail the
/// GPU cannot offload, and at 13,600 seeds/s it displaces ~0.69 of a core.
const EVM_GPU_TAIL_SECS: f64 = 50.5e-6;

#[derive(Clone, Copy, PartialEq)]
pub enum AppState {
    Configuring,
    Searching,
}

pub struct App {
    pub state: AppState,
    pub should_quit: bool,

    // Form fields
    pub active_field: usize,
    pub chain: ChainKind,
    pub match_position: MatchPosition,
    pub vanity_prefix: String,
    pub vanity_suffix: String,
    pub case_sensitive: bool,
    pub thread_count: String,
    /// Validated thread count, populated by validate() before start_search.
    pub validated_thread_count: usize,
    pub error_message: Option<String>,

    // Help overlay
    pub show_help: bool,

    // Search state
    pub matches: VecDeque<Match>,
    /// Every match this run that reached `drain_matches`, including those
    /// evicted by MATCH_CAP. Matches still queued when the user stops are
    /// drained by `stop_search` before the receiver is dropped (Task 6.7
    /// Step 3), so this is the honest run total. It is the number the stats
    /// pane and the exit summary must show.
    pub total_matches: u64,
    /// Where the CSV lives. Production is `CSV_PATH`; tests point it at a temp
    /// dir, because `cargo test` runs tests as threads in one process and
    /// `set_current_dir` is therefore racy.
    pub csv_path: PathBuf,
    /// The CSV handle held open for the whole search. At a 1-character EVM
    /// vanity the match rate reaches ~1,700/s; reopening per row costs ~5,100
    /// syscalls/s (open + fstat + chmod) on the UI thread. 0600 is asserted on
    /// this open, as on every other — but note this CHANGES the guarantee
    /// CLAUDE.md states: it is re-asserted once per search now, not once per
    /// row. Step 8a rewrites that line to match.
    csv_file: Option<File>,
    /// How many rows failed to reach the CSV this run. Nothing in this codebase
    /// checks that a row was actually written, so eviction cannot claim "it is
    /// already durably in the CSV" without this counter: while it is non-zero
    /// the in-memory list is the ONLY copy of those seed phrases, so eviction
    /// stops (Step 7) and the exit summary must not claim they were saved
    /// (Step 9).
    pub csv_write_failures: u64,
    pub selected_match: usize,
    pub counter: Arc<AtomicU64>,
    pub start_time: Option<Instant>,
    pub stop: Arc<AtomicBool>,
    pub rx: Option<mpsc::Receiver<Match>>,
    pub thread_pool: Option<rayon::ThreadPool>,

    // ---- GPU offload (EVM only). See docs/superpowers/specs/2026-08-26-metal-gpu-pbkdf2-design.md
    /// From `GpuEngine::probe()` at startup; promoted to `Running`/`Disabled`
    /// by `drain_matches`. This is the single source of truth the TUI renders.
    pub gpu_status: GpuStatus,
    /// The form toggle. Defaults to "on" iff the probe found a device and the
    /// env lever did not veto it.
    pub gpu_requested: bool,
    /// `VANADDY_GPU=0` or `VANADDY_NO_GPU=1` was set. Env ALWAYS wins over the
    /// form; kept as a field so the TUI can say *why* the toggle is stuck off.
    pub gpu_env_off: bool,
    /// Mirrors `validated_thread_count`: the decision `validate()` made, frozen
    /// so `start_search` acts on what the user saw, not on a status that may
    /// have changed since.
    pub validated_gpu: bool,
    /// Shared fault cell. Written by the producer thread and by Rayon workers,
    /// read by `drain_matches` on the UI tick. Never a Mutex on this path.
    pub gpu_health: Arc<GpuHealth>,
    /// App's own clone of the seed channel. Dropping it is shutdown wake-path
    /// #2: once App and every worker have dropped their clones, a producer that
    /// missed the stop flag still exits on `Disconnected`.
    pub gpu_rx: Option<GpuRx>,
    /// Parked engines awaiting reap. NEVER joined on the UI thread — see
    /// `stop_search` and `shutdown_gpu`.
    ///
    /// `pub` like every other `App` field, and not for style: the first READ is
    /// Task 6.6 Step 4, so a private field here fires `warning: field
    /// `gpu_engines` is never read` and pushes the clippy count from 12 to 13
    /// through five consecutive gates (6.1, 6.2, 6.3, 6.4, 6.5). Measured.
    pub gpu_engines: Vec<GpuEngine>,
}

impl App {
    /// The no-probe constructor: used by tests and by any caller that has not
    /// run `GpuEngine::probe()`. Deliberately yields a status that
    /// `gpu_effective()` rejects, so nothing can spawn a GPU by accident.
    pub fn new() -> Self {
        App::with_gpu_status(GpuStatus::Unavailable("not probed".to_string()))
    }

    /// The real constructor. `main()` probes for a Metal device BEFORE entering
    /// raw mode and hands the result in here.
    pub fn with_gpu_status(gpu_status: GpuStatus) -> Self {
        let recommended_threads = detect_optimal_threads();
        // The one env read in the binary. The local is deliberately NOT named
        // `gpu_env_off`: that would shadow the function in the value namespace
        // for the rest of this body.
        let env_off = gpu_env_off(
            std::env::var("VANADDY_GPU").ok().as_deref(),
            std::env::var("VANADDY_NO_GPU").ok().as_deref(),
        );
        // Default the toggle on only when a device actually exists. `Ready` is
        // the post-probe resting state; anything else means there is nothing to
        // turn on.
        let gpu_requested = !env_off && matches!(gpu_status, GpuStatus::Ready { .. });
        let mut app = App {
            state: AppState::Configuring,
            should_quit: false,
            active_field: 0,
            chain: ChainKind::Solana,
            match_position: MatchPosition::StartsWith,
            vanity_prefix: String::new(),
            vanity_suffix: String::new(),
            case_sensitive: false,
            thread_count: recommended_threads.to_string(),
            validated_thread_count: 0,
            error_message: None,
            show_help: false,
            matches: VecDeque::new(),
            total_matches: 0,
            csv_path: PathBuf::from(CSV_PATH),
            csv_file: None,
            csv_write_failures: 0,
            selected_match: 0,
            counter: Arc::new(AtomicU64::new(0)),
            start_time: None,
            stop: Arc::new(AtomicBool::new(false)),
            rx: None,
            thread_pool: None,
            gpu_status,
            gpu_requested,
            gpu_env_off: env_off,
            validated_gpu: false,
            gpu_health: Arc::new(GpuHealth::default()),
            gpu_rx: None,
            gpu_engines: Vec::new(),
        };
        // Make the veto visible. A `Ready` probe the environment vetoed becomes
        // `Disabled(UserOff)`, so the config row can say *why* the toggle refuses
        // to turn on — this is the ` GPU:      [disabled — UserOff]` row Task 8.3
        // Step 9 checks for. ONLY `Ready` is rewritten: when there was no device
        // to begin with, `Unavailable(..)` is the more informative status and
        // must survive.
        if env_off && matches!(app.gpu_status, GpuStatus::Ready { .. }) {
            app.gpu_status = GpuStatus::Disabled(crate::gpu::GpuDisableReason::UserOff);
        }
        app
    }

    /// Chain, match position, vanity (+ suffix when StartsAndEndsWith), case,
    /// GPU, threads. GPU sits at `field_count() - 2` — between Case and
    /// Threads — so the Case arm's hard-coded `if both { 4 } else { 3 }` and
    /// the Threads arm's `field_count() - 1` both stay correct, and
    /// `is_text_field` needs no change at all.
    pub fn field_count(&self) -> usize {
        if matches!(self.match_position, MatchPosition::StartsAndEndsWith) {
            7
        } else {
            6
        }
    }

    /// The GPU actually runs iff: the user wants it, a device exists and has not
    /// faulted, and the chain is EVM.
    ///
    /// ADVISORY ONLY. `validate()` never returns `Err` because this is false —
    /// the CPU path is complete on its own, and this value goes stale the moment
    /// a fault is raised mid-run. Blocking a search on it would strand the user
    /// in the config screen with a toggle they cannot satisfy.
    pub fn gpu_effective(&self) -> bool {
        self.gpu_requested
            && matches!(
                self.gpu_status,
                GpuStatus::Ready { .. } | GpuStatus::Initializing | GpuStatus::Running { .. }
            )
            && self.chain == ChainKind::Evm
    }

    pub fn is_text_field(&self) -> bool {
        match self.active_field {
            2 => true,
            3 if matches!(self.match_position, MatchPosition::StartsAndEndsWith) => true,
            f if f == self.field_count() - 1 => true,
            _ => false,
        }
    }

    pub fn valid_charset(&self) -> &'static str {
        self.chain.charset()
    }

    pub fn max_vanity_len(&self) -> usize {
        self.chain.max_vanity()
    }

    /// Total number of vanity characters the user is searching for
    /// (prefix + suffix, depending on match position).
    pub fn total_vanity_chars(&self) -> usize {
        match self.match_position {
            MatchPosition::StartsWith => self.vanity_prefix.chars().count(),
            MatchPosition::EndsWith => self.vanity_suffix.chars().count(),
            MatchPosition::StartsAndEndsWith => {
                self.vanity_prefix.chars().count() + self.vanity_suffix.chars().count()
            }
        }
    }

    /// Effective alphabet size for probability calculations. Case-insensitive
    /// searches match against a smaller effective alphabet because a single
    /// typed char matches both upper and lower variants in the address.
    pub fn effective_alphabet_size(&self) -> u64 {
        match self.chain {
            // Base58 alphabet: 58 chars case-sensitive. Case-insensitive folds
            // letters to ~24 unique + 9 digits = 33 effective chars.
            ChainKind::Solana | ChainKind::Monero => if self.case_sensitive { 58 } else { 33 },
            // EVM hex: 16 values per position. Case-sensitive uses EIP-55 where
            // each letter position must match both value (1/16) and case (1/2) →
            // effective 32 for letters. Digits unchanged (1/10 → 1/16). Approximate
            // uniformly as 32 for case-sensitive EVM.
            ChainKind::Evm => if self.case_sensitive { 32 } else { 16 },
            // Bech32 is lowercase-only (32 alphabet). Case toggle has no effect.
            ChainKind::Bitcoin => 32,
            // Base64url: A-Z a-z 0-9 - _ = 64 case-sensitive. Insensitive folds
            // letters to 26 unique + 10 digits + 2 symbols = 38.
            ChainKind::Ton => if self.case_sensitive { 64 } else { 38 },
        }
    }

    /// Expected number of generated addresses before a match (geometric mean).
    /// Returns None if no vanity is set (trivial).
    pub fn expected_attempts(&self) -> Option<u64> {
        let n = self.total_vanity_chars();
        if n == 0 {
            return None;
        }
        let alphabet = self.effective_alphabet_size() as f64;
        let expected = alphabet.powi(n as i32);
        Some(expected as u64)
    }

    /// Rough per-thread throughput estimate (attempts/sec), used for ETA when
    /// the user hasn't started a search yet. Measured on an Apple M1 P-core
    /// (release build, 4-lane PBKDF2 path); see the table in CLAUDE.md.
    fn single_thread_rate(&self) -> f64 {
        match self.chain {
            ChainKind::Solana => 3_470.0, // ~288 µs/gen
            ChainKind::Evm => 3_115.0,    // ~321 µs/gen
            ChainKind::Bitcoin => 3_115.0, // ~321 µs/gen
            ChainKind::Ton => 38.4,       // ~26 ms/gen — intrinsically slow
            ChainKind::Monero => 28_600.0, // ~35 µs/gen
        }
    }

    /// Pre-search throughput estimate, attempts/sec. `projected_seconds` uses
    /// this ONLY until a search has actually started; after that it uses the
    /// live measured rate, which is automatically correct because GPU
    /// candidates increment the same `counter`.
    ///
    /// The GPU does not add its seeds/s for free: every GPU seed still costs
    /// the CPU `EVM_GPU_TAIL_SECS`, so the CPU workers lose that fraction of a
    /// core. Gate on `gpu_effective()` alone — the status here is always
    /// `Ready` (the pre-search resting state), never `Running`, so also
    /// requiring `Running` would make this branch dead code.
    ///
    /// Honest hybrid on the M1 defaults: ~23,000-26,000 cand/s, about 2x.
    /// The number this returns is higher than that, because
    /// `single_thread_rate() * threads` is ALREADY ~1.6x optimistic on a
    /// 4P+4E machine. That pre-existing optimism is not fixed here — it would
    /// change ETA behaviour for all five chains — but do not attribute the
    /// post-Enter ETA jump to the GPU.
    fn estimated_rate(&self) -> f64 {
        let threads = self.thread_count.parse::<f64>().unwrap_or(1.0).max(1.0);
        let per_thread = self.single_thread_rate();
        if !self.gpu_effective() {
            return per_thread * threads;
        }
        // Single source of truth — Task 4.8 measures and owns this number.
        let gpu_rate = crate::gpu::EVM_GPU_SEEDS_PER_SEC;
        let tail = Self::gpu_tail_cores(gpu_rate, threads);
        gpu_rate + (threads - tail) * per_thread
    }

    /// The GPU's CPU tail, in cores. Clamped, and the threshold SCALES WITH
    /// `threads`: the clamp binds at `threads / EVM_GPU_TAIL_SECS`, which is
    /// ~19,800 seeds/s at one thread but ~158,400 at the default eight. It is
    /// not a fixed 19,800 — an earlier version of this comment said so, which
    /// understated the real threshold by a factor of `threads`. Above it an
    /// unclamped `threads - tail` would go negative. Extracted so the clamp can
    /// be tested directly — through `estimated_rate` it is unreachable at the
    /// defaults.
    fn gpu_tail_cores(gpu_rate: f64, threads: f64) -> f64 {
        (gpu_rate * EVM_GPU_TAIL_SECS).min(threads)
    }

    /// Projected seconds until a match. Uses live rate if searching,
    /// otherwise estimates from chain throughput × thread count (× GPU).
    pub fn projected_seconds(&self) -> Option<f64> {
        let expected = self.expected_attempts()? as f64;
        let rate = if let Some(start) = self.start_time {
            let secs = start.elapsed().as_secs_f64().max(0.5);
            let count = self.counter.load(Ordering::Relaxed) as f64;
            (count / secs).max(1.0)
        } else {
            self.estimated_rate()
        };
        Some(expected / rate)
    }

    /// Measured GPU throughput: `(seeds per second, percent of all candidates
    /// checked)`. Derived only from `GpuHealth::seeds_delivered` — which the
    /// workers increment as they actually consume GPU blocks — over observed
    /// wall time. NEVER modelled: mid-run throughput collapse to 3,000-7,000
    /// seeds/s was reproducibly observed while the desktop compositor was
    /// busy, and a modelled rate would lie by up to 4x.
    pub fn gpu_measured_rate(&self) -> (u64, u8) {
        let Some(start) = self.start_time else {
            return (0, 0);
        };
        let secs = start.elapsed().as_secs_f64().max(0.5);
        let gpu = self.gpu_health.seeds_delivered.load(Ordering::Relaxed);
        let total = self.counter.load(Ordering::Relaxed);
        // `counter` and `seeds_delivered` are two separate stores, so a UI tick
        // can observe them out of step; clamp instead of printing 400%.
        let share = if total == 0 {
            0
        } else {
            ((gpu.min(total) as f64 / total as f64) * 100.0).round() as u8
        };
        ((gpu as f64 / secs) as u64, share)
    }

    pub fn validate(&mut self) -> Result<(), String> {
        let charset = self.valid_charset();
        let max_len = self.max_vanity_len();

        let input_str = match self.match_position {
            MatchPosition::EndsWith => &self.vanity_suffix,
            _ => &self.vanity_prefix,
        };
        if input_str.is_empty() {
            return Err("Vanity string cannot be empty".to_string());
        }
        if input_str.len() > max_len {
            return Err(format!("Must be 1-{} characters", max_len));
        }
        if let Some(c) = input_str.chars().find(|c| !charset.contains(*c)) {
            return Err(format!("'{}' is not valid for this chain", c));
        }

        if matches!(self.match_position, MatchPosition::StartsAndEndsWith) {
            if self.vanity_suffix.is_empty() {
                return Err("Suffix cannot be empty".to_string());
            }
            if self.vanity_suffix.len() > max_len {
                return Err(format!("Suffix must be 1-{} characters", max_len));
            }
            if let Some(c) = self.vanity_suffix.chars().find(|c| !charset.contains(*c)) {
                return Err(format!("'{}' is not valid for this chain", c));
            }
        }

        let max_threads = num_cpus::get().max(1) * 2;
        let count = self.thread_count.parse::<usize>().map_err(|_| "Invalid thread count".to_string())?;
        if count == 0 || count > max_threads {
            return Err(format!("Threads must be 1-{}", max_threads));
        }
        self.validated_thread_count = count;

        // ADVISORY. This line records the GPU decision; it CANNOT fail the
        // validation. Every GPU state — no device, wrong chain, faulted this
        // session, vetoed by VANADDY_GPU=0 — resolves to a CPU-only search that
        // starts normally. Returning Err here would let a stale toggle or a
        // mid-run fault trap the user in the config screen with no way to start,
        // which is strictly worse than losing the acceleration.
        self.validated_gpu = self.gpu_effective();

        Ok(())
    }

    pub fn start_search(&mut self) {
        let num_threads = self.validated_thread_count;
        self.error_message = None;

        // Reap finished engines NON-BLOCKING. `is_finished()` is a plain atomic
        // load and `reap()` joins a thread that has already returned, so neither
        // can block. Anything still running is left parked for the next attempt
        // or for `shutdown_gpu` at process exit.
        let mut still_running: Vec<GpuEngine> = Vec::new();
        for engine in std::mem::take(&mut self.gpu_engines) {
            if engine.is_finished() {
                engine.reap();
            } else {
                still_running.push(engine);
            }
        }
        self.gpu_engines = still_running;
        let spawn_gpu = gpu_spawn_allowed(self.validated_gpu, self.gpu_engines.len());
        if self.validated_gpu && !spawn_gpu {
            self.error_message =
                Some("GPU: previous session winding down — this run is CPU only".to_string());
        }
        self.matches.clear();
        self.total_matches = 0;
        self.csv_write_failures = 0;
        self.selected_match = 0;
        self.counter = Arc::new(AtomicU64::new(0));
        self.stop = Arc::new(AtomicBool::new(false));
        self.start_time = Some(Instant::now());
        self.state = AppState::Searching;

        let (prefix, suffix) = match self.match_position {
            MatchPosition::StartsWith => (self.vanity_prefix.clone(), String::new()),
            MatchPosition::EndsWith => (String::new(), self.vanity_suffix.clone()),
            MatchPosition::StartsAndEndsWith => (self.vanity_prefix.clone(), self.vanity_suffix.clone()),
        };

        let matcher = Matcher::new(prefix, suffix, self.case_sensitive, self.chain);
        let chain = self.chain;
        let stop = self.stop.clone();
        let counter = self.counter.clone();

        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);

        // Open the CSV ONCE for this search and keep the handle. 0600 is
        // asserted here, on create and on the post-open re-assert inside
        // open_csv_secure. No `expect`: a panic here now runs inside the
        // alternate screen, and a search that cannot write its CSV should
        // report that in the UI, not take the process down.
        let mut csv_failed = false;
        match open_csv_secure(&self.csv_path) {
            Ok(mut file) => {
                let needs_header = file.metadata().map(|m| m.len() == 0).unwrap_or(true);
                if needs_header {
                    let mut wtr = WriterBuilder::new()
                        .has_headers(false)
                        .from_writer(&mut file);
                    // Do NOT discard these. A swallowed header failure leaves
                    // the CSV with data rows and no header — subtly malformed
                    // — while the UI reports nothing wrong, the same class of
                    // silent-loss this task's drain_matches fix (below) exists
                    // to prevent for row writes.
                    if let Err(e) =
                        wtr.write_record(["Chain", "Address", "Private Key (hex)", "Seed Phrase"])
                    {
                        self.error_message = Some(format!(
                            "Failed to write CSV header ({e}); the file may be missing its header row"
                        ));
                        csv_failed = true;
                    } else if let Err(e) = wtr.flush() {
                        self.error_message = Some(format!(
                            "Failed to write CSV header ({e}); the file may be missing its header row"
                        ));
                        csv_failed = true;
                    }
                }
                if !csv_failed {
                    self.csv_file = Some(file);
                }
            }
            Err(e) => {
                self.csv_file = None;
                self.error_message = Some(format!("Cannot open {}: {e}", self.csv_path.display()));
                csv_failed = true;
            }
        }
        // A CSV that cannot be opened or headed must not start a search: no
        // GPU thread, no Rayon pool. The error string above is the one the UI
        // already shows.
        if csv_failed {
            self.rx = None;
            self.csv_file = None;
            self.state = AppState::Configuring;
            return;
        }

        // A FRESH health cell per run, UNCONDITIONALLY — outside the branch on
        // purpose. `reason` is a set-once OnceLock and cannot be reset; a
        // faulted run is made sticky by drain_matches clearing
        // `gpu_requested`/`validated_gpu`, not by reusing the cell. Resetting
        // it only when the GPU spawns would leave a CPU-only run holding the
        // previous run's `seeds_delivered` while `counter` and `start_time`
        // (reset above) start from zero — the Stats pane would then divide a
        // stale numerator by a fresh denominator.
        self.gpu_health = Arc::new(GpuHealth::default());

        let gpu_rx = if spawn_gpu {
            let (gpu_tx, rx) = crossbeam_channel::bounded(crate::gpu::CHANNEL_CAPACITY);
            let engine = GpuEngine::start(gpu_tx, self.gpu_health.clone());
            // Initializing: the device, the ~60-95 ms shader compile and the
            // ~300 ms self-test all run on the spawned thread, not here.
            self.gpu_status = engine.status();
            self.gpu_engines.push(engine);
            self.gpu_rx = Some(rx.clone());
            Some(rx)
        } else {
            self.gpu_rx = None;
            None
        };
        let health = self.gpu_health.clone();

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .expect("Failed to build Rayon thread pool");

        pool.spawn(move || {
            (0..num_threads).into_par_iter().for_each(|_| {
                chain.search(&matcher, &stop, &counter, &tx, gpu_rx.as_ref(), &health);
            });
            drop(tx);
        });

        self.thread_pool = Some(pool);
    }

    pub fn stop_search(&mut self) {
        // Signal FIRST, then drain. Everything still in the mpsc queue is a
        // match a worker already found and verified; dropping the receiver
        // below would discard it silently — never written to the CSV, never
        // counted in total_matches. `drain_matches` is a `try_recv` loop, so it
        // is bounded and non-blocking, and the CSV handle is still open here
        // (it closes at the bottom of this function).
        //
        // Setting `stop` before the drain rather than after narrows, but does
        // not close, a race: a worker between its last stop check and its
        // `send` can still enqueue a match after the final `try_recv` returns
        // Empty, and `Receiver::drop` discards it while the sender saw Ok.
        // The window is one worker batch wide and cannot be closed without
        // blocking the UI thread on the producers, which this function exists
        // to avoid. Draining after the signal at least catches the final flush
        // instead of racing ongoing production.
        self.stop.store(true, Ordering::Relaxed);
        self.drain_matches();
        self.rx = None;
        // Dropping App's Receiver clone is producer wake-path #2: once App and
        // every Rayon worker have dropped theirs, the channel disconnects and a
        // producer that missed the stop flag still exits cleanly on
        // SendTimeoutError::Disconnected instead of parking on send_timeout.
        self.gpu_rx = None;
        // NON-BLOCKING. signal_stop() is a flag store. The engines stay PARKED
        // in gpu_engines and are reaped by the next start_search or by
        // shutdown_gpu at process exit. Joining here would stall the 100 ms
        // render tick for up to a whole wave (~135 ms in steady state, ~400 ms
        // during startup) and forever if the GPU has wedged.
        for engine in &self.gpu_engines {
            engine.signal_stop();
        }
        // Drops the pool handle; workers will exit on the next stop check.
        self.thread_pool = None;

        // Task 6.7 addition: detect whether the file this handle points at is
        // still the file at `csv_path`. Task 6.5 made start_search open the
        // CSV once and hold the handle for the whole search — if the file is
        // deleted or replaced mid-search, every write after that lands in the
        // orphaned inode: invisible in the filesystem, freed only when this
        // handle closes. Those writes still succeed, so csv_write_failures
        // stays 0 and drain_matches keeps evicting matches from memory on the
        // (now false) assumption that they are durably on disk. This is the
        // only point where the handle is dropped, so it is the only point
        // where this is detectable — one stat, not a re-open per row.
        if let Some(ref file) = self.csv_file {
            use std::os::unix::fs::MetadataExt;
            if let Ok(held_meta) = file.metadata() {
                match std::fs::metadata(&self.csv_path) {
                    Ok(current_meta) => {
                        if held_meta.dev() != current_meta.dev()
                            || held_meta.ino() != current_meta.ino()
                        {
                            self.error_message = Some(format!(
                                "The CSV file was replaced during the search; rows may have been \
                                 written to a file no longer reachable at {}",
                                self.csv_path.display()
                            ));
                        }
                    }
                    Err(_) => {
                        self.error_message = Some(format!(
                            "The CSV file was deleted during the search; rows may have been \
                             written to a file no longer reachable at {}",
                            self.csv_path.display()
                        ));
                    }
                }
            }
        }
        // Closes and flushes the CSV. start_search reopens it, re-asserting 0600.
        self.csv_file = None;
        self.state = AppState::Configuring;
    }

    /// Process-exit reaper. Signals every parked engine, then waits UP TO
    /// `deadline` for them to finish, polling rather than joining.
    ///
    /// Any engine still running when the deadline expires is ABANDONED: its
    /// thread is detached and its 3.5 MiB of Metal buffers go un-zeroized. That
    /// is the accepted trade — a GPU wedged inside `waitUntilCompleted` would
    /// otherwise hang the process forever with `kill -9` as the only exit, and
    /// the CSV already writes the same secret material to disk in plaintext.
    pub fn shutdown_gpu(&mut self, deadline: std::time::Duration) {
        for engine in &self.gpu_engines {
            engine.signal_stop();
        }
        // Drop App's clone of the receiver. This alone does NOT disconnect the
        // channel: every Rayon worker holds its own clone, so a producer parked
        // in `send_timeout` only wakes on `Disconnected` once the last worker
        // has dropped too. At process exit that follows shortly, because the
        // workers see `app.stop`.
        self.gpu_rx = None;

        let start = Instant::now();
        while !self.gpu_engines.is_empty() && start.elapsed() < deadline {
            let mut still_running: Vec<GpuEngine> = Vec::with_capacity(self.gpu_engines.len());
            for engine in std::mem::take(&mut self.gpu_engines) {
                if engine.is_finished() {
                    engine.reap();
                } else {
                    still_running.push(engine);
                }
            }
            self.gpu_engines = still_running;
            if self.gpu_engines.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        // Abandon the rest. `GpuEngine::drop` must not join.
        self.gpu_engines.clear();
    }

    pub fn drain_matches(&mut self) {
        // ---- 1. Fault promotion. Runs first, on every 100 ms tick, so a fault
        // raised by a Rayon worker or the producer becomes visible within one
        // frame. STICKY for the process: gpu_requested and validated_gpu go
        // false, so gpu_effective() can never turn the GPU back on without a
        // restart. A mis-derived seed is a correctness fault, not a transient.
        let disabled_now = self.gpu_health.disable.load(Ordering::Relaxed);
        if disabled_now && !matches!(self.gpu_status, GpuStatus::Disabled(_)) {
            // `raise` sets the reason BEFORE the flag, so by the time the flag
            // is observed the reason is there. Panicked is the defensive floor.
            let reason = self
                .gpu_health
                .take_reason()
                .unwrap_or(crate::gpu::GpuDisableReason::Panicked);
            self.gpu_status = GpuStatus::Disabled(reason);
            self.gpu_requested = false;
            self.validated_gpu = false;
            // Releasing the receiver stops the workers draining, wakes a
            // producer that has not noticed, and keeps the stats pane from
            // rendering a live GPU line AND a fault line in the same frame.
            self.gpu_rx = None;
        }

        // ---- 2. Status refresh: Initializing -> Running once the shader has
        // compiled and the self-test has passed. Only while this run owns a
        // live channel, and never over a Disabled status.
        if self.gpu_rx.is_some() && !matches!(self.gpu_status, GpuStatus::Disabled(_)) {
            if let Some(engine) = self.gpu_engines.last() {
                let s = engine.status();
                if s != self.gpu_status {
                    self.gpu_status = s;
                }
            }
        }

        // ---- 3. Unexpected exit: the engine finished but nothing was raised.
        // NOTE the asymmetry with section 2, which reads `.last()` while this
        // folds over ALL engines. The two agree only because
        // `gpu_spawn_allowed` requires `engines_parked == 0`, so a live
        // `gpu_rx` implies exactly one parked engine. That invariant lives two
        // functions away and nothing here enforces it: if it is ever relaxed —
        // say, to allow a spawn while an old engine winds down — section 2
        // would report the newest engine while this fires on ANY engine
        // finishing, and a healthy GPU would be declared dead. Relax that
        // invariant and these two must be reconciled in the same change.
        let engine_finished = self.gpu_engines.iter().any(|e| e.is_finished());
        if is_unexpected_gpu_exit(GpuExitCheck {
            state: self.state,
            gpu_live: self.gpu_rx.is_some(),
            disabled: self.gpu_health.disable.load(Ordering::Relaxed),
            engine_finished,
        }) {
            self.gpu_status = GpuStatus::Disabled(crate::gpu::GpuDisableReason::Panicked);
            self.gpu_requested = false;
            self.validated_gpu = false;
            self.gpu_rx = None;
        }

        // ---- 4. Matches. The CPU search is untouched by any of the above.
        if let Some(ref rx) = self.rx {
            while let Ok(payload) = rx.try_recv() {
                let write_result = match self.csv_file.as_mut() {
                    Some(file) => write_match_row(file, &payload),
                    // No handle held (start_search's open failed, or this is a
                    // test driving drain_matches directly). Never drop a match.
                    None => append_match_row(&self.csv_path, &payload),
                };
                // Do NOT discard this. Task 6.4 Step 7 evicts on the claim that
                // an evicted row is "already durably in the CSV", and Step 6
                // above removed the `.expect()` that used to make a failed open
                // loud. With both, a `let _ =` here means a mid-run ENOSPC
                // silently destroys seed phrases while the exit summary reports
                // them saved.
                if let Err(e) = write_result {
                    self.csv_write_failures += 1;
                    self.error_message = Some(format!(
                        "CSV write failed ({e}); matches are NOT being saved"
                    ));
                }

                self.total_matches += 1;
                self.matches.push_back(payload);
                // Evict from the FRONT: the newest matches are the ones on
                // screen. Eviction is only a RENDER budget while every row is
                // durably on disk — and nothing above proves that until Task
                // 6.5 Step 7 checks the write result. Once a write has failed,
                // the in-memory list is the ONLY copy of those seed phrases, so
                // stop evicting rather than destroying a found wallet.
                if self.csv_write_failures == 0 {
                    while self.matches.len() > MATCH_CAP {
                        self.matches.pop_front();
                    }
                }
                self.selected_match = self.matches.len().saturating_sub(1);
            }
        }
    }
}

/// The one CSV every production caller writes to.
const CSV_PATH: &str = "vanity_wallets.csv";

/// Open the CSV at `path` for append, creating it with mode 0o600 on Unix and
/// re-asserting 0o600 on every open in case a pre-existing file had looser
/// permissions. The file holds plaintext seed phrases, so this is the single
/// chokepoint for that security guarantee — all writers MUST go through here.
///
/// `path` is a parameter rather than the `CSV_PATH` constant so the permission
/// tests can use a temp dir: `cargo test` runs tests as threads in one process,
/// so `set_current_dir` is racy, and `start_stop_restart_does_not_leak_threads`
/// already writes the real CSV into the repo root.
fn open_csv_secure(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = file.metadata() {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }
    }
    Ok(file)
}

/// The single place a `Match` becomes CSV bytes. Both writers — the held-open
/// handle in `drain_matches` and the path-based `append_match_row` — funnel
/// through here, so a row can never be written two different ways.
///
/// Taking `&Match` is the enforcement point for the trust boundary: a `Match`
/// cannot be constructed without a `verify::Verified` token, so an unverified
/// GPU candidate has no path to disk.
fn write_match_row(file: &mut File, m: &Match) -> io::Result<()> {
    let mut wtr = WriterBuilder::new()
        .has_headers(false)
        .from_writer(&mut *file);
    wtr.write_record([&m.chain, &m.address, &m.secret_hex, &m.mnemonic])?;
    wtr.flush()
}

/// Append one verified match to the CSV at `path`, opening it 0600 for the
/// write. Used when no handle is held open (a failed `start_search` open, and
/// every test that does not run a real search).
fn append_match_row(path: &Path, m: &Match) -> io::Result<()> {
    let mut file = open_csv_secure(path)?;
    write_match_row(&mut file, m)
}

/// May this run spawn a GPU producer?
///
/// Only if `validate()` said so AND no engine from a previous run is still
/// winding down. When one is, we run CPU-only for this search rather than
/// joining: a join on the UI thread blocks the 100 ms render tick for the rest
/// of a ~250 ms cold shader compile on an Enter-Ctrl+C-Enter sequence, and
/// blocks FOREVER if the GPU has wedged inside `waitUntilCompleted`, leaving
/// the terminal in raw mode with the alternate screen up and `kill -9` as the
/// only exit.
///
/// Pure, so the decision is testable on every target — `GpuEngine` is a no-op
/// on non-Apple-Silicon builds and a test cannot conjure a live one.
fn gpu_spawn_allowed(validated_gpu: bool, engines_parked: usize) -> bool {
    validated_gpu && engines_parked == 0
}

/// The four facts the quiet-death check weighs.
///
/// NAMED FIELDS, not four positional `bool`s — but be precise about what that
/// buys, because an earlier draft of this comment overclaimed it. Named fields
/// do NOT make a transposition a compile error: struct literals are keyed by
/// name, so reordering them is a no-op, and writing the wrong expression under
/// the right name (`gpu_live: self.gpu_health.disable.load(..)`) still compiles
/// cleanly. What they DO buy is narrower and still worth it: omitting a field
/// is a hard error, so `engine_finished` can never be silently dropped at the
/// call site, and a wrong expression is legible next to its name instead of
/// hiding in argument position. The transposition itself is caught by review
/// and by the live-engine test in Task 6.10, not by the type system.
struct GpuExitCheck {
    state: AppState,
    gpu_live: bool,
    disabled: bool,
    engine_finished: bool,
}

/// Did a GPU engine die quietly?
///
/// A producer that returns without raising a reason — a panic that escaped the
/// `catch_unwind` bookkeeping, or a `return` on a path that forgot to raise —
/// would otherwise leave the TUI reporting `Running` at 0/s forever. Only
/// meaningful while THIS run has a live GPU channel: when the GPU was skipped,
/// a leftover engine finishing is the wind-down we asked for, not a fault.
///
/// Pure, so it is testable on targets where a live `GpuEngine` cannot be
/// constructed in a test.
fn is_unexpected_gpu_exit(c: GpuExitCheck) -> bool {
    c.state == AppState::Searching && c.gpu_live && !c.disabled && c.engine_finished
}

/// Rollback lever #2: `VANADDY_GPU=0` (equivalently `VANADDY_NO_GPU=1`) turns the
/// GPU off with no rebuild. Env always wins over the TUI toggle, so an operator
/// can kill the feature on a machine without editing anything.
///
/// Pure over the two values rather than reading the environment itself: `cargo
/// test` runs every test as a thread in ONE process, so a test that mutated the
/// process environment would race every other test.
///
/// `VANADDY_GPU` is value-based because a user types `VANADDY_GPU=0`.
/// `VANADDY_NO_GPU` is presence-based because `gpu_for_test` in
/// `src/gpu/metal.rs` already gates on `var_os("VANADDY_NO_GPU").is_some()`.
pub fn gpu_env_off(vanaddy_gpu: Option<&str>, vanaddy_no_gpu: Option<&str>) -> bool {
    if vanaddy_no_gpu.is_some() {
        return true;
    }
    match vanaddy_gpu {
        Some(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "off" | "false" | "no"
        ),
        None => false,
    }
}

pub fn detect_optimal_threads() -> usize {
    let physical = num_cpus::get_physical();
    let logical = num_cpus::get();

    // On Apple Silicon: physical == logical (no hyperthreading).
    // Use all cores — the OS scheduler handles P/E core assignment.
    // On x86 with hyperthreading: physical < logical.
    // For crypto-heavy work, physical cores are usually optimal.
    if logical > physical {
        // Hyperthreaded (x86): use physical cores for compute-bound work
        physical
    } else {
        // Apple Silicon or non-HT: use all cores
        logical
    }
}

pub fn handle_key_event(app: &mut App, key: event::KeyEvent) {
    if key.kind != KeyEventKind::Press {
        return;
    }

    // Help popup: dismiss with any key when open
    if app.show_help {
        app.show_help = false;
        return;
    }

    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        if app.state == AppState::Searching {
            app.stop_search();
        } else {
            app.should_quit = true;
        }
        return;
    }

    // 'h' toggles help (when not in a text field during configuring)
    if key.code == KeyCode::Char('h') {
        if app.state == AppState::Searching || !app.is_text_field() {
            app.show_help = true;
            return;
        }
    }

    match app.state {
        AppState::Configuring => handle_configuring_key(app, key),
        AppState::Searching => handle_searching_key(app, key),
    }
}

fn handle_configuring_key(app: &mut App, key: event::KeyEvent) {
    match key.code {
        KeyCode::Char('q') if !app.is_text_field() => {
            app.should_quit = true;
        }

        // Navigation: Tab/Down = next, BackTab/Up = previous
        KeyCode::Tab | KeyCode::Down => {
            app.active_field = (app.active_field + 1) % app.field_count();
            app.error_message = None;
        }
        KeyCode::BackTab | KeyCode::Up => {
            if app.active_field == 0 {
                app.active_field = app.field_count() - 1;
            } else {
                app.active_field -= 1;
            }
            app.error_message = None;
        }

        KeyCode::Enter => {
            match app.validate() {
                Ok(()) => app.start_search(),
                Err(e) => app.error_message = Some(e),
            }
        }

        _ => handle_field_input(app, key),
    }
}

fn handle_field_input(app: &mut App, key: event::KeyEvent) {
    let both = matches!(app.match_position, MatchPosition::StartsAndEndsWith);

    match app.active_field {
        // Chain (cycle with Left/Right or 1/2/3/4/5)
        0 => match key.code {
            KeyCode::Char('1') => app.chain = ChainKind::Solana,
            KeyCode::Char('2') => app.chain = ChainKind::Evm,
            KeyCode::Char('3') => app.chain = ChainKind::Bitcoin,
            KeyCode::Char('4') => app.chain = ChainKind::Ton,
            KeyCode::Char('5') => app.chain = ChainKind::Monero,
            KeyCode::Left => {
                app.chain = match app.chain {
                    ChainKind::Solana => ChainKind::Monero,
                    ChainKind::Evm => ChainKind::Solana,
                    ChainKind::Bitcoin => ChainKind::Evm,
                    ChainKind::Ton => ChainKind::Bitcoin,
                    ChainKind::Monero => ChainKind::Ton,
                };
            }
            KeyCode::Right => {
                app.chain = match app.chain {
                    ChainKind::Solana => ChainKind::Evm,
                    ChainKind::Evm => ChainKind::Bitcoin,
                    ChainKind::Bitcoin => ChainKind::Ton,
                    ChainKind::Ton => ChainKind::Monero,
                    ChainKind::Monero => ChainKind::Solana,
                };
            }
            _ => {}
        },

        // Match position (cycle with Left/Right or 1/2/3)
        1 => match key.code {
            KeyCode::Char('1') => app.match_position = MatchPosition::StartsWith,
            KeyCode::Char('2') => app.match_position = MatchPosition::EndsWith,
            KeyCode::Char('3') => app.match_position = MatchPosition::StartsAndEndsWith,
            KeyCode::Right => {
                app.match_position = match app.match_position {
                    MatchPosition::StartsWith => MatchPosition::EndsWith,
                    MatchPosition::EndsWith => MatchPosition::StartsAndEndsWith,
                    MatchPosition::StartsAndEndsWith => MatchPosition::StartsWith,
                };
            }
            KeyCode::Left => {
                app.match_position = match app.match_position {
                    MatchPosition::StartsWith => MatchPosition::StartsAndEndsWith,
                    MatchPosition::EndsWith => MatchPosition::StartsWith,
                    MatchPosition::StartsAndEndsWith => MatchPosition::EndsWith,
                };
            }
            _ => {}
        },

        // Vanity prefix (or single vanity string for StartsWith/EndsWith)
        2 => match key.code {
            KeyCode::Char(c) if app.valid_charset().contains(c) => {
                app.error_message = None;
                if matches!(app.match_position, MatchPosition::EndsWith) {
                    if app.vanity_suffix.len() < app.max_vanity_len() {
                        app.vanity_suffix.push(c);
                    } else {
                        app.error_message = Some(format!("Max {} chars", app.max_vanity_len()));
                    }
                } else if app.vanity_prefix.len() < app.max_vanity_len() {
                    app.vanity_prefix.push(c);
                } else {
                    app.error_message = Some(format!("Max {} chars", app.max_vanity_len()));
                }
            }
            KeyCode::Char(c) => {
                app.error_message = Some(format!(
                    "'{}' not valid for {} — allowed: {}",
                    c, app.chain.label(), app.valid_charset()
                ));
            }
            KeyCode::Backspace => {
                app.error_message = None;
                if matches!(app.match_position, MatchPosition::EndsWith) {
                    app.vanity_suffix.pop();
                } else {
                    app.vanity_prefix.pop();
                }
            }
            _ => {}
        },

        // Suffix (only when StartsAndEndsWith, field index 3)
        3 if both => match key.code {
            KeyCode::Char(c) if app.valid_charset().contains(c) => {
                app.error_message = None;
                if app.vanity_suffix.len() < app.max_vanity_len() {
                    app.vanity_suffix.push(c);
                } else {
                    app.error_message = Some(format!("Max {} chars", app.max_vanity_len()));
                }
            }
            KeyCode::Char(c) => {
                app.error_message = Some(format!(
                    "'{}' not valid for {} — allowed: {}",
                    c, app.chain.label(), app.valid_charset()
                ));
            }
            KeyCode::Backspace => {
                app.error_message = None;
                app.vanity_suffix.pop();
            }
            _ => {}
        },

        // Case sensitivity (toggle with Left/Right or y/n)
        f if f == (if both { 4 } else { 3 }) => match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => app.case_sensitive = true,
            KeyCode::Char('n') | KeyCode::Char('N') => app.case_sensitive = false,
            KeyCode::Left | KeyCode::Right => app.case_sensitive = !app.case_sensitive,
            _ => {}
        },

        // GPU offload (toggle with Left/Right or y/n) — always second-to-last,
        // between Case and Threads. Turning it OFF always works. Turning it ON
        // is refused LOUDLY — visibly disabled, never silently ignored — when
        // there is no device, when a fault disabled it for this process, or
        // when the selected chain is not EVM. `gpu_requested` is deliberately
        // NOT cleared when the chain changes: the preference survives a
        // round-trip through Solana and back to EVM.
        f if f == app.field_count() - 2 => {
            let want = match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => Some(true),
                KeyCode::Char('n') | KeyCode::Char('N') => Some(false),
                KeyCode::Left | KeyCode::Right => Some(!app.gpu_requested),
                _ => None,
            };
            match want {
                None => {}
                Some(false) => {
                    app.gpu_requested = false;
                    app.error_message = None;
                }
                Some(true) => {
                    // Precedence: no device beats disabled beats wrong chain.
                    let refusal = match &app.gpu_status {
                        GpuStatus::Unavailable(r) => Some(format!("GPU unavailable: {r}")),
                        GpuStatus::Disabled(r) => Some(format!("GPU disabled this session: {r:?}")),
                        _ if app.chain != ChainKind::Evm => Some(format!(
                            "GPU offload is EVM-only — {} runs on CPU",
                            app.chain.label()
                        )),
                        _ => None,
                    };
                    match refusal {
                        Some(msg) => app.error_message = Some(msg),
                        None => {
                            app.gpu_requested = true;
                            app.error_message = None;
                        }
                    }
                }
            }
        }

        // Thread count (always last field)
        f if f == app.field_count() - 1 => match key.code {
            KeyCode::Char(c) if c.is_ascii_digit() => {
                if app.thread_count.len() < 3 {
                    app.thread_count.push(c);
                }
            }
            KeyCode::Backspace => {
                app.thread_count.pop();
            }
            _ => {}
        },

        _ => {}
    }
}

fn handle_searching_key(app: &mut App, key: event::KeyEvent) {
    match key.code {
        KeyCode::Char('q') => {
            app.stop_search();
            app.should_quit = true;
        }
        KeyCode::Up => {
            if app.selected_match > 0 {
                app.selected_match -= 1;
            }
        }
        KeyCode::Down => {
            if app.selected_match + 1 < app.matches.len() {
                app.selected_match += 1;
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn start_stop_restart_does_not_leak_threads() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new();
        // Write into a temp dir, not the repo root: `cargo test` runs tests as
        // threads in one process, so a shared CSV path races other tests.
        app.csv_path = dir.path().join("vanity_wallets.csv");
        app.chain = crate::chains::ChainKind::Evm;
        // Extremely unlikely prefix so search will genuinely run for the duration.
        app.vanity_prefix = "aaaaaaaa".into();
        app.thread_count = "2".into();
        // CPU-only: this test is about lifecycle, and it must pass identically
        // on a Linux CI box with no Metal device.
        app.gpu_requested = false;
        app.validate().unwrap();

        app.start_search();
        assert!(
            app.gpu_engines.is_empty(),
            "no engine spawned when the GPU is off"
        );
        assert!(app.gpu_rx.is_none());
        thread::sleep(Duration::from_millis(50));
        app.stop_search();

        // Second cycle
        app.validate().unwrap();
        app.start_search();
        thread::sleep(Duration::from_millis(50));
        app.stop_search();

        assert!(app.thread_pool.is_none());
        assert!(app.stop.load(Ordering::Relaxed));
        assert!(app.csv_file.is_none(), "the CSV handle is released on stop");
        assert!(
            app.gpu_engines.is_empty(),
            "no engine may accumulate across start/stop cycles"
        );

        // The exit reaper is a no-op here and must return instantly.
        let before = Instant::now();
        app.shutdown_gpu(Duration::from_millis(600));
        assert!(before.elapsed() < Duration::from_millis(50));
        assert!(app.gpu_engines.is_empty());
    }

    /// Field identity in this form is a bare integer, and three places do
    /// arithmetic on it: `is_text_field` (src/app.rs:84-91), the Case arm
    /// (src/app.rs:512, `if both { 4 } else { 3 }`) and the Threads arm
    /// (src/app.rs:520, `field_count() - 1`). The literals below ARE the
    /// contract — do not rewrite them in terms of `field_count()`, that is
    /// exactly the tautology this test exists to avoid.
    #[test]
    fn gpu_field_index_is_stable_across_match_positions() {
        let mut app = App::new();

        app.match_position = MatchPosition::StartsWith;
        assert_eq!(
            app.field_count(),
            6,
            "StartsWith fields: chain, match, vanity, case, gpu, threads"
        );
        assert_eq!(app.field_count() - 2, 4, "GPU is field 4 for StartsWith");
        assert_eq!(
            app.field_count() - 1,
            5,
            "Threads is field 5 for StartsWith"
        );

        app.match_position = MatchPosition::EndsWith;
        assert_eq!(app.field_count(), 6, "EndsWith has the same six fields");
        assert_eq!(app.field_count() - 2, 4, "GPU is field 4 for EndsWith");

        app.match_position = MatchPosition::StartsAndEndsWith;
        assert_eq!(
            app.field_count(),
            7,
            "StartsAndEndsWith adds the suffix field"
        );
        assert_eq!(
            app.field_count() - 2,
            5,
            "GPU is field 5 for StartsAndEndsWith"
        );
        assert_eq!(
            app.field_count() - 1,
            6,
            "Threads is field 6 for StartsAndEndsWith"
        );

        // The GPU index must never land on the Case field, whose arm is
        // hard-coded to `if both { 4 } else { 3 }`.
        for (pos, case_ix) in [
            (MatchPosition::StartsWith, 3usize),
            (MatchPosition::EndsWith, 3),
            (MatchPosition::StartsAndEndsWith, 4),
        ] {
            app.match_position = pos;
            assert_ne!(
                app.field_count() - 2,
                case_ix,
                "the GPU field must not collide with the Case field"
            );
        }

        // GPU is a toggle, so `q` must still quit from it; Threads is text.
        for pos in [
            MatchPosition::StartsWith,
            MatchPosition::EndsWith,
            MatchPosition::StartsAndEndsWith,
        ] {
            app.match_position = pos;
            app.active_field = app.field_count() - 2;
            assert!(!app.is_text_field(), "the GPU field is a toggle, not text");
            app.active_field = app.field_count() - 1;
            assert!(
                app.is_text_field(),
                "the Threads field must stay a text field"
            );
        }
    }

    /// Navigation is modulo `field_count()`; if the count is wrong the new
    /// field is simply unreachable and nothing else complains.
    #[test]
    fn tab_visits_every_field_and_wraps_including_the_new_gpu_field() {
        let mut app = App::new();
        app.match_position = MatchPosition::StartsWith;

        let mut seen = vec![app.active_field];
        for _ in 0..5 {
            handle_key_event(
                &mut app,
                event::KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
            );
            seen.push(app.active_field);
        }
        assert_eq!(
            seen,
            vec![0, 1, 2, 3, 4, 5],
            "Tab must reach all six fields"
        );

        handle_key_event(
            &mut app,
            event::KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
        );
        assert_eq!(app.active_field, 0, "Tab wraps from Threads back to Chain");

        handle_key_event(
            &mut app,
            event::KeyEvent::new(KeyCode::BackTab, KeyModifiers::NONE),
        );
        assert_eq!(app.active_field, 5, "BackTab from Chain lands on Threads");
    }

    /// The Threads field moved from index 4/5 to 5/6. Literal indices, so a
    /// wrong `field_count()` makes this fail instead of silently agreeing.
    #[test]
    fn threads_field_still_edits_at_its_new_index() {
        let mut app = App::new();

        app.match_position = MatchPosition::StartsWith;
        app.active_field = 5;
        app.thread_count.clear();
        handle_key_event(
            &mut app,
            event::KeyEvent::new(KeyCode::Char('4'), KeyModifiers::NONE),
        );
        assert_eq!(
            app.thread_count, "4",
            "Threads is field 5 once the GPU field exists"
        );

        app.match_position = MatchPosition::StartsAndEndsWith;
        app.active_field = 6;
        app.thread_count.clear();
        handle_key_event(
            &mut app,
            event::KeyEvent::new(KeyCode::Char('8'), KeyModifiers::NONE),
        );
        assert_eq!(
            app.thread_count, "8",
            "Threads is field 6 with both prefix and suffix"
        );
    }

    /// `q` and `h` are gated on `is_text_field()`. Before the GPU field
    /// existed, index 4 WAS the Threads text field, so both keys were inert
    /// there — proof that this guard is index-sensitive.
    #[test]
    fn q_quits_and_h_opens_help_from_the_gpu_field() {
        let mut app = App::new();
        app.match_position = MatchPosition::StartsWith;
        app.active_field = 4; // GPU

        handle_key_event(
            &mut app,
            event::KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE),
        );
        assert!(app.show_help, "h must still open help from the GPU field");

        handle_key_event(
            &mut app,
            event::KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE),
        );
        assert!(!app.show_help, "any key dismisses the help popup");

        handle_key_event(
            &mut app,
            event::KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
        );
        assert!(app.should_quit, "q must still quit from the GPU field");
    }

    /// The half the CPU-only test above cannot reach. That test sets
    /// `gpu_requested = false`, so `validate()` leaves `validated_gpu` false,
    /// `gpu_spawn_allowed` is false, and NO engine is ever created on either
    /// cycle: `gpu_engines` is empty because it was never non-empty, and
    /// deleting Task 6.6 Step 4's whole reap loop leaves it green. This one
    /// runs REAL engines through two start/stop cycles, so accumulation is
    /// actually observable. Same graceful-skip idiom as Task 6.9 Step 1.
    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64", feature = "metal"))]
    fn a_live_engine_never_accumulates_across_start_stop_cycles() {
        if std::env::var_os("VANADDY_NO_GPU").is_some() {
            eprintln!("SKIP: VANADDY_NO_GPU is set");
            return;
        }
        if let GpuStatus::Unavailable(reason) = GpuEngine::probe() {
            eprintln!("SKIP: no Metal device on this machine ({reason})");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::with_gpu_status(GpuEngine::probe());
        app.csv_path = dir.path().join("vanity_wallets.csv");
        app.chain = crate::chains::ChainKind::Evm;
        app.vanity_prefix = "aaaaaaaa".into();
        app.thread_count = "2".into();
        app.gpu_requested = true;
        for cycle in 0..2 {
            app.validate().unwrap();
            app.start_search();
            assert!(
                app.gpu_engines.len() <= 1,
                "at most one engine is ever live: {}",
                app.gpu_engines.len()
            );
            assert_eq!(
                app.gpu_engines.len(),
                1,
                "cycle {cycle}: an engine must actually be live — if this is 0, \
                 gpu_spawn_allowed refused to spawn and the rest of this cycle \
                 asserts nothing"
            );
            // The discriminator for Task 6.6's reap loop. With the reap in
            // place, cycle 1's start_search reaps cycle 0's finished engine and
            // spawns a fresh one, which is NOT finished. Delete the reap loop
            // and cycle 1 still sees exactly one engine — but it is the
            // previous cycle's corpse, already finished, and this fails.
            assert!(
                !app.gpu_engines[0].is_finished(),
                "cycle {cycle}: this is the previous cycle's finished engine, not a \
                 fresh one — start_search's reap loop did not run"
            );

            // The status-refresh coverage Task 6.8 could not provide. Its
            // `status_refresh_leaves_the_status_alone_when_no_engine_is_parked`
            // enters the refresh branch but parks no engine, so
            // `gpu_engines.last()` is None and the block is a no-op whether it
            // exists or not -- deleting it outright leaves that test green
            // (measured). THIS is the only test with a real parked engine, so
            // it is the only one that can prove the block actually reads it.
            // Deleting Task 6.8's section-2 block makes the assert below fail:
            // the app would sit on the probe's status forever while the engine
            // reports Running.
            //
            // 60s, not 30s, and not for the reason a first reading suggests.
            // Cycle 0 reaches Running in ~7.0s debug / ~1.3s release, so 30s
            // already looked like 4x headroom -- but this test was MEASURED
            // failing at 114.99s wall with a load average of 20.31 (a second
            // Claude session compiling in the same checkout). A timeout only
            // costs wall-clock when the test is already failing, so buying
            // immunity to contention is nearly free; a flaky test in this
            // suite is not, because it teaches people to ignore red.
            let deadline = Instant::now() + Duration::from_secs(60);
            while Instant::now() < deadline {
                app.drain_matches();
                if matches!(app.gpu_status, GpuStatus::Running { .. }) {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
            assert!(
                matches!(app.gpu_status, GpuStatus::Running { .. }),
                "cycle {cycle}: drain_matches must refresh the status from the \
                 parked engine within 60s, got {:?}",
                app.gpu_status
            );

            thread::sleep(Duration::from_millis(50));
            app.stop_search();

            // Wait for the engine to actually finish. Without this the test
            // does not cycle at all: `stop_search` only SIGNALS and leaves the
            // engine parked, a real engine needs seconds to wind down, and
            // `start_search`'s reap loop only reaps `is_finished()` engines.
            // So at cycle 1 the old engine would still be running,
            // `gpu_spawn_allowed` would see `engines_parked == 1` and refuse to
            // spawn, and cycle 1 would assert against cycle 0's leftovers.
            // Measured: with only the 50 ms sleep, cycle 1 reached "Running" in
            // under 2 microseconds because `gpu_rx` was None and the refresh
            // block never re-entered.
            let give_up = Instant::now() + Duration::from_secs(60);
            while !app.gpu_engines.iter().all(|e| e.is_finished()) && Instant::now() < give_up {
                thread::sleep(Duration::from_millis(10));
            }
            assert!(
                app.gpu_engines.iter().all(|e| e.is_finished()),
                "cycle {cycle}: the engine must wind down within 60s of stop_search"
            );
        }
        app.shutdown_gpu(Duration::from_millis(600));
        assert!(app.gpu_engines.is_empty());
    }

    #[test]
    fn stop_search_releases_everything_and_never_blocks_the_ui_thread() {
        let dir = tempfile::tempdir().unwrap();
        // NOT `App::new()`. That is
        // `with_gpu_status(GpuStatus::Unavailable("not probed"))`, so
        // `gpu_requested` is false on EVERY target, no engine is ever spawned,
        // and both the "never joins a GPU thread" timing assertion and the
        // `gpu_rx` assertion below are vacuous everywhere — Task 6.1's own
        // `app_new_never_requests_a_gpu_it_has_not_probed` asserts exactly that.
        // Probe for real; the probe result decides whether it takes effect.
        let mut app = App::with_gpu_status(crate::gpu::GpuEngine::probe());
        app.gpu_requested = true;
        app.csv_path = dir.path().join("vanity_wallets.csv");
        app.chain = crate::chains::ChainKind::Evm;
        app.vanity_prefix = "aaaaaaaa".into();
        app.thread_count = "2".into();
        app.validate().unwrap();
        app.start_search();

        // On a machine that really has a device, prove the precondition rather
        // than assuming it: without a parked engine there is nothing a join
        // could block on, and the timing assertion below means nothing.
        #[cfg(all(target_os = "macos", target_arch = "aarch64", feature = "metal"))]
        if app.validated_gpu {
            assert!(
                !app.gpu_engines.is_empty(),
                "precondition: a real engine must be parked for the never-join assertion to mean anything"
            );
        }

        assert!(app.csv_file.is_some(), "start_search holds the CSV open");

        let before = Instant::now();
        app.stop_search();
        let elapsed = before.elapsed();

        assert!(
            elapsed < Duration::from_millis(50),
            "stop_search must never join a GPU thread: took {elapsed:?}"
        );
        assert!(app.stop.load(Ordering::Relaxed), "workers are told to exit");
        assert!(app.rx.is_none(), "match channel released");
        assert!(
            app.gpu_rx.is_none(),
            "GPU channel released — this is producer wake-path #2"
        );
        assert!(app.csv_file.is_none(), "CSV handle closed and flushed");
        assert!(app.thread_pool.is_none());
        assert!(app.state == AppState::Configuring);
    }

    #[test]
    fn stop_search_drains_matches_still_queued_at_stop_time() {
        // Every match sitting in the mpsc queue when the user presses Ctrl+C is
        // a FOUND WALLET. Dropping the receiver without a final drain destroys
        // it: never written to the CSV, never counted, unrecoverable. Step 3
        // therefore drains FIRST, before `self.rx = None` and before the CSV
        // handle is closed.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vanity_wallets.csv");
        let mut app = App::new();
        app.csv_path = path.clone();
        app.csv_file = Some(open_csv_secure(&path).unwrap());
        app.state = AppState::Searching;

        let (tx, rx) = mpsc::channel();
        app.rx = Some(rx);
        for i in 0..5 {
            tx.send(Match {
                chain: "EVM".to_string(),
                address: format!("0x{i:040x}"),
                secret_hex: "44".repeat(32),
                mnemonic: "abandon abandon abandon".to_string(),
                verified: crate::verify::Verified::cpu_reference(),
            })
            .unwrap();
        }
        drop(tx);

        app.stop_search();

        assert_eq!(
            app.total_matches, 5,
            "a match queued at stop time is still a found wallet"
        );
        let csv = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            csv.lines().count(),
            5,
            "every queued match reached the CSV: {csv}"
        );
    }

    #[test]
    fn stop_search_flags_error_when_the_csv_file_is_replaced_mid_search() {
        // Task 6.5 holds the CSV handle open for the whole search. If the file
        // at csv_path is deleted and recreated while the handle is held, the
        // held handle keeps writing into the orphaned inode -- invisible in
        // the filesystem, freed only when the handle closes. Those writes
        // still succeed, so csv_write_failures stays 0 and nothing else in
        // this codebase would ever notice. stop_search is where the handle is
        // dropped, so it is the only place this is detectable.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vanity_wallets.csv");
        let mut app = App::new();
        app.csv_path = path.clone();
        app.csv_file = Some(open_csv_secure(&path).unwrap());
        app.state = AppState::Searching;

        // Replace the file at the same path: a new inode under the same name.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"").unwrap();

        app.stop_search();

        let msg = app
            .error_message
            .expect("replacing the file mid-search must be flagged");
        assert!(
            msg.contains("replaced"),
            "error should explain the file was replaced: {msg}"
        );
    }

    #[test]
    fn stop_search_flags_error_when_the_csv_file_is_deleted_mid_search() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vanity_wallets.csv");
        let mut app = App::new();
        app.csv_path = path.clone();
        app.csv_file = Some(open_csv_secure(&path).unwrap());
        app.state = AppState::Searching;

        std::fs::remove_file(&path).unwrap();

        app.stop_search();

        let msg = app
            .error_message
            .expect("deleting the file mid-search must be flagged");
        assert!(
            msg.contains("deleted"),
            "error should explain the file was deleted: {msg}"
        );
    }

    #[test]
    fn stop_search_leaves_error_message_alone_when_the_csv_file_is_untouched() {
        // Negative case: a normal stop, nothing replaced or deleted, must not
        // set error_message. A test that only checks the positive case would
        // pass on an implementation that always warns.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vanity_wallets.csv");
        let mut app = App::new();
        app.csv_path = path.clone();
        app.csv_file = Some(open_csv_secure(&path).unwrap());
        app.state = AppState::Searching;

        app.stop_search();

        assert!(
            app.error_message.is_none(),
            "an untouched CSV file must not be flagged: {:?}",
            app.error_message
        );
    }

    #[test]
    fn gpu_spawn_is_skipped_while_a_previous_engine_is_still_winding_down() {
        assert!(
            gpu_spawn_allowed(true, 0),
            "validated and nothing parked -> spawn"
        );
        assert!(
            !gpu_spawn_allowed(true, 1),
            "a previous engine has not finished -> skip the GPU this run, NEVER join"
        );
        assert!(!gpu_spawn_allowed(true, 3));
        assert!(
            !gpu_spawn_allowed(false, 0),
            "user, chain or status said no"
        );
        assert!(!gpu_spawn_allowed(false, 2));
    }

    #[test]
    fn start_search_without_gpu_leaves_no_channel_and_no_engine() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new();
        app.csv_path = dir.path().join("vanity_wallets.csv");
        app.chain = crate::chains::ChainKind::Evm;
        // Eight 'a's will not be found during this test.
        app.vanity_prefix = "aaaaaaaa".into();
        app.thread_count = "1".into();
        app.gpu_requested = false;

        app.validate().unwrap();
        assert!(!app.validated_gpu);

        app.start_search();
        assert!(
            app.gpu_rx.is_none(),
            "no GPU channel when the GPU is not effective"
        );
        assert!(
            app.gpu_engines.is_empty(),
            "no engine spawned when the GPU is not effective"
        );
        assert!(app.state == AppState::Searching);

        app.stop_search();
    }

    #[test]
    fn gpu_health_resets_even_when_no_gpu_spawns() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new();
        app.csv_path = dir.path().join("vanity_wallets.csv");
        app.chain = crate::chains::ChainKind::Evm;
        app.vanity_prefix = "aaaaaaaa".into();
        app.thread_count = "1".into();
        app.gpu_requested = false;

        app.validate().unwrap();
        assert!(!app.validated_gpu);

        // Poison the health cell as if a previous GPU run had delivered seeds.
        app.gpu_health
            .seeds_delivered
            .store(5_000_000, Ordering::Relaxed);

        app.start_search();

        assert_eq!(
            app.gpu_health.seeds_delivered.load(Ordering::Relaxed),
            0,
            "a fresh GpuHealth must replace the stale one on every start_search, \
             even when this run spawns no GPU -- otherwise the stats pane divides \
             a stale numerator by a fresh denominator and shows a fabricated rate"
        );

        app.stop_search();
    }

    #[test]
    fn gpu_effective_requires_user_device_and_evm() {
        use crate::gpu::{GpuDisableReason, GpuStatus};

        let ready = || GpuStatus::Ready {
            device: "Apple M1".to_string(),
        };

        // The happy case: user wants it, a device exists, chain is EVM.
        // Set the status explicitly instead of trusting the constructor: the env
        // lever rewrites a `Ready` probe into `Disabled(UserOff)`, so a developer
        // with VANADDY_NO_GPU=1 exported in their shell must still see this test
        // exercise the happy path.
        let mut app = App::with_gpu_status(ready());
        app.gpu_status = ready();
        app.chain = crate::chains::ChainKind::Evm;
        app.gpu_requested = true;
        assert!(app.gpu_effective());

        // Initializing and Running are both "the GPU is live for this run".
        app.gpu_status = GpuStatus::Initializing;
        assert!(app.gpu_effective());
        app.gpu_status = GpuStatus::Running {
            device: "Apple M1".to_string(),
        };
        assert!(app.gpu_effective());

        // User said no.
        app.gpu_status = ready();
        app.gpu_requested = false;
        assert!(!app.gpu_effective());

        // Wrong chain: the GPU pipeline is EVM-only.
        app.gpu_requested = true;
        app.chain = crate::chains::ChainKind::Solana;
        assert!(!app.gpu_effective());

        // No device.
        app.chain = crate::chains::ChainKind::Evm;
        app.gpu_status = GpuStatus::Unavailable("no Metal device".to_string());
        assert!(!app.gpu_effective());

        // Disabled is sticky: gpu_effective() must never resurrect a faulted GPU.
        app.gpu_status = GpuStatus::Disabled(GpuDisableReason::AuditMismatch { index: 5183 });
        assert!(!app.gpu_effective());
    }

    #[test]
    fn app_new_never_requests_a_gpu_it_has_not_probed() {
        // App::new() is the test/no-probe constructor. It must default to a
        // status that gpu_effective() rejects, so a test that forgets to set up
        // the GPU can never accidentally spawn a real one.
        let app = App::new();
        assert!(matches!(
            app.gpu_status,
            crate::gpu::GpuStatus::Unavailable(_)
        ));
        assert!(!app.gpu_requested);
        assert!(!app.validated_gpu);
        assert!(app.gpu_rx.is_none());
        assert!(!app.gpu_effective());
    }

    #[test]
    fn validate_never_returns_err_for_a_gpu_reason() {
        use crate::gpu::{GpuDisableReason, GpuStatus};

        let mut app = App::with_gpu_status(GpuStatus::Ready {
            device: "Apple M1".to_string(),
        });
        // Pin the status: the constructor's env lever rewrites a `Ready` probe
        // into `Disabled(UserOff)`, and this test must not depend on the
        // developer's shell.
        app.gpu_status = GpuStatus::Ready {
            device: "Apple M1".to_string(),
        };
        app.chain = crate::chains::ChainKind::Evm;
        app.vanity_prefix = "abcd".into();
        app.thread_count = "2".into();

        // GPU on and healthy: validated_gpu latches true.
        app.gpu_requested = true;
        assert!(app.validate().is_ok());
        assert!(app.validated_gpu);

        // GPU requested but the device faulted mid-session. This is the case a
        // naive implementation turns into Err and locks the user out of the app.
        app.gpu_status = GpuStatus::Disabled(GpuDisableReason::VerifyMismatch {
            address: "0x0000000000000000000000000000000000000000".to_string(),
        });
        assert!(
            app.validate().is_ok(),
            "a faulted GPU must never block a CPU search"
        );
        assert!(!app.validated_gpu);

        // GPU requested on a non-EVM chain: still fine, still CPU-only.
        app.gpu_status = GpuStatus::Ready {
            device: "Apple M1".to_string(),
        };
        app.chain = crate::chains::ChainKind::Solana;
        app.vanity_prefix = "abcd".into();
        assert!(
            app.validate().is_ok(),
            "EVM-only offload must never block another chain"
        );
        assert!(!app.validated_gpu);

        // No device at all.
        app.chain = crate::chains::ChainKind::Evm;
        app.gpu_status = GpuStatus::Unavailable("no Metal device".to_string());
        assert!(app.validate().is_ok());
        assert!(!app.validated_gpu);

        // A real, non-GPU error still errors. The advisory line must not have
        // swallowed the thread-count validation.
        app.thread_count = "0".into();
        assert!(
            app.validate().is_err(),
            "thread-count validation is unaffected"
        );
    }

    /// The CSV holds plaintext seed phrases. Both halves of the 0600 guarantee
    /// must survive: `.mode(0o600)` on create AND the post-open `set_permissions`
    /// re-assert, which is the half that catches a pre-existing loose file.
    #[test]
    #[cfg(unix)]
    fn open_csv_secure_reasserts_0600_on_preexisting_0644() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vanity_wallets.csv");
        std::fs::write(&path, b"Chain,Address,Private Key (hex),Seed Phrase\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644,
            "precondition: the file starts world-readable"
        );

        let file = open_csv_secure(&path).expect("open must succeed");
        drop(file);

        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "a pre-existing loose-permission CSV must be tightened on every open"
        );
    }

    /// A `Match` cannot exist without a `verify::Verified`, so `append_match_row`
    /// is structurally unable to write an unverified row. Assert the consequence:
    /// what lands on disk re-derives, and the file is 0600.
    #[test]
    #[cfg(unix)]
    fn verified_match_is_written_and_file_is_0600() {
        use crate::chains::evm::Evm;
        use crate::chains::Bip39GpuChain;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vanity_wallets.csv");

        let m = one_cpu_match();
        append_match_row(&path, &m).expect("append must succeed");

        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_path(&path)
            .unwrap();
        let rows: Vec<csv::StringRecord> = rdr.records().map(|r| r.unwrap()).collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].len(), 4);
        assert_eq!(&rows[0][0], "EVM");
        assert_eq!(&rows[0][1], m.address.as_str());
        assert!(
            Evm::verify(&rows[0][1], &rows[0][2], &rows[0][3]),
            "every CSV row must re-derive from its own phrase"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    /// The gate's end-to-end consequence: a GPU candidate whose seed carries one
    /// flipped bit is rejected by `verify_gpu`, so no `Match` is ever minted for
    /// it, so its address cannot appear in the file. Every row that IS there
    /// re-derives.
    #[test]
    #[cfg(unix)]
    fn unverified_match_is_never_written_to_csv() {
        use crate::chains::evm::Evm;
        use crate::chains::{Bip39GpuChain, Chain};
        use bip39::{Language, Mnemonic};
        use std::os::unix::fs::PermissionsExt;

        // Deterministic entropy so a red build replays exactly.
        let mut entropy = [0u8; 16];
        entropy[15] = 77;
        let mn = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
        let mut seed = crate::seed::derive_seed(&mn);
        seed[0] ^= 0x01; // exactly what a faulty kernel would produce
        let (bad_addr, _sk) = Evm::from_gpu_seed(&seed);
        let bad_address = Evm::encode_address(&bad_addr);

        assert!(
            crate::verify::verify_gpu::<Evm>(&entropy, &bad_addr).is_none(),
            "the gate must reject a corrupted GPU seed, so no Match can be minted"
        );

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vanity_wallets.csv");
        // Write everything the gate DID accept.
        let good = one_cpu_match();
        append_match_row(&path, &good).expect("append must succeed");

        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            !body.contains(&bad_address),
            "a rejected candidate must never reach the CSV"
        );
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_path(&path)
            .unwrap();
        for rec in rdr.records() {
            let r = rec.unwrap();
            assert!(
                Evm::verify(&r[1], &r[2], &r[3]),
                "every CSV row must re-derive: {}",
                &r[1]
            );
        }
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    /// Milestone 5's end-to-end gate. A real EVM search with a 1-character
    /// prefix, fed by the real Metal producer, writing through the production
    /// CSV writer. Asserts three things at once:
    ///   1. the GPU path actually ran (otherwise this test proves nothing),
    ///   2. every CSV row re-derives from its phrase alone through `ring`,
    ///   3. the counter is honest — every candidate it counted was examined,
    ///      as whole 64-candidate GPU chunks plus whole 4-candidate CPU batches.
    ///
    /// What (2) does and does not establish. The loop parses each phrase back out
    /// of the PERSISTED file and recomputes the address without touching the
    /// in-memory `Match`, so it proves the CSV writer, the channel and the phrase
    /// round-trip are faithful. It is NOT a second, independent check of the Metal
    /// kernel: `verify_gpu` already ran that same `derive_seed` -> `from_gpu_seed`
    /// chain before the row was built, and the row carries ITS output, never the
    /// GPU's. The kernel's honesty is what `verify_rejections == 0` asserts — a GPU
    /// seed that matched the prefix but failed re-derivation would have raised
    /// `VerifyMismatch` and been counted there. The two assertions together are
    /// what support the product claim; neither does it alone.
    #[test]
    #[ignore = "requires a Metal device and runs for ~5 s; run with --ignored"]
    #[cfg(all(target_os = "macos", target_arch = "aarch64", feature = "metal"))]
    fn hybrid_evm_search_with_live_gpu_emits_only_rederivable_matches() {
        use crate::chains::{evm::Evm, search_hybrid, Bip39GpuChain, Chain};
        use crate::gpu::{GpuEngine, GpuHealth, SeedBlock, CHANNEL_CAPACITY};
        use bip39::{Language, Mnemonic};

        let health = Arc::new(GpuHealth::default());
        let (gtx, grx) = crossbeam_channel::bounded::<Box<SeedBlock>>(CHANNEL_CAPACITY);
        let engine = GpuEngine::start(gtx, Arc::clone(&health));

        // One hex character: ~1 match in 16 candidates, so a few seconds of
        // searching produces thousands of rows to re-derive.
        let matcher = Matcher::new(
            "a".into(),
            String::new(),
            false,
            crate::chains::ChainKind::Evm,
        );
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let (tx, rx) = mpsc::channel();

        thread::scope(|s| {
            for _ in 0..4 {
                let grx_w = grx.clone();
                let health_w = Arc::clone(&health);
                let tx_w = tx.clone();
                let matcher_w = &matcher;
                let stop_w = &stop;
                let counter_w = &counter;
                s.spawn(move || {
                    search_hybrid::<Evm>(
                        matcher_w,
                        stop_w,
                        counter_w,
                        &tx_w,
                        Some(&grx_w),
                        &health_w,
                    );
                });
            }
            thread::sleep(Duration::from_secs(5));
            stop.store(true, Ordering::Relaxed);
        });

        engine.signal_stop();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !engine.is_finished() && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            engine.is_finished(),
            "GPU producer did not stop within 5 s of signal_stop()"
        );
        engine.reap();

        // 1. The GPU path actually ran.
        let delivered = health.seeds_delivered.load(Ordering::Relaxed);
        assert!(
            delivered > 0,
            "the GPU produced no seeds in 5 s - this test proves nothing"
        );
        assert_eq!(
            delivered % 64,
            0,
            "GPU seeds are counted one whole 64-chunk at a time, got {delivered}"
        );
        assert!(
            !health.disable.load(Ordering::Relaxed),
            "GPU disabled mid-run: {:?}",
            health.take_reason()
        );
        assert_eq!(health.verify_rejections.load(Ordering::Relaxed), 0);

        // 3. The counter is honest.
        let n = counter.load(Ordering::Relaxed);
        assert!(
            n >= delivered,
            "counter {n} must include every one of {delivered} GPU candidates"
        );
        assert_eq!(
            (n - delivered) % Evm::BATCH as u64,
            0,
            "the non-GPU remainder must be whole CPU batches, got {}",
            n - delivered
        );

        // 2. Every CSV row re-derives. Written through the production writer.
        let dir = tempfile::tempdir().unwrap();
        let csv = dir.path().join("vanity_wallets.csv");
        drop(tx);
        let mut rows = 0usize;
        while let Ok(m) = rx.try_recv() {
            append_match_row(&csv, &m).unwrap();
            rows += 1;
        }
        assert!(
            rows > 0,
            "a 1-character EVM prefix must produce matches in 5 s"
        );

        let text = std::fs::read_to_string(&csv).unwrap();
        for line in text.lines() {
            let f: Vec<&str> = line.split(',').collect();
            assert_eq!(
                f.len(),
                4,
                "row must be Chain,Address,Secret,Phrase: {line}"
            );
            assert_eq!(f[0], "EVM");
            assert!(
                f[1].starts_with("0xa"),
                "row does not match the prefix: {line}"
            );
            let m = Mnemonic::from_phrase(f[3], Language::English)
                .unwrap_or_else(|e| panic!("CSV phrase is not a valid mnemonic ({e}): {line}"));
            let (addr, sk) = Evm::from_gpu_seed(&crate::seed::derive_seed(&m));
            assert_eq!(
                Evm::encode_address(&addr),
                f[1],
                "CSV address does not re-derive: {line}"
            );
            assert_eq!(
                Evm::encode_secret(&sk),
                f[2],
                "CSV secret does not re-derive: {line}"
            );
        }

        eprintln!(
            "counter={n}  gpu_seeds={delivered}  cpu_candidates={}  csv_rows={rows}",
            n - delivered
        );
    }

    #[test]
    fn match_cap_evicts_oldest_and_total_keeps_counting() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new();
        app.csv_path = dir.path().join("vanity_wallets.csv");

        let (tx, rx) = mpsc::channel();
        app.rx = Some(rx);
        for i in 0..(MATCH_CAP + 7) {
            tx.send(Match {
                chain: "EVM".to_string(),
                address: format!("0x{i:040x}"),
                secret_hex: "00".repeat(32),
                mnemonic: "abandon abandon abandon".to_string(),
                verified: crate::verify::Verified::cpu_reference(),
            })
            .unwrap();
        }
        drop(tx);

        app.drain_matches();

        assert_eq!(app.matches.len(), MATCH_CAP, "the in-memory list is capped");
        assert_eq!(
            app.total_matches,
            (MATCH_CAP + 7) as u64,
            "total_matches keeps counting past the cap"
        );
        assert_eq!(
            app.matches.front().unwrap().address,
            format!("0x{:040x}", 7),
            "the OLDEST matches are the ones evicted"
        );
        assert_eq!(
            app.matches.back().unwrap().address,
            format!("0x{:040x}", MATCH_CAP + 6),
            "the newest match is retained"
        );
        assert_eq!(
            app.selected_match,
            MATCH_CAP - 1,
            "selection tracks the newest row"
        );

        // Eviction is a RENDER budget, not data loss: every match is on disk.
        let csv = std::fs::read_to_string(&app.csv_path).unwrap();
        assert_eq!(
            csv.lines().count(),
            MATCH_CAP + 7,
            "the CSV holds every match, cap or no cap"
        );
    }

    /// One genuine CPU-path match, produced by the real `search` loop so the
    /// `Verified` token is minted at its real site rather than forged here
    /// (which is impossible — the field is private to `crate::verify`).
    #[cfg(unix)]
    fn one_cpu_match() -> Match {
        use crate::chains::evm::Evm;
        use crate::chains::search;

        // Empty prefix and suffix accept every address, so the very first batch
        // emits.
        let matcher = Matcher::new(String::new(), String::new(), false, ChainKind::Evm);
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let (tx, rx) = mpsc::channel();
        thread::scope(|s| {
            s.spawn(|| search::<Evm>(&matcher, &stop, &counter, &tx));
            let m = rx
                .recv()
                .expect("CPU search must emit for an empty pattern");
            stop.store(true, Ordering::Relaxed);
            m
        })
    }

    #[test]
    fn held_open_csv_file_takes_every_row_and_stays_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vanity_wallets.csv");

        let mut app = App::new();
        app.csv_path = path.clone();
        // Pre-create the file LOOSE, so the post-open `set_permissions` inside
        // `open_csv_secure` is what makes the mode assertion below pass — not
        // `.mode(0o600)` at create, which passes even with the re-assert
        // deleted. (Measured: deleting the re-assert leaves this test green and
        // correctly fails `open_csv_secure_reasserts_0600_on_preexisting_0644`.)
        //
        // Note what this task CHANGES: the mode is now re-asserted per OPEN,
        // i.e. once per search, not once per row. A chmod applied by another
        // process mid-search is no longer corrected until the next
        // `start_search`. That is the contract this test pins.
        std::fs::write(&path, b"").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        app.csv_file = Some(open_csv_secure(&path).unwrap());

        let (tx, rx) = mpsc::channel();
        app.rx = Some(rx);
        for addr in ["0xaaaa", "0xbbbb", "0xcccc"] {
            tx.send(Match {
                chain: "EVM".to_string(),
                address: addr.to_string(),
                secret_hex: "11".repeat(32),
                mnemonic: "abandon abandon abandon".to_string(),
                verified: crate::verify::Verified::cpu_reference(),
            })
            .unwrap();
        }
        drop(tx);

        app.drain_matches();

        let csv = std::fs::read_to_string(&path).unwrap();
        assert!(csv.contains("0xaaaa"), "first row landed: {csv}");
        assert!(
            csv.contains("0xbbbb"),
            "second row landed through the SAME handle: {csv}"
        );
        assert!(
            csv.contains("0xcccc"),
            "third row landed through the SAME handle: {csv}"
        );
        assert_eq!(csv.lines().count(), 3, "no row duplicated or lost: {csv}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "the CSV holds plaintext seed phrases: owner-only, always"
            );
        }
    }

    #[test]
    fn drain_falls_back_to_the_path_when_no_file_is_held() {
        // start_search could not open the CSV (read-only dir, ENOSPC). A found
        // match must still be written, not silently dropped.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vanity_wallets.csv");

        let mut app = App::new();
        app.csv_path = path.clone();
        assert!(app.csv_file.is_none());

        let (tx, rx) = mpsc::channel();
        app.rx = Some(rx);
        tx.send(Match {
            chain: "EVM".to_string(),
            address: "0xfallback".to_string(),
            secret_hex: "22".repeat(32),
            mnemonic: "abandon abandon abandon".to_string(),
            verified: crate::verify::Verified::cpu_reference(),
        })
        .unwrap();
        drop(tx);

        app.drain_matches();

        let csv = std::fs::read_to_string(&path).unwrap();
        assert!(
            csv.contains("0xfallback"),
            "fallback writer must not drop a match: {csv}"
        );
    }

    #[test]
    fn a_failed_csv_write_is_counted_and_never_evicts_the_only_copy() {
        // Neither writer can succeed: `csv_path` points inside a directory that
        // does not exist. The match must survive in memory — with the write
        // failed, that in-memory row is the ONLY copy of the seed phrase — and
        // the user must be told, because Step 7 otherwise swallows the error.
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new();
        app.csv_path = dir.path().join("no-such-dir").join("vanity_wallets.csv");
        assert!(app.csv_file.is_none());

        let (tx, rx) = mpsc::channel();
        app.rx = Some(rx);
        tx.send(Match {
            chain: "EVM".to_string(),
            address: "0xdoomed".to_string(),
            secret_hex: "33".repeat(32),
            mnemonic: "abandon abandon abandon".to_string(),
            verified: crate::verify::Verified::cpu_reference(),
        })
        .unwrap();
        drop(tx);

        app.drain_matches();

        assert_eq!(
            app.csv_write_failures, 1,
            "the failed write must be counted"
        );
        assert_eq!(
            app.matches.len(),
            1,
            "the in-memory row is now the ONLY copy"
        );
        assert!(
            app.error_message.is_some(),
            "the user must be told the CSV is not being written"
        );
    }

    #[test]
    fn mismatch_disables_gpu_and_leaves_app_running() {
        use crate::gpu::{GpuDisableReason, GpuStatus};

        let mut app = App::with_gpu_status(GpuStatus::Running {
            device: "Apple M1".to_string(),
        });
        app.chain = crate::chains::ChainKind::Evm;
        app.gpu_requested = true;
        app.validated_gpu = true;
        app.state = AppState::Searching;
        app.start_time = Some(Instant::now());

        // Bind a LIVE drain side. `with_gpu_status` initialises `gpu_rx: None`
        // and nothing else in this milestone ever assigns it, so without this
        // the `gpu_rx.is_none()` assertion below is vacuous: deleting
        // `self.gpu_rx = None;` from Step 4's promotion block leaves the test
        // green. `crossbeam-channel` is an unconditional dependency, so this is
        // portable to every leg.
        let (keep_tx, rx) = crossbeam_channel::bounded::<Box<crate::gpu::SeedBlock>>(1);
        app.gpu_rx = Some(rx);
        assert!(
            app.gpu_rx.is_some(),
            "precondition: a live drain side exists"
        );

        // A Rayon worker found a GPU candidate that MATCHED the pattern but did
        // not re-derive on the CPU. That is a GPU fault, never a false positive.
        app.gpu_health.raise(GpuDisableReason::VerifyMismatch {
            address: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        });

        app.drain_matches();

        assert!(
            matches!(
                app.gpu_status,
                GpuStatus::Disabled(GpuDisableReason::VerifyMismatch { .. })
            ),
            "the fault must be promoted to a visible status on the next tick"
        );
        assert!(!app.gpu_requested, "sticky for the process");
        assert!(!app.validated_gpu, "sticky for the process");
        assert!(
            !app.gpu_effective(),
            "a faulted GPU can never turn itself back on"
        );
        assert!(
            app.gpu_rx.is_none(),
            "the drain side is released so workers stop draining"
        );

        // And the whole point: the app keeps searching on CPU.
        assert!(!app.should_quit, "a GPU fault must never quit the app");
        assert!(
            app.state == AppState::Searching,
            "the search continues on CPU"
        );
        assert!(
            !app.stop.load(Ordering::Relaxed),
            "the GPU has its OWN stop flag; App::stop must be untouched or every worker exits"
        );
        drop(keep_tx);
    }

    #[test]
    fn fault_promotion_is_idempotent_and_never_overwrites_the_first_reason() {
        use crate::gpu::{GpuDisableReason, GpuStatus};

        let mut app = App::with_gpu_status(GpuStatus::Running {
            device: "Apple M1".to_string(),
        });
        app.chain = crate::chains::ChainKind::Evm;
        app.gpu_requested = true;
        app.state = AppState::Searching;

        app.gpu_health
            .raise(GpuDisableReason::AuditMismatch { index: 5183 });
        app.drain_matches();

        // A DIFFERENT reason on a FRESH cell. Re-ticking the SAME cell proves
        // nothing: `GpuHealth::reason` is a set-once `OnceLock` and
        // `take_reason` clones without consuming, so ticks 2 and 3 re-derive
        // the identical `AuditMismatch { index: 5183 }` and every field the
        // promotion body writes is idempotent — removing the
        // `!matches!(.., Disabled(_))` guard at Step 4, the guard this test
        // exists to protect, leaves it green (and the set-once property itself
        // is already covered by
        // `gpu::tests::raise_records_the_first_reason_and_never_overwrites_it`).
        // With a fresh cell carrying a different reason, an unguarded second
        // promotion overwrites the first and this test fails.
        app.gpu_health = Arc::new(crate::gpu::GpuHealth::default());
        app.gpu_health.raise(GpuDisableReason::Panicked);
        app.drain_matches();
        app.drain_matches();

        assert_eq!(
            app.gpu_status,
            GpuStatus::Disabled(GpuDisableReason::AuditMismatch { index: 5183 }),
            "the first reason is the one that stands, and repeated ticks do not churn it"
        );
    }

    #[test]
    fn unexpected_gpu_exit_is_detected_only_on_a_live_faultless_run() {
        // Searching, live channel, no fault raised, yet the engine finished:
        // the producer died quietly and the TUI would report Running at 0/s.
        assert!(is_unexpected_gpu_exit(GpuExitCheck {
            state: AppState::Searching,
            gpu_live: true,
            disabled: false,
            engine_finished: true,
        }));
        // A finished engine after a clean stop is expected, not a fault.
        assert!(!is_unexpected_gpu_exit(GpuExitCheck {
            state: AppState::Configuring,
            gpu_live: true,
            disabled: false,
            engine_finished: true,
        }));
        // The GPU was skipped this run (no live channel): a leftover engine from
        // the previous run finishing is exactly what we asked it to do.
        assert!(!is_unexpected_gpu_exit(GpuExitCheck {
            state: AppState::Searching,
            gpu_live: false,
            disabled: false,
            engine_finished: true,
        }));
        // A fault was already raised: the promotion branch owns that case and
        // has the real reason. Do not overwrite it with Panicked.
        assert!(!is_unexpected_gpu_exit(GpuExitCheck {
            state: AppState::Searching,
            gpu_live: true,
            disabled: true,
            engine_finished: true,
        }));
        // Engine still running: nothing to report.
        assert!(!is_unexpected_gpu_exit(GpuExitCheck {
            state: AppState::Searching,
            gpu_live: true,
            disabled: false,
            engine_finished: false,
        }));
    }

    #[test]
    fn status_refresh_leaves_the_status_alone_when_no_engine_is_parked() {
        use crate::gpu::GpuStatus;

        // The only test that runs a full faultless tick with a LIVE channel, so
        // it is the only one that notices section 3 firing when it must not:
        // change `gpu_engines.iter().any(..)` to `.all(..)` and this test fails,
        // because `all()` is vacuously true on the empty list and the tick then
        // treats an idle-but-alive GPU as a quiet death and releases the
        // channel. Measured: that one-character edit fails this test and no
        // other in the suite.
        //
        // It does NOT cover the opposite error — a call site that UNDER-reports,
        // such as a transposed `gpu_live`/`disabled` — because `gpu_engines` is
        // empty in every test here, so section 3's true branch never executes.
        // That needs a live engine: Task 6.10.
        //
        // It also does NOT prove the status-refresh block is present. With
        // nothing parked, `gpu_engines.last()` is None, so that block is a no-op
        // whether it exists or not — deleting it outright leaves this test
        // green (measured). Refresh behaviour that actually reads a parked
        // engine is covered by the metal-gated test in Task 6.10, not here.
        let (keep_tx, rx) = crossbeam_channel::bounded::<Box<crate::gpu::SeedBlock>>(1);
        let mut app = App::with_gpu_status(GpuStatus::Initializing);
        app.chain = crate::chains::ChainKind::Evm;
        app.gpu_requested = true;
        app.state = AppState::Searching;
        app.gpu_rx = Some(rx);
        assert!(
            app.gpu_engines.is_empty(),
            "precondition: nothing is parked"
        );

        app.drain_matches();

        assert_eq!(
            app.gpu_status,
            GpuStatus::Initializing,
            "no engine, so no status to read"
        );
        assert!(
            app.gpu_rx.is_some(),
            "a faultless tick must not release the channel"
        );
        drop(keep_tx);
    }

    #[test]
    fn shutdown_gpu_returns_immediately_when_nothing_is_parked() {
        let mut app = App::new();
        // Without this the assertion below is vacuous: `App::new()` already
        // leaves `gpu_rx` None, so it holds whether or not `shutdown_gpu`
        // clears it.
        let (keep_tx, rx) = crossbeam_channel::bounded::<Box<crate::gpu::SeedBlock>>(1);
        app.gpu_rx = Some(rx);
        let before = Instant::now();
        app.shutdown_gpu(Duration::from_millis(600));
        let elapsed = before.elapsed();
        assert!(
            elapsed < Duration::from_millis(50),
            "must not sleep out the deadline when there is nothing to wait for: {elapsed:?}"
        );
        assert!(app.gpu_engines.is_empty());
        assert!(app.gpu_rx.is_none());
        drop(keep_tx);
    }

    /// A real, still-running engine is parked before the call, so this exercises
    /// the path `shutdown_gpu_returns_immediately_when_nothing_is_parked` cannot:
    /// `App::new()` leaves `gpu_engines` empty, so the polling loop never runs an
    /// iteration there and the call returns in microseconds under ANY
    /// implementation, an unbounded join included.
    ///
    /// WHAT THIS TEST PROVES: the engine is signalled, it winds down on its own,
    /// and the call returns within `deadline + 25 ms` rather than joining.
    ///
    /// WHAT IT DELIBERATELY DOES NOT PROVE: that the DEADLINE, rather than an
    /// early `is_finished()`, is what ended the wait. It cannot, and an earlier
    /// version of this test that tried to — `assert!(elapsed >= deadline)` — was
    /// actively harmful. That assertion demands the producer still be starting up
    /// at the 10 ms mark, which holds only with a COLD Metal shader compile. Warm,
    /// `MetalPbkdf2::new()` returns in ~5 ms, the stop flag lands, the engine
    /// finishes early and `shutdown_gpu` reaps it cleanly at ~7.7 ms. The result:
    /// the CORRECT implementation failed, while a mutant with the `signal_stop`
    /// loop deleted PASSED — the engine then never finished, the loop ran the full
    /// 10 ms, and the assertion was satisfied by the bug. Measured 2026-08-31.
    ///
    /// The `Arc::strong_count` poll below is the timing-immune replacement. The
    /// producer thread holds its own `Arc<GpuHealth>` clone for its whole life
    /// (`src/gpu/metal.rs:588`, captured by the spawned closure), and this test
    /// keeps `rx` alive so there is no `Disconnected` shortcut — so the thread can
    /// only ever exit via the stop flag. Delete the `signal_stop` loop from
    /// `shutdown_gpu` and the count never reaches 1, on any machine, at any cache
    /// temperature. Verified by mutation.
    ///
    /// The engine is abandoned mid-flight, exactly as `shutdown_gpu`'s doc comment
    /// describes: its thread exits on the stop flag shortly after this returns.
    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64", feature = "metal"))]
    fn shutdown_gpu_honours_its_deadline_with_a_live_engine() {
        use crate::gpu::{SeedBlock, CHANNEL_CAPACITY};

        // Same graceful-skip idiom as `gpu_for_test` in `src/gpu/metal.rs`:
        // this test must pass on a machine with no Metal device.
        if std::env::var_os("VANADDY_NO_GPU").is_some() {
            eprintln!("SKIP: VANADDY_NO_GPU is set");
            return;
        }
        if let GpuStatus::Unavailable(reason) = GpuEngine::probe() {
            eprintln!("SKIP: no Metal device on this machine ({reason})");
            return;
        }

        let mut app = App::new();
        app.gpu_health = Arc::new(GpuHealth::default());
        let (gpu_tx, rx) = crossbeam_channel::bounded::<Box<SeedBlock>>(CHANNEL_CAPACITY);
        let engine = GpuEngine::start(gpu_tx, app.gpu_health.clone());
        app.gpu_engines.push(engine);
        // App's own clone, exactly as `start_search` holds it. The local `rx`
        // stays alive for the whole test, so the producer can only ever see the
        // stop flag — never a `Disconnected` shortcut that would let it finish
        // early and hand this test a free pass.
        app.gpu_rx = Some(rx.clone());

        // No `recv` first: shut down while the producer is still starting up.
        let deadline = Duration::from_millis(10);
        let before = Instant::now();
        app.shutdown_gpu(deadline);
        let elapsed = before.elapsed();

        assert!(
            elapsed < deadline + Duration::from_millis(25),
            "shutdown_gpu is a bounded wait, never a join: {elapsed:?}"
        );
        assert!(
            app.gpu_engines.is_empty(),
            "an engine still running past the deadline is abandoned, not left parked"
        );
        assert!(
            app.gpu_rx.is_none(),
            "shutdown_gpu drops App's channel clone"
        );

        // The producer must actually have been TOLD to stop. `rx` is still
        // alive here, so there is no `Disconnected` shortcut: the thread can
        // only exit via the stop flag. Delete the `signal_stop` loop from
        // `shutdown_gpu` and this count never reaches 1.
        //
        // Deliberately NOT a wall-clock assertion. The version this replaces
        // required `elapsed >= deadline`, which demanded the engine still be
        // starting up at the 10 ms mark — true only with a COLD Metal shader
        // cache. Warm, `MetalPbkdf2::new()` returns in ~5 ms, the engine
        // finishes early, shutdown_gpu reaps it at ~7.7 ms, and the CORRECT
        // implementation failed while a mutant with `signal_stop` deleted
        // passed. Measured on this machine, 2026-08-31.
        let give_up = Instant::now() + Duration::from_secs(2);
        while Arc::strong_count(&app.gpu_health) > 1 && Instant::now() < give_up {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            Arc::strong_count(&app.gpu_health),
            1,
            "the producer still holds its Arc<GpuHealth> 2s after shutdown_gpu \
             returned: it was never told to stop"
        );
        drop(rx);
    }

    /// The half the 10 ms test cannot pin down on a warm cache. With a ZERO
    /// deadline the polling loop runs no iterations at all, so the engine is
    /// abandoned while definitely still live. This is the path that keeps a
    /// GPU wedged inside `waitUntilCompleted` from hanging process exit, and
    /// unlike a timing assertion it is deterministic everywhere.
    ///
    /// KNOWN GAP: no test here kills the deadline itself. Drop
    /// `&& start.elapsed() < deadline` from the loop and all three tests still
    /// pass on a warm machine, because every producer winds down inside the
    /// bounds. Closing it deterministically needs the engine's finished/stop
    /// state to be injectable, which is an API change and out of scope. A
    /// tighter wall-clock bound was considered and rejected: the honest margin
    /// is 3-5 ms, so it would flake under full-suite load. The live witness for
    /// "quitting never hangs" is the manual acceptance run in Task 6.11.
    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64", feature = "metal"))]
    fn shutdown_gpu_abandons_a_live_engine_rather_than_waiting() {
        use crate::gpu::{SeedBlock, CHANNEL_CAPACITY};

        if std::env::var_os("VANADDY_NO_GPU").is_some() {
            eprintln!("SKIP: VANADDY_NO_GPU is set");
            return;
        }
        if let GpuStatus::Unavailable(reason) = GpuEngine::probe() {
            eprintln!("SKIP: no Metal device on this machine ({reason})");
            return;
        }

        let mut app = App::new();
        app.gpu_health = Arc::new(GpuHealth::default());
        let (gpu_tx, rx) = crossbeam_channel::bounded::<Box<SeedBlock>>(CHANNEL_CAPACITY);
        app.gpu_engines
            .push(GpuEngine::start(gpu_tx, app.gpu_health.clone()));
        app.gpu_rx = Some(rx.clone());

        let before = Instant::now();
        app.shutdown_gpu(Duration::ZERO);
        let elapsed = before.elapsed();

        assert!(
            elapsed < Duration::from_millis(25),
            "a zero deadline abandons immediately, it does not wait: {elapsed:?}"
        );
        assert!(
            app.gpu_engines.is_empty(),
            "the engine is abandoned, never left parked"
        );
        assert!(app.gpu_rx.is_none());

        // Abandoned, but still signalled, so it winds down on its own.
        let give_up = Instant::now() + Duration::from_secs(2);
        while Arc::strong_count(&app.gpu_health) > 1 && Instant::now() < give_up {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            Arc::strong_count(&app.gpu_health),
            1,
            "an abandoned engine must still have been signalled to stop"
        );
        drop(rx);
    }

    use crate::gpu::{GpuDisableReason, GpuStatus};

    fn press(app: &mut App, code: KeyCode) {
        handle_key_event(app, event::KeyEvent::new(code, KeyModifiers::NONE));
    }

    fn app_on_gpu_field() -> App {
        let mut app = App::new();
        app.chain = ChainKind::Evm;
        app.match_position = MatchPosition::StartsWith;
        app.gpu_status = GpuStatus::Ready {
            device: "Apple M1".to_string(),
        };
        app.gpu_requested = false;
        app.error_message = None;
        app.active_field = app.field_count() - 2;
        app
    }

    #[test]
    fn gpu_field_toggles_with_y_n_and_arrows() {
        let mut app = app_on_gpu_field();

        press(&mut app, KeyCode::Char('y'));
        assert!(app.gpu_requested, "y turns GPU offload on");
        press(&mut app, KeyCode::Char('n'));
        assert!(!app.gpu_requested, "n turns GPU offload off");
        press(&mut app, KeyCode::Right);
        assert!(app.gpu_requested, "Right toggles GPU offload on");
        press(&mut app, KeyCode::Left);
        assert!(!app.gpu_requested, "Left toggles GPU offload off");
        press(&mut app, KeyCode::Char('Y'));
        assert!(app.gpu_requested, "uppercase Y works too");
    }

    #[test]
    fn gpu_field_refuses_to_turn_on_for_a_non_evm_chain() {
        let mut app = app_on_gpu_field();
        app.chain = ChainKind::Solana;

        press(&mut app, KeyCode::Char('y'));

        assert!(!app.gpu_requested, "GPU offload is EVM-only");
        let msg = app
            .error_message
            .clone()
            .expect("refusal must be visible, not silent");
        assert!(msg.contains("EVM-only"), "unhelpful refusal: {msg}");
        assert!(msg.contains("Solana"), "refusal must name the chain: {msg}");
    }

    #[test]
    fn gpu_field_refuses_to_turn_on_when_there_is_no_device() {
        let mut app = app_on_gpu_field();
        app.gpu_status = GpuStatus::Unavailable("no Metal device".to_string());

        press(&mut app, KeyCode::Char('y'));

        assert!(
            !app.gpu_requested,
            "cannot request a GPU that does not exist"
        );
        let msg = app.error_message.clone().expect("refusal must be visible");
        assert!(
            msg.contains("no Metal device"),
            "refusal must carry the reason: {msg}"
        );
    }

    #[test]
    fn gpu_field_refuses_to_turn_on_after_a_fault_disabled_it() {
        let mut app = app_on_gpu_field();
        app.gpu_status = GpuStatus::Disabled(GpuDisableReason::AuditMismatch { index: 5183 });

        press(&mut app, KeyCode::Char('y'));

        assert!(
            !app.gpu_requested,
            "a disabled GPU is sticky for the process"
        );
        let msg = app.error_message.clone().expect("refusal must be visible");
        assert!(
            msg.contains("AuditMismatch"),
            "refusal must carry the reason: {msg}"
        );
    }

    #[test]
    fn turning_the_gpu_off_always_works_and_clears_the_error() {
        let mut app = app_on_gpu_field();
        app.chain = ChainKind::Monero;
        // ON first. `app_on_gpu_field` leaves the toggle off, so without this
        // the assertion below passes against an already-off flag and would
        // survive deleting the `gpu_requested = false` line it exists to pin.
        app.gpu_requested = true;
        app.error_message = Some("stale complaint".to_string());

        press(&mut app, KeyCode::Char('n'));

        assert!(
            !app.gpu_requested,
            "'n' must turn a live preference off, on a chain where 'y' is refused"
        );
        assert!(
            app.error_message.is_none(),
            "off is never refused, and clears the error"
        );
    }

    #[test]
    fn gpu_preference_survives_a_round_trip_through_another_chain() {
        let mut app = app_on_gpu_field();
        press(&mut app, KeyCode::Char('y'));
        assert!(app.gpu_requested);

        app.active_field = 0; // Chain
        press(&mut app, KeyCode::Char('1')); // Solana
        press(&mut app, KeyCode::Char('2')); // back to EVM

        assert!(
            app.gpu_requested,
            "the preference must survive a trip through Solana"
        );
        assert!(
            app.gpu_effective(),
            "and must be effective again once the chain is EVM"
        );
    }

    #[test]
    fn gpu_measured_rate_is_derived_from_seeds_delivered_not_modelled() {
        let mut app = App::new();
        app.start_time = Some(
            Instant::now()
                .checked_sub(Duration::from_secs(10))
                .expect("the monotonic clock is at least 10 s past boot"),
        );
        app.counter.store(1_000_000, Ordering::Relaxed);
        app.gpu_health
            .seeds_delivered
            .store(500_000, Ordering::Relaxed);

        let (rate, share) = app.gpu_measured_rate();
        assert!(
            (49_900..=50_000).contains(&rate),
            "500,000 delivered seeds over 10 s of wall time is ~50,000/s, got {rate}"
        );
        assert_eq!(
            share, 50,
            "500,000 of 1,000,000 candidates came from the GPU"
        );
        // The figures above are chosen to sit FAR from the modelled constant,
        // and that is the whole test. The plan's original numbers were 136,000
        // seeds over 10 s = 13,600/s — exactly `EVM_GPU_SEEDS_PER_SEC` — so
        // replacing the entire rate expression with the modelled constant
        // passed this test and the whole suite. Measured, not modelled.
        assert_ne!(
            rate,
            crate::gpu::EVM_GPU_SEEDS_PER_SEC as u64,
            "a measured rate that equals the modelled constant proves nothing"
        );
    }

    #[test]
    fn gpu_measured_rate_is_zero_before_a_search_starts() {
        let app = App::new();
        // Load both counters first. A fresh `App` has zeroes everywhere, which
        // makes `(0, 0)` true for a second reason and hides the early return:
        // swapping `let Some(start) = .. else { return (0, 0) }` for a fallback
        // clock still yields (0, 0) when there is nothing to divide. With real
        // numbers here, only the early return can produce (0, 0).
        app.gpu_health
            .seeds_delivered
            .store(500_000, Ordering::Relaxed);
        app.counter.store(1_000_000, Ordering::Relaxed);
        assert_eq!(
            app.gpu_measured_rate(),
            (0, 0),
            "no elapsed time means no measurement — never a modelled guess"
        );
    }

    #[test]
    fn gpu_measured_rate_share_cannot_exceed_100_percent() {
        let mut app = App::new();
        app.start_time = Some(
            Instant::now()
                .checked_sub(Duration::from_secs(1))
                .expect("the monotonic clock is at least 1 s past boot"),
        );
        // The worker increments `counter` and `seeds_delivered` separately, so
        // a UI tick can land between the two stores.
        app.counter.store(100, Ordering::Relaxed);
        app.gpu_health.seeds_delivered.store(400, Ordering::Relaxed);
        assert_eq!(
            app.gpu_measured_rate().1,
            100,
            "share is clamped, never 400%"
        );
    }

    #[test]
    fn estimated_rate_without_gpu_is_unchanged() {
        let mut app = App::new();
        app.chain = ChainKind::Evm;
        app.thread_count = "8".to_string();
        app.gpu_requested = false;
        // src/app.rs:152 — EVM measures ~321 us/gen on an M1 P-core.
        assert_eq!(
            app.estimated_rate(),
            3_115.0 * 8.0,
            "with no GPU this must stay exactly threads x per-thread"
        );
    }

    #[test]
    fn estimated_rate_with_gpu_adds_the_gpu_and_charges_for_its_cpu_tail() {
        let mut app = App::new();
        app.chain = ChainKind::Evm;
        app.thread_count = "8".to_string();
        app.gpu_status = GpuStatus::Ready {
            device: "Apple M1".to_string(),
        };
        app.gpu_requested = true;

        let cpu_only = 3_115.0 * 8.0;
        let hybrid = app.estimated_rate();
        assert!(
            hybrid > cpu_only,
            "the GPU must raise the estimate: {hybrid} vs {cpu_only}"
        );
        assert!(
            hybrid < crate::gpu::EVM_GPU_SEEDS_PER_SEC + cpu_only,
            "every GPU seed still costs the CPU its BIP-32 + Keccak tail; that must be \
             charged, not free: {hybrid}"
        );
        // MAGNITUDE, not just direction. The band above is ~24,920..38,520 wide,
        // so a typo of 50.5e-9 for 50.5e-6 in EVM_GPU_TAIL_SECS passes it — and
        // passes every other test in this task.
        //
        // Expressing this in cores does NOT decouple it from
        // EVM_GPU_SEEDS_PER_SEC, and an earlier version of this comment claimed
        // it did. The tail IS `EVM_GPU_SEEDS_PER_SEC * EVM_GPU_TAIL_SECS`, so
        // the band below pins that constant to [10,891, 16,832) seeds/s. The
        // on-record 14,276 seeds/s measurement sits inside it. A re-measure
        // outside the band fails this test loudly, which is the right outcome:
        // a GPU that much faster changes the tail's premise, so the number here
        // should be re-derived rather than quietly widened.
        let displaced_cores = (cpu_only - (hybrid - crate::gpu::EVM_GPU_SEEDS_PER_SEC)) / 3_115.0;
        assert!(
            (0.55..0.85).contains(&displaced_cores),
            "the GPU's CPU tail must cost ~0.69 of a core at 13.6k seeds/s, got {displaced_cores}"
        );
    }

    #[test]
    fn estimated_rate_ignores_the_gpu_for_a_non_evm_chain() {
        let mut app = App::new();
        app.chain = ChainKind::Solana;
        app.thread_count = "8".to_string();
        app.gpu_status = GpuStatus::Ready {
            device: "Apple M1".to_string(),
        };
        app.gpu_requested = true;
        // src/app.rs:151 — Solana measures ~288 us/gen.
        assert_eq!(
            app.estimated_rate(),
            3_470.0 * 8.0,
            "GPU offload is EVM-only"
        );
    }

    /// Tests the clamp DIRECTLY. Going through `estimated_rate` cannot: at
    /// `threads = 1` the tail is 13,600 x 50.5e-6 = 0.687 < 1, so the clamp
    /// never binds, and with the clamp in place `r >= EVM_GPU_SEEDS_PER_SEC`
    /// is true by construction for every input.
    #[test]
    fn gpu_tail_cores_is_clamped_to_the_machine() {
        assert!((App::gpu_tail_cores(13_600.0, 8.0) - 0.687).abs() < 0.01);
        assert_eq!(
            App::gpu_tail_cores(1.0e6, 1.0),
            1.0,
            "unclamped this would be 50.5 cores"
        );
    }

    #[test]
    fn estimated_rate_survives_an_unparseable_thread_count() {
        let mut app = App::new();
        app.chain = ChainKind::Evm;
        app.thread_count = String::new();
        app.gpu_requested = false;
        let r = app.estimated_rate();
        assert!(
            r.is_finite() && r > 0.0,
            "a half-typed thread count must not poison the ETA: {r}"
        );
    }

    #[test]
    fn projected_seconds_uses_the_hybrid_estimate_before_a_search_starts() {
        let mut app = App::new();
        app.chain = ChainKind::Evm;
        app.thread_count = "8".to_string();
        app.vanity_prefix = "abc".to_string();
        app.gpu_status = GpuStatus::Ready {
            device: "Apple M1".to_string(),
        };

        app.gpu_requested = false;
        let cpu = app
            .projected_seconds()
            .expect("3 hex chars is a finite ETA");
        app.gpu_requested = true;
        let hybrid = app
            .projected_seconds()
            .expect("3 hex chars is a finite ETA");

        assert!(
            hybrid < cpu,
            "the GPU must shorten the pre-search ETA: {hybrid} vs {cpu}"
        );
    }

    #[test]
    fn gpu_env_off_recognises_every_documented_spelling() {
        // VANADDY_GPU: value-based, case-insensitive, trimmed.
        assert!(gpu_env_off(Some("0"), None));
        assert!(gpu_env_off(Some("off"), None));
        assert!(gpu_env_off(Some("OFF"), None));
        assert!(gpu_env_off(Some("false"), None));
        assert!(gpu_env_off(Some("no"), None));
        assert!(gpu_env_off(Some(" 0 "), None));

        // VANADDY_NO_GPU: presence-based, matching gpu_for_test's var_os().is_some().
        assert!(gpu_env_off(None, Some("1")));
        assert!(gpu_env_off(None, Some("")));
        assert!(gpu_env_off(None, Some("0")));

        // Neither set, or set to something affirmative: GPU stays on.
        assert!(!gpu_env_off(None, None));
        assert!(!gpu_env_off(Some("1"), None));
        assert!(!gpu_env_off(Some("on"), None));
        assert!(!gpu_env_off(Some("yes"), None));
    }

    #[test]
    fn gpu_env_off_makes_gpu_effective_false_on_evm() {
        let mut app = App::new();
        app.chain = crate::chains::ChainKind::Evm;
        app.gpu_status = crate::gpu::GpuStatus::Ready {
            device: "Apple M1".to_string(),
        };
        app.gpu_requested = true;
        assert!(app.gpu_effective(), "precondition: EVM + Ready + requested");

        // Exactly what App::with_gpu_status applies when the env lever is pulled.
        if gpu_env_off(Some("0"), None) {
            app.gpu_requested = false;
            app.gpu_status = crate::gpu::GpuStatus::Disabled(crate::gpu::GpuDisableReason::UserOff);
        }

        assert!(!app.gpu_effective());
        assert_eq!(
            app.gpu_status,
            crate::gpu::GpuStatus::Disabled(crate::gpu::GpuDisableReason::UserOff)
        );
    }

    #[test]
    fn ends_with_search_uses_vanity_suffix() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new();
        app.csv_path = dir.path().join("vanity_wallets.csv");
        app.chain = crate::chains::ChainKind::Solana;
        app.match_position = MatchPosition::EndsWith;
        app.vanity_prefix = String::new();
        app.vanity_suffix = "zzzzzzzzz".into();
        app.thread_count = "1".into();

        app.validate().unwrap();
        app.start_search();
        // A debug Solana batch finishes between ~40 ms and ~80 ms. 40 ms often
        // stops before `counter` moves, so 0 matches would not prove the suffix.
        thread::sleep(Duration::from_millis(80));
        app.stop_search();

        assert_eq!(app.total_matches, 0);
        assert_eq!(app.total_vanity_chars(), app.vanity_suffix.chars().count());
    }
}
