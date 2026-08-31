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
    pub matches: Vec<Match>,
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
            matches: Vec::new(),
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

    pub fn field_count(&self) -> usize {
        if matches!(self.match_position, MatchPosition::StartsAndEndsWith) {
            6
        } else {
            5
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
            MatchPosition::EndsWith => self.vanity_prefix.chars().count(),
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

    /// Projected seconds until a match. Uses live rate if searching,
    /// otherwise estimates from chain throughput × thread count.
    pub fn projected_seconds(&self) -> Option<f64> {
        let expected = self.expected_attempts()? as f64;
        let rate = if let Some(start) = self.start_time {
            let secs = start.elapsed().as_secs_f64().max(0.5);
            let count = self.counter.load(Ordering::Relaxed) as f64;
            (count / secs).max(1.0)
        } else {
            let threads = self.thread_count.parse::<u64>().unwrap_or(1).max(1) as f64;
            self.single_thread_rate() * threads
        };
        Some(expected / rate)
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

        Ok(())
    }

    pub fn start_search(&mut self) {
        let num_threads = self.validated_thread_count;
        self.error_message = None;
        self.matches.clear();
        self.selected_match = 0;
        self.counter = Arc::new(AtomicU64::new(0));
        self.stop = Arc::new(AtomicBool::new(false));
        self.start_time = Some(Instant::now());
        self.state = AppState::Searching;

        let (prefix, suffix) = match self.match_position {
            MatchPosition::StartsWith => (self.vanity_prefix.clone(), String::new()),
            MatchPosition::EndsWith => (String::new(), self.vanity_prefix.clone()),
            MatchPosition::StartsAndEndsWith => (self.vanity_prefix.clone(), self.vanity_suffix.clone()),
        };

        let matcher = Matcher::new(prefix, suffix, self.case_sensitive, self.chain);
        let chain = self.chain;
        let stop = self.stop.clone();
        let counter = self.counter.clone();
        // Milestone 6 replaces this with `self.gpu_health.clone()` once `App`
        // owns the cell. Until then the workers still need a health cell to
        // read, and `gpu: None` means nothing can ever write to it.
        let health = Arc::new(crate::gpu::GpuHealth::default());

        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);

        // Ensure CSV has header
        {
            let file =
                open_csv_secure(Path::new(CSV_PATH)).expect("Failed to open vanity_wallets.csv");
            let needs_header = file.metadata().map(|m| m.len() == 0).unwrap_or(true);
            if needs_header {
                let mut wtr = WriterBuilder::new().has_headers(false).from_writer(file);
                wtr.write_record(["Chain", "Address", "Private Key (hex)", "Seed Phrase"]).unwrap();
                wtr.flush().unwrap();
            }
        }

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .expect("Failed to build Rayon thread pool");

        pool.spawn(move || {
            (0..num_threads).into_par_iter().for_each(|_| {
                chain.search(&matcher, &stop, &counter, &tx, None, &health);
            });
            drop(tx);
        });

        self.thread_pool = Some(pool);
    }

    pub fn stop_search(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.rx = None;
        // Drops the pool handle; workers will exit on the next stop check.
        self.thread_pool = None;
        self.state = AppState::Configuring;
    }

    pub fn drain_matches(&mut self) {
        if let Some(ref rx) = self.rx {
            while let Ok(payload) = rx.try_recv() {
                // append_match_row is the only writer; it re-asserts 0600 on
                // every open and cannot be handed anything unverified.
                let _ = append_match_row(Path::new(CSV_PATH), &payload);
                self.matches.push(payload);
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
            let _ = std::fs::set_permissions(path, perms);
        }
    }
    Ok(file)
}

/// The SINGLE writer of match rows. It takes a `&Match`, and a `Match` cannot be
/// constructed without a `crate::verify::Verified` token, so an unverified
/// candidate is unrepresentable here rather than merely filtered out.
fn append_match_row(path: &Path, m: &Match) -> io::Result<()> {
    let file = open_csv_secure(path)?;
    let mut wtr = WriterBuilder::new().has_headers(false).from_writer(file);
    wtr.write_record([&m.chain, &m.address, &m.secret_hex, &m.mnemonic])?;
    wtr.flush()?;
    Ok(())
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
        let mut app = App::new();
        app.chain = crate::chains::ChainKind::Evm;
        // Extremely unlikely prefix so search will genuinely run for the duration.
        app.vanity_prefix = "aaaaaaaa".into();
        app.thread_count = "2".into();
        app.validate().unwrap();

        app.start_search();
        thread::sleep(Duration::from_millis(50));
        app.stop_search();

        // Second cycle
        app.validate().unwrap();
        app.start_search();
        thread::sleep(Duration::from_millis(50));
        app.stop_search();

        assert!(app.thread_pool.is_none());
        assert!(app.stop.load(Ordering::Relaxed));
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
}
