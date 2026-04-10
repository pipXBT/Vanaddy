# Ratatui TUI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the println-based UI with a full Ratatui terminal UI featuring a logo banner, config form, live stats, and scrollable match results.

**Architecture:** Single-file approach — all TUI code added to `main.rs`. An `App` struct holds all state. A main event loop renders at 10fps (100ms tick), handles keyboard input, and drains match results from worker threads via the existing `mpsc` channel. Search engine code is untouched.

**Tech Stack:** ratatui 0.29, crossterm (bundled with ratatui)

**Spec:** `docs/superpowers/specs/2026-04-11-ratatui-tui-design.md`

---

### File Structure

- **Modify:** `Cargo.toml` — add ratatui + crossterm dependencies
- **Modify:** `src/main.rs` — add App struct, TUI rendering, event handling; remove old println UI functions; rewrite main()

No new files. The existing search functions, Matcher, derive_seed, bip32_derive_evm_key, CSV writer, and all crypto logic are untouched.

---

### Task 1: Add Dependencies

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Add ratatui and crossterm to Cargo.toml**

Add these two lines to the `[dependencies]` section:

```toml
ratatui = "0.29"
crossterm = "0.28"
```

- [ ] **Step 2: Build to verify dependencies resolve**

Run: `cargo build --release 2>&1`
Expected: Build succeeds, ratatui and crossterm downloaded and compiled.

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "deps: add ratatui and crossterm for TUI"
```

---

### Task 2: Add App State Struct and Enums

**Files:**
- Modify: `src/main.rs` — add after the `MatchPayload` type alias (currently line ~315)

- [ ] **Step 1: Add AppState enum and App struct**

Add this code after the `type MatchPayload = ...` line:

```rust
// ---------------------------------------------------------------------------
// TUI state
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum AppState {
    Configuring,
    Searching,
}

struct App {
    state: AppState,
    should_quit: bool,

    // Form fields
    active_field: usize,
    chain: Chain,
    match_position: MatchPosition,
    vanity_prefix: String,
    vanity_suffix: String,
    case_sensitive: bool,
    thread_count: String,
    error_message: Option<String>,

    // Search state
    matches: Vec<MatchPayload>,
    selected_match: usize,
    counter: Arc<AtomicU64>,
    match_count: Arc<AtomicU64>,
    start_time: Option<Instant>,
    stop: Arc<AtomicBool>,
    rx: Option<mpsc::Receiver<MatchPayload>>,
}

impl App {
    fn new() -> Self {
        let recommended_threads = detect_optimal_threads();
        App {
            state: AppState::Configuring,
            should_quit: false,
            active_field: 0,
            chain: Chain::Solana,
            match_position: MatchPosition::StartsWith,
            vanity_prefix: String::new(),
            vanity_suffix: String::new(),
            case_sensitive: false,
            thread_count: recommended_threads.to_string(),
            error_message: None,
            matches: Vec::new(),
            selected_match: 0,
            counter: Arc::new(AtomicU64::new(0)),
            match_count: Arc::new(AtomicU64::new(0)),
            start_time: None,
            stop: Arc::new(AtomicBool::new(false)),
            rx: None,
        }
    }

    /// Number of form fields. Returns 6 when "StartsAndEndsWith" (prefix + suffix separate), 5 otherwise.
    fn field_count(&self) -> usize {
        if matches!(self.match_position, MatchPosition::StartsAndEndsWith) {
            6 // chain, position, prefix, suffix, case, threads
        } else {
            5 // chain, position, vanity_string, case, threads
        }
    }

    /// Returns true if the active field is a text input field (vanity string or thread count).
    fn is_text_field(&self) -> bool {
        match self.active_field {
            2 => true, // vanity prefix (or single vanity string)
            3 if matches!(self.match_position, MatchPosition::StartsAndEndsWith) => true, // vanity suffix
            f if f == self.field_count() - 1 => true, // threads (always last)
            _ => false,
        }
    }

    fn valid_charset(&self) -> &'static str {
        match self.chain {
            Chain::Solana => "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
            Chain::Evm => "0123456789abcdefABCDEF",
        }
    }

    fn max_vanity_len(&self) -> usize {
        match self.chain {
            Chain::Solana => 9,
            Chain::Evm => 8,
        }
    }
}
```

- [ ] **Step 2: Build to verify it compiles**

Run: `cargo build 2>&1`
Expected: Compiles (App is unused yet, may get dead_code warnings — that's fine).

- [ ] **Step 3: Commit**

```bash
git add src/main.rs
git commit -m "feat(tui): add App state struct and helpers"
```

---

### Task 3: Add Validation and Search Start Logic

**Files:**
- Modify: `src/main.rs` — add methods to `impl App`

- [ ] **Step 1: Add validate and start_search methods to App**

Add these methods inside the `impl App` block:

```rust
    /// Validate form inputs. Returns Ok(()) or Err with error message.
    fn validate(&self) -> Result<(), String> {
        let charset = self.valid_charset();
        let max_len = self.max_vanity_len();

        // Validate prefix
        let prefix = match self.match_position {
            MatchPosition::StartsWith | MatchPosition::StartsAndEndsWith => &self.vanity_prefix,
            MatchPosition::EndsWith => &self.vanity_suffix,
        };
        if prefix.is_empty() {
            return Err("Vanity string cannot be empty".to_string());
        }
        if prefix.len() > max_len {
            return Err(format!("Must be 1-{} characters", max_len));
        }
        if let Some(c) = prefix.chars().find(|c| !charset.contains(*c)) {
            return Err(format!("'{}' is not valid for this chain", c));
        }

        // Validate suffix if both
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

        // Validate thread count
        let max_threads = num_cpus::get().max(1) * 2;
        let count = self.thread_count.parse::<usize>().map_err(|_| "Invalid thread count".to_string())?;
        if count == 0 || count > max_threads {
            return Err(format!("Threads must be 1-{}", max_threads));
        }

        Ok(())
    }

    /// Start search workers. Sets up channels, spawns rayon workers and CSV writer.
    fn start_search(&mut self) {
        let num_threads: usize = self.thread_count.parse().unwrap();
        self.error_message = None;
        self.matches.clear();
        self.selected_match = 0;
        self.counter = Arc::new(AtomicU64::new(0));
        self.match_count = Arc::new(AtomicU64::new(0));
        self.stop = Arc::new(AtomicBool::new(false));
        self.start_time = Some(Instant::now());
        self.state = AppState::Searching;

        let (prefix, suffix) = match self.match_position {
            MatchPosition::StartsWith => (self.vanity_prefix.clone(), String::new()),
            MatchPosition::EndsWith => (String::new(), self.vanity_suffix.clone()),
            MatchPosition::StartsAndEndsWith => (self.vanity_prefix.clone(), self.vanity_suffix.clone()),
        };

        // Note: EndsWith uses vanity_suffix as the user input, stored in suffix
        let (prefix, suffix) = if matches!(self.match_position, MatchPosition::EndsWith) {
            (String::new(), self.vanity_prefix.clone())
        } else {
            (prefix, suffix)
        };

        let matcher = Matcher::new(prefix, suffix, self.match_position, self.case_sensitive, self.chain);
        let chain = self.chain;
        let stop = self.stop.clone();
        let counter = self.counter.clone();

        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);

        // Ensure CSV has header
        {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open("vanity_wallets.csv")
                .expect("Failed to open vanity_wallets.csv");
            let needs_header = file.metadata().map(|m| m.len() == 0).unwrap_or(true);
            if needs_header {
                let mut wtr = WriterBuilder::new().has_headers(false).from_writer(file);
                wtr.write_record(["Chain", "Address", "Private Key (hex)", "Seed Phrase"]).unwrap();
                wtr.flush().unwrap();
            }
        }

        // Build thread pool and spawn workers
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .expect("Failed to build Rayon thread pool");

        pool.spawn(move || {
            (0..num_threads).into_par_iter().for_each(|_| {
                match chain {
                    Chain::Solana => search_solana_raw(&matcher, &stop, &counter, &tx),
                    Chain::Evm => search_evm_raw(&matcher, &stop, &counter, &tx),
                }
            });
            drop(tx);
        });
    }

    /// Stop running search workers.
    fn stop_search(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.rx = None;
        self.state = AppState::Configuring;
    }

    /// Drain match channel, append to matches vec, write to CSV.
    fn drain_matches(&mut self) {
        if let Some(ref rx) = self.rx {
            while let Ok(payload) = rx.try_recv() {
                self.match_count.fetch_add(1, Ordering::Relaxed);

                // Write to CSV
                if let Ok(file) = OpenOptions::new().create(true).append(true).open("vanity_wallets.csv") {
                    let mut wtr = WriterBuilder::new().has_headers(false).from_writer(file);
                    let _ = wtr.write_record(&[&payload.0, &payload.1, &payload.2, &payload.3]);
                    let _ = wtr.flush();
                }

                self.matches.push(payload);
                // Auto-select latest match
                self.selected_match = self.matches.len().saturating_sub(1);
            }
        }
    }
```

- [ ] **Step 2: Build to verify it compiles**

Run: `cargo build 2>&1`
Expected: Compiles (methods unused yet — dead_code warnings expected).

- [ ] **Step 3: Commit**

```bash
git add src/main.rs
git commit -m "feat(tui): add validation, search start/stop, and match draining"
```

---

### Task 4: Add TUI Rendering Functions

**Files:**
- Modify: `src/main.rs` — add after the `impl App` block

- [ ] **Step 1: Add imports for ratatui and crossterm at the top of the file**

Replace the existing imports block with:

```rust
use bip39::{Language, Mnemonic, MnemonicType};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use csv::WriterBuilder;
use ed25519_dalek::SigningKey;
use rayon::prelude::*;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap},
    Frame, Terminal,
};
use ring::hmac;
use sha3::{Digest, Keccak256};
use std::{
    fs::OpenOptions,
    io::{self, stdout, Write},
    num::NonZeroU32,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};
```

- [ ] **Step 2: Add the main `ui` rendering function**

Add this after the `impl App` block (after `drain_matches`):

```rust
// ---------------------------------------------------------------------------
// TUI rendering
// ---------------------------------------------------------------------------

fn ui(f: &mut Frame, app: &App) {
    let size = f.area();

    // Top-level vertical split: 20% logo, 80% body
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(20), Constraint::Percentage(80)])
        .split(size);

    render_banner(f, main_chunks[0]);

    // Body: 25% left (config), 75% right (results)
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(25), Constraint::Percentage(75)])
        .split(main_chunks[1]);

    render_left_panel(f, body_chunks[0], app);
    render_right_panel(f, body_chunks[1], app);
}

fn render_banner(f: &mut Frame, area: Rect) {
    let logo = vec![
        Line::from("██╗   ██╗ █████╗ ███╗   ██╗ █████╗ ██████╗ ██████╗ ██╗   ██╗"),
        Line::from("██║   ██║██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝"),
        Line::from("██║   ██║███████║██╔██╗ ██║███████║██║  ██║██║  ██║ ╚████╔╝ "),
        Line::from("╚██╗ ██╔╝██╔══██║██║╚██╗██║██╔══██║██║  ██║██║  ██║  ╚██╔╝  "),
        Line::from(" ╚████╔╝ ██║  ██║██║ ╚████║██║  ██║██████╔╝██████╔╝   ██║   "),
        Line::from("  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝ ╚═════╝    ╚═╝   "),
        Line::from(""),
        Line::from(Span::styled(
            "v0.4 — Solana & EVM Vanity Address Generator",
            Style::default().fg(Color::Cyan),
        )),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(" Vanaddy ");
    let paragraph = Paragraph::new(logo)
        .block(block)
        .alignment(ratatui::layout::Alignment::Center);
    f.render_widget(paragraph, area);
}

fn render_left_panel(f: &mut Frame, area: Rect, app: &App) {
    // Split left panel: config form (top), stats (bottom), keyhints (footer)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(10),      // config form
            Constraint::Length(7),     // stats
            Constraint::Length(3),     // key hints
        ])
        .split(area);

    render_config_form(f, chunks[0], app);
    render_stats(f, chunks[1], app);
    render_key_hints(f, chunks[2], app);
}

fn render_config_form(f: &mut Frame, area: Rect, app: &App) {
    let is_configuring = app.state == AppState::Configuring;
    let highlight = Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD);
    let normal = Style::default().fg(Color::White);
    let dimmed = Style::default().fg(Color::DarkGray);

    let style_for = |field: usize| -> Style {
        if !is_configuring {
            dimmed
        } else if app.active_field == field {
            highlight
        } else {
            normal
        }
    };

    let chain_str = match app.chain {
        Chain::Solana => "Solana",
        Chain::Evm => "EVM",
    };

    let position_str = match app.match_position {
        MatchPosition::StartsWith => "Starts with",
        MatchPosition::EndsWith => "Ends with",
        MatchPosition::StartsAndEndsWith => "Starts & Ends",
    };

    let case_str = if app.case_sensitive { "Yes" } else { "No" };

    let both = matches!(app.match_position, MatchPosition::StartsAndEndsWith);

    let mut lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled(" Chain:    ", style_for(0)),
            Span::styled(format!("[{}]", chain_str), style_for(0)),
        ]),
        Line::from(vec![
            Span::styled(" Match:    ", style_for(1)),
            Span::styled(format!("[{}]", position_str), style_for(1)),
        ]),
    ];

    if both {
        lines.push(Line::from(vec![
            Span::styled(" Prefix:   ", style_for(2)),
            Span::styled(
                if app.vanity_prefix.is_empty() { "_".to_string() } else { app.vanity_prefix.clone() },
                style_for(2),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled(" Suffix:   ", style_for(3)),
            Span::styled(
                if app.vanity_suffix.is_empty() { "_".to_string() } else { app.vanity_suffix.clone() },
                style_for(3),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled(" Case:     ", style_for(4)),
            Span::styled(format!("[{}]", case_str), style_for(4)),
        ]));
        lines.push(Line::from(vec![
            Span::styled(" Threads:  ", style_for(5)),
            Span::styled(
                if app.thread_count.is_empty() { "_".to_string() } else { app.thread_count.clone() },
                style_for(5),
            ),
        ]));
    } else {
        let vanity_label = match app.match_position {
            MatchPosition::StartsWith => " Prefix:   ",
            MatchPosition::EndsWith => " Suffix:   ",
            _ => " Vanity:   ",
        };
        let vanity_val = match app.match_position {
            MatchPosition::EndsWith => &app.vanity_suffix,
            _ => &app.vanity_prefix,
        };
        lines.push(Line::from(vec![
            Span::styled(vanity_label, style_for(2)),
            Span::styled(
                if vanity_val.is_empty() { "_".to_string() } else { vanity_val.clone() },
                style_for(2),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled(" Case:     ", style_for(3)),
            Span::styled(format!("[{}]", case_str), style_for(3)),
        ]));
        lines.push(Line::from(vec![
            Span::styled(" Threads:  ", style_for(4)),
            Span::styled(
                if app.thread_count.is_empty() { "_".to_string() } else { app.thread_count.clone() },
                style_for(4),
            ),
        ]));
    }

    // Error message
    if let Some(ref err) = app.error_message {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!(" {}", err),
            Style::default().fg(Color::Red),
        )));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(" Config ");
    let paragraph = Paragraph::new(lines).block(block);
    f.render_widget(paragraph, area);
}

fn render_stats(f: &mut Frame, area: Rect, app: &App) {
    let (checked, rate, matches, elapsed) = if let Some(start) = app.start_time {
        let count = app.counter.load(Ordering::Relaxed);
        let secs = start.elapsed().as_secs();
        let rate = if secs > 0 { count / secs } else { 0 };
        (count, rate, app.matches.len() as u64, secs)
    } else {
        (0, 0, 0, 0)
    };

    let lines = vec![
        Line::from(Span::styled(
            format!(" Checked:  {}", checked),
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            format!(" Rate:     {}/s", rate),
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            format!(" Matches:  {}", matches),
            Style::default().fg(if matches > 0 { Color::Green } else { Color::White }),
        )),
        Line::from(Span::styled(
            format!(" Elapsed:  {}s", elapsed),
            Style::default().fg(Color::White),
        )),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(" Stats ");
    let paragraph = Paragraph::new(lines).block(block);
    f.render_widget(paragraph, area);
}

fn render_key_hints(f: &mut Frame, area: Rect, app: &App) {
    let hints = match app.state {
        AppState::Configuring => " Tab:Next  Enter:Start  q:Quit",
        AppState::Searching => " Ctrl+C:Stop  q:Quit",
    };
    let paragraph = Paragraph::new(Line::from(Span::styled(
        hints,
        Style::default().fg(Color::DarkGray),
    )));
    f.render_widget(paragraph, area);
}

fn render_right_panel(f: &mut Frame, area: Rect, app: &App) {
    if app.state == AppState::Configuring && app.matches.is_empty() {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(" Results ");
        let placeholder = Paragraph::new(Line::from(Span::styled(
            "  Configure and press Enter to start searching",
            Style::default().fg(Color::DarkGray),
        )))
        .block(block);
        f.render_widget(placeholder, area);
        return;
    }

    // Split: match table (top 60%), detail view (bottom 40%)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    render_match_table(f, chunks[0], app);
    render_detail_view(f, chunks[1], app);
}

fn render_match_table(f: &mut Frame, area: Rect, app: &App) {
    let header_cells = ["#", "Chain", "Address"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1);

    let rows: Vec<Row> = app
        .matches
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let addr_display = if m.1.len() > 30 {
                format!("{}...{}", &m.1[..14], &m.1[m.1.len() - 10..])
            } else {
                m.1.clone()
            };
            let cells = vec![
                Cell::from(format!("{}", i + 1)),
                Cell::from(m.0.clone()),
                Cell::from(addr_display),
            ];
            Row::new(cells)
        })
        .collect();

    let widths = [Constraint::Length(4), Constraint::Length(8), Constraint::Min(20)];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(" Matches "),
        )
        .row_highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD));

    let mut table_state = TableState::default();
    if !app.matches.is_empty() {
        table_state.select(Some(app.selected_match));
    }
    f.render_stateful_widget(table, area, &mut table_state);
}

fn render_detail_view(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(" Detail ");

    if app.matches.is_empty() || app.selected_match >= app.matches.len() {
        let paragraph = Paragraph::new(Line::from(Span::styled(
            "  No matches yet",
            Style::default().fg(Color::DarkGray),
        )))
        .block(block);
        f.render_widget(paragraph, area);
        return;
    }

    let m = &app.matches[app.selected_match];
    let lines = vec![
        Line::from(vec![
            Span::styled(" Chain:   ", Style::default().fg(Color::Cyan)),
            Span::raw(&m.0),
        ]),
        Line::from(vec![
            Span::styled(" Address: ", Style::default().fg(Color::Cyan)),
            Span::raw(&m.1),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Key:     ", Style::default().fg(Color::Cyan)),
            Span::raw(&m.2),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Phrase:  ", Style::default().fg(Color::Cyan)),
            Span::raw(&m.3),
        ]),
    ];

    let paragraph = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    f.render_widget(paragraph, area);
}
```

- [ ] **Step 3: Build to verify**

Run: `cargo build 2>&1`
Expected: Compiles (functions unused yet, dead_code warnings expected).

- [ ] **Step 4: Commit**

```bash
git add src/main.rs
git commit -m "feat(tui): add all rendering functions for layout"
```

---

### Task 5: Add Event Handling

**Files:**
- Modify: `src/main.rs` — add after the rendering functions

- [ ] **Step 1: Add keyboard event handler**

```rust
// ---------------------------------------------------------------------------
// TUI event handling
// ---------------------------------------------------------------------------

fn handle_key_event(app: &mut App, key: event::KeyEvent) {
    // Only handle key press events (not release/repeat)
    if key.kind != KeyEventKind::Press {
        return;
    }

    // Ctrl+C: stop search or quit
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        if app.state == AppState::Searching {
            app.stop_search();
        } else {
            app.should_quit = true;
        }
        return;
    }

    match app.state {
        AppState::Configuring => handle_configuring_key(app, key),
        AppState::Searching => handle_searching_key(app, key),
    }
}

fn handle_configuring_key(app: &mut App, key: event::KeyEvent) {
    match key.code {
        // Quit
        KeyCode::Char('q') if !app.is_text_field() => {
            app.should_quit = true;
        }

        // Navigation
        KeyCode::Tab => {
            app.active_field = (app.active_field + 1) % app.field_count();
            app.error_message = None;
        }
        KeyCode::BackTab => {
            if app.active_field == 0 {
                app.active_field = app.field_count() - 1;
            } else {
                app.active_field -= 1;
            }
            app.error_message = None;
        }

        // Start search
        KeyCode::Enter => {
            match app.validate() {
                Ok(()) => app.start_search(),
                Err(e) => app.error_message = Some(e),
            }
        }

        // Field-specific input
        _ => handle_field_input(app, key),
    }
}

fn handle_field_input(app: &mut App, key: event::KeyEvent) {
    let both = matches!(app.match_position, MatchPosition::StartsAndEndsWith);

    match app.active_field {
        // Chain
        0 => match key.code {
            KeyCode::Char('1') => app.chain = Chain::Solana,
            KeyCode::Char('2') => app.chain = Chain::Evm,
            _ => {}
        },

        // Match position
        1 => match key.code {
            KeyCode::Char('1') => app.match_position = MatchPosition::StartsWith,
            KeyCode::Char('2') => app.match_position = MatchPosition::EndsWith,
            KeyCode::Char('3') => app.match_position = MatchPosition::StartsAndEndsWith,
            _ => {}
        },

        // Vanity prefix (or single vanity string for StartsWith/EndsWith)
        2 => match key.code {
            KeyCode::Char(c) if app.valid_charset().contains(c) => {
                if matches!(app.match_position, MatchPosition::EndsWith) {
                    if app.vanity_suffix.len() < app.max_vanity_len() {
                        app.vanity_suffix.push(c);
                    }
                } else if app.vanity_prefix.len() < app.max_vanity_len() {
                    app.vanity_prefix.push(c);
                }
            }
            KeyCode::Backspace => {
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
                if app.vanity_suffix.len() < app.max_vanity_len() {
                    app.vanity_suffix.push(c);
                }
            }
            KeyCode::Backspace => {
                app.vanity_suffix.pop();
            }
            _ => {}
        },

        // Case sensitivity
        f if f == (if both { 4 } else { 3 }) => match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => app.case_sensitive = true,
            KeyCode::Char('n') | KeyCode::Char('N') => app.case_sensitive = false,
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
```

- [ ] **Step 2: Build to verify**

Run: `cargo build 2>&1`
Expected: Compiles.

- [ ] **Step 3: Commit**

```bash
git add src/main.rs
git commit -m "feat(tui): add keyboard event handling for both states"
```

---

### Task 6: Rewrite main() and Remove Old UI

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Remove old UI functions**

Delete these functions entirely:
- `display_banner()`
- `read_line_trimmed()`
- `read_chain()`
- `read_match_position()`
- `read_vanity_string()`
- `read_case_sensitivity()`
- `read_thread_count()`
- `start_csv_writer()`

Also delete the old `main()` function.

- [ ] **Step 2: Remove old imports that are no longer needed**

The `io::Write` trait is still needed for crossterm. Make sure `stdout` is imported. The `io` module is still needed. No changes should be needed after Step 1 of Task 4 which set up the correct imports.

- [ ] **Step 3: Write the new main() function**

Replace with:

```rust
// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> io::Result<()> {
    // Set up terminal
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();

    // Main event loop — 10fps (100ms tick)
    let tick_rate = Duration::from_millis(100);

    loop {
        terminal.draw(|f| ui(f, &app))?;

        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                handle_key_event(&mut app, key);
            }
        }

        // Drain any new matches from workers
        app.drain_matches();

        if app.should_quit {
            // Stop any running search
            app.stop.store(true, Ordering::Relaxed);
            break;
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;

    // Print summary if we had results
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
        }
        println!("==========================================================\n");
    }

    Ok(())
}
```

- [ ] **Step 4: Build and verify zero warnings**

Run: `cargo build --release 2>&1`
Expected: Clean build, zero warnings. If there are dead_code warnings for `detect_optimal_threads` or `ChainInfo`, keep them — they're still used by `App::new()` and validation respectively.

- [ ] **Step 5: Run the binary to smoke test**

Run: `./target/release/vanaddy`
Expected: TUI launches with logo banner, config form on left, empty results on right. Tab navigates fields. q quits cleanly.

- [ ] **Step 6: Commit**

```bash
git add src/main.rs
git commit -m "feat(tui): rewrite main() with Ratatui event loop, remove old println UI"
```

---

### Task 7: Final Cleanup and Push

**Files:**
- Modify: `src/main.rs` — fix any remaining warnings
- Modify: `Cargo.toml` — remove `rand` dependency if no longer needed directly

- [ ] **Step 1: Check for unused dependencies**

Run: `cargo build --release 2>&1`
Check for any warnings. Fix any dead code warnings by removing truly unused code.

The `ChainInfo` trait and `SolanaInfo`/`EvmInfo` structs may now be unused since validation moved into `App`. If so, remove them and inline the charset/max_len logic into `App::valid_charset()` and `App::max_vanity_len()` which already exist.

- [ ] **Step 2: Check if `rand` is still a direct dependency**

`tiny-bip39` pulls in `rand 0.7` transitively. If our code no longer calls `rand` directly, remove it from `Cargo.toml`. Run `cargo build` to verify.

- [ ] **Step 3: Full smoke test**

Run: `./target/release/vanaddy`
Test:
1. Tab through all fields
2. Set chain to Solana, prefix to "A", case no, threads to auto
3. Press Enter — search starts, stats update at 10fps
4. Wait for a match (single char should be fast)
5. Up/Down to select matches
6. Ctrl+C to stop search
7. Tweak config and start again
8. q to quit

- [ ] **Step 4: Commit and push**

```bash
git add -A
git commit -m "feat: v0.5 — full Ratatui TUI with config form, live stats, and match browser"
git push
```
