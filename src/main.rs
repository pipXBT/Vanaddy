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
use sha3::{Digest, Keccak256};
use std::{
    fs::OpenOptions,
    io::{self, stdout},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};

mod seed;
mod bip32;
mod matcher;
use seed::derive_seed;
use matcher::{Matcher, MatchPosition};

// ---------------------------------------------------------------------------
// Chain abstraction
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Chain {
    Solana,
    Evm,
}

// ---------------------------------------------------------------------------
// Search functions
// ---------------------------------------------------------------------------

/// Channel payload: (chain_label, address, secret_hex, mnemonic)
type MatchPayload = (String, String, String, String);

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

    // Help overlay
    show_help: bool,

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
            show_help: false,
            matches: Vec::new(),
            selected_match: 0,
            counter: Arc::new(AtomicU64::new(0)),
            match_count: Arc::new(AtomicU64::new(0)),
            start_time: None,
            stop: Arc::new(AtomicBool::new(false)),
            rx: None,
        }
    }

    fn field_count(&self) -> usize {
        if matches!(self.match_position, MatchPosition::StartsAndEndsWith) {
            6
        } else {
            5
        }
    }

    fn is_text_field(&self) -> bool {
        match self.active_field {
            2 => true,
            3 if matches!(self.match_position, MatchPosition::StartsAndEndsWith) => true,
            f if f == self.field_count() - 1 => true,
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

    fn validate(&self) -> Result<(), String> {
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

        Ok(())
    }

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
            MatchPosition::EndsWith => (String::new(), self.vanity_prefix.clone()),
            MatchPosition::StartsAndEndsWith => (self.vanity_prefix.clone(), self.vanity_suffix.clone()),
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

    fn stop_search(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.rx = None;
        self.state = AppState::Configuring;
    }

    fn drain_matches(&mut self) {
        if let Some(ref rx) = self.rx {
            while let Ok(payload) = rx.try_recv() {
                self.match_count.fetch_add(1, Ordering::Relaxed);

                if let Ok(file) = OpenOptions::new().create(true).append(true).open("vanity_wallets.csv") {
                    let mut wtr = WriterBuilder::new().has_headers(false).from_writer(file);
                    let _ = wtr.write_record(&[&payload.0, &payload.1, &payload.2, &payload.3]);
                    let _ = wtr.flush();
                }

                self.matches.push(payload);
                self.selected_match = self.matches.len().saturating_sub(1);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TUI rendering
// ---------------------------------------------------------------------------

fn ui(f: &mut Frame, app: &App) {
    let size = f.area();

    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(20), Constraint::Percentage(80)])
        .split(size);

    render_banner(f, main_chunks[0]);

    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(25), Constraint::Percentage(75)])
        .split(main_chunks[1]);

    render_left_panel(f, body_chunks[0], app);
    render_right_panel(f, body_chunks[1], app);

    if app.show_help {
        render_help_popup(f, size);
    }
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
            "v0.5 — Solana & EVM Vanity Address Generator",
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
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(10),
            Constraint::Length(7),
            Constraint::Length(3),
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
        AppState::Configuring => " h:Help  Enter:Start  q:Quit",
        AppState::Searching => " h:Help  Ctrl+C:Stop  q:Quit",
    };
    let paragraph = Paragraph::new(Line::from(Span::styled(
        hints,
        Style::default().fg(Color::DarkGray),
    )));
    f.render_widget(paragraph, area);
}

fn render_help_popup(f: &mut Frame, area: Rect) {
    // Center a popup ~60x18
    let popup_width = 56.min(area.width.saturating_sub(4));
    let popup_height = 20.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(x, y, popup_width, popup_height);

    // Clear background
    let clear = Block::default().style(Style::default().bg(Color::Black));
    f.render_widget(clear, popup_area);

    let lines = vec![
        Line::from(Span::styled(" Navigation", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from("  Up/Down      Move between fields"),
        Line::from("  Tab          Next field"),
        Line::from("  Shift-Tab    Previous field"),
        Line::from(""),
        Line::from(Span::styled(" Field Input", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from("  Left/Right   Toggle options (chain, match, case)"),
        Line::from("  1/2/3        Select option directly"),
        Line::from("  y/n          Case sensitivity"),
        Line::from("  Type         Text input (prefix, suffix, threads)"),
        Line::from("  Backspace    Delete character"),
        Line::from(""),
        Line::from(Span::styled(" Actions", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from("  Enter        Start search"),
        Line::from("  Ctrl+C       Stop search"),
        Line::from("  q            Quit (not in text fields)"),
        Line::from("  h            Toggle this help"),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Help ")
        .style(Style::default().bg(Color::Black));
    let paragraph = Paragraph::new(lines).block(block);
    f.render_widget(paragraph, popup_area);
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

// ---------------------------------------------------------------------------
// TUI event handling
// ---------------------------------------------------------------------------

fn handle_key_event(app: &mut App, key: event::KeyEvent) {
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
        // Chain (toggle with Left/Right or 1/2)
        0 => match key.code {
            KeyCode::Char('1') => app.chain = Chain::Solana,
            KeyCode::Char('2') => app.chain = Chain::Evm,
            KeyCode::Left | KeyCode::Right => {
                app.chain = match app.chain {
                    Chain::Solana => Chain::Evm,
                    Chain::Evm => Chain::Solana,
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

/// Generate a Solana keypair returning raw pubkey bytes — only base58-encode on match.
pub fn generate_solana_raw() -> ([u8; 32], SigningKey, String) {
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let seed_bytes = derive_seed(&mnemonic);
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&seed_bytes[..32]);
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let pubkey_bytes = signing_key.verifying_key().to_bytes();
    (pubkey_bytes, signing_key, mnemonic.phrase().to_string())
}

fn search_solana_raw(
    matcher: &Matcher,
    stop: &AtomicBool,
    counter: &AtomicU64,
    tx: &mpsc::Sender<MatchPayload>,
) {
    let has_raw_prefix = matcher.raw_prefix.is_some();

    while !stop.load(Ordering::Relaxed) {
        let (pubkey_bytes, signing_key, phrase) = generate_solana_raw();
        counter.fetch_add(1, Ordering::Relaxed);

        // Fast path: reject on raw prefix bytes before base58-encoding
        if has_raw_prefix && !matcher.matches_raw(&pubkey_bytes) {
            continue;
        }

        // Only base58-encode when prefix matched (or no prefix to check)
        let addr = bs58::encode(&pubkey_bytes).into_string();
        if matcher.matches_str(&addr) {
            // Solana keypair format: 64 bytes = secret_key (32) || public_key (32)
            let mut keypair_bytes = [0u8; 64];
            keypair_bytes[..32].copy_from_slice(signing_key.as_bytes());
            keypair_bytes[32..].copy_from_slice(&pubkey_bytes);
            let secret_hex = hex::encode(keypair_bytes);
            let _ = tx.send(("Solana".to_string(), addr, secret_hex, phrase));
        }
    }
}

/// Generate an EVM address as raw 20 bytes — only format to hex on match.
pub fn generate_evm_raw() -> ([u8; 20], libsecp256k1::SecretKey, String) {
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let seed_bytes = derive_seed(&mnemonic);
    let secret_key = bip32::bip32_derive_secp256k1(&seed_bytes, &bip32::EVM_PATH);
    let public_key = libsecp256k1::PublicKey::from_secret_key(&secret_key);
    let pubkey_bytes = public_key.serialize();
    let pubkey_uncompressed = &pubkey_bytes[1..];
    let hash = Keccak256::digest(pubkey_uncompressed);

    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);

    (addr, secret_key, mnemonic.phrase().to_string())
}

fn search_evm_raw(
    matcher: &Matcher,
    stop: &AtomicBool,
    counter: &AtomicU64,
    tx: &mpsc::Sender<MatchPayload>,
) {
    while !stop.load(Ordering::Relaxed) {
        let (addr_bytes, secret_key, phrase) = generate_evm_raw();
        counter.fetch_add(1, Ordering::Relaxed);

        if matcher.matches_evm_raw(&addr_bytes) {
            // Only format to hex string on match
            let addr = format!("0x{}", hex::encode(addr_bytes));
            let secret_hex = hex::encode(secret_key.serialize());
            let _ = tx.send(("EVM".to_string(), addr, secret_hex, phrase));
        }
    }
}

fn detect_optimal_threads() -> usize {
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

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> io::Result<()> {
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();

    let tick_rate = Duration::from_millis(100);

    loop {
        terminal.draw(|f| ui(f, &app))?;

        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                handle_key_event(&mut app, key);
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
        }
        println!("==========================================================\n");
    }

    Ok(())
}
