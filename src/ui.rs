use super::app::{App, AppState};
use super::chains::ChainKind;
use super::matcher::MatchPosition;
use crate::gpu::{GpuDisableReason, GpuError, GpuStatus};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap},
    Frame,
};
use std::sync::atomic::Ordering;

pub fn ui(f: &mut Frame, app: &App) {
    let size = f.area();

    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(20),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(size);

    render_banner(f, main_chunks[0]);

    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(25), Constraint::Percentage(75)])
        .split(main_chunks[1]);

    render_left_panel(f, body_chunks[0], app);
    render_right_panel(f, body_chunks[1], app);
    render_key_hints(f, main_chunks[2], app);

    if app.show_help {
        render_help_popup(f, size);
    }
}

fn panel(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(title)
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
            "v0.6 — Multi-Chain Vanity Address Generator",
            Style::default().fg(Color::Cyan),
        )),
    ];

    let block = panel(" Vanaddy ");
    let paragraph = Paragraph::new(logo)
        .block(block)
        .alignment(ratatui::layout::Alignment::Center);
    f.render_widget(paragraph, area);
}

fn render_left_panel(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(stats_height(app))])
        .split(area);

    render_config_form(f, chunks[0], app);
    render_stats(f, chunks[1], app);
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

    let chain_str = app.chain.label();

    let position_str = match app.match_position {
        MatchPosition::StartsWith => "Starts with",
        MatchPosition::EndsWith => "Ends with",
        MatchPosition::StartsAndEndsWith => "Starts & Ends",
    };

    let case_str = if app.case_sensitive { "Yes" } else { "No" };

    let blank = |s: &str| {
        if s.is_empty() {
            "_".to_string()
        } else {
            s.to_string()
        }
    };

    // Row index == App field index; the GPU and Threads rows take theirs from
    // `lines.len()`, so the one- and two-pattern layouts share one code path.
    let mut rows = vec![
        (" Chain:    ", format!("[{}]", chain_str)),
        (" Match:    ", format!("[{}]", position_str)),
    ];
    if !matches!(app.match_position, MatchPosition::EndsWith) {
        rows.push((" Prefix:   ", blank(&app.vanity_prefix)));
    }
    if !matches!(app.match_position, MatchPosition::StartsWith) {
        rows.push((" Suffix:   ", blank(&app.vanity_suffix)));
    }
    rows.push((" Case:     ", format!("[{}]", case_str)));

    let mut lines: Vec<Line> = rows
        .into_iter()
        .enumerate()
        .map(|(i, (label, value))| {
            Line::from(vec![
                Span::styled(label, style_for(i)),
                Span::styled(value, style_for(i)),
            ])
        })
        .collect();
    lines.push(gpu_form_line(app, style_for(lines.len())));
    let threads = style_for(lines.len());
    lines.push(Line::from(vec![
        Span::styled(" Threads:  ", threads),
        Span::styled(blank(&app.thread_count), threads),
    ]));

    let hint = match app.chain {
        ChainKind::Solana | ChainKind::Evm => None,
        ChainKind::Bitcoin => Some("Bitcoin: vanity applies after 'bc1q'"),
        ChainKind::Ton => Some("TON: vanity applies after 'UQ' (chars 3+) — wallet-v5r1 (W5), Tonkeeper-compatible"),
        ChainKind::Monero => Some("Monero: vanity applies after leading '4'"),
    };
    if let Some(h) = hint {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!(" {}", h),
            Style::default().fg(Color::DarkGray),
        )));
    }

    if let Some(ref err) = app.error_message {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!(" {}", err),
            Style::default().fg(Color::Red),
        )));
    }

    let block = panel(" Config ");
    let paragraph = Paragraph::new(lines).block(block);
    f.render_widget(paragraph, area);
}

/// Flatten a status string for display in a ratatui Buffer.
/// `GpuError::ShaderCompile(String)` carries multi-line Metal compiler
/// diagnostics; a raw newline or tab written into a cell corrupts the frame.
/// Every control character becomes a space, and the result is truncated on a
/// CHAR boundary (byte slicing would panic on the '—' this UI is full of).
fn sanitize_status_text(s: &str, max: usize) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if cleaned.chars().count() <= max {
        return cleaned;
    }
    let mut out: String = cleaned.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Bare variant name, for the config form's narrow value column. The payload —
/// a compiler diagnostic, a wave index, an address — goes to the Stats pane's
/// fault line instead, which is where the user looks once a fault has fired.
fn gpu_reason_label(r: &GpuDisableReason) -> &'static str {
    match r {
        GpuDisableReason::NotSupported => "NotSupported",
        GpuDisableReason::UserOff => "UserOff",
        GpuDisableReason::Backend(GpuError::NoDevice) => "NoDevice",
        GpuDisableReason::Backend(GpuError::ShaderCompile(_)) => "ShaderCompile",
        GpuDisableReason::Backend(GpuError::PipelineCreate(_)) => "PipelineCreate",
        GpuDisableReason::Backend(GpuError::BufferAlloc) => "BufferAlloc",
        GpuDisableReason::Backend(GpuError::BadConfig(_)) => "BadConfig",
        GpuDisableReason::Backend(GpuError::CommandBuffer { .. }) => "CommandBuffer",
        GpuDisableReason::SelfTest(_) => "SelfTest",
        GpuDisableReason::AuditMismatch { .. } => "AuditMismatch",
        GpuDisableReason::VerifyMismatch { .. } => "VerifyMismatch",
        GpuDisableReason::Panicked => "Panicked",
    }
}

/// The GPU field's value text and its style.
/// Precedence: no device beats disabled beats wrong-chain beats the toggle —
/// the same order as the input arm's refusal, so what the form shows and what
/// pressing `y` does can never disagree.
fn gpu_form_value(app: &App) -> (String, Style) {
    let dimmed = Style::default().fg(Color::DarkGray);
    match &app.gpu_status {
        GpuStatus::Unavailable(r) => (format!("[n/a — {}]", sanitize_status_text(r, 24)), dimmed),
        GpuStatus::Disabled(r) => (
            format!("[disabled — {}]", gpu_reason_label(r)),
            Style::default().fg(Color::Red),
        ),
        _ if app.chain != ChainKind::Evm => ("[n/a — EVM only]".to_string(), dimmed),
        _ if app.gpu_requested => ("[On]".to_string(), Style::default().fg(Color::Green)),
        _ => ("[Off]".to_string(), Style::default().fg(Color::White)),
    }
}

/// The GPU config-form row. The LABEL keeps the normal focus styling so the
/// field stays discoverable and navigable even when the GPU cannot run; the
/// VALUE carries the disabled styling and the reason — visibly disabled, never
/// silently ignored.
fn gpu_form_line(app: &App, label_style: Style) -> Line<'static> {
    let (value, value_style) = gpu_form_value(app);
    Line::from(vec![
        Span::styled(" GPU:      ", label_style),
        Span::styled(value, value_style),
    ])
}

/// The single source of truth for the Stats pane's GPU row: `render_stats`
/// draws it and `stats_height` counts it, so the two can never disagree about
/// whether the row is there. Exactly one row — a fault REPLACES the live rate,
/// it never adds a second `GPU rate:` line. `None` means no row at all.
///
/// The label is `GPU rate:`, NOT `GPU:`. The config form's row (Task 7.3) is
/// labelled ` GPU:      ` and renders in the same left-hand panel, above this
/// one; a test that greps the rendered frame for `GPU:` would find the config
/// row first. Both labels are 11 columns, so the value columns still line up.
///
/// Every row here is kept short on purpose. `render_stats` builds a
/// `Paragraph` with NO `.wrap()`, and the left panel is 25% of the terminal
/// minus two border columns — 23 usable columns at 100 chars wide. A row that
/// spells out the device name and the reason payload is 34 and 80 columns
/// long, so the measured rate and the share — the entire point of this row —
/// get clipped off the pane. The device name already appears on the config
/// form's ` GPU:      ` row above.
fn gpu_stats_line(app: &App) -> Option<(String, Color)> {
    match &app.gpu_status {
        // This run must actually own the GPU. `stop_search` clears `gpu_rx` but
        // deliberately leaves `gpu_status` alone, so a Running status outlives
        // the run that produced it; without this arm a following CPU-only run
        // renders the previous run's seeds_delivered against a fresh counter.
        GpuStatus::Initializing | GpuStatus::Running { .. } if app.gpu_rx.is_none() => None,
        GpuStatus::Disabled(r) => Some((
            format!(" GPU rate: OFF — {} (CPU cont.)", gpu_reason_label(r)),
            Color::Red,
        )),
        GpuStatus::Initializing => Some((" GPU rate: initialising…".to_string(), Color::Yellow)),
        GpuStatus::Running { .. } => {
            // MEASURED per delivery, never modelled — see App::gpu_measured_rate.
            let (rate, share) = app.gpu_measured_rate();
            Some((
                format!(" GPU rate: {}/s ({share}%)", format_count(rate)),
                Color::Green,
            ))
        }
        // Probed but not started, or no device: the config form says so, the
        // Stats pane stays quiet.
        GpuStatus::Ready { .. } | GpuStatus::Unavailable(_) => None,
    }
}

/// Rows the stats block needs: 4 fixed lines, the optional GPU row, the
/// optional Expected/ETA lines, plus borders. The GPU row is counted through
/// `gpu_stats_line` — the same function `render_stats` draws from — so the
/// height can never disagree with what is rendered.
fn stats_height(app: &App) -> u16 {
    let optional = u16::from(app.expected_attempts().is_some())
        + u16::from(app.projected_seconds().is_some())
        + u16::from(gpu_stats_line(app).is_some());
    4 + optional + 2
}

fn render_stats(f: &mut Frame, area: Rect, app: &App) {
    let (checked, rate, matches, elapsed) = if let Some(start) = app.start_time {
        let count = app.counter.load(Ordering::Relaxed);
        let secs = start.elapsed().as_secs();
        let rate = if secs > 0 { count / secs } else { 0 };
        (count, rate, app.total_matches, secs)
    } else {
        (0, 0, 0, 0)
    };

    let expected = app.expected_attempts();
    let eta_seconds = app.projected_seconds();

    let mut lines = vec![
        Line::from(Span::styled(
            format!(" Checked:  {}", format_count(checked)),
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            format!(" Rate:     {}/s", format_count(rate)),
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

    // Directly under Rate: the GPU's contribution to the rate above it.
    if let Some((text, color)) = gpu_stats_line(app) {
        lines.insert(
            2,
            Line::from(Span::styled(text, Style::default().fg(color))),
        );
    }

    if let Some(attempts) = expected {
        lines.push(Line::from(Span::styled(
            format!(" Expected: 1 in {}", format_count(attempts)),
            Style::default().fg(Color::Cyan),
        )));
    }
    if let Some(secs) = eta_seconds {
        lines.push(Line::from(Span::styled(
            format!(" ETA:      {}", format_duration(secs)),
            Style::default().fg(Color::Cyan),
        )));
    }

    let block = panel(" Stats ");
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

/// The popup is a fixed rectangle, so its content list has a hard budget:
/// `HELP_POPUP_HEIGHT - 2` lines of at most `HELP_POPUP_WIDTH - 2` columns.
/// Overrun either and Paragraph clips silently — the entry simply is not there.
const HELP_POPUP_WIDTH: u16 = 56;
const HELP_POPUP_HEIGHT: u16 = 29;

/// Extracted from `render_help_popup` so a test can measure it against the
/// popup it has to fit inside. Adding an entry without raising
/// `HELP_POPUP_HEIGHT` clips the LAST entries, not the new one.
fn help_lines() -> Vec<Line<'static>> {
    vec![
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
        Line::from("  y/n          Case sensitivity, GPU offload"),
        Line::from("  GPU offload  Metal PBKDF2, EVM only (Apple Silicon)"),
        Line::from("  Type         Text input (prefix, suffix, threads)"),
        Line::from("  Backspace    Delete character"),
        Line::from(""),
        Line::from(Span::styled(" Actions", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from("  Enter        Start search"),
        Line::from("  Ctrl+C       Stop search"),
        Line::from("  q            Quit (not in text fields)"),
        Line::from("  h            Toggle this help"),
        Line::from(""),
        Line::from(Span::styled(" Supported Chains", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from("  1=Solana  2=EVM  3=Bitcoin"),
        Line::from("  4=TON     5=Monero"),
        Line::from("  Monero generation is slower (crypto intrinsic)"),
    ]
}

fn render_help_popup(f: &mut Frame, area: Rect) {
    let popup_width = HELP_POPUP_WIDTH.min(area.width.saturating_sub(4));
    let popup_height = HELP_POPUP_HEIGHT.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(x, y, popup_width, popup_height);

    // Clear background
    let clear = Block::default().style(Style::default().bg(Color::Black));
    f.render_widget(clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Help ")
        .style(Style::default().bg(Color::Black));
    let paragraph = Paragraph::new(help_lines()).block(block);
    f.render_widget(paragraph, popup_area);
}

fn render_right_panel(f: &mut Frame, area: Rect, app: &App) {
    if app.state == AppState::Configuring && app.matches.is_empty() {
        let block = panel(" Results ");
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
            let addr_display = if m.address.len() > 30 {
                format!("{}...{}", &m.address[..14], &m.address[m.address.len() - 10..])
            } else {
                m.address.clone()
            };
            let cells = vec![
                // Number from the run's total, not the window index: after the
                // cap evicts, restarting at 1 would silently claim the run found
                // fewer matches than it did.
                Cell::from(format!(
                    "{}",
                    (app.total_matches as usize).saturating_sub(app.matches.len()) + i + 1
                )),
                Cell::from(m.chain.clone()),
                Cell::from(addr_display),
            ];
            Row::new(cells)
        })
        .collect();

    let widths = [Constraint::Length(4), Constraint::Length(10), Constraint::Min(20)];

    let table = Table::new(rows, widths)
        .header(header)
        .block(panel(" Matches "))
        .row_highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD));

    let mut table_state = TableState::default();
    if !app.matches.is_empty() {
        table_state.select(Some(app.selected_match));
    }
    f.render_stateful_widget(table, area, &mut table_state);
}

fn render_detail_view(f: &mut Frame, area: Rect, app: &App) {
    let block = panel(" Detail ");

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
            Span::raw(&m.chain),
        ]),
        Line::from(vec![
            Span::styled(" Address: ", Style::default().fg(Color::Cyan)),
            Span::raw(&m.address),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Key:     ", Style::default().fg(Color::Cyan)),
            Span::raw(&m.secret_hex),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Phrase:  ", Style::default().fg(Color::Cyan)),
            Span::raw(&m.mnemonic),
        ]),
    ];

    let paragraph = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    f.render_widget(paragraph, area);
}

/// Format large counts as "12.3K", "4.5M", "1.2B" for compact display.
fn format_count(n: u64) -> String {
    if n < 1_000 {
        n.to_string()
    } else if n < 1_000_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else if n < 1_000_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n < 1_000_000_000_000 {
        format!("{:.1}B", n as f64 / 1_000_000_000.0)
    } else {
        format!("{:.1}T", n as f64 / 1_000_000_000_000.0)
    }
}

/// Format a duration in seconds into a human-readable approximation.
fn format_duration(secs: f64) -> String {
    if !secs.is_finite() || secs < 0.0 {
        return "—".to_string();
    }
    if secs < 1.0 {
        "< 1s".to_string()
    } else if secs < 60.0 {
        format!("{}s", secs as u64)
    } else if secs < 3600.0 {
        format!("{}m {}s", (secs / 60.0) as u64, (secs % 60.0) as u64)
    } else if secs < 86_400.0 {
        format!("{}h {}m", (secs / 3600.0) as u64, ((secs % 3600.0) / 60.0) as u64)
    } else if secs < 86_400.0 * 365.0 {
        format!("{}d {}h", (secs / 86_400.0) as u64, ((secs % 86_400.0) / 3600.0) as u64)
    } else {
        let years = secs / (86_400.0 * 365.0);
        if years < 100.0 {
            format!("{:.1}y", years)
        } else {
            ">100y".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpu::{GpuDisableReason, GpuError, GpuStatus};

    /// Render the whole TUI into an in-memory buffer.
    fn render_buffer(app: &App, width: u16, height: u16) -> ratatui::buffer::Buffer {
        let backend = ratatui::backend::TestBackend::new(width, height);
        let mut terminal = ratatui::Terminal::new(backend).expect("TestBackend never fails");
        terminal
            .draw(|f| ui(f, app))
            .expect("TestBackend never fails");
        terminal.backend().buffer().clone()
    }

    /// The rendered frame as one newline-separated String, so a test can
    /// assert on what the user sees.
    fn render_to_string(app: &App, width: u16, height: u16) -> String {
        let buf = render_buffer(app, width, height);
        let w = buf.area.width as usize;
        let mut out = String::new();
        for (i, cell) in buf.content.iter().enumerate() {
            if i > 0 && i % w == 0 {
                out.push('\n');
            }
            out.push_str(cell.symbol());
        }
        out
    }

    #[test]
    fn sanitize_status_text_flattens_control_characters() {
        assert_eq!(
            sanitize_status_text("line 1\nline 2\ttab", 64),
            "line 1 line 2 tab"
        );
        assert_eq!(sanitize_status_text("\u{7}bell", 64), " bell");
        assert_eq!(sanitize_status_text("plain", 64), "plain");
    }

    #[test]
    fn sanitize_status_text_truncates_with_an_ellipsis() {
        assert_eq!(sanitize_status_text("abcdefgh", 4), "abc…");
        assert_eq!(sanitize_status_text("abcd", 4), "abcd");
    }

    #[test]
    fn sanitize_status_text_never_splits_a_multi_byte_char() {
        // 'é' is two bytes; byte-wise truncation would panic here.
        assert_eq!(sanitize_status_text("ééééé", 3), "éé…");
    }

    #[test]
    fn gpu_form_value_says_which_state_the_gpu_is_in() {
        let mut app = App::new();
        app.chain = ChainKind::Evm;

        app.gpu_status = GpuStatus::Ready {
            device: "Apple M1".to_string(),
        };
        app.gpu_requested = true;
        assert_eq!(gpu_form_value(&app).0, "[On]");

        app.gpu_requested = false;
        assert_eq!(gpu_form_value(&app).0, "[Off]");

        app.gpu_requested = true;
        app.chain = ChainKind::Solana;
        assert_eq!(gpu_form_value(&app).0, "[n/a — EVM only]");

        app.chain = ChainKind::Evm;
        app.gpu_status = GpuStatus::Unavailable("not supported on this target".to_string());
        assert_eq!(gpu_form_value(&app).0, "[n/a — not supported on this t…]");

        app.gpu_status = GpuStatus::Disabled(GpuDisableReason::VerifyMismatch {
            address: "0xdead".to_string(),
        });
        assert_eq!(gpu_form_value(&app).0, "[disabled — VerifyMismatch]");
    }

    #[test]
    fn gpu_form_value_never_leaks_a_multi_line_compiler_diagnostic() {
        let mut app = App::new();
        app.chain = ChainKind::Evm;
        app.gpu_status = GpuStatus::Disabled(GpuDisableReason::Backend(GpuError::ShaderCompile(
            "program_source:14:3: error: use of undeclared identifier\nnote: here".to_string(),
        )));
        let (text, _) = gpu_form_value(&app);
        assert_eq!(text, "[disabled — ShaderCompile]");

        // The Unavailable arm is the one that renders a raw reason string, so
        // it is the arm where `sanitize_status_text` has to fire. Asserting the
        // newline here is falsifiable: drop the helper from that arm and this
        // test goes red. (Asserting it on the Disabled arm above would not —
        // `gpu_reason_label` returns a &'static str that structurally cannot
        // carry one.)
        app.gpu_status = GpuStatus::Unavailable("no Metal device\nfound".to_string());
        let (text, _) = gpu_form_value(&app);
        assert!(
            !text.contains('\n'),
            "a newline in a ratatui Buffer corrupts the frame: {text:?}"
        );
        assert_eq!(text, "[n/a — no Metal device found]");
    }

    /// The row whose cells carry the highlight style (yellow + bold).
    ///
    /// `render_to_string` reads only `cell.symbol()`, so it is blind to WHICH
    /// row is highlighted. The off-by-one this milestone repaired — Threads
    /// drawn with the GPU field's index, so the wrong label lights up while
    /// keystrokes go elsewhere — survives every symbol-only test in this file.
    /// Reading the style back is the only thing that pins it.
    fn highlighted_row(app: &App, width: u16, height: u16) -> String {
        let buf = render_buffer(app, width, height);
        let w = buf.area.width as usize;
        let mut found: Option<String> = None;
        for row in 0..buf.area.height as usize {
            let cells = &buf.content[row * w..(row + 1) * w];
            // Yellow AND bold together occur only in `render_config_form`'s
            // `highlight`. Task 7.5 added a second Yellow (the Stats pane's
            // "initialising…" row), which is why this tests the conjunction
            // and not the colour alone. A future Yellow+bold span would trip
            // the "two rows highlighted" panic below — loudly, by design.
            if !cells
                .iter()
                .any(|c| c.fg == Color::Yellow && c.modifier.contains(Modifier::BOLD))
            {
                continue;
            }
            let text: String = cells.iter().map(|c| c.symbol()).collect();
            if let Some(prev) = &found {
                panic!("two rows highlighted at once:\n{prev}\n{text}");
            }
            found = Some(text);
        }
        found.expect("no row carries the highlight style")
    }

    /// Pins the config form's `style_for` arguments to `App`'s field indices,
    /// for both layouts, by reading the rendered highlight back. Without it,
    /// swapping any `style_for` argument in `render_config_form` passes the
    /// entire suite — verified by mutation, not assumed.
    #[test]
    fn the_highlighted_row_tracks_the_active_field() {
        let mut app = App::new();
        app.chain = ChainKind::Evm;

        for pos in [
            MatchPosition::StartsWith,
            MatchPosition::EndsWith,
            MatchPosition::StartsAndEndsWith,
        ] {
            app.match_position = pos;
            let n = app.field_count();

            app.active_field = n - 2;
            let row = highlighted_row(&app, 100, 40);
            assert!(
                row.contains("GPU:"),
                "field_count()-2 must light the GPU row (field_count()={n}), got {row:?}"
            );

            app.active_field = n - 1;
            let row = highlighted_row(&app, 100, 40);
            assert!(
                row.contains("Threads:"),
                "field_count()-1 must light the Threads row (field_count()={n}), got {row:?}"
            );
        }
    }

    /// Small-terminal rendering, which nothing else covers. `render_help_popup`
    /// and the Stats block both size themselves against the terminal area, and
    /// ratatui clips rather than erroring — so a layout that underflows on a
    /// short terminal is silent until a user hits it. 80x24 is the classic
    /// floor. Task 7.8 hands the colour and timing judgements to a human; this
    /// is the part of that walkthrough a machine can hold.
    #[test]
    fn every_pane_survives_an_80_by_24_terminal() {
        let mut app = App::new();
        app.chain = ChainKind::Evm;
        app.gpu_status = GpuStatus::Ready {
            device: "Apple M1".to_string(),
        };
        app.gpu_requested = true;

        // The last two are absurd as terminals and deliberate as inputs: they
        // are what makes the saturating arithmetic in the pane sizing
        // load-bearing. Swap any `saturating_sub` in `render_help_popup` for a
        // plain `-` and this test panics on them.
        for (w, h) in [
            (80u16, 24u16),
            (100, 30),
            (120, 40),
            (60, 20),
            (30, 6),
            (20, 3),
        ] {
            for help in [false, true] {
                app.show_help = help;
                for state in [AppState::Configuring, AppState::Searching] {
                    app.state = state;
                    // The assertion is that this returns at all: a wrapping
                    // subtraction in any pane's size arithmetic panics here.
                    let frame = render_to_string(&app, w, h);
                    assert_eq!(
                        frame.lines().count(),
                        h as usize,
                        "a {w}x{h} frame must have {h} rows"
                    );
                }
            }
        }
    }

    /// The acceptance criterion deferred from Task 6.11, which could not be
    /// checked at Milestone 6 because `src/ui.rs` had no GPU surface at all.
    /// Two GPU rows in one frame would mean two engines were being reported.
    /// Note `"GPU rate:"` does not contain `"GPU:"`, so the two labels count
    /// separately and neither can mask the other. Also pins the config row
    /// order Case, GPU, Threads for every match position.
    #[test]
    fn one_gpu_row_per_frame_never_two() {
        let mut app = App::new();
        app.chain = ChainKind::Evm;
        app.gpu_status = GpuStatus::Ready {
            device: "Apple M1".to_string(),
        };
        app.gpu_requested = true;

        for state in [AppState::Configuring, AppState::Searching] {
            app.state = state;
            for pos in [
                MatchPosition::StartsWith,
                MatchPosition::EndsWith,
                MatchPosition::StartsAndEndsWith,
            ] {
                app.match_position = pos;
                let frame = render_to_string(&app, 120, 40);
                let config_rows = frame.lines().filter(|r| r.contains("GPU:")).count();
                let stats_rows = frame.lines().filter(|r| r.contains("GPU rate:")).count();
                assert_eq!(
                    config_rows, 1,
                    "exactly one config GPU row per frame, got {config_rows}\n{frame}"
                );
                assert!(
                    stats_rows <= 1,
                    "never two GPU rate rows in one frame, got {stats_rows}\n{frame}"
                );

                let rows: Vec<&str> = frame.lines().collect();
                let case = rows
                    .iter()
                    .position(|r| r.contains("Case:"))
                    .expect("Case row");
                // `GPU:` is the CONFIG row's label. The Stats pane's row is
                // labelled `GPU rate:` (Task 7.5) precisely so this substring
                // stays unambiguous — do not rename either one to match.
                let gpu = rows
                    .iter()
                    .position(|r| r.contains("GPU:"))
                    .expect("GPU row");
                let threads = rows
                    .iter()
                    .position(|r| r.contains("Threads:"))
                    .expect("Threads row");
                assert!(
                    case < gpu && gpu < threads,
                    "row order must be Case, GPU, Threads; got {case}, {gpu}, {threads}\n{frame}"
                );
            }
        }
    }

    #[test]
    fn format_count_cases() {
        for (n, want) in [
            (0, "0"),
            (999, "999"),
            (1_500, "1.5K"),
            (999_999, "1000.0K"),
            (12_300_000, "12.3M"),
        ] {
            assert_eq!(format_count(n), want, "format_count({n})");
        }
    }

    #[test]
    fn format_duration_cases() {
        for (secs, want) in [
            (0.5, "< 1s"),
            (45.0, "45s"),
            (125.0, "2m 5s"),
            (3665.0, "1h 1m"),
            (90_000.0, "1d 1h"),
        ] {
            assert_eq!(format_duration(secs), want, "format_duration({secs})");
        }
    }

    /// A `gpu_rx` for the Stats-pane tests. `gpu_stats_line` only asks whether
    /// this run still owns the channel, so a disconnected receiver is enough;
    /// what matters is that it is `Some`, exactly as `start_search` leaves it.
    fn test_gpu_rx() -> crate::gpu::GpuRx {
        let (_tx, rx) = crossbeam_channel::bounded::<Box<crate::gpu::SeedBlock>>(1);
        rx
    }

    fn searching_app_with_gpu(status: GpuStatus) -> App {
        let mut app = App::new();
        app.chain = ChainKind::Evm;
        app.gpu_requested = true;
        app.gpu_status = status;
        // This run owns the GPU channel. `gpu_stats_line` refuses to draw a
        // live row without it, so every Running/Initializing case needs one.
        app.gpu_rx = Some(test_gpu_rx());
        app.state = AppState::Searching;
        app.start_time = Some(
            std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(10))
                .expect("the monotonic clock is at least 10 s past boot"),
        );
        app.counter
            .store(200_000, std::sync::atomic::Ordering::Relaxed);
        app.gpu_health
            .seeds_delivered
            .store(136_000, std::sync::atomic::Ordering::Relaxed);
        app
    }

    #[test]
    fn gpu_stats_line_is_absent_when_there_is_nothing_to_report() {
        let mut app = App::new();
        app.gpu_status = GpuStatus::Ready {
            device: "Apple M1".to_string(),
        };
        assert!(
            gpu_stats_line(&app).is_none(),
            "a probed-but-idle GPU gets no stats row"
        );

        app.gpu_status = GpuStatus::Unavailable("not supported on this target".to_string());
        assert!(
            gpu_stats_line(&app).is_none(),
            "an absent GPU gets no stats row"
        );
    }

    #[test]
    fn gpu_stats_line_is_absent_once_this_run_released_the_gpu() {
        let mut app = searching_app_with_gpu(GpuStatus::Running {
            device: "Apple M1".to_string(),
        });
        app.gpu_rx = None; // what stop_search leaves behind
        assert!(
            gpu_stats_line(&app).is_none(),
            "a stale Running status must not draw a live row"
        );
    }

    #[test]
    fn gpu_stats_line_reports_the_measured_rate_and_share() {
        let app = searching_app_with_gpu(GpuStatus::Running {
            device: "Apple M1".to_string(),
        });
        let (text, color) = gpu_stats_line(&app).expect("a running GPU gets a stats row");
        assert!(
            text.contains("13.6K/s"),
            "must show the measured rate: {text}"
        );
        assert!(
            text.contains("(68%)"),
            "must show the GPU's share of candidates: {text}"
        );
        assert_eq!(color, Color::Green);
    }

    /// NOT "without control characters": via `{r:?}` the text can never carry
    /// one, so that assertion could not fail. `sanitize_status_text_flattens_
    /// control_characters` covers the helper directly. What is load-bearing
    /// here is that the row shows the BARE variant label and stays short
    /// enough to survive a pane that does not wrap.
    #[test]
    fn gpu_stats_line_reports_a_fault_without_the_raw_diagnostic() {
        let app = searching_app_with_gpu(GpuStatus::Disabled(GpuDisableReason::Backend(
            GpuError::ShaderCompile(
                "program_source:14:3: error: use of undeclared identifier\nnote: here".to_string(),
            ),
        )));
        let (text, color) = gpu_stats_line(&app).expect("a fault always gets a stats row");
        assert!(text.contains("OFF"), "must say the GPU is off: {text}");
        assert!(
            text.contains("ShaderCompile"),
            "must carry the reason: {text}"
        );
        assert!(
            text.contains("CPU cont."),
            "the user must know the search did not die: {text}"
        );
        assert!(
            !text.contains("program_source"),
            "the raw compiler diagnostic must never reach the pane: {text}"
        );
        assert!(
            text.chars().count() <= 48,
            "the fault row must stay bounded, got {}: {text}",
            text.chars().count()
        );
        assert_eq!(color, Color::Red);
    }

    #[test]
    fn gpu_stats_line_announces_initialisation() {
        let app = searching_app_with_gpu(GpuStatus::Initializing);
        let (text, _) = gpu_stats_line(&app).expect("initialising gets a stats row");
        assert!(
            text.contains("initialising"),
            "the ~300 ms self-test must be visible: {text}"
        );
    }

    #[test]
    fn stats_height_counts_the_gpu_row_exactly_once() {
        let mut app = App::new();
        app.chain = ChainKind::Evm;
        app.gpu_rx = Some(test_gpu_rx()); // the live-row arms require it
        app.gpu_status = GpuStatus::Ready {
            device: "Apple M1".to_string(),
        };
        let base = stats_height(&app);

        app.gpu_status = GpuStatus::Running {
            device: "Apple M1".to_string(),
        };
        assert_eq!(
            stats_height(&app),
            base + 1,
            "the live row needs exactly one line"
        );

        app.gpu_status = GpuStatus::Disabled(GpuDisableReason::AuditMismatch { index: 5183 });
        assert_eq!(
            stats_height(&app),
            base + 1,
            "a fault row REPLACES the live row; it never adds a second GPU line"
        );
    }

    #[test]
    fn stats_pane_renders_the_gpu_row_while_searching() {
        let app = searching_app_with_gpu(GpuStatus::Running {
            device: "Apple M1".to_string(),
        });
        // 120, not 100. The left panel is 25% of the width minus two border
        // columns and `render_stats` sets no `.wrap()`, so 100 leaves only 23
        // usable columns and clips the 24-column row by one character — which
        // would take the `)` off `(68%)`. At 120 the panel is 28 wide and the
        // payload survives, which is what the second assertion below pins.
        let frame = render_to_string(&app, 120, 40);
        let rows: Vec<&str> = frame.lines().collect();
        let rate = rows
            .iter()
            .position(|r| r.contains("Rate:"))
            .expect("Rate row");
        // `GPU rate:` — the Stats row's label. The config form's ` GPU:      `
        // row renders in the same panel ABOVE this one, so grepping for `GPU:`
        // here would find the wrong row.
        let gpu = rows
            .iter()
            .position(|r| r.contains("GPU rate:"))
            .expect("GPU row in the Stats pane");
        assert_eq!(
            gpu,
            rate + 1,
            "the GPU row belongs directly under Rate:\n{frame}"
        );
        assert!(
            rows[gpu].contains("13.6K/s") && rows[gpu].contains("(68%)"),
            "the measured rate must survive the pane width:\n{frame}"
        );
    }

    #[test]
    fn help_popup_documents_gpu_offload_and_nothing_is_clipped() {
        let lines = help_lines();

        assert!(
            lines.len() + 2 <= HELP_POPUP_HEIGHT as usize,
            "the help popup is {HELP_POPUP_HEIGHT} rows tall (2 of them border) but the list has \
             {} lines — the last entries would be silently clipped",
            lines.len()
        );
        for (i, line) in lines.iter().enumerate() {
            assert!(
                line.width() + 2 <= HELP_POPUP_WIDTH as usize,
                "help line {i} is {} columns wide, the popup's inner width is {}: {line}",
                line.width(),
                HELP_POPUP_WIDTH - 2
            );
        }

        let text: String = lines.iter().map(|l| format!("{l}\n")).collect();
        assert!(
            text.contains("Case sensitivity, GPU offload"),
            "the y/n hint must mention the GPU field:\n{text}"
        );
        assert!(
            text.contains("Metal PBKDF2, EVM only (Apple Silicon)"),
            "help must explain what GPU offload actually is:\n{text}"
        );
    }

    #[test]
    fn help_popup_renders_the_gpu_entry() {
        let mut app = App::new();
        app.show_help = true;
        let frame = render_to_string(&app, 100, 40);
        assert!(
            frame.contains("Metal PBKDF2, EVM only (Apple Silicon)"),
            "the GPU entry must survive the render, not fall off the popup:\n{frame}"
        );
        assert!(
            frame.contains("Monero generation is slower"),
            "the last pre-existing entry must still be visible:\n{frame}"
        );
    }
}
