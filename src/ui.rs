use super::app::{App, AppState};
use super::chains::ChainKind;
use super::matcher::MatchPosition;
use crate::gpu::{GpuDisableReason, GpuStatus};
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
        lines.push(gpu_form_line(app, style_for(5)));
        lines.push(Line::from(vec![
            Span::styled(" Threads:  ", style_for(6)),
            Span::styled(
                if app.thread_count.is_empty() { "_".to_string() } else { app.thread_count.clone() },
                style_for(6),
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
        lines.push(gpu_form_line(app, style_for(4)));
        lines.push(Line::from(vec![
            Span::styled(" Threads:  ", style_for(5)),
            Span::styled(
                if app.thread_count.is_empty() { "_".to_string() } else { app.thread_count.clone() },
                style_for(5),
            ),
        ]));
    }

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

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(" Config ");
    let paragraph = Paragraph::new(lines).block(block);
    f.render_widget(paragraph, area);
}

/// Flatten a status string for display in a ratatui Buffer.
/// `GpuDisableReason::ShaderCompile(String)` carries multi-line Metal compiler
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
        GpuDisableReason::NoDevice => "NoDevice",
        GpuDisableReason::UserOff => "UserOff",
        GpuDisableReason::ShaderCompile(_) => "ShaderCompile",
        GpuDisableReason::PipelineCreate(_) => "PipelineCreate",
        GpuDisableReason::BufferAlloc => "BufferAlloc",
        GpuDisableReason::BadConfig(_) => "BadConfig",
        GpuDisableReason::SelfTest(_) => "SelfTest",
        GpuDisableReason::CommandBuffer { .. } => "CommandBuffer",
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

/// Rows the stats block needs: 4 fixed lines, the optional Expected/ETA lines, plus borders.
fn stats_height(app: &App) -> u16 {
    let optional =
        u16::from(app.expected_attempts().is_some()) + u16::from(app.projected_seconds().is_some());
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
    let popup_height = 26.min(area.height.saturating_sub(4));
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
        Line::from(""),
        Line::from(Span::styled(" Supported Chains", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from("  1=Solana  2=EVM  3=Bitcoin"),
        Line::from("  4=TON     5=Monero"),
        Line::from("  Monero generation is slower (crypto intrinsic)"),
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
    use crate::gpu::{GpuDisableReason, GpuStatus};

    /// Render the whole TUI into an in-memory buffer and return it as one
    /// newline-separated String, so a test can assert on what the user sees.
    fn render_to_string(app: &App, width: u16, height: u16) -> String {
        let backend = ratatui::backend::TestBackend::new(width, height);
        let mut terminal = ratatui::Terminal::new(backend).expect("TestBackend never fails");
        terminal
            .draw(|f| ui(f, app))
            .expect("TestBackend never fails");
        let buf = terminal.backend().buffer();
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
        app.gpu_status = GpuStatus::Disabled(GpuDisableReason::ShaderCompile(
            "program_source:14:3: error: use of undeclared identifier\nnote: here".to_string(),
        ));
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

    #[test]
    fn config_form_puts_the_gpu_row_between_case_and_threads() {
        let mut app = App::new();
        app.chain = ChainKind::Evm;
        app.gpu_status = GpuStatus::Ready {
            device: "Apple M1".to_string(),
        };
        app.gpu_requested = true;

        for pos in [
            MatchPosition::StartsWith,
            MatchPosition::EndsWith,
            MatchPosition::StartsAndEndsWith,
        ] {
            app.match_position = pos;
            let frame = render_to_string(&app, 100, 40);
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

    #[test]
    fn format_count_small() {
        assert_eq!(format_count(0), "0");
        assert_eq!(format_count(999), "999");
    }

    #[test]
    fn format_count_thousands() {
        assert_eq!(format_count(1_500), "1.5K");
        assert_eq!(format_count(999_999), "1000.0K");
    }

    #[test]
    fn format_count_millions() {
        assert_eq!(format_count(12_300_000), "12.3M");
    }

    #[test]
    fn format_duration_seconds() {
        assert_eq!(format_duration(0.5), "< 1s");
        assert_eq!(format_duration(45.0), "45s");
    }

    #[test]
    fn format_duration_minutes() {
        assert_eq!(format_duration(125.0), "2m 5s");
    }

    #[test]
    fn format_duration_hours() {
        assert_eq!(format_duration(3665.0), "1h 1m");
    }

    #[test]
    fn format_duration_days() {
        assert_eq!(format_duration(90_000.0), "1d 1h");
    }
}
