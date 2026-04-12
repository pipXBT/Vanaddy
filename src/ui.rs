use crate::app::{App, AppState};
use crate::matcher::MatchPosition;
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
