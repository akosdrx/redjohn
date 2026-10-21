use crate::render::*;
use crate::state::*;
use crate::theme::*;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph};
use ratatui::Frame;
use std::collections::HashSet;
use unicode_width::UnicodeWidthStr;

const SETUP_PLACEHOLDER: &str = "Describe what to test, or name a target";
const SETUP_PLACEHOLDER_SHORT: &str = "What should RedJohn test?";
const CHAT_PLACEHOLDER: &str = "Send a message";

pub fn draw(frame: &mut Frame, state: &mut AppState) {
    let area = frame.area();
    state.width = area.width;
    state.height = area.height;

    // Paint the entire screen obsidian black so terminal profile colors never bleed through.
    let bg_block = Block::default().style(Style::default().bg(BLACK).fg(TEXT));
    frame.render_widget(bg_block, area);

    if state.show_splash {
        draw_splash(frame, state, area);
        return;
    }

    if !state.ready {
        let msg = Paragraph::new(Line::from(Span::styled(
            "Connecting to RedJohn…",
            style_dim(),
        )))
        .alignment(Alignment::Center)
        .style(Style::default().bg(BLACK).fg(DIM));
        let y = area.height / 2;
        frame.render_widget(msg, Rect::new(0, y, area.width, 1.min(area.height)));
        return;
    }

    if state.snapshot.setup_mode {
        draw_setup(frame, state, area);
    } else {
        draw_main(frame, state, area);
    }

    if state.modal != ModalMode::None {
        draw_modal(frame, state, area);
    }

    if !state.toast.is_empty() {
        draw_toast(frame, state, area);
    }
}

fn wordmark_lines(version_label: &str) -> Vec<Line<'static>> {
    let rule = "━".repeat(55);
    let mut rows = Vec::with_capacity(SMILEY_ROWS.len());

    for (i, &s_row) in SMILEY_ROWS.iter().enumerate() {
        let smiley_color = if i >= 9 { CRIMSON } else { RED };
        let mut spans = vec![
            Span::styled(s_row.to_string(), style_bold(smiley_color)),
            Span::raw("   "),
        ];

        match i {
            1 => {
                spans.push(Span::styled("◈", style_bold(RED)));
                spans.push(Span::styled(
                    "  R E D J O H N   O F F E N S I V E   S W A R M  ",
                    style_bold(WHITE),
                ));
                spans.push(Span::styled("◈", style_bold(RED)));
            }
            2 | 8 => {
                spans.push(Span::styled(rule.clone(), style_dim()));
            }
            3..=7 => {
                let b_row = BANNER_ROWS[i - 3];
                let chars: Vec<char> = b_row.chars().collect();
                let red_cut = 22.min(chars.len());
                let red_part: String = chars[..red_cut].iter().collect();
                let white_part: String = chars[red_cut..].iter().collect();
                spans.push(Span::styled(red_part, style_bold(RED)));
                spans.push(Span::styled(white_part, style_bold(BRIGHT_WHITE)));
            }
            9 => {
                spans.push(Span::styled("▪", style_bold(RED)));
                spans.push(Span::styled(" Edition : ", style_dim()));
                spans.push(Span::styled(version_label.to_string(), style_bold(RED)));
            }
            _ => {}
        }
        rows.push(Line::from(spans));
    }
    rows
}

fn draw_splash(frame: &mut Frame, state: &AppState, area: Rect) {
    let mut lines = wordmark_lines(&state.version_label());
    lines.push(Line::from(Span::raw("")));
    lines.push(Line::from(vec![
        Span::styled("Welcome to ", style_bold(WHITE)),
        Span::styled("RED", style_bold(RED)),
        Span::styled("JOHN", style_bold(BRIGHT_WHITE)),
    ]));
    lines.push(Line::from(Span::styled(
        format!("◈  {}  ◈", state.version_label()),
        style_bold(RED),
    )));
    lines.push(Line::from(Span::styled(
        "Autonomous P2P Multi-Agent Offensive Swarm",
        style_dim(),
    )));
    lines.push(Line::from(Span::raw("")));

    let shine = "Starting RedJohn Swarm";
    let chars: Vec<char> = shine.chars().collect();
    let pos = (state.splash_frame % (chars.len() + 8)) as isize;
    let mut shine_spans = Vec::with_capacity(chars.len());
    for (i, ch) in chars.into_iter().enumerate() {
        let dist = (i as isize - pos).abs();
        let style = if dist <= 1 {
            style_bold(BRIGHT_WHITE)
        } else if dist <= 3 {
            style_bold(WHITE)
        } else if dist <= 5 {
            style_fg(MID)
        } else {
            style_fg(DIM)
        };
        shine_spans.push(Span::styled(ch.to_string(), style));
    }
    lines.push(Line::from(shine_spans));
    lines.push(Line::from(Span::raw("")));
    lines.push(Line::from(Span::styled(
        format!(
            "{} registered skills  ·  P2P Signal Bus  ·  Kali Native",
            state.registered_skill_count()
        ),
        style_dim(),
    )));

    let box_w = 98.min(area.width.saturating_sub(2));
    let box_h = (lines.len() as u16 + 4).min(area.height);
    let rect = centered_rect(area, box_w, box_h);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(style_fg(RED))
        .style(Style::default().bg(BLACK).fg(TEXT));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let p = Paragraph::new(lines).alignment(Alignment::Center);
    frame.render_widget(p, inner);
}

fn draw_setup(frame: &mut Frame, state: &AppState, area: Rect) {
    let rail_w: u16 = if area.width >= 96 && area.height >= 16 {
        (area.width / 5).clamp(26, 32)
    } else {
        0
    };
    let main_w = area.width.saturating_sub(rail_w);
    let col_w = if main_w >= 87 {
        85u16
    } else {
        main_w.saturating_sub(4).clamp(24, 72)
    };
    let col_x = main_w.saturating_sub(col_w) / 2;

    let show_full_logo = col_w >= 85 && area.height >= 24;
    let logo_h: u16 = if show_full_logo { 13 } else { 2 };
    let input_lines = composer_lines(state, (col_w.saturating_sub(4)) as usize, true);
    let summary_line = setup_summary_line(state, (col_w.saturating_sub(4)) as usize);
    let target_lines = targets_lines(state, (col_w.saturating_sub(4)) as usize, 6);

    let mut composer_body = input_lines;
    composer_body.push(Line::from(Span::raw("")));
    composer_body.push(summary_line);
    composer_body.extend(target_lines);
    let composer_h = (composer_body.len() as u16 + 2).min(area.height.saturating_sub(4));

    let log_count = state.setup_log.len().min(5);
    let log_h = if log_count > 0 {
        log_count as u16 + 1
    } else {
        0
    };

    let total_h = logo_h + 1 + composer_h + log_h + 2;
    let mut cur_y = area.height.saturating_sub(total_h) / 2;

    // 1. Logo / Banner
    if show_full_logo && cur_y + logo_h <= area.height {
        let wm = Paragraph::new(wordmark_lines(&state.version_label()));
        frame.render_widget(wm, Rect::new(col_x, cur_y, col_w, logo_h));
        cur_y += logo_h + 1;
    } else if cur_y + 2 <= area.height {
        let compact = vec![
            Line::from(vec![
                Span::styled("☻ RED", style_bold(RED)),
                Span::styled("JOHN", style_bold(BRIGHT_WHITE)),
                Span::styled(" · ", style_dim()),
                Span::styled(state.version_label(), style_bold(RED)),
            ]),
            Line::from(Span::styled(
                "Autonomous P2P Multi-Agent Offensive Swarm",
                style_dim(),
            )),
        ];
        let p = Paragraph::new(compact).alignment(Alignment::Center);
        frame.render_widget(p, Rect::new(col_x, cur_y, col_w, 2));
        cur_y += 3;
    }

    // 2. Composer Panel
    if cur_y + composer_h <= area.height {
        let border_col = if state.focus == FocusMode::Input {
            RED
        } else {
            DARK_BORDER
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(style_fg(border_col))
            .style(Style::default().bg(BLACK).fg(TEXT));
        let rect = Rect::new(col_x, cur_y, col_w, composer_h);
        let inner = block.inner(rect);
        frame.render_widget(block, rect);
        let inner_padded = Rect::new(
            inner.x + 1,
            inner.y,
            inner.width.saturating_sub(2),
            inner.height,
        );
        frame.render_widget(Paragraph::new(composer_body), inner_padded);
        cur_y += composer_h + 1;
    }

    // 3. Setup feedback log
    if log_count > 0 && cur_y + (log_count as u16) <= area.height {
        let start = state.setup_log.len() - log_count;
        let log_lines: Vec<Line<'static>> = state.setup_log[start..]
            .iter()
            .map(|entry| {
                let col = match entry.level.as_str() {
                    "error" => RED,
                    "warning" => BRIGHT_RED,
                    _ => DIM,
                };
                Line::from(vec![
                    Span::raw("  "),
                    Span::styled(
                        truncate_width(&entry.text, col_w.saturating_sub(4) as usize),
                        style_fg(col),
                    ),
                ])
            })
            .collect();
        frame.render_widget(
            Paragraph::new(log_lines),
            Rect::new(col_x, cur_y, col_w, log_count as u16),
        );
        cur_y += log_count as u16 + 1;
    }

    // 4. Key Hints Footer
    if cur_y < area.height {
        let hint_line = setup_hints_line(state, col_w as usize);
        frame.render_widget(Paragraph::new(vec![hint_line]), Rect::new(col_x, cur_y, col_w, 1));
    }

    // 5. Right-hand Launch Rail
    if rail_w > 0 {
        let rail_rect = Rect::new(main_w, 0, rail_w, area.height);
        draw_launch_rail(frame, state, rail_rect);
    }
}

fn setup_summary_line(state: &AppState, width: usize) -> Line<'static> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    let model = state.snapshot.model.trim();
    if !model.is_empty() {
        let short_name = state.display_model_name();
        spans.push(Span::styled("● ", style_fg(BRIGHT_RED)));
        spans.push(Span::styled(short_name.clone(), style_bold(BRIGHT_WHITE)));
        let effort = state.snapshot.reasoning_effort.trim();
        if !effort.is_empty() && effort != "none" {
            spans.push(Span::styled(" · ", style_dim()));
            spans.push(Span::styled("effort ", style_dim()));
            spans.push(Span::styled(effort.to_string(), style_fg(BRIGHT_RED)));
        }
        let swarm_short = state.display_swarm_model_name();
        if !swarm_short.is_empty() && swarm_short != short_name {
            spans.push(Span::styled(" · ", style_dim()));
            spans.push(Span::styled("swarm ", style_dim()));
            spans.push(Span::styled(swarm_short, style_fg(WHITE)));
        }
    } else {
        spans.push(Span::styled("○ no model", style_fg(BRIGHT_RED)));
        spans.push(Span::styled(" · /models to choose", style_dim()));
    }

    spans.push(Span::styled(" · ", style_dim()));
    spans.push(Span::styled("◈", style_fg(RED)));
    let total_skills = state.registered_skill_count();
    let sel_skills = state.snapshot.selected_skills.len();
    let skill_chip = if sel_skills > 0 {
        format!(" P2P Swarm · {sel_skills}/{total_skills} skills")
    } else {
        format!(" P2P Swarm · {total_skills} skills")
    };
    spans.push(Span::styled(skill_chip, style_dim()));

    if let Some(budget) = state.snapshot.max_budget_usd {
        spans.push(Span::styled(format!(" · ${budget:.2} budget"), style_dim()));
    }
    let _ = width;
    Line::from(spans)
}

fn setup_hints_line(state: &AppState, width: usize) -> Line<'static> {
    let mut spans = vec![Span::raw("  ")];
    let pairs = [
        ("enter", "launch"),
        ("/models", "model"),
        ("/swarm", "swarm"),
        ("/skills", "skills"),
        ("/rj", "pentest"),
        ("ctrl+c", "quit"),
    ];
    let mut used = 2usize;
    for (i, (k, desc)) in pairs.iter().enumerate() {
        let item_w = k.len() + 1 + desc.len() + if i > 0 { 2 } else { 0 };
        if used + item_w + 10 > width && i >= 2 {
            break;
        }
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        spans.push(Span::styled((*k).to_string(), style_bold(BRIGHT_RED)));
        spans.push(Span::styled(format!(" {desc}"), style_dim()));
        used += item_w;
    }
    let ver = state.version_label();
    let ver_w = UnicodeWidthStr::width(ver.as_str());
    if width > used + ver_w + 4 {
        let gap = width - used - ver_w - 2;
        spans.push(Span::raw(" ".repeat(gap)));
        spans.push(Span::styled(ver, style_bold(RED)));
    }
    Line::from(spans)
}

fn draw_launch_rail(frame: &mut Frame, state: &AppState, rect: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(style_fg(DARK_BORDER))
        .style(Style::default().bg(BLACK).fg(TEXT));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let inner_padded = Rect::new(
        inner.x + 1,
        inner.y,
        inner.width.saturating_sub(2),
        inner.height,
    );
    let max_rows = inner_padded.height as usize;
    if max_rows == 0 {
        return;
    }
    let mut lines = resource_lines(state, inner_padded.width as usize);
    if lines.len() > max_rows {
        let hidden = lines.len() - (max_rows - 1);
        lines.truncate(max_rows - 1);
        lines.push(Line::from(Span::styled(
            format!("+{hidden} more"),
            style_dim(),
        )));
    }
    frame.render_widget(Paragraph::new(lines), inner_padded);
}

fn resource_lines(state: &AppState, width: usize) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let in_use = state.mcp_in_use();
    let frames = ['◐', '◓', '◑', '◒'];
    if !state.snapshot.connections.is_empty() {
        lines.push(Line::from(Span::styled("MCP", style_fg(BRIGHT_RED))));
        for conn in &state.snapshot.connections {
            let (glyph, g_col, right_txt, r_col) = if conn.dead {
                ("●".to_string(), RED, "offline".to_string(), RED)
            } else if in_use.contains(&conn.name) {
                (
                    frames[state.sweep_frame % frames.len()].to_string(),
                    RED,
                    tools_label(conn.tool_count),
                    DIM,
                )
            } else {
                ("●".to_string(), RED, tools_label(conn.tool_count), DIM)
            };
            let name_max = width.saturating_sub(right_txt.len() + 4).max(1);
            let name = truncate_width(&conn.name, name_max);
            let gap = width
                .saturating_sub(2 + UnicodeWidthStr::width(name.as_str()) + right_txt.len())
                .max(1);
            lines.push(Line::from(vec![
                Span::styled(format!("{glyph} "), style_fg(g_col)),
                Span::styled(name, style_fg(TEXT)),
                Span::raw(" ".repeat(gap)),
                Span::styled(right_txt, style_fg(r_col)),
            ]));
        }
    }
    if !state.snapshot.skills.is_empty() {
        if !lines.is_empty() {
            lines.push(Line::from(Span::raw("")));
        }
        lines.push(Line::from(Span::styled("Skills", style_fg(BRIGHT_RED))));
        for skill in &state.snapshot.skills {
            lines.push(Line::from(Span::styled(
                truncate_width(skill, width),
                style_fg(TEXT),
            )));
        }
    }
    lines
}

fn tools_label(count: usize) -> String {
    if count == 1 {
        "1 tool".to_string()
    } else {
        format!("{count} tools")
    }
}

fn targets_lines(state: &AppState, width: usize, max_rows: usize) -> Vec<Line<'static>> {
    if state.snapshot.targets.is_empty() || max_rows < 2 {
        return Vec::new();
    }
    let total = state
        .snapshot
        .target_count
        .max(state.snapshot.targets.len());
    let mut visible = state.snapshot.targets.len().min(4).min(max_rows - 1);
    if visible < total {
        visible = visible.min(max_rows.saturating_sub(2));
    }
    let mut rows = vec![Line::from(vec![
        Span::styled("Active Targets", style_bold(WHITE)),
        Span::styled(format!(" {total}"), style_dim()),
    ])];
    for (idx, target) in state.snapshot.targets.iter().take(visible).enumerate() {
        rows.push(Line::from(vec![
            Span::styled(format!("{}  ", idx + 1), style_fg(DIM)),
            Span::styled(
                truncate_width(target, width.saturating_sub(3).max(1)),
                style_fg(WHITE),
            ),
        ]));
    }
    if total > visible {
        rows.push(Line::from(Span::styled(
            format!("+{} more", total - visible),
            style_dim(),
        )));
    }
    rows
}

fn composer_lines(state: &AppState, width: usize, setup_mode: bool) -> Vec<Line<'static>> {
    let min_rows = if setup_mode { 3 } else { 1 };
    let max_rows = 8usize;
    let focused = state.focus == FocusMode::Input && state.modal == ModalMode::None;
    let prompt_style = if focused {
        style_bold(RED)
    } else {
        style_fg(CRIMSON)
    };
    let cursor_style = Style::default()
        .fg(BLACK)
        .bg(RED)
        .add_modifier(Modifier::BOLD);

    if state.input_text.is_empty() {
        let ph = if setup_mode {
            if width < SETUP_PLACEHOLDER.len() + 4 {
                SETUP_PLACEHOLDER_SHORT
            } else {
                SETUP_PLACEHOLDER
            }
        } else {
            CHAT_PLACEHOLDER
        };
        let mut first_spans = vec![Span::styled("> ", prompt_style)];
        if focused {
            let mut chars = ph.chars();
            let first_ch = chars.next().unwrap_or(' ');
            first_spans.push(Span::styled(first_ch.to_string(), cursor_style));
            first_spans.push(Span::styled(chars.as_str().to_string(), style_fg(DIM)));
        } else {
            first_spans.push(Span::styled(ph.to_string(), style_fg(DIM)));
        }
        let mut lines = vec![Line::from(first_spans)];
        while lines.len() < min_rows {
            lines.push(Line::from(Span::raw("  ")));
        }
        return lines;
    }

    let ghost = state.slash_ghost();
    let raw_lines: Vec<&str> = state.input_text.split('\n').collect();
    let mut lines = Vec::new();
    for (idx, raw) in raw_lines.iter().enumerate() {
        let pfx = if idx == 0 { "> " } else { "  " };
        let mut spans = vec![Span::styled(pfx.to_string(), prompt_style)];
        spans.push(Span::styled((*raw).to_string(), style_fg(TEXT)));
        if idx == 0 && !ghost.is_empty() {
            spans.push(Span::styled(ghost.clone(), style_dim()));
        }
        if focused && idx + 1 == raw_lines.len() {
            spans.push(Span::styled("█", style_fg(RED)));
        }
        lines.push(Line::from(spans));
        if lines.len() >= max_rows {
            break;
        }
    }
    while lines.len() < min_rows {
        lines.push(Line::from(Span::raw("  ")));
    }
    lines
}

fn draw_main(frame: &mut Frame, state: &mut AppState, area: Rect) {
    let show_sidebar = area.width >= 120 && !state.sidebar_hidden;
    let sidebar_w: u16 = if show_sidebar {
        (area.width / 5).max(24)
    } else if state.sidebar_hidden && area.width >= 120 {
        6
    } else {
        0
    };
    let chat_w = if sidebar_w > 0 {
        area.width.saturating_sub(sidebar_w + 1)
    } else {
        area.width
    };

    let status_h: u16 = if !state.snapshot.agents.is_empty() {
        1
    } else {
        0
    };
    let comp_lines = composer_lines(state, chat_w.saturating_sub(4) as usize, false);
    let comp_h = (comp_lines.len() as u16 + 2).min(10);
    let chat_h = area.height.saturating_sub(status_h + comp_h).max(4);

    // 1. Left Chat Trace Pane
    let chat_rect = Rect::new(0, 0, chat_w, chat_h);
    draw_chat_pane(frame, state, chat_rect);

    // 2. Optional Status Row
    if status_h > 0 && chat_h < area.height {
        let status_rect = Rect::new(0, chat_h, chat_w, 1);
        draw_status_row(frame, state, status_rect);
    }

    // 3. Composer Input Box
    let input_top = chat_h + status_h;
    if input_top < area.height {
        let input_h = area.height.saturating_sub(input_top);
        let input_rect = Rect::new(0, input_top, chat_w, input_h);
        let border_col = if state.focus == FocusMode::Input {
            RED
        } else {
            DARK_BORDER
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(style_fg(border_col))
            .style(Style::default().bg(BLACK).fg(TEXT));
        let inner = block.inner(input_rect);
        frame.render_widget(block, input_rect);
        let padded = Rect::new(
            inner.x + 1,
            inner.y,
            inner.width.saturating_sub(1),
            inner.height,
        );
        frame.render_widget(Paragraph::new(comp_lines), padded);
    }

    // 4. Right Sidebar or Collapsed Rail
    if show_sidebar {
        let sb_rect = Rect::new(chat_w + 1, 0, sidebar_w, area.height);
        draw_sidebar(frame, state, sb_rect);
    } else if sidebar_w > 0 {
        let btn_rect = Rect::new(area.width.saturating_sub(5), 0, 5, 3.min(area.height));
        let btn = Paragraph::new(vec![
            Line::from(Span::raw("")),
            Line::from(Span::styled("  «  ", style_bold(BRIGHT_WHITE))),
        ])
        .style(Style::default().bg(Color::Rgb(38, 38, 38)).fg(BRIGHT_WHITE));
        frame.render_widget(btn, btn_rect);
    }
}

fn draw_chat_pane(frame: &mut Frame, state: &mut AppState, rect: Rect) {
    let border_col = if state.focus == FocusMode::Chat {
        RED
    } else {
        DARK_BG
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(style_fg(border_col))
        .style(Style::default().bg(BLACK).fg(TEXT));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);

    if inner.width == 0 || inner.height == 0 {
        return;
    }

    if state.snapshot.agents.is_empty() {
        let placeholder = match state.snapshot.scan_state.as_str() {
            "failed" => {
                if let Some(err) = &state.snapshot.error {
                    format!("Scan failed — {}", err.replace('\n', " "))
                } else {
                    "Scan failed".to_string()
                }
            }
            "stopped" => "Scan stopped".to_string(),
            "completed" => "Scan completed".to_string(),
            "preparing" => "Preparing scan...".to_string(),
            _ => "Loading...".to_string(),
        };
        let y = inner.y + inner.height / 2;
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                truncate_width(&placeholder, inner.width as usize),
                Style::default().fg(DIM).add_modifier(Modifier::ITALIC),
            )))
            .alignment(Alignment::Center),
            Rect::new(inner.x, y, inner.width, 1),
        );
        return;
    }

    let content_w = inner.width.saturating_sub(2).max(1) as usize;
    let mut all_lines: Vec<Line<'static>> = build_header_lines(state, content_w);

    let selected_id = state.selected_agent_id();
    let mut events = state.snapshot.events.clone();
    events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp).then_with(|| a.id.cmp(&b.id)));

    let mut parked_on = String::new();
    if !state.all_agents_view
        && state
            .snapshot
            .agents
            .get(state.selected_agent)
            .is_some_and(|a| a.status == "waiting")
    {
        for ev in &events {
            if ev.agent_id == selected_id && ev.event_type == "tool" {
                parked_on = ev.id.clone();
            }
        }
    }

    let mut event_count = 0usize;
    for ev in &events {
        if !state.all_agents_view && ev.agent_id != selected_id {
            continue;
        }
        let expanded = state.expanded_events.contains(&ev.id);
        let badge = if state.all_agents_view {
            state
                .snapshot
                .agents
                .iter()
                .find(|a| a.id == ev.agent_id)
                .map(|a| a.name.as_str())
        } else {
            None
        };
        let (ev_lines, _) = render_event_lines(
            ev,
            expanded,
            ev.id == parked_on,
            state.sweep_frame / 2,
            badge,
        );
        if ev_lines.is_empty() {
            continue;
        }
        all_lines.push(Line::from(Span::raw("")));
        all_lines.extend(wrap_styled_lines(ev_lines, content_w));
        event_count += 1;
    }

    if event_count == 0 {
        let header_lines: Vec<Line<'static>> = all_lines
            .into_iter()
            .map(|mut l| {
                let mut s = vec![Span::raw(" ")];
                s.append(&mut l.spans);
                Line::from(s)
            })
            .collect();
        let header_h = (header_lines.len() as u16).min(inner.height);
        if header_h > 0 {
            frame.render_widget(
                Paragraph::new(header_lines),
                Rect::new(inner.x, inner.y, inner.width, header_h),
            );
        }
        let y = (inner.y + inner.height / 2).max(inner.y + header_h);
        if y < inner.y + inner.height {
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    "Starting agent...",
                    Style::default().fg(DIM).add_modifier(Modifier::ITALIC),
                )))
                .alignment(Alignment::Center),
                Rect::new(inner.x, y, inner.width, 1),
            );
        }
        return;
    }

    let vis = inner.height as usize;
    state.chat_total_lines = all_lines.len();
    state.chat_visible_lines = vis;
    let max_scroll = state.chat_total_lines.saturating_sub(vis);
    if state.follow_output || state.chat_scroll > max_scroll {
        state.chat_scroll = max_scroll;
    }

    let slice_end = (state.chat_scroll + vis).min(all_lines.len());
    let visible_lines: Vec<Line<'static>> = all_lines[state.chat_scroll..slice_end]
        .iter()
        .cloned()
        .map(|mut l| {
            let mut s = vec![Span::raw(" ")];
            s.append(&mut l.spans);
            Line::from(s)
        })
        .collect();

    frame.render_widget(Paragraph::new(visible_lines), inner);
}

fn build_header_lines(state: &AppState, width: usize) -> Vec<Line<'static>> {
    if width < 20 || state.snapshot.agents.is_empty() {
        return Vec::new();
    }
    let target_label = state
        .snapshot
        .targets
        .first()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("Security audit");

    let row1 = Line::from(vec![
        Span::styled("☻ RedJohn", style_bold(RED)),
        Span::styled(" / ", style_dim()),
        Span::styled(target_label.to_string(), style_bold(BRIGHT_WHITE)),
        Span::styled("  │  RJ-001    ", style_dim()),
        Span::styled("●", style_bold(BRIGHT_RED)),
        Span::styled(" API Live", style_bold(BRIGHT_WHITE)),
        Span::styled("  │  ", style_dim()),
        Span::styled("●", style_bold(BRIGHT_RED)),
        Span::styled(" Swarm Live", style_bold(BRIGHT_WHITE)),
    ]);

    let total_mcp = state.snapshot.connections.len();
    let live_mcp = state
        .snapshot
        .connections
        .iter()
        .filter(|c| !c.dead)
        .count();
    let key_style = Style::default()
        .fg(BRIGHT_WHITE)
        .bg(CRIMSON)
        .add_modifier(Modifier::BOLD);
    let lbl_style = style_fg(MID);
    let val_style = style_bold(BRIGHT_RED);

    let row2 = Line::from(vec![
        Span::styled(" F2 ", key_style),
        Span::styled(" All Agents   ", lbl_style),
        Span::styled(" F3 ", key_style),
        Span::styled(" MCPs ", lbl_style),
        Span::styled(format!("{live_mcp}/{total_mcp}"), val_style),
        Span::styled("   ", lbl_style),
        Span::styled(" F4 ", key_style),
        Span::styled(" Skills ", lbl_style),
        Span::styled(state.registered_skill_count().to_string(), val_style),
        Span::styled("   ", lbl_style),
        Span::styled(" F5 / F ", key_style),
        Span::styled(" Findings ", lbl_style),
        Span::styled(state.snapshot.vulnerabilities.len().to_string(), val_style),
        Span::styled("   ", lbl_style),
        Span::styled(" F1 ", key_style),
        Span::styled(" Help", lbl_style),
    ]);

    let rule = Line::from(Span::styled("─".repeat(width), style_fg(DARK_BORDER)));

    let active_tab = Style::default()
        .fg(BRIGHT_WHITE)
        .bg(CRIMSON)
        .add_modifier(Modifier::BOLD);
    let inactive_tab = style_fg(MID);
    let mut tab_spans = vec![Span::styled(
        " 0 All agents ",
        if state.all_agents_view {
            active_tab
        } else {
            inactive_tab
        },
    )];
    for (i, ag) in state.snapshot.agents.iter().enumerate() {
        tab_spans.push(Span::styled(" │ ", style_fg(DARK_BORDER)));
        let selected = !state.all_agents_view && i == state.selected_agent;
        tab_spans.push(Span::styled(
            format!(" {} {} ", i + 1, ag.name),
            if selected { active_tab } else { inactive_tab },
        ));
    }
    let row4 = Line::from(tab_spans);

    let mut row5_spans = Vec::new();
    if !state.all_agents_view {
        if let Some(ag) = state.snapshot.agents.get(state.selected_agent) {
            row5_spans.push(Span::styled(
                format!("Live Terminal — {}", ag.name),
                style_bold(BRIGHT_WHITE),
            ));
            row5_spans.push(Span::styled(format!(" / {}    ", ag.id), style_dim()));
        }
    } else {
        row5_spans.push(Span::styled(
            "Live Terminal — All Swarm Agents    ",
            style_bold(BRIGHT_WHITE),
        ));
    }
    if state.follow_output {
        row5_spans.push(Span::styled("●", style_bold(BRIGHT_RED)));
        row5_spans.push(Span::styled(" Following", style_fg(BRIGHT_WHITE)));
    } else {
        row5_spans.push(Span::styled("○", style_fg(BRIGHT_RED)));
        row5_spans.push(Span::styled(" Scrollback", style_fg(MID)));
    }

    vec![
        row1,
        row2,
        rule.clone(),
        row4,
        Line::from(row5_spans),
        rule,
    ]
}

fn draw_status_row(frame: &mut Frame, state: &AppState, rect: Rect) {
    let mut left_spans: Vec<Span<'static>> = vec![Span::raw(" ")];
    let mut right_spans: Vec<Span<'static>> = Vec::new();

    if let Some(ag) = state.snapshot.agents.get(state.selected_agent) {
        match ag.status.as_str() {
            "running" => {
                left_spans.extend(sweep_spans(state.sweep_frame));
                if state.agent_has_events(&ag.id) {
                    left_spans.push(Span::styled("esc", style_fg(WHITE)));
                    left_spans.push(Span::styled(" stop", style_dim()));
                } else {
                    left_spans.push(Span::styled("Initializing", style_fg(WHITE)));
                }
                right_spans.push(Span::styled("ctrl-q", style_fg(WHITE)));
                right_spans.push(Span::styled(" quit", style_dim()));
            }
            "waiting" => {
                if !ag.error_message.is_empty() {
                    left_spans.push(Span::styled(
                        truncate_width(&ag.error_message, rect.width.saturating_sub(28) as usize),
                        style_fg(RED),
                    ));
                    left_spans.push(Span::styled(" · Send message to resume", style_dim()));
                } else {
                    left_spans.push(Span::styled("Send message to resume", style_dim()));
                }
            }
            "budget_paused" => {
                left_spans.push(Span::styled("Budget limit reached", style_fg(BRIGHT_RED)));
                left_spans.push(Span::styled(" · Send a message to continue", style_dim()));
                right_spans.push(Span::styled("ctrl-q", style_fg(WHITE)));
                right_spans.push(Span::styled(" quit", style_dim()));
            }
            "completed" => {
                left_spans.push(Span::styled("Agent completed", style_fg(MID)));
            }
            "stopped" => {
                left_spans.push(Span::styled("Agent stopped", style_fg(MID)));
            }
            "failed" | "crashed" => {
                let msg = if ag.error_message.is_empty() {
                    "Agent failed"
                } else {
                    &ag.error_message
                };
                left_spans.push(Span::styled(
                    truncate_width(msg, rect.width.saturating_sub(28) as usize),
                    style_fg(RED),
                ));
                left_spans.push(Span::styled(" · Send message to resume", style_dim()));
            }
            _ => {}
        }
    }

    if !state.error_text.is_empty() {
        left_spans = vec![
            Span::raw(" "),
            Span::styled(
                truncate_width(&state.error_text, rect.width.saturating_sub(14) as usize),
                style_fg(RED),
            ),
        ];
    }

    let left_w: usize = left_spans
        .iter()
        .map(|s| UnicodeWidthStr::width(s.content.as_ref()))
        .sum();
    let right_w: usize = right_spans
        .iter()
        .map(|s| UnicodeWidthStr::width(s.content.as_ref()))
        .sum();
    let gap = (rect.width as usize).saturating_sub(left_w + right_w);
    left_spans.push(Span::raw(" ".repeat(gap)));
    left_spans.extend(right_spans);

    frame.render_widget(Paragraph::new(Line::from(left_spans)), rect);
}

fn sweep_spans(sweep_frame: usize) -> Vec<Span<'static>> {
    let palette = [
        BLACK,
        Color::Rgb(42, 6, 6),
        Color::Rgb(69, 10, 10),
        DARK_CRIMSON,
        CRIMSON,
        RED,
        BRIGHT_RED,
        BRIGHT_WHITE,
    ];
    let num_squares = 6isize;
    let num_colors = palette.len() as isize;
    let offset = num_colors - 1;
    let max_pos = (num_squares - 1) + offset;
    let total_range = max_pos + offset;
    let cycle_len = (total_range * 2) as usize;
    let frame_in_cycle = (sweep_frame % cycle_len) as isize;
    let wave_pos = total_range - (total_range - frame_in_cycle).abs();
    let sweep_pos = wave_pos - offset;

    let mut spans = Vec::with_capacity(7);
    for i in 0..num_squares {
        let dist = (i - sweep_pos).abs();
        let color_idx = num_colors - 1 - dist;
        if color_idx <= 0 {
            spans.push(Span::styled("·", style_fg(Color::Rgb(69, 10, 10))));
        } else {
            spans.push(Span::styled("▪", style_fg(palette[color_idx as usize])));
        }
    }
    spans.push(Span::raw(" "));
    spans
}

fn draw_sidebar(frame: &mut Frame, state: &AppState, rect: Rect) {
    if rect.height < 6 {
        return;
    }
    let mut cur_y = rect.y;

    // 1. Top Swarm / Findings Header Box (height = 3)
    let top_h = 3u16.min(rect.height);
    let top_rect = Rect::new(rect.x, cur_y, rect.width, top_h);
    let top_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(style_fg(DARK_BORDER))
        .style(Style::default().bg(BLACK).fg(TEXT));
    let top_inner = top_block.inner(top_rect);
    frame.render_widget(top_block, top_rect);
    if top_inner.height > 0 && top_inner.width > 4 {
        let left_spans = vec![
            Span::styled(" ◈ ", style_bold(RED)),
            Span::styled("SWARM", style_bold(BRIGHT_WHITE)),
            Span::styled(" · ", style_dim()),
            Span::styled("F", style_bold(BRIGHT_RED)),
            Span::styled(" Findings", style_fg(MID)),
        ];
        let left_w: usize = left_spans
            .iter()
            .map(|s| UnicodeWidthStr::width(s.content.as_ref()))
            .sum();
        let gap = (top_inner.width as usize).saturating_sub(left_w + 4);
        let mut row_spans = left_spans;
        row_spans.push(Span::raw(" ".repeat(gap)));
        row_spans.push(Span::styled(
            " » ",
            Style::default()
                .fg(BRIGHT_WHITE)
                .bg(Color::Rgb(38, 38, 38))
                .add_modifier(Modifier::BOLD),
        ));
        frame.render_widget(Paragraph::new(Line::from(row_spans)), top_inner);
    }
    cur_y += top_h;

    // 2. Stats Box at Bottom
    let stats_lines = build_stats_lines(state);
    let stats_h = ((stats_lines.len() as u16) + 2)
        .clamp(3, 8)
        .min(rect.height.saturating_sub(3));
    let stats_top = rect.y + rect.height.saturating_sub(stats_h);

    // 3. Optional Targets Box
    let inner_w = rect.width.saturating_sub(4).max(1) as usize;
    let t_lines = targets_lines(state, inner_w, 6);
    if !t_lines.is_empty() && stats_top.saturating_sub(cur_y) >= (t_lines.len() as u16 + 7) {
        let th = t_lines.len() as u16 + 2;
        let t_rect = Rect::new(rect.x, cur_y, rect.width, th);
        let t_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(style_fg(DARK_BORDER))
            .style(Style::default().bg(BLACK).fg(TEXT));
        let t_inner = t_block.inner(t_rect);
        frame.render_widget(t_block, t_rect);
        frame.render_widget(
            Paragraph::new(t_lines),
            Rect::new(
                t_inner.x + 1,
                t_inner.y,
                t_inner.width.saturating_sub(2),
                t_inner.height,
            ),
        );
        cur_y += th;
    }

    // 4. Agents Panel (fills remaining height)
    let agents_h = stats_top.saturating_sub(cur_y);
    if agents_h >= 3 {
        let ag_rect = Rect::new(rect.x, cur_y, rect.width, agents_h);
        let ag_border = if state.focus == FocusMode::Agents {
            RED
        } else {
            DARK_BORDER
        };
        let ag_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(style_fg(ag_border))
            .style(Style::default().bg(BLACK).fg(TEXT));
        let ag_inner = ag_block.inner(ag_rect);
        frame.render_widget(ag_block, ag_rect);

        let mut panel_lines = vec![
            Line::from(vec![
                Span::styled("▾ ", style_bold(BRIGHT_RED)),
                Span::styled(
                    format!("Agents ({})", state.snapshot.agents.len()),
                    style_bold(BRIGHT_WHITE),
                ),
            ]),
            Line::from(Span::raw("")),
        ];

        let entries = agent_tree_entries(&state.snapshot.agents, &state.collapsed_agents);
        let max_ag_rows = ag_inner.height.saturating_sub(2) as usize;
        for entry in entries.into_iter().take(max_ag_rows) {
            let ag = &state.snapshot.agents[entry.index];
            let icon = match ag.status.as_str() {
                "running" => "◉",
                "waiting" | "budget_paused" => "⏸",
                "completed" => "●",
                "failed" | "crashed" => "✕",
                "stopped" => "■",
                _ => "○",
            };
            let disclosure = if has_agent_children(&ag.id, &state.snapshot.agents) {
                if state.collapsed_agents.contains(&ag.id) {
                    "▶ "
                } else {
                    "▼ "
                }
            } else {
                ""
            };
            let v_count = state.agent_vuln_count(&ag.id);
            let v_suffix = if v_count > 0 {
                format!(" ({v_count})")
            } else {
                String::new()
            };
            let label = format!("{disclosure}{icon} {}{v_suffix}", ag.name);
            let label_style = if entry.index == state.selected_agent {
                Style::default()
                    .fg(BRIGHT_WHITE)
                    .bg(CRIMSON)
                    .add_modifier(Modifier::BOLD)
            } else {
                style_fg(WHITE)
            };
            let pfx_w = UnicodeWidthStr::width(entry.prefix.as_str());
            panel_lines.push(Line::from(vec![
                Span::styled(entry.prefix, style_fg(DIM)),
                Span::styled(
                    truncate_width(&label, inner_w.saturating_sub(pfx_w).max(1)),
                    label_style,
                ),
            ]));
        }

        frame.render_widget(
            Paragraph::new(panel_lines),
            Rect::new(
                ag_inner.x + 1,
                ag_inner.y,
                ag_inner.width.saturating_sub(2),
                ag_inner.height,
            ),
        );
    }

    // Render Stats Box
    let st_rect = Rect::new(rect.x, stats_top, rect.width, stats_h);
    let st_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(style_fg(DARK_BORDER))
        .style(Style::default().bg(BLACK).fg(TEXT));
    let st_inner = st_block.inner(st_rect);
    frame.render_widget(st_block, st_rect);
    frame.render_widget(
        Paragraph::new(stats_lines),
        Rect::new(
            st_inner.x + 1,
            st_inner.y,
            st_inner.width.saturating_sub(2),
            st_inner.height,
        ),
    );
}

fn build_stats_lines(state: &AppState) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let short_name = state.display_model_name();
    if !short_name.is_empty() {
        let mut row = vec![
            Span::styled("● ", style_bold(BRIGHT_RED)),
            Span::styled(short_name.clone(), style_bold(BRIGHT_WHITE)),
        ];
        let effort = state.snapshot.reasoning_effort.trim();
        if !effort.is_empty() && effort != "none" {
            row.push(Span::styled(" · ", style_dim()));
            row.push(Span::styled(effort.to_string(), style_fg(BRIGHT_RED)));
        }
        lines.push(Line::from(row));

        let swarm_short = state.display_swarm_model_name();
        if !swarm_short.is_empty() && swarm_short != short_name {
            lines.push(Line::from(vec![
                Span::styled("Swarm: ", style_dim()),
                Span::styled(swarm_short, style_bold(WHITE)),
            ]));
        }
    }
    if state.snapshot.subscription {
        let label = if state.snapshot.model.starts_with("grok/") {
            "SuperGrok subscription"
        } else {
            "ChatGPT subscription"
        };
        lines.push(Line::from(Span::styled(label, style_fg(BRIGHT_RED))));
    }
    if let Some(tokens) = val_num(state.snapshot.usage.get("total_tokens")) {
        let t_int = tokens as i64;
        if t_int > 0 {
            let mut txt = format!("{} tokens", format_count(t_int));
            if let Some(cost) = val_num(state.snapshot.usage.get("cost")) {
                if !state.snapshot.subscription && cost > 0.0 {
                    txt.push_str(&format!(" · ${cost:.2}"));
                }
            }
            lines.push(Line::from(Span::styled(txt, style_fg(WHITE))));
        }
    }
    if !state.snapshot.caido_url.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Caido: ", style_bold(WHITE)),
            Span::styled(state.snapshot.caido_url.clone(), style_fg(WHITE)),
        ]));
    }
    lines.push(Line::from(Span::styled(
        state.version_label(),
        style_bold(RED),
    )));
    lines
}

fn format_count(val: i64) -> String {
    if val >= 1_000_000 {
        format!("{:.1}M", val as f64 / 1_000_000.0)
    } else if val >= 1_000 {
        format!("{:.1}K", val as f64 / 1_000.0)
    } else {
        val.to_string()
    }
}

fn draw_modal(frame: &mut Frame, state: &AppState, area: Rect) {
    match state.modal {
        ModalMode::Help => draw_help_modal(frame, area),
        ModalMode::Quit => draw_confirm_modal(frame, state, area, "Quit RedJohn?", 28),
        ModalMode::Stop => {
            let name = state
                .snapshot
                .agents
                .get(state.selected_agent)
                .map(|a| a.name.as_str())
                .unwrap_or("agent");
            draw_confirm_modal(frame, state, area, &format!("🛑 Stop '{name}'?"), 34);
        }
        ModalMode::ConfirmMount => draw_mount_modal(frame, state, area),
        ModalMode::Mcp => draw_mcp_modal(frame, state, area),
        ModalMode::Skills => draw_skills_modal(frame, state, area),
        ModalMode::Findings => draw_findings_modal(frame, state, area),
        ModalMode::Vulnerability => draw_vulnerability_modal(frame, state, area),
        ModalMode::Picker => draw_picker_modal(frame, state, area),
        ModalMode::None => {}
    }
}

fn render_dialog_box(
    frame: &mut Frame,
    rect: Rect,
    border_col: Color,
    lines: Vec<Line<'static>>,
    align: Alignment,
) {
    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(style_fg(border_col))
        .style(Style::default().bg(BLACK).fg(TEXT));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let padded = Rect::new(
        inner.x + 2,
        inner.y + 1,
        inner.width.saturating_sub(4),
        inner.height.saturating_sub(2),
    );
    frame.render_widget(Paragraph::new(lines).alignment(align), padded);
}

fn draw_help_modal(frame: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from(Span::styled("RedJohn Help", style_bold(RED))),
        Line::from(Span::raw("")),
        Line::from(Span::styled("0 / F2       All agents stream", style_fg(TEXT))),
        Line::from(Span::styled("1-9          Switch agent (1-9)", style_fg(TEXT))),
        Line::from(Span::styled("F3 / /mcp    MCP connections modal", style_fg(TEXT))),
        Line::from(Span::styled(
            "F4 / /skills Skills catalog & selector",
            style_fg(TEXT),
        )),
        Line::from(Span::styled(
            "F5 / F       Findings list & reports",
            style_fg(TEXT),
        )),
        Line::from(Span::styled("/models      Choose model", style_fg(TEXT))),
        Line::from(Span::styled(
            "/swarm       Swarm & role model routing",
            style_fg(TEXT),
        )),
        Line::from(Span::styled("/effort      Reasoning effort", style_fg(TEXT))),
        Line::from(Span::styled(
            "/rj <target> Launch pentest swarm",
            style_fg(TEXT),
        )),
        Line::from(Span::styled("F1           Help", style_fg(TEXT))),
        Line::from(Span::styled("Ctrl+Q/C     Quit RedJohn", style_fg(TEXT))),
        Line::from(Span::styled("ESC          Stop Agent", style_fg(TEXT))),
        Line::from(Span::styled("Enter        Send / expand node", style_fg(TEXT))),
        Line::from(Span::styled("Tab          Switch panels", style_fg(TEXT))),
    ];
    let rect = centered_rect(area, 48.min(area.width), 20.min(area.height));
    render_dialog_box(frame, rect, RED, lines, Alignment::Left);
}

fn draw_confirm_modal(
    frame: &mut Frame,
    state: &AppState,
    area: Rect,
    title: &str,
    width: u16,
) {
    let yes_style = if state.modal_choice == 0 {
        Style::default()
            .fg(BRIGHT_WHITE)
            .bg(RED)
            .add_modifier(Modifier::BOLD)
    } else {
        style_bold(RED)
    };
    let no_style = if state.modal_choice != 0 {
        Style::default()
            .fg(BRIGHT_WHITE)
            .bg(Color::Rgb(62, 62, 62))
            .add_modifier(Modifier::BOLD)
    } else {
        style_bold(DIM)
    };

    let lines = vec![
        Line::from(Span::styled(title.to_string(), style_bold(BRIGHT_WHITE))),
        Line::from(Span::raw("")),
        Line::from(vec![
            Span::styled("  Yes  ", yes_style),
            Span::raw("   "),
            Span::styled("  No   ", no_style),
        ]),
    ];
    let rect = centered_rect(area, width.min(area.width), 7.min(area.height));
    render_dialog_box(frame, rect, CRIMSON, lines, Alignment::Center);
}

fn draw_mount_modal(frame: &mut Frame, state: &AppState, area: Rect) {
    let dir = if state.snapshot.pending_mount.trim().is_empty() {
        "the current directory"
    } else {
        state.snapshot.pending_mount.trim()
    };
    let yes_style = if state.modal_choice == 0 {
        Style::default()
            .fg(BRIGHT_WHITE)
            .bg(BRIGHT_RED)
            .add_modifier(Modifier::BOLD)
    } else {
        style_bold(BRIGHT_RED)
    };
    let no_style = if state.modal_choice != 0 {
        Style::default()
            .fg(BRIGHT_WHITE)
            .bg(Color::Rgb(62, 62, 62))
            .add_modifier(Modifier::BOLD)
    } else {
        style_bold(DIM)
    };
    let lines = vec![
        Line::from(Span::styled(
            "△ Mount working directory?",
            style_bold(BRIGHT_RED),
        )),
        Line::from(Span::styled(truncate_width(dir, 44), style_fg(WHITE))),
        Line::from(Span::styled(
            "writable in the sandbox · skip to run without it",
            style_dim(),
        )),
        Line::from(vec![
            Span::styled(" Mount ", yes_style),
            Span::raw("  "),
            Span::styled(" Skip ", no_style),
        ]),
    ];
    let rect = centered_rect(area, 54.min(area.width), 8.min(area.height));
    render_dialog_box(frame, rect, BRIGHT_RED, lines, Alignment::Left);
}

fn modal_header_line(
    mut left: Vec<Span<'static>>,
    right_label: &'static str,
    inner_w: usize,
) -> Line<'static> {
    let left_w: usize = left
        .iter()
        .map(|s| UnicodeWidthStr::width(s.content.as_ref()))
        .sum();
    let right_w = UnicodeWidthStr::width(right_label);
    let gap = inner_w.saturating_sub(left_w + right_w).max(2);
    left.push(Span::raw(" ".repeat(gap)));
    left.push(Span::styled(right_label, style_dim()));
    Line::from(left)
}

fn draw_mcp_modal(frame: &mut Frame, state: &AppState, area: Rect) {
    let w = area.width.saturating_sub(10).clamp(40, 68);
    let inner_w = w.saturating_sub(6) as usize;
    let mut lines = vec![
        modal_header_line(
            vec![
                Span::styled("◈ RedJohn MCP Connections", style_bold(BRIGHT_RED)),
                Span::styled(
                    format!("  ({} configured)", state.snapshot.connections.len()),
                    style_dim(),
                ),
            ],
            "F3 / esc close",
            inner_w,
        ),
        Line::from(Span::styled("─".repeat(inner_w), style_fg(DARK_BORDER))),
    ];
    if state.snapshot.connections.is_empty() {
        lines.push(Line::from(Span::raw("")));
        lines.push(Line::from(Span::styled(
            "No external MCP servers attached to this session.",
            style_fg(BRIGHT_WHITE),
        )));
        lines.push(Line::from(Span::styled(
            "Configure MCP servers in ~/.redjohn/mcp.json to expose external tools.",
            style_dim(),
        )));
        lines.push(Line::from(Span::raw("")));
    } else {
        let in_use = state.mcp_in_use();
        for conn in &state.snapshot.connections {
            let (st_txt, st_style) = if conn.dead {
                ("○ OFFLINE", style_fg(DIM))
            } else if in_use.contains(&conn.name) {
                ("◉ ACTIVE", style_bold(BRIGHT_WHITE))
            } else {
                ("● LIVE", style_bold(BRIGHT_RED))
            };
            lines.push(Line::from(vec![
                Span::styled(format!("{st_txt}  "), st_style),
                Span::styled(conn.name.clone(), style_bold(BRIGHT_WHITE)),
                Span::styled(format!("  ({})", tools_label(conn.tool_count)), style_fg(MID)),
            ]));
        }
        lines.push(Line::from(Span::raw("")));
    }
    lines.push(Line::from(Span::styled("enter / esc close", style_dim())));
    let h = (lines.len() as u16 + 4).min(area.height);
    let rect = centered_rect(area, w, h);
    render_dialog_box(frame, rect, CRIMSON, lines, Alignment::Left);
}

fn draw_skills_modal(frame: &mut Frame, state: &AppState, area: Rect) {
    let w = area.width.saturating_sub(8).clamp(44, 84);
    let inner_w = w.saturating_sub(6) as usize;
    let entries = state.effective_skills();
    let total_count = state.registered_skill_count().max(entries.len());
    let sel_count = state.snapshot.selected_skills.len();
    let sel_summary = if sel_count > 0 {
        format!("{sel_count} pinned")
    } else {
        "all active (default)".to_string()
    };

    let rule = Line::from(Span::styled("─".repeat(inner_w), style_fg(DARK_BORDER)));
    let mut lines = vec![
        modal_header_line(
            vec![
                Span::styled("◈ RedJohn Skills Catalog", style_bold(BRIGHT_RED)),
                Span::styled(format!("  {total_count} skills"), style_bold(BRIGHT_WHITE)),
                Span::styled(format!(" · {sel_summary}"), style_dim()),
            ],
            "F4 / esc close",
            inner_w,
        ),
        rule.clone(),
    ];

    if entries.is_empty() {
        lines.push(Line::from(Span::raw("")));
        lines.push(Line::from(Span::styled(
            "Loading skills catalog…",
            style_dim(),
        )));
        lines.push(Line::from(Span::raw("")));
    } else {
        let selected = state.skill_selected.min(entries.len() - 1);
        let page = (area.height.saturating_sub(14) as usize).clamp(5, 14);
        let start = if selected >= page {
            selected - page + 1
        } else {
            0
        };
        let end = (start + page).min(entries.len());
        let selected_set: HashSet<&str> = state
            .snapshot
            .selected_skills
            .iter()
            .map(|s| s.as_str())
            .collect();

        for (idx, entry) in entries.iter().enumerate().take(end).skip(start) {
            let is_sel = entry.selected || selected_set.contains(entry.name.as_str());
            let check = if is_sel { "[●]" } else { "[ ]" };
            let cat = if entry.category.is_empty() {
                "assessment"
            } else {
                &entry.category
            };
            let ready = if !entry.available && !entry.missing.is_empty() {
                "○"
            } else {
                "●"
            };
            let row_text = format!(
                " {check} {ready} {:<34} [{cat}]",
                truncate_width(&entry.name, 34)
            );
            if idx == selected {
                lines.push(Line::from(Span::styled(
                    pad_right_width(&row_text, inner_w),
                    Style::default()
                        .fg(BRIGHT_WHITE)
                        .bg(CRIMSON)
                        .add_modifier(Modifier::BOLD),
                )));
            } else {
                lines.push(Line::from(vec![
                    Span::raw(" "),
                    Span::styled(
                        check.to_string(),
                        if is_sel {
                            style_bold(BRIGHT_RED)
                        } else {
                            style_dim()
                        },
                    ),
                    Span::raw(" "),
                    Span::styled(ready.to_string(), style_fg(BRIGHT_RED)),
                    Span::raw(" "),
                    Span::styled(
                        format!("{:<34}", truncate_width(&entry.name, 34)),
                        style_fg(BRIGHT_WHITE),
                    ),
                    Span::raw(" "),
                    Span::styled(format!("[{cat}]"), style_dim()),
                ]));
            }
        }
        let cur = &entries[selected];
        lines.push(rule);
        let desc = if cur.description.trim().is_empty() {
            format!("RedJohn specialized skill module ({})", cur.category)
        } else {
            cur.description.trim().to_string()
        };
        lines.push(Line::from(vec![
            Span::styled(cur.name.clone(), style_bold(BRIGHT_WHITE)),
            Span::styled(" — ", style_dim()),
            Span::styled(
                truncate_width(&desc, inner_w.saturating_sub(cur.name.len() + 4).max(10)),
                style_fg(TEXT),
            ),
        ]));
    }
    lines.push(Line::from(Span::raw("")));
    lines.push(Line::from(vec![
        Span::styled("↑/↓", style_bold(BRIGHT_RED)),
        Span::styled(" navigate   ", style_dim()),
        Span::styled("space/enter", style_bold(BRIGHT_RED)),
        Span::styled(" toggle skill   ", style_dim()),
        Span::styled("esc", style_bold(BRIGHT_RED)),
        Span::styled(" close", style_dim()),
    ]));

    let h = (lines.len() as u16 + 4).min(area.height);
    let rect = centered_rect(area, w, h);
    render_dialog_box(frame, rect, CRIMSON, lines, Alignment::Left);
}

fn draw_findings_modal(frame: &mut Frame, state: &AppState, area: Rect) {
    let w = area.width.saturating_sub(8).clamp(44, 86);
    let inner_w = w.saturating_sub(6) as usize;
    let total = state.snapshot.vulnerabilities.len();
    let rule = Line::from(Span::styled("─".repeat(inner_w), style_fg(DARK_BORDER)));

    let mut lines = vec![
        modal_header_line(
            vec![
                Span::styled("◈ RedJohn Findings", style_bold(BRIGHT_RED)),
                Span::styled(format!("  ({total})"), style_bold(BRIGHT_WHITE)),
            ],
            "F5 / F / esc close",
            inner_w,
        ),
        rule.clone(),
    ];

    if total == 0 {
        lines.push(Line::from(Span::raw("")));
        lines.push(Line::from(Span::styled(
            "No findings recorded yet.",
            style_bold(BRIGHT_WHITE),
        )));
        lines.push(Line::from(Span::styled(
            "Verified vulnerabilities reported by the RedJohn Swarm will appear here.",
            style_dim(),
        )));
        lines.push(Line::from(Span::raw("")));
        lines.push(Line::from(vec![
            Span::styled("esc", style_bold(BRIGHT_RED)),
            Span::styled(" close", style_dim()),
        ]));
    } else {
        let selected = state.selected_vuln.min(total - 1);
        let page = (area.height.saturating_sub(14) as usize).clamp(4, 12);
        let start = if selected >= page {
            selected - page + 1
        } else {
            0
        };
        let end = (start + page).min(total);
        for (idx, vuln) in state
            .snapshot
            .vulnerabilities
            .iter()
            .enumerate()
            .take(end)
            .skip(start)
        {
            let mut sev = val_str(vuln.get("severity")).to_uppercase();
            if sev.is_empty() {
                sev = "HIGH".to_string();
            }
            let mut v_title = val_str(vuln.get("title"));
            if v_title.is_empty() {
                v_title = "Untitled Vulnerability".to_string();
            }
            let mut target = val_str(vuln.get("endpoint"));
            if target.is_empty() {
                target = val_str(vuln.get("target"));
            }
            let mut row_str = format!(" F-{:03}  [{:<8}]  {v_title}", idx + 1, sev);
            if !target.is_empty() {
                row_str.push_str(&format!("  · {target}"));
            }
            if idx == selected {
                lines.push(Line::from(Span::styled(
                    pad_right_width(&row_str, inner_w),
                    Style::default()
                        .fg(BRIGHT_WHITE)
                        .bg(CRIMSON)
                        .add_modifier(Modifier::BOLD),
                )));
            } else {
                let mut spans = vec![
                    Span::styled(format!(" F-{:03}  ", idx + 1), style_bold(BRIGHT_RED)),
                    Span::styled(format!("[{:<8}]  ", sev), style_bold(severity_color(&sev))),
                    Span::styled(v_title, style_fg(BRIGHT_WHITE)),
                ];
                if !target.is_empty() {
                    spans.push(Span::styled(format!("  · {target}"), style_dim()));
                }
                lines.push(Line::from(spans));
            }
        }
        lines.push(rule);
        lines.push(Line::from(vec![
            Span::styled("↑/↓", style_bold(BRIGHT_RED)),
            Span::styled(" select   ", style_dim()),
            Span::styled("enter", style_bold(BRIGHT_RED)),
            Span::styled(" open full report   ", style_dim()),
            Span::styled("c", style_bold(BRIGHT_RED)),
            Span::styled(" copy markdown   ", style_dim()),
            Span::styled("esc", style_bold(BRIGHT_RED)),
            Span::styled(" close", style_dim()),
        ]));
    }

    let h = (lines.len() as u16 + 4).min(area.height);
    let rect = centered_rect(area, w, h);
    render_dialog_box(frame, rect, CRIMSON, lines, Alignment::Left);
}

fn draw_vulnerability_modal(frame: &mut Frame, state: &AppState, area: Rect) {
    let Some(vuln) = state.snapshot.vulnerabilities.get(state.selected_vuln) else {
        return;
    };
    let w = (area.width * 85 / 100).clamp(40, 110).min(area.width);
    let h = (area.height * 85 / 100).clamp(10, 45).min(area.height);
    let inner_w = w.saturating_sub(8).max(1) as usize;
    let body_h = h.saturating_sub(7).max(2) as usize;

    let raw_lines = vulnerability_detail_lines(vuln);
    let wrapped = wrap_styled_lines(raw_lines, inner_w);
    let scroll = state
        .vuln_report_scroll
        .min(wrapped.len().saturating_sub(body_h));
    let mut visible: Vec<Line<'static>> =
        wrapped.into_iter().skip(scroll).take(body_h).collect();
    while visible.len() < body_h {
        visible.push(Line::from(Span::raw("")));
    }

    visible.push(Line::from(Span::styled(
        "─".repeat(inner_w),
        style_fg(DARK_BORDER),
    )));
    let focused = state.focused_report_button();
    let mut btn_spans = Vec::new();
    if state.snapshot.vulnerabilities.len() > 1 {
        btn_spans.push(Span::styled(
            format!(
                "{}/{}  ",
                state.selected_vuln + 1,
                state.snapshot.vulnerabilities.len()
            ),
            style_dim(),
        ));
    }
    for btn in state.report_buttons() {
        let mut lbl = btn.to_string();
        if btn == REPORT_COPY {
            if state.vulnerability_copied {
                lbl = "Copied!".to_string();
            } else if !state.vulnerability_copy_error.is_empty() {
                lbl = "Copy failed".to_string();
            }
        }
        let st = if btn == focused {
            Style::default()
                .fg(BRIGHT_WHITE)
                .bg(CRIMSON)
                .add_modifier(Modifier::BOLD)
        } else {
            style_fg(MID)
        };
        btn_spans.push(Span::styled(format!(" {lbl} "), st));
        btn_spans.push(Span::raw("  "));
    }
    visible.push(Line::from(btn_spans));

    let rect = centered_rect(area, w, h);
    render_dialog_box(frame, rect, CRIMSON, visible, Alignment::Left);
}

fn draw_picker_modal(frame: &mut Frame, state: &AppState, area: Rect) {
    let w = area.width.saturating_sub(8).clamp(36, 66);
    let inner_w = w.saturating_sub(6).max(1) as usize;
    let title = if state.picker.title.is_empty() {
        "Select model"
    } else {
        &state.picker.title
    };

    let mut lines = vec![modal_header_line(
        vec![Span::styled(
            truncate_width(title, inner_w.saturating_sub(6)),
            style_bold(WHITE),
        )],
        "esc",
        inner_w,
    )];

    match state.picker.phase {
        PickerPhase::Key => {
            let masked = if state.picker.key.is_empty() {
                " ".to_string()
            } else {
                "•".repeat(state.picker.key.chars().count().min(24))
            };
            lines.push(Line::from(Span::raw("")));
            lines.push(Line::from(Span::styled("API key", style_dim())));
            lines.push(Line::from(Span::styled(
                pad_right_width(&masked, inner_w),
                Style::default()
                    .fg(WHITE)
                    .bg(Color::Rgb(28, 25, 23)),
            )));
            lines.push(Line::from(Span::raw("")));
            lines.push(Line::from(Span::styled("enter save", style_dim())));
        }
        PickerPhase::Wait => {
            lines.push(Line::from(Span::raw("")));
            if !state.picker.message.is_empty() {
                for l in wrap_plain_text(&state.picker.message, inner_w) {
                    lines.push(Line::from(Span::styled(l, style_fg(TEXT))));
                }
            }
            if !state.picker.url.is_empty() {
                lines.push(Line::from(Span::raw("")));
                lines.push(Line::from(Span::styled(
                    truncate_width(&state.picker.url, inner_w),
                    style_fg(BRIGHT_RED),
                )));
            }
            if !state.picker.user_code.is_empty() {
                lines.push(Line::from(Span::raw("")));
                lines.push(Line::from(Span::styled(
                    truncate_width(&format!("Code  {}", state.picker.user_code), inner_w),
                    style_bold(BRIGHT_RED),
                )));
            }
            if !state.picker.err.is_empty() {
                lines.push(Line::from(Span::raw("")));
                lines.push(Line::from(Span::styled(
                    truncate_width(&state.picker.err, inner_w),
                    style_fg(RED),
                )));
            }
            lines.push(Line::from(Span::raw("")));
            lines.push(Line::from(Span::styled("esc cancel", style_dim())));
        }
        PickerPhase::List | PickerPhase::Models => {
            let p_frame = state
                .active_picker_frame()
                .unwrap_or(&state.picker.frame);
            let q = if p_frame.query.is_empty() {
                " ".to_string()
            } else {
                p_frame.query.clone()
            };
            lines.push(Line::from(Span::styled("Search", style_dim())));
            lines.push(Line::from(Span::styled(
                truncate_width(&q, inner_w),
                style_fg(WHITE),
            )));
            lines.push(Line::from(Span::raw("")));

            if !state.picker.note.is_empty() && state.picker.phase == PickerPhase::Models {
                lines.push(Line::from(Span::styled(
                    truncate_width(&state.picker.note, inner_w),
                    style_dim(),
                )));
                lines.push(Line::from(Span::raw("")));
            }

            let rows = p_frame.rows();
            let count = selectable_count(&rows);
            let cursor = if count == 0 {
                0
            } else {
                p_frame.cursor.min(count - 1)
            };

            if rows.is_empty() {
                let msg = if !state.picker.message.is_empty() && p_frame.sections.is_empty() {
                    &state.picker.message
                } else {
                    "No matches"
                };
                lines.push(Line::from(Span::styled(
                    truncate_width(msg, inner_w),
                    style_dim(),
                )));
            } else {
                let mut drawn: Vec<Line<'static>> = Vec::with_capacity(rows.len());
                let mut selected_visual = 0usize;
                for row in rows {
                    if let Some(hdr) = row.header {
                        drawn.push(Line::from(Span::styled(
                            truncate_width(&hdr, inner_w),
                            style_bold(BRIGHT_RED),
                        )));
                        continue;
                    }
                    let Some(entry) = row.entry else {
                        continue;
                    };
                    let label = format!("  {}", entry.label);
                    let is_sel = row.selectable == cursor as isize;
                    if is_sel {
                        selected_visual = drawn.len();
                        drawn.push(Line::from(Span::styled(
                            pad_right_width(&label, inner_w),
                            Style::default()
                                .fg(BRIGHT_WHITE)
                                .bg(CRIMSON)
                                .add_modifier(Modifier::BOLD),
                        )));
                    } else {
                        drawn.push(Line::from(Span::styled(
                            pad_right_width(&label, inner_w),
                            style_fg(TEXT),
                        )));
                    }
                }
                let page = PICKER_PAGE.min((area.height.saturating_sub(12) as usize).max(4));
                let start = if selected_visual >= page {
                    selected_visual - page + 1
                } else {
                    0
                };
                let end = (start + page).min(drawn.len());
                lines.extend(drawn.into_iter().skip(start).take(end - start));
                lines.push(Line::from(Span::raw("")));
                lines.push(Line::from(Span::styled("enter select", style_dim())));
            }
        }
    }

    if !state.picker.err.is_empty() && state.picker.phase != PickerPhase::Wait {
        lines.push(Line::from(Span::styled(
            truncate_width(&state.picker.err, inner_w),
            style_fg(RED),
        )));
    }

    let h = (lines.len() as u16 + 4).min(area.height);
    let rect = centered_rect(area, w, h);
    render_dialog_box(frame, rect, CRIMSON, lines, Alignment::Left);
}

fn draw_toast(frame: &mut Frame, state: &AppState, area: Rect) {
    let txt = truncate_width(&state.toast, area.width.saturating_sub(8) as usize);
    let box_w = (UnicodeWidthStr::width(txt.as_str()) as u16 + 4).min(area.width);
    let box_h = 3u16.min(area.height);
    let x = area.width.saturating_sub(box_w + 2);
    let y = area.height.saturating_sub(box_h + 1);
    let rect = Rect::new(x, y, box_w, box_h);
    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(style_fg(RED))
        .style(Style::default().bg(BLACK).fg(TEXT));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(format!(" {txt} "), style_fg(TEXT)))),
        inner,
    );
}

fn centered_rect(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    let x = area.x + area.width.saturating_sub(w) / 2;
    let y = area.y + area.height.saturating_sub(h) / 2;
    Rect::new(x, y, w, h)
}
