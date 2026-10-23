use crate::protocol::Event;
use crate::theme::*;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use serde_json::{Map, Value};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

pub const SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub fn val_str(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Number(n)) => n.to_string(),
        Some(other) => serde_json::to_string(other).unwrap_or_default(),
    }
}

pub fn val_num(v: Option<&Value>) -> Option<f64> {
    match v {
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(s)) => s.parse::<f64>().ok(),
        _ => None,
    }
}

pub fn strip_controls(s: &str) -> String {
    s.chars()
        .filter(|&c| c == '\n' || c == '\t' || (c as u32) >= 32)
        .collect()
}

pub fn truncate_width(s: &str, max_width: usize) -> String {
    if max_width == 0 {
        return String::new();
    }
    if UnicodeWidthStr::width(s) <= max_width {
        return s.to_string();
    }
    if max_width <= 1 {
        return "…".to_string();
    }
    let mut out = String::new();
    let mut used = 0;
    for ch in s.chars() {
        let w = UnicodeWidthChar::width(ch).unwrap_or(0);
        if used + w > max_width - 1 {
            break;
        }
        out.push(ch);
        used += w;
    }
    out.push('…');
    out
}

pub fn pad_right_width(s: &str, width: usize) -> String {
    let w = UnicodeWidthStr::width(s);
    if w >= width {
        truncate_width(s, width)
    } else {
        format!("{s}{}", " ".repeat(width - w))
    }
}

pub fn wrap_plain_text(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut out = Vec::new();
    for raw_line in text.split('\n') {
        if raw_line.is_empty() {
            out.push(String::new());
            continue;
        }
        if UnicodeWidthStr::width(raw_line) <= width {
            out.push(raw_line.to_string());
            continue;
        }
        let mut cur = String::new();
        let mut cur_w = 0;
        for ch in raw_line.chars() {
            let w = UnicodeWidthChar::width(ch).unwrap_or(0);
            if cur_w + w > width && !cur.is_empty() {
                out.push(cur);
                cur = String::new();
                cur_w = 0;
            }
            cur.push(ch);
            cur_w += w;
        }
        if !cur.is_empty() {
            out.push(cur);
        }
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

pub fn wrap_styled_line(line: Line<'static>, width: usize) -> Vec<Line<'static>> {
    let width = width.max(1);
    let total_w: usize = line
        .spans
        .iter()
        .map(|sp| UnicodeWidthStr::width(sp.content.as_ref()))
        .sum();
    if total_w <= width {
        return vec![line];
    }
    let mut rows: Vec<Line<'static>> = Vec::new();
    let mut cur_spans: Vec<Span<'static>> = Vec::new();
    let mut cur_w = 0usize;

    for span in line.spans {
        let style = span.style;
        let mut seg = String::new();
        for ch in span.content.chars() {
            let cw = UnicodeWidthChar::width(ch).unwrap_or(0);
            if cur_w + cw > width && (cur_w > 0 || !seg.is_empty()) {
                if !seg.is_empty() {
                    cur_spans.push(Span::styled(std::mem::take(&mut seg), style));
                }
                rows.push(Line::from(std::mem::take(&mut cur_spans)));
                cur_w = 0;
            }
            seg.push(ch);
            cur_w += cw;
        }
        if !seg.is_empty() {
            cur_spans.push(Span::styled(seg, style));
        }
    }
    if !cur_spans.is_empty() || rows.is_empty() {
        rows.push(Line::from(cur_spans));
    }
    rows
}

pub fn wrap_styled_lines(lines: Vec<Line<'static>>, width: usize) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    for line in lines {
        out.extend(wrap_styled_line(line, width));
    }
    out
}

fn status_icon(status: &str) -> (&'static str, Color) {
    match status {
        "running" => ("● In progress...", BRIGHT_RED),
        "completed" => ("✓ Done", RED),
        "failed" => ("✗ Failed", SEV_CRIT),
        "error" => ("✗ Error", SEV_CRIT),
        _ => ("○ Unknown", DIM),
    }
}

pub fn is_collapsible_tool(name: &str) -> bool {
    matches!(
        name,
        "exec_command"
            | "write_stdin"
            | "apply_patch"
            | "view_request"
            | "repeat_request"
            | "view_sitemap_entry"
            | "list_coverage"
            | "get_threat_model"
    )
}

pub fn render_event_lines(
    event: &Event,
    expanded: bool,
    live_spinner: bool,
    spinner_frame: usize,
    agent_badge: Option<&str>,
) -> (Vec<Line<'static>>, bool) {
    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut expandable = false;

    match event.event_type.as_str() {
        "chat" => {
            lines = render_chat_event(&event.data);
        }
        "tool" => {
            let name = val_str(event.data.get("tool_name"));
            let full = render_tool_event(&event.data, live_spinner, spinner_frame);
            if is_collapsible_tool(&name) && full.len() > 10 {
                expandable = true;
                if expanded {
                    lines = full;
                    lines.push(Line::from(Span::styled(
                        "  ▲ click to collapse",
                        Style::default().fg(DIM).add_modifier(Modifier::ITALIC),
                    )));
                } else {
                    let hidden = full.len() - 10;
                    let plural = if hidden == 1 { "" } else { "s" };
                    lines = full.into_iter().take(10).collect();
                    lines.push(Line::from(Span::styled(
                        format!("  … +{hidden} line{plural} — click to expand"),
                        Style::default().fg(DIM).add_modifier(Modifier::ITALIC),
                    )));
                }
            } else {
                lines = full;
            }
        }
        _ => {}
    }

    if let Some(badge) = agent_badge {
        if let Some(first) = lines.first_mut() {
            let mut spans = vec![Span::styled(
                format!("[{}] ", badge.to_uppercase()),
                style_bold(BRIGHT_RED),
            )];
            spans.append(&mut first.spans);
            first.spans = spans;
        }
    }

    (lines, expandable)
}

fn render_chat_event(data: &Map<String, Value>) -> Vec<Line<'static>> {
    let role = val_str(data.get("role"));
    let content = strip_controls(&val_str(data.get("content")));
    if role == "user" {
        let mut lines = Vec::new();
        lines.push(Line::from(vec![
            Span::styled("▍ ", style_fg(CRIMSON)),
            Span::styled("You:", style_bold(BRIGHT_WHITE)),
        ]));
        for l in content.split('\n') {
            lines.push(Line::from(vec![
                Span::styled("▍ ", style_fg(CRIMSON)),
                Span::styled(l.to_string(), style_fg(TEXT)),
            ]));
        }
        lines
    } else {
        render_markdown_lines(&content)
    }
}

pub fn render_markdown_lines(content: &str) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let mut in_code = false;
    for raw in content.split('\n') {
        let trimmed = raw.trim_start();
        if trimmed.starts_with("```") {
            in_code = !in_code;
            lines.push(Line::from(Span::styled(raw.to_string(), style_fg(DIM))));
            continue;
        }
        if in_code {
            lines.push(Line::from(Span::styled(
                format!("  {raw}"),
                Style::default().fg(SOFT_RED).bg(DARK_BG),
            )));
            continue;
        }
        if let Some(h) = trimmed.strip_prefix("### ") {
            lines.push(Line::from(Span::styled(
                h.to_string(),
                style_bold(BRIGHT_RED),
            )));
        } else if let Some(h) = trimmed.strip_prefix("## ") {
            lines.push(Line::from(Span::styled(h.to_string(), style_bold(RED))));
        } else if let Some(h) = trimmed.strip_prefix("# ") {
            lines.push(Line::from(Span::styled(
                h.to_string(),
                style_bold(BRIGHT_WHITE),
            )));
        } else if let Some(bullet) = trimmed
            .strip_prefix("- ")
            .or_else(|| trimmed.strip_prefix("* "))
        {
            lines.push(Line::from(vec![
                Span::styled("  • ", style_fg(BRIGHT_RED)),
                Span::styled(bullet.to_string(), style_fg(TEXT)),
            ]));
        } else {
            lines.push(render_inline_markdown(raw));
        }
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::raw("")));
    }
    lines
}

fn render_inline_markdown(line: &str) -> Line<'static> {
    if !line.contains("**") && !line.contains('`') {
        return Line::from(Span::styled(line.to_string(), style_fg(TEXT)));
    }
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut rest = line;
    while !rest.is_empty() {
        if let Some(bold_start) = rest.find("**") {
            let code_start = rest.find('`');
            if code_start.is_none_or(|cs| bold_start <= cs) {
                if bold_start > 0 {
                    spans.push(Span::styled(rest[..bold_start].to_string(), style_fg(TEXT)));
                }
                let after = &rest[bold_start + 2..];
                if let Some(bold_end) = after.find("**") {
                    spans.push(Span::styled(
                        after[..bold_end].to_string(),
                        style_bold(BRIGHT_WHITE),
                    ));
                    rest = &after[bold_end + 2..];
                    continue;
                }
            }
        }
        if let Some(code_start) = rest.find('`') {
            if code_start > 0 {
                spans.push(Span::styled(rest[..code_start].to_string(), style_fg(TEXT)));
            }
            let after = &rest[code_start + 1..];
            if let Some(code_end) = after.find('`') {
                spans.push(Span::styled(
                    after[..code_end].to_string(),
                    Style::default().fg(BRIGHT_RED).bg(DARK_BG),
                ));
                rest = &after[code_end + 1..];
                continue;
            }
        }
        spans.push(Span::styled(rest.to_string(), style_fg(TEXT)));
        break;
    }
    Line::from(spans)
}

fn render_tool_event(
    data: &Map<String, Value>,
    live_spinner: bool,
    spinner_frame: usize,
) -> Vec<Line<'static>> {
    let name = val_str(data.get("tool_name"));
    let status = val_str(data.get("status"));
    let empty_map = Map::new();
    let args = data
        .get("args")
        .and_then(|v| v.as_object())
        .unwrap_or(&empty_map);
    let result = data.get("result");

    let mcp_conn = val_str(data.get("mcp_connection"));
    if !mcp_conn.is_empty() {
        if name == "describe_mcp" {
            let (icon, col) = status_icon(&status);
            return vec![
                Line::from(vec![
                    Span::raw("🔌 "),
                    Span::styled("Inspecting MCP server ", style_dim()),
                    Span::styled(mcp_conn, style_bold(SOFT_RED)),
                ]),
                Line::from(Span::styled(icon.to_string(), style_fg(col))),
            ];
        }
        let mut tool_name = val_str(data.get("mcp_tool"));
        if tool_name.is_empty() {
            tool_name = name.clone();
        }
        let mut lines = vec![Line::from(vec![
            Span::raw("🔌 "),
            Span::styled(tool_name, style_bold(SOFT_RED)),
            Span::styled("  via MCP server ", style_dim()),
            Span::styled(mcp_conn, style_fg(MID)),
        ])];
        for (k, v) in args {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(format!("{k}: "), style_dim()),
                Span::styled(val_str(Some(v)), style_fg(TEXT)),
            ]));
        }
        let (icon, col) = status_icon(&status);
        lines.push(Line::from(Span::styled(icon.to_string(), style_fg(col))));
        return lines;
    }

    match name.as_str() {
        "exec_command" => render_exec_command(args, result, &status),
        "write_stdin" => render_write_stdin(args, result, &status),
        "apply_patch" => render_apply_patch(args, result, &status),
        "think" => {
            let thought = val_str(args.get("thought"));
            let body = if thought.is_empty() {
                "Thinking...".to_string()
            } else {
                thought
            };
            vec![
                Line::from(vec![
                    Span::raw("🧠 "),
                    Span::styled("Thinking", style_bold(BRIGHT_RED)),
                ]),
                Line::from(vec![
                    Span::raw("  "),
                    Span::styled(
                        body,
                        Style::default().fg(DIM).add_modifier(Modifier::ITALIC),
                    ),
                ]),
            ]
        }
        "web_search" => {
            let query = val_str(args.get("query"));
            let mut lines = vec![Line::from(vec![
                Span::raw("🌐 "),
                Span::styled("Searching the web...", style_bold(BRIGHT_RED)),
            ])];
            if !query.is_empty() {
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(query, style_dim()),
                ]));
            }
            lines
        }
        "load_skill" => {
            let skills_str = if let Some(arr) = args.get("skills").and_then(|v| v.as_array()) {
                arr.iter()
                    .map(|x| val_str(Some(x)))
                    .collect::<Vec<_>>()
                    .join(", ")
            } else {
                val_str(args.get("skills"))
            };
            let mut spans = vec![
                Span::styled("◇ ", style_fg(RED)),
                Span::styled("loading skill", style_dim()),
            ];
            if !skills_str.is_empty() {
                spans.push(Span::raw(" "));
                spans.push(Span::styled(skills_str, style_fg(RED)));
            }
            vec![Line::from(spans)]
        }
        "wait_for_user" => vec![Line::from(vec![
            Span::styled("○ ", style_fg(DIM)),
            Span::styled("waiting for your reply", style_dim()),
        ])],
        "respond_to_user" => {
            let mut lines = Vec::new();
            let msg = val_str(args.get("message"));
            if !msg.is_empty() {
                lines.extend(render_markdown_lines(&msg));
                lines.push(Line::from(Span::raw("")));
            }
            lines.push(Line::from(vec![
                Span::styled("○ ", style_fg(DIM)),
                Span::styled("waiting for your reply", style_dim()),
            ]));
            lines
        }
        "finish_scan" => {
            let mut lines = vec![Line::from(vec![
                Span::styled("◆ ", style_fg(RED)),
                Span::styled("Penetration test completed", style_bold(RED)),
            ])];
            for (label, key) in [
                ("Executive Summary", "executive_summary"),
                ("Methodology", "methodology"),
                ("Technical Analysis", "technical_analysis"),
                ("Recommendations", "recommendations"),
            ] {
                let v = val_str(args.get(key));
                if !v.is_empty() {
                    lines.push(Line::from(Span::raw("")));
                    lines.push(Line::from(Span::styled(label, style_bold(BRIGHT_RED))));
                    lines.extend(render_markdown_lines(&v));
                }
            }
            lines
        }
        "create_vulnerability_report" | "update_vulnerability_report" => {
            let heading = if name == "create_vulnerability_report" {
                "Vulnerability Report"
            } else {
                "Vulnerability Report Updated"
            };
            let title = val_str(args.get("title"));
            let target = val_str(args.get("target"));
            let sev = result
                .and_then(|r| r.get("severity"))
                .map(|v| val_str(Some(v)))
                .unwrap_or_else(|| val_str(args.get("severity")));
            let mut lines = vec![Line::from(vec![
                Span::raw("🐞 "),
                Span::styled(heading, style_bold(RED)),
            ])];
            if !title.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("Title: ", style_bold(BRIGHT_RED)),
                    Span::styled(title, style_fg(BRIGHT_WHITE)),
                ]));
            }
            if !sev.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("Severity: ", style_bold(BRIGHT_RED)),
                    Span::styled(sev.to_uppercase(), style_bold(severity_color(&sev))),
                ]));
            }
            if !target.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("Target: ", style_bold(BRIGHT_RED)),
                    Span::styled(target, style_fg(TEXT)),
                ]));
            }
            let desc = val_str(args.get("description"));
            if !desc.is_empty() {
                lines.push(Line::from(Span::styled(
                    "Description",
                    style_bold(BRIGHT_RED),
                )));
                lines.extend(render_markdown_lines(&desc));
            }
            lines
        }
        "delete_vulnerability_report" => {
            let report_id = val_str(args.get("report_id"));
            vec![
                Line::from(vec![
                    Span::raw("🐞 "),
                    Span::styled("Vulnerability Report Deleted", style_bold(RED)),
                ]),
                Line::from(vec![
                    Span::styled("Report: ", style_bold(BRIGHT_RED)),
                    Span::styled(report_id, style_fg(TEXT)),
                ]),
            ]
        }
        "view_agent_graph"
        | "create_agent"
        | "send_message_to_agent"
        | "agent_finish"
        | "wait_for_agents"
        | "stop_agent" => render_agent_graph_tool(&name, args, result, live_spinner, spinner_frame),
        "create_note" | "delete_note" | "update_note" | "list_notes" | "get_note" => {
            let title = val_str(args.get("title"));
            let content = val_str(args.get("content"));
            let mut lines = vec![Line::from(vec![
                Span::styled("◇ ", style_fg(SOFT_RED)),
                Span::styled(name.replace('_', " "), style_dim()),
            ])];
            if !title.is_empty() {
                lines.push(Line::from(Span::styled(
                    format!("  {title}"),
                    style_fg(TEXT),
                )));
            }
            if !content.is_empty() {
                lines.push(Line::from(Span::styled(
                    format!("  {content}"),
                    style_dim(),
                )));
            }
            lines
        }
        "create_todo" | "list_todos" | "update_todo" | "mark_todo_done" | "mark_todo_pending"
        | "delete_todo" => {
            let mut lines = vec![Line::from(vec![
                Span::raw("📋 "),
                Span::styled("Todos", style_bold(SOFT_RED)),
            ])];
            if let Some(todos) = result
                .and_then(|r| r.get("todos"))
                .and_then(|t| t.as_array())
            {
                for t in todos {
                    let st = val_str(t.get("status"));
                    let marker = match st.as_str() {
                        "done" => "[•]",
                        "in_progress" => "[~]",
                        _ => "[ ]",
                    };
                    let title = val_str(t.get("title"));
                    lines.push(Line::from(vec![
                        Span::styled(format!("  {marker} "), style_fg(BRIGHT_RED)),
                        Span::styled(title, style_fg(TEXT)),
                    ]));
                }
            }
            lines
        }
        _ => {
            let mut lines = vec![Line::from(vec![
                Span::styled("→ Using tool ", style_dim()),
                Span::styled(name, style_bold(CRIMSON)),
            ])];
            for (k, v) in args {
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(format!("{k}: "), style_dim()),
                    Span::styled(val_str(Some(v)), style_fg(TEXT)),
                ]));
            }
            let (icon, col) = status_icon(&status);
            lines.push(Line::from(Span::styled(icon.to_string(), style_fg(col))));
            lines
        }
    }
}

fn render_exec_command(
    args: &Map<String, Value>,
    result: Option<&Value>,
    status: &str,
) -> Vec<Line<'static>> {
    let cmd = val_str(args.get("cmd"));
    let wd = val_str(args.get("workdir"));
    let mut header = vec![Span::styled(">_ ", style_dim())];
    if cmd.trim().is_empty() {
        header.push(Span::styled("getting logs...", style_dim()));
    } else {
        header.push(Span::styled("$ ", style_bold(RED)));
        header.push(Span::styled(cmd, style_fg(BRIGHT_WHITE)));
    }
    if !wd.is_empty() {
        header.push(Span::styled(format!("  cwd:{wd}"), style_dim()));
    }
    let mut lines = vec![Line::from(header)];
    append_shell_result(&mut lines, result, status);
    lines
}

fn render_write_stdin(
    args: &Map<String, Value>,
    result: Option<&Value>,
    status: &str,
) -> Vec<Line<'static>> {
    let chars = val_str(args.get("chars"));
    let sid = val_str(args.get("session_id"));
    let mut header = vec![
        Span::styled(">_ ", style_dim()),
        Span::styled(">>> ", style_bold(CRIMSON)),
        Span::styled(chars, style_fg(BRIGHT_WHITE)),
    ];
    if !sid.is_empty() {
        header.push(Span::styled(format!("  session #{sid}"), style_dim()));
    }
    let mut lines = vec![Line::from(header)];
    append_shell_result(&mut lines, result, status);
    lines
}

fn append_shell_result(lines: &mut Vec<Line<'static>>, result: Option<&Value>, _status: &str) {
    let Some(res) = result else {
        return;
    };
    let raw = if let Some(obj) = res.as_object() {
        val_str(obj.get("content"))
    } else if let Some(s) = res.as_str() {
        if let Some(idx) = s.find("\nOutput:\n") {
            s[idx + "\nOutput:\n".len()..].to_string()
        } else {
            s.to_string()
        }
    } else {
        val_str(Some(res))
    };

    let cleaned: Vec<&str> = raw
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty()
                && t != "Output:"
                && !t.starts_with("Chunk ID:")
                && !t.starts_with("Wall time:")
                && !t.starts_with("Process exited with code")
                && !t.starts_with("Process running with session ID")
                && !t.starts_with("Original token count:")
        })
        .collect();

    if cleaned.is_empty() {
        return;
    }
    let max_lines = 50usize;
    if cleaned.len() <= max_lines {
        for l in cleaned {
            let clipped = if l.len() > 200 {
                format!("{}...", &l[..197])
            } else {
                l.to_string()
            };
            lines.push(Line::from(Span::styled(
                format!("  {clipped}"),
                style_dim(),
            )));
        }
    } else {
        let head = 25;
        let tail = 24;
        for l in &cleaned[..head] {
            lines.push(Line::from(Span::styled(format!("  {l}"), style_dim())));
        }
        lines.push(Line::from(Span::styled(
            format!("  ... {} lines truncated ...", cleaned.len() - head - tail),
            Style::default().fg(DIM).add_modifier(Modifier::ITALIC),
        )));
        for l in &cleaned[cleaned.len() - tail..] {
            lines.push(Line::from(Span::styled(format!("  {l}"), style_dim())));
        }
    }
}

fn render_apply_patch(
    args: &Map<String, Value>,
    result: Option<&Value>,
    status: &str,
) -> Vec<Line<'static>> {
    let patch = val_str(args.get("patch")).trim().to_string();
    let mut lines = vec![Line::from(vec![
        Span::styled("◇ ", style_fg(RED)),
        Span::styled("patch", style_dim()),
    ])];
    if !patch.is_empty() {
        for l in patch.lines().take(24) {
            if l.starts_with('+') && !l.starts_with("+++") {
                lines.push(Line::from(Span::styled(
                    format!("  {l}"),
                    style_fg(BRIGHT_RED),
                )));
            } else if l.starts_with('-') && !l.starts_with("---") {
                lines.push(Line::from(Span::styled(
                    format!("  {l}"),
                    style_fg(CRIMSON),
                )));
            } else {
                lines.push(Line::from(Span::styled(format!("  {l}"), style_dim())));
            }
        }
    } else if status == "failed" {
        let s = val_str(result);
        if !s.is_empty() {
            lines.push(Line::from(Span::styled(format!("  {s}"), style_fg(RED))));
        }
    }
    lines
}

fn render_agent_graph_tool(
    name: &str,
    args: &Map<String, Value>,
    _result: Option<&Value>,
    live_spinner: bool,
    spinner_frame: usize,
) -> Vec<Line<'static>> {
    match name {
        "view_agent_graph" => vec![Line::from(vec![
            Span::styled("◇ ", style_fg(SOFT_RED)),
            Span::styled("viewing agents graph", style_dim()),
        ])],
        "create_agent" => {
            let mut agent_name = val_str(args.get("name"));
            if agent_name.is_empty() {
                agent_name = "Agent".to_string();
            }
            let mut lines = vec![Line::from(vec![
                Span::styled("◈ ", style_fg(SOFT_RED)),
                Span::styled("spawning ", style_dim()),
                Span::styled(agent_name, style_bold(SOFT_RED)),
            ])];
            let task = val_str(args.get("task"));
            if !task.is_empty() {
                lines.push(Line::from(Span::styled(format!("  {task}"), style_dim())));
            }
            lines
        }
        "send_message_to_agent" => {
            let target = val_str(args.get("target_agent_id"));
            let mut lines = vec![Line::from(vec![
                Span::styled("→ ", style_fg(BRIGHT_RED)),
                Span::styled(
                    if target.is_empty() {
                        "sending message".to_string()
                    } else {
                        format!("to {target}")
                    },
                    style_dim(),
                ),
            ])];
            let msg = val_str(args.get("message"));
            if !msg.is_empty() {
                lines.push(Line::from(Span::styled(format!("  {msg}"), style_dim())));
            }
            lines
        }
        "agent_finish" => {
            let success = args
                .get("success")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let mut lines = vec![Line::from(vec![
                Span::styled("◆ ", style_fg(if success { RED } else { SEV_CRIT })),
                Span::styled(
                    if success {
                        "Agent completed"
                    } else {
                        "Agent failed"
                    },
                    style_bold(if success { RED } else { SEV_CRIT }),
                ),
            ])];
            let summary = val_str(args.get("result_summary"));
            if !summary.is_empty() {
                lines.push(Line::from(Span::styled(
                    format!("  {summary}"),
                    style_bold(BRIGHT_WHITE),
                )));
            }
            lines
        }
        "wait_for_agents" => {
            let glyph = if live_spinner {
                SPINNER_FRAMES[spinner_frame % SPINNER_FRAMES.len()]
            } else {
                "○"
            };
            let mut lines = vec![Line::from(vec![
                Span::styled(format!("{glyph} "), style_fg(DIM)),
                Span::styled("waiting", style_dim()),
            ])];
            let reason = val_str(args.get("reason"));
            if !reason.is_empty() {
                lines.push(Line::from(Span::styled(format!("  {reason}"), style_dim())));
            }
            lines
        }
        "stop_agent" => {
            let target = val_str(args.get("target_agent_id"));
            vec![Line::from(vec![
                Span::styled("◼ ", style_fg(RED)),
                Span::styled("stopping ", style_dim()),
                Span::styled(target, style_bold(RED)),
            ])]
        }
        _ => vec![],
    }
}

pub fn cvss_vector_parts(bd: &Map<String, Value>) -> Vec<String> {
    let keys = [
        ("attack_vector", "AV"),
        ("attack_complexity", "AC"),
        ("privileges_required", "PR"),
        ("user_interaction", "UI"),
        ("scope", "S"),
        ("confidentiality", "C"),
        ("integrity", "I"),
        ("availability", "A"),
    ];
    let mut parts = Vec::new();
    for (k, short) in keys {
        let v = val_str(bd.get(k));
        if !v.is_empty() {
            parts.push(format!("{short}:{v}"));
        }
    }
    parts
}

pub fn title_case_words(s: &str) -> String {
    s.split_whitespace()
        .map(|w| {
            let mut chars = w.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => {
                    first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase()
                }
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn vulnerability_detail_lines(v: &Map<String, Value>) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(vec![
        Span::raw("🐞 "),
        Span::styled("Vulnerability Report", style_bold(RED)),
    ])];

    let push_field = |lines: &mut Vec<Line<'static>>, label: &str, value: String| {
        if !value.is_empty() {
            lines.push(Line::from(Span::raw("")));
            lines.push(Line::from(vec![
                Span::styled(format!("{label}: "), style_bold(BRIGHT_RED)),
                Span::styled(value, style_fg(TEXT)),
            ]));
        }
    };

    push_field(&mut lines, "Agent", val_str(v.get("agent_name")));
    push_field(&mut lines, "Title", val_str(v.get("title")));

    let sev = val_str(v.get("severity"));
    if !sev.is_empty() {
        lines.push(Line::from(Span::raw("")));
        lines.push(Line::from(vec![
            Span::styled("Severity: ", style_bold(BRIGHT_RED)),
            Span::styled(sev.to_uppercase(), style_bold(severity_color(&sev))),
        ]));
    }
    if let Some(score) = val_num(v.get("cvss")) {
        lines.push(Line::from(Span::raw("")));
        lines.push(Line::from(vec![
            Span::styled("CVSS Score: ", style_bold(BRIGHT_RED)),
            Span::styled(val_str(v.get("cvss")), style_bold(cvss_color(score))),
        ]));
    }
    push_field(&mut lines, "Target", val_str(v.get("target")));
    if let Some(dep) = v.get("dependency_metadata").and_then(|d| d.as_object()) {
        push_field(&mut lines, "Package", val_str(dep.get("package_name")));
        push_field(
            &mut lines,
            "Ecosystem",
            val_str(dep.get("package_ecosystem")),
        );
        push_field(
            &mut lines,
            "Installed Version",
            val_str(dep.get("installed_version")),
        );
        push_field(
            &mut lines,
            "Fixed Version",
            val_str(dep.get("fixed_version")),
        );
        push_field(
            &mut lines,
            "Introduced By",
            val_str(dep.get("introduced_by")),
        );
        push_field(
            &mut lines,
            "Dependency Chain",
            val_str(dep.get("dependency_path")),
        );
    }
    push_field(&mut lines, "Endpoint", val_str(v.get("endpoint")));
    push_field(&mut lines, "Method", val_str(v.get("method")));
    push_field(&mut lines, "CVE", val_str(v.get("cve")));
    push_field(&mut lines, "CWE", val_str(v.get("cwe")));
    let fe = val_str(v.get("fix_effort"));
    if !fe.is_empty() {
        push_field(&mut lines, "Fix Effort", title_case_words(&fe));
    }
    if let Some(bd) = v.get("cvss_breakdown").and_then(|b| b.as_object()) {
        let parts = cvss_vector_parts(bd);
        if !parts.is_empty() {
            lines.push(Line::from(Span::raw("")));
            lines.push(Line::from(vec![
                Span::styled("CVSS Vector: ", style_bold(BRIGHT_RED)),
                Span::styled(parts.join("/"), style_dim()),
            ]));
        }
    }

    for (label, key) in [
        ("Description", "description"),
        ("Impact", "impact"),
        ("Technical Analysis", "technical_analysis"),
        ("Evidence", "evidence"),
        ("PoC Description", "poc_description"),
        ("PoC Code", "poc_script_code"),
        ("Remediation", "remediation_steps"),
        ("Assumptions", "assumptions"),
    ] {
        let val = val_str(v.get(key));
        if !val.is_empty() {
            lines.push(Line::from(Span::raw("")));
            lines.push(Line::from(Span::styled(label, style_bold(BRIGHT_RED))));
            for l in val.split('\n') {
                lines.push(Line::from(Span::styled(l.to_string(), style_fg(TEXT))));
            }
        }
    }

    lines
}

pub fn vulnerability_markdown_report(v: &Map<String, Value>) -> String {
    let mut lines: Vec<String> = Vec::new();
    let mut title = val_str(v.get("title"));
    if title.is_empty() {
        title = "Untitled Vulnerability".to_string();
    }
    lines.push(format!("# {title}"));
    lines.push(String::new());

    let mut push_field = |label: &str, value: String| {
        if !value.is_empty() {
            lines.push(format!("**{label}:** {value}"));
        }
    };
    push_field("ID", val_str(v.get("id")));
    push_field("Severity", val_str(v.get("severity")).to_uppercase());
    push_field("Found", val_str(v.get("timestamp")));
    push_field("Agent", val_str(v.get("agent_name")));
    push_field("Target", val_str(v.get("target")));
    if let Some(dep) = v.get("dependency_metadata").and_then(|d| d.as_object()) {
        push_field("Package", val_str(dep.get("package_name")));
        push_field("Ecosystem", val_str(dep.get("package_ecosystem")));
        push_field("Installed Version", val_str(dep.get("installed_version")));
        push_field("Fixed Version", val_str(dep.get("fixed_version")));
        push_field("Introduced By", val_str(dep.get("introduced_by")));
        push_field("Dependency Chain", val_str(dep.get("dependency_path")));
    }
    push_field("Endpoint", val_str(v.get("endpoint")));
    push_field("Method", val_str(v.get("method")));
    push_field("CVE", val_str(v.get("cve")));
    push_field("CWE", val_str(v.get("cwe")));
    push_field("CVSS", val_str(v.get("cvss")));
    let fe = val_str(v.get("fix_effort"));
    if !fe.is_empty() {
        push_field("Fix Effort", title_case_words(&fe));
    }
    if let Some(bd) = v.get("cvss_breakdown").and_then(|b| b.as_object()) {
        let parts = cvss_vector_parts(bd);
        if !parts.is_empty() {
            push_field("CVSS Vector", parts.join("/"));
        }
    }

    let mut desc = val_str(v.get("description"));
    if desc.is_empty() {
        desc = "No description provided.".to_string();
    }
    lines.push(String::new());
    lines.push("## Description".to_string());
    lines.push(String::new());
    lines.push(desc);

    for (label, key) in [
        ("Impact", "impact"),
        ("Technical Analysis", "technical_analysis"),
        ("Evidence", "evidence"),
    ] {
        let val = val_str(v.get(key));
        if !val.is_empty() {
            lines.push(String::new());
            lines.push(format!("## {label}"));
            lines.push(String::new());
            lines.push(val);
        }
    }

    let poc_desc = val_str(v.get("poc_description"));
    let poc_code = val_str(v.get("poc_script_code"));
    if !poc_desc.is_empty() || !poc_code.is_empty() {
        lines.push(String::new());
        lines.push("## Proof of Concept".to_string());
        lines.push(String::new());
        if !poc_desc.is_empty() {
            lines.push(poc_desc);
            lines.push(String::new());
        }
        if !poc_code.is_empty() {
            let (mut lang, code_body) = parse_fenced_code(&poc_code);
            if lang.is_empty() {
                lang = "python".to_string();
            }
            let fence = safe_fence(&code_body);
            lines.push(format!("{fence}{lang}"));
            lines.push(code_body);
            lines.push(fence);
        }
    }

    for (label, key) in [
        ("Remediation", "remediation_steps"),
        ("Assumptions", "assumptions"),
    ] {
        let val = val_str(v.get(key));
        if !val.is_empty() {
            lines.push(String::new());
            lines.push(format!("## {label}"));
            lines.push(String::new());
            lines.push(val);
        }
    }

    lines.push(String::new());
    lines.join("\n")
}

pub fn safe_fence(content: &str) -> String {
    let mut longest = 0usize;
    let mut cur = 0usize;
    for ch in content.chars() {
        if ch == '`' {
            cur += 1;
            if cur > longest {
                longest = cur;
            }
        } else {
            cur = 0;
        }
    }
    "`".repeat(3usize.max(longest + 1))
}

pub fn parse_fenced_code(raw: &str) -> (String, String) {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("```") {
        if let Some((first_line, body)) = rest.split_once('\n') {
            let lang = first_line.trim().to_string();
            let code = body
                .strip_suffix("```")
                .unwrap_or(body)
                .trim_end_matches('\n');
            return (lang, code.to_string());
        }
    }
    (String::new(), raw.to_string())
}
