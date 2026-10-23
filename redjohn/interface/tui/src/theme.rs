use ratatui::style::{Color, Modifier, Style};

// RedJohn Native Palette — Zero Green, Pure Arterial Red / Bright Red / White
pub const BLACK: Color = Color::Rgb(0, 0, 0);
pub const DARK_BG: Color = Color::Rgb(10, 10, 10);
pub const DARK_BORDER: Color = Color::Rgb(51, 51, 51);
pub const DIM: Color = Color::Rgb(115, 115, 115);
pub const MID: Color = Color::Rgb(163, 163, 163);
pub const TEXT: Color = Color::Rgb(212, 212, 212);
pub const WHITE: Color = Color::Rgb(250, 250, 249);
pub const BRIGHT_WHITE: Color = Color::Rgb(255, 255, 255);

pub const RED: Color = Color::Rgb(239, 68, 68); // #ef4444
pub const BRIGHT_RED: Color = Color::Rgb(248, 113, 113); // #f87171
pub const SOFT_RED: Color = Color::Rgb(252, 165, 165); // #fca5a5
pub const CRIMSON: Color = Color::Rgb(220, 38, 38); // #dc2626
pub const DARK_CRIMSON: Color = Color::Rgb(127, 29, 29); // #7f1d1d

pub const SEV_CRIT: Color = Color::Rgb(220, 38, 38);
pub const SEV_HIGH: Color = Color::Rgb(239, 68, 68);
pub const SEV_MED: Color = Color::Rgb(248, 113, 113);
pub const SEV_LOW: Color = Color::Rgb(252, 165, 165);
pub const SEV_INFO: Color = Color::Rgb(161, 161, 170);

pub fn severity_color(sev: &str) -> Color {
    match sev.trim().to_ascii_lowercase().as_str() {
        "critical" => SEV_CRIT,
        "high" => SEV_HIGH,
        "medium" => SEV_MED,
        "low" => SEV_LOW,
        "info" => SEV_INFO,
        _ => MID,
    }
}

pub fn cvss_color(score: f64) -> Color {
    if score >= 9.0 {
        SEV_CRIT
    } else if score >= 7.0 {
        SEV_HIGH
    } else if score >= 4.0 {
        SEV_MED
    } else if score >= 0.1 {
        SEV_LOW
    } else {
        MID
    }
}

pub fn style_fg(c: Color) -> Style {
    Style::default().fg(c)
}

pub fn style_bold(c: Color) -> Style {
    Style::default().fg(c).add_modifier(Modifier::BOLD)
}

pub fn style_dim() -> Style {
    Style::default().fg(DIM)
}

pub const SMILEY_ROWS: &[&str] = &[
    "        ▄▄█████▄▄▄▄        ",
    "    ▄█████▀▀▀▀▀▀▀████▄     ",
    "  ▄████▀▀          ▀██▄▄   ",
    " ████▀          ▄▄▄  ▀███  ",
    "▄███▀   ▄██▄   █████   ██▄ ",
    "████   █████   ▀███▀  ▄███ ",
    " ███   ▀███      ██  ▄█▀██ ",
    " ███ ▄█▄ █        ▄▄██▀ ██ ",
    " ▀███▀█████▄▄▄▄▄████▀  ▄█▀ ",
    "  ▀████ ▀▀▀████▀▀▀▀  ▄██▀  ",
    "    █▀██▄▄▄▄▄▄ ▄▄▄▄███▀    ",
    "       ▀▀▀▀▀▀████▀▀▀       ",
    "             █  ▀          ",
];

pub const BANNER_ROWS: &[&str] = &[
    "█████▄  ██████  █████▄      ██  ▄████▄  ██  ██  ███  ██",
    "██  ██  ██      ██  ██      ██  ██  ██  ██  ██  ████ ██",
    "█████▀  █████   ██  ██      ██  ██  ██  ██████  ██ ████",
    "██  ██  ██      ██  ██  ██  ██  ██  ██  ██  ██  ██  ███",
    "██  ██  ██████  █████▀  ▀████▀  ▀████▀  ██  ██  ██   ██",
];

pub fn short_model_name(model: &str) -> String {
    let raw = model.trim();
    if raw.is_empty() {
        return String::new();
    }
    let mut slug = raw.rsplit('/').next().unwrap_or(raw);
    if let Some((head, _)) = slug.split_once(':') {
        if !head.is_empty() {
            slug = head;
        }
    }
    let lower = slug.to_ascii_lowercase();
    let mappings: &[(&str, &str)] = &[
        ("qwen3.5", "Qwen3.5"),
        ("qwen3", "Qwen3"),
        ("qwen2.5", "Qwen2.5"),
        ("glm-5.3", "GLM5.3"),
        ("glm5.3", "GLM5.3"),
        ("glm-5.1", "GLM5.1"),
        ("glm5.1", "GLM5.1"),
        ("glm-5", "GLM5"),
        ("glm5", "GLM5"),
        ("glm-4.7", "GLM4.7"),
        ("glm-4.6", "GLM4.6"),
        ("glm-4.5", "GLM4.5"),
        ("claude-opus-4-7", "Opus 4.7"),
        ("claude-opus-4-6", "Opus 4.6"),
        ("claude-sonnet-4-6", "Sonnet 4.6"),
        ("claude-sonnet-4-5", "Sonnet 4.5"),
        ("claude-haiku-4-5", "Haiku 4.5"),
        ("kimi-k2.5", "Kimi K2.5"),
        ("kimi-k2", "Kimi K2"),
        ("deepseek-flash", "DeepSeek-V4.1-Flash"),
        ("deepseek-v4.1-flash", "DeepSeek-V4.1-Flash"),
        ("deepseek-v4-pro", "DeepSeek-V4-Pro"),
        ("deepseek-r1", "DeepSeek R1"),
        ("deepseek-v3", "DeepSeek V3"),
        ("grok-4", "Grok 4"),
        ("grok-3", "Grok 3"),
        ("mimo-v2-pro", "MiMo V2 Pro"),
        ("mimo-v2-omni", "MiMo V2 Omni"),
        ("mimo-v2-flash", "MiMo V2 Flash"),
        ("gpt-5.4", "GPT-5.4"),
        ("gpt-5.3-codex", "GPT-5.3 Codex"),
        ("gpt-5.2-codex", "GPT-5.2 Codex"),
        ("gpt-5.2", "GPT-5.2"),
        ("gpt-5.1-codex", "GPT-5.1 Codex"),
        ("gpt-5", "GPT-5"),
        ("gemini-3.1-pro", "Gemini 3.1 Pro"),
        ("gemini-3-flash", "Gemini 3 Flash"),
        ("gemini-2.5-pro", "Gemini 2.5 Pro"),
        ("gemini-2.5-flash", "Gemini 2.5 Flash"),
    ];
    for (prefix, label) in mappings {
        if lower.starts_with(prefix) {
            return (*label).to_string();
        }
    }
    if slug.chars().count() > 18 {
        let parts: Vec<&str> = slug.split('-').collect();
        if parts.len() >= 2 {
            let candidate = format!("{}-{}", parts[0], parts[1]);
            if candidate.chars().count() <= 18 {
                return candidate;
            }
        }
        return slug.chars().take(18).collect();
    }
    slug.to_string()
}
