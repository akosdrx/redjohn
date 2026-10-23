use crate::ipc::Client;
use crate::protocol::*;
use crate::render::{val_str, vulnerability_markdown_report};
use crate::theme::short_model_name;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const PICKER_PAGE: usize = 12;
pub const EFFORT_LEVELS: &[&str] = &["none", "minimal", "low", "medium", "high", "xhigh", "max"];
pub const SLASH_COMMANDS: &[&str] = &[
    "/models",
    "/effort",
    "/swarm",
    "/openviking",
    "/skills",
    "/findings",
    "/mcp",
    "/rj",
];

pub const SWARM_PROFILES: &[&str] = &[
    "full", "balanced", "deep", "recon", "exploit", "whitebox", "fast", "single",
];

pub const REPORT_PREV: &str = "‹ Prev";
pub const REPORT_NEXT: &str = "Next ›";
pub const REPORT_COPY: &str = "Copy";
pub const REPORT_DONE: &str = "Done";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModalMode {
    None,
    Help,
    Quit,
    Stop,
    ConfirmMount,
    Vulnerability,
    Picker,
    Skills,
    Mcp,
    Findings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusMode {
    Input,
    Chat,
    Agents,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickerPhase {
    List,
    Key,
    Wait,
    Models,
}

#[derive(Debug, Clone, Default)]
pub struct PickerFrame {
    pub title: String,
    pub sections: Vec<PickerSection>,
    pub cursor: usize,
    pub query: String,
}

#[derive(Debug, Clone)]
pub struct PickerRow {
    pub header: Option<String>,
    pub entry: Option<PickerEntry>,
    pub selectable: isize,
}

impl PickerFrame {
    pub fn rows(&self) -> Vec<PickerRow> {
        let q = self.query.trim().to_ascii_lowercase();
        let mut rows = Vec::new();
        let mut selectable = 0isize;
        for section in &self.sections {
            let matched: Vec<PickerEntry> = section
                .entries
                .iter()
                .filter(|e| q.is_empty() || e.label.to_ascii_lowercase().contains(&q))
                .cloned()
                .collect();
            if matched.is_empty() {
                continue;
            }
            if !section.title.trim().is_empty() {
                rows.push(PickerRow {
                    header: Some(section.title.clone()),
                    entry: None,
                    selectable: -1,
                });
            }
            for entry in matched {
                rows.push(PickerRow {
                    header: None,
                    entry: Some(entry),
                    selectable,
                });
                selectable += 1;
            }
        }
        rows
    }
}

pub fn selectable_count(rows: &[PickerRow]) -> usize {
    rows.iter().filter(|r| r.selectable >= 0).count()
}

#[derive(Debug, Clone)]
pub struct PickerState {
    pub phase: PickerPhase,
    pub title: String,
    pub scope: String,
    pub stack: Vec<PickerFrame>,
    pub frame: PickerFrame,
    pub models: PickerFrame,
    pub key: String,
    pub url: String,
    pub user_code: String,
    pub message: String,
    pub note: String,
    pub err: String,
    pub poll_in_flight: bool,
    pub last_poll: Option<Instant>,
    pub leaf_id: String,
}

impl Default for PickerState {
    fn default() -> Self {
        Self {
            phase: PickerPhase::List,
            title: String::new(),
            scope: "both".to_string(),
            stack: Vec::new(),
            frame: PickerFrame::default(),
            models: PickerFrame::default(),
            key: String::new(),
            url: String::new(),
            user_code: String::new(),
            message: String::new(),
            note: String::new(),
            err: String::new(),
            poll_in_flight: false,
            last_poll: None,
            leaf_id: String::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AgentTreeEntry {
    pub index: usize,
    pub prefix: String,
}

pub fn agent_tree_entries(agents: &[Agent], collapsed: &HashSet<String>) -> Vec<AgentTreeEntry> {
    let mut index_by_id = HashMap::with_capacity(agents.len());
    for (i, ag) in agents.iter().enumerate() {
        index_by_id.insert(ag.id.as_str(), i);
    }
    let mut children: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut roots = Vec::new();
    for (i, ag) in agents.iter().enumerate() {
        let mut parent_idx = None;
        if let Some(pid) = ag.parent_id.as_deref() {
            if let Some(&cand) = index_by_id.get(pid) {
                if cand != i {
                    parent_idx = Some(cand);
                }
            }
        }
        if let Some(p) = parent_idx {
            children.entry(p).or_default().push(i);
        } else {
            roots.push(i);
        }
    }

    let mut entries = Vec::with_capacity(agents.len());
    let mut visited = vec![false; agents.len()];

    fn hide_descendants(idx: usize, children: &HashMap<usize, Vec<usize>>, visited: &mut [bool]) {
        if let Some(ch) = children.get(&idx) {
            for &c in ch {
                if !visited[c] {
                    visited[c] = true;
                    hide_descendants(c, children, visited);
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn walk(
        idx: usize,
        depth: usize,
        continuations: &[bool],
        is_last: bool,
        agents: &[Agent],
        collapsed: &HashSet<String>,
        children: &HashMap<usize, Vec<usize>>,
        visited: &mut [bool],
        entries: &mut Vec<AgentTreeEntry>,
    ) {
        if visited[idx] {
            return;
        }
        visited[idx] = true;
        let mut prefix = String::new();
        if depth > 0 {
            for &cont in continuations {
                if cont {
                    prefix.push_str("│  ");
                } else {
                    prefix.push_str("   ");
                }
            }
            if is_last {
                prefix.push_str("└─ ");
            } else {
                prefix.push_str("├─ ");
            }
        }
        entries.push(AgentTreeEntry { index: idx, prefix });
        if collapsed.contains(&agents[idx].id) {
            hide_descendants(idx, children, visited);
            return;
        }
        let mut next_cont = continuations.to_vec();
        if depth > 0 {
            next_cont.push(!is_last);
        }
        if let Some(ch) = children.get(&idx) {
            for (ci, &child) in ch.iter().enumerate() {
                walk(
                    child,
                    depth + 1,
                    &next_cont,
                    ci + 1 == ch.len(),
                    agents,
                    collapsed,
                    children,
                    visited,
                    entries,
                );
            }
        }
    }

    for (ri, &root) in roots.iter().enumerate() {
        walk(
            root,
            0,
            &[],
            ri + 1 == roots.len(),
            agents,
            collapsed,
            &children,
            &mut visited,
            &mut entries,
        );
    }
    for i in 0..agents.len() {
        if !visited[i] {
            walk(
                i,
                0,
                &[],
                true,
                agents,
                collapsed,
                &children,
                &mut visited,
                &mut entries,
            );
        }
    }
    entries
}

pub fn has_agent_children(agent_id: &str, agents: &[Agent]) -> bool {
    agents
        .iter()
        .any(|a| a.parent_id.as_deref() == Some(agent_id))
}

#[derive(Debug, Default)]
pub struct CollectionAssembly {
    pub kind: String,
    pub revision: i64,
    pub base_revision: i64,
    pub cursor: usize,
    pub agents: Vec<Agent>,
    pub events: Vec<Event>,
    pub findings: Vec<Map<String, Value>>,
    pub operations: Vec<CollectionOperation>,
    pub ids: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct SetupLogEntry {
    pub text: String,
    pub level: String,
}

pub struct AppState {
    pub client: Option<Client>,
    pub app_version: String,
    pub width: u16,
    pub height: u16,
    pub snapshot: Snapshot,
    pub input_text: String,
    pub input_cursor: usize,
    pub input_history: Vec<String>,
    pub history_cursor: Option<usize>,
    pub input_draft: String,
    pub modal: ModalMode,
    pub focus: FocusMode,
    pub collapsed_agents: HashSet<String>,
    pub sidebar_hidden: bool,
    pub expanded_events: HashSet<String>,
    pub setup_log: Vec<SetupLogEntry>,
    pub pending_prompt: String,
    pub error_text: String,
    pub fatal_error: Option<String>,
    pub selected_agent: usize,
    pub all_agents_view: bool,
    pub selected_vuln: usize,
    pub mcp_offset: usize,
    pub chat_scroll: usize,
    pub chat_total_lines: usize,
    pub chat_visible_lines: usize,
    pub vuln_report_scroll: usize,
    pub modal_choice: usize,
    pub report_focus: String,
    pub ready: bool,
    pub quitting: bool,
    pub show_splash: bool,
    pub splash_started: Instant,
    pub splash_frame: usize,
    pub sweep_frame: usize,
    pub budget_pause_notified: bool,
    pub follow_output: bool,
    pub toast: String,
    pub toast_expires: Option<Instant>,
    pub state_revision: i64,
    pub collection_revisions: HashMap<String, i64>,
    pub collection_assemblies: HashMap<String, CollectionAssembly>,
    pub resync_requested: HashMap<String, bool>,
    pub resync_requests: HashMap<String, String>,
    pub seen_messages: HashSet<String>,
    pub vulnerability_copied: bool,
    pub vulnerability_copy_error: String,
    pub picker: PickerState,
    pub skill_catalog: Vec<SkillEntry>,
    pub skill_selected: usize,
}

fn command_history_path() -> Option<std::path::PathBuf> {
    if let Ok(custom) = std::env::var("REDJOHN_COMMAND_HISTORY_PATH") {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return Some(std::path::PathBuf::from(trimmed));
        }
    }
    let home = std::env::var("HOME")
        .ok()
        .or_else(|| std::env::var("USERPROFILE").ok())?;
    if home.trim().is_empty() {
        return None;
    }
    Some(
        std::path::PathBuf::from(home)
            .join(".redjohn")
            .join("command_history.json"),
    )
}

fn load_command_history() -> Vec<String> {
    let Some(path) = command_history_path() else {
        return Vec::new();
    };
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    serde_json::from_str::<Vec<String>>(&raw)
        .unwrap_or_default()
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn save_command_history(history: &[String]) {
    let Some(path) = command_history_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(serialized) = serde_json::to_string_pretty(history) {
        let _ = std::fs::write(path, serialized);
    }
}

impl AppState {
    pub fn new(client: Option<Client>, version: Option<String>) -> Self {
        let mut app_version = "dev".to_string();
        if let Some(v) = version {
            let t = v.trim();
            if !t.is_empty() {
                app_version = t.to_string();
            }
        }
        Self {
            client,
            app_version,
            width: 120,
            height: 40,
            snapshot: Snapshot::default(),
            input_text: String::new(),
            input_cursor: 0,
            input_history: load_command_history(),
            history_cursor: None,
            input_draft: String::new(),
            modal: ModalMode::None,
            focus: FocusMode::Input,
            collapsed_agents: HashSet::new(),
            sidebar_hidden: false,
            expanded_events: HashSet::new(),
            setup_log: Vec::new(),
            pending_prompt: String::new(),
            error_text: String::new(),
            fatal_error: None,
            selected_agent: 0,
            all_agents_view: false,
            selected_vuln: 0,
            mcp_offset: 0,
            chat_scroll: 0,
            chat_total_lines: 0,
            chat_visible_lines: 20,
            vuln_report_scroll: 0,
            modal_choice: 1,
            report_focus: REPORT_DONE.to_string(),
            ready: false,
            quitting: false,
            show_splash: true,
            splash_started: Instant::now(),
            splash_frame: 0,
            sweep_frame: 0,
            budget_pause_notified: false,
            follow_output: true,
            toast: String::new(),
            toast_expires: None,
            state_revision: 0,
            collection_revisions: HashMap::new(),
            collection_assemblies: HashMap::new(),
            resync_requested: HashMap::new(),
            resync_requests: HashMap::new(),
            seen_messages: HashSet::new(),
            vulnerability_copied: false,
            vulnerability_copy_error: String::new(),
            picker: PickerState::default(),
            skill_catalog: Vec::new(),
            skill_selected: 0,
        }
    }

    pub fn record_history(&mut self, value: &str) {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return;
        }
        self.input_history.retain(|item| item != trimmed);
        self.input_history.push(trimmed.to_string());
        if self.input_history.len() > 200 {
            let drain_count = self.input_history.len() - 200;
            self.input_history.drain(0..drain_count);
        }
        self.history_cursor = None;
        self.input_draft.clear();
        save_command_history(&self.input_history);
    }

    pub fn history_prev(&mut self) {
        if self.input_history.is_empty() {
            return;
        }
        let next_idx = match self.history_cursor {
            None => {
                self.input_draft = self.input_text.clone();
                self.input_history.len() - 1
            }
            Some(cur) => cur.saturating_sub(1),
        };
        self.history_cursor = Some(next_idx);
        if let Some(entry) = self.input_history.get(next_idx) {
            self.input_text = entry.clone();
            self.input_cursor = self.input_text.len();
        }
    }

    pub fn history_next(&mut self) {
        let Some(cur) = self.history_cursor else {
            return;
        };
        if cur + 1 < self.input_history.len() {
            let next_idx = cur + 1;
            self.history_cursor = Some(next_idx);
            if let Some(entry) = self.input_history.get(next_idx) {
                self.input_text = entry.clone();
                self.input_cursor = self.input_text.len();
            }
        } else {
            self.history_cursor = None;
            self.input_text = std::mem::take(&mut self.input_draft);
            self.input_cursor = self.input_text.len();
        }
    }

    pub fn version_label(&self) -> String {
        let v = self.app_version.trim();
        if v.is_empty() || v == "dev" {
            return "dev".to_string();
        }
        if v.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            return format!("v{v}");
        }
        v.to_string()
    }

    pub fn registered_skill_count(&self) -> usize {
        self.snapshot.skill_count.max(self.snapshot.skills.len())
    }

    pub fn display_model_name(&self) -> String {
        let s = self.snapshot.short_model.trim();
        if !s.is_empty() {
            return s.to_string();
        }
        short_model_name(&self.snapshot.model)
    }

    pub fn display_swarm_model_name(&self) -> String {
        let s = self.snapshot.short_swarm_model.trim();
        if !s.is_empty() {
            return s.to_string();
        }
        short_model_name(&self.snapshot.swarm_model)
    }

    pub fn display_swarm_profile(&self) -> String {
        let p = self.snapshot.swarm_profile.trim();
        if p.is_empty() {
            "balanced".to_string()
        } else {
            p.to_string()
        }
    }

    pub fn display_openviking_model(&self) -> String {
        let m = self.snapshot.openviking_model.trim();
        if !m.is_empty() {
            return short_model_name(m);
        }
        let orch = self.display_model_name();
        if !orch.is_empty() {
            orch
        } else {
            "auto".to_string()
        }
    }

    pub fn is_openviking_online(&self) -> bool {
        if self.snapshot.openviking_online {
            return true;
        }
        self.snapshot
            .connections
            .iter()
            .any(|c| c.name == "openviking" && !c.dead)
    }

    pub fn selected_agent_id(&self) -> String {
        self.snapshot
            .agents
            .get(self.selected_agent)
            .map(|a| a.id.clone())
            .unwrap_or_default()
    }

    pub fn selected_agent_can_stop(&self) -> bool {
        let Some(ag) = self.snapshot.agents.get(self.selected_agent) else {
            return false;
        };
        matches!(ag.status.as_str(), "running" | "waiting" | "budget_paused")
    }

    pub fn agent_has_events(&self, agent_id: &str) -> bool {
        self.snapshot.events.iter().any(|e| e.agent_id == agent_id)
    }

    pub fn agent_vuln_count(&self, agent_id: &str) -> usize {
        self.snapshot
            .vulnerabilities
            .iter()
            .filter(|v| val_str(v.get("agent_id")) == agent_id)
            .count()
    }

    pub fn mcp_in_use(&self) -> HashSet<String> {
        let mut set = HashSet::new();
        for ev in &self.snapshot.events {
            if ev.event_type != "tool" {
                continue;
            }
            let conn = val_str(ev.data.get("mcp_connection"));
            if !conn.is_empty() && val_str(ev.data.get("status")) == "running" {
                set.insert(conn);
            }
        }
        set
    }

    pub fn show_toast(&mut self, text: impl Into<String>) {
        self.show_toast_for(text, Duration::from_secs(4));
    }

    pub fn show_toast_for(&mut self, text: impl Into<String>, duration: Duration) {
        self.toast = text.into();
        self.toast_expires = Some(Instant::now() + duration);
    }

    pub fn tick(&mut self) {
        self.splash_frame = self.splash_frame.wrapping_add(1);
        self.sweep_frame = self.sweep_frame.wrapping_add(1);
        if self.show_splash && self.splash_started.elapsed() >= Duration::from_millis(4500) {
            self.show_splash = false;
        }
        if let Some(exp) = self.toast_expires {
            if Instant::now() >= exp {
                self.toast.clear();
                self.toast_expires = None;
            }
        }
        if self.modal == ModalMode::Picker
            && self.picker.phase == PickerPhase::Wait
            && !self.picker.poll_in_flight
            && self
                .picker
                .last_poll
                .is_none_or(|t| t.elapsed() >= Duration::from_secs(1))
        {
            self.picker.poll_in_flight = true;
            self.picker.last_poll = Some(Instant::now());
            self.send_command("llm.auth_status", json!({}));
        }
    }

    pub fn send_command(&mut self, command: &str, payload: Value) {
        let Some(client) = self.client.clone() else {
            return;
        };
        let col = payload
            .get("collection")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        match client.send(command, payload) {
            Ok(request_id) => {
                if command == "collection.resync"
                    && !request_id.is_empty()
                    && !col.is_empty()
                    && *self.resync_requested.get(&col).unwrap_or(&false)
                {
                    self.resync_requests.insert(request_id, col);
                }
            }
            Err(err) => {
                if command.starts_with("llm.") {
                    self.fail_picker(&err);
                } else {
                    self.error_text = err;
                    if command == "collection.resync" && !col.is_empty() {
                        self.resync_requested.insert(col, false);
                    }
                }
            }
        }
    }

    pub fn handle_wire_error(&mut self, err: &str) {
        if !self.quitting {
            self.error_text = format!("Backend disconnected: {err}");
            self.fatal_error = Some(format!("backend disconnected: {err}"));
        }
        self.quitting = true;
    }

    pub fn handle_envelope(&mut self, envelope: Envelope) {
        if envelope.version != PROTOCOL_VERSION {
            let msg = format!(
                "Protocol mismatch: backend={} client={}",
                envelope.version, PROTOCOL_VERSION
            );
            self.error_text = msg.clone();
            self.fatal_error = Some(msg.to_ascii_lowercase());
            self.quitting = true;
            return;
        }
        match envelope.msg_type.as_str() {
            "state" => {
                let update: StateUpdate = match serde_json::from_value(envelope.payload) {
                    Ok(u) => u,
                    Err(e) => {
                        self.error_text = e.to_string();
                        return;
                    }
                };
                if update.revision <= self.state_revision {
                    return;
                }
                let prev_agent_id = self.selected_agent_id();
                let prev_events = std::mem::take(&mut self.snapshot.events);
                let prev_vulns = std::mem::take(&mut self.snapshot.vulnerabilities);
                let prev_agents = std::mem::take(&mut self.snapshot.agents);

                self.consume_messages(&update.state.messages, update.state.setup_mode);
                self.snapshot = update.state;
                self.snapshot.events = prev_events;
                self.snapshot.vulnerabilities = prev_vulns;
                self.snapshot.agents = prev_agents;
                self.state_revision = update.revision;

                if let Some(err) = &self.snapshot.error {
                    self.error_text = err.clone();
                } else {
                    self.error_text.clear();
                }
                if self.snapshot.setup_mode {
                    self.show_splash = false;
                }
                self.selected_agent = selected_agent_index(&self.snapshot.agents, &prev_agent_id);
                if !self.snapshot.vulnerabilities.is_empty() {
                    self.selected_vuln = self
                        .selected_vuln
                        .min(self.snapshot.vulnerabilities.len() - 1);
                } else {
                    self.selected_vuln = 0;
                }
                if self.modal == ModalMode::Stop && !self.selected_agent_can_stop() {
                    self.close_modal();
                }
                self.sync_mount_prompt();
                self.ready = true;
            }
            "collection_bootstrap" => self.handle_collection_bootstrap(envelope.payload),
            "collection_delta" => self.handle_collection_delta(envelope.payload),
            "command_result" => self.handle_command_result(&envelope.request_id, envelope.payload),
            _ => {}
        }
    }

    fn consume_messages(&mut self, messages: &[Message], setup_mode: bool) {
        for msg in messages {
            let key = if msg.id.is_empty() {
                format!("{}\0{}", msg.level, msg.text)
            } else {
                msg.id.clone()
            };
            if !self.seen_messages.insert(key) {
                continue;
            }
            if !setup_mode || msg.text.trim().is_empty() {
                continue;
            }
            self.setup_msg(&msg.text, &msg.level);
        }
    }

    pub fn setup_msg(&mut self, text: &str, level: &str) {
        let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
        self.setup_log.retain(|e| e.text != flat);
        self.setup_log.push(SetupLogEntry {
            text: flat,
            level: level.to_string(),
        });
    }

    fn sync_mount_prompt(&mut self) {
        if !self.snapshot.pending_mount.is_empty() && self.modal != ModalMode::ConfirmMount {
            self.open_modal(ModalMode::ConfirmMount);
        } else if self.snapshot.pending_mount.is_empty() && self.modal == ModalMode::ConfirmMount {
            self.close_modal();
        }
    }

    fn valid_collection(name: &str) -> bool {
        matches!(name, "agents" | "events" | "vulnerabilities")
    }

    fn collection_mismatch(&mut self, name: &str) {
        self.collection_assemblies.remove(name);
        if !Self::valid_collection(name)
            || *self.resync_requested.get(name).unwrap_or(&false)
            || self.client.is_none()
        {
            return;
        }
        self.resync_requested.insert(name.to_string(), true);
        self.send_command("collection.resync", json!({ "collection": name }));
    }

    fn clear_collection_resync(&mut self, name: &str) {
        self.resync_requested.insert(name.to_string(), false);
        self.resync_requests.retain(|_, col| col != name);
    }

    fn handle_collection_bootstrap(&mut self, payload: Value) {
        let chunk: CollectionBootstrap = match serde_json::from_value(payload) {
            Ok(c) => c,
            Err(e) => {
                self.error_text = e.to_string();
                return;
            }
        };
        let col = chunk.collection.clone();
        if !Self::valid_collection(&col) {
            self.error_text = format!("Unknown collection: {col}");
            return;
        }
        if chunk.cursor == 0 {
            self.resync_requested.insert(col.clone(), false);
            let cur_rev = *self.collection_revisions.get(&col).unwrap_or(&0);
            if chunk.revision <= cur_rev {
                return;
            }
            self.collection_assemblies.insert(
                col.clone(),
                CollectionAssembly {
                    kind: "bootstrap".to_string(),
                    revision: chunk.revision,
                    ..Default::default()
                },
            );
        }
        let valid = {
            let Some(assembly) = self.collection_assemblies.get_mut(&col) else {
                self.collection_mismatch(&col);
                return;
            };
            if assembly.kind != "bootstrap"
                || assembly.revision != chunk.revision
                || assembly.cursor != chunk.cursor
                || chunk.next_cursor != chunk.cursor + chunk.items.len()
            {
                false
            } else {
                let mut ok = true;
                for raw in chunk.items {
                    if col == "agents" {
                        let Ok(ag) = serde_json::from_value::<Agent>(raw) else {
                            ok = false;
                            break;
                        };
                        if ag.id.is_empty() || !assembly.ids.insert(ag.id.clone()) {
                            ok = false;
                            break;
                        }
                        assembly.agents.push(ag);
                    } else if col == "events" {
                        let Ok(ev) = serde_json::from_value::<Event>(raw) else {
                            ok = false;
                            break;
                        };
                        if ev.id.is_empty() || !assembly.ids.insert(ev.id.clone()) {
                            ok = false;
                            break;
                        }
                        assembly.events.push(ev);
                    } else {
                        let Some(obj) = raw.as_object().cloned() else {
                            ok = false;
                            break;
                        };
                        let id = val_str(obj.get("id"));
                        if id.is_empty() || !assembly.ids.insert(id) {
                            ok = false;
                            break;
                        }
                        assembly.findings.push(obj);
                    }
                }
                if ok {
                    assembly.cursor = chunk.next_cursor;
                }
                ok
            }
        };
        if !valid {
            self.collection_mismatch(&col);
            return;
        }
        if !chunk.done {
            return;
        }
        let Some(assembly) = self.collection_assemblies.remove(&col) else {
            return;
        };
        if col == "agents" {
            let prev_id = self.selected_agent_id();
            self.snapshot.agents = assembly.agents;
            self.selected_agent = selected_agent_index(&self.snapshot.agents, &prev_id);
            self.notify_budget_pause();
        } else if col == "events" {
            self.snapshot.events = assembly.events;
        } else {
            self.snapshot.vulnerabilities = assembly.findings;
            if !self.snapshot.vulnerabilities.is_empty() {
                self.selected_vuln = self
                    .selected_vuln
                    .min(self.snapshot.vulnerabilities.len() - 1);
            } else {
                self.selected_vuln = 0;
            }
        }
        self.collection_revisions
            .insert(col.clone(), chunk.revision);
        self.clear_collection_resync(&col);
    }

    fn handle_collection_delta(&mut self, payload: Value) {
        let chunk: CollectionDelta = match serde_json::from_value(payload) {
            Ok(c) => c,
            Err(e) => {
                self.error_text = e.to_string();
                return;
            }
        };
        let col = chunk.collection.clone();
        if !Self::valid_collection(&col) {
            self.error_text = format!("Unknown collection: {col}");
            return;
        }
        if chunk.cursor == 0 {
            let cur_rev = *self.collection_revisions.get(&col).unwrap_or(&0);
            if chunk.base_revision != cur_rev || chunk.revision <= chunk.base_revision {
                self.collection_mismatch(&col);
                return;
            }
            self.collection_assemblies.insert(
                col.clone(),
                CollectionAssembly {
                    kind: "delta".to_string(),
                    revision: chunk.revision,
                    base_revision: chunk.base_revision,
                    ..Default::default()
                },
            );
        }
        let valid = {
            let Some(assembly) = self.collection_assemblies.get_mut(&col) else {
                self.collection_mismatch(&col);
                return;
            };
            if assembly.kind != "delta"
                || assembly.revision != chunk.revision
                || assembly.base_revision != chunk.base_revision
                || assembly.cursor != chunk.cursor
                || chunk.next_cursor != chunk.cursor + chunk.operations.len()
            {
                false
            } else {
                assembly.operations.extend(chunk.operations);
                assembly.cursor = chunk.next_cursor;
                true
            }
        };
        if !valid {
            self.collection_mismatch(&col);
            return;
        }
        if !chunk.done {
            return;
        }
        let Some(assembly) = self.collection_assemblies.remove(&col) else {
            return;
        };
        if !self.apply_collection_operations(&col, &assembly.operations) {
            self.collection_mismatch(&col);
            return;
        }
        self.collection_revisions
            .insert(col.clone(), chunk.revision);
        self.clear_collection_resync(&col);
        if col == "agents" {
            self.notify_budget_pause();
        } else if col == "vulnerabilities" {
            if !self.snapshot.vulnerabilities.is_empty() {
                self.selected_vuln = self
                    .selected_vuln
                    .min(self.snapshot.vulnerabilities.len() - 1);
            } else {
                self.selected_vuln = 0;
            }
        }
    }

    pub fn apply_collection_operations(
        &mut self,
        name: &str,
        operations: &[CollectionOperation],
    ) -> bool {
        let mut seen = HashSet::with_capacity(operations.len());
        if name == "agents" {
            let prev_id = self.selected_agent_id();
            let mut values = self.snapshot.agents.clone();
            for op in operations {
                if op.op == "delete" {
                    if op.id.is_empty() || !seen.insert(op.id.clone()) {
                        return false;
                    }
                    let Some(pos) = values.iter().position(|a| a.id == op.id) else {
                        return false;
                    };
                    values.remove(pos);
                    continue;
                }
                if op.op != "upsert" {
                    return false;
                }
                let Ok(agent) = serde_json::from_value::<Agent>(op.item.clone()) else {
                    return false;
                };
                if agent.id.is_empty() || !seen.insert(agent.id.clone()) {
                    return false;
                }
                if let Some(pos) = values.iter().position(|a| a.id == agent.id) {
                    values[pos] = agent;
                } else {
                    values.push(agent);
                }
            }
            self.snapshot.agents = values;
            self.selected_agent = selected_agent_index(&self.snapshot.agents, &prev_id);
            return true;
        }
        if name == "events" {
            let mut values = self.snapshot.events.clone();
            for op in operations {
                if op.op == "delete" {
                    if op.id.is_empty() || !seen.insert(op.id.clone()) {
                        return false;
                    }
                    let Some(pos) = values.iter().position(|e| e.id == op.id) else {
                        return false;
                    };
                    values.remove(pos);
                    continue;
                }
                if op.op != "upsert" {
                    return false;
                }
                let Ok(event) = serde_json::from_value::<Event>(op.item.clone()) else {
                    return false;
                };
                if event.id.is_empty() || event.version < 0 || !seen.insert(event.id.clone()) {
                    return false;
                }
                if let Some(pos) = values.iter().position(|e| e.id == event.id) {
                    if event.version <= values[pos].version {
                        return false;
                    }
                    values[pos] = event;
                } else {
                    values.push(event);
                }
            }
            self.snapshot.events = values;
            return true;
        }

        let mut values = self.snapshot.vulnerabilities.clone();
        for op in operations {
            if op.op == "delete" {
                if op.id.is_empty() || !seen.insert(op.id.clone()) {
                    return false;
                }
                let Some(pos) = values.iter().position(|f| val_str(f.get("id")) == op.id) else {
                    return false;
                };
                values.remove(pos);
                continue;
            }
            if op.op != "upsert" {
                return false;
            }
            let Some(finding) = op.item.as_object().cloned() else {
                return false;
            };
            let id = val_str(finding.get("id"));
            if id.is_empty() || !seen.insert(id.clone()) {
                return false;
            }
            if let Some(pos) = values.iter().position(|f| val_str(f.get("id")) == id) {
                values[pos] = finding;
            } else {
                values.push(finding);
            }
        }
        self.snapshot.vulnerabilities = values;
        true
    }

    fn notify_budget_pause(&mut self) {
        let paused = self
            .snapshot
            .agents
            .iter()
            .any(|a| a.status == "budget_paused");
        if paused && !self.budget_pause_notified {
            self.budget_pause_notified = true;
            self.show_toast_for(
                "Budget limit reached — agents paused. Send a message to continue (this extends the budget), or ctrl-q to quit.",
                Duration::from_secs(15),
            );
        } else if !paused {
            self.budget_pause_notified = false;
        }
    }

    fn handle_command_result(&mut self, request_id: &str, payload: Value) {
        let Some(client) = self.client.clone() else {
            return;
        };
        let Some(expected_cmd) = client.expected_command(request_id) else {
            return;
        };
        let result: CommandResult = match serde_json::from_value(payload) {
            Ok(r) => r,
            Err(e) => {
                self.error_text = e.to_string();
                return;
            }
        };
        if result.command != expected_cmd || !client.resolve(request_id, &result.command) {
            return;
        }
        if !result.ok {
            let mut msg = "Command failed".to_string();
            if let Some(err) = &result.error {
                if !err.message.trim().is_empty() {
                    msg = err.message.clone();
                }
            }
            if result.command.starts_with("llm.") {
                self.fail_picker(&msg);
                return;
            }
            if result.command == "collection.resync" {
                if let Some(col) = self.resync_requests.remove(request_id) {
                    self.resync_requested.insert(col, false);
                } else {
                    for val in self.resync_requested.values_mut() {
                        *val = false;
                    }
                }
            }
            if self.snapshot.setup_mode {
                self.setup_msg(&msg, "error");
            } else {
                self.error_text = msg;
            }
            return;
        }
        if self.snapshot.scan_started
            && !self.snapshot.setup_mode
            && result.command.starts_with("setup.")
        {
            return;
        }
        self.error_text.clear();
        match result.command.as_str() {
            "llm.catalog" | "llm.connect" | "llm.auth_status" | "llm.auth_cancel"
            | "llm.select_model" | "llm.set_effort" | "llm.set_swarm" => {
                self.handle_llm_result(result);
            }
            "skills.catalog" | "skills.toggle" => {
                #[derive(Deserialize, Default)]
                struct SkillsPayload {
                    #[serde(default)]
                    skills: Vec<SkillEntry>,
                    #[serde(default)]
                    selected_skills: Option<Vec<String>>,
                }
                if let Ok(data) = serde_json::from_value::<SkillsPayload>(result.result) {
                    if !data.skills.is_empty() {
                        self.skill_catalog = data.skills;
                    }
                    if let Some(sel) = data.selected_skills {
                        self.snapshot.selected_skills = sel;
                    }
                }
            }
            "viewer.open" => {
                if let Some(obj) = result.result.as_object() {
                    self.snapshot.viewer_status = val_str(obj.get("status"));
                    self.snapshot.viewer_url =
                        obj.get("url").and_then(|v| v.as_str()).map(String::from);
                }
            }
            _ => {}
        }
    }

    pub fn fail_picker(&mut self, message: &str) {
        if self.modal != ModalMode::Picker {
            self.error_text = message.to_string();
            return;
        }
        self.picker.err = message.to_string();
        self.picker.poll_in_flight = false;
        if self.picker.phase == PickerPhase::Wait {
            self.picker.message = message.to_string();
        }
    }

    fn handle_llm_result(&mut self, result: CommandResult) {
        if self.modal != ModalMode::Picker {
            match result.command.as_str() {
                "llm.select_model" => self.finish_saved(result.result, "Model saved"),
                "llm.set_effort" => self.finish_saved(result.result, "Effort saved"),
                "llm.set_swarm" => self.finish_saved(result.result, "Swarm configuration saved"),
                _ => {}
            }
            return;
        }
        self.picker.poll_in_flight = false;
        match result.command.as_str() {
            "llm.catalog" => {
                #[derive(Deserialize, Default)]
                struct CatalogPayload {
                    #[serde(default)]
                    title: String,
                    #[serde(default)]
                    sections: Vec<PickerSection>,
                }
                match serde_json::from_value::<CatalogPayload>(result.result) {
                    Ok(data) => {
                        let mut title = self.picker.title.clone();
                        if title.is_empty() {
                            title = data.title;
                        }
                        if title.is_empty() {
                            title = "Select model".to_string();
                        }
                        self.picker.phase = PickerPhase::List;
                        self.picker.title = title.clone();
                        self.picker.stack.clear();
                        self.picker.frame = PickerFrame {
                            title,
                            sections: data.sections,
                            cursor: 0,
                            query: String::new(),
                        };
                        self.picker.message.clear();
                        self.picker.err.clear();
                    }
                    Err(e) => self.fail_picker(&e.to_string()),
                }
            }
            "llm.connect" | "llm.auth_status" => self.apply_auth_status(result.result),
            "llm.select_model" => self.finish_saved(result.result, "Model saved"),
            "llm.set_effort" => self.finish_saved(result.result, "Effort saved"),
            "llm.set_swarm" => self.finish_saved(result.result, "Swarm configuration saved"),
            _ => {}
        }
    }

    fn apply_auth_status(&mut self, raw: Value) {
        #[derive(Deserialize, Default)]
        struct ModelItem {
            #[serde(default)]
            id: String,
            #[serde(default)]
            label: String,
        }
        #[derive(Deserialize, Default)]
        struct AuthStatusPayload {
            #[serde(default)]
            phase: String,
            #[serde(default)]
            url: String,
            #[serde(default)]
            user_code: String,
            #[serde(default)]
            message: String,
            #[serde(default)]
            note: String,
            #[serde(default)]
            provider: String,
            #[serde(default)]
            models: Vec<ModelItem>,
        }
        let data: AuthStatusPayload = match serde_json::from_value(raw) {
            Ok(d) => d,
            Err(e) => {
                self.fail_picker(&e.to_string());
                return;
            }
        };
        match data.phase.as_str() {
            "models" => {
                let entries: Vec<PickerEntry> = data
                    .models
                    .into_iter()
                    .map(|m| PickerEntry {
                        label: if m.label.is_empty() {
                            m.id.clone()
                        } else {
                            m.label
                        },
                        id: m.id,
                        auth: "model".to_string(),
                        children: Vec::new(),
                    })
                    .collect();
                let title = if data.provider.is_empty() {
                    "Select model".to_string()
                } else {
                    data.provider
                };
                self.picker.phase = PickerPhase::Models;
                self.picker.title = title.clone();
                self.picker.key.clear();
                self.picker.note = data.note;
                self.picker.err.clear();
                self.picker.message.clear();
                self.picker.models = PickerFrame {
                    title,
                    sections: vec![PickerSection {
                        title: String::new(),
                        entries,
                    }],
                    cursor: 0,
                    query: String::new(),
                };
            }
            "error" => self.fail_picker(&data.message),
            "browser" | "device" | "pending" => {
                self.picker.phase = PickerPhase::Wait;
                if !data.url.is_empty() {
                    self.picker.url = data.url;
                }
                if !data.user_code.is_empty() {
                    self.picker.user_code = data.user_code;
                }
                if !data.message.is_empty() {
                    self.picker.message = data.message;
                }
                self.picker.last_poll = Some(Instant::now());
            }
            _ => {}
        }
    }

    fn finish_saved(&mut self, raw: Value, fallback: &str) {
        let status = val_str(raw.get("status"));
        let model = val_str(raw.get("model"));
        let short_model = val_str(raw.get("short_model"));
        let effort = val_str(raw.get("effort"));
        let applied = val_str(raw.get("applied"));
        let swarm_profile = val_str(raw.get("swarm_profile"));
        let ov_model = val_str(raw.get("openviking_model"));
        let ov_embed = val_str(raw.get("openviking_embed_model"));
        let ov_enabled = raw.get("openviking_enabled").and_then(|v| v.as_bool());

        if !swarm_profile.is_empty() {
            self.snapshot.swarm_profile = swarm_profile.clone();
        }
        if !ov_model.is_empty() {
            self.snapshot.openviking_model = ov_model.clone();
        }
        if !ov_embed.is_empty() {
            self.snapshot.openviking_embed_model = ov_embed.clone();
        }
        if let Some(en) = ov_enabled {
            self.snapshot.openviking_online = en;
        }

        let display_model = if !short_model.is_empty() {
            short_model
        } else {
            model.clone()
        };
        let text = if status == "profile_updated" && !swarm_profile.is_empty() {
            format!("Swarm profile set to {swarm_profile}")
        } else if status == "openviking_inherit" {
            format!("OpenViking Memory set to inherit Orchestrator ({ov_model})")
        } else if status == "openviking_embed_updated" {
            format!("OpenViking Embedding set to {ov_embed}")
        } else if status == "openviking_toggled" {
            if ov_enabled.unwrap_or(true) {
                "OpenViking Memory MCP enabled".to_string()
            } else {
                "OpenViking Memory MCP disabled".to_string()
            }
        } else if applied == "next_scan" {
            "Saved for the next scan".to_string()
        } else if !model.is_empty() {
            if !effort.is_empty() && effort != "none" {
                format!("Model set to {display_model} (effort: {effort})")
            } else {
                format!("Model set to {display_model}")
            }
        } else if !effort.is_empty() {
            format!("Effort set to {effort}")
        } else {
            fallback.to_string()
        };
        self.close_modal();
        self.picker = PickerState::default();
        self.show_toast(text);
    }

    pub fn open_modal(&mut self, mode: ModalMode) {
        self.modal = mode;
        if mode == ModalMode::ConfirmMount {
            self.modal_choice = 1;
        } else if mode == ModalMode::Vulnerability {
            self.report_focus = REPORT_DONE.to_string();
            self.modal_choice = 1;
            self.vulnerability_copied = false;
            self.vulnerability_copy_error.clear();
            self.vuln_report_scroll = 0;
        }
    }

    pub fn close_modal(&mut self) {
        self.modal = ModalMode::None;
    }

    pub fn open_skills_modal(&mut self) {
        self.open_modal(ModalMode::Skills);
        self.send_command("skills.catalog", json!({}));
    }

    pub fn effective_skills(&self) -> Vec<SkillEntry> {
        if !self.skill_catalog.is_empty() {
            return self.skill_catalog.clone();
        }
        let selected_set: HashSet<&str> = self
            .snapshot
            .selected_skills
            .iter()
            .map(|s| s.as_str())
            .collect();
        self.snapshot
            .skills
            .iter()
            .map(|name| SkillEntry {
                name: name.clone(),
                category: "assessment".to_string(),
                description: String::new(),
                available: true,
                missing: Vec::new(),
                selected: selected_set.contains(name.as_str()),
            })
            .collect()
    }

    pub fn move_skill_selection(&mut self, delta: isize) {
        let entries = self.effective_skills();
        if entries.is_empty() {
            self.skill_selected = 0;
            return;
        }
        let next =
            (self.skill_selected as isize + delta).clamp(0, entries.len() as isize - 1) as usize;
        self.skill_selected = next;
    }

    pub fn toggle_selected_skill(&mut self) {
        let entries = self.effective_skills();
        if let Some(entry) = entries.get(self.skill_selected) {
            self.send_command("skills.toggle", json!({ "skill": entry.name }));
        }
    }

    pub fn open_model_picker_with_scope(&mut self, scope: &str) {
        let scope = if scope.is_empty() { "both" } else { scope };
        let title = if scope == "orchestrator" {
            "Select Orchestrator model".to_string()
        } else if scope == "swarm" {
            "Select Swarm default model".to_string()
        } else if scope == "openviking" {
            "Select OpenViking Memory VLM model".to_string()
        } else if let Some(role) = scope.strip_prefix("role:") {
            format!("Select Swarm model [{role}]")
        } else {
            "Select model (Orchestrator + Swarm)".to_string()
        };
        self.modal = ModalMode::Picker;
        self.picker = PickerState {
            phase: PickerPhase::List,
            title,
            scope: scope.to_string(),
            message: "Loading…".to_string(),
            ..Default::default()
        };
        self.send_command("llm.catalog", json!({}));
    }

    pub fn open_effort_picker(&mut self) {
        if self.snapshot.model.trim().is_empty() {
            self.show_toast("Select a model first (/models)");
            return;
        }
        self.modal = ModalMode::Picker;
        let levels: Vec<String> = if !self.snapshot.supported_efforts.is_empty() {
            self.snapshot.supported_efforts.clone()
        } else {
            EFFORT_LEVELS.iter().map(|s| (*s).to_string()).collect()
        };
        let current = self.snapshot.reasoning_effort.trim();
        let mut cursor = 0usize;
        let mut entries = Vec::with_capacity(levels.len());
        for (idx, level) in levels.into_iter().enumerate() {
            let mut label = level.clone();
            if level == current {
                label.push_str("  ●");
                cursor = idx;
            }
            entries.push(PickerEntry {
                id: level,
                label,
                auth: "effort".to_string(),
                children: Vec::new(),
            });
        }
        let title = if !self.snapshot.short_model.is_empty() {
            format!("Select effort ({})", self.snapshot.short_model)
        } else {
            "Select effort".to_string()
        };
        self.picker = PickerState {
            phase: PickerPhase::List,
            title: title.clone(),
            frame: PickerFrame {
                title,
                sections: vec![PickerSection {
                    title: String::new(),
                    entries,
                }],
                cursor,
                query: String::new(),
            },
            ..Default::default()
        };
    }

    pub fn open_openviking_picker(&mut self) {
        self.modal = ModalMode::Picker;
        let orch_label = {
            let s = self.display_model_name();
            if s.is_empty() {
                "Not configured".to_string()
            } else {
                s
            }
        };
        let ov_model_label = {
            let raw = self.snapshot.openviking_model.trim();
            if raw.is_empty() {
                format!("Inherits Orchestrator ({orch_label})")
            } else {
                format!("{} ({raw})", self.display_openviking_model())
            }
        };
        let ov_embed_label = {
            let raw = self.snapshot.openviking_embed_model.trim();
            if raw.is_empty() {
                "local/local-fast-512".to_string()
            } else {
                raw.to_string()
            }
        };
        let ov_status = if self.is_openviking_online() {
            "ONLINE (13 tools)"
        } else {
            "OFFLINE"
        };
        let sections = vec![PickerSection {
            title: format!("OPENVIKING MEMORY MCP · {ov_status}"),
            entries: vec![
                PickerEntry {
                    id: "openviking".to_string(),
                    label: format!("Select Memory VLM Model        · {ov_model_label}"),
                    auth: "swarm_scope".to_string(),
                    children: Vec::new(),
                },
                PickerEntry {
                    id: "openviking_inherit".to_string(),
                    label: format!("Inherit Orchestrator Model     · {orch_label}"),
                    auth: "openviking_action".to_string(),
                    children: Vec::new(),
                },
                PickerEntry {
                    id: "embed:local".to_string(),
                    label: format!(
                        "Embedding: Local Fast (512d)   · {}",
                        if ov_embed_label.starts_with("local/") {
                            "active ●"
                        } else {
                            "no API key needed"
                        }
                    ),
                    auth: "openviking_action".to_string(),
                    children: Vec::new(),
                },
                PickerEntry {
                    id: "embed:openai".to_string(),
                    label: format!(
                        "Embedding: OpenAI 3-Small      · {}",
                        if ov_embed_label.starts_with("openai/") {
                            "active ●"
                        } else {
                            "text-embedding-3-small"
                        }
                    ),
                    auth: "openviking_action".to_string(),
                    children: Vec::new(),
                },
                PickerEntry {
                    id: "openviking_toggle".to_string(),
                    label: format!("Toggle OpenViking MCP          · [{ov_status}]"),
                    auth: "openviking_action".to_string(),
                    children: Vec::new(),
                },
            ],
        }];
        let title = "OpenViking Agent Memory & MCP Configuration".to_string();
        self.picker = PickerState {
            phase: PickerPhase::List,
            title: title.clone(),
            frame: PickerFrame {
                title,
                sections,
                cursor: 0,
                query: String::new(),
            },
            ..Default::default()
        };
    }

    pub fn open_swarm_picker(&mut self) {
        self.modal = ModalMode::Picker;
        let orch_label = {
            let s = self.display_model_name();
            if s.is_empty() {
                "Not configured".to_string()
            } else {
                s
            }
        };
        let swarm_label = {
            let s = self.display_swarm_model_name();
            if s.is_empty() {
                format!("Inherits Orchestrator ({orch_label})")
            } else {
                s
            }
        };
        let ov_label = {
            let m = self.display_openviking_model();
            let st = if self.is_openviking_online() {
                "online"
            } else {
                "offline"
            };
            format!("{m} [{st}]")
        };
        let profile = {
            let p = self.snapshot.swarm_profile.trim();
            if p.is_empty() {
                "balanced"
            } else {
                p
            }
        };
        let role_label = |role: &str, desc: &str| -> String {
            if let Some(ov) = self.snapshot.swarm_role_models.get(role) {
                if !ov.trim().is_empty() {
                    return format!("{desc}  [{}]", ov.trim());
                }
            }
            format!("{desc}  [default]")
        };
        let mark_cur = |label: &str, active: bool| -> String {
            if active {
                format!("{label}  ●")
            } else {
                label.to_string()
            }
        };

        let sections = vec![
            PickerSection {
                title: "MODEL ROUTING".to_string(),
                entries: vec![
                    PickerEntry {
                        id: "both".to_string(),
                        label: format!("Orchestrator + Swarm (Shared)  · {orch_label}"),
                        auth: "swarm_scope".to_string(),
                        children: Vec::new(),
                    },
                    PickerEntry {
                        id: "orchestrator".to_string(),
                        label: format!("Orchestrator Only              · {orch_label}"),
                        auth: "swarm_scope".to_string(),
                        children: Vec::new(),
                    },
                    PickerEntry {
                        id: "swarm".to_string(),
                        label: format!("Swarm Sub-Agents Default       · {swarm_label}"),
                        auth: "swarm_scope".to_string(),
                        children: Vec::new(),
                    },
                    PickerEntry {
                        id: "openviking".to_string(),
                        label: format!("OpenViking Memory VLM          · {ov_label}"),
                        auth: "swarm_scope".to_string(),
                        children: Vec::new(),
                    },
                ],
            },
            PickerSection {
                title: "SWARM ROLE OVERRIDES".to_string(),
                entries: vec![
                    PickerEntry {
                        id: "role:recon".to_string(),
                        label: role_label("recon", "Recon / Attack Surface Agents"),
                        auth: "swarm_scope".to_string(),
                        children: Vec::new(),
                    },
                    PickerEntry {
                        id: "role:exploit".to_string(),
                        label: role_label("exploit", "Exploit / Verification Agents"),
                        auth: "swarm_scope".to_string(),
                        children: Vec::new(),
                    },
                    PickerEntry {
                        id: "role:validator".to_string(),
                        label: role_label("validator", "PoC / Validation Agents"),
                        auth: "swarm_scope".to_string(),
                        children: Vec::new(),
                    },
                    PickerEntry {
                        id: "role:report".to_string(),
                        label: role_label("report", "Report / Triage Agents"),
                        auth: "swarm_scope".to_string(),
                        children: Vec::new(),
                    },
                ],
            },
            PickerSection {
                title: "SWARM PROFILE".to_string(),
                entries: vec![
                    PickerEntry {
                        id: "full".to_string(),
                        label: mark_cur(
                            "full      — Complete multi-agent offensive swarm",
                            profile == "full",
                        ),
                        auth: "swarm_profile".to_string(),
                        children: Vec::new(),
                    },
                    PickerEntry {
                        id: "balanced".to_string(),
                        label: mark_cur(
                            "balanced  — Balanced recon + exploitation swarm",
                            profile == "balanced",
                        ),
                        auth: "swarm_profile".to_string(),
                        children: Vec::new(),
                    },
                    PickerEntry {
                        id: "deep".to_string(),
                        label: mark_cur(
                            "deep      — Exhaustive multi-stage deep audit swarm",
                            profile == "deep",
                        ),
                        auth: "swarm_profile".to_string(),
                        children: Vec::new(),
                    },
                    PickerEntry {
                        id: "recon".to_string(),
                        label: mark_cur(
                            "recon     — Attack surface & discovery swarm",
                            profile == "recon",
                        ),
                        auth: "swarm_profile".to_string(),
                        children: Vec::new(),
                    },
                    PickerEntry {
                        id: "exploit".to_string(),
                        label: mark_cur(
                            "exploit   — Deep exploitation & PoC verification swarm",
                            profile == "exploit",
                        ),
                        auth: "swarm_profile".to_string(),
                        children: Vec::new(),
                    },
                    PickerEntry {
                        id: "whitebox".to_string(),
                        label: mark_cur(
                            "whitebox  — Source code & dependency review swarm",
                            profile == "whitebox",
                        ),
                        auth: "swarm_profile".to_string(),
                        children: Vec::new(),
                    },
                    PickerEntry {
                        id: "fast".to_string(),
                        label: mark_cur(
                            "fast      — Rapid lightweight triage swarm",
                            profile == "fast",
                        ),
                        auth: "swarm_profile".to_string(),
                        children: Vec::new(),
                    },
                    PickerEntry {
                        id: "single".to_string(),
                        label: mark_cur(
                            "single    — Single orchestrator agent only",
                            profile == "single",
                        ),
                        auth: "swarm_profile".to_string(),
                        children: Vec::new(),
                    },
                ],
            },
            PickerSection {
                title: "OPENVIKING MEMORY & RESET".to_string(),
                entries: vec![
                    PickerEntry {
                        id: "openviking_inherit".to_string(),
                        label: "OpenViking Memory: Inherit Orchestrator model".to_string(),
                        auth: "openviking_action".to_string(),
                        children: Vec::new(),
                    },
                    PickerEntry {
                        id: "openviking_toggle".to_string(),
                        label: "OpenViking Memory: Toggle MCP enable/disable".to_string(),
                        auth: "openviking_action".to_string(),
                        children: Vec::new(),
                    },
                    PickerEntry {
                        id: "inherit".to_string(),
                        label: "Reset Swarm to inherit Orchestrator model".to_string(),
                        auth: "swarm_reset".to_string(),
                        children: Vec::new(),
                    },
                ],
            },
        ];
        let title = format!("Swarm & Memory Configuration [profile: {profile}]");
        self.picker = PickerState {
            phase: PickerPhase::List,
            title: title.clone(),
            frame: PickerFrame {
                title,
                sections,
                cursor: 0,
                query: String::new(),
            },
            ..Default::default()
        };
    }

    pub fn slash_ghost(&self) -> String {
        let value = &self.input_text;
        if value.is_empty() || value.contains('\n') || value.contains(' ') {
            return String::new();
        }
        let lower = value.to_ascii_lowercase();
        let mut matched = "";
        for &cmd in SLASH_COMMANDS {
            if cmd.starts_with(&lower) && cmd != lower {
                if !matched.is_empty() {
                    return String::new();
                }
                matched = cmd;
            }
        }
        if matched.is_empty() || value.len() > matched.len() {
            return String::new();
        }
        matched[value.len()..].to_string()
    }

    pub fn complete_slash(&mut self) -> bool {
        let ghost = self.slash_ghost();
        if ghost.is_empty() {
            return false;
        }
        self.input_text.push_str(&ghost);
        self.input_cursor = self.input_text.len();
        true
    }

    pub fn intercept_slash(&mut self, value: &str) -> bool {
        let fields: Vec<&str> = value.split_whitespace().collect();
        if fields.is_empty() || !fields[0].starts_with('/') {
            return false;
        }
        match fields[0].to_ascii_lowercase().as_str() {
            "/models" => {
                if let Some(&arg) = fields.get(1) {
                    let lower = arg.trim().to_ascii_lowercase();
                    if lower == "swarm"
                        || lower == "orchestrator"
                        || lower == "openviking"
                        || lower.starts_with("role:")
                    {
                        self.open_model_picker_with_scope(&lower);
                        return true;
                    }
                }
                self.open_model_picker_with_scope("both");
                true
            }
            "/effort" => {
                self.open_effort_picker();
                true
            }
            "/swarm" => {
                if let Some(&arg) = fields.get(1) {
                    let lower = arg.trim().to_ascii_lowercase();
                    if SWARM_PROFILES.contains(&lower.as_str()) {
                        self.snapshot.swarm_profile = lower.clone();
                        self.send_command(
                            "llm.set_swarm",
                            json!({ "action": "profile", "profile": lower }),
                        );
                        self.show_toast(format!("Swarm profile set to {lower}"));
                        return true;
                    }
                }
                self.open_swarm_picker();
                true
            }
            "/openviking" | "/ov" | "/memory" => {
                if let Some(&arg) = fields.get(1) {
                    let lower = arg.trim().to_ascii_lowercase();
                    if lower == "model" || lower == "models" {
                        self.open_model_picker_with_scope("openviking");
                        return true;
                    } else if lower == "inherit" {
                        self.send_command(
                            "llm.set_swarm",
                            json!({ "action": "openviking_inherit" }),
                        );
                        return true;
                    } else if lower == "toggle" || lower == "on" || lower == "off" {
                        let enabled = if lower == "on" {
                            Some(true)
                        } else if lower == "off" {
                            Some(false)
                        } else {
                            None
                        };
                        let mut payload = json!({ "action": "openviking_toggle" });
                        if let Some(en) = enabled {
                            payload["enabled"] = json!(en);
                        }
                        self.send_command("llm.set_swarm", payload);
                        return true;
                    }
                }
                self.open_openviking_picker();
                true
            }
            "/skills" => {
                self.open_skills_modal();
                true
            }
            "/findings" | "/f" => {
                self.open_modal(ModalMode::Findings);
                true
            }
            "/mcp" | "/mcps" => {
                self.open_modal(ModalMode::Mcp);
                true
            }
            "/rj" => {
                if fields.len() < 2 {
                    self.show_toast("Usage: /rj <target> [instructions]");
                    return true;
                }
                let target = fields[1].trim();
                let instruction = if fields.len() > 2 {
                    fields[2..].join(" ")
                } else {
                    String::new()
                };
                self.send_command(
                    "pentest.run",
                    json!({
                        "target": target,
                        "instruction": instruction,
                    }),
                );
                true
            }
            _ => false,
        }
    }

    pub fn submit(&mut self, value: &str) {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return;
        }
        self.record_history(trimmed);
        if self.intercept_slash(trimmed) {
            return;
        }
        if self.snapshot.setup_mode {
            self.submit_setup_prompt(trimmed);
            return;
        }
        if self.snapshot.agents.is_empty() {
            self.error_text = "No agent is available".to_string();
            return;
        }
        if self.selected_agent >= self.snapshot.agents.len() {
            self.selected_agent = 0;
        }
        let agent_id = self.snapshot.agents[self.selected_agent].id.clone();
        self.send_command(
            "agent.send_message",
            json!({
                "agent_id": agent_id,
                "message": trimmed,
            }),
        );
    }

    fn submit_setup_prompt(&mut self, value: &str) {
        let fields: Vec<&str> = value.split_whitespace().collect();
        let mut targets = 0usize;
        for field in &fields {
            let token = field.trim_matches(|c| c == ',' || c == ';');
            if !looks_like_target(token) || self.snapshot.targets.iter().any(|t| t == token) {
                continue;
            }
            targets += 1;
            self.send_command("setup.add_target", json!({ "target": token }));
        }
        if fields.len() > targets {
            self.send_command("setup.set_instruction", json!({ "instruction": value }));
        }
        let mut payload = json!({});
        if targets == 0 && self.snapshot.targets.is_empty() {
            self.pending_prompt = value.to_string();
            payload = json!({ "mount_working_dir": true });
        }
        self.send_command("setup.start", payload);
    }

    pub fn answer_mount_confirmation(&mut self, approved: bool) {
        self.pending_prompt.clear();
        self.send_command("setup.confirm_mount", json!({ "approved": approved }));
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        if self.show_splash {
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.quitting = true;
                    self.send_command("app.quit", json!({}));
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.quitting = true;
                    self.send_command("app.quit", json!({}));
                }
                _ => {
                    self.show_splash = false;
                }
            }
            return;
        }
        if self.modal != ModalMode::None {
            self.handle_modal_key(key);
            return;
        }
        self.handle_main_key(key);
    }

    fn handle_main_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);

        if ctrl {
            match key.code {
                KeyCode::Char('c' | 'q') => {
                    if self.snapshot.setup_mode {
                        self.quitting = true;
                        self.send_command("app.quit", json!({}));
                    } else {
                        self.modal_choice = 1;
                        self.open_modal(ModalMode::Quit);
                    }
                    return;
                }
                KeyCode::Char('o') => {
                    self.send_command("viewer.open", json!({}));
                    return;
                }
                KeyCode::Char('j') => {
                    if self.focus == FocusMode::Input {
                        self.insert_char('\n');
                    }
                    return;
                }
                KeyCode::Char('h') => {
                    if self.focus == FocusMode::Input {
                        self.backspace_char();
                    }
                    return;
                }
                KeyCode::Char('u') => {
                    if self.focus == FocusMode::Input {
                        self.input_text.clear();
                        self.input_cursor = 0;
                    }
                    return;
                }
                KeyCode::Up => {
                    if !self.snapshot.setup_mode && !self.snapshot.agents.is_empty() {
                        self.focus = FocusMode::Agents;
                        self.step_agent_selection(-1, false);
                    }
                    return;
                }
                KeyCode::Down => {
                    if !self.snapshot.setup_mode && !self.snapshot.agents.is_empty() {
                        self.focus = FocusMode::Agents;
                        self.step_agent_selection(1, false);
                    }
                    return;
                }
                _ => {}
            }
        }

        if alt {
            match key.code {
                KeyCode::Char('0') => {
                    if !self.snapshot.setup_mode && !self.snapshot.agents.is_empty() {
                        self.all_agents_view = !self.all_agents_view;
                        self.follow_output = true;
                    }
                    return;
                }
                KeyCode::Char(c @ '1'..='9') => {
                    if !self.snapshot.setup_mode && !self.snapshot.agents.is_empty() {
                        let idx = (c as u8 - b'1') as usize;
                        if idx < self.snapshot.agents.len() {
                            self.all_agents_view = false;
                            self.selected_agent = idx;
                            self.follow_output = true;
                        }
                    }
                    return;
                }
                KeyCode::Up | KeyCode::Left => {
                    if !self.snapshot.setup_mode && !self.snapshot.agents.is_empty() {
                        self.focus = FocusMode::Agents;
                        self.step_agent_selection(-1, key.code == KeyCode::Left);
                    }
                    return;
                }
                KeyCode::Down | KeyCode::Right => {
                    if !self.snapshot.setup_mode && !self.snapshot.agents.is_empty() {
                        self.focus = FocusMode::Agents;
                        self.step_agent_selection(1, key.code == KeyCode::Right);
                    }
                    return;
                }
                KeyCode::Char('f' | 'F') => {
                    self.open_modal(ModalMode::Findings);
                    return;
                }
                KeyCode::Enter => {
                    if self.focus == FocusMode::Input {
                        self.insert_char('\n');
                    }
                    return;
                }
                _ => {}
            }
        }

        match key.code {
            KeyCode::F(1) => {
                self.open_modal(ModalMode::Help);
                return;
            }
            KeyCode::F(2) => {
                if !self.snapshot.setup_mode && !self.snapshot.agents.is_empty() {
                    self.all_agents_view = !self.all_agents_view;
                    self.follow_output = true;
                }
                return;
            }
            KeyCode::F(3) => {
                self.open_modal(ModalMode::Mcp);
                return;
            }
            KeyCode::F(4) => {
                self.open_skills_modal();
                return;
            }
            KeyCode::F(5) => {
                self.open_modal(ModalMode::Findings);
                return;
            }
            KeyCode::Char('F') => {
                if !self.snapshot.setup_mode
                    && (self.focus != FocusMode::Input || self.input_text.trim().is_empty())
                {
                    self.open_modal(ModalMode::Findings);
                    return;
                }
            }
            KeyCode::Char('f') => {
                if !self.snapshot.setup_mode && self.focus != FocusMode::Input {
                    self.open_modal(ModalMode::Findings);
                    return;
                }
            }
            KeyCode::Char('0') if !self.snapshot.setup_mode && self.focus != FocusMode::Input => {
                if !self.snapshot.agents.is_empty() {
                    self.all_agents_view = !self.all_agents_view;
                    self.follow_output = true;
                }
                return;
            }
            KeyCode::Char(c @ '1'..='9')
                if !self.snapshot.setup_mode && self.focus != FocusMode::Input =>
            {
                let idx = (c as u8 - b'1') as usize;
                if idx < self.snapshot.agents.len() {
                    self.all_agents_view = false;
                    self.selected_agent = idx;
                    self.follow_output = true;
                }
                return;
            }
            KeyCode::Tab => {
                if self.focus == FocusMode::Input && self.complete_slash() {
                    return;
                }
                self.cycle_focus(1);
                return;
            }
            KeyCode::BackTab => {
                self.cycle_focus(-1);
                return;
            }
            KeyCode::Esc => {
                if !self.snapshot.setup_mode && self.selected_agent_can_stop() {
                    self.modal_choice = 1;
                    self.open_modal(ModalMode::Stop);
                }
                return;
            }
            KeyCode::Up => {
                if self.focus == FocusMode::Input {
                    self.history_prev();
                    return;
                }
                if self.focus == FocusMode::Agents && !self.snapshot.agents.is_empty() {
                    self.step_agent_selection(-1, false);
                    return;
                }
                if self.focus == FocusMode::Chat {
                    self.follow_output = false;
                    self.chat_scroll = self.chat_scroll.saturating_sub(1);
                    return;
                }
            }
            KeyCode::Down => {
                if self.focus == FocusMode::Input {
                    self.history_next();
                    return;
                }
                if self.focus == FocusMode::Agents && !self.snapshot.agents.is_empty() {
                    self.step_agent_selection(1, false);
                    return;
                }
                if self.focus == FocusMode::Chat {
                    let max_scroll = self
                        .chat_total_lines
                        .saturating_sub(self.chat_visible_lines);
                    self.chat_scroll = (self.chat_scroll + 1).min(max_scroll);
                    if self.chat_scroll >= max_scroll {
                        self.follow_output = true;
                    }
                    return;
                }
            }
            KeyCode::Left if self.focus == FocusMode::Agents => {
                self.step_agent_selection(-1, true);
                return;
            }
            KeyCode::Right if self.focus == FocusMode::Agents => {
                self.step_agent_selection(1, true);
                return;
            }
            KeyCode::PageUp => {
                self.focus = FocusMode::Chat;
                self.follow_output = false;
                let step = (self.chat_visible_lines / 2).max(1);
                self.chat_scroll = self.chat_scroll.saturating_sub(step);
                return;
            }
            KeyCode::PageDown => {
                self.focus = FocusMode::Chat;
                let step = (self.chat_visible_lines / 2).max(1);
                let max_scroll = self
                    .chat_total_lines
                    .saturating_sub(self.chat_visible_lines);
                self.chat_scroll = (self.chat_scroll + step).min(max_scroll);
                if self.chat_scroll >= max_scroll {
                    self.follow_output = true;
                }
                return;
            }
            KeyCode::End if self.focus != FocusMode::Input => {
                self.follow_output = true;
                self.chat_scroll = self
                    .chat_total_lines
                    .saturating_sub(self.chat_visible_lines);
                return;
            }
            KeyCode::Enter => {
                if shift && self.focus == FocusMode::Input {
                    self.insert_char('\n');
                    return;
                }
                if self.focus == FocusMode::Agents {
                    if let Some(ag) = self.snapshot.agents.get(self.selected_agent) {
                        let id = ag.id.clone();
                        if has_agent_children(&id, &self.snapshot.agents)
                            && !self.collapsed_agents.remove(&id)
                        {
                            self.collapsed_agents.insert(id);
                        }
                    }
                    return;
                }
                if self.focus == FocusMode::Input {
                    let value = std::mem::take(&mut self.input_text);
                    self.input_cursor = 0;
                    if !value.trim().is_empty() {
                        self.submit(&value);
                    }
                    return;
                }
            }
            KeyCode::Char(' ') if self.focus == FocusMode::Agents => {
                if let Some(ag) = self.snapshot.agents.get(self.selected_agent) {
                    let id = ag.id.clone();
                    if has_agent_children(&id, &self.snapshot.agents)
                        && !self.collapsed_agents.remove(&id)
                    {
                        self.collapsed_agents.insert(id);
                    }
                }
                return;
            }
            _ => {}
        }

        if self.focus == FocusMode::Input {
            match key.code {
                KeyCode::Backspace => self.backspace_char(),
                KeyCode::Delete => self.delete_char(),
                KeyCode::Left => self.move_cursor_left(),
                KeyCode::Right => self.move_cursor_right(),
                KeyCode::Home => self.input_cursor = 0,
                KeyCode::End => self.input_cursor = self.input_text.len(),
                KeyCode::Char(c) if !ctrl && !alt => self.insert_char(c),
                _ => {}
            }
        }
    }

    fn insert_char(&mut self, c: char) {
        if self.input_text.len() >= 4096 {
            return;
        }
        let idx = self.input_cursor.min(self.input_text.len());
        self.input_text.insert(idx, c);
        self.input_cursor = idx + c.len_utf8();
    }

    fn backspace_char(&mut self) {
        if self.input_cursor == 0 || self.input_text.is_empty() {
            return;
        }
        let idx = self.input_cursor.min(self.input_text.len());
        if let Some((prev_idx, _)) = self.input_text[..idx].char_indices().next_back() {
            self.input_text.remove(prev_idx);
            self.input_cursor = prev_idx;
        }
    }

    fn delete_char(&mut self) {
        let idx = self.input_cursor.min(self.input_text.len());
        if idx < self.input_text.len() {
            self.input_text.remove(idx);
        }
    }

    fn move_cursor_left(&mut self) {
        let idx = self.input_cursor.min(self.input_text.len());
        if let Some((prev_idx, _)) = self.input_text[..idx].char_indices().next_back() {
            self.input_cursor = prev_idx;
        }
    }

    fn move_cursor_right(&mut self) {
        let idx = self.input_cursor.min(self.input_text.len());
        if let Some((_, ch)) = self.input_text[idx..].char_indices().next() {
            self.input_cursor = idx + ch.len_utf8();
        }
    }

    pub fn step_agent_selection(&mut self, delta: isize, allow_all_agents: bool) {
        if self.snapshot.agents.is_empty() {
            return;
        }
        let entries = agent_tree_entries(&self.snapshot.agents, &self.collapsed_agents);
        if entries.is_empty() {
            return;
        }
        if self.all_agents_view {
            self.all_agents_view = false;
            self.selected_agent = if delta < 0 {
                entries[entries.len() - 1].index
            } else {
                entries[0].index
            };
            self.follow_output = true;
            return;
        }
        let row = entries
            .iter()
            .position(|e| e.index == self.selected_agent)
            .unwrap_or(0);
        if delta > 0 {
            if row + 1 < entries.len() {
                self.selected_agent = entries[row + 1].index;
                self.all_agents_view = false;
            } else if allow_all_agents {
                self.all_agents_view = true;
            } else {
                self.selected_agent = entries[0].index;
                self.all_agents_view = false;
            }
        } else if delta < 0 {
            if row > 0 {
                self.selected_agent = entries[row - 1].index;
                self.all_agents_view = false;
            } else if allow_all_agents {
                self.all_agents_view = true;
            } else {
                self.selected_agent = entries[entries.len() - 1].index;
                self.all_agents_view = false;
            }
        }
        self.follow_output = true;
    }

    fn cycle_focus(&mut self, delta: isize) {
        let mut available = vec![FocusMode::Input, FocusMode::Chat];
        if !self.snapshot.setup_mode && !self.snapshot.agents.is_empty() {
            available.push(FocusMode::Agents);
        }
        let cur = available.iter().position(|&f| f == self.focus).unwrap_or(0) as isize;
        let len = available.len() as isize;
        let next = ((cur + delta) % len + len) % len;
        self.focus = available[next as usize];
    }

    fn handle_modal_key(&mut self, key: KeyEvent) {
        match self.modal {
            ModalMode::Picker => self.handle_picker_key(key),
            ModalMode::Mcp => match key.code {
                KeyCode::Esc | KeyCode::F(3) | KeyCode::Char('q') | KeyCode::Enter => {
                    self.close_modal();
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.mcp_offset = self.mcp_offset.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    let max_off = self.snapshot.connections.len().saturating_sub(1);
                    self.mcp_offset = (self.mcp_offset + 1).min(max_off);
                }
                _ => {}
            },
            ModalMode::Skills => match key.code {
                KeyCode::Esc | KeyCode::F(4) | KeyCode::Char('q') => self.close_modal(),
                KeyCode::Up | KeyCode::Char('k') => self.move_skill_selection(-1),
                KeyCode::Down | KeyCode::Char('j') => self.move_skill_selection(1),
                KeyCode::PageUp => self.move_skill_selection(-10),
                KeyCode::PageDown => self.move_skill_selection(10),
                KeyCode::Char(' ') | KeyCode::Enter => self.toggle_selected_skill(),
                _ => {}
            },
            ModalMode::Findings => match key.code {
                KeyCode::Esc
                | KeyCode::F(5)
                | KeyCode::Char('f')
                | KeyCode::Char('F')
                | KeyCode::Char('q') => self.close_modal(),
                KeyCode::Up | KeyCode::Char('k') => self.move_vulnerability_selection(-1),
                KeyCode::Down | KeyCode::Char('j') => self.move_vulnerability_selection(1),
                KeyCode::PageUp => self.move_vulnerability_selection(-8),
                KeyCode::PageDown => self.move_vulnerability_selection(8),
                KeyCode::Char('c') => self.copy_selected_vulnerability(),
                KeyCode::Enter if !self.snapshot.vulnerabilities.is_empty() => {
                    self.open_modal(ModalMode::Vulnerability);
                }
                _ => {}
            },
            ModalMode::Help => {
                self.close_modal();
            }
            ModalMode::Vulnerability => match key.code {
                KeyCode::Esc => self.close_modal(),
                KeyCode::Left => self.show_vulnerability(self.selected_vuln.saturating_sub(1)),
                KeyCode::Right => self.show_vulnerability(self.selected_vuln + 1),
                KeyCode::Tab => self.step_report_focus(1),
                KeyCode::BackTab => self.step_report_focus(-1),
                KeyCode::Enter => {
                    let focused = self.focused_report_button();
                    self.press_report_button(&focused);
                }
                KeyCode::Char('c') => {
                    self.report_focus = REPORT_COPY.to_string();
                    self.copy_selected_vulnerability();
                }
                KeyCode::Up => {
                    self.vuln_report_scroll = self.vuln_report_scroll.saturating_sub(1);
                }
                KeyCode::Down => {
                    self.vuln_report_scroll = self.vuln_report_scroll.saturating_add(1);
                }
                KeyCode::PageUp => {
                    self.vuln_report_scroll = self.vuln_report_scroll.saturating_sub(10);
                }
                KeyCode::PageDown => {
                    self.vuln_report_scroll = self.vuln_report_scroll.saturating_add(10);
                }
                KeyCode::Home => self.vuln_report_scroll = 0,
                _ => {}
            },
            ModalMode::Quit | ModalMode::Stop | ModalMode::ConfirmMount => match key.code {
                KeyCode::Esc => {
                    if self.modal == ModalMode::ConfirmMount {
                        self.answer_mount_confirmation(false);
                    } else {
                        self.close_modal();
                    }
                }
                KeyCode::Left
                | KeyCode::Right
                | KeyCode::Up
                | KeyCode::Down
                | KeyCode::Tab
                | KeyCode::BackTab => {
                    self.modal_choice = 1 - self.modal_choice;
                }
                KeyCode::Enter => {
                    let modal = self.modal;
                    let choice = self.modal_choice;
                    if modal == ModalMode::ConfirmMount {
                        self.answer_mount_confirmation(choice == 0);
                        return;
                    }
                    self.close_modal();
                    if choice == 1 {
                        return;
                    }
                    if modal == ModalMode::Quit {
                        self.quitting = true;
                        self.send_command("app.quit", json!({}));
                    } else if modal == ModalMode::Stop && self.selected_agent_can_stop() {
                        let agent_id = self.snapshot.agents[self.selected_agent].id.clone();
                        self.send_command("agent.stop", json!({ "agent_id": agent_id }));
                    }
                }
                _ => {}
            },
            ModalMode::None => {}
        }
    }

    pub fn move_vulnerability_selection(&mut self, delta: isize) {
        if self.snapshot.vulnerabilities.is_empty() {
            self.selected_vuln = 0;
            return;
        }
        let max_idx = self.snapshot.vulnerabilities.len() as isize - 1;
        self.selected_vuln = (self.selected_vuln as isize + delta).clamp(0, max_idx) as usize;
    }

    pub fn show_vulnerability(&mut self, index: usize) {
        if index >= self.snapshot.vulnerabilities.len() || index == self.selected_vuln {
            return;
        }
        self.selected_vuln = index;
        self.vulnerability_copied = false;
        self.vulnerability_copy_error.clear();
        self.vuln_report_scroll = 0;
    }

    pub fn report_buttons(&self) -> Vec<&'static str> {
        let mut buttons = Vec::with_capacity(4);
        if self.selected_vuln > 0 {
            buttons.push(REPORT_PREV);
        }
        if self.selected_vuln + 1 < self.snapshot.vulnerabilities.len() {
            buttons.push(REPORT_NEXT);
        }
        buttons.push(REPORT_COPY);
        buttons.push(REPORT_DONE);
        buttons
    }

    pub fn focused_report_button(&self) -> String {
        for b in self.report_buttons() {
            if b == self.report_focus {
                return b.to_string();
            }
        }
        REPORT_DONE.to_string()
    }

    pub fn step_report_focus(&mut self, delta: isize) {
        let buttons = self.report_buttons();
        let cur = buttons
            .iter()
            .position(|&b| b == self.focused_report_button())
            .unwrap_or(0) as isize;
        let len = buttons.len() as isize;
        let next = ((cur + delta) % len + len) % len;
        self.report_focus = buttons[next as usize].to_string();
    }

    pub fn press_report_button(&mut self, button: &str) {
        match button {
            REPORT_PREV => self.show_vulnerability(self.selected_vuln.saturating_sub(1)),
            REPORT_NEXT => self.show_vulnerability(self.selected_vuln + 1),
            REPORT_COPY => {
                self.report_focus = REPORT_COPY.to_string();
                self.copy_selected_vulnerability();
            }
            _ => self.close_modal(),
        }
    }

    pub fn copy_selected_vulnerability(&mut self) {
        self.vulnerability_copied = false;
        self.vulnerability_copy_error.clear();
        let Some(vuln) = self.snapshot.vulnerabilities.get(self.selected_vuln) else {
            return;
        };
        let report = vulnerability_markdown_report(vuln);
        match copy_to_system_clipboard(&report) {
            Ok(()) => {
                self.vulnerability_copied = true;
                self.show_toast("Copied vulnerability report to clipboard");
            }
            Err(e) => {
                self.vulnerability_copy_error = e;
            }
        }
    }

    fn handle_picker_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Esc => self.back_picker(),
            KeyCode::Char('c') if ctrl => self.back_picker(),
            KeyCode::Up => self.move_picker(-1),
            KeyCode::Char('p') if ctrl => self.move_picker(-1),
            KeyCode::Down => self.move_picker(1),
            KeyCode::Char('n') if ctrl => self.move_picker(1),
            KeyCode::PageUp => self.move_picker(-(PICKER_PAGE as isize)),
            KeyCode::PageDown => self.move_picker(PICKER_PAGE as isize),
            KeyCode::Enter => self.activate_picker(),
            KeyCode::Backspace => self.edit_picker(-1, ""),
            KeyCode::Char('h') if ctrl => self.edit_picker(-1, ""),
            KeyCode::Char(c) if !ctrl && !key.modifiers.contains(KeyModifiers::ALT) => {
                self.edit_picker(0, &c.to_string());
            }
            _ => {}
        }
    }

    fn active_picker_frame_mut(&mut self) -> Option<&mut PickerFrame> {
        match self.picker.phase {
            PickerPhase::Models => Some(&mut self.picker.models),
            PickerPhase::List => Some(&mut self.picker.frame),
            _ => None,
        }
    }

    pub fn active_picker_frame(&self) -> Option<&PickerFrame> {
        match self.picker.phase {
            PickerPhase::Models => Some(&self.picker.models),
            PickerPhase::List => Some(&self.picker.frame),
            _ => None,
        }
    }

    pub fn move_picker(&mut self, delta: isize) {
        let Some(frame) = self.active_picker_frame_mut() else {
            return;
        };
        let count = selectable_count(&frame.rows());
        if count == 0 {
            frame.cursor = 0;
            return;
        }
        frame.cursor = (frame.cursor as isize + delta).clamp(0, count as isize - 1) as usize;
    }

    fn edit_picker(&mut self, drop_chars: isize, insert: &str) {
        match self.picker.phase {
            PickerPhase::Key => {
                if drop_chars < 0 && !self.picker.key.is_empty() {
                    self.picker.key.pop();
                }
                if !insert.is_empty() {
                    self.picker.key.push_str(insert);
                }
            }
            PickerPhase::List => {
                if drop_chars < 0 && !self.picker.frame.query.is_empty() {
                    self.picker.frame.query.pop();
                }
                if !insert.is_empty() {
                    self.picker.frame.query.push_str(insert);
                }
                self.picker.frame.cursor = 0;
            }
            PickerPhase::Models => {
                if drop_chars < 0 && !self.picker.models.query.is_empty() {
                    self.picker.models.query.pop();
                }
                if !insert.is_empty() {
                    self.picker.models.query.push_str(insert);
                }
                self.picker.models.cursor = 0;
            }
            PickerPhase::Wait => {}
        }
    }

    fn selected_picker_entry(&mut self) -> Option<PickerEntry> {
        let frame = self.active_picker_frame_mut()?;
        let rows = frame.rows();
        let count = selectable_count(&rows);
        if count == 0 {
            frame.cursor = 0;
            return None;
        }
        frame.cursor = frame.cursor.min(count - 1);
        let target = frame.cursor as isize;
        rows.into_iter()
            .find(|r| r.selectable == target)
            .and_then(|r| r.entry)
    }

    fn activate_picker(&mut self) {
        match self.picker.phase {
            PickerPhase::Key => {
                if self.picker.key.trim().is_empty() {
                    self.picker.err = "API key is required".to_string();
                    return;
                }
                self.picker.phase = PickerPhase::Wait;
                self.picker.message = "Checking the key…".to_string();
                self.picker.err.clear();
                let id = self.picker.leaf_id.clone();
                let api_key = self.picker.key.clone();
                self.send_command("llm.connect", json!({ "id": id, "api_key": api_key }));
            }
            PickerPhase::Wait => {}
            PickerPhase::List | PickerPhase::Models => {
                if let Some(entry) = self.selected_picker_entry() {
                    self.choose_picker_entry(entry);
                }
            }
        }
    }

    fn choose_picker_entry(&mut self, entry: PickerEntry) {
        if !entry.children.is_empty() {
            let prev = self.picker.frame.clone();
            self.picker.stack.push(prev);
            self.picker.frame = PickerFrame {
                title: entry.label.clone(),
                sections: vec![PickerSection {
                    title: String::new(),
                    entries: entry.children,
                }],
                cursor: 0,
                query: String::new(),
            };
            self.picker.title = entry.label;
            self.picker.err.clear();
            return;
        }
        match entry.auth.as_str() {
            "swarm_scope" => self.open_model_picker_with_scope(&entry.id),
            "swarm_profile" => {
                self.send_command(
                    "llm.set_swarm",
                    json!({ "action": "profile", "profile": entry.id }),
                );
            }
            "swarm_reset" => {
                self.send_command("llm.set_swarm", json!({ "action": "inherit" }));
            }
            "openviking_action" => match entry.id.as_str() {
                "openviking_inherit" => {
                    self.send_command("llm.set_swarm", json!({ "action": "openviking_inherit" }));
                }
                "openviking_toggle" => {
                    self.send_command("llm.set_swarm", json!({ "action": "openviking_toggle" }));
                }
                "embed:local" => {
                    self.send_command(
                        "llm.set_swarm",
                        json!({
                            "action": "openviking_embed",
                            "provider": "local",
                            "model": "local-fast-512",
                        }),
                    );
                }
                "embed:openai" => {
                    self.send_command(
                        "llm.set_swarm",
                        json!({
                            "action": "openviking_embed",
                            "provider": "openai",
                            "model": "text-embedding-3-small",
                        }),
                    );
                }
                _ => {}
            },
            "model" => {
                self.picker.message = "Saving…".to_string();
                let scope = if self.picker.scope.is_empty() {
                    "both".to_string()
                } else {
                    self.picker.scope.clone()
                };
                if let Some(role) = scope.strip_prefix("role:") {
                    self.send_command(
                        "llm.select_model",
                        json!({
                            "model": entry.id,
                            "target": "swarm",
                            "role": role,
                        }),
                    );
                } else {
                    self.send_command(
                        "llm.select_model",
                        json!({
                            "model": entry.id,
                            "target": scope,
                        }),
                    );
                }
            }
            "effort" => {
                self.send_command("llm.set_effort", json!({ "effort": entry.id }));
            }
            "api_key" => {
                self.picker.phase = PickerPhase::Key;
                self.picker.title = entry.label;
                self.picker.key.clear();
                self.picker.err.clear();
                self.picker.leaf_id = entry.id;
            }
            _ => {
                self.picker.phase = PickerPhase::Wait;
                self.picker.title = entry.label;
                self.picker.message = "Waiting for sign-in…".to_string();
                self.picker.url.clear();
                self.picker.user_code.clear();
                self.picker.err.clear();
                self.picker.leaf_id = entry.id.clone();
                self.send_command("llm.connect", json!({ "id": entry.id }));
            }
        }
    }

    fn back_picker(&mut self) {
        match self.picker.phase {
            PickerPhase::Key => {
                self.picker.phase = PickerPhase::List;
                self.picker.key.clear();
                self.picker.err.clear();
                self.picker.title = if self.picker.frame.title.is_empty() {
                    "Select model".to_string()
                } else {
                    self.picker.frame.title.clone()
                };
            }
            PickerPhase::Wait | PickerPhase::Models => {
                self.send_command("llm.auth_cancel", json!({}));
                self.picker.phase = PickerPhase::List;
                self.picker.poll_in_flight = false;
                self.picker.err.clear();
                self.picker.message.clear();
                self.picker.title = if self.picker.frame.title.is_empty() {
                    "Select model".to_string()
                } else {
                    self.picker.frame.title.clone()
                };
            }
            PickerPhase::List => {
                if let Some(prev) = self.picker.stack.pop() {
                    self.picker.title = if prev.title.is_empty() {
                        "Select model".to_string()
                    } else {
                        prev.title.clone()
                    };
                    self.picker.frame = prev;
                    self.picker.err.clear();
                } else {
                    self.close_modal();
                }
            }
        }
    }

    fn handle_header_virtual_button_click(&mut self, col: u16) -> bool {
        if col < 2 {
            return false;
        }
        let rel = (col - 2) as usize;
        let total_mcp = self.snapshot.connections.len();
        let live_mcp = self.snapshot.connections.iter().filter(|c| !c.dead).count();
        let f2_str = " F2  All Agents   ";
        let f3_str = format!(" F3  MCPs {live_mcp}/{total_mcp}   ");
        let f4_str = format!(" F4  Skills {}   ", self.registered_skill_count());
        let f5_str = format!(
            " F5 / F  Findings {}   ",
            self.snapshot.vulnerabilities.len()
        );
        let f1_str = " F1  Help    ";

        let mut cursor = 0usize;
        let f2_end = cursor + unicode_width::UnicodeWidthStr::width(f2_str);
        if rel < f2_end {
            if !self.snapshot.agents.is_empty() {
                self.all_agents_view = !self.all_agents_view;
                self.follow_output = true;
            }
            return true;
        }
        cursor = f2_end;
        let f3_end = cursor + unicode_width::UnicodeWidthStr::width(f3_str.as_str());
        if rel < f3_end {
            self.open_modal(ModalMode::Mcp);
            return true;
        }
        cursor = f3_end;
        let f4_end = cursor + unicode_width::UnicodeWidthStr::width(f4_str.as_str());
        if rel < f4_end {
            self.open_skills_modal();
            return true;
        }
        cursor = f4_end;
        let f5_end = cursor + unicode_width::UnicodeWidthStr::width(f5_str.as_str());
        if rel < f5_end {
            self.open_modal(ModalMode::Findings);
            return true;
        }
        cursor = f5_end;
        let f1_end = cursor + unicode_width::UnicodeWidthStr::width(f1_str);
        if rel < f1_end {
            self.open_modal(ModalMode::Help);
            return true;
        }
        false
    }

    fn handle_top_agent_tab_click(&mut self, col: u16) {
        self.focus = FocusMode::Agents;
        if col < 2 || self.snapshot.agents.is_empty() {
            return;
        }
        let rel = (col - 2) as usize;
        let all_lbl = " 0 All agents ";
        let mut cursor = unicode_width::UnicodeWidthStr::width(all_lbl);
        if rel < cursor {
            self.all_agents_view = true;
            self.follow_output = true;
            return;
        }
        for (i, ag) in self.snapshot.agents.iter().enumerate() {
            let sep_w = 3usize; // " │ "
            let tab_lbl = format!(" {} {} ", i + 1, ag.name);
            let tab_w = unicode_width::UnicodeWidthStr::width(tab_lbl.as_str());
            let start = cursor + sep_w;
            let end = start + tab_w;
            if rel >= cursor && rel < end {
                self.all_agents_view = false;
                self.selected_agent = i;
                self.follow_output = true;
                return;
            }
            cursor = end;
        }
    }

    fn sidebar_agents_bounds(&self, sidebar_w: u16) -> (u16, u16) {
        let top_h = 3u16.min(self.height);
        let mut cur_y = top_h;
        let mut stats_rows = 2usize; // Profile + Version + Memory minimum
        if !self.display_model_name().is_empty() {
            stats_rows += 1;
            let sw = self.display_swarm_model_name();
            if !sw.is_empty() && sw != self.display_model_name() {
                stats_rows += 1;
            }
        }
        if self.snapshot.subscription {
            stats_rows += 1;
        }
        if self
            .snapshot
            .usage
            .get("total_tokens")
            .and_then(|v| v.as_f64())
            .is_some_and(|t| t as i64 > 0)
        {
            stats_rows += 1;
        }
        if !self.snapshot.caido_url.is_empty() {
            stats_rows += 1;
        }
        stats_rows += 1; // Memory row
        let stats_h = ((stats_rows as u16) + 2)
            .clamp(3, 10)
            .min(self.height.saturating_sub(3));
        let stats_top = self.height.saturating_sub(stats_h);

        if !self.snapshot.targets.is_empty() {
            let total = self.snapshot.target_count.max(self.snapshot.targets.len());
            let mut visible = self.snapshot.targets.len().min(4).min(5);
            if visible < total {
                visible = visible.min(4);
            }
            let t_rows = 1 + visible + usize::from(total > visible);
            if sidebar_w > 4 && stats_top.saturating_sub(cur_y) >= (t_rows as u16 + 7) {
                cur_y += t_rows as u16 + 2;
            }
        }
        (cur_y, stats_top)
    }

    pub fn handle_mouse(&mut self, mouse: MouseEvent) {
        if self.show_splash || !self.ready {
            return;
        }
        let show_sidebar = self.width >= 90 && !self.sidebar_hidden;
        let sidebar_w: u16 = if show_sidebar {
            (self.width / 5).max(24)
        } else if self.sidebar_hidden && self.width >= 90 {
            6
        } else {
            0
        };
        let chat_w = if sidebar_w > 0 {
            self.width.saturating_sub(sidebar_w + 1)
        } else {
            self.width
        };

        match mouse.kind {
            MouseEventKind::ScrollUp => {
                if self.modal == ModalMode::Picker {
                    self.move_picker(-3);
                } else if self.modal == ModalMode::Skills {
                    self.move_skill_selection(-3);
                } else if self.modal == ModalMode::Findings {
                    self.move_vulnerability_selection(-3);
                } else if self.modal == ModalMode::Vulnerability {
                    self.vuln_report_scroll = self.vuln_report_scroll.saturating_sub(3);
                } else if !self.snapshot.setup_mode
                    && ((show_sidebar && mouse.column >= chat_w)
                        || (mouse.column < chat_w && (3..=5).contains(&mouse.row)))
                {
                    self.focus = FocusMode::Agents;
                    self.step_agent_selection(-1, false);
                } else {
                    self.follow_output = false;
                    self.chat_scroll = self.chat_scroll.saturating_sub(3);
                }
            }
            MouseEventKind::ScrollDown => {
                if self.modal == ModalMode::Picker {
                    self.move_picker(3);
                } else if self.modal == ModalMode::Skills {
                    self.move_skill_selection(3);
                } else if self.modal == ModalMode::Findings {
                    self.move_vulnerability_selection(3);
                } else if self.modal == ModalMode::Vulnerability {
                    self.vuln_report_scroll = self.vuln_report_scroll.saturating_add(3);
                } else if !self.snapshot.setup_mode
                    && ((show_sidebar && mouse.column >= chat_w)
                        || (mouse.column < chat_w && (3..=5).contains(&mouse.row)))
                {
                    self.focus = FocusMode::Agents;
                    self.step_agent_selection(1, false);
                } else {
                    let max_scroll = self
                        .chat_total_lines
                        .saturating_sub(self.chat_visible_lines);
                    self.chat_scroll = (self.chat_scroll + 3).min(max_scroll);
                    if self.chat_scroll >= max_scroll {
                        self.follow_output = true;
                    }
                }
            }
            MouseEventKind::Down(MouseButton::Left) => {
                if self.modal != ModalMode::None {
                    if self.modal == ModalMode::Help || self.modal == ModalMode::Mcp {
                        self.close_modal();
                    }
                    return;
                }
                if self.snapshot.setup_mode {
                    self.focus = FocusMode::Input;
                    return;
                }
                if mouse.column < chat_w {
                    if mouse.row == 2 && self.handle_header_virtual_button_click(mouse.column) {
                        return;
                    }
                    if mouse.row == 4 {
                        self.handle_top_agent_tab_click(mouse.column);
                        return;
                    }
                    if mouse.row == 5 {
                        self.focus = FocusMode::Agents;
                        return;
                    }
                    if mouse.row >= self.height.saturating_sub(5) {
                        self.focus = FocusMode::Input;
                    } else {
                        self.focus = FocusMode::Chat;
                    }
                } else if sidebar_w > 0 {
                    if self.sidebar_hidden {
                        if mouse.row < 3 && mouse.column >= self.width.saturating_sub(6) {
                            self.sidebar_hidden = false;
                        }
                        return;
                    }
                    if mouse.row < 3 {
                        if mouse.column >= self.width.saturating_sub(5) {
                            self.sidebar_hidden = !self.sidebar_hidden;
                        } else {
                            self.open_modal(ModalMode::Findings);
                        }
                        return;
                    }
                    let (agents_top, stats_top) = self.sidebar_agents_bounds(sidebar_w);
                    if mouse.row >= agents_top && mouse.row < stats_top {
                        self.focus = FocusMode::Agents;
                        let list_first_row = agents_top.saturating_add(3);
                        if mouse.row >= list_first_row {
                            let row_idx = (mouse.row - list_first_row) as usize;
                            let entries =
                                agent_tree_entries(&self.snapshot.agents, &self.collapsed_agents);
                            if let Some(entry) = entries.get(row_idx) {
                                self.all_agents_view = false;
                                self.selected_agent = entry.index;
                                self.follow_output = true;
                            }
                        } else {
                            self.all_agents_view = false;
                            self.follow_output = true;
                        }
                    } else if mouse.row >= stats_top {
                        self.open_swarm_picker();
                    }
                }
            }
            _ => {}
        }
    }
}

pub fn selected_agent_index(agents: &[Agent], selected_id: &str) -> usize {
    if !selected_id.is_empty() {
        if let Some(pos) = agents.iter().position(|a| a.id == selected_id) {
            return pos;
        }
    }
    0
}

pub fn looks_like_target(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    if token.contains("://") || token.ends_with(".git") {
        return true;
    }
    if token.starts_with('/')
        || token.starts_with("./")
        || token.starts_with("~/")
        || token.starts_with("../")
    {
        return true;
    }
    if token.parse::<IpAddr>().is_ok() {
        return true;
    }
    let mut host = token;
    if let Some((_, after_at)) = host.rsplit_once('@') {
        host = after_at;
    }
    host = host.split('/').next().unwrap_or(host);
    host = host.split(':').next().unwrap_or(host);
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    for part in &parts {
        if part.is_empty()
            || part.starts_with('-')
            || part.ends_with('-')
            || !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return false;
        }
    }
    let tld = parts.last().copied().unwrap_or_default();
    tld.len() >= 2 && !tld.chars().all(|c| c.is_ascii_digit())
}

fn copy_to_system_clipboard(text: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        if let Ok(mut child) = Command::new("pbcopy").stdin(Stdio::piped()).spawn() {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            if child.wait().is_ok_and(|s| s.success()) {
                return Ok(());
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        for (bin, args) in [
            ("wl-copy", &[][..]),
            ("xclip", &["-selection", "clipboard"][..]),
            ("xsel", &["--clipboard", "--input"][..]),
        ] {
            if let Ok(mut child) = Command::new(bin).args(args).stdin(Stdio::piped()).spawn() {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(text.as_bytes());
                }
                if child.wait().map_or(false, |s| s.success()) {
                    return Ok(());
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::TransportStream;
    #[cfg(unix)]
    use std::os::unix::net::UnixStream;

    fn sized_state() -> AppState {
        let mut s = AppState::new(None, None);
        s.width = 120;
        s.height = 40;
        s.show_splash = false;
        s
    }

    #[test]
    fn test_state_revision_preserves_streamed_history() {
        let mut s = sized_state();
        s.snapshot.events = vec![Event {
            id: "proof".to_string(),
            version: 1,
            ..Default::default()
        }];
        s.snapshot.agents = vec![Agent {
            id: "worker".to_string(),
            status: "running".to_string(),
            ..Default::default()
        }];

        s.handle_envelope(Envelope {
            version: 3,
            msg_type: "state".to_string(),
            request_id: String::new(),
            payload: json!({
                "revision": 2,
                "state": { "scan_state": "running" }
            }),
        });
        s.handle_envelope(Envelope {
            version: 3,
            msg_type: "state".to_string(),
            request_id: String::new(),
            payload: json!({
                "revision": 1,
                "state": { "scan_state": "stale" }
            }),
        });
        assert_eq!(s.state_revision, 2);
        assert_eq!(s.snapshot.scan_state, "running");
        assert_eq!(s.snapshot.events.len(), 1);
        assert_eq!(s.snapshot.agents.len(), 1);
    }

    #[test]
    fn test_collection_bootstrap_is_atomic_and_rejects_duplicate_ids() {
        let mut s = sized_state();
        s.snapshot.events = vec![Event {
            id: "old".to_string(),
            ..Default::default()
        }];
        s.handle_envelope(Envelope {
            version: 3,
            msg_type: "collection_bootstrap".to_string(),
            request_id: String::new(),
            payload: json!({
                "collection": "events",
                "revision": 1,
                "cursor": 0,
                "next_cursor": 1,
                "done": false,
                "items": [{"id": "new", "version": 1}]
            }),
        });
        assert_eq!(s.snapshot.events[0].id, "old");

        // Duplicate ID in second chunk is rejected
        s.handle_envelope(Envelope {
            version: 3,
            msg_type: "collection_bootstrap".to_string(),
            request_id: String::new(),
            payload: json!({
                "collection": "events",
                "revision": 1,
                "cursor": 1,
                "next_cursor": 2,
                "done": true,
                "items": [{"id": "new", "version": 1}]
            }),
        });
        assert_eq!(s.snapshot.events[0].id, "old");
        assert_eq!(*s.collection_revisions.get("events").unwrap_or(&0), 0);

        // Single valid chunk commits
        s.handle_envelope(Envelope {
            version: 3,
            msg_type: "collection_bootstrap".to_string(),
            request_id: String::new(),
            payload: json!({
                "collection": "events",
                "revision": 1,
                "cursor": 0,
                "next_cursor": 1,
                "done": true,
                "items": [{"id": "new", "version": 1}]
            }),
        });
        assert_eq!(s.snapshot.events.len(), 1);
        assert_eq!(s.snapshot.events[0].id, "new");
        assert_eq!(s.collection_revisions["events"], 1);
    }

    #[test]
    fn test_collection_delta_rejects_stale_events_and_rolls_back_whole_batch() {
        let mut s = sized_state();
        s.snapshot.events = vec![Event {
            id: "existing".to_string(),
            version: 2,
            ..Default::default()
        }];
        let mut ops = vec![
            CollectionOperation {
                op: "upsert".to_string(),
                id: String::new(),
                item: json!({"id": "new", "version": 1}),
            },
            CollectionOperation {
                op: "upsert".to_string(),
                id: String::new(),
                item: json!({"id": "existing", "version": 1}),
            },
        ];
        assert!(!s.apply_collection_operations("events", &ops));
        assert_eq!(s.snapshot.events.len(), 1);
        assert_eq!(s.snapshot.events[0].version, 2);

        ops[1].item = json!({"id": "existing", "version": 3});
        assert!(s.apply_collection_operations("events", &ops));
        assert_eq!(s.snapshot.events.len(), 2);
        assert_eq!(s.snapshot.events[0].version, 3);
    }

    #[cfg(unix)]
    #[test]
    fn test_stop_requires_explicit_confirmation_and_targets_selected_agent() {
        let (client_sock, peer_sock) = UnixStream::pair().expect("pair");
        let client = Client::from_stream(TransportStream::Unix(client_sock)).expect("client");
        let peer = Client::from_stream(TransportStream::Unix(peer_sock)).expect("peer");

        let mut s = sized_state();
        s.client = Some(client);
        s.snapshot.agents = vec![Agent {
            id: "worker".to_string(),
            name: "Worker".to_string(),
            status: "running".to_string(),
            ..Default::default()
        }];

        // Esc opens stop modal with default Cancel (choice = 1)
        s.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(s.modal, ModalMode::Stop);
        assert_eq!(s.modal_choice, 1);

        // Enter on Cancel closes modal without sending stop
        s.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(s.modal, ModalMode::None);

        // Esc, Left, Enter confirms stop
        s.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        s.handle_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
        s.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));

        let env = peer.read().expect("read stop command");
        assert_eq!(env.msg_type, "agent.stop");
        assert_eq!(env.payload["agent_id"], "worker");
    }

    #[cfg(unix)]
    #[test]
    fn test_function_key_modals_and_slash_commands() {
        let (client_sock, peer_sock) = UnixStream::pair().expect("pair");
        let client = Client::from_stream(TransportStream::Unix(client_sock)).expect("client");
        let peer = Client::from_stream(TransportStream::Unix(peer_sock)).expect("peer");

        let mut s = sized_state();
        s.client = Some(client);
        s.snapshot.agents = vec![Agent {
            id: "root".to_string(),
            name: "RedJohn".to_string(),
            status: "running".to_string(),
            ..Default::default()
        }];
        s.snapshot.skills = vec!["sql-injection".to_string(), "xss".to_string()];
        s.snapshot.skill_count = 59;

        // F3 -> MCP modal
        s.handle_key(KeyEvent::new(KeyCode::F(3), KeyModifiers::NONE));
        assert_eq!(s.modal, ModalMode::Mcp);
        s.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(s.modal, ModalMode::None);

        // F5 -> Findings modal
        s.handle_key(KeyEvent::new(KeyCode::F(5), KeyModifiers::NONE));
        assert_eq!(s.modal, ModalMode::Findings);
        s.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(s.modal, ModalMode::None);

        // /swarm opens Swarm picker
        s.submit("/swarm");
        assert_eq!(s.modal, ModalMode::Picker);
        assert!(s.picker.title.contains("Swarm"));
        s.close_modal();

        // /rj sends pentest.run
        s.submit("/rj https://target.local focus on auth");
        let env = peer.read().expect("read pentest.run");
        assert_eq!(env.msg_type, "pentest.run");
        assert_eq!(env.payload["target"], "https://target.local");
        assert_eq!(env.payload["instruction"], "focus on auth");

        // /swarm <profile> updates swarm_profile and sends llm.set_swarm
        s.submit("/swarm recon");
        assert_eq!(s.snapshot.swarm_profile, "recon");
        let env2 = peer.read().expect("read llm.set_swarm");
        assert_eq!(env2.msg_type, "llm.set_swarm");
        assert_eq!(env2.payload["action"], "profile");
        assert_eq!(env2.payload["profile"], "recon");

        // /openviking opens OpenViking picker
        s.submit("/openviking");
        assert_eq!(s.modal, ModalMode::Picker);
        assert!(s.picker.title.contains("OpenViking"));
        s.close_modal();

        // Up/Down arrow keys cycle command history in FocusMode::Input
        s.focus = FocusMode::Input;
        s.input_text = "draft in progress".to_string();
        s.input_cursor = s.input_text.len();

        s.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(s.input_text, "/openviking");
        s.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(s.input_text, "/swarm recon");
        s.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(s.input_text, "/openviking");
        s.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(s.input_text, "draft in progress");
    }

    #[test]
    fn test_short_model_name_and_report_fence() {
        assert_eq!(
            short_model_name(
                "abliteration/Qwen3.5-27B-Claude-4.6-Opus-Deckard-Heretic-Uncensored-GGUF:Q8_0"
            ),
            "Qwen3.5"
        );
        assert_eq!(short_model_name("zai/glm-5.3"), "GLM5.3");

        let mut v = Map::new();
        v.insert("title".to_string(), json!("Owned finding"));
        v.insert("severity".to_string(), json!("high"));
        v.insert(
            "poc_script_code".to_string(),
            json!("print('owned')\n````\n# injected heading"),
        );
        let report = vulnerability_markdown_report(&v);
        assert!(report.contains("`````python\nprint('owned')\n````\n# injected heading\n`````"));
    }

    #[test]
    fn test_mouse_virtual_buttons_and_agent_switching() {
        let mut s = sized_state();
        s.ready = true;
        s.snapshot.setup_mode = false;
        s.snapshot.agents = vec![
            Agent {
                id: "root".to_string(),
                name: "RedJohn".to_string(),
                status: "running".to_string(),
                ..Default::default()
            },
            Agent {
                id: "recon".to_string(),
                name: "ReconAgent".to_string(),
                parent_id: Some("root".to_string()),
                status: "running".to_string(),
                ..Default::default()
            },
            Agent {
                id: "exploit".to_string(),
                name: "ExploitAgent".to_string(),
                parent_id: Some("root".to_string()),
                status: "running".to_string(),
                ..Default::default()
            },
        ];

        let left_click = |col: u16, row: u16| MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: col,
            row,
            modifiers: KeyModifiers::NONE,
        };

        // Click F2 virtual button on row 2 -> toggles all_agents_view
        assert!(!s.all_agents_view);
        s.handle_mouse(left_click(4, 2));
        assert!(s.all_agents_view);

        // Click F3 virtual button on row 2 -> opens MCP modal
        s.handle_mouse(left_click(22, 2));
        assert_eq!(s.modal, ModalMode::Mcp);
        s.close_modal();

        // Click top agent tab "2 ReconAgent" on row 4 -> focuses Agents and selects agent 1
        s.handle_mouse(left_click(34, 4));
        assert_eq!(s.focus, FocusMode::Agents);
        assert!(!s.all_agents_view);
        assert_eq!(s.selected_agent, 1);

        // Pressing Down arrow in FocusMode::Agents moves to agent 2 (ExploitAgent)
        s.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(s.selected_agent, 2);

        // Pressing Up arrow in FocusMode::Agents moves back to agent 1 (ReconAgent)
        s.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(s.selected_agent, 1);

        // Click on the right sidebar Agents panel row for agent 0 (RedJohn) -> row = 6
        s.handle_mouse(left_click(105, 6));
        assert_eq!(s.focus, FocusMode::Agents);
        assert_eq!(s.selected_agent, 0);

        // Click on the right sidebar Agents panel row for agent 2 (ExploitAgent) -> row = 8
        s.handle_mouse(left_click(105, 8));
        assert_eq!(s.focus, FocusMode::Agents);
        assert_eq!(s.selected_agent, 2);
    }
}
