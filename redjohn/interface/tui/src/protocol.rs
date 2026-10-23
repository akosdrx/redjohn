use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;

pub const PROTOCOL_VERSION: u32 = 3;

pub const CAPABILITIES: &[&str] = &[
    "state-revisions",
    "collection-deltas",
    "structured-command-errors",
    "agents-collection",
];

fn null_to_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    #[serde(default, deserialize_with = "null_to_default")]
    pub version: u32,
    #[serde(rename = "type", default, deserialize_with = "null_to_default")]
    pub msg_type: String,
    #[serde(
        default,
        deserialize_with = "null_to_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub request_id: String,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Hello {
    #[serde(default, deserialize_with = "null_to_default")]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Message {
    #[serde(default, deserialize_with = "null_to_default")]
    pub id: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub text: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Agent {
    #[serde(default, deserialize_with = "null_to_default")]
    pub id: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub name: String,
    #[serde(default)]
    pub parent_id: Option<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub status: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub error_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Connection {
    #[serde(default, deserialize_with = "null_to_default")]
    pub name: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub tool_count: usize,
    #[serde(default, deserialize_with = "null_to_default")]
    pub dead: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Event {
    #[serde(default, deserialize_with = "null_to_default")]
    pub id: String,
    #[serde(rename = "type", default, deserialize_with = "null_to_default")]
    pub event_type: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub agent_id: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub timestamp: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub version: i64,
    #[serde(default, deserialize_with = "null_to_default")]
    pub data: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SkillEntry {
    #[serde(default, deserialize_with = "null_to_default")]
    pub name: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub category: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub description: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub available: bool,
    #[serde(default, deserialize_with = "null_to_default")]
    pub missing: Vec<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub selected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Snapshot {
    #[serde(default, deserialize_with = "null_to_default")]
    pub setup_mode: bool,
    #[serde(default, deserialize_with = "null_to_default")]
    pub scan_started: bool,
    #[serde(default, deserialize_with = "null_to_default")]
    pub scan_state: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub targets: Vec<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub target_count: usize,
    #[serde(default, deserialize_with = "null_to_default")]
    pub working_dir: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub pending_mount: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub instruction: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub scan_mode: String,
    #[serde(default)]
    pub max_budget_usd: Option<f64>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub max_turns: usize,
    #[serde(default, deserialize_with = "null_to_default")]
    pub scope_mode: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub diff_base: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub model: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub short_model: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub reasoning_effort: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub supported_efforts: Vec<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub swarm_model: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub short_swarm_model: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub swarm_reasoning_effort: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub swarm_profile: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub swarm_role_models: HashMap<String, String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub openviking_online: bool,
    #[serde(default, deserialize_with = "null_to_default")]
    pub openviking_model: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub openviking_embed_model: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub selected_skills: Vec<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub caido_url: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub messages: Vec<Message>,
    #[serde(skip)]
    pub agents: Vec<Agent>,
    #[serde(skip)]
    pub events: Vec<Event>,
    #[serde(skip)]
    pub vulnerabilities: Vec<Map<String, Value>>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub usage: Map<String, Value>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub subscription: bool,
    #[serde(default, deserialize_with = "null_to_default")]
    pub connections: Vec<Connection>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub skills: Vec<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub skill_count: usize,
    #[serde(default, deserialize_with = "null_to_default")]
    pub viewer_status: String,
    #[serde(default)]
    pub viewer_url: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub projection_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StateUpdate {
    #[serde(default, deserialize_with = "null_to_default")]
    pub revision: i64,
    #[serde(default, deserialize_with = "null_to_default")]
    pub state: Snapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CollectionBootstrap {
    #[serde(default, deserialize_with = "null_to_default")]
    pub collection: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub revision: i64,
    #[serde(default, deserialize_with = "null_to_default")]
    pub cursor: usize,
    #[serde(default, deserialize_with = "null_to_default")]
    pub next_cursor: usize,
    #[serde(default, deserialize_with = "null_to_default")]
    pub done: bool,
    #[serde(default, deserialize_with = "null_to_default")]
    pub items: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CollectionOperation {
    #[serde(default, deserialize_with = "null_to_default")]
    pub op: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub id: String,
    #[serde(default)]
    pub item: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CollectionDelta {
    #[serde(default, deserialize_with = "null_to_default")]
    pub collection: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub base_revision: i64,
    #[serde(default, deserialize_with = "null_to_default")]
    pub revision: i64,
    #[serde(default, deserialize_with = "null_to_default")]
    pub cursor: usize,
    #[serde(default, deserialize_with = "null_to_default")]
    pub next_cursor: usize,
    #[serde(default, deserialize_with = "null_to_default")]
    pub done: bool,
    #[serde(default, deserialize_with = "null_to_default")]
    pub operations: Vec<CollectionOperation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CommandError {
    #[serde(default, deserialize_with = "null_to_default")]
    pub code: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub message: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub retryable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CommandResult {
    #[serde(default, deserialize_with = "null_to_default")]
    pub ok: bool,
    #[serde(default, deserialize_with = "null_to_default")]
    pub command: String,
    #[serde(default)]
    pub result: Value,
    #[serde(default)]
    pub error: Option<CommandError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PickerEntry {
    #[serde(default, deserialize_with = "null_to_default")]
    pub id: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub label: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub auth: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub children: Vec<PickerEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PickerSection {
    #[serde(default, deserialize_with = "null_to_default")]
    pub title: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub entries: Vec<PickerEntry>,
}
