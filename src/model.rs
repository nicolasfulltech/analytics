use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    Pageview,
    Search,
    Custom,
}

impl EventType {
    pub fn as_str(self) -> &'static str {
        match self {
            EventType::Pageview => "pageview",
            EventType::Search => "search",
            EventType::Custom => "custom",
        }
    }
}

/// Payload accepted by the ingestion endpoints.
///
/// Fields populated server-side (device, source, visitor hash, utm_*, timestamp)
/// are not expected from the client; any client-supplied values are ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct IncomingEvent {
    #[serde(rename = "type", default = "default_event_type")]
    pub event_type: EventType,

    #[serde(default)]
    pub name: Option<String>,

    pub url: String,

    #[serde(default)]
    pub title: Option<String>,

    #[serde(default)]
    pub referer: Option<String>,

    #[serde(default)]
    pub segments: Vec<String>,

    /// HMAC-signed user object (raw JSON string as signed). Paired with
    /// `user_sig`. The server re-hashes these exact bytes before trusting the
    /// object — prevents forged attribution from the public browser path.
    #[serde(default)]
    pub user: Option<String>,

    /// Hex blake3 keyed MAC over the `user` bytes. Required when `user` is set.
    #[serde(default)]
    pub user_sig: Option<String>,

    #[serde(default)]
    pub search: Option<SearchPayload>,

    #[serde(default)]
    pub extra: Option<serde_json::Value>,
}

fn default_event_type() -> EventType {
    EventType::Pageview
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchPayload {
    pub query: String,
    #[serde(default)]
    pub result_count: Option<i64>,
    #[serde(default)]
    pub results: Option<Vec<String>>,
    #[serde(default)]
    pub clicked_result: Option<String>,
}
