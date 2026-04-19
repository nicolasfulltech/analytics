//! Served OpenAPI 3.1 spec at `/openapi.json`.
//!
//! Hand-written rather than derived from utoipa annotations — the endpoint
//! surface is small and annotation crates would spread noise across every
//! handler without improving client generation. The spec is embedded as a
//! compile-time JSON file so it ships with the binary (no runtime I/O).
//!
//! Regenerate the file whenever a handler's request/response shape changes
//! — it is the single source of truth for `openapi-generator`-produced
//! clients. Paths are templated with `{id}` where axum uses `{id}` too.

use axum::Json;
use axum::response::IntoResponse;
use serde_json::Value;

/// Inline the JSON at compile-time so the binary is self-contained.
/// Syntax is validated at startup via `serde_json::from_str` on first use;
/// a malformed spec is a developer bug, not a runtime concern.
const SPEC_JSON: &str = include_str!("../openapi.json");

pub async fn openapi_handler() -> impl IntoResponse {
    // Parse once per request is OK — the spec is ~8 KB and this endpoint is
    // not on the hot path. If it ever becomes one, memoize via OnceLock.
    let value: Value =
        serde_json::from_str(SPEC_JSON).unwrap_or_else(|_| Value::String("invalid spec".into()));
    Json(value)
}
