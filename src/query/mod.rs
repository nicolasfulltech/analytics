pub mod aggregates;
pub mod export;

use axum::Json;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::routing::get;
use serde::{Deserialize, Serialize};
use sqlx::{QueryBuilder, Sqlite};

use crate::auth::{AdminAuth, ReadAuth};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// Column list for the `events` table. Referenced by `list_events`, export, and
/// the webhook delivery loader so adding a column is a one-line change.
pub(crate) const EVENTS_COLUMNS: &str = "id, ts, event_type, event_name, url, page_title, user_agent, \
     device_type, device_os, device_browser, referer, source, \
     utm_source, utm_medium, utm_campaign, utm_term, utm_content, \
     visitor_hash, segments, extra, user_id, country, user, session_id";

pub fn routes() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/events", get(list_events).delete(delete_events))
        .route("/stats", get(aggregates::stats_handler))
        .route("/stats/urls", get(aggregates::url_stats_handler))
        .route("/stats/pages", get(aggregates::page_stats_handler))
        .route("/stats/user_pages", get(aggregates::user_pages_handler))
        .route("/stats/sources", get(aggregates::source_stats_handler))
        .route("/stats/timeseries", get(aggregates::timeseries_handler))
        .route("/stats/searches", get(aggregates::searches_handler))
        .route(
            "/stats/user_timeline",
            get(aggregates::user_timeline_handler),
        )
        .route("/stats/funnels", get(aggregates::funnels_handler))
        .route(
            "/stats/new_returning",
            get(aggregates::new_returning_handler),
        )
        .route("/export", get(export::export_handler))
}

#[derive(Debug, Deserialize, Default)]
pub struct EventFilters {
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub event_type: Option<String>,
    pub source: Option<String>,
    pub device_type: Option<String>,
    pub segment: Option<String>,
    pub url: Option<String>,
    pub user_id: Option<String>,
    pub country: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl EventFilters {
    pub fn limit(&self) -> i64 {
        self.limit.unwrap_or(100).clamp(1, 1_000)
    }

    pub fn offset(&self) -> i64 {
        // Cap offset to keep a single read from being a full-table scan when
        // the caller pages past the tail of the data. SQLite's OFFSET is
        // O(offset + limit) — an attacker with `?offset=i64::MAX` would pin
        // a pool connection for the duration of the scan.
        self.offset.unwrap_or(0).clamp(0, 1_000_000)
    }
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct EventRow {
    pub id: i64,
    pub ts: i64,
    pub event_type: String,
    pub event_name: Option<String>,
    pub url: String,
    pub page_title: Option<String>,
    pub user_agent: String,
    pub device_type: Option<String>,
    pub device_os: Option<String>,
    pub device_browser: Option<String>,
    pub referer: Option<String>,
    pub source: Option<String>,
    pub utm_source: Option<String>,
    pub utm_medium: Option<String>,
    pub utm_campaign: Option<String>,
    pub utm_term: Option<String>,
    pub utm_content: Option<String>,
    pub visitor_hash: String,
    #[serde(serialize_with = "serialize_json_string")]
    pub segments: Option<String>,
    #[serde(serialize_with = "serialize_json_string")]
    pub extra: Option<String>,
    pub user_id: Option<String>,
    pub country: Option<String>,
    /// Full JSON of the verified user object, when present. Serialized as the
    /// parsed object so consumers don't have to JSON-decode twice.
    #[serde(serialize_with = "serialize_json_string")]
    pub user: Option<String>,
    pub session_id: Option<String>,
}

/// Serializer helper: when a column stores a JSON string, emit the parsed
/// value rather than the raw string, so clients see a proper nested object.
fn serialize_json_string<S>(v: &Option<String>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match v.as_deref() {
        Some(raw) => match serde_json::from_str::<serde_json::Value>(raw) {
            Ok(parsed) => parsed.serialize(s),
            Err(_) => raw.serialize(s),
        },
        None => s.serialize_none(),
    }
}

#[derive(Debug, Serialize)]
pub struct EventListResponse {
    pub events: Vec<serde_json::Value>,
    pub next_offset: Option<i64>,
}

async fn list_events(
    State(state): State<AppState>,
    _auth: ReadAuth,
    Query(filters): Query<EventFilters>,
) -> AppResult<impl IntoResponse> {
    let limit = filters.limit();
    let offset = filters.offset();
    let mut qb: QueryBuilder<Sqlite> =
        QueryBuilder::new(format!("SELECT {EVENTS_COLUMNS} FROM events WHERE 1=1"));
    push_filters(&mut qb, &filters);
    qb.push(" ORDER BY ts DESC, id DESC LIMIT ")
        .push_bind(limit)
        .push(" OFFSET ")
        .push_bind(offset);

    let rows: Vec<EventRow> = qb.build_query_as().fetch_all(&state.pool).await?;
    let count = rows.len() as i64;
    let expose_hash = state.config.privacy.expose_visitor_hash;
    let expose_user = state.config.privacy.expose_user_payload;
    let events: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            let mut v = serde_json::to_value(&r).unwrap_or(serde_json::Value::Null);
            if let Some(obj) = v.as_object_mut() {
                if !expose_hash {
                    obj.remove("visitor_hash");
                }
                // The `user` column carries the raw signed JSON blob (PII:
                // email, plan, etc.). Gate behind the same opt-in flag that
                // webhook delivery honors — otherwise any read-key holder
                // gets full user records regardless of operator config.
                if !expose_user {
                    obj.remove("user");
                }
            }
            v
        })
        .collect();

    let next_offset = if count == limit {
        Some(offset + limit)
    } else {
        None
    };

    Ok(Json(EventListResponse {
        events,
        next_offset,
    }))
}

/// GDPR right-to-be-forgotten. Admin-gated because a leaked read key must
/// never be able to delete. Accepts exactly one of `user_id` or
/// `visitor_hash` — not both — to avoid wide deletes.
#[derive(Debug, Deserialize)]
pub struct DeleteEventsQuery {
    pub user_id: Option<String>,
    pub visitor_hash: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeleteEventsResponse {
    pub deleted: u64,
}

async fn delete_events(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Query(q): Query<DeleteEventsQuery>,
) -> AppResult<Json<DeleteEventsResponse>> {
    let user_id = q.user_id.as_deref().filter(|s| !s.is_empty());
    let visitor_hash = q.visitor_hash.as_deref().filter(|s| !s.is_empty());

    let deleted = match (user_id, visitor_hash) {
        (Some(uid), None) => {
            let res = sqlx::query("DELETE FROM events WHERE user_id = ?")
                .bind(uid)
                .execute(&state.pool)
                .await?;
            res.rows_affected()
        }
        (None, Some(vh)) => {
            let res = sqlx::query("DELETE FROM events WHERE visitor_hash = ?")
                .bind(vh)
                .execute(&state.pool)
                .await?;
            res.rows_affected()
        }
        (Some(_), Some(_)) => {
            return Err(AppError::BadRequest(
                "specify exactly one of user_id or visitor_hash".into(),
            ));
        }
        (None, None) => {
            return Err(AppError::BadRequest(
                "user_id or visitor_hash is required".into(),
            ));
        }
    };

    // Aggregates may include deleted events; trigger a refresh by clearing
    // the materialization cursor so the next worker tick recomputes from
    // the now-smaller events table.
    let _ = sqlx::query("DELETE FROM materialization_cursor WHERE name = 'agg_daily'")
        .execute(&state.pool)
        .await;

    // Drop rollups for days whose last remaining event was just deleted.
    // Without this, `/stats?from=D&to=D` keeps reporting the pre-deletion
    // counts forever because the refresh worker's touched-days scan never
    // sees an event for `D` to trigger a rebuild.
    let _ = sqlx::query(
        "DELETE FROM agg_daily WHERE day NOT IN
           (SELECT DISTINCT strftime('%Y-%m-%d', ts/1000, 'unixepoch') FROM events)",
    )
    .execute(&state.pool)
    .await;
    let _ = sqlx::query(
        "DELETE FROM agg_daily_url WHERE day NOT IN
           (SELECT DISTINCT strftime('%Y-%m-%d', ts/1000, 'unixepoch') FROM events)",
    )
    .execute(&state.pool)
    .await;

    Ok(Json(DeleteEventsResponse { deleted }))
}

pub fn push_filters(qb: &mut QueryBuilder<'_, Sqlite>, f: &EventFilters) {
    if let Some(from) = f.from {
        qb.push(" AND ts >= ").push_bind(from);
    }
    if let Some(to) = f.to {
        qb.push(" AND ts <= ").push_bind(to);
    }
    if let Some(t) = &f.event_type {
        qb.push(" AND event_type = ").push_bind(t.clone());
    }
    if let Some(s) = &f.source {
        qb.push(" AND source = ").push_bind(s.clone());
    }
    if let Some(d) = &f.device_type {
        qb.push(" AND device_type = ").push_bind(d.clone());
    }
    if let Some(url) = &f.url {
        qb.push(" AND url = ").push_bind(url.clone());
    }
    if let Some(uid) = &f.user_id {
        qb.push(" AND user_id = ").push_bind(uid.clone());
    }
    if let Some(c) = &f.country {
        qb.push(" AND country = ").push_bind(c.to_ascii_uppercase());
    }
    if let Some(segment) = &f.segment {
        // segments column stores a JSON array like ["paid","club100"]
        qb.push(" AND EXISTS (SELECT 1 FROM json_each(segments) WHERE value = ")
            .push_bind(segment.clone())
            .push(")");
    }
}
