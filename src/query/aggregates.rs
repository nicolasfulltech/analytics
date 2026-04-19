use std::time::Duration;

use axum::Json;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use sqlx::{QueryBuilder, Sqlite, SqlitePool};
use time::OffsetDateTime;
use tokio::time::interval;

use crate::auth::ReadAuth;
use crate::config::ServerConfig;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// Resolve a `(from, to)` millisecond window that is always bounded by
/// `server.stats_max_range_days`. When the caller omits one or both sides,
/// we default to the most recent `stats_default_range_days`. This prevents
/// naked `/stats/*` calls from running full-table scans with
/// `COUNT(DISTINCT visitor_hash)` — the stated DoS finding.
fn resolve_range(cfg: &ServerConfig, from: Option<i64>, to: Option<i64>) -> AppResult<(i64, i64)> {
    // Ingest writes ts as `now_nanos() / 1_000_000` (sub-second precision);
    // using `unix_timestamp() * 1000` here floors the current second and
    // can land BEFORE a just-inserted event's ts, making the default range
    // accidentally exclude the most recent writes. Use the same nanos-derived
    // value to stay consistent.
    let now_ms = i64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
        .unwrap_or(i64::MAX);
    let default_window_ms = i64::from(cfg.stats_default_range_days) * 86_400_000;
    let max_window_ms = i64::from(cfg.stats_max_range_days) * 86_400_000;

    let to = to.unwrap_or(now_ms);
    let from = from.unwrap_or_else(|| to.saturating_sub(default_window_ms));
    if from > to {
        return Err(AppError::BadRequest("`from` must be <= `to`".into()));
    }
    if to.saturating_sub(from) > max_window_ms {
        return Err(AppError::BadRequest(format!(
            "requested range exceeds server.stats_max_range_days ({}d)",
            cfg.stats_max_range_days
        )));
    }
    Ok((from, to))
}

/// Parse a `from_day`/`to_day` string. Only accepts the canonical
/// `YYYY-MM-DD` form; any other string (including empty) is a 400.
/// Without this, `from_day=1` silently becomes `"1" <= day` which matches
/// every row of `agg_daily` — a tautology that turns a filtered aggregate
/// into a full-rollup scan.
fn parse_day_opt(raw: Option<&String>, field: &str) -> AppResult<Option<time::Date>> {
    let Some(s) = raw else {
        return Ok(None);
    };
    let fmt = time::macros::format_description!("[year]-[month]-[day]");
    let date = time::Date::parse(s, &fmt)
        .map_err(|_| AppError::BadRequest(format!("{field} must be YYYY-MM-DD")))?;
    Ok(Some(date))
}

/// Resolve `(from_day, to_day)` for `/stats` which reads the daily rollup.
/// Same shape as `resolve_range` but in `Date` space.
fn resolve_day_range(
    cfg: &ServerConfig,
    from_day: Option<&String>,
    to_day: Option<&String>,
) -> AppResult<(time::Date, time::Date)> {
    let today = OffsetDateTime::now_utc().date();
    let to = parse_day_opt(to_day, "to_day")?.unwrap_or(today);
    let default_window = time::Duration::days(i64::from(cfg.stats_default_range_days));
    let from = parse_day_opt(from_day, "from_day")?.unwrap_or(to - default_window);
    if from > to {
        return Err(AppError::BadRequest(
            "`from_day` must be <= `to_day`".into(),
        ));
    }
    let span = (to - from).whole_days();
    if span > i64::from(cfg.stats_max_range_days) {
        return Err(AppError::BadRequest(format!(
            "requested day range exceeds server.stats_max_range_days ({}d)",
            cfg.stats_max_range_days
        )));
    }
    Ok((from, to))
}

#[derive(Debug, Deserialize, Default)]
pub struct StatsFilters {
    pub from_day: Option<String>,
    pub to_day: Option<String>,
    pub event_type: Option<String>,
    pub source: Option<String>,
    pub segment: Option<String>,
    pub device_type: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StatsRow {
    pub day: String,
    pub event_type: String,
    pub source: Option<String>,
    pub segment: Option<String>,
    pub device_type: Option<String>,
    pub country: Option<String>,
    pub count: i64,
    pub visitors: i64,
}

impl<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> for StatsRow {
    fn from_row(row: &'r sqlx::sqlite::SqliteRow) -> sqlx::Result<Self> {
        use sqlx::Row;
        Ok(Self {
            day: row.try_get("day")?,
            event_type: row.try_get("event_type")?,
            source: empty_to_none(row.try_get("source")?),
            segment: empty_to_none(row.try_get("segment")?),
            device_type: empty_to_none(row.try_get("device_type")?),
            country: empty_to_none(row.try_get("country")?),
            count: row.try_get("count")?,
            visitors: row.try_get("visitors")?,
        })
    }
}

fn empty_to_none(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}

pub async fn stats_handler(
    State(state): State<AppState>,
    _auth: ReadAuth,
    Query(f): Query<StatsFilters>,
) -> AppResult<impl IntoResponse> {
    // Resolve the day range up front so callers get a 400 on garbage
    // `from_day=1` instead of a silent full-rollup scan.
    let (from_day, to_day) =
        resolve_day_range(&state.config.server, f.from_day.as_ref(), f.to_day.as_ref())?;
    let from_day_s = format_day(from_day);
    let to_day_s = format_day(to_day);

    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        "SELECT day, event_type, source, segment, device_type, country, count, visitors
         FROM agg_daily WHERE day >= ",
    );
    qb.push_bind(from_day_s);
    qb.push(" AND day <= ");
    qb.push_bind(to_day_s);

    if let Some(t) = &f.event_type {
        qb.push(" AND event_type = ").push_bind(t.clone());
    }
    if let Some(s) = &f.source {
        qb.push(" AND source = ").push_bind(s.clone());
    }
    if let Some(s) = &f.segment {
        qb.push(" AND segment = ").push_bind(s.clone());
    }
    if let Some(d) = &f.device_type {
        qb.push(" AND device_type = ").push_bind(d.clone());
    }
    if let Some(c) = &f.country {
        qb.push(" AND country = ").push_bind(c.to_ascii_uppercase());
    }

    // Hard ceiling keeps the response memory bounded even when the configured
    // max range × dimensions would otherwise yield millions of rows.
    qb.push(" ORDER BY day DESC, event_type LIMIT 100000");

    let rows: Vec<StatsRow> = qb.build_query_as().fetch_all(&state.pool).await?;
    Ok(Json(rows))
}

fn format_day(d: time::Date) -> String {
    let fmt = time::macros::format_description!("[year]-[month]-[day]");
    d.format(&fmt).unwrap_or_default()
}

#[derive(Debug, Deserialize, Default)]
pub struct UrlStatsFilters {
    pub from_day: Option<String>,
    pub to_day: Option<String>,
    pub event_type: Option<String>,
    pub url: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct UrlStatsRow {
    pub day: String,
    pub url: String,
    pub event_type: String,
    pub count: i64,
    pub visitors: i64,
}

pub async fn url_stats_handler(
    State(state): State<AppState>,
    _auth: ReadAuth,
    Query(f): Query<UrlStatsFilters>,
) -> AppResult<impl IntoResponse> {
    let limit = f.limit.unwrap_or(1_000).clamp(1, 10_000);
    let (from_day, to_day) =
        resolve_day_range(&state.config.server, f.from_day.as_ref(), f.to_day.as_ref())?;
    let from_day_s = format_day(from_day);
    let to_day_s = format_day(to_day);

    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        "SELECT day, url, event_type, count, visitors
         FROM agg_daily_url WHERE day >= ",
    );
    qb.push_bind(from_day_s);
    qb.push(" AND day <= ");
    qb.push_bind(to_day_s);

    if let Some(t) = &f.event_type {
        qb.push(" AND event_type = ").push_bind(t.clone());
    }
    if let Some(u) = &f.url {
        qb.push(" AND url = ").push_bind(u.clone());
    }
    qb.push(" ORDER BY day DESC, count DESC LIMIT ")
        .push_bind(limit);

    let rows: Vec<UrlStatsRow> = qb.build_query_as().fetch_all(&state.pool).await?;
    Ok(Json(rows))
}

/// Filters for `/stats/pages` — hits-per-page rolled up over a time range
/// (NOT per-day). Reads raw events so `visitors` stays correct (distinct
/// visitor hashes can't be summed across days).
#[derive(Debug, Deserialize, Default)]
pub struct PageStatsFilters {
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub event_type: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct PageStatsRow {
    pub url: String,
    pub count: i64,
    pub visitors: i64,
    pub last_ts: i64,
}

pub async fn page_stats_handler(
    State(state): State<AppState>,
    _auth: ReadAuth,
    Query(f): Query<PageStatsFilters>,
) -> AppResult<impl IntoResponse> {
    let limit = f.limit.unwrap_or(1_000).clamp(1, 10_000);
    let event_type = f.event_type.as_deref().unwrap_or("pageview");
    let (from, to) = resolve_range(&state.config.server, f.from, f.to)?;

    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        "SELECT url,
                COUNT(*) AS count,
                COUNT(DISTINCT visitor_hash) AS visitors,
                MAX(ts) AS last_ts
         FROM events WHERE event_type = ",
    );
    qb.push_bind(event_type.to_string());
    qb.push(" AND ts >= ").push_bind(from);
    qb.push(" AND ts <= ").push_bind(to);

    qb.push(" GROUP BY url ORDER BY count DESC, url ASC LIMIT ")
        .push_bind(limit);

    let rows: Vec<PageStatsRow> = qb.build_query_as().fetch_all(&state.pool).await?;
    Ok(Json(rows))
}

/// Filters for `/stats/user_pages` — pages viewed by a specific attributed
/// user. `user_id` is required; attributed users come from signed `user`
/// payloads so there's no "anonymous" case here.
#[derive(Debug, Deserialize, Default)]
pub struct UserPagesFilters {
    pub user_id: Option<String>,
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub event_type: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct UserPageRow {
    pub url: String,
    pub count: i64,
    pub first_ts: i64,
    pub last_ts: i64,
}

pub async fn user_pages_handler(
    State(state): State<AppState>,
    _auth: ReadAuth,
    Query(f): Query<UserPagesFilters>,
) -> AppResult<impl IntoResponse> {
    let user_id = f
        .user_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| crate::error::AppError::BadRequest("user_id is required".into()))?;

    let limit = f.limit.unwrap_or(1_000).clamp(1, 10_000);
    let event_type = f.event_type.as_deref().unwrap_or("pageview");
    let (from, to) = resolve_range(&state.config.server, f.from, f.to)?;

    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        "SELECT url,
                COUNT(*) AS count,
                MIN(ts) AS first_ts,
                MAX(ts) AS last_ts
         FROM events WHERE user_id = ",
    );
    qb.push_bind(user_id.to_string());
    qb.push(" AND event_type = ")
        .push_bind(event_type.to_string());
    qb.push(" AND ts >= ").push_bind(from);
    qb.push(" AND ts <= ").push_bind(to);

    qb.push(" GROUP BY url ORDER BY last_ts DESC LIMIT ")
        .push_bind(limit);

    let rows: Vec<UserPageRow> = qb.build_query_as().fetch_all(&state.pool).await?;
    Ok(Json(rows))
}

// ---------------------------------------------------------------------------
// /stats/sources — top referrers / utm_sources across a time range.
// Reads raw events so `visitors` is accurate (distinct hashes can't be
// summed across daily rollups).
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct SourceStatsFilters {
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub event_type: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct SourceStatsRow {
    pub source: Option<String>,
    pub count: i64,
    pub visitors: i64,
}

pub async fn source_stats_handler(
    State(state): State<AppState>,
    _auth: ReadAuth,
    Query(f): Query<SourceStatsFilters>,
) -> AppResult<impl IntoResponse> {
    let limit = f.limit.unwrap_or(1_000).clamp(1, 10_000);
    let (from, to) = resolve_range(&state.config.server, f.from, f.to)?;

    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        "SELECT source,
                COUNT(*) AS count,
                COUNT(DISTINCT visitor_hash) AS visitors
         FROM events WHERE ts >= ",
    );
    qb.push_bind(from);
    qb.push(" AND ts <= ").push_bind(to);

    if let Some(t) = &f.event_type {
        qb.push(" AND event_type = ").push_bind(t.clone());
    }

    qb.push(" GROUP BY source ORDER BY count DESC LIMIT ")
        .push_bind(limit);

    let rows: Vec<SourceStatsRow> = qb.build_query_as().fetch_all(&state.pool).await?;
    Ok(Json(rows))
}

// ---------------------------------------------------------------------------
// /stats/timeseries — event counts bucketed by time. Used for "last 24h"
// sparklines and rate-over-time dashboards.
// Granularity is one of {hour, day}. Buckets without events are omitted.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct TimeseriesFilters {
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub event_type: Option<String>,
    pub url: Option<String>,
    pub source: Option<String>,
    pub country: Option<String>,
    pub user_id: Option<String>,
    /// "hour" or "day". Default "hour" — best for "last 24h" views.
    pub granularity: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct TimeseriesRow {
    pub bucket: String,
    pub count: i64,
    pub visitors: i64,
}

pub async fn timeseries_handler(
    State(state): State<AppState>,
    _auth: ReadAuth,
    Query(f): Query<TimeseriesFilters>,
) -> AppResult<impl IntoResponse> {
    // Bucketing: SQLite's strftime on ts/1000 (ms→s). 'hour' groups to
    // `YYYY-MM-DDTHH:00Z`; 'day' to `YYYY-MM-DD`. Minute would also work
    // but high cardinality under load — `limit` guards against runaway
    // responses regardless.
    let granularity = f
        .granularity
        .as_deref()
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| "hour".into());

    let format = match granularity.as_str() {
        "hour" => "%Y-%m-%dT%H:00:00Z",
        "day" => "%Y-%m-%d",
        _ => {
            return Err(crate::error::AppError::BadRequest(
                "granularity must be 'hour' or 'day'".into(),
            ));
        }
    };

    let limit = f.limit.unwrap_or(10_000).clamp(1, 10_000);
    let (from, to) = resolve_range(&state.config.server, f.from, f.to)?;

    // `format` is resolved from a static whitelist above ("hour"/"day") so
    // binding it as a parameter is safe — strftime accepts a bound param as
    // the format argument in SQLite.
    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new("SELECT strftime(");
    qb.push_bind(format.to_string());
    qb.push(
        ", ts/1000, 'unixepoch') AS bucket,
                COUNT(*) AS count,
                COUNT(DISTINCT visitor_hash) AS visitors
         FROM events WHERE ts >= ",
    );
    qb.push_bind(from);
    qb.push(" AND ts <= ").push_bind(to);

    if let Some(t) = &f.event_type {
        qb.push(" AND event_type = ").push_bind(t.clone());
    }
    if let Some(u) = &f.url {
        qb.push(" AND url = ").push_bind(u.clone());
    }
    if let Some(s) = &f.source {
        qb.push(" AND source = ").push_bind(s.clone());
    }
    if let Some(c) = &f.country {
        qb.push(" AND country = ").push_bind(c.to_ascii_uppercase());
    }
    if let Some(uid) = &f.user_id {
        qb.push(" AND user_id = ").push_bind(uid.clone());
    }

    qb.push(" GROUP BY bucket ORDER BY bucket ASC LIMIT ")
        .push_bind(limit);

    let rows: Vec<TimeseriesRow> = qb.build_query_as().fetch_all(&state.pool).await?;
    Ok(Json(rows))
}

// ---------------------------------------------------------------------------
// /stats/searches — top search queries, zero-result queries, total volume.
// Reads from `events` where event_type='search' and `extra` carries the
// `search.query` string.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct SearchStatsFilters {
    pub from: Option<i64>,
    pub to: Option<i64>,
    /// When true, only return queries where result_count = 0 (zero-result
    /// queries — usually the most actionable subset).
    #[serde(default)]
    pub zero_only: bool,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct SearchStatsRow {
    pub query: String,
    pub count: i64,
    pub visitors: i64,
    /// Median-ish result count across occurrences. SQLite has no median
    /// aggregate; AVG is good enough for a top-queries list.
    pub avg_result_count: Option<f64>,
    pub zero_result_count: i64,
}

pub async fn searches_handler(
    State(state): State<AppState>,
    _auth: ReadAuth,
    Query(f): Query<SearchStatsFilters>,
) -> AppResult<impl IntoResponse> {
    let limit = f.limit.unwrap_or(100).clamp(1, 10_000);
    let (from, to) = resolve_range(&state.config.server, f.from, f.to)?;

    // json_extract is the stdlib way to pull a nested field out of the
    // `extra` blob. The time-range bound applies unconditionally so a naked
    // call can't scan the whole events table.
    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        "SELECT json_extract(extra, '$.search.query') AS query,
                COUNT(*) AS count,
                COUNT(DISTINCT visitor_hash) AS visitors,
                AVG(json_extract(extra, '$.search.result_count')) AS avg_result_count,
                SUM(CASE WHEN json_extract(extra, '$.search.result_count') = 0 THEN 1 ELSE 0 END) AS zero_result_count
         FROM events
         WHERE event_type = 'search' AND json_extract(extra, '$.search.query') IS NOT NULL
           AND ts >= ",
    );
    qb.push_bind(from);
    qb.push(" AND ts <= ").push_bind(to);

    qb.push(" GROUP BY query");
    if f.zero_only {
        // at least one zero-result occurrence; `avg = 0` would drop any query
        // that had a single non-zero occurrence and miss obvious bugs.
        qb.push(" HAVING zero_result_count > 0");
    }
    qb.push(" ORDER BY count DESC LIMIT ").push_bind(limit);

    let rows: Vec<SearchStatsRow> = qb.build_query_as().fetch_all(&state.pool).await?;
    Ok(Json(rows))
}

// ---------------------------------------------------------------------------
// /stats/user_timeline — chronological event list for a specific user,
// optionally grouped into sessions. Designed for "what did this user do"
// support-style queries.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct UserTimelineFilters {
    pub user_id: Option<String>,
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct UserTimelineRow {
    pub ts: i64,
    pub event_type: String,
    pub event_name: Option<String>,
    pub url: String,
    pub page_title: Option<String>,
    pub source: Option<String>,
    pub device_type: Option<String>,
    pub session_id: Option<String>,
}

pub async fn user_timeline_handler(
    State(state): State<AppState>,
    _auth: ReadAuth,
    Query(f): Query<UserTimelineFilters>,
) -> AppResult<impl IntoResponse> {
    let user_id = f
        .user_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| crate::error::AppError::BadRequest("user_id is required".into()))?;

    let limit = f.limit.unwrap_or(500).clamp(1, 10_000);
    let (from, to) = resolve_range(&state.config.server, f.from, f.to)?;

    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        "SELECT ts, event_type, event_name, url, page_title, source, device_type, session_id
         FROM events WHERE user_id = ",
    );
    qb.push_bind(user_id.to_string());
    qb.push(" AND ts >= ").push_bind(from);
    qb.push(" AND ts <= ").push_bind(to);

    qb.push(" ORDER BY ts DESC LIMIT ").push_bind(limit);

    let rows: Vec<UserTimelineRow> = qb.build_query_as().fetch_all(&state.pool).await?;
    Ok(Json(rows))
}

// ---------------------------------------------------------------------------
// /stats/funnels — conversion across an ordered sequence of URL steps for
// the same visitor within the range. Returns `[{step, url, visitors,
// dropoff_pct}]`. The match semantics are: a visitor "reached" step N if
// they have an event for steps 1..N in increasing `ts` order.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct FunnelFilters {
    pub from: Option<i64>,
    pub to: Option<i64>,
    /// URLs in order, comma-separated. e.g. `?steps=/pricing,/signup,/welcome`
    pub steps: Option<String>,
    pub event_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FunnelStep {
    pub step: usize,
    pub url: String,
    pub visitors: i64,
    pub dropoff_pct: f64,
}

pub async fn funnels_handler(
    State(state): State<AppState>,
    _auth: ReadAuth,
    Query(f): Query<FunnelFilters>,
) -> AppResult<impl IntoResponse> {
    let steps_raw = f
        .steps
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            crate::error::AppError::BadRequest(
                "steps is required (comma-separated URLs, ≥2 entries)".into(),
            )
        })?;

    let steps: Vec<String> = steps_raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if steps.len() < 2 {
        return Err(crate::error::AppError::BadRequest(
            "funnel requires at least 2 steps".into(),
        ));
    }
    // Cap at 5 steps: each extra step adds a self-join against `events` whose
    // worst-case cost grows combinatorially. 10 steps on a table with real
    // history pins a pool connection for tens of seconds; 5 is plenty for
    // the usual landing → signup → convert shape.
    if steps.len() > 5 {
        return Err(crate::error::AppError::BadRequest(
            "funnel is capped at 5 steps".into(),
        ));
    }

    let event_type = f.event_type.as_deref().unwrap_or("pageview");
    let (from, to) = resolve_range(&state.config.server, f.from, f.to)?;

    // Funnel math in SQL: for each step N, count the visitor_hashes that
    // have hit steps 1..=N in increasing `ts` order. Each step's query is
    // independent so we run them concurrently — but only two at a time, so
    // a single funnel request can never pin more than two pool connections.
    // The previous `buffered(5)` × 8-conn pool let a handful of concurrent
    // funnel requests starve every other DB caller.
    use futures::stream::{self, StreamExt, TryStreamExt};
    let pool = &state.pool;
    let counts: Vec<i64> = stream::iter(0..steps.len())
        .map(|idx| {
            let prefix = steps[..=idx].to_vec();
            async move {
                count_funnel_prefix(pool, &prefix, event_type, Some(from), Some(to)).await
            }
        })
        .buffered(2)
        .try_collect()
        .await?;

    let mut results: Vec<FunnelStep> = Vec::with_capacity(steps.len());
    let mut prev_count: Option<i64> = None;
    for (idx, count) in counts.into_iter().enumerate() {
        let dropoff_pct = match prev_count {
            Some(p) if p > 0 => ((p - count) as f64 / p as f64) * 100.0,
            _ => 0.0,
        };
        results.push(FunnelStep {
            step: idx + 1,
            url: steps[idx].clone(),
            visitors: count,
            dropoff_pct,
        });
        prev_count = Some(count);
    }

    Ok(Json(results))
}

async fn count_funnel_prefix(
    pool: &sqlx::SqlitePool,
    prefix: &[String],
    event_type: &str,
    from: Option<i64>,
    to: Option<i64>,
) -> AppResult<i64> {
    // Chain inner joins: e1 has step 1, e2 has step 2 with e2.ts > e1.ts,
    // etc. Visitor hash must be the same across the chain. Count distinct
    // visitors that satisfy the full prefix.
    let mut qb: QueryBuilder<Sqlite> =
        QueryBuilder::new("SELECT COUNT(DISTINCT e1.visitor_hash) FROM events e1");
    for i in 2..=prefix.len() {
        qb.push(format!(
            " JOIN events e{i} ON e{i}.visitor_hash = e1.visitor_hash AND e{i}.ts > e{prev}.ts",
            prev = i - 1,
        ));
    }
    qb.push(" WHERE e1.event_type = ")
        .push_bind(event_type.to_string());
    qb.push(" AND e1.url = ").push_bind(prefix[0].clone());
    for (i, url) in prefix.iter().enumerate().skip(1) {
        let alias = format!("e{}", i + 1);
        qb.push(format!(" AND {alias}.event_type = "))
            .push_bind(event_type.to_string());
        qb.push(format!(" AND {alias}.url = "))
            .push_bind(url.clone());
    }
    if let Some(from) = from {
        qb.push(" AND e1.ts >= ").push_bind(from);
    }
    if let Some(to) = to {
        qb.push(format!(" AND e{}.ts <= ", prefix.len()))
            .push_bind(to);
    }

    // Per-query wall-clock cap. SQLite cannot cancel a running query from
    // the tokio side — dropping the future still leaves the connection
    // pinned on the DB side until the statement completes. Adding an
    // explicit timeout here gives us a 500 on the HTTP side while keeping
    // the pool's `acquire_timeout` as the last-resort defense.
    let query = qb.build_query_scalar::<i64>().fetch_one(pool);
    let count = tokio::time::timeout(Duration::from_secs(5), query)
        .await
        .map_err(|_| {
            crate::error::AppError::BadRequest(
                "funnel query exceeded 5s — narrow the time range or reduce steps".into(),
            )
        })??;
    Ok(count)
}

// ---------------------------------------------------------------------------
// /stats/new_returning — new vs returning visitor counts over a range.
// A visitor is "new" if their first session in the events table falls
// inside the requested range; "returning" if their first session is older.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct NewReturningFilters {
    pub from: Option<i64>,
    pub to: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct NewReturningRow {
    pub new_visitors: i64,
    pub returning_visitors: i64,
    pub total_sessions: i64,
}

pub async fn new_returning_handler(
    State(state): State<AppState>,
    _auth: ReadAuth,
    Query(f): Query<NewReturningFilters>,
) -> AppResult<impl IntoResponse> {
    // Default window is 24h, overridable up to the server-configured max.
    let now = time::OffsetDateTime::now_utc().unix_timestamp() * 1000;
    let to_default = f.to.unwrap_or(now);
    let from_default = f.from.unwrap_or_else(|| to_default - 86_400_000);
    let (from, to) = resolve_range(&state.config.server, Some(from_default), Some(to_default))?;

    // Cheap version: only look up `first_ts` for visitors that actually
    // appeared inside the range. The previous shape scanned every event ever
    // ingested to compute `first_ts` per visitor, which was the most expensive
    // read endpoint once the table had any real history.
    //
    // COALESCE on both SUMs because an empty range otherwise decodes NULL
    // into i64 and 500s the request.
    //
    // Visitors with no session_id (pre-migration rows) are filtered out
    // so they don't inflate either bucket.
    //
    // Cap the historical `first_seen` lookback at `stats_max_range_days`
    // BEFORE the requested range. Without this, a long-lived deployment's
    // `first_seen` CTE scans years of history on every call — classifying a
    // visitor as "returning" if their first session lives in that pre-window
    // is not worth a table scan, and wider recall can be added later with a
    // dedicated "first_seen_by_visitor" rollup if operators ask.
    let lookback_ms = i64::from(state.config.server.stats_max_range_days) * 86_400_000;
    let history_floor = from.saturating_sub(lookback_ms);
    let query = sqlx::query_as::<_, (i64, i64, i64)>(
        "WITH in_range AS (
            SELECT DISTINCT visitor_hash
            FROM events
            WHERE session_id IS NOT NULL AND ts >= ?1 AND ts <= ?2
        ),
        first_seen AS (
            SELECT e.visitor_hash, MIN(e.ts) AS first_ts
            FROM events e
            JOIN in_range ir ON ir.visitor_hash = e.visitor_hash
            WHERE e.session_id IS NOT NULL AND e.ts >= ?3
            GROUP BY e.visitor_hash
        )
        SELECT
            COALESCE(SUM(CASE WHEN fs.first_ts >= ?1 AND fs.first_ts <= ?2 THEN 1 ELSE 0 END), 0) AS new_visitors,
            COALESCE(SUM(CASE WHEN fs.first_ts < ?1 THEN 1 ELSE 0 END), 0) AS returning_visitors,
            (SELECT COUNT(DISTINCT session_id) FROM events WHERE session_id IS NOT NULL AND ts >= ?1 AND ts <= ?2) AS total_sessions
        FROM first_seen fs",
    )
    .bind(from)
    .bind(to)
    .bind(history_floor)
    .fetch_one(&state.pool);

    // Same 5s wall-clock cap as the funnel path — protects the pool against
    // a long-history dataset being hammered by concurrent calls.
    let row = tokio::time::timeout(Duration::from_secs(5), query)
        .await
        .map_err(|_| {
            crate::error::AppError::BadRequest(
                "new_returning query exceeded 5s — narrow the time range".into(),
            )
        })??;

    Ok(Json(NewReturningRow {
        new_visitors: row.0,
        returning_visitors: row.1,
        total_sessions: row.2,
    }))
}

/// Refresh aggregates for every UTC day that has new events since the last
/// cursor.
///
/// Days are recomputed from scratch because visitor counts require
/// `COUNT(DISTINCT visitor_hash)` and that can't be merged incrementally. This
/// keeps the math correct at the cost of reprocessing today's rows on each
/// tick — typically cheap and bounded by the materialization interval.
pub async fn refresh(pool: &SqlitePool) -> anyhow::Result<u64> {
    let last_id: i64 =
        sqlx::query_scalar("SELECT last_id FROM materialization_cursor WHERE name = 'agg_daily'")
            .fetch_optional(pool)
            .await?
            .unwrap_or(0);

    let max_id: Option<i64> = sqlx::query_scalar("SELECT MAX(id) FROM events WHERE id > ?1")
        .bind(last_id)
        .fetch_one(pool)
        .await?;

    let Some(max_id) = max_id else {
        return Ok(0);
    };

    let touched_days: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT date(ts/1000, 'unixepoch') FROM events WHERE id > ?1 AND id <= ?2",
    )
    .bind(last_id)
    .bind(max_id)
    .fetch_all(pool)
    .await?;

    if touched_days.is_empty() {
        return Ok(0);
    }

    let now = OffsetDateTime::now_utc().unix_timestamp() * 1000;
    let mut tx = pool.begin().await?;
    let mut total = 0u64;

    for day in &touched_days {
        sqlx::query("DELETE FROM agg_daily WHERE day = ?1")
            .bind(day)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM agg_daily_url WHERE day = ?1")
            .bind(day)
            .execute(&mut *tx)
            .await?;

        // Two branches deliberately combined:
        //   branch 1: one row per `segment` value — for dashboards that slice
        //             by segment.
        //   branch 2: the `segment=''` row — every event for the day, used as
        //             the "all traffic" total. It INCLUDES events that also
        //             have explicit segments; that is the intended semantic.
        //             Don't "fix" this by filtering — `/stats` without a
        //             segment filter must return the real total, not just
        //             segment-less events.
        let n = sqlx::query(
            r#"
            INSERT INTO agg_daily (day, event_type, source, segment, device_type, country, count, visitors, refreshed_at)
            SELECT day, event_type, source, segment, device_type, country,
                   COUNT(*) AS c, COUNT(DISTINCT visitor_hash) AS v, ?2
            FROM (
                SELECT date(ts/1000, 'unixepoch') AS day, event_type,
                       COALESCE(source, '') AS source,
                       COALESCE(device_type, '') AS device_type,
                       COALESCE(country, '') AS country,
                       visitor_hash, js.value AS segment
                FROM events, json_each(events.segments) js
                WHERE date(ts/1000, 'unixepoch') = ?1 AND events.segments IS NOT NULL

                UNION ALL

                SELECT date(ts/1000, 'unixepoch') AS day, event_type,
                       COALESCE(source, '') AS source,
                       COALESCE(device_type, '') AS device_type,
                       COALESCE(country, '') AS country,
                       visitor_hash, '' AS segment
                FROM events
                WHERE date(ts/1000, 'unixepoch') = ?1
            )
            GROUP BY day, event_type, source, segment, device_type, country
            "#,
        )
        .bind(day)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        total += n.rows_affected();

        // Per-URL rollup is plain (no segment fan-out): counts and unique
        // visitors per (day, url, event_type). High-cardinality but indexed.
        let m = sqlx::query(
            r#"
            INSERT INTO agg_daily_url (day, url, event_type, count, visitors, refreshed_at)
            SELECT date(ts/1000, 'unixepoch') AS day, url, event_type,
                   COUNT(*), COUNT(DISTINCT visitor_hash), ?2
            FROM events
            WHERE date(ts/1000, 'unixepoch') = ?1
            GROUP BY day, url, event_type
            "#,
        )
        .bind(day)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        total += m.rows_affected();
    }

    sqlx::query(
        "INSERT INTO materialization_cursor (name, last_id, updated_at)
         VALUES ('agg_daily', ?1, ?2)
         ON CONFLICT(name) DO UPDATE SET last_id = excluded.last_id, updated_at = excluded.updated_at",
    )
    .bind(max_id)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(total)
}

pub async fn run_worker(state: AppState, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let mut ticker = interval(Duration::from_secs(
        state.config.materialization.interval_secs.max(10),
    ));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                match refresh(&state.pool).await {
                    Ok(n) if n > 0 => tracing::debug!(rows = n, "refreshed aggregates"),
                    Ok(_) => {}
                    Err(err) => tracing::error!(error = ?err, "aggregate refresh failed"),
                }
                if let Err(err) = state.salts.refresh().await {
                    tracing::error!(error = ?err, "salt refresh failed");
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("materialization worker shutting down");
                    let _ = refresh(&state.pool).await;
                    return;
                }
            }
        }
    }
}
