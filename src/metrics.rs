//! Prometheus-compatible text exposition at `/metrics`.
//!
//! Intentionally hand-rolled — we only expose a handful of counters and
//! gauges, and pulling in the full `metrics` / `prometheus` ecosystem
//! would triple the dependency footprint for a small win. The format
//! is plain text per the Prometheus text exposition spec; scrapers
//! (Prometheus, VictoriaMetrics, Grafana Agent) all accept it.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use sqlx::SqlitePool;
use time::OffsetDateTime;

use crate::state::AppState;

/// Process-wide counters. All cheap atomic bumps; read in `render()`.
#[derive(Default)]
pub struct Metrics {
    /// Accepted events by `/collect` (server-side).
    pub events_ingested_server: AtomicU64,
    /// Accepted events by the browser beacon.
    pub events_ingested_beacon: AtomicU64,
    /// Rejected events (any reason: validation, auth, rate-limit).
    pub events_rejected: AtomicU64,
    /// Successfully delivered webhooks.
    pub webhook_delivered: AtomicU64,
    /// Webhook deliveries that exhausted retries (final `failed` state).
    pub webhook_failed: AtomicU64,
    /// Total worker panic restarts. Non-zero = bug.
    pub worker_restarts: AtomicU64,

    // Gauge cache: `SELECT COUNT(*) FROM events` can scan the whole B-tree,
    // and Prometheus scrapes land every 15s. We throttle the underlying
    // queries to at most once per `GAUGE_REFRESH_INTERVAL_MS` and serve
    // cached atomics in between. `0` as the initial `last_refresh_ms`
    // guarantees the very first scrape triggers a fresh read.
    gauge_events_rows: AtomicI64,
    gauge_webhooks_rows: AtomicI64,
    gauge_pending_deliveries: AtomicI64,
    gauge_last_refresh_ms: AtomicI64,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }
}

const GAUGE_REFRESH_INTERVAL_MS: i64 = 30_000;

pub async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    let m = &state.metrics;
    refresh_gauges_if_stale(&state).await;

    // `# HELP` / `# TYPE` lines are required for some scrapers to pick up
    // the metric type correctly.
    let body = format!(
        "\
# HELP analytics_events_ingested_total Accepted events by ingest path.
# TYPE analytics_events_ingested_total counter
analytics_events_ingested_total{{path=\"server\"}} {server}
analytics_events_ingested_total{{path=\"beacon\"}} {beacon}

# HELP analytics_events_rejected_total Rejected events across all ingest paths.
# TYPE analytics_events_rejected_total counter
analytics_events_rejected_total {rejected}

# HELP analytics_webhook_delivered_total Webhook deliveries that succeeded.
# TYPE analytics_webhook_delivered_total counter
analytics_webhook_delivered_total {delivered}

# HELP analytics_webhook_failed_total Webhook deliveries that exhausted retries.
# TYPE analytics_webhook_failed_total counter
analytics_webhook_failed_total {failed}

# HELP analytics_worker_restarts_total Panic restarts of background workers.
# TYPE analytics_worker_restarts_total counter
analytics_worker_restarts_total {restarts}

# HELP analytics_events_rows Total rows currently in the events table.
# TYPE analytics_events_rows gauge
analytics_events_rows {events_rows}

# HELP analytics_webhooks_rows Total registered webhook subscribers.
# TYPE analytics_webhooks_rows gauge
analytics_webhooks_rows {webhooks_rows}

# HELP analytics_webhook_pending Pending webhook deliveries (queued or retrying).
# TYPE analytics_webhook_pending gauge
analytics_webhook_pending {pending_deliveries}
",
        server = m.events_ingested_server.load(Ordering::Relaxed),
        beacon = m.events_ingested_beacon.load(Ordering::Relaxed),
        rejected = m.events_rejected.load(Ordering::Relaxed),
        delivered = m.webhook_delivered.load(Ordering::Relaxed),
        failed = m.webhook_failed.load(Ordering::Relaxed),
        restarts = m.worker_restarts.load(Ordering::Relaxed),
        events_rows = m.gauge_events_rows.load(Ordering::Relaxed),
        webhooks_rows = m.gauge_webhooks_rows.load(Ordering::Relaxed),
        pending_deliveries = m.gauge_pending_deliveries.load(Ordering::Relaxed),
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        "text/plain; version=0.0.4; charset=utf-8".parse().unwrap(),
    );
    (headers, body)
}

/// Refresh the cached gauges if the last refresh was more than
/// `GAUGE_REFRESH_INTERVAL_MS` ago. Uses `compare_exchange` on the timestamp
/// so concurrent scrapers don't pile up DB queries: only the first to flip
/// the clock does the work; the rest read the cached values.
async fn refresh_gauges_if_stale(state: &AppState) {
    let now_ms =
        i64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000).unwrap_or(0);
    let last = state.metrics.gauge_last_refresh_ms.load(Ordering::Relaxed);
    if now_ms.saturating_sub(last) < GAUGE_REFRESH_INTERVAL_MS {
        return;
    }
    if state
        .metrics
        .gauge_last_refresh_ms
        .compare_exchange(last, now_ms, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return;
    }

    refresh_gauges(&state.pool, &state.metrics).await;
}

async fn refresh_gauges(pool: &SqlitePool, m: &Metrics) {
    // Fallthrough on error — keep whatever we had cached rather than blip to
    // zero and confuse alerting.
    if let Ok(v) = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM events")
        .fetch_one(pool)
        .await
    {
        m.gauge_events_rows.store(v, Ordering::Relaxed);
    }
    if let Ok(v) = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM webhooks")
        .fetch_one(pool)
        .await
    {
        m.gauge_webhooks_rows.store(v, Ordering::Relaxed);
    }
    if let Ok(v) = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM webhook_deliveries WHERE status = 'pending'",
    )
    .fetch_one(pool)
    .await
    {
        m.gauge_pending_deliveries.store(v, Ordering::Relaxed);
    }
}

/// Returned to readers who want an Ordering hint — avoids repeating
/// the const in ingest/delivery paths.
pub const R: Ordering = Ordering::Relaxed;

/// Increment helper used across the codebase — keeps call sites terse.
pub fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// Set a gauge-like atomic value.
pub fn set(gauge: &AtomicI64, value: i64) {
    gauge.store(value, Ordering::Relaxed);
}
