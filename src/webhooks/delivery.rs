use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use moka::future::Cache;
use reqwest::Client;
use serde_json::json;
use sqlx::SqlitePool;
use time::OffsetDateTime;

use crate::config::WebhooksConfig;
use crate::state::AppState;

/// Rate-limit the "queue is full" warning log so a long-running full-queue
/// state doesn't flood operator log pipelines with one line per `/collect`.
static LAST_FULL_QUEUE_WARN_MS: AtomicU64 = AtomicU64::new(0);
const FULL_QUEUE_WARN_INTERVAL_MS: u64 = 60_000;

/// Process-wide cache of per-host pinned reqwest clients. Each `Client` owns
/// its own connection pool + rustls config; building one per delivery adds a
/// full TLS handshake per retry. Cache by `(host, sorted-addrs)` so a DNS
/// flip on the same host gets a fresh client rather than reusing a stale pin.
/// TTL is short — we still revalidate SSRF rules per delivery, the cache is
/// only here to reuse the TCP+TLS state.
fn pinned_client_cache() -> &'static Cache<String, Client> {
    static C: OnceLock<Cache<String, Client>> = OnceLock::new();
    C.get_or_init(|| {
        Cache::builder()
            .max_capacity(1_000)
            .time_to_idle(Duration::from_secs(300))
            .build()
    })
}

const ENQUEUE_BATCH: i64 = 500;
const DEQUEUE_BATCH: i64 = 100;

/// Single enqueue + deliver cycle, exposed so integration tests can drive the
/// worker deterministically without spinning the full loop.
pub async fn run_worker_tick(state: &AppState) {
    sweep_stale_pending(state).await;
    if let Err(err) = enqueue_pending(state).await {
        tracing::error!(error = ?err, "webhook enqueue failed");
    }
    if let Err(err) = deliver_batch(state).await {
        tracing::error!(error = ?err, "webhook delivery batch failed");
    }
}

/// Runs in a loop: enqueue deliveries for new events, then poll pending
/// deliveries and attempt them.
pub async fn run_worker(state: AppState, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    loop {
        sweep_stale_pending(&state).await;

        match enqueue_pending(&state).await {
            Ok(n) if n > 0 => tracing::debug!(enqueued = n, "webhook deliveries enqueued"),
            Ok(_) => {}
            Err(err) => tracing::error!(error = ?err, "webhook enqueue failed"),
        }

        match deliver_batch(&state).await {
            Ok(n) if n > 0 => tracing::debug!(delivered = n, "webhook batch delivered"),
            Ok(_) => {}
            Err(err) => tracing::error!(error = ?err, "webhook delivery batch failed"),
        }

        let wait = tokio::time::sleep(Duration::from_secs(1));
        tokio::pin!(wait);

        tokio::select! {
            _ = &mut wait => {}
            _ = state.delivery_notify.notified() => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("webhook worker shutting down; flushing");
                    if let Err(err) = enqueue_pending(&state).await {
                        tracing::error!(error = ?err, "final webhook enqueue failed");
                    }
                    if let Err(err) = deliver_batch(&state).await {
                        tracing::error!(error = ?err, "final webhook delivery batch failed");
                    }
                    return;
                }
            }
        }
    }
}

/// Build-or-reuse a delivery-scoped client that resolves the target host to
/// the already-verified address(es). This closes the DNS-rebinding window
/// because reqwest/hyper won't re-query DNS for this request. Process-cached
/// by `(host, sorted-addrs)` so repeat deliveries to the same subscriber
/// reuse TCP+TLS instead of paying a handshake per event.
async fn build_pinned_client(
    cfg: &WebhooksConfig,
    host: Option<&str>,
    addrs: &[std::net::SocketAddr],
) -> anyhow::Result<Client> {
    let Some(h) = host else {
        anyhow::bail!("cannot build pinned client without a host");
    };

    // Sort addrs so caller ordering doesn't split the cache key.
    let mut sorted = addrs.to_vec();
    sorted.sort();
    let mut key = String::with_capacity(64 + sorted.len() * 22);
    key.push_str(h);
    for a in &sorted {
        key.push('|');
        key.push_str(&a.to_string());
    }
    let cfg_timeout = cfg.delivery_timeout_ms;

    let cache = pinned_client_cache();
    let client = cache
        .try_get_with(key, async move {
            let mut builder = Client::builder()
                .no_proxy()
                .timeout(Duration::from_millis(cfg_timeout))
                .redirect(reqwest::redirect::Policy::none())
                .user_agent(concat!("simple-analytics/", env!("CARGO_PKG_VERSION")));
            for addr in &sorted {
                builder = builder.resolve(h, *addr);
            }
            builder.build().map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| anyhow::anyhow!("build pinned client: {e}"))?;
    Ok(client)
}

/// For every new event (above the webhook cursor) and every active subscriber
/// whose event_types match, insert a pending delivery row.
///
/// All reads + INSERTs run inside one `BEGIN IMMEDIATE` on a single pooled
/// connection so they share a snapshot. `pool.begin()` always opens DEFERRED
/// and nesting another `BEGIN` inside it is a SQLite error — so we skip the
/// sqlx transaction helper and drive the lock manually.
async fn enqueue_pending(state: &AppState) -> anyhow::Result<u64> {
    // Guard the pending-row cap BEFORE taking the write lock. A subscriber
    // that fails forever would otherwise grow `webhook_deliveries`
    // unboundedly; the cap makes `/collect` still succeed (events land) but
    // the webhook tail stops advancing until the backlog drains.
    let cap = state.config.webhooks.max_pending_deliveries;
    if cap > 0 {
        let pending: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM webhook_deliveries WHERE status = 'pending'")
                .fetch_one(&state.pool)
                .await
                .unwrap_or(0);
        if (pending as u64) >= cap {
            let now_ms = OffsetDateTime::now_utc().unix_timestamp() * 1000;
            let now_ms_u = now_ms.max(0) as u64;
            let last = LAST_FULL_QUEUE_WARN_MS.load(Ordering::Relaxed);
            if now_ms_u.saturating_sub(last) >= FULL_QUEUE_WARN_INTERVAL_MS {
                LAST_FULL_QUEUE_WARN_MS.store(now_ms_u, Ordering::Relaxed);
                tracing::warn!(
                    pending = pending,
                    cap = cap,
                    "webhook pending queue at cap — enqueue paused"
                );
            }
            return Ok(0);
        }
    }

    let mut conn = state.pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

    let outcome = enqueue_pending_inner(&mut conn).await;

    // Release the lock regardless of outcome. A failed ROLLBACK is noisy but
    // not fatal; the connection will be recycled by the pool.
    let end_sql = if outcome.is_ok() {
        "COMMIT"
    } else {
        "ROLLBACK"
    };
    if let Err(err) = sqlx::query(end_sql).execute(&mut *conn).await {
        tracing::warn!(error = ?err, txn_end = end_sql, "enqueue txn close failed");
    }

    outcome
}

/// Drop `status='pending'` rows older than the configured age. These are
/// zombies — orphaned by a subscriber delete race, a worker crash, or an
/// INSERT that somehow escaped the happy-path retry flow. Retention's own
/// sweep deliberately skips `pending` (that's where active deliveries
/// live), so this is the one place that garbage-collects them.
async fn sweep_stale_pending(state: &AppState) {
    let hours = state.config.webhooks.pending_max_age_hours;
    if hours == 0 {
        return;
    }
    let cutoff = OffsetDateTime::now_utc().unix_timestamp() * 1000 - i64::from(hours) * 3_600_000;
    let _ =
        sqlx::query("DELETE FROM webhook_deliveries WHERE status = 'pending' AND created_at < ?1")
            .bind(cutoff)
            .execute(&state.pool)
            .await;
}

async fn enqueue_pending_inner(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Sqlite>,
) -> anyhow::Result<u64> {
    let cursor: i64 =
        sqlx::query_scalar("SELECT last_id FROM materialization_cursor WHERE name = 'webhooks'")
            .fetch_optional(&mut **conn)
            .await?
            .unwrap_or(0);

    let rows: Vec<(i64, String)> =
        sqlx::query_as("SELECT id, event_type FROM events WHERE id > ?1 ORDER BY id LIMIT ?2")
            .bind(cursor)
            .bind(ENQUEUE_BATCH)
            .fetch_all(&mut **conn)
            .await?;

    if rows.is_empty() {
        return Ok(0);
    }

    // Delete zombie pending rows past their age limit before deciding
    // whether we are queue-full. An abandoned subscriber that fails forever
    // will otherwise keep the cap tripped indefinitely.
    // NOTE: this currently inherits the caller's txn so the sweep commits
    // with the enqueue; on rollback both are discarded, which is correct.
    // DELETE happens here rather than in retention.rs because retention
    // explicitly skips pending (pending = in-progress SLO) and we want the
    // cap check below to see the post-sweep count.

    let webhooks: Vec<(String, String)> =
        sqlx::query_as("SELECT id, event_types FROM webhooks WHERE active = 1")
            .fetch_all(&mut **conn)
            .await?;

    let now = OffsetDateTime::now_utc().unix_timestamp() * 1000;
    let mut max_id = cursor;

    // Build the set of (webhook_id, event_id) pairs to insert. O(events × hooks)
    // in memory but the batch is bounded by ENQUEUE_BATCH * |webhooks|.
    let mut pairs: Vec<(String, i64)> = Vec::new();
    for (event_id, event_type) in rows {
        max_id = max_id.max(event_id);
        for (wh_id, types_json) in &webhooks {
            let types: Vec<String> = serde_json::from_str(types_json).unwrap_or_default();
            if types.iter().any(|t| t == "*" || t == &event_type) {
                pairs.push((wh_id.clone(), event_id));
            }
        }
    }

    // Chunk multi-row INSERTs to stay well under the SQLite parameter limit
    // (6 params per row; keep chunks small enough that 6 * chunk_size is
    // comfortably below SQLITE_LIMIT_VARIABLE_NUMBER = 32766).
    let mut enqueued = 0u64;
    const INSERT_CHUNK: usize = 500;
    for chunk in pairs.chunks(INSERT_CHUNK) {
        let mut qb: sqlx::QueryBuilder<sqlx::Sqlite> = sqlx::QueryBuilder::new(
            "INSERT OR IGNORE INTO webhook_deliveries \
             (webhook_id, event_id, status, attempts, next_attempt, created_at) ",
        );
        qb.push_values(chunk.iter(), |mut b, (wh_id, event_id)| {
            b.push_bind(wh_id)
                .push_bind(*event_id)
                .push_bind("pending")
                .push_bind(0i64)
                .push_bind(now)
                .push_bind(now);
        });
        let res = qb.build().execute(&mut **conn).await?;
        enqueued += res.rows_affected();
    }

    sqlx::query(
        "INSERT INTO materialization_cursor (name, last_id, updated_at)
         VALUES ('webhooks', ?1, ?2)
         ON CONFLICT(name) DO UPDATE SET last_id = excluded.last_id, updated_at = excluded.updated_at",
    )
    .bind(max_id)
    .bind(now)
    .execute(&mut **conn)
    .await?;

    Ok(enqueued)
}

/// Stuck `in_progress` rows older than this are revived to `pending` on the
/// next tick — covers a worker crashing after claim but before the
/// delivered/failed flip.
const CLAIM_STALE_MS: i64 = 5 * 60 * 1000;

async fn deliver_batch(state: &AppState) -> anyhow::Result<u64> {
    let now = OffsetDateTime::now_utc().unix_timestamp() * 1000;

    // Revive claims that outlived their worker (kill -9, container OOM).
    // Any in_progress row with claimed_at older than CLAIM_STALE_MS goes back
    // to pending so it can be delivered. This is best-effort — a second
    // attempt may deliver the same event twice, so subscribers must treat
    // `x-analytics-event-id` as an idempotency key (README flags this).
    sqlx::query(
        "UPDATE webhook_deliveries
            SET status='pending'
          WHERE status='in_progress'
            AND claimed_at IS NOT NULL
            AND claimed_at < ?1",
    )
    .bind(now - CLAIM_STALE_MS)
    .execute(&state.pool)
    .await?;

    // Atomic claim: flip `pending` → `in_progress` and return the rows we
    // own. Two ticks overlapping (e.g. a test-triggered `run_worker_tick`
    // concurrent with the background loop) can no longer both see the same
    // row as pending. `UPDATE ... RETURNING` is atomic in SQLite ≥3.35.
    let batch: Vec<PendingDelivery> = sqlx::query_as(
        "UPDATE webhook_deliveries
            SET status='in_progress', claimed_at=?1
          WHERE id IN (
              SELECT d.id
                FROM webhook_deliveries d
                JOIN webhooks w ON w.id = d.webhook_id AND w.active = 1
               WHERE d.status='pending'
                 AND d.next_attempt <= ?1
               ORDER BY d.next_attempt ASC
               LIMIT ?2
          )
         RETURNING
            id,
            webhook_id,
            event_id,
            attempts,
            (SELECT url    FROM webhooks WHERE id = webhook_id) AS url,
            (SELECT secret FROM webhooks WHERE id = webhook_id) AS secret",
    )
    .bind(now)
    .bind(DEQUEUE_BATCH)
    .fetch_all(&state.pool)
    .await?;

    if batch.is_empty() {
        return Ok(0);
    }

    let concurrency = state.config.webhooks.concurrency.max(1);
    let futures = batch.into_iter().map(|d| {
        let state = state.clone();
        async move { deliver_one(&state, d).await }
    });

    use futures::stream::{self, StreamExt};
    let results: Vec<bool> = stream::iter(futures)
        .buffer_unordered(concurrency)
        .collect()
        .await;

    Ok(results.iter().filter(|ok| **ok).count() as u64)
}

struct PendingDelivery {
    id: i64,
    webhook_id: String,
    event_id: i64,
    attempts: i64,
    url: String,
    secret: Option<String>,
}

impl sqlx::FromRow<'_, sqlx::sqlite::SqliteRow> for PendingDelivery {
    fn from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            id: row.try_get("id")?,
            webhook_id: row.try_get("webhook_id")?,
            event_id: row.try_get("event_id")?,
            attempts: row.try_get("attempts")?,
            url: row.try_get("url")?,
            secret: row.try_get("secret")?,
        })
    }
}

async fn deliver_one(state: &AppState, d: PendingDelivery) -> bool {
    // Re-check and pin per-delivery. The base client has no baked-in resolve,
    // so we build a short-lived client scoped to this delivery that pins the
    // resolved IP — defeats DNS rebinding between validate and connect.
    //
    // `allow_private_targets` widens which IP ranges are acceptable but does
    // NOT skip pinning: without `.resolve()`, reqwest re-queries DNS at
    // connect time and a hostile resolver can still flip the target between
    // our check and the socket open.
    let allow_private = state.config.webhooks.allow_private_targets;
    let (parsed, addrs) = match crate::net::validate_webhook_url_async(&d.url, allow_private).await
    {
        Ok(pair) => pair,
        Err(err) => {
            // Never echo the raw URL: a webhook URL like
            // `https://hooks.example.com/push?token=<secret>` would otherwise
            // leak the token to every structured-log consumer.
            tracing::warn!(
                webhook = %d.webhook_id,
                host = %crate::net::host_for_log_str(&d.url),
                error = %err,
                "refusing delivery to unsafe URL"
            );
            let _ = sqlx::query(
                "UPDATE webhook_deliveries
                    SET status='failed', last_error=?2
                  WHERE id=?1",
            )
            .bind(d.id)
            .bind(format!("unsafe_url: {err}"))
            .execute(&state.pool)
            .await;
            return false;
        }
    };

    let pinned_client =
        match build_pinned_client(&state.config.webhooks, parsed.host_str(), &addrs).await {
            Ok(c) => c,
            Err(err) => {
                tracing::warn!(error = %err, "failed to build pinned client");
                return false;
            }
        };
    let client = &pinned_client;

    let event_json = match load_event_json(
        &state.pool,
        d.event_id,
        state.config.privacy.expose_visitor_hash,
        state.config.privacy.expose_user_payload,
    )
    .await
    {
        Ok(Some(v)) => v,
        Ok(None) => {
            tracing::warn!(
                event_id = d.event_id,
                "webhook event row missing, dropping delivery"
            );
            let _ = sqlx::query(
                "UPDATE webhook_deliveries SET status='failed', last_error='event_missing' WHERE id=?",
            )
            .bind(d.id)
            .execute(&state.pool)
            .await;
            return false;
        }
        Err(err) => {
            tracing::error!(error = ?err, "load event for webhook failed");
            return false;
        }
    };

    let body = serde_json::to_vec(&event_json).unwrap_or_else(|_| b"{}".to_vec());
    let ts_ms = OffsetDateTime::now_utc().unix_timestamp() * 1000;
    let ts_str = ts_ms.to_string();

    let mut req = client.post(&d.url).body(body.clone());
    req = req.header("content-type", "application/json");
    req = req.header("x-analytics-event-id", d.event_id.to_string());
    // `x-analytics-timestamp` is bound into the signature (separator `.`)
    // so a subscriber that verifies correctly also gets replay protection
    // for free — captured signatures become invalid after the clock drifts
    // outside the subscriber's acceptance window.
    req = req.header("x-analytics-timestamp", &ts_str);
    if let Some(secret) = &d.secret {
        let sig = sign(secret, ts_str.as_bytes(), &body);
        req = req.header("x-analytics-signature", sig);
    }

    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            let now = OffsetDateTime::now_utc().unix_timestamp() * 1000;
            let _ = sqlx::query(
                "UPDATE webhook_deliveries
                    SET status='delivered', attempts = attempts + 1,
                        last_status = ?2, delivered_at = ?3, last_error = NULL
                  WHERE id = ?1",
            )
            .bind(d.id)
            .bind(resp.status().as_u16() as i64)
            .bind(now)
            .execute(&state.pool)
            .await;
            true
        }
        Ok(resp) => {
            let status = resp.status().as_u16();
            mark_failed_or_retry(state, &d, Some(status as i64), &format!("status {status}")).await;
            false
        }
        Err(err) => {
            // Don't pass `err.to_string()` into the DB — reqwest includes the
            // failing URL which, for operators running validators behind
            // HTTP-Basic, can contain credentials. Persist a category + the
            // sanitized host instead.
            let safe = redact_reqwest_error(&err, parsed.host_str().unwrap_or(""));
            mark_failed_or_retry(state, &d, None, &safe).await;
            false
        }
    }
}

fn redact_reqwest_error(err: &reqwest::Error, host: &str) -> String {
    let category = if err.is_connect() {
        "connect"
    } else if err.is_timeout() {
        "timeout"
    } else if err.is_request() {
        "request"
    } else if err.is_body() {
        "body"
    } else if err.is_decode() {
        "decode"
    } else {
        "other"
    };
    // Only the host, never the path/query/userinfo. `parse_and_sanitize`
    // rejects userinfo but defense-in-depth.
    format!("{category} error for host={host}")
}

async fn mark_failed_or_retry(
    state: &AppState,
    d: &PendingDelivery,
    status: Option<i64>,
    err: &str,
) {
    let attempts = d.attempts + 1;
    let max = state.config.webhooks.max_retries as i64;
    let now = OffsetDateTime::now_utc().unix_timestamp() * 1000;

    if attempts >= max {
        let _ = sqlx::query(
            "UPDATE webhook_deliveries
                SET status='failed', attempts=?2, last_status=?3, last_error=?4
              WHERE id=?1",
        )
        .bind(d.id)
        .bind(attempts)
        .bind(status)
        .bind(err)
        .execute(&state.pool)
        .await;
        tracing::warn!(delivery = d.id, webhook = %d.webhook_id, "delivery gave up");
        return;
    }

    // Cap attempts exponent at 16 so `1 << attempts` stays in u32 range.
    // Cast retry_base_ms through i64::try_from; config.validate() already
    // bounds it to ≤ 3_600_000, but double-check to keep the arithmetic
    // sound even if that guard is bypassed in tests/future refactors.
    let base = i64::try_from(state.config.webhooks.retry_base_ms).unwrap_or(3_600_000);
    let shift = attempts.min(16);
    let backoff = base.saturating_mul(1i64 << shift);
    // `now` is unix_timestamp() which may be negative in principle (pre-1970
    // clock); `.rem_euclid` keeps the jitter non-negative without the abs()
    // footgun on i64::MIN.
    let jitter = now.rem_euclid(1_000);
    let next = now.saturating_add(backoff).saturating_add(jitter);

    // Release the claim: flip back to pending with updated retry metadata
    // and clear claimed_at so the stale-claim sweep doesn't revive it too.
    let _ = sqlx::query(
        "UPDATE webhook_deliveries
            SET status='pending', attempts=?2, next_attempt=?3,
                last_status=?4, last_error=?5, claimed_at=NULL
          WHERE id=?1",
    )
    .bind(d.id)
    .bind(attempts)
    .bind(next)
    .bind(status)
    .bind(err)
    .execute(&state.pool)
    .await;
}

#[derive(sqlx::FromRow)]
struct EventRecord {
    id: i64,
    ts: i64,
    event_type: String,
    event_name: Option<String>,
    url: String,
    page_title: Option<String>,
    user_agent: String,
    device_type: Option<String>,
    device_os: Option<String>,
    device_browser: Option<String>,
    referer: Option<String>,
    source: Option<String>,
    utm_source: Option<String>,
    utm_medium: Option<String>,
    utm_campaign: Option<String>,
    utm_term: Option<String>,
    utm_content: Option<String>,
    visitor_hash: String,
    segments: Option<String>,
    extra: Option<String>,
    user_id: Option<String>,
    country: Option<String>,
    user: Option<String>,
    session_id: Option<String>,
}

async fn load_event_json(
    pool: &SqlitePool,
    id: i64,
    expose_visitor_hash: bool,
    expose_user_payload: bool,
) -> anyhow::Result<Option<serde_json::Value>> {
    use crate::query::EVENTS_COLUMNS;

    let row: Option<EventRecord> =
        sqlx::query_as(&format!("SELECT {EVENTS_COLUMNS} FROM events WHERE id = ?"))
            .bind(id)
            .fetch_optional(pool)
            .await?;

    let Some(r) = row else {
        return Ok(None);
    };

    let segments: Option<serde_json::Value> = r
        .segments
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok());
    let extra: Option<serde_json::Value> = r
        .extra
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok());

    // Webhooks are an outbound "read" of event rows; honor the same privacy
    // flag as /events and /export.
    let mut payload = json!({
        "id": r.id,
        "ts": r.ts,
        "event_type": r.event_type,
        "event_name": r.event_name,
        "url": r.url,
        "page_title": r.page_title,
        "user_agent": r.user_agent,
        "device_type": r.device_type,
        "device_os": r.device_os,
        "device_browser": r.device_browser,
        "referer": r.referer,
        "source": r.source,
        "utm_source": r.utm_source,
        "utm_medium": r.utm_medium,
        "utm_campaign": r.utm_campaign,
        "utm_term": r.utm_term,
        "utm_content": r.utm_content,
        "segments": segments,
        "extra": extra,
        "user_id": r.user_id,
        "country": r.country,
        "session_id": r.session_id,
    });
    if let Some(obj) = payload.as_object_mut() {
        if expose_visitor_hash {
            obj.insert(
                "visitor_hash".into(),
                serde_json::Value::String(r.visitor_hash),
            );
        }
        if expose_user_payload {
            // The `user` column is the raw JSON the client signed — it
            // typically carries PII (id/email/plan). Ship it to subscribers
            // only when the operator opts in. `user_id` is always present
            // and is sufficient for attribution in most downstream systems.
            let user_value = r
                .user
                .as_deref()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
            obj.insert("user".into(), user_value.unwrap_or(serde_json::Value::Null));
        }
    }
    Ok(Some(payload))
}

/// v2 (current): signature covers `{timestamp}.{body}` so receivers that
/// verify correctly also reject replays outside their acceptance window.
/// v1 (`simple-analytics webhook v1`) is retired — the derivation context
/// has changed so captured v1 signatures are not accepted on the v2 path.
pub const WEBHOOK_SIGNATURE_CONTEXT: &str = "simple-analytics webhook v2";

fn sign(secret: &str, timestamp: &[u8], body: &[u8]) -> String {
    let key = blake3::derive_key(WEBHOOK_SIGNATURE_CONTEXT, secret.as_bytes());
    let mut hasher = blake3::Hasher::new_keyed(&key);
    hasher.update(timestamp);
    hasher.update(b".");
    hasher.update(body);
    format!("blake3={}", hasher.finalize().to_hex())
}
