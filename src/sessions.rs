//! Session assignment at ingest.
//!
//! Events from the same `visitor_hash` within `idle_timeout_mins` share a
//! session; a longer gap mints a new UUID. We cache `(last_session_id,
//! last_ts)` per visitor so the common case is one hash lookup, no DB round
//! trip. The first event of the day is a DB lookup (cache miss) — fine,
//! that's at most ~one query per new visitor per process lifetime.
//!
//! The cache is bounded and uses time-to-idle eviction so cardinality can't
//! grow unbounded under many-visitor loads.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use moka::future::Cache;
use sqlx::SqlitePool;
use uuid::Uuid;

/// Per-visitor cached session state. Held behind a Mutex because two
/// requests for the same visitor could race; the assignment must be
/// linearizable so both events observe the same `session_id` when their
/// timestamps are inside the window.
struct Entry {
    state: Mutex<EntryState>,
}

struct EntryState {
    session_id: String,
    last_ts: i64,
}

pub struct SessionAssigner {
    cache: Cache<String, Arc<Entry>>,
    idle_timeout_ms: i64,
    pool: SqlitePool,
}

impl SessionAssigner {
    pub fn new(pool: SqlitePool, idle_timeout_mins: u32) -> Self {
        let idle_timeout_ms = i64::from(idle_timeout_mins.max(1)) * 60_000;
        Self {
            cache: Cache::builder()
                .max_capacity(100_000)
                // A visitor who idles past `idle_timeout` on a fresh process
                // falls back to the DB lookup, which correctly returns a new
                // session. So setting TTI equal to the timeout keeps memory
                // tight without breaking correctness.
                .time_to_idle(Duration::from_millis(
                    u64::try_from(idle_timeout_ms).unwrap_or(1_800_000),
                ))
                .build(),
            idle_timeout_ms,
            pool,
        }
    }

    /// Returns the session_id for the given event. Updates the cache so
    /// subsequent events from the same visitor within the window reuse it.
    pub async fn assign(&self, visitor_hash: &str, ts: i64) -> sqlx::Result<String> {
        let entry = self
            .cache
            .get_with(visitor_hash.to_string(), async {
                // Cache miss: look up the most recent event for this visitor.
                // If the gap is within the window, keep that session. Else,
                // mint a new one. The DB row might be stale (our cache is the
                // hot-path authority), but on cold start it's the only truth.
                let row: Option<(String, i64)> = sqlx::query_as(
                    "SELECT session_id, ts FROM events
                     WHERE visitor_hash = ?1 AND session_id IS NOT NULL
                     ORDER BY ts DESC LIMIT 1",
                )
                .bind(visitor_hash)
                .fetch_optional(&self.pool)
                .await
                .ok()
                .flatten();

                // Directional gap: only `ts - last_ts` (forward in time) can
                // extend a session. A back-dated event from a buffered mobile
                // client must not fold into a newer live session, and it
                // must not rewind `last_ts` for future events.
                let (session_id, last_ts) = match row {
                    Some((sid, last)) if ts >= last && ts - last <= self.idle_timeout_ms => {
                        (sid, ts)
                    }
                    _ => (Uuid::new_v4().to_string(), ts),
                };

                Arc::new(Entry {
                    state: Mutex::new(EntryState {
                        session_id,
                        last_ts,
                    }),
                })
            })
            .await;

        // `into_inner` on poisoning keeps the limiter alive rather than
        // cascading panics across every subsequent event for this visitor.
        let mut state = entry
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if ts > state.last_ts {
            if ts - state.last_ts > self.idle_timeout_ms {
                state.session_id = Uuid::new_v4().to_string();
            }
            state.last_ts = ts;
        }
        Ok(state.session_id.clone())
    }
}
