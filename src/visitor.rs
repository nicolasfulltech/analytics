use std::sync::Arc;

use sqlx::SqlitePool;
use time::OffsetDateTime;
use tokio::sync::{Mutex, RwLock};

/// Daily-rotating salt for visitor_hash.
///
/// Two goals that shape the design:
///
/// 1. A hostile read-key holder can't correlate visitors across UTC day
///    boundaries because every day's hash is keyed off a different salt.
/// 2. A thundering herd at 00:00:00 UTC doesn't fan out into many DB
///    writers racing to insert the new day's salt, and *every* concurrent
///    ingest sees the same post-rotation salt in the same tick.
///
/// The old implementation used `std::sync::RwLock` with a check-then-act
/// pattern: read the cache, drop the lock, call `refresh()` async, take the
/// write lock, update. Two problems:
///
/// - The read-then-refresh gap meant a handler entering at 23:59:59.999
///   could fetch `salt_old`, and a sibling handler entering 1ms later could
///   fetch `salt_new` — the same physical visitor's two pageviews across
///   midnight would hash to two different `visitor_hash`es.
/// - Blocking `RwLock::write()` held across awaited DB I/O stalls Tokio
///   worker threads under contention (multi-thread runtime).
///
/// New shape:
///
/// - `tokio::sync::RwLock` so waiting on the write side yields.
/// - A `Mutex<Option<Task>>` single-flight guard so all concurrent cache
///   misses await the same DB round-trip; only one writer hits the DB per
///   rotation.
/// - `current()` returns the salt that was valid at the moment of the call;
///   a rotation in flight blocks the caller until the new salt is installed
///   so adjacent ingest paths see a consistent value.
///
/// The day key is derived from `OffsetDateTime::now_utc()` (wall clock). An
/// NTP step-back that crosses midnight would re-use yesterday's stored
/// salt — the DB is canonical. That's correctness-preserving (no salt
/// divergence) rather than a rotation; see the module docs.
pub struct SaltStore {
    pool: SqlitePool,
    cached: RwLock<CachedSalt>,
    /// Single-flight gate for `refresh()`. The `()` payload is just "someone
    /// is already refreshing — wait your turn".
    refresh_lock: Arc<Mutex<()>>,
}

#[derive(Clone)]
struct CachedSalt {
    day: String,
    salt: [u8; 32],
}

impl SaltStore {
    pub async fn new(pool: SqlitePool) -> anyhow::Result<Self> {
        let store = Self {
            pool,
            cached: RwLock::new(CachedSalt {
                day: String::new(),
                salt: [0u8; 32],
            }),
            refresh_lock: Arc::new(Mutex::new(())),
        };
        store.refresh().await?;
        Ok(store)
    }

    /// Force a refresh from the DB. Single-flighted: if another task is
    /// already inside `refresh()`, the second caller awaits the same update
    /// and then returns — so at most one DB round-trip per rotation.
    pub async fn refresh(&self) -> anyhow::Result<()> {
        // Acquire the single-flight gate. All concurrent `refresh()` calls
        // serialize here; the first does the actual write, the rest no-op
        // after the re-check below (cache is already current by then).
        let _guard = self.refresh_lock.lock().await;

        let day = today_utc()?;
        {
            let cur = self.cached.read().await;
            if cur.day == day {
                return Ok(());
            }
        }

        // ON CONFLICT DO NOTHING ensures only one writer per-day wins even
        // across process restarts; we always read the canonical row so the
        // DB and the in-process cache agree byte-for-byte.
        let candidate: [u8; 32] = rand::random();
        let now = OffsetDateTime::now_utc().unix_timestamp() * 1000;
        sqlx::query(
            "INSERT INTO daily_salts (day_utc, salt, created_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(day_utc) DO NOTHING",
        )
        .bind(&day)
        .bind(&candidate[..])
        .bind(now)
        .execute(&self.pool)
        .await?;

        let (canonical,): (Vec<u8>,) =
            sqlx::query_as("SELECT salt FROM daily_salts WHERE day_utc = ?1")
                .bind(&day)
                .fetch_one(&self.pool)
                .await?;

        let mut salt_bytes = [0u8; 32];
        let n = canonical.len().min(32);
        salt_bytes[..n].copy_from_slice(&canonical[..n]);

        let mut guard = self.cached.write().await;
        guard.day = day;
        guard.salt = salt_bytes;
        Ok(())
    }

    /// Returns the salt for today's UTC day, refreshing if the cached value
    /// is stale. On the fast path this is a single async RwLock read.
    pub async fn current(&self) -> anyhow::Result<[u8; 32]> {
        let day = today_utc()?;
        {
            let cur = self.cached.read().await;
            if cur.day == day {
                return Ok(cur.salt);
            }
        }
        self.refresh().await?;
        Ok(self.cached.read().await.salt)
    }
}

pub fn visitor_hash(salt: &[u8; 32], ip: &str, user_agent: &str) -> String {
    let mut hasher = blake3::Hasher::new_keyed(salt);
    hasher.update(ip.as_bytes());
    hasher.update(b"|");
    hasher.update(user_agent.as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn today_utc() -> anyhow::Result<String> {
    let now = OffsetDateTime::now_utc();
    let fmt = time::macros::format_description!("[year]-[month]-[day]");
    Ok(now.format(&fmt)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visitor_hash_is_deterministic_for_same_inputs() {
        let salt = [7u8; 32];
        let a = visitor_hash(&salt, "1.2.3.4", "Mozilla/5.0");
        let b = visitor_hash(&salt, "1.2.3.4", "Mozilla/5.0");
        assert_eq!(a, b);
    }

    #[test]
    fn visitor_hash_differs_with_different_salt() {
        let a = visitor_hash(&[1u8; 32], "1.2.3.4", "Mozilla/5.0");
        let b = visitor_hash(&[2u8; 32], "1.2.3.4", "Mozilla/5.0");
        assert_ne!(a, b);
    }

    #[test]
    fn visitor_hash_differs_with_different_ua() {
        let salt = [7u8; 32];
        let a = visitor_hash(&salt, "1.2.3.4", "Mozilla/5.0");
        let b = visitor_hash(&salt, "1.2.3.4", "curl/8");
        assert_ne!(a, b);
    }
}
