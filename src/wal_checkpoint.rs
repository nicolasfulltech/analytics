//! Periodic `PRAGMA wal_checkpoint(TRUNCATE)`.
//!
//! SQLite's auto-checkpoint is PASSIVE: it advances the checkpoint pointer
//! but cannot reset or truncate the WAL while any reader is still holding
//! an older snapshot. Under sustained write load with any concurrent
//! readers (export streams, webhook cursor scans, validator lookups), the
//! WAL file therefore grows without bound — we measured 1 GB of WAL after
//> 30 s of 6.5k rps ingest even with `wal_autocheckpoint` bumped to 10k
//! pages.
//!
//! TRUNCATE mode waits for readers to clear, runs a full checkpoint, then
//! shrinks the WAL file back to zero bytes. Running it on a fixed interval
//! bounds disk usage at (interval × write rate × row size) between runs.
//!
//! We tolerate individual failures (BUSY, lock contention); the next tick
//! will retry.

use std::time::Duration;

use sqlx::SqlitePool;

use crate::state::AppState;

pub async fn run_worker(state: AppState, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let interval_secs = state.config.database.wal_checkpoint_interval_secs;
    if interval_secs == 0 {
        tracing::warn!("wal_checkpoint worker disabled — WAL may grow unbounded");
        // Supervise() treats an Ok(()) return without shutdown as a bug.
        // Park on shutdown so a deliberately-disabled worker looks like a
        // running worker to the supervisor.
        park_until_shutdown(&mut shutdown).await;
        return;
    }
    let interval = Duration::from_secs(interval_secs);
    tracing::info!(interval_secs, "wal_checkpoint worker started");

    // First tick happens immediately (no startup delay) — WAL can grow fast
    // under load and there's no reason to wait. Subsequent ticks space out
    // by `interval_secs`. Shutdown is observed at the tick boundary, not
    // mid-checkpoint.
    loop {
        let start = std::time::Instant::now();
        match checkpoint_truncate(&state.pool).await {
            Ok((busy, log, checkpointed)) => {
                tracing::info!(
                    busy,
                    log,
                    checkpointed,
                    elapsed_ms = start.elapsed().as_millis() as u64,
                    "wal_checkpoint(TRUNCATE)"
                );
            }
            Err(err) => {
                tracing::warn!(error = ?err, "wal_checkpoint failed; will retry");
            }
        }

        let wait = tokio::time::sleep(interval);
        tokio::pin!(wait);
        tokio::select! {
            _ = &mut wait => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("wal_checkpoint worker shutting down");
                    return;
                }
            }
        }
    }
}

/// Wait for the shutdown signal, then return. Used by workers that are
/// configured-out so they still look alive to `supervise()` (which treats
/// an early clean return as a bug, not a "worker disabled" signal).
async fn park_until_shutdown(shutdown: &mut tokio::sync::watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

/// Returns `(busy, log_frames, checkpointed_frames)`.
///
/// `busy` is 0 if the checkpoint completed without being blocked, 1 if it
/// gave up because a reader held the old snapshot. Non-zero busy still
/// counts as "we tried"; the next tick will get it.
async fn checkpoint_truncate(pool: &SqlitePool) -> sqlx::Result<(i64, i64, i64)> {
    use sqlx::Row;

    let row = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .fetch_one(pool)
        .await?;
    Ok((row.try_get(0)?, row.try_get(1)?, row.try_get(2)?))
}
