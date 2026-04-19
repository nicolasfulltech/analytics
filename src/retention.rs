//! Background retention sweep. Deletes old rows from the time-series tables
//! on a fixed interval. Each table has its own TTL (config). Zero disables
//! deletion for that table.
//!
//! The sweep is intentionally cheap: it only touches indexed columns (`ts`
//! / `created_at` / `day`), runs in small-ish batches via LIMIT, and holds
//! the write lock only for the duration of each DELETE.

use std::time::Duration;

use sqlx::SqlitePool;
use time::OffsetDateTime;

use crate::config::RetentionConfig;
use crate::state::AppState;

pub async fn run_worker(state: AppState, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let cfg = state.config.retention.clone();
    let interval = Duration::from_secs(cfg.interval_secs.max(60));

    // Stagger the first run so we don't collide with aggregate refresh.
    // Cancellable: on SIGTERM within the stagger window, return immediately
    // instead of holding the 30s sleep open and being killed mid-sleep by
    // the shutdown timer.
    {
        let stagger = tokio::time::sleep(Duration::from_secs(30));
        tokio::pin!(stagger);
        tokio::select! {
            _ = &mut stagger => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
        }
    }

    loop {
        if let Err(err) = sweep(&state.pool, &cfg).await {
            tracing::error!(error = ?err, "retention sweep failed");
        }

        let wait = tokio::time::sleep(interval);
        tokio::pin!(wait);
        tokio::select! {
            _ = &mut wait => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("retention worker shutting down");
                    return;
                }
            }
        }
    }
}

/// Max rows to delete per transaction. Keeps the write-lock hold time bounded
/// even on a first sweep against a table with years of history — critical for
/// a deployment that enables retention long after ingest has been running.
const DELETE_CHUNK: i64 = 10_000;

async fn sweep(pool: &SqlitePool, cfg: &RetentionConfig) -> anyhow::Result<()> {
    let now_ms = OffsetDateTime::now_utc().unix_timestamp() * 1000;
    let day_ms = 86_400_000i64;

    if cfg.events_days > 0 {
        let cutoff = now_ms.saturating_sub(i64::from(cfg.events_days) * day_ms);
        let total = delete_in_chunks(
            pool,
            "DELETE FROM events WHERE id IN (SELECT id FROM events WHERE ts < ?1 LIMIT ?2)",
            cutoff,
        )
        .await?;
        if total > 0 {
            tracing::info!(table = "events", deleted = total, "retention swept");
        }
    }

    if cfg.webhook_deliveries_days > 0 {
        let cutoff = now_ms.saturating_sub(i64::from(cfg.webhook_deliveries_days) * day_ms);
        let total = delete_in_chunks(
            pool,
            "DELETE FROM webhook_deliveries WHERE id IN (
                SELECT id FROM webhook_deliveries
                WHERE status IN ('delivered', 'failed') AND created_at < ?1
                LIMIT ?2
            )",
            cutoff,
        )
        .await?;
        if total > 0 {
            tracing::info!(
                table = "webhook_deliveries",
                deleted = total,
                "retention swept"
            );
        }
    }

    if cfg.agg_daily_days > 0 {
        // agg_daily / agg_daily_url keyed on `day` TEXT in YYYY-MM-DD form —
        // cheap to compare lexicographically because ISO dates sort naturally.
        // Explicit per-table queries rather than a format!-loop to keep every
        // piece of SQL in this crate literal (project rule).
        let cutoff_date = OffsetDateTime::from_unix_timestamp(
            now_ms.saturating_sub(i64::from(cfg.agg_daily_days) * day_ms) / 1000,
        )?
        .format(&time::format_description::well_known::Iso8601::DATE)?;

        let deleted = sqlx::query("DELETE FROM agg_daily WHERE day < ?1")
            .bind(&cutoff_date)
            .execute(pool)
            .await?
            .rows_affected();
        if deleted > 0 {
            tracing::info!(table = "agg_daily", deleted, "retention swept");
        }

        let deleted = sqlx::query("DELETE FROM agg_daily_url WHERE day < ?1")
            .bind(&cutoff_date)
            .execute(pool)
            .await?
            .rows_affected();
        if deleted > 0 {
            tracing::info!(table = "agg_daily_url", deleted, "retention swept");
        }
    }

    Ok(())
}

/// Loop `DELETE ... LIMIT ?2` until no rows are affected. The query must take
/// `?1 = cutoff` and `?2 = chunk size`; the subselect shape keeps each
/// transaction short even on a huge backlog.
async fn delete_in_chunks(pool: &SqlitePool, sql: &str, cutoff: i64) -> anyhow::Result<u64> {
    let mut total = 0u64;
    loop {
        let affected = sqlx::query(sql)
            .bind(cutoff)
            .bind(DELETE_CHUNK)
            .execute(pool)
            .await?
            .rows_affected();
        total += affected;
        if affected < DELETE_CHUNK as u64 {
            break;
        }
        // Yield between chunks so `/collect` inserts can interleave rather
        // than starving behind a long retention run.
        tokio::task::yield_now().await;
    }
    Ok(total)
}
