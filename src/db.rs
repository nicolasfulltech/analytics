use std::str::FromStr;
use std::time::Duration;

use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};

use crate::config::DatabaseConfig;

pub async fn init(cfg: &DatabaseConfig) -> anyhow::Result<SqlitePool> {
    if let Some(parent) = cfg.path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent).await.ok();
    }

    let url = format!("sqlite://{}", cfg.path.display());
    let opts = SqliteConnectOptions::from_str(&url)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(5))
        .foreign_keys(true)
        .pragma("temp_store", "memory")
        .pragma("mmap_size", "268435456")
        .pragma("cache_size", "-20000")
        // 10k pages ≈ 40 MB of WAL before auto-checkpoint. The 1k default
        // checkpoints roughly every 300 ms under sustained ingest (~13 MB/s
        // of WAL growth at 6–7k rps), and each checkpoint stalls writers
        // long enough to push a handful of INSERTs past 1 s. A larger window
        // amortizes fsync cost and keeps tail latency flat.
        .pragma("wal_autocheckpoint", "10000");

    let pool = SqlitePoolOptions::new()
        .max_connections(cfg.max_connections)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(opts)
        .await?;

    Ok(pool)
}

pub async fn migrate(pool: &SqlitePool) -> anyhow::Result<()> {
    // Cross-process coordination: SQLite's file lock + `busy_timeout=5s`
    // serializes writers, so two replicas starting at the same time race
    // on `_sqlx_migrations` but one wins per migration while the other
    // waits. After the winner commits, the loser sees the migration is
    // applied and no-ops. Retry once on transient SQLITE_BUSY to cover
    // the case where the lock times out during a long migration.
    match sqlx::migrate!("./migrations").run(pool).await {
        Ok(()) => Ok(()),
        Err(err) => {
            tracing::warn!(error = ?err, "migration attempt failed; retrying once");
            tokio::time::sleep(Duration::from_secs(1)).await;
            sqlx::migrate!("./migrations").run(pool).await?;
            Ok(())
        }
    }
}

pub async fn in_memory_for_tests() -> anyhow::Result<SqlitePool> {
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")?
        .journal_mode(SqliteJournalMode::Memory)
        .foreign_keys(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await?;

    migrate(&pool).await?;
    Ok(pool)
}
