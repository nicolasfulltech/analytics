//! Periodic snapshot of the SQLite DB.
//!
//! Uses `VACUUM INTO` rather than a raw file copy because WAL mode needs the
//! WAL + `-shm` to be consistent with the main DB file; `VACUUM INTO` emits a
//! single standalone DB at a consistent point in time without blocking
//! writers. Output is named `analytics-<YYYYMMDDTHHMMSS>Z.db` in the
//! configured backup directory.
//!
//! Retention: after each successful snapshot, the worker lists matching
//! files in the backup directory, sorts by name (chronological because of
//! the timestamp-prefix naming), and deletes everything older than
//! `keep_count` entries. A simple LRU — if an operator wants to keep a
//! specific snapshot, they should move it out of the directory first.

use std::path::{Path, PathBuf};
use std::time::Duration;

use time::OffsetDateTime;
use time::format_description::well_known::Iso8601;

use crate::state::AppState;

pub async fn run_worker(state: AppState, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let cfg = &state.config.backup;
    if cfg.path.is_empty() || cfg.interval_hours == 0 {
        tracing::info!("backup worker disabled (path or interval not set)");
        // Park so `supervise()` doesn't treat a disabled-by-config worker
        // as a clean exit bug and restart-loop it forever.
        park_until_shutdown(&mut shutdown).await;
        return;
    }

    let dir = PathBuf::from(&cfg.path);
    if let Err(err) = tokio::fs::create_dir_all(&dir).await {
        tracing::error!(error = ?err, path = %dir.display(), "cannot create backup directory; worker exiting");
        // Can't create the target dir — panic so the supervisor picks it up,
        // gets the structured restart log, and backs off properly. A silent
        // return would look like a clean exit and trip the bug trap above.
        panic!("backup dir {} not writable: {err}", dir.display());
    }

    let interval = Duration::from_secs(u64::from(cfg.interval_hours) * 3600);
    tracing::info!(
        interval_hours = cfg.interval_hours,
        keep = cfg.keep_count,
        path = %dir.display(),
        "backup worker started"
    );

    // First tick after one interval — the process just started, the DB is
    // already on disk, no reason to take a snapshot immediately.
    loop {
        let sleep = tokio::time::sleep(interval);
        tokio::pin!(sleep);
        tokio::select! {
            _ = &mut sleep => {
                // Skip the snapshot if shutdown fired during the sleep — the
                // tokio::select above picks the first-ready branch, so the
                // sleep arm may win by a hair even after the shutdown flag
                // flipped. VACUUM INTO can't be cancelled mid-flight, so
                // best to never start one during shutdown.
                if *shutdown.borrow() {
                    tracing::info!("backup worker shutting down (post-sleep check)");
                    return;
                }
                if let Err(err) = snapshot(&state, &dir).await {
                    tracing::error!(error = ?err, "backup failed; will retry next tick");
                }
                if let Err(err) = prune(&dir, cfg.keep_count).await {
                    tracing::warn!(error = ?err, "backup prune failed");
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("backup worker shutting down");
                    return;
                }
            }
        }
    }
}

async fn park_until_shutdown(shutdown: &mut tokio::sync::watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

async fn snapshot(state: &AppState, dir: &Path) -> anyhow::Result<()> {
    // `VACUUM INTO` returns when the snapshot file is fully written and
    // fsynced. We name with a strict sortable timestamp so `prune()` can
    // rely on lexical order.
    let now = OffsetDateTime::now_utc();
    let stamp = now
        .format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| now.unix_timestamp().to_string())
        .replace([':', '-'], "");
    let name = format!("analytics-{stamp}.db");
    let target = dir.join(&name);

    // sqlx doesn't let us bind the output path into `VACUUM INTO`, and
    // plain `bind()` wouldn't work anyway (PRAGMAs and VACUUM can't be
    // parameterized). The path is operator-controlled via `backup.path`,
    // but a single-char allowlist keeps us from needing to reason about
    // every SQL metacharacter: refuse anything outside
    // `[A-Za-z0-9/_.-]`. The timestamp piece already matches; the parent
    // directory comes from config and would fail `create_dir_all` above
    // if it contained anything useful to an attacker anyway.
    let target_str = target
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("backup path is not valid utf-8"))?;
    if !target_str
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '.' | '-'))
    {
        anyhow::bail!(
            "backup path must contain only [A-Za-z0-9/_.-]; got {:?}",
            target_str
        );
    }

    let sql = format!("VACUUM INTO '{target_str}'");
    sqlx::query(&sql).execute(&state.pool).await?;

    tracing::info!(path = %target.display(), "backup snapshot written");
    Ok(())
}

async fn prune(dir: &Path, keep: u32) -> anyhow::Result<()> {
    let keep = keep.max(1) as usize;
    let mut entries: Vec<PathBuf> = Vec::new();
    let mut rd = tokio::fs::read_dir(dir).await?;
    while let Some(e) = rd.next_entry().await? {
        let p = e.path();
        if let Some(name) = p.file_name().and_then(|s| s.to_str())
            && name.starts_with("analytics-")
            && name.ends_with(".db")
        {
            entries.push(p);
        }
    }
    entries.sort();
    if entries.len() <= keep {
        return Ok(());
    }
    let drop_count = entries.len() - keep;
    for p in entries.into_iter().take(drop_count) {
        if let Err(err) = tokio::fs::remove_file(&p).await {
            tracing::warn!(error = ?err, path = %p.display(), "failed to prune old backup");
        } else {
            tracing::debug!(path = %p.display(), "pruned old backup");
        }
    }
    Ok(())
}
