use std::net::SocketAddr;
use std::sync::Arc;

use simple_analytics::backup;
use simple_analytics::config::Config;
use simple_analytics::ingest::validator as url_validator;
use simple_analytics::query::aggregates;
use simple_analytics::retention;
use simple_analytics::wal_checkpoint;
use simple_analytics::webhooks::delivery as webhook_delivery;
use simple_analytics::{build_app, telemetry};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    telemetry::init();

    let config = Arc::new(Config::load()?);
    tracing::info!(bind = %config.server.bind, db = %config.database.path.display(), "starting");

    let (router, state) = build_app(config.clone()).await?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // SIGHUP listener: re-read the config file and swap the hot-reloadable
    // snapshot. Only keys, origins, and segment allowlist are reloaded;
    // everything else requires a restart.
    #[cfg(unix)]
    {
        let reloadable = state.reloadable.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let Ok(mut sighup) = signal(SignalKind::hangup()) else {
                tracing::warn!("failed to install SIGHUP handler");
                return;
            };
            while sighup.recv().await.is_some() {
                match simple_analytics::hot_reload::reload(&reloadable) {
                    Ok(_) => tracing::info!("config hot-reloaded (SIGHUP)"),
                    Err(err) => {
                        tracing::error!(error = ?err, "config reload failed; keeping old snapshot")
                    }
                }
            }
        });
    }

    // Wrap each worker so a panic restarts it instead of silently dying. The
    // aggregates and webhook workers are load-bearing; if they stop without
    // the process dying, /healthz keeps reporting OK while stats freeze and
    // webhooks pile up. `AssertUnwindSafe` is fine here because the futures
    // don't share mutable state with anything outside their own scope.
    let agg_state = state.clone();
    let agg_shutdown = shutdown_rx.clone();
    let agg_metrics = state.metrics.clone();
    let agg_handle = tokio::spawn(supervise(
        "aggregates_worker",
        shutdown_rx.clone(),
        agg_metrics,
        move || {
            let s = agg_state.clone();
            let sd = agg_shutdown.clone();
            async move { aggregates::run_worker(s, sd).await }
        },
    ));

    let wh_state = state.clone();
    let wh_shutdown = shutdown_rx.clone();
    let wh_metrics = state.metrics.clone();
    let wh_handle = tokio::spawn(supervise(
        "webhook_worker",
        shutdown_rx.clone(),
        wh_metrics,
        move || {
            let s = wh_state.clone();
            let sd = wh_shutdown.clone();
            async move { webhook_delivery::run_worker(s, sd).await }
        },
    ));

    let ret_state = state.clone();
    let ret_shutdown = shutdown_rx.clone();
    let ret_metrics = state.metrics.clone();
    let ret_handle = tokio::spawn(supervise(
        "retention_worker",
        shutdown_rx.clone(),
        ret_metrics,
        move || {
            let s = ret_state.clone();
            let sd = ret_shutdown.clone();
            async move { retention::run_worker(s, sd).await }
        },
    ));

    let wal_state = state.clone();
    let wal_shutdown = shutdown_rx.clone();
    let wal_metrics = state.metrics.clone();
    let wal_handle = tokio::spawn(supervise(
        "wal_checkpoint_worker",
        shutdown_rx.clone(),
        wal_metrics,
        move || {
            let s = wal_state.clone();
            let sd = wal_shutdown.clone();
            async move { wal_checkpoint::run_worker(s, sd).await }
        },
    ));

    let backup_state = state.clone();
    let backup_shutdown = shutdown_rx.clone();
    let backup_metrics = state.metrics.clone();
    let backup_handle = tokio::spawn(supervise(
        "backup_worker",
        shutdown_rx.clone(),
        backup_metrics,
        move || {
            let s = backup_state.clone();
            let sd = backup_shutdown.clone();
            async move { backup::run_worker(s, sd).await }
        },
    ));

    // Periodic DNS refresh for the pinned validator client. Picks up IP
    // rotation at the operator's validator host without needing a restart —
    // the reqwest client is rebuilt with the freshly-resolved IP pinned.
    let validator_handle = {
        let validator = state.validator.clone();
        let sd = shutdown_rx.clone();
        let metrics = state.metrics.clone();
        tokio::spawn(supervise(
            "validator_refresh_worker",
            shutdown_rx.clone(),
            metrics,
            move || {
                let v = validator.clone();
                let sd = sd.clone();
                async move { url_validator::run_refresh_worker(v, sd).await }
            },
        ))
    };

    let addr: SocketAddr = config.server.bind.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("listening on {addr}");

    // Serve on its own task so the 30s shutdown-deadline timer only starts
    // once SIGTERM fires. Wrapping the whole `serve` future in a timeout
    // would cap total server lifetime — which is the bug the prior shape had.
    // `with_graceful_shutdown` listens on a watch channel; the signal handler
    // in main flips it and then waits up to 30s for handlers/streams to drain.
    let graceful_rx = shutdown_rx.clone();
    let serve = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let mut rx = graceful_rx;
        while !*rx.borrow() {
            if rx.changed().await.is_err() {
                return;
            }
        }
    });
    let server_handle = tokio::spawn(async move { serve.await });

    shutdown_signal().await;
    tracing::info!("shutdown signal received");
    let _ = shutdown_tx.send(true);

    // Close the export semaphore before waiting on the HTTP server. Each
    // /export stream holds a permit until its inner task finishes; those
    // tasks poll the shutdown watch channel via the same signal we just
    // flipped, so they'll unwind cleanly. The close() prevents NEW exports
    // from acquiring during the drain window. Without this, a long-running
    // export started 1s before SIGTERM can hold a pool connection across
    // the full 30s drain and block worker flushes.
    state.export_semaphore.close();

    match tokio::time::timeout(std::time::Duration::from_secs(30), server_handle).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(e))) => return Err(e.into()),
        Ok(Err(join_err)) => tracing::error!(error = ?join_err, "server task panicked"),
        Err(_) => tracing::warn!("graceful shutdown exceeded 30s, forcing exit"),
    }

    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), agg_handle).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), wh_handle).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), ret_handle).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), wal_handle).await;
    // VACUUM INTO can take many seconds on a large DB; give it a longer
    // drain window than the other workers so a mid-flight snapshot can
    // finish writing and not leave a partial `.db` file behind.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(60), backup_handle).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), validator_handle).await;

    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal;

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = signal::ctrl_c() => {}
        _ = terminate => {}
    }
}

/// Run `factory` in a loop, restarting on panic (or on an unexpected clean
/// return) after a short backoff. Used for long-lived background workers
/// whose failure would otherwise silently freeze a subsystem while the HTTP
/// server keeps returning OK. The backoff sleep races with `shutdown` so a
/// panic right before SIGTERM doesn't stall process exit.
///
/// A clean `Ok(())` return is only treated as success when the shutdown
/// watch channel is set; otherwise it is treated like a panic (log + bump
/// restart counter + backoff + retry). The distinction matters because
/// workers that return early for a non-panic reason (e.g. an early `return`
/// on a config-shaped edge) would otherwise silently disappear and
/// `/healthz` would keep returning OK while the subsystem is dead.
async fn supervise<F, Fut>(
    name: &'static str,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    metrics: Arc<simple_analytics::metrics::Metrics>,
    factory: F,
) where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    use futures::FutureExt;
    let mut backoff_ms = 500u64;
    loop {
        let result = std::panic::AssertUnwindSafe(factory()).catch_unwind().await;
        let (err_label, msg): (&str, String) = match result {
            Ok(()) if *shutdown.borrow() => {
                tracing::info!(worker = name, "worker returned cleanly during shutdown");
                return;
            }
            Ok(()) => (
                "clean_return",
                "worker returned without shutdown signal".into(),
            ),
            Err(panic) => {
                let m = panic
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "<non-string panic>".into());
                ("panic", m)
            }
        };
        tracing::error!(
            worker = name,
            reason = err_label,
            detail = %msg,
            "worker exited unexpectedly; restarting"
        );
        simple_analytics::metrics::bump(&metrics.worker_restarts);
        let sleep = tokio::time::sleep(std::time::Duration::from_millis(backoff_ms));
        tokio::pin!(sleep);
        tokio::select! {
            _ = &mut sleep => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!(worker = name, "shutdown during backoff");
                    return;
                }
            }
        }
        backoff_ms = (backoff_ms * 2).min(30_000);
    }
}
