pub mod auth;
pub mod backup;
pub mod beacon;
pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod geoip;
pub mod hot_reload;
pub mod ingest;
pub mod metrics;
pub mod model;
pub mod net;
pub mod openapi;
pub mod query;
pub mod rate_limit;
pub mod retention;
pub mod sessions;
pub mod state;
pub mod telemetry;
pub mod user_token;
pub mod visitor;
pub mod wal_checkpoint;
pub mod webhooks;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{Request, StatusCode};
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::state::AppState;

/// Install the rustls crypto provider exactly once per process. Both `ring`
/// and `aws-lc-rs` are compiled into rustls 0.23 via transitive features, and
/// with no explicit choice rustls panics on the first TLS handshake. Tests
/// only exercise HTTP so it's latent — we install here so the first outbound
/// webhook (HTTPS) doesn't crash the worker.
pub fn install_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // `install_default` returns Err if a provider is already installed —
        // ignore; means the host crate (or a test) set one first.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

pub async fn build_app(config: Arc<Config>) -> anyhow::Result<(Router, AppState)> {
    install_crypto_provider();
    let pool = db::init(&config.database).await?;
    db::migrate(&pool).await?;
    build_app_with_pool(config, pool).await
}

pub async fn build_app_with_pool(
    config: Arc<Config>,
    pool: sqlx::SqlitePool,
) -> anyhow::Result<(Router, AppState)> {
    install_crypto_provider();
    let state = AppState::new(config.clone(), pool).await?;

    let router = Router::new()
        .merge(ingest::routes(&config.endpoints))
        .merge(query::routes())
        .merge(webhooks::routes())
        .merge(beacon::routes(&config.endpoints))
        .merge(health_routes())
        // Catch-all 404 that matches the `AppError` JSON shape. The default
        // axum 404 is an empty body with no Content-Type, which lets an
        // attacker distinguish "unmapped route" from "auth-gated 401" by
        // body shape — minor but useful fingerprint when probing the API.
        .fallback(not_found_handler)
        .layer(DefaultBodyLimit::max(config.server.max_body_bytes))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_millis(config.server.request_timeout_ms),
        ))
        // Custom span so query strings (which can carry `user_id` / arbitrary
        // filters) never land in logs, and attacker-controlled User-Agent
        // values can't inject ANSI/CRLF escapes into the compact formatter.
        // Structured JSON logs (`LOG_FORMAT=json`) escape control chars
        // automatically but the compact default doesn't.
        .layer(
            TraceLayer::new_for_http().make_span_with(|req: &Request<_>| {
                tracing::info_span!(
                    "http",
                    method = %req.method(),
                    path = %req.uri().path(),
                )
            }),
        )
        // gzip on JSON/ndjson/csv responses. /events and /stats responses
        // compress very well (highly repetitive JSON); /export too. The
        // client opts in via `Accept-Encoding: gzip` so anything that can't
        // handle it gets the raw body.
        .layer(CompressionLayer::new().gzip(true))
        .layer(cors_layer(&config))
        .with_state(state.clone());

    Ok((router, state))
}

fn cors_layer(config: &Config) -> CorsLayer {
    use axum::http::{HeaderName, Method};

    let origins: Vec<_> = config
        .auth
        .allowed_origins
        .iter()
        .filter_map(|o| o.parse().ok())
        .collect();

    // Header names must be lowercase for axum; we also fall back to "content-type"
    // if the configured header can't be parsed (wouldn't normally happen — the
    // config validator rejects empty values).
    let token_header =
        HeaderName::try_from(config.endpoints.browser_token_header.to_ascii_lowercase())
            .unwrap_or_else(|_| HeaderName::from_static("content-type"));

    // If no origins are configured the browser endpoint is disabled — emit a CORS
    // layer that denies every cross-origin request rather than a wildcard.
    let layer = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([HeaderName::from_static("content-type"), token_header])
        .max_age(Duration::from_secs(600));

    if origins.is_empty() {
        layer
    } else {
        layer.allow_origin(origins)
    }
}

fn health_routes() -> Router<AppState> {
    use axum::routing::get;

    // `/metrics` exposes gauge + counter values (event volumes, queue depth,
    // worker restarts) that an external attacker should not be able to
    // enumerate. `/openapi.json` exposes the full API surface — also gated.
    // Scrapers pass `x-read-key` like any other read consumer.
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(readyz))
        .route(
            "/metrics",
            get(
                |_auth: crate::auth::ReadAuth,
                 state: axum::extract::State<AppState>| async move {
                    crate::metrics::metrics_handler(state).await
                },
            ),
        )
        .route(
            "/openapi.json",
            get(|_auth: crate::auth::ReadAuth| async move {
                crate::openapi::openapi_handler().await
            }),
        )
}

async fn not_found_handler() -> crate::error::AppError {
    crate::error::AppError::NotFound
}

async fn readyz(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> (StatusCode, &'static str) {
    // Unauthenticated: external load balancers need to reach this. Two
    // defenses keep it from being an amplification vector:
    //
    //   1. `pool.try_acquire` — if the pool is saturated by real traffic
    //      we return 503 WITHOUT queuing for a connection. A probe flood
    //      can't deepen pool pressure.
    //   2. A short timeout bounds any individual probe's DB cost even if
    //      a connection was acquired but the query stalls (WAL lock).
    let Some(mut conn) = state.pool.try_acquire() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "not ready");
    };
    let query = sqlx::query_scalar::<_, i64>("SELECT 1").fetch_one(&mut *conn);
    match tokio::time::timeout(Duration::from_millis(500), query).await {
        Ok(Ok(_)) => (StatusCode::OK, "ready"),
        _ => (StatusCode::SERVICE_UNAVAILABLE, "not ready"),
    }
}
