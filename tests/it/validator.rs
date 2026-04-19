use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use axum::Router;
use axum::extract::Query;
use axum::http::StatusCode;
use serde::Deserialize;
use simple_analytics::config::ValidatorConfig;
use simple_analytics::ingest::validator::{UrlValidator, ValidationOutcome};
use tokio::net::TcpListener;

#[derive(Deserialize)]
struct ValidateParams {
    url: String,
}

async fn spawn_validator(ok_urls: Arc<Vec<String>>) -> (String, Arc<AtomicU32>) {
    let calls = Arc::new(AtomicU32::new(0));
    let calls_c = calls.clone();
    let app = Router::new().route(
        "/v",
        axum::routing::get(move |Query(q): Query<ValidateParams>| {
            let ok = ok_urls.clone();
            let calls = calls_c.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                if ok.iter().any(|u| u == &q.url) {
                    StatusCode::OK
                } else {
                    StatusCode::NOT_FOUND
                }
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, calls)
}

/// The integration tests spin up validators on 127.0.0.1 — production
/// deployments must keep `allow_private_targets = false` (the default) to
/// block SSRF pivots. Each test below opts in explicitly so the pinned
/// client skips the public-IP safety check and accepts the loopback target.
fn test_validator_cfg(url: String, fail_open: bool, timeout_ms: u64) -> ValidatorConfig {
    ValidatorConfig {
        url: Some(url),
        cache_ttl_secs: 60,
        cache_size: 100,
        timeout_ms,
        fail_open,
        allow_private_targets: true,
    }
}

#[tokio::test]
async fn validator_returns_valid_for_200() {
    let (addr, _) = spawn_validator(Arc::new(vec!["https://example.com/ok".into()])).await;
    let cfg = test_validator_cfg(format!("http://{addr}/v"), true, 1_000);
    let v = UrlValidator::new(&cfg);
    assert_eq!(
        v.validate("https://example.com/ok").await,
        ValidationOutcome::Valid
    );
}

#[tokio::test]
async fn validator_returns_invalid_for_404() {
    let (addr, _) = spawn_validator(Arc::new(vec![])).await;
    let cfg = test_validator_cfg(format!("http://{addr}/v"), true, 1_000);
    let v = UrlValidator::new(&cfg);
    assert_eq!(
        v.validate("https://example.com/nope").await,
        ValidationOutcome::Invalid
    );
}

#[tokio::test]
async fn validator_caches_results() {
    let ok = Arc::new(vec!["https://example.com/a".into()]);
    let (addr, calls) = spawn_validator(ok).await;
    let cfg = test_validator_cfg(format!("http://{addr}/v"), true, 1_000);
    let v = UrlValidator::new(&cfg);
    for _ in 0..5 {
        assert_eq!(
            v.validate("https://example.com/a").await,
            ValidationOutcome::Valid
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn validator_fail_open_when_unreachable() {
    let cfg = test_validator_cfg("http://127.0.0.1:1/does-not-exist".into(), true, 100);
    let v = UrlValidator::new(&cfg);
    assert_eq!(
        v.validate("https://any.example/").await,
        ValidationOutcome::Valid
    );
}

#[tokio::test]
async fn validator_fail_closed_when_unreachable() {
    let cfg = test_validator_cfg("http://127.0.0.1:1/does-not-exist".into(), false, 100);
    let v = UrlValidator::new(&cfg);
    assert_eq!(
        v.validate("https://any.example/").await,
        ValidationOutcome::Invalid
    );
}

#[tokio::test]
async fn config_rejects_private_validator_url() {
    use simple_analytics::config::Config;
    let mut cfg = simple_analytics::config::Config {
        server: Default::default(),
        database: Default::default(),
        auth: simple_analytics::config::AuthConfig {
            write_keys: vec!["a".repeat(32)],
            read_keys: vec!["b".repeat(32)],
            admin_keys: vec!["c".repeat(32)],
            site_token: String::new(),
            allowed_origins: vec![],
            user_signing_secret: String::new(),
            admin_ip_allowlist: vec![],
            user_token_max_age_secs: 900,
        },
        ingest: Default::default(),
        validator: ValidatorConfig {
            url: Some("http://169.254.169.254/meta".into()),
            ..Default::default()
        },
        webhooks: Default::default(),
        materialization: Default::default(),
        sessions: Default::default(),
        backup: Default::default(),
        endpoints: Default::default(),
        geoip: Default::default(),
        privacy: Default::default(),
        retention: Default::default(),
    };
    // allow_private_targets=false (default) — must reject
    assert!(<Config as Clone>::clone(&cfg).validate().is_err());
    // opting in bypasses the check
    cfg.validator.allow_private_targets = true;
    assert!(cfg.validate().is_ok());
}

#[tokio::test]
async fn validator_skipped_when_not_configured() {
    let cfg = ValidatorConfig {
        url: None,
        cache_ttl_secs: 60,
        cache_size: 100,
        timeout_ms: 100,
        fail_open: true,
        ..Default::default()
    };
    let v = UrlValidator::new(&cfg);
    assert_eq!(
        v.validate("https://any.example/").await,
        ValidationOutcome::Skipped
    );
}
