#![allow(dead_code)]

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, Response, StatusCode};
use serde_json::Value;
use simple_analytics::config::{
    AuthConfig, BackupConfig, Config, DatabaseConfig, EndpointsConfig, GeoIpConfig, IngestConfig,
    MaterializationConfig, PrivacyConfig, RetentionConfig, ServerConfig, SessionsConfig,
    ValidatorConfig, WebhooksConfig,
};
use simple_analytics::state::AppState;
use tower::ServiceExt;

pub const WRITE_KEY: &str = "test-write-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub const READ_KEY: &str = "test-read-key-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
pub const ADMIN_KEY: &str = "test-admin-key-ccccccccccccccccccccccccccccccccc";
pub const SITE_TOKEN: &str = "site-token-dddddddddddddddddddddddddddddddd";
pub const USER_SIGNING_SECRET: &str = "user-signing-secret-eeeeeeeeeeeeeeeeeeeeeee";

pub const BROWSER_PATH: &str = "/e";
pub const BROWSER_SCRIPT_PATH: &str = "/s.js";
pub const BROWSER_TOKEN_HEADER: &str = "x-id";

pub fn test_config() -> Config {
    Config {
        server: ServerConfig::default(),
        database: DatabaseConfig::default(),
        auth: AuthConfig {
            write_keys: vec![WRITE_KEY.into()],
            read_keys: vec![READ_KEY.into()],
            admin_keys: vec![ADMIN_KEY.into()],
            site_token: SITE_TOKEN.into(),
            allowed_origins: vec!["https://example.com".into()],
            user_signing_secret: USER_SIGNING_SECRET.into(),
            admin_ip_allowlist: vec![],
            user_token_max_age_secs: 900,
        },
        ingest: IngestConfig {
            allowed_segments: vec!["paid".into(), "free".into(), "anonymous".into()],
            allow_unknown_segments: false,
            browser_rate_limit_per_min: 1_000,
            browser_rate_limit_burst: 1_000,
            beacon_token_rate_limit_per_min: 1_000_000,
            beacon_token_rate_limit_burst: 1_000_000,
            server_rate_limit_per_min: 1_000_000,
            server_rate_limit_burst: 1_000_000,
            read_rate_limit_per_min: 1_000_000,
            read_rate_limit_burst: 1_000_000,
            auth_ip_rate_limit_per_min: 1_000_000,
            auth_ip_rate_limit_burst: 1_000_000,
            trust_proxy: false,
        },
        validator: ValidatorConfig {
            url: None,
            cache_ttl_secs: 60,
            cache_size: 100,
            timeout_ms: 500,
            fail_open: true,
            ..Default::default()
        },
        webhooks: WebhooksConfig {
            // Integration tests spin up a test receiver on 127.0.0.1:<port>.
            // Production deployments should leave this false to block SSRF.
            allow_private_targets: true,
            // Generous cap so tests that register many webhooks don't trip
            // the fan-out guard.
            max_webhooks: 1_000,
            ..WebhooksConfig::default()
        },
        materialization: MaterializationConfig::default(),
        sessions: SessionsConfig::default(),
        backup: BackupConfig::default(),
        endpoints: EndpointsConfig::default(),
        geoip: GeoIpConfig::default(),
        // Tests assert on visitor_hash; they take the expose-enabled path.
        // Webhook-body tests want the full user blob too.
        privacy: PrivacyConfig {
            expose_visitor_hash: true,
            expose_user_payload: true,
        },
        retention: RetentionConfig::default(),
    }
}

pub async fn build() -> (Router, AppState) {
    build_with(|_| {}).await
}

/// Build with a config customization callback. Useful when a test needs to
/// exercise the `false`-default path of an opt-in we enable in test_config()
/// (e.g. `webhooks.allow_private_targets`).
pub async fn build_with(f: impl FnOnce(&mut Config)) -> (Router, AppState) {
    let mut config = test_config();
    f(&mut config);
    let pool = simple_analytics::db::in_memory_for_tests().await.unwrap();
    simple_analytics::build_app_with_pool(Arc::new(config), pool)
        .await
        .unwrap()
}

pub async fn send(router: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.unwrap();
    decode(resp).await
}

pub async fn decode(resp: Response<Body>) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1_000_000).await.unwrap();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, value)
}

pub async fn decode_bytes(resp: Response<Body>) -> (StatusCode, Vec<u8>) {
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 10_000_000).await.unwrap();
    (status, bytes.to_vec())
}

pub fn collect_body(url: &str, user_agent: &str, ip: &str) -> Value {
    serde_json::json!({
        "type": "pageview",
        "url": url,
        "title": "Test Page",
        "referer": null,
        "segments": [],
        "user_agent": user_agent,
        "ip": ip,
    })
}

pub fn collect_req(body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/collect")
        .header("content-type", "application/json")
        .header("x-write-key", WRITE_KEY)
        .body(Body::from(body.to_string()))
        .unwrap()
}

pub fn beacon_req(body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(BROWSER_PATH)
        .header("content-type", "application/json")
        .header(BROWSER_TOKEN_HEADER, SITE_TOKEN)
        .header("origin", "https://example.com")
        .header("user-agent", "Mozilla/5.0 (X11; Linux) Firefox/123.0")
        .body(Body::from(body.to_string()))
        .unwrap()
}

pub fn get_req(uri: &str, read_key: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-read-key", read_key)
        .body(Body::empty())
        .unwrap()
}

/// Helper: produces the `(user, user_sig)` pair a real caller's backend would
/// compute and pass to the browser. Stamps `iat = now` into the object if the
/// caller didn't supply one so tokens produced here pass the freshness check
/// that verify() enforces.
pub fn sign_user(mut obj: Value) -> (String, String) {
    if let Some(map) = obj.as_object_mut()
        && !map.contains_key("iat")
    {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        map.insert("iat".into(), serde_json::Value::Number(now.into()));
    }
    let body = serde_json::to_string(&obj).unwrap();
    let sig = simple_analytics::user_token::sign(USER_SIGNING_SECRET, body.as_bytes());
    (body, sig)
}

pub fn admin_req(method: &str, uri: &str, body: Option<Value>) -> Request<Body> {
    let b = match &body {
        Some(v) => Body::from(v.to_string()),
        None => Body::empty(),
    };
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-admin-key", ADMIN_KEY);
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    builder.body(b).unwrap()
}
