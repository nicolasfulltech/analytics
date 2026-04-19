use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use super::common::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::{Json, Router};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

#[tokio::test]
async fn admin_can_create_list_and_delete_webhook() {
    let (router, _) = build().await;

    let create = admin_req(
        "POST",
        "/webhooks",
        Some(serde_json::json!({
            "url": "https://example.com/hook",
            "event_types": ["pageview"],
            "secret": "s3cr3t",
        })),
    );
    let (status, value) = send(&router, create).await;
    assert_eq!(status, StatusCode::CREATED);
    let id = value["id"].as_str().unwrap().to_string();

    // Secret must NEVER appear in any response. `has_secret: true` instead.
    assert!(value.get("secret").is_none());
    assert_eq!(value["has_secret"], serde_json::json!(true));

    let (status, value) = send(&router, admin_req("GET", "/webhooks", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value.as_array().unwrap().len(), 1);
    assert!(value[0].get("secret").is_none());
    assert_eq!(value[0]["has_secret"], serde_json::json!(true));

    let (status, _) = send(
        &router,
        admin_req("DELETE", &format!("/webhooks/{id}"), None),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, value) = send(&router, admin_req("GET", "/webhooks", None)).await;
    assert_eq!(value.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn webhook_rejects_loopback_url() {
    // Strict mode — matches a production deployment where SSRF is fatal.
    let (router, _) = build_with(|c| c.webhooks.allow_private_targets = false).await;
    for url in [
        "http://127.0.0.1/hook",
        "http://localhost/hook",
        "http://169.254.169.254/latest/",
        "http://10.0.0.1/hook",
        "http://192.168.1.1/hook",
        "http://[::1]/hook",
        "file:///etc/passwd",
    ] {
        let req = admin_req(
            "POST",
            "/webhooks",
            Some(serde_json::json!({
                "url": url,
                "event_types": ["*"],
            })),
        );
        let (status, value) = send(&router, req).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "should reject {url}, got {value}"
        );
    }
}

#[tokio::test]
async fn webhook_rejects_non_http_port_on_public_ip() {
    // Port-based SSRF pivot: admin-attacker could aim webhooks at internal
    // plaintext services (redis, postgres, smtp) on any public IP — including
    // the deployment's own public IP. reqwest's `.resolve()` IP pin does NOT
    // cover the port, so the URL's port wins. Strict mode rejects.
    let (router, _) = build_with(|c| c.webhooks.allow_private_targets = false).await;
    for url in [
        "http://1.1.1.1:22/hook",
        "http://1.1.1.1:25/hook",
        "http://1.1.1.1:6379/hook",
        "http://1.1.1.1:5432/hook",
        "https://1.1.1.1:8443/hook",
    ] {
        let req = admin_req(
            "POST",
            "/webhooks",
            Some(serde_json::json!({
                "url": url,
                "event_types": ["*"],
            })),
        );
        let (status, value) = send(&router, req).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "should reject {url}, got {value}"
        );
    }
}

#[tokio::test]
async fn webhook_rejects_oversized_secret() {
    let (router, _) = build().await;
    let req = admin_req(
        "POST",
        "/webhooks",
        Some(serde_json::json!({
            "url": "https://example.com/hook",
            "event_types": ["*"],
            "secret": "x".repeat(1024),
        })),
    );
    let (status, _) = send(&router, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delivery_worker_delivers_to_http_receiver() {
    let (router, state) = build().await;

    let (addr, received) = spawn_test_receiver(2).await;

    // create webhook
    let create = admin_req(
        "POST",
        "/webhooks",
        Some(serde_json::json!({
            "url": format!("http://{}/hook", addr),
            "event_types": ["*"],
            "secret": "s3cr3t"
        })),
    );
    let (status, _) = send(&router, create).await;
    assert_eq!(status, StatusCode::CREATED);

    // collect two events
    for i in 0..2 {
        let body = collect_body(&format!("https://example.com/{i}"), "Mozilla", "1.1.1.1");
        let (status, _) = send(&router, collect_req(body)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    // run delivery a few times until all received
    for _ in 0..20 {
        simple_analytics::webhooks::delivery::run_worker_tick(&state).await;
        if received.load(Ordering::SeqCst) >= 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    assert_eq!(received.load(Ordering::SeqCst), 2);

    // verify deliveries marked delivered
    let delivered: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM webhook_deliveries WHERE status = 'delivered'")
            .fetch_one(&state.pool)
            .await
            .unwrap();
    assert_eq!(delivered, 2);
}

#[tokio::test]
async fn failing_webhook_is_retried_then_gives_up() {
    let (router, state) = build().await;

    let (addr, _) = spawn_failing_receiver().await;

    let create = admin_req(
        "POST",
        "/webhooks",
        Some(serde_json::json!({
            "url": format!("http://{}/hook", addr),
            "event_types": ["*"],
        })),
    );
    send(&router, create).await;

    let body = collect_body("https://example.com/x", "Mozilla", "1.1.1.1");
    send(&router, collect_req(body)).await;

    // force all retries by moving next_attempt into the past between ticks
    for _ in 0..20 {
        simple_analytics::webhooks::delivery::run_worker_tick(&state).await;
        sqlx::query("UPDATE webhook_deliveries SET next_attempt = 0 WHERE status = 'pending'")
            .execute(&state.pool)
            .await
            .unwrap();
    }

    let failed: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM webhook_deliveries WHERE status = 'failed'")
            .fetch_one(&state.pool)
            .await
            .unwrap();
    assert_eq!(failed, 1);
}

async fn spawn_test_receiver(_expected: u32) -> (String, Arc<AtomicU32>) {
    let counter = Arc::new(AtomicU32::new(0));
    let received = Arc::new(Mutex::new(Vec::<Value>::new()));

    let counter_c = counter.clone();
    let received_c = received.clone();

    let app = Router::new().route(
        "/hook",
        axum::routing::post(move |Json(body): Json<Value>| {
            let counter = counter_c.clone();
            let received = received_c.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                received.lock().await.push(body);
                StatusCode::OK
            }
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, counter)
}

#[tokio::test]
async fn enqueue_is_idempotent_under_unique_constraint() {
    // Direct INSERT bypassing the cursor — simulates a crash/replay where the
    // same (webhook, event) would otherwise double-enqueue.
    let (router, state) = build().await;

    let create = admin_req(
        "POST",
        "/webhooks",
        Some(serde_json::json!({
            "url": "https://example.com/hook",
            "event_types": ["*"],
        })),
    );
    let (_, value) = send(&router, create).await;
    let wh_id = value["id"].as_str().unwrap().to_string();

    let body = collect_body("https://example.com/x", "Mozilla", "1.1.1.1");
    send(&router, collect_req(body)).await;

    let event_id: i64 = sqlx::query_scalar("SELECT id FROM events ORDER BY id DESC LIMIT 1")
        .fetch_one(&state.pool)
        .await
        .unwrap();

    for _ in 0..3 {
        sqlx::query(
            "INSERT OR IGNORE INTO webhook_deliveries
               (webhook_id, event_id, status, attempts, next_attempt, created_at)
             VALUES (?, ?, 'pending', 0, 0, 0)",
        )
        .bind(&wh_id)
        .bind(event_id)
        .execute(&state.pool)
        .await
        .unwrap();
    }

    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM webhook_deliveries WHERE webhook_id = ? AND event_id = ?",
    )
    .bind(&wh_id)
    .bind(event_id)
    .fetch_one(&state.pool)
    .await
    .unwrap();
    assert_eq!(rows, 1, "UNIQUE constraint must dedupe");
}

/// `privacy.expose_user_payload = false` (the production default) must
/// strip the full `user` JSON blob from webhook payloads — only `user_id`
/// ever ships to subscribers. Without this test, a refactor that moves or
/// renames the gate in `load_event_json` would silently start leaking PII.
#[tokio::test]
async fn webhook_delivery_strips_user_when_expose_user_payload_false() {
    let (router, state) = build_with(|c| {
        c.privacy.expose_user_payload = false;
    })
    .await;

    let (addr, _) = spawn_test_receiver(1).await;
    let received_bodies = Arc::new(Mutex::new(Vec::<Value>::new()));
    // spawn_test_receiver's counter doesn't return bodies; spin our own.
    let rb = received_bodies.clone();
    let capture_app = Router::new().route(
        "/hook",
        axum::routing::post(move |Json(body): Json<Value>| {
            let rb = rb.clone();
            async move {
                rb.lock().await.push(body);
                StatusCode::OK
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let capture_addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        axum::serve(listener, capture_app).await.unwrap();
    });
    let _ = addr; // unused but keeps the helper alive for parity

    let create = admin_req(
        "POST",
        "/webhooks",
        Some(serde_json::json!({
            "url": format!("http://{}/hook", capture_addr),
            "event_types": ["*"],
        })),
    );
    let (status, _) = send(&router, create).await;
    assert_eq!(status, StatusCode::CREATED);

    // Ingest an event with a signed user payload containing a realistic
    // PII shape.
    let (user_body, user_sig) = sign_user(serde_json::json!({
        "id": "user-42",
        "email": "leak@example.com",
        "plan": "enterprise"
    }));
    let body = serde_json::json!({
        "type": "pageview",
        "url": "https://example.com/",
        "user_agent": "Mozilla",
        "ip": "1.1.1.1",
        "user": user_body,
        "user_sig": user_sig,
    });
    let (status, _) = send(&router, collect_req(body)).await;
    assert_eq!(status, StatusCode::ACCEPTED);

    // Drive delivery.
    for _ in 0..20 {
        simple_analytics::webhooks::delivery::run_worker_tick(&state).await;
        if !received_bodies.lock().await.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let bodies = received_bodies.lock().await;
    assert_eq!(bodies.len(), 1, "expected exactly one delivery");
    let delivered = &bodies[0];
    assert_eq!(
        delivered["user_id"], "user-42",
        "user_id should always be present"
    );
    assert!(
        delivered.get("user").is_none(),
        "user blob must be absent when expose_user_payload = false, got {delivered}"
    );
    let raw = serde_json::to_string(delivered).unwrap();
    assert!(
        !raw.contains("leak@example.com"),
        "PII email leaked into delivered payload: {raw}"
    );
    assert!(
        !raw.contains("enterprise"),
        "PII plan leaked into delivered payload: {raw}"
    );
}

async fn spawn_failing_receiver() -> (String, ()) {
    let app = Router::new().route(
        "/hook",
        axum::routing::post(|_req: Request<Body>| async { StatusCode::INTERNAL_SERVER_ERROR }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, ())
}
