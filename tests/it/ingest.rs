use super::common::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;

#[tokio::test]
async fn collect_accepts_valid_pageview() {
    let (router, _state) = build().await;

    let body = collect_body("https://example.com/home", "Mozilla/5.0", "1.2.3.4");
    let (status, value) = send(&router, collect_req(body)).await;

    assert_eq!(status, StatusCode::ACCEPTED);
    assert!(value.get("id").is_some());
}

#[tokio::test]
async fn collect_requires_write_key() {
    let (router, _) = build().await;

    let req = Request::builder()
        .method("POST")
        .uri("/collect")
        .header("content-type", "application/json")
        .body(Body::from(
            collect_body("https://example.com/", "Mozilla", "1.1.1.1").to_string(),
        ))
        .unwrap();

    let (status, _) = send(&router, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn collect_rejects_invalid_write_key() {
    let (router, _) = build().await;

    let req = Request::builder()
        .method("POST")
        .uri("/collect")
        .header("content-type", "application/json")
        .header("x-write-key", "wrong-key")
        .body(Body::from(
            collect_body("https://example.com/", "Mozilla", "1.1.1.1").to_string(),
        ))
        .unwrap();

    let (status, _) = send(&router, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn collect_rejects_unknown_segment() {
    let (router, _) = build().await;

    let mut body = collect_body("https://example.com/", "Mozilla", "1.1.1.1");
    body["segments"] = json!(["paid", "ghost-segment"]);

    let (status, value) = send(&router, collect_req(body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        value["error"]["code"],
        json!("invalid_segment"),
        "body = {value}"
    );
}

#[tokio::test]
async fn collect_accepts_known_segments() {
    let (router, _) = build().await;

    let mut body = collect_body("https://example.com/", "Mozilla", "1.1.1.1");
    body["segments"] = json!(["paid", "anonymous"]);

    let (status, _) = send(&router, collect_req(body)).await;
    assert_eq!(status, StatusCode::ACCEPTED);
}

#[tokio::test]
async fn collect_parses_utm_and_source() {
    let (router, state) = build().await;

    let body = json!({
        "type": "pageview",
        "url": "https://example.com/?utm_source=newsletter&utm_medium=email",
        "referer": "https://twitter.com/somepost",
        "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) Safari/604.1",
        "ip": "2.2.2.2",
        "segments": [],
    });
    let (status, _) = send(&router, collect_req(body)).await;
    assert_eq!(status, StatusCode::ACCEPTED);

    let row: (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT utm_source, utm_medium, source, device_type FROM events ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&state.pool)
    .await
    .unwrap();

    assert_eq!(row.0.as_deref(), Some("newsletter"));
    assert_eq!(row.1.as_deref(), Some("email"));
    // utm_source wins over referer classification
    assert_eq!(row.2.as_deref(), Some("newsletter"));
    assert_eq!(row.3.as_deref(), Some("mobile"));
}

#[tokio::test]
async fn search_event_stores_query_and_results() {
    let (router, state) = build().await;

    let body = json!({
        "type": "search",
        "url": "https://example.com/search?q=rust",
        "user_agent": "Mozilla",
        "ip": "3.3.3.3",
        "segments": [],
        "search": {
            "query": "rust",
            "result_count": 42,
            "results": ["r1", "r2", "r3"],
            "clicked_result": "r1",
        },
    });
    let (status, _) = send(&router, collect_req(body)).await;
    assert_eq!(status, StatusCode::ACCEPTED);

    let extra: String = sqlx::query_scalar("SELECT extra FROM events ORDER BY id DESC LIMIT 1")
        .fetch_one(&state.pool)
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&extra).unwrap();
    assert_eq!(parsed["search"]["query"], json!("rust"));
    assert_eq!(parsed["search"]["result_count"], json!(42));
    assert_eq!(parsed["search"]["clicked_result"], json!("r1"));
}

#[tokio::test]
async fn beacon_requires_site_token() {
    let (router, _) = build().await;

    let req = Request::builder()
        .method("POST")
        .uri(BROWSER_PATH)
        .header("content-type", "application/json")
        .header("origin", "https://example.com")
        .body(Body::from(
            json!({ "type": "pageview", "url": "https://example.com/" }).to_string(),
        ))
        .unwrap();

    let (status, _) = send(&router, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn beacon_rejects_wrong_origin() {
    let (router, _) = build().await;

    let req = Request::builder()
        .method("POST")
        .uri(BROWSER_PATH)
        .header("content-type", "application/json")
        .header(BROWSER_TOKEN_HEADER, SITE_TOKEN)
        .header("origin", "https://evil.example")
        .header("user-agent", "Mozilla/5.0")
        .body(Body::from(
            json!({ "type": "pageview", "url": "https://example.com/" }).to_string(),
        ))
        .unwrap();

    let (status, value) = send(&router, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(value["error"]["code"], json!("forbidden"));
}

#[tokio::test]
async fn beacon_accepts_valid_request() {
    let (router, state) = build().await;

    let body = json!({
        "type": "pageview",
        "url": "https://example.com/about",
        "title": "About",
        "referer": "https://google.com/",
        "segments": ["paid"],
    });
    let (status, _) = send(&router, beacon_req(body)).await;
    assert_eq!(status, StatusCode::ACCEPTED);

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
        .fetch_one(&state.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn snippet_is_served_and_templated() {
    let (router, _) = build().await;

    let req = Request::builder()
        .method("GET")
        .uri(BROWSER_SCRIPT_PATH)
        .body(Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(router.clone(), req)
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.starts_with("application/javascript"));

    let (_, bytes) = decode_bytes(resp).await;
    let body = String::from_utf8(bytes).unwrap();
    // Placeholders must be resolved and the configured endpoint + header
    // must land in the snippet so the browser copy actually works.
    assert!(!body.contains("__ENDPOINT__"));
    assert!(body.contains("\"/e\""));
    assert!(body.contains("\"x-id\""));
}

#[tokio::test]
async fn signed_user_is_stored_and_decoded() {
    let (router, state) = build().await;

    let (user, user_sig) = sign_user(json!({"id":"user-42","plan":"pro"}));
    let mut body = collect_body("https://example.com/", "Mozilla", "1.1.1.1");
    body["user"] = json!(user);
    body["user_sig"] = json!(user_sig);
    let (status, _) = send(&router, collect_req(body)).await;
    assert_eq!(status, StatusCode::ACCEPTED);

    let (user_id, user_json): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT user_id, user FROM events ORDER BY id DESC LIMIT 1")
            .fetch_one(&state.pool)
            .await
            .unwrap();
    assert_eq!(user_id.as_deref(), Some("user-42"));
    let parsed: serde_json::Value = serde_json::from_str(user_json.as_deref().unwrap()).unwrap();
    assert_eq!(parsed["plan"], json!("pro"));
}

#[tokio::test]
async fn unsigned_user_is_rejected() {
    let (router, _) = build().await;

    let mut body = collect_body("https://example.com/", "Mozilla", "1.1.1.1");
    body["user"] = json!(r#"{"id":"attacker"}"#);
    // no user_sig — all attribution failures return the same 401 to avoid
    // leaking whether the secret is configured.
    let (status, _) = send(&router, collect_req(body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn oversized_user_agent_is_rejected() {
    let (router, _) = build().await;
    let big_ua = "U".repeat(3000);
    let body = serde_json::json!({
        "type": "pageview",
        "url": "https://example.com/",
        "user_agent": big_ua,
        "ip": "1.1.1.1",
        "segments": [],
    });
    let (status, _) = send(&router, collect_req(body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn oversized_page_title_is_rejected() {
    let (router, _) = build().await;
    let big_title = "T".repeat(2000);
    let body = serde_json::json!({
        "type": "pageview",
        "url": "https://example.com/",
        "title": big_title,
        "user_agent": "Mozilla",
        "ip": "1.1.1.1",
        "segments": [],
    });
    let (status, _) = send(&router, collect_req(body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn oversized_segment_string_is_rejected() {
    let (router, _) = build().await;
    let big = "s".repeat(200);
    let mut body = collect_body("https://example.com/", "Mozilla", "1.1.1.1");
    body["segments"] = json!([big]);
    let (status, _) = send(&router, collect_req(body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn collect_origin_normalizes_case_and_trailing_slash() {
    // Token accepted; origin comes in with different case + trailing slash.
    let (router, _) = build().await;
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(BROWSER_PATH)
        .header("content-type", "application/json")
        .header(BROWSER_TOKEN_HEADER, SITE_TOKEN)
        // allowed_origins is "https://example.com" — send "https://EXAMPLE.com/"
        .header("origin", "https://EXAMPLE.com/")
        .header("user-agent", "Mozilla/5.0 (X11; Linux) Firefox/123.0")
        .body(axum::body::Body::from(
            json!({ "type": "pageview", "url": "https://example.com/" }).to_string(),
        ))
        .unwrap();
    let (status, _) = send(&router, req).await;
    assert_eq!(status, StatusCode::ACCEPTED);
}

#[tokio::test]
async fn collect_is_rate_limited_per_write_key() {
    // Tight per-write-key bucket: 3 burst, 60/min refill. Fourth request 429s.
    let (router, _) = build_with(|c| {
        c.ingest.server_rate_limit_per_min = 60;
        c.ingest.server_rate_limit_burst = 3;
    })
    .await;

    for _ in 0..3 {
        let body = collect_body("https://example.com/", "Mozilla", "1.1.1.1");
        let (status, _) = send(&router, collect_req(body)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }
    let body = collect_body("https://example.com/", "Mozilla", "1.1.1.1");
    let (status, _) = send(&router, collect_req(body)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn auth_ip_limiter_returns_429_regardless_of_key_validity() {
    // The pre-auth IP limiter fires BEFORE the key check. An attacker can
    // no longer probe key validity via 401-vs-429: once the IP bucket is
    // drained, both paths observe 429, even for a valid key.
    let (router, _) = build_with(|c| {
        c.ingest.auth_ip_rate_limit_per_min = 60;
        c.ingest.auth_ip_rate_limit_burst = 2;
    })
    .await;

    // Drain the bucket with requests that would otherwise 401 (bad key).
    for _ in 0..2 {
        let req = Request::builder()
            .method("GET")
            .uri("/events?limit=1")
            .header("x-read-key", "definitely-not-a-real-key")
            .body(Body::empty())
            .unwrap();
        let (status, _) = send(&router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // Bucket drained — a VALID key now sees 429, same as an invalid one.
    let (status_valid, _) = send(&router, get_req("/events?limit=1", READ_KEY)).await;
    assert_eq!(status_valid, StatusCode::TOO_MANY_REQUESTS);
    let req = Request::builder()
        .method("GET")
        .uri("/events?limit=1")
        .header("x-read-key", "also-not-real")
        .body(Body::empty())
        .unwrap();
    let (status_invalid, _) = send(&router, req).await;
    assert_eq!(status_invalid, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn reads_are_rate_limited_per_read_key() {
    // A leaked read key shouldn't be able to drain the event table in a
    // tight loop. Tight bucket (3 burst, 60/min) to keep the test fast.
    let (router, _) = build_with(|c| {
        c.ingest.read_rate_limit_per_min = 60;
        c.ingest.read_rate_limit_burst = 3;
    })
    .await;

    for _ in 0..3 {
        let (status, _) = send(&router, get_req("/events?limit=1", READ_KEY)).await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, _) = send(&router, get_req("/events?limit=1", READ_KEY)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn visitor_hash_is_omitted_unless_privacy_flag_set() {
    // Defaults (expose_visitor_hash=false, set via build_with override) hide
    // the hash. Our test_config() flips it on for other tests; this one
    // intentionally reverses it to cover the default-deny path.
    let (router, _) = build_with(|c| {
        c.privacy.expose_visitor_hash = false;
    })
    .await;

    let body = collect_body("https://example.com/hidden", "Mozilla", "1.1.1.1");
    send(&router, collect_req(body)).await;

    let (status, value) = send(&router, get_req("/events?limit=10", READ_KEY)).await;
    assert_eq!(status, StatusCode::OK);
    for ev in value["events"].as_array().unwrap() {
        assert!(
            ev.get("visitor_hash").is_none(),
            "visitor_hash must be absent when flag is off: {ev}"
        );
    }
}

#[tokio::test]
async fn user_payload_is_omitted_from_events_unless_privacy_flag_set() {
    // Critical-1 regression: `/events` used to always emit the full signed
    // `user` JSON regardless of expose_user_payload. A read-key holder would
    // get the full PII blob (email / plan / whatever the operator embedded).
    // Default is false (production default), so flip the test config off
    // here and assert the field is stripped.
    let (router, _) = build_with(|c| {
        c.privacy.expose_user_payload = false;
    })
    .await;

    let (user_body, user_sig) = sign_user(serde_json::json!({
        "id": "user-1",
        "email": "leak@example.com",
        "plan": "enterprise",
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

    let (status, value) = send(&router, get_req("/events?limit=10", READ_KEY)).await;
    assert_eq!(status, StatusCode::OK);
    let events = value["events"].as_array().unwrap();
    assert!(!events.is_empty());
    for ev in events {
        assert_eq!(
            ev["user_id"], "user-1",
            "user_id should always be present for attribution"
        );
        assert!(
            ev.get("user").is_none(),
            "user blob must be absent when expose_user_payload = false: {ev}"
        );
    }
    let raw = serde_json::to_string(&value).unwrap();
    assert!(
        !raw.contains("leak@example.com"),
        "PII email leaked into /events response"
    );
}

#[tokio::test]
async fn unmapped_route_returns_json_404() {
    // Without the fallback, axum returned an empty body — an attacker probing
    // /webhooks (401) vs /no-such-route (empty 404) could enumerate the API.
    // Now both are JSON with the same AppError shape; distinguishing them
    // requires parsing, not header-level sniffing.
    let (router, _) = build().await;
    let req = Request::builder()
        .method("GET")
        .uri("/definitely-not-a-real-route")
        .body(Body::empty())
        .unwrap();
    let (status, value) = send(&router, req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(value["error"]["code"], json!("not_found"));
}

#[tokio::test]
async fn beacon_rejects_origin_null() {
    // Sandboxed iframes, file://, data: URIs and some cross-origin redirects
    // emit `Origin: null`. Never a real trusted origin — reject unconditionally
    // regardless of what's in allowed_origins.
    let (router, _) = build().await;
    let body = serde_json::json!({
        "type": "pageview",
        "url": "https://example.com/",
        "title": null,
        "referer": null,
        "segments": [],
    });
    let req = Request::builder()
        .method("POST")
        .uri(BROWSER_PATH)
        .header("content-type", "application/json")
        .header(BROWSER_TOKEN_HEADER, SITE_TOKEN)
        .header("origin", "null")
        .header("user-agent", "Mozilla/5.0")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, _) = send(&router, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn oversized_user_is_rejected() {
    let (router, _) = build().await;

    let big = "x".repeat(5000);
    let (user, sig) = sign_user(json!({"id": "u", "pad": big}));
    let mut body = collect_body("https://example.com/", "Mozilla", "1.1.1.1");
    body["user"] = json!(user);
    body["user_sig"] = json!(sig);
    let (status, value) = send(&router, collect_req(body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value["error"]["code"], json!("bad_request"));
}

#[tokio::test]
async fn tampered_user_signature_is_rejected() {
    let (router, _) = build().await;

    let (user, _) = sign_user(json!({"id":"user-42"}));
    let mut body = collect_body("https://example.com/", "Mozilla", "1.1.1.1");
    body["user"] = json!(user);
    body["user_sig"] = json!("0".repeat(64));
    let (status, _) = send(&router, collect_req(body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn list_events_filters_by_user_id() {
    let (router, _) = build().await;

    for id in ["alice", "bob"] {
        let (user, user_sig) = sign_user(json!({"id": id}));
        let mut a = collect_body(&format!("https://example.com/{id}"), "Mozilla", "1.1.1.1");
        a["user"] = json!(user);
        a["user_sig"] = json!(user_sig);
        send(&router, collect_req(a)).await;
    }

    let (status, value) = send(&router, get_req("/events?user_id=alice", READ_KEY)).await;
    assert_eq!(status, StatusCode::OK);
    let rows = value["events"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["user_id"], json!("alice"));
}

#[tokio::test]
async fn search_payload_without_search_type_is_rejected() {
    let (router, _) = build().await;

    let body = json!({
        "type": "pageview",
        "url": "https://example.com/",
        "user_agent": "Mozilla",
        "ip": "1.1.1.1",
        "segments": [],
        "search": { "query": "oops" }
    });
    let (status, value) = send(&router, collect_req(body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value["error"]["code"], json!("bad_request"));
}
