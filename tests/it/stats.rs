use super::common::*;
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn aggregates_refresh_produces_segment_rollups() {
    let (router, state) = build().await;

    let ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3"];
    for ip in ips {
        let mut body = collect_body("https://example.com/", "Mozilla/5.0", ip);
        body["segments"] = json!(["paid"]);
        let (status, _) = send(&router, collect_req(body)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }
    let mut free = collect_body("https://example.com/", "Mozilla/5.0", "10.0.0.1");
    free["segments"] = json!(["free"]);
    let (status, _) = send(&router, collect_req(free)).await;
    assert_eq!(status, StatusCode::ACCEPTED);

    simple_analytics::query::aggregates::refresh(&state.pool)
        .await
        .unwrap();

    let (status, value) = send(&router, get_req("/stats?segment=paid", READ_KEY)).await;
    assert_eq!(status, StatusCode::OK);
    let rows = value.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["count"], json!(3));
    assert_eq!(rows[0]["visitors"], json!(3));
    assert_eq!(rows[0]["segment"], json!("paid"));

    let (_, all_seg) = send(&router, get_req("/stats", READ_KEY)).await;
    let rows = all_seg.as_array().unwrap();
    let all_row = rows
        .iter()
        .find(|r| r["segment"].is_null())
        .expect("expected a segment=all row");
    assert_eq!(all_row["count"], json!(4));
    assert_eq!(all_row["visitors"], json!(3));
}

#[tokio::test]
async fn url_stats_rollup_per_url_per_day() {
    let (router, state) = build().await;

    // 3 hits on /a (2 unique visitors), 1 hit on /b
    for ip in ["1.1.1.1", "1.1.1.1", "2.2.2.2"] {
        let body = collect_body("https://example.com/a", "Mozilla/5.0", ip);
        send(&router, collect_req(body)).await;
    }
    let body = collect_body("https://example.com/b", "Mozilla/5.0", "3.3.3.3");
    send(&router, collect_req(body)).await;

    simple_analytics::query::aggregates::refresh(&state.pool)
        .await
        .unwrap();

    let (status, value) = send(&router, get_req("/stats/urls", READ_KEY)).await;
    assert_eq!(status, StatusCode::OK);
    let rows = value.as_array().unwrap();
    assert_eq!(rows.len(), 2);

    let a = rows
        .iter()
        .find(|r| r["url"] == json!("https://example.com/a"))
        .unwrap();
    assert_eq!(a["count"], json!(3));
    assert_eq!(a["visitors"], json!(2));

    let b = rows
        .iter()
        .find(|r| r["url"] == json!("https://example.com/b"))
        .unwrap();
    assert_eq!(b["count"], json!(1));
}

#[tokio::test]
async fn url_stats_can_filter_by_url() {
    let (router, state) = build().await;

    for path in ["/a", "/b"] {
        let body = collect_body(&format!("https://example.com{path}"), "Mozilla", "1.1.1.1");
        send(&router, collect_req(body)).await;
    }
    simple_analytics::query::aggregates::refresh(&state.pool)
        .await
        .unwrap();

    let (_, value) = send(
        &router,
        get_req("/stats/urls?url=https://example.com/a", READ_KEY),
    )
    .await;
    let rows = value.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["url"], json!("https://example.com/a"));
}

#[tokio::test]
async fn aggregate_refresh_is_idempotent_for_same_events() {
    let (router, state) = build().await;

    for i in 0..3 {
        let body = collect_body(&format!("https://example.com/{i}"), "Mozilla", "1.1.1.1");
        let (status, _) = send(&router, collect_req(body)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    simple_analytics::query::aggregates::refresh(&state.pool)
        .await
        .unwrap();
    simple_analytics::query::aggregates::refresh(&state.pool)
        .await
        .unwrap();

    let (_, value) = send(&router, get_req("/stats", READ_KEY)).await;
    let rows = value.as_array().unwrap();
    let all_row = rows
        .iter()
        .find(|r| r["segment"].is_null())
        .expect("expected segment=all row");
    assert_eq!(all_row["count"], json!(3));
}

#[tokio::test]
async fn page_stats_counts_hits_and_unique_visitors_across_range() {
    let (router, _) = build().await;

    // /a: 3 hits, 2 unique visitors. /b: 1 hit, 1 visitor.
    for ip in ["1.1.1.1", "1.1.1.1", "2.2.2.2"] {
        let body = collect_body("https://example.com/a", "Mozilla", ip);
        send(&router, collect_req(body)).await;
    }
    let body = collect_body("https://example.com/b", "Mozilla", "3.3.3.3");
    send(&router, collect_req(body)).await;

    let (status, value) = send(&router, get_req("/stats/pages", READ_KEY)).await;
    assert_eq!(status, StatusCode::OK);
    let rows = value.as_array().unwrap();
    assert_eq!(rows.len(), 2);

    let a = rows
        .iter()
        .find(|r| r["url"] == json!("https://example.com/a"))
        .unwrap();
    assert_eq!(a["count"], json!(3));
    assert_eq!(a["visitors"], json!(2));
    assert!(a["last_ts"].as_i64().unwrap() > 0);

    // Ordered by count DESC, so /a is first.
    assert_eq!(rows[0]["url"], json!("https://example.com/a"));
}

#[tokio::test]
async fn page_stats_defaults_to_pageview_and_filters_event_type() {
    let (router, _) = build().await;

    send(
        &router,
        collect_req(collect_body("https://example.com/home", "M", "1.1.1.1")),
    )
    .await;

    let search = json!({
        "type": "search",
        "url": "https://example.com/search",
        "user_agent": "Mozilla",
        "ip": "2.2.2.2",
        "segments": [],
        "search": { "query": "x", "result_count": 0 }
    });
    send(&router, collect_req(search)).await;

    // Default (pageview) — only /home.
    let (_, value) = send(&router, get_req("/stats/pages", READ_KEY)).await;
    let rows = value.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["url"], json!("https://example.com/home"));

    // Explicit search — only /search.
    let (_, value) = send(&router, get_req("/stats/pages?event_type=search", READ_KEY)).await;
    let rows = value.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["url"], json!("https://example.com/search"));
}

#[tokio::test]
async fn page_stats_respects_time_range() {
    let (router, state) = build().await;

    send(
        &router,
        collect_req(collect_body("https://example.com/a", "M", "1.1.1.1")),
    )
    .await;
    sqlx::query("UPDATE events SET ts = 1000 WHERE id = 1")
        .execute(&state.pool)
        .await
        .unwrap();

    let (_, out_of_range) =
        send(&router, get_req("/stats/pages?from=5000&to=6000", READ_KEY)).await;
    assert_eq!(out_of_range.as_array().unwrap().len(), 0);

    let (_, in_range) = send(&router, get_req("/stats/pages?from=500&to=2000", READ_KEY)).await;
    assert_eq!(in_range.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn page_stats_requires_read_key() {
    let (router, _) = build().await;
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/stats/pages")
        .body(axum::body::Body::empty())
        .unwrap();
    let (status, _) = send(&router, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn user_pages_returns_pages_visited_by_user() {
    let (router, _) = build().await;

    // Alice visits /a twice and /b once.
    for url in [
        "https://example.com/a",
        "https://example.com/a",
        "https://example.com/b",
    ] {
        let (user, user_sig) = sign_user(json!({"id": "alice"}));
        let mut body = collect_body(url, "Mozilla", "1.1.1.1");
        body["user"] = json!(user);
        body["user_sig"] = json!(user_sig);
        send(&router, collect_req(body)).await;
    }
    // Bob visits /c — must NOT show up for alice.
    let (user, user_sig) = sign_user(json!({"id": "bob"}));
    let mut body = collect_body("https://example.com/c", "Mozilla", "2.2.2.2");
    body["user"] = json!(user);
    body["user_sig"] = json!(user_sig);
    send(&router, collect_req(body)).await;

    let (status, value) = send(
        &router,
        get_req("/stats/user_pages?user_id=alice", READ_KEY),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let rows = value.as_array().unwrap();
    assert_eq!(rows.len(), 2);

    let a = rows
        .iter()
        .find(|r| r["url"] == json!("https://example.com/a"))
        .unwrap();
    assert_eq!(a["count"], json!(2));
    assert!(a["first_ts"].as_i64().unwrap() <= a["last_ts"].as_i64().unwrap());

    // Bob's page is not in the result.
    assert!(
        rows.iter()
            .all(|r| r["url"] != json!("https://example.com/c"))
    );
}

#[tokio::test]
async fn user_pages_requires_user_id() {
    let (router, _) = build().await;
    let (status, _) = send(&router, get_req("/stats/user_pages", READ_KEY)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Empty user_id is also rejected.
    let (status, _) = send(&router, get_req("/stats/user_pages?user_id=", READ_KEY)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn user_pages_requires_read_key() {
    let (router, _) = build().await;
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/stats/user_pages?user_id=alice")
        .body(axum::body::Body::empty())
        .unwrap();
    let (status, _) = send(&router, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
