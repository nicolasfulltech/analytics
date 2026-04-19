use super::common::*;
use axum::http::StatusCode;
use serde_json::json;

async fn seed(router: &axum::Router, events: &[serde_json::Value]) {
    for body in events {
        let (status, _) = send(router, collect_req(body.clone())).await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }
}

#[tokio::test]
async fn list_events_requires_read_key() {
    let (router, _) = build().await;

    let (status, _) = send(
        &router,
        axum::http::Request::builder()
            .method("GET")
            .uri("/events")
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn list_events_returns_seeded_rows() {
    let (router, _) = build().await;

    seed(
        &router,
        &[
            collect_body("https://example.com/a", "Mozilla/5.0", "1.1.1.1"),
            collect_body("https://example.com/b", "Mozilla/5.0", "1.1.1.2"),
        ],
    )
    .await;

    let (status, value) = send(&router, get_req("/events", READ_KEY)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["events"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn filter_by_event_type() {
    let (router, _) = build().await;

    let pv = collect_body("https://example.com/a", "Mozilla", "1.1.1.1");
    let search = json!({
        "type": "search",
        "url": "https://example.com/search?q=x",
        "user_agent": "Mozilla",
        "ip": "2.2.2.2",
        "segments": [],
        "search": { "query": "x", "result_count": 1 }
    });
    seed(&router, &[pv, search]).await;

    let (status, value) = send(&router, get_req("/events?event_type=search", READ_KEY)).await;
    assert_eq!(status, StatusCode::OK);
    let rows = value["events"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["event_type"], json!("search"));
}

#[tokio::test]
async fn filter_by_segment() {
    let (router, _) = build().await;

    let mut a = collect_body("https://example.com/a", "Mozilla", "1.1.1.1");
    a["segments"] = json!(["paid"]);
    let mut b = collect_body("https://example.com/b", "Mozilla", "2.2.2.2");
    b["segments"] = json!(["free"]);
    seed(&router, &[a, b]).await;

    let (status, value) = send(&router, get_req("/events?segment=paid", READ_KEY)).await;
    assert_eq!(status, StatusCode::OK);
    let rows = value["events"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["url"], json!("https://example.com/a"));
}

#[tokio::test]
async fn events_response_parses_segments_as_array_not_string() {
    let (router, _) = build().await;
    let mut body = collect_body("https://example.com/", "Mozilla", "1.1.1.1");
    body["segments"] = json!(["paid"]);
    send(&router, collect_req(body)).await;

    let (_, value) = send(&router, get_req("/events", READ_KEY)).await;
    let first = &value["events"][0];
    // Array, not a JSON-encoded string.
    assert_eq!(first["segments"], json!(["paid"]));
}

#[tokio::test]
async fn filter_by_country() {
    let (router, state) = build().await;

    // Seed directly — GeoIP is disabled in tests so country is always NULL
    // through the ingest path. Write rows explicitly.
    send(
        &router,
        collect_req(collect_body("https://example.com/", "Mozilla", "1.1.1.1")),
    )
    .await;
    send(
        &router,
        collect_req(collect_body("https://example.com/", "Mozilla", "2.2.2.2")),
    )
    .await;
    sqlx::query("UPDATE events SET country = 'FR' WHERE id = 1")
        .execute(&state.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE events SET country = 'US' WHERE id = 2")
        .execute(&state.pool)
        .await
        .unwrap();

    let (_, value) = send(&router, get_req("/events?country=fr", READ_KEY)).await;
    let rows = value["events"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["country"], json!("FR"));
}

#[tokio::test]
async fn pagination_respects_limit_and_offset() {
    let (router, _) = build().await;

    let mut bodies = Vec::new();
    for i in 0..5 {
        bodies.push(collect_body(
            &format!("https://example.com/{i}"),
            "Mozilla",
            "1.1.1.1",
        ));
    }
    seed(&router, &bodies).await;

    let (_, page1) = send(&router, get_req("/events?limit=2", READ_KEY)).await;
    assert_eq!(page1["events"].as_array().unwrap().len(), 2);
    assert_eq!(page1["next_offset"], json!(2));

    let (_, page2) = send(&router, get_req("/events?limit=2&offset=2", READ_KEY)).await;
    assert_eq!(page2["events"].as_array().unwrap().len(), 2);
    assert_eq!(page2["next_offset"], json!(4));
}
