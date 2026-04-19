use super::common::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;

#[tokio::test]
async fn webhooks_create_requires_admin_key() {
    let (router, _) = build().await;

    let req = Request::builder()
        .method("POST")
        .uri("/webhooks")
        .header("content-type", "application/json")
        .header("x-admin-key", "wrong")
        .body(Body::from(
            json!({ "url": "https://example.com/hook" }).to_string(),
        ))
        .unwrap();

    let (status, _) = send(&router, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn read_endpoints_reject_write_key() {
    let (router, _) = build().await;

    let req = Request::builder()
        .method("GET")
        .uri("/events")
        .header("x-write-key", WRITE_KEY)
        .body(Body::empty())
        .unwrap();

    let (status, _) = send(&router, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
