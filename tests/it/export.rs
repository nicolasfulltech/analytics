use super::common::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

async fn seed(router: &axum::Router, n: usize) {
    for i in 0..n {
        let body = collect_body(&format!("https://example.com/{i}"), "Mozilla", "1.1.1.1");
        let (status, _) = send(router, collect_req(body)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }
}

#[tokio::test]
async fn ndjson_export_contains_one_row_per_line() {
    let (router, _) = build().await;
    seed(&router, 3).await;

    let req = Request::builder()
        .method("GET")
        .uri("/export?format=ndjson")
        .header("x-read-key", READ_KEY)
        .body(Body::empty())
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("ndjson"));

    let (_, bytes) = decode_bytes(resp).await;
    let text = String::from_utf8(bytes).unwrap();
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 3);
    for line in lines {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(v.get("id").is_some());
        assert!(v.get("url").is_some());
    }
}

#[tokio::test]
async fn csv_export_has_header_and_rows() {
    let (router, _) = build().await;
    seed(&router, 2).await;

    let req = Request::builder()
        .method("GET")
        .uri("/export?format=csv")
        .header("x-read-key", READ_KEY)
        .body(Body::empty())
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let (_, bytes) = decode_bytes(resp).await;
    let text = String::from_utf8(bytes).unwrap();
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 3); // header + 2 rows
    assert!(lines[0].starts_with("id,ts,event_type"));
}

#[tokio::test]
async fn export_strips_user_payload_when_flag_off() {
    // Mirror of /events: /export (both csv and ndjson) must honor
    // privacy.expose_user_payload. A read-key holder who can stream the
    // table must not pull PII out of it.
    let (router, _) = build_with(|c| {
        c.privacy.expose_user_payload = false;
    })
    .await;

    let (user_body, user_sig) = sign_user(serde_json::json!({
        "id": "u1",
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
    send(&router, collect_req(body)).await;

    for (format, tag) in [("ndjson", "ndjson"), ("csv", "csv")] {
        let req = Request::builder()
            .method("GET")
            .uri(format!("/export?format={format}"))
            .header("x-read-key", READ_KEY)
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let (_, bytes) = decode_bytes(resp).await;
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            !text.contains("leak@example.com"),
            "{tag} export leaked PII: {text}"
        );
        assert!(
            !text.contains("\"user\":"),
            "{tag} export emitted user field with flag off: {text}"
        );
        if tag == "csv" {
            assert!(
                !text.starts_with("id,") || !text.lines().next().unwrap().contains(",user,"),
                "csv header contains `user` column: {text}"
            );
        }
    }
}

#[tokio::test]
async fn csv_field_with_comma_is_quoted() {
    let (router, _) = build().await;
    let body = serde_json::json!({
        "type": "pageview",
        "url": "https://example.com/path,with,commas",
        "title": "a \"quoted\" title, yes",
        "user_agent": "Mozilla",
        "ip": "1.1.1.1",
        "segments": [],
    });
    send(&router, collect_req(body)).await;

    let req = Request::builder()
        .method("GET")
        .uri("/export?format=csv")
        .header("x-read-key", READ_KEY)
        .body(Body::empty())
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    let (_, bytes) = decode_bytes(resp).await;
    let text = String::from_utf8(bytes).unwrap();
    let lines: Vec<_> = text.lines().collect();
    assert!(lines[1].contains("\"https://example.com/path,with,commas\""));
    assert!(lines[1].contains("\"a \"\"quoted\"\" title, yes\""));
}

#[tokio::test]
async fn csv_fields_starting_with_formula_trigger_are_neutralized() {
    let (router, _) = build().await;
    // page_title is used verbatim in the CSV; a `=` prefix would execute in
    // Excel / LibreOffice if we didn't neutralize it.
    let body = serde_json::json!({
        "type": "pageview",
        "url": "https://example.com/",
        "title": "=HYPERLINK(\"http://evil/\",\"click\")",
        "user_agent": "Mozilla",
        "ip": "1.1.1.1",
        "segments": [],
    });
    send(&router, collect_req(body)).await;

    let req = Request::builder()
        .method("GET")
        .uri("/export?format=csv")
        .header("x-read-key", READ_KEY)
        .body(Body::empty())
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    let (_, bytes) = decode_bytes(resp).await;
    let text = String::from_utf8(bytes).unwrap();
    // Must contain the literal with a leading apostrophe — never a raw `=`
    // at the start of a cell.
    assert!(text.contains("\"'=HYPERLINK"), "CSV was: {text}");
    assert!(
        !text.contains(",=HYPERLINK"),
        "unescaped formula leaked: {text}"
    );
}

#[tokio::test]
async fn export_rejects_unknown_format() {
    let (router, _) = build().await;

    let req = Request::builder()
        .method("GET")
        .uri("/export?format=parquet")
        .header("x-read-key", READ_KEY)
        .body(Body::empty())
        .unwrap();

    let (status, value) = send(&router, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value["error"]["code"], serde_json::json!("bad_request"));
}
