pub mod parse;
pub mod validator;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use serde::Deserialize;
use serde_json::Value;
use time::OffsetDateTime;

use crate::auth::{BeaconAuth, WriteAuth};
use crate::config::EndpointsConfig;
use crate::error::{AppError, AppResult};
use crate::model::{EventType, IncomingEvent};
use crate::state::AppState;
use crate::user_token::{self, UserTokenError};
use crate::visitor::visitor_hash;

pub fn routes(endpoints: &EndpointsConfig) -> axum::Router<AppState> {
    axum::Router::new()
        .route("/collect", post(collect_handler))
        .route(&endpoints.browser_collect_path, post(beacon_handler))
}

#[derive(Debug, Deserialize)]
pub struct CollectPayload {
    #[serde(flatten)]
    pub event: IncomingEvent,
    pub user_agent: String,
    pub ip: String,
}

async fn collect_handler(
    State(state): State<AppState>,
    _auth: WriteAuth,
    Json(body): Json<CollectPayload>,
) -> AppResult<impl IntoResponse> {
    // Rate-limit enforcement moved into `WriteAuth::from_request_parts`
    // so a rate-limited valid key returns the same status as a bad key —
    // no key-validity oracle.
    let id = match insert_event(&state, body.event, &body.user_agent, &body.ip).await {
        Ok(id) => id,
        Err(err) => {
            crate::metrics::bump(&state.metrics.events_rejected);
            return Err(err);
        }
    };
    crate::metrics::bump(&state.metrics.events_ingested_server);
    // `notify_one` stores a permit if no worker is currently awaiting —
    // `notify_waiters` discards the wakeup when the delivery worker is
    // mid-`deliver_batch`, so bursts during a delivery pass were lost.
    state.delivery_notify.notify_one();
    Ok((StatusCode::ACCEPTED, Json(serde_json::json!({ "id": id }))))
}

async fn beacon_handler(
    State(state): State<AppState>,
    auth: BeaconAuth,
    headers: axum::http::HeaderMap,
    Json(event): Json<IncomingEvent>,
) -> AppResult<impl IntoResponse> {
    // Per-IP and per-site-token rate limits are enforced inside `BeaconAuth`
    // (per-IP first, then the global bucket) so a single attacker IP cannot
    // drain the global site_token bucket and lock out real browsers.
    let ua = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if ua.is_empty() {
        crate::metrics::bump(&state.metrics.events_rejected);
        return Err(AppError::BadRequest("missing user-agent".into()));
    }

    if let Err(err) = insert_event(&state, event, &ua, &auth.client_ip).await {
        crate::metrics::bump(&state.metrics.events_rejected);
        return Err(err);
    }
    crate::metrics::bump(&state.metrics.events_ingested_beacon);
    state.delivery_notify.notify_one();
    // No body: returning the autoincrement row id would let any caller
    // subtract two responses to estimate global event volume. The beacon is
    // fire-and-forget — the browser doesn't need an id.
    Ok(StatusCode::ACCEPTED)
}

/// Upper bound on `extra` JSON bytes. Keeps a single event from monopolizing
/// parser allocation even when the overall 64 KB body limit has room.
const MAX_EXTRA_BYTES: usize = 8 * 1024;
/// Maximum nesting depth inside `extra`. serde_json's default recursion limit
/// (128) already protects the parser from stack overflow, but we want an
/// explicit much-smaller cap so analytics storage isn't a dumping ground for
/// deeply-nested structures nothing downstream can consume.
const MAX_EXTRA_DEPTH: usize = 8;
/// Upper bound on the signed `user` JSON bytes. 4 KB fits any reasonable user
/// object (id + plan + a few attributes); anything larger is almost certainly
/// abuse.
const MAX_USER_BYTES: usize = 4 * 1024;
/// Upper bound on segments array length.
const MAX_SEGMENTS: usize = 32;
/// Per-string caps. Prevents a single event from monopolizing disk/WAL via a
/// giant field value, and bounds the index size for columns we index.
const MAX_URL_BYTES: usize = 4 * 1024;
const MAX_USER_AGENT_BYTES: usize = 2 * 1024;
const MAX_TITLE_BYTES: usize = 1024;
const MAX_REFERER_BYTES: usize = 2 * 1024;
const MAX_NAME_BYTES: usize = 256;
const MAX_UTM_BYTES: usize = 256;
const MAX_SEGMENT_BYTES: usize = 128;
/// Caller-supplied `SearchPayload.results` caps. `results` is stored inside
/// `extra` but arrives as a structured array — without these, an attacker
/// with a write key could fill the 64 KB body with thousands of short strings
/// that all slip past the `extra` byte cap after JSON encoding.
const MAX_SEARCH_RESULTS: usize = 50;
const MAX_SEARCH_RESULT_BYTES: usize = 256;

async fn insert_event(
    state: &AppState,
    event: IncomingEvent,
    user_agent: &str,
    ip: &str,
) -> AppResult<i64> {
    // `ip` lands in `visitor_hash = blake3(salt, ip, ua)`. Reject non-IP
    // strings so a write-key holder can't feed arbitrary bytes into the
    // hash input to target a specific visitor's hash (which would let them
    // call `DELETE /events?visitor_hash=<forged>` to erase that visitor's
    // history, or inject events under another visitor's identity). Canonical
    // form also keeps `::ffff:1.2.3.4` and `1.2.3.4` from splitting into two
    // visitor_hashes for the same real client.
    let ip_canonical = match ip.trim().parse::<std::net::IpAddr>() {
        Ok(parsed) => parsed.to_canonical().to_string(),
        Err(_) => return Err(AppError::BadRequest("ip must be a valid address".into())),
    };

    // Parse the URL once up front and reuse it for length-capping and for
    // the INSERT. The previous shape re-parsed the URL five times in
    // `enforce_field_caps` plus once more here.
    let utm = parse::parse_utm(&event.url);
    enforce_field_caps(&event, user_agent, &utm)?;
    validate_segments(state, &event.segments)?;

    match state.validator.validate(&event.url).await {
        validator::ValidationOutcome::Invalid => return Err(AppError::InvalidUrl),
        validator::ValidationOutcome::Valid | validator::ValidationOutcome::Skipped => {}
    }

    let device = parse::parse_user_agent(user_agent);
    let source = parse::classify_source(&utm, event.referer.as_deref());
    let salt = state.salts.current().await?;
    let v_hash = visitor_hash(&salt, &ip_canonical, user_agent);
    let country = state.geoip.country_code(&ip_canonical);
    let (user_id, user_json) = verify_user(state, &event)?;
    let ts = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let ts_i64 = i64::try_from(ts).unwrap_or(i64::MAX);
    let session_id = state.session_assigner.assign(&v_hash, ts_i64).await?;

    let segments_json = if event.segments.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&event.segments)?)
    };

    let extra_json = build_extra(&event)?;

    let id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO events (
            ts, event_type, event_name, url, page_title, user_agent,
            device_type, device_os, device_browser, referer, source,
            utm_source, utm_medium, utm_campaign, utm_term, utm_content,
            visitor_hash, segments, extra, user_id, country, user, session_id
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        RETURNING id",
    )
    .bind(ts_i64)
    .bind(event.event_type.as_str())
    .bind(event.name.as_deref())
    .bind(&event.url)
    .bind(event.title.as_deref())
    .bind(user_agent)
    .bind(device.device_type)
    .bind(device.os)
    .bind(device.browser)
    .bind(event.referer.as_deref())
    .bind(source.as_deref())
    .bind(utm.source.as_deref())
    .bind(utm.medium.as_deref())
    .bind(utm.campaign.as_deref())
    .bind(utm.term.as_deref())
    .bind(utm.content.as_deref())
    .bind(&v_hash)
    .bind(segments_json.as_deref())
    .bind(extra_json.as_deref())
    .bind(user_id.as_deref())
    .bind(country.as_deref())
    .bind(user_json.as_deref())
    .bind(&session_id)
    .fetch_one(&state.pool)
    .await?;

    Ok(id)
}

/// Returns `(user_id, user_json)` after validating the signed payload. Both
/// are `None` when the caller didn't supply a `user` blob. Invalid/unsigned
/// blobs short-circuit the request — we never silently drop attribution.
fn verify_user(
    state: &AppState,
    event: &IncomingEvent,
) -> AppResult<(Option<String>, Option<String>)> {
    let Some(user_json) = event.user.as_deref() else {
        return Ok((None, None));
    };

    // Every failure path maps to the SAME response — we never tell a caller
    // whether their problem was a bad signature, missing secret, bad JSON, or
    // missing id. Otherwise an attacker could probe whether attribution is
    // configured at all on this deployment.
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let result = if state.config.user_attribution_enabled() {
        user_token::verify(
            &state.config.auth.user_signing_secret,
            user_json,
            event.user_sig.as_deref(),
            now,
            state.config.auth.user_token_max_age_secs,
        )
    } else {
        Err(UserTokenError::NotConfigured)
    };
    match result {
        Ok(id) => Ok((Some(id), Some(user_json.to_string()))),
        Err(_) => {
            // Uniform log line. The `UserTokenError` Display variants each
            // reveal a distinct deployment-shape fact (e.g. "attribution is
            // not configured"), so we deliberately drop the error here —
            // log pipelines that ship to shared indexers would otherwise
            // leak topology through the error classifier.
            tracing::debug!("user attribution rejected");
            Err(AppError::Unauthorized)
        }
    }
}

/// Enforce per-field length caps. Every caller-supplied string flows through
/// here so a single oversized field can't bloat the DB or the WAL even when
/// the overall 64 KB body limit has room. Expects the UTM params already
/// parsed (see `insert_event`) so we don't re-parse the URL for each key.
fn enforce_field_caps(
    event: &IncomingEvent,
    user_agent: &str,
    utm: &parse::UtmParams,
) -> AppResult<()> {
    fn cap(field: &str, value: &str, max: usize) -> AppResult<()> {
        if value.len() > max {
            return Err(AppError::BadRequest(format!("{field} is too long")));
        }
        Ok(())
    }

    if event.url.is_empty() {
        return Err(AppError::BadRequest("url is required".into()));
    }
    cap("url", &event.url, MAX_URL_BYTES)?;
    cap("user_agent", user_agent, MAX_USER_AGENT_BYTES)?;

    if let Some(t) = &event.title {
        cap("title", t, MAX_TITLE_BYTES)?;
    }
    if let Some(r) = &event.referer {
        cap("referer", r, MAX_REFERER_BYTES)?;
    }
    if let Some(n) = &event.name {
        cap("name", n, MAX_NAME_BYTES)?;
    }

    if event.segments.len() > MAX_SEGMENTS {
        return Err(AppError::BadRequest("too many segments".into()));
    }
    for s in &event.segments {
        cap("segment", s, MAX_SEGMENT_BYTES)?;
    }

    if let Some(user) = event.user.as_deref() {
        cap("user", user, MAX_USER_BYTES)?;
    }
    if let Some(extra) = &event.extra {
        // Fail-closed: a serialization failure must reject the event, not
        // silently pass a 0-byte check. `serde_json::to_string` of a Value
        // shouldn't fail in practice, but the previous `unwrap_or(0)` made
        // this a latent bypass.
        let sz = serde_json::to_string(extra)
            .map_err(|_| AppError::BadRequest("extra is not serializable".into()))?
            .len();
        if sz > MAX_EXTRA_BYTES {
            return Err(AppError::BadRequest("extra is too long".into()));
        }
        if json_depth(extra) > MAX_EXTRA_DEPTH {
            return Err(AppError::BadRequest("extra is too deeply nested".into()));
        }
    }

    if let Some(search) = &event.search {
        if search.query.len() > MAX_UTM_BYTES {
            return Err(AppError::BadRequest("search.query is too long".into()));
        }
        if let Some(click) = &search.clicked_result {
            cap("search.clicked_result", click, MAX_SEARCH_RESULT_BYTES)?;
        }
        if let Some(results) = &search.results {
            if results.len() > MAX_SEARCH_RESULTS {
                return Err(AppError::BadRequest(
                    "search.results has too many entries".into(),
                ));
            }
            for r in results {
                cap("search.results entry", r, MAX_SEARCH_RESULT_BYTES)?;
            }
        }
    }

    // UTM columns are narrow because they feed source classification + indexes.
    // Bounded transitively by the url cap, but we keep an explicit check so the
    // limit is documented at the struct boundary.
    for (field, value) in [
        ("utm_source", utm.source.as_deref()),
        ("utm_medium", utm.medium.as_deref()),
        ("utm_campaign", utm.campaign.as_deref()),
        ("utm_term", utm.term.as_deref()),
        ("utm_content", utm.content.as_deref()),
    ] {
        if let Some(v) = value {
            cap(field, v, MAX_UTM_BYTES)?;
        }
    }

    Ok(())
}

/// Iterative depth measurement for a `serde_json::Value`. Recursing would
/// match serde_json's own parse-time recursion and stack-overflow on adversarial
/// input; this walks the tree with an explicit stack so the measurement itself
/// is safe even if something upstream ever raises the 128-level parser limit.
fn json_depth(v: &Value) -> usize {
    let mut stack: Vec<(&Value, usize)> = vec![(v, 1)];
    let mut max = 1usize;
    while let Some((node, depth)) = stack.pop() {
        if depth > max {
            max = depth;
        }
        match node {
            Value::Array(items) => {
                for item in items {
                    stack.push((item, depth + 1));
                }
            }
            Value::Object(map) => {
                for (_, item) in map {
                    stack.push((item, depth + 1));
                }
            }
            _ => {}
        }
    }
    max
}

fn validate_segments(state: &AppState, segments: &[String]) -> AppResult<()> {
    // Reload-aware: the allowlist can grow via SIGHUP without restart.
    let snap = state.reloadable.load();
    if snap.allowed_segments.is_empty() || snap.allow_unknown_segments {
        return Ok(());
    }
    for s in segments {
        if !snap.allowed_segments.contains(s) {
            return Err(AppError::InvalidSegment);
        }
    }
    Ok(())
}

fn build_extra(event: &IncomingEvent) -> AppResult<Option<String>> {
    let mut obj = serde_json::Map::new();

    if let Some(search) = &event.search {
        if event.event_type != EventType::Search {
            return Err(AppError::BadRequest(
                "search payload requires type=\"search\"".into(),
            ));
        }
        let mut s = serde_json::Map::new();
        s.insert("query".into(), Value::String(search.query.clone()));
        if let Some(rc) = search.result_count {
            s.insert("result_count".into(), Value::from(rc));
        }
        if let Some(results) = &search.results {
            s.insert("results".into(), serde_json::to_value(results)?);
        }
        if let Some(click) = &search.clicked_result {
            s.insert("clicked_result".into(), Value::String(click.clone()));
        }
        obj.insert("search".into(), Value::Object(s));
    }

    if let Some(extra) = &event.extra {
        obj.insert("extra".into(), extra.clone());
    }

    if obj.is_empty() {
        Ok(None)
    } else {
        Ok(Some(serde_json::to_string(&Value::Object(obj))?))
    }
}
