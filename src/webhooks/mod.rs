pub mod delivery;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, post};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auth::AdminAuth;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

const MAX_WEBHOOK_SECRET_BYTES: usize = 256;

pub fn routes() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/webhooks", post(create_webhook).get(list_webhooks))
        .route("/webhooks/{id}", delete(delete_webhook).get(get_webhook))
}

#[derive(Debug, Deserialize)]
pub struct CreateWebhook {
    pub url: String,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default = "default_event_types")]
    pub event_types: Vec<String>,
}

fn default_event_types() -> Vec<String> {
    vec!["*".into()]
}

/// Row shape as stored; kept internal so the secret never gets returned to a
/// client. All responses use `WebhookResponse` below.
#[derive(Debug, sqlx::FromRow)]
struct Webhook {
    id: String,
    url: String,
    secret: Option<String>,
    event_types: String,
    active: i64,
    created_at: i64,
}

#[derive(Debug, Serialize)]
pub struct WebhookResponse {
    pub id: String,
    pub url: String,
    pub has_secret: bool,
    /// Parsed back into an array — the DB column is a JSON string but
    /// callers shouldn't have to double-decode.
    pub event_types: Vec<String>,
    pub active: bool,
    pub created_at: i64,
}

impl From<Webhook> for WebhookResponse {
    fn from(w: Webhook) -> Self {
        // Treat a corrupt `event_types` column as empty rather than crashing
        // the whole list response — operators can still see the row exists
        // and fix it. Shouldn't happen in practice because we only ever write
        // valid JSON from `serde_json::to_string(&Vec<String>)`.
        let event_types = serde_json::from_str::<Vec<String>>(&w.event_types).unwrap_or_default();
        Self {
            id: w.id,
            url: w.url,
            has_secret: w.secret.is_some(),
            event_types,
            active: w.active != 0,
            created_at: w.created_at,
        }
    }
}

async fn create_webhook(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Json(body): Json<CreateWebhook>,
) -> AppResult<impl IntoResponse> {
    if body.url.is_empty() {
        return Err(AppError::BadRequest("url is required".into()));
    }
    // Cap the subscriber count so a compromised admin key can't register
    // thousands of endpoints and multiply every event into a fan-out storm
    // that fills `max_pending_deliveries`.
    let max_hooks = state.config.webhooks.max_webhooks;
    if max_hooks > 0 {
        let existing: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhooks")
            .fetch_one(&state.pool)
            .await?;
        if existing as u32 >= max_hooks {
            return Err(AppError::BadRequest(format!(
                "webhook count at cap ({max_hooks}); delete an existing subscriber first"
            )));
        }
    }
    // Rejects non-http(s) schemes, unresolvable hosts, loopback/private/
    // link-local / CGNAT / reserved / documentation / multicast targets.
    // Async variant: blocking DNS runs on a dedicated thread pool so we don't
    // stall a runtime worker. Delivery re-checks this too + pins the IP.
    crate::net::validate_webhook_url_async(&body.url, state.config.webhooks.allow_private_targets)
        .await
        .map_err(|e| AppError::BadRequest(format!("url: {e}")))?;

    if let Some(s) = &body.secret
        && s.len() > MAX_WEBHOOK_SECRET_BYTES
    {
        return Err(AppError::BadRequest(format!(
            "secret must be at most {MAX_WEBHOOK_SECRET_BYTES} bytes"
        )));
    }

    let id = Uuid::new_v4().to_string();
    let now = OffsetDateTime::now_utc().unix_timestamp() * 1000;
    let event_types = serde_json::to_string(&body.event_types)?;

    sqlx::query(
        "INSERT INTO webhooks (id, url, secret, event_types, active, created_at)
         VALUES (?,?,?,?,1,?)",
    )
    .bind(&id)
    .bind(&body.url)
    .bind(body.secret.as_deref())
    .bind(&event_types)
    .bind(now)
    .execute(&state.pool)
    .await?;

    let wh: Webhook = sqlx::query_as("SELECT * FROM webhooks WHERE id = ?")
        .bind(&id)
        .fetch_one(&state.pool)
        .await?;

    Ok((StatusCode::CREATED, Json(WebhookResponse::from(wh))))
}

async fn list_webhooks(
    State(state): State<AppState>,
    _auth: AdminAuth,
) -> AppResult<impl IntoResponse> {
    let rows: Vec<Webhook> = sqlx::query_as("SELECT * FROM webhooks ORDER BY created_at DESC")
        .fetch_all(&state.pool)
        .await?;
    let out: Vec<WebhookResponse> = rows.into_iter().map(WebhookResponse::from).collect();
    Ok(Json(out))
}

async fn get_webhook(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
) -> AppResult<impl IntoResponse> {
    let row: Option<Webhook> = sqlx::query_as("SELECT * FROM webhooks WHERE id = ?")
        .bind(&id)
        .fetch_optional(&state.pool)
        .await?;
    row.map(|w| Json(WebhookResponse::from(w)))
        .ok_or(AppError::NotFound)
}

async fn delete_webhook(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path(id): Path<String>,
) -> AppResult<impl IntoResponse> {
    let res = sqlx::query("DELETE FROM webhooks WHERE id = ?")
        .bind(&id)
        .execute(&state.pool)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}
