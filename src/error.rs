use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden: {0}")]
    Forbidden(&'static str),

    #[error("not found")]
    NotFound,

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("rate limited")]
    RateLimited,

    #[error("invalid url")]
    InvalidUrl,

    #[error("invalid segment")]
    InvalidSegment,

    #[error("internal error")]
    Internal(#[from] anyhow::Error),

    #[error("database error")]
    Db(#[from] sqlx::Error),

    #[error("serialization error")]
    Serde(#[from] serde_json::Error),
}

pub type AppResult<T> = Result<T, AppError>;

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, "bad_request", m.clone()),
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "missing or invalid credentials".into(),
            ),
            AppError::Forbidden(m) => (StatusCode::FORBIDDEN, "forbidden", (*m).into()),
            AppError::NotFound => (StatusCode::NOT_FOUND, "not_found", "not found".into()),
            AppError::Conflict(m) => (StatusCode::CONFLICT, "conflict", m.clone()),
            AppError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "too many requests".into(),
            ),
            AppError::InvalidUrl => (
                StatusCode::BAD_REQUEST,
                "invalid_url",
                "url rejected by validator".into(),
            ),
            AppError::InvalidSegment => (
                StatusCode::BAD_REQUEST,
                "invalid_segment",
                "segment value is not in the allowed list".into(),
            ),
            AppError::Internal(err) => {
                tracing::error!(error = ?err, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "internal server error".into(),
                )
            }
            AppError::Db(err) => {
                tracing::error!(error = ?err, "database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "database_error",
                    "database error".into(),
                )
            }
            AppError::Serde(err) => {
                tracing::warn!(error = ?err, "serde error");
                (
                    StatusCode::BAD_REQUEST,
                    "invalid_json",
                    "invalid json body".into(),
                )
            }
        };

        let body = Json(json!({
            "error": { "code": code, "message": message }
        }));

        (status, body).into_response()
    }
}
