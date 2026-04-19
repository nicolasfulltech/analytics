use axum::Router;
use axum::extract::State;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::config::EndpointsConfig;
use crate::state::AppState;

pub fn routes(endpoints: &EndpointsConfig) -> Router<AppState> {
    Router::new().route(&endpoints.browser_script_path, get(beacon_js))
}

// readable source lives in assets/beacon.js. edit there, then regenerate
// assets/beacon.min.js (the file we actually serve).
const BEACON_TEMPLATE: &str = include_str!("../assets/beacon.min.js");

pub fn render_script(endpoints: &EndpointsConfig) -> String {
    BEACON_TEMPLATE
        .replace("__ENDPOINT__", &endpoints.browser_collect_path)
        .replace("__TOKEN_HEADER__", &endpoints.browser_token_header)
        .replace("__NS__", &endpoints.js_namespace)
}

async fn beacon_js(State(state): State<AppState>) -> Response {
    let body = render_script(&state.config.endpoints);
    let mut resp = body.into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/javascript; charset=utf-8"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_are_replaced() {
        let cfg = EndpointsConfig {
            browser_collect_path: "/e".into(),
            browser_script_path: "/s.js".into(),
            browser_token_header: "x-id".into(),
            js_namespace: "sa".into(),
        };
        let out = render_script(&cfg);
        assert!(!out.contains("__ENDPOINT__"));
        assert!(!out.contains("__TOKEN_HEADER__"));
        assert!(!out.contains("__NS__"));
        assert!(out.contains("\"/e\""));
        assert!(out.contains("\"x-id\""));
        assert!(out.contains("window[ns]"));
    }
}
