//! Sign a user JSON payload with the same keyed blake3 MAC the server expects.
//!
//! Usage:
//!   cargo run --release --example sign_user -- '<secret>' '<user-json>'
//!
//! The `user-json` MUST include `id` (attribution key) and `iat` (unix
//! seconds). Tokens without `iat` are rejected by the server, and tokens
//! older than `auth.user_token_max_age_secs` are rejected as stale — so the
//! example injects `iat` automatically if it's missing.
//!
//! Prints the hex signature to stdout.

use time::OffsetDateTime;

fn main() {
    let mut args = std::env::args().skip(1);
    let secret = args.next().expect("secret");
    let payload = args.next().expect("user json");

    // Convenience: if the caller forgot `iat`, stamp `now` into the payload
    // before signing so the example produces a token the server accepts
    // out of the box. Callers that supply their own `iat` (e.g. for testing
    // staleness) get their bytes signed verbatim.
    let finalized = inject_iat_if_missing(&payload);
    println!(
        "{}",
        simple_analytics::user_token::sign(&secret, finalized.as_bytes())
    );
    if finalized != payload {
        eprintln!("signed payload: {finalized}");
    }
}

fn inject_iat_if_missing(raw: &str) -> String {
    let Ok(mut v) = serde_json::from_str::<serde_json::Value>(raw) else {
        return raw.to_string();
    };
    let Some(obj) = v.as_object_mut() else {
        return raw.to_string();
    };
    if obj.contains_key("iat") {
        return raw.to_string();
    }
    let now = OffsetDateTime::now_utc().unix_timestamp();
    obj.insert("iat".into(), serde_json::Value::Number(now.into()));
    serde_json::to_string(&v).unwrap_or_else(|_| raw.to_string())
}
