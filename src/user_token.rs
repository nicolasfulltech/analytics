//! Signed user attribution tokens.
//!
//! The browser-facing token (public) lets any caller set `user_id` otherwise,
//! so we require the server that owns the visitor session to HMAC-sign the
//! user object first. The wire format is intentionally simple:
//!
//! - `user`: the raw JSON bytes of the object as the client serialized them.
//!   Must include `id` (attribution key) and `iat` (issued-at unix seconds).
//! - `user_sig`: hex-encoded blake3 keyed MAC over those bytes.
//!
//! Clients sign the *exact bytes* they send to avoid JSON canonicalization
//! headaches. The server only has to hash-compare; it never re-encodes.
//!
//! The `iat` field binds the signature to a moment in time: a token intercepted
//! from `/collect` traffic is only usable within `user_token_max_age_secs` of
//! when it was minted, so captured-and-replayed attribution is bounded rather
//! than valid forever.

use serde::Deserialize;

use crate::crypto::ct_eq;

/// Domain-separation context so the user-id secret can't be replayed against
/// the webhook-signing flow (they derive independent keys from the same input).
pub const USER_CONTEXT: &str = "simple-analytics user v1";

/// Stand-in key used only so the NotConfigured branch still spends the
/// same MAC + ct_eq cost as a real verify. Never matches anything real
/// because we return NotConfigured before trusting the outcome.
const DUMMY_SECRET: &str = "unconfigured-dummy-secret-for-timing-parity-only";

#[derive(Debug, thiserror::Error)]
pub enum UserTokenError {
    #[error("user attribution is not configured")]
    NotConfigured,
    #[error("user payload requires a signature")]
    MissingSignature,
    #[error("user signature is not valid hex")]
    BadSignatureEncoding,
    #[error("user signature did not match")]
    BadSignature,
    #[error("user payload is not valid JSON")]
    BadJson,
    #[error("user payload is missing the required `id` field")]
    MissingId,
    #[error("user payload is missing the required `iat` field")]
    MissingIat,
    #[error("user payload is stale (iat outside acceptance window)")]
    StaleIat,
    #[error("user payload is past its `exp`")]
    Expired,
}

#[derive(Debug, Deserialize)]
struct UserIdOnly {
    id: Option<serde_json::Value>,
    iat: Option<i64>,
    exp: Option<i64>,
}

/// Verify a signed user payload, returning the decoded `id` (as a string).
/// The caller can keep the original JSON bytes to store verbatim.
///
/// `sign()` always emits lowercase hex. We lowercase the incoming signature
/// once up front, validate the alphabet eagerly (no secret involved in that
/// check), then do a single constant-time compare on a fixed 64-byte form.
///
/// Timing parity: when `secret` is empty we still perform a dummy `sign()` +
/// `ct_eq` so an attacker can't tell "attribution disabled" from "configured
/// but wrong signature" by response latency — a deployment-shape leak that
/// tells them whether the calling app issues signed user tokens.
///
/// `max_age_secs = 0` disables the freshness check (legacy callers that
/// haven't started emitting `iat` yet). Production configs default to a real
/// window.
pub fn verify(
    secret: &str,
    user_json: &str,
    signature_hex: Option<&str>,
    now_unix_secs: i64,
    max_age_secs: u64,
) -> Result<String, UserTokenError> {
    let effective_secret = if secret.is_empty() {
        DUMMY_SECRET
    } else {
        secret
    };

    let sig_hex = signature_hex.unwrap_or("");
    let normalized = sig_hex.to_ascii_lowercase();
    let encoding_ok = normalized.len() == 64 && normalized.bytes().all(|b| b.is_ascii_hexdigit());

    // Do the keyed MAC + compare unconditionally so this path has the same
    // cost shape whether the secret is set, the signature is missing, or
    // the encoding is bad. Padding to 64 hex ensures ct_eq compares a
    // fixed-width input.
    let expected = sign(effective_secret, user_json.as_bytes());
    let compare_input: [u8; 64] = if encoding_ok {
        let mut buf = [0u8; 64];
        buf.copy_from_slice(normalized.as_bytes());
        buf
    } else {
        [0u8; 64]
    };
    let mac_matches = ct_eq(expected.as_bytes(), &compare_input);

    // Now that the expensive work is done identically in every branch, fail
    // the correct error for the real caller.
    if secret.is_empty() {
        return Err(UserTokenError::NotConfigured);
    }
    if signature_hex.is_none() {
        return Err(UserTokenError::MissingSignature);
    }
    if !encoding_ok {
        return Err(UserTokenError::BadSignatureEncoding);
    }
    if !mac_matches {
        return Err(UserTokenError::BadSignature);
    }

    let parsed: UserIdOnly =
        serde_json::from_str(user_json).map_err(|_| UserTokenError::BadJson)?;
    let id = parsed.id.ok_or(UserTokenError::MissingId)?;
    let id_str = match id {
        serde_json::Value::String(s) => s,
        serde_json::Value::Number(n) => n.to_string(),
        _ => return Err(UserTokenError::MissingId),
    };
    if id_str.trim().is_empty() {
        return Err(UserTokenError::MissingId);
    }

    // Hard expiry if the backend stamped one. `exp` is always enforced when
    // present, independent of `max_age_secs` — it's the caller's declared
    // expiration wall-clock time, useful for Varnish-cached flows where the
    // cookie can't be re-signed on every page hit (so a generous `max_age`
    // would be the only freshness bound) and for backends that want to bind
    // the token's validity to the browser cookie's declared lifetime.
    if let Some(exp) = parsed.exp
        && now_unix_secs > exp
    {
        return Err(UserTokenError::Expired);
    }

    // Freshness check. `iat` is unix seconds the caller's backend stamped
    // into the signed JSON; a captured token is valid only inside the
    // acceptance window. A small tolerance covers clock skew / in-flight
    // latency; everything beyond `max_age_secs` is rejected.
    if max_age_secs > 0 {
        let iat = parsed.iat.ok_or(UserTokenError::MissingIat)?;
        let age = now_unix_secs.saturating_sub(iat);
        // Reject tokens from the future by more than the clock-skew slack
        // (negative age beyond -`max_age_secs` — a pre-minted token is not
        // a useful concept).
        let max_i64 = i64::try_from(max_age_secs).unwrap_or(i64::MAX);
        if age > max_i64 || age < -max_i64 {
            return Err(UserTokenError::StaleIat);
        }
    }

    Ok(id_str)
}

/// Hex-encoded blake3 keyed MAC (lowercase). Clients produce the same string
/// and send it as `user_sig`.
pub fn sign(secret: &str, payload: &[u8]) -> String {
    let key = blake3::derive_key(USER_CONTEXT, secret.as_bytes());
    let mut hasher = blake3::Hasher::new_keyed(&key);
    hasher.update(payload);
    hasher.finalize().to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "a-32-character-signing-secret-xxxxxxx";
    const NOW: i64 = 1_700_000_000;
    const MAX_AGE: u64 = 900;

    fn body_with_iat(id: &str, iat: i64) -> String {
        format!(r#"{{"id":"{id}","iat":{iat}}}"#)
    }

    #[test]
    fn round_trip_with_string_id() {
        let body = body_with_iat("user-42", NOW);
        let sig = sign(SECRET, body.as_bytes());
        let id = verify(SECRET, &body, Some(&sig), NOW, MAX_AGE).unwrap();
        assert_eq!(id, "user-42");
    }

    #[test]
    fn round_trip_with_numeric_id() {
        let body = format!(r#"{{"id":42,"iat":{NOW}}}"#);
        let sig = sign(SECRET, body.as_bytes());
        let id = verify(SECRET, &body, Some(&sig), NOW, MAX_AGE).unwrap();
        assert_eq!(id, "42");
    }

    #[test]
    fn rejects_mismatched_signature() {
        let body = body_with_iat("x", NOW);
        let err = verify(SECRET, &body, Some(&"0".repeat(64)), NOW, MAX_AGE).unwrap_err();
        assert!(matches!(err, UserTokenError::BadSignature));
    }

    #[test]
    fn rejects_missing_signature() {
        let body = body_with_iat("x", NOW);
        let err = verify(SECRET, &body, None, NOW, MAX_AGE).unwrap_err();
        assert!(matches!(err, UserTokenError::MissingSignature));
    }

    #[test]
    fn rejects_missing_id() {
        let body = format!(r#"{{"email":"x@y","iat":{NOW}}}"#);
        let sig = sign(SECRET, body.as_bytes());
        let err = verify(SECRET, &body, Some(&sig), NOW, MAX_AGE).unwrap_err();
        assert!(matches!(err, UserTokenError::MissingId));
    }

    #[test]
    fn rejects_when_secret_unset() {
        let err = verify("", "{}", Some("00"), NOW, MAX_AGE).unwrap_err();
        assert!(matches!(err, UserTokenError::NotConfigured));
    }

    #[test]
    fn tamper_with_json_breaks_sig() {
        let body = format!(r#"{{"id":"user-42","plan":"free","iat":{NOW}}}"#);
        let sig = sign(SECRET, body.as_bytes());
        let tampered = format!(r#"{{"id":"user-42","plan":"pro","iat":{NOW}}}"#);
        let err = verify(SECRET, &tampered, Some(&sig), NOW, MAX_AGE).unwrap_err();
        assert!(matches!(err, UserTokenError::BadSignature));
    }

    #[test]
    fn rejects_missing_iat() {
        let body = r#"{"id":"x"}"#;
        let sig = sign(SECRET, body.as_bytes());
        let err = verify(SECRET, body, Some(&sig), NOW, MAX_AGE).unwrap_err();
        assert!(matches!(err, UserTokenError::MissingIat));
    }

    #[test]
    fn rejects_stale_iat() {
        let body = body_with_iat("x", NOW - 3_600);
        let sig = sign(SECRET, body.as_bytes());
        let err = verify(SECRET, &body, Some(&sig), NOW, MAX_AGE).unwrap_err();
        assert!(matches!(err, UserTokenError::StaleIat));
    }

    #[test]
    fn rejects_future_iat_beyond_slack() {
        let body = body_with_iat("x", NOW + 3_600);
        let sig = sign(SECRET, body.as_bytes());
        let err = verify(SECRET, &body, Some(&sig), NOW, MAX_AGE).unwrap_err();
        assert!(matches!(err, UserTokenError::StaleIat));
    }

    #[test]
    fn max_age_zero_disables_check() {
        let body = r#"{"id":"x"}"#;
        let sig = sign(SECRET, body.as_bytes());
        let id = verify(SECRET, body, Some(&sig), NOW, 0).unwrap();
        assert_eq!(id, "x");
    }

    #[test]
    fn rejects_past_exp() {
        let body = format!(r#"{{"id":"x","iat":{NOW},"exp":{}}}"#, NOW - 10);
        let sig = sign(SECRET, body.as_bytes());
        let err = verify(SECRET, &body, Some(&sig), NOW, MAX_AGE).unwrap_err();
        assert!(matches!(err, UserTokenError::Expired));
    }

    #[test]
    fn accepts_future_exp() {
        let body = format!(r#"{{"id":"x","iat":{NOW},"exp":{}}}"#, NOW + 3600);
        let sig = sign(SECRET, body.as_bytes());
        let id = verify(SECRET, &body, Some(&sig), NOW, MAX_AGE).unwrap();
        assert_eq!(id, "x");
    }

    #[test]
    fn exp_enforced_even_with_max_age_zero() {
        let body = format!(r#"{{"id":"x","exp":{}}}"#, NOW - 1);
        let sig = sign(SECRET, body.as_bytes());
        let err = verify(SECRET, &body, Some(&sig), NOW, 0).unwrap_err();
        assert!(matches!(err, UserTokenError::Expired));
    }
}
