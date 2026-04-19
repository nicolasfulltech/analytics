use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;

use crate::crypto::{API_KEY_CONTEXT, ct_eq, fixed_digest};
use crate::error::AppError;
use crate::state::AppState;

/// Verified server-to-server write request. Holds a stable, non-reversible
/// fingerprint of the key used so callers can rate-limit per key without
/// stashing the plaintext anywhere.
pub struct WriteAuth {
    pub key_fingerprint: [u8; 32],
}
pub struct ReadAuth;
pub struct AdminAuth;

/// Verified browser beacon request. The site token and Origin header have been
/// checked against the configured allowlist. Holds the client IP for rate
/// limiting and visitor hashing.
pub struct BeaconAuth {
    pub client_ip: String,
}

/// Hex-encoded 16-byte prefix of a key fingerprint. Enough collision-resistance
/// to partition rate-limit buckets but short enough to keep the cache key small.
fn bucket_key_from_fingerprint(fp: &[u8; 32]) -> String {
    let mut out = String::with_capacity(32);
    for byte in &fp[..16] {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn header<'a>(parts: &'a Parts, name: &str) -> Option<&'a str> {
    parts.headers.get(name).and_then(|v| v.to_str().ok())
}

/// Compare a candidate API key against every configured key in constant time
/// over a **fixed-width** digest, so we never leak the configured key length.
/// Every iteration does the same amount of work regardless of match/length.
fn match_any(candidate: &str, list: &[String]) -> bool {
    let cand_digest = fixed_digest(API_KEY_CONTEXT, candidate.as_bytes());
    let mut ok = false;
    for known in list {
        let k = fixed_digest(API_KEY_CONTEXT, known.as_bytes());
        if ct_eq(&cand_digest, &k) {
            ok = true;
        }
    }
    ok
}

/// Normalizes an origin for equality comparison. Strips trailing slash and
/// lowercases (scheme + host are case-insensitive per RFC 6454; path of the
/// origin should be empty anyway). Guards against case and trailing-slash
/// surprises that would otherwise desynchronize the allowlist from the CORS
/// layer's own matcher.
fn normalize_origin(s: &str) -> String {
    let trimmed = s.trim();
    let stripped = trimmed.strip_suffix('/').unwrap_or(trimmed);
    stripped.to_ascii_lowercase()
}

/// Normalize a caller-supplied IP string into the canonical form emitted by
/// `IpAddr::Display`. Also collapses IPv4-mapped-v6 (`::ffff:1.2.3.4`) onto
/// the bare v4 form so the same client isn't split across two rate-limit
/// buckets depending on the socket-layer address family. Rejects anything
/// that doesn't parse, so a hostile upstream can't fabricate unique bucket
/// keys (`"1.1.1.1  "`, `"1.1.1.1."`) and defeat the moka LRU.
fn parse_ip(s: &str) -> Option<String> {
    s.trim()
        .parse::<IpAddr>()
        .ok()
        .map(|ip| ip.to_canonical().to_string())
}

/// Header-based IP extraction. When `trust_proxy=true`, the LAST XFF token is
/// authoritative. A present-but-unparseable XFF indicates either operator
/// misconfiguration or a hostile upstream sinking every request into one
/// bucket — return `None` so the caller refuses the request rather than
/// silently collapsing the rate-limit fleet onto the proxy's own IP.
enum IpSource {
    /// Canonical IP string — safe to use as a rate-limit bucket key.
    Canonical(String),
    /// Header was present but didn't parse — reject the request.
    Malformed,
    /// No trusted header; use the socket peer address.
    Socket,
}

fn ip_from_headers(parts: &Parts, trust_proxy: bool) -> IpSource {
    if !trust_proxy {
        return IpSource::Socket;
    }
    if let Some(xff) = header(parts, "x-forwarded-for")
        && let Some(last) = xff.split(',').next_back()
    {
        return parse_ip(last)
            .map(IpSource::Canonical)
            .unwrap_or(IpSource::Malformed);
    }
    if let Some(real) = header(parts, "x-real-ip") {
        return parse_ip(real)
            .map(IpSource::Canonical)
            .unwrap_or(IpSource::Malformed);
    }
    IpSource::Socket
}

fn socket_ip(parts: &Parts) -> String {
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_canonical())
        .unwrap_or_else(|| IpAddr::from([0, 0, 0, 0]))
        .to_string()
}

/// Returns the bucket-safe client IP, or an AppError if `trust_proxy=true` and
/// a trusted header was present but unparseable. Use this from auth paths.
fn extract_client_ip(parts: &Parts, trust_proxy: bool) -> Result<String, AppError> {
    match ip_from_headers(parts, trust_proxy) {
        IpSource::Canonical(ip) => Ok(ip),
        IpSource::Socket => Ok(socket_ip(parts)),
        IpSource::Malformed => Err(AppError::BadRequest(
            "malformed X-Forwarded-For / X-Real-IP header".into(),
        )),
    }
}

/// Pre-auth per-IP gate. Fires BEFORE the key check so an attacker can't
/// distinguish "invalid key" (401) from "valid key, rate-limited" (429) to
/// probe key validity under load — both paths see 429 once the IP's bucket
/// is drained. Returns a canonical IP for the bucket; malformed XFF with
/// `trust_proxy=true` becomes a 400.
async fn check_auth_ip_limit(parts: &Parts, state: &AppState) -> Result<(), AppError> {
    let ip = extract_client_ip(parts, state.config.ingest.trust_proxy)?;
    if !state.auth_ip_limiter.check(&ip).await {
        return Err(AppError::RateLimited);
    }
    Ok(())
}

impl FromRequestParts<AppState> for WriteAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        check_auth_ip_limit(parts, state).await?;
        let key = header(parts, "x-write-key").ok_or(AppError::Unauthorized)?;
        // Load from the hot-reloadable snapshot so SIGHUP-rotated keys take
        // effect without restarting.
        let snap = state.reloadable.load();
        if !match_any(key, &snap.write_keys) {
            return Err(AppError::Unauthorized);
        }
        let fp = fixed_digest(API_KEY_CONTEXT, key.as_bytes());
        // Per-write-key bucket BEFORE returning success. Kept inside the
        // extractor (rather than in `collect_handler`) so an attacker probing
        // stolen keys can't distinguish "invalid key" from "valid key, per-
        // key-bucket drained" by status code: both paths see the same shape.
        if !state
            .write_key_limiter
            .check(&bucket_key_from_fingerprint(&fp))
            .await
        {
            return Err(AppError::RateLimited);
        }
        Ok(WriteAuth {
            key_fingerprint: fp,
        })
    }
}

impl FromRequestParts<AppState> for ReadAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        check_auth_ip_limit(parts, state).await?;
        let key = header(parts, "x-read-key").ok_or(AppError::Unauthorized)?;
        let snap = state.reloadable.load();
        if !match_any(key, &snap.read_keys) {
            return Err(AppError::Unauthorized);
        }
        // Per-key cap on /events, /stats, /export so a leaked read key can't
        // drain the event table in a tight loop. The bucket key is the
        // fingerprint prefix, never the plaintext.
        let fp = fixed_digest(API_KEY_CONTEXT, key.as_bytes());
        if !state
            .read_key_limiter
            .check(&bucket_key_from_fingerprint(&fp))
            .await
        {
            return Err(AppError::RateLimited);
        }
        Ok(ReadAuth)
    }
}

impl FromRequestParts<AppState> for AdminAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        check_auth_ip_limit(parts, state).await?;

        // IP allowlist fires BEFORE the key check. If it's set and the
        // request IP isn't on it, reject with a generic Unauthorized — same
        // shape as bad-key / bad-header so an outsider can't tell whether
        // the admin interface is enabled. `Forbidden` would be slightly more
        // precise but leaks "the route exists, your IP is wrong".
        //
        // Run `match_any` against the key header UNCONDITIONALLY even when
        // the IP is off the allowlist, so an outside attacker can't tell
        // whether their source IP is on the allowlist by timing the cost of
        // the digest loop against the configured admin keys.
        let allowlist = &state.config.auth.admin_ip_allowlist;
        let snap = state.reloadable.load();
        let candidate_key = header(parts, "x-admin-key").unwrap_or("");
        let key_matches = match_any(candidate_key, &snap.admin_keys);

        if !allowlist.is_empty() {
            let ip_str = extract_client_ip(parts, state.config.ingest.trust_proxy)?;
            let ip: IpAddr = match ip_str.parse() {
                Ok(ip) => ip,
                Err(_) => return Err(AppError::Unauthorized),
            };
            if !ip_in_allowlist(&ip, allowlist) {
                return Err(AppError::Unauthorized);
            }
        }

        if candidate_key.is_empty() || !key_matches {
            return Err(AppError::Unauthorized);
        }
        Ok(AdminAuth)
    }
}

/// Returns true if `ip` matches any entry. Entries can be plain IPs (exact
/// match, with IPv4-mapped-v6 normalization) or CIDR (`"10.0.0.0/8"`,
/// `"2001:db8::/32"`). Malformed entries don't match anything — they were
/// supposed to be caught at startup by `Config::validate`.
pub(crate) fn ip_in_allowlist(ip: &IpAddr, allowlist: &[String]) -> bool {
    let target = ip.to_canonical();
    for entry in allowlist {
        if let Some((net, prefix)) = entry.split_once('/')
            && let (Ok(net), Ok(prefix)) = (net.parse::<IpAddr>(), prefix.parse::<u8>())
            && ip_in_cidr(&target, &net.to_canonical(), prefix)
        {
            return true;
        }
        if let Ok(single) = entry.parse::<IpAddr>()
            && single.to_canonical() == target
        {
            return true;
        }
    }
    false
}

fn ip_in_cidr(ip: &IpAddr, net: &IpAddr, prefix: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => prefix <= 32 && v4_match(a.octets(), n.octets(), prefix),
        (IpAddr::V6(a), IpAddr::V6(n)) => prefix <= 128 && v6_match(a.octets(), n.octets(), prefix),
        _ => false,
    }
}

fn v4_match(a: [u8; 4], n: [u8; 4], prefix: u8) -> bool {
    let a = u32::from_be_bytes(a);
    let n = u32::from_be_bytes(n);
    if prefix == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - prefix);
    (a & mask) == (n & mask)
}

fn v6_match(a: [u8; 16], n: [u8; 16], prefix: u8) -> bool {
    let a = u128::from_be_bytes(a);
    let n = u128::from_be_bytes(n);
    if prefix == 0 {
        return true;
    }
    let mask = u128::MAX << (128 - prefix);
    (a & mask) == (n & mask)
}

impl FromRequestParts<AppState> for BeaconAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Always run the same work regardless of whether the beacon is
        // configured or the token is right. `browser_enabled()` short-
        // circuits would otherwise leak "beacon on / off" via response
        // timing — a deployment-shape signal an attacker can fingerprint.
        let header_name = state.config.endpoints.browser_token_header.as_str();
        let token = header(parts, header_name).unwrap_or("");
        let candidate = fixed_digest(API_KEY_CONTEXT, token.as_bytes());
        let expected = fixed_digest(API_KEY_CONTEXT, state.config.auth.site_token.as_bytes());
        let token_matches = ct_eq(&candidate, &expected);

        if !state.config.browser_enabled() || token.is_empty() || !token_matches {
            return Err(AppError::Unauthorized);
        }

        // Single generic "origin not allowed" message for every Origin-side
        // rejection: missing header, literal "null", or outside the allowlist.
        // Distinct messages would tell the attacker which check fired.
        let origin = header(parts, "origin").ok_or(AppError::Forbidden("origin not allowed"))?;
        let normalized = normalize_origin(origin);
        // Browsers emit `Origin: null` for sandboxed iframes, file://, data:,
        // and some cross-origin redirect chains. Never a real trusted origin,
        // so reject unconditionally — even if an operator accidentally adds
        // "null" to the allowlist (config.validate() also blocks this).
        if normalized == "null" {
            return Err(AppError::Forbidden("origin not allowed"));
        }
        let snap = state.reloadable.load();
        if !snap
            .allowed_origins
            .iter()
            .any(|o| normalize_origin(o) == normalized)
        {
            return Err(AppError::Forbidden("origin not allowed"));
        }

        // Per-IP cap FIRST. The site_token is public (embedded in `/s.js`),
        // so an attacker who captures it from one page load can drain the
        // global `beacon_token_limiter` bucket from a single IP and lock out
        // every legitimate browser visitor. Checking per-IP first means a
        // single source can consume at most its own per-IP budget before
        // being 429'd — the global bucket only caps aggregate traffic.
        let client_ip = extract_client_ip(parts, state.config.ingest.trust_proxy)?;
        if !state.beacon_limiter.check(&client_ip).await {
            return Err(AppError::RateLimited);
        }

        // Global cap across all browsers sharing the site_token — limits
        // the aggregate when an attacker rotates through an IP pool.
        if !state.beacon_token_limiter.check("site").await {
            return Err(AppError::RateLimited);
        }

        Ok(BeaconAuth { client_ip })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_any_finds_each_configured_key() {
        let keys = vec!["abcdef".into(), "zzzzzz".into()];
        assert!(match_any("abcdef", &keys));
        assert!(match_any("zzzzzz", &keys));
    }

    #[test]
    fn match_any_rejects_wrong_key() {
        let keys = vec!["abcdef".into()];
        assert!(!match_any("wrong", &keys));
    }

    #[test]
    fn match_any_is_length_independent() {
        let keys = vec!["a-very-long-api-key-xxxxxxxxxxxx".into()];
        // Different length candidate still returns a definitive false
        // (and goes through the same fixed-width digest path).
        assert!(!match_any("short", &keys));
    }

    #[test]
    fn parse_ip_rejects_garbage_and_canonicalizes() {
        assert_eq!(parse_ip("1.1.1.1"), Some("1.1.1.1".into()));
        assert_eq!(parse_ip("  1.1.1.1  "), Some("1.1.1.1".into()));
        // Trailing junk a hostile upstream might append to inflate bucket
        // cardinality (defeating moka's LRU via eviction churn) is rejected.
        assert_eq!(parse_ip("1.1.1.1."), None);
        assert_eq!(parse_ip("1.1.1.1\t"), Some("1.1.1.1".into()));
        assert_eq!(parse_ip("1.1.1.1xxxx"), None);
        assert_eq!(parse_ip(""), None);
        // IPv6 gets the canonical compact form, so `::1` and longer forms
        // collapse to the same bucket.
        assert_eq!(parse_ip("::1"), Some("::1".into()));
        assert_eq!(
            parse_ip("0000:0000:0000:0000:0000:0000:0000:0001"),
            Some("::1".into())
        );
    }

    #[test]
    fn normalize_origin_handles_case_and_slash() {
        assert_eq!(
            normalize_origin("https://Example.com"),
            "https://example.com"
        );
        assert_eq!(
            normalize_origin("https://example.com/"),
            "https://example.com"
        );
        assert_eq!(
            normalize_origin(" https://EXAMPLE.COM/ "),
            "https://example.com"
        );
    }
}
