//! Network safety helpers — DNS checks that keep outbound callers away from
//! loopback / private / link-local / reserved ranges. Used by the webhook
//! client to prevent SSRF from an admin-controlled URL into internal infra.
//!
//! DNS rebinding is mitigated by pinning: we resolve once, verify every
//! resolved address, then hand the verified IP to `reqwest` via
//! `ClientBuilder::resolve(...)` so the connect phase uses the same address
//! — a hostile DNS server can't flip public→private between check and connect.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use anyhow::anyhow;

#[derive(Debug, thiserror::Error)]
pub enum UrlSafetyError {
    #[error("webhook url must use http or https")]
    BadScheme,
    #[error("webhook url must include a host")]
    NoHost,
    #[error("webhook url resolves to a private/loopback/link-local address")]
    PrivateAddress,
    #[error("webhook url uses a non-HTTP(S) port")]
    BadPort,
    #[error("webhook url could not be resolved: {0}")]
    ResolveFailed(String),
}

/// Ports allowed for outbound HTTP(S). Anything else (22, 25, 6379, 5432, …)
/// would let an admin pivot into plaintext services on a *public* IP — and
/// `reqwest::ClientBuilder::resolve` pins the IP but NOT the port, so the URL's
/// port always wins. Operators who need a non-standard port must opt in via
/// `allow_private_targets = true`.
const ALLOWED_HTTP_PORTS: &[u16] = &[80, 443];

/// Always-rejected ports, even when `allow_private_targets = true`. The
/// private-targets escape hatch is documented as "I run analytics and
/// subscribers in the same private network" — that is not license to fire
/// a POST at SSH, SMTP, Redis, Postgres, Mongo, etc. High random ports used
/// by test / application servers stay available.
const DANGEROUS_PORTS: &[u16] = &[
    22,    // SSH
    23,    // Telnet
    25,    // SMTP
    53,    // DNS
    110,   // POP3
    135,   // MSRPC
    139,   // NetBIOS
    143,   // IMAP
    445,   // SMB
    465,   // SMTPS
    587,   // SMTP submission
    636,   // LDAPS
    993,   // IMAPS
    995,   // POP3S
    1433,  // MSSQL
    1521,  // Oracle
    2049,  // NFS
    2375,  // Docker (plaintext)
    2376,  // Docker (TLS)
    3306,  // MySQL
    3389,  // RDP
    5432,  // Postgres
    5984,  // CouchDB
    6379,  // Redis
    7001,  // Weblogic
    8086,  // InfluxDB
    8500,  // Consul
    9042,  // Cassandra
    9092,  // Kafka
    9200,  // Elasticsearch
    11211, // Memcached
    27017, // MongoDB
];

/// Refuse `file://`, `ftp://`, etc. Only http(s) may be a webhook target.
pub fn check_scheme(url: &url::Url) -> Result<(), UrlSafetyError> {
    match url.scheme() {
        "http" | "https" => Ok(()),
        _ => Err(UrlSafetyError::BadScheme),
    }
}

/// Returns the resolved, safety-checked addresses for `url`. Rejects
/// loopback / private / link-local / CGNAT / broadcast / multicast /
/// unspecified / documentation / unique-local v6 etc. The caller should pin
/// these addresses into the HTTP client (see [`resolve_safe_async`]) so the
/// connect phase doesn't re-query DNS.
pub fn check_public_destination(url: &url::Url) -> Result<Vec<SocketAddr>, UrlSafetyError> {
    let host = url.host_str().ok_or(UrlSafetyError::NoHost)?;
    let port = url.port_or_known_default().unwrap_or(80);

    if !ALLOWED_HTTP_PORTS.contains(&port) {
        return Err(UrlSafetyError::BadPort);
    }

    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| UrlSafetyError::ResolveFailed(e.to_string()))?;

    let collected: Vec<SocketAddr> = addrs.collect();
    if collected.is_empty() {
        return Err(UrlSafetyError::ResolveFailed("no addresses".into()));
    }
    for addr in &collected {
        if !is_public_ip(&addr.ip()) {
            return Err(UrlSafetyError::PrivateAddress);
        }
    }
    Ok(collected)
}

/// Resolve `url` without the public-IP safety check. Only used on paths where
/// the operator explicitly opted into private targets AND we still want to pin
/// the resolved IP into the HTTP client. Port checks still apply (the
/// dangerous-ports denylist guards this path separately at the caller).
pub fn resolve_unchecked(url: &url::Url) -> Result<Vec<SocketAddr>, UrlSafetyError> {
    let host = url.host_str().ok_or(UrlSafetyError::NoHost)?;
    let port = url.port_or_known_default().unwrap_or(80);
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| UrlSafetyError::ResolveFailed(e.to_string()))?;
    let collected: Vec<SocketAddr> = addrs.collect();
    if collected.is_empty() {
        return Err(UrlSafetyError::ResolveFailed("no addresses".into()));
    }
    Ok(collected)
}

/// Async wrapper that runs the blocking DNS on a dedicated thread pool so we
/// don't stall a tokio worker. Use this from every async path (webhook create
/// handler and delivery worker); the sync version stays available for startup
/// config validation.
pub async fn resolve_safe_async(url: url::Url) -> Result<Vec<SocketAddr>, UrlSafetyError> {
    tokio::task::spawn_blocking(move || check_public_destination(&url))
        .await
        .map_err(|e| UrlSafetyError::ResolveFailed(format!("join: {e}")))?
}

async fn resolve_unchecked_async(url: url::Url) -> Result<Vec<SocketAddr>, UrlSafetyError> {
    tokio::task::spawn_blocking(move || resolve_unchecked(&url))
        .await
        .map_err(|e| UrlSafetyError::ResolveFailed(format!("join: {e}")))?
}

/// True when `ip` is routable on the public internet. Errs on the side of
/// rejection — any uncertain range is treated as unsafe.
pub fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: &Ipv4Addr) -> bool {
    if ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.is_documentation()
    {
        return false;
    }
    let o = ip.octets();
    // 100.64.0.0/10 (CGNAT / shared address space).
    if o[0] == 100 && (o[1] & 0xc0) == 0x40 {
        return false;
    }
    // 0.0.0.0/8 — reserved / "this network".
    if o[0] == 0 {
        return false;
    }
    // 192.0.0.0/24 — IANA special purpose.
    if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        return false;
    }
    // 198.18.0.0/15 — benchmarking.
    if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
        return false;
    }
    // 240.0.0.0/4 — reserved (class E), minus 255.255.255.255 already covered.
    if o[0] >= 240 {
        return false;
    }
    true
}

fn is_public_v6(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() {
        return false;
    }
    let seg = ip.segments();
    // fc00::/7 unique-local.
    if (seg[0] & 0xfe00) == 0xfc00 {
        return false;
    }
    // fe80::/10 link-local.
    if (seg[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    // ::ffff:0:0/96 IPv4-mapped — apply v4 rules.
    if seg[0] == 0 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0xffff {
        let v4 = Ipv4Addr::new(
            (seg[6] >> 8) as u8,
            (seg[6] & 0xff) as u8,
            (seg[7] >> 8) as u8,
            (seg[7] & 0xff) as u8,
        );
        return is_public_v4(&v4);
    }
    // 2002::/16 (6to4): bits 16..48 encode an IPv4 address. Without this
    // check, `2002:7f00:0001::1` reaches 127.0.0.1 and `2002:a9fe:a9fe::`
    // reaches 169.254.169.254 (cloud metadata). Apply v4 rules to the
    // embedded address.
    if seg[0] == 0x2002 {
        let v4 = Ipv4Addr::new(
            (seg[1] >> 8) as u8,
            (seg[1] & 0xff) as u8,
            (seg[2] >> 8) as u8,
            (seg[2] & 0xff) as u8,
        );
        return is_public_v4(&v4);
    }
    // 64:ff9b::/96 (RFC 6052) and 64:ff9b:1::/48 (RFC 8215) NAT64 well-known
    // prefixes: the low 32 bits carry an IPv4 address. Dual-stack resolvers
    // on IPv6-only networks synthesize these for arbitrary IPv4 hosts —
    // including metadata endpoints.
    if seg[0] == 0x0064
        && seg[1] == 0xff9b
        && seg[2] == 0
        && seg[3] == 0
        && seg[4] == 0
        && seg[5] == 0
    {
        let v4 = Ipv4Addr::new(
            (seg[6] >> 8) as u8,
            (seg[6] & 0xff) as u8,
            (seg[7] >> 8) as u8,
            (seg[7] & 0xff) as u8,
        );
        return is_public_v4(&v4);
    }
    if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0x0001 {
        let v4 = Ipv4Addr::new(
            (seg[6] >> 8) as u8,
            (seg[6] & 0xff) as u8,
            (seg[7] >> 8) as u8,
            (seg[7] & 0xff) as u8,
        );
        return is_public_v4(&v4);
    }
    // 2001:db8::/32 documentation.
    if seg[0] == 0x2001 && seg[1] == 0x0db8 {
        return false;
    }
    // ::/96 — IPv4-compatible; treat as unsafe (historical, internal).
    if seg[0] == 0 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0 {
        return false;
    }
    true
}

/// Parse + sanitize a webhook/validator URL. Rejects userinfo (credentials
/// baked into the URL) because reqwest would include them in an Authorization
/// header and any connect / TLS error would format them back into the error
/// message, leaking secrets into logs + the `last_error` DB column.
fn parse_and_sanitize(raw: &str) -> anyhow::Result<url::Url> {
    let parsed = url::Url::parse(raw).map_err(|e| anyhow!("invalid URL: {e}"))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        anyhow::bail!("webhook URL must not contain userinfo / credentials");
    }
    check_scheme(&parsed)?;
    Ok(parsed)
}

/// Enforce the dangerous-port deny list. Runs even when
/// `allow_private_targets = true` — opting into private-network targets is
/// not opting into pivoting through SSH / SMTP / Redis / Postgres / etc.
fn check_port_not_dangerous(url: &url::Url) -> Result<(), UrlSafetyError> {
    let port = url.port_or_known_default().unwrap_or(80);
    if DANGEROUS_PORTS.contains(&port) {
        return Err(UrlSafetyError::BadPort);
    }
    Ok(())
}

pub fn validate_webhook_url(raw: &str, allow_private: bool) -> anyhow::Result<url::Url> {
    let parsed = parse_and_sanitize(raw)?;
    check_port_not_dangerous(&parsed)?;
    if !allow_private {
        check_public_destination(&parsed)?;
    }
    Ok(parsed)
}

/// Async counterpart used on ingest/worker paths: parse, scheme-check, then
/// run the blocking DNS call off-runtime with a timeout so a slow resolver
/// can't pin a blocking-pool thread indefinitely. Returns the parsed URL and
/// the pinned addresses (caller passes them to `reqwest::ClientBuilder::resolve`).
///
/// When `allow_private = true`, the public-IP safety check is skipped but we
/// still resolve and return the addresses — the caller needs them to pin the
/// resolved IP into the reqwest client, otherwise reqwest re-queries DNS at
/// connect time and a rebinding attack wins. Opting into private targets is
/// NOT opting out of DNS pinning.
pub async fn validate_webhook_url_async(
    raw: &str,
    allow_private: bool,
) -> anyhow::Result<(url::Url, Vec<SocketAddr>)> {
    let parsed = parse_and_sanitize(raw)?;
    check_port_not_dangerous(&parsed)?;
    let resolve = async {
        if allow_private {
            resolve_unchecked_async(parsed.clone()).await
        } else {
            resolve_safe_async(parsed.clone()).await
        }
    };
    let addrs = tokio::time::timeout(std::time::Duration::from_secs(5), resolve)
        .await
        .map_err(|_| anyhow!("DNS resolution timed out for {}", host_for_log(&parsed)))??;
    Ok((parsed, addrs))
}

/// Host + port for log messages. Never includes userinfo (we reject it above)
/// or path (ingest URLs often carry ids, session tokens, etc.).
pub fn host_for_log(url: &url::Url) -> String {
    match (url.host_str(), url.port()) {
        (Some(h), Some(p)) => format!("{h}:{p}"),
        (Some(h), None) => h.to_string(),
        _ => "<unknown>".into(),
    }
}

/// Same as `host_for_log` but for raw strings, used on the SSRF-reject path
/// where parsing may itself have failed. Never echoes the raw input so a URL
/// carrying credentials in its query string doesn't end up in logs.
pub fn host_for_log_str(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(u) => host_for_log(&u),
        Err(_) => "<unparseable>".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn v4(s: &str) -> Ipv4Addr {
        Ipv4Addr::from_str(s).unwrap()
    }

    fn v6(s: &str) -> Ipv6Addr {
        Ipv6Addr::from_str(s).unwrap()
    }

    #[test]
    fn rejects_private_v4() {
        assert!(!is_public_v4(&v4("10.0.0.1")));
        assert!(!is_public_v4(&v4("192.168.1.1")));
        assert!(!is_public_v4(&v4("172.16.0.1")));
        assert!(!is_public_v4(&v4("127.0.0.1")));
        assert!(!is_public_v4(&v4("169.254.169.254")));
        assert!(!is_public_v4(&v4("100.64.0.1")));
        assert!(!is_public_v4(&v4("0.0.0.0")));
        assert!(!is_public_v4(&v4("240.0.0.1")));
    }

    #[test]
    fn accepts_public_v4() {
        assert!(is_public_v4(&v4("8.8.8.8")));
        assert!(is_public_v4(&v4("1.1.1.1")));
    }

    #[test]
    fn rejects_private_v6() {
        assert!(!is_public_v6(&v6("::1")));
        assert!(!is_public_v6(&v6("fe80::1")));
        assert!(!is_public_v6(&v6("fc00::1")));
        assert!(!is_public_v6(&v6("::ffff:10.0.0.1")));
        assert!(!is_public_v6(&v6("::ffff:127.0.0.1")));
        assert!(!is_public_v6(&v6("2001:db8::1")));
    }

    #[test]
    fn rejects_6to4_to_private_v4() {
        // 2002:7f00:0001:: decodes to 127.0.0.1 — must NOT be treated as a
        // public v6 just because 2002::/16 isn't loopback itself.
        assert!(!is_public_v6(&v6("2002:7f00:0001::1")));
        // 2002:a9fe:a9fe:: decodes to 169.254.169.254 (AWS/GCP/Azure metadata).
        assert!(!is_public_v6(&v6("2002:a9fe:a9fe::")));
        // 2002:0a00:0001:: decodes to 10.0.0.1.
        assert!(!is_public_v6(&v6("2002:0a00:0001::")));
    }

    #[test]
    fn accepts_6to4_to_public_v4() {
        // 2002:0808:0808:: decodes to 8.8.8.8 — publicly routable.
        assert!(is_public_v6(&v6("2002:0808:0808::")));
    }

    #[test]
    fn rejects_nat64_to_private_v4() {
        // 64:ff9b::a9fe:a9fe decodes to 169.254.169.254.
        assert!(!is_public_v6(&v6("64:ff9b::a9fe:a9fe")));
        // 64:ff9b::7f00:1 decodes to 127.0.0.1.
        assert!(!is_public_v6(&v6("64:ff9b::7f00:1")));
        // RFC 8215 64:ff9b:1::/48 variant.
        assert!(!is_public_v6(&v6("64:ff9b:1::a9fe:a9fe")));
    }

    #[test]
    fn dangerous_ports_rejected_even_with_allow_private() {
        // 127.0.0.1:6379 (Redis) with allow_private=true must still be
        // rejected — opting into private targets isn't opting into pivots
        // through plaintext database ports.
        for port in [22, 25, 3306, 3389, 5432, 6379, 9200, 11211, 27017] {
            let url = format!("http://127.0.0.1:{port}/");
            let err = validate_webhook_url(&url, true).unwrap_err();
            assert!(
                err.to_string().contains("port"),
                "port {port} should be rejected: {err}"
            );
        }
    }

    #[test]
    fn accepts_public_v6() {
        assert!(is_public_v6(&v6("2606:4700:4700::1111")));
    }

    #[test]
    fn rejects_non_http_schemes() {
        let bad = url::Url::parse("file:///etc/passwd").unwrap();
        assert!(matches!(check_scheme(&bad), Err(UrlSafetyError::BadScheme)));
        let ftp = url::Url::parse("ftp://example.com/").unwrap();
        assert!(matches!(check_scheme(&ftp), Err(UrlSafetyError::BadScheme)));
    }

    #[test]
    fn rejects_non_http_ports_on_public_ip() {
        // 1.1.1.1:6379 — public IP, but Redis port. reqwest.resolve() does NOT
        // pin ports, so without a port allowlist an admin-attacker could pivot
        // into plaintext services on any public IP (including the deployment's
        // own public IP).
        for port in [22, 25, 6379, 5432, 11211, 9200, 8080] {
            let u = url::Url::parse(&format!("http://1.1.1.1:{port}/")).unwrap();
            assert!(
                matches!(check_public_destination(&u), Err(UrlSafetyError::BadPort)),
                "port {port} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_userinfo_in_url() {
        let result = validate_webhook_url("https://user:pass@example.com/hook", true);
        assert!(result.is_err(), "userinfo URL should be rejected");
    }

    #[test]
    fn accepts_standard_http_ports() {
        // Standard 80/443 on a public IP — should reach the DNS/IP check
        // rather than short-circuiting on port.
        let ok_80 = url::Url::parse("http://1.1.1.1/").unwrap();
        let ok_443 = url::Url::parse("https://1.1.1.1/").unwrap();
        assert!(!matches!(
            check_public_destination(&ok_80),
            Err(UrlSafetyError::BadPort)
        ));
        assert!(!matches!(
            check_public_destination(&ok_443),
            Err(UrlSafetyError::BadPort)
        ));
    }
}
