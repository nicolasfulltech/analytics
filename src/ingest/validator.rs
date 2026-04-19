use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use moka::future::Cache;
use reqwest::{Client, StatusCode};
use url::Url;

use crate::config::ValidatorConfig;

/// Max bytes we will consume from a validator response. We never *use* the
/// body (only the status), so this is purely a guard against a malicious
/// validator target that streams forever — dropping a reqwest response
/// cancels the stream but the underlying TCP slot in the connection pool
/// can still sit occupied until the server closes. Reading-and-discarding a
/// tiny window closes it deterministically.
const MAX_VALIDATOR_BODY: usize = 4 * 1024;

/// How often the DNS-pinned validator client gets rebuilt. Fires independently
/// of the DNS TTL so we don't need to parse it — a 5-minute refresh keeps us
/// within typical CDN / load-balancer rotation windows and bounds the damage
/// if the validator host is ever re-IPed.
const VALIDATOR_RESOLVE_REFRESH: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationOutcome {
    Valid,
    Invalid,
    Skipped,
}

pub struct UrlValidator {
    inner: Option<Inner>,
    fail_open: bool,
}

struct Inner {
    client: ArcSwap<Client>,
    endpoint: Url,
    cache: Cache<String, bool>,
    timeout_ms: u64,
    allow_private: bool,
}

impl UrlValidator {
    pub fn new(cfg: &ValidatorConfig) -> Self {
        let Some(endpoint_raw) = cfg.url.clone() else {
            return Self {
                inner: None,
                fail_open: cfg.fail_open,
            };
        };

        // Parsing + validating the endpoint URL ran at startup (Config::validate),
        // but we re-parse here so we can hand a normalized Url to every request
        // path. Any parse failure is a build-time bug, not a runtime surprise.
        let endpoint = Url::parse(&endpoint_raw).expect("validator endpoint already validated");

        // Build the initial DNS-pinned client synchronously using the blocking
        // resolver. This MUST succeed for the process to start — otherwise
        // `fail_open = false` would silently start accepting events until the
        // first refresh tick pinned a real IP. Panicking here is correct: the
        // operator set a validator URL that can't resolve at startup.
        let initial_client = build_pinned_validator_client(&endpoint, cfg)
            .expect("validator endpoint resolves at startup");
        let inner = Inner {
            client: ArcSwap::from_pointee(initial_client),
            endpoint,
            cache: Cache::builder()
                .max_capacity(cfg.cache_size)
                .time_to_live(Duration::from_secs(cfg.cache_ttl_secs))
                .build(),
            timeout_ms: cfg.timeout_ms,
            allow_private: cfg.allow_private_targets,
        };

        Self {
            inner: Some(inner),
            fail_open: cfg.fail_open,
        }
    }

    /// Refresh the DNS-pinned client. Called on a timer from a background
    /// task so a validator-host IP rotation gets picked up within
    /// `VALIDATOR_RESOLVE_REFRESH` without needing a service restart.
    async fn refresh_client(&self) {
        let Some(inner) = &self.inner else {
            return;
        };
        let endpoint = inner.endpoint.clone();
        let timeout_ms = inner.timeout_ms;
        let allow_private = inner.allow_private;
        let built = tokio::task::spawn_blocking(move || {
            let cfg_stub = ValidatorConfig {
                url: Some(endpoint.to_string()),
                cache_ttl_secs: 0,
                cache_size: 0,
                timeout_ms,
                fail_open: false,
                allow_private_targets: allow_private,
            };
            build_pinned_validator_client(&endpoint, &cfg_stub)
        })
        .await;
        match built {
            Ok(Ok(c)) => inner.client.store(Arc::new(c)),
            Ok(Err(err)) => {
                tracing::warn!(error = %err, "validator DNS refresh failed; keeping old pinned client")
            }
            Err(join_err) => {
                tracing::warn!(error = ?join_err, "validator DNS refresh join failed")
            }
        }
    }

    pub async fn validate(&self, url: &str) -> ValidationOutcome {
        let Some(inner) = &self.inner else {
            return ValidationOutcome::Skipped;
        };

        // Normalize the caller-supplied URL for cache keying so minor
        // representation differences (trailing `?`, default-port forms,
        // uppercased host) don't split the cache and let an attacker bypass
        // a validator-rejected URL with a trivial variant. We still forward
        // the original string to the validator as the `url` query parameter
        // — operators expect to see what their caller sent.
        let cache_key = match Url::parse(url) {
            Ok(u) => u.to_string(),
            Err(_) => url.to_string(),
        };

        // `try_get_with` coalesces concurrent lookups for the same URL into a
        // single HTTP call — the thundering herd on the operator's validator
        // collapses to one in-flight request per unique URL. Only Ok(bool)
        // values are cached; Err paths (transport errors, non-200/404
        // responses) stay uncached and fall back to `fail_open`.
        let client = inner.client.load_full();
        let endpoint = inner.endpoint.clone();
        let url_owned = url.to_string();
        let init = async move {
            let built = Url::parse_with_params(endpoint.as_str(), &[("url", url_owned.as_str())])
                .map_err(|_| ValidatorError::BadEndpoint)?;
            let resp = client.get(built).send().await.map_err(|err| {
                tracing::warn!(error = ?err, "url validator request failed");
                ValidatorError::Transport
            })?;
            let status = resp.status();
            // Bound the body consumption: a malicious validator target
            // could stream indefinitely and hold the connection slot.
            // `chunk()` + explicit break closes the response cleanly
            // regardless of server behavior.
            let mut stream = resp;
            let mut read = 0usize;
            while read < MAX_VALIDATOR_BODY {
                match stream.chunk().await {
                    Ok(Some(c)) => read += c.len(),
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
            drop(stream);
            match status {
                StatusCode::OK => Ok(true),
                StatusCode::NOT_FOUND => Ok(false),
                other => {
                    tracing::warn!(status = %other, "url validator returned non-200/404 status");
                    Err(ValidatorError::UnexpectedStatus)
                }
            }
        };

        match inner.cache.try_get_with(cache_key, init).await {
            Ok(true) => ValidationOutcome::Valid,
            Ok(false) => ValidationOutcome::Invalid,
            Err(_) => {
                if self.fail_open {
                    ValidationOutcome::Valid
                } else {
                    ValidationOutcome::Invalid
                }
            }
        }
    }
}

/// Resolve the validator host, enforce the same SSRF rules as webhook
/// delivery, then build a reqwest client with the resolved IP pinned via
/// `.resolve(host, ip)`. Reqwest will not re-query DNS for this client, so
/// a rebinding attack between build-time and request-time cannot win.
fn build_pinned_validator_client(endpoint: &Url, cfg: &ValidatorConfig) -> anyhow::Result<Client> {
    use std::net::ToSocketAddrs;

    let host = endpoint
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("validator endpoint has no host"))?;
    let port = endpoint.port_or_known_default().unwrap_or(443);
    let addrs: Vec<std::net::SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| anyhow::anyhow!("validator DNS resolve failed: {e}"))?
        .collect();
    if addrs.is_empty() {
        anyhow::bail!("validator endpoint resolved to zero addresses");
    }
    if !cfg.allow_private_targets {
        for addr in &addrs {
            if !crate::net::is_public_ip(&addr.ip()) {
                anyhow::bail!(
                    "validator endpoint resolved to a non-public address; refusing to build client"
                );
            }
        }
    }

    // `.no_proxy()` is essential: reqwest otherwise silently honors
    // `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` env vars, and a proxy set in the
    // container environment would route every outbound request through a host
    // that bypasses the SSRF-validated IP pin.
    let mut builder = Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(cfg.timeout_ms))
        .connect_timeout(Duration::from_millis(cfg.timeout_ms))
        .user_agent(concat!("simple-analytics/", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::none());
    for addr in &addrs {
        builder = builder.resolve(host, *addr);
    }
    builder
        .build()
        .map_err(|e| anyhow::anyhow!("build pinned validator client: {e}"))
}

/// Background task that periodically re-resolves the validator host and
/// swaps in a fresh pinned client. Short-lived loop spawned from `main` so
/// a DNS change at the operator's validator (IP rotation, cert migration,
/// re-IP) gets picked up without a restart.
pub async fn run_refresh_worker(
    validator: SharedValidator,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    if validator.inner.is_none() {
        // Supervise() flags an early Ok(()) return as a bug; park so a
        // config-disabled validator looks like a running worker.
        while !*shutdown.borrow() {
            if shutdown.changed().await.is_err() {
                return;
            }
        }
        return;
    }
    loop {
        let sleep = tokio::time::sleep(VALIDATOR_RESOLVE_REFRESH);
        tokio::pin!(sleep);
        tokio::select! {
            _ = &mut sleep => {
                validator.refresh_client().await;
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
        }
    }
}

/// Cheap Clone-able error used as the `try_get_with` Err type. Moka wraps it
/// in `Arc<E>` so the cost is per-lookup; the values are deliberately
/// unit-like so no URL / response data leaks into the shared type.
#[derive(Debug, Clone, Copy)]
enum ValidatorError {
    BadEndpoint,
    Transport,
    UnexpectedStatus,
}

impl std::fmt::Display for ValidatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BadEndpoint => "bad validator endpoint",
            Self::Transport => "validator transport error",
            Self::UnexpectedStatus => "validator unexpected status",
        })
    }
}

impl std::error::Error for ValidatorError {}

/// Type alias to expose `Arc<UrlValidator>` concisely in handlers.
pub type SharedValidator = Arc<UrlValidator>;
