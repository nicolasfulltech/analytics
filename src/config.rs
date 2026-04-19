use std::fmt;
use std::path::PathBuf;

use figment::Figment;
use figment::providers::{Env, Format, Toml};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub ingest: IngestConfig,
    #[serde(default)]
    pub validator: ValidatorConfig,
    #[serde(default)]
    pub webhooks: WebhooksConfig,
    #[serde(default)]
    pub materialization: MaterializationConfig,
    #[serde(default)]
    pub sessions: SessionsConfig,
    #[serde(default)]
    pub backup: BackupConfig,
    #[serde(default)]
    pub endpoints: EndpointsConfig,
    #[serde(default)]
    pub geoip: GeoIpConfig,
    #[serde(default)]
    pub privacy: PrivacyConfig,
    #[serde(default)]
    pub retention: RetentionConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_body_limit")]
    pub max_body_bytes: usize,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_ms: u64,
    /// Cap on simultaneous `/export` streams. Each export pins a SQLite
    /// connection for up to `export_deadline_secs`; with the default pool
    /// of 8, a handful of slow readers would starve every other DB call.
    #[serde(default = "default_export_concurrency")]
    pub export_concurrency: usize,
    /// Per-stream ceiling (seconds) for `/export`. Shorter = less damage a
    /// slow/backpressured client can cause; too short truncates big exports.
    #[serde(default = "default_export_deadline_secs")]
    pub export_deadline_secs: u64,
    /// Default window (days) applied to `/stats/*` endpoints that read raw
    /// events when the caller didn't pass `from`/`to`. Bounds the cost of
    /// a naked `/stats/pages` etc. call: without a window, those queries
    /// do a full-table scan with `COUNT(DISTINCT)` and pin a pool connection.
    #[serde(default = "default_stats_default_range_days")]
    pub stats_default_range_days: u32,
    /// Hard maximum window (days) for `/stats/*`. A caller who passes a
    /// `from`/`to` wider than this gets `400`. Prevents a single request
    /// from scanning the whole history when retention is long.
    #[serde(default = "default_stats_max_range_days")]
    pub stats_max_range_days: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            max_body_bytes: default_body_limit(),
            request_timeout_ms: default_request_timeout(),
            export_concurrency: default_export_concurrency(),
            export_deadline_secs: default_export_deadline_secs(),
            stats_default_range_days: default_stats_default_range_days(),
            stats_max_range_days: default_stats_max_range_days(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_db_path")]
    pub path: PathBuf,
    #[serde(default = "default_pool_max")]
    pub max_connections: u32,
    /// How often the background task runs `PRAGMA wal_checkpoint(TRUNCATE)`.
    /// The default PASSIVE auto-checkpoint can't truncate the WAL while any
    /// reader is open, so under sustained ingest the WAL grows unbounded.
    /// A periodic TRUNCATE keeps it capped. 0 disables the worker (don't —
    /// the WAL will grow forever).
    #[serde(default = "default_wal_checkpoint_interval")]
    pub wal_checkpoint_interval_secs: u64,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: default_db_path(),
            max_connections: default_pool_max(),
            wal_checkpoint_interval_secs: default_wal_checkpoint_interval(),
        }
    }
}

#[derive(Clone, Deserialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub write_keys: Vec<String>,
    #[serde(default)]
    pub read_keys: Vec<String>,
    #[serde(default)]
    pub admin_keys: Vec<String>,
    #[serde(default)]
    pub site_token: String,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Secret used to HMAC-sign caller-supplied user objects. When set, events
    /// may carry a signed `user` blob; clients without the secret cannot forge
    /// attribution. Leave empty to disable user attribution entirely.
    #[serde(default)]
    pub user_signing_secret: String,
    /// Max age (seconds) for a signed `user` payload's `iat` field. Captured
    /// tokens become useless outside this window — an attacker replaying a
    /// sniffed `user` + `user_sig` pair past the window gets a 401 the same
    /// way a bad signature does. 0 disables the age check (don't — that makes
    /// intercepted tokens valid forever).
    #[serde(default = "default_user_token_max_age")]
    pub user_token_max_age_secs: u64,
    /// IP / CIDR allowlist for admin endpoints (`/webhooks*`,
    /// `DELETE /events`). Empty = no allowlist (any IP can hit admin
    /// routes if it has the key). When set, requests from outside the list
    /// get `403` BEFORE the key check — a leaked admin key is still bounded
    /// to your office / VPN / jump-host subnet. IPv4 and IPv6 supported.
    #[serde(default)]
    pub admin_ip_allowlist: Vec<String>,
}

impl fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthConfig")
            .field(
                "write_keys",
                &format!("[{} key(s) redacted]", self.write_keys.len()),
            )
            .field(
                "read_keys",
                &format!("[{} key(s) redacted]", self.read_keys.len()),
            )
            .field(
                "admin_keys",
                &format!("[{} key(s) redacted]", self.admin_keys.len()),
            )
            .field(
                "site_token",
                &(if self.site_token.is_empty() {
                    "[empty]"
                } else {
                    "[redacted]"
                }),
            )
            .field("allowed_origins", &self.allowed_origins)
            .field(
                "user_signing_secret",
                &(if self.user_signing_secret.is_empty() {
                    "[empty]"
                } else {
                    "[redacted]"
                }),
            )
            .field("admin_ip_allowlist", &self.admin_ip_allowlist)
            .field("user_token_max_age_secs", &self.user_token_max_age_secs)
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct IngestConfig {
    #[serde(default)]
    pub allowed_segments: Vec<String>,
    #[serde(default)]
    pub allow_unknown_segments: bool,
    #[serde(default = "default_browser_rate_per_min")]
    pub browser_rate_limit_per_min: u32,
    #[serde(default = "default_browser_burst")]
    pub browser_rate_limit_burst: u32,
    /// Global-per-site-token cap on the browser beacon. The per-IP limiter
    /// caps one browser; this caps what any attacker rotating IPs can drive
    /// through a single leaked site_token.
    #[serde(default = "default_beacon_token_rate_per_min")]
    pub beacon_token_rate_limit_per_min: u32,
    #[serde(default = "default_beacon_token_burst")]
    pub beacon_token_rate_limit_burst: u32,
    /// Server-side ingest rate limit bucket PER WRITE KEY. Defends against a
    /// leaked key being used to flood the DB. 0 disables (not recommended).
    #[serde(default = "default_server_rate_per_min")]
    pub server_rate_limit_per_min: u32,
    #[serde(default = "default_server_burst")]
    pub server_rate_limit_burst: u32,
    /// Per-read-key cap for /events, /stats, /export. Stops a leaked read key
    /// from streaming the entire event table in a tight loop.
    #[serde(default = "default_read_rate_per_min")]
    pub read_rate_limit_per_min: u32,
    #[serde(default = "default_read_burst")]
    pub read_rate_limit_burst: u32,
    /// Pre-auth per-IP cap on all authenticated endpoints. Applied BEFORE
    /// the auth-key check, so an attacker probing keys can't distinguish
    /// "wrong key" (401) from "valid key, per-key bucket hit" (429) by the
    /// status code — both collapse into 429 once this bucket is hit. Set
    /// generously: legitimate traffic from one IP shouldn't approach it.
    #[serde(default = "default_auth_ip_rate_per_min")]
    pub auth_ip_rate_limit_per_min: u32,
    #[serde(default = "default_auth_ip_burst")]
    pub auth_ip_rate_limit_burst: u32,
    #[serde(default)]
    pub trust_proxy: bool,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            allowed_segments: Vec::new(),
            allow_unknown_segments: false,
            browser_rate_limit_per_min: default_browser_rate_per_min(),
            browser_rate_limit_burst: default_browser_burst(),
            beacon_token_rate_limit_per_min: default_beacon_token_rate_per_min(),
            beacon_token_rate_limit_burst: default_beacon_token_burst(),
            server_rate_limit_per_min: default_server_rate_per_min(),
            server_rate_limit_burst: default_server_burst(),
            read_rate_limit_per_min: default_read_rate_per_min(),
            read_rate_limit_burst: default_read_burst(),
            auth_ip_rate_limit_per_min: default_auth_ip_rate_per_min(),
            auth_ip_rate_limit_burst: default_auth_ip_burst(),
            trust_proxy: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValidatorConfig {
    pub url: Option<String>,
    #[serde(default = "default_validator_cache_ttl")]
    pub cache_ttl_secs: u64,
    #[serde(default = "default_validator_cache_size")]
    pub cache_size: u64,
    #[serde(default = "default_validator_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_fail_open")]
    pub fail_open: bool,
    /// Mirrors `webhooks.allow_private_targets`. Off by default so a
    /// misconfigured validator URL can't be used as an SSRF pivot.
    #[serde(default)]
    pub allow_private_targets: bool,
}

impl Default for ValidatorConfig {
    fn default() -> Self {
        Self {
            url: None,
            cache_ttl_secs: default_validator_cache_ttl(),
            cache_size: default_validator_cache_size(),
            timeout_ms: default_validator_timeout(),
            fail_open: default_fail_open(),
            allow_private_targets: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebhooksConfig {
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    #[serde(default = "default_retry_base_ms")]
    pub retry_base_ms: u64,
    #[serde(default = "default_webhook_concurrency")]
    pub concurrency: usize,
    #[serde(default = "default_webhook_delivery_timeout")]
    pub delivery_timeout_ms: u64,
    /// DANGEROUS — only enable if you run analytics and subscribers in the
    /// same trusted private network. When false (default), webhook URLs that
    /// resolve to loopback, RFC-1918, link-local, or cloud-metadata ranges are
    /// rejected to prevent SSRF from a compromised admin key.
    #[serde(default)]
    pub allow_private_targets: bool,
    /// Upper bound on rows in `status='pending'`. When the queue hits this
    /// cap, new deliveries stop being enqueued until the worker drains the
    /// backlog — a failing subscriber can't grow the table without bound.
    /// 0 disables the cap (not recommended).
    #[serde(default = "default_max_pending_deliveries")]
    pub max_pending_deliveries: u64,
    /// Retention for `status='pending'` rows that have given up retrying.
    /// Unlike `delivered`/`failed` which are pruned by the retention worker,
    /// stuck-pending rows (e.g. orphaned by a subscriber delete that races
    /// the worker) need their own sweep. 0 disables.
    #[serde(default = "default_pending_max_age_hours")]
    pub pending_max_age_hours: u32,
    /// Upper bound on the number of webhook subscribers. Creates past this
    /// cap get a 400. An admin-key holder who registers many subscribers can
    /// fan-out a single event into many deliveries and fill
    /// `max_pending_deliveries`; this bounds that fan-out. 0 disables.
    #[serde(default = "default_max_webhooks")]
    pub max_webhooks: u32,
}

impl Default for WebhooksConfig {
    fn default() -> Self {
        Self {
            max_retries: default_max_retries(),
            retry_base_ms: default_retry_base_ms(),
            concurrency: default_webhook_concurrency(),
            delivery_timeout_ms: default_webhook_delivery_timeout(),
            allow_private_targets: false,
            max_pending_deliveries: default_max_pending_deliveries(),
            pending_max_age_hours: default_pending_max_age_hours(),
            max_webhooks: default_max_webhooks(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct MaterializationConfig {
    #[serde(default = "default_materialize_interval")]
    pub interval_secs: u64,
}

impl Default for MaterializationConfig {
    fn default() -> Self {
        Self {
            interval_secs: default_materialize_interval(),
        }
    }
}

/// Sessions: events from the same visitor within `idle_timeout_mins` belong
/// to the same session; a longer gap mints a new one. Industry-standard
/// default is 30 min (Google Analytics parity).
#[derive(Debug, Clone, Deserialize)]
pub struct SessionsConfig {
    #[serde(default = "default_session_idle_timeout")]
    pub idle_timeout_mins: u32,
}

impl Default for SessionsConfig {
    fn default() -> Self {
        Self {
            idle_timeout_mins: default_session_idle_timeout(),
        }
    }
}

/// Periodic snapshot of the SQLite DB to a backup directory.
/// `VACUUM INTO` is used (not a file copy) so the output is consistent
/// without locking ingest. Oldest snapshots get pruned when the dir
/// exceeds `keep_count`.
#[derive(Debug, Clone, Deserialize)]
pub struct BackupConfig {
    /// Where snapshots get written. Empty string disables the worker.
    #[serde(default)]
    pub path: String,
    /// Run interval in hours. 0 disables.
    #[serde(default = "default_backup_interval_hours")]
    pub interval_hours: u32,
    /// Max snapshots to retain; oldest pruned on each tick.
    #[serde(default = "default_backup_keep")]
    pub keep_count: u32,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            path: String::new(),
            interval_hours: default_backup_interval_hours(),
            keep_count: default_backup_keep(),
        }
    }
}

/// Customizes the browser-facing URL paths / header names so the service
/// doesn't match common blocklist patterns (`/beacon`, `/analytics`, etc.).
/// Server-to-server routes (`/collect`, `/stats`, `/webhooks`, …) aren't here
/// because ad-blockers don't see them.
#[derive(Debug, Clone, Deserialize)]
pub struct EndpointsConfig {
    #[serde(default = "default_browser_collect_path")]
    pub browser_collect_path: String,
    #[serde(default = "default_browser_script_path")]
    pub browser_script_path: String,
    #[serde(default = "default_browser_token_header")]
    pub browser_token_header: String,
    #[serde(default = "default_js_namespace")]
    pub js_namespace: String,
}

impl Default for EndpointsConfig {
    fn default() -> Self {
        Self {
            browser_collect_path: default_browser_collect_path(),
            browser_script_path: default_browser_script_path(),
            browser_token_header: default_browser_token_header(),
            js_namespace: default_js_namespace(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct GeoIpConfig {
    #[serde(default)]
    pub enabled: bool,
    pub database_path: Option<PathBuf>,
}

/// Output-shape privacy knobs. Default is the conservative option —
/// visitor_hash is a stable cross-session identifier that a leaked read key
/// would turn into a full visitor-activity graph.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PrivacyConfig {
    /// When false (default), `visitor_hash` is omitted from `/events` and
    /// `/export` responses. Set true only if your dashboard genuinely needs
    /// per-visitor correlation AND you trust every read-key holder with
    /// that level of detail.
    #[serde(default)]
    pub expose_visitor_hash: bool,
    /// When false (default), the full signed `user` JSON object is stripped
    /// from webhook payloads (only `user_id` is kept). Set true only when
    /// every subscriber is trusted with the full user record (name / email
    /// / plan / whatever the operator embedded at sign time). `/events` and
    /// `/export` are separately gated by read-key access.
    #[serde(default)]
    pub expose_user_payload: bool,
}

/// How long to keep time-series data before the retention worker deletes
/// it. `0` for any field disables deletion for that table.
#[derive(Debug, Clone, Deserialize)]
pub struct RetentionConfig {
    /// Delete raw events older than this. 0 = keep forever.
    #[serde(default = "default_retention_events_days")]
    pub events_days: u32,
    /// Delete delivered/failed webhook delivery rows older than this.
    /// `pending` rows are never pruned by retention.
    #[serde(default = "default_retention_deliveries_days")]
    pub webhook_deliveries_days: u32,
    /// Keep daily aggregate rollups at most this long.
    #[serde(default = "default_retention_agg_days")]
    pub agg_daily_days: u32,
    /// How often the retention sweep runs.
    #[serde(default = "default_retention_interval_secs")]
    pub interval_secs: u64,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            events_days: default_retention_events_days(),
            webhook_deliveries_days: default_retention_deliveries_days(),
            agg_daily_days: default_retention_agg_days(),
            interval_secs: default_retention_interval_secs(),
        }
    }
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config.toml".into());

        let cfg: Self = Figment::new()
            .merge(Toml::file(path))
            .merge(Env::prefixed("ANALYTICS_").split("__"))
            .extract()?;

        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.auth.write_keys.is_empty() {
            anyhow::bail!("auth.write_keys must contain at least one key");
        }
        if self.auth.read_keys.is_empty() {
            anyhow::bail!("auth.read_keys must contain at least one key");
        }
        if self.auth.admin_keys.is_empty() {
            anyhow::bail!("auth.admin_keys must contain at least one key");
        }

        let short = self
            .auth
            .write_keys
            .iter()
            .chain(&self.auth.read_keys)
            .chain(&self.auth.admin_keys)
            .any(|k| k.len() < 32);
        if short {
            anyhow::bail!("all API keys must be at least 32 characters");
        }

        // Reject the placeholders from `config.example.toml` outright. They
        // pass the 32-char length check but would be a catastrophic default
        // if an operator copied the example and forgot to replace them.
        let placeholder = self
            .auth
            .write_keys
            .iter()
            .chain(&self.auth.read_keys)
            .chain(&self.auth.admin_keys)
            .chain(std::iter::once(&self.auth.user_signing_secret))
            .any(|k| k.starts_with("REPLACE-") || k.starts_with("CHANGEME"));
        if placeholder {
            anyhow::bail!(
                "API keys / secrets use the config.example.toml placeholder — \
                 replace with real random keys (e.g. `openssl rand -hex 32`)"
            );
        }

        // site_token is optional (browser beacon opt-in). When set, it must be a
        // strong public token (≥16 chars) AND the Origin allowlist must be set —
        // otherwise the browser endpoint would be open to any origin.
        if !self.auth.site_token.is_empty() {
            if self.auth.site_token.len() < 16 {
                anyhow::bail!("auth.site_token must be at least 16 characters when set");
            }
            if self.auth.allowed_origins.is_empty() {
                anyhow::bail!(
                    "auth.allowed_origins must be set when auth.site_token is configured"
                );
            }
        }

        // Validate each allowed origin parses as scheme+host[:port]. Rejects
        // typos like "example.com" (no scheme) and the literal "null" (an
        // attacker can always send Origin: null from sandboxed iframes or
        // cross-origin redirects — it's never a real trusted origin).
        for origin in &self.auth.allowed_origins {
            if origin.eq_ignore_ascii_case("null") {
                anyhow::bail!(
                    "auth.allowed_origins must not contain 'null' — see README on browser Origin"
                );
            }
            let parsed = url::Url::parse(origin)
                .map_err(|e| anyhow::anyhow!("auth.allowed_origins entry {origin:?}: {e}"))?;
            if !matches!(parsed.scheme(), "http" | "https") {
                anyhow::bail!("auth.allowed_origins entry {origin:?} must use http(s) scheme");
            }
            if parsed.host_str().is_none() {
                anyhow::bail!("auth.allowed_origins entry {origin:?} must include a host");
            }
            // Origins have no path — `https://example.com/foo` would never
            // match a browser's real Origin header.
            if !matches!(parsed.path(), "" | "/") {
                anyhow::bail!(
                    "auth.allowed_origins entry {origin:?} must not include a path (scheme+host[:port] only)"
                );
            }
        }

        if !self.auth.user_signing_secret.is_empty() && self.auth.user_signing_secret.len() < 32 {
            anyhow::bail!("auth.user_signing_secret must be at least 32 characters when set");
        }

        // Every admin_ip_allowlist entry must parse as either a bare IP or a
        // CIDR (`<ip>/<prefix>`). Reject at startup so a typo doesn't silently
        // disable admin access. Bound the prefix per address family: a `/33`
        // on IPv4 would wrap to a mask of 0 at runtime (`u32::MAX << -1`),
        // silently turning "10.0.0.0/33" into "allow every IPv4".
        for entry in &self.auth.admin_ip_allowlist {
            let ok = match entry.split_once('/') {
                Some((net, prefix)) => {
                    let ip = net.parse::<std::net::IpAddr>().ok();
                    let p = prefix.parse::<u8>().ok();
                    match (ip, p) {
                        (Some(std::net::IpAddr::V4(_)), Some(p)) => p <= 32,
                        (Some(std::net::IpAddr::V6(_)), Some(p)) => p <= 128,
                        _ => false,
                    }
                }
                None => entry.parse::<std::net::IpAddr>().is_ok(),
            };
            if !ok {
                anyhow::bail!(
                    "auth.admin_ip_allowlist entry {entry:?} must be an IP or CIDR (e.g. 10.0.0.0/8)"
                );
            }
        }

        // Values below land verbatim in the browser snippet and/or HTTP
        // routing, so we enforce tight character whitelists to keep an
        // operator's typo (or a hostile config reviewer) from turning into
        // script-content injection or a weird route.
        for (field, value) in [
            ("browser_collect_path", &self.endpoints.browser_collect_path),
            ("browser_script_path", &self.endpoints.browser_script_path),
        ] {
            if !value.starts_with('/') {
                anyhow::bail!("endpoints.{field} must start with '/'");
            }
            if value.len() > 64
                || !value[1..]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/'))
            {
                anyhow::bail!(
                    "endpoints.{field} must be ≤64 chars of [A-Za-z0-9_-./] after the leading /"
                );
            }
            // Reject `.` / `..` path segments. These confuse browser relative-
            // URL normalization and axum route registration.
            if value.split('/').any(|seg| seg == "." || seg == "..") {
                anyhow::bail!("endpoints.{field} must not contain '.' or '..' path segments");
            }
        }
        if !is_http_token(&self.endpoints.browser_token_header) {
            anyhow::bail!(
                "endpoints.browser_token_header must be a valid HTTP token (letters, digits, and !#$%&'*+-.^_`|~)"
            );
        }
        if !is_js_identifier(&self.endpoints.js_namespace) {
            anyhow::bail!(
                "endpoints.js_namespace must be a valid JS identifier (ASCII, no operators)"
            );
        }

        if self.geoip.enabled && self.geoip.database_path.is_none() {
            anyhow::bail!("geoip.database_path is required when geoip.enabled = true");
        }

        // Validator URL is operator-set but it's an outbound target on every
        // ingest call — treat it like a webhook target and block private
        // ranges unless opted in.
        if let Some(url_str) = &self.validator.url {
            crate::net::validate_webhook_url(url_str, self.validator.allow_private_targets)
                .map_err(|e| anyhow::anyhow!("validator.url: {e}"))?;
        }

        // Bound retry_base_ms so the `base * 2^attempts` doubling in the
        // delivery worker can't overflow i64 math and wrap into a past
        // timestamp (which would spin the retry loop at max speed).
        // 1 hour is generous; anything beyond is an operator foot-gun.
        if self.webhooks.retry_base_ms > 3_600_000 {
            anyhow::bail!("webhooks.retry_base_ms must be ≤ 3_600_000 (1 hour)");
        }

        // `backup.path` is interpolated (unparameterizable) into a
        // `VACUUM INTO '...'` statement at snapshot time. Validate the
        // allowed character set at startup so a typo fails fast rather than
        // surfacing on the first backup tick. Mirrors the runtime allowlist
        // in backup::snapshot.
        if self.backup.interval_hours > 0
            && !self.backup.path.is_empty()
            && !self
                .backup
                .path
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '.' | '-'))
        {
            anyhow::bail!(
                "backup.path must contain only [A-Za-z0-9/_.-]; got {:?}",
                self.backup.path
            );
        }

        if self.server.export_concurrency == 0 {
            anyhow::bail!("server.export_concurrency must be ≥ 1");
        }
        if self.server.export_deadline_secs == 0 {
            anyhow::bail!("server.export_deadline_secs must be ≥ 1");
        }

        if self.server.stats_default_range_days == 0
            || self.server.stats_max_range_days == 0
            || self.server.stats_default_range_days > self.server.stats_max_range_days
        {
            anyhow::bail!(
                "server.stats_default_range_days and stats_max_range_days must be ≥ 1, with default ≤ max"
            );
        }

        Ok(())
    }

    pub fn browser_enabled(&self) -> bool {
        !self.auth.site_token.is_empty() && !self.auth.allowed_origins.is_empty()
    }

    pub fn user_attribution_enabled(&self) -> bool {
        !self.auth.user_signing_secret.is_empty()
    }
}

fn default_bind() -> String {
    "0.0.0.0:8080".into()
}
fn default_body_limit() -> usize {
    64 * 1024
}
fn default_request_timeout() -> u64 {
    10_000
}
fn default_db_path() -> PathBuf {
    PathBuf::from("./data/analytics.db")
}
fn default_pool_max() -> u32 {
    8
}
fn default_wal_checkpoint_interval() -> u64 {
    60
}
fn default_browser_rate_per_min() -> u32 {
    120
}
fn default_browser_burst() -> u32 {
    30
}
fn default_beacon_token_rate_per_min() -> u32 {
    // Global cap across all browsers sharing the site_token. Even if an
    // attacker rotates through a huge IP pool, this caps the aggregate.
    60_000
}
fn default_beacon_token_burst() -> u32 {
    5_000
}
fn default_read_rate_per_min() -> u32 {
    // 120/min ≈ 2/sec — legitimate dashboards poll a handful of times per
    // page. A leaked read key can burst but can't sustain a table dump.
    120
}
fn default_read_burst() -> u32 {
    60
}
fn default_retention_events_days() -> u32 {
    // 0 = disabled. Operators opt in — retention is a business decision.
    0
}
fn default_retention_deliveries_days() -> u32 {
    30
}
fn default_retention_agg_days() -> u32 {
    // Aggregates are cheap; default longer than raw events.
    365
}
fn default_retention_interval_secs() -> u64 {
    // Every 6 hours. Fine for a sweep that deletes by timestamp index.
    6 * 3600
}
fn default_user_token_max_age() -> u64 {
    // 15 minutes. Long enough that ordinary clock skew + page-load latency
    // never trips it; short enough that a sniffed token is near-useless.
    // Callers that need a longer window can raise this explicitly.
    900
}
fn default_auth_ip_rate_per_min() -> u32 {
    // 60k/min = 1k/sec per IP. A legitimate server batching to /collect
    // rarely approaches this; an attacker probing stolen keys from one IP
    // definitely will. Set high enough to never bite real traffic.
    60_000
}
fn default_auth_ip_burst() -> u32 {
    5_000
}
fn default_export_concurrency() -> usize {
    2
}
fn default_export_deadline_secs() -> u64 {
    60
}
fn default_stats_default_range_days() -> u32 {
    30
}
fn default_stats_max_range_days() -> u32 {
    365
}
fn default_max_pending_deliveries() -> u64 {
    // A single subscriber failing permanently at 100 events/s would hit
    // this in ~30 minutes — long enough for alerting, short enough that the
    // table doesn't eat disk. Operators who ingest higher volume should
    // raise this along with pool size.
    200_000
}
fn default_max_webhooks() -> u32 {
    // 50 is generous — most deployments have 1-5 subscribers. Operators
    // with genuine bulk fan-out can raise this explicitly. The cap exists
    // so a compromised admin key can't register thousands of endpoints to
    // amplify ingest volume.
    50
}
fn default_pending_max_age_hours() -> u32 {
    // Beyond the final backoff window (`retry_base * 2^max_retries`), the
    // row is a zombie — the worker has long since marked it failed or the
    // process crashed mid-claim. 72h is comfortably past any reasonable
    // retry schedule.
    72
}
fn default_server_rate_per_min() -> u32 {
    // Server-side callers (PHP/Node/etc) typically batch within normal rates.
    // 6k/min ≈ 100/sec/key gives plenty of headroom for legitimate traffic,
    // and acts as a belt-and-suspenders cap if a write_key ever leaks.
    6_000
}
fn default_server_burst() -> u32 {
    500
}
fn default_validator_cache_ttl() -> u64 {
    3_600
}
fn default_validator_cache_size() -> u64 {
    10_000
}
fn default_validator_timeout() -> u64 {
    500
}
fn default_fail_open() -> bool {
    // Fail closed by default: if the operator configured a validator URL and
    // it's unreachable, events that would have been rejected should keep
    // being rejected rather than silently flooding through during a validator
    // outage. Operators who want "best-effort validation" can opt in.
    false
}
fn default_max_retries() -> u32 {
    8
}
fn default_retry_base_ms() -> u64 {
    1_000
}
fn default_webhook_concurrency() -> usize {
    4
}
fn default_webhook_delivery_timeout() -> u64 {
    5_000
}
fn default_materialize_interval() -> u64 {
    300
}
fn default_session_idle_timeout() -> u32 {
    30
}
fn default_backup_interval_hours() -> u32 {
    24
}
fn default_backup_keep() -> u32 {
    7
}
fn default_browser_collect_path() -> String {
    "/e".into()
}
fn default_browser_script_path() -> String {
    "/s.js".into()
}
fn default_browser_token_header() -> String {
    "x-id".into()
}
fn default_js_namespace() -> String {
    "sa".into()
}

fn is_http_token(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 {
        return false;
    }
    s.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            )
    })
}

fn is_js_identifier(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 {
        return false;
    }
    let mut chars = s.bytes();
    let first = chars.next().unwrap();
    if !(first.is_ascii_alphabetic() || first == b'_' || first == b'$') {
        return false;
    }
    chars.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Config {
        Config {
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            auth: AuthConfig {
                write_keys: vec!["a".repeat(32)],
                read_keys: vec!["b".repeat(32)],
                admin_keys: vec!["c".repeat(32)],
                site_token: String::new(),
                allowed_origins: vec![],
                user_signing_secret: String::new(),
                admin_ip_allowlist: vec![],
                user_token_max_age_secs: default_user_token_max_age(),
            },
            ingest: IngestConfig::default(),
            validator: ValidatorConfig::default(),
            webhooks: WebhooksConfig::default(),
            materialization: MaterializationConfig::default(),
            sessions: SessionsConfig::default(),
            backup: BackupConfig::default(),
            endpoints: EndpointsConfig::default(),
            geoip: GeoIpConfig::default(),
            privacy: PrivacyConfig::default(),
            retention: RetentionConfig::default(),
        }
    }

    #[test]
    fn rejects_path_with_dot_dot_segment() {
        let mut c = base();
        c.endpoints.browser_collect_path = "/../admin".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_path_with_dot_segment() {
        let mut c = base();
        c.endpoints.browser_collect_path = "/./admin".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn accepts_nested_normal_path() {
        let mut c = base();
        c.endpoints.browser_collect_path = "/api/v1/events".into();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn rejects_non_identifier_js_namespace() {
        let mut c = base();
        c.endpoints.js_namespace = "\"; alert(1); //".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_non_http_token_header() {
        let mut c = base();
        c.endpoints.browser_token_header = "bad header".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_origin_null() {
        let mut c = base();
        c.auth.site_token = "x".repeat(16);
        c.auth.allowed_origins = vec!["null".into()];
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_origin_without_scheme() {
        let mut c = base();
        c.auth.site_token = "x".repeat(16);
        c.auth.allowed_origins = vec!["example.com".into()];
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_origin_with_path() {
        let mut c = base();
        c.auth.site_token = "x".repeat(16);
        c.auth.allowed_origins = vec!["https://example.com/app".into()];
        assert!(c.validate().is_err());
    }

    #[test]
    fn accepts_valid_origin() {
        let mut c = base();
        c.auth.site_token = "x".repeat(16);
        c.auth.allowed_origins = vec!["https://example.com".into()];
        assert!(c.validate().is_ok());
    }

    #[test]
    fn rejects_oversized_retry_base_ms() {
        let mut c = base();
        c.webhooks.retry_base_ms = 4_000_000;
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_zero_export_concurrency() {
        let mut c = base();
        c.server.export_concurrency = 0;
        assert!(c.validate().is_err());
    }
}
