use std::sync::Arc;

use sqlx::SqlitePool;
use tokio::sync::{Notify, Semaphore};

use crate::config::Config;
use crate::geoip::GeoIp;
use crate::hot_reload;
use crate::ingest::validator::UrlValidator;
use crate::metrics::Metrics;
use crate::rate_limit::RateLimiter;
use crate::sessions::SessionAssigner;
use crate::visitor::SaltStore;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub pool: SqlitePool,
    pub salts: Arc<SaltStore>,
    pub validator: Arc<UrlValidator>,
    pub delivery_notify: Arc<Notify>,
    /// Per-IP cap on the browser beacon. Caps one browser.
    pub beacon_limiter: Arc<RateLimiter>,
    /// Global cap across all browsers sharing the site_token. Caps an
    /// attacker who rotates through an IP pool with a leaked token.
    pub beacon_token_limiter: Arc<RateLimiter>,
    /// Per-write-key rate limit for server-side ingest. Complements the
    /// beacon (per-IP) limiter and protects against leaked write keys.
    pub write_key_limiter: Arc<RateLimiter>,
    /// Per-read-key rate limit on /events, /stats, /export. Stops a leaked
    /// read key from streaming the entire event table in a tight loop.
    pub read_key_limiter: Arc<RateLimiter>,
    /// Pre-auth per-IP cap that runs BEFORE the auth-key check on all
    /// authenticated endpoints. Without this, an attacker can distinguish
    /// "invalid key" (401) from "valid key, rate-limited" (429) and
    /// brute-force key enumeration under legitimate load. With it, both
    /// paths observe a uniform 429 once the IP's bucket is drained.
    pub auth_ip_limiter: Arc<RateLimiter>,
    /// Bounds simultaneous /export streams so slow readers can't pin all
    /// DB connections.
    pub export_semaphore: Arc<Semaphore>,
    pub geoip: Arc<GeoIp>,
    pub session_assigner: Arc<SessionAssigner>,
    pub metrics: Arc<Metrics>,
    /// Subset of config fields that SIGHUP can swap at runtime without a
    /// restart. Read on the hot path via `.load()`; see `hot_reload` module.
    pub reloadable: hot_reload::Handle,
}

impl AppState {
    pub async fn new(config: Arc<Config>, pool: SqlitePool) -> anyhow::Result<Self> {
        let salts = Arc::new(SaltStore::new(pool.clone()).await?);
        let validator = Arc::new(UrlValidator::new(&config.validator));
        let delivery_notify = Arc::new(Notify::new());
        let beacon_limiter = Arc::new(RateLimiter::new(
            config.ingest.browser_rate_limit_per_min,
            config.ingest.browser_rate_limit_burst,
        ));
        let beacon_token_limiter = Arc::new(RateLimiter::new(
            config.ingest.beacon_token_rate_limit_per_min,
            config.ingest.beacon_token_rate_limit_burst,
        ));
        let write_key_limiter = Arc::new(RateLimiter::new(
            config.ingest.server_rate_limit_per_min,
            config.ingest.server_rate_limit_burst,
        ));
        let read_key_limiter = Arc::new(RateLimiter::new(
            config.ingest.read_rate_limit_per_min,
            config.ingest.read_rate_limit_burst,
        ));
        let auth_ip_limiter = Arc::new(RateLimiter::new(
            config.ingest.auth_ip_rate_limit_per_min,
            config.ingest.auth_ip_rate_limit_burst,
        ));
        let export_semaphore = Arc::new(Semaphore::new(config.server.export_concurrency));
        let geoip = Arc::new(GeoIp::from_config(&config.geoip)?);
        let session_assigner = Arc::new(SessionAssigner::new(
            pool.clone(),
            config.sessions.idle_timeout_mins,
        ));
        let metrics = Arc::new(Metrics::new());
        let reloadable = hot_reload::new_handle(&config);

        Ok(Self {
            config,
            pool,
            salts,
            validator,
            delivery_notify,
            beacon_limiter,
            beacon_token_limiter,
            write_key_limiter,
            read_key_limiter,
            auth_ip_limiter,
            export_semaphore,
            geoip,
            session_assigner,
            metrics,
            reloadable,
        })
    }
}
