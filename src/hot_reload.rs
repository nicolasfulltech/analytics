//! Hot-reloadable subset of the config.
//!
//! On `SIGHUP` the process re-reads its config file and swaps these fields
//! in-place without dropping connections. Only fields that are safe to
//! change at runtime live here: auth keys (rotation), origin allowlist
//! (adding a new domain), segment allowlist (adding a new tag). Everything
//! else (DB path, listen address, endpoint paths) requires a restart.
//!
//! Uses `arc-swap` because reads happen on every authenticated request —
//! an `RwLock` would serialize them, and moka's `Cache::get` is already on
//! that hot path. `ArcSwap::load` is a relaxed atomic load with no
//! contention.

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::config::Config;

/// Snapshot of config fields that can be hot-reloaded. Cloned into an
/// `Arc` and published via `ArcSwap` so reads never block.
///
/// `Debug` is hand-written so a `tracing::debug!(config = ?snap, …)` call
/// site can't accidentally leak plaintext API keys through the log pipeline.
/// `AuthConfig` does the same thing; keep them in sync when adding fields.
#[derive(Clone)]
pub struct ReloadableConfig {
    pub write_keys: Vec<String>,
    pub read_keys: Vec<String>,
    pub admin_keys: Vec<String>,
    pub allowed_origins: Vec<String>,
    pub allowed_segments: HashSet<String>,
    pub allow_unknown_segments: bool,
}

impl fmt::Debug for ReloadableConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReloadableConfig")
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
            .field("allowed_origins", &self.allowed_origins)
            .field("allowed_segments", &self.allowed_segments)
            .field("allow_unknown_segments", &self.allow_unknown_segments)
            .finish()
    }
}

impl ReloadableConfig {
    pub fn from_config(c: &Config) -> Self {
        Self {
            write_keys: c.auth.write_keys.clone(),
            read_keys: c.auth.read_keys.clone(),
            admin_keys: c.auth.admin_keys.clone(),
            allowed_origins: c.auth.allowed_origins.clone(),
            allowed_segments: c.ingest.allowed_segments.iter().cloned().collect(),
            allow_unknown_segments: c.ingest.allow_unknown_segments,
        }
    }
}

/// Shared handle. Clone is cheap (just the Arc).
pub type Handle = Arc<ArcSwap<ReloadableConfig>>;

pub fn new_handle(cfg: &Config) -> Handle {
    Arc::new(ArcSwap::from_pointee(ReloadableConfig::from_config(cfg)))
}

/// Re-load the config file from disk and publish the new snapshot.
/// Returns the parsed `Config` so the caller can log a diff if it wants.
/// Validation failures leave the old snapshot in place.
pub fn reload(handle: &Handle) -> anyhow::Result<Config> {
    let new_cfg = Config::load()?;
    handle.store(Arc::new(ReloadableConfig::from_config(&new_cfg)));
    Ok(new_cfg)
}
