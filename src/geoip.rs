use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

use anyhow::Context;
use maxminddb::Reader;

use crate::config::GeoIpConfig;

/// GeoIP country lookup, wrapping a MaxMind DB reader.
///
/// Opens the database once at startup and keeps it memory-mapped via
/// `Reader::open_readfile`. When disabled or unreachable it's a no-op — the
/// service never fails ingest because of geolocation.
pub struct GeoIp {
    reader: Option<Reader<Vec<u8>>>,
}

impl GeoIp {
    pub fn from_config(cfg: &GeoIpConfig) -> anyhow::Result<Self> {
        if !cfg.enabled {
            return Ok(Self { reader: None });
        }
        let path = cfg
            .database_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("geoip.database_path is required"))?;
        Self::open(path)
    }

    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let reader = Reader::open_readfile(path)
            .with_context(|| format!("failed to open GeoIP DB at {}", path.display()))?;
        Ok(Self {
            reader: Some(reader),
        })
    }

    pub fn disabled() -> Self {
        Self { reader: None }
    }

    pub fn is_enabled(&self) -> bool {
        self.reader.is_some()
    }

    /// Returns the uppercase 2-letter ISO country code for `ip`, or `None` if
    /// the DB isn't loaded, the IP can't be parsed, or the DB has no record.
    pub fn country_code(&self, ip: &str) -> Option<String> {
        let reader = self.reader.as_ref()?;
        let parsed = IpAddr::from_str(ip.trim()).ok()?;
        let lookup = reader.lookup(parsed).ok()?;
        if !lookup.has_data() {
            return None;
        }
        let iso: Option<String> = lookup
            .decode_path(&[
                maxminddb::PathElement::Key("country"),
                maxminddb::PathElement::Key("iso_code"),
            ])
            .ok()
            .flatten();
        iso.map(|s| s.to_ascii_uppercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_returns_none() {
        let g = GeoIp::disabled();
        assert!(!g.is_enabled());
        assert_eq!(g.country_code("1.2.3.4"), None);
    }

    #[test]
    fn disabled_config_yields_disabled() {
        let cfg = GeoIpConfig::default();
        let g = GeoIp::from_config(&cfg).unwrap();
        assert!(!g.is_enabled());
    }
}
