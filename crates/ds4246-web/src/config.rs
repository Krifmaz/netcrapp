use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// LAN address to listen on, e.g. "192.168.1.10:8446".
    pub bind: SocketAddr,
    /// argon2 PHC string from `ds4246-web hash-password`.
    pub password_hash: String,
    #[serde(default = "default_dump_dir")]
    pub dump_dir: PathBuf,
    /// Seconds between SES status polls (standard pages only).
    #[serde(default = "default_poll")]
    pub poll_secs: u64,
    /// Seconds between drive temperature reads (LOG SENSE). 0 disables.
    #[serde(default = "default_temp")]
    pub drive_temp_secs: u64,
    #[serde(default = "default_session")]
    pub session_hours: u64,
    /// Allow binding to 0.0.0.0/:: or a public address. Off by default.
    #[serde(default)]
    pub allow_non_lan: bool,
    /// Temperature-driven fan requests (SEND DIAGNOSTIC). Off unless enabled.
    #[serde(default)]
    pub fan_curve: Option<FanCurveConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FanCurveConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(flatten)]
    pub curve: ds4246_core::control::FanCurve,
}

fn default_dump_dir() -> PathBuf {
    PathBuf::from("dumps")
}
fn default_poll() -> u64 {
    10
}
fn default_temp() -> u64 {
    300
}
fn default_session() -> u64 {
    12
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let cfg: Config = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if !self.password_hash.starts_with("$argon2") || self.password_hash.contains("REPLACE_ME") {
            bail!("password_hash must be an argon2 hash (run `ds4246-web hash-password`)");
        }
        if let Some(fc) = self.fan_curve.as_ref().filter(|f| f.enabled) {
            fc.curve.validate().map_err(anyhow::Error::msg)?;
        }
        if self.poll_secs < 2 {
            bail!("poll_secs must be >= 2");
        }
        if !self.allow_non_lan && !is_lan(self.bind.ip()) {
            bail!(
                "refusing to bind {}: not a loopback/private LAN address. Use your LAN IP, or set allow_non_lan = true if you really mean it",
                self.bind
            );
        }
        Ok(())
    }
}

pub fn is_lan(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_unspecified() && (v4.is_loopback() || v4.is_private() || v4.is_link_local()),
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            !v6.is_unspecified() && (v6.is_loopback() || (seg0 & 0xfe00) == 0xfc00 || (seg0 & 0xffc0) == 0xfe80)
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn lan_only() {
        for ok in ["127.0.0.1", "192.168.1.5", "10.0.0.1", "172.16.4.4", "fd00::1", "fe80::1", "::1"] {
            assert!(super::is_lan(ok.parse().unwrap()), "{ok}");
        }
        for bad in ["0.0.0.0", "::", "8.8.8.8", "2001:db8::1", "172.32.0.1"] {
            assert!(!super::is_lan(bad.parse().unwrap()), "{bad}");
        }
    }
}
