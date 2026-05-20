use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

// ── Top-level config ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub log: LogConfig,
    pub hysteria2: Option<Hysteria2Config>,
    pub vless: Option<VlessConfig>,
}

// ── Hysteria2 ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Hysteria2Config {
    /// TCP listen address, e.g. "0.0.0.0:443"
    pub listen: String,
    pub tls: Hy2TlsConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub bandwidth: BandwidthConfig,
    #[serde(default)]
    pub masquerade: MasqueradeConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Hy2TlsConfig {
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    /// Used to generate a self-signed cert when cert_path/key_path are not provided.
    pub self_signed_domain: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AuthConfig {
    Password { password: String },
    None,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct BandwidthConfig {
    pub up: Option<String>,
    pub down: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct MasqueradeConfig {
    #[serde(default = "default_masquerade_type")]
    pub r#type: String,
    pub proxy: Option<MasqueradeProxy>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MasqueradeProxy {
    pub url: String,
    #[serde(default)]
    pub rewrite_host: bool,
}

// ── VLESS ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VlessConfig {
    /// TCP listen address, e.g. "0.0.0.0:8443"
    pub listen: String,
    /// UUID for authentication
    pub uuid: String,
    /// Transport layer (tcp / ws). Omit entirely to use plain TCP.
    #[serde(default)]
    pub transport: VlessTransportConfig,
    /// TLS layer (tls / reality). Omit entirely for plaintext.
    pub tls: Option<VlessTlsConfig>,
}

// ── Transport layer ───────────────────────────────────────────────────────────

/// Controls how raw bytes are carried: plain TCP or WebSocket framing.
/// This is independent of whether TLS is used.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VlessTransportConfig {
    /// "tcp" (default) or "ws"
    #[serde(default = "default_transport_type")]
    pub r#type: String,

    // ── WebSocket fields (type = "ws" only) ───────────────────────────────
    #[serde(default = "default_ws_path")]
    pub ws_path: String,
    pub ws_host: Option<String>,
}

impl Default for VlessTransportConfig {
    fn default() -> Self {
        Self {
            r#type: default_transport_type(),
            ws_path: default_ws_path(),
            ws_host: None,
        }
    }
}

// ── TLS layer ─────────────────────────────────────────────────────────────────

/// Controls the TLS layer. Absence of this field means plaintext.
///
/// Two mutually exclusive variants:
///   [vless.tls]  type = "tls"     → standard TLS with cert + key
///   [vless.tls]  type = "reality" → Reality camouflage (no cert files needed)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum VlessTlsConfig {
    /// Standard TLS: supply a certificate file and private key file,
    /// or let the server generate a self-signed certificate.
    Tls {
        cert_path: Option<String>,
        key_path: Option<String>,
        self_signed_domain: Option<String>,
    },
    /// Reality: TLS-camouflage transport.
    /// Clients authenticate via a short ID instead of a CA chain,
    /// so no certificate file is required.
    Reality(RealityConfig),
}

// ── Reality config ────────────────────────────────────────────────────────────

/// Reality protocol configuration.
///
/// Reality is a TLS-camouflage transport where the server impersonates a real
/// TLS destination. Clients authenticate via a short ID instead of a CA chain,
/// so no certificate file is required.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RealityConfig {
    /// x25519 private key (base64-encoded, 32 bytes).
    pub private_key: String,

    /// Corresponding x25519 public key (base64). Shared with clients.
    pub public_key: String,

    /// One or more short IDs (hex strings, 0-16 hex chars / 0-8 bytes).
    /// Clients must present a matching short ID in the ClientHello.
    pub short_ids: Vec<String>,

    /// Destination (host:port) whose TLS fingerprint to impersonate.
    pub dest: String,

    /// SNI the server expects from Reality clients.
    pub server_name: String,
}

// ── Shared ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

impl BandwidthConfig {
    pub fn parse_bps(s: &str) -> Option<u64> {
        let s = s.trim().to_lowercase().replace(' ', "");
        if let Some(n) = s.strip_suffix("gbps") {
            n.parse::<f64>().ok().map(|v| (v * 1e9 / 8.0) as u64)
        } else if let Some(n) = s.strip_suffix("mbps") {
            n.parse::<f64>().ok().map(|v| (v * 1e6 / 8.0) as u64)
        } else if let Some(n) = s.strip_suffix("kbps") {
            n.parse::<f64>().ok().map(|v| (v * 1e3 / 8.0) as u64)
        } else if let Some(n) = s.strip_suffix("bps") {
            n.parse::<u64>().ok()
        } else {
            None
        }
    }
    pub fn up_bps(&self) -> Option<u64> {
        self.up.as_deref().and_then(Self::parse_bps)
    }
    #[allow(dead_code)]
    pub fn down_bps(&self) -> Option<u64> {
        self.down.as_deref().and_then(Self::parse_bps)
    }
}

fn default_log_level() -> String {
    "info".to_string()
}
fn default_masquerade_type() -> String {
    "none".to_string()
}
fn default_transport_type() -> String {
    "tcp".to_string()
}
fn default_ws_path() -> String {
    "/".to_string()
}

pub fn load(path: &str) -> Result<Config> {
    let content = std::fs::read_to_string(Path::new(path))
        .with_context(|| format!("cannot read config file: {path}"))?;
    let cfg: Config =
        toml::from_str(&content).with_context(|| format!("invalid TOML in {path}"))?;
    Ok(cfg)
}
