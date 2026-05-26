use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::Path, time::Duration};
use uuid::Uuid;

use crate::common::tls::config::StandardTlsConfig;

// ── Top-level config ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub log: LogConfig,
    pub hysteria2: Option<Hysteria2Config>,
    pub vless: Option<VlessConfig>,
    pub tuic: Option<TuicConfig>,
    pub trojan: Option<TrojanConfig>,
    pub vmess: Option<VmessConfig>,
    pub shadowsocks: Option<ShadowsocksConfig>,
    pub wireguard: Option<WireGuardConfig>,
    pub anytls: Option<AnyTlsConfig>,
}

// ── TUIC ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TuicConfig {
    pub listen: String,
    pub users: HashMap<Uuid, String>,
    pub tls: Option<StandardTlsConfig>,
    #[serde(default = "default_tuic_idle_time", with = "humantime_serde")]
    pub max_idle_time: Duration,
    #[serde(default = "default_tuic_auth_timeout", with = "humantime_serde")]
    pub auth_timeout: Duration,
    #[serde(default = "default_tuic_udp_timeout", with = "humantime_serde")]
    pub udp_timeout: Duration,
    #[serde(default)]
    pub udp_relay_ipv6: bool,
    #[serde(default = "default_tuic_max_udp_packet_size")]
    pub max_udp_packet_size: usize,
}

fn default_tuic_idle_time() -> Duration { Duration::from_secs(30) }
fn default_tuic_auth_timeout() -> Duration { Duration::from_secs(3) }
fn default_tuic_udp_timeout() -> Duration { Duration::from_secs(30) }
fn default_tuic_max_udp_packet_size() -> usize { 65535 }

// ── Hysteria2 ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Hysteria2Config {
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

// ── Shared Transport config ───────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransportConfig {
    #[serde(default = "default_transport_type")]
    pub r#type: String,
    #[serde(default = "default_ws_path")]
    pub ws_path: String,
    pub ws_host: Option<String>,
    #[serde(default = "default_xhttp_path")]
    pub xhttp_path: String,
    pub xhttp_host: Option<String>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            r#type: default_transport_type(),
            ws_path: default_ws_path(),
            ws_host: None,
            xhttp_path: default_xhttp_path(),
            xhttp_host: None,
        }
    }
}

// ── TLS layer ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum VlessTlsConfig {
    Tls {
        #[serde(flatten)]
        standard: StandardTlsConfig,
    },
    Reality(RealityConfig),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RealityConfig {
    pub private_key: String,
    pub public_key: String,
    pub short_ids: Vec<String>,
    pub dest: String,
    pub server_name: String,
}

// ── VLESS ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VlessConfig {
    pub listen: String,
    pub uuid: String,
    #[serde(default)]
    pub transport: TransportConfig,
    pub tls: Option<VlessTlsConfig>,
}

// ── Trojan ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TrojanConfig {
    pub listen: String,
    pub password: String,
    #[serde(default)]
    pub transport: TransportConfig,
    pub tls: Option<StandardTlsConfig>,
}

// ── VMess ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VmessConfig {
    pub listen: String,
    pub uuid: String,
    #[serde(default)]
    pub transport: TransportConfig,
    pub tls: Option<StandardTlsConfig>,
}

// ── Shadowsocks 2022 ──────────────────────────────────────────────────────────

/// Shadowsocks 2022 cipher methods (AEAD-2022 only).
/// Password must be a base64-encoded key of the correct length.
/// Key lengths: aes-128-gcm → 16 bytes, aes-256-gcm → 32 bytes, chacha20 → 32 bytes.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ShadowsocksCipher {
    /// 2022-blake3-aes-128-gcm  (16-byte key)
    #[serde(rename = "2022-blake3-aes-128-gcm")]
    Blake3Aes128Gcm,
    /// 2022-blake3-aes-256-gcm  (32-byte key)
    #[serde(rename = "2022-blake3-aes-256-gcm")]
    Blake3Aes256Gcm,
    /// 2022-blake3-chacha20-poly1305  (32-byte key)
    #[serde(rename = "2022-blake3-chacha20-poly1305")]
    Blake3Chacha20Poly1305,
}

impl ShadowsocksCipher {
    /// Key length in bytes.
    pub fn key_len(&self) -> usize {
        match self {
            ShadowsocksCipher::Blake3Aes128Gcm => 16,
            ShadowsocksCipher::Blake3Aes256Gcm => 32,
            ShadowsocksCipher::Blake3Chacha20Poly1305 => 32,
        }
    }
    /// Salt length = key length for 2022 ciphers.
    pub fn salt_len(&self) -> usize { self.key_len() }
    /// AEAD tag length (always 16).
    pub fn tag_len(&self) -> usize { 16 }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ShadowsocksConfig {
    /// TCP listen address, e.g. "0.0.0.0:8388"
    pub listen: String,
    /// Pre-shared key: base64-encoded bytes matching the cipher key length.
    /// Generate with: openssl rand -base64 16  (for aes-128)
    ///                openssl rand -base64 32  (for aes-256 / chacha20)
    pub password: String,
    /// 2022 cipher method (default: 2022-blake3-aes-256-gcm)
    #[serde(default = "default_ss_cipher")]
    pub method: ShadowsocksCipher,
    /// Transport layer (tcp / ws / xhttp). Omit for plain TCP.
    #[serde(default)]
    pub transport: TransportConfig,
    /// Optional TLS.
    pub tls: Option<StandardTlsConfig>,
}

// ── AnyTLS ────────────────────────────────────────────────────────────────────

/// AnyTLS server configuration.
///
/// AnyTLS multiplexes streams over a single TLS connection using a lightweight
/// session layer with padding obfuscation.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AnyTlsConfig {
    /// TCP listen address, e.g. "0.0.0.0:8443"
    pub listen: String,
    /// Pre-shared password for authentication (sha256 is verified on connection).
    pub password: String,
    /// TLS configuration (required — AnyTLS is always over TLS).
    pub tls: StandardTlsConfig,
    /// Optional padding scheme override (server-side).
    /// If unset, the built-in default scheme is used.
    pub padding_scheme: Option<String>,
}

// ── WireGuard ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WireGuardConfig {
    pub listen: String,
    pub private_key: String,
    #[serde(default)]
    pub server_address: Vec<String>,
    #[serde(default = "default_wg_mtu")]
    pub mtu: u16,
    pub peers: Vec<WireGuardPeerConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WireGuardPeerConfig {
    pub public_key: String,
    pub pre_shared_key: Option<String>,
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub keepalive_interval: Option<u16>,
    #[serde(default)]
    pub dns: Vec<String>,
}

fn default_wg_mtu() -> u16 { 1420 }

fn default_ss_cipher() -> ShadowsocksCipher {
    ShadowsocksCipher::Blake3Aes256Gcm
}

// ── Shared ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self { level: default_log_level() }
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

fn default_log_level() -> String { "info".to_string() }
fn default_masquerade_type() -> String { "none".to_string() }
fn default_transport_type() -> String { "tcp".to_string() }
fn default_ws_path() -> String { "/".to_string() }
fn default_xhttp_path() -> String { "/".to_string() }

pub fn load(path: &str) -> Result<Config> {
    let content = std::fs::read_to_string(Path::new(path))
        .with_context(|| format!("cannot read config file: {path}"))?;
    let cfg: Config =
        toml::from_str(&content).with_context(|| format!("invalid TOML in {path}"))?;
    Ok(cfg)
}
