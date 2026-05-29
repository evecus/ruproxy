mod anytls;
mod common;
mod config;
mod hysteria2;
mod shadowsocks;
mod socks;
mod trojan;
mod tuic;
mod vless;
mod vmess;
mod wireguard;

use anyhow::{Context, Result};
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // ── Install TLS crypto provider ───────────────────────────────────────────
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    // ── Parse CLI ─────────────────────────────────────────────────────────────
    let config_path = parse_config_arg();

    // ── Load config ───────────────────────────────────────────────────────────
    let cfg = config::load(&config_path)
        .with_context(|| format!("failed to load config: {config_path}"))?;

    // ── Init logging ──────────────────────────────────────────────────────────
    let filter = EnvFilter::try_new(&cfg.log.level).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    info!("ruproxy starting, config: {config_path}");

    // ── Validate ──────────────────────────────────────────────────────────────
    if cfg.hysteria2.is_none()
        && cfg.vless.is_none()
        && cfg.tuic.is_none()
        && cfg.trojan.is_none()
        && cfg.vmess.is_none()
        && cfg.shadowsocks.is_none()
        && cfg.wireguard.is_none()
        && cfg.anytls.is_none()
        && cfg.socks.is_none()
    {
        anyhow::bail!(
            "no protocols configured — add a [hysteria2], [vless], [tuic], [trojan], [vmess], [shadowsocks], [wireguard], [anytls], or [socks] section"
        );
    }

    let mut handles = Vec::new();

    // ── Hysteria2 ─────────────────────────────────────────────────────────────
    if let Some(hy2_cfg) = cfg.hysteria2.clone() {
        let hy2_cfg = Arc::new(hy2_cfg);
        info!("[hy2] enabled, listen: {}", hy2_cfg.listen);
        let h = tokio::spawn(async move {
            if let Err(e) = hysteria2::server::run(hy2_cfg).await {
                tracing::error!("[hy2] server exited with error: {e:#}");
            }
        });
        handles.push(h);
    }

    // ── VLESS ─────────────────────────────────────────────────────────────────
    if let Some(vless_cfg) = cfg.vless.clone() {
        let vless_cfg = Arc::new(vless_cfg);
        info!("[vless] enabled, listen: {}", vless_cfg.listen);
        let tls_label = match &vless_cfg.tls {
            None => "none",
            Some(crate::config::VlessTlsConfig::Tls { .. }) => "tls",
            Some(crate::config::VlessTlsConfig::Reality(_)) => "reality",
        };
        info!("[vless] transport={}, tls={tls_label}", vless_cfg.transport.r#type);
        let h = tokio::spawn(async move {
            if let Err(e) = vless::listener::run(vless_cfg).await {
                tracing::error!("[vless] server exited with error: {e:#}");
            }
        });
        handles.push(h);
    }

    // ── Trojan ────────────────────────────────────────────────────────────────
    if let Some(trojan_cfg) = cfg.trojan.clone() {
        let trojan_cfg = Arc::new(trojan_cfg);
        info!("[trojan] enabled, listen: {}", trojan_cfg.listen);
        let h = tokio::spawn(async move {
            if let Err(e) = trojan::run(trojan_cfg).await {
                tracing::error!("[trojan] server exited with error: {e:#}");
            }
        });
        handles.push(h);
    }

    // ── VMess ─────────────────────────────────────────────────────────────────
    if let Some(vmess_cfg) = cfg.vmess.clone() {
        let vmess_cfg = Arc::new(vmess_cfg);
        info!("[vmess] enabled, listen: {}", vmess_cfg.listen);
        let h = tokio::spawn(async move {
            if let Err(e) = vmess::run(vmess_cfg).await {
                tracing::error!("[vmess] server exited with error: {e:#}");
            }
        });
        handles.push(h);
    }

    // ── Shadowsocks ───────────────────────────────────────────────────────────
    if let Some(ss_cfg) = cfg.shadowsocks.clone() {
        let ss_cfg = Arc::new(ss_cfg);
        info!(
            "[shadowsocks] enabled, listen: {}, method={:?}, transport={}",
            ss_cfg.listen, ss_cfg.method, ss_cfg.transport.r#type,
        );
        let h = tokio::spawn(async move {
            if let Err(e) = shadowsocks::server::run(ss_cfg).await {
                tracing::error!("[shadowsocks] server exited with error: {e:#}");
            }
        });
        handles.push(h);
    }

    // ── TUIC ──────────────────────────────────────────────────────────────────
    if let Some(tuic_cfg) = cfg.tuic.clone() {
        let tuic_cfg = Arc::new(tuic_cfg);
        info!("[tuic] enabled, listen: {}", tuic_cfg.listen);
        info!("[tuic] users: {}", tuic_cfg.users.len());
        let h = tokio::spawn(async move {
            if let Err(e) = tuic::run(tuic_cfg).await {
                tracing::error!("[tuic] server exited with error: {e:#}");
            }
        });
        handles.push(h);
    }

    // ── WireGuard ─────────────────────────────────────────────────────────────
    if let Some(wg_cfg) = cfg.wireguard.clone() {
        let wg_cfg = Arc::new(wg_cfg);
        info!("[wireguard] enabled, listen: {}", wg_cfg.listen);
        info!("[wireguard] peers: {}", wg_cfg.peers.len());
        let h = tokio::spawn(async move {
            if let Err(e) = wireguard::server::run(wg_cfg).await {
                tracing::error!("[wireguard] server exited with error: {e:#}");
            }
        });
        handles.push(h);
    }

    // ── AnyTLS ────────────────────────────────────────────────────────────────
    if let Some(anytls_cfg) = cfg.anytls.clone() {
        let anytls_cfg = Arc::new(anytls_cfg);
        info!("[anytls] enabled, listen: {}", anytls_cfg.listen);
        let h = tokio::spawn(async move {
            if let Err(e) = anytls::server::run(anytls_cfg).await {
                tracing::error!("[anytls] server exited with error: {e:#}");
            }
        });
        handles.push(h);
    }

    // ── SOCKS5 ────────────────────────────────────────────────────────────────
    if let Some(socks_cfg) = cfg.socks.clone() {
        let socks_cfg = Arc::new(socks_cfg);
        let auth_label = if socks_cfg.users.is_empty() { "no-auth" } else { "password" };
        info!("[socks5] enabled, listen: {}, auth={auth_label}", socks_cfg.listen);
        let h = tokio::spawn(async move {
            if let Err(e) = socks::run(socks_cfg).await {
                tracing::error!("[socks5] server exited with error: {e:#}");
            }
        });
        handles.push(h);
    }

    // ── Wait for Ctrl-C ───────────────────────────────────────────────────────
    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for ctrl-c")?;
    info!("Shutting down...");

    for h in handles {
        h.abort();
    }

    Ok(())
}

fn parse_config_arg() -> String {
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "-c" {
            if let Some(path) = args.get(i + 1) {
                return path.clone();
            }
        }
        i += 1;
    }
    "config.toml".to_string()
}
