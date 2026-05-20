mod config;
mod hysteria2;
mod vless;

use anyhow::{Context, Result};
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // ── Install TLS crypto provider (required by rustls + quinn) ─────────────
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    // ── Parse CLI: ./ruproxy -c config.toml ──────────────────────────────────
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

    // ── Validate: at least one protocol section must be present ───────────────
    if cfg.hysteria2.is_none() && cfg.vless.is_none() {
        anyhow::bail!(
            "no protocols configured — add a [hysteria2] or [vless] section to your config"
        );
    }

    let mut handles = Vec::new();

    // ── Hysteria2 server ──────────────────────────────────────────────────────
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

    // ── VLESS server ──────────────────────────────────────────────────────────
    if let Some(vless_cfg) = cfg.vless.clone() {
        let vless_cfg = Arc::new(vless_cfg);
        info!("[vless] enabled, listen: {}", vless_cfg.listen);
        let tls_label = match &vless_cfg.tls {
            None => "none",
            Some(crate::config::VlessTlsConfig::Tls { .. }) => "tls",
            Some(crate::config::VlessTlsConfig::Reality(_)) => "reality",
        };
        info!(
            "[vless] transport={}, tls={tls_label}",
            vless_cfg.transport.r#type,
        );
        let h = tokio::spawn(async move {
            if let Err(e) = vless::listener::run(vless_cfg).await {
                tracing::error!("[vless] server exited with error: {e:#}");
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

/// Parse `-c <path>` from argv, defaulting to "config.toml".
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
