mod anytls;
mod common;
mod config;
mod generate;
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
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    // ── generate 子命令（不需要 config，执行后直接退出）────────────────────────
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("generate") {
        match args.get(2).map(|s| s.as_str()) {
            Some("wireguard-keypair") => return generate::wireguard_keypair(),
            Some("reality-keypair")   => return generate::reality_keypair(),
            _ => {
                eprintln!("用法:");
                eprintln!("  ruproxy generate wireguard-keypair   生成 WireGuard 服务端+客户端密钥对");
                eprintln!("  ruproxy generate reality-keypair     生成 Reality x25519 密钥对");
                std::process::exit(1);
            }
        }
    }

    let config_path = parse_config_arg();

    let cfg = config::load(&config_path)
        .with_context(|| format!("failed to load config: {config_path}"))?;

    let filter = EnvFilter::try_new(&cfg.log.level).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    info!("ruproxy starting, config: {config_path}");

    if cfg.is_empty() {
        anyhow::bail!(
            "no protocols configured — add at least one [hysteria2], [[vless]], [[vmess]], \
             [[trojan]], [[shadowsocks]], [[wireguard]], [[tuic]], [[anytls]], or [[socks]] section"
        );
    }

    let mut handles = Vec::new();

    // ── Hysteria2 ─────────────────────────────────────────────────────────────
    for hy2_cfg in cfg.hysteria2 {
        let hy2_cfg = Arc::new(hy2_cfg);
        info!("[hy2] enabled, listen: {}", hy2_cfg.listen);
        handles.push(tokio::spawn(async move {
            if let Err(e) = hysteria2::server::run(hy2_cfg).await {
                tracing::error!("[hy2] server exited: {e:#}");
            }
        }));
    }

    // ── VLESS ─────────────────────────────────────────────────────────────────
    for vless_cfg in cfg.vless {
        let vless_cfg = Arc::new(vless_cfg);
        let tls_label = match &vless_cfg.tls {
            None => "none",
            Some(crate::config::VlessTlsConfig::Tls { .. }) => "tls",
            Some(crate::config::VlessTlsConfig::Reality(_)) => "reality",
        };
        info!(
            "[vless] enabled, listen: {}, transport={}, tls={tls_label}",
            vless_cfg.listen, vless_cfg.transport.r#type,
        );
        handles.push(tokio::spawn(async move {
            if let Err(e) = vless::listener::run(vless_cfg).await {
                tracing::error!("[vless] server exited: {e:#}");
            }
        }));
    }

    // ── Trojan ────────────────────────────────────────────────────────────────
    for trojan_cfg in cfg.trojan {
        let trojan_cfg = Arc::new(trojan_cfg);
        info!("[trojan] enabled, listen: {}", trojan_cfg.listen);
        handles.push(tokio::spawn(async move {
            if let Err(e) = trojan::run(trojan_cfg).await {
                tracing::error!("[trojan] server exited: {e:#}");
            }
        }));
    }

    // ── VMess ─────────────────────────────────────────────────────────────────
    for vmess_cfg in cfg.vmess {
        let vmess_cfg = Arc::new(vmess_cfg);
        info!("[vmess] enabled, listen: {}", vmess_cfg.listen);
        handles.push(tokio::spawn(async move {
            if let Err(e) = vmess::run(vmess_cfg).await {
                tracing::error!("[vmess] server exited: {e:#}");
            }
        }));
    }

    // ── Shadowsocks ───────────────────────────────────────────────────────────
    for ss_cfg in cfg.shadowsocks {
        let ss_cfg = Arc::new(ss_cfg);
        info!(
            "[shadowsocks] enabled, listen: {}, method={:?}, transport={}",
            ss_cfg.listen, ss_cfg.method, ss_cfg.transport.r#type,
        );
        handles.push(tokio::spawn(async move {
            if let Err(e) = shadowsocks::server::run(ss_cfg).await {
                tracing::error!("[shadowsocks] server exited: {e:#}");
            }
        }));
    }

    // ── TUIC ──────────────────────────────────────────────────────────────────
    for tuic_cfg in cfg.tuic {
        let tuic_cfg = Arc::new(tuic_cfg);
        info!("[tuic] enabled, listen: {}, users: {}", tuic_cfg.listen, tuic_cfg.users.len());
        handles.push(tokio::spawn(async move {
            if let Err(e) = tuic::run(tuic_cfg).await {
                tracing::error!("[tuic] server exited: {e:#}");
            }
        }));
    }

    // ── WireGuard ─────────────────────────────────────────────────────────────
    for wg_cfg in cfg.wireguard {
        let wg_cfg = Arc::new(wg_cfg);
        info!("[wireguard] enabled, listen: {}, peers: {}", wg_cfg.listen, wg_cfg.peers.len());
        handles.push(tokio::spawn(async move {
            if let Err(e) = wireguard::server::run(wg_cfg).await {
                tracing::error!("[wireguard] server exited: {e:#}");
            }
        }));
    }

    // ── AnyTLS ────────────────────────────────────────────────────────────────
    for anytls_cfg in cfg.anytls {
        let anytls_cfg = Arc::new(anytls_cfg);
        info!("[anytls] enabled, listen: {}", anytls_cfg.listen);
        handles.push(tokio::spawn(async move {
            if let Err(e) = anytls::server::run(anytls_cfg).await {
                tracing::error!("[anytls] server exited: {e:#}");
            }
        }));
    }

    // ── SOCKS5 ────────────────────────────────────────────────────────────────
    for socks_cfg in cfg.socks {
        let socks_cfg = Arc::new(socks_cfg);
        let auth_label = if socks_cfg.users.is_empty() { "no-auth" } else { "password" };
        info!("[socks5] enabled, listen: {}, auth={auth_label}", socks_cfg.listen);
        handles.push(tokio::spawn(async move {
            if let Err(e) = socks::run(socks_cfg).await {
                tracing::error!("[socks5] server exited: {e:#}");
            }
        }));
    }

    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for ctrl-c")?;
    info!("Shutting down...");
    for h in handles { h.abort(); }

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
