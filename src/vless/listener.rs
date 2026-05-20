//! VLESS TCP listener.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::config::{VlessConfig, VlessTlsConfig};
use crate::vless::protocol::{decode_request, encode_response, parse_uuid, CMD_TCP};
use crate::vless::tls::{reality as vless_reality, standard as vless_tls};
use crate::vless::transport::websocket as vless_ws;

pub async fn run(cfg: Arc<VlessConfig>) -> Result<()> {
    let uuid_bytes =
        parse_uuid(&cfg.uuid).map_err(|e| anyhow::anyhow!("vless: invalid UUID in config: {e}"))?;

    // Build TLS acceptor once, reuse across connections.
    let tls_acceptor: Option<Arc<TlsAcceptor>> = match &cfg.tls {
        None => None,
        Some(VlessTlsConfig::Tls {
            cert_path,
            key_path,
            self_signed_domain,
        }) => {
            let sc = vless_tls::build(
                cert_path.as_deref(),
                key_path.as_deref(),
                self_signed_domain.as_deref(),
            )?;
            Some(Arc::new(TlsAcceptor::from(Arc::new(sc))))
        }
        Some(VlessTlsConfig::Reality(reality_cfg)) => {
            let sc = vless_reality::build(reality_cfg)?;
            Some(Arc::new(TlsAcceptor::from(Arc::new(sc))))
        }
    };

    let tls_label = match &cfg.tls {
        None => "none",
        Some(VlessTlsConfig::Tls { .. }) => "tls",
        Some(VlessTlsConfig::Reality(_)) => "reality",
    };

    let addr: SocketAddr = cfg.listen.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!(
        "[vless] Listening on {addr} (transport={}, tls={tls_label})",
        cfg.transport.r#type,
    );

    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg2 = Arc::clone(&cfg);
        let acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            debug!("[vless] New connection from {peer}");
            if let Err(e) = handle_conn(stream, peer, &cfg2, uuid_bytes, acceptor).await {
                warn!("[vless] Connection from {peer} error: {e:#}");
            }
        });
    }
}

async fn handle_conn(
    stream: TcpStream,
    peer: SocketAddr,
    cfg: &VlessConfig,
    uuid_bytes: [u8; 16],
    tls_acceptor: Option<Arc<TlsAcceptor>>,
) -> Result<()> {
    let transport_type = cfg.transport.r#type.as_str();
    let ws_path = cfg.transport.ws_path.as_str();
    let ws_host = cfg.transport.ws_host.as_deref();

    match (transport_type, &cfg.tls) {
        // ── TCP, no TLS ───────────────────────────────────────────────────
        ("tcp", None) => {
            debug!("[vless] {peer} → plain TCP");
            process_vless_stream(stream, peer, uuid_bytes).await
        }

        // ── TCP + standard TLS ────────────────────────────────────────────
        ("tcp", Some(VlessTlsConfig::Tls { .. })) => {
            debug!("[vless] {peer} → TCP+TLS");
            let acceptor =
                tls_acceptor.ok_or_else(|| anyhow::anyhow!("[vless] TLS acceptor missing"))?;
            let tls_stream = acceptor
                .accept(stream)
                .await
                .map_err(|e| anyhow::anyhow!("vless TLS handshake failed: {e}"))?;
            process_vless_stream(tls_stream, peer, uuid_bytes).await
        }

        // ── TCP + Reality ─────────────────────────────────────────────────
        // Reality 不使用全局 tls_acceptor：accept() 内部按连接实时生成 per-connection
        // TLS ServerConfig（因为 Reality 证书的 Signature = HMAC-SHA512(auth_key, pub_key)，
        // 而 auth_key 依赖客户端 ECDHE 临时公钥，每个连接不同）。
        ("tcp", Some(VlessTlsConfig::Reality(reality_cfg))) => {
            debug!("[vless] {peer} → TCP+Reality");
            let reality_stream = vless_reality::accept(stream, peer, reality_cfg).await?;
            process_vless_stream(reality_stream, peer, uuid_bytes).await
        }

        // ── WS, no TLS ────────────────────────────────────────────────────
        ("ws", None) => {
            debug!("[vless] {peer} → WS");
            let ws = vless_ws::accept_plain(stream, ws_path, ws_host).await?;
            process_vless_stream(ws, peer, uuid_bytes).await
        }

        // ── WS + standard TLS ─────────────────────────────────────────────
        ("ws", Some(VlessTlsConfig::Tls { .. })) => {
            debug!("[vless] {peer} → WS+TLS");
            let acceptor =
                tls_acceptor.ok_or_else(|| anyhow::anyhow!("[vless] TLS acceptor missing"))?;
            let tls_stream = acceptor
                .accept(stream)
                .await
                .map_err(|e| anyhow::anyhow!("vless WS+TLS handshake failed: {e}"))?;
            let ws = vless_ws::accept_tls(tls_stream, ws_path, ws_host).await?;
            process_vless_stream(ws, peer, uuid_bytes).await
        }

        // ── WS + Reality ──────────────────────────────────────────────────
        ("ws", Some(VlessTlsConfig::Reality(reality_cfg))) => {
            debug!("[vless] {peer} → WS+Reality");
            let reality_stream = vless_reality::accept(stream, peer, reality_cfg).await?;
            let ws = vless_ws::accept_tls(reality_stream, ws_path, ws_host).await?;
            process_vless_stream(ws, peer, uuid_bytes).await
        }

        (other, _) => anyhow::bail!("vless: unknown transport type '{other}'"),
    }
}

async fn process_vless_stream<S>(
    mut stream: S,
    peer: SocketAddr,
    uuid_bytes: [u8; 16],
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = decode_request(&mut stream, &uuid_bytes)
        .await
        .map_err(|e| {
            warn!("[vless] {peer} header decode failed: {e}");
            e
        })?;

    if request.command != CMD_TCP {
        anyhow::bail!("vless: UDP not supported (cmd={:#x})", request.command);
    }

    info!("[vless] {peer} → {}", request.target);

    let outbound = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect(&request.target),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!("[vless] {peer} connect {} failed: {e}", request.target);
            return Err(e.into());
        }
        Err(_) => {
            warn!("[vless] {peer} connect {} timeout", request.target);
            anyhow::bail!("connect timeout");
        }
    };

    encode_response(&mut stream).await?;

    relay(stream, outbound, peer, &request.target).await
}

async fn relay<S>(inbound: S, outbound: TcpStream, peer: SocketAddr, target: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut out_r, mut out_w) = outbound.into_split();
    let (mut in_r, mut in_w) = tokio::io::split(inbound);
    let target_str = target.to_string();

    let uplink = async {
        match tokio::io::copy(&mut in_r, &mut out_w).await {
            Ok(n) => debug!("[vless] {peer}→{target_str} uplink {n}B"),
            Err(e) => debug!("[vless] {peer}→{target_str} uplink: {e}"),
        }
        let _ = out_w.shutdown().await;
    };

    let target_str2 = target.to_string();
    let downlink = async {
        match tokio::io::copy(&mut out_r, &mut in_w).await {
            Ok(n) => debug!("[vless] {target_str2}→{peer} downlink {n}B"),
            Err(e) => debug!("[vless] {target_str2}→{peer} downlink: {e}"),
        }
        let _ = in_w.shutdown().await;
    };

    tokio::join!(uplink, downlink);
    debug!("[vless] relay closed: {peer} ↔ {target}");
    Ok(())
}
