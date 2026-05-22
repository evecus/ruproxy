//! Shadowsocks server listener.
//!
//! Supports:
//!   - Transports: TCP, WebSocket (ws), XHTTP (xhttp)
//!   - Optional TLS on any transport
//!   - AEAD ciphers: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
//!
//! Wire format:
//!   1. Read `salt_len` bytes (plaintext salt)
//!   2. Derive per-session subkey via HKDF-SHA1("ss-subkey")
//!   3. Decrypt AEAD chunks → SOCKS5 address header → relay

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::common::tls::standard as shared_tls;
use crate::common::transport::websocket as shared_ws;
use crate::common::transport::xhttp::{self, XhttpConfig};
use crate::config::ShadowsocksConfig;
use crate::shadowsocks::protocol::{
    derive_subkey, evp_bytes_to_key, read_address, AeadReader, AeadWriter,
};

pub async fn run(cfg: Arc<ShadowsocksConfig>) -> Result<()> {
    let key_len = cfg.method.key_len();
    let master_key = Arc::new(evp_bytes_to_key(&cfg.password, key_len));

    let tls_acceptor: Option<Arc<TlsAcceptor>> = if let Some(tls_cfg) = &cfg.tls {
        let sc = shared_tls::build(
            tls_cfg.cert_path.as_deref(),
            tls_cfg.key_path.as_deref(),
            tls_cfg.self_signed_domain.as_deref(),
        )?;
        Some(Arc::new(TlsAcceptor::from(Arc::new(sc))))
    } else {
        None
    };

    let addr: SocketAddr = cfg.listen.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!(
        "[shadowsocks] listening on {addr} (method={:?}, transport={}, tls={})",
        cfg.method,
        cfg.transport.r#type,
        if tls_acceptor.is_some() { "yes" } else { "no" },
    );

    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg2 = Arc::clone(&cfg);
        let key = Arc::clone(&master_key);
        let acc = tls_acceptor.clone();

        tokio::spawn(async move {
            debug!("[shadowsocks] new connection from {peer}");
            if let Err(e) = handle_conn(stream, peer, &cfg2, &key, acc).await {
                warn!("[shadowsocks] {peer}: {e:#}");
            }
        });
    }
}

async fn handle_conn(
    stream: TcpStream,
    peer: SocketAddr,
    cfg: &ShadowsocksConfig,
    master_key: &[u8],
    tls_acceptor: Option<Arc<TlsAcceptor>>,
) -> Result<()> {
    let transport = cfg.transport.r#type.as_str();
    let ws_path  = cfg.transport.ws_path.as_str();
    let ws_host  = cfg.transport.ws_host.as_deref();
    let xh_path  = cfg.transport.xhttp_path.as_str();
    let xh_host  = cfg.transport.xhttp_host.clone();

    match (transport, tls_acceptor) {
        ("tcp", None) => {
            debug!("[shadowsocks] {peer} plain TCP");
            process(stream, peer, cfg, master_key).await
        }
        ("tcp", Some(acc)) => {
            debug!("[shadowsocks] {peer} TCP+TLS");
            let tls = acc.accept(stream).await?;
            process(tls, peer, cfg, master_key).await
        }
        ("ws", None) => {
            debug!("[shadowsocks] {peer} WS");
            let ws = shared_ws::accept_plain(stream, ws_path, ws_host).await?;
            process(ws, peer, cfg, master_key).await
        }
        ("ws", Some(acc)) => {
            debug!("[shadowsocks] {peer} WS+TLS");
            let tls = acc.accept(stream).await?;
            let ws = shared_ws::accept_tls(tls, ws_path, ws_host).await?;
            process(ws, peer, cfg, master_key).await
        }
        ("xhttp", None) => {
            debug!("[shadowsocks] {peer} XHTTP");
            let xh_cfg = XhttpConfig { path: xh_path.to_string(), host: xh_host };
            let xh = xhttp::accept_plain(stream, peer, &xh_cfg).await?;
            process(xh, peer, cfg, master_key).await
        }
        ("xhttp", Some(acc)) => {
            debug!("[shadowsocks] {peer} XHTTP+TLS");
            let tls = acc.accept(stream).await?;
            let xh_cfg = XhttpConfig { path: xh_path.to_string(), host: xh_host };
            let xh = xhttp::accept_tls(tls, peer, &xh_cfg).await?;
            process(xh, peer, cfg, master_key).await
        }
        (other, _) => anyhow::bail!("shadowsocks: unknown transport '{other}'"),
    }
}

/// Core: decrypt, parse address, relay bidirectionally.
async fn process<S>(
    mut stream: S,
    peer: SocketAddr,
    cfg: &ShadowsocksConfig,
    master_key: &[u8],
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let salt_len = cfg.method.salt_len();
    let cipher   = cfg.method.clone();

    // ── 1. Read client salt ───────────────────────────────────────────────────
    let mut client_salt = vec![0u8; salt_len];
    stream.read_exact(&mut client_salt).await?;

    // ── 2. Derive uplink subkey ───────────────────────────────────────────────
    let up_subkey = derive_subkey(master_key, &client_salt, salt_len);

    // ── 3. Split stream → AEAD reader + raw writer ────────────────────────────
    // We split at the tokio level so reader and writer can be moved into
    // separate tasks for concurrent relay.
    let (read_half, write_half) = tokio::io::split(stream);
    let mut aead_r = AeadReader::new(read_half, cipher.clone(), up_subkey);

    // ── 4. Parse SOCKS5 address header from decrypted stream ─────────────────
    let target = read_address(&mut aead_r).await?;
    info!("[shadowsocks] {peer} → {target}");

    // ── 5. Connect upstream ───────────────────────────────────────────────────
    let outbound = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect(&target),
    )
    .await
    .map_err(|_| anyhow::anyhow!("connect timeout: {target}"))?
    .map_err(|e| anyhow::anyhow!("connect {target} failed: {e}"))?;

    // ── 6. Write response salt → derive downlink subkey ───────────────────────
    let mut resp_salt = vec![0u8; salt_len];
    rand::thread_rng().fill_bytes(&mut resp_salt);

    let dn_subkey = derive_subkey(master_key, &resp_salt, salt_len);
    let mut aead_w = AeadWriter::new(write_half, cipher.clone(), vec![0u8; salt_len]);
    // Write salt raw (unencrypted), then switch to the real subkey
    aead_w.write_raw(&resp_salt).await?;
    aead_w.reset_subkey(dn_subkey);

    // ── 7. Relay ──────────────────────────────────────────────────────────────
    let (mut out_r, mut out_w) = outbound.into_split();

    let t = target.clone();
    let uplink = async move {
        // client → upstream: decrypt AEAD chunks, pipe to upstream TCP
        let mut tmp = vec![0u8; 32 * 1024];
        loop {
            let n = match aead_r.read_bytes(&mut tmp).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => { debug!("[shadowsocks] {peer}→{t} uplink read: {e}"); break; }
            };
            if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut out_w, &tmp[..n]).await {
                debug!("[shadowsocks] {peer}→{t} uplink write: {e}");
                break;
            }
        }
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut out_w).await;
        debug!("[shadowsocks] uplink closed {peer}→{t}");
    };

    let t2 = target.clone();
    let downlink = async move {
        // upstream → client: read plain bytes, encrypt AEAD chunks
        let mut tmp = vec![0u8; 32 * 1024];
        loop {
            let n = match tokio::io::AsyncReadExt::read(&mut out_r, &mut tmp).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => { debug!("[shadowsocks] {t2}→{peer} downlink read: {e}"); break; }
            };
            if let Err(e) = aead_w.write_data(&tmp[..n]).await {
                debug!("[shadowsocks] {t2}→{peer} downlink write: {e}");
                break;
            }
            if let Err(e) = aead_w.flush().await {
                debug!("[shadowsocks] {t2}→{peer} downlink flush: {e}");
                break;
            }
        }
        debug!("[shadowsocks] downlink closed {t2}→{peer}");
    };

    tokio::join!(uplink, downlink);
    debug!("[shadowsocks] relay done: {peer} ↔ {target}");
    Ok(())
}
