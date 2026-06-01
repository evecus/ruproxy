//! VMess inbound — AEAD header + AES-128-GCM / ChaCha20-Poly1305 chunked body.
//!
//! ## 数据流（与 Xray 对齐）
//!
//! ### Request header
//!   authid(16) | enc_len(18) | nonce(8) | enc_header(header_len+16)
//!
//! ### Request body (security=AES-128-GCM, option has ChunkStream=0x01)
//!   loop:
//!     size_field(2 bytes, optionally XOR Shake128(requestBodyIV))
//!     ciphertext(size bytes, includes 16-byte GCM tag)
//!   nonce per chunk = count_BE_u16 ++ requestBodyIV[2..12]
//!   terminate on size_field==16 and plaintext==empty (EOF chunk)
//!
//! ### Response header
//!   responseBodyKey = SHA256(requestBodyKey)[:16]
//!   responseBodyIV  = SHA256(requestBodyIV)[:16]
//!   payload = [V_byte, option, 0x00, 0x00]
//!   write: AES-GCM(len) ++ AES-GCM(payload)   (same as request header format)
//!
//! ### Response body (same chunk format, but using responseBodyKey/IV)

use std::{net::SocketAddr, sync::Arc};

use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes128Gcm, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use crate::common::tls::standard as shared_tls;
use crate::common::transport::websocket as shared_ws;
use crate::common::transport::xhttp::{XhttpConfig, XhttpServer};
use crate::config::VmessConfig;
use crate::vless::protocol::parse_uuid;

// ── KDF salts (matching Xray consts) ─────────────────────────────────────────
const KDF_ROOT: &[u8]           = b"VMess AEAD KDF";
const KDF_AUTH_ID: &[u8]        = b"AES Auth ID Encryption";
const KDF_HDR_LEN_KEY: &[u8]    = b"VMess Header AEAD Key_Length";
const KDF_HDR_LEN_IV: &[u8]     = b"VMess Header AEAD Nonce_Length";
const KDF_HDR_KEY: &[u8]        = b"VMess Header AEAD Key";
const KDF_HDR_IV: &[u8]         = b"VMess Header AEAD Nonce";
const KDF_RESP_LEN_KEY: &[u8]   = b"AEAD Resp Header Len Key";
const KDF_RESP_LEN_IV: &[u8]    = b"AEAD Resp Header Len IV";
const KDF_RESP_PAY_KEY: &[u8]   = b"AEAD Resp Header Key";
const KDF_RESP_PAY_IV: &[u8]    = b"AEAD Resp Header IV";

// Option flags
const OPT_CHUNK_STREAM: u8       = 0x01;
const OPT_CHUNK_MASKING: u8      = 0x04;
const OPT_GLOBAL_PADDING: u8     = 0x08;
const OPT_AUTH_LEN: u8           = 0x10;

// Security types
const SEC_NONE: u8               = 0x00;
const SEC_AES128_GCM: u8         = 0x03;
const SEC_CHACHA20: u8           = 0x04;
const SEC_AUTO: u8               = 0x05; // server treats as AES-128-GCM

const CHUNK_SIZE: usize = 8192;

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn run(cfg: Arc<VmessConfig>) -> Result<()> {
    let uuid     = parse_uuid(&cfg.uuid)?;
    let cmd_key  = vmess_cmd_key(&uuid);
    let acceptor = build_tls(&cfg)?;
    let addr: SocketAddr = cfg.listen.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!("[vmess] Listening on {addr}");

    if cfg.transport.r#type == "xhttp" {
        let xh_cfg = XhttpConfig {
            path: cfg.transport.xhttp_path.clone(),
            host: cfg.transport.xhttp_host.clone(),
        };
        let srv = XhttpServer::new(xh_cfg);
        let srv_feed = srv.clone();
        let tls2 = acceptor.clone();
        tokio::spawn(async move {
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(p) => p,
                    Err(e) => { warn!("[vmess] accept: {e}"); continue; }
                };
                match &tls2 {
                    None => { srv_feed.feed_plain(stream, peer); }
                    Some(a) => {
                        let a = Arc::clone(a);
                        let s = srv_feed.clone();
                        tokio::spawn(async move {
                            match a.accept(stream).await {
                                Ok(t) => s.feed_tls(t, peer),
                                Err(e) => warn!("[vmess] {peer} TLS: {e}"),
                            }
                        });
                    }
                }
            }
        });
        loop {
            match srv.accept().await {
                None => { warn!("[vmess] xhttp closed"); break; }
                Some(xhs) => {
                    tokio::spawn(async move {
                        let peer: SocketAddr = "0.0.0.0:0".parse().unwrap();
                        let mut io: Box<dyn RW> = Box::new(xhs);
                        if let Err(e) = process(&mut *io, peer, cmd_key).await {
                            warn!("[vmess] {peer}: {e:#}");
                        }
                    });
                }
            }
        }
        return Ok(());
    }

    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg2 = Arc::clone(&cfg);
        let tls  = acceptor.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, peer, &cfg2, cmd_key, tls).await {
                warn!("[vmess] {peer}: {e:#}");
            }
        });
    }
}

fn build_tls(cfg: &VmessConfig) -> Result<Option<Arc<TlsAcceptor>>> {
    match &cfg.tls {
        None => Ok(None),
        Some(t) => {
            let sc = shared_tls::build(t.cert_path.as_deref(), t.key_path.as_deref(), t.self_signed_domain.as_deref())?;
            Ok(Some(Arc::new(TlsAcceptor::from(Arc::new(sc)))))
        }
    }
}

trait RW: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> RW for T {}

async fn handle(
    stream: TcpStream, peer: SocketAddr, cfg: &VmessConfig,
    cmd_key: [u8; 16], tls: Option<Arc<TlsAcceptor>>,
) -> Result<()> {
    let mut io: Box<dyn RW> = match (cfg.transport.r#type.as_str(), tls) {
        ("tcp", None) => Box::new(stream),
        ("tcp", Some(a)) => Box::new(a.accept(stream).await?),
        ("ws", None) => Box::new(shared_ws::accept_plain(stream, &cfg.transport.ws_path, cfg.transport.ws_host.as_deref()).await?),
        ("ws", Some(a)) => {
            let t = a.accept(stream).await?;
            Box::new(shared_ws::accept_tls(t, &cfg.transport.ws_path, cfg.transport.ws_host.as_deref()).await?)
        }
        _ => bail!("unknown transport"),
    };
    process(&mut *io, peer, cmd_key).await
}

// ── Core process ──────────────────────────────────────────────────────────────

async fn process<S: AsyncRead + AsyncWrite + Unpin + Send + ?Sized>(
    io: &mut S, peer: SocketAddr, cmd_key: [u8; 16],
) -> Result<()> {
    let req = decode_request_header(io, &cmd_key).await.context("decode header")?;
    info!("[vmess] {peer} -> {}", req.target);

    let outbound = TcpStream::connect(&req.target).await?;
    encode_response_header(io, &req).await?;

    let (mut out_r, mut out_w) = outbound.into_split();
    let (mut in_r, mut in_w)   = tokio::io::split(io);

    let opt = req.option;
    let sec = req.security;

    let up = {
        let k = req.request_body_key;
        let v = req.request_body_iv;
        async move {
            if let Err(e) = relay_up(&mut in_r, &mut out_w, k, v, opt, sec).await {
                tracing::debug!("[vmess] up: {e}");
            }
            let _ = out_w.shutdown().await;
        }
    };

    let dn = {
        let k = req.response_body_key;
        let v = req.response_body_iv;
        async move {
            if let Err(e) = relay_down(&mut out_r, &mut in_w, k, v, opt, sec).await {
                tracing::debug!("[vmess] dn: {e}");
            }
            let _ = in_w.shutdown().await;
        }
    };

    tokio::join!(up, dn);
    Ok(())
}

// ── Uplink: decrypt AES-GCM chunks → target ───────────────────────────────────

async fn relay_up<R, W>(
    r: &mut R, w: &mut W,
    key: [u8; 16], iv: [u8; 16],
    opt: u8, sec: u8,
) -> Result<()>
where R: AsyncRead + Unpin, W: AsyncWrite + Unpin,
{
    // If ChunkStream bit not set, raw relay (SEC_NONE without chunk)
    if sec == SEC_NONE && opt & OPT_CHUNK_STREAM == 0 {
        tokio::io::copy(r, w).await?;
        return Ok(());
    }

    let use_masking = opt & OPT_CHUNK_MASKING != 0;
    let use_auth_len = opt & OPT_AUTH_LEN != 0;
    let use_padding = opt & OPT_GLOBAL_PADDING != 0;

    let mut shake_size = use_masking.then(|| Shake128Reader::new(&iv));
    let mut count: u16 = 0;

    // auth_len uses a separate AES-GCM cipher for the length field
    let auth_len_key = use_auth_len.then(|| kdf16(&key, &[b"auth_len"]));
    let auth_len_iv_seed = iv; // nonce derived per chunk

    loop {
        // ── Read size field ───────────────────────────────────────────────
        let data_len: usize = if use_auth_len {
            // 18 bytes = 2 plaintext + 16 GCM tag
            let mut buf = [0u8; 18];
            r.read_exact(&mut buf).await?;
            let nonce = chunk_nonce(&auth_len_iv_seed, count);
            let lc = Aes128Gcm::new_from_slice(&auth_len_key.unwrap())?;
            let plain = lc.decrypt(Nonce::from_slice(&nonce), buf.as_ref())
                .map_err(|_| anyhow!("auth_len decrypt"))?;
            count = count.wrapping_add(1);
            u16::from_be_bytes([plain[0], plain[1]]) as usize
        } else {
            let mut buf = [0u8; 2];
            r.read_exact(&mut buf).await?;
            let raw = u16::from_be_bytes(buf);
            if let Some(ref mut sk) = shake_size {
                (raw ^ sk.next_u16()) as usize
            } else {
                raw as usize
            }
        };

        if data_len == 0 { break; }

        // ── Read & decrypt payload ────────────────────────────────────────
        match sec {
            SEC_NONE => {
                let mut buf = vec![0u8; data_len];
                r.read_exact(&mut buf).await?;
                // SEC_NONE with ChunkStream: no encryption, just size-delimited
                let write_len = if use_padding && data_len >= 2 { data_len - 2 } else { data_len };
                w.write_all(&buf[..write_len]).await?;
            }
            SEC_AES128_GCM | SEC_AUTO => {
                if data_len < 16 { bail!("chunk too small: {data_len}"); }
                let mut ct = vec![0u8; data_len];
                r.read_exact(&mut ct).await?;
                let nonce = chunk_nonce(&iv, count);
                let cipher = Aes128Gcm::new_from_slice(&key)?;
                let plain = cipher.decrypt(Nonce::from_slice(&nonce), ct.as_slice())
                    .map_err(|_| anyhow!("aes-gcm decrypt at {count}"))?;
                count = count.wrapping_add(1);
                let payload_len = plain.len().saturating_sub(if use_padding { padding_len(&mut shake_size) } else { 0 });
                if plain.is_empty() { break; } // EOF chunk
                w.write_all(&plain[..payload_len]).await?;
            }
            SEC_CHACHA20 => {
                use chacha20poly1305::ChaCha20Poly1305;
                if data_len < 16 { bail!("chunk too small"); }
                let mut ct = vec![0u8; data_len];
                r.read_exact(&mut ct).await?;
                let nonce = chunk_nonce(&iv, count);
                let ck = chacha_key(&key);
                let cipher = ChaCha20Poly1305::new_from_slice(&ck)?;
                let plain = cipher.decrypt(chacha20poly1305::Nonce::from_slice(&nonce), ct.as_slice())
                    .map_err(|_| anyhow!("chacha decrypt"))?;
                count = count.wrapping_add(1);
                if plain.is_empty() { break; }
                w.write_all(&plain).await?;
            }
            _ => bail!("unsupported security {sec}"),
        }
    }
    Ok(())
}

// ── Downlink: target → AES-GCM chunks → client ───────────────────────────────

async fn relay_down<R, W>(
    r: &mut R, w: &mut W,
    key: [u8; 16], iv: [u8; 16],
    opt: u8, sec: u8,
) -> Result<()>
where R: AsyncRead + Unpin, W: AsyncWrite + Unpin,
{
    if sec == SEC_NONE && opt & OPT_CHUNK_STREAM == 0 {
        tokio::io::copy(r, w).await?;
        return Ok(());
    }

    let use_masking  = opt & OPT_CHUNK_MASKING != 0;
    let use_auth_len = opt & OPT_AUTH_LEN != 0;

    let mut shake_size = use_masking.then(|| Shake128Reader::new(&iv));
    let mut count: u16 = 0;
    let auth_len_key = use_auth_len.then(|| kdf16(&key, &[b"auth_len"]));

    let mut buf = vec![0u8; CHUNK_SIZE];

    loop {
        let n = r.read(&mut buf).await?;
        let is_eof = n == 0;

        // Encrypt payload (or empty slice for EOF chunk)
        let plain = if is_eof { &[][..] } else { &buf[..n] };

        let ct: Vec<u8> = match sec {
            SEC_NONE => plain.to_vec(), // no encryption
            SEC_AES128_GCM | SEC_AUTO => {
                let nonce = chunk_nonce(&iv, count);
                let cipher = Aes128Gcm::new_from_slice(&key)?;
                cipher.encrypt(Nonce::from_slice(&nonce), plain)
                    .map_err(|_| anyhow!("aes-gcm encrypt"))?
            }
            SEC_CHACHA20 => {
                use chacha20poly1305::ChaCha20Poly1305;
                let nonce = chunk_nonce(&iv, count);
                let ck = chacha_key(&key);
                let cipher = ChaCha20Poly1305::new_from_slice(&ck)?;
                cipher.encrypt(chacha20poly1305::Nonce::from_slice(&nonce), plain)
                    .map_err(|_| anyhow!("chacha encrypt"))?
            }
            _ => bail!("unsupported security {sec}"),
        };
        count = count.wrapping_add(1);

        let data_len = ct.len() as u16;

        // Write size field
        if use_auth_len {
            let nonce = chunk_nonce(&iv, count); // use next count for len
            let lc = Aes128Gcm::new_from_slice(&auth_len_key.unwrap())?;
            let enc_len = lc.encrypt(Nonce::from_slice(&nonce), data_len.to_be_bytes().as_ref())
                .map_err(|_| anyhow!("len encrypt"))?;
            count = count.wrapping_add(1);
            w.write_all(&enc_len).await?;
        } else if let Some(ref mut sk) = shake_size {
            w.write_all(&(data_len ^ sk.next_u16()).to_be_bytes()).await?;
        } else {
            w.write_all(&data_len.to_be_bytes()).await?;
        }

        w.write_all(&ct).await?;
        w.flush().await?;

        if is_eof { break; }
    }
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Chunk nonce: [count_BE(2)] ++ iv[2..12]  = 12 bytes
fn chunk_nonce(iv: &[u8; 16], count: u16) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0..2].copy_from_slice(&count.to_be_bytes());
    n[2..12].copy_from_slice(&iv[2..12]);
    n
}

fn padding_len(shake: &mut Option<Shake128Reader>) -> usize {
    shake.as_mut().map(|s| (s.next_u16() % 64) as usize).unwrap_or(0)
}

/// ChaCha20 key = MD5(key) ++ MD5(MD5(key))
fn chacha_key(key: &[u8; 16]) -> [u8; 32] {
    use md5::{Digest as _, Md5};
    let h1 = Md5::digest(key);
    let h2 = Md5::digest(h1);
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&h1);
    out[16..].copy_from_slice(&h2);
    out
}

// ── Shake128 stateful reader for chunk masking ────────────────────────────────

struct Shake128Reader {
    inner: sha3::Shake128Reader,
}

impl Shake128Reader {
    fn new(seed: &[u8]) -> Self {
        let mut h = sha3::Shake128::default();
        h.update(seed);
        Self { inner: h.finalize_xof() }
    }

    fn next_u16(&mut self) -> u16 {
        let mut b = [0u8; 2];
        self.inner.read(&mut b);
        u16::from_be_bytes(b)
    }
}

// ── Request/Response header en/decode ────────────────────────────────────────

struct VmessRequest {
    target:            String,
    request_body_key:  [u8; 16],
    request_body_iv:   [u8; 16],
    response_body_key: [u8; 16],
    response_body_iv:  [u8; 16],
    response_token:    u8,
    option:            u8,
    security:          u8,
}

async fn decode_request_header<S: AsyncRead + Unpin + ?Sized>(
    s: &mut S, cmd_key: &[u8; 16],
) -> Result<VmessRequest> {
    let mut auth_id = [0u8; 16];
    s.read_exact(&mut auth_id).await?;
    validate_auth_id(&auth_id, cmd_key)?;

    let mut enc_len = [0u8; 18];
    s.read_exact(&mut enc_len).await?;

    let mut nonce = [0u8; 8];
    s.read_exact(&mut nonce).await?;

    let len_key = kdf16(cmd_key, &[KDF_HDR_LEN_KEY, &auth_id, &nonce]);
    let len_iv  = kdf12(cmd_key, &[KDF_HDR_LEN_IV,  &auth_id, &nonce]);
    let plen = aead_open(&enc_len, &len_key, &len_iv, &auth_id).context("header len")?;
    let header_len = u16::from_be_bytes([plen[0], plen[1]]) as usize;
    if !(41..=2048).contains(&header_len) { bail!("bad header len {header_len}"); }

    let mut enc_hdr = vec![0u8; header_len + 16];
    s.read_exact(&mut enc_hdr).await?;

    let hdr_key = kdf16(cmd_key, &[KDF_HDR_KEY, &auth_id, &nonce]);
    let hdr_iv  = kdf12(cmd_key, &[KDF_HDR_IV,  &auth_id, &nonce]);
    let header = aead_open(&enc_hdr, &hdr_key, &hdr_iv, &auth_id).context("header")?;

    parse_plain_header(&header)
}

fn parse_plain_header(h: &[u8]) -> Result<VmessRequest> {
    if h.len() < 41 { bail!("header too short"); }
    if h[0] != 1    { bail!("unsupported version {}", h[0]); }

    let mut req_iv  = [0u8; 16]; req_iv.copy_from_slice(&h[1..17]);
    let mut req_key = [0u8; 16]; req_key.copy_from_slice(&h[17..33]);
    let response_token = h[33];
    let option   = h[34];
    let pad_len  = (h[35] >> 4) as usize;
    let security = h[35] & 0x0f;
    let cmd      = h[37];
    if cmd != 0x01 { bail!("UDP not supported (cmd={cmd:#x})"); }

    let port = u16::from_be_bytes([h[38], h[39]]);
    let mut idx = 41;
    let host = match h[40] {
        0x01 => {
            let ip = std::net::Ipv4Addr::from(<[u8;4]>::try_from(&h[idx..idx+4])?);
            idx += 4; ip.to_string()
        }
        0x02 => {
            let l = h[idx] as usize; idx += 1;
            let d = String::from_utf8(h[idx..idx+l].to_vec())?;
            idx += l; d
        }
        0x03 => {
            let ip = std::net::Ipv6Addr::from(<[u8;16]>::try_from(&h[idx..idx+16])?);
            idx += 16; format!("[{ip}]")
        }
        t => bail!("unsupported atyp {t:#x}"),
    };
    idx += pad_len;
    if h.len() < idx + 4 { bail!("missing fnv"); }
    let exp = u32::from_be_bytes(h[idx..idx+4].try_into().unwrap());
    if fnv1a32(&h[..idx]) != exp { bail!("fnv mismatch"); }

    let response_body_key = sha256_16(&req_key);
    let response_body_iv  = sha256_16(&req_iv);

    Ok(VmessRequest {
        target: format!("{host}:{port}"),
        request_body_key:  req_key,
        request_body_iv:   req_iv,
        response_body_key,
        response_body_iv,
        response_token,
        option,
        security,
    })
}

async fn encode_response_header<S: AsyncWrite + Unpin + ?Sized>(
    s: &mut S, req: &VmessRequest,
) -> Result<()> {
    let rk = &req.response_body_key;
    let ri = &req.response_body_iv;
    let payload = [req.response_token, req.option, 0x00, 0x00];

    let len_key = kdf16(rk, &[KDF_RESP_LEN_KEY]);
    let len_iv  = kdf12(ri, &[KDF_RESP_LEN_IV]);
    let enc_len = aead_seal(&(payload.len() as u16).to_be_bytes(), &len_key, &len_iv, b"")?;
    s.write_all(&enc_len).await?;

    let pay_key = kdf16(rk, &[KDF_RESP_PAY_KEY]);
    let pay_iv  = kdf12(ri, &[KDF_RESP_PAY_IV]);
    let enc_pay = aead_seal(&payload, &pay_key, &pay_iv, b"")?;
    s.write_all(&enc_pay).await?;
    s.flush().await?;
    Ok(())
}

// ── Auth ID ───────────────────────────────────────────────────────────────────

fn validate_auth_id(auth_id: &[u8; 16], cmd_key: &[u8; 16]) -> Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let auth_key = kdf16(cmd_key, &[KDF_AUTH_ID]);
    let plain = aes128_ecb_decrypt(&auth_key, auth_id)?;
    let ck = crc32fast::hash(&plain[..12]);
    let stored = u32::from_be_bytes(plain[12..16].try_into().unwrap());
    if ck != stored { bail!("auth id bad checksum"); }
    let ts = i64::from_be_bytes(plain[..8].try_into().unwrap());
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    if (ts - now).abs() > 120 { bail!("auth id stale"); }
    Ok(())
}

fn aes128_ecb_decrypt(key: &[u8; 16], block: &[u8; 16]) -> Result<[u8; 16]> {
    use aes_gcm::aes::{Aes128, cipher::{BlockDecrypt, KeyInit as _}};
    let cipher = Aes128::new_from_slice(key).map_err(|_| anyhow!("aes key"))?;
    let mut out = aes_gcm::aes::Block::clone_from_slice(block);
    cipher.decrypt_block(&mut out);
    Ok(out.into())
}

// ── KDF (Xray HMAC-SHA256 chain) ──────────────────────────────────────────────
//
// Xray KDF(key, path...):
//   h = HMAC-SHA256(KDF_ROOT)(key)          // outer key = KDF_ROOT
//   for each salt in path:
//     h = HMAC-SHA256(salt)(h)
//   return h

fn vmess_kdf(key: &[u8], path: &[&[u8]]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(KDF_ROOT).unwrap();
    Mac::update(&mut mac, key);
    let mut h: Vec<u8> = mac.finalize().into_bytes().to_vec();

    for salt in path {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(salt).unwrap();
        Mac::update(&mut mac, &h);
        h = mac.finalize().into_bytes().to_vec();
    }
    h
}

fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    vmess_kdf(key, path)[..16].try_into().unwrap()
}

fn kdf12(key: &[u8], path: &[&[u8]]) -> [u8; 12] {
    vmess_kdf(key, path)[..12].try_into().unwrap()
}

// ── Misc ──────────────────────────────────────────────────────────────────────

fn aead_open(ct: &[u8], key: &[u8; 16], nonce: &[u8; 12], aad: &[u8]) -> Result<Vec<u8>> {
    Aes128Gcm::new_from_slice(key)?
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| anyhow!("aead decrypt"))
}

fn aead_seal(pt: &[u8], key: &[u8; 16], nonce: &[u8; 12], aad: &[u8]) -> Result<Vec<u8>> {
    Aes128Gcm::new_from_slice(key)?
        .encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad })
        .map_err(|_| anyhow!("aead encrypt"))
}

fn sha256_16(b: &[u8; 16]) -> [u8; 16] {
    Sha256::digest(b)[..16].try_into().unwrap()
}

fn fnv1a32(data: &[u8]) -> u32 {
    let mut h: u32 = 2166136261;
    for &b in data { h ^= b as u32; h = h.wrapping_mul(16777619); }
    h
}

fn vmess_cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    use md5::{Digest as _, Md5};
    let mut v = uuid.to_vec();
    v.extend_from_slice(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    Md5::digest(&v)[..16].try_into().unwrap()
}
