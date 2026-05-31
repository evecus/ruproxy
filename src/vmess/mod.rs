use std::{
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    aes::Aes128,
    Aes128Gcm, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use crate::common::tls::standard as shared_tls;
use crate::common::transport::websocket as shared_ws;
use crate::common::transport::xhttp::{XhttpConfig, XhttpServer};
use crate::config::VmessConfig;
use crate::vless::protocol::parse_uuid;

// Salt constants matching Xray/V2Ray spec
const KDF_SALT_VMESS_AEAD_KDF: &[u8] = b"VMess AEAD KDF";
const KDF_SALT_AUTH_ID_ENCRYPTION_KEY: &[u8] = b"AES Auth ID Encryption";
const KDF_SALT_HEADER_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const KDF_SALT_HEADER_LEN_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
const KDF_SALT_HEADER_KEY: &[u8] = b"VMess Header AEAD Key";
const KDF_SALT_HEADER_IV: &[u8] = b"VMess Header AEAD Nonce";

// Response header KDF salts (Xray: KDFSaltConstAEADResp*)
const KDF_SALT_AEAD_RESP_HEADER_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const KDF_SALT_AEAD_RESP_HEADER_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const KDF_SALT_AEAD_RESP_HEADER_KEY: &[u8] = b"AEAD Resp Header Key";
const KDF_SALT_AEAD_RESP_HEADER_IV: &[u8] = b"AEAD Resp Header IV";

pub async fn run(cfg: Arc<VmessConfig>) -> Result<()> {
    let uuid = parse_uuid(&cfg.uuid)?;
    let cmd_key = vmess_cmd_key(&uuid);
    let tls_acceptor = if let Some(t) = &cfg.tls {
        let sc = shared_tls::build(
            t.cert_path.as_deref(),
            t.key_path.as_deref(),
            t.self_signed_domain.as_deref(),
        )?;
        Some(Arc::new(TlsAcceptor::from(Arc::new(sc))))
    } else {
        None
    };

    let addr: SocketAddr = cfg.listen.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!("[vmess] Listening on {addr}");

    // ── xhttp：server 级别 session 表 ─────────────────────────────────────────
    if cfg.transport.r#type == "xhttp" {
        let xh_cfg = XhttpConfig {
            path: cfg.transport.xhttp_path.clone(),
            host: cfg.transport.xhttp_host.clone(),
        };
        let xhttp_server = XhttpServer::new(xh_cfg);

        // 任务1：接受 TCP，feed 给 xhttp_server
        let srv_feed = xhttp_server.clone();
        let tls2 = tls_acceptor.clone();
        tokio::spawn(async move {
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(p) => p,
                    Err(e) => { warn!("[vmess] accept error: {e}"); continue; }
                };
                match &tls2 {
                    None => { srv_feed.feed_plain(stream, peer); }
                    Some(acc) => {
                        let acc = Arc::clone(acc);
                        let srv = srv_feed.clone();
                        tokio::spawn(async move {
                            match acc.accept(stream).await {
                                Ok(tls) => srv.feed_tls(tls, peer),
                                Err(e) => warn!("[vmess] {peer} TLS: {e}"),
                            }
                        });
                    }
                }
            }
        });

        // 任务2：accept() 取完整逻辑连接
        loop {
            match xhttp_server.accept().await {
                None => { warn!("[vmess] xhttp server closed"); break; }
                Some(xhs) => {
                    tokio::spawn(async move {
                        let peer: SocketAddr = "0.0.0.0:0".parse().unwrap();
                        if let Err(e) = process(xhs, peer, cmd_key, uuid).await {
                            warn!("[vmess] {peer}: {e:#}");
                        }
                    });
                }
            }
        }
        return Ok(());
    }

    // ── 其他 transport ────────────────────────────────────────────────────────
    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg2 = Arc::clone(&cfg);
        let tls = tls_acceptor.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, peer, &cfg2, cmd_key, uuid, tls).await {
                warn!("[vmess] {peer}: {e:#}");
            }
        });
    }
}

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

async fn handle(
    stream: TcpStream,
    peer: SocketAddr,
    cfg: &VmessConfig,
    cmd_key: [u8; 16],
    uuid: [u8; 16],
    tls_acceptor: Option<Arc<TlsAcceptor>>,
) -> Result<()> {
    let mut io: Box<dyn AsyncReadWrite> = match (cfg.transport.r#type.as_str(), tls_acceptor) {
        ("tcp", None) => Box::new(stream),
        ("tcp", Some(a)) => Box::new(a.accept(stream).await?),
        ("ws", None) => Box::new(
            shared_ws::accept_plain(stream, &cfg.transport.ws_path, cfg.transport.ws_host.as_deref()).await?,
        ),
        ("ws", Some(a)) => {
            let tls = a.accept(stream).await?;
            Box::new(shared_ws::accept_tls(tls, &cfg.transport.ws_path, cfg.transport.ws_host.as_deref()).await?)
        }
        _ => bail!("bad transport"),
    };
    process(&mut *io, peer, cmd_key, uuid).await
}

async fn process<S>(io: &mut S, peer: SocketAddr, cmd_key: [u8; 16], uuid: [u8; 16]) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let req = decode_vmess_aead_request(io, &cmd_key, &uuid)
        .await
        .context("decode vmess aead request")?;
    info!("[vmess] {peer} -> {}", req.target);

    let outbound = TcpStream::connect(&req.target).await?;
    encode_vmess_aead_response(io, req.request_body_key, req.request_body_iv).await?;

    let (mut out_r, mut out_w) = outbound.into_split();
    let (mut in_r, mut in_w) = tokio::io::split(io);

    let uplink = async {
        let _ = tokio::io::copy(&mut in_r, &mut out_w).await;
        let _ = out_w.shutdown().await;
    };
    let downlink = async {
        let _ = tokio::io::copy(&mut out_r, &mut in_w).await;
        let _ = in_w.shutdown().await;
    };
    tokio::join!(uplink, downlink);
    Ok(())
}

struct VmessRequest {
    target: String,
    request_body_key: [u8; 16],
    request_body_iv: [u8; 16],
}

async fn decode_vmess_aead_request<S: AsyncRead + Unpin>(
    s: &mut S,
    cmd_key: &[u8; 16],
    _uuid: &[u8; 16],
) -> Result<VmessRequest> {
    let mut auth_id = [0u8; 16];
    s.read_exact(&mut auth_id).await?;
    validate_auth_id(&auth_id, cmd_key)?;

    let mut enc_len = [0u8; 18];
    s.read_exact(&mut enc_len).await?;

    let mut nonce = [0u8; 8];
    s.read_exact(&mut nonce).await?;

    let len_key = kdf16(cmd_key, &[KDF_SALT_HEADER_LEN_KEY, &auth_id, &nonce]);
    let len_iv = kdf12(cmd_key, &[KDF_SALT_HEADER_LEN_IV, &auth_id, &nonce]);
    let plain_len_bytes =
        aead_open_aad(&enc_len, &len_key, &len_iv, &auth_id).context("decrypt len")?;
    if plain_len_bytes.len() != 2 {
        bail!("invalid length block");
    }
    let header_len = u16::from_be_bytes([plain_len_bytes[0], plain_len_bytes[1]]) as usize;
    if !(41..=2048).contains(&header_len) {
        bail!("invalid vmess header length: {header_len}");
    }

    let mut enc_header = vec![0u8; header_len + 16];
    s.read_exact(&mut enc_header).await?;

    let header_key = kdf16(cmd_key, &[KDF_SALT_HEADER_KEY, &auth_id, &nonce]);
    let header_iv = kdf12(cmd_key, &[KDF_SALT_HEADER_IV, &auth_id, &nonce]);
    let header =
        aead_open_aad(&enc_header, &header_key, &header_iv, &auth_id).context("decrypt header")?;

    parse_vmess_plain_header(&header)
}

fn parse_vmess_plain_header(header: &[u8]) -> Result<VmessRequest> {
    if header.len() < 41 {
        bail!("vmess header too short");
    }
    let ver = header[0];
    if ver != 1 {
        bail!("unsupported vmess version: {ver}");
    }

    let mut req_iv = [0u8; 16];
    req_iv.copy_from_slice(&header[1..17]);
    let mut req_key = [0u8; 16];
    req_key.copy_from_slice(&header[17..33]);

    let _response_token = header[33];
    let opt = header[34];
    let pad_len = (header[35] >> 4) as usize;
    let security = header[35] & 0x0f;
    if security != 0x05 && security != 0x03 && security != 0x00 {
        bail!("unsupported security type: {security:#x}");
    }
    let cmd = header[37];
    if cmd != 0x01 {
        bail!("only tcp supported, cmd={cmd:#x}");
    }

    let port = u16::from_be_bytes([header[38], header[39]]);
    let mut idx = 41;
    let atyp = header[40];
    let host = match atyp {
        0x01 => {
            if header.len() < idx + 4 { bail!("short ipv4") }
            let mut b = [0; 4];
            b.copy_from_slice(&header[idx..idx + 4]);
            idx += 4;
            std::net::Ipv4Addr::from(b).to_string()
        }
        0x02 => {
            if header.len() < idx + 1 { bail!("short domain len") }
            let l = header[idx] as usize;
            idx += 1;
            if header.len() < idx + l { bail!("short domain") }
            let d = String::from_utf8(header[idx..idx + l].to_vec())?;
            idx += l;
            d
        }
        0x03 => {
            if header.len() < idx + 16 { bail!("short ipv6") }
            let mut b = [0; 16];
            b.copy_from_slice(&header[idx..idx + 16]);
            idx += 16;
            format!("[{}]", std::net::Ipv6Addr::from(b))
        }
        _ => bail!("unsupported atyp {atyp:#x}"),
    };

    idx += pad_len;

    if header.len() < idx + 4 {
        bail!("vmess header missing fnv checksum");
    }
    let expected_fnv = u32::from_be_bytes(header[idx..idx + 4].try_into().unwrap());
    let actual_fnv = fnv1a_32(&header[..idx]);
    if actual_fnv != expected_fnv {
        bail!("vmess header fnv checksum mismatch");
    }

    let _ = opt;

    Ok(VmessRequest {
        target: format!("{host}:{port}"),
        request_body_key: req_key,
        request_body_iv: req_iv,
    })
}

fn fnv1a_32(data: &[u8]) -> u32 {
    const OFFSET_BASIS: u32 = 2166136261;
    const PRIME: u32 = 16777619;
    let mut h = OFFSET_BASIS;
    for &b in data {
        h ^= b as u32;
        h = h.wrapping_mul(PRIME);
    }
    h
}

async fn encode_vmess_aead_response<S: AsyncWrite + Unpin>(
    s: &mut S,
    request_body_key: [u8; 16],
    request_body_iv: [u8; 16],
) -> Result<()> {
    let resp_key = sha256_16(&request_body_key);
    let resp_iv = sha256_16(&request_body_iv);

    let len_key = kdf16(&resp_key, &[KDF_SALT_AEAD_RESP_HEADER_LEN_KEY]);
    let len_iv = kdf12(&resp_iv, &[KDF_SALT_AEAD_RESP_HEADER_LEN_IV]);
    let pay_key = kdf16(&resp_key, &[KDF_SALT_AEAD_RESP_HEADER_KEY]);
    let pay_iv = kdf12(&resp_iv, &[KDF_SALT_AEAD_RESP_HEADER_IV]);

    let payload: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
    let payload_len_be = (payload.len() as u16).to_be_bytes();

    let enc_len = aead_seal(&payload_len_be, &len_key, &len_iv, b"")?;
    s.write_all(&enc_len).await?;

    let enc_pay = aead_seal(&payload, &pay_key, &pay_iv, b"")?;
    s.write_all(&enc_pay).await?;

    Ok(())
}

fn vmess_cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    md5_two(uuid, b"c48619fe-8f02-49e0-b9e9-edf763e17e21")
}

fn md5_two(a: &[u8], b: &[u8]) -> [u8; 16] {
    let mut msg = Vec::with_capacity(a.len() + b.len());
    msg.extend_from_slice(a);
    msg.extend_from_slice(b);
    md5_hash(&msg)
}

fn md5_hash(input: &[u8]) -> [u8; 16] {
    #[rustfmt::skip]
    const T: [u32; 64] = [
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391,
    ];
    #[rustfmt::skip]
    const S: [u32; 64] = [
        7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
        5, 9,14,20,5, 9,14,20,5, 9,14,20,5, 9,14,20,
        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
        6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21,
    ];

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut msg = input.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let (mut a0, mut b0, mut c0, mut d0) =
        (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);

    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for (i, w) in m.iter_mut().enumerate() {
            let j = i * 4;
            *w = u32::from_le_bytes(chunk[j..j + 4].try_into().unwrap());
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0usize..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(f).wrapping_add(T[i]).wrapping_add(m[g]).rotate_left(S[i]),
            );
            a = temp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

fn validate_auth_id(auth_id: &[u8; 16], cmd_key: &[u8; 16]) -> Result<()> {
    let auth_key = kdf16(cmd_key, &[KDF_SALT_AUTH_ID_ENCRYPTION_KEY]);
    let plain = aes128_ecb_decrypt(&auth_key, auth_id)?;

    let checksum = crc32fast::hash(&plain[..12]);
    let stored = u32::from_be_bytes([plain[12], plain[13], plain[14], plain[15]]);
    if checksum != stored { bail!("invalid auth id"); }

    let ts = i64::from_be_bytes(plain[..8].try_into().unwrap());
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    if (ts - now).abs() > 120 { bail!("invalid auth id"); }

    Ok(())
}

fn aes128_ecb_decrypt(key: &[u8; 16], block: &[u8; 16]) -> Result<[u8; 16]> {
    use aes_gcm::aes::cipher::{BlockDecrypt, KeyInit as _};
    let cipher = Aes128::new_from_slice(key).map_err(|_| anyhow!("aes key error"))?;
    let mut out = aes_gcm::aes::Block::clone_from_slice(block);
    cipher.decrypt_block(&mut out);
    Ok(out.into())
}

fn vmess_kdf(key: &[u8], path: &[&[u8]]) -> Vec<u8> {
    const BLOCK: usize = 64;
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    type HashFn = Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;

    fn make_layer(hmac_key: &[u8], hash_fn: HashFn) -> HashFn {
        let k_raw = if hmac_key.len() > BLOCK { hash_fn(hmac_key) } else { hmac_key.to_vec() };
        let mut k_padded = [0u8; BLOCK];
        k_padded[..k_raw.len()].copy_from_slice(&k_raw);
        let ipad: Vec<u8> = k_padded.iter().map(|b| b ^ IPAD).collect();
        let opad: Vec<u8> = k_padded.iter().map(|b| b ^ OPAD).collect();
        Arc::new(move |msg: &[u8]| {
            let mut inner_input = ipad.clone();
            inner_input.extend_from_slice(msg);
            let inner_hash = hash_fn(&inner_input);
            let mut outer_input = opad.clone();
            outer_input.extend_from_slice(&inner_hash);
            hash_fn(&outer_input)
        })
    }

    let sha256_fn: HashFn = Arc::new(|m: &[u8]| {
        let mut h = Sha256::new();
        h.update(m);
        h.finalize().to_vec()
    });

    let mut h = make_layer(KDF_SALT_VMESS_AEAD_KDF, sha256_fn);
    for salt in path { h = make_layer(salt, h); }
    h(key)
}

fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let r = vmess_kdf(key, path);
    let mut out = [0u8; 16];
    out.copy_from_slice(&r[..16]);
    out
}

fn kdf12(key: &[u8], path: &[&[u8]]) -> [u8; 12] {
    let r = vmess_kdf(key, path);
    let mut out = [0u8; 12];
    out.copy_from_slice(&r[..12]);
    out
}

fn aead_open_aad(ct: &[u8], key: &[u8; 16], nonce: &[u8; 12], aad: &[u8]) -> Result<Vec<u8>> {
    let c = Aes128Gcm::new_from_slice(key)?;
    c.decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| anyhow!("aead decrypt failed"))
}

fn aead_seal(pt: &[u8], key: &[u8; 16], nonce: &[u8; 12], aad: &[u8]) -> Result<Vec<u8>> {
    let c = Aes128Gcm::new_from_slice(key)?;
    c.encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad })
        .map_err(|_| anyhow!("aead encrypt failed"))
}

fn sha256_16(input: &[u8; 16]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(input);
    let out = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&out[..16]);
    b
}
