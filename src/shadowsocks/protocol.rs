//! Shadowsocks AEAD protocol helpers.
//!
//! Wire format for TCP (AEAD, matching Xray/shadowsocks-go):
//!
//! ```text
//! [salt: key_len bytes]  — sent in plaintext before any AEAD chunks
//! repeated:
//!   [2-byte ciphertext length + 16-byte tag]
//!   [N-byte ciphertext payload  + 16-byte tag]
//! ```
//!
//! Address header (first decrypted bytes, SOCKS5-style):
//! ```text
//! [1B]  ATYP      0x01=IPv4, 0x03=Domain, 0x04=IPv6
//! [NB]  address   4 / (1+N) / 16 bytes
//! [2B]  port      big-endian u16
//! ```
//!
//! References:
//! - https://shadowsocks.org/doc/aead.html
//! - Xray proxy/shadowsocks/{protocol,config}.go

use anyhow::{bail, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use bytes::{Buf, BufMut, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::ShadowsocksCipher;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum plaintext chunk (matches shadowsocks-go / Xray).
pub const MAX_CHUNK: usize = 0x3FFF; // 16383 bytes

// ── Key derivation ────────────────────────────────────────────────────────────

/// Derive a per-session subkey with HKDF-SHA1 ("ss-subkey").
pub fn derive_subkey(key: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha1>::new(Some(salt), key);
    let mut okm = vec![0u8; key_len];
    hk.expand(b"ss-subkey", &mut okm)
        .expect("HKDF expand failed");
    okm
}

/// Derive a fixed-length master key from a password using EVP_BytesToKey (MD5).
pub fn evp_bytes_to_key(password: &str, key_len: usize) -> Vec<u8> {
    use md5::{Digest, Md5};
    let mut key = Vec::with_capacity(key_len);
    let mut prev: Vec<u8> = Vec::new();
    while key.len() < key_len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(password.as_bytes());
        prev = h.finalize().to_vec();
        key.extend_from_slice(&prev);
    }
    key.truncate(key_len);
    key
}

// ── AEAD helpers ──────────────────────────────────────────────────────────────

pub fn aead_encrypt(cipher: &ShadowsocksCipher, key: &[u8], nonce: &[u8; 12], pt: &[u8]) -> Result<Vec<u8>> {
    let n = GenericArray::from_slice(nonce);
    let r = match cipher {
        ShadowsocksCipher::Aes128Gcm => Aes128Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("{e}"))?.encrypt(n, pt),
        ShadowsocksCipher::Aes256Gcm => Aes256Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("{e}"))?.encrypt(n, pt),
        ShadowsocksCipher::Chacha20IetfPoly1305 => ChaCha20Poly1305::new_from_slice(key).map_err(|e| anyhow::anyhow!("{e}"))?.encrypt(n, pt),
    };
    r.map_err(|_| anyhow::anyhow!("AEAD encrypt failed"))
}

pub fn aead_decrypt(cipher: &ShadowsocksCipher, key: &[u8], nonce: &[u8; 12], ct: &[u8]) -> Result<Vec<u8>> {
    let n = GenericArray::from_slice(nonce);
    let r = match cipher {
        ShadowsocksCipher::Aes128Gcm => Aes128Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("{e}"))?.decrypt(n, ct),
        ShadowsocksCipher::Aes256Gcm => Aes256Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("{e}"))?.decrypt(n, ct),
        ShadowsocksCipher::Chacha20IetfPoly1305 => ChaCha20Poly1305::new_from_slice(key).map_err(|e| anyhow::anyhow!("{e}"))?.decrypt(n, ct),
    };
    r.map_err(|_| anyhow::anyhow!("AEAD decrypt failed"))
}

/// Little-endian counter increment (Shadowsocks AEAD nonce spec).
pub fn increment_nonce(n: &mut [u8; 12]) {
    for b in n.iter_mut() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            break;
        }
    }
}

// ── Address I/O ───────────────────────────────────────────────────────────────

const ATYP_IPV4: u8   = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8   = 0x04;

/// Read SOCKS5-style address from an async reader → `"host:port"`.
pub async fn read_address<R: AsyncRead + Unpin>(r: &mut R) -> Result<String> {
    let atyp = r.read_u8().await?;
    let host = match atyp {
        ATYP_IPV4 => {
            let mut b = [0u8; 4];
            r.read_exact(&mut b).await?;
            Ipv4Addr::from(b).to_string()
        }
        ATYP_DOMAIN => {
            let len = r.read_u8().await? as usize;
            let mut b = vec![0u8; len];
            r.read_exact(&mut b).await?;
            String::from_utf8(b)?
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 16];
            r.read_exact(&mut b).await?;
            format!("[{}]", Ipv6Addr::from(b))
        }
        _ => bail!("shadowsocks: unknown ATYP {atyp:#x}"),
    };
    let port = r.read_u16().await?;
    Ok(format!("{host}:{port}"))
}

// ── Async AEAD codec (read/write via explicit async fn, not poll_*) ───────────
//
// Rather than implementing AsyncRead/AsyncWrite directly (which requires a
// poll-based state machine that cannot call async fns), we expose simple
// async methods.  The relay loop drives them with `tokio::io::copy` by
// wrapping them in a thin adapter only when needed — but for the internal
// relay we just use these methods directly via two tasks.

/// Decrypts a Shadowsocks AEAD stream.
pub struct AeadReader<R> {
    pub inner: R,
    pub cipher: ShadowsocksCipher,
    pub subkey: Vec<u8>,
    pub nonce: [u8; 12],
    /// Decrypted bytes not yet consumed by the caller
    pub buf: BytesMut,
}

impl<R: AsyncRead + Unpin> AeadReader<R> {
    pub fn new(inner: R, cipher: ShadowsocksCipher, subkey: Vec<u8>) -> Self {
        Self { inner, cipher, subkey, nonce: [0u8; 12], buf: BytesMut::new() }
    }

    /// Read exactly one AEAD chunk from the wire and append plaintext to `self.buf`.
    /// Returns `false` on clean EOF.
    pub async fn read_chunk(&mut self) -> Result<bool> {
        let tag_len = self.cipher.tag_len();
        let len_ct_len = 2 + tag_len;

        let mut len_ct = vec![0u8; len_ct_len];
        match self.inner.read_exact(&mut len_ct).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(false),
            Err(e) => return Err(e.into()),
        }
        let len_pt = aead_decrypt(&self.cipher, &self.subkey, &self.nonce, &len_ct)?;
        increment_nonce(&mut self.nonce);

        let payload_len = u16::from_be_bytes([len_pt[0], len_pt[1]]) as usize;
        let mut payload_ct = vec![0u8; payload_len + tag_len];
        self.inner.read_exact(&mut payload_ct).await?;
        let payload_pt = aead_decrypt(&self.cipher, &self.subkey, &self.nonce, &payload_ct)?;
        increment_nonce(&mut self.nonce);

        self.buf.put_slice(&payload_pt);
        Ok(true)
    }

    /// Read bytes into `dst` (fills `dst` fully, may read multiple chunks).
    pub async fn read_bytes(&mut self, dst: &mut [u8]) -> Result<usize> {
        let mut written = 0;
        while written < dst.len() {
            if self.buf.is_empty() {
                if !self.read_chunk().await? {
                    break; // EOF
                }
            }
            let n = self.buf.len().min(dst.len() - written);
            dst[written..written + n].copy_from_slice(&self.buf[..n]);
            self.buf.advance(n);
            written += n;
        }
        Ok(written)
    }
}

/// Encrypts data as a Shadowsocks AEAD stream.
pub struct AeadWriter<W> {
    pub inner: W,
    pub cipher: ShadowsocksCipher,
    pub subkey: Vec<u8>,
    pub nonce: [u8; 12],
}

impl<W: AsyncWrite + Unpin> AeadWriter<W> {
    pub fn new(inner: W, cipher: ShadowsocksCipher, subkey: Vec<u8>) -> Self {
        Self { inner, cipher, subkey, nonce: [0u8; 12] }
    }

    /// Write raw (unencrypted) bytes — for the response salt.
    pub async fn write_raw(&mut self, data: &[u8]) -> Result<()> {
        self.inner.write_all(data).await?;
        Ok(())
    }

    /// Reset subkey and nonce counter — called after writing the response salt.
    pub fn reset_subkey(&mut self, new_subkey: Vec<u8>) {
        self.subkey = new_subkey;
        self.nonce = [0u8; 12];
    }

    /// Encrypt and write `data` as one or more AEAD chunks.
    pub async fn write_data(&mut self, data: &[u8]) -> Result<()> {
        let mut offset = 0;
        while offset < data.len() {
            let chunk_len = (data.len() - offset).min(MAX_CHUNK);
            let chunk = &data[offset..offset + chunk_len];

            let len_pt = [(chunk_len >> 8) as u8, chunk_len as u8];
            let len_ct = aead_encrypt(&self.cipher, &self.subkey, &self.nonce, &len_pt)?;
            increment_nonce(&mut self.nonce);

            let payload_ct = aead_encrypt(&self.cipher, &self.subkey, &self.nonce, chunk)?;
            increment_nonce(&mut self.nonce);

            self.inner.write_all(&len_ct).await?;
            self.inner.write_all(&payload_ct).await?;

            offset += chunk_len;
        }
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<()> {
        self.inner.flush().await?;
        Ok(())
    }
}
