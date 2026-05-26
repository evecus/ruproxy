//! AnyTLS padding scheme.
//!
//! Implements the default padding scheme and parsing of server-sent updates.
//! The scheme controls how the first N TLS records are padded/split to
//! defeat traffic-analysis fingerprinting.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Sentinel value in a size list meaning "check if payload is exhausted".
pub const CHECK_MARK: i64 = -1;

/// Default padding scheme (matches anytls-go reference implementation).
static DEFAULT_SCHEME_BYTES: &[u8] = b"stop=8\n\
    0=30-30\n\
    1=100-400\n\
    2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n\
    3=9-9,500-1000\n\
    4=500-1000\n\
    5=500-1000\n\
    6=500-1000\n\
    7=500-1000";

#[derive(Clone, Debug)]
pub struct PaddingScheme {
    /// Packet index at which padding stops.
    pub stop: u32,
    /// For each packet index that has a rule: list of sizes or CHECK_MARK.
    pub rules: HashMap<u32, Vec<i64>>,
    /// Raw bytes of the scheme (for sending to clients in cmdUpdatePaddingScheme).
    pub raw: Vec<u8>,
    /// MD5 hex of raw bytes.
    pub md5_hex: String,
}

impl PaddingScheme {
    pub fn from_bytes(raw: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(raw).ok()?;
        let mut stop: Option<u32> = None;
        let mut rules = HashMap::new();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() { continue; }
            let (k, v) = line.split_once('=')?;
            let k = k.trim();
            let v = v.trim();
            if k == "stop" {
                stop = Some(v.parse().ok()?);
            } else if let Ok(idx) = k.parse::<u32>() {
                let sizes = parse_size_list(v);
                rules.insert(idx, sizes);
            }
        }

        let stop = stop?;
        let md5_hex = format!("{:x}", md5::compute(raw));
        Some(PaddingScheme { stop, rules, raw: raw.to_vec(), md5_hex })
    }

    /// Generate TLS record payload sizes for packet index `pkt`.
    /// Returns empty vec if no rule exists (send as-is).
    pub fn sizes_for(&self, pkt: u32) -> &[i64] {
        self.rules.get(&pkt).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

fn parse_size_list(s: &str) -> Vec<i64> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part == "c" {
            out.push(CHECK_MARK);
        } else if let Some((lo, hi)) = part.split_once('-') {
            let lo: i64 = lo.parse().unwrap_or(0);
            let hi: i64 = hi.parse().unwrap_or(0);
            if lo <= 0 || hi <= 0 { continue; }
            let lo = lo.min(hi);
            let hi = lo.max(hi);
            if lo == hi {
                out.push(lo);
            } else {
                // Random value in [lo, hi]
                use rand::Rng;
                let r = rand::thread_rng().gen_range(lo..=hi);
                out.push(r);
            }
        }
    }
    out
}

/// Shared, atomically replaceable padding scheme.
#[derive(Clone)]
pub struct SharedPadding(Arc<RwLock<Arc<PaddingScheme>>>);

impl SharedPadding {
    pub fn new_default() -> Self {
        let scheme = PaddingScheme::from_bytes(DEFAULT_SCHEME_BYTES)
            .expect("default padding scheme is valid");
        Self(Arc::new(RwLock::new(Arc::new(scheme))))
    }

    pub fn get(&self) -> Arc<PaddingScheme> {
        self.0.read().unwrap().clone()
    }

    pub fn update(&self, raw: &[u8]) -> bool {
        if let Some(scheme) = PaddingScheme::from_bytes(raw) {
            *self.0.write().unwrap() = Arc::new(scheme);
            true
        } else {
            false
        }
    }
}
