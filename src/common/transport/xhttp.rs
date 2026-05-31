//! XHTTP (SplitHTTP) transport — server-side accept.
//!
//! ## 与 Xray splithttp hub.go 的对齐说明
//!
//! ### Xray 默认行为（mode = "auto" → "packet-up"，无 Reality 时）
//!
//! URL 结构（sessionPlacement=path, seqPlacement=path 为默认值）：
//!   GET  /<basepath>/<sessionId>          → downlink（流式响应体）
//!   POST /<basepath>/<sessionId>/<seq>    → packet-up（带序号的单包）
//!   POST /<basepath>/<sessionId>          → stream-up（无序号，流式 body）
//!   GET  /<basepath>                      → stream-one（无 sessionId）
//!
//! ### 原版 ruproxy xhttp.rs 的核心问题
//!
//! 原版把每个 TCP 连接当作一个独立的 session，在 HTTP 层没有 session 管理：
//!   - 没有解析 sessionId：GET/<base>/<sid> 和 POST/<base>/<sid> 无法对应
//!   - accept_hyper 等待一个 GET，但 packet-up 模式下 POST 会先到达（甚至只有 POST）
//!   - path 解析逻辑错误：Xray 路径是 /<base>/<sid>[/<seq>]，原版解析的格式不同
//!
//! ### 本次修复内容
//!
//! 1. **Session 表**
//!    用 `Arc<Mutex<HashMap<String, Arc<Notify>>>>` 追踪已知 sessionId。
//!    每个 session 有一个 `Notify`，GET handler 到达时触发，供 TTL 清理用。
//!    核心的 up_tx / down_rx 仍然是全局唯一的（每个 TCP 连接一对），
//!    因为 accept_hyper 只返回一个 XhttpStream，所有 session 共享同一上下行通道。
//!
//! 2. **Path 解析修正**（对齐 Xray ExtractMetaFromRequest）
//!    /<basepath>/<sessionId>          → session_id=Some, seq=None
//!    /<basepath>/<sessionId>/<seq>    → session_id=Some, seq=Some
//!    /<basepath>                      → session_id=None  (stream-one)
//!
//! 3. **Session TTL**
//!    POST 先到时创建 session 记录并启动 30s TTL；
//!    GET 到达时通知 TTL goroutine 退出，防止内存泄漏。
//!
//! 4. **accept_hyper 等待逻辑修正**
//!    等待 GET 就绪通知（无论 GET/POST 谁先到），超时 30s。
//!
//! ### 数据流
//!
//! ```text
//!  客户端 POST ──► handle_post ──► up_tx ──► up_rx ──► XhttpStream::poll_read
//!  XhttpStream::poll_write ──► down_tx ──► down_rx ──► GET response body (StreamBody)
//! ```

use anyhow::Result;
use bytes::{Buf, BytesMut};
use http_body_util::BodyExt;
use hyper::{Method, Request, Response, StatusCode};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, Notify, oneshot};
use tokio_util::sync::PollSender;
use tracing::{debug, warn};

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct XhttpConfig {
    pub path: String,
    pub host: Option<String>,
}

impl Default for XhttpConfig {
    fn default() -> Self {
        Self { path: "/".to_string(), host: None }
    }
}

impl XhttpConfig {
    /// 返回规范化后的 base path，末尾统一带 '/'
    pub fn normalized_path(&self) -> String {
        let p = self.path.trim_end_matches('/');
        let p = if p.starts_with('/') { p.to_string() } else { format!("/{p}") };
        format!("{p}/")
    }
}

// ── 上行数据包 ─────────────────────────────────────────────────────────────────

enum UploadPacket {
    Chunk(bytes::Bytes),                     // stream-up chunk
    Packet { seq: u64, data: bytes::Bytes }, // packet-up with seq
    Eof,
}

// ── Public API ────────────────────────────────────────────────────────────────

pub async fn accept_plain(
    stream: TcpStream,
    peer: SocketAddr,
    cfg: &XhttpConfig,
) -> Result<XhttpStream> {
    accept_hyper(hyper_util::rt::TokioIo::new(stream), peer, cfg).await
}

pub async fn accept_tls<S>(stream: S, peer: SocketAddr, cfg: &XhttpConfig) -> Result<XhttpStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    accept_hyper(hyper_util::rt::TokioIo::new(stream), peer, cfg).await
}

// ── accept_hyper ──────────────────────────────────────────────────────────────

async fn accept_hyper<IO>(io: IO, peer: SocketAddr, cfg: &XhttpConfig) -> Result<XhttpStream>
where
    IO: hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
{
    let base_path = cfg.normalized_path();
    let host = cfg.host.clone();

    // 上行 channel：HTTP POST handler → XhttpStream 读端
    let (up_tx, up_rx) = mpsc::channel::<UploadPacket>(64);

    // 下行 channel：XhttpStream 写端 → GET response body
    let (down_tx, down_rx) = mpsc::channel::<bytes::Bytes>(64);

    // GET handler 取走 down_rx 后通知 accept 可以继续
    let (get_done_tx, get_done_rx) = oneshot::channel::<()>();

    // GET 到达通知
    let get_ready = Arc::new(Notify::new());

    // Session 表：记录已见到的 sessionId，每个 session 有 get_arrived Notify
    // 用于 POST 先到时启动 TTL，GET 到达时取消 TTL
    let sessions: Arc<Mutex<HashMap<String, Arc<Notify>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let shared = Arc::new(ServiceShared {
        base_path,
        host,
        up_tx: up_tx.clone(),
        down_rx_slot: Mutex::new(Some((down_rx, get_done_tx))),
        get_ready: Arc::clone(&get_ready),
        down_tx_clone: down_tx,
        sessions,
    });

    tokio::spawn({
        let shared = Arc::clone(&shared);
        async move {
            let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                let shared = Arc::clone(&shared);
                async move {
                    let resp = handle_request(req, &shared, peer).await;
                    Ok::<_, std::convert::Infallible>(resp)
                }
            });

            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .await
            {
                debug!("[xhttp] {peer} conn closed: {e}");
            }
            // 连接关闭 → 上行 EOF
            let _ = up_tx.send(UploadPacket::Eof).await;
        }
    });

    // 等待 GET 请求到达（最多 30s）
    tokio::time::timeout(Duration::from_secs(30), get_ready.notified())
        .await
        .map_err(|_| anyhow::anyhow!("[xhttp] {peer}: timeout waiting for GET downlink"))?;

    // 等 GET handler 确认已取走 down_rx
    let _ = tokio::time::timeout(Duration::from_millis(200), get_done_rx).await;

    Ok(XhttpStream::new(up_rx, shared.down_tx_clone.clone()))
}

// ── 服务端共享状态 ─────────────────────────────────────────────────────────────

struct ServiceShared {
    base_path: String,
    host: Option<String>,
    up_tx: mpsc::Sender<UploadPacket>,
    /// 第一个 GET handler 从这里取走 (down_rx, get_done_tx)（只取一次）
    down_rx_slot: Mutex<Option<(mpsc::Receiver<bytes::Bytes>, oneshot::Sender<()>)>>,
    /// GET 到达通知（通知 accept_hyper）
    get_ready: Arc<Notify>,
    /// 供 XhttpStream 写端使用的下行 sender clone
    down_tx_clone: mpsc::Sender<bytes::Bytes>,
    /// Session 表：sessionId → get_arrived Notify
    sessions: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
}

// ── 路径解析 ───────────────────────────────────────────────────────────────────

/// 从请求路径中解析 (session_id, seq_str)。
///
/// Xray 默认 sessionPlacement=path, seqPlacement=path：
///   /<basepath>/<sessionId>          → (Some(sessionId), None)
///   /<basepath>/<sessionId>/<seq>    → (Some(sessionId), Some(seq))
///   /<basepath> 或 /<basepath>/      → (None, None)  ← stream-one
///
/// 返回 None 表示 path 不匹配 base_path，应返回 404。
fn parse_path(req_path: &str, base_path: &str) -> Option<(Option<String>, Option<String>)> {
    // base_path 末尾有 '/'，例如 "/xhttp/"
    // req_path 可能是 "/xhttp"（stream-one, 无 trailing slash）
    let base_no_slash = base_path.trim_end_matches('/');

    let rest = if req_path == base_no_slash || req_path == base_path {
        // stream-one 或 /<base>/
        ""
    } else if let Some(s) = req_path.strip_prefix(base_path) {
        // /<base>/<rest>
        s.trim_start_matches('/')
    } else {
        return None; // 路径不匹配
    };

    if rest.is_empty() {
        return Some((None, None));
    }

    // rest 形如 "<sessionId>" 或 "<sessionId>/<seq>"
    let mut parts = rest.splitn(2, '/');
    let session_id = parts.next().filter(|s| !s.is_empty()).map(str::to_string);
    let seq = parts.next().filter(|s| !s.is_empty()).map(str::to_string);
    Some((session_id, seq))
}

// ── HTTP 请求处理 ──────────────────────────────────────────────────────────────

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    shared: &Arc<ServiceShared>,
    peer: SocketAddr,
) -> Response<ResponseBody> {
    // Host 校验
    if let Some(expected) = &shared.host {
        let req_host = req.headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if req_host != expected.as_str() {
            warn!("[xhttp] {peer} bad host: {req_host} != {expected}");
            return plain(StatusCode::NOT_FOUND);
        }
    }

    // CORS preflight
    if *req.method() == Method::OPTIONS {
        return cors_ok();
    }

    // Path 解析
    let req_path = req.uri().path().to_string();
    let (session_id, seq_str) = match parse_path(&req_path, &shared.base_path) {
        Some(p) => p,
        None => {
            warn!("[xhttp] {peer} bad path: {req_path} (base={})", shared.base_path);
            return plain(StatusCode::NOT_FOUND);
        }
    };

    // 路由：GET 无 seq → downlink/stream-one；其他 → uplink
    let is_downlink = *req.method() == Method::GET && seq_str.is_none();

    if is_downlink {
        handle_get(req, shared, session_id.as_deref(), peer).await
    } else {
        handle_post(req, shared, session_id.as_deref(), seq_str.as_deref(), peer).await
    }
}

/// GET handler：downlink 或 stream-one
async fn handle_get(
    req: Request<hyper::body::Incoming>,
    shared: &Arc<ServiceShared>,
    session_id: Option<&str>,
    peer: SocketAddr,
) -> Response<ResponseBody> {
    debug!("[xhttp] {peer} GET downlink session={session_id:?}");

    // 若有 sessionId，通知对应 session 的 TTL 任务可以退出
    if let Some(sid) = session_id {
        let mut smap = shared.sessions.lock().await;
        let notify = smap.entry(sid.to_string())
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone();
        // 通知 TTL 任务：GET 已到，无需清理
        notify.notify_one();
        drop(smap);
    }

    // stream-one：无 sessionId，把 request body 作为上行数据
    if session_id.is_none() {
        let up_tx = shared.up_tx.clone();
        let mut body = req.into_body();
        tokio::spawn(async move {
            loop {
                match body.frame().await {
                    None => break,
                    Some(Ok(frame)) => {
                        if let Ok(data) = frame.into_data() {
                            if up_tx.send(UploadPacket::Chunk(data)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        debug!("[xhttp] {peer} stream-one up frame error: {e}");
                        break;
                    }
                }
            }
        });
    }

    // 取出 down_rx slot（只有第一个 GET 能取到）
    let taken = shared.down_rx_slot.lock().await.take();
    let (down_rx, done_tx) = match taken {
        Some(pair) => pair,
        None => {
            warn!("[xhttp] {peer} duplicate GET or no down_rx slot");
            return plain(StatusCode::CONFLICT);
        }
    };

    // 通知 accept_hyper：GET 已就绪，down_rx 已被 response body 持有
    shared.get_ready.notify_one();
    let _ = done_tx.send(());

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/octet-stream")
        .header("Cache-Control", "no-cache, no-store")
        .header("Access-Control-Allow-Origin", "*")
        .header("X-Accel-Buffering", "no")
        .body(ResponseBody::Stream(down_rx))
        .unwrap()
}

/// POST/PUT handler：接收上行数据
async fn handle_post(
    req: Request<hyper::body::Incoming>,
    shared: &Arc<ServiceShared>,
    session_id: Option<&str>,
    seq_str: Option<&str>,
    peer: SocketAddr,
) -> Response<ResponseBody> {
    debug!("[xhttp] {peer} {} uplink session={session_id:?} seq={seq_str:?}", req.method());

    // POST 先到时，在 session 表中创建记录，并启动 30s TTL
    // 如果 GET 在 30s 内到达，TTL 任务会被通知提前退出
    if let Some(sid) = session_id {
        let mut smap = shared.sessions.lock().await;
        if !smap.contains_key(sid) {
            let get_arrived = Arc::new(Notify::new());
            smap.insert(sid.to_string(), Arc::clone(&get_arrived));
            // 启动 TTL 任务（仅做日志，实际上连接关闭会自动清理）
            let sid_owned = sid.to_string();
            let sessions2 = Arc::clone(&shared.sessions);
            tokio::spawn(async move {
                // 等待 GET 到达，或 30s 超时
                let timed_out = tokio::time::timeout(
                    Duration::from_secs(30),
                    get_arrived.notified(),
                ).await.is_err();
                if timed_out {
                    debug!("[xhttp] session {sid_owned} TTL expired (GET never arrived)");
                    sessions2.lock().await.remove(&sid_owned);
                }
            });
        }
    }

    let up_tx = shared.up_tx.clone();

    match seq_str {
        None => {
            // stream-up：逐帧转发 body
            let mut body = req.into_body();
            tokio::spawn(async move {
                loop {
                    match body.frame().await {
                        None => break,
                        Some(Ok(frame)) => {
                            if let Ok(data) = frame.into_data() {
                                if up_tx.send(UploadPacket::Chunk(data)).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Some(Err(e)) => {
                            debug!("[xhttp] {peer} stream-up frame error: {e}");
                            break;
                        }
                    }
                }
            });
        }
        Some(s) => {
            // packet-up：带序号的单包
            let seq: u64 = match s.parse() {
                Ok(n) => n,
                Err(_) => {
                    warn!("[xhttp] {peer} invalid seq: {s}");
                    return plain(StatusCode::BAD_REQUEST);
                }
            };
            let body = req.into_body();
            tokio::spawn(async move {
                match body.collect().await {
                    Ok(c) => {
                        let _ = up_tx.send(UploadPacket::Packet {
                            seq,
                            data: c.to_bytes(),
                        }).await;
                    }
                    Err(e) => debug!("[xhttp] {peer} packet-up collect error: {e}"),
                }
            });
        }
    }

    plain(StatusCode::OK)
}

fn plain(code: StatusCode) -> Response<ResponseBody> {
    Response::builder()
        .status(code)
        .header("Access-Control-Allow-Origin", "*")
        .body(ResponseBody::Empty)
        .unwrap()
}

fn cors_ok() -> Response<ResponseBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
        .header("Access-Control-Allow-Headers", "Content-Type")
        .body(ResponseBody::Empty)
        .unwrap()
}

// ── Response body ─────────────────────────────────────────────────────────────

enum ResponseBody {
    Empty,
    Stream(mpsc::Receiver<bytes::Bytes>),
}

impl http_body::Body for ResponseBody {
    type Data = bytes::Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            ResponseBody::Empty => Poll::Ready(None),
            ResponseBody::Stream(rx) => match rx.poll_recv(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Ready(Some(d)) => Poll::Ready(Some(Ok(http_body::Frame::data(d)))),
            },
        }
    }
}

// ── XhttpStream ───────────────────────────────────────────────────────────────

/// packet-up 序号重排队列（对应 Xray 的 uploadQueue）
struct PktQueue {
    heap: BinaryHeap<Reverse<PktEntry>>,
    next_seq: u64,
    leftover: BytesMut,
}

#[derive(Eq, PartialEq)]
struct PktEntry { seq: u64, data: bytes::Bytes }

impl Ord for PktEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering { self.seq.cmp(&other.seq) }
}
impl PartialOrd for PktEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(other)) }
}

/// 双向字节流：AsyncRead（上行）+ AsyncWrite（下行）
pub struct XhttpStream {
    // 上行
    up_rx:      mpsc::Receiver<UploadPacket>,
    pkt_queue:  PktQueue,
    stream_buf: BytesMut,
    eof:        bool,

    // 下行：PollSender 保证 channel 满时真正挂起，不 busy-loop
    down_tx: PollSender<bytes::Bytes>,
}

impl XhttpStream {
    fn new(up_rx: mpsc::Receiver<UploadPacket>, down_tx: mpsc::Sender<bytes::Bytes>) -> Self {
        Self {
            up_rx,
            pkt_queue: PktQueue {
                heap: BinaryHeap::new(),
                next_seq: 0,
                leftover: BytesMut::new(),
            },
            stream_buf: BytesMut::new(),
            eof: false,
            down_tx: PollSender::new(down_tx),
        }
    }
}

impl AsyncRead for XhttpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        loop {
            // 1. packet-up leftover（当前包未读完的部分）
            if !this.pkt_queue.leftover.is_empty() {
                let n = this.pkt_queue.leftover.len().min(buf.remaining());
                buf.put_slice(&this.pkt_queue.leftover[..n]);
                this.pkt_queue.leftover.advance(n);
                return Poll::Ready(Ok(()));
            }

            // 2. stream-up 尾部缓冲
            if !this.stream_buf.is_empty() {
                let n = this.stream_buf.len().min(buf.remaining());
                buf.put_slice(&this.stream_buf[..n]);
                this.stream_buf.advance(n);
                return Poll::Ready(Ok(()));
            }

            // 3. 按序弹出 packet-up 包
            if let Some(Reverse(top)) = this.pkt_queue.heap.peek() {
                if top.seq == this.pkt_queue.next_seq {
                    let Reverse(entry) = this.pkt_queue.heap.pop().unwrap();
                    let n = entry.data.len().min(buf.remaining());
                    buf.put_slice(&entry.data[..n]);
                    if n < entry.data.len() {
                        this.pkt_queue.leftover.extend_from_slice(&entry.data[n..]);
                    }
                    this.pkt_queue.next_seq += 1;
                    return Poll::Ready(Ok(()));
                }
                // 堆顶不是期望序号，等更多包到来后再弹
            }

            // 4. EOF
            if this.eof {
                return Poll::Ready(Ok(()));
            }

            // 5. 从 up_rx 拿新包，继续循环处理
            match this.up_rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(pkt)) => match pkt {
                    UploadPacket::Chunk(data) => {
                        let n = data.len().min(buf.remaining());
                        buf.put_slice(&data[..n]);
                        if n < data.len() {
                            this.stream_buf.extend_from_slice(&data[n..]);
                        }
                        return Poll::Ready(Ok(()));
                    }
                    UploadPacket::Packet { seq, data } => {
                        this.pkt_queue.heap.push(Reverse(PktEntry { seq, data }));
                        // 继续 loop，尝试按序弹出
                    }
                    UploadPacket::Eof => {
                        this.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                },
            }
        }
    }
}

impl AsyncWrite for XhttpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        // poll_reserve：等 channel 有空位，满时真正挂起（不 busy-loop）
        match this.down_tx.poll_reserve(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "xhttp downlink closed")
            )),
            Poll::Ready(Ok(())) => {
                match this.down_tx.send_item(bytes::Bytes::copy_from_slice(buf)) {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(_) => Poll::Ready(Err(
                        std::io::Error::new(std::io::ErrorKind::BrokenPipe, "xhttp downlink closed")
                    )),
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// ── 单元测试 ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_path_stream_one_no_slash() {
        assert_eq!(parse_path("/xhttp", "/xhttp/"), Some((None, None)));
    }

    #[test]
    fn test_parse_path_stream_one_with_slash() {
        assert_eq!(parse_path("/xhttp/", "/xhttp/"), Some((None, None)));
    }

    #[test]
    fn test_parse_path_stream_down() {
        let sid = "550e8400-e29b-41d4-a716-446655440000";
        let p = format!("/xhttp/{sid}");
        assert_eq!(parse_path(&p, "/xhttp/"), Some((Some(sid.to_string()), None)));
    }

    #[test]
    fn test_parse_path_packet_up() {
        let sid = "550e8400-e29b-41d4-a716-446655440000";
        let p = format!("/xhttp/{sid}/42");
        assert_eq!(
            parse_path(&p, "/xhttp/"),
            Some((Some(sid.to_string()), Some("42".to_string())))
        );
    }

    #[test]
    fn test_parse_path_bad_prefix() {
        assert_eq!(parse_path("/other/path", "/xhttp/"), None);
    }

    #[test]
    fn test_normalized_path() {
        let cfg = XhttpConfig { path: "/xhttp".to_string(), host: None };
        assert_eq!(cfg.normalized_path(), "/xhttp/");

        let cfg2 = XhttpConfig { path: "/xhttp/".to_string(), host: None };
        assert_eq!(cfg2.normalized_path(), "/xhttp/");

        let cfg3 = XhttpConfig { path: "/".to_string(), host: None };
        assert_eq!(cfg3.normalized_path(), "/");
    }
}
