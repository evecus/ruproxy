//! XHTTP (SplitHTTP) transport — server-side accept.
//!
//! ## 修复说明（对照 Xray splithttp hub.go）
//!
//! ### 原版三个核心 Bug
//!
//! 1. **accept 永久阻塞**
//!    原版 `accept_hyper` 死等 `ready_rx.await`，要求 GET 请求必须先于 POST 到达。
//!    但 xhttp 协议不保证顺序，POST 先到时连接永久挂死。
//!    ✔ 新版：GET handler 到达时通过 `Notify` 通知 accept，accept 仅等待 GET 就绪
//!      （30s 超时），GET/POST 顺序无关。
//!
//! 2. **Mutex 跨 await 持锁**
//!    原版用 `Arc<Mutex<Receiver>>` 在 GET handler 持锁跨 await，有死锁风险。
//!    ✔ 新版：down_rx 存在 `ServiceShared` 里，GET handler 直接 take() 独占，
//!      不共享，不加锁跨 await。
//!
//! 3. **poll_write busy-loop**
//!    原版 channel 满时 `wake_by_ref() + Pending` = CPU 忙等，可能饿死其他任务。
//!    ✔ 新版：改用 `tokio_util::sync::PollSender`，channel 满时真正挂起。
//!
//! ### 新增（对齐 Xray）
//!
//! - **stream-up**：POST body 整体作为持续流（无序号）
//! - **packet-up**：POST `<path>/<session>/<seq>` 带序号分包，最小堆重排
//!   （对应 Xray 的 `uploadQueue`）
//!
//! ### 数据流
//!
//! ```text
//!  客户端 POST ──► [up_tx → up_rx] ──► XhttpStream::poll_read
//!  XhttpStream::poll_write ──► [down_tx → down_rx] ──► GET response body (StreamBody)
//! ```
//!
//! `accept_hyper` 创建这两对 channel；`down_rx` 由 GET handler 独占作为 response
//! body，`down_tx` 由 `XhttpStream` 持有用于写下行数据。

use anyhow::Result;
use bytes::{Buf, BytesMut};
use http_body_util::BodyExt;
use hyper::{Method, Request, Response, StatusCode};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Notify};
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
    pub fn normalized_path(&self) -> String {
        let p = self.path.trim_end_matches('/');
        if p.starts_with('/') { p.to_string() } else { format!("/{p}") }
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
    let path = cfg.normalized_path();
    let host = cfg.host.clone();

    // 上行 channel：HTTP handler (POST) → XhttpStream 读端
    let (up_tx, up_rx) = mpsc::channel::<UploadPacket>(64);

    // 下行 channel：XhttpStream 写端 → GET response body
    // down_tx 由 XhttpStream 持有，down_rx 由 GET handler 独占作为 StreamBody。
    let (down_tx, down_rx) = mpsc::channel::<bytes::Bytes>(64);

    // GET handler 取走 down_rx 后，通过 oneshot 告知 accept 可以继续
    let (get_done_tx, get_done_rx) = oneshot::channel::<()>();

    // GET 到达通知（先于 get_done，保证 accept 能及时唤醒）
    let get_ready = Arc::new(Notify::new());
    let get_ready_srv = Arc::clone(&get_ready);

    let shared = Arc::new(ServiceShared {
        path,
        host,
        up_tx: up_tx.clone(),
        // down_rx 和 get_done_tx 存在 Mutex 里，只被 GET handler 取一次
        down_rx: tokio::sync::Mutex::new(Some((down_rx, get_done_tx))),
        get_ready: get_ready_srv,
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

    // 等 GET handler 确认已取走 down_rx（防止 XhttpStream 写入时 receiver 未就绪）
    let _ = tokio::time::timeout(Duration::from_millis(200), get_done_rx).await;

    Ok(XhttpStream::new(up_rx, down_tx))
}

// ── 服务端共享状态 ─────────────────────────────────────────────────────────────

struct ServiceShared {
    path: String,
    host: Option<String>,
    up_tx: mpsc::Sender<UploadPacket>,
    /// GET handler 从这里 take() down_rx 和 get_done_tx（只取一次）
    down_rx: tokio::sync::Mutex<Option<(mpsc::Receiver<bytes::Bytes>, oneshot::Sender<()>)>>,
    get_ready: Arc<Notify>,
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

    // Path 校验
    let req_path = req.uri().path();
    if !req_path.starts_with(shared.path.as_str()) {
        warn!("[xhttp] {peer} bad path: {req_path}");
        return plain(StatusCode::NOT_FOUND);
    }

    // CORS preflight
    if req.method() == Method::OPTIONS {
        return cors_ok();
    }

    // 解析 path 尾部 /<session>[/<seq>]
    let suffix = req_path[shared.path.len()..].trim_start_matches('/');
    let seq_str = suffix.splitn(2, '/').nth(1); // 取第二段（序号）

    match req.method() {
        &Method::GET => handle_get(shared, peer).await,
        _ => handle_post(req, shared, seq_str, peer).await,
    }
}

/// GET handler：取走 down_rx 作为 response body，然后通知 accept 就绪
async fn handle_get(shared: &Arc<ServiceShared>, peer: SocketAddr) -> Response<ResponseBody> {
    debug!("[xhttp] {peer} GET downlink");

    let taken = shared.down_rx.lock().await.take();
    let (down_rx, done_tx) = match taken {
        Some(pair) => pair,
        None => {
            warn!("[xhttp] {peer} duplicate GET or GET before setup");
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

/// POST/PUT handler：接收上行数据，转发到 up_tx
async fn handle_post(
    req: Request<hyper::body::Incoming>,
    shared: &Arc<ServiceShared>,
    seq_str: Option<&str>,
    peer: SocketAddr,
) -> Response<ResponseBody> {
    debug!("[xhttp] {peer} {} uplink seq={:?}", req.method(), seq_str);

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
    leftover: BytesMut, // 当前包未读完的尾部
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
    stream_buf: BytesMut, // stream-up 未读完的尾部
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
    ) -> Poll<std::io::Result<()>> {
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
