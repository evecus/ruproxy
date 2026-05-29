//! XHTTP (SplitHTTP) transport — server-side accept.
//!
//! Protocol overview (mirrors Xray's splithttp / xhttp transport):
//!
//! The client opens HTTP connections to send/receive data.
//! The server exposes a GET endpoint (downlink) and POST endpoint (uplink),
//! identified by a session ID embedded in the URL path:
//!
//! ```text
//! GET  <path>/<session-id>       → server streams response body (downlink)
//! POST <path>/<session-id>[/seq] → client body → uplink data
//! ```
//!
//! This implementation presents the accepted session as an `XhttpStream`
//! that implements `AsyncRead + AsyncWrite`, making it a drop-in replacement
//! for a plain TCP stream from the perspective of protocol handlers.

use anyhow::Result;
use bytes::{Buf, BytesMut};
use http_body_util::BodyExt;
use hyper::{Method, Request, Response, StatusCode};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::{debug, warn};

// ── Config ────────────────────────────────────────────────────────────────────

/// Configuration for the XHTTP transport layer.
#[derive(Debug, Clone)]
pub struct XhttpConfig {
    /// HTTP path prefix (e.g. "/").
    pub path: String,
    /// Optional Host header validation.
    pub host: Option<String>,
}

impl Default for XhttpConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            host: None,
        }
    }
}

impl XhttpConfig {
    /// Normalise: ensure path starts with '/'.
    pub fn normalized_path(&self) -> String {
        let p = self.path.clone();
        if p.starts_with('/') {
            p
        } else {
            format!("/{p}")
        }
    }
}

// ── Public accept API ─────────────────────────────────────────────────────────

/// Accept an XHTTP session on a plain TCP stream.
pub async fn accept_plain(
    stream: TcpStream,
    peer: SocketAddr,
    cfg: &XhttpConfig,
) -> Result<XhttpStream> {
    accept_hyper(hyper_util::rt::TokioIo::new(stream), peer, cfg).await
}

/// Accept an XHTTP session on an already-TLS-wrapped stream.
pub async fn accept_tls<S>(stream: S, peer: SocketAddr, cfg: &XhttpConfig) -> Result<XhttpStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    accept_hyper(hyper_util::rt::TokioIo::new(stream), peer, cfg).await
}

// ── Internal hyper server ─────────────────────────────────────────────────────

async fn accept_hyper<IO>(io: IO, peer: SocketAddr, cfg: &XhttpConfig) -> Result<XhttpStream>
where
    IO: hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
{
    let path = cfg.normalized_path();
    let host = cfg.host.clone();

    // Channel: client POST body → XhttpStream reader
    let (up_tx, up_rx) = mpsc::channel::<bytes::Bytes>(64);
    // Channel: XhttpStream writer → GET response body
    let (down_tx, down_rx) = mpsc::channel::<bytes::Bytes>(64);
    // Oneshot: HTTP handler notifies accept_hyper when GET is received
    let (ready_tx, ready_rx) = oneshot::channel::<()>();

    // Share these between the HTTP service closure and this function
    let up_tx = Arc::new(up_tx);
    let down_rx = Arc::new(Mutex::new(down_rx));
    let ready_tx = Arc::new(Mutex::new(Some(ready_tx)));
    let down_tx_clone = down_tx.clone();

    tokio::spawn({
        let up_tx = Arc::clone(&up_tx);
        let down_rx = Arc::clone(&down_rx);
        let ready_tx = Arc::clone(&ready_tx);

        async move {
            let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                let up_tx = Arc::clone(&up_tx);
                let down_rx = Arc::clone(&down_rx);
                let ready_tx = Arc::clone(&ready_tx);
                let path = path.clone();
                let host = host.clone();

                async move {
                    let resp =
                        handle_request(req, &path, &host, &up_tx, &down_rx, &ready_tx, peer).await;
                    Ok::<_, std::convert::Infallible>(resp)
                }
            });

            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .await
            {
                debug!("[xhttp] {peer} closed: {e}");
            }
        }
    });

    // Block until the GET (downlink) connection has been received
    let _ = ready_rx.await;

    Ok(XhttpStream {
        up_rx,
        down_tx: down_tx_clone,
        read_buf: BytesMut::new(),
    })
}

// ── HTTP handler ──────────────────────────────────────────────────────────────

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    path: &str,
    host: &Option<String>,
    up_tx: &Arc<mpsc::Sender<bytes::Bytes>>,
    down_rx: &Arc<Mutex<mpsc::Receiver<bytes::Bytes>>>,
    ready_tx: &Arc<Mutex<Option<oneshot::Sender<()>>>>,
    peer: SocketAddr,
) -> Response<ResponseBody> {
    // Validate Host header
    if let Some(expected) = host {
        let req_host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if req_host != expected.as_str() {
            warn!("[xhttp] {peer} bad host: got={req_host} want={expected}");
            return empty_response(StatusCode::NOT_FOUND);
        }
    }

    // Validate path prefix
    if !req.uri().path().starts_with(path) {
        warn!("[xhttp] {peer} bad path: {}", req.uri().path());
        return empty_response(StatusCode::NOT_FOUND);
    }

    // CORS preflight
    if req.method() == Method::OPTIONS {
        return Response::builder()
            .status(StatusCode::OK)
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
            .header("Access-Control-Allow-Headers", "Content-Type")
            .body(ResponseBody::Empty)
            .unwrap();
    }

    match req.method() {
        &Method::GET => {
            // Downlink: stream data from our proxy to the client
            debug!("[xhttp] {peer} GET downlink");

            // Signal that we're ready
            if let Some(tx) = ready_tx.lock().await.take() {
                let _ = tx.send(());
            }

            // Spawn a task that drains down_rx → body_rx
            let (body_tx, body_rx) = mpsc::channel::<bytes::Bytes>(64);
            let actual_down_rx = Arc::clone(down_rx);

            tokio::spawn(async move {
                loop {
                    let data = {
                        let mut guard = actual_down_rx.lock().await;
                        guard.recv().await
                    };
                    match data {
                        None => break,
                        Some(chunk) => {
                            if body_tx.send(chunk).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });

            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/octet-stream")
                .header("Cache-Control", "no-cache, no-store")
                .header("Access-Control-Allow-Origin", "*")
                .header("X-Accel-Buffering", "no")
                .body(ResponseBody::Stream(body_rx))
                .unwrap()
        }
        _ => {
            // Uplink: POST / PUT body → up_tx
            debug!("[xhttp] {peer} {} uplink", req.method());
            let up_tx = up_tx.clone();
            let body = req.into_body();
            tokio::spawn(async move {
                match body.collect().await {
                    Ok(collected) => {
                        let data = collected.to_bytes();
                        if !data.is_empty() {
                            let _ = up_tx.send(data).await;
                        }
                    }
                    Err(e) => debug!("[xhttp] POST body read error: {e}"),
                }
            });
            empty_response(StatusCode::OK)
        }
    }
}

fn empty_response(status: StatusCode) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .header("Access-Control-Allow-Origin", "*")
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
                Poll::Ready(Some(data)) => Poll::Ready(Some(Ok(http_body::Frame::data(data)))),
            },
        }
    }
}

// ── XhttpStream ───────────────────────────────────────────────────────────────

/// A bidirectional byte-stream over an XHTTP (SplitHTTP) session.
///
/// `AsyncRead`  ← uplink data from the client's POST requests.
/// `AsyncWrite` → downlink data streamed in the GET response body.
pub struct XhttpStream {
    up_rx: mpsc::Receiver<bytes::Bytes>,
    down_tx: mpsc::Sender<bytes::Bytes>,
    read_buf: BytesMut,
}

impl AsyncRead for XhttpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if !this.read_buf.is_empty() {
            let n = this.read_buf.len().min(buf.remaining());
            buf.put_slice(&this.read_buf[..n]);
            this.read_buf.advance(n);
            return Poll::Ready(Ok(()));
        }

        match this.up_rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Ready(Some(chunk)) => {
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    this.read_buf.extend_from_slice(&chunk[n..]);
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for XhttpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let data = bytes::Bytes::copy_from_slice(buf);
        match this.down_tx.try_send(data) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                // Channel full — caller should retry; wake immediately so
                // the executor re-polls us (busy-wait is acceptable here
                // since the channel drains as hyper reads frames).
                _cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "xhttp downlink closed"),
            )),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
