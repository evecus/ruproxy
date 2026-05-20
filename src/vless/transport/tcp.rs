//! Plain TCP transport — no TLS, no WebSocket.
//! Simplest case: TcpStream is already AsyncRead + AsyncWrite.

use anyhow::Result;
use tokio::net::TcpStream;
use tracing::debug;

#[allow(dead_code)]
pub async fn accept(stream: TcpStream) -> Result<TcpStream> {
    debug!(
        "vless/transport/tcp: plain TCP accepted from {:?}",
        stream.peer_addr()
    );
    Ok(stream)
}
