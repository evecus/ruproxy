# ruproxy

A multi-protocol proxy server written in Rust.

## Supported Protocols

| Protocol | Transport |
|---|---|
| Hysteria2 | QUIC + TLS |
| VLESS | plain TCP |
| VLESS | TCP + TLS |
| VLESS | WebSocket |
| VLESS | WebSocket + TLS |
| VLESS | **Reality** (new) |

## Usage

```
ruproxy -c config.toml
```

Default config path is `config.toml` in the current directory.

## Configuration

Only configure what you need. Omit a section entirely to disable that protocol — no `enable: false` required.

### Minimal examples

See the `configs/` directory for ready-to-use examples:

| File | Description |
|---|---|
| `configs/hysteria2-only.toml` | Hysteria2 only |
| `configs/vless-tls.toml` | VLESS + TLS |
| `configs/vless-ws.toml` | VLESS + WebSocket |
| `configs/vless-reality.toml` | VLESS + Reality |
| `configs/full.toml` | All protocols |

### Config reference

```toml
# Logging — optional, default: info
[log]
level = "info"   # trace | debug | info | warn | error

# Hysteria2 — omit section to disable
[hysteria2]
listen = "0.0.0.0:443"

[hysteria2.tls]
cert = "/path/to/cert.pem"        # omit both cert+key to auto-generate self-signed
key  = "/path/to/key.pem"
# self_signed_domain = "example.com"

[hysteria2.auth]
type     = "password"
password = "your-password"

# optional
[hysteria2.bandwidth]
up   = "1000 mbps"
down = "1000 mbps"

# VLESS — omit section to disable
[vless]
listen = "0.0.0.0:8443"
uuid   = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# transport defaults to plain TCP if omitted
[vless.transport]
type = "tcp"        # tcp | ws | reality
tls  = true         # ignored for type=reality

# TLS fields (for type=tcp/ws with tls=true)
cert               = "/path/to/cert.pem"
key                = "/path/to/key.pem"
self_signed_domain = "example.com"

# WebSocket fields (for type=ws)
ws_path = "/vless"
ws_host = "your.domain.com"   # optional

# Reality fields (for type=reality)
[vless.transport.reality]
private_key = "<base64 x25519 private key>"
public_key  = "<base64 x25519 public key>"
short_ids   = ["abcd1234", "ef567890"]
dest        = "example.com:443"
server_name = "example.com"
```

### Generating a Reality keypair

```bash
# Private key (base64)
openssl genpkey -algorithm x25519 2>/dev/null | openssl pkey -noout -text 2>&1 \
  | grep -A 3 "priv:" | tail -n +2 | tr -d ' :\n' | xxd -r -p | base64

# Public key (base64) — derive from the private key
# Use xray or any x25519 tool, e.g.:
#   xray x25519
```

## Build

```bash
cargo build --release
```

Binary: `target/release/ruproxy`
