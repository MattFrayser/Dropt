# Dropt
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

Secure peer-to-peer file transfer CLI for Linux. Transfer files directly between your devices without uploading to cloud services.

## Why Dropt?
  - **Zero Cloud Storage**: Files transfer directly peer-to-peer
  - **Cross-Platform**: Linux CLI ↔ Any device with web browser
  - **Privacy First**: No data retention, sessions auto-destruct after transfer

## Requirements

**Linux Host:**
- Linux kernel 2.6+
- Rust 1.70+ (for building from source)
- Optional: `cloudflared` for Cloudflare tunnels
- Optional: `tailscale` + running `tailscaled` for Tailscale funnels

**Client (Receiver/Sender):**
- Any modern browser (Chrome 92+, Firefox 95+, Safari 15.4+)
- JavaScript enabled
- For downloads >500MB: Chrome/Edge recommended (uses FileSystem API)

## Installation

### Install prebuilt binary (recommended)

Run the installer from the latest GitHub release:

```bash
curl -fsSL https://github.com/MattFrayser/ArchDrop/releases/latest/download/install.sh | bash
```

### Build from source

```bash
cargo build --release
sudo install -m 0755 target/release/dropt /usr/local/bin/dropt
```

## Usage

### Send Files

```bash
# Local network (HTTPS on your host, best for trusted LAN)
dropt send file.txt --via local

# Internet-accessible via Cloudflare tunnel
dropt send file.txt --via cloudflare

# Internet-accessible via Tailscale funnel
dropt send file.txt --via tailscale

# Apply port only to selected transport
dropt send file.txt --via local --port 8443
```

### Receive Files

```bash
# Receive files to current directory
dropt receive --via local

# Receive files to specific directory
dropt receive ~/Downloads --via cloudflare
```

### Transfer Flow

1. Run `dropt send` or `dropt receive` on your Linux machine
2. Scan the QR code with your phone/other device
3. Files are encrypted client-side and transferred directly
4. Server shuts down automatically after transfer completes

## Configuration

### Config File Path

- Linux default path: `~/.config/dropt/config.toml`
- Print active path at runtime: `dropt config path`

### Precedence Order

Configuration is layered in this order:

1. Built-in defaults
2. Config file (`config.toml`)
3. Environment variables (`DROPT_*`)
4. CLI flags (`--via`, `--port`)

In short: `defaults < file < env < CLI`.

### Transport-Scoped `--port`

`--port` no longer overrides every transport. It only applies to the effective transport for that command:

- Effective transport = `--via` if provided, otherwise `default_transport` from config.
- Examples:
  - `dropt send file.txt --via cloudflare --port 7000` only changes Cloudflare port for this run.
  - `dropt send file.txt --port 7000` changes port for whatever `default_transport` is.

### Config Example

```toml
default_transport = "local"

[local]
port = 0
chunk_size = 10485760
concurrency = 8

[cloudflare]
port = 0
chunk_size = 1048576
concurrency = 2

[tailscale]
port = 0
chunk_size = 2097152
concurrency = 4

[tui]
show_qr = true
show_url = true
```

`chunk_size` must be between `1` and `10485760` bytes (10 MiB). This conservative cap keeps upload chunks within the receiver's multipart/body envelope.

Environment override examples:

```bash
DROPT_LOCAL_PORT=8443 dropt send file.txt --via local
DROPT_CLOUDFLARE_CONCURRENCY=4 dropt send file.txt --via cloudflare
```

## Tunnel Providers

### Security Model

- Transport links may differ (`local` HTTPS, `cloudflare` tunnel, `tailscale` funnel), but transfer payloads are encrypted in the app layer.
- Session credentials (`token`, encryption key, nonce) are embedded in the URL fragment (`#...`), which browsers do not send in HTTP requests.
- Tunnel providers route traffic but do not receive URL fragments from browser requests.
- Local mode uses a self-signed cert and LAN binding. On shared/untrusted networks, do not bypass browser certificate warnings; a spoofed host could serve malicious page code and steal session secrets.
- Recommended defaults:
  - Use `--via local` on trusted LANs (smallest external exposure).
  - Use `--via tailscale` when both devices are in your tailnet and you want identity-based access control.
  - Use `--via cloudflare` for easiest ad-hoc internet sharing when Tailscale is unavailable.

### Setup

Install Cloudflare tunnel support:

```bash
# Debian/Ubuntu
wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared-linux-amd64.deb
```

Install Tailscale support:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

### Troubleshooting Matrix

| Provider | Symptom | Likely Cause | What to Do |
|---------|---------|--------------|------------|
| Cloudflare | `cloudflared not found` | Binary missing | Install `cloudflared` and retry |
| Cloudflare | Tunnel URL timeout | Startup/network/firewall issue | Check outbound network/firewall; retry or use another provider |
| Cloudflare | `failed to bind` / `address already in use` | Local port conflict (metrics or service) | Retry (built-in retries exist), free conflicting ports |
| Tailscale | `permission denied` / `serve config denied` | Missing operator permissions | Run `sudo tailscale set --operator=$USER` once, then retry |
| Tailscale | `daemon not available` | `tailscaled` not running | Start Tailscale (`sudo tailscale up`) |
| Tailscale | `already in use` | Funnel already exists on port | ArchDrop reuses existing funnel; choose another port if needed |

## Testing

ArchDrop keeps default test runs fast and deterministic. Heavy stress scenarios are explicitly marked with `#[ignore]` and run in a separate lane.

```bash
# Fast/default suite (used for normal local dev and PR checks)
cargo test --tests

# Stress lane (heavy concurrency + fault-injection tests)
cargo test --test concurrency_stress_tests -- --ignored
cargo test --test error_injection_tests -- --ignored

# Full sweep (everything including ignored tests)
cargo test --tests -- --include-ignored
```

Suggested CI split:
- PR pipeline: `cargo test --tests`
- Nightly/perf pipeline: ignored stress commands above

## Browser Compatibility

| Browser | Max File Size |
|---------|---------------|
| Chrome 92+ | Unlimited 
| Edge 92+ | Unlimited 
| Firefox 95+ | 500MB 
| Safari 15.4+ | 500MB 
| Mobile Safari | 500MB 
| Mobile Chrome | Unlimited (Varies by device memory)

**Requirements:** JavaScript enabled, crypto.subtle API support
