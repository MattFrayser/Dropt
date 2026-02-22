<h1 align="center">dropt</h1>
<p align="center">Secure peer-to-peer file transfer from Linux to any browser.</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#installation">Install</a> ·
  <a href="#usage">Usage</a> ·
  <a href="#security">Security</a> ·
  <a href="#faq">FAQ</a>
</p>

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

---

<p align="center">
  <img src="docs/assets/readme/demo.gif" alt="dropt demo" width="880" />
</p>

> Add your product demo GIF at `docs/assets/readme/demo.gif`.

---

## Quick Start

```bash
# 1) Install latest release
curl -fsSL https://github.com/MattFrayser/ArchDrop/releases/latest/download/install.sh | bash

# 2) Send a file
dropt send ./file.txt --via local
```

On your other device:
1. Scan the QR code or open the generated link.
3. Preview download / upload list.
4. Session shuts down automatically after completion.

---

## Why dropt

- Zero cloud storage: files transfer directly peer-to-peer.
- Supports Local and Over network transfers.
- Cross-device by default: Linux CLI host and any modern browser peer.
- Privacy-first sessions: one-time transfer links and auto shutdown.

---

## Installation

### Prebuilt Binary (Recommended)

```bash
curl -fsSL https://github.com/MattFrayser/ArchDrop/releases/latest/download/install.sh | bash
```

### Build From Source

```bash
cargo build --release
sudo install -m 0755 target/release/dropt /usr/local/bin/dropt
```

### Requirements

**Linux host:**
- Linux kernel 2.6+
- Rust 1.70+ (source builds only)
- Optional: `cloudflared` for Cloudflare tunnels
- Optional: `tailscale` and running `tailscaled` for Tailscale funnels

**Client device (receiver or sender):**
- Any modern browser (Chrome 92+, Firefox 95+, Safari 15.4+)
- JavaScript enabled
- For downloads larger than 500MB, Chrome or Edge are recommended

---

## Usage

### Send Files

```bash
# Trusted local network
dropt send ./file.txt --via local

# Internet via Cloudflare tunnel
dropt send ./file.txt --via cloudflare

# Internet via Tailscale funnel
dropt send ./file.txt --via tailscale

# Apply port only to selected transport
dropt send ./file.txt --via local --port 8443
```

### Receive Files

```bash
# Receive into current directory
dropt receive --via local

# Receive into a specific directory
dropt receive ~/Downloads --via cloudflare
```

---

## Configuration

- Default config path: `~/.config/dropt/config.toml`
- Print active config path: `dropt config path`
- Precedence: `defaults < file < env < CLI`

`chunk_size` must be between `1` and `10485760` bytes (10 MiB).

---

## Security

- Transfer payloads are encrypted in the application layer.
- Session credentials (`token`, encryption key, nonce) stay in URL fragments (`#...`) and are not sent in HTTP requests.
- Tunnel providers route traffic but do not receive URL fragments.
- In local mode, do not bypass certificate warnings on untrusted networks.

Recommended defaults:
- Use `--via local` on trusted LANs.
- Use `--via tailscale` when both devices are in your tailnet.
- Use `--via cloudflare` for ad-hoc internet sharing when Tailscale is unavailable.

---

## Browser Compatibility

| Browser | Max File Size |
|---------|---------------|
| Chrome 92+ | Unlimited |
| Edge 92+ | Unlimited |
| Firefox 95+ | 500MB |
| Safari 15.4+ | 500MB |
| Mobile Safari | 500MB |
| Mobile Chrome | Unlimited (varies by device memory) |

**Note: Max File sizes could change. Above are estimates.**

---

## FAQ

### Is dropt cloud storage?

No. Files transfer directly between peers.

### Which transport should I use?

- `local` for trusted LAN transfers
- `tailscale` for identity-based private networking
- `cloudflare` for easiest internet sharing

### Where is config stored?

`~/.config/dropt/config.toml`

---

## Support

Open a GitHub issue with:
- command used
- transport mode
- terminal output
- OS and browser version

---

## Contributing

Contributions are welcome. Keep changes focused, include tests when behavior changes, and update docs for user-facing changes.

---

## License

MIT. See `LICENSE`.

---

## Project Status

Active development. Interfaces and flags may evolve before `1.0`.
