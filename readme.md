# ArchDrop

Secure peer-to-peer file transfer CLI for Linux. Transfer files directly between your devices without uploading to cloud services.

## Features

- End-to-end AES-256-GCM encryption
- QR code for easy cross-device transfers
- No file size limits
- Single binary, no external dependencies

## Installation

```bash
cargo build --release
sudo cp target/release/archdrop /usr/local/bin/
```

## Usage

### Send Files

```bash
# Local network (faster, requires HTTPS certificate acceptance)
archdrop send file.txt --local

# Internet-accessible (via Cloudflare tunnel)
archdrop send file.txt
```

### Receive Files

```bash
# Receive files to current directory
archdrop receive

# Receive files to specific directory
archdrop receive ~/Downloads --local
```

### Transfer Flow

1. Run `archdrop send` or `archdrop receive` on your Linux machine
2. Scan the QR code with your phone/other device
3. Files are encrypted client-side and transferred directly
4. Server shuts down automatically after transfer completes

## Tunnel Mode

To use tunnel mode (default), install cloudflared:

```bash
# Debian/Ubuntu
wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared-linux-amd64.deb
```

Or use `--local` flag for local network transfers without tunnel.
