#!/usr/bin/env bash
set -euo pipefail

REPO="MattFrayser/ArchDrop"
BASE_URL="https://github.com/${REPO}/releases/latest/download"
ARCHIVE="dropt-linux-x86_64.tar.gz"
CHECKSUMS="checksums.txt"

usage() {
  cat <<'EOF'
ArchDrop installer

Usage:
  install.sh [--bin-dir <path>]

Options:
  --bin-dir <path>  Install directory override.
  -h, --help        Show this help.
EOF
}

BIN_DIR=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --bin-dir)
      if [ "$#" -lt 2 ]; then
        echo "error: --bin-dir requires a path" >&2
        exit 1
      fi
      BIN_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [ "$(uname -s)" != "Linux" ]; then
  echo "error: this installer currently supports Linux only" >&2
  exit 1
fi

if [ "$(uname -m)" != "x86_64" ]; then
  echo "error: this installer currently supports x86_64 only" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "error: curl is required" >&2
  exit 1
fi

if ! command -v tar >/dev/null 2>&1; then
  echo "error: tar is required" >&2
  exit 1
fi

if ! command -v sha256sum >/dev/null 2>&1; then
  echo "error: sha256sum is required" >&2
  exit 1
fi

if [ -z "$BIN_DIR" ]; then
  if [ -d "/usr/local/bin" ] && [ -w "/usr/local/bin" ]; then
    BIN_DIR="/usr/local/bin"
  else
    BIN_DIR="${HOME}/.local/bin"
  fi
fi

mkdir -p "$BIN_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Downloading release artifacts..."
curl -fsSL --retry 3 --retry-all-errors -o "${TMP_DIR}/${ARCHIVE}" "${BASE_URL}/${ARCHIVE}"
curl -fsSL --retry 3 --retry-all-errors -o "${TMP_DIR}/${CHECKSUMS}" "${BASE_URL}/${CHECKSUMS}"

echo "Verifying checksum..."
(
  cd "$TMP_DIR"
  if ! grep -q " ${ARCHIVE}$" "$CHECKSUMS"; then
    echo "error: checksum entry for ${ARCHIVE} not found" >&2
    exit 1
  fi
  sha256sum -c "$CHECKSUMS" --ignore-missing
)

echo "Extracting archive..."
tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "$TMP_DIR"

if [ ! -f "${TMP_DIR}/dropt" ]; then
  echo "error: archive did not contain expected 'dropt' binary" >&2
  exit 1
fi

TARGET="${BIN_DIR}/dropt"
OLD_VERSION=""
if [ -x "$TARGET" ]; then
  OLD_VERSION="$($TARGET --version 2>/dev/null || true)"
fi

install -m 0755 "${TMP_DIR}/dropt" "$TARGET"

NEW_VERSION="$($TARGET --version 2>/dev/null || true)"

echo "Installed ArchDrop to ${TARGET}"
if [ -n "$OLD_VERSION" ]; then
  echo "Replaced existing version: ${OLD_VERSION}"
fi
if [ -n "$NEW_VERSION" ]; then
  echo "Current version: ${NEW_VERSION}"
fi

case ":${PATH}:" in
  *":${BIN_DIR}:"*) ;;
  *)
    if [ "$BIN_DIR" = "${HOME}/.local/bin" ]; then
      echo "Note: ${BIN_DIR} is not on PATH in this shell."
      echo "Add this to your shell profile: export PATH=\"${HOME}/.local/bin:\$PATH\""
    fi
    ;;
esac
