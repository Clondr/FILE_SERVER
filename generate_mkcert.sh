#!/usr/bin/env bash
set -euo pipefail

# Helper to generate a locally-trusted certificate with mkcert.
# mkcert creates certificates trusted by the local machine after installing its CA.
# Requirements:
# - mkcert installed and available in PATH (https://github.com/FiloSottile/mkcert)
# Usage:
# ./generate_mkcert.sh myhost.local
# Produces files: cert.pem key.pem in ./certs/<name>/

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 hostname [hostname2 ...]"
  exit 1
fi

INSTALL_CA=0
if [ "$1" = "--install-ca" ]; then
  INSTALL_CA=1
  shift
fi

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 [--install-ca] hostname [hostname2 ...]" >&2
  exit 1
fi

OUTDIR=./certs/mkcert
mkdir -p "$OUTDIR"

# Find mkcert in PATH or download into ./bin
if command -v mkcert >/dev/null 2>&1; then
  MKCERT=$(command -v mkcert)
else
  echo "mkcert not found in PATH. Attempting to download a local copy to ./bin/mkcert"
  mkdir -p ./bin
  OS=$(uname -s | tr '[:upper:]' '[:lower:]')
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) echo "Unsupported architecture: $ARCH" >&2; exit 2 ;;
  esac

  # Resolve asset URL from GitHub releases
  API_URL="https://api.github.com/repos/FiloSottile/mkcert/releases/latest"
  ASSET_URL=$(curl -s "$API_URL" | grep -Po '"browser_download_url": "\K[^"]+' | grep "${OS}-${ARCH}" | head -n1)
  if [ -z "$ASSET_URL" ]; then
    # fallback: try linux-amd64 name pattern
    ASSET_URL=$(curl -s "$API_URL" | grep -Po '"browser_download_url": "\K[^"]+' | grep -E "linux-amd64|darwin-amd64|windows-amd64" | head -n1)
  fi
  if [ -z "$ASSET_URL" ]; then
    echo "Could not find mkcert binary for $OS-$ARCH on GitHub releases. Please install mkcert manually: https://github.com/FiloSottile/mkcert" >&2
    exit 2
  fi

  echo "Downloading mkcert from: $ASSET_URL"
  curl -L -o ./bin/mkcert "$ASSET_URL"
  chmod +x ./bin/mkcert
  MKCERT=./bin/mkcert
  echo "Downloaded mkcert to $MKCERT"
fi

echo "Generating mkcert certificate for: $*"
"$MKCERT" -cert-file "$OUTDIR/cert.pem" -key-file "$OUTDIR/key.pem" "$@"

echo "Generated files:"
echo "  $OUTDIR/cert.pem"
echo "  $OUTDIR/key.pem"
echo
if [ "$INSTALL_CA" -eq 1 ]; then
  echo "Attempting to install local CA (this may require user interaction / sudo)..."
  if "$MKCERT" -install; then
    echo "Local CA installed in the current machine trust store. For other client machines, run 'mkcert -install' there or import rootCA.pem into their trust stores.";
  else
    echo "mkcert -install failed or requires manual action. Please run '$MKCERT -install' manually and follow the prompts." >&2
  fi
fi

echo
echo "To use with server:"
echo "  python3 file_server.py --protocol https --cert $OUTDIR/cert.pem --key $OUTDIR/key.pem --host 0.0.0.0 --port 443 --token ..."
