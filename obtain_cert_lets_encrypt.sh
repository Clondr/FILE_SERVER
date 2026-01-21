#!/usr/bin/env bash
set -euo pipefail

# Simple helper to request a Let's Encrypt certificate using certbot and the webroot challenge.
# Requirements:
# - certbot installed and available in PATH
# - a public domain name pointing to this machine (or forwarded port 80 to this host)
# - this script must be run as root (or certbot will fail to bind sockets on port 80)
# Usage:
# ./obtain_cert_lets_encrypt.sh -d your.domain.tld -m you@example.com -w ./static

usage(){
  cat <<EOF
Usage: $0 -d domain -m email [-w webroot] [-o outdir]

This will run certbot in webroot mode to obtain a certificate for DOMAIN and store
the cert and key in OUTDIR (default: ./certs/<domain>). The server can then be
started with --tls --cert <outdir>/fullchain.pem --key <outdir>/privkey.pem

Requirements: certbot, port 80 reachable for HTTP-01 challenge.
EOF
  exit 1
}

WEBROOT=./static
OUTDIR=
DOMAIN=
EMAIL=

while getopts "d:m:w:o:h" opt; do
  case "$opt" in
    d) DOMAIN="$OPTARG" ;;
    m) EMAIL="$OPTARG" ;;
    w) WEBROOT="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    h|*) usage ;;
  esac
done

[ -n "$DOMAIN" ] || usage
[ -n "$EMAIL" ] || usage

OUTDIR=${OUTDIR:-./certs/${DOMAIN}}
mkdir -p "$OUTDIR"

echo "Requesting certificate for $DOMAIN using webroot $WEBROOT"

if ! command -v certbot >/dev/null 2>&1; then
  echo "certbot not found. Install certbot and rerun. On Debian/Ubuntu: sudo apt install certbot" >&2
  exit 2
fi

sudo certbot certonly --non-interactive --agree-tos --email "$EMAIL" --webroot -w "$WEBROOT" -d "$DOMAIN"

# certbot stores certs in /etc/letsencrypt/live/<domain>
SRC="/etc/letsencrypt/live/$DOMAIN"
if [ -d "$SRC" ]; then
  echo "Copying certificate files to $OUTDIR"
  sudo cp "$SRC/fullchain.pem" "$OUTDIR/"
  sudo cp "$SRC/privkey.pem" "$OUTDIR/"
  echo "Certificate and key copied to $OUTDIR"
  echo "Start server with: python3 file_server.py --tls --cert $OUTDIR/fullchain.pem --key $OUTDIR/privkey.pem --host 0.0.0.0 --port 443 --token ..."
else
  echo "Certbot did not produce expected files in $SRC" >&2
  exit 3
fi
