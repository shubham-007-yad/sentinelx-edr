#!/usr/bin/env bash
set -e

CERTS_DIR="$(cd "$(dirname "$0")" && pwd)/certs"
mkdir -p "$CERTS_DIR"

CRT_PATH="$CERTS_DIR/sentinelx.crt"
KEY_PATH="$CERTS_DIR/sentinelx.key"

if [ ! -f "$CRT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
    echo "[+] Generating self-signed TLS/SSL certificate for SentinelX EDR..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$KEY_PATH" \
        -out "$CRT_PATH" \
        -subj "/C=US/ST=State/L=City/O=SentinelX EDR/OU=Security/CN=localhost"
    echo "[+] Certificate generated successfully at $CERTS_DIR"
else
    echo "[=] Self-signed TLS certificate already exists at $CERTS_DIR"
fi
