#!/bin/bash

# Simple SSL Certificate Generation for NetworkMapper
set -e

DOMAIN="$1"
if [[ -z "$DOMAIN" ]]; then
    echo "Usage: $0 <domain_or_ip>"
    exit 1
fi

CERT_DIR="ssl/certs"
mkdir -p "$CERT_DIR"

KEY_FILE="$CERT_DIR/networkmapper.key"
CRT_FILE="$CERT_DIR/networkmapper.crt"

echo "Generating SSL certificate for $DOMAIN..."

# Generate private key
openssl genrsa -out "$KEY_FILE" 2048
chmod 600 "$KEY_FILE"

# Generate self-signed certificate with SAN
openssl req -new -x509 -key "$KEY_FILE" -out "$CRT_FILE" -days 365 \
    -subj "/C=US/ST=State/L=City/O=NetworkMapper/CN=$DOMAIN" \
    -addext "subjectAltName=DNS:localhost,DNS:$DOMAIN,IP:127.0.0.1,IP:$DOMAIN"

chmod 644 "$CRT_FILE"

echo "SSL certificate generated successfully!"
echo "Certificate: $CRT_FILE"
echo "Private key: $KEY_FILE"