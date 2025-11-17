#!/bin/bash
# Script to generate a self-signed certificate for XML signing

echo "Generating self-signed X.509 certificate..."
openssl req -new -x509 -key private_key.pem -out certificate.pem -days 365 \
  -subj "/C=US/ST=California/L=San Francisco/O=Example Org/OU=IT Department/CN=Example CA"

echo ""
echo "Certificate generated successfully: certificate.pem"
echo ""
echo "Certificate details:"
openssl x509 -in certificate.pem -noout -subject -issuer -serial -dates