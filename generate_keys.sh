#!/bin/bash
# Script to generate RSA private and public key pair for XML signing

echo "Generating RSA private key (2048 bits)..."
openssl genrsa -out private_key.pem 2048

echo "Extracting public key from private key..."
openssl rsa -in private_key.pem -pubout -out public_key.pem

echo ""
echo "Keys generated successfully:"
echo "  - Private key: private_key.pem"
echo "  - Public key: public_key.pem"
echo ""
echo "IMPORTANT: Keep your private_key.pem secure and never share it!"