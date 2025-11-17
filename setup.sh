#!/bin/bash
set -e

PASSWORD="${1:-changeit}"
KEYSTORE="keystore.jks"

echo "🔐 Generating JKS keystore with self-signed certificate..."
echo "Password: $PASSWORD"
echo ""

keytool -genkeypair -alias xml-signer -keyalg RSA -keysize 2048 \
  -keystore "$KEYSTORE" \
  -storepass "$PASSWORD" \
  -keypass "$PASSWORD" \
  -dname "CN=XML Signer,OU=Development,O=Example,L=City,ST=State,C=US" \
  -validity 3650

echo ""
echo "✅ JKS keystore created: $KEYSTORE"
echo "   Password: $PASSWORD"
echo "   Alias: xml-signer"
echo ""
echo "🐳 Starting Docker service..."
KEYSTORE_PASSWORD=$PASSWORD docker-compose up --build