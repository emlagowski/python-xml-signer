# SOAP XML Signer - Kotlin

Simple HTTP service to sign SOAP XML with JKS keystore.

## Quick Start

```bash
# Generate JKS and start service (one command!)
chmod +x setup.sh
./setup.sh

# Or with custom password
./setup.sh mypassword

# Test in another terminal
chmod +x test.sh
./test.sh
```

## Manual Setup

```bash
# Generate JKS only
keytool -genkeypair -alias xml-signer -keyalg RSA -keysize 2048 \
  -keystore keystore.jks -storepass changeit -keypass changeit \
  -dname "CN=XML Signer,OU=Dev,O=Example,L=City,ST=State,C=US" \
  -validity 3650

# Start service
docker-compose up --build
```

## Environment Variables

- `KEYSTORE_PATH` - Path to JKS file (default: `/app/keystore.jks`)
- `KEYSTORE_PASSWORD` - Keystore password (default: `changeit`)
- `PORT` - Server port (default: `8080`)

## Endpoints

- `POST /sign` - Sign XML (send raw XML in body, port 8083)
- `GET /health` - Health check