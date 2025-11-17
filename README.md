# XML Signer with WS-Security

A Python script that signs XML documents using a private key and X.509 certificate with WS-Security (Web Services Security) standards. The signature is placed inside the `Header/Security` element following SOAP security specifications.

## Features

- **WS-Security compliant**: Places signature in `Header/Security` element (auto-created if missing)
- **Custom canonicalization**: Uses Exclusive XML Canonicalization (xml-exc-c14n)
- **RSA-SHA1 signature**: Industry-standard signature method
- **X509 certificate required**: Automatically extracts IssuerName and SerialNumber from certificate
- **SecurityTokenReference**: Includes proper WS-Security token reference structure
- **Namespace aware**: Handles properly namespaced SOAP/XML documents
- **Auto-creates Security header**: If your XML doesn't have a Security element, it will be created automatically
- **Command-line interface**: Easy to use from terminal

## Requirements

- Python 3.7+
- OpenSSL (for key and certificate generation)

## Installation

1. Install the required Python packages:

```bash
pip3 install -r requirements.txt
```

2. Generate a private/public key pair and certificate:

```bash
# Generate keys
./generate_keys.sh

# Generate self-signed certificate
./generate_certificate.sh
```

This will create:
- `private_key.pem` - Your private key (keep this secure!)
- `public_key.pem` - Your public key
- `certificate.pem` - Your X.509 certificate (contains issuer and serial number)

## XML Structure

Your XML document can be a simple SOAP envelope. The script will automatically:
- Create the `Header` element if it doesn't exist
- Create the `wsse:Security` element if it doesn't exist
- Add `wsu:Id="Body"` attribute to the Body element if missing
- Insert the signature into the Security element

Minimum structure:
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Body>
        <!-- Your content here -->
    </soapenv:Body>
</soapenv:Envelope>
```

The script will transform it to:
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Header>
        <wsse:Security>
            <ds:Signature>
                <!-- Signature content -->
            </ds:Signature>
        </wsse:Security>
    </soapenv:Header>
    <soapenv:Body wsu:Id="Body">
        <!-- Your content -->
    </soapenv:Body>
</soapenv:Envelope>
```

## Usage

### Basic Usage

**File Mode:**
```bash
python3 xml_signer.py <input_xml> <private_key> <certificate> [-o <output_file>]
```

**Stdin/Stdout Mode (for piping with other tools):**
```bash
cat input.xml | python3 xml_signer.py --stdin <private_key> <certificate> > output.xml
```

### Command-Line Arguments

- `xml_file` - Path to the input XML file to be signed (not used with --stdin)
- `private_key` - Path to the private key file in PEM format (required)
- `certificate` - Path to X.509 certificate file in PEM format (required)
- `-o, --output` - Path to save the signed XML file (optional, default: `signed_output.xml`, ignored with --stdin)
- `--stdin` - Read XML from stdin and write signed XML to stdout (for use with pipes and other tools)

### Examples

#### File Mode

1. **Basic signing with default output:**

```bash
python3 xml_signer.py example_input.xml private_key.pem certificate.pem
```

2. **Signing with custom output file:**

```bash
python3 xml_signer.py example_input.xml private_key.pem certificate.pem -o my_signed_document.xml
```

3. **Sign a simple SOAP envelope (Security header will be auto-created):**

```bash
python3 xml_signer.py example_input_simple.xml private_key.pem certificate.pem -o signed.xml
```

#### Stdin/Stdout Mode (for integration with other tools)

4. **Sign XML from stdin:**

```bash
cat input.xml | python3 xml_signer.py --stdin private_key.pem certificate.pem > signed.xml
```

5. **Use in a pipeline:**

```bash
curl https://api.example.com/xml | python3 xml_signer.py --stdin private_key.pem certificate.pem | curl -X POST https://api.example.com/signed -d @-
```

6. **Sign XML from echo/heredoc:**

```bash
echo '<soapenv:Envelope>...</soapenv:Envelope>' | python3 xml_signer.py --stdin private_key.pem certificate.pem > output.xml
```

## How It Works

The script performs the following steps:

1. **Loads the private key** from the specified PEM file
2. **Loads the X.509 certificate** and extracts issuer name and serial number
3. **Parses the input XML** document
4. **Creates Header/Security elements** if they don't exist
5. **Ensures Body has wsu:Id** attribute
6. **Creates the digital signature** with:
   - **CanonicalizationMethod**: Exclusive XML Canonicalization (`xml-exc-c14n`)
   - **SignatureMethod**: RSA-SHA1
   - **Transform**: Exclusive XML Canonicalization with InclusiveNamespaces
   - **DigestMethod**: SHA-1
   - **KeyInfo**: SecurityTokenReference with X509Data (IssuerName and SerialNumber)
7. **Inserts the signature** into the `Header/Security` element
8. **Saves the signed XML** to the output file

## Signature Structure

The generated signature includes:

```xml
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
        <ds:Reference URI="#Body">
            <ds:Transforms>
                <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
                    <ds:InclusiveNamespaces PrefixList="soapenv urn"/>
                </ds:Transform>
            </ds:Transforms>
            <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
            <ds:DigestValue>...</ds:DigestValue>
        </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>...</ds:SignatureValue>
    <ds:KeyInfo>
        <wsse:SecurityTokenReference>
            <ds:X509Data>
                <ds:X509IssuerSerial>
                    <ds:X509IssuerName>CN=Example CA,OU=IT Department,O=Example Org,L=San Francisco,ST=California,C=US</ds:X509IssuerName>
                    <ds:X509SerialNumber>568239987788340143663974911563854167826714304262</ds:X509SerialNumber>
                </ds:X509IssuerSerial>
            </ds:X509Data>
        </wsse:SecurityTokenReference>
    </ds:KeyInfo>
</ds:Signature>
```

## Technical Specifications

| Component | Value |
|-----------|-------|
| Canonicalization | Exclusive XML Canonicalization (xml-exc-c14n) |
| Signature Method | RSA-SHA1 |
| Digest Method | SHA-1 |
| Transform | xml-exc-c14n with InclusiveNamespaces |
| Signature Placement | `Header/Security` element (auto-created) |
| Referenced Element | `Body` element with `wsu:Id` |
| KeyInfo Structure | SecurityTokenReference → X509Data → X509IssuerSerial |

## Security Notes

⚠️ **Important Security Considerations:**

1. **Never share your private key** (`private_key.pem`)
2. Store private keys securely with appropriate file permissions (`chmod 600 private_key.pem`)
3. Use strong keys (minimum 2048 bits for RSA, 4096 recommended for production)
4. Rotate keys and certificates periodically according to your security policy
5. The example keys generated are for demonstration only - generate new keys for production
6. **Note**: RSA-SHA1 is used for compatibility but consider SHA-256 for new implementations
7. Keep your certificate valid and up-to-date
8. The certificate's IssuerName and SerialNumber are automatically extracted and included in the signature

## Certificate Information

The script automatically extracts the following from your certificate:
- **IssuerName**: The distinguished name of the certificate issuer (e.g., `CN=Example CA,O=Example Org,C=US`)
- **SerialNumber**: The unique serial number of the certificate (e.g., `568239987788340143663974911563854167826714304262`)

These values are included in the signature's `SecurityTokenReference` for proper WS-Security compliance.

## File Structure

```
.
├── xml_signer.py              # Main signing script
├── requirements.txt           # Python dependencies
├── generate_keys.sh           # Script to generate key pair
├── generate_certificate.sh    # Script to generate self-signed certificate
├── example_input.xml          # Example SOAP XML with Security header
├── example_input_simple.xml   # Simple SOAP XML (no Security header)
├── private_key.pem            # Private key (generated, keep secure!)
├── public_key.pem             # Public key (generated, can be shared)
├── certificate.pem            # X.509 certificate (generated)
├── signed_output.xml          # Signed output (generated)
├── .gitignore                 # Git ignore file (protects keys)
└── README.md                  # This file
```

## Dependencies

- **lxml**: XML processing library with canonicalization support
- **cryptography**: Cryptographic operations (RSA signing, SHA-1 hashing, X.509 certificate handling)

## Troubleshooting

### "Error: Certificate is required for signing"
- Ensure you've generated a certificate using `./generate_certificate.sh`
- Provide the correct path to your certificate file

### "Error: Body element not found"
- Verify your XML has a `soapenv:Body` element
- Check the namespace prefix matches (`soapenv` by default)

### "Error: Private key file not found"
- Ensure the path to your private key is correct
- Check that you have read permissions for the key file

### "Error reading certificate"
- Verify your certificate is in PEM format
- Ensure the certificate file is not corrupted
- Check file permissions

### "Error signing XML"
- Verify your private key matches your certificate
- Ensure the key is not corrupted or password-protected
- Check that the XML structure is valid

## Compatibility

This implementation follows these standards:
- **WS-Security 1.0/1.1**: Web Services Security
- **XML Signature**: W3C XML Signature Syntax and Processing
- **SOAP 1.1/1.2**: Simple Object Access Protocol

## Example Output

When you run the script successfully, you'll see:

```
Loading private key from: private_key.pem
Loading certificate from: certificate.pem
Loading XML from: example_input_simple.xml
Signing XML with RSA-SHA1 and xml-exc-c14n...
Using certificate: Issuer=CN=Example CA,OU=IT Department,O=Example Org,L=San Francisco,ST=California,C=US, Serial=568239987788340143663974911563854167826714304262
Successfully signed XML saved to: signed_output.xml
```

The signature will be embedded in the `Header/Security` element with:
- SecurityTokenReference containing X509IssuerName and X509SerialNumber
- Complete cryptographic signature
- Proper namespace declarations

## Advanced Usage

### Viewing certificate details

To view your certificate information:

```bash
# View certificate details
openssl x509 -in certificate.pem -noout -text

# View issuer
openssl x509 -in certificate.pem -noout -issuer

# View serial number
openssl x509 -in certificate.pem -noout -serial
```

### Generating a production certificate

For production use, obtain a certificate from a trusted Certificate Authority (CA) instead of using a self-signed certificate:

```bash
# Create a certificate signing request (CSR)
openssl req -new -key private_key.pem -out certificate.csr

# Submit the CSR to your CA, then use the issued certificate
```

### Working with different XML structures

The script automatically adapts to your XML structure:
- Creates missing Header elements
- Creates missing Security elements  
- Adds required wsu:Id to Body
- Preserves all existing content and namespaces

## License

This script is provided as-is for educational and practical purposes.

---

**Version:** 3.0.0  
**Last Updated:** 2025-11-17