#!/usr/bin/env python3
"""
XML Signer - Sign XML documents using a private key with WS-Security standards
Places signature in Header/Security element with custom configuration
"""

import argparse
import sys
from lxml import etree
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import base64


# Namespace definitions
NAMESPACES = {
    'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/',
    'wsse': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
    'wsu': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
    'ds': 'http://www.w3.org/2000/09/xmldsig#',
}


def load_private_key(key_path: str):
    """
    Load private key from PEM file
    
    Args:
        key_path: Path to the private key file
        
    Returns:
        Private key object
    """
    try:
        with open(key_path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        return private_key
    except FileNotFoundError:
        print(f"Error: Private key file not found: {key_path}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading private key: {e}", file=sys.stderr)
        sys.exit(1)


def load_certificate(cert_path: str = None):
    """
    Load X.509 certificate from PEM file (optional)
    
    Args:
        cert_path: Path to the certificate file
        
    Returns:
        Certificate object or None
    """
    if not cert_path:
        return None
        
    try:
        with open(cert_path, 'rb') as cert_file:
            cert = x509.load_pem_x509_certificate(
                cert_file.read(),
                backend=default_backend()
            )
        return cert
    except FileNotFoundError:
        print(f"Warning: Certificate file not found: {cert_path}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Warning: Error reading certificate: {e}", file=sys.stderr)
        return None


def load_xml(xml_path: str = None, xml_string: str = None) -> etree.Element:
    """
    Load and parse XML file or string
    
    Args:
        xml_path: Path to the XML file (optional if xml_string provided)
        xml_string: XML string to parse (optional if xml_path provided)
        
    Returns:
        Parsed XML element
    """
    try:
        parser = etree.XMLParser(remove_blank_text=False, resolve_entities=False)
        
        if xml_string:
            # Parse from string
            return etree.fromstring(xml_string.encode('utf-8'), parser)
        elif xml_path:
            # Parse from file
            tree = etree.parse(xml_path, parser)
            return tree.getroot()
        else:
            print("Error: Either xml_path or xml_string must be provided", file=sys.stderr)
            sys.exit(1)
            
    except FileNotFoundError:
        print(f"Error: XML file not found: {xml_path}", file=sys.stderr)
        sys.exit(1)
    except etree.XMLSyntaxError as e:
        print(f"Error parsing XML: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading XML: {e}", file=sys.stderr)
        sys.exit(1)


def c14n_exclusive(element):
    """
    Perform exclusive canonicalization (xml-exc-c14n) on an element
    
    Args:
        element: XML element to canonicalize
        
    Returns:
        Canonicalized bytes
    """
    return etree.tostring(
        element,
        method='c14n',
        exclusive=True,
        with_comments=False
    )


def create_digest(data: bytes) -> str:
    """
    Create SHA-256 digest of data
    
    Args:
        data: Data to digest
        
    Returns:
        Base64-encoded digest
    """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return base64.b64encode(digest.finalize()).decode('utf-8')


def create_signature_element(private_key, cert, body_element):
    """
    Create the Signature element with all required sub-elements
    
    Args:
        private_key: Private key for signing
        cert: X.509 certificate (required)
        body_element: Body element to sign
        
    Returns:
        Signature element
    """
    if not cert:
        print("Error: Certificate is required for signing", file=sys.stderr)
        sys.exit(1)
    
    # Create Signature element
    signature = etree.Element(
        f"{{{NAMESPACES['ds']}}}Signature",
        nsmap={'ds': NAMESPACES['ds']}
    )
    
    # Create SignedInfo
    signed_info = etree.SubElement(signature, f"{{{NAMESPACES['ds']}}}SignedInfo")
    
    # CanonicalizationMethod - xml-exc-c14n with InclusiveNamespaces
    c14n_method = etree.SubElement(signed_info, f"{{{NAMESPACES['ds']}}}CanonicalizationMethod")
    c14n_method.set('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#')
    
    # Add InclusiveNamespaces to CanonicalizationMethod
    c14n_inclusive_ns = etree.SubElement(
        c14n_method,
        f"{{{NAMESPACES['ds']}}}InclusiveNamespaces",
        nsmap={'ec': 'http://www.w3.org/2001/10/xml-exc-c14n#'}
    )
    c14n_inclusive_ns.set('PrefixList', 'soapenv urn')
    
    # SignatureMethod - RSA-SHA1
    sig_method = etree.SubElement(signed_info, f"{{{NAMESPACES['ds']}}}SignatureMethod")
    sig_method.set('Algorithm', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1')
    
    # Reference to Body
    reference = etree.SubElement(signed_info, f"{{{NAMESPACES['ds']}}}Reference")
    body_id = body_element.get(f"{{{NAMESPACES['wsu']}}}Id", "Body")
    reference.set('URI', f"#{body_id}")
    
    # Transforms
    transforms = etree.SubElement(reference, f"{{{NAMESPACES['ds']}}}Transforms")
    
    # Transform - xml-exc-c14n
    transform = etree.SubElement(transforms, f"{{{NAMESPACES['ds']}}}Transform")
    transform.set('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#')
    
    # InclusiveNamespaces
    inclusive_ns = etree.SubElement(
        transform,
        f"{{{NAMESPACES['ds']}}}InclusiveNamespaces",
        nsmap={'ec': 'http://www.w3.org/2001/10/xml-exc-c14n#'}
    )
    inclusive_ns.set('PrefixList', 'soapenv urn')
    
    # DigestMethod - SHA256
    digest_method = etree.SubElement(reference, f"{{{NAMESPACES['ds']}}}DigestMethod")
    digest_method.set('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256')
    
    # DigestValue - calculate digest of canonicalized Body
    body_c14n = c14n_exclusive(body_element)
    digest_value = create_digest(body_c14n)
    digest_value_elem = etree.SubElement(reference, f"{{{NAMESPACES['ds']}}}DigestValue")
    digest_value_elem.text = digest_value
    
    # Calculate SignatureValue
    signed_info_c14n = c14n_exclusive(signed_info)
    signature_value = sign_data(private_key, signed_info_c14n)
    
    # Add SignatureValue
    sig_value_elem = etree.SubElement(signature, f"{{{NAMESPACES['ds']}}}SignatureValue")
    sig_value_elem.text = signature_value
    
    # Add KeyInfo
    key_info = etree.SubElement(signature, f"{{{NAMESPACES['ds']}}}KeyInfo")
    
    # Add SecurityTokenReference
    sec_token_ref = etree.SubElement(
        key_info,
        f"{{{NAMESPACES['wsse']}}}SecurityTokenReference",
        nsmap={'wsse': NAMESPACES['wsse']}
    )
    
    # Add X509Data with certificate info
    x509_data = etree.SubElement(sec_token_ref, f"{{{NAMESPACES['ds']}}}X509Data")
    
    # Extract issuer and serial from certificate
    issuer = cert.issuer.rfc4514_string()
    serial = str(cert.serial_number)
    
    x509_issuer_serial = etree.SubElement(x509_data, f"{{{NAMESPACES['ds']}}}X509IssuerSerial")
    x509_issuer_name = etree.SubElement(x509_issuer_serial, f"{{{NAMESPACES['ds']}}}X509IssuerName")
    x509_issuer_name.text = issuer
    x509_serial_number = etree.SubElement(x509_issuer_serial, f"{{{NAMESPACES['ds']}}}X509SerialNumber")
    x509_serial_number.text = serial
    
    return signature


def sign_data(private_key, data: bytes) -> str:
    """
    Sign data using RSA-SHA1
    
    Args:
        private_key: Private key object
        data: Data to sign
        
    Returns:
        Base64-encoded signature
    """
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA1()
    )
    return base64.b64encode(signature).decode('utf-8')


def sign_xml(xml_element: etree.Element, private_key, cert) -> etree.Element:
    """
    Sign XML element and place signature in Header/Security
    Creates Security header if it doesn't exist
    
    Args:
        xml_element: XML element to sign
        private_key: Private key for signing
        cert: X.509 certificate (required)
        
    Returns:
        Signed XML element
    """
    try:
        # Find or create Header element
        header = xml_element.find('.//soapenv:Header', namespaces=NAMESPACES)
        if header is None:
            # Create Header if it doesn't exist
            header = etree.Element(
                f"{{{NAMESPACES['soapenv']}}}Header",
                nsmap={'soapenv': NAMESPACES['soapenv']}
            )
            # Insert Header as first child of Envelope
            xml_element.insert(0, header)
        
        # Find or create Security element in Header
        security = header.find('.//wsse:Security', namespaces=NAMESPACES)
        if security is None:
            # Create Security element if it doesn't exist
            security = etree.SubElement(
                header,
                f"{{{NAMESPACES['wsse']}}}Security",
                nsmap={
                    'wsse': NAMESPACES['wsse'],
                    'wsu': NAMESPACES['wsu']
                }
            )
        
        # Find Body element
        body = xml_element.find('.//soapenv:Body', namespaces=NAMESPACES)
        if body is None:
            print("Error: Body element not found", file=sys.stderr)
            sys.exit(1)
        
        # Ensure Body has wsu:Id attribute
        if f"{{{NAMESPACES['wsu']}}}Id" not in body.attrib:
            body.set(f"{{{NAMESPACES['wsu']}}}Id", "Body")
        
        # Create signature
        signature = create_signature_element(private_key, cert, body)
        
        # Insert signature into Security element (at the beginning)
        security.insert(0, signature)
        
        return xml_element
    except Exception as e:
        print(f"Error signing XML: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


def save_xml(xml_element: etree.Element, output_path: str = None, to_stdout: bool = False):
    """
    Save signed XML to file or stdout
    
    Args:
        xml_element: Signed XML element
        output_path: Path to save the signed XML (optional if to_stdout=True)
        to_stdout: If True, write to stdout instead of file
    """
    try:
        xml_string = etree.tostring(
            xml_element,
            pretty_print=True,
            xml_declaration=True,
            encoding='UTF-8'
        )
        
        if to_stdout:
            # Write to stdout
            sys.stdout.buffer.write(xml_string)
            sys.stdout.buffer.flush()
        elif output_path:
            # Write to file
            with open(output_path, 'wb') as output_file:
                output_file.write(xml_string)
            print(f"Successfully signed XML saved to: {output_path}", file=sys.stderr)
        else:
            print("Error: Either output_path or to_stdout must be specified", file=sys.stderr)
            sys.exit(1)
            
    except Exception as e:
        print(f"Error saving signed XML: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    """Main function to handle command-line arguments and orchestrate signing"""
    parser = argparse.ArgumentParser(
        description='Sign XML documents using a private key with WS-Security standards',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # File mode (default)
  python xml_signer.py input.xml private_key.pem certificate.pem
  python xml_signer.py input.xml private_key.pem certificate.pem -o signed_output.xml
  
  # Stdin/stdout mode (for use with other tools)
  cat input.xml | python xml_signer.py --stdin private_key.pem certificate.pem > output.xml
  echo '<xml>...</xml>' | python xml_signer.py --stdin private_key.pem certificate.pem
        """
    )
    
    parser.add_argument(
        'xml_file',
        nargs='?',
        help='Path to the input XML file to be signed (not used with --stdin)'
    )
    
    parser.add_argument(
        'private_key',
        help='Path to the private key file (PEM format)'
    )
    
    parser.add_argument(
        'certificate',
        help='Path to the X.509 certificate file (PEM format, required)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='signed_output.xml',
        help='Path to save the signed XML file (default: signed_output.xml, ignored with --stdin)'
    )
    
    parser.add_argument(
        '--stdin',
        action='store_true',
        help='Read XML from stdin and write signed XML to stdout'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.stdin:
        if args.xml_file:
            print("Warning: xml_file argument ignored when using --stdin", file=sys.stderr)
    else:
        if not args.xml_file:
            parser.error("xml_file is required when not using --stdin")
    
    # Load private key
    if not args.stdin:
        print(f"Loading private key from: {args.private_key}", file=sys.stderr)
    private_key = load_private_key(args.private_key)
    
    # Load certificate
    if not args.stdin:
        print(f"Loading certificate from: {args.certificate}", file=sys.stderr)
    cert = load_certificate(args.certificate)
    
    if not cert:
        print("Error: Certificate is required for signing", file=sys.stderr)
        sys.exit(1)
    
    # Load XML
    if args.stdin:
        # Read from stdin
        xml_string = sys.stdin.read()
        xml_element = load_xml(xml_string=xml_string)
    else:
        # Read from file
        print(f"Loading XML from: {args.xml_file}", file=sys.stderr)
        xml_element = load_xml(xml_path=args.xml_file)
    
    # Sign XML
    if not args.stdin:
        print("Signing XML with RSA-SHA1 and xml-exc-c14n...", file=sys.stderr)
        print(f"Using certificate: Issuer={cert.issuer.rfc4514_string()}, Serial={cert.serial_number}", file=sys.stderr)
    signed_xml = sign_xml(xml_element, private_key, cert)
    
    # Save signed XML
    if args.stdin:
        # Write to stdout
        save_xml(signed_xml, to_stdout=True)
    else:
        # Write to file
        save_xml(signed_xml, output_path=args.output)


if __name__ == '__main__':
    main()