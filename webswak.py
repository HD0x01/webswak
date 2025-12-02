#!/usr/bin/env python3

import argparse
import http.server
import ssl
import os
import tempfile
import sys
import socket
import shutil
import logging
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta, UTC

TLS_VERSIONS = {
    "TLS1.2": ssl.TLSVersion.TLSv1_2,
    "TLS1.3": ssl.TLSVersion.TLSv1_3
}

temp_cert_dir = None

def generate_self_signed_cert():
    """Generate a temporary self-signed certificate and return file paths."""
    global temp_cert_dir
    temp_cert_dir = tempfile.mkdtemp()
    cert_path = os.path.join(temp_cert_dir, "webcert.pem")
    key_path = os.path.join(temp_cert_dir, "webkey.pem")

    # Generate RSA key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"DE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Hessen"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Frankfurt"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"TestServer"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )

    # Save private key
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save certificate
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return cert_path, key_path

def valid_port(value):
    ivalue = int(value)
    if ivalue < 1 or ivalue > 65535:
        raise argparse.ArgumentTypeError("Port must be between 1 and 65535.")
    return ivalue

class SafeHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def handle(self):
        try:
            super().handle()
        except (ssl.SSLError, BrokenPipeError, socket.error):
            pass

def cleanup_temp_cert():
    if temp_cert_dir and os.path.isdir(temp_cert_dir):
        shutil.rmtree(temp_cert_dir)
        logging.info(f"Temporary certificate directory {temp_cert_dir} removed.")

def main():
    logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

    parser = argparse.ArgumentParser(description="""Start an HTTPS or HTTP server.
    
    Note: To create your own certificate, you can use OpenSSL:

    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes""",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-m", "--mode", default="HTTPS", help="Server mode: HTTP or HTTPS")
    parser.add_argument("-P", "--protocol", default="HTTP/1.0", help="HTTP protocol version")
    parser.add_argument("-d", "--directory", default=os.getcwd(), help="Root directory")
    parser.add_argument("-b", "--bind", default="0.0.0.0", help="Bind address (IPv4)")
    parser.add_argument("-p", "--port", type=valid_port, help="Port number")
    parser.add_argument("-c", "--cert", help="Path to SSL certificate")
    parser.add_argument("-k", "--key", help="Path to SSL private key")
    parser.add_argument("-min", "--tls-min", choices=TLS_VERSIONS.keys(), default="TLS1.2", help="Minimal version =TLS1.2")
    parser.add_argument("-max", "--tls-max", choices=TLS_VERSIONS.keys(), default="TLS1.3", help="Maximal version =TLS1.3")
    args = parser.parse_args()

    args.mode = args.mode.upper()
    args.protocol = args.protocol.upper()

    if args.mode not in ["HTTP", "HTTPS"]:
        logging.error("--mode must be HTTP or HTTPS.")
        sys.exit(1)

    if args.port is None:
        args.port = 80 if args.mode == "HTTP" else 443

    args.directory = os.path.abspath(os.path.expanduser(args.directory))
    os.chdir(args.directory)

    handler = SafeHTTPRequestHandler
    handler.protocol_version = args.protocol

    try:
        httpd = http.server.HTTPServer((args.bind, args.port), handler)
    except OSError as e:
        logging.error(f"Failed to bind server: {e}")
        sys.exit(1)

    if args.mode == "HTTPS":
        cert_path, key_path = args.cert, args.key
        if not cert_path or not key_path:
            logging.info("No certificate provided – generating temporary self-signed certificate...")
            cert_path, key_path = generate_self_signed_cert()
        else:
            if not os.path.isfile(cert_path):
                logging.error(f"Certificate file not found: {cert_path}")
                sys.exit(1)
            if not os.path.isfile(key_path):
                logging.error(f"Key file not found: {key_path}")
                sys.exit(1)
            if os.path.getsize(cert_path) == 0:
                logging.error(f"Certificate file is empty: {cert_path}")
                sys.exit(1)
            if os.path.getsize(key_path) == 0:
                logging.error(f"Key file is empty: {key_path}")
                sys.exit(1)

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
        
        try:
            ssl_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        except ssl.SSLError:
            print("Problem loading certificate or key file, exiting.")
            sys.exit(1)
        
        ssl_context.minimum_version = TLS_VERSIONS[args.tls_min]
        ssl_context.maximum_version = TLS_VERSIONS[args.tls_max]

        httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)
        logging.info("HTTPS enabled. Make sure to use https:// in your client.")

    logging.info(f"Starting {args.mode} server on {args.bind}:{args.port}")
    logging.info(f"Protocol: {args.protocol}")
    if args.mode == "HTTPS":
        logging.info(f"TLS versions: min={args.tls_min}, max={args.tls_max}")
    logging.info(f"Serving directory: {args.directory}")
    logging.info("Press CTRL+C to stop.")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received, exiting.")
    finally:
        cleanup_temp_cert()
        sys.exit(0)

if __name__ == "__main__":
    main()
