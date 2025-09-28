import ssl
from pathlib import Path


def create_tls_context(cert_dir: str = "/certs") -> ssl.SSLContext:
    cert_path = Path(cert_dir)
    ca_cert = cert_path / "ca.crt"
    server_cert = cert_path / "core.crt"
    server_key = cert_path / "core.key"

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    # Load server cert & key
    context.load_cert_chain(certfile=str(server_cert), keyfile=str(server_key))
    # Load CA for client verification (optional in dev)
    if ca_cert.exists():
        context.load_verify_locations(cafile=str(ca_cert))
    # TLS 1.3 minimum
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    # Strong ciphers
    try:
        context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!DSS")
    except Exception:
        pass
    return context
