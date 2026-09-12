import socket
import ssl
from urllib.parse import urlparse

import requests


def check_ssl_config(url: str) -> dict:
    """Check the TLS/SSL configuration of a URL.

    Performs a real TLS handshake to read the negotiated protocol version, cipher
    suite and certificate, and a plain request to check for the HSTS header.

    Args:
        url: The target URL (e.g. "https://example.com").

    Returns:
        dict with the negotiated TLS version, cipher, certificate details and HSTS
        status, or an {"error": ...} dict if the site cannot be reached.
    """
    parsed = urlparse(url if "://" in url else "https://" + url)
    host = parsed.hostname
    port = parsed.port or 443
    if not host:
        return {"error": f"could not parse a host from '{url}'"}
    if parsed.scheme != "https":
        return {
            "host": host,
            "https": False,
            "note": "URL is not HTTPS; there is no TLS layer to inspect.",
        }

    result: dict = {"host": host, "port": port, "https": True}

    # 1. TLS handshake: negotiated version, cipher, and peer certificate.
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                result["tls_version"] = tls.version()
                cipher = tls.cipher()  # (name, protocol, secret_bits)
                if cipher:
                    result["cipher"] = cipher[0]
                    result["cipher_bits"] = cipher[2]
                cert = tls.getpeercert()
    except (OSError, ssl.SSLError) as exc:
        return {"error": f"TLS connection to {host}:{port} failed: {exc}"}

    # 2. Certificate details (getpeercert returns nested tuples).
    if cert:

        def _flatten(rdns) -> dict:
            out: dict = {}
            for rdn in rdns:
                for key, value in rdn:
                    out[key] = value
            return out

        subject = _flatten(cert.get("subject", []))
        issuer = _flatten(cert.get("issuer", []))
        result["certificate"] = {
            "subject_cn": subject.get("commonName"),
            "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "valid_from": cert.get("notBefore"),
            "valid_until": cert.get("notAfter"),
            "sans": [v for t, v in cert.get("subjectAltName", []) if t == "DNS"],
        }

    # 3. HSTS header via a normal request.
    try:
        resp = requests.get(url if "://" in url else "https://" + host, timeout=10)
        hsts = resp.headers.get("strict-transport-security")
        result["hsts_present"] = bool(hsts)
        result["hsts"] = hsts
    except requests.RequestException as exc:
        result["hsts_error"] = str(exc)

    result["modern_tls"] = result.get("tls_version") in ("TLSv1.2", "TLSv1.3")
    return result
