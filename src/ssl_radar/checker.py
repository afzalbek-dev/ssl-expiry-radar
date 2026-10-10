"""TLS certificate inspection and validation engine."""
import ssl
import socket
from datetime import datetime, timezone
from typing import Dict, Any, Optional

class CertInspector:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def check_host(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """Connects via TLS and fetches certificate metadata."""
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        return {
                            "hostname": hostname,
                            "valid": False,
                            "error": "No certificate presented"
                        }
                    return self.parse_cert(cert, hostname)
        except Exception as e:
            return {
                "hostname": hostname,
                "valid": False,
                "error": str(e)
            }

    def parse_cert(self, cert: Dict[str, Any], hostname: str) -> Dict[str, Any]:
        """Parses ssl peer cert dict into structured inspection result."""
        not_after_str = cert.get("notAfter", "")
        not_before_str = cert.get("notBefore", "")

        # Format: 'May  9 12:00:00 2026 GMT'
        expires_at = None
        days_remaining = 0
        if not_after_str:
            try:
                expires_at = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                delta = expires_at - now
                days_remaining = max(0, delta.days)
            except Exception:
                pass

        issuer_dict = {}
        for rdn in cert.get("issuer", ()):
            for key, val in rdn:
                issuer_dict[key] = val

        subject_dict = {}
        for rdn in cert.get("subject", ()):
            for key, val in rdn:
                subject_dict[key] = val

        san = [val for key, val in cert.get("subjectAltName", ()) if key == "DNS"]

        return {
            "hostname": hostname,
            "valid": True,
            "days_remaining": days_remaining,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "issuer": issuer_dict.get("organizationName", issuer_dict.get("commonName", "Unknown Issuer")),
            "common_name": subject_dict.get("commonName", hostname),
            "san": san
        }
