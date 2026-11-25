"""Module 6: SSL/TLS Certificate Analysis — issuer, subject, validity period,
days to expiry, SAN entries (often reveal more subdomains), protocol version,
cipher strength and support for old TLS 1.0/1.1."""
import socket
import ssl
from datetime import datetime, timezone
from utils import good, warn, bad

NAME = "ssl"
DESCRIPTION = "TLS certificate, expiry, SANs, protocol and cipher analysis"


def _flatten(name_tuple):
    return {k: v for rdn in name_tuple for k, v in rdn}


def _supports(domain, version):
    """Return True if server accepts the given (legacy) TLS version."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        with socket.create_connection((domain, 443), timeout=5) as s:
            with ctx.wrap_socket(s, server_hostname=domain):
                return True
    except (ssl.SSLError, OSError, ValueError):
        return False


def run(domain, ctx):
    result = {}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as s:
                cert = s.getpeercert()
                result["protocol"] = s.version()
                cipher = s.cipher()
                result["cipher"] = {"name": cipher[0], "bits": cipher[2]}
        result["trusted"] = True
    except ssl.SSLCertVerificationError as e:
        bad(f"Certificate NOT trusted: {e.verify_message}")
        result["trusted"] = False
        result["verify_error"] = e.verify_message
        return result
    except (OSError, ssl.SSLError) as e:
        warn(f"No HTTPS on port 443: {e}")
        return {"error": str(e)}

    subject, issuer = _flatten(cert["subject"]), _flatten(cert["issuer"])
    not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days_left = (not_after - datetime.now(timezone.utc)).days
    sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

    result.update({
        "subject_cn": subject.get("commonName"),
        "issuer": issuer.get("organizationName", issuer.get("commonName")),
        "valid_from": not_before.isoformat(),
        "valid_to": not_after.isoformat(),
        "days_left": days_left,
        "san": sans,
        "serial": cert.get("serialNumber"),
    })
    good(f"Subject CN : {result['subject_cn']}")
    good(f"Issuer     : {result['issuer']}")
    good(f"Valid      : {not_before.date()} -> {not_after.date()}")
    (good if days_left > 30 else warn)(f"Expires in : {days_left} days")
    good(f"Protocol   : {result['protocol']}  Cipher: {result['cipher']['name']} ({result['cipher']['bits']} bit)")
    good(f"SAN ({len(sans)}) : {', '.join(sans[:10])}{' ...' if len(sans) > 10 else ''}")

    legacy = {}
    for label, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
        legacy[label] = _supports(domain, ver)
        (bad if legacy[label] else good)(f"{label} {'ENABLED (deprecated, weak)' if legacy[label] else 'disabled'}")
    result["legacy_protocols"] = legacy
    return result
