"""Module 2: DNS Enumeration — A, AAAA, MX, NS, TXT, SOA, CNAME, CAA records,
SPF/DMARC analysis and zone-transfer (AXFR) test. Uses dnspython when installed,
otherwise falls back to basic socket resolution."""
import socket
from utils import good, warn, info, bad

NAME = "dns"
DESCRIPTION = "DNS records, SPF/DMARC check and zone-transfer test"

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"]

try:
    import dns.resolver
    import dns.query
    import dns.zone
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False


def _records(domain):
    records = {}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 6
    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = [a.to_text().strip('"') for a in answers]
        except Exception:
            continue
    return records


def _axfr(domain, nameservers):
    results = {}
    for ns in nameservers:
        ns = ns.rstrip(".")
        try:
            ns_ip = socket.gethostbyname(ns)
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=6, lifetime=10))
            names = [str(n) for n in zone.nodes.keys()]
            results[ns] = {"vulnerable": True, "hosts": names[:200]}
            bad(f"ZONE TRANSFER ALLOWED on {ns} — {len(names)} entries leaked!")
        except Exception:
            results[ns] = {"vulnerable": False}
            good(f"Zone transfer refused by {ns}")
    return results


def _email_security(records, domain):
    """Check SPF and DMARC — missing ones allow email spoofing."""
    out = {}
    spf = [t for t in records.get("TXT", []) if t.lower().startswith("v=spf1")]
    out["spf"] = spf[0] if spf else None
    try:
        dmarc = [a.to_text().strip('"') for a in dns.resolver.resolve(f"_dmarc.{domain}", "TXT")]
        out["dmarc"] = next((d for d in dmarc if d.lower().startswith("v=dmarc1")), None)
    except Exception:
        out["dmarc"] = None
    (good if out["spf"] else warn)(f"SPF   : {out['spf'] or 'MISSING (spoofing risk)'}")
    (good if out["dmarc"] else warn)(f"DMARC : {out['dmarc'] or 'MISSING (spoofing risk)'}")
    return out


def run(domain, ctx):
    if not HAVE_DNSPYTHON:
        warn("dnspython not installed — only A records (pip install dnspython)")
        try:
            ips = sorted({ai[4][0] for ai in socket.getaddrinfo(domain, None)})
            for ip in ips:
                good(f"A/AAAA : {ip}")
            return {"records": {"A/AAAA": ips}}
        except socket.gaierror as e:
            return {"error": str(e)}

    records = _records(domain)
    if not records:
        bad("No DNS records found")
        return {"records": {}}
    for rtype, vals in records.items():
        for v in vals:
            good(f"{rtype:6}: {v}")

    result = {"records": records}
    info("Checking email security records")
    result["email_security"] = _email_security(records, domain)
    if ctx.get("args") and not ctx["args"].passive:
        info("Testing zone transfer (AXFR) on each name server")
        result["zone_transfer"] = _axfr(domain, records.get("NS", []))
    return result
