"""Module 1: WHOIS Lookup — raw WHOIS over TCP/43 (no external library).
Queries IANA to find the TLD's WHOIS server, then follows registrar referrals."""
import re
import socket
from utils import good, warn, info

NAME = "whois"
DESCRIPTION = "Domain registration details (registrar, dates, name servers)"

FIELDS = {
    "registrar": r"Registrar:\s*(.+)",
    "creation_date": r"Creation Date:\s*(.+)",
    "updated_date": r"Updated Date:\s*(.+)",
    "expiry_date": r"(?:Registry Expiry Date|Registrar Registration Expiration Date|Expiry Date):\s*(.+)",
    "registrant_org": r"Registrant Organization:\s*(.+)",
    "registrant_country": r"Registrant Country:\s*(.+)",
    "abuse_email": r"Registrar Abuse Contact Email:\s*(.+)",
    "dnssec": r"DNSSEC:\s*(.+)",
}


def _query(server, query, timeout=10):
    data = b""
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.sendall((query + "\r\n").encode())
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    return data.decode("utf-8", errors="replace")


def run(domain, ctx):
    result = {}
    try:
        # registered domain = last two labels (simple heuristic; e.g. example.co.in needs 3)
        parts = domain.split(".")
        reg_domain = ".".join(parts[-3:]) if len(parts) > 2 and len(parts[-2]) <= 3 else ".".join(parts[-2:])
        tld = parts[-1]

        iana = _query("whois.iana.org", tld)
        m = re.search(r"whois:\s*(\S+)", iana)
        server = m.group(1) if m else f"whois.nic.{tld}"
        info(f"WHOIS server: {server}")
        raw = _query(server, reg_domain)

        # follow registrar referral for thin registries (.com/.net)
        ref = re.search(r"Registrar WHOIS Server:\s*(\S+)", raw)
        if ref and ref.group(1).lower() != server.lower():
            try:
                raw += "\n" + _query(ref.group(1), reg_domain)
            except OSError:
                pass

        for key, pat in FIELDS.items():
            m = re.search(pat, raw, re.I)
            if m:
                result[key] = m.group(1).strip()
        result["name_servers"] = sorted({ns.strip().lower() for ns in re.findall(r"Name Server:\s*(\S+)", raw, re.I)})
        result["status"] = sorted({s.split()[0] for s in re.findall(r"Domain Status:\s*(.+)", raw, re.I)})

        for k, v in result.items():
            good(f"{k:20}: {', '.join(v) if isinstance(v, list) else v}")
        if not result.get("registrar"):
            warn("Registrar not parsed — raw response saved in report")
            result["raw"] = raw[:3000]
    except OSError as e:
        warn(f"WHOIS failed: {e}")
        result["error"] = str(e)
    return result
