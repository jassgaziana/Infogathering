"""Shared helpers: colored output, HTTP requests, target normalisation."""
import json
import re
import socket
import ssl
import urllib.request
import urllib.error

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) InfoGather/1.0 (MCA CS&FS Project)"
DEFAULT_TIMEOUT = 8


class C:
    """ANSI colors for terminal output."""
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
    M = "\033[95m"; CY = "\033[96m"; W = "\033[97m"; BOLD = "\033[1m"; END = "\033[0m"


def info(msg):  print(f"{C.B}[*]{C.END} {msg}")
def good(msg):  print(f"{C.G}[+]{C.END} {msg}")
def warn(msg):  print(f"{C.Y}[!]{C.END} {msg}")
def bad(msg):   print(f"{C.R}[-]{C.END} {msg}")


def section(title):
    print(f"\n{C.BOLD}{C.CY}{'=' * 60}\n  {title}\n{'=' * 60}{C.END}")


def clean_domain(target: str) -> str:
    """Strip scheme, path and port: 'https://www.x.com/a' -> 'www.x.com'."""
    target = target.strip().lower()
    target = re.sub(r"^[a-z]+://", "", target)
    target = target.split("/")[0].split(":")[0]
    return target


def is_valid_domain(domain: str) -> bool:
    pattern = r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$"
    return bool(re.match(pattern, domain))


def resolve(host: str):
    """Return the first IPv4 address of a host, or None."""
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, UnicodeError):
        return None


def http_get(url, timeout=DEFAULT_TIMEOUT, verify=True, method="GET", max_bytes=2_000_000):
    """
    Minimal HTTP client built on urllib (no external dependency).
    Returns dict: {status, headers, body, url} or {error}.
    HTTP error codes (403, 404...) are returned as normal responses.
    """
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(max_bytes).decode("utf-8", errors="replace") if method != "HEAD" else ""
            return {"status": r.status, "headers": dict(r.headers), "body": body, "url": r.geturl()}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(max_bytes).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return {"status": e.code, "headers": dict(e.headers or {}), "body": body, "url": url}
    except Exception as e:  # timeout, DNS failure, TLS failure...
        return {"error": str(e)}


def http_json(url, timeout=DEFAULT_TIMEOUT):
    r = http_get(url, timeout=timeout)
    if "error" in r or r.get("status") != 200:
        return None
    try:
        return json.loads(r["body"])
    except ValueError:
        return None


def base_url(domain: str) -> str:
    """Prefer HTTPS; fall back to HTTP if the HTTPS request fails."""
    r = http_get(f"https://{domain}", method="HEAD", verify=False)
    if "error" not in r:
        return f"https://{domain}"
    return f"http://{domain}"
