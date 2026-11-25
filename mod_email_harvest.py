"""Module 8: Email, Phone & Social Media Harvesting (OSINT) — crawls the target
website (same domain, limited depth) and extracts email addresses, phone
numbers and social-media profile links. Useful for social-engineering
risk assessment."""
import re
from urllib.parse import urljoin, urlparse
from utils import http_get, good, info, warn

NAME = "osint"
DESCRIPTION = "Emails, phone numbers and social profiles from website crawl"

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PHONE_RE = re.compile(r"(?<!\w)\+?\(?\d[\d\s().-]{8,16}\d(?!\w)")
LINK_RE = re.compile(r'href=["\']([^"\'#]+)["\']', re.I)
SOCIAL = {
    "Facebook": r"facebook\.com/[A-Za-z0-9_.-]+", "Twitter/X": r"(?:twitter|x)\.com/[A-Za-z0-9_]+",
    "LinkedIn": r"linkedin\.com/(?:company|in)/[A-Za-z0-9_-]+", "Instagram": r"instagram\.com/[A-Za-z0-9_.]+",
    "YouTube": r"youtube\.com/(?:c/|channel/|@)[A-Za-z0-9_-]+", "GitHub": r"github\.com/[A-Za-z0-9_-]+",
}
PRIORITY = ("contact", "about", "team", "support", "career", "privacy", "imprint")
IGNORE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".js", ".pdf", ".zip", ".ico", ".woff", ".woff2")


def run(domain, ctx):
    args = ctx.get("args")
    max_pages = args.crawl_pages if args else 25
    start = ctx.get("base_url", f"https://{domain}")
    root = domain.removeprefix("www.")

    queue, seen = [start], set()
    emails, phones, socials = set(), set(), {}
    info(f"Crawling up to {max_pages} pages on {domain}")

    while queue and len(seen) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        r = http_get(url, verify=False, timeout=6)
        if "error" in r or "text/html" not in r["headers"].get("Content-Type", "text/html"):
            continue
        body = r["body"]

        for e in EMAIL_RE.findall(body):
            if not e.lower().endswith(IGNORE_EXT):
                emails.add(e.lower())
        text = re.sub(r"<[^>]+>", " ", body)
        for p in PHONE_RE.findall(text):
            digits = re.sub(r"\D", "", p)
            if 10 <= len(digits) <= 13:
                phones.add(p.strip())
        for name, pat in SOCIAL.items():
            for m in re.findall(pat, body, re.I):
                socials.setdefault(name, set()).add("https://" + m)

        links = []
        for href in LINK_RE.findall(body):
            full = urljoin(url, href).split("#")[0]
            host = urlparse(full).netloc.lower()
            if host.endswith(root) and not full.lower().endswith(IGNORE_EXT) and full not in seen:
                links.append(full)
        # crawl contact/about pages first
        links.sort(key=lambda l: not any(k in l.lower() for k in PRIORITY))
        queue = links + queue

    domain_emails = sorted(e for e in emails if e.endswith(root))
    other_emails = sorted(emails - set(domain_emails))
    for e in domain_emails:
        good(f"Email  : {e}")
    for e in other_emails:
        good(f"Email  : {e} (external)")
    for p in sorted(phones)[:20]:
        good(f"Phone  : {p}")
    for net, links in socials.items():
        for l in sorted(links)[:3]:
            good(f"{net:9}: {l}")
    if not emails:
        warn("No email addresses found")
    return {"pages_crawled": len(seen), "emails": domain_emails, "external_emails": other_emails,
            "phones": sorted(phones)[:20], "social": {k: sorted(v) for k, v in socials.items()}}
