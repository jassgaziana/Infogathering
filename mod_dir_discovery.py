"""Module 10: Directory & Sensitive File Discovery — reads robots.txt and
sitemap.xml, then brute-forces common paths (admin panels, backups, .git,
.env, config files) with a wordlist. Flags critical exposures."""
import os
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from utils import http_get, good, info, warn, bad

NAME = "dirs"
DESCRIPTION = "robots.txt, sitemap and sensitive path brute-force"

WORDLIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlist_directories.txt")
CRITICAL = [".git/", ".env", ".svn/", "backup", ".sql", "wp-config", "config.php", ".htpasswd",
            "phpinfo", ".DS_Store", "id_rsa", "web.config", "server-status", ".bak", "dump"]


def _robots(base):
    r = http_get(f"{base}/robots.txt", verify=False)
    if "error" in r or r["status"] != 200 or "<html" in r["body"][:200].lower():
        return [], []
    disallow = re.findall(r"(?im)^\s*disallow:\s*(\S+)", r["body"])
    sitemaps = re.findall(r"(?im)^\s*sitemap:\s*(\S+)", r["body"])
    return sorted(set(disallow)), sitemaps


def _sitemap(url):
    r = http_get(url, verify=False)
    if "error" in r or r["status"] != 200:
        return []
    return re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", r["body"])


def run(domain, ctx):
    base = ctx.get("base_url", f"https://{domain}")
    args = ctx.get("args")
    threads = args.threads if args else 20
    result = {}

    info("Reading robots.txt")
    disallow, sitemaps = _robots(base)
    result["robots_disallow"] = disallow
    for d in disallow[:25]:
        good(f"robots Disallow: {d}")

    info("Reading sitemap.xml")
    urls = []
    for sm in (sitemaps or [f"{base}/sitemap.xml"])[:3]:
        urls += _sitemap(sm)
    result["sitemap_urls"] = urls[:300]
    good(f"Sitemap URLs: {len(urls)}")

    if args and args.passive:
        return result

    # Soft-404 detection: some servers return 200 for every path
    probe = http_get(f"{base}/{uuid.uuid4().hex}", verify=False)
    soft404_len = len(probe.get("body", "")) if probe.get("status") == 200 else None
    if soft404_len is not None:
        warn("Server returns 200 for missing pages — filtering by response size")

    try:
        with open(WORDLIST) as f:
            paths = [p.strip().lstrip("/") for p in f if p.strip() and not p.startswith("#")]
    except OSError:
        paths = []
    paths += [d.lstrip("/") for d in disallow if "*" not in d and d != "/"]
    paths = sorted(set(paths))
    info(f"Probing {len(paths)} paths with {threads} threads")

    def probe_path(p):
        r = http_get(f"{base}/{p}", verify=False, timeout=6, max_bytes=200_000)
        if "error" in r:
            return None
        st = r["status"]
        if st == 404 or st >= 500:
            return None
        if soft404_len is not None and st == 200 and abs(len(r["body"]) - soft404_len) < 50:
            return None
        return {"path": "/" + p, "status": st, "size": len(r["body"]),
                "critical": any(c in p.lower() for c in CRITICAL) and st == 200}

    found = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for res in ex.map(probe_path, paths):
            if res:
                found.append(res)
                msg = f"[{res['status']}] {res['path']:35} ({res['size']} bytes)"
                if res["critical"]:
                    bad(msg + "  <-- SENSITIVE FILE EXPOSED")
                elif res["status"] == 200:
                    good(msg)
                else:
                    info(msg)
    result["found"] = found
    result["critical"] = [f["path"] for f in found if f["critical"]]
    return result
