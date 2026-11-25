"""Module 11: Wayback Machine / Archive Recon — pulls historical URLs from the
Internet Archive CDX API to discover old endpoints, parameters, and
interesting files (.php, .sql, .bak, .json, admin pages) that may still exist."""
from urllib.parse import urlparse, parse_qs
from utils import http_json, good, info, warn

NAME = "wayback"
DESCRIPTION = "Historical URLs, parameters and juicy files from archive.org"

INTERESTING_EXT = (".php", ".asp", ".aspx", ".jsp", ".json", ".xml", ".sql", ".bak",
                   ".zip", ".tar", ".gz", ".log", ".conf", ".config", ".env", ".txt", ".pdf", ".xls", ".doc")
INTERESTING_WORDS = ("admin", "login", "api", "backup", "debug", "upload", "config", "test", "dev", "token")


def run(domain, ctx):
    info("Querying Internet Archive CDX API")
    url = (f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json"
           f"&fl=original,timestamp,statuscode&collapse=urlkey&limit=5000")
    data = http_json(url, timeout=40)
    if not data or len(data) < 2:
        warn("No archived URLs found (or archive.org timed out)")
        return {"total": 0}

    rows = data[1:]
    urls = sorted({r[0] for r in rows})
    first = min(r[1] for r in rows)
    last = max(r[1] for r in rows)

    params, files, keywords = set(), [], []
    for u in urls:
        p = urlparse(u)
        params.update(parse_qs(p.query).keys())
        path = p.path.lower()
        if path.endswith(INTERESTING_EXT):
            files.append(u)
        elif any(w in path for w in INTERESTING_WORDS):
            keywords.append(u)

    good(f"Archived URLs  : {len(urls)}  (first seen {first[:4]}-{first[4:6]}, last {last[:4]}-{last[4:6]})")
    good(f"Unique params  : {len(params)}  {', '.join(sorted(params)[:15])}")
    good(f"Interesting files: {len(files)}")
    for f in files[:10]:
        good(f"   {f}")
    good(f"Sensitive-looking endpoints: {len(keywords)}")
    for k in keywords[:10]:
        good(f"   {k}")
    return {"total": len(urls), "first_seen": first, "last_seen": last,
            "parameters": sorted(params), "interesting_files": files[:200],
            "sensitive_endpoints": keywords[:200], "sample_urls": urls[:200]}
