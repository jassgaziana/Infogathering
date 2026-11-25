"""Module 5: Web Technology Fingerprinting — identifies server, CMS, frameworks,
JS libraries, analytics and CDN from headers, cookies and HTML signatures
(similar idea to WhatWeb / Wappalyzer)."""
import re
from utils import http_get, good, warn

NAME = "tech"
DESCRIPTION = "Web server, CMS, framework and library fingerprinting"

# (category, name, where, regex)
SIGNATURES = [
    ("CMS", "WordPress", "body", r"wp-content|wp-includes"),
    ("CMS", "Joomla", "body", r"/media/jui/|Joomla!"),
    ("CMS", "Drupal", "body", r"Drupal\.settings|/sites/default/files"),
    ("CMS", "Shopify", "body", r"cdn\.shopify\.com"),
    ("CMS", "Wix", "body", r"static\.wixstatic\.com"),
    ("CMS", "Magento", "body", r"Mage\.Cookies|/static/frontend/"),
    ("Framework", "Laravel", "cookie", r"laravel_session"),
    ("Framework", "Django", "cookie", r"csrftoken|django"),
    ("Framework", "ASP.NET", "header", r"X-AspNet-Version|ASP\.NET"),
    ("Framework", "Express.js", "header", r"Express"),
    ("Framework", "Next.js", "body", r"__NEXT_DATA__|/_next/static"),
    ("Framework", "Nuxt.js", "body", r"__NUXT__|/_nuxt/"),
    ("Framework", "Angular", "body", r"ng-version=|ng-app"),
    ("Framework", "React", "body", r"data-reactroot|react(?:\.production)?\.min\.js"),
    ("Framework", "Vue.js", "body", r"vue(?:\.min)?\.js|data-v-[0-9a-f]{8}"),
    ("Language", "PHP", "header", r"PHP/[\d.]+|PHPSESSID"),
    ("Language", "Java", "cookie", r"JSESSIONID"),
    ("JS Library", "jQuery", "body", r"jquery[.-]?([\d.]+)?(?:\.min)?\.js"),
    ("JS Library", "Bootstrap", "body", r"bootstrap(?:\.min)?\.(?:css|js)"),
    ("Analytics", "Google Analytics", "body", r"googletagmanager\.com|google-analytics\.com"),
    ("Analytics", "Facebook Pixel", "body", r"connect\.facebook\.net"),
    ("CDN", "Cloudflare", "header", r"cloudflare|cf-ray"),
    ("CDN", "Akamai", "header", r"akamai"),
    ("CDN", "Amazon CloudFront", "header", r"cloudfront"),
    ("CDN", "Fastly", "header", r"fastly"),
    ("Security", "reCAPTCHA", "body", r"google\.com/recaptcha"),
]


def run(domain, ctx):
    url = ctx.get("base_url", f"https://{domain}")
    r = http_get(url, verify=False)
    if "error" in r:
        warn(f"Could not fetch {url}: {r['error']}")
        return {"error": r["error"]}

    headers = r["headers"]
    header_blob = "\n".join(f"{k}: {v}" for k, v in headers.items())
    cookie_blob = headers.get("Set-Cookie", "")
    body = r["body"]
    sources = {"header": header_blob, "cookie": cookie_blob, "body": body}

    found = {}
    for cat, name, where, pat in SIGNATURES:
        m = re.search(pat, sources[where], re.I)
        if m:
            label = name + (f" {m.group(1)}" if m.lastindex and m.group(1) else "")
            found.setdefault(cat, []).append(label)

    result = {"url": r["url"], "status": r["status"], "technologies": found}
    for h in ("Server", "X-Powered-By", "X-Generator", "Via"):
        if h in headers:
            result[h.lower()] = headers[h]
            good(f"{h:14}: {headers[h]}")

    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if gen:
        result["meta_generator"] = gen.group(1)
        good(f"{'Generator':14}: {gen.group(1)}")
    title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if title:
        result["title"] = title.group(1).strip()[:120]
        good(f"{'Page title':14}: {result['title']}")

    for cat, names in found.items():
        good(f"{cat:14}: {', '.join(sorted(set(names)))}")
    if not found:
        warn("No known technology signatures matched")
    return result
