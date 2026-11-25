"""Module 7: HTTP Security Header Audit — checks for missing security headers,
information-leaking headers, insecure cookies and gives a letter grade."""
from utils import http_get, good, warn, bad

NAME = "headers"
DESCRIPTION = "Security header audit, cookie flags and grading"

SECURITY_HEADERS = {
    "Strict-Transport-Security": (20, "Forces HTTPS; prevents SSL-stripping"),
    "Content-Security-Policy": (25, "Mitigates XSS and data injection"),
    "X-Frame-Options": (15, "Prevents clickjacking"),
    "X-Content-Type-Options": (10, "Stops MIME-type sniffing"),
    "Referrer-Policy": (10, "Limits referrer leakage"),
    "Permissions-Policy": (10, "Restricts browser features (camera, mic...)"),
    "Cross-Origin-Opener-Policy": (5, "Isolates browsing context"),
    "Cross-Origin-Resource-Policy": (5, "Controls cross-origin resource loading"),
}
LEAKY = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"]


def _grade(score):
    for limit, g in ((90, "A"), (75, "B"), (55, "C"), (35, "D"), (15, "E")):
        if score >= limit:
            return g
    return "F"


def run(domain, ctx):
    url = ctx.get("base_url", f"https://{domain}")
    r = http_get(url, verify=False)
    if "error" in r:
        warn(f"Could not fetch {url}: {r['error']}")
        return {"error": r["error"]}
    headers = {k.lower(): v for k, v in r["headers"].items()}

    present, missing, score = {}, {}, 0
    for h, (weight, why) in SECURITY_HEADERS.items():
        if h.lower() in headers:
            present[h] = headers[h.lower()]
            score += weight
            good(f"{h:30} present")
        else:
            missing[h] = why
            bad(f"{h:30} MISSING  - {why}")
    if url.startswith("http://"):
        warn("Site served over plain HTTP")
        score = max(0, score - 20)

    leaks = {h: headers[h.lower()] for h in LEAKY if h.lower() in headers}
    for h, v in leaks.items():
        warn(f"Information leak: {h}: {v}")

    cookie_issues = []
    raw_cookies = r["headers"].get("Set-Cookie", "")
    if raw_cookies:
        for c in raw_cookies.split(", "):
            if "=" not in c.split(";")[0]:
                continue
            name = c.split("=")[0].strip()
            lc = c.lower()
            miss = [f for f in ("secure", "httponly", "samesite") if f not in lc]
            if miss:
                cookie_issues.append({"cookie": name, "missing_flags": miss})
                warn(f"Cookie '{name}' missing: {', '.join(miss)}")

    grade = _grade(score)
    (good if grade in "AB" else warn)(f"Security header score: {score}/100  Grade: {grade}")
    return {"url": url, "score": score, "grade": grade, "present": present,
            "missing": missing, "info_leaks": leaks, "cookie_issues": cookie_issues}
