"""Module 12: WAF / CDN Detection — sends a normal request and a harmless
"attack-looking" request (XSS/SQLi pattern in a query string) and compares
responses, headers and cookies against known WAF signatures."""
import re
from utils import http_get, good, warn, info

NAME = "waf"
DESCRIPTION = "Web Application Firewall / CDN detection"

WAF_SIGNATURES = {
    "Cloudflare": r"cf-ray|__cfduid|cf_clearance|cloudflare",
    "AWS WAF / CloudFront": r"x-amz-cf-id|awselb|x-amzn-requestid|cloudfront",
    "Akamai": r"akamai|x-akamai|ak_bmsc",
    "Imperva Incapsula": r"incap_ses|visid_incap|x-iinfo|incapsula",
    "Sucuri": r"x-sucuri|sucuri",
    "F5 BIG-IP ASM": r"bigipserver|x-wa-info|ts[0-9a-f]{6,}=",
    "Barracuda": r"barra_counter_session|barracuda",
    "ModSecurity": r"mod_security|modsecurity|not acceptable",
    "Fastly": r"x-fastly|fastly",
    "Azure Front Door": r"x-azure-ref|azurefd",
    "Wordfence": r"wordfence|wfvt_",
    "StackPath": r"x-sp-|stackpath",
}
TEST_PAYLOAD = "/?id=1%27%20OR%20%271%27=%271&q=%3Cscript%3Ealert(1)%3C/script%3E"


def _blob(r):
    return "\n".join(f"{k}: {v}" for k, v in r.get("headers", {}).items()).lower() + "\n" + r.get("body", "")[:5000].lower()


def run(domain, ctx):
    base = ctx.get("base_url", f"https://{domain}")
    normal = http_get(base, verify=False)
    if "error" in normal:
        warn(f"Could not reach {base}")
        return {"error": normal["error"]}

    detected = {n for n, pat in WAF_SIGNATURES.items() if re.search(pat, _blob(normal), re.I)}

    blocked = False
    if not (ctx.get("args") and ctx["args"].passive):
        info("Sending benign attack-pattern request to observe filtering behaviour")
        attack = http_get(base + TEST_PAYLOAD, verify=False)
        if "error" not in attack:
            detected |= {n for n, pat in WAF_SIGNATURES.items() if re.search(pat, _blob(attack), re.I)}
            if attack["status"] in (403, 406, 429, 501, 503) and normal["status"] != attack["status"]:
                blocked = True
        else:
            blocked = True  # connection reset on malicious payload is a WAF hint

    if detected:
        for w in sorted(detected):
            good(f"WAF/CDN detected: {w}")
    elif blocked:
        good("Generic WAF detected (malicious request blocked, vendor unknown)")
    else:
        warn("No WAF detected — application may be directly exposed")
    return {"detected": sorted(detected), "malicious_request_blocked": blocked}
