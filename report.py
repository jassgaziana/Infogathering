"""Report generation: risk-finding extraction, JSON, TXT and HTML reports."""
import html
import json
import os
from datetime import datetime

SEV_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}


def extract_findings(results):
    """Turn raw module output into a prioritised list of security findings."""
    f = []
    add = lambda sev, mod, title, detail="": f.append({"severity": sev, "module": mod, "title": title, "detail": detail})

    dns = results.get("dns", {})
    for ns, z in (dns.get("zone_transfer") or {}).items():
        if z.get("vulnerable"):
            add("High", "dns", f"DNS zone transfer allowed on {ns}", f"{len(z.get('hosts', []))} records exposed")
    es = dns.get("email_security") or {}
    if "spf" in es and not es["spf"]:
        add("Medium", "dns", "SPF record missing", "Domain can be spoofed in phishing emails")
    if "dmarc" in es and not es["dmarc"]:
        add("Medium", "dns", "DMARC record missing", "No policy for handling spoofed mail")

    for p in (results.get("ports", {}).get("open") or []):
        if p.get("risky"):
            add("High", "ports", f"Sensitive service exposed: {p['service']} ({p['port']}/tcp)", p.get("banner", ""))

    ssl_r = results.get("ssl", {})
    if ssl_r.get("trusted") is False:
        add("High", "ssl", "Untrusted TLS certificate", ssl_r.get("verify_error", ""))
    if isinstance(ssl_r.get("days_left"), int) and ssl_r["days_left"] < 30:
        add("Medium", "ssl", f"Certificate expires in {ssl_r['days_left']} days")
    for proto, on in (ssl_r.get("legacy_protocols") or {}).items():
        if on:
            add("Medium", "ssl", f"Deprecated protocol {proto} enabled")

    hdr = results.get("headers", {})
    for h in (hdr.get("missing") or {}):
        sev = "Medium" if h in ("Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options") else "Low"
        add(sev, "headers", f"Missing header: {h}", hdr["missing"][h])
    for h, v in (hdr.get("info_leaks") or {}).items():
        add("Low", "headers", f"Version disclosure via {h}", v)
    for c in (hdr.get("cookie_issues") or []):
        add("Low", "headers", f"Cookie '{c['cookie']}' missing flags", ", ".join(c["missing_flags"]))

    for path in (results.get("dirs", {}).get("critical") or []):
        add("High", "dirs", f"Sensitive file exposed: {path}")

    waf = results.get("waf", {})
    if waf and "error" not in waf and not waf.get("detected") and not waf.get("malicious_request_blocked"):
        add("Low", "waf", "No WAF detected")

    emails = results.get("osint", {}).get("emails") or []
    if emails:
        add("Info", "osint", f"{len(emails)} email addresses publicly exposed", ", ".join(emails[:5]))
    subs = results.get("subdomains", {}).get("live") or {}
    if subs:
        add("Info", "subdomains", f"{len(subs)} live subdomains discovered (attack surface)")

    f.sort(key=lambda x: SEV_ORDER[x["severity"]])
    return f


def risk_score(findings):
    w = {"High": 15, "Medium": 6, "Low": 2, "Info": 0}
    score = min(100, sum(w[x["severity"]] for x in findings))
    level = "Critical" if score >= 60 else "High" if score >= 35 else "Medium" if score >= 15 else "Low"
    return score, level


def save_json(data, path):
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2, default=str)


def save_txt(data, path):
    lines = [f"InfoGather Report — {data['meta']['target']}", "=" * 60]
    for k, v in data["meta"].items():
        lines.append(f"{k:15}: {v}")
    lines += ["", "FINDINGS", "-" * 60]
    for x in data["findings"]:
        lines.append(f"[{x['severity']:6}] ({x['module']}) {x['title']}  {x['detail']}")
    lines += ["", "RAW RESULTS", "-" * 60, json.dumps(data["results"], indent=2, default=str)]
    with open(path, "w") as fh:
        fh.write("\n".join(lines))


def _render(value, depth=0):
    """Recursively render module data as HTML tables / lists."""
    e = lambda s: html.escape(str(s))
    if isinstance(value, dict):
        if not value:
            return "<span class='muted'>none</span>"
        rows = "".join(f"<tr><th>{e(k)}</th><td>{_render(v, depth + 1)}</td></tr>" for k, v in value.items())
        return f"<table class='kv'>{rows}</table>"
    if isinstance(value, list):
        if not value:
            return "<span class='muted'>none</span>"
        if all(isinstance(i, dict) for i in value):
            keys = list(dict.fromkeys(k for i in value for k in i))
            head = "".join(f"<th>{e(k)}</th>" for k in keys)
            body = "".join("<tr>" + "".join(f"<td>{_render(i.get(k, ''), depth + 1)}</td>" for k in keys) + "</tr>" for i in value[:300])
            return f"<table class='grid'><tr>{head}</tr>{body}</table>"
        items = "".join(f"<li>{e(i)}</li>" for i in value[:300])
        more = f"<li class='muted'>... {len(value) - 300} more</li>" if len(value) > 300 else ""
        return f"<ul>{items}{more}</ul>"
    if isinstance(value, bool):
        return f"<span class='{'yes' if value else 'no'}'>{value}</span>"
    return e(value)


def save_html(data, path, descriptions):
    e = html.escape
    meta, findings = data["meta"], data["findings"]
    counts = {s: sum(1 for x in findings if x["severity"] == s) for s in SEV_ORDER}
    finding_rows = "".join(
        f"<tr><td><span class='sev {x['severity']}'>{x['severity']}</span></td><td>{e(x['module'])}</td>"
        f"<td>{e(x['title'])}</td><td>{e(x['detail'])}</td></tr>" for x in findings) or \
        "<tr><td colspan=4>No issues identified</td></tr>"
    sections = "".join(
        f"<section id='{e(name)}'><h2>{e(name.upper())} <small>{e(descriptions.get(name, ''))}</small></h2>"
        f"{_render(res)}</section>" for name, res in data["results"].items())
    nav = "".join(f"<a href='#{e(n)}'>{e(n)}</a>" for n in data["results"])

    page = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>InfoGather Report - {e(meta['target'])}</title><style>
:root{{--bg:#0f1419;--card:#1a2129;--text:#d8dee6;--muted:#7d8896;--acc:#3fb6c9;--line:#2a333d}}
*{{box-sizing:border-box}}body{{margin:0;font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text)}}
header{{padding:28px 32px;border-bottom:1px solid var(--line)}}h1{{margin:0;color:var(--acc)}}
.wrap{{max-width:1200px;margin:auto;padding:24px 32px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px}}
.card b{{display:block;font-size:24px}}.card span{{color:var(--muted);font-size:12px;text-transform:uppercase}}
nav{{margin:12px 0 24px;display:flex;flex-wrap:wrap;gap:8px}}nav a{{color:var(--acc);text-decoration:none;border:1px solid var(--line);padding:4px 10px;border-radius:14px}}
section{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px 20px;margin-bottom:18px;overflow-x:auto}}
h2{{margin:0 0 12px;font-size:17px;color:var(--acc)}}h2 small{{color:var(--muted);font-weight:400;font-size:12px}}
table{{border-collapse:collapse;width:100%}}th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}}
.kv>tbody>tr>th,.kv>tr>th{{width:200px;color:var(--muted);font-weight:500}}.grid th{{color:var(--muted)}}
ul{{margin:0;padding-left:18px}}.muted{{color:var(--muted)}}.yes{{color:#e8a33d}}.no{{color:#5fbf7a}}
.sev{{padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600}}
.High{{background:#5c1d1d;color:#ff8a8a}}.Medium{{background:#5a4314;color:#ffc861}}.Low{{background:#1d3a5c;color:#8cc3ff}}.Info{{background:#2a333d;color:#c0c8d2}}
footer{{color:var(--muted);text-align:center;padding:20px;font-size:12px}}
</style></head><body>
<header><h1>InfoGather Reconnaissance Report</h1>
<div class="muted">Target: <b>{e(meta['target'])}</b> ({e(meta.get('ip') or 'unresolved')}) &middot; {e(meta['started'])} &middot; Duration {e(meta['duration'])}</div></header>
<div class="wrap">
<div class="cards">
<div class="card"><span>Risk score</span><b>{meta['risk_score']}/100</b>{e(meta['risk_level'])}</div>
<div class="card"><span>High</span><b style="color:#ff8a8a">{counts['High']}</b></div>
<div class="card"><span>Medium</span><b style="color:#ffc861">{counts['Medium']}</b></div>
<div class="card"><span>Low</span><b style="color:#8cc3ff">{counts['Low']}</b></div>
<div class="card"><span>Modules run</span><b>{len(data['results'])}</b></div></div>
<section><h2>Key Findings</h2><table class="grid"><tr><th>Severity</th><th>Module</th><th>Finding</th><th>Detail</th></tr>{finding_rows}</table></section>
<nav>{nav}</nav>{sections}</div>
<footer>Generated by InfoGather v{e(meta['version'])} &middot; For authorised security assessment only</footer>
</body></html>"""
    with open(path, "w") as fh:
        fh.write(page)


def generate(data, out_dir, fmt, descriptions):
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.join(out_dir, f"{data['meta']['target'].replace('.', '_')}_{stamp}")
    paths = []
    if fmt in ("json", "all"):
        save_json(data, base + ".json"); paths.append(base + ".json")
    if fmt in ("txt", "all"):
        save_txt(data, base + ".txt"); paths.append(base + ".txt")
    if fmt in ("html", "all"):
        save_html(data, base + ".html", descriptions); paths.append(base + ".html")
    return paths
