# InfoGather: Modular Information Gathering Framework

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?logo=kalilinux&logoColor=white)
![Modules](https://img.shields.io/badge/Modules-12-success)
![License](https://img.shields.io/badge/License-MIT-yellow)

**MCA (Cyber Security & Forensics) Project**
Developed by: Jaskaran Singh (Roll No. 72519736)

InfoGather is a Python-based reconnaissance framework that combines **12 information-gathering modules** into one command-line tool. For a target domain, it collects WHOIS, DNS, network, web, TLS and OSINT intelligence, maps each result to a security finding with a severity, calculates an overall risk score, and writes a consolidated **HTML / JSON / TXT report**.

> ⚠️ **Legal notice:** Use this only on domains you own or have written permission to test. Unauthorised scanning may be an offence under the IT Act, 2000 (Sections 43 and 66) and similar laws. The tool asks you to confirm authorisation before every scan.

---

## 1. Features (12 integrated modules)

| # | Module | Type | What it does |
|---|--------|------|--------------|
| 1 | `whois` | Passive | Raw WHOIS over TCP/43. Gets the registrar, creation/expiry dates, name servers, status and DNSSEC. |
| 2 | `dns` | Passive + Active | A, AAAA, MX, NS, TXT, SOA, CNAME and CAA records. Checks SPF/DMARC (email spoofing) and tests **zone transfer (AXFR)**. |
| 3 | `geoip` | Passive | IP geolocation, ISP, ASN, reverse DNS, and hosting/proxy detection. |
| 4 | `subdomains` | Passive + Active | Certificate Transparency (crt.sh), the HackerTarget API, and multithreaded wordlist brute-force with wildcard-DNS filtering. |
| 5 | `ports` | Active | Multithreaded TCP connect scan with banner grabbing. Flags risky exposed services (DB, RDP, SMB...). Optional `nmap -sV`. |
| 6 | `ssl` | Passive | Certificate issuer, validity, days to expiry, SAN list, protocol, cipher, and **TLS 1.0/1.1 support**. |
| 7 | `headers` | Passive | Audits 8 security headers, version-disclosure headers and cookie flags (Secure/HttpOnly/SameSite), then gives an A–F grade. |
| 8 | `tech` | Passive | Fingerprints the CMS, frameworks, languages, JS libraries, analytics and CDN (25+ signatures). |
| 9 | `waf` | Passive + Active | Detects WAFs and CDNs (Cloudflare, Akamai, Imperva, AWS, ModSecurity...) from signatures and how the site responds to a test payload. |
| 10 | `dirs` | Passive + Active | Parses robots.txt and sitemap.xml, brute-forces paths, detects soft-404 pages and flags exposed `.git`, `.env` and backups. |
| 11 | `wayback` | Passive | Pulls historical URLs from archive.org. Extracts parameters, interesting files and sensitive endpoints. |
| 12 | `osint` | Passive | Crawls the site to collect emails, phone numbers and social media profiles (social engineering surface). |

**Framework-level features**
- One CLI with module selection, a **passive mode**, thread control and a custom port range.
- An interactive menu when run with no arguments.
- An automatic **findings engine** (High/Medium/Low/Info) and a **risk score from 0 to 100**.
- Reports in HTML (a dark-theme dashboard), JSON (machine-readable) and TXT.
- Fault isolation: if one module crashes, the rest of the scan keeps running.
- The core needs only the Python standard library. `dnspython` and `python-nmap` are optional add-ons.
- An installer that makes it a Kali Linux command (`infogather`).

---

## 2. System architecture

```
                 ┌─────────────────────────────┐
  User (CLI) ──► │ infogather.py               │  argument parsing, validation,
                 │  (controller / orchestrator)│  authorisation prompt, scheduling
                 └──────────────┬──────────────┘
                                │ shared context {args, ip, base_url, results}
        ┌───────────┬───────────┼───────────┬────────────┬───────────┐
        ▼           ▼           ▼           ▼            ▼           ▼
     whois  dns  geoip  subdomains  ports  ssl  headers  tech  waf  dirs  wayback  osint
        │  (each module exposes NAME, DESCRIPTION, run(domain, ctx) -> dict)
        └───────────────────────────┬───────────────────────────────────┘
                                    ▼
                 ┌─────────────────────────────┐
                 │ core/report.py              │  findings engine → risk score →
                 │                             │  HTML / JSON / TXT reports
                 └─────────────────────────────┘
```

**Project structure**
```
InfoGather/
├── infogather.py              # main entry point / orchestrator
├── registry.py                # list of modules and run order
├── utils.py                   # HTTP client, DNS resolve, colored output, validation
├── banner.py                  # ASCII banner, version
├── report.py                  # findings engine, risk scoring, report writers
├── mod_whois_lookup.py        # 1  WHOIS
├── mod_dns_enum.py            # 2  DNS + SPF/DMARC + AXFR
├── mod_geoip.py               # 3  IP geolocation / ASN
├── mod_subdomain_enum.py      # 4  subdomain discovery
├── mod_port_scan.py           # 5  port scan + banners
├── mod_ssl_check.py           # 6  TLS certificate analysis
├── mod_headers_check.py       # 7  security headers
├── mod_tech_detect.py         # 8  technology fingerprinting
├── mod_waf_detect.py          # 9  WAF / CDN detection
├── mod_dir_discovery.py       # 10 sensitive paths
├── mod_wayback.py             # 11 archive.org recon
├── mod_email_harvest.py       # 12 OSINT crawler
├── wordlist_subdomains.txt
├── wordlist_directories.txt
├── sample_report.html         # example HTML report
├── requirements.txt
└── install.sh                 # Kali/Debian installer
```

**Adding a new module:** create `mod_mymodule.py` with `NAME`, `DESCRIPTION` and `run(domain, ctx)`, then add it to `ALL_MODULES` in `registry.py`.

---

## 3. Installation

```bash
# Option A: run directly (Python 3.8+)
git clone https://github.com/<your-username>/InfoGather.git
cd InfoGather
pip3 install -r requirements.txt        # optional extras
python3 infogather.py -h

# Option B: install as a Kali Linux tool
git clone https://github.com/<your-username>/InfoGather.git
cd InfoGather
sudo ./install.sh
infogather -d example.com --all
```

## 4. Usage

```bash
infogather --list                                   # list modules
infogather                                          # interactive menu
infogather -d example.com --all                     # full scan, all reports
infogather -d example.com --all --passive           # no intrusive checks
infogather -d example.com -m whois,dns,ssl,headers  # chosen modules
infogather -d example.com -m ports -p 1-1024 --nmap -t 100
infogather -d example.com --all -o html --out-dir results/
```

| Option | Meaning |
|--------|---------|
| `-d, --domain` | Target domain (URLs are cleaned automatically) |
| `-m, --modules` | Comma-separated module list |
| `-a, --all` | Run all modules |
| `--passive` | Skip port scan, brute-force, AXFR and attack-pattern probes |
| `-p, --ports` | `top` (default), `1-1024`, or `22,80,443` |
| `--nmap` | Service version detection with python-nmap |
| `-t, --threads` | Thread count (default 30) |
| `--crawl-pages` | Page limit for the OSINT crawler (default 25) |
| `-o, --output` | `html`, `json`, `txt`, `all` or `none` |
| `-y, --yes` | Skip the authorisation prompt |

---

## 5. Risk scoring

| Severity | Weight | Examples |
|----------|--------|----------|
| High | 15 | Zone transfer allowed, exposed `.git`/`.env`, public DB/RDP port, untrusted certificate |
| Medium | 6 | Missing SPF/DMARC/CSP/HSTS, TLS 1.0 enabled, certificate expiring soon |
| Low | 2 | Version disclosure, insecure cookie flags, no WAF |
| Info | 0 | Live subdomains, public emails |

Score = sum of weights, capped at 100. Levels: **0–14 Low · 15–34 Medium · 35–59 High · 60+ Critical**.

---

## 6. Technologies used
- **Language:** Python 3 (socket, ssl, urllib, concurrent.futures, argparse, re, json)
- **Optional libraries:** dnspython, python-nmap
- **Data sources:** WHOIS servers (IANA), crt.sh, HackerTarget, ip-api.com, Internet Archive CDX API
- **Platform:** Kali Linux / any Linux, Windows or macOS with Python 3.8+

## 7. Safe practice targets
- Your own domain or a local lab (DVWA, Metasploitable, OWASP Juice Shop)
- `scanme.nmap.org` (Nmap's official practice host, for port scanning only)
- `testphp.vulnweb.com` (Acunetix test site)

## 8. Sample report
Open [`sample_report.html`](sample_report.html) in a browser to see the HTML dashboard.

## 9. Future scope
- Shodan / VirusTotal / SecurityTrails API integration
- Screenshots of live subdomains
- CVE lookup for detected software versions
- Web GUI (Flask) and scheduled scans
- PDF report export

## License
Released under the [MIT License](LICENSE). For educational and authorised testing only.
