#!/usr/bin/env python3
"""
InfoGather — Modular Information Gathering Framework
MCA (Cyber Security & Forensics) Project

Usage examples:
    python3 infogather.py -d example.com --all
    python3 infogather.py -d example.com -m whois,dns,ssl,headers
    python3 infogather.py -d example.com --all --passive -o html
    python3 infogather.py --list

LEGAL: Run only against domains you own or have written permission to test.
"""
import argparse
import sys
import time
from datetime import datetime

import banner
import report
from utils import (C, clean_domain, is_valid_domain, resolve, base_url,
                        info, good, warn, bad, section)
from registry import ALL_MODULES, REGISTRY

PASSIVE_SAFE = {"whois", "dns", "geoip", "subdomains", "ssl", "headers", "tech", "wayback", "osint", "waf", "dirs"}


def parse_args():
    p = argparse.ArgumentParser(
        prog="infogather",
        description="InfoGather - modular reconnaissance / information gathering framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Modules: " + ", ".join(REGISTRY))
    p.add_argument("-d", "--domain", help="target domain (e.g. example.com)")
    p.add_argument("-m", "--modules", help="comma-separated modules to run")
    p.add_argument("-a", "--all", action="store_true", help="run all modules")
    p.add_argument("--passive", action="store_true",
                   help="passive mode: no port scan, brute-force, AXFR or attack-pattern requests")
    p.add_argument("-p", "--ports", default="top", help="ports: 'top' | '1-1024' | '22,80,443' (default top)")
    p.add_argument("--nmap", action="store_true", help="use python-nmap for service version detection")
    p.add_argument("-t", "--threads", type=int, default=30, help="threads for scanning (default 30)")
    p.add_argument("--crawl-pages", type=int, default=25, help="max pages for OSINT crawler (default 25)")
    p.add_argument("-o", "--output", choices=["html", "json", "txt", "all", "none"], default="all",
                   help="report format (default all)")
    p.add_argument("--out-dir", default="reports", help="report directory (default ./reports)")
    p.add_argument("-l", "--list", action="store_true", help="list available modules and exit")
    p.add_argument("-y", "--yes", action="store_true", help="skip the authorisation confirmation")
    return p.parse_args()


def list_modules():
    print(f"\n{C.BOLD}{'#':<4}{'Module':<12}Description{C.END}")
    for i, m in enumerate(ALL_MODULES, 1):
        print(f"{i:<4}{C.G}{m.NAME:<12}{C.END}{m.DESCRIPTION}")
    print()


def interactive_menu():
    """Menu shown when the tool is run without arguments."""
    list_modules()
    domain = input(f"{C.CY}Target domain: {C.END}").strip()
    choice = input(f"{C.CY}Modules (numbers/names comma-separated, or 'all') [all]: {C.END}").strip() or "all"
    if choice.lower() == "all":
        mods = [m.NAME for m in ALL_MODULES]
    else:
        mods = []
        for c in choice.split(","):
            c = c.strip()
            if c.isdigit() and 1 <= int(c) <= len(ALL_MODULES):
                mods.append(ALL_MODULES[int(c) - 1].NAME)
            elif c in REGISTRY:
                mods.append(c)
    return domain, mods


def main():
    args = parse_args()
    banner.show()

    if args.list:
        list_modules()
        return

    if args.domain:
        domain = args.domain
        if args.all or not args.modules:
            selected = [m.NAME for m in ALL_MODULES]
        else:
            selected = [m.strip() for m in args.modules.split(",")]
    else:
        domain, selected = interactive_menu()

    domain = clean_domain(domain)
    if not is_valid_domain(domain):
        bad(f"Invalid domain: {domain}")
        sys.exit(1)
    unknown = [m for m in selected if m not in REGISTRY]
    if unknown:
        bad(f"Unknown module(s): {', '.join(unknown)}  (use --list)")
        sys.exit(1)
    if args.passive:
        skipped = [m for m in selected if m not in PASSIVE_SAFE]
        if skipped:
            warn(f"Passive mode — skipping active module(s): {', '.join(skipped)}")
        selected = [m for m in selected if m in PASSIVE_SAFE]

    if not args.yes:
        ans = input(f"{C.Y}[?] Do you own or have permission to test '{domain}'? (y/N): {C.END}")
        if ans.strip().lower() != "y":
            bad("Authorisation not confirmed. Exiting.")
            sys.exit(0)

    start = time.time()
    info(f"Target      : {domain}")
    ip = resolve(domain)
    if ip:
        good(f"Resolved IP : {ip}")
    else:
        warn("Domain does not resolve — network modules may fail")
    url = base_url(domain) if ip else f"https://{domain}"
    info(f"Base URL    : {url}")
    info(f"Modules     : {', '.join(selected)}")

    ctx = {"args": args, "ip": ip, "base_url": url, "results": {}}
    order = [m.NAME for m in ALL_MODULES if m.NAME in selected]

    for name in order:
        mod = REGISTRY[name]
        section(f"[{order.index(name) + 1}/{len(order)}] {mod.NAME.upper()} — {mod.DESCRIPTION}")
        t0 = time.time()
        try:
            ctx["results"][name] = mod.run(domain, ctx)
        except KeyboardInterrupt:
            warn("Module interrupted by user — continuing")
            ctx["results"][name] = {"error": "interrupted"}
        except Exception as e:  # one failing module must not stop the framework
            bad(f"Module crashed: {e}")
            ctx["results"][name] = {"error": str(e)}
        info(f"Finished in {time.time() - t0:.1f}s")

    findings = report.extract_findings(ctx["results"])
    score, level = report.risk_score(findings)
    duration = f"{time.time() - start:.1f}s"

    section("SUMMARY")
    colors = {"High": C.R, "Medium": C.Y, "Low": C.B, "Info": C.W}
    for f in findings:
        print(f"  {colors[f['severity']]}[{f['severity']:6}]{C.END} ({f['module']}) {f['title']}")
    if not findings:
        good("No issues identified")
    print(f"\n  {C.BOLD}Overall risk score: {score}/100 ({level}){C.END}   Duration: {duration}")

    if args.output != "none":
        data = {"meta": {"target": domain, "ip": ip, "base_url": url,
                         "started": datetime.fromtimestamp(start).strftime("%Y-%m-%d %H:%M:%S"),
                         "duration": duration, "modules": order, "passive": args.passive,
                         "risk_score": score, "risk_level": level, "version": banner.VERSION},
                "findings": findings, "results": ctx["results"]}
        descriptions = {m.NAME: m.DESCRIPTION for m in ALL_MODULES}
        for path in report.generate(data, args.out_dir, args.output, descriptions):
            good(f"Report saved: {path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.R}[-] Aborted by user{C.END}")
        sys.exit(130)
