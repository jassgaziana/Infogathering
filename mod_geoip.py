"""Module 9: IP Geolocation, ASN & Reverse DNS — finds hosting provider,
country/city, ASN, reverse DNS (PTR) and whether the IP is behind a
proxy/hosting network. Uses the free ip-api.com service."""
import socket
from utils import http_json, good, warn

NAME = "geoip"
DESCRIPTION = "IP geolocation, ASN, ISP/hosting provider and reverse DNS"

FIELDS = "status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,proxy,hosting"


def run(domain, ctx):
    try:
        ips = sorted({ai[4][0] for ai in socket.getaddrinfo(domain, None, socket.AF_INET)})
    except socket.gaierror as e:
        warn(f"Could not resolve: {e}")
        return {"error": str(e)}

    out = {}
    for ip in ips[:5]:
        data = http_json(f"http://ip-api.com/json/{ip}?fields={FIELDS}") or {}
        try:
            ptr = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            ptr = None
        if data.get("status") != "success":
            warn(f"{ip}: geolocation lookup failed")
            out[ip] = {"reverse_dns": ptr}
            continue
        data.pop("status", None)
        data["reverse_dns"] = ptr
        out[ip] = data
        good(f"IP        : {ip}")
        good(f"Location  : {data.get('city')}, {data.get('regionName')}, {data.get('country')}  ({data.get('lat')}, {data.get('lon')})")
        good(f"ISP / Org : {data.get('isp')} / {data.get('org')}")
        good(f"ASN       : {data.get('as')}")
        good(f"PTR       : {ptr}")
        good(f"Hosting   : {data.get('hosting')}   Proxy/VPN: {data.get('proxy')}")
    return out
