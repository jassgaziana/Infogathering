"""Module registry — order here is the order modules run in."""
import mod_whois_lookup, mod_dns_enum, mod_subdomain_enum, mod_port_scan, mod_tech_detect, mod_ssl_check
import mod_headers_check, mod_email_harvest, mod_geoip, mod_dir_discovery, mod_wayback, mod_waf_detect

ALL_MODULES = [mod_whois_lookup, mod_dns_enum, mod_geoip, mod_subdomain_enum, mod_port_scan, mod_ssl_check,
               mod_headers_check, mod_tech_detect, mod_waf_detect, mod_dir_discovery, mod_wayback, mod_email_harvest]

REGISTRY = {m.NAME: m for m in ALL_MODULES}
