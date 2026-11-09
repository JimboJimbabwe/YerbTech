#!/usr/bin/env python3
"""
WSTG-CONF-09 — File Permission Testing: Log Path Wordlist Generator
(svc_recon component only — service disseminator handled separately)

Reads Burp Suite XML + services JSON, matches detected services,
then filters all endpoints to those containing log-file/log-directory
strings. Augments with a hardcoded list of common log paths.

Usage:
  python3 conf09_logs.py -x burp.xml -j services.json -w wordlists/logs.txt
"""

import argparse
import xml.etree.ElementTree as ET
import base64
import sys
import os
import json
import re
from collections import defaultdict


# ---------------------------------------------------------------------------
# Log keyword patterns
# Keywords that indicate a path is log-related
# ---------------------------------------------------------------------------

LOG_KEYWORDS = [
    # Generic log terms
    'log', 'logs', 'logging',
    # Common log file names / extensions
    'error.log', 'access.log', 'debug.log', 'system.log',
    'error_log', 'access_log', 'audit.log', 'audit_log',
    # Log directories
    '/log/', '/logs/', '/var/log', '/var/logs',
    # Application-specific
    'application.log', 'app.log', 'server.log',
    'catalina.out', 'catalina.log',   # Tomcat
    'php_errors', 'php-errors',
    'mysql.log', 'mysql_error',
    'nginx_error', 'nginx_access',
    'apache_error', 'apache_access',
    'event.log', 'events.log',
    'trace.log', 'trace_log',
    'diagnostic', 'diagnostics',
    'stacktrace', 'stack_trace',
]

# Compiled as a single OR pattern for speed
_LOG_RE = re.compile(
    '|'.join(re.escape(kw) for kw in LOG_KEYWORDS),
    re.IGNORECASE,
)


def _is_log_path(path: str) -> bool:
    return bool(_LOG_RE.search(path))


# ---------------------------------------------------------------------------
# Hardcoded log paths (augments JSON)
# Common locations across Linux/Windows app stacks
# ---------------------------------------------------------------------------

HARDCODED_LOG_PATHS = [
    # Web server logs (Linux paths — useful for path traversal context)
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/apache/access.log",
    "/var/log/apache/error.log",
    "/var/log/httpd/access_log",
    "/var/log/httpd/error_log",
    # App server logs
    "/var/log/tomcat/catalina.out",
    "/var/log/tomcat8/catalina.out",
    "/var/log/tomcat9/catalina.out",
    "/opt/tomcat/logs/catalina.out",
    # PHP
    "/var/log/php_errors.log",
    "/var/log/php-fpm/error.log",
    "/var/log/php/error.log",
    # MySQL / MariaDB
    "/var/log/mysql/error.log",
    "/var/log/mysql/mysql.log",
    "/var/log/mariadb/mariadb.log",
    # System logs
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/auth.log",
    "/var/log/kern.log",
    "/var/log/dmesg",
    "/var/log/boot.log",
    "/var/log/cron.log",
    "/var/log/mail.log",
    # Web-accessible log paths (endpoints that may directly serve logs)
    "/logs/",
    "/log/",
    "/error.log",
    "/access.log",
    "/debug.log",
    "/application.log",
    "/app.log",
    "/server.log",
    "/error_log",
    "/access_log",
    "/logs/error.log",
    "/logs/access.log",
    "/logs/debug.log",
    "/logs/application.log",
    "/logs/app.log",
    "/admin/logs/",
    "/admin/log/",
    # IIS / Windows
    "/iislog/",
    "/logfiles/",
    "/W3SVC/",
    # Application-level diagnostic endpoints
    "/diagnostics",
    "/diagnostic",
    "/trace.log",
    "/trace",
    "/stacktrace",
    # Framework-specific
    "/storage/logs/laravel.log",       # Laravel
    "/storage/logs/",                   # Laravel general
    "/log/production.log",             # Rails
    "/log/development.log",            # Rails
    "/log/test.log",                   # Rails
    "/tmp/app.log",
    "/tmp/error.log",
    # Audit logs
    "/audit.log",
    "/audit_log",
    "/logs/audit.log",
    "/var/log/audit/audit.log",        # Linux auditd
    # Event logs
    "/events.log",
    "/event.log",
    "/logs/events.log",
    # Catalina (Tomcat)
    "/catalina.out",
    "/logs/catalina.out",
    "/catalina.log",
]


# ---------------------------------------------------------------------------
# Burp XML helpers (consistent with other CONF scripts)
# ---------------------------------------------------------------------------

TARGET_HEADERS = [
    'server', 'x-powered-by', 'x-aspnet-version', 'x-generator',
    'x-drupal-cache', 'x-varnish', 'x-cache', 'x-served-by',
    'x-runtime', 'x-frame-options', 'x-content-type-options',
    'x-xss-protection', 'x-pingback', 'link', 'via', 'x-forwarded-server',
    'x-proxy', 'x-load-balancer', 'x-application-context', 'x-version',
    'x-service', 'x-application', 'x-technology', 'x-framework',
    'x-cms', 'x-webserver', 'x-backend', 'x-frontend', 'x-middleware',
]

HEADER_NAME_INDICATORS = [
    'x-drupal-cache', 'x-varnish', 'x-cache', 'x-served-by',
    'x-pingback', 'x-generator', 'x-powered-by', 'x-aspnet-version',
    'x-runtime', 'x-application-context', 'x-version', 'x-service',
    'x-application', 'x-technology', 'x-framework', 'x-cms',
    'x-webserver', 'x-backend', 'x-frontend', 'x-middleware',
]

IGNORE_WORDS = {'server', 'service', 'http', 'https', 'ssl', 'tls', 'web', 'application', 'api'}


def decode_element(elem) -> str:
    if elem is None:
        return ""
    raw = elem.text or ""
    if elem.attrib.get("base64", "false").lower() == "true":
        try:
            return base64.b64decode(raw).decode("utf-8", errors="replace")
        except Exception:
            return raw
    return raw


def parse_burp_xml(xml_path: str):
    try:
        tree = ET.parse(xml_path)
    except FileNotFoundError:
        print(f"[!] XML not found: {xml_path}")
        sys.exit(1)
    except ET.ParseError as e:
        print(f"[!] XML parse error: {e}")
        sys.exit(1)
    items = tree.getroot().findall('.//item')
    if not items:
        print("[!] No <item> elements found in XML.")
        sys.exit(1)
    return items


def extract_headers_from_response(response_text: str):
    lines = response_text.split('\r\n')
    headers = []
    for line in lines[1:]:
        if not line or line.isspace():
            break
        parts = line.split(':', 1)
        if len(parts) == 2:
            headers.append((parts[0].strip(), parts[1].strip()))
    return headers


def collect_server_info(items) -> list:
    seen = set()
    result = []
    for item in items:
        resp_text = decode_element(item.find('./response'))
        if not resp_text:
            continue
        headers = extract_headers_from_response(resp_text)
        for name, value in headers:
            if any(t in name.lower() for t in TARGET_HEADERS):
                line = f"{name}: {value}"
                if line not in seen:
                    seen.add(line)
                    result.append(line)
    return result


# ---------------------------------------------------------------------------
# Service matching
# ---------------------------------------------------------------------------

def normalize(text: str) -> str:
    return re.sub(r'[^a-zA-Z0-9\s]', '', text.lower())


def service_keywords(service_name: str) -> list:
    words = re.findall(r'\b\w+\b', service_name.lower())
    return [w for w in words if len(w) > 2 and w not in IGNORE_WORDS]


def should_match_name(header_name: str) -> bool:
    return any(ind in header_name for ind in HEADER_NAME_INDICATORS)


def extract_header_parts(line: str):
    if ':' in line:
        parts = line.split(':', 1)
        return parts[0].strip().lower(), parts[1].strip()
    return None, line


def match_services(server_info_lines: list, services_data: dict):
    all_endpoints = []
    matched_names = set()

    for line in server_info_lines:
        header_name, header_value = extract_header_parts(line)
        if header_name == 'server':
            match_text = header_value
        elif header_name and should_match_name(header_name):
            match_text = header_name
        else:
            match_text = line

        norm = normalize(match_text)

        for port_info in services_data.get('Ports', []):
            for svc in port_info.get('PotentialServices', []):
                svc_name = svc.get('Service', '')
                found = False

                if svc_name.lower() in match_text.lower():
                    found = True
                if not found:
                    for kw in service_keywords(svc_name):
                        if kw in norm:
                            found = True
                            break
                if not found:
                    for word in re.findall(r'\b\w+\b', norm):
                        if len(word) > 2 and word in normalize(svc_name):
                            found = True
                            break

                if found and svc_name not in matched_names:
                    matched_names.add(svc_name)
                    for ep in svc.get('CommonEndpoints', []):
                        all_endpoints.append((svc_name, ep))
                    for ep in svc.get('UndesirableEndpoints', []):
                        all_endpoints.append((svc_name, ep))

    return all_endpoints, matched_names


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description='CONF-09: Generate log path wordlist from Burp XML + services JSON'
    )
    p.add_argument('-x', '--xml',      required=True, help='Burp Suite XML export')
    p.add_argument('-j', '--json',     required=True, help='Services JSON file')
    p.add_argument('-w', '--wordlist', required=True, help='Output wordlist path (.txt)')
    p.add_argument('-p', '--profile',  default='Profile', help='Profile directory for raw.txt (default: Profile)')
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    try:
        with open(args.json) as f:
            services_data = json.load(f)
    except FileNotFoundError:
        print(f"[!] Services JSON not found: {args.json}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] Invalid services JSON: {e}")
        sys.exit(1)

    total_svcs = sum(len(p.get('PotentialServices', [])) for p in services_data.get('Ports', []))
    print(f"[*] Loaded {len(services_data.get('Ports', []))} ports / {total_svcs} services")

    items = parse_burp_xml(args.xml)
    print(f"[*] Found {len(items)} Burp items")

    server_info = collect_server_info(items)
    print(f"[*] Unique server info lines: {len(server_info)}")

    os.makedirs(args.profile, exist_ok=True)
    raw_path = os.path.join(args.profile, "raw.txt")
    with open(raw_path, 'w') as f:
        f.write('\n'.join(server_info) + '\n')
    print(f"[*] Raw data → {raw_path}")

    all_endpoints, matched_names = match_services(server_info, services_data)
    print(f"\n[+] Matched services ({len(matched_names)}): {', '.join(sorted(matched_names))}")
    print(f"[*] Total candidate endpoints from JSON: {len(all_endpoints)}")

    # Filter to log-related paths from JSON
    json_log = [(svc, ep) for svc, ep in all_endpoints if _is_log_path(ep)]
    print(f"[*] JSON endpoints matching log keywords: {len(json_log)}")

    final_endpoints = set()
    for _, ep in json_log:
        final_endpoints.add(ep)
    final_endpoints.update(HARDCODED_LOG_PATHS)

    sorted_eps = sorted(final_endpoints)

    os.makedirs(os.path.dirname(os.path.abspath(args.wordlist)), exist_ok=True)
    with open(args.wordlist, 'w') as f:
        f.write("# CONF-09 Log Path Wordlist (svc_recon component)\n")
        f.write("# Use with path traversal testing — service disseminator handled separately\n")
        f.write(f"# Matched services: {', '.join(sorted(matched_names))}\n")
        f.write(f"# Log keywords: {', '.join(LOG_KEYWORDS[:10])}...\n\n")
        for ep in sorted_eps:
            f.write(ep + '\n')

    print(f"\n[+] Wordlist written → {args.wordlist} ({len(sorted_eps)} paths)")
    print(f"    - From JSON endpoints: {len(json_log)}")
    print(f"    - From hardcoded list: {len(HARDCODED_LOG_PATHS)}")
    print(f"    - Deduplicated total:  {len(sorted_eps)}")

    print(f"\n{'='*55}")
    print("CONF-09 SUMMARY")
    print(f"{'='*55}")
    print(f"  Burp items:         {len(items)}")
    print(f"  Server info lines:  {len(server_info)}")
    print(f"  Matched services:   {len(matched_names)}")
    print(f"  Log path entries:   {len(sorted_eps)}")
    print(f"  Raw data:           {raw_path}")
    print(f"  Wordlist:           {args.wordlist}")


if __name__ == "__main__":
    main()
