#!/usr/bin/env python3
"""
WSTG-CONF-03 — Backup and Unreferenced Files
Reads Burp Suite XML + services JSON, matches detected services,
then filters all endpoints (CommonEndpoints + UndesirableEndpoints)
to those with backup/archive file extensions — plus a hardcoded
extension list for extensions that may not appear in the JSON.
"""

import argparse
import xml.etree.ElementTree as ET
import base64
import sys
import os
import json
import re
from pathlib import Path
from collections import defaultdict


# ---------------------------------------------------------------------------
# Backup / archive extensions (hardcoded — OWASP WSTG-CONF-03 scope)
# ---------------------------------------------------------------------------

BACKUP_EXTENSIONS = {
    # Editor / version backups
    '.bak', '.old', '.orig', '.save', '.swp', '.swo',
    # Archive formats
    '.zip', '.tar', '.gz', '.tgz', '.tar.gz', '.tar.bz2',
    '.bz2', '.rar', '.7z', '.xz', '.z',
    # Generic copies / dumps
    '.backup', '.copy', '.tmp', '.temp', '.dump', '.sql',
    # Tilde editor backups (handled separately — see _has_backup_ext)
}

# Paths/filenames that end with ~ (vim/emacs editor backups)
TILDE_BACKUP = True

# ---------------------------------------------------------------------------
# Reused service-matching constants (same as CONF-02)
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


# ---------------------------------------------------------------------------
# Extension filter
# ---------------------------------------------------------------------------

def _has_backup_ext(path: str) -> bool:
    """Return True if path has a backup-class extension or ends with ~."""
    p = path.lower().rstrip('/')
    if TILDE_BACKUP and p.endswith('~'):
        return True
    # Check compound extensions first (.tar.gz etc.)
    for ext in ['.tar.gz', '.tar.bz2']:
        if p.endswith(ext):
            return True
    # Single extension
    _, ext = os.path.splitext(p)
    return ext in BACKUP_EXTENSIONS


# ---------------------------------------------------------------------------
# Burp XML helpers
# ---------------------------------------------------------------------------

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
    status_line = lines[0] if lines else ""
    headers = []
    for line in lines[1:]:
        if not line or line.isspace():
            break
        parts = line.split(':', 1)
        if len(parts) == 2:
            headers.append((parts[0].strip(), parts[1].strip()))
    return status_line, headers


def collect_server_info(items) -> list:
    seen = set()
    result = []
    for item in items:
        resp_text = decode_element(item.find('./response'))
        if not resp_text:
            continue
        _, headers = extract_headers_from_response(resp_text)
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
    """Return all endpoints from matched services (common + undesirable)."""
    all_endpoints = []    # (svc_name, endpoint)
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
        description='CONF-03: Generate backup/archive file wordlist from Burp XML + services JSON'
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

    # Load services JSON
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

    # Parse Burp XML
    items = parse_burp_xml(args.xml)
    print(f"[*] Found {len(items)} Burp items")

    # Extract server info
    server_info = collect_server_info(items)
    print(f"[*] Unique server info lines: {len(server_info)}")

    # Write raw.txt
    os.makedirs(args.profile, exist_ok=True)
    raw_path = os.path.join(args.profile, "raw.txt")
    with open(raw_path, 'w') as f:
        f.write('\n'.join(server_info) + '\n')
    print(f"[*] Raw data → {raw_path}")

    # Match services
    all_endpoints, matched_names = match_services(server_info, services_data)
    print(f"\n[+] Matched services ({len(matched_names)}): {', '.join(sorted(matched_names))}")
    print(f"[*] Total candidate endpoints from JSON: {len(all_endpoints)}")

    # Filter: backup extensions from JSON endpoints
    json_backup = [(svc, ep) for svc, ep in all_endpoints if _has_backup_ext(ep)]
    print(f"[*] JSON endpoints with backup extensions: {len(json_backup)}")

    # Hardcoded backup paths — standalone entries not tied to a specific service
    # These are generic backup probes derived from common web root files
    HARDCODED_BACKUP_PATHS = [
        # Config file backups
        "/.env.bak", "/.env.old", "/.env.backup", "/.env~",
        "/web.config.bak", "/web.config.old",
        "/config.php.bak", "/config.php.old", "/config.php~",
        "/wp-config.php.bak", "/wp-config.php.old", "/wp-config.php~",
        "/settings.php.bak", "/settings.py.bak",
        "/application.yml.bak", "/application.properties.bak",
        "/database.yml.bak", "/database.php.bak",
        # Archive dumps of common directories
        "/backup.zip", "/backup.tar.gz", "/backup.tgz", "/backup.tar",
        "/www.zip", "/www.tar.gz", "/html.zip", "/html.tar.gz",
        "/site.zip", "/site.tar.gz", "/web.zip",
        "/public.zip", "/public_html.zip", "/public_html.tar.gz",
        # SQL dumps
        "/backup.sql", "/dump.sql", "/db.sql", "/database.sql",
        "/data.sql", "/schema.sql",
        # Editor swap files for common targets
        "/.htaccess.swp", "/index.php.swp", "/index.html.swp",
        # Old/orig copies
        "/index.php.old", "/index.php.orig", "/index.php.bak",
        "/index.html.old", "/index.html.bak",
    ]

    final_endpoints = set()

    # Add filtered JSON endpoints
    for _, ep in json_backup:
        final_endpoints.add(ep)

    # Add hardcoded backup paths
    final_endpoints.update(HARDCODED_BACKUP_PATHS)

    sorted_eps = sorted(final_endpoints)

    # Write wordlist
    os.makedirs(os.path.dirname(os.path.abspath(args.wordlist)), exist_ok=True)
    with open(args.wordlist, 'w') as f:
        f.write("# CONF-03 Backup & Archive File Wordlist\n")
        f.write(f"# Matched services: {', '.join(sorted(matched_names))}\n")
        f.write(f"# Extensions: {', '.join(sorted(BACKUP_EXTENSIONS))}, ~\n\n")
        for ep in sorted_eps:
            f.write(ep + '\n')

    print(f"\n[+] Wordlist written → {args.wordlist} ({len(sorted_eps)} endpoints)")
    print(f"    - From JSON endpoints: {len(json_backup)}")
    print(f"    - From hardcoded list: {len(HARDCODED_BACKUP_PATHS)}")
    print(f"    - Deduplicated total:  {len(sorted_eps)}")

    # Summary
    print(f"\n{'='*55}")
    print("CONF-03 SUMMARY")
    print(f"{'='*55}")
    print(f"  Burp items:            {len(items)}")
    print(f"  Server info lines:     {len(server_info)}")
    print(f"  Matched services:      {len(matched_names)}")
    print(f"  Backup endpoints:      {len(sorted_eps)}")
    print(f"  Raw data:              {raw_path}")
    print(f"  Wordlist:              {args.wordlist}")


if __name__ == "__main__":
    main()