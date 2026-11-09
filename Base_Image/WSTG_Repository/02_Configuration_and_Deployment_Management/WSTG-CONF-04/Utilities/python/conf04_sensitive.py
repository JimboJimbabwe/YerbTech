#!/usr/bin/env python3
"""
WSTG-CONF-04 — HTTP Methods and Cross-Domain Policy / Sensitive File Exposure
Reads Burp Suite XML + services JSON, matches detected services,
then filters all endpoints to those with credential/secret/source
extensions — plus special paths (.git/, .docker/) and a hardcoded
extension list based on the OWASP WSTG-CONF-04 sensitive file taxonomy.
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
# Sensitive file extensions — hardcoded (WSTG-CONF-04 scope)
# ---------------------------------------------------------------------------

# Credentials and secrets — should NEVER be publicly served
CREDENTIAL_EXTENSIONS = {
    '.env', '.pem', '.key', '.p12', '.pfx',
    '.tfstate', '.tfvars', '.kdbx',
    '.htpasswd', '.npmrc',
    '.asa', '.inc',
}

# Source / configuration — should NEVER be publicly served
SOURCE_EXTENSIONS = {
    '.java',
    '.yaml', '.yml',
}

# Data artifacts — sensitivity depends on content
DATA_EXTENSIONS = {
    '.db', '.sqlite', '.sqlite3',
    '.parquet', '.avro',
    '.csv',
    '.ipynb',
}

# All sensitive extensions combined
SENSITIVE_EXTENSIONS = CREDENTIAL_EXTENSIONS | SOURCE_EXTENSIONS | DATA_EXTENSIONS

# Special paths (directory names, not extensions) — always include these
SPECIAL_PATHS = {
    '/.git/',
    '/.git/config',
    '/.git/HEAD',
    '/.git/COMMIT_EDITMSG',
    '/.docker/',
    '/.dockercfg',
    '/.docker/config.json',
}

# Docker/container config files (named files, no extension)
SENSITIVE_NAMED_FILES = {
    '/.dockercfg',
    '/docker-compose.yml',
    '/.env',
    '/.htpasswd',
    '/.npmrc',
    '/.aws/credentials',
    '/.ssh/id_rsa',
    '/.ssh/id_rsa.pub',
    '/.bash_history',
    '/.mysql_history',
}

# Hardcoded sensitive file probes (augments what may be in svc JSON)
HARDCODED_SENSITIVE_PATHS = [
    # Terraform state
    "/terraform.tfstate", "/terraform.tfstate.backup",
    "/terraform.tfvars",
    # Kubernetes / CI
    "/kubernetes.yml", "/k8s.yml",
    "/.gitlab-ci.yml", "/.travis.yml",
    "/Jenkinsfile", "/jenkins.xml",
    "/docker-compose.yml", "/docker-compose.override.yml",
    # Secrets / keys
    "/.env", "/.env.local", "/.env.production", "/.env.staging",
    "/.env.dev", "/.env.test",
    "/id_rsa", "/id_rsa.pub",
    "/.aws/credentials", "/.aws/config",
    "/.ssh/known_hosts",
    "/.dockercfg", "/.docker/config.json",
    "/.npmrc", "/.yarnrc",
    # Password files
    "/.htpasswd", "/etc/passwd", "/etc/shadow",
    # Certificates / keys
    "/server.pem", "/server.key", "/server.crt",
    "/ssl.pem", "/ssl.key", "/privkey.pem", "/cert.pem",
    # Java source / compiled
    "/WEB-INF/web.xml", "/WEB-INF/classes/",
    # KeePass / password managers
    "/passwords.kdbx", "/keepass.kdbx",
    # Config files
    "/.htaccess", "/web.config",
    "/config.inc.php", "/config.php",
    "/settings.py", "/local_settings.py",
    "/database.yml",
    # Git internals
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
    "/.svn/entries",
    # Notebooks (can contain hardcoded creds in cell output)
    "/notebook.ipynb", "/analysis.ipynb",
    # SQLite databases
    "/db.sqlite3", "/database.sqlite", "/data.db",
    # CSV data
    "/data.csv", "/users.csv", "/export.csv",
]


# ---------------------------------------------------------------------------
# Extension filter
# ---------------------------------------------------------------------------

def _is_sensitive(path: str) -> bool:
    """Return True if path matches a sensitive extension or special path."""
    p_lower = path.lower().rstrip('/')

    # Special directory paths
    for sp in SPECIAL_PATHS:
        if p_lower == sp.rstrip('/') or p_lower.startswith(sp):
            return True

    # Named sensitive files (exact match)
    if p_lower in {s.lower() for s in SENSITIVE_NAMED_FILES}:
        return True

    # Extension match
    _, ext = os.path.splitext(p_lower)
    if ext in SENSITIVE_EXTENSIONS:
        return True

    # .json is sensitive outside expected API paths; include all .json here
    # (testers can prune false positives)
    if ext == '.json':
        return True

    return False


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
        description='CONF-04: Generate sensitive file wordlist from Burp XML + services JSON'
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

    # Filter: sensitive extensions from JSON endpoints
    json_sensitive = [(svc, ep) for svc, ep in all_endpoints if _is_sensitive(ep)]
    print(f"[*] JSON endpoints with sensitive extensions/paths: {len(json_sensitive)}")

    # Build final set
    final_endpoints = set()
    for _, ep in json_sensitive:
        final_endpoints.add(ep)
    final_endpoints.update(HARDCODED_SENSITIVE_PATHS)
    final_endpoints.update(SPECIAL_PATHS)
    final_endpoints.update(SENSITIVE_NAMED_FILES)

    sorted_eps = sorted(final_endpoints)

    # Write wordlist
    os.makedirs(os.path.dirname(os.path.abspath(args.wordlist)), exist_ok=True)
    with open(args.wordlist, 'w') as f:
        f.write("# CONF-04 Sensitive File Wordlist\n")
        f.write(f"# Matched services: {', '.join(sorted(matched_names))}\n")
        cred_exts = ', '.join(sorted(CREDENTIAL_EXTENSIONS))
        src_exts  = ', '.join(sorted(SOURCE_EXTENSIONS))
        data_exts = ', '.join(sorted(DATA_EXTENSIONS))
        f.write(f"# Credential extensions: {cred_exts}\n")
        f.write(f"# Source extensions:     {src_exts}\n")
        f.write(f"# Data extensions:       {data_exts}\n")
        f.write(f"# Special paths:         .git/, .docker/\n\n")
        for ep in sorted_eps:
            f.write(ep + '\n')

    print(f"\n[+] Wordlist written → {args.wordlist} ({len(sorted_eps)} endpoints)")
    print(f"    - From JSON endpoints:    {len(json_sensitive)}")
    print(f"    - From hardcoded list:    {len(HARDCODED_SENSITIVE_PATHS)}")
    print(f"    - Special paths:          {len(SPECIAL_PATHS)}")
    print(f"    - Named sensitive files:  {len(SENSITIVE_NAMED_FILES)}")
    print(f"    - Deduplicated total:     {len(sorted_eps)}")

    # Summary
    print(f"\n{'='*55}")
    print("CONF-04 SUMMARY")
    print(f"{'='*55}")
    print(f"  Burp items:         {len(items)}")
    print(f"  Server info lines:  {len(server_info)}")
    print(f"  Matched services:   {len(matched_names)}")
    print(f"  Sensitive entries:  {len(sorted_eps)}")
    print(f"  Raw data:           {raw_path}")
    print(f"  Wordlist:           {args.wordlist}")


if __name__ == "__main__":
    main()