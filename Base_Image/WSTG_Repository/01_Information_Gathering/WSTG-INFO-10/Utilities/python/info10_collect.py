#!/usr/bin/env python3
"""
WSTG-INFO-10 — Application Architecture Data Collector
Script 1 of 2: info10_collect.py

Reads output files from multiple WSTG test cases and extracts structured
data about the target application's architecture into per-topic wordlists
and a master JSON used by info10_diagram.py to produce the SVG diagram.

Sources consumed:
  WSTG-INFO-04/Outputs/data/uxp_scan.xml          nmap service scan XML
  WSTG-CONF-11/outputs/test_output/test_findings.txt  cloud storage report
  WSTG-CONF-10/outputs/test_outputs/findings.md   subdomain takeover report
  WSTG-INFO-04/Outputs/test_outputs/DNS_MODULE/results.txt  dig DNS output
  WSTG-INFO-06/inputs/xml/*.xml                   Burp XML (auth endpoints)
  WSTG-ATHZ-02/inputs/xml/*.xml                   Burp XML (authed user funcs)

Outputs (all to WSTG-INFO-10/inputs/data/):
  server.txt              server name, OS, version strings
  services.txt            open ports and services
  cloud_providers.txt     detected cloud/CDN providers
  subdomains.txt          subdomains with takeover verdict
  auth_endpoints.txt      authentication-related endpoints
  authed_endpoints.txt    authenticated-user endpoints
  main_app_endpoints.txt  remaining application endpoints
  databases.txt           detected database services
  third_parties.txt       [EMPTY — placeholder for future data]
  config_mgmt.txt         [EMPTY — placeholder for future data]
  arch_data.json          master structured JSON for the diagram script

Usage:
  python3 info10_collect.py [--base <repo_root>] [--nmap <uxp_scan.xml>]
                             [--conf11 <test_findings.txt>]
                             [--conf10 <findings.md>]
                             [--dns <results.txt>]
                             [--info06-xml <dir>]
                             [--athz02-xml <dir>]
                             [--out <output_dir>]
"""

import argparse
import base64
import glob
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime

# ---------------------------------------------------------------------------
# ANSI
# ---------------------------------------------------------------------------
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
WIDTH  = 65

# ---------------------------------------------------------------------------
# Default paths (relative to repo root — override via CLI args)
# ---------------------------------------------------------------------------
DEFAULT_NMAP    = "WSTG-INFO-04/Outputs/data/uxp_scan.xml"
DEFAULT_CONF11  = "WSTG-CONF-11/outputs/test_output/test_findings.txt"
DEFAULT_CONF10  = "WSTG-CONF-10/outputs/test_outputs/findings.md"
DEFAULT_DNS     = "WSTG-INFO-04/Outputs/test_outputs/DNS_MODULE/results.txt"
DEFAULT_INFO06  = "WSTG-INFO-06/inputs/xml"
DEFAULT_ATHZ02  = "WSTG-ATHZ-02/inputs/xml"
DEFAULT_OUT     = "WSTG-INFO-10/inputs/data"

# ---------------------------------------------------------------------------
# Auth endpoint keywords
# ---------------------------------------------------------------------------
AUTH_PATH_RE = re.compile(
    r'(?:login|logout|signin|sign-in|sign_in|signup|sign-up|sign_up|'
    r'register|auth|authenticate|authentication|oauth|oidc|sso|saml|'
    r'jwt|token|refresh|session|password|passwd|reset|forgot|mfa|'
    r'2fa|totp|verify|verification|callback|authorize|consent)',
    re.IGNORECASE,
)

AUTH_PROVIDER_HEADERS = {
    "x-powered-by":   "framework",
    "server":         "server",
    "www-authenticate": "auth_scheme",
}

AUTH_PROVIDER_PATTERNS = [
    (re.compile(r'okta',       re.I), "Okta"),
    (re.compile(r'auth0',      re.I), "Auth0"),
    (re.compile(r'cognito',    re.I), "AWS Cognito"),
    (re.compile(r'azure.*ad|microsoft.*identity|login\.microsoftonline', re.I), "Azure AD / Microsoft Identity"),
    (re.compile(r'google.*oauth|accounts\.google', re.I), "Google OAuth"),
    (re.compile(r'keycloak',   re.I), "Keycloak"),
    (re.compile(r'ping.*identity|pingfederate', re.I), "PingIdentity"),
    (re.compile(r'onelogin',   re.I), "OneLogin"),
    (re.compile(r'duo',        re.I), "Duo Security"),
    (re.compile(r'firebase.*auth', re.I), "Firebase Auth"),
    (re.compile(r'passport',   re.I), "Passport.js"),
    (re.compile(r'devise',     re.I), "Devise (Rails)"),
    (re.compile(r'spring.*security', re.I), "Spring Security"),
    (re.compile(r'jwt',        re.I), "JWT-based"),
    (re.compile(r'bearer',     re.I), "Bearer token"),
    (re.compile(r'basic',      re.I), "HTTP Basic Auth"),
    (re.compile(r'digest',     re.I), "HTTP Digest Auth"),
    (re.compile(r'ntlm',       re.I), "NTLM"),
    (re.compile(r'kerberos',   re.I), "Kerberos"),
    (re.compile(r'saml',       re.I), "SAML"),
]

# ---------------------------------------------------------------------------
# Database service patterns
# ---------------------------------------------------------------------------
DB_PATTERNS = [
    (re.compile(r'mysql|mariadb',     re.I), "MySQL / MariaDB"),
    (re.compile(r'postgresql|postgres', re.I), "PostgreSQL"),
    (re.compile(r'mssql|sqlserver|microsoft.*sql', re.I), "MS SQL Server"),
    (re.compile(r'oracle',            re.I), "Oracle DB"),
    (re.compile(r'mongodb',           re.I), "MongoDB"),
    (re.compile(r'redis',             re.I), "Redis"),
    (re.compile(r'elasticsearch|elastic', re.I), "Elasticsearch"),
    (re.compile(r'cassandra',         re.I), "Cassandra"),
    (re.compile(r'couchdb',           re.I), "CouchDB"),
    (re.compile(r'neo4j',             re.I), "Neo4j"),
    (re.compile(r'sqlite',            re.I), "SQLite"),
    (re.compile(r'memcached',         re.I), "Memcached"),
    (re.compile(r'rabbitmq',          re.I), "RabbitMQ"),
    (re.compile(r'kafka',             re.I), "Apache Kafka"),
    (re.compile(r'db2',               re.I), "IBM DB2"),
]

# ---------------------------------------------------------------------------
# Burp XML decode helper (consistent with rest of toolset)
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


def parse_request_line(request_text: str) -> tuple:
    first = request_text.split('\n', 1)[0].strip()
    parts = first.split(' ')
    if len(parts) >= 2:
        return parts[0], parts[1]
    return "UNKNOWN", "/"


def parse_response_headers(response_text: str) -> dict:
    """Return dict of {header_name_lower: value} from response."""
    lines = response_text.split('\n')
    headers = {}
    for line in lines[1:]:
        if '\n\n' in response_text and line == '':
            break
        if ':' in line:
            name, _, value = line.partition(':')
            headers[name.strip().lower()] = value.strip()
    return headers


def load_burp_items(xml_paths: list) -> list:
    """Load all Burp items from a list of XML files."""
    items = []
    for path in xml_paths:
        try:
            tree = ET.parse(path)
            for item in tree.getroot().findall('.//item'):
                url_elem = item.find('./url')
                url = url_elem.text.strip() if url_elem is not None and url_elem.text else ""
                request_text  = decode_element(item.find('./request'))
                response_text = decode_element(item.find('./response'))
                method, path_str = parse_request_line(request_text)

                # Get path without query string
                clean_path = path_str.split('?')[0] if path_str else "/"

                status_elem  = item.find('./status')
                status = status_elem.text.strip() if status_elem is not None and status_elem.text else ""

                resp_headers = parse_response_headers(response_text)

                items.append({
                    "method":        method,
                    "path":          clean_path,
                    "url":           url,
                    "status":        status,
                    "resp_headers":  resp_headers,
                    "request_raw":   request_text,
                    "response_raw":  response_text,
                    "_source_file":  os.path.basename(path),
                })
        except ET.ParseError as e:
            print(f"  {YELLOW}[!] XML parse error in {path}: {e}{RESET}")
        except FileNotFoundError:
            print(f"  {YELLOW}[!] File not found: {path}{RESET}")
    return items


# ---------------------------------------------------------------------------
# Source 1: nmap XML (INFO-04 uxp_scan.xml)
# ---------------------------------------------------------------------------

def parse_nmap_xml(nmap_path: str) -> dict:
    """
    Extract server info, open ports/services, and database services
    from an nmap -sV XML output.

    Returns:
      {
        "hosts": [{
          "ip": str, "hostname": str, "os_guess": str,
          "ports": [{"port": int, "protocol": str, "state": str,
                     "service": str, "product": str, "version": str,
                     "extrainfo": str, "is_db": bool, "db_label": str}]
        }],
        "databases": [{"label": str, "port": int, "service": str, "version": str}],
        "server_strings": [str],   # raw version strings for Obj1
      }
    """
    result = {"hosts": [], "databases": [], "server_strings": []}

    if not os.path.isfile(nmap_path):
        print(f"  {YELLOW}[!] nmap XML not found: {nmap_path}{RESET}")
        return result

    try:
        tree = ET.parse(nmap_path)
    except ET.ParseError as e:
        print(f"  {YELLOW}[!] nmap XML parse error: {e}{RESET}")
        return result

    root = tree.getroot()

    for host_elem in root.findall('.//host'):
        host_data = {
            "ip":        "",
            "hostname":  "",
            "os_guess":  "",
            "ports":     [],
        }

        # IP address
        for addr in host_elem.findall('./address'):
            if addr.get('addrtype') in ('ipv4', 'ipv6'):
                host_data["ip"] = addr.get('addr', '')
                break

        # Hostname
        for hn in host_elem.findall('./hostnames/hostname'):
            if hn.get('type') in ('user', 'PTR', 'dns'):
                host_data["hostname"] = hn.get('name', '')
                break

        # OS detection (best match)
        for osmatch in host_elem.findall('./os/osmatch'):
            host_data["os_guess"] = osmatch.get('name', '')
            break

        # Ports
        for port_elem in host_elem.findall('./ports/port'):
            state_elem   = port_elem.find('./state')
            service_elem = port_elem.find('./service')

            state   = state_elem.get('state', '') if state_elem is not None else ''
            if state not in ('open', 'open|filtered'):
                continue

            portid   = port_elem.get('portid', '')
            protocol = port_elem.get('protocol', 'tcp')
            svc_name = ''
            product  = ''
            version  = ''
            extrainfo= ''

            if service_elem is not None:
                svc_name  = service_elem.get('name', '')
                product   = service_elem.get('product', '')
                version   = service_elem.get('version', '')
                extrainfo = service_elem.get('extrainfo', '')

            # Build version string
            version_parts = [p for p in [product, version, extrainfo] if p]
            version_str   = " ".join(version_parts)

            # Database detection
            combined_svc = f"{svc_name} {product} {version_str}"
            is_db     = False
            db_label  = ""
            for db_re, db_name in DB_PATTERNS:
                if db_re.search(combined_svc):
                    is_db    = True
                    db_label = db_name
                    result["databases"].append({
                        "label":   db_name,
                        "port":    int(portid) if portid.isdigit() else portid,
                        "service": svc_name,
                        "version": version_str,
                    })
                    break

            port_entry = {
                "port":      int(portid) if portid.isdigit() else portid,
                "protocol":  protocol,
                "state":     state,
                "service":   svc_name,
                "product":   product,
                "version":   version,
                "extrainfo": extrainfo,
                "is_db":     is_db,
                "db_label":  db_label,
            }
            host_data["ports"].append(port_entry)

            # Server string for Obj1
            if version_str:
                label = f"Port {portid}/{protocol} — {svc_name}: {version_str}"
                result["server_strings"].append(label)

        result["hosts"].append(host_data)

    return result


# ---------------------------------------------------------------------------
# Source 2: CONF-11 text report
# ---------------------------------------------------------------------------

def parse_conf11_report(conf11_path: str) -> dict:
    """
    Parse the CONF-11 test_findings.txt report.
    Returns {
      "providers": {"aws_s3": 3, "azure_blob": 1, ...},
      "endpoints": [{"method": str, "path": str, "categories": [str]}]
    }
    """
    result = {"providers": defaultdict(int), "endpoints": []}

    if not os.path.isfile(conf11_path):
        print(f"  {YELLOW}[!] CONF-11 report not found: {conf11_path}{RESET}")
        return result

    category_map = {
        'AWS S3':              'aws_s3',
        'AWS Regions':         'aws_regions',
        'AWS Other Services':  'aws_other',
        'Azure Blob Storage':  'azure_blob',
        'Google Cloud Storage':'gcp_storage',
        'Generic Cloud':       'generic_cloud',
    }

    current_endpoint = None
    current_cats     = []

    with open(conf11_path, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.rstrip()

            # Endpoint header: "ENDPOINT  123 | GET     | /path"
            m_ep = re.match(r'ENDPOINT\s+(\d+)\s*\|\s*(\S+)\s*\|\s*(\S+)', line)
            if m_ep:
                if current_endpoint:
                    result["endpoints"].append(current_endpoint)
                current_endpoint = {
                    "method":     m_ep.group(2),
                    "path":       m_ep.group(3),
                    "categories": [],
                }
                current_cats = []
                continue

            # Category line: "  [AWS S3] — 3 hit(s)"
            m_cat = re.match(r'\s+\[([^\]]+)\]\s*—\s*(\d+)\s*hit', line)
            if m_cat and current_endpoint is not None:
                cat_label = m_cat.group(1)
                cat_id    = category_map.get(cat_label, cat_label.lower().replace(' ', '_'))
                result["providers"][cat_id] += int(m_cat.group(2))
                if cat_id not in current_endpoint["categories"]:
                    current_endpoint["categories"].append(cat_id)

    if current_endpoint:
        result["endpoints"].append(current_endpoint)

    result["providers"] = dict(result["providers"])
    return result


# ---------------------------------------------------------------------------
# Source 3: CONF-10 findings.md
# ---------------------------------------------------------------------------

def parse_conf10_findings(conf10_path: str) -> dict:
    """
    Parse CONF-10 findings.md.
    Returns {
      "subdomains": [{"subdomain": str, "verdict": str, "provider": str,
                      "cname": str, "confidence": str}]
    }
    """
    result = {"subdomains": []}

    if not os.path.isfile(conf10_path):
        print(f"  {YELLOW}[!] CONF-10 findings not found: {conf10_path}{RESET}")
        return result

    with open(conf10_path, encoding='utf-8', errors='replace') as f:
        content = f.read()

    # Extract subdomain sections by verdict
    # Sections start with "### `subdomain`"
    sub_blocks = re.split(r'\n### `([^`]+)`\n', content)
    if len(sub_blocks) < 2:
        return result

    # Determine which block each subdomain is in
    # Check preceding section header (## 🔴 or ## 🟡 or ## 🟢)
    verdict_sections = {}
    for section_re, verdict in [
        (r'##.*🔴.*Takeover',   'TAKEOVER_CANDIDATE'),
        (r'##.*🟡.*Investigate', 'INVESTIGATE'),
        (r'##.*🟢.*Clean',       'CLEAN'),
    ]:
        for m in re.finditer(section_re + r'.*?(?=\n## |\Z)', content, re.DOTALL | re.IGNORECASE):
            # Find all subdomain headers within this section
            for sub_m in re.finditer(r'### `([^`]+)`', m.group(0)):
                verdict_sections[sub_m.group(1)] = verdict

    # Parse each subdomain block
    for i in range(1, len(sub_blocks), 2):
        subdomain = sub_blocks[i]
        block     = sub_blocks[i + 1] if i + 1 < len(sub_blocks) else ""

        verdict    = verdict_sections.get(subdomain, "UNKNOWN")
        provider   = ""
        cname      = ""
        confidence = ""

        m_prov = re.search(r'\|\s*Provider\s*\|\s*([^|]+)\|', block)
        m_cname= re.search(r'\|\s*CNAME Target\s*\|\s*`([^`]*)`', block)
        m_conf = re.search(r'\|\s*Confidence\s*\|\s*\*?\*?([A-Z]+)\*?\*?', block)

        if m_prov:   provider   = m_prov.group(1).strip()
        if m_cname:  cname      = m_cname.group(1).strip()
        if m_conf:   confidence = m_conf.group(1).strip()

        result["subdomains"].append({
            "subdomain":  subdomain,
            "verdict":    verdict,
            "provider":   provider,
            "cname":      cname,
            "confidence": confidence,
        })

    return result


# ---------------------------------------------------------------------------
# Source 4: DNS results.txt (INFO-04)
# ---------------------------------------------------------------------------

def parse_dns_results(dns_path: str) -> dict:
    """
    Parse INFO-04 DNS results.txt.
    Returns {
      "domains": {"example.com": {"A": [...], "NS": [...], "MX": [...], ...}}
    }
    """
    result = {"domains": {}}

    if not os.path.isfile(dns_path):
        print(f"  {YELLOW}[!] DNS results not found: {dns_path}{RESET}")
        return result

    current_domain  = None
    current_rtype   = None

    with open(dns_path, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.rstrip()

            # Domain section header: "=== example.com ==="
            m_dom = re.match(r'^=== (.+?) ===$', line)
            if m_dom:
                current_domain = m_dom.group(1).strip()
                result["domains"][current_domain] = {}
                current_rtype = None
                continue

            # Record type header: "--- A ---"
            m_rtype = re.match(r'^--- ([A-Z]+) ---$', line)
            if m_rtype and current_domain:
                current_rtype = m_rtype.group(1)
                result["domains"][current_domain][current_rtype] = []
                continue

            # Record line (non-empty, non-header, within a domain section)
            if current_domain and current_rtype and line.strip():
                result["domains"][current_domain][current_rtype].append(line.strip())

    return result


# ---------------------------------------------------------------------------
# Source 5 + 6 + 7: Burp XML (INFO-06 auth, ATHZ-02 authed)
# ---------------------------------------------------------------------------

def extract_auth_endpoints(items: list) -> dict:
    """
    From INFO-06 Burp items, split into:
      - auth_endpoints: paths matching AUTH_PATH_RE
      - auth_providers: detected provider names
    """
    auth_eps    = []
    providers   = set()
    seen        = set()

    for item in items:
        path   = item["path"]
        method = item["method"]
        key    = f"{method}:{path}"

        if AUTH_PATH_RE.search(path):
            if key not in seen:
                seen.add(key)
                auth_eps.append({"method": method, "path": path})

        # Detect provider from response headers
        for header_name, header_val in item["resp_headers"].items():
            combined = f"{header_name}: {header_val}"
            for pat, name in AUTH_PROVIDER_PATTERNS:
                if pat.search(combined):
                    providers.add(name)

        # Also check Location headers and response bodies for provider clues
        body_snippet = item["response_raw"][:2000]
        for pat, name in AUTH_PROVIDER_PATTERNS:
            if pat.search(body_snippet):
                providers.add(name)

    return {
        "endpoints": auth_eps,
        "providers": sorted(providers),
    }


def extract_authed_endpoints(items: list, auth_paths: set) -> list:
    """
    From ATHZ-02 Burp items, return endpoints NOT in auth_paths.
    Split is done by the caller — this returns all unique METHOD:path pairs.
    """
    eps  = []
    seen = set()

    for item in items:
        path   = item["path"]
        method = item["method"]
        key    = f"{method}:{path}"

        if key not in seen:
            seen.add(key)
            eps.append({"method": method, "path": path})

    return eps


# ---------------------------------------------------------------------------
# Wordlist writers
# ---------------------------------------------------------------------------

def write_txt(out_dir: str, filename: str, lines: list, header: str = "") -> str:
    path = os.path.join(out_dir, filename)
    os.makedirs(out_dir, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        if header:
            f.write(f"# {header}\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
        for line in lines:
            f.write(str(line) + "\n")
    return path


# ---------------------------------------------------------------------------
# Empty-function stubs for future data sources
# ---------------------------------------------------------------------------

def collect_third_parties() -> list:
    """
    STUB — Third-party detection.
    TODO: implement when data source is decided.
    Possible sources: JS file scanning for CDN domains, response headers,
    Content-Security-Policy header parsing.
    Returns list of {"name": str, "type": str} dicts.
    """
    return []   # placeholder


def collect_config_mgmt() -> list:
    """
    STUB — Configuration management detection.
    TODO: implement when data source is decided.
    Possible sources: X-Powered-By, response body fingerprinting,
    CONF-05 admin paths output.
    Returns list of {"name": str, "evidence": str} dicts.
    """
    return []   # placeholder


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="WSTG-INFO-10: Collect architecture data from WSTG outputs"
    )
    p.add_argument("--base",      default=".",
                   help="Repository root (default: .)")
    p.add_argument("--nmap",      default=None,
                   help=f"nmap XML path (default: <base>/{DEFAULT_NMAP})")
    p.add_argument("--conf11",    default=None,
                   help=f"CONF-11 report path (default: <base>/{DEFAULT_CONF11})")
    p.add_argument("--conf10",    default=None,
                   help=f"CONF-10 findings.md (default: <base>/{DEFAULT_CONF10})")
    p.add_argument("--dns",       default=None,
                   help=f"DNS results.txt (default: <base>/{DEFAULT_DNS})")
    p.add_argument("--info06-xml", default=None,
                   help=f"INFO-06 Burp XML dir (default: <base>/{DEFAULT_INFO06})")
    p.add_argument("--athz02-xml", default=None,
                   help=f"ATHZ-02 Burp XML dir (default: <base>/{DEFAULT_ATHZ02})")
    p.add_argument("--out",        default=None,
                   help=f"Output directory (default: <base>/{DEFAULT_OUT})")
    return p.parse_args()


def resolve(base: str, override, default: str) -> str:
    return override if override else os.path.join(base, default)


def main():
    args    = parse_args()
    base    = os.path.abspath(args.base)
    out_dir = resolve(base, args.out, DEFAULT_OUT)

    nmap_path   = resolve(base, args.nmap,        DEFAULT_NMAP)
    conf11_path = resolve(base, args.conf11,       DEFAULT_CONF11)
    conf10_path = resolve(base, args.conf10,       DEFAULT_CONF10)
    dns_path    = resolve(base, args.dns,          DEFAULT_DNS)
    info06_dir  = resolve(base, args.info06_xml,   DEFAULT_INFO06)
    athz02_dir  = resolve(base, args.athz02_xml,   DEFAULT_ATHZ02)

    print(f"\n{BOLD}{'='*WIDTH}{RESET}")
    print(f"{BOLD}  WSTG-INFO-10 — Architecture Data Collector{RESET}")
    print(f"{BOLD}{'='*WIDTH}{RESET}\n")

    os.makedirs(out_dir, exist_ok=True)
    arch = {}   # master dict → arch_data.json

    # ── 1. nmap XML ──────────────────────────────────────────────────────────
    print(f"  {CYAN}[1/7] nmap XML — server, services, databases{RESET}")
    nmap_data = parse_nmap_xml(nmap_path)
    arch["nmap"] = nmap_data

    # server.txt
    server_lines = []
    for host in nmap_data["hosts"]:
        server_lines.append(f"IP: {host['ip']}")
        if host["hostname"]:
            server_lines.append(f"Hostname: {host['hostname']}")
        if host["os_guess"]:
            server_lines.append(f"OS: {host['os_guess']}")
        for vs in nmap_data["server_strings"][:20]:
            server_lines.append(vs)
    p = write_txt(out_dir, "server.txt", server_lines, "Server — INFO-04 nmap")
    print(f"    {GREEN}[+]{RESET} {p}  ({len(server_lines)} lines)")

    # services.txt
    svc_lines = []
    for host in nmap_data["hosts"]:
        for port in host["ports"]:
            ver = " ".join(filter(None, [port["product"], port["version"], port["extrainfo"]]))
            svc_lines.append(
                f"{port['port']}/{port['protocol']}  {port['service']}  {ver}".strip()
            )
    p = write_txt(out_dir, "services.txt", svc_lines, "Open ports + services — INFO-04 nmap")
    print(f"    {GREEN}[+]{RESET} {p}  ({len(svc_lines)} lines)")

    # databases.txt
    db_lines = []
    for db in nmap_data["databases"]:
        db_lines.append(f"{db['label']}  port={db['port']}  {db['version']}".strip())
    p = write_txt(out_dir, "databases.txt", db_lines, "Detected databases — INFO-04 nmap")
    print(f"    {GREEN}[+]{RESET} {p}  ({len(db_lines)} line(s))")

    # ── 2. CONF-11 cloud storage ─────────────────────────────────────────────
    print(f"\n  {CYAN}[2/7] CONF-11 — cloud providers{RESET}")
    conf11_data = parse_conf11_report(conf11_path)
    arch["cloud"] = conf11_data

    cloud_lines = []
    for cat_id, count in conf11_data["providers"].items():
        cloud_lines.append(f"{cat_id}  hits={count}")
    p = write_txt(out_dir, "cloud_providers.txt", cloud_lines,
                  "Detected cloud providers — CONF-11")
    print(f"    {GREEN}[+]{RESET} {p}  ({len(cloud_lines)} line(s))")

    # ── 3. CONF-10 subdomains ────────────────────────────────────────────────
    print(f"\n  {CYAN}[3/7] CONF-10 — subdomains{RESET}")
    conf10_data = parse_conf10_findings(conf10_path)
    arch["subdomains"] = conf10_data

    sub_lines = []
    for s in conf10_data["subdomains"]:
        sub_lines.append(
            f"{s['subdomain']}  verdict={s['verdict']}  provider={s['provider']}  cname={s['cname']}"
        )
    p = write_txt(out_dir, "subdomains.txt", sub_lines,
                  "Subdomains — CONF-10 takeover analysis")
    print(f"    {GREEN}[+]{RESET} {p}  ({len(sub_lines)} line(s))")

    # ── 4. DNS ───────────────────────────────────────────────────────────────
    print(f"\n  {CYAN}[4/7] DNS — INFO-04 results{RESET}")
    dns_data = parse_dns_results(dns_path)
    arch["dns"] = dns_data
    # DNS data folds into server.txt and is available in arch_data.json
    dns_count = sum(len(recs) for dom in dns_data["domains"].values()
                    for recs in dom.values())
    print(f"    {GREEN}[+]{RESET} {len(dns_data['domains'])} domain(s), {dns_count} DNS record(s) loaded")

    # ── 5. INFO-06 Burp XML — auth endpoints ─────────────────────────────────
    print(f"\n  {CYAN}[5/7] INFO-06 Burp XML — auth endpoints{RESET}")
    info06_xmls = sorted(glob.glob(os.path.join(info06_dir, "*.xml")))
    if not info06_xmls:
        print(f"    {YELLOW}[!] No XML files found in {info06_dir}{RESET}")
        info06_items = []
    else:
        info06_items = load_burp_items(info06_xmls)
        print(f"    Loaded {len(info06_items)} items from {len(info06_xmls)} file(s)")

    auth_data = extract_auth_endpoints(info06_items)
    arch["auth"] = auth_data

    auth_lines = []
    for ep in auth_data["endpoints"]:
        auth_lines.append(f"{ep['method']}  {ep['path']}")
    if auth_data["providers"]:
        auth_lines.append("")
        auth_lines.append("# Detected auth providers:")
        for prov in auth_data["providers"]:
            auth_lines.append(f"#   {prov}")

    p = write_txt(out_dir, "auth_endpoints.txt", auth_lines,
                  "Authentication endpoints — INFO-06 Burp XML")
    print(f"    {GREEN}[+]{RESET} {p}  ({len(auth_data['endpoints'])} endpoint(s), "
          f"{len(auth_data['providers'])} provider(s))")

    # ── 6 + 7. ATHZ-02 Burp XML — authed + main app ─────────────────────────
    print(f"\n  {CYAN}[6/7] ATHZ-02 Burp XML — authed user + main app endpoints{RESET}")
    athz02_xmls = sorted(glob.glob(os.path.join(athz02_dir, "*.xml")))
    if not athz02_xmls:
        print(f"    {YELLOW}[!] No XML files found in {athz02_dir}{RESET}")
        athz02_items = []
    else:
        athz02_items = load_burp_items(athz02_xmls)
        print(f"    Loaded {len(athz02_items)} items from {len(athz02_xmls)} file(s)")

    auth_path_set = {f"{ep['method']}:{ep['path']}" for ep in auth_data["endpoints"]}
    all_athz02    = extract_authed_endpoints(athz02_items, auth_path_set)

    # Split: authed = those in ATHZ-02, main_app = those NOT in auth set
    authed_eps  = [ep for ep in all_athz02
                   if f"{ep['method']}:{ep['path']}" not in auth_path_set]
    main_app_eps= [ep for ep in all_athz02
                   if f"{ep['method']}:{ep['path']}" not in auth_path_set
                   and not AUTH_PATH_RE.search(ep["path"])]

    arch["authed"]   = authed_eps
    arch["main_app"] = main_app_eps

    authed_lines = [f"{ep['method']}  {ep['path']}" for ep in authed_eps]
    p = write_txt(out_dir, "authed_endpoints.txt", authed_lines,
                  "Authenticated user endpoints — ATHZ-02 Burp XML")
    print(f"    {GREEN}[+]{RESET} {p}  ({len(authed_eps)} endpoint(s))")

    main_lines = [f"{ep['method']}  {ep['path']}" for ep in main_app_eps]
    p = write_txt(out_dir, "main_app_endpoints.txt", main_lines,
                  "Main application endpoints — ATHZ-02 Burp XML (non-auth, non-authed)")
    print(f"    {GREEN}[+]{RESET} {p}  ({len(main_app_eps)} endpoint(s))")

    # ── 7. Stubs ─────────────────────────────────────────────────────────────
    print(f"\n  {CYAN}[7/7] Stubs — third parties + config management{RESET}")
    third_parties = collect_third_parties()
    config_mgmt   = collect_config_mgmt()
    arch["third_parties"] = third_parties
    arch["config_mgmt"]   = config_mgmt

    p = write_txt(out_dir, "third_parties.txt", third_parties or ["# STUB — no data yet"],
                  "Third-party services — STUB")
    print(f"    {YELLOW}[~]{RESET} {p}  (stub — no data)")
    p = write_txt(out_dir, "config_mgmt.txt", config_mgmt or ["# STUB — no data yet"],
                  "Config management — STUB")
    print(f"    {YELLOW}[~]{RESET} {p}  (stub — no data)")

    # ── Master JSON ───────────────────────────────────────────────────────────
    arch["_meta"] = {
        "generated":  datetime.now().isoformat(),
        "tool":       "WSTG-INFO-10 info10_collect.py",
        "sources": {
            "nmap":     nmap_path,
            "conf11":   conf11_path,
            "conf10":   conf10_path,
            "dns":      dns_path,
            "info06":   info06_dir,
            "athz02":   athz02_dir,
        },
    }

    json_path = os.path.join(out_dir, "arch_data.json")
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(arch, f, indent=2)

    print(f"\n  {'─'*50}")
    print(f"  {GREEN}[+] Master JSON → {json_path}{RESET}")
    print(f"\n  {DIM}Next: run info10_diagram.py --data {json_path}{RESET}\n")


if __name__ == "__main__":
    main()
