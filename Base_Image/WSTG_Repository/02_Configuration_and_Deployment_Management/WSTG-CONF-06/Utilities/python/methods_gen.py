#!/usr/bin/env python3
"""
WSTG-CONF-06 — HTTP Methods: URL + Wordlist Generator
Step 1 of 3

Extracts all unique URLs from a Burp Suite XML export (sitemap),
writes them to a curl target list, and writes the safe methods
wordlist (OPTIONS, TRACE, HEAD, CONNECT — never PUT/DELETE/PATCH).

Outputs:
  -o / --output   → curl target URL list  (default: inputs/wordlists/curl_urls.txt)
  --methods-out   → safe methods wordlist (default: inputs/wordlists/methods.txt)

Usage:
  python3 methods_gen.py --xml-file inputs/xml/subfolder/export.xml
  python3 methods_gen.py --xml-file inputs/xml/export.xml -o inputs/wordlists/curl_urls.txt
"""

import argparse
import base64
import sys
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse, urlunparse


# ---------------------------------------------------------------------------
# Safe methods only — PUT/DELETE/PATCH are NEVER included here.
# Testing dangerous write methods is always a manual, controlled operation.
# ---------------------------------------------------------------------------
SAFE_TEST_METHODS = [
    "OPTIONS",
    "TRACE",
    "HEAD",
    "CONNECT",
]

# Auth-related path segments — used to flag authentication pathways
AUTH_PATH_KEYWORDS = [
    "login", "logout", "signin", "signout", "sign-in", "sign-out",
    "auth", "authenticate", "authentication",
    "oauth", "oauth2", "oidc",
    "sso", "saml",
    "token", "refresh", "revoke",
    "password", "reset-password", "forgot-password",
    "register", "signup", "sign-up",
    "account", "profile",
    "session", "sessions",
    "mfa", "2fa", "totp",
]

_AUTH_RE = re.compile(
    '|'.join(re.escape(kw) for kw in AUTH_PATH_KEYWORDS),
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Burp XML helpers
# ---------------------------------------------------------------------------

def decode_element(elem) -> str:
    """Safely decode a Burp XML element, respecting the base64 attribute."""
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


def extract_url(item) -> str:
    """Extract the URL from a Burp item, falling back to request line parse."""
    url_elem = item.find('./url')
    if url_elem is not None and url_elem.text:
        return url_elem.text.strip()

    # Fallback: reconstruct from host + request first line
    host_elem = item.find('./host')
    req_text = decode_element(item.find('./request'))
    if host_elem is not None and req_text:
        first_line = req_text.split('\n', 1)[0].strip()
        # e.g. "GET /path HTTP/1.1"
        parts = first_line.split(' ')
        if len(parts) >= 2:
            path = parts[1]
            protocol = item.find('./protocol')
            scheme = (protocol.text or "https").lower() if protocol is not None else "https"
            host = host_elem.text.strip() if host_elem.text else ""
            if host:
                return f"{scheme}://{host}{path}"
    return ""


def normalise_url(url: str) -> str:
    """Strip query strings and fragments; keep scheme+host+path only."""
    try:
        parsed = urlparse(url)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
    except Exception:
        return url


def is_auth_url(url: str) -> bool:
    parsed = urlparse(url)
    return bool(_AUTH_RE.search(parsed.path))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description='CONF-06 Step 1: Extract URLs from Burp XML and generate method wordlist'
    )
    p.add_argument(
        '--xml-file', '-x', required=True,
        help='Path to Burp Suite XML export'
    )
    p.add_argument(
        '-o', '--output',
        default='inputs/wordlists/curl_urls.txt',
        help='Output path for curl URL list (default: inputs/wordlists/curl_urls.txt)'
    )
    p.add_argument(
        '--methods-out',
        default='inputs/wordlists/methods.txt',
        help='Output path for safe methods wordlist (default: inputs/wordlists/methods.txt)'
    )
    p.add_argument(
        '--include-query', action='store_true',
        help='Keep query strings in URLs (default: strip them)'
    )
    p.add_argument(
        '--auth-only', action='store_true',
        help='Only output URLs that match authentication path patterns'
    )
    p.add_argument(
        '--auth-flag', action='store_true',
        help='Tag auth-pathway URLs with a comment in the output file'
    )
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    print("=" * 60)
    print("CONF-06 — URL & Methods Generator")
    print("=" * 60)

    # Parse XML
    items = parse_burp_xml(args.xml_file)
    print(f"[*] Found {len(items)} Burp items")

    # Extract URLs
    raw_urls = []
    for item in items:
        url = extract_url(item)
        if url:
            raw_urls.append(url)

    print(f"[*] Extracted {len(raw_urls)} URLs (before dedup)")

    # Normalise and deduplicate
    seen = set()
    unique_urls = []
    for url in raw_urls:
        normalised = url if args.include_query else normalise_url(url)
        if normalised and normalised not in seen:
            seen.add(normalised)
            unique_urls.append(normalised)

    print(f"[*] Unique URLs after normalisation: {len(unique_urls)}")

    # Filter to auth paths if requested
    if args.auth_only:
        unique_urls = [u for u in unique_urls if is_auth_url(u)]
        print(f"[*] Auth-pathway URLs only: {len(unique_urls)}")

    # Separate auth vs non-auth for flagging
    auth_urls = set(u for u in unique_urls if is_auth_url(u))
    print(f"[*] Authentication pathway URLs detected: {len(auth_urls)}")

    # ---------------------------------------------------------------------------
    # Write curl URL list
    # ---------------------------------------------------------------------------
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, 'w') as f:
        f.write("# CONF-06 curl target URLs\n")
        f.write(f"# Source: {args.xml_file}\n")
        f.write(f"# Total: {len(unique_urls)} URLs\n")
        f.write(f"# Auth pathways: {len(auth_urls)}\n")
        f.write("# NOTE: Use with methods_test.py — safe methods only (OPTIONS/TRACE/HEAD/CONNECT)\n")
        f.write("# PUT/DELETE/PATCH are NEVER tested automatically — always by hand.\n\n")

        if args.auth_flag:
            for url in sorted(unique_urls):
                tag = "  # [AUTH PATHWAY]" if url in auth_urls else ""
                f.write(url + tag + '\n')
        else:
            for url in sorted(unique_urls):
                f.write(url + '\n')

    print(f"[+] curl URL list → {args.output} ({len(unique_urls)} URLs)")

    # ---------------------------------------------------------------------------
    # Write methods wordlist
    # ---------------------------------------------------------------------------
    os.makedirs(os.path.dirname(os.path.abspath(args.methods_out)), exist_ok=True)
    with open(args.methods_out, 'w') as f:
        f.write("# CONF-06 safe HTTP methods for automated testing\n")
        f.write("# DO NOT ADD: PUT, DELETE, PATCH, POST\n")
        f.write("# Write methods (PUT/DELETE/PATCH) are ALWAYS tested manually.\n")
        f.write("# OPTIONS: discover what the server advertises as allowed\n")
        f.write("# TRACE:   check if cross-site tracing (XST) is possible\n")
        f.write("# HEAD:    safe variant of GET — reveals headers without body\n")
        f.write("# CONNECT: tunnelling — should be blocked on app servers\n\n")
        for method in SAFE_TEST_METHODS:
            f.write(method + '\n')

    print(f"[+] Methods wordlist → {args.methods_out} ({len(SAFE_TEST_METHODS)} methods)")

    # Summary
    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Burp items parsed:     {len(items)}")
    print(f"  Unique URLs:           {len(unique_urls)}")
    print(f"  Auth pathway URLs:     {len(auth_urls)}")
    print(f"  Methods in wordlist:   {', '.join(SAFE_TEST_METHODS)}")
    print(f"  curl URL list:         {args.output}")
    print(f"  Methods wordlist:      {args.methods_out}")
    print(f"\n  ⚠  PUT/DELETE/PATCH are never run automatically.")
    print(f"     Test dangerous write methods by hand only.")


if __name__ == "__main__":
    main()
