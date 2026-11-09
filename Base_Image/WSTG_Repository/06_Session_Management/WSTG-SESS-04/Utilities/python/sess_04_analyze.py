#!/usr/bin/env python3
"""
WSTG-SESS-04 — Testing for Exposed Session Variables
Script: sess_04_analyze.py

Reads a Burp Suite proxy history XML export (multiple requests/responses)
and searches each item for sensitive environment variable names pulled from
svc_env_grab.py's output.

Five locations are searched per item:
  1. Request headers
  2. Request cookies
  3. Request URL (query string + path)
  4. Request body data
  5. Response HTML/body data

A match means a variable name from the wordlist was found in that location,
whether as a key, a value prefix, or an inline string (e.g. SESSION_TOKEN=,
Authorization: Bearer ..., ?api_key=..., etc.)

Output JSON schema:
  {
    "Findings": {
      "Exposed variables": {
        "Endpoint[N]": {
          "PATH": "/api/v1/...",
          "Headers":         [...],
          "Cookies":         [...],
          "Url":             [...],
          "Body data":       [...],
          "Html response data": [...]
        }
      }
    }
  }

Usage:
  python3 WSTG-SESS-04/utilities/python/sess_04_analyze.py \\
      --proxy   WSTG-SESS-04/inputs/xml/proxy_history.xml \\
      [--wordlist WSTG-SESS-04/inputs/data/wordlist.txt]

Outputs:
  WSTG-SESS-04/outputs/test_outputs/json_SESS04.json
  WSTG-SESS-04/outputs/test_outputs/markdown_SESS04.md
"""

import argparse
import base64
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote


# ---------------------------------------------------------------------------
# ANSI
# ---------------------------------------------------------------------------
BOLD    = "\033[1m"
DIM     = "\033[2m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
RESET   = "\033[0m"

LOC_COLOR = {
    "Headers":            CYAN,
    "Cookies":            MAGENTA,
    "Url":                YELLOW,
    "Body data":          GREEN,
    "Html response data": RED,
}


# ---------------------------------------------------------------------------
# Default wordlist — common session / secret variable names
# Used when no --wordlist is provided.
# ---------------------------------------------------------------------------

DEFAULT_WORDLIST = [
    "SESSION", "SESSION_ID", "SESSION_TOKEN", "SESSION_KEY",
    "SESSIONID", "SESS_ID",
    "JWT", "JWT_SECRET", "JWT_KEY", "JWT_TOKEN",
    "TOKEN", "ACCESS_TOKEN", "REFRESH_TOKEN", "AUTH_TOKEN",
    "API_KEY", "API_SECRET", "APIKEY",
    "SECRET", "APP_SECRET", "SECRET_KEY", "APP_KEY",
    "PASSWORD", "PASSWD", "DB_PASSWORD",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "OAUTH", "CLIENT_SECRET", "OAUTH_TOKEN",
    "PRIVATE_KEY", "SIGNING_KEY", "ENCRYPTION_KEY",
    "AUTHORIZATION", "BEARER",
    "X-API-KEY", "X-AUTH-TOKEN", "X-SESSION-TOKEN",
    "CSRF", "XSRF", "CSRF_TOKEN", "XSRF_TOKEN",
    "COOKIE", "AUTH",
]


# ---------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------

def decode_element(el) -> str:
    if el is None:
        return ""
    if el.get("base64") == "true":
        try:
            return base64.b64decode(el.text or "").decode("utf-8", errors="replace")
        except Exception:
            return ""
    return (el.text or "").strip()


def split_headers_and_body(raw: str) -> tuple[str, str]:
    """Split raw HTTP message into headers section and body."""
    sep = raw.find("\r\n\r\n")
    if sep == -1:
        sep = raw.find("\n\n")
        if sep == -1:
            return raw, ""
        return raw[:sep], raw[sep + 2:]
    return raw[:sep], raw[sep + 4:]


def extract_cookies_from_header(headers_raw: str) -> str:
    """Pull Cookie: or Set-Cookie: header lines."""
    lines = []
    for line in headers_raw.splitlines():
        low = line.lower()
        if low.startswith("cookie:") or low.startswith("set-cookie:"):
            lines.append(line)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Wordlist loader
# ---------------------------------------------------------------------------

def load_wordlist(path: str) -> list[str]:
    if not path or not os.path.exists(path):
        print(f"  {YELLOW}[!] Wordlist not found at {path} — using built-in defaults{RESET}")
        return DEFAULT_WORDLIST
    with open(path, encoding="utf-8") as f:
        terms = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    if not terms:
        print(f"  {YELLOW}[!] Wordlist empty — using built-in defaults{RESET}")
        return DEFAULT_WORDLIST
    print(f"  {DIM}Wordlist: {len(terms)} terms from {path}{RESET}")
    return terms


def build_search_pattern(wordlist: list[str]) -> re.Pattern:
    """
    Build a single compiled regex that matches any term from the wordlist
    as a whole word (case-insensitive, boundary-aware).
    """
    escaped = [re.escape(t) for t in wordlist]
    pattern = '|'.join(r'(?<![A-Za-z0-9_])' + e + r'(?![A-Za-z0-9_])' for e in escaped)
    return re.compile(pattern, re.IGNORECASE)


# ---------------------------------------------------------------------------
# Per-location search helpers
# ---------------------------------------------------------------------------

def find_matches_in_text(text: str, pattern: re.Pattern, context_chars: int = 60) -> list[str]:
    """
    Find all matches of pattern in text.
    Returns a list of short context snippets, e.g.:
      "SESSION_TOKEN=eyJhb..." (at offset 142)
    """
    results = []
    for m in pattern.finditer(text):
        start = max(0, m.start() - 10)
        end   = min(len(text), m.end() + context_chars)
        snippet = text[start:end].replace("\n", " ").replace("\r", "")
        results.append(snippet.strip())
    return results


def search_headers(headers_raw: str, pattern: re.Pattern) -> list[str]:
    # Skip the request line (first line), search the rest
    lines = headers_raw.splitlines()
    header_block = "\n".join(lines[1:]) if lines else headers_raw
    return find_matches_in_text(header_block, pattern)


def search_cookies(headers_raw: str, pattern: re.Pattern) -> list[str]:
    cookie_lines = extract_cookies_from_header(headers_raw)
    if not cookie_lines:
        return []
    return find_matches_in_text(cookie_lines, pattern)


def search_url(url: str, pattern: re.Pattern) -> list[str]:
    if not url:
        return []
    # Search both the raw URL and decoded form
    decoded = unquote(url)
    combined = url + " " + decoded if decoded != url else url
    return find_matches_in_text(combined, pattern)


def search_body(body: str, pattern: re.Pattern) -> list[str]:
    if not body:
        return []
    return find_matches_in_text(body, pattern)


# ---------------------------------------------------------------------------
# XML parser — proxy history format
# ---------------------------------------------------------------------------

def parse_proxy_xml(xml_path: str) -> list[dict]:
    """
    Parse Burp proxy history XML.
    Each <item> contains <url>, <request>, <response>, etc.
    Returns list of dicts with url, request_raw, response_raw.
    """
    try:
        tree = ET.parse(xml_path)
    except FileNotFoundError:
        print(f"{RED}[!] Proxy XML not found: {xml_path}{RESET}", file=sys.stderr)
        sys.exit(1)
    except ET.ParseError as e:
        print(f"{RED}[!] XML parse error: {e}{RESET}", file=sys.stderr)
        sys.exit(1)

    root = tree.getroot()
    # Support both <items> root and bare item list
    if root.tag == "items":
        item_list = root.findall("item")
    else:
        item_list = root.findall(".//item")

    results = []
    for item in item_list:
        url          = decode_element(item.find("url"))
        request_raw  = decode_element(item.find("request"))
        response_raw = decode_element(item.find("response"))

        results.append({
            "url":          url,
            "request_raw":  request_raw,
            "response_raw": response_raw,
        })

    return results


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def analyze_items(items: list[dict], pattern: re.Pattern) -> list[dict]:
    """
    For each item, search across all 5 locations.
    Returns only items that have at least one match.
    """
    findings = []
    for item in items:
        url          = item["url"]
        request_raw  = item["request_raw"]
        response_raw = item["response_raw"]

        req_headers, req_body   = split_headers_and_body(request_raw)
        _resp_headers, resp_body = split_headers_and_body(response_raw)

        header_hits  = search_headers(req_headers, pattern)
        cookie_hits  = search_cookies(req_headers, pattern)
        url_hits     = search_url(url, pattern)
        body_hits    = search_body(req_body, pattern)
        resp_hits    = search_body(resp_body, pattern)

        if not any([header_hits, cookie_hits, url_hits, body_hits, resp_hits]):
            continue

        # Extract path from URL
        try:
            path = urlparse(url).path or url
        except Exception:
            path = url

        findings.append({
            "path":                path,
            "url":                 url,
            "Headers":             header_hits,
            "Cookies":             cookie_hits,
            "Url":                 url_hits,
            "Body data":           body_hits,
            "Html response data":  resp_hits,
        })

    return findings


# ---------------------------------------------------------------------------
# Output builders
# ---------------------------------------------------------------------------

def build_json(findings: list[dict], meta: dict) -> dict:
    exposed = {}
    for i, f in enumerate(findings, start=1):
        key = f"Endpoint[{i}]"
        exposed[key] = {
            "PATH":                f["path"],
            "Headers":             f["Headers"],
            "Cookies":             f["Cookies"],
            "Url":                 f["Url"],
            "Body data":           f["Body data"],
            "Html response data":  f["Html response data"],
        }

    return {
        "_meta":    meta,
        "Findings": {
            "Exposed variables": exposed,
        },
    }


def build_markdown(findings: list[dict], meta: dict) -> str:
    lines = []
    lines.append("# WSTG-SESS-04 — Exposed Session Variables")
    lines.append("")
    lines.append(f"**Generated:** {meta['generated']}  ")
    lines.append(f"**Proxy XML:** `{meta['proxy_xml']}`  ")
    lines.append(f"**Wordlist:**  `{meta['wordlist']}`  ")
    lines.append(f"**Items scanned:** {meta['items_scanned']}  ")
    lines.append(f"**Endpoints with findings:** {len(findings)}  ")
    lines.append("")

    if not findings:
        lines.append("No exposed session variables found in proxy history.")
        return "\n".join(lines)

    LOCATIONS = ["Headers", "Cookies", "Url", "Body data", "Html response data"]

    for i, f in enumerate(findings, start=1):
        lines.append(f"---")
        lines.append(f"## Endpoint[{i}] — `{f['path']}`")
        lines.append("")
        lines.append(f"**URL:** `{f['url']}`  ")
        lines.append("")

        any_hit = False
        for loc in LOCATIONS:
            hits = f[loc]
            if hits:
                any_hit = True
                lines.append(f"### {loc}")
                lines.append("")
                for h in hits:
                    lines.append(f"- `{h}`")
                lines.append("")

        if not any_hit:
            lines.append("*(no matches)*")
            lines.append("")

    lines.append("---")
    lines.append("*Generated by sess_04_analyze.py — WSTG-SESS-04*")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-SESS-04 proxy history exposed session variable analyzer"
    )
    p.add_argument("--proxy",
        default=os.path.join("WSTG-SESS-04", "inputs", "xml", "proxy_history.xml"),
        metavar="PATH",
        help="Burp proxy history XML export")
    p.add_argument("--wordlist",
        default=os.path.join("WSTG-SESS-04", "inputs", "data", "wordlist.txt"),
        metavar="PATH",
        help="Flat wordlist from svc_env_grab.py (default: WSTG-SESS-04/inputs/data/wordlist.txt)")
    p.add_argument("--json-out",
        default=os.path.join("WSTG-SESS-04", "outputs", "test_outputs", "json_SESS04.json"),
        metavar="PATH")
    p.add_argument("--md-out",
        default=os.path.join("WSTG-SESS-04", "outputs", "test_outputs", "markdown_SESS04.md"),
        metavar="PATH")
    args = p.parse_args()

    width = 65
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD}  WSTG-SESS-04 — Exposed Session Variables Analysis{RESET}")
    print(f"{BOLD}{'='*width}{RESET}\n")
    print(f"  Proxy XML : {args.proxy}")
    print(f"  Wordlist  : {args.wordlist}\n")

    wordlist = load_wordlist(args.wordlist)
    pattern  = build_search_pattern(wordlist)

    print(f"  {BOLD}Parsing proxy history...{RESET}")
    items = parse_proxy_xml(args.proxy)
    print(f"  {DIM}{len(items)} items loaded{RESET}\n")

    print(f"  {BOLD}Scanning across 5 locations per item...{RESET}")
    print(f"  {DIM}Locations: Headers | Cookies | URL | Body data | HTML response data{RESET}\n")
    findings = analyze_items(items, pattern)

    # ── Terminal summary ─────────────────────────────────────────────────────
    LOCATIONS = ["Headers", "Cookies", "Url", "Body data", "Html response data"]
    loc_counts = {loc: 0 for loc in LOCATIONS}
    for f in findings:
        for loc in LOCATIONS:
            if f[loc]:
                loc_counts[loc] += 1

    print(f"  {'─'*50}")
    print(f"  Items scanned   : {len(items)}")
    print(f"  Endpoints hit   : {len(findings)}")
    print()

    for loc in LOCATIONS:
        c = loc_counts[loc]
        if c:
            col = LOC_COLOR.get(loc, RESET)
            print(f"  {col}{loc:<26}{RESET}  {c} endpoint(s)")

    # Print first handful of findings inline
    if findings:
        print(f"\n  {'─'*50}")
        for i, f in enumerate(findings[:10], start=1):
            print(f"  {BOLD}Endpoint[{i}]{RESET}  {f['path']}")
            for loc in LOCATIONS:
                hits = f[loc]
                if hits:
                    col = LOC_COLOR.get(loc, DIM)
                    print(f"    {col}{loc:<26}{RESET}  {hits[0][:60]}")
                    if len(hits) > 1:
                        print(f"    {DIM}{'':26}  (+{len(hits)-1} more){RESET}")
        if len(findings) > 10:
            print(f"\n  {DIM}... {len(findings)-10} more endpoint(s) in output files{RESET}")

    # ── Write outputs ────────────────────────────────────────────────────────
    os.makedirs(os.path.dirname(args.json_out), exist_ok=True)
    os.makedirs(os.path.dirname(args.md_out),   exist_ok=True)

    meta = {
        "generated":       datetime.now().isoformat(),
        "proxy_xml":       args.proxy,
        "wordlist":        args.wordlist,
        "wordlist_terms":  len(wordlist),
        "items_scanned":   len(items),
        "endpoints_hit":   len(findings),
        "location_counts": loc_counts,
    }

    json_out = build_json(findings, meta)
    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(json_out, f, indent=2)

    md_out = build_markdown(findings, meta)
    with open(args.md_out, "w", encoding="utf-8") as f:
        f.write(md_out)

    print(f"\n  {'─'*50}")
    print(f"  {GREEN}json_SESS04.json{RESET}     →  {args.json_out}")
    print(f"  {GREEN}markdown_SESS04.md{RESET}   →  {args.md_out}\n")


if __name__ == "__main__":
    main()
