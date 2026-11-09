#!/usr/bin/env python3
"""
WSTG-SESS-01 — Testing for Session Management Schema
Module 0: sess01_m0_pull_cookies.py

Parses a single-user Burp Suite XML export and extracts all cookie
names and values from every request and response.

Outputs:
  WSTG-SESS-01/outputs/cookies_raw.txt      — NAME=VALUE per line
  WSTG-SESS-01/outputs/cookies_by_name.json — {name: [value, value, ...]}
  WSTG-SESS-01/outputs/cookies_dataset.json — [{request_index, url, name, value}, ...]

The dataset JSON feeds Modules 1–3.

Usage:
  python3 WSTG-SESS-01/utilities/python/sess01_m0_pull_cookies.py \\
      --xml WSTG-SESS-01/inputs/xml/session_walk.xml
"""

import argparse
import base64
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# ANSI
# ---------------------------------------------------------------------------
BOLD  = "\033[1m"
DIM   = "\033[2m"
GREEN = "\033[92m"
CYAN  = "\033[96m"
YELLOW= "\033[93m"
RED   = "\033[91m"
RESET = "\033[0m"

RE_COOKIE_PAIR    = re.compile(r'([^=;\s]+)=([^;]*)')
RE_SET_COOKIE_HDR = re.compile(r'^Set-Cookie\s*:', re.IGNORECASE)
RE_COOKIE_HDR     = re.compile(r'^Cookie\s*:', re.IGNORECASE)


# ---------------------------------------------------------------------------
# Burp XML decode — checks base64="true" attribute before decoding
# ---------------------------------------------------------------------------

def decode_element(elem) -> str:
    if elem is None:
        return ""
    raw = elem.text or ""
    if elem.get("base64") == "true":
        try:
            return base64.b64decode(raw).decode("utf-8", errors="replace")
        except Exception:
            return raw
    return raw


# ---------------------------------------------------------------------------
# Parse Burp XML
# ---------------------------------------------------------------------------

def parse_burp_xml(path: str) -> list[dict]:
    try:
        tree = ET.parse(path)
    except ET.ParseError as e:
        print(f"{RED}[!] XML parse error: {e}{RESET}", file=sys.stderr)
        sys.exit(1)

    items = []
    for idx, item in enumerate(tree.getroot().findall("item")):
        url    = decode_element(item.find("url"))
        method = decode_element(item.find("method")).upper()
        req    = decode_element(item.find("request"))
        resp   = decode_element(item.find("response"))
        status = decode_element(item.find("status"))

        req_head  = req.split("\r\n\r\n", 1)[0]
        resp_head = resp.split("\r\n\r\n", 1)[0]

        items.append({
            "index":        idx,
            "url":          url,
            "method":       method,
            "request_raw":  req,
            "response_raw": resp,
            "req_headers":  req_head,
            "resp_headers": resp_head,
            "status":       status,
        })
    return items


# ---------------------------------------------------------------------------
# Cookie extraction
# ---------------------------------------------------------------------------

def extract_request_cookies(req_headers: str) -> dict[str, str]:
    """Parses Cookie: header from raw request headers."""
    cookies = {}
    for line in req_headers.splitlines():
        if RE_COOKIE_HDR.match(line):
            value_part = line.split(":", 1)[1].strip()
            for m in RE_COOKIE_PAIR.finditer(value_part):
                cookies[m.group(1)] = m.group(2)
    return cookies


def extract_set_cookies(resp_headers: str) -> list[dict]:
    """
    Parses Set-Cookie headers from raw response headers.
    Returns list of {name, value, directives_raw} per Set-Cookie line.
    """
    results = []
    for line in resp_headers.splitlines():
        if RE_SET_COOKIE_HDR.match(line):
            value_part = line.split(":", 1)[1].strip()
            # First pair is name=value; rest are directives
            pairs = value_part.split(";")
            first = pairs[0].strip()
            m = RE_COOKIE_PAIR.match(first)
            if m:
                results.append({
                    "name":           m.group(1),
                    "value":          m.group(2),
                    "directives_raw": value_part,
                    "directives":     [p.strip() for p in pairs[1:]],
                })
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="SESS-01 M0: Extract all cookies from Burp XML walk"
    )
    p.add_argument("--xml",
        default=os.path.join("WSTG-SESS-01", "inputs", "xml", "session_walk.xml"),
        metavar="PATH")
    p.add_argument("--out-dir",
        default=os.path.join("WSTG-SESS-01", "outputs"),
        metavar="DIR")
    args = p.parse_args()

    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"{BOLD} WSTG-SESS-01 M0 — Cookie Puller{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"  XML: {args.xml}\n")

    items = parse_burp_xml(args.xml)
    print(f"  Parsed {len(items)} requests\n")

    os.makedirs(args.out_dir, exist_ok=True)

    cookies_raw_lines  = []
    cookies_by_name    = defaultdict(list)   # {name: [values]}
    cookies_dataset    = []                  # [{index, url, source, name, value, directives}]

    for item in items:
        # Request cookies
        req_cookies = extract_request_cookies(item["req_headers"])
        for name, value in req_cookies.items():
            cookies_raw_lines.append(f"{name}={value}")
            if value not in cookies_by_name[name]:
                cookies_by_name[name].append(value)
            cookies_dataset.append({
                "request_index": item["index"],
                "url":           item["url"],
                "source":        "request",
                "name":          name,
                "value":         value,
                "directives":    [],
            })

        # Response Set-Cookie
        set_cookies = extract_set_cookies(item["resp_headers"])
        for sc in set_cookies:
            cookies_raw_lines.append(f"{sc['name']}={sc['value']}")
            if sc["value"] not in cookies_by_name[sc["name"]]:
                cookies_by_name[sc["name"]].append(sc["value"])
            cookies_dataset.append({
                "request_index": item["index"],
                "url":           item["url"],
                "source":        "set-cookie",
                "name":          sc["name"],
                "value":         sc["value"],
                "directives":    sc["directives"],
                "directives_raw":sc["directives_raw"],
            })

    # Write outputs
    raw_path = os.path.join(args.out_dir, "cookies_raw.txt")
    with open(raw_path, "w") as f:
        f.write("\n".join(sorted(set(cookies_raw_lines))) + "\n")
    print(f"{GREEN}[+] {raw_path}{RESET}  ({len(set(cookies_raw_lines))} unique pairs)")

    by_name_path = os.path.join(args.out_dir, "cookies_by_name.json")
    with open(by_name_path, "w") as f:
        json.dump(dict(cookies_by_name), f, indent=2)
    print(f"{GREEN}[+] {by_name_path}{RESET}  ({len(cookies_by_name)} unique names)")

    dataset_path = os.path.join(args.out_dir, "cookies_dataset.json")
    with open(dataset_path, "w") as f:
        json.dump(cookies_dataset, f, indent=2)
    print(f"{GREEN}[+] {dataset_path}{RESET}  ({len(cookies_dataset)} cookie observations)")

    print(f"\n  Cookie names found:")
    for name, vals in sorted(cookies_by_name.items()):
        print(f"    {CYAN}{name}{RESET} — {len(vals)} unique value(s)")

    print(f"\n  Next: sess01_m1_string_seeker.py --xml {args.xml}")
    print()


if __name__ == "__main__":
    main()
