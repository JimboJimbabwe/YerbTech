#!/usr/bin/env python3
"""
WSTG-CRYP-04 — Testing for Weak Encryption
Script 1: cryp04_gather.py

Extracts parameter values from a Burp Suite XML export across four
sources, saves them to objects_gathered.json for downstream analysis.

Separately ingests a storage_dump.json file (produced by the JS
DevTools snippet) into local_storage.json.

Sources extracted from Burp XML:
  a) URL parameters      (query string)
  b) Body parameters     (form-encoded and JSON top-level strings)
  c) Cookies             (Cookie: request header)
  d) Headers             (all request headers, excluding Cookie line)

Source collected separately (manual JS snippet → DevTools → save file):
  e) Local/Session/IndexedDB storage  → local_storage.json

Output schema (objects_gathered.json):
  {
    "url_params":   [ { "endpoint_index", "url", "method", "name", "value" }, ... ],
    "body_params":  [ { ... } ],
    "cookies":      [ { ... } ],
    "headers":      [ { ... } ],
    "_meta": { "source_xml": str, "generated": str, "total_values": int }
  }

Usage:
  python3 WSTG-CRYP-04/utilities/python/cryp04_gather.py \\
      --xml WSTG-CRYP-04/inputs/xml/cryp04_targets.xml \\
      [--storage WSTG-CRYP-04/inputs/json/storage_dump.json]

Local storage notes:
  1. Open the target application in your browser.
  2. Open DevTools (F12) → Console tab.
  3. Paste and run the storage dumper JS snippet.
  4. Save the downloaded storage_dump.json to:
       WSTG-CRYP-04/inputs/json/storage_dump.json
  5. Re-run this script with --storage pointing to that file.
"""

import argparse
import base64
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import parse_qs, urlparse


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


# ---------------------------------------------------------------------------
# Burp XML helpers
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


def parse_burp_xml(path: str) -> list[dict]:
    try:
        tree = ET.parse(path)
    except (ET.ParseError, FileNotFoundError) as e:
        print(f"{RED}[!] XML error: {e}{RESET}", file=sys.stderr)
        sys.exit(1)

    items = []
    for idx, item in enumerate(tree.getroot().findall("item")):
        url    = decode_element(item.find("url"))
        method = decode_element(item.find("method")).upper()
        req    = decode_element(item.find("request"))

        parts    = req.split("\r\n\r\n", 1)
        req_head = parts[0]
        req_body = parts[1] if len(parts) > 1 else ""

        items.append({
            "index":    idx,
            "url":      url,
            "method":   method,
            "req_head": req_head,
            "req_body": req_body,
        })
    return items


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

RE_COOKIE_HDR = re.compile(r'^Cookie\s*:', re.IGNORECASE)
RE_SKIP_HDRS  = re.compile(r'^(Cookie|Host|Content-Length|Content-Type)\s*:', re.IGNORECASE)
RE_HDR_LINE   = re.compile(r'^([^:]+):\s*(.+)$')


def _base_entry(item: dict, name: str, value: str) -> dict:
    return {
        "endpoint_index": item["index"],
        "url":            item["url"],
        "method":         item["method"],
        "name":           name,
        "value":          value,
        # enrichment fields — populated by cryp04_analyze.py
        "decode_analysis": None,
        "entropy_analysis": None,
    }


def extract_url_params(item: dict) -> list[dict]:
    parsed = urlparse(item["url"])
    results = []
    if parsed.query:
        for key, vals in parse_qs(parsed.query, keep_blank_values=False).items():
            for v in vals:
                results.append(_base_entry(item, key, v))
    return results


def extract_body_params(item: dict) -> list[dict]:
    body = item["req_body"].strip()
    results = []
    if not body:
        return results

    if body.startswith("{") or body.startswith("["):
        # JSON body — extract top-level string values
        try:
            obj = json.loads(body)
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, str):
                        results.append(_base_entry(item, k, v))
        except Exception:
            pass
    elif "=" in body:
        # Form-encoded
        try:
            for key, vals in parse_qs(body, keep_blank_values=False).items():
                for v in vals:
                    results.append(_base_entry(item, key, v))
        except Exception:
            pass

    return results


def extract_cookies(item: dict) -> list[dict]:
    results = []
    for line in item["req_head"].splitlines():
        if RE_COOKIE_HDR.match(line):
            value_part = line.split(":", 1)[1].strip()
            for pair in value_part.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    name, _, value = pair.partition("=")
                    results.append(_base_entry(item, name.strip(), value.strip()))
                elif pair:
                    results.append(_base_entry(item, pair, ""))
    return results


def extract_headers(item: dict) -> list[dict]:
    results = []
    lines = item["req_head"].splitlines()
    # Skip the request line (first line)
    for line in lines[1:]:
        if RE_SKIP_HDRS.match(line):
            continue
        m = RE_HDR_LINE.match(line)
        if m:
            results.append(_base_entry(item, m.group(1).strip(), m.group(2).strip()))
    return results


# ---------------------------------------------------------------------------
# Local storage ingestion
# ---------------------------------------------------------------------------

def ingest_storage_dump(path: str) -> dict:
    """
    Reads a storage_dump.json produced by the DevTools JS snippet and
    returns a normalised dict ready for local_storage.json.
    """
    try:
        with open(path) as f:
            raw = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"{YELLOW}  ⚠  Could not read storage dump: {e}{RESET}")
        return _empty_storage()

    pulled = raw.get("Pulled_Objects", raw)  # handle both wrapped and bare

    return {
        "local_storage":   pulled.get("Local_Storage",   {}),
        "session_storage": pulled.get("Session_Storage", {}),
        "cookies_js":      pulled.get("Cookies",         {}),
        "indexed_db":      pulled.get("IndexedDB",       {}),
        "cache_storage":   pulled.get("Cache_Storage",   {}),
        "_meta": {
            "source_file": path,
            "ingested":    datetime.now().isoformat(),
            "note": (
                "Collected via DevTools JS snippet (storage dumper). "
                "Keys and values are raw strings as seen by JavaScript. "
                "cookies_js reflects document.cookie — may differ from "
                "HttpOnly cookies visible only in Burp XML."
            ),
        },
    }


def _empty_storage() -> dict:
    return {
        "local_storage":   {},
        "session_storage": {},
        "cookies_js":      {},
        "indexed_db":      {},
        "cache_storage":   {},
        "_meta": {
            "source_file": None,
            "ingested":    None,
            "note": (
                "No storage_dump.json provided. To collect browser storage:\n"
                "  1. Open the target app in your browser.\n"
                "  2. Open DevTools (F12) → Console.\n"
                "  3. Paste and run the storage dumper JS snippet.\n"
                "  4. Save storage_dump.json to "
                "WSTG-CRYP-04/inputs/json/storage_dump.json\n"
                "  5. Re-run: cryp04_gather.py --storage <path>"
            ),
        },
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-CRYP-04 Script 1: Parameter gatherer"
    )
    p.add_argument("--xml",
        default=os.path.join("WSTG-CRYP-04", "inputs", "xml", "cryp04_targets.xml"),
        metavar="PATH",
        help="Burp Suite XML export")
    p.add_argument("--storage",
        default=None,
        metavar="PATH",
        help="storage_dump.json from DevTools JS snippet (optional)")
    p.add_argument("--out-dir",
        default=os.path.join("WSTG-CRYP-04", "outputs", "test_outputs"),
        metavar="DIR")
    args = p.parse_args()

    # Default storage path if not given
    default_storage = os.path.join("WSTG-CRYP-04", "inputs", "json", "storage_dump.json")
    storage_path = args.storage or (default_storage if os.path.exists(default_storage) else None)

    width = 65
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD} WSTG-CRYP-04 — Parameter Gatherer{RESET}")
    print(f"{BOLD}{'='*width}{RESET}")
    print(f"  XML     : {args.xml}")
    print(f"  Storage : {storage_path or '(not provided)'}\n")

    items = parse_burp_xml(args.xml)
    print(f"  Parsed {len(items)} request(s)\n")

    os.makedirs(args.out_dir, exist_ok=True)

    url_params   = []
    body_params  = []
    cookies      = []
    headers      = []

    for item in items:
        up = extract_url_params(item)
        bp = extract_body_params(item)
        ck = extract_cookies(item)
        hd = extract_headers(item)

        url_params.extend(up)
        body_params.extend(bp)
        cookies.extend(ck)
        headers.extend(hd)

        idx = item["index"]
        print(
            f"  [{idx:3d}] {item['method']:<7} "
            f"{item['url'][:50]}{'...' if len(item['url'])>50 else ''}"
        )
        print(
            f"         url_params={len(up)}  body={len(bp)}  "
            f"cookies={len(ck)}  headers={len(hd)}"
        )

    total = len(url_params) + len(body_params) + len(cookies) + len(headers)

    gathered = {
        "_meta": {
            "source_xml":    args.xml,
            "generated":     datetime.now().isoformat(),
            "total_values":  total,
            "breakdown": {
                "url_params":  len(url_params),
                "body_params": len(body_params),
                "cookies":     len(cookies),
                "headers":     len(headers),
            },
        },
        "url_params":  url_params,
        "body_params": body_params,
        "cookies":     cookies,
        "headers":     headers,
    }

    gathered_path = os.path.join(args.out_dir, "objects_gathered.json")
    with open(gathered_path, "w") as f:
        json.dump(gathered, f, indent=2)
    print(f"\n{GREEN}[+] objects_gathered.json → {gathered_path}{RESET}")
    print(f"    {total} values across {len(items)} request(s)")
    print(f"    url_params={len(url_params)}  body={len(body_params)}  "
          f"cookies={len(cookies)}  headers={len(headers)}")

    # Local storage
    if storage_path:
        storage_data = ingest_storage_dump(storage_path)
        print(f"\n{GREEN}[+] Storage dump ingested from: {storage_path}{RESET}")
    else:
        storage_data = _empty_storage()
        print(f"\n{YELLOW}[!] No storage_dump.json — local_storage.json written with instructions.{RESET}")

    storage_out = os.path.join(args.out_dir, "local_storage.json")
    with open(storage_out, "w") as f:
        json.dump(storage_data, f, indent=2)
    print(f"{GREEN}[+] local_storage.json     → {storage_out}{RESET}")

    print(f"\n  Next: cryp04_analyze.py --gathered {gathered_path}")
    print()


if __name__ == "__main__":
    main()
