#!/usr/bin/env python3
"""
WSTG-CRYP-04 — Testing for Weak Encryption
Script 3: case2_cryp04.py

Scans a Burp Suite XML export (entropy_targs.xml) for UUID patterns
in all locations where they commonly appear:
  - URL paths and path segments
  - Query string parameter values
  - POST body values (form-encoded and JSON top-level)
  - Cookie values
  - Request header values
  - Response bodies (if present in Burp XML)

Deduplicates UUIDs and writes them to inputs/data/UUIDs.txt, one
per line, for consumption by here_place_UUID.py.

Also prints a summary of where each UUID was found for context.

Inputs:
  WSTG-CRYP-04/inputs/xml/entropy_targs.xml

Outputs:
  WSTG-CRYP-04/inputs/data/UUIDs.txt   (one UUID per line, deduplicated)
  WSTG-CRYP-04/outputs/test_outputs/uuid_locations.json  (context map)

Usage:
  python3 WSTG-CRYP-04/utilities/python/case2_cryp04.py \\
      [--xml WSTG-CRYP-04/inputs/xml/entropy_targs.xml]
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
# UUID regex — matches standard hyphenated format (case-insensitive)
# ---------------------------------------------------------------------------
UUID_RE = re.compile(
    r'\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b',
    re.IGNORECASE
)


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
        url      = decode_element(item.find("url"))
        method   = decode_element(item.find("method")).upper()
        req      = decode_element(item.find("request"))
        resp     = decode_element(item.find("response"))

        parts    = req.split("\r\n\r\n", 1)
        req_head = parts[0]
        req_body = parts[1] if len(parts) > 1 else ""

        resp_parts = resp.split("\r\n\r\n", 1) if resp else ["", ""]
        resp_body  = resp_parts[1] if len(resp_parts) > 1 else ""

        items.append({
            "index":    idx,
            "url":      url,
            "method":   method,
            "req_head": req_head,
            "req_body": req_body,
            "resp_body": resp_body,
        })
    return items


# ---------------------------------------------------------------------------
# UUID extraction
# ---------------------------------------------------------------------------

def find_uuids_in(text: str, location_label: str, endpoint_index: int, url: str) -> list[dict]:
    """Finds all UUIDs in text, returns list of occurrence dicts."""
    found = []
    for m in UUID_RE.finditer(text):
        found.append({
            "uuid":             m.group(0).lower(),
            "location":         location_label,
            "endpoint_index":   endpoint_index,
            "url":              url,
            "context":          text[max(0, m.start()-30):m.end()+30].replace("\n", " "),
        })
    return found


def extract_uuids_from_item(item: dict) -> list[dict]:
    idx = item["index"]
    url = item["url"]
    hits = []

    # URL (path + query)
    hits.extend(find_uuids_in(url, "url", idx, url))

    # Request headers (excluding Cookie)
    req_head_lines = item["req_head"].splitlines()
    for line in req_head_lines[1:]:  # skip request line
        if re.match(r'^Cookie\s*:', line, re.IGNORECASE):
            # Cookies get their own label
            hits.extend(find_uuids_in(line, "cookie_header", idx, url))
        else:
            hits.extend(find_uuids_in(line, "request_header", idx, url))

    # Request body
    body = item["req_body"].strip()
    if body:
        hits.extend(find_uuids_in(body, "request_body", idx, url))

    # Response body
    if item["resp_body"]:
        hits.extend(find_uuids_in(item["resp_body"], "response_body", idx, url))

    return hits


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-CRYP-04 Script 3: UUID extractor from Burp XML"
    )
    p.add_argument("--xml",
        default=os.path.join("WSTG-CRYP-04", "inputs", "xml", "entropy_targs.xml"),
        metavar="PATH")
    p.add_argument("--out-dir",
        default=os.path.join("WSTG-CRYP-04", "outputs", "test_outputs"),
        metavar="DIR")
    p.add_argument("--uuid-out",
        default=os.path.join("WSTG-CRYP-04", "inputs", "data", "UUIDs.txt"),
        metavar="PATH",
        help="Output path for UUID list (consumed by here_place_UUID.py)")
    args = p.parse_args()

    width = 65
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD} WSTG-CRYP-04 — UUID Extractor{RESET}")
    print(f"{BOLD}{'='*width}{RESET}")
    print(f"  XML : {args.xml}\n")

    items = parse_burp_xml(args.xml)
    print(f"  Parsed {len(items)} request(s)\n")

    all_hits = []
    for item in items:
        hits = extract_uuids_from_item(item)
        if hits:
            for h in hits:
                print(
                    f"  [{h['endpoint_index']:3d}] {CYAN}{h['uuid']}{RESET}  "
                    f"{DIM}{h['location']}{RESET}"
                )
            all_hits.extend(hits)

    if not all_hits:
        print(f"  {YELLOW}No UUIDs found in the XML.{RESET}\n")
        print(f"  Check that entropy_targs.xml contains requests with UUIDs")
        print(f"  in paths, query strings, cookies, headers, or bodies.\n")
        sys.exit(0)

    # Deduplicate — preserve order of first occurrence
    seen = {}
    for h in all_hits:
        u = h["uuid"]
        if u not in seen:
            seen[u] = h

    unique_uuids = list(seen.keys())
    print(f"\n  {len(all_hits)} occurrence(s) → {len(unique_uuids)} unique UUID(s)")

    # Write UUIDs.txt
    os.makedirs(os.path.dirname(args.uuid_out), exist_ok=True)
    with open(args.uuid_out, "w") as f:
        f.write("\n".join(unique_uuids) + "\n")
    print(f"\n{GREEN}[+] UUIDs.txt → {args.uuid_out}{RESET}")

    # Write location context JSON
    os.makedirs(args.out_dir, exist_ok=True)
    locations_path = os.path.join(args.out_dir, "uuid_locations.json")
    with open(locations_path, "w") as f:
        json.dump({
            "_meta": {
                "source_xml":    args.xml,
                "generated":     datetime.now().isoformat(),
                "total_hits":    len(all_hits),
                "unique_uuids":  len(unique_uuids),
            },
            "occurrences": all_hits,
            "unique":      {u: seen[u] for u in unique_uuids},
        }, f, indent=2)
    print(f"{GREEN}[+] uuid_locations.json → {locations_path}{RESET}")

    print(f"\n  Next: here_place_UUID.py --uuids {args.uuid_out}")
    print()


if __name__ == "__main__":
    main()
