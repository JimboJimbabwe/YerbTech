#!/usr/bin/env python3
"""
WSTG-CONF-11 — Cloud Storage Scanner

Reads a Burp Suite XML export and scans EVERY part of each item
(request URL, request headers, request body, response status line,
response headers, response body — including base64-decoded content)
for cloud storage indicator strings defined in cloud_strings.json.

Categorizes hits by provider (AWS S3, Azure Blob, GCS, etc.) and
produces a findings report showing exactly which endpoint, method,
and file matched, which strings were found, and in which field.

Usage:
  python3 conf11_cloud_storage.py \\
      --xml  inputs/XML/subfolder/export.xml \\
      --strings inputs/Data/cloud_strings.json \\
      -o outputs/test_output/test_findings.txt

Flags:
  -x / --xml        Burp XML export (required)
  -s / --strings    cloud_strings.json (default: inputs/Data/cloud_strings.json)
  -o / --output     Output report (default: outputs/test_output/test_findings.txt)
  --min-hits N      Only report endpoints with at least N matches (default: 1)
  --category CAT    Filter to a specific category ID (e.g. aws_s3, azure_blob)
"""

import argparse
import base64
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Burp XML helpers
# ---------------------------------------------------------------------------

def decode_element(elem) -> str:
    """Decode a Burp XML element, handling base64="true" attribute."""
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
    """Extract method and path from the HTTP request first line."""
    first = request_text.split('\n', 1)[0].strip()
    parts = first.split(' ')
    if len(parts) >= 2:
        return parts[0], parts[1]
    return "UNKNOWN", "/"


def split_headers_body(text: str) -> tuple:
    """Split an HTTP message into headers block and body."""
    # Handle both \r\n and \n
    normalized = text.replace('\r\n', '\n')
    if '\n\n' in normalized:
        headers_part, body = normalized.split('\n\n', 1)
    else:
        headers_part = normalized
        body = ""
    return headers_part, body


def parse_headers(headers_text: str) -> list:
    """Parse header lines into (name_lower, value) tuples, skipping status line."""
    lines = headers_text.split('\n')
    headers = []
    for line in lines[1:]:   # skip status/request line
        if ':' in line:
            name, _, value = line.partition(':')
            headers.append((name.strip().lower(), value.strip()))
    return headers


def parse_cookies(headers: list) -> str:
    """Extract cookie string from parsed headers."""
    cookies = []
    for name, value in headers:
        if name in ('cookie', 'set-cookie'):
            cookies.append(value)
    return ' | '.join(cookies)


# ---------------------------------------------------------------------------
# String loading
# ---------------------------------------------------------------------------

def load_strings(strings_path: str, category_filter: str = None) -> list:
    """
    Load cloud_strings.json and return a flat list of:
      {category_id, category_name, value, note}
    Optionally filtered by category_id.
    """
    try:
        with open(strings_path) as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"[!] Strings file not found: {strings_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON in {strings_path}: {e}")
        sys.exit(1)

    entries = []
    for cat in data.get('categories', []):
        cat_id = cat.get('id', '')
        cat_name = cat.get('name', cat_id)
        if category_filter and cat_id != category_filter:
            continue
        for s in cat.get('strings', []):
            entries.append({
                'category_id':   cat_id,
                'category_name': cat_name,
                'value':         s.get('value', ''),
                'note':          s.get('note', ''),
            })

    if not entries:
        if category_filter:
            print(f"[!] No strings found for category: {category_filter}")
        else:
            print(f"[!] No strings found in {strings_path}")
        sys.exit(1)

    return entries


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

FIELD_NAMES = [
    'request_url',
    'request_headers',
    'request_body',
    'request_cookies',
    'response_status',
    'response_headers',
    'response_body',
]


def scan_field(text: str, field: str, entries: list) -> list:
    """
    Scan a single text field for all string entries.
    Returns list of {field, value, category_id, category_name, note} dicts.
    """
    hits = []
    seen = set()
    for e in entries:
        val = e['value']
        if val and val.lower() in text.lower():
            key = (field, val, e['category_id'])
            if key not in seen:
                seen.add(key)
                hits.append({
                    'field':         field,
                    'value':         val,
                    'category_id':   e['category_id'],
                    'category_name': e['category_name'],
                    'note':          e['note'],
                })
    return hits


def scan_item(index: int, item, entries: list) -> dict | None:
    """
    Scan all fields of a single Burp item.
    Returns a result dict or None if no hits.
    """
    # --- Extract URL ---
    url_elem = item.find('./url')
    url = ""
    if url_elem is not None and url_elem.text:
        url = url_elem.text.strip()

    # --- Extract and decode request ---
    request_text = decode_element(item.find('./request'))
    req_method, req_path = parse_request_line(request_text)
    req_headers_text, req_body = split_headers_body(request_text)
    req_headers = parse_headers(req_headers_text)
    req_cookies = parse_cookies(req_headers)

    # Fallback URL from request
    if not url and req_path:
        host_elem = item.find('./host')
        host = host_elem.text.strip() if host_elem is not None and host_elem.text else "unknown"
        protocol_elem = item.find('./protocol')
        protocol = protocol_elem.text.strip() if protocol_elem is not None and protocol_elem.text else "https"
        url = f"{protocol}://{host}{req_path}"

    # --- Extract and decode response ---
    response_text = decode_element(item.find('./response'))
    resp_headers_text, resp_body = split_headers_body(response_text)
    resp_headers = parse_headers(resp_headers_text)

    # Status line is first line of response
    resp_status_line = response_text.split('\n', 1)[0].strip() if response_text else ""

    # Status code
    status_elem = item.find('./status')
    status_code = status_elem.text.strip() if status_elem is not None and status_elem.text else ""

    # --- Parse URL for path ---
    try:
        parsed = urlparse(url)
        path = parsed.path or req_path
        host_display = parsed.netloc or "unknown"
    except Exception:
        path = req_path
        host_display = "unknown"

    # --- File name ---
    file_elem = item.find('..')   # we can't easily get filename from item alone
    # We'll pass filename from the caller

    # --- Scan all fields ---
    all_hits = []

    # Request URL
    all_hits.extend(scan_field(url, 'request_url', entries))

    # Request headers (scan as full text block)
    all_hits.extend(scan_field(req_headers_text, 'request_headers', entries))

    # Request body
    if req_body:
        all_hits.extend(scan_field(req_body, 'request_body', entries))

    # Request cookies
    if req_cookies:
        all_hits.extend(scan_field(req_cookies, 'request_cookies', entries))

    # Response status line
    if resp_status_line:
        all_hits.extend(scan_field(resp_status_line, 'response_status', entries))

    # Response headers
    if resp_headers_text:
        all_hits.extend(scan_field(resp_headers_text, 'response_headers', entries))

    # Response body
    if resp_body:
        all_hits.extend(scan_field(resp_body, 'response_body', entries))

    if not all_hits:
        return None

    # Group hits by category
    by_category = defaultdict(list)
    for h in all_hits:
        by_category[h['category_id']].append(h)

    return {
        'index':       index,
        'method':      req_method,
        'url':         url,
        'path':        path,
        'host':        host_display,
        'status_code': status_code,
        'hits':        all_hits,
        'by_category': dict(by_category),
        'total_hits':  len(all_hits),
    }


# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------

CATEGORY_DISPLAY = {
    'aws_s3':       'AWS S3',
    'aws_regions':  'AWS Regions',
    'aws_other':    'AWS Other Services',
    'azure_blob':   'Azure Blob Storage',
    'gcp_storage':  'Google Cloud Storage',
    'generic_cloud':'Generic Cloud / Multi-Cloud',
}

FIELD_DISPLAY = {
    'request_url':      'Request URL',
    'request_headers':  'Request Headers',
    'request_body':     'Request Body',
    'request_cookies':  'Request Cookies',
    'response_status':  'Response Status Line',
    'response_headers': 'Response Headers',
    'response_body':    'Response Body',
}


def write_report(output_path: str, results: list, xml_filename: str,
                 entries: list, meta: dict):
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    # Category summary counts
    cat_totals = defaultdict(int)
    for r in results:
        for cat_id in r['by_category']:
            cat_totals[cat_id] += len(r['by_category'][cat_id])

    lines = []
    lines.append("=" * 72)
    lines.append("CONF-11 — Cloud Storage Exposure Scan")
    lines.append("WSTG-CONF-11 | Test Cloud Storage")
    lines.append("=" * 72)
    lines.append(f"Generated  : {meta['generated']}")
    lines.append(f"XML File   : {xml_filename}")
    lines.append(f"Strings DB : {meta['strings_path']}")
    lines.append(f"Items scanned      : {meta['total_items']}")
    lines.append(f"Endpoints with hits: {len(results)}")
    lines.append(f"Total string hits  : {sum(r['total_hits'] for r in results)}")
    lines.append("")

    if cat_totals:
        lines.append("Category Breakdown:")
        for cat_id, count in sorted(cat_totals.items(), key=lambda x: -x[1]):
            cat_name = CATEGORY_DISPLAY.get(cat_id, cat_id)
            lines.append(f"  {cat_name:<35} {count:>4} hit(s)")
    lines.append("")
    lines.append("=" * 72)
    lines.append("")

    if not results:
        lines.append("No cloud storage indicators found across all scanned items.")
    else:
        for r in results:
            idx      = r['index']
            method   = r['method']
            url      = r['url']
            path     = r['path']
            status   = r['status_code']
            total    = r['total_hits']
            by_cat   = r['by_category']

            # Build category hit summary string
            cat_summary = ", ".join(
                f"{len(hits)} {CATEGORY_DISPLAY.get(cat_id, cat_id)}"
                for cat_id, hits in by_cat.items()
            )

            lines.append(
                f"ENDPOINT {idx:>4} | {method:<7} | {path}"
            )
            lines.append(
                f"  URL    : {url}"
            )
            lines.append(
                f"  Status : {status or 'N/A'}  |  File: {xml_filename}"
            )
            lines.append(
                f"  Hits   : {total} string(s) across {len(by_cat)} category/categories: {cat_summary}"
            )
            lines.append("")

            for cat_id, hits in by_cat.items():
                cat_name = CATEGORY_DISPLAY.get(cat_id, cat_id)
                lines.append(f"  [{cat_name}] — {len(hits)} hit(s)")

                # Group by field
                by_field = defaultdict(list)
                for h in hits:
                    by_field[h['field']].append(h)

                for field, field_hits in by_field.items():
                    fd = FIELD_DISPLAY.get(field, field)
                    strings_found = sorted(set(h['value'] for h in field_hits))
                    lines.append(f"    Field : {fd}")
                    for s in strings_found:
                        # Find note for this string
                        note = next((h['note'] for h in field_hits if h['value'] == s), "")
                        lines.append(f"      ✓ \"{s}\"")
                        if note:
                            lines.append(f"        Note: {note}")
                lines.append("")

            lines.append("-" * 72)
            lines.append("")

    # Footer
    lines.append("")
    lines.append("=" * 72)
    lines.append("MANUAL FOLLOW-UP")
    lines.append("=" * 72)
    lines.append("")
    lines.append("For each endpoint above, consider:")
    lines.append("  1. Is the cloud storage URL/reference accessible without authentication?")
    lines.append("  2. Do signed/presigned URLs in responses allow unauthenticated access?")
    lines.append("  3. Are S3 ACLs or Azure container access levels set to public?")
    lines.append("  4. Do bucket names in error responses indicate takeover candidates?")
    lines.append("     (NoSuchBucket / NoSuchKey with a bucket name = test for takeover)")
    lines.append("  5. Are CORS headers (Access-Control-Allow-Origin: *) present on storage endpoints?")
    lines.append("  6. Do x-amz-acl or PublicAccess values reveal misconfigured permissions?")
    lines.append("")

    with open(output_path, 'w') as f:
        f.write('\n'.join(lines))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description='CONF-11: Scan Burp XML for cloud storage indicator strings'
    )
    p.add_argument(
        '-x', '--xml', required=True,
        help='Burp Suite XML export file'
    )
    p.add_argument(
        '-s', '--strings',
        default='inputs/Data/cloud_strings.json',
        help='Cloud strings JSON (default: inputs/Data/cloud_strings.json)'
    )
    p.add_argument(
        '-o', '--output',
        default='outputs/test_output/test_findings.txt',
        help='Output report (default: outputs/test_output/test_findings.txt)'
    )
    p.add_argument(
        '--min-hits', type=int, default=1,
        help='Minimum hit count to include an endpoint (default: 1)'
    )
    p.add_argument(
        '--category',
        help='Filter to a single category ID (e.g. aws_s3, azure_blob, gcp_storage)'
    )
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    print("=" * 60)
    print("CONF-11 — Cloud Storage Scanner")
    print("=" * 60)

    # Load strings
    entries = load_strings(args.strings, args.category)
    print(f"[*] Loaded {len(entries)} indicator strings from {args.strings}")
    if args.category:
        print(f"[*] Filtering to category: {args.category}")

    # Parse XML
    try:
        tree = ET.parse(args.xml)
    except FileNotFoundError:
        print(f"[!] XML not found: {args.xml}")
        sys.exit(1)
    except ET.ParseError as e:
        print(f"[!] XML parse error: {e}")
        sys.exit(1)

    items = tree.getroot().findall('.//item')
    if not items:
        print("[!] No <item> elements found in XML.")
        sys.exit(1)

    xml_filename = os.path.basename(args.xml)
    print(f"[*] XML: {xml_filename} — {len(items)} items")

    # Scan
    results = []
    for i, item in enumerate(items, start=1):
        result = scan_item(i, item, entries)
        if result and result['total_hits'] >= args.min_hits:
            results.append(result)

    print(f"[*] Endpoints with hits: {len(results)} / {len(items)}")
    if results:
        total_hits = sum(r['total_hits'] for r in results)
        print(f"[*] Total string hits : {total_hits}")

        # Category breakdown
        cat_totals = defaultdict(int)
        for r in results:
            for cat_id, hits in r['by_category'].items():
                cat_totals[cat_id] += len(hits)
        for cat_id, count in sorted(cat_totals.items(), key=lambda x: -x[1]):
            print(f"    {CATEGORY_DISPLAY.get(cat_id, cat_id)}: {count}")

    meta = {
        'generated':    datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
        'strings_path': args.strings,
        'total_items':  len(items),
    }

    write_report(args.output, results, xml_filename, entries, meta)
    print(f"\n[+] Report written → {args.output}")

    print(f"\n{'=' * 60}")
    print("CONF-11 SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Items scanned       : {len(items)}")
    print(f"  Endpoints with hits : {len(results)}")
    print(f"  Output              : {args.output}")


if __name__ == "__main__":
    main()
