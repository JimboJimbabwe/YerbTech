#!/usr/bin/env python3
"""
WSTG-CLNT-09 — Clickjacking Scanner
=====================================
Reads Burp Suite proxy history XML exports from Inputs/XML/, checks every
response for clickjacking protection headers (X-Frame-Options and
Content-Security-Policy frame-ancestors), generates HTML proof-of-concept
test files for unprotected endpoints, and writes a scan results JSON for
the verdict GUI.

Outputs
-------
    Outputs/test_outputs/clickjacking_tests/test_N.html  — one per unprotected URL
    Outputs/test_outputs/scan_results.json               — full scan data

Usage
-----
    python clnt_09_scan.py                     # scan all XMLs in Inputs/XML/
    python clnt_09_scan.py --xml-dir /other/   # alternate XML folder
    python clnt_09_scan.py --only clnt09       # single XML stem
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR       = Path(__file__).resolve().parent
TOOL_ROOT        = SCRIPT_DIR.parent.parent
DEFAULT_XML_DIR  = TOOL_ROOT / "Inputs"  / "XML"
DEFAULT_OUT_DIR  = TOOL_ROOT / "Outputs" / "test_outputs"
TEST_SUBDIR      = "clickjacking_tests"


# ── Header extraction ──────────────────────────────────────────────────────────

def _extract_response_headers(raw: str) -> dict[str, str]:
    """
    Parse HTTP response headers from a raw response string.
    Returns a dict of lowercase header-name → value.
    """
    headers: dict[str, str] = {}
    # Split on first blank line (headers / body)
    head_block = raw.split("\r\n\r\n", 1)[0]
    lines      = head_block.split("\r\n")

    for line in lines[1:]:   # skip status line
        if ":" in line:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()

    return headers


def _check_protection(headers: dict[str, str]) -> tuple[bool, list[str]]:
    """
    Check headers for clickjacking mitigations.
    Returns (is_protected, list_of_protection_strings).
    """
    protections: list[str] = []

    # X-Frame-Options
    xfo = headers.get("x-frame-options", "")
    if xfo and any(kw in xfo.upper() for kw in ("DENY", "SAMEORIGIN", "ALLOW-FROM")):
        protections.append(f"X-Frame-Options: {xfo}")

    # Content-Security-Policy — frame-ancestors directive
    csp = headers.get("content-security-policy", "")
    if csp:
        m = re.search(r"frame-ancestors\s+([^;]+)", csp, re.IGNORECASE)
        if m:
            fa = m.group(1).strip()
            if "'none'" in fa or "'self'" in fa:
                protections.append(f"CSP frame-ancestors: {fa}")

    return bool(protections), protections


# ── HTML test file generator ───────────────────────────────────────────────────

def _make_test_html(url: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Clickjacking Test — {url}</title>
  <style>
    body {{ font-family: monospace; background: #1a1a1a; color: #ccc; padding: 20px; }}
    h2   {{ color: #e06c75; }}
    .meta{{ color: #abb2bf; font-size: 0.9em; margin-bottom: 16px; }}
    iframe{{ border: 2px dashed #e06c75; background: #fff; display: block; margin-top: 12px; }}
  </style>
</head>
<body>
  <h2>WSTG-CLNT-09 — Clickjacking PoC</h2>
  <p class="meta">Target: <b>{url}</b></p>
  <p>If the page loads inside the iframe below, it may be vulnerable to clickjacking.</p>
  <iframe src="{url}" width="900" height="600" sandbox></iframe>
</body>
</html>
"""


# ── XML parsing ────────────────────────────────────────────────────────────────

def parse_xml_file(xml_path: Path) -> list[dict]:
    """
    Parse one Burp proxy history XML export.
    Returns a list of { url, protected, protection_headers } records.
    Skips items with no response or a non-HTML content type.
    """
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError as e:
        print(f"  [!] XML parse error in {xml_path.name}: {e}")
        return []
    except FileNotFoundError:
        print(f"  [!] File not found: {xml_path}")
        return []

    records: list[dict] = []

    for item in root.findall(".//item"):
        url_el  = item.find(".//url")
        resp_el = item.find(".//response")

        if url_el is None or resp_el is None or not resp_el.text:
            continue

        url = (url_el.text or "").strip()
        if not url:
            continue

        try:
            raw     = base64.b64decode(resp_el.text).decode("utf-8", errors="ignore")
            headers = _extract_response_headers(raw)
        except Exception:
            continue

        # Only care about HTML responses for clickjacking
        ct = headers.get("content-type", "")
        if ct and "html" not in ct.lower() and ct not in ("", "text/plain"):
            continue

        protected, prot_list = _check_protection(headers)
        records.append({
            "url":                url,
            "protected":          protected,
            "protection_headers": prot_list,
        })

    return records


# ── Main scanning flow ─────────────────────────────────────────────────────────

def scan(xml_dir: Path, out_dir: Path, only: set[str] | None) -> None:
    xml_files = sorted(xml_dir.glob("*.xml"))
    if not xml_files:
        sys.exit(f"[!] No *.xml files found in {xml_dir}")

    if only:
        xml_files = [f for f in xml_files if f.stem in only]
        if not xml_files:
            sys.exit(f"[!] --only filter matched nothing.")

    print(f"\n[*] WSTG-CLNT-09 — Clickjacking Scanner")
    print(f"    XML dir : {xml_dir}")
    print(f"    Files   : {[f.name for f in xml_files]}\n")

    # Collect all records, deduplicate by URL (last-seen wins for header data)
    url_map: OrderedDict[str, dict] = OrderedDict()

    for xml_path in xml_files:
        print(f"  Scanning {xml_path.name} …")
        records = parse_xml_file(xml_path)
        for rec in records:
            url_map[rec["url"]] = rec
        print(f"    {len(records)} response(s) processed.")

    total    = len(url_map)
    all_recs = list(url_map.values())

    # Separate protected / unprotected
    protected   = [r for r in all_recs if r["protected"]]
    unprotected = [r for r in all_recs if not r["protected"]]

    print(f"\n  Total unique URLs : {total}")
    print(f"  Protected         : {len(protected)}")
    print(f"  Unprotected       : {len(unprotected)}")

    # Generate HTML test files for unprotected endpoints
    tests_dir = out_dir / TEST_SUBDIR
    tests_dir.mkdir(parents=True, exist_ok=True)

    endpoints: list[dict] = []

    # Protected endpoints — no test file needed
    for i, rec in enumerate(protected):
        endpoints.append({
            "index":              i,
            "url":                rec["url"],
            "scan_result":        "PROTECTED",
            "protection_headers": rec["protection_headers"],
            "test_file":          None,
        })

    # Unprotected endpoints — generate test HTML
    for j, rec in enumerate(unprotected):
        idx       = len(protected) + j
        test_file = tests_dir / f"test_{j}.html"
        test_file.write_text(_make_test_html(rec["url"]), encoding="utf-8")

        endpoints.append({
            "index":              idx,
            "url":                rec["url"],
            "scan_result":        "NO_PROTECTION",
            "protection_headers": [],
            "test_file":          str(test_file),
        })

    print(f"\n  HTML test files → {tests_dir.relative_to(TOOL_ROOT)}/test_N.html")

    # Write scan results JSON
    out_dir.mkdir(parents=True, exist_ok=True)
    scan_json = out_dir / "scan_results.json"

    payload = {
        "scan_metadata": {
            "wstg_id":             "WSTG-CLNT-09",
            "title":               "Testing for Clickjacking",
            "scan_time":           datetime.now(timezone.utc).isoformat(),
            "source_files":        [f.name for f in xml_files],
            "total_urls":          total,
            "protected":           len(protected),
            "unprotected":         len(unprotected),
        },
        "endpoints": endpoints,
    }

    scan_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"  Scan results    → {scan_json.relative_to(TOOL_ROOT)}")
    print(f"\n[+] Done — run clnt_09_verdict.py to record verdicts.\n")


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="WSTG-CLNT-09 — Clickjacking Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--xml-dir", metavar="DIR", default=str(DEFAULT_XML_DIR),
        help=f"Burp XML input folder  [default: {DEFAULT_XML_DIR}]",
    )
    ap.add_argument(
        "--out-dir", metavar="DIR", default=str(DEFAULT_OUT_DIR),
        help=f"Output folder          [default: {DEFAULT_OUT_DIR}]",
    )
    ap.add_argument(
        "--only", metavar="NAME[,NAME]",
        help="Process only these XML stems",
    )

    args    = ap.parse_args()
    xml_dir = Path(args.xml_dir)
    out_dir = Path(args.out_dir)
    only    = {s.strip() for s in args.only.split(",")} if args.only else None

    if not xml_dir.is_dir():
        sys.exit(f"[!] XML directory not found: {xml_dir}")

    scan(xml_dir, out_dir, only)


if __name__ == "__main__":
    main()
