#!/usr/bin/env python3
"""
WSTG-BUSL-05 Analyze — Intruder Result Scanner
===============================================
Reads a Burp Suite Intruder results XML export, groups responses by endpoint
path, counts the longest run of consecutive HTTP 200 OK responses, and flags
any endpoint where that run exceeds the threshold (default > 3).

A run > 3 means the application returned 200 at least 4 times in a row with
no rate-limit or block response — indicative of missing function-use limits.

Output
------
Writes findings to  Outputs/test_outputs/findings.json

Usage
-----
    python busl_05_analyze.py
    python busl_05_analyze.py -x /path/to/intruder_test.xml
    python busl_05_analyze.py --threshold 5    # change the trigger point
"""

from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────────
#   Place this file at  WSTG-BUSL-05/Utilities/python/busl_05_analyze.py
SCRIPT_DIR  = Path(__file__).resolve().parent
TOOL_ROOT   = SCRIPT_DIR.parent.parent
DEFAULT_XML = TOOL_ROOT / "Inputs"  / "XML"          / "intruder_test.xml"
DEFAULT_OUT = TOOL_ROOT / "Outputs" / "test_outputs"  / "findings.json"

DEFAULT_THRESHOLD = 3   # flag when consecutive 200s EXCEED this value (i.e., >= 4)


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── XML parsing ───────────────────────────────────────────────────────────────

def parse_intruder_xml(xml_path: Path) -> dict[str, list[int]]:
    """
    Parse a Burp Intruder results XML export.

    Returns:
        { "/path": [200, 200, 429, 200, ...], ... }
        preserving the original request order within each path.
    """
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError as e:
        sys.exit(f"[!] XML parse error in {xml_path}: {e}")
    except FileNotFoundError:
        sys.exit(f"[!] XML not found: {xml_path}")

    endpoints: dict[str, list[int]] = {}

    for el in root.findall("item"):
        path       = (el.findtext("path") or "/").strip()
        status_raw = (el.findtext("status") or "").strip()

        try:
            code = int(status_raw)
        except ValueError:
            continue   # no parseable status — skip

        if path not in endpoints:
            endpoints[path] = []
        endpoints[path].append(code)

    if not endpoints:
        sys.exit(
            "[!] No parseable <item> entries found.\n"
            "    Is this a Burp Intruder results export with <status> fields?"
        )

    total = sum(len(v) for v in endpoints.values())
    print(f"[*] Loaded {total} response(s) across {len(endpoints)} unique path(s).")
    return endpoints


# ── Analysis ──────────────────────────────────────────────────────────────────

def max_consecutive_200s(statuses: list[int]) -> int:
    """Return the length of the longest unbroken run of HTTP 200 responses."""
    max_run = cur = 0
    for code in statuses:
        if code == 200:
            cur += 1
            if cur > max_run:
                max_run = cur
        else:
            cur = 0
    return max_run


def build_findings(endpoints: dict[str, list[int]], threshold: int) -> list[dict]:
    """
    Produce the findings list, one entry per endpoint path.

    Each entry:
        {
          "index":            int,
          "path":             str,
          "successive_200ok": int,    # longest consecutive 200 run
          "vulnerable":       bool    # True if run > threshold
        }
    """
    results: list[dict] = []

    for idx, (path, statuses) in enumerate(endpoints.items()):
        run        = max_consecutive_200s(statuses)
        vulnerable = run > threshold

        results.append({
            "index":            idx,
            "path":             path,
            "successive_200ok": run,
            "vulnerable":       vulnerable,
        })

    return results


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="WSTG-BUSL-05 Analyze — detect missing function-use limits in Intruder results",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            f"Flags an endpoint as vulnerable when its consecutive-200 run\n"
            f"exceeds --threshold (default {DEFAULT_THRESHOLD}), i.e. > 3 in a row."
        ),
    )
    ap.add_argument(
        "-x", "--xml", metavar="FILE", default=str(DEFAULT_XML),
        help=f"Burp Intruder results XML  [default: {DEFAULT_XML}]",
    )
    ap.add_argument(
        "-o", "--output", metavar="FILE", default=str(DEFAULT_OUT),
        help=f"JSON findings output       [default: {DEFAULT_OUT}]",
    )
    ap.add_argument(
        "--threshold", type=int, default=DEFAULT_THRESHOLD,
        help=(
            f"Flag when consecutive 200s exceed this count  "
            f"[default: {DEFAULT_THRESHOLD}  →  ≥ 4 in a row triggers]"
        ),
    )

    args = ap.parse_args()

    endpoints = parse_intruder_xml(Path(args.xml))
    findings  = build_findings(endpoints, args.threshold)

    vuln      = [f for f in findings if f["vulnerable"]]
    total     = len(findings)

    # ── Console summary ───────────────────────────────────────────────────
    print(f"[*] Threshold: > {args.threshold} consecutive 200s → vulnerable")
    if vuln:
        print(f"[!] {len(vuln)}/{total} endpoint(s) flagged:\n")
        for f in vuln:
            print(
                f"    [{f['index']}]  {f['path']}"
                f"  —  {f['successive_200ok']} consecutive 200s"
            )
    else:
        print(f"[+] 0/{total} endpoints flagged — no rate-limit bypass detected.")

    # ── Write JSON ────────────────────────────────────────────────────────
    payload = {
        "scan_metadata": {
            "wstg_id":   "WSTG-BUSL-05",
            "title":     "Testing for Number of Times a Function Can Be Used Limits",
            "scan_time": _ts(),
            "source":    args.xml,
            "threshold": args.threshold,
        },
        "findings": {
            "endpoints": findings,
        },
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\n[+] Findings → {out_path}")


if __name__ == "__main__":
    main()
