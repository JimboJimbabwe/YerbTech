#!/usr/bin/env python3
"""
WSTG-BUSL-03 — Integrity Checks
Script 2: verdict_busl_03.py

Reads a Burp Intruder XML export of integrity-check probe results,
classifies each response by status code and body size, and emits
structured alerts for interesting findings.

Alert logic (identical to busl01_validation.py):
  200                          → HIGH   (request accepted — possible logic bypass)
  302 / 202 / 301              → MEDIUM (redirect/queued — worth investigating)
  403 / 500  ≥ --min-bytes     → LOW    (verbose error leaks info)
  403 / 500  <  --min-bytes    → SKIP   (bare error, noise)
  404                          → SKIP   (always)
  other 2xx/3xx                → LOW
  everything else              → SKIP

Inputs:
  WSTG-BUSL-03/inputs/xml/intruder_tests.xml

Outputs:
  WSTG-BUSL-03/inputs/json/intruder_alerts.json

Usage:
  python3 WSTG-BUSL-03/utilities/python/verdict_busl_03.py \\
      [--intruder WSTG-BUSL-03/inputs/xml/intruder_tests.xml] \\
      [--min-bytes 500]
"""

import argparse
import base64
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urlparse


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

SEVERITY_COLOR = {
    "HIGH":   RED,
    "MEDIUM": YELLOW,
    "LOW":    CYAN,
}


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


def parse_intruder_xml(path: str) -> list[dict]:
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
        resp   = decode_element(item.find("response"))
        status_elem = item.find("status")

        # Status: prefer explicit element, fall back to parsing response line
        if status_elem is not None and status_elem.text:
            try:
                status = int(status_elem.text.strip())
            except ValueError:
                status = _parse_status_from_response(resp)
        else:
            status = _parse_status_from_response(resp)

        # Response body
        resp_parts = resp.split("\r\n\r\n", 1) if resp else ["", ""]
        resp_body  = resp_parts[1] if len(resp_parts) > 1 else ""

        # Extract payload from request
        payload = extract_payload_from_request(req)

        items.append({
            "index":     idx,
            "url":       url,
            "method":    method,
            "status":    status,
            "resp_body": resp_body,
            "payload":   payload,
            "request":   req,
        })
    return items


def _parse_status_from_response(resp: str) -> int:
    if not resp:
        return 0
    first_line = resp.split("\n", 1)[0].strip()
    m = re.match(r'HTTP/[\d.]+\s+(\d+)', first_line)
    if m:
        return int(m.group(1))
    return 0


# ---------------------------------------------------------------------------
# Payload extraction
# ---------------------------------------------------------------------------

def extract_payload_from_request(req: str) -> str:
    """
    Try to extract the injected payload value from the request.
    Intruder marks the payload position with § in some exports; otherwise
    look at the last body parameter value.
    """
    if not req:
        return ""

    # Check for § markers (Burp Intruder marks payload positions)
    if "§" in req:
        m = re.search(r'§([^§]*)§', req)
        if m:
            return m.group(1)

    # Fall back to last line of body
    parts = req.split("\r\n\r\n", 1)
    if len(parts) < 2:
        return ""
    body = parts[1].strip()
    if not body:
        return ""

    # URL-encoded body: last param value
    if "=" in body and "&" in body:
        try:
            last_pair = body.split("&")[-1]
            return last_pair.split("=", 1)[1] if "=" in last_pair else body
        except Exception:
            pass

    # JSON body: return raw (truncated)
    if body.startswith("{") or body.startswith("["):
        return body[:120]

    return body[:120]


# ---------------------------------------------------------------------------
# Payload → test case inference
# ---------------------------------------------------------------------------

CATEGORY_PATTERNS = [
    (re.compile(r'\\x[0-9a-f]{2}', re.IGNORECASE),       "Hex encoding"),
    (re.compile(r'[01]{8}(\s[01]{8})+'),                   "Binary encoding"),
    (re.compile(r'\d+(\s\d+){3,}'),                        "Decimal encoding"),
    (re.compile(r'0x[0-9a-f]+', re.IGNORECASE),            "Hex representation"),
    (re.compile(r'^0o[0-7]+$', re.IGNORECASE),             "Octal representation"),
    (re.compile(r'\{\{7\*7\}\}|\$\{7\*7\}|#\{7\*7\}'),    "Template injection"),
    (re.compile(r'javascript:|<script|fetch\(', re.I),     "JavaScript injection"),
    (re.compile(r'\.\./', ),                                "Path traversal"),
    (re.compile(r'[а-яА-Яα-ωΑ-Ω]'),
                                                             "Unicode confusion"),
    (re.compile(r'^-\d+$'),                                 "Negative value"),
    (re.compile(r'^(admin|true|false|nan|null|undefined)$', re.I),
                                                             "Alpha-only substitute"),
    (re.compile(r'^\d{1,20}$'),                             "Numeric substitute"),
    (re.compile(r'\x00|\x01|\x02|﻿|​'),           "Special characters"),
]

def infer_test_case(payload: str) -> str:
    for pattern, label in CATEGORY_PATTERNS:
        if pattern.search(payload):
            return label
    return "Unknown"


# ---------------------------------------------------------------------------
# Alert classification
# ---------------------------------------------------------------------------

def classify_response(status: int, body_bytes: int, min_bytes: int) -> tuple:
    """
    Returns (severity | None, reason_str).
    None means skip.
    """
    if status == 404:
        return None, "404 Not Found — skip"
    if status in (403, 500):
        if body_bytes < min_bytes:
            return None, f"{status} with <{min_bytes}B body — bare error, skip"
        return "LOW", f"{status} with {body_bytes}B body — verbose error, may leak info"
    if status == 200:
        return "HIGH", "200 OK — request accepted, possible logic bypass"
    if status in (302, 202, 301):
        return "MEDIUM", f"{status} — redirect/queued, warrants investigation"
    if 200 <= status < 400:
        return "LOW", f"{status} — unexpected 2xx/3xx, investigate"
    return None, f"{status} — not interesting, skip"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-BUSL-03 Script 2: Intruder result classifier"
    )
    p.add_argument("--intruder",
        default=os.path.join("WSTG-BUSL-03", "inputs", "xml", "intruder_tests.xml"),
        metavar="PATH")
    p.add_argument("--json-out",
        default=os.path.join("WSTG-BUSL-03", "inputs", "json", "intruder_alerts.json"),
        metavar="PATH")
    p.add_argument("--min-bytes", type=int, default=500, metavar="N",
        help="Minimum body bytes for 403/500 to be flagged LOW (default: 500)")
    args = p.parse_args()

    width = 65
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD} WSTG-BUSL-03 — Intruder Result Classifier{RESET}")
    print(f"{BOLD}{'='*width}{RESET}")
    print(f"  Intruder XML : {args.intruder}")
    print(f"  Min bytes    : {args.min_bytes}\n")

    items = parse_intruder_xml(args.intruder)
    print(f"  Parsed {len(items)} result(s)\n")

    alerts   = []
    skipped  = 0
    by_ep    = {}

    for item in items:
        idx       = item["index"]
        url       = item["url"]
        status    = item["status"]
        body_len  = len(item["resp_body"].encode("utf-8", errors="replace"))
        payload   = item["payload"]
        method    = item["method"]
        test_case = infer_test_case(payload)

        severity, reason = classify_response(status, body_len, args.min_bytes)

        parsed   = urlparse(url)
        path     = parsed.path or url
        ep_key   = f"{method} {path}"

        if severity is None:
            skipped += 1
            print(
                f"  [{idx:3d}] {DIM}{status}  {reason[:55]}{RESET}"
            )
            continue

        color = SEVERITY_COLOR.get(severity, RESET)
        print(
            f"  [{idx:3d}] {color}{severity:<6}{RESET}  "
            f"HTTP {status}  {path[:40]}{'...' if len(path)>40 else ''}  "
            f"payload: {DIM}{payload[:35]}{'...' if len(payload)>35 else ''}{RESET}"
        )

        alert = {
            "alert_index":  len(alerts),
            "endpoint_index": idx,
            "url":          url,
            "method":       method,
            "status_code":  status,
            "severity":     severity,
            "reason":       reason,
            "body_bytes":   body_len,
            "payload":      payload,
            "test_case":    test_case,
        }
        alerts.append(alert)

        if ep_key not in by_ep:
            by_ep[ep_key] = {"method": method, "path": path, "alerts": []}
        by_ep[ep_key]["alerts"].append(alert)

    # Summary counts
    sev_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in alerts:
        sev_counts[a["severity"]] += 1

    print(f"\n  {'─'*50}")
    print(f"  Total:   {len(items)}")
    print(f"  Alerts:  {len(alerts)}  "
          f"(HIGH={sev_counts['HIGH']}  "
          f"MEDIUM={sev_counts['MEDIUM']}  "
          f"LOW={sev_counts['LOW']})")
    print(f"  Skipped: {skipped}")

    # Write JSON
    os.makedirs(os.path.dirname(args.json_out), exist_ok=True)
    output = {
        "_meta": {
            "source_xml":   args.intruder,
            "generated":    datetime.now().isoformat(),
            "total_items":  len(items),
            "alerts":       len(alerts),
            "skipped":      skipped,
            "min_bytes":    args.min_bytes,
            "severity_counts": sev_counts,
        },
        "alerts": alerts,
        "findings_metadata": {
            "by_endpoint": {
                ep_key: {
                    "method":      ep_val["method"],
                    "path":        ep_val["path"],
                    "alert_count": len(ep_val["alerts"]),
                    "severities":  list({a["severity"] for a in ep_val["alerts"]}),
                    "alerts":      ep_val["alerts"],
                }
                for ep_key, ep_val in by_ep.items()
            }
        },
    }

    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\n{GREEN}[+] intruder_alerts.json → {args.json_out}{RESET}\n")


if __name__ == "__main__":
    main()
