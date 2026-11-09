#!/usr/bin/env python3
"""
WSTG-BUSL-01 — Business Logic Validation
Script 2: busl01_validation.py

Reads a Burp Intruder results XML export and identifies responses
that indicate a business logic validation failure — i.e. the server
accepted a payload it should have rejected.

Alert logic:
  ┌─────────────────────────────────────────────────────────────┐
  │  Response code   │  Body bytes    │  Decision               │
  ├─────────────────────────────────────────────────────────────┤
  │  404             │  any           │  SKIP — not found        │
  │  403             │  < min_bytes   │  SKIP — bare forbidden   │
  │  500             │  < min_bytes   │  SKIP — bare error       │
  │  403             │  ≥ min_bytes   │  ALERT — app responded   │
  │  500             │  ≥ min_bytes   │  ALERT — verbose error   │
  │  200             │  any           │  ALERT (severity: HIGH)  │
  │  302 / 301       │  any           │  ALERT (severity: MED)   │
  │  202             │  any           │  ALERT (severity: MED)   │
  │  other 2xx/3xx   │  any           │  ALERT (severity: LOW)   │
  └─────────────────────────────────────────────────────────────┘

  Default min_bytes: 500  (configurable via --min-bytes)

Alert severity order (for sorting):
  1. 200 OK       — server fully accepted the malicious payload
  2. 302 Found    — redirect after acceptance (login-like flow)
  3. 202 Accepted — async acceptance
  4. 301 Moved    — redirect (lower confidence than 302)
  5. 403/500 ≥N   — verbose error (information disclosure)
  6. Other 2xx/3xx

Outputs:
  WSTG-BUSL-01/inputs/json/intruder_alerts.json

Usage:
  python3 WSTG-BUSL-01/utilities/python/busl01_validation.py \\
      --intruder WSTG-BUSL-01/inputs/xml/intruder_test.xml \\
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


# ---------------------------------------------------------------------------
# ANSI
# ---------------------------------------------------------------------------
BOLD    = "\033[1m"
DIM     = "\033[2m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
CYAN    = "\033[96m"
RESET   = "\033[0m"


# ---------------------------------------------------------------------------
# Severity ordering (lower = worse)
# ---------------------------------------------------------------------------
SEVERITY_RANK = {
    "HIGH":   1,
    "MEDIUM": 2,
    "LOW":    3,
    "INFO":   4,
}

SEVERITY_COLOR = {
    "HIGH":   RED,
    "MEDIUM": YELLOW,
    "LOW":    CYAN,
    "INFO":   DIM,
}


# ---------------------------------------------------------------------------
# Test-case label inference
# Parses the payload value to determine which wordlist category it came from.
# Falls back to the raw payload if no pattern matches.
# ---------------------------------------------------------------------------

def infer_test_case(payload: str) -> str:
    """Guess the wordlist category from the payload string."""
    if not payload:
        return "unknown"

    p = payload.strip()

    # Comment-style category headers left in the value (shouldn't happen but guard)
    if p.startswith("# ---"):
        return "comment"

    # Template injection
    if re.search(r'\{\{.*\}\}|\$\{.*\}|<%.*%>', p):
        return "template_injection"

    # JavaScript
    if re.search(r'javascript:|<script|fetch\(|document\.cookie', p, re.IGNORECASE):
        return "javascript_injection"

    # Special chars — zero-width, control, path traversal
    if re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f]|\.\./', p):
        return "special_chars"

    # URL percent-encoded special chars
    if re.search(r'%[0-9a-fA-F]{2}', p) and len(p) < 20:
        return "special_chars_encoded"

    # Binary: space-separated 8-bit strings
    if re.fullmatch(r'[01]{8}( [01]{8})*', p):
        return "binary_encoding"

    # Hex: \xHH sequences
    if re.fullmatch(r'(\\x[0-9a-fA-F]{2})+', p):
        return "hex_encoding"

    # Hex: 0x prefix
    if re.fullmatch(r'0x[0-9a-fA-F]+', p):
        return "hex_numeric"

    # Octal: 0o prefix
    if re.fullmatch(r'0o[0-7]+', p):
        return "octal_numeric"

    # Binary with 0b prefix
    if re.fullmatch(r'0b[01]+', p):
        return "binary_numeric"

    # Decimal: space-separated integers
    if re.fullmatch(r'\d+( \d+)+', p):
        return "decimal_encoding"

    # Negative number
    if re.fullmatch(r'-\d+(\.\d+)?', p):
        return "negative_numeric"

    # Pure integer
    if re.fullmatch(r'\d+(\.\d+)?', p):
        return "integer_only"

    # Pure alphabetic (might be random word or alpha-only)
    if p.isalpha():
        return "alpha_string"

    # Unicode-rich (many non-ASCII chars)
    non_ascii = sum(1 for c in p if ord(c) > 127)
    if non_ascii > len(p) * 0.3:
        return "unicode_confusion"

    return "other"


# ---------------------------------------------------------------------------
# Burp Intruder XML parsing
# Intruder XML structure differs slightly from Proxy XML:
#   <items>
#     <item>
#       <serialNumber>0</serialNumber>
#       <time>...</time>
#       <url>...</url>
#       <host ip="...">...</host>
#       <port>443</port>
#       <protocol>https</protocol>
#       <method>POST</method>
#       <path>/api/login</path>
#       <extension>...</extension>
#       <request base64="true">...</request>
#       <status>200</status>
#       <responselength>1234</responselength>
#       <mimetype>JSON</mimetype>
#       <response base64="true">...</response>
#       <comment></comment>
#     </item>
#   </items>
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


def get_text(elem, tag: str, default: str = "") -> str:
    child = elem.find(tag)
    if child is None:
        return default
    return (child.text or "").strip()


def extract_payload_from_request(req_text: str) -> str:
    """
    Burp Intruder inserts §markers§ around the payload position in the
    stored request. After the attack those are replaced with the actual
    payload value. We extract the body or query string value that was
    injected — take the last value in the body or query string as the
    most likely payload position (common Intruder pattern for Sniper mode).
    """
    if not req_text:
        return ""

    parts = req_text.split("\r\n\r\n", 1)
    body  = parts[1].strip() if len(parts) > 1 else ""

    # Form-encoded body: last value
    if body and "=" in body and not body.startswith("{"):
        pairs = body.split("&")
        if pairs:
            last = pairs[-1]
            if "=" in last:
                return last.split("=", 1)[1]

    # JSON body: extract first string value
    if body.startswith("{"):
        m = re.search(r':\s*"([^"]*)"', body)
        if m:
            return m.group(1)

    # Query string fallback
    if parts[0]:
        request_line = parts[0].splitlines()[0]
        m = re.search(r'\?(.+?)\s', request_line)
        if m:
            qs = m.group(1)
            pairs = qs.split("&")
            if pairs:
                last = pairs[-1]
                if "=" in last:
                    return last.split("=", 1)[1]

    return ""


def parse_intruder_xml(path: str) -> list[dict]:
    try:
        tree = ET.parse(path)
    except (ET.ParseError, FileNotFoundError) as e:
        print(f"{RED}[!] XML error: {e}{RESET}", file=sys.stderr)
        sys.exit(1)

    root = tree.getroot()
    # Root may be <items> or <burpresults>; find all <item> children
    items_elem = root if root.tag == "items" else root.find("items")
    if items_elem is None:
        items_elem = root

    results = []
    for item in items_elem.findall("item"):
        serial     = get_text(item, "serialNumber", "0")
        url        = decode_element(item.find("url"))
        path_val   = get_text(item, "path")
        method     = get_text(item, "method", "GET").upper()
        status_str = get_text(item, "status", "0")
        resp_len   = get_text(item, "responselength", "0")
        request    = decode_element(item.find("request"))
        response   = decode_element(item.find("response"))

        try:
            status = int(status_str)
        except ValueError:
            status = 0

        try:
            body_bytes = int(resp_len)
        except ValueError:
            # Fall back to measuring the response body directly
            resp_parts = response.split("\r\n\r\n", 1) if response else ["", ""]
            body_bytes = len(resp_parts[1]) if len(resp_parts) > 1 else 0

        # Extract the actual payload from the request
        payload = extract_payload_from_request(request)

        # Also try to get it from the response body context
        # (some Intruder exports store payload in <comment> or <payload> tags)
        payload_elem = item.find("payload")
        if payload_elem is not None and payload_elem.text:
            payload = payload_elem.text.strip()

        results.append({
            "serial":     int(serial) if serial.isdigit() else 0,
            "url":        url,
            "path":       path_val or url,
            "method":     method,
            "status":     status,
            "body_bytes": body_bytes,
            "payload":    payload,
            "response":   response,
        })

    return results


# ---------------------------------------------------------------------------
# Alert classification
# ---------------------------------------------------------------------------

def classify_response(status: int, body_bytes: int, min_bytes: int) -> tuple[str | None, str]:
    """
    Returns (severity, reason) or (None, reason) if this response is benign.
    """
    # Always skip 404
    if status == 404:
        return None, "404 Not Found — resource absent, no validation issue"

    # 403 / 500 — only alert if body is large enough to be interesting
    if status in (403, 500):
        if body_bytes < min_bytes:
            return None, f"{status} with {body_bytes}B body — bare error page, no verbose content"
        else:
            return "LOW", (
                f"{status} with {body_bytes}B body — verbose error/forbidden response. "
                f"May contain stack trace, version, or internal detail."
            )

    # Alert codes — ordered by severity
    if status == 200:
        return "HIGH",   "200 OK — server accepted the payload without rejection"
    if status == 302:
        return "MEDIUM", "302 Found — redirect after payload accepted (possible login/flow bypass)"
    if status == 202:
        return "MEDIUM", "202 Accepted — async acceptance of payload"
    if status == 301:
        return "MEDIUM", "301 Moved Permanently — redirect (lower confidence than 302)"

    # Other 2xx / 3xx
    if 200 <= status < 400:
        return "LOW", f"{status} — unexpected success/redirect response"

    return None, f"{status} — no alert criteria met"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-BUSL-01 Script 2: Intruder results analyzer"
    )
    p.add_argument("--intruder",
        default=os.path.join("WSTG-BUSL-01", "inputs", "xml", "intruder_test.xml"),
        metavar="PATH",
        help="Burp Intruder results XML export")
    p.add_argument("--out-dir",
        default=os.path.join("WSTG-BUSL-01", "inputs", "json"),
        metavar="DIR",
        help="Output directory for intruder_alerts.json")
    p.add_argument("--min-bytes",
        type=int,
        default=500,
        metavar="N",
        help="Minimum response body size (bytes) for 403/500 to trigger alert (default: 500)")
    args = p.parse_args()

    width = 65
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD} WSTG-BUSL-01 — Intruder Results Analyzer{RESET}")
    print(f"{BOLD}{'='*width}{RESET}")
    print(f"  Intruder XML : {args.intruder}")
    print(f"  Min bytes    : {args.min_bytes} (403/500 alert threshold)\n")

    results = parse_intruder_xml(args.intruder)
    if not results:
        print(f"{YELLOW}[!] No items found in intruder XML.{RESET}\n")
        sys.exit(0)

    print(f"  {len(results)} intruder result(s) loaded\n")

    # Sort by serial number to process in order
    results.sort(key=lambda r: r["serial"])

    alerts          = []
    skipped         = 0
    eps_with_alerts = set()

    # Group by endpoint path for the findings metadata
    path_groups: dict[str, list[dict]] = {}

    for r in results:
        severity, reason = classify_response(r["status"], r["body_bytes"], args.min_bytes)
        test_case = infer_test_case(r["payload"])

        path_key = r["path"] or r["url"]

        if severity is None:
            skipped += 1
            print(
                f"  {DIM}[{r['serial']:4d}] {r['status']}  "
                f"{r['body_bytes']:6d}B  SKIP  {path_key[:45]}{RESET}"
            )
            continue

        # Alert
        col = SEVERITY_COLOR.get(severity, RESET)
        print(
            f"  {col}{BOLD}[{r['serial']:4d}] {r['status']}  "
            f"{r['body_bytes']:6d}B  {severity:<6}{RESET}  "
            f"{DIM}{test_case:<25}{RESET}  "
            f"{path_key[:35]}"
        )
        if r["payload"]:
            print(f"         payload: {r['payload'][:70]}")

        alert_entry = {
            "serial":       r["serial"],
            "endpoint_path": path_key,
            "parameter":    "",          # Burp Intruder XML doesn't always carry param name
            "value":        r["payload"],
            "return_code":  r["status"],
            "body_bytes":   r["body_bytes"],
            "test_case":    test_case,
            "severity":     severity,
            "reason":       reason,
        }
        alerts.append(alert_entry)
        eps_with_alerts.add(path_key)

        if path_key not in path_groups:
            path_groups[path_key] = []
        path_groups[path_key].append(alert_entry)

    # Sort alerts: HIGH first, then by severity rank, then by serial
    alerts.sort(key=lambda a: (SEVERITY_RANK.get(a["severity"], 99), a["serial"]))

    # Build findings metadata
    findings_metadata = {
        "endpoints_with_alerts": sorted(eps_with_alerts),
        "alert_count_by_severity": {
            "HIGH":   sum(1 for a in alerts if a["severity"] == "HIGH"),
            "MEDIUM": sum(1 for a in alerts if a["severity"] == "MEDIUM"),
            "LOW":    sum(1 for a in alerts if a["severity"] == "LOW"),
            "INFO":   sum(1 for a in alerts if a["severity"] == "INFO"),
        },
        "by_endpoint": {
            path: {
                "alert_count": len(entries),
                "severities":  list({e["severity"] for e in entries}),
                "test_cases":  list({e["test_case"] for e in entries}),
                "values":      [e["value"] for e in entries[:10]],  # first 10
            }
            for path, entries in path_groups.items()
        },
    }

    # Final output
    output = {
        "_meta": {
            "source_xml":  args.intruder,
            "generated":   datetime.now().isoformat(),
            "min_bytes":   args.min_bytes,
            "total_results": len(results),
            "alerts_found":  len(alerts),
            "skipped":       skipped,
        },
        "alerts": [
            {
                "endpoint_index": idx,
                "parameter":      a["parameter"],
                "value":          a["value"],
                "return_code":    a["return_code"],
                "test_case":      a["test_case"],
                "og_datatype":    (
                    "numeric" if re.search(
                        r'hex_|octal_|binary_|decimal_|integer_|negative_', a["test_case"]
                    ) else "alpha"
                ),
                "severity":       a["severity"],
                "reason":         a["reason"],
                "body_bytes":     a["body_bytes"],
                "path":           a["endpoint_path"],
            }
            for idx, a in enumerate(alerts)
        ],
        "findings_metadata": findings_metadata,
    }

    os.makedirs(args.out_dir, exist_ok=True)
    out_path = os.path.join(args.out_dir, "intruder_alerts.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    # Summary
    print(f"\n{BOLD}{'─'*width}{RESET}")
    print(f"\n{GREEN}[+] intruder_alerts.json → {out_path}{RESET}")
    print(f"    {len(results)} results processed  |  {len(alerts)} alert(s)  |  {skipped} skipped\n")

    meta = output["_meta"]
    bysev = findings_metadata["alert_count_by_severity"]
    if alerts:
        print(f"  Alert breakdown:")
        for sev in ("HIGH", "MEDIUM", "LOW", "INFO"):
            n   = bysev.get(sev, 0)
            col = SEVERITY_COLOR.get(sev, RESET)
            bar = "█" * n
            print(f"    {col}{sev:<8}{RESET}  {n:3d}  {bar}")
        print()
        print(f"  Endpoints with alerts ({len(eps_with_alerts)}):")
        for ep in sorted(eps_with_alerts):
            print(f"    {CYAN}{ep}{RESET}")
    else:
        print(f"  {GREEN}✓  No alerts — all responses within expected error range.{RESET}")
    print()


if __name__ == "__main__":
    main()
