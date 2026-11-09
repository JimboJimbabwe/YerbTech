#!/usr/bin/env python3
"""
WSTG-ATHZ-04 — Testing for Insecure Direct Object References (IDOR)
Script: athz_04_scan.py

Reads a Burp proxy history XML export and scans every request/response
across four locations for values that match known weak-entropy or
enumerable ID patterns:

  Patterns detected:
    - Sequential integers            (HIGH)
    - Base64-encoded integers        (HIGH)
    - Hex-encoded integers           (HIGH)
    - MongoDB ObjectIDs              (HIGH)
    - UUIDv1 (time-based)            (MEDIUM)
    - UUIDv4 (random)                (LOW)
    - Unix timestamps (seconds)      (HIGH)
    - Unix timestamps (milliseconds) (HIGH)
    - Compound IDs with numeric part (HIGH)

  Scan locations per item:
    1. URL parameters
    2. Request body parameters
    3. Request/response headers
    4. Raw body (JSON/XML field extraction)

Findings are deduplicated on (pattern_type, location, value).

Usage:
  python3 WSTG-ATHZ-04/utilities/python/athz_04_scan.py \\
      [--proxy  WSTG-ATHZ-04/inputs/xml/proxy_history.xml] \\
      [--min-confidence  MEDIUM]

Outputs:
  WSTG-ATHZ-04/outputs/test_outputs/athz04_findings.json
  WSTG-ATHZ-04/outputs/test_outputs/athz04_report.md
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

CONF_COLOR = {"HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN}
WIDTH = 65


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


def split_headers_body(raw: str) -> tuple[str, str]:
    sep = raw.find("\r\n\r\n")
    if sep == -1:
        sep = raw.find("\n\n")
        if sep == -1:
            return raw, ""
        return raw[:sep], raw[sep + 2:]
    return raw[:sep], raw[sep + 4:]


def parse_headers(raw: str) -> list[tuple[str, str]]:
    """Returns list of (name, value) tuples, skipping request/status line."""
    result = []
    lines  = raw.splitlines()
    for line in lines[1:]:
        if not line.strip():
            break
        if ":" in line:
            k, _, v = line.partition(":")
            result.append((k.strip(), v.strip()))
    return result


def parse_url_params(url: str) -> list[tuple[str, str]]:
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=False)
        return [(k, v[0]) for k, v in params.items() if v]
    except Exception:
        return []


def parse_body_params(body: str) -> list[tuple[str, str]]:
    """Parse application/x-www-form-urlencoded body."""
    if not body or "=" not in body:
        return []
    try:
        params = parse_qs(body.strip(), keep_blank_values=False)
        return [(k, v[0]) for k, v in params.items() if v]
    except Exception:
        return []


# JSON/XML field patterns for raw body scan
_BODY_FIELD_PATTERNS = [
    re.compile(r'"(?:id|_id|userId|user_id|orderId|order_id|accountId|account_id|'
               r'customerId|customer_id|recordId|record_id|itemId|item_id|'
               r'fileId|file_id|docId|doc_id|uuid|objectId)"\s*:\s*"([^"]{2,})"',
               re.IGNORECASE),
    re.compile(r'"(?:id|_id|userId|user_id|orderId|accountId|customerId|recordId|'
               r'itemId|fileId|docId)"\s*:\s*(\d{2,})',
               re.IGNORECASE),
    re.compile(r'<(?:id|userId|orderId|accountId|recordId)>([^<]{2,})</\w+>',
               re.IGNORECASE),
]


def extract_body_fields(body: str) -> list[tuple[str, str]]:
    """Returns list of (field_name_hint, value) from JSON/XML body."""
    results = []
    seen    = set()
    for pat in _BODY_FIELD_PATTERNS:
        for m in pat.finditer(body):
            val = m.group(1).strip()
            hint = m.group(0)[:40]
            key  = (hint, val)
            if key not in seen:
                seen.add(key)
                results.append((hint, val))
    return results


# ---------------------------------------------------------------------------
# Pattern detector
# ---------------------------------------------------------------------------

# Auth-related header names to skip (not IDOR candidates)
_SKIP_HEADERS = {
    "authorization", "cookie", "set-cookie", "x-auth-token",
    "x-api-key", "x-access-token", "x-session-token",
    "x-csrf-token", "x-xsrf-token", "content-type",
    "accept", "user-agent", "referer", "origin", "host",
    "accept-encoding", "accept-language", "connection",
    "cache-control", "pragma",
}


def _try_base64_int(s: str):
    if not re.match(r'^[A-Za-z0-9+/]{4,}={0,2}$', s):
        return None
    try:
        decoded = base64.b64decode(s + "==").decode("utf-8", errors="ignore").strip()
        if decoded.isdigit() and len(decoded) >= 2:
            return decoded
        if re.match(r'^[a-zA-Z0-9_-]{2,48}$', decoded):
            return decoded
    except Exception:
        pass
    return None


def _try_hex_int(s: str):
    clean = s.replace("0x", "").replace("0X", "")
    if not re.match(r'^[0-9a-fA-F]{2,16}$', clean):
        return None
    # Exclude pure-decimal strings that also happen to be valid hex
    if s.isdigit():
        return None
    try:
        val = int(clean, 16)
        if 0 < val < 10**15:
            return val
    except Exception:
        pass
    return None


_UUID_RE = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
)
_MONGO_RE = re.compile(r'^[0-9a-fA-F]{24}$')


def detect_patterns(value: str) -> list[dict]:
    if not value or len(value) < 2:
        return []

    patterns = []
    v = value.strip()

    # Sequential integer (2–10 digits, not a timestamp)
    if v.isdigit() and 2 <= len(v) <= 9:
        patterns.append({
            "type":        "Sequential Integer",
            "confidence":  "HIGH",
            "description": "Numeric ID — directly enumerable",
            "exploitation":"Increment or decrement to access other records",
            "generator":   ("sequential_int", int(v)),
        })

    # Unix timestamp (seconds) — 10 digits
    if v.isdigit() and len(v) == 10:
        patterns.append({
            "type":        "Unix Timestamp (seconds)",
            "confidence":  "HIGH",
            "description": "Epoch timestamp in seconds",
            "exploitation":"Enumerate timestamps before/after to find adjacent records",
            "generator":   ("unix_timestamp", int(v)),
        })

    # Unix timestamp (milliseconds) — 13 digits
    if v.isdigit() and len(v) == 13:
        patterns.append({
            "type":        "Unix Timestamp (milliseconds)",
            "confidence":  "HIGH",
            "description": "Epoch timestamp in milliseconds",
            "exploitation":"Enumerate timestamps in ±60s window",
            "generator":   ("unix_timestamp_ms", int(v)),
        })

    # Base64-encoded integer
    b64 = _try_base64_int(v)
    if b64:
        patterns.append({
            "type":        "Base64 Encoded ID",
            "confidence":  "HIGH",
            "description": f"Base64 decodes to: {b64}",
            "exploitation":"Decode → increment → re-encode",
            "generator":   ("base64_int", b64),
        })

    # Hex-encoded integer
    hex_val = _try_hex_int(v)
    if hex_val is not None:
        patterns.append({
            "type":        "Hex Encoded Integer",
            "confidence":  "HIGH",
            "description": f"Hex value: {hex_val} (decimal)",
            "exploitation":"Convert to decimal → increment → convert back",
            "generator":   ("hex_int", hex_val),
        })

    # MongoDB ObjectID (24 hex chars)
    if _MONGO_RE.match(v):
        ts_hex  = v[:8]
        ctr_hex = v[-6:]
        patterns.append({
            "type":        "MongoDB ObjectID",
            "confidence":  "HIGH",
            "description": f"Timestamp segment: {ts_hex}, Counter: {ctr_hex}",
            "exploitation":"Keep timestamp, enumerate counter (last 6 hex chars)",
            "generator":   ("mongodb_objectid", ts_hex, int(ctr_hex, 16)),
        })

    # UUID
    if _UUID_RE.match(v):
        version = v[14] if len(v) > 14 else "?"
        if version == "1":
            patterns.append({
                "type":        "UUIDv1 (Time-based)",
                "confidence":  "MEDIUM",
                "description": "Time-based UUID — partially predictable",
                "exploitation":"Extract timestamp segment, generate nearby UUIDs",
                "generator":   ("uuidv1", v),
            })
        elif version == "4":
            patterns.append({
                "type":        "UUIDv4 (Random)",
                "confidence":  "LOW",
                "description": "Cryptographically random — likely secure",
                "exploitation":"Not typically enumerable",
                "generator":   None,
            })

    # Compound ID with numeric part
    if not patterns:  # only if no stronger match already
        for sep in ("-", "_", "."):
            if sep in v:
                parts = v.split(sep)
                numeric = [(i, p) for i, p in enumerate(parts) if p.isdigit()]
                if numeric and len(parts) >= 2:
                    patterns.append({
                        "type":        "Compound ID",
                        "confidence":  "HIGH",
                        "description": f"Parts: {parts}  numeric segments: {[p for _,p in numeric]}",
                        "exploitation":f"Enumerate the numeric part(s): {[p for _,p in numeric]}",
                        "generator":   ("compound_id", parts, sep, numeric),
                    })
                    break

    return patterns


# ---------------------------------------------------------------------------
# XML loader
# ---------------------------------------------------------------------------

def load_proxy_xml(xml_path: str) -> list[dict]:
    try:
        tree = ET.parse(xml_path)
    except FileNotFoundError:
        print(f"{RED}[!] Proxy XML not found: {xml_path}{RESET}", file=sys.stderr)
        sys.exit(1)
    except ET.ParseError as e:
        print(f"{RED}[!] XML parse error: {e}{RESET}", file=sys.stderr)
        sys.exit(1)

    root      = tree.getroot()
    item_list = root.findall("item") if root.tag == "items" else root.findall(".//item")

    items = []
    for item in item_list:
        url          = decode_element(item.find("url"))
        request_raw  = decode_element(item.find("request"))
        response_raw = decode_element(item.find("response"))
        items.append({"url": url, "request_raw": request_raw, "response_raw": response_raw})

    return items


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

CONF_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def scan_items(items: list[dict], min_confidence: str) -> list[dict]:
    min_rank = CONF_RANK.get(min_confidence.upper(), 2)
    findings = []
    seen     = set()   # (type, location_key, value)

    def add(url, location, param_name, value, pat):
        rank = CONF_RANK.get(pat["confidence"], 9)
        if rank > min_rank:
            return
        key = (pat["type"], location, param_name, value[:60])
        if key in seen:
            return
        seen.add(key)
        findings.append({
            "url":         url,
            "location":    location,
            "param_name":  param_name,
            "value":       value,
            "type":        pat["type"],
            "confidence":  pat["confidence"],
            "description": pat["description"],
            "exploitation":pat["exploitation"],
            "generator":   pat.get("generator"),
        })

    for item in items:
        url          = item["url"]
        req_raw      = item["request_raw"]
        resp_raw     = item["response_raw"]
        req_hdr, req_body = split_headers_body(req_raw)
        _,        resp_body = split_headers_body(resp_raw)

        # 1. URL parameters
        for name, val in parse_url_params(url):
            for pat in detect_patterns(unquote(val)):
                add(url, "URL Parameter", name, unquote(val), pat)

        # 2. Request body parameters
        for name, val in parse_body_params(req_body):
            for pat in detect_patterns(unquote(val)):
                add(url, "Request Body Parameter", name, unquote(val), pat)

        # 3. Request headers (skip auth/session headers)
        for name, val in parse_headers(req_raw):
            if name.lower() in _SKIP_HEADERS:
                continue
            for pat in detect_patterns(val):
                add(url, "Request Header", name, val, pat)

        # 4. Response headers
        for name, val in parse_headers(resp_raw):
            if name.lower() in _SKIP_HEADERS:
                continue
            for pat in detect_patterns(val):
                add(url, "Response Header", name, val, pat)

        # 5. Raw body field extraction (JSON/XML)
        for hint, val in extract_body_fields(req_body):
            for pat in detect_patterns(val):
                add(url, "Request Body Field", hint[:50], val, pat)

        for hint, val in extract_body_fields(resp_body):
            for pat in detect_patterns(val):
                add(url, "Response Body Field", hint[:50], val, pat)

    return findings


# ---------------------------------------------------------------------------
# Output builders
# ---------------------------------------------------------------------------

def write_json(findings: list[dict], meta: dict, path: str):
    # generator tuples aren't JSON-serializable as-is; convert to list
    out_findings = []
    for f in findings:
        fc = dict(f)
        if fc.get("generator") and isinstance(fc["generator"], tuple):
            fc["generator"] = list(fc["generator"])
        out_findings.append(fc)

    out = {"_meta": meta, "findings": out_findings}
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)


def write_markdown(findings: list[dict], meta: dict, path: str) -> None:
    now_str = meta["generated"]
    lines   = []
    lines.append("# WSTG-ATHZ-04 — IDOR Pattern Scan Report")
    lines.append("")
    lines.append(f"**Generated:** {now_str}  ")
    lines.append(f"**Proxy XML:** `{meta['proxy_xml']}`  ")
    lines.append(f"**Items scanned:** {meta['items_scanned']}  ")
    lines.append(f"**Findings:** {len(findings)}  ")
    lines.append("")

    if not findings:
        lines.append("No IDOR patterns detected.")
        lines.append("")
        lines.append("---")
        lines.append("*Generated by athz_04_scan.py — WSTG-ATHZ-04*")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        return

    # Group by confidence
    for conf in ("HIGH", "MEDIUM", "LOW"):
        group = [f for f in findings if f["confidence"] == conf]
        if not group:
            continue
        lines.append(f"## {conf} Confidence ({len(group)})")
        lines.append("")
        for i, f in enumerate(group, start=1):
            lines.append(f"### [{conf}] {f['type']} — `{f['param_name']}`")
            lines.append("")
            lines.append(f"- **URL:** `{f['url']}`")
            lines.append(f"- **Location:** {f['location']}")
            lines.append(f"- **Value:** `{f['value']}`")
            lines.append(f"- **Description:** {f['description']}")
            lines.append(f"- **Exploitation:** {f['exploitation']}")
            lines.append("")
            lines.append(f"  > Run `athz_04_wordlist.py` to generate an enumeration "
                         f"wordlist for this finding.")
            lines.append("")

    lines.append("---")
    lines.append("*Generated by athz_04_scan.py — WSTG-ATHZ-04*")

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-ATHZ-04 IDOR pattern scanner"
    )
    p.add_argument("--proxy",
        default=os.path.join("WSTG-ATHZ-04", "inputs", "xml", "proxy_history.xml"),
        metavar="PATH",
        help="Burp proxy history XML export")
    p.add_argument("--json-out",
        default=os.path.join("WSTG-ATHZ-04", "outputs", "test_outputs", "athz04_findings.json"),
        metavar="PATH")
    p.add_argument("--md-out",
        default=os.path.join("WSTG-ATHZ-04", "outputs", "test_outputs", "athz04_report.md"),
        metavar="PATH")
    p.add_argument("--min-confidence",
        default="LOW",
        choices=["HIGH", "MEDIUM", "LOW"],
        metavar="LEVEL",
        help="Minimum confidence to report: HIGH | MEDIUM | LOW  (default: LOW)")
    args = p.parse_args()

    print(f"\n{BOLD}{'='*WIDTH}{RESET}")
    print(f"{BOLD}  WSTG-ATHZ-04 — IDOR Pattern Scanner{RESET}")
    print(f"{BOLD}{'='*WIDTH}{RESET}\n")
    print(f"  Proxy XML       : {args.proxy}")
    print(f"  Min confidence  : {args.min_confidence}\n")

    items = load_proxy_xml(args.proxy)
    print(f"  {DIM}{len(items)} items loaded{RESET}\n")

    findings = scan_items(items, args.min_confidence)

    # ── Terminal summary ─────────────────────────────────────────────────────
    conf_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    type_counts: dict[str, int] = {}
    for f in findings:
        conf_counts[f["confidence"]] = conf_counts.get(f["confidence"], 0) + 1
        type_counts[f["type"]]       = type_counts.get(f["type"], 0) + 1

    print(f"  {'─'*50}")
    print(f"  Items scanned : {len(items)}")
    print(f"  Findings      : {len(findings)}")
    print()

    for conf in ("HIGH", "MEDIUM", "LOW"):
        c = conf_counts.get(conf, 0)
        if c:
            print(f"  {CONF_COLOR.get(conf, RESET)}{conf:<10}{RESET}  {c}")

    if type_counts:
        print()
        print(f"  {'Pattern type':<35} {'Count':>5}")
        print(f"  {'─'*42}")
        for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
            print(f"  {t:<35} {c:>5}")

    # Print HIGH/MEDIUM inline
    notable = [f for f in findings if f["confidence"] in ("HIGH", "MEDIUM")]
    if notable:
        print(f"\n  {'─'*50}")
        for f in notable[:20]:
            col = CONF_COLOR.get(f["confidence"], RESET)
            path = urlparse(f["url"]).path or f["url"]
            print(f"  {col}{f['confidence']:<8}{RESET}  "
                  f"{f['type']:<30}  "
                  f"{f['param_name'][:20]:<20}  "
                  f"{path[:35]}")
        if len(notable) > 20:
            print(f"  {DIM}... {len(notable)-20} more in output files{RESET}")

    # ── Write outputs ────────────────────────────────────────────────────────
    meta = {
        "generated":      datetime.now().isoformat(),
        "proxy_xml":      args.proxy,
        "items_scanned":  len(items),
        "total_findings": len(findings),
        "conf_counts":    conf_counts,
        "type_counts":    type_counts,
    }
    write_json(findings, meta, args.json_out)
    write_markdown(findings, meta, args.md_out)

    print(f"\n  {GREEN}[+] findings JSON  →  {args.json_out}{RESET}")
    print(f"  {GREEN}[+] report MD      →  {args.md_out}{RESET}")
    print(f"\n  {DIM}Run athz_04_wordlist.py to generate enumeration wordlists.{RESET}\n")


if __name__ == "__main__":
    main()
