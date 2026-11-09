#!/usr/bin/env python3
"""
WSTG-SESS-01 — Testing for Session Management Schema
Module 1: sess01_m1_string_seeker.py

Examines every Set-Cookie directive and request/response header
across the full XML walk to surface cookie security misconfigurations.

Checks:
  1. Are all Set-Cookie headers tagged Secure?
  2. Do any cookie operations occur over HTTP (unencrypted transport)?
  3. Can a cookie be forced over HTTP? (HTTP endpoint exists for same host)
  4. Are any cookies Persistent? (have Expires or Max-Age directive)
  5. Is the expiry time reasonable? (>24h flagged as long-lived)
  6. HTTP/1.1 Cache-Control directives present? (no-store, no-cache, must-revalidate)
  7. HTTP/1.0 Pragma: no-cache present?
  8. HttpOnly flag present on session cookies?
  9. SameSite attribute present and set to Strict or Lax?

Output:
  WSTG-SESS-01/outputs/m1_findings.json
  WSTG-SESS-01/outputs/m1_report.txt    (human-readable)

Usage:
  python3 WSTG-SESS-01/utilities/python/sess01_m1_string_seeker.py \\
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
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# ANSI
# ---------------------------------------------------------------------------
BOLD  = "\033[1m"
DIM   = "\033[2m"
GREEN = "\033[92m"
YELLOW= "\033[93m"
RED   = "\033[91m"
CYAN  = "\033[96m"
RESET = "\033[0m"


# ---------------------------------------------------------------------------
# Cache-Control values considered protective (per spec and OWASP)
# HTTP/1.1 response Cache-Control directives that protect sensitive content
# ---------------------------------------------------------------------------
HTTP11_PROTECTIVE_CACHE = [
    "no-store",
    "no-cache",
    "must-revalidate",
    "private",
]

# HTTP/1.0 protective header — Pragma: no-cache
HTTP10_PROTECTIVE_PRAGMA = "no-cache"

# Reasonable expiry threshold in seconds
# OWASP recommends session cookies expire when browser closes (no Max-Age/Expires)
# If persistent, anything beyond 24 hours is flagged as long-lived
REASONABLE_EXPIRY_SECONDS = 86400   # 24 hours


# ---------------------------------------------------------------------------
# Burp XML decode
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

        req_parts  = req.split("\r\n\r\n", 1)
        resp_parts = resp.split("\r\n\r\n", 1)

        items.append({
            "index":       idx,
            "url":         url,
            "method":      method,
            "req_head":    req_parts[0]  if req_parts  else "",
            "req_body":    req_parts[1]  if len(req_parts)  > 1 else "",
            "resp_head":   resp_parts[0] if resp_parts else "",
            "resp_body":   resp_parts[1] if len(resp_parts) > 1 else "",
            "status":      status,
        })
    return items


# ---------------------------------------------------------------------------
# Header parsers
# ---------------------------------------------------------------------------

def parse_headers(raw_head: str) -> dict[str, list[str]]:
    """
    Returns {header_name_lower: [value, ...]} allowing multiple values
    for the same header (e.g. multiple Set-Cookie lines).
    """
    result = defaultdict(list)
    for line in raw_head.splitlines()[1:]:   # skip request/status line
        if ":" in line:
            k, _, v = line.partition(":")
            result[k.strip().lower()].append(v.strip())
    return dict(result)


def parse_set_cookie(raw_line: str) -> dict:
    """
    Parses one Set-Cookie value string into structured fields.
    e.g. "sessionid=abc123; Secure; HttpOnly; SameSite=Strict; Max-Age=3600"
    """
    parts    = [p.strip() for p in raw_line.split(";")]
    name_val = parts[0]
    name, _, value = name_val.partition("=")

    directives = {}
    for part in parts[1:]:
        if "=" in part:
            dk, _, dv = part.partition("=")
            directives[dk.strip().lower()] = dv.strip()
        else:
            directives[part.strip().lower()] = True

    return {
        "name":       name.strip(),
        "value":      value.strip(),
        "secure":     "secure"    in directives,
        "httponly":   "httponly"  in directives,
        "samesite":   directives.get("samesite", None),
        "max_age":    directives.get("max-age",  None),
        "expires":    directives.get("expires",  None),
        "path":       directives.get("path",     None),
        "domain":     directives.get("domain",   None),
        "raw":        raw_line,
    }


def seconds_until_expiry(sc: dict) -> int | None:
    """
    Returns seconds until expiry from Max-Age or Expires.
    Returns None if cookie is session-scoped (no expiry directive).
    """
    if sc["max_age"] is not None:
        try:
            return int(sc["max_age"])
        except ValueError:
            return None
    if sc["expires"] is not None:
        try:
            exp_dt = parsedate_to_datetime(sc["expires"])
            now    = datetime.now(timezone.utc)
            delta  = (exp_dt - now).total_seconds()
            return int(delta)
        except Exception:
            return None
    return None


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

Finding = dict   # {check_id, severity, url, cookie_name, detail}

def run_checks(items: list[dict]) -> list[Finding]:
    findings = []

    # Collect all hosts seen in the walk to detect HTTP endpoints
    https_hosts: set[str] = set()
    http_hosts:  set[str] = set()

    for item in items:
        parsed = urlparse(item["url"])
        scheme = parsed.scheme.lower()
        host   = parsed.netloc
        if scheme == "https":
            https_hosts.add(host)
        elif scheme == "http":
            http_hosts.add(host)

    for item in items:
        parsed    = urlparse(item["url"])
        scheme    = parsed.scheme.lower()
        url       = item["url"]
        idx       = item["index"]
        resp_hdrs = parse_headers(item["resp_head"])
        req_hdrs  = parse_headers(item["req_head"])

        set_cookie_lines = resp_hdrs.get("set-cookie", [])

        for sc_raw in set_cookie_lines:
            sc = parse_set_cookie(sc_raw)
            name = sc["name"]

            # ── Check 1: Secure flag ───────────────────────────────────
            if not sc["secure"]:
                findings.append({
                    "check_id":    "C1_SECURE_FLAG",
                    "severity":    "HIGH",
                    "url":         url,
                    "cookie_name": name,
                    "detail":      f"Set-Cookie for '{name}' is missing the Secure flag. "
                                   f"Cookie may be transmitted over HTTP.",
                })

            # ── Check 2: Cookie set/sent over HTTP ─────────────────────
            if scheme == "http":
                findings.append({
                    "check_id":    "C2_HTTP_TRANSPORT",
                    "severity":    "HIGH",
                    "url":         url,
                    "cookie_name": name,
                    "detail":      f"Set-Cookie for '{name}' issued over plaintext HTTP "
                                   f"at {url}",
                })

            # ── Check 3: HTTP endpoint exists for same host ────────────
            if parsed.netloc in http_hosts and scheme == "https":
                findings.append({
                    "check_id":    "C3_HTTP_DOWNGRADE_POSSIBLE",
                    "severity":    "MEDIUM",
                    "url":         url,
                    "cookie_name": name,
                    "detail":      f"Cookie '{name}' set over HTTPS but HTTP endpoints "
                                   f"exist on same host ({parsed.netloc}). "
                                   f"Cookie may be forceable over unencrypted transport "
                                   f"if HSTS is absent.",
                })

            # ── Check 4 & 5: Persistent + expiry time ─────────────────
            expiry_secs = seconds_until_expiry(sc)
            if expiry_secs is not None:
                if expiry_secs > REASONABLE_EXPIRY_SECONDS:
                    findings.append({
                        "check_id":    "C4_PERSISTENT_LONG",
                        "severity":    "MEDIUM",
                        "url":         url,
                        "cookie_name": name,
                        "detail":      f"Cookie '{name}' is persistent with expiry "
                                       f"~{expiry_secs // 3600}h. "
                                       f"Threshold is {REASONABLE_EXPIRY_SECONDS // 3600}h. "
                                       f"Long-lived session cookies increase the window for "
                                       f"session hijacking.",
                    })
                elif expiry_secs <= 0:
                    findings.append({
                        "check_id":    "C4_ALREADY_EXPIRED",
                        "severity":    "INFO",
                        "url":         url,
                        "cookie_name": name,
                        "detail":      f"Cookie '{name}' has already-expired or zero Max-Age "
                                       f"(may be a logout/clear operation).",
                    })
                else:
                    findings.append({
                        "check_id":    "C4_PERSISTENT_REASONABLE",
                        "severity":    "INFO",
                        "url":         url,
                        "cookie_name": name,
                        "detail":      f"Cookie '{name}' is persistent, expiry "
                                       f"~{expiry_secs // 60}min (within threshold).",
                    })
            # No expiry directive = session cookie = good
            else:
                findings.append({
                    "check_id":    "C4_SESSION_SCOPED",
                    "severity":    "INFO",
                    "url":         url,
                    "cookie_name": name,
                    "detail":      f"Cookie '{name}' is session-scoped (no Expires/Max-Age). Good.",
                })

            # ── Check 8: HttpOnly ──────────────────────────────────────
            if not sc["httponly"]:
                findings.append({
                    "check_id":    "C8_HTTPONLY",
                    "severity":    "MEDIUM",
                    "url":         url,
                    "cookie_name": name,
                    "detail":      f"Cookie '{name}' is missing HttpOnly. "
                                   f"Accessible via JavaScript — XSS → session theft.",
                })

            # ── Check 9: SameSite ──────────────────────────────────────
            ss = sc["samesite"]
            if ss is None:
                findings.append({
                    "check_id":    "C9_SAMESITE_ABSENT",
                    "severity":    "LOW",
                    "url":         url,
                    "cookie_name": name,
                    "detail":      f"Cookie '{name}' has no SameSite attribute. "
                                   f"Browsers default to Lax in modern Chrome/Firefox, "
                                   f"but explicit declaration is preferred.",
                })
            elif ss.lower() == "none":
                findings.append({
                    "check_id":    "C9_SAMESITE_NONE",
                    "severity":    "MEDIUM",
                    "url":         url,
                    "cookie_name": name,
                    "detail":      f"Cookie '{name}' has SameSite=None — "
                                   f"sent on all cross-site requests. CSRF risk.",
                })

        # ── Check 6: HTTP/1.1 Cache-Control ───────────────────────────
        cache_vals = [v.lower() for v in resp_hdrs.get("cache-control", [])]
        cache_str  = " ".join(cache_vals)
        missing_cc = [d for d in HTTP11_PROTECTIVE_CACHE if d not in cache_str]
        if missing_cc and set_cookie_lines:
            # Only flag on responses that set cookies (otherwise noise)
            findings.append({
                "check_id":    "C6_CACHE_CONTROL_HTTP11",
                "severity":    "LOW",
                "url":         url,
                "cookie_name": "(response)",
                "detail":      f"Response sets cookie(s) but Cache-Control is missing "
                               f"protective directives: {', '.join(missing_cc)}. "
                               f"Sensitive pages may be cached by intermediaries.",
            })

        # ── Check 7: HTTP/1.0 Pragma ───────────────────────────────────
        pragma_vals = [v.lower() for v in resp_hdrs.get("pragma", [])]
        if set_cookie_lines and HTTP10_PROTECTIVE_PRAGMA not in " ".join(pragma_vals):
            findings.append({
                "check_id":    "C7_PRAGMA_HTTP10",
                "severity":    "LOW",
                "url":         url,
                "cookie_name": "(response)",
                "detail":      f"Response sets cookie(s) but Pragma: no-cache is absent. "
                               f"HTTP/1.0 proxies may cache this response.",
            })

    return findings


# ---------------------------------------------------------------------------
# Report printer
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
SEVERITY_COLOR = {
    "HIGH":   RED,
    "MEDIUM": YELLOW,
    "LOW":    CYAN,
    "INFO":   DIM,
}


def print_and_write_report(findings: list[Finding], out_dir: str):
    by_sev = defaultdict(list)
    for f in findings:
        by_sev[f["severity"]].append(f)

    lines = []
    lines.append("WSTG-SESS-01 M1 — String Seeker Findings")
    lines.append("=" * 65)

    for sev in ["HIGH", "MEDIUM", "LOW", "INFO"]:
        group = by_sev.get(sev, [])
        if not group:
            continue
        lines.append(f"\n[{sev}] — {len(group)} finding(s)")
        lines.append("-" * 40)
        for f in group:
            lines.append(f"  Check : {f['check_id']}")
            lines.append(f"  Cookie: {f['cookie_name']}")
            lines.append(f"  URL   : {f['url']}")
            lines.append(f"  Detail: {f['detail']}")
            lines.append("")

    # Print to terminal
    print()
    for line in lines:
        sev_match = None
        for s in SEVERITY_ORDER:
            if f"[{s}]" in line:
                sev_match = s
                break
        if sev_match:
            print(f"{SEVERITY_COLOR[sev_match]}{BOLD}{line}{RESET}")
        else:
            print(f"  {line}")

    # Write to file
    report_path = os.path.join(out_dir, "m1_report.txt")
    with open(report_path, "w") as f:
        f.write("\n".join(lines))
    print(f"\n{GREEN}[+] {report_path}{RESET}")

    json_path = os.path.join(out_dir, "m1_findings.json")
    with open(json_path, "w") as f:
        json.dump(findings, f, indent=2)
    print(f"{GREEN}[+] {json_path}{RESET}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="SESS-01 M1: Cookie security string seeker"
    )
    p.add_argument("--xml",
        default=os.path.join("WSTG-SESS-01", "inputs", "xml", "session_walk.xml"),
        metavar="PATH")
    p.add_argument("--out-dir",
        default=os.path.join("WSTG-SESS-01", "outputs"),
        metavar="DIR")
    args = p.parse_args()

    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"{BOLD} WSTG-SESS-01 M1 — String Seeker{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"  XML: {args.xml}\n")

    items    = parse_burp_xml(args.xml)
    findings = run_checks(items)

    os.makedirs(args.out_dir, exist_ok=True)
    print_and_write_report(findings, args.out_dir)

    highs = sum(1 for f in findings if f["severity"] == "HIGH")
    meds  = sum(1 for f in findings if f["severity"] == "MEDIUM")
    print(f"  Summary: {RED}{highs} HIGH{RESET}  {YELLOW}{meds} MEDIUM{RESET}  "
          f"{len([f for f in findings if f['severity']=='LOW'])} LOW  "
          f"{len([f for f in findings if f['severity']=='INFO'])} INFO")
    print(f"\n  Next: sess01_m2_cookie_analyzer.py")
    print()


if __name__ == "__main__":
    main()
