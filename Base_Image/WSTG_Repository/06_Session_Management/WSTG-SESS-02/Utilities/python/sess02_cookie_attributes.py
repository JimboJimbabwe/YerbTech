#!/usr/bin/env python3
"""
WSTG-SESS-02 — Testing for Cookie Attributes
sess02_cookie_attributes.py

Reads a Burp Suite XML export and audits every Set-Cookie directive
across all responses. For each endpoint that sets a cookie, checks:

  Attributes audited
  ──────────────────
  Secure          — must be present (HIGH if absent)
  HttpOnly        — must be present (MEDIUM if absent)
  Domain          — informational; over-broad domain widens cookie scope
  Path            — informational; "/" is broad but normal
  Expires/Max-Age — persistent cookies flagged (MEDIUM if >24h)
  SameSite        — must be Strict or Lax
    SameSite=None   → MEDIUM (sent cross-site, CSRF surface)
    SameSite=Lax    → INFO  (top-level GET navigation unprotected)
    SameSite absent → LOW

  Secure prefix rules (RFC 6265bis)
  ──────────────────────────────────
  __Secure-  cookie must: have Secure flag; be set over HTTPS
  __Host-    cookie must: have Secure flag; be set over HTTPS;
                          have no Domain directive; have Path=/

  If a cookie claims a prefix but violates its requirements → HIGH

Inputs:
  WSTG-SESS-02/inputs/xml/<filename>.xml   (--xml)

Outputs:
  WSTG-SESS-02/outputs/test_outputs/<filename>_report.md
  WSTG-SESS-02/outputs/test_outputs/<filename>_findings.json

Usage:
  python3 WSTG-SESS-02/utilities/python/sess02_cookie_attributes.py \\
      --xml WSTG-SESS-02/inputs/xml/session_walk.xml
"""

import argparse
import base64
import json
import os
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
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
BLUE   = "\033[94m"
RESET  = "\033[0m"

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3, "PASS": 4}
SEVERITY_EMOJI = {
    "HIGH":   "🔴",
    "MEDIUM": "🟡",
    "LOW":    "🔵",
    "INFO":   "ℹ️",
    "PASS":   "✅",
}
SEVERITY_COLOR = {
    "HIGH":   RED,
    "MEDIUM": YELLOW,
    "LOW":    CYAN,
    "INFO":   DIM,
    "PASS":   GREEN,
}

REASONABLE_EXPIRY_SECONDS = 86400  # 24 hours


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

        resp_parts = resp.split("\r\n\r\n", 1)

        items.append({
            "index":     idx,
            "url":       url,
            "method":    method,
            "status":    status,
            "resp_head": resp_parts[0] if resp_parts else "",
        })
    return items


# ---------------------------------------------------------------------------
# Header / Set-Cookie parsing
# ---------------------------------------------------------------------------

def parse_resp_headers(raw: str) -> dict[str, list[str]]:
    """Returns {header_name_lower: [value, ...]}"""
    result = defaultdict(list)
    for line in raw.splitlines()[1:]:   # skip status line
        if ":" in line:
            k, _, v = line.partition(":")
            result[k.strip().lower()].append(v.strip())
    return dict(result)


def parse_set_cookie(raw_line: str) -> dict:
    """
    Parses one Set-Cookie value into structured fields.
    e.g. "sessionid=abc123; Secure; HttpOnly; SameSite=Strict; Max-Age=3600"
    """
    parts    = [p.strip() for p in raw_line.split(";")]
    name_val = parts[0]
    name, _, value = name_val.partition("=")
    name  = name.strip()
    value = value.strip()

    directives = {}
    for part in parts[1:]:
        if "=" in part:
            dk, _, dv = part.partition("=")
            directives[dk.strip().lower()] = dv.strip()
        else:
            key = part.strip().lower()
            if key:
                directives[key] = True

    samesite_raw = directives.get("samesite", None)
    samesite     = samesite_raw.lower() if isinstance(samesite_raw, str) else samesite_raw

    return {
        "name":       name,
        "value":      value,
        "secure":     "secure"   in directives,
        "httponly":   "httponly" in directives,
        "samesite":   samesite,          # None | "strict" | "lax" | "none"
        "domain":     directives.get("domain",   None),
        "path":       directives.get("path",     None),
        "max_age":    directives.get("max-age",  None),
        "expires":    directives.get("expires",  None),
        "raw":        raw_line,
        "directives": directives,
    }


def seconds_until_expiry(sc: dict) -> int | None:
    """None = session-scoped cookie."""
    if sc["max_age"] is not None:
        try:
            return int(sc["max_age"])
        except ValueError:
            return None
    if sc["expires"] is not None:
        try:
            exp_dt = parsedate_to_datetime(sc["expires"])
            now    = datetime.now(timezone.utc)
            return int((exp_dt - now).total_seconds())
        except Exception:
            return None
    return None


# ---------------------------------------------------------------------------
# Attribute checks
# ---------------------------------------------------------------------------

def check_cookie(sc: dict, scheme: str, url: str) -> list[dict]:
    """
    Returns list of finding dicts for one parsed Set-Cookie.

    Each finding: {
        cookie_name, attribute, severity, status,
        verdict, detail, url
    }
    """
    name     = sc["name"]
    findings = []

    def finding(attribute, severity, verdict, detail, status=None):
        findings.append({
            "cookie_name": name,
            "attribute":   attribute,
            "severity":    severity,
            "status":      status or severity,
            "verdict":     verdict,
            "detail":      detail,
            "url":         url,
        })

    # ── Secure prefix validation ────────────────────────────────────────────
    if name.startswith("__Host-"):
        violations = []
        if not sc["secure"]:
            violations.append("missing Secure flag")
        if scheme != "https":
            violations.append("set over HTTP (not HTTPS)")
        if sc["domain"] is not None:
            violations.append(f"has Domain directive ({sc['domain']})")
        if sc["path"] != "/":
            violations.append(f"Path is not '/' (got: {sc['path']!r})")
        if violations:
            finding(
                "Secure Prefix (__Host-)",
                "HIGH",
                "FAIL",
                f"Cookie claims __Host- prefix but violates requirements: "
                f"{'; '.join(violations)}. "
                f"Prefix is cosmetic only — browser will still accept it, "
                f"but the protections the prefix implies are absent.",
            )
        else:
            finding(
                "Secure Prefix (__Host-)",
                "PASS",
                "PASS",
                "__Host- prefix requirements satisfied (Secure, HTTPS, no Domain, Path=/).",
            )

    elif name.startswith("__Secure-"):
        violations = []
        if not sc["secure"]:
            violations.append("missing Secure flag")
        if scheme != "https":
            violations.append("set over HTTP (not HTTPS)")
        if violations:
            finding(
                "Secure Prefix (__Secure-)",
                "HIGH",
                "FAIL",
                f"Cookie claims __Secure- prefix but violates requirements: "
                f"{'; '.join(violations)}.",
            )
        else:
            finding(
                "Secure Prefix (__Secure-)",
                "PASS",
                "PASS",
                "__Secure- prefix requirements satisfied (Secure flag + HTTPS).",
            )

    # ── Secure flag ─────────────────────────────────────────────────────────
    if not sc["secure"]:
        finding(
            "Secure",
            "HIGH",
            "MISSING",
            f"Secure flag absent. Cookie may be transmitted over plaintext HTTP "
            f"(e.g. mixed-content requests, HTTP redirects before HTTPS upgrade).",
        )
    else:
        finding("Secure", "PASS", "PRESENT", "Secure flag is set.")

    # ── HttpOnly ─────────────────────────────────────────────────────────────
    if not sc["httponly"]:
        finding(
            "HttpOnly",
            "MEDIUM",
            "MISSING",
            f"HttpOnly flag absent. Cookie is accessible via JavaScript. "
            f"XSS vulnerability on any page in scope → attacker can read this cookie.",
        )
    else:
        finding("HttpOnly", "PASS", "PRESENT", "HttpOnly flag is set.")

    # ── SameSite ─────────────────────────────────────────────────────────────
    ss = sc["samesite"]
    if ss is None:
        finding(
            "SameSite",
            "LOW",
            "ABSENT",
            "SameSite attribute not declared. Modern Chrome/Firefox default to Lax, "
            "but explicit declaration is required per OWASP and avoids relying on "
            "browser-specific defaults.",
        )
    elif ss == "none":
        finding(
            "SameSite",
            "MEDIUM",
            "NONE",
            "SameSite=None — cookie is sent on all cross-site requests including "
            "third-party iframes and cross-origin fetches. CSRF attack surface exists "
            "unless additional CSRF token controls are in place.",
        )
    elif ss == "lax":
        finding(
            "SameSite",
            "INFO",
            "LAX",
            "SameSite=Lax — cookie is sent on top-level navigation GET requests from "
            "external sites. Safe-method cross-site navigation sends this cookie. "
            "Strict is preferred for session cookies.",
        )
    elif ss == "strict":
        finding("SameSite", "PASS", "STRICT", "SameSite=Strict — best setting.")
    else:
        finding(
            "SameSite",
            "INFO",
            "UNKNOWN",
            f"SameSite has unrecognised value: {sc['samesite']!r}. "
            f"Browser may fall back to Lax or reject.",
        )

    # ── Domain ───────────────────────────────────────────────────────────────
    if sc["domain"] is not None:
        # Leading dot or explicit subdomain broadens scope
        dom = sc["domain"]
        if dom.startswith("."):
            finding(
                "Domain",
                "INFO",
                "BROAD",
                f"Domain={dom!r} — leading dot matches all subdomains. "
                f"Cookie will be sent to any subdomain of {dom.lstrip('.')}. "
                f"Confirm all subdomains are in scope and equally trusted.",
            )
        else:
            finding(
                "Domain",
                "INFO",
                "SET",
                f"Domain={dom!r} — explicit domain. Sent to this domain and "
                f"its subdomains per RFC 6265.",
            )
    else:
        finding(
            "Domain",
            "PASS",
            "HOST-ONLY",
            "No Domain directive — cookie is host-only (sent only to the exact "
            "origin host, not subdomains). Tightest scope.",
        )

    # ── Path ─────────────────────────────────────────────────────────────────
    path_val = sc["path"]
    if path_val is None:
        finding(
            "Path",
            "INFO",
            "UNSET",
            "No Path directive — browser defaults to the request path's directory. "
            "May be narrower than intended if login/session is set from a deep URL.",
        )
    elif path_val == "/":
        finding(
            "Path",
            "INFO",
            "ROOT",
            "Path=/ — cookie is sent on all requests to this origin. "
            "Expected for session cookies; acceptable.",
        )
    else:
        finding(
            "Path",
            "INFO",
            "RESTRICTED",
            f"Path={path_val!r} — cookie scoped to this path prefix. "
            f"Verify this is intentional and not inadvertently narrower than needed.",
        )

    # ── Expires / Max-Age (persistence) ──────────────────────────────────────
    expiry_secs = seconds_until_expiry(sc)
    if expiry_secs is None:
        finding(
            "Expires / Max-Age",
            "PASS",
            "SESSION",
            "No Expires or Max-Age — session-scoped cookie. Cleared when browser closes.",
        )
    elif expiry_secs <= 0:
        finding(
            "Expires / Max-Age",
            "INFO",
            "ALREADY_EXPIRED",
            f"Cookie has already-expired or zero Max-Age. Likely a logout/clear operation.",
        )
    elif expiry_secs > REASONABLE_EXPIRY_SECONDS:
        hrs = expiry_secs // 3600
        finding(
            "Expires / Max-Age",
            "MEDIUM",
            "LONG_LIVED",
            f"Persistent cookie — expires in ~{hrs}h "
            f"(threshold: {REASONABLE_EXPIRY_SECONDS // 3600}h). "
            f"Long-lived session cookies extend the hijacking window if token is compromised.",
        )
    else:
        mins = expiry_secs // 60
        finding(
            "Expires / Max-Age",
            "INFO",
            "PERSISTENT_SHORT",
            f"Persistent cookie — expires in ~{mins} min (within 24h threshold).",
        )

    return findings


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

SEV_BADGE = {
    "HIGH":   "![HIGH](https://img.shields.io/badge/HIGH-red)",
    "MEDIUM": "![MEDIUM](https://img.shields.io/badge/MEDIUM-orange)",
    "LOW":    "![LOW](https://img.shields.io/badge/LOW-blue)",
    "INFO":   "![INFO](https://img.shields.io/badge/INFO-lightgrey)",
    "PASS":   "![PASS](https://img.shields.io/badge/PASS-green)",
}


def build_report(
    xml_filename: str,
    items: list[dict],
    all_findings: list[dict],
) -> str:
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")

    # Group findings by URL → cookie_name
    by_url: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for f in all_findings:
        by_url[f["url"]][f["cookie_name"]].append(f)

    # Summary counts (exclude PASS from issue counts)
    issues = [f for f in all_findings if f["severity"] not in ("PASS",)]
    highs  = sum(1 for f in issues if f["severity"] == "HIGH")
    meds   = sum(1 for f in issues if f["severity"] == "MEDIUM")
    lows   = sum(1 for f in issues if f["severity"] == "LOW")
    infos  = sum(1 for f in issues if f["severity"] == "INFO")

    total_endpoints = len(by_url)
    total_cookies   = len({f["cookie_name"] for f in all_findings})

    lines = []
    lines.append(f"# WSTG-SESS-02 Cookie Attribute Audit")
    lines.append(f"")
    lines.append(f"**Source file:** `{xml_filename}`  ")
    lines.append(f"**Generated:** {now_str}  ")
    lines.append(f"**Endpoints with Set-Cookie:** {total_endpoints}  ")
    lines.append(f"**Unique cookie names:** {total_cookies}  ")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")
    lines.append(f"## Summary")
    lines.append(f"")
    lines.append(f"| Severity | Count |")
    lines.append(f"|----------|-------|")
    lines.append(f"| 🔴 HIGH   | {highs} |")
    lines.append(f"| 🟡 MEDIUM | {meds} |")
    lines.append(f"| 🔵 LOW    | {lows} |")
    lines.append(f"| ℹ️ INFO   | {infos} |")
    lines.append(f"")

    # Quick-reference: all HIGH and MEDIUM across the board
    critical = [f for f in all_findings if f["severity"] in ("HIGH", "MEDIUM")]
    if critical:
        lines.append(f"### Issues Requiring Action")
        lines.append(f"")
        lines.append(f"| Severity | Cookie | Attribute | Endpoint |")
        lines.append(f"|----------|--------|-----------|---------|")
        for f in sorted(critical, key=lambda x: (SEVERITY_ORDER[x["severity"]], x["cookie_name"])):
            badge = SEVERITY_EMOJI[f["severity"]]
            lines.append(
                f"| {badge} {f['severity']} "
                f"| `{f['cookie_name']}` "
                f"| {f['attribute']} "
                f"| `{f['url']}` |"
            )
        lines.append(f"")

    lines.append(f"---")
    lines.append(f"")
    lines.append(f"## Per-Endpoint Findings")
    lines.append(f"")

    for url in sorted(by_url.keys()):
        cookies_at_url = by_url[url]
        lines.append(f"### `{url}`")
        lines.append(f"")

        for cookie_name in sorted(cookies_at_url.keys()):
            cookie_findings = cookies_at_url[cookie_name]
            # Sort by severity
            cookie_findings.sort(key=lambda x: SEVERITY_ORDER[x["severity"]])

            # Worst severity for this cookie
            worst = cookie_findings[0]["severity"] if cookie_findings else "PASS"
            worst_emoji = SEVERITY_EMOJI.get(worst, "")

            lines.append(f"#### {worst_emoji} `{cookie_name}`")
            lines.append(f"")
            lines.append(f"| Attribute | Verdict | Severity | Detail |")
            lines.append(f"|-----------|---------|----------|--------|")

            for f in cookie_findings:
                emoji   = SEVERITY_EMOJI[f["severity"]]
                detail  = f["detail"].replace("\n", " ").replace("|", "\\|")
                lines.append(
                    f"| {f['attribute']} "
                    f"| {f['verdict']} "
                    f"| {emoji} {f['severity']} "
                    f"| {detail} |"
                )
            lines.append(f"")

    # Secure prefix summary section
    prefix_findings = [
        f for f in all_findings
        if "Secure Prefix" in f["attribute"]
    ]
    if prefix_findings:
        lines.append(f"---")
        lines.append(f"")
        lines.append(f"## Secure Prefix Summary")
        lines.append(f"")
        lines.append(
            f"RFC 6265bis defines two cookie name prefixes that signal "
            f"stronger security requirements to the browser:\n\n"
            f"- **`__Secure-`** — cookie MUST have `Secure` flag and be set over HTTPS.\n"
            f"- **`__Host-`** — cookie MUST have `Secure` flag, be set over HTTPS, "
            f"have no `Domain` directive, and `Path=/`.\n\n"
            f"Browsers *accept* cookies that claim a prefix but violate requirements — "
            f"the prefix provides no browser enforcement, only a naming contract. "
            f"Violations mean the name implies security that doesn't exist."
        )
        lines.append(f"")
        lines.append(f"| Cookie | Prefix | Result | Detail |")
        lines.append(f"|--------|--------|--------|--------|")
        for f in prefix_findings:
            emoji  = SEVERITY_EMOJI[f["severity"]]
            detail = f["detail"].replace("|", "\\|")
            lines.append(
                f"| `{f['cookie_name']}` "
                f"| `{f['attribute']}` "
                f"| {emoji} {f['verdict']} "
                f"| {detail} |"
            )
        lines.append(f"")

    lines.append(f"---")
    lines.append(f"")
    lines.append(f"## Reference")
    lines.append(f"")
    lines.append(f"| Item | Reference |")
    lines.append(f"|------|-----------|")
    lines.append(f"| OWASP WSTG-SESS-02 | https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes |")
    lines.append(f"| RFC 6265 (Cookies) | https://datatracker.ietf.org/doc/html/rfc6265 |")
    lines.append(f"| RFC 6265bis (Prefixes) | https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis |")
    lines.append(f"| NIST SP 800-63B §7 | https://pages.nist.gov/800-63-3/sp800-63b.html |")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"*Generated by sess02_cookie_attributes.py — WSTG-SESS-02*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Terminal summary
# ---------------------------------------------------------------------------

def print_summary(all_findings: list[dict]):
    by_sev = defaultdict(list)
    for f in all_findings:
        if f["severity"] != "PASS":
            by_sev[f["severity"]].append(f)

    for sev in ["HIGH", "MEDIUM", "LOW", "INFO"]:
        group = by_sev.get(sev, [])
        if not group:
            continue
        color = SEVERITY_COLOR[sev]
        print(f"\n{color}{BOLD}[{sev}] — {len(group)} finding(s){RESET}")
        print(f"{color}{'-'*50}{RESET}")
        for f in group:
            print(f"  {color}{f['cookie_name']}{RESET}  ·  {f['attribute']}  ·  {f['verdict']}")
            print(f"    {DIM}{f['detail'][:120]}{'...' if len(f['detail'])>120 else ''}{RESET}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-SESS-02: Cookie attribute audit from Burp XML"
    )
    p.add_argument("--xml",
        default=os.path.join("WSTG-SESS-02", "inputs", "xml", "session_walk.xml"),
        metavar="PATH",
        help="Path to Burp Suite XML export")
    p.add_argument("--out-dir",
        default=os.path.join("WSTG-SESS-02", "outputs", "test_outputs"),
        metavar="DIR",
        help="Output directory (default: WSTG-SESS-02/outputs/test_outputs)")
    args = p.parse_args()

    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"{BOLD} WSTG-SESS-02 — Cookie Attribute Audit{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"  XML: {args.xml}\n")

    # Derive output filename from input filename
    xml_stem     = os.path.splitext(os.path.basename(args.xml))[0]
    report_name  = f"{xml_stem}_report.md"
    findings_name = f"{xml_stem}_findings.json"

    items = parse_burp_xml(args.xml)
    print(f"  Parsed {len(items)} request(s)\n")

    os.makedirs(args.out_dir, exist_ok=True)

    all_findings: list[dict] = []
    cookie_count = 0

    for item in items:
        resp_hdrs     = parse_resp_headers(item["resp_head"])
        set_cookie_raw = resp_hdrs.get("set-cookie", [])
        if not set_cookie_raw:
            continue

        scheme = urlparse(item["url"]).scheme.lower()
        url    = item["url"]

        for sc_raw in set_cookie_raw:
            sc = parse_set_cookie(sc_raw)
            cookie_count += 1
            findings = check_cookie(sc, scheme, url)
            all_findings.extend(findings)

            issues = [f for f in findings if f["severity"] not in ("PASS",)]
            color  = RED if any(f["severity"] == "HIGH" for f in issues) \
                     else YELLOW if any(f["severity"] == "MEDIUM" for f in issues) \
                     else CYAN if any(f["severity"] == "LOW" for f in issues) \
                     else GREEN
            print(f"  {color}{sc['name']}{RESET}  ←  {DIM}{url}{RESET}")
            if issues:
                for f in sorted(issues, key=lambda x: SEVERITY_ORDER[x["severity"]]):
                    sev_col = SEVERITY_COLOR[f["severity"]]
                    print(f"    {sev_col}[{f['severity']}]{RESET} {f['attribute']}: {f['verdict']}")

    print_summary(all_findings)

    # Write outputs
    report_content = build_report(
        os.path.basename(args.xml),
        items,
        all_findings,
    )

    report_path = os.path.join(args.out_dir, report_name)
    with open(report_path, "w") as f:
        f.write(report_content)
    print(f"\n{GREEN}[+] {report_path}{RESET}")

    findings_path = os.path.join(args.out_dir, findings_name)
    with open(findings_path, "w") as f:
        json.dump(all_findings, f, indent=2)
    print(f"{GREEN}[+] {findings_path}{RESET}")

    # Final counts
    issues = [f for f in all_findings if f["severity"] not in ("PASS",)]
    highs  = sum(1 for f in issues if f["severity"] == "HIGH")
    meds   = sum(1 for f in issues if f["severity"] == "MEDIUM")
    lows   = sum(1 for f in issues if f["severity"] == "LOW")
    print(
        f"\n  {BOLD}Summary:{RESET}  "
        f"{RED}{highs} HIGH{RESET}  "
        f"{YELLOW}{meds} MEDIUM{RESET}  "
        f"{CYAN}{lows} LOW{RESET}  "
        f"{len(items)} requests scanned  "
        f"{cookie_count} Set-Cookie headers evaluated"
    )
    print()


if __name__ == "__main__":
    main()
