#!/usr/bin/env python3
"""
WSTG-CONF-06 — HTTP Methods: Findings Analyser
Step 3 of 3

Reads the markdown outcome file from methods_test.py, parses every
result row, and produces a findings report focussed on:

  1. Dangerous methods advertised in Allow headers (PUT, CONNECT, DELETE,
     PATCH) — these require manual follow-up.
  2. TRACE accepted (XST risk).
  3. Methods returning unexpected 2xx on auth pathways.
  4. CONNECT accepted (proxy tunnelling).

Output:
  -o / --output  → findings markdown (default: outputs/test_outputs/WSTG-CONF-06/methods_findings.md)

Usage:
  python3 methods_outcome.py \
    -i outputs/test_outputs/WSTG-CONF-06/methods_outcome.md \
    -o outputs/test_outputs/WSTG-CONF-06/methods_findings.md
"""

import argparse
import re
import sys
import os
from datetime import datetime, timezone
from collections import defaultdict


# ---------------------------------------------------------------------------
# Methods that warrant a finding when seen in Allow headers or as a 2xx response
# ---------------------------------------------------------------------------

DANGEROUS_IN_ALLOW = ["PUT", "DELETE", "PATCH"]
INVESTIGATE_IN_ALLOW = ["CONNECT"]
TRACE_XST_RISK = True

AUTH_PATH_KEYWORDS = [
    "login", "logout", "signin", "signout", "sign-in", "sign-out",
    "auth", "authenticate", "authentication",
    "oauth", "oauth2", "oidc", "sso", "saml",
    "token", "refresh", "revoke",
    "password", "reset-password", "forgot-password",
    "register", "signup", "sign-up",
    "account", "profile", "session", "sessions",
    "mfa", "2fa", "totp",
]

_AUTH_RE = re.compile(
    '|'.join(re.escape(kw) for kw in AUTH_PATH_KEYWORDS),
    re.IGNORECASE,
)

# Regex to match table rows in methods_outcome.md
# | `METHOD` | ✅ 200 | `Allow: GET, POST` | notes |
_ROW_RE = re.compile(
    r'\|\s*`(?P<method>[A-Z]+)`\s*\|'
    r'\s*(?P<status_cell>[^|]+)\|'
    r'\s*`(?P<allow_cell>[^`]*)`\s*\|'
    r'\s*(?P<notes>[^|]*)\|'
)

# Regex to match URL section headers: ## `https://...`
_URL_RE = re.compile(r'^##\s+`(?P<url>https?://[^`]+)`')


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def parse_outcome_md(path: str) -> list:
    """
    Parse the outcome markdown and return a list of dicts:
      {url, method, status_code, allow_header, notes, is_auth}
    """
    try:
        with open(path) as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[!] Outcome file not found: {path}")
        sys.exit(1)

    records = []
    current_url = None

    for line in content.splitlines():
        url_match = _URL_RE.match(line.strip())
        if url_match:
            current_url = url_match.group("url").strip()
            continue

        row_match = _ROW_RE.match(line.strip())
        if row_match and current_url:
            method = row_match.group("method").strip()
            status_cell = row_match.group("status_cell").strip()
            allow_cell = row_match.group("allow_cell").strip()
            notes = row_match.group("notes").strip()

            # Parse status code from cell like "✅ 200" or "⚠ Timeout"
            status_code = None
            m = re.search(r'\b(\d{3})\b', status_cell)
            if m:
                status_code = int(m.group(1))

            # Clean up allow header
            allow_header = allow_cell if allow_cell != "—" else ""

            records.append({
                "url": current_url,
                "method": method,
                "status_code": status_code,
                "allow_header": allow_header,
                "notes": notes,
                "is_auth": bool(_AUTH_RE.search(current_url)),
            })

    return records


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def analyse(records: list) -> list:
    """
    Return a list of finding dicts:
      {severity, title, url, method, allow_header, detail, recommendation}
    """
    findings = []

    for r in records:
        url = r["url"]
        method = r["method"]
        allow = r["allow_header"].upper()
        code = r["status_code"]
        is_auth = r["is_auth"]

        # ----- Dangerous methods in Allow header -----
        for dm in DANGEROUS_IN_ALLOW:
            if dm in allow:
                sev = "HIGH" if not is_auth else "CRITICAL"
                findings.append({
                    "severity": sev,
                    "title": f"{dm} method advertised via Allow header",
                    "url": url,
                    "method": method,
                    "allow_header": r["allow_header"],
                    "detail": (
                        f"The OPTIONS response for `{url}` includes `{dm}` in the Allow header. "
                        f"This means the server is advertising support for a write method. "
                        f"{'This URL is an authentication pathway — elevated risk.' if is_auth else ''}"
                    ),
                    "recommendation": (
                        f"Manually test `{dm} {url}` to confirm whether the method is truly accepted "
                        f"or merely advertised. Do NOT automate this. "
                        f"If confirmed: restrict `{dm}` to authenticated, authorised sessions only, "
                        f"or disable it entirely if not required."
                    ),
                })

        # ----- CONNECT in Allow header -----
        if "CONNECT" in allow:
            findings.append({
                "severity": "MEDIUM",
                "title": "CONNECT method advertised via Allow header",
                "url": url,
                "method": method,
                "allow_header": r["allow_header"],
                "detail": (
                    f"The Allow header for `{url}` includes CONNECT. "
                    f"If the web server (not a proxy) honours CONNECT, it may allow "
                    f"attackers to use it as an open proxy to reach internal services."
                ),
                "recommendation": (
                    "Verify manually whether CONNECT is honoured by the application server. "
                    "CONNECT should only be supported by intentional forward proxies, "
                    "not by application endpoints."
                ),
            })

        # ----- CONNECT method itself returned 2xx -----
        if method == "CONNECT" and code and code < 300:
            findings.append({
                "severity": "HIGH",
                "title": "CONNECT method accepted (proxy tunnelling possible)",
                "url": url,
                "method": "CONNECT",
                "allow_header": r["allow_header"],
                "detail": (
                    f"`CONNECT {url}` returned HTTP {code}. "
                    f"The server appears to accept CONNECT requests, potentially allowing "
                    f"attackers to tunnel arbitrary TCP connections through it."
                ),
                "recommendation": (
                    "Disable CONNECT on application servers that are not intended to function "
                    "as forward proxies. Investigate what traffic can be tunnelled."
                ),
            })

        # ----- TRACE accepted (XST) -----
        if method == "TRACE" and code and code < 300:
            sev = "MEDIUM" if not is_auth else "HIGH"
            findings.append({
                "severity": sev,
                "title": "TRACE method accepted — potential Cross-Site Tracing (XST)",
                "url": url,
                "method": "TRACE",
                "allow_header": r["allow_header"],
                "detail": (
                    f"`TRACE {url}` returned HTTP {code}. "
                    f"TRACE echoes the request back to the client including headers. "
                    f"Combined with XSS, this can be used to steal HttpOnly cookies (XST). "
                    f"{'Auth pathway — higher impact if session cookies are present.' if is_auth else ''}"
                ),
                "recommendation": (
                    "Disable TRACE on all application servers. "
                    "In Apache: `TraceEnable Off`. In Nginx: `proxy_pass` removes TRACE by default; "
                    "ensure no `limit_except` block re-enables it."
                ),
            })

        # ----- Unexpected 2xx for non-GET/HEAD on auth pathway -----
        if (is_auth and method not in ("GET", "HEAD", "OPTIONS")
                and code and code < 300):
            findings.append({
                "severity": "MEDIUM",
                "title": f"Unexpected {method} 2xx on authentication pathway",
                "url": url,
                "method": method,
                "allow_header": r["allow_header"],
                "detail": (
                    f"`{method} {url}` returned HTTP {code} on an authentication pathway. "
                    f"Unexpected successful responses on auth endpoints can indicate "
                    f"misconfigured access controls or logic flaws."
                ),
                "recommendation": (
                    f"Manually investigate `{method} {url}`. "
                    f"Confirm whether the response reveals sensitive information or "
                    f"allows state modification without proper authorisation."
                ),
            })

    # Deduplicate by (severity, title, url, method)
    seen = set()
    unique = []
    for f in findings:
        key = (f["severity"], f["title"], f["url"], f["method"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Sort by severity then URL
    unique.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 99), f["url"]))
    return unique


# ---------------------------------------------------------------------------
# Markdown report writer
# ---------------------------------------------------------------------------

SEVERITY_BADGE = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH":     "🟠 HIGH",
    "MEDIUM":   "🟡 MEDIUM",
    "LOW":      "🔵 LOW",
    "INFO":     "ℹ INFO",
}


def write_findings(output_path: str, findings: list, records: list, meta: dict):
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    by_sev = defaultdict(list)
    for f in findings:
        by_sev[f["severity"]].append(f)

    lines = []
    lines.append("# CONF-06 HTTP Methods — Findings")
    lines.append("")
    lines.append(f"**Generated:** {meta['generated']}")
    lines.append(f"**Source:** `{meta['source']}`")
    lines.append(f"**URLs analysed:** {meta['url_count']}")
    lines.append(f"**Total responses:** {meta['record_count']}")
    lines.append(f"**Findings:** {len(findings)}")
    lines.append("")

    if not findings:
        lines.append("## ✅ No significant findings")
        lines.append("")
        lines.append("No dangerous methods advertised, TRACE not accepted, "
                     "no unexpected responses on auth pathways.")
    else:
        # Severity summary table
        lines.append("## Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = len(by_sev.get(sev, []))
            if count:
                lines.append(f"| {SEVERITY_BADGE[sev]} | {count} |")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Individual findings
        for i, f in enumerate(findings, 1):
            badge = SEVERITY_BADGE.get(f["severity"], f["severity"])
            lines.append(f"## Finding {i}: {f['title']}")
            lines.append("")
            lines.append(f"**Severity:** {badge}")
            lines.append(f"**URL:** `{f['url']}`")
            lines.append(f"**Method tested:** `{f['method']}`")
            if f["allow_header"]:
                lines.append(f"**Allow header:** `{f['allow_header']}`")
            lines.append("")
            lines.append("### Detail")
            lines.append("")
            lines.append(f.get("detail", ""))
            lines.append("")
            lines.append("### Recommendation")
            lines.append("")
            lines.append(f.get("recommendation", ""))
            lines.append("")
            lines.append("---")
            lines.append("")

    # Appendix: PUT/CONNECT manual test checklist
    put_urls = set()
    connect_urls = set()
    for r in records:
        allow_up = r["allow_header"].upper()
        if "PUT" in allow_up:
            put_urls.add(r["url"])
        if "CONNECT" in allow_up or (r["method"] == "CONNECT" and r["status_code"] and r["status_code"] < 300):
            connect_urls.add(r["url"])

    if put_urls or connect_urls:
        lines.append("## Manual Testing Checklist")
        lines.append("")
        lines.append("> These entries require **manual, controlled testing**.")
        lines.append("> Never automate PUT or file-write requests against a target.")
        lines.append("")

        if put_urls:
            lines.append("### PUT — Manual Verification Required")
            lines.append("")
            lines.append("For each URL below, manually attempt:")
            lines.append("```")
            for url in sorted(put_urls):
                lines.append(f"curl -v -X PUT {url} -d 'test_content' -H 'Content-Type: text/plain'")
            lines.append("```")
            lines.append("")
            lines.append("Check: does the server accept the body? Does a subsequent GET return it?")
            lines.append("")

        if connect_urls:
            lines.append("### CONNECT — Manual Verification Required")
            lines.append("")
            lines.append("For each URL below, manually attempt a tunnel:")
            lines.append("```")
            for url in sorted(connect_urls):
                from urllib.parse import urlparse
                parsed = urlparse(url)
                host = parsed.hostname or parsed.netloc
                port = parsed.port or 443
                lines.append(f"curl -v -X CONNECT {parsed.scheme}://{host}:{port} --proxytunnel")
            lines.append("```")
            lines.append("")

    with open(output_path, 'w') as f:
        f.write('\n'.join(lines))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description='CONF-06 Step 3: Analyse methods outcome and produce findings report'
    )
    p.add_argument(
        '-i', '--input',
        default='outputs/test_outputs/WSTG-CONF-06/methods_outcome.md',
        help='Outcome markdown from methods_test.py'
    )
    p.add_argument(
        '-o', '--output',
        default='outputs/test_outputs/WSTG-CONF-06/methods_findings.md',
        help='Output findings markdown'
    )
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    print("=" * 60)
    print("CONF-06 — HTTP Methods Findings Analyser")
    print("=" * 60)

    records = parse_outcome_md(args.input)
    print(f"[*] Parsed {len(records)} result rows from {args.input}")

    url_count = len(set(r["url"] for r in records))
    auth_count = sum(1 for r in records if r["is_auth"])
    print(f"[*] Unique URLs: {url_count}")
    print(f"[*] Auth-pathway responses: {auth_count}")

    findings = analyse(records)
    print(f"[+] Findings: {len(findings)}")

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = sum(1 for f in findings if f["severity"] == sev)
        if count:
            print(f"    {sev}: {count}")

    meta = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": args.input,
        "url_count": url_count,
        "record_count": len(records),
    }

    write_findings(args.output, findings, records, meta)
    print(f"\n[+] Findings written → {args.output}")

    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Responses analysed: {len(records)}")
    print(f"  Findings:           {len(findings)}")
    print(f"  Output:             {args.output}")


if __name__ == "__main__":
    main()
