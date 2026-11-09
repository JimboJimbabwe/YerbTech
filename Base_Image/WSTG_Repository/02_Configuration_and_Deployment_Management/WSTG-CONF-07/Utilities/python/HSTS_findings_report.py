#!/usr/bin/env python3
"""
WSTG-CONF-07 — HSTS Findings Report Generator

Reads the report.txt produced by HSTS_test.py, parses the three
checks per domain, and emits a structured findings report with
severity ratings and remediation guidance.

Three signals per domain:
  1. HSTS header — present, max-age adequate, includeSubDomains, preload
  2. Preload status — listed, pending, stale directive, eligible but not submitted
  3. HTTP redirect — does plain HTTP redirect to HTTPS?

Usage:
  python3 HSTS_findings_report.py \
    -i outputs/test_outputs/report.txt \
    -o outputs/test_outputs/HSTS_findings.md
"""

import argparse
import re
import sys
import os
from datetime import datetime, timezone
from collections import defaultdict


# ---------------------------------------------------------------------------
# Parser for report.txt
# ---------------------------------------------------------------------------

def parse_report(path: str) -> list:
    """
    Parse HSTS_test.py's report.txt into a list of domain result dicts.
    Each dict has keys mirroring the three check sections.
    """
    try:
        with open(path) as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[!] Report file not found: {path}")
        sys.exit(1)

    # Split on domain separators
    # "DOMAIN: example.com\n" marks the start of each block
    domain_blocks = re.split(r'(?=^DOMAIN: )', content, flags=re.MULTILINE)
    results = []

    for block in domain_blocks:
        if not block.strip() or not block.startswith("DOMAIN:"):
            continue

        r = {
            "domain": "",
            # Check 1
            "hsts_present": False,
            "hsts_raw": "",
            "max_age": None,
            "include_subdomains": False,
            "preload_directive": False,
            "hsts_issues": [],
            "https_status": None,
            # Check 2
            "preload_status": "unknown",
            "preload_in_progress": False,
            "preload_issues": [],
            "preload_notes": [],
            # Check 3
            "http_status": None,
            "http_location": None,
            "redirects_to_https": False,
            "redirect_issue": False,
        }

        lines = block.splitlines()

        for line in lines:
            line_s = line.strip()

            # Domain
            m = re.match(r'^DOMAIN:\s+(.+)$', line_s)
            if m:
                r["domain"] = m.group(1).strip()
                continue

            # Check 1 fields
            m = re.match(r'^Header present:\s+(YES|NO)', line_s, re.IGNORECASE)
            if m:
                r["hsts_present"] = m.group(1).upper() == "YES"

            m = re.match(r'^Raw value:\s+Strict-Transport-Security:\s*(.+)$', line_s, re.IGNORECASE)
            if m:
                r["hsts_raw"] = m.group(1).strip()

            m = re.match(r'^max-age:\s+(\d+)', line_s, re.IGNORECASE)
            if m:
                r["max_age"] = int(m.group(1))

            m = re.match(r'^includeSubDomains:\s+(True|False)', line_s, re.IGNORECASE)
            if m:
                r["include_subdomains"] = m.group(1).lower() == "true"

            m = re.match(r'^preload:\s+(True|False)', line_s, re.IGNORECASE)
            if m:
                r["preload_directive"] = m.group(1).lower() == "true"

            m = re.match(r'^HTTPS status:\s+(\d+)', line_s, re.IGNORECASE)
            if m:
                r["https_status"] = int(m.group(1))

            # Issues and notes within check 1 vs check 2 vs check 3
            # We track which section we're in
            if line_s.startswith("[CHECK 1]"):
                r["_section"] = 1
            elif line_s.startswith("[CHECK 2]"):
                r["_section"] = 2
            elif line_s.startswith("[CHECK 3]"):
                r["_section"] = 3

            section = r.get("_section", 0)

            if line_s.startswith("ISSUE:"):
                issue_text = line_s[len("ISSUE:"):].strip()
                if section == 1:
                    r["hsts_issues"].append(issue_text)
                elif section == 2:
                    r["preload_issues"].append(issue_text)
                elif section == 3:
                    r["redirect_issue"] = True

            if line_s.startswith("NOTE:"):
                note_text = line_s[len("NOTE:"):].strip()
                r["preload_notes"].append(note_text)

            # Check 2 fields
            m = re.match(r'^API status:\s+(.+)$', line_s, re.IGNORECASE)
            if m:
                r["preload_status"] = m.group(1).strip()

            m = re.match(r'^In progress:\s+(True|False)', line_s, re.IGNORECASE)
            if m:
                r["preload_in_progress"] = m.group(1).lower() == "true"

            # Check 3 fields
            m = re.match(r'^HTTP status:\s+(.+)$', line_s, re.IGNORECASE)
            if m:
                try:
                    r["http_status"] = int(m.group(1).strip())
                except ValueError:
                    pass

            m = re.match(r'^Location:\s+(.+)$', line_s, re.IGNORECASE)
            if m:
                loc = m.group(1).strip()
                r["http_location"] = loc if loc != "none" else None

            m = re.match(r'^Redirects to HTTPS:\s+(True|False)', line_s, re.IGNORECASE)
            if m:
                r["redirects_to_https"] = m.group(1).lower() == "true"

        # Clean up internal state key
        r.pop("_section", None)

        if r["domain"]:
            results.append(r)

    return results


# ---------------------------------------------------------------------------
# Findings generator
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def generate_findings(results: list) -> list:
    findings = []

    for r in results:
        domain = r["domain"]

        # ---- F1: HSTS header absent ----
        if not r["hsts_present"]:
            findings.append({
                "severity": "HIGH",
                "domain": domain,
                "check": "HSTS Header",
                "title": "HSTS header absent",
                "detail": (
                    f"`{domain}` does not return a Strict-Transport-Security header over HTTPS. "
                    f"Without HSTS, browsers may accept HTTP connections, making the site "
                    f"vulnerable to SSL stripping attacks."
                ),
                "remediation": (
                    "Add to your web server config:\n"
                    "```\n"
                    "Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
                    "```\n"
                    "Minimum max-age is 31536000 (1 year). Add `; preload` and submit to "
                    "hstspreload.org once you are confident in your HTTPS configuration."
                ),
            })
            continue     # No point checking header fields if it's absent

        # ---- F2: max-age too short ----
        max_age = r.get("max_age")
        if max_age is not None:
            if max_age < 10886400:
                findings.append({
                    "severity": "HIGH",
                    "domain": domain,
                    "check": "HSTS Header",
                    "title": f"max-age too short: {max_age}s (minimum for preload: 10886400s / 18 weeks)",
                    "detail": (
                        f"Current max-age is {max_age} seconds ({max_age // 86400} days). "
                        f"The hstspreload.org preload list requires at least 10886400s (18 weeks). "
                        f"A short max-age reduces the effective protection period — browsers "
                        f"that haven't visited recently will not enforce HTTPS."
                    ),
                    "remediation": (
                        "Increase max-age to at least 31536000 (1 year):\n"
                        "```\n"
                        "Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
                        "```"
                    ),
                })
            elif max_age < 31536000:
                findings.append({
                    "severity": "MEDIUM",
                    "domain": domain,
                    "check": "HSTS Header",
                    "title": f"max-age below recommended 1 year: {max_age}s",
                    "detail": (
                        f"Current max-age is {max_age}s ({max_age // 86400} days). "
                        f"The recommended value is 31536000s (1 year) per OWASP and hstspreload.org."
                    ),
                    "remediation": "Increase max-age to 31536000 (1 year).",
                })

        # ---- F3: includeSubDomains missing ----
        if not r["include_subdomains"]:
            findings.append({
                "severity": "MEDIUM",
                "domain": domain,
                "check": "HSTS Header",
                "title": "includeSubDomains directive missing",
                "detail": (
                    f"`{domain}` HSTS header lacks `includeSubDomains`. "
                    f"Subdomains can be reached over plain HTTP, bypassing HSTS protection. "
                    f"Required for preload list inclusion."
                ),
                "remediation": (
                    "Add `includeSubDomains`:\n"
                    "```\n"
                    "Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
                    "```\n"
                    "Ensure all subdomains also serve valid HTTPS before adding this."
                ),
            })

        # ---- F4: preload directive present but not in list ----
        if r["preload_directive"]:
            status = r["preload_status"]
            in_progress = r["preload_in_progress"]

            if status not in ("preloaded", "pending") and not in_progress:
                findings.append({
                    "severity": "LOW",
                    "domain": domain,
                    "check": "Preload Status",
                    "title": "Stale preload directive — domain not in preload list or pending",
                    "detail": (
                        f"`{domain}` has the `preload` directive in its HSTS header, "
                        f"but hstspreload.org shows status: '{status}'. "
                        f"The preload directive has no effect unless the domain is listed or submitted. "
                        f"This may be a stale config."
                    ),
                    "remediation": (
                        "Either:\n"
                        "1. Submit the domain at https://hstspreload.org (ensure max-age ≥ 10886400, "
                        "includeSubDomains, preload are all set, and all subdomains serve HTTPS), or\n"
                        "2. Remove the `preload` directive if you do not intend to preload the domain."
                    ),
                })

        # ---- F5: eligible but not submitted ----
        if r["preload_status"] == "eligible" and not r["preload_directive"]:
            findings.append({
                "severity": "INFO",
                "domain": domain,
                "check": "Preload Status",
                "title": "Domain eligible for HSTS preloading but not submitted",
                "detail": (
                    f"`{domain}` meets the technical requirements for HSTS preloading "
                    f"but has not been submitted to the preload list."
                ),
                "remediation": (
                    "Add `; preload` to the HSTS header and submit at https://hstspreload.org. "
                    "Note: preloading is difficult to undo — only preload if you are committed to HTTPS."
                ),
            })

        # ---- F6: HTTP does not redirect to HTTPS ----
        if not r["redirects_to_https"]:
            location = r.get("http_location") or "none"
            http_status = r.get("http_status", "unknown")
            findings.append({
                "severity": "HIGH",
                "domain": domain,
                "check": "HTTP Redirect",
                "title": "HTTP does not redirect to HTTPS",
                "detail": (
                    f"`http://{domain}` returned HTTP {http_status} with Location: {location}. "
                    f"Plain HTTP is accessible without redirecting to HTTPS, "
                    f"leaving users vulnerable to passive eavesdropping and SSL stripping even if "
                    f"HSTS is set (first-visit users may not have the HSTS policy cached)."
                ),
                "remediation": (
                    "Configure a permanent (301) redirect from HTTP to HTTPS:\n\n"
                    "**Nginx:**\n"
                    "```nginx\n"
                    "server {\n"
                    "    listen 80;\n"
                    f"    server_name {domain};\n"
                    "    return 301 https://$host$request_uri;\n"
                    "}\n"
                    "```\n\n"
                    "**Apache:**\n"
                    "```apache\n"
                    "RewriteEngine On\n"
                    "RewriteCond %{HTTPS} off\n"
                    "RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n"
                    "```"
                ),
            })

        # Surface any raw issues parsed from report
        for issue in r.get("hsts_issues", []):
            # Avoid duplicating findings already generated above
            if ("max-age" in issue.lower() or "subdomain" in issue.lower()
                    or "preload" in issue.lower()):
                continue
            findings.append({
                "severity": "MEDIUM",
                "domain": domain,
                "check": "HSTS Header",
                "title": f"HSTS issue: {issue[:80]}",
                "detail": issue,
                "remediation": "Review HSTS header configuration.",
            })

    # Sort: severity order, then domain
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 99), f["domain"]))
    return findings


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

SEVERITY_BADGE = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH":     "🟠 HIGH",
    "MEDIUM":   "🟡 MEDIUM",
    "LOW":      "🔵 LOW",
    "INFO":     "ℹ INFO",
}

PASS_CRITERIA = [
    "HSTS header present",
    "max-age ≥ 31536000 (1 year)",
    "includeSubDomains set",
    "HTTP redirects to HTTPS (301/302)",
]


def write_findings_report(output_path: str, results: list, findings: list):
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    by_domain = defaultdict(list)
    for f in findings:
        by_domain[f["domain"]].append(f)

    by_severity = defaultdict(list)
    for f in findings:
        by_severity[f["severity"]].append(f)

    lines = []
    lines.append("# CONF-07 HSTS — Findings Report")
    lines.append("")
    lines.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(f"**Domains assessed:** {len(results)}")
    lines.append(f"**Total findings:** {len(findings)}")
    lines.append("")

    # Per-domain pass/fail summary table
    lines.append("## Domain Overview")
    lines.append("")
    lines.append("| Domain | HSTS Header | max-age | incl. Subdomains | Preload | HTTP → HTTPS | Findings |")
    lines.append("|--------|-------------|---------|-----------------|---------|--------------|----------|")
    for r in results:
        domain = r["domain"]
        hsts_ok = "✅" if r["hsts_present"] else "❌"
        max_age_val = r.get("max_age")
        if max_age_val is None:
            max_age_cell = "❌ absent"
        elif max_age_val >= 31536000:
            max_age_cell = f"✅ {max_age_val}"
        elif max_age_val >= 10886400:
            max_age_cell = f"🟡 {max_age_val}"
        else:
            max_age_cell = f"❌ {max_age_val}"
        incl_sub = "✅" if r.get("include_subdomains") else "❌"
        preload_s = r.get("preload_status", "?")
        preload_d = "✅" if r.get("preload_directive") else "—"
        preload_cell = f"{preload_d} ({preload_s})"
        redir = "✅" if r.get("redirects_to_https") else "❌"
        count = len(by_domain.get(domain, []))
        count_cell = f"**{count}**" if count else "0"
        lines.append(
            f"| `{domain}` | {hsts_ok} | {max_age_cell} | {incl_sub} | {preload_cell} | {redir} | {count_cell} |"
        )
    lines.append("")

    if not findings:
        lines.append("## ✅ All domains passed HSTS checks")
        lines.append("")
        lines.append("All assessed domains have:")
        for c in PASS_CRITERIA:
            lines.append(f"- {c}")
    else:
        # Severity summary
        lines.append("## Findings Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = len(by_severity.get(sev, []))
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
            lines.append(f"**Domain:** `{f['domain']}`")
            lines.append(f"**Check:** {f['check']}")
            lines.append("")
            lines.append("### Detail")
            lines.append("")
            lines.append(f["detail"])
            lines.append("")
            lines.append("### Remediation")
            lines.append("")
            lines.append(f["remediation"])
            lines.append("")
            lines.append("---")
            lines.append("")

    # Reference
    lines.append("## Reference")
    lines.append("")
    lines.append("- [WSTG-CONF-07](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security)")
    lines.append("- [hstspreload.org](https://hstspreload.org)")
    lines.append("- Preload requirements: max-age ≥ 10886400, includeSubDomains, preload directive, all subdomains HTTPS")

    with open(output_path, 'w') as f:
        f.write('\n'.join(lines))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description='CONF-07: Parse HSTS test report and generate findings'
    )
    p.add_argument(
        '-i', '--input',
        default='outputs/test_outputs/report.txt',
        help='Input report.txt from HSTS_test.py'
    )
    p.add_argument(
        '-o', '--output',
        default='outputs/test_outputs/HSTS_findings.md',
        help='Output findings markdown'
    )
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    print("=" * 60)
    print("CONF-07 — HSTS Findings Report")
    print("=" * 60)

    results = parse_report(args.input)
    print(f"[*] Parsed {len(results)} domain(s) from {args.input}")

    for r in results:
        domain = r["domain"]
        hsts = "✓ present" if r["hsts_present"] else "✗ ABSENT"
        redir = "✓ redirects" if r["redirects_to_https"] else "✗ no redirect"
        preload = r["preload_status"]
        print(f"    {domain}: HSTS={hsts} | redirect={redir} | preload={preload}")

    findings = generate_findings(results)
    print(f"\n[+] Findings: {len(findings)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = sum(1 for f in findings if f["severity"] == sev)
        if count:
            print(f"    {sev}: {count}")

    write_findings_report(args.output, results, findings)
    print(f"\n[+] Findings report written → {args.output}")

    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Domains assessed: {len(results)}")
    print(f"  Total findings:   {len(findings)}")
    print(f"  Output:           {args.output}")


if __name__ == "__main__":
    main()
