#!/usr/bin/env python3
"""
WSTG-ATHN-03 — Weak Lockout Mechanism
Report Generator: weak_lockout_report.py

Reads the completed q1.json (written by weak_lockout.py) and outputs
a markdown findings report.

Usage:
  python3 utilities/python/weak_lockout_report.py -questionnaire inputs/data/q1.json
  python3 utilities/python/weak_lockout_report.py \
      -questionnaire inputs/data/q1.json \
      -o outputs/test_outputs/weak_lockout_findings.md
"""

import argparse
import json
import os
import sys
import textwrap
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_json(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON in {path}: {e}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Verdict helpers
# ---------------------------------------------------------------------------

def bool_label(v) -> str:
    if v is True:
        return "**Yes** ⚠"
    if v is False:
        return "No ✓"
    if isinstance(v, str):
        return v
    return "—"


def verdict_badge(verdict: str) -> str:
    v = (verdict or "").strip().lower()
    if "not" in v:
        return "✅ NOT VULNERABLE"
    return "🔴 VULNERABLE"


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

def build_report(data: dict) -> str:
    lines = []
    q = data.get("questionnaire", {})
    findings = q.get("findings", {})
    verdict = findings.get("verdict", "Unknown")
    reasons = findings.get("reasons", [])
    ts = findings.get("timestamp", datetime.now(timezone.utc).isoformat())

    i1 = q.get("Item_1", {})
    i2 = q.get("Item_2", {})
    i3 = q.get("Item_3", {})

    # Header
    lines.append("# WSTG-ATHN-03 — Weak Lockout Mechanism")
    lines.append("")
    lines.append(f"> **Verdict:** {verdict_badge(verdict)}")
    lines.append(f">")
    lines.append(f"> **Assessed:** {ts[:19].replace('T', ' ')} UTC")
    lines.append("")

    # Overview
    lines.append("## Overview")
    lines.append("")
    lines.append(
        "This assessment checks whether the application's account lockout controls "
        "are sufficient to prevent brute-force attacks, OTP guessing, and exploitation "
        "of weak security questions."
    )
    lines.append("")

    # Question table
    lines.append("## Assessment Items")
    lines.append("")
    lines.append("| # | Question | Verdict | Notes |")
    lines.append("|---|----------|---------|-------|")

    def row_note(item: dict) -> str:
        return item.get("tester_note", "").replace("|", "\\|") or "—"

    lines.append(
        f"| 1 | {i1.get('question', '')} "
        f"| {bool_label(i1.get('verdict'))} "
        f"| {row_note(i1)} |"
    )
    lines.append(
        f"| 2 | {i2.get('question', '')} "
        f"| {bool_label(i2.get('verdict'))} "
        f"| {row_note(i2)} |"
    )
    lines.append(
        f"| 3 | {i3.get('question', '')} "
        f"| {bool_label(i3.get('verdict'))} "
        f"| {row_note(i3)} |"
    )
    lines.append("")

    # Branch logic note
    bf_allowed = i1.get("verdict") is True
    if not bf_allowed:
        lines.append(
            "> **Note:** Item 1 verdict was **No** — brute force is not possible on this "
            "endpoint. Item 3 (OTP guessing) was automatically eliminated and not assessed."
        )
        lines.append("")

    # Findings
    lines.append("## Findings")
    lines.append("")
    if reasons:
        lines.append(f"The following weakness(es) were identified:")
        lines.append("")
        for r in reasons:
            lines.append(f"- {r}")
        lines.append("")
    else:
        lines.append("No weaknesses identified. The lockout mechanism appears adequate.")
        lines.append("")

    # Remediation (only if vulnerable)
    if "vulnerable" in verdict.lower() and "not" not in verdict.lower():
        lines.append("## Remediation Guidance")
        lines.append("")

        if i1.get("verdict") is True:
            lines.append("### Brute Force Protection")
            lines.append("")
            lines.append(
                "Implement account lockout or progressive delay after a configurable "
                "number of failed attempts (OWASP recommends temporary lockout after "
                "3–5 failures). Combine with CAPTCHA and IP-based rate limiting. "
                "Ensure lockout applies to all authentication endpoints, including "
                "password reset and MFA challenge flows."
            )
            lines.append("")

        if i2.get("verdict") is True:
            lines.append("### Security Question Strength")
            lines.append("")
            lines.append(
                "Replace knowledge-based authentication (KBA) with phishing-resistant "
                "MFA (TOTP app, hardware key). If KBA must be retained, enforce "
                "minimum answer length, reject common/dictionary answers, and allow "
                "users to define their own questions. NIST SP 800-63B discourages "
                "use of KBA entirely."
            )
            lines.append("")

        i3v = i3.get("verdict", "")
        if isinstance(i3v, str) and i3v == "Y":
            lines.append("### OTP Lockout")
            lines.append("")
            lines.append(
                "Apply the same lockout policy to OTP/TOTP verification endpoints as "
                "to the primary login flow. Short numeric OTPs (6 digits) have only "
                "1,000,000 possible values — without lockout, an attacker can brute-force "
                "a valid code within minutes. Enforce lockout after 3–5 failed OTP "
                "attempts and consider short OTP validity windows (30–60 seconds)."
            )
            lines.append("")

    # References
    lines.append("## References")
    lines.append("")
    lines.append("- [OWASP WSTG-ATHN-03: Testing for Weak Lock Out Mechanism]"
                 "(https://owasp.org/www-project-web-security-testing-guide/latest/"
                 "4-Web_Application_Security_Testing/04-Authentication_Testing/"
                 "03-Testing_for_Weak_Lock_Out_Mechanism)")
    lines.append("- [NIST SP 800-63B — Digital Identity Guidelines: Authentication]"
                 "(https://pages.nist.gov/800-63-3/sp800-63b.html)")
    lines.append("")
    lines.append("---")
    lines.append(f"*Generated by weak_lockout_report.py — WSTG-ATHN-03*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description='ATHN-03: Generate weak lockout findings report from completed q1.json'
    )
    p.add_argument(
        '-questionnaire', '--questionnaire',
        required=True,
        metavar='PATH',
        help='Path to completed q1.json'
    )
    p.add_argument(
        '-o', '--output',
        default='outputs/test_outputs/weak_lockout_findings.md',
        help='Output markdown path (default: outputs/test_outputs/weak_lockout_findings.md)'
    )
    return p.parse_args()


def main():
    args = parse_args()
    data = load_json(args.questionnaire)

    # Check the questionnaire has been filled
    q = data.get("questionnaire", {})
    if q.get("findings", {}).get("verdict") is None:
        print("[!] Questionnaire findings are empty — run weak_lockout.py first.", file=sys.stderr)
        sys.exit(1)

    report = build_report(data)

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, 'w') as f:
        f.write(report)

    verdict = q.get("findings", {}).get("verdict", "Unknown")
    print(f"[+] Report written → {args.output}")
    print(f"    Verdict: {verdict}")


if __name__ == "__main__":
    main()
