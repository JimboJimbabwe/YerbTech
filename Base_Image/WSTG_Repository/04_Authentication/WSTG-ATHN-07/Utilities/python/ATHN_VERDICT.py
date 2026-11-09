#!/usr/bin/env python3
"""
WSTG-ATHN-07 — Weak Password Policy
Verdict Script: ATHN_VERDICT.py

Reads the completed WSTG_verdict.json (written by ATHN-07.py) and reports:
  - Overall verdict: Vulnerable / Not Vulnerable
  - Which controls failed
  - A human-readable explanation of why the asset is considered flawed

Usage:
  python3 utilities/python/ATHN_VERDICT.py
  python3 utilities/python/ATHN_VERDICT.py -i outputs/test_outputs/WSTG_verdict.json
"""

import argparse
import json
import os
import sys


# ---------------------------------------------------------------------------
# ANSI
# ---------------------------------------------------------------------------
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
RESET  = "\033[0m"


# ---------------------------------------------------------------------------
# Question labels (for human-readable output)
# ---------------------------------------------------------------------------

QUESTION_LABELS = {
    "Q1_entropy":              "Password entropy / complexity requirements",
    "Q2_history_bypass":       "Password history bypass resistance",
    "Q3_nist_expiry":          "NIST-aligned expiry policy (no forced periodic changes)",
    "Q4_history_maintained":   "Password history maintained (prevents immediate reuse)",
    "Q5_personal_info_rejected": "Personal info (name/username) rejected in passwords",
    "Q6_common_passwords_blocked": "Common/dictionary passwords blocked",
}


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
        print(f"[!] Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Verdict logic
# ---------------------------------------------------------------------------

def assess(data: dict) -> None:
    q = data.get("questionnaire", {})
    questions = q.get("questions", {})
    findings  = q.get("findings", {})

    # Re-derive failed questions from verdicts (don't trust stored list alone)
    failed = [
        key for key, val in questions.items()
        if val.get("verdict") is False
    ]

    # Stored verdict (from questionnaire script)
    stored_verdict = findings.get("verdict", "Unknown")
    ts = findings.get("timestamp", "—")

    print()
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"{BOLD} WSTG-ATHN-07 — Password Policy Verdict{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"  Assessed: {ts[:19].replace('T', ' ')} UTC")
    print()

    # -----------------------------------------------------------------------
    # Detailed results table
    # -----------------------------------------------------------------------
    print(f"{BOLD}  {'Control':<52} {'Result'}{RESET}")
    print(f"  {'─'*52} {'─'*10}")

    for key, val in questions.items():
        label   = QUESTION_LABELS.get(key, key)
        verdict = val.get("verdict")
        note    = val.get("tester_note", "")

        if verdict is True:
            mark = f"{GREEN}PASS ✓{RESET}"
        elif verdict is False:
            mark = f"{RED}FAIL ✗{RESET}"
        else:
            mark = f"{YELLOW}N/A{RESET}"

        print(f"  {label:<52} {mark}")
        if note:
            print(f"  {DIM}  Note: {note}{RESET}")

    print()

    # -----------------------------------------------------------------------
    # Verdict
    # -----------------------------------------------------------------------
    if failed:
        print(f"  {RED}{BOLD}This asset is FLAWED / VULNERABLE.{RESET}")
        print()
        print(f"  {RED}The following password policy control(s) were not in place:{RESET}")
        for key in failed:
            label = QUESTION_LABELS.get(key, key)
            note  = questions[key].get("tester_note", "")
            print(f"    {RED}✗ {label}{RESET}")
            if note:
                print(f"      {DIM}Tester note: {note}{RESET}")
        print()
        print(f"  {RED}A password policy missing any of the above controls allows attackers to:{RESET}")

        if "Q1_entropy" in failed:
            print(f"    • Brute-force or dictionary-attack weak passwords")
        if "Q2_history_bypass" in failed:
            print(f"    • Immediately reuse a previous password by cycling through the history window")
        if "Q3_nist_expiry" in failed:
            print(f"    • Predict passwords through forced-expiry patterns (e.g. Summer2024 → Summer2025)")
        if "Q4_history_maintained" in failed:
            print(f"    • Reuse the immediately preceding password after any forced change")
        if "Q5_personal_info_rejected" in failed:
            print(f"    • Set passwords guessable via OSINT on the target (name, username)")
        if "Q6_common_passwords_blocked" in failed:
            print(f"    • Set passwords from the top-N most-breached credential lists")

        print()
        print(f"  {RED}Refer to NIST SP 800-63B and OWASP ASVS v4 §2.1 for remediation guidance.{RESET}")
    else:
        print(f"  {GREEN}{BOLD}No failures detected — password policy appears adequate.{RESET}")
        print()
        print(f"  {GREEN}All six controls passed. Document this as a positive finding.{RESET}")

    print()
    print(f"  Stored verdict (from questionnaire run): {stored_verdict}")
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description='ATHN-07: Read WSTG_verdict.json and output final password policy verdict'
    )
    p.add_argument(
        '-i', '--input',
        default='outputs/test_outputs/WSTG_verdict.json',
        metavar='PATH',
        help='Path to WSTG_verdict.json (default: outputs/test_outputs/WSTG_verdict.json)'
    )
    return p.parse_args()


def main():
    args = parse_args()
    data = load_json(args.input)
    assess(data)


if __name__ == "__main__":
    main()
