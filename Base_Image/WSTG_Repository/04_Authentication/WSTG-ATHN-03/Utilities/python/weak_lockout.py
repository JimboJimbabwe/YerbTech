#!/usr/bin/env python3
"""
WSTG-ATHN-03 — Weak Lockout Mechanism
Questionnaire Script: weak_lockout.py

Three-question branching questionnaire:
  Item_1: Does the endpoint allow brute force?
    └─ No  → OTP guessing eliminated; Item_3 skipped
    └─ Yes → continue to Item_3
  Item_2: Are security questions easy to guess? (always asked)
  Item_3: Is OTP code guessing present? (only if Item_1 = Yes)

Reads the questionnaire structure from a JSON file, fills verdicts
interactively, writes the completed JSON back to disk.

Usage:
  python3 utilities/python/weak_lockout.py -questionnaire inputs/data/q1.json
  python3 utilities/python/weak_lockout.py -questionnaire inputs/data/q1.json -o inputs/data/q1.json
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# ANSI
# ---------------------------------------------------------------------------
BOLD   = "\033[1m"
DIM    = "\033[2m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
RESET  = "\033[0m"


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_questionnaire(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"{RED}[!] Questionnaire file not found: {path}{RESET}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"{RED}[!] Invalid JSON in {path}: {e}{RESET}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Prompt helpers
# ---------------------------------------------------------------------------

def prompt_yn(prompt: str) -> bool:
    while True:
        raw = input(f"  {prompt} [Y/N]: ").strip().lower()
        if raw in ('y', 'yes'):
            return True
        if raw in ('n', 'no'):
            return False
        print(f"  {YELLOW}Please enter Y or N{RESET}")


def prompt_otp(prompt: str) -> str:
    """Y / N / No OTP Code found"""
    options = {'y': 'Y', 'n': 'N', 'no otp code found': 'No OTP Code found', 'x': 'No OTP Code found'}
    print(f"  {prompt}")
    print(f"  {DIM}Enter: Y | N | X (no OTP code found){RESET}")
    while True:
        raw = input("  > ").strip().lower()
        if raw in options:
            return options[raw]
        if raw in ('y', 'yes'):
            return 'Y'
        if raw in ('n', 'no'):
            return 'N'
        print(f"  {YELLOW}Enter Y, N, or X (no OTP code found){RESET}")


def prompt_note(optional: bool = True) -> str:
    label = "Optional note" if optional else "Note"
    raw = input(f"  {DIM}{label} (Enter to skip): {RESET}").strip()
    return raw


# ---------------------------------------------------------------------------
# Questionnaire logic
# ---------------------------------------------------------------------------

def run(data: dict) -> dict:
    q = data.get("questionnaire", {})

    print()
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"{BOLD} WSTG-ATHN-03 — Weak Lockout Mechanism{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"  {DIM}{data.get('description', '')}{RESET}")
    print()

    findings_reasons = []

    # -----------------------------------------------------------------------
    # Item_1: Brute force allowed?
    # -----------------------------------------------------------------------
    i1 = q.get("Item_1", {})
    print(f"{CYAN}Item 1: {i1['question']}{RESET}")
    bf_allowed = prompt_yn("Brute force allowed?")
    i1["verdict"] = bf_allowed
    i1_note = prompt_note()
    if i1_note:
        i1["tester_note"] = i1_note
    print()

    if bf_allowed:
        print(f"  {RED}⚠ Brute force possible — continuing to Item 3{RESET}")
        findings_reasons.append("Endpoint allows brute force (no effective lockout or rate limiting)")
    else:
        print(f"  {GREEN}✓ Brute force not possible — OTP guessing eliminated{RESET}")
    print()

    # -----------------------------------------------------------------------
    # Item_2: Security questions easy to guess? (always asked)
    # -----------------------------------------------------------------------
    i2 = q.get("Item_2", {})
    print(f"{CYAN}Item 2: {i2['question']}{RESET}")
    sq_weak = prompt_yn("Security questions easy to guess?")
    i2["verdict"] = sq_weak
    i2_note = prompt_note()
    if i2_note:
        i2["tester_note"] = i2_note
    print()

    if sq_weak:
        print(f"  {RED}⚠ Weak security questions — indicator of compromise{RESET}")
        findings_reasons.append("Security questions are weak or easily guessable")
    else:
        print(f"  {GREEN}✓ Security questions appear adequately strong{RESET}")
    print()

    # -----------------------------------------------------------------------
    # Item_3: OTP guessing present? (only if brute force allowed)
    # -----------------------------------------------------------------------
    i3 = q.get("Item_3", {})
    if bf_allowed:
        print(f"{CYAN}Item 3: {i3['question']}{RESET}")
        otp_verdict = prompt_otp("OTP code guessing possible?")
        i3["verdict"] = otp_verdict
        i3_note = prompt_note()
        if i3_note:
            i3["tester_note"] = i3_note
        print()

        if otp_verdict == 'Y':
            print(f"  {RED}⚠ OTP guessing is possible{RESET}")
            findings_reasons.append("OTP endpoint lacks lockout — code guessing is viable")
        elif otp_verdict == 'N':
            print(f"  {GREEN}✓ OTP endpoint has lockout controls{RESET}")
        else:
            print(f"  {DIM}No OTP code found — Item 3 not applicable{RESET}")
    else:
        i3["verdict"] = "N/A — brute force not possible"
        print(f"  {DIM}Item 3 skipped — OTP guessing eliminated (brute force not possible){RESET}")
        print()

    # -----------------------------------------------------------------------
    # Findings
    # -----------------------------------------------------------------------
    is_vulnerable = len(findings_reasons) > 0
    verdict_str = "Vulnerable" if is_vulnerable else "Not Vulnerable"
    q["findings"]["verdict"] = verdict_str
    q["findings"]["reasons"] = findings_reasons
    q["findings"]["timestamp"] = datetime.now(timezone.utc).isoformat()

    # -----------------------------------------------------------------------
    # Terminal summary
    # -----------------------------------------------------------------------
    print(f"{BOLD}{'─'*65}{RESET}")
    print(f"{BOLD} Findings Summary{RESET}")
    print(f"{BOLD}{'─'*65}{RESET}")
    color = RED if is_vulnerable else GREEN
    print(f"  Verdict: {color}{verdict_str}{RESET}")
    if findings_reasons:
        for r in findings_reasons:
            print(f"  {RED}• {r}{RESET}")
    else:
        print(f"  {GREEN}No weaknesses identified{RESET}")
    print()

    return data


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description='ATHN-03: Weak Lockout Mechanism questionnaire'
    )
    p.add_argument(
        '-questionnaire', '--questionnaire',
        required=True,
        metavar='PATH',
        help='Path to q1.json questionnaire file'
    )
    p.add_argument(
        '-o', '--output',
        default=None,
        metavar='PATH',
        help='Output path for completed JSON (default: overwrites input file)'
    )
    return p.parse_args()


def main():
    args = parse_args()
    data = load_questionnaire(args.questionnaire)
    data = run(data)

    out_path = args.output or args.questionnaire
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"{GREEN}[+] Questionnaire written → {out_path}{RESET}")
    print(f"  Run the report generator:")
    print(f"  python3 utilities/python/weak_lockout_report.py -questionnaire {out_path}")
    print()


if __name__ == "__main__":
    main()
