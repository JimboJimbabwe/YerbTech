#!/usr/bin/env python3
"""
WSTG-IDNT-02 — User Registration Process Assessment
Questionnaire 1 of 2: Registration Process

Interactive CLI questionnaire covering the 6 core registration process
questions from IDNT-02. Each question accepts Y / N / ? (unknown).
At the end, optionally flag the registration process as flawed/vulnerable
and provide a reason.

Output: /outputs/test_outputs/q1_json.json

Usage:
  python3 utilities/python/q1.py
  python3 utilities/python/q1.py -o outputs/test_outputs/q1_json.json
  python3 utilities/python/q1.py --target "MyApp v2.1" --tester "jsmith"
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Questions
# ---------------------------------------------------------------------------

QUESTIONS = [
    {
        "id":       "IDNT02-Q1-01",
        "question": "Can anyone register for access?",
        "guidance": (
            "Consider: is registration open to the public, restricted by invite, "
            "IP range, email domain, or other criteria? "
            "Open registration is higher risk."
        ),
    },
    {
        "id":       "IDNT02-Q1-02",
        "question": "Are registrations vetted by a human prior to provisioning, "
                    "or are they automatically granted if the criteria are met?",
        "guidance": (
            "Automatic provisioning with no human review can allow fraudulent "
            "accounts to be created at scale. "
            "Note the vetting mechanism if one exists."
        ),
    },
    {
        "id":       "IDNT02-Q1-03",
        "question": "Can the same person or identity register multiple times?",
        "guidance": (
            "Test: are duplicate email addresses, usernames, or device fingerprints "
            "rejected? Can a slightly modified email (e.g. plus-aliasing, dots in Gmail) "
            "bypass uniqueness checks?"
        ),
    },
    {
        "id":       "IDNT02-Q1-04",
        "question": "Can users register for different roles or permissions?",
        "guidance": (
            "Can a registrant self-select an elevated role (e.g. admin, employer, "
            "verified user) during sign-up, or are roles assigned post-registration "
            "by a privileged actor?"
        ),
    },
    {
        "id":       "IDNT02-Q1-05",
        "question": "What proof of identity is required for a registration to be successful?",
        "guidance": (
            "Examples: none, email confirmation only, phone/SMS OTP, government ID, "
            "credit card, invite code, organisational SSO. "
            "Weak identity proofing allows impersonation."
        ),
    },
    {
        "id":       "IDNT02-Q1-06",
        "question": "Are registered identities verified?",
        "guidance": (
            "Distinct from the proof above — after registration is complete, "
            "does the application re-verify the identity at any point "
            "(e.g. periodic re-verification, email re-confirmation, MFA enforcement)?"
        ),
    },
]

ANSWER_OPTIONS = {"y": "Yes", "n": "No", "?": "Unknown / Not tested"}

BOLD  = "\033[1m"
DIM   = "\033[2m"
CYAN  = "\033[96m"
GREEN = "\033[92m"
YELLOW= "\033[93m"
RED   = "\033[91m"
RESET = "\033[0m"


# ---------------------------------------------------------------------------
# Prompt helpers
# ---------------------------------------------------------------------------

def prompt_yn_unknown(prompt: str) -> tuple:
    """Prompt for Y / N / ? and an optional note. Returns (answer_code, note)."""
    while True:
        raw = input(f"  {prompt} [Y/N/?]: ").strip().lower()
        if raw in ANSWER_OPTIONS:
            note = ""
            note_raw = input(f"  {DIM}Optional note (Enter to skip): {RESET}").strip()
            if note_raw:
                note = note_raw
            return raw, note
        print(f"  {YELLOW}Please enter Y, N, or ? (unknown){RESET}")


def prompt_multiline(prompt: str) -> str:
    """Prompt for a multiline string. Empty line to finish."""
    print(f"  {prompt}")
    print(f"  {DIM}(Enter text; blank line to finish){RESET}")
    lines = []
    while True:
        line = input("  > ")
        if not line:
            break
        lines.append(line)
    return "\n".join(lines).strip()


def prompt_yn_simple(prompt: str) -> bool:
    while True:
        raw = input(f"  {prompt} [Y/N]: ").strip().lower()
        if raw in ('y', 'yes'):
            return True
        if raw in ('n', 'no'):
            return False
        print(f"  {YELLOW}Please enter Y or N{RESET}")


# ---------------------------------------------------------------------------
# Main questionnaire
# ---------------------------------------------------------------------------

def run_questionnaire(target: str, tester: str) -> dict:
    print()
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"{BOLD} WSTG-IDNT-02 — User Registration Process{RESET}")
    print(f"{BOLD} Questionnaire 1 of 2: Registration Process{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    if target:
        print(f"  Target : {target}")
    if tester:
        print(f"  Tester : {tester}")
    print()
    print(f"  {DIM}Answer each question with Y (Yes), N (No), or ? (Unknown/not tested).{RESET}")
    print(f"  {DIM}You will have a chance to add a note after each answer.{RESET}")
    print()

    responses = []

    for i, q in enumerate(QUESTIONS, start=1):
        print(f"{CYAN}Q{i}: {q['question']}{RESET}")
        print(f"  {DIM}Guidance: {q['guidance']}{RESET}")
        answer, note = prompt_yn_unknown(f"Answer")
        responses.append({
            "id":       q["id"],
            "question": q["question"],
            "answer":   ANSWER_OPTIONS[answer],
            "answer_code": answer,
            "note":     note,
        })
        print()

    # ---------------------------------------------------------------------------
    # Vulnerability flag
    # ---------------------------------------------------------------------------
    print(f"{BOLD}{'─'*65}{RESET}")
    print(f"{BOLD} Vulnerability Assessment{RESET}")
    print(f"{BOLD}{'─'*65}{RESET}")
    print()
    print(f"  Based on your answers above, do you consider the registration")
    print(f"  process to be {RED}flawed or vulnerable{RESET}?")
    print()

    is_vulnerable = prompt_yn_simple("Flag as flawed/vulnerable?")
    vuln_why = ""
    if is_vulnerable:
        print()
        vuln_why = prompt_multiline(
            f"{RED}Why is it flawed/vulnerable?{RESET} "
            "(describe the specific weakness)"
        )
    else:
        print(f"\n  {GREEN}Marked as: not vulnerable{RESET}")

    print()

    # ---------------------------------------------------------------------------
    # Build output
    # ---------------------------------------------------------------------------
    result = {
        "wstg_id":         "WSTG-IDNT-02",
        "questionnaire":   "Q1 — Registration Process",
        "target":          target or "(not specified)",
        "tester":          tester or "(not specified)",
        "timestamp":       datetime.now(timezone.utc).isoformat(),
        "responses":       responses,
        "vulnerability_assessment": {
            "flagged_as_vulnerable": is_vulnerable,
            "why":                   vuln_why if is_vulnerable else "not-vulnerable",
        },
    }

    # Quick summary to terminal
    print(f"{BOLD}{'─'*65}{RESET}")
    print(f"{BOLD} Summary{RESET}")
    print(f"{BOLD}{'─'*65}{RESET}")
    yes_count = sum(1 for r in responses if r["answer_code"] == "y")
    no_count  = sum(1 for r in responses if r["answer_code"] == "n")
    unk_count = sum(1 for r in responses if r["answer_code"] == "?")
    print(f"  Yes: {yes_count}  |  No: {no_count}  |  Unknown: {unk_count}")
    verdict = f"{RED}FLAWED / VULNERABLE{RESET}" if is_vulnerable else f"{GREEN}NOT VULNERABLE{RESET}"
    print(f"  Verdict: {verdict}")
    if is_vulnerable and vuln_why:
        print(f"  Reason : {vuln_why[:120]}{'...' if len(vuln_why) > 120 else ''}")
    print()

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description='IDNT-02 Q1: User Registration Process questionnaire'
    )
    p.add_argument(
        '-o', '--output',
        default='outputs/test_outputs/q1_json.json',
        help='Output JSON (default: outputs/test_outputs/q1_json.json)'
    )
    p.add_argument('--target', default='', help='Target application name/version')
    p.add_argument('--tester', default='', help='Tester name / handle')
    return p.parse_args()


def main():
    args = parse_args()

    result = run_questionnaire(args.target, args.tester)

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)

    print(f"{GREEN}[+] Output written → {args.output}{RESET}")
    print()
    print(f"  Next: run q2.py for the identity forgery assessment.")
    print(f"  python3 utilities/python/q2.py -o outputs/test_outputs/q2_json.json")
    print()


if __name__ == "__main__":
    main()
