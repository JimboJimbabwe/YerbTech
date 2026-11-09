#!/usr/bin/env python3
"""
WSTG-ATHN-07 — Weak Password Policy
Questionnaire Script: ATHN-07.py

Six password policy questions, each rendered as a two-column reference table
before prompting. Reads from q1.json, fills verdicts, writes completed JSON
to outputs/test_outputs/WSTG_verdict.json.

Usage:
  python3 utilities/python/ATHN-07.py
  python3 utilities/python/ATHN-07.py -q inputs/json/q1.json
  python3 utilities/python/ATHN-07.py -q inputs/json/q1.json -o outputs/test_outputs/WSTG_verdict.json

Reference tool: https://github.com/JimboJimbabwe/ForSelf/blob/main/MissionTools/Credential_Auditing/PasswordChecker.py
"""

import argparse
import json
import os
import sys
import textwrap
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
BLUE   = "\033[94m"
RESET  = "\033[0m"

COL_WIDTH = 36   # width of each table column

# ---------------------------------------------------------------------------
# Question metadata: question, why, how
# Each entry drives the two-column reference table printed before each prompt.
# ---------------------------------------------------------------------------

QUESTION_META = {
    "Q1_entropy": {
        "label": "Q1 — Password Entropy",
        "question": "Does the policy enforce sufficient entropy?",
        "why": (
            "Weak passwords are trivially brute-forced or found in breach-credential "
            "databases. NIST SP 800-63B requires a minimum of 8 characters; industry "
            "best practice is 12–16+ with mixed character classes. Low entropy "
            "dramatically reduces the time to crack offline hashes."
        ),
        "how": (
            "Attempt to register/change passwords of varying length and complexity:\n"
            "  • 4-char numeric only (e.g. '1234')\n"
            "  • 6-char lowercase only (e.g. 'abc123')\n"
            "  • 8-char no symbols\n"
            "  • 12-char mixed case + number + symbol\n"
            "Record which the application accepts. Use PasswordChecker.py for "
            "automated complexity scoring:\n"
            "  https://github.com/JimboJimbabwe/ForSelf/blob/main/MissionTools/"
            "Credential_Auditing/PasswordChecker.py\n"
            "Verdict: True = strong policy enforced. False = weak accepted."
        ),
        "nist_ref": "NIST SP 800-63B §5.1.1"
    },
    "Q2_history_bypass": {
        "label": "Q2 — Password History Bypass",
        "question": "Can password history be bypassed?",
        "why": (
            "If a user can immediately cycle back to a previous password (e.g. "
            "change to P2, P3, … P10, then back to P1), history controls are "
            "meaningless. Attackers who obtain an old credential can verify it "
            "remains valid."
        ),
        "how": (
            "Perform 10 sequential password changes:\n"
            "  1. Set password to PW_A\n"
            "  2–9. Change to PW_B, PW_C … PW_I\n"
            "  10. Attempt to set back to PW_A\n"
            "If PW_A is accepted on step 10, history is not enforced (or the window "
            "is <10). Record the minimum cycle depth the application enforces.\n"
            "Verdict: True = history enforced (PW_A rejected). False = bypass possible."
        ),
        "nist_ref": "NIST SP 800-63B §5.1.1.2"
    },
    "Q3_nist_expiry": {
        "label": "Q3 — NIST-Aligned Password Expiry",
        "question": "Does expiry policy align with NIST SP 800-63B?",
        "why": (
            "NIST SP 800-63B explicitly recommends AGAINST mandatory periodic password "
            "expiry (e.g. 'change every 90 days') because it leads to predictable "
            "patterns (Summer2024! → Summer2025!) without improving security. "
            "Expiry should only be triggered on suspected compromise."
        ),
        "how": (
            "Review the application's password policy documentation and account "
            "settings:\n"
            "  • Does the app force periodic password changes (30/60/90-day expiry)?\n"
            "  • Is expiry triggered only on suspected compromise / credential breach?\n"
            "  • Does it allow passwords to never expire (NIST-compliant)?\n"
            "Reference: https://pages.nist.gov/800-63-3/sp800-63b.html#sec5\n"
            "Verdict: True = NIST-aligned (no forced periodic expiry). "
            "False = non-compliant forced expiry in place."
        ),
        "nist_ref": "NIST SP 800-63B §5.1.1.2 (Memorized Secrets)"
    },
    "Q4_history_maintained": {
        "label": "Q4 — Password History Maintained",
        "question": "Does the application maintain password history?",
        "why": (
            "Without a stored history, users can immediately reuse a previous password "
            "after a forced change, defeating the purpose of the change. "
            "NIST recommends checking against at least the last N passwords "
            "(common baseline: 5–10)."
        ),
        "how": (
            "After a password change, attempt to set the password back to the "
            "immediately preceding value:\n"
            "  1. Current password: PW_A\n"
            "  2. Change to PW_B (succeeds)\n"
            "  3. Attempt to change back to PW_A\n"
            "If PW_A is accepted, no history is maintained.\n"
            "Verdict: True = previous passwords rejected. False = reuse allowed."
        ),
        "nist_ref": "NIST SP 800-63B §5.1.1.2"
    },
    "Q5_personal_info_rejected": {
        "label": "Q5 — Personal Info Rejected",
        "question": "Does the policy reject passwords with name/username info?",
        "why": (
            "Passwords derived from personal information (first name, last name, "
            "username, email prefix) are trivially guessable through targeted "
            "dictionary attacks and OSINT. Policies should check against known "
            "account attributes."
        ),
        "how": (
            "For a test account with known name (e.g. 'John Smith', username 'jsmith'):\n"
            "  • Attempt: 'JohnSmith1!'\n"
            "  • Attempt: 'jsmith2024'\n"
            "  • Attempt: 'Smith@123'\n"
            "  • Attempt: 'johnsmith!'\n"
            "Record whether any are accepted.\n"
            "Verdict: True = rejected. False = personal info accepted in password."
        ),
        "nist_ref": "NIST SP 800-63B §5.1.1.2 (context-specific words)"
    },
    "Q6_common_passwords_blocked": {
        "label": "Q6 — Common Passwords Blocked",
        "question": "Does the policy reject common/dictionary passwords?",
        "why": (
            "The most frequently compromised accounts use passwords from the top "
            "10,000 most common list (rockyou, SecLists). NIST requires checking "
            "new passwords against breach credential corpora and common password "
            "lists. Accepting 'Password1!' or 'Summer2024' is a critical failure."
        ),
        "how": (
            "Attempt to set passwords from a common list — test at least 15:\n"
            "  Password1, 123456789, Password1!, Qwerty123, Welcome1\n"
            "  Summer2024, Admin1234, Monkey123, Dragon123, Football1\n"
            "  Iloveyou1, Sunshine1, Shadow123, Master123, Superman1\n"
            "Record how many are accepted. Even 1 acceptance = policy failure.\n"
            "Verdict: True = all rejected. False = common passwords accepted."
        ),
        "nist_ref": "NIST SP 800-63B §5.1.1.2 (banned password list)"
    },
}

COMMON_PASSWORDS = [
    "Password1", "123456789", "Password1!", "Qwerty123", "Welcome1",
    "Summer2024", "Admin1234", "Monkey123", "Dragon123", "Football1",
    "Iloveyou1", "Sunshine1", "Shadow123", "Master123", "Superman1",
]


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def print_table(label: str, question: str, why: str, how: str, nist_ref: str = ""):
    """Print a two-column reference table for a question."""
    sep = "─" * (COL_WIDTH * 2 + 3)
    print(f"\n{BOLD}{CYAN}{sep}{RESET}")
    print(f"{BOLD}{CYAN}  {label}{RESET}")
    print(f"{CYAN}{sep}{RESET}")

    # Two-column header
    print(f"{BOLD}  {'QUESTION / WHAT TO TEST':<{COL_WIDTH}}  {'WHY DO THIS / HOW TO TEST'}{RESET}")
    print(f"  {'─'*COL_WIDTH}  {'─'*COL_WIDTH}")

    # Wrap content to column width
    q_lines  = textwrap.wrap(question, width=COL_WIDTH) or [""]
    why_wrap = textwrap.wrap(f"WHY: {why}", width=COL_WIDTH) or [""]
    how_wrap = textwrap.wrap(f"HOW: {how}", width=COL_WIDTH) or [""]
    right_lines = why_wrap + [""] + how_wrap
    if nist_ref:
        right_lines += ["", f"REF: {nist_ref}"]

    max_rows = max(len(q_lines), len(right_lines))
    q_lines  += [""] * (max_rows - len(q_lines))
    right_lines += [""] * (max_rows - len(right_lines))

    for l, r in zip(q_lines, right_lines):
        print(f"  {l:<{COL_WIDTH}}  {DIM}{r}{RESET}")

    print(f"{CYAN}{sep}{RESET}")


def prompt_yn(prompt: str) -> bool:
    while True:
        raw = input(f"\n  {prompt} [Y/N]: ").strip().lower()
        if raw in ('y', 'yes'):
            return True
        if raw in ('n', 'no'):
            return False
        print(f"  {YELLOW}Please enter Y or N{RESET}")


def prompt_note() -> str:
    raw = input(f"  {DIM}Optional note (Enter to skip): {RESET}").strip()
    return raw


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_questionnaire(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"{RED}[!] Not found: {path}{RESET}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"{RED}[!] Invalid JSON: {e}{RESET}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Main questionnaire
# ---------------------------------------------------------------------------

def run(data: dict) -> dict:
    questions = data["questionnaire"]["questions"]
    failed = []

    print()
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"{BOLD} WSTG-ATHN-07 — Weak Password Policy{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"  {DIM}{data.get('description', '')}{RESET}")
    print()
    print(f"  {DIM}For each question: Y = control IS in place (True / pass).{RESET}")
    print(f"  {DIM}                   N = control is NOT in place (False / fail).{RESET}")

    # Print common password list for Q6 reference
    print()
    print(f"  {BLUE}Common password test list (for Q6):{RESET}")
    for i, pw in enumerate(COMMON_PASSWORDS, 1):
        print(f"    {i:>2}. {pw}")

    for key, meta in QUESTION_META.items():
        print_table(
            label=meta["label"],
            question=meta["question"],
            why=meta["why"],
            how=meta["how"],
            nist_ref=meta.get("nist_ref", ""),
        )

        verdict = prompt_yn(f"Verdict — control is in place?")
        note = prompt_note()

        questions[key]["verdict"] = verdict
        if note:
            questions[key]["tester_note"] = note

        if not verdict:
            failed.append(key)
            print(f"  {RED}✗ Marked as FAILED — {meta['label']}{RESET}")
        else:
            print(f"  {GREEN}✓ Marked as PASSED{RESET}")

    # Findings
    is_vulnerable = len(failed) > 0
    verdict_str = "Vulnerable" if is_vulnerable else "Not Vulnerable"
    data["questionnaire"]["findings"]["verdict"] = verdict_str
    data["questionnaire"]["findings"]["failed_questions"] = failed
    data["questionnaire"]["findings"]["timestamp"] = datetime.now(timezone.utc).isoformat()

    # Summary
    print()
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"{BOLD} Summary{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    color = RED if is_vulnerable else GREEN
    print(f"  Overall verdict: {color}{verdict_str}{RESET}")
    if failed:
        print(f"  Failed controls ({len(failed)}):")
        for f_key in failed:
            print(f"    {RED}• {QUESTION_META[f_key]['label']}{RESET}")
    else:
        print(f"  {GREEN}All controls passed{RESET}")
    print()

    return data


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description='ATHN-07: Weak Password Policy questionnaire'
    )
    p.add_argument(
        '-q', '--questionnaire',
        default='inputs/json/q1.json',
        metavar='PATH',
        help='Path to q1.json (default: inputs/json/q1.json)'
    )
    p.add_argument(
        '-o', '--output',
        default='outputs/test_outputs/WSTG_verdict.json',
        metavar='PATH',
        help='Output JSON path (default: outputs/test_outputs/WSTG_verdict.json)'
    )
    return p.parse_args()


def main():
    args = parse_args()
    data = load_questionnaire(args.questionnaire)
    data = run(data)

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"{GREEN}[+] Verdict JSON written → {args.output}{RESET}")
    print(f"  Run verdict script:")
    print(f"  python3 utilities/python/ATHN_VERDICT.py -i {args.output}")
    print()


if __name__ == "__main__":
    main()
