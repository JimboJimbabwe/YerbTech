#!/usr/bin/env python3
"""
WSTG-IDNT-02 — User Registration Process Assessment
Questionnaire 2 of 2: Identity Forgery & Manipulation

Interactive CLI questionnaire covering the 2 identity integrity questions
from IDNT-02. Accepts Y / N / ? per question, optional notes, and a
vulnerability flag with free-text reason.

Output: /outputs/test_outputs/q2_json.json

Usage:
  python3 utilities/python/q2.py
  python3 utilities/python/q2.py -o outputs/test_outputs/q2_json.json
  python3 utilities/python/q2.py --target "MyApp v2.1" --tester "jsmith"
  python3 utilities/python/q2.py --q1 outputs/test_outputs/q1_json.json
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
        "id":       "IDNT02-Q2-01",
        "question": "Can identity information be easily forged or faked?",
        "guidance": (
            "Consider: can a registrant supply arbitrary values for name, email, "
            "organisation, role, or other identity fields without any validation? "
            "Is an email confirmation the only verification, and can that be bypassed "
            "with a disposable address? Can claimed attributes (e.g. 'I am an employee') "
            "be verified by the application?"
        ),
    },
    {
        "id":       "IDNT02-Q2-02",
        "question": "Can the exchange of identity information be manipulated during registration?",
        "guidance": (
            "Consider: are registration form fields, hidden parameters, JWT claims, "
            "OAuth tokens, or API request bodies modifiable in transit? "
            "Test: intercept the registration request in a proxy and modify role, "
            "privilege, or identity fields — does the application accept them? "
            "Is the registration flow protected against parameter tampering, "
            "mass assignment, or race conditions?"
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
# Prompt helpers (same pattern as q1.py)
# ---------------------------------------------------------------------------

def prompt_yn_unknown(prompt: str) -> tuple:
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
# Load Q1 output for cross-reference (optional)
# ---------------------------------------------------------------------------

def load_q1(path: str) -> dict | None:
    if not path:
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Main questionnaire
# ---------------------------------------------------------------------------

def run_questionnaire(target: str, tester: str, q1_data: dict | None) -> dict:
    print()
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"{BOLD} WSTG-IDNT-02 — User Registration Process{RESET}")
    print(f"{BOLD} Questionnaire 2 of 2: Identity Forgery & Manipulation{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    if target:
        print(f"  Target : {target}")
    if tester:
        print(f"  Tester : {tester}")

    # Cross-reference Q1 verdict if loaded
    if q1_data:
        q1_vuln = q1_data.get("vulnerability_assessment", {})
        flag = q1_vuln.get("flagged_as_vulnerable", False)
        print()
        print(f"  {DIM}Q1 (Registration Process) verdict: "
              f"{'FLAWED/VULNERABLE' if flag else 'Not vulnerable'}{RESET}")

    print()
    print(f"  {DIM}Answer each question with Y (Yes), N (No), or ? (Unknown/not tested).{RESET}")
    print(f"  {DIM}Y = this attack vector is possible / confirmed.{RESET}")
    print()

    responses = []

    for i, q in enumerate(QUESTIONS, start=1):
        print(f"{CYAN}Q{i}: {q['question']}{RESET}")
        print(f"  {DIM}Guidance: {q['guidance']}{RESET}")
        answer, note = prompt_yn_unknown("Answer")
        responses.append({
            "id":          q["id"],
            "question":    q["question"],
            "answer":      ANSWER_OPTIONS[answer],
            "answer_code": answer,
            "note":        note,
        })
        print()

    # ---------------------------------------------------------------------------
    # Vulnerability flag
    # ---------------------------------------------------------------------------
    print(f"{BOLD}{'─'*65}{RESET}")
    print(f"{BOLD} Vulnerability Assessment{RESET}")
    print(f"{BOLD}{'─'*65}{RESET}")
    print()
    print(f"  Based on your answers, do you consider the identity exchange")
    print(f"  mechanism to be {RED}flawed or vulnerable{RESET}?")
    print()
    print(f"  {DIM}Note: answering Y to either question above typically warrants a finding.{RESET}")
    print()

    is_vulnerable = prompt_yn_simple("Flag as flawed/vulnerable?")
    vuln_why = ""
    if is_vulnerable:
        print()
        vuln_why = prompt_multiline(
            f"{RED}Why is it flawed/vulnerable?{RESET} "
            "(describe the specific attack vector or evidence)"
        )
    else:
        print(f"\n  {GREEN}Marked as: not vulnerable{RESET}")

    print()

    # ---------------------------------------------------------------------------
    # Build output
    # ---------------------------------------------------------------------------
    result = {
        "wstg_id":       "WSTG-IDNT-02",
        "questionnaire": "Q2 — Identity Forgery & Manipulation",
        "target":        target or "(not specified)",
        "tester":        tester or "(not specified)",
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "responses":     responses,
        "vulnerability_assessment": {
            "flagged_as_vulnerable": is_vulnerable,
            "why":                   vuln_why if is_vulnerable else "not-vulnerable",
        },
    }

    # Cross-reference Q1 if loaded
    if q1_data:
        result["q1_cross_reference"] = {
            "q1_flagged_vulnerable": q1_data.get("vulnerability_assessment", {})
                                              .get("flagged_as_vulnerable", False),
            "q1_output_path":        q1_data.get("_source_path", "(loaded)"),
        }

    # Terminal summary
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

    # Combined risk hint
    if q1_data:
        q1_flag = q1_data.get("vulnerability_assessment", {}).get("flagged_as_vulnerable", False)
        if q1_flag and is_vulnerable:
            print()
            print(f"  {RED}⚠ Both Q1 and Q2 flagged vulnerable — consider a HIGH severity finding.{RESET}")
        elif q1_flag or is_vulnerable:
            print()
            print(f"  {YELLOW}⚠ One questionnaire flagged vulnerable — review for MEDIUM finding.{RESET}")
    print()

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description='IDNT-02 Q2: Identity Forgery & Manipulation questionnaire'
    )
    p.add_argument(
        '-o', '--output',
        default='outputs/test_outputs/q2_json.json',
        help='Output JSON (default: outputs/test_outputs/q2_json.json)'
    )
    p.add_argument('--target', default='', help='Target application name/version')
    p.add_argument('--tester', default='', help='Tester name / handle')
    p.add_argument(
        '--q1',
        help='Path to q1_json.json output for cross-reference (optional)'
    )
    return p.parse_args()


def main():
    args = parse_args()

    q1_data = load_q1(args.q1)
    if args.q1 and q1_data is None:
        print(f"[!] Could not load Q1 output from {args.q1} — continuing without cross-reference.")
    if q1_data:
        q1_data["_source_path"] = args.q1

    result = run_questionnaire(
        target=args.target,
        tester=args.tester,
        q1_data=q1_data,
    )

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)

    print(f"{GREEN}[+] Output written → {args.output}{RESET}")
    print()


if __name__ == "__main__":
    main()
