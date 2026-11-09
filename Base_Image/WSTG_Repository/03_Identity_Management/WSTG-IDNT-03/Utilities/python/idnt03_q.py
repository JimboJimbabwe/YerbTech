#!/usr/bin/env python3
"""
WSTG-IDNT-03 — Account Provisioning Process Assessment
Questionnaire: Account Provisioning

Interactive CLI questionnaire covering the 7 core provisioning questions
from IDNT-03. Each question accepts Y / N / ? (unknown), with an optional
note per answer. A vulnerability flag section follows at the end.

Output: outputs/test_outputs/idnt03_q_json.json

Usage:
  python3 utilities/python/idnt03_q.py
  python3 utilities/python/idnt03_q.py -o outputs/test_outputs/idnt03_q_json.json
  python3 utilities/python/idnt03_q.py --target "MyApp v2.1" --tester "jsmith"
"""

import argparse
import json
import os
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Questions — WSTG-IDNT-03 Account Provisioning Process
# ---------------------------------------------------------------------------

QUESTIONS = [
    {
        "id":       "IDNT03-Q-01",
        "question": "Is there any authorisation required before an account is provisioned?",
        "guidance": (
            "Consider: does an administrator, manager, or approver need to explicitly "
            "grant access before the account is created? Or is provisioning fully "
            "automatic (e.g. triggered by HRIS events, SSO first-login, or self-service)? "
            "Lack of an authorisation gate is a risk for over-provisioning and insider threat."
        ),
    },
    {
        "id":       "IDNT03-Q-02",
        "question": "Can accounts be provisioned with excessive privileges?",
        "guidance": (
            "Consider: does the provisioning workflow enforce a least-privilege baseline, "
            "or can a requestor/provisioner assign any role including admin? "
            "Test: attempt to provision an account with elevated roles via the API or "
            "admin UI and observe whether any controls prevent it."
        ),
    },
    {
        "id":       "IDNT03-Q-03",
        "question": "Can one user provision an account for another user without oversight?",
        "guidance": (
            "Consider: is there a separation-of-duties control so no single person can "
            "both request and approve provisioning? Can a standard user create accounts "
            "for others? Is the provisioning workflow single-approval or does it require "
            "a second reviewer?"
        ),
    },
    {
        "id":       "IDNT03-Q-04",
        "question": "Are provisioned accounts tied to a verified identity?",
        "guidance": (
            "Consider: is the identity confirmed before or during provisioning (e.g. "
            "verified corporate email, HR record match, government ID, invite token)? "
            "Or can an account be provisioned for an unverified or fictional identity?"
        ),
    },
    {
        "id":       "IDNT03-Q-05",
        "question": "Is the provisioning process logged and auditable?",
        "guidance": (
            "Consider: are provisioning events (account created, role assigned, approver, "
            "timestamp) written to an immutable or tamper-evident log? "
            "Can the organisation reconstruct who provisioned which account and why? "
            "Are logs retained for an appropriate period?"
        ),
    },
    {
        "id":       "IDNT03-Q-06",
        "question": "Is there a de-provisioning (offboarding) process, and is it enforced?",
        "guidance": (
            "Consider: are accounts disabled promptly when a user leaves or changes role? "
            "Is de-provisioning triggered automatically (e.g. HR system event) or manual? "
            "Test: check for active accounts belonging to former employees or contractors. "
            "Look for orphaned service/API accounts with no current owner."
        ),
    },
    {
        "id":       "IDNT03-Q-07",
        "question": "Are provisioning requests validated before execution?",
        "guidance": (
            "Consider: is the provisioning API or admin form protected against parameter "
            "tampering (e.g. forcing a role field, mass assignment of privileges)? "
            "Are there server-side checks that enforce what the requestor is allowed to "
            "grant? Test with a proxy: modify role/permission fields in the provisioning "
            "request and observe the response."
        ),
    },
]

ANSWER_OPTIONS = {"y": "Yes", "n": "No", "?": "Unknown / Not tested"}

BOLD   = "\033[1m"
DIM    = "\033[2m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
RESET  = "\033[0m"


# ---------------------------------------------------------------------------
# Prompt helpers
# ---------------------------------------------------------------------------

def prompt_yn_unknown(prompt: str) -> tuple:
    while True:
        raw = input(f"  {prompt} [Y/N/?]: ").strip().lower()
        if raw in ANSWER_OPTIONS:
            note_raw = input(f"  {DIM}Optional note (Enter to skip): {RESET}").strip()
            return raw, note_raw
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
# Main questionnaire
# ---------------------------------------------------------------------------

def run_questionnaire(target: str, tester: str) -> dict:
    print()
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"{BOLD} WSTG-IDNT-03 — Account Provisioning Process{RESET}")
    print(f"{BOLD} Questionnaire: Account Provisioning Controls{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    if target:
        print(f"  Target : {target}")
    if tester:
        print(f"  Tester : {tester}")
    print()
    print(f"  {DIM}Answer each question with Y (Yes), N (No), or ? (Unknown/not tested).{RESET}")
    print(f"  {DIM}Y = the described weakness or vector is present / confirmed.{RESET}")
    print(f"  {DIM}N = the control is in place.{RESET}")
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
    print(f"  Based on your answers, do you consider the provisioning process")
    print(f"  to be {RED}flawed or vulnerable{RESET}?")
    print()

    is_vulnerable = prompt_yn_simple("Flag as flawed/vulnerable?")
    vuln_why = ""
    if is_vulnerable:
        print()
        vuln_why = prompt_multiline(
            f"{RED}Why is it flawed/vulnerable?{RESET} "
            "(describe the specific weakness, e.g. which control is missing)"
        )
    else:
        print(f"\n  {GREEN}Marked as: not vulnerable{RESET}")

    print()

    # ---------------------------------------------------------------------------
    # Build output
    # ---------------------------------------------------------------------------
    result = {
        "wstg_id":       "WSTG-IDNT-03",
        "questionnaire": "Account Provisioning Process",
        "target":        target or "(not specified)",
        "tester":        tester or "(not specified)",
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "responses":     responses,
        "vulnerability_assessment": {
            "flagged_as_vulnerable": is_vulnerable,
            "why":                   vuln_why if is_vulnerable else "not-vulnerable",
        },
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
    print()

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description='IDNT-03: Account Provisioning Process questionnaire'
    )
    p.add_argument(
        '-o', '--output',
        default='outputs/test_outputs/idnt03_q_json.json',
        help='Output JSON (default: outputs/test_outputs/idnt03_q_json.json)'
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
    print(f"  Next: run script_me.py to generate the full IDNT-03 report.")
    print(f"  python3 script_me.py -How_To_bridge /inputs/data/how_to_bridge.json \\")
    print(f"                       -questionnaire /inputs/data/q_base.json \\")
    print(f"                       -input_strings /inputs/data/how_to_query.txt")
    print()


if __name__ == "__main__":
    main()
