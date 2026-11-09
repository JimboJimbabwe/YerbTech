#!/usr/bin/env python3
"""
WSTG-ATHN-09 — Weak Password Change or Reset Functionalities
Questionnaire Script: q1_ATHN09.py

Walks through the nested categorical questionnaire (categories a–g).
Leaf categories (a–d) are single questions.
Branch categories (e–g) have a gating first question; sub-questions are
only asked if the gate is Flawed.

Reads  from: /input/json/ATHN_09_questionnaire.json
Outputs to:  /outputs/test_outputs/questionnaire_ATHN09.json

Usage:
  python3 utilities/python/q1_ATHN09.py
  python3 utilities/python/q1_ATHN09.py \\
    -q  input/json/ATHN_09_questionnaire.json \\
    -o  outputs/test_outputs/questionnaire_ATHN09.json
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
RESET  = "\033[0m"

# ---------------------------------------------------------------------------
# Verdict semantics for ATHN-09
# Each question is phrased so that "Flawed" = a problem exists.
# For leaf questions the tester picks Flawed / Not Flawed.
# For sub-questions inside e/f/g: same, but only asked when gate is Flawed.
# ---------------------------------------------------------------------------

VERDICT_FLAWED     = "Flawed"
VERDICT_NOT_FLAWED = "Not Flawed"
VERDICT_NA         = "N/A"


# ---------------------------------------------------------------------------
# Guidance blurbs per question (keyed by category + question index)
# Used to print context before prompting.
# ---------------------------------------------------------------------------

GUIDANCE = {
    # Category a
    ("a", 0): (
        "Attempt rapid sequential password reset requests for the same account "
        "(50+ in <30s). If no lockout, CAPTCHA, or delay is imposed, rate limiting "
        "is absent. This allows enumeration and token brute-force."
    ),
    # Category b
    ("b", 0): (
        "Inject common SQL payloads into the email/username field of the reset form: "
        "  ' OR '1'='1  |  admin'--  |  ' UNION SELECT 1-- \n"
        "Observe error messages, unexpected redirects, or different response timings."
    ),
    # Category c
    ("c", 0): (
        "Walk through the password reset flow end-to-end. Observe whether MFA "
        "(TOTP, push, SMS OTP) is required at any point before the reset is "
        "completed. Absence of MFA here allows account takeover with only an "
        "email address."
    ),
    # Category d
    ("d", 0): (
        "Attempt to log in without completing any MFA challenge. If successful, "
        "MFA is absent or bypassable on the login flow itself."
    ),
    # Category e
    ("e", 0): (
        "Trigger a password reset and observe the mechanism. Is a NEW plaintext "
        "password delivered to the user's email inbox? This is the weakest pattern "
        "— it implies the application can reconstruct or generate plaintext credentials."
    ),
    ("e", 1): (
        "After receiving the new password by email, log in with it. Does the "
        "application immediately require the user to change it on first login? "
        "If not, the emailed password becomes long-lived."
    ),
    ("e", 2): (
        "Assess the emailed password: length ≥12, mixed case, numbers, symbols? "
        "Or is it short / dictionary-based / user-guessable?"
    ),
    ("e", 3): (
        "Does the email contain the user's CURRENT/EXISTING password in plaintext? "
        "This definitively confirms plaintext storage — critical finding."
    ),
    ("e", 4): (
        "Check the sending domain's DNS: does it have SPF, DKIM, and DMARC records? "
        "  dig TXT _dmarc.<domain>  |  dig TXT <domain>  (look for v=spf1)\n"
        "Absence means the reset email can be spoofed."
    ),
    ("e", 5): (
        "Is email an appropriate channel? Consider: email accounts are often "
        "accessible from multiple devices, may be compromised, and do not provide "
        "the same assurance as TOTP or hardware keys. Flag as contextually weak."
    ),
    # Category f
    ("f", 0): (
        "Trigger a password reset. Is a one-time link (with a token in the URL or "
        "as a POST body parameter) sent to the user's email? This is the standard "
        "modern pattern — sub-questions assess its implementation quality."
    ),
    ("f", 1): (
        "Click the reset link. Does it use HTTPS? A plaintext HTTP link exposes "
        "the token to network interception."
    ),
    ("f", 2): (
        "After using the reset link to change the password, attempt to use the "
        "same link again. Does the application reject it (single-use enforcement)?"
    ),
    ("f", 3): (
        "Note the time of receiving the link. Wait the documented expiry window "
        "(or 24h if undocumented) and attempt to use it. Does it expire?"
    ),
    ("f", 4): (
        "Extract the token from the reset URL. Assess its length and entropy: "
        "≥128 bits of random data is the standard. Short (≤6 hex chars) or "
        "sequential tokens are brute-forceable."
    ),
    ("f", 5): (
        "Inspect the reset URL for a uid=, user_id=, or similar parameter. "
        "Presence leaks account existence and may allow token substitution attacks."
    ),
    ("f", 6): (
        "Construct a dork: site:<domain> inurl:reset inurl:token\n"
        "If reset links appear in Google results, the application's reset endpoints "
        "are being indexed — tokens may be live."
    ),
    ("f", 7): (
        "Same as e.4 — check SPF, DKIM, DMARC on the sending domain."
    ),
    # Category g
    ("g", 0): (
        "Trigger password reset. Is an OTP or reset link sent via SMS to the "
        "user's registered phone number?"
    ),
    ("g", 1): (
        "Inspect the SMS OTP length and format. Numeric-only 6-digit OTPs have "
        "only 1M possibilities — adequate if rate-limited, weak if not. "
        "Alphanumeric ≥8 chars is preferred."
    ),
    ("g", 2): (
        "Request two OTPs in sequence. Does the first OTP remain valid after "
        "the second is issued? Can the first be replayed after use?"
    ),
    ("g", 3): (
        "Request an OTP and wait. Does it expire (typically 5–10 min)?"
    ),
    ("g", 4): (
        "Send 20+ OTP requests in rapid succession. Are any blocked or delayed? "
        "Rate limiting prevents OTP flooding and SIM-swap abuse."
    ),
    ("g", 5): (
        "SMS is NIST SP 800-63B RESTRICTED due to SIM-swapping and SS7 vulnerabilities. "
        "Flag as contextually weak regardless of implementation quality. "
        "Ref: https://pages.nist.gov/800-63-3/sp800-63b.html#pstnOOB"
    ),
}


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_questionnaire(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"{RED}[!] Questionnaire not found: {path}{RESET}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"{RED}[!] Invalid JSON: {e}{RESET}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Prompt helpers
# ---------------------------------------------------------------------------

def prompt_verdict(prompt: str, allow_na: bool = False) -> str:
    opts = "F=Flawed / N=Not Flawed" + (" / S=Skip (N/A)" if allow_na else "")
    while True:
        raw = input(f"  {prompt} [{opts}]: ").strip().lower()
        if raw in ('f', 'flawed'):
            return VERDICT_FLAWED
        if raw in ('n', 'not', 'not flawed'):
            return VERDICT_NOT_FLAWED
        if allow_na and raw in ('s', 'skip', 'na', 'n/a'):
            return VERDICT_NA
        print(f"  {YELLOW}Enter F (Flawed), N (Not Flawed)" + (", or S (Skip)" if allow_na else "") + f"{RESET}")


def prompt_reasoning() -> str:
    raw = input(f"  {DIM}Reasoning / evidence (Enter to skip): {RESET}").strip()
    return raw


def print_guidance(cat: str, idx: int):
    text = GUIDANCE.get((cat, idx), "")
    if text:
        for line in text.split('\n'):
            print(f"  {DIM}{line}{RESET}")


# ---------------------------------------------------------------------------
# Main questionnaire
# ---------------------------------------------------------------------------

def run(data: dict) -> dict:
    categories = data.get("questions_categories", [])
    total_flawed = 0
    total_asked = 0

    print()
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"{BOLD} WSTG-ATHN-09 — Weak Password Reset / Change Functionalities{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"  {DIM}{data.get('description', '')}{RESET}")
    print()
    print(f"  {DIM}F = Flawed (weakness present) | N = Not Flawed (control in place){RESET}")
    print()

    for cat_entry in categories:
        cat  = cat_entry["category"]
        name = cat_entry["name"]
        qs   = cat_entry["questions"]
        leaf = cat_entry.get("is_leaf", True)

        print(f"{BOLD}{CYAN}{'─'*65}{RESET}")
        print(f"{BOLD}{CYAN} Category {cat.upper()}: {name}{RESET}")
        print(f"{BOLD}{CYAN}{'─'*65}{RESET}")

        if leaf:
            # Single question
            q = qs[0]
            print(f"\n  {q['question']}")
            print_guidance(cat, 0)
            verdict   = prompt_verdict("Verdict")
            reasoning = prompt_reasoning()
            q["verdict"]   = verdict
            q["reasoning"] = reasoning
            total_asked += 1
            if verdict == VERDICT_FLAWED:
                total_flawed += 1
                print(f"  {RED}⚠ Flawed{RESET}")
            else:
                print(f"  {GREEN}✓ Not Flawed{RESET}")
            print()

        else:
            # Gating first question
            gate_q = qs[0]
            print(f"\n  {gate_q['question']}")
            if gate_q.get("note"):
                print(f"  {YELLOW}Note: {gate_q['note']}{RESET}")
            print_guidance(cat, 0)
            gate_verdict   = prompt_verdict("Verdict")
            gate_reasoning = prompt_reasoning()
            gate_q["verdict"]   = gate_verdict
            gate_q["reasoning"] = gate_reasoning
            total_asked += 1
            if gate_verdict == VERDICT_FLAWED:
                total_flawed += 1
                print(f"  {RED}⚠ Flawed — assessing sub-questions{RESET}")
                print()

                # Sub-questions
                for i, sq in enumerate(qs[1:], start=1):
                    print(f"  {CYAN}Sub-question {cat}.{i+1}: {sq['question']}{RESET}")
                    if sq.get("note"):
                        print(f"    {YELLOW}Note: {sq['note']}{RESET}")
                    print_guidance(cat, i)
                    sv   = prompt_verdict("Verdict", allow_na=True)
                    sr   = prompt_reasoning()
                    sq["verdict"]   = sv
                    sq["reasoning"] = sr
                    total_asked += 1
                    if sv == VERDICT_FLAWED:
                        total_flawed += 1
                        print(f"    {RED}⚠ Flawed{RESET}")
                    elif sv == VERDICT_NA:
                        print(f"    {DIM}Skipped (N/A){RESET}")
                    else:
                        print(f"    {GREEN}✓ Not Flawed{RESET}")
                    print()
            else:
                # Gate = Not Flawed → mark all sub-questions N/A
                print(f"  {GREEN}✓ Not Flawed — sub-questions not applicable{RESET}")
                for sq in qs[1:]:
                    sq["verdict"]   = VERDICT_NA
                    sq["reasoning"] = "Gate question answered Not Flawed — not applicable"
                print()

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    data["meta"] = {
        "total_questions_asked": total_asked,
        "total_flawed":          total_flawed,
        "total_not_flawed":      total_asked - total_flawed,
        "timestamp":             datetime.now(timezone.utc).isoformat(),
    }

    print(f"{BOLD}{'='*65}{RESET}")
    print(f"{BOLD} Summary{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"  Questions assessed: {total_asked}")
    color = RED if total_flawed else GREEN
    print(f"  Flawed findings:    {color}{total_flawed}{RESET}")
    print()

    return data


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description='ATHN-09: Weak Password Reset questionnaire'
    )
    p.add_argument(
        '-q', '--questionnaire',
        default='input/json/ATHN_09_questionnaire.json',
        metavar='PATH',
        help='Questionnaire JSON (default: input/json/ATHN_09_questionnaire.json)'
    )
    p.add_argument(
        '-o', '--output',
        default='outputs/test_outputs/questionnaire_ATHN09.json',
        metavar='PATH',
        help='Output JSON (default: outputs/test_outputs/questionnaire_ATHN09.json)'
    )
    return p.parse_args()


def main():
    args = parse_args()
    data = load_questionnaire(args.questionnaire)
    data = run(data)

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"{GREEN}[+] Completed questionnaire written → {args.output}{RESET}")
    print(f"  Run verdict script:")
    print(f"  python3 utilities/python/verdict_ATHN09.py -i {args.output}")
    print()


if __name__ == "__main__":
    main()
