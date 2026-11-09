#!/usr/bin/env python3
"""
WSTG-ATHN-09 — Weak Password Change or Reset Functionalities
Verdict Script: verdict_ATHN09.py

Reads the completed questionnaire_ATHN09.json and determines three failure modes:

  Mode 1 — Combination fail:
    Specific sets of questions that together constitute a high-risk scenario
    even if individually each seems minor.

  Mode 2 — Cumulative fail:
    If N or more total "Flawed" verdicts are recorded across all questions,
    the asset is considered failed regardless of which specific questions they are.

  Mode 3 — Single question fail:
    Certain questions are individually sufficient to fail the asset — critical
    findings that indicate a severe weakness on their own.

Usage:
  python3 utilities/python/verdict_ATHN09.py
  python3 utilities/python/verdict_ATHN09.py -i outputs/test_outputs/questionnaire_ATHN09.json
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
CYAN   = "\033[96m"
RESET  = "\033[0m"

VERDICT_FLAWED = "Flawed"

# ---------------------------------------------------------------------------
# Failure mode definitions
# ---------------------------------------------------------------------------

# Mode 3 — Single critical questions (any one of these alone = fail)
# Keyed by (category, question_index_0_based): human label
SINGLE_FAIL_QUESTIONS = {
    ("b", 0): "SQL Injection vulnerability in password reset flow",
    ("e", 3): "User's EXISTING password sent in email (plaintext storage confirmed)",
    ("f", 1): "Reset link uses HTTP (plaintext token transmission)",
    ("f", 4): "Reset token has insufficient entropy (brute-forceable)",
}

# Mode 1 — Combination sets that together constitute high risk
# Each entry: (label, frozenset of (category, q_index) tuples)
COMBINATION_FAIL_SETS = [
    (
        "No rate limiting + no MFA on reset (automated takeover possible)",
        frozenset([("a", 0), ("c", 0)])
    ),
    (
        "Reset link reusable + no expiry (persistent takeover window)",
        frozenset([("f", 2), ("f", 3)])
    ),
    (
        "Reset link contains User ID + insufficient token entropy (targeted token substitution)",
        frozenset([("f", 5), ("f", 4)])
    ),
    (
        "SMS reset with no rate limiting + multi-use token (OTP brute-force viable)",
        frozenset([("g", 2), ("g", 4)])
    ),
    (
        "No rate limiting on reset + SQL injection present (unauthenticated DB access)",
        frozenset([("a", 0), ("b", 0)])
    ),
    (
        "New password emailed in plaintext + not forced to change on login (long-lived exposure)",
        frozenset([("e", 0), ("e", 1)])
    ),
]

# Mode 2 — Cumulative threshold
CUMULATIVE_FAIL_THRESHOLD = 3   # 3+ Flawed verdicts = fail


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
# Flatten all answers into {(category, q_index): verdict}
# ---------------------------------------------------------------------------

def flatten_answers(data: dict) -> dict:
    result = {}
    for cat_entry in data.get("questions_categories", []):
        cat = cat_entry["category"]
        for i, q in enumerate(cat_entry.get("questions", [])):
            result[(cat, i)] = q.get("verdict", None)
    return result


def is_flawed(verdict) -> bool:
    return verdict == VERDICT_FLAWED


# ---------------------------------------------------------------------------
# Verdict assessment
# ---------------------------------------------------------------------------

def assess(data: dict) -> None:
    answers = flatten_answers(data)
    meta    = data.get("meta", {})
    total_flawed = sum(1 for v in answers.values() if is_flawed(v))

    print()
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"{BOLD} WSTG-ATHN-09 — Password Reset Verdict{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    ts = meta.get("timestamp", "—")
    print(f"  Assessed: {ts[:19].replace('T', ' ')} UTC")
    print(f"  Flawed findings: {total_flawed} / {meta.get('total_questions_asked', '?')} assessed")
    print()

    failures = []      # list of (mode_label, description) tuples
    fail_modes_hit = set()

    # -----------------------------------------------------------------------
    # Mode 3 — Single critical questions
    # -----------------------------------------------------------------------
    print(f"{BOLD} Mode 3 — Single-Question Critical Failures{RESET}")
    print(f"  {DIM}Any one of these alone constitutes a failing finding.{RESET}")
    print()
    mode3_hits = []
    for key, label in SINGLE_FAIL_QUESTIONS.items():
        verdict = answers.get(key)
        if is_flawed(verdict):
            mode3_hits.append(label)
            failures.append(("Mode 3 — Critical single finding", label))
            fail_modes_hit.add(3)
            print(f"  {RED}✗ FAIL: {label}{RESET}")
        else:
            status = f"{GREEN}pass{RESET}" if verdict == "Not Flawed" else f"{DIM}N/A{RESET}"
            print(f"  {status} — {label}")
    if not mode3_hits:
        print(f"  {GREEN}No critical single-question failures.{RESET}")
    print()

    # -----------------------------------------------------------------------
    # Mode 1 — Combination failures
    # -----------------------------------------------------------------------
    print(f"{BOLD} Mode 1 — Combination Failures{RESET}")
    print(f"  {DIM}Specific pairs/groups that together create high-risk scenarios.{RESET}")
    print()
    mode1_hits = []
    for label, combo_keys in COMBINATION_FAIL_SETS:
        # A combination triggers if ALL its keys are Flawed
        all_flawed = all(is_flawed(answers.get(k)) for k in combo_keys)
        # Any key with N/A / unanswered — treat as unknown
        any_na     = any(answers.get(k) is None for k in combo_keys)
        if all_flawed:
            mode1_hits.append(label)
            failures.append(("Mode 1 — Combination failure", label))
            fail_modes_hit.add(1)
            print(f"  {RED}✗ FAIL: {label}{RESET}")
        elif any_na:
            print(f"  {YELLOW}? UNKNOWN (some sub-questions not assessed): {label}{RESET}")
        else:
            print(f"  {GREEN}pass{RESET} — {label}")
    if not mode1_hits:
        print(f"  {GREEN}No combination failures triggered.{RESET}")
    print()

    # -----------------------------------------------------------------------
    # Mode 2 — Cumulative count
    # -----------------------------------------------------------------------
    print(f"{BOLD} Mode 2 — Cumulative Failure (threshold: {CUMULATIVE_FAIL_THRESHOLD}+){RESET}")
    print(f"  {DIM}If the total Flawed count reaches the threshold, the asset fails.{RESET}")
    print()
    if total_flawed >= CUMULATIVE_FAIL_THRESHOLD:
        label = (
            f"{total_flawed} Flawed findings recorded — "
            f"threshold of {CUMULATIVE_FAIL_THRESHOLD} met"
        )
        failures.append(("Mode 2 — Cumulative failure", label))
        fail_modes_hit.add(2)
        print(f"  {RED}✗ FAIL: {label}{RESET}")
    else:
        print(f"  {GREEN}pass — {total_flawed} Flawed finding(s) "
              f"(threshold {CUMULATIVE_FAIL_THRESHOLD} not reached){RESET}")
    print()

    # -----------------------------------------------------------------------
    # Overall verdict
    # -----------------------------------------------------------------------
    print(f"{BOLD}{'─'*65}{RESET}")
    print(f"{BOLD} Overall Verdict{RESET}")
    print(f"{BOLD}{'─'*65}{RESET}")
    print()

    if failures:
        print(f"  {RED}{BOLD}This asset is FLAWED / VULNERABLE.{RESET}")
        print()
        print(f"  {RED}Failure modes triggered: {', '.join(f'Mode {m}' for m in sorted(fail_modes_hit))}{RESET}")
        print()
        print(f"  {RED}Specific failures:{RESET}")
        for mode_label, desc in failures:
            print(f"    {RED}[{mode_label}]{RESET}")
            print(f"      {desc}")
        print()
        print(f"  {RED}Recommendation: raise findings for each failure mode above.{RESET}")
        print(f"  {RED}Reference: OWASP WSTG-ATHN-09 and NIST SP 800-63B §5.1.2{RESET}")
    else:
        print(f"  {GREEN}{BOLD}No failure modes triggered — asset appears adequate.{RESET}")
        print()
        if total_flawed > 0:
            print(f"  {YELLOW}Note: {total_flawed} Flawed finding(s) recorded but below the "
                  f"cumulative threshold and no critical/combination triggers hit.{RESET}")
            print(f"  {YELLOW}Document as observations and revisit if additional evidence is found.{RESET}")

    print()

    # Flawed question breakdown
    if total_flawed:
        print(f"{BOLD} Flawed Finding Detail{RESET}")
        print()
        for cat_entry in data.get("questions_categories", []):
            cat  = cat_entry["category"]
            name = cat_entry["name"]
            for i, q in enumerate(cat_entry.get("questions", [])):
                if is_flawed(q.get("verdict")):
                    reasoning = q.get("reasoning", "")
                    print(f"  {RED}[{cat.upper()}.{i+1}] {q['question']}{RESET}")
                    if reasoning:
                        print(f"    Evidence: {reasoning}")
        print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description='ATHN-09: Determine verdict from completed questionnaire_ATHN09.json'
    )
    p.add_argument(
        '-i', '--input',
        default='outputs/test_outputs/questionnaire_ATHN09.json',
        metavar='PATH',
        help='Completed questionnaire JSON (default: outputs/test_outputs/questionnaire_ATHN09.json)'
    )
    return p.parse_args()


def main():
    args = parse_args()
    data = load_json(args.input)
    assess(data)


if __name__ == "__main__":
    main()
