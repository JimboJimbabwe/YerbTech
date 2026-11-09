#!/usr/bin/env python3
"""
WSTG-ATHN-11 — Testing Multi-Factor Authentication
Verdict Script: verdict_ATHN11.py

ATHN-09 equivalent three-mode verdict structure applied to MFA:

  Mode 3 — Single-question critical failures:
    • MFA absent entirely
    • Only password present (pure SFA)
    • SMS OTP is the ONLY second factor (NIST RESTRICTED)

  Mode 1 — Combination failures:
    • SMS OTP as second factor + no rate limiting indicator
    • Backup codes checked as the only second factor
    • Security question (KBA) counted as a factor

  Mode 2 — Cumulative / count-based:
    • Fewer than 2 confirmed factors = Compromised

Reads: outputs/test_outputs/athn11_results.json
       (written by athn11_mfa.py)

Usage:
  python3 utilities/python/verdict_ATHN11.py
  python3 utilities/python/verdict_ATHN11.py -i outputs/test_outputs/athn11_results.json
"""

import argparse
import json
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


# ---------------------------------------------------------------------------
# Factor IDs of interest
# ---------------------------------------------------------------------------
WEAK_FACTORS     = {"sms_otp", "security_question", "backup_codes"}
NIST_RESTRICTED  = {"sms_otp"}
KBA_FACTORS      = {"security_question"}
BACKUP_FACTORS   = {"backup_codes"}
STRONG_FACTORS   = {"totp", "hardware_key", "push_notification", "biometric", "voice_call"}
PASSWORD_FACTORS = {"password"}


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
# Verdict
# ---------------------------------------------------------------------------

def assess(data: dict) -> None:
    survey       = data.get("mfa_test_results", {}).get("survey", {})
    factors      = survey.get("factors", [])
    mfa_exists   = survey.get("mfa_exists", True)
    stored_verd  = survey.get("findings", "Unknown")
    tech         = survey.get("technology_mfa", "")
    endpoints    = survey.get("endpoints", [])
    xml_file     = survey.get("xml_file", "")
    ts           = survey.get("timestamp", "—")

    factor_ids   = {f["id"] for f in factors}
    factor_count = len(factors)

    # Non-password factors (password is always factor 1 — doesn't count toward MFA)
    second_factors = factor_ids - PASSWORD_FACTORS
    strong_second  = second_factors & STRONG_FACTORS
    weak_second    = second_factors & WEAK_FACTORS

    failures     = []
    fail_modes   = set()

    print()
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"{BOLD} WSTG-ATHN-11 — MFA Verdict{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"  Assessed : {ts[:19].replace('T', ' ')} UTC")
    print(f"  Technology: {tech or '(not recorded)'}")
    if xml_file:
        print(f"  XML file : {xml_file}")
    if endpoints:
        print(f"  Auth endpoints: {endpoints}")
    print()

    # -----------------------------------------------------------------------
    # Factor summary table
    # -----------------------------------------------------------------------
    print(f"{BOLD} Confirmed Factors{RESET}")
    print()
    if not factors:
        print(f"  {RED}None confirmed.{RESET}")
    else:
        for f in factors:
            fid   = f.get("id", "")
            fname = f.get("name", fid)
            ftech = f.get("technology", "")
            fcat  = f.get("category", "")
            tech_note = f"  [{ftech}]" if ftech else ""
            weak_note = f"  {YELLOW}(weak — see below){RESET}" if fid in WEAK_FACTORS else ""
            print(f"  • {fname}{tech_note}  {DIM}{fcat}{RESET}{weak_note}")
    print()

    # -----------------------------------------------------------------------
    # Mode 3 — Single critical failures
    # -----------------------------------------------------------------------
    print(f"{BOLD} Mode 3 — Single Critical Failures{RESET}")
    print(f"  {DIM}Any one of these alone constitutes a failing finding.{RESET}")
    print()

    # 3a: MFA absent
    if not mfa_exists:
        label = "MFA is entirely absent — authentication is single-factor"
        failures.append(("Mode 3 — Critical", label))
        fail_modes.add(3)
        print(f"  {RED}✗ FAIL: {label}{RESET}")
    else:
        print(f"  {GREEN}pass{RESET} — MFA is present")

    # 3b: Password only (no second factor at all)
    if mfa_exists and len(second_factors) == 0:
        label = "MFA claimed present but only password (Something You Know) confirmed — no second factor"
        failures.append(("Mode 3 — Critical", label))
        fail_modes.add(3)
        print(f"  {RED}✗ FAIL: {label}{RESET}")
    else:
        if mfa_exists:
            print(f"  {GREEN}pass{RESET} — at least one second factor confirmed")

    # 3c: SMS OTP is the SOLE second factor
    if second_factors and second_factors <= NIST_RESTRICTED:
        label = (
            "SMS OTP is the only second factor — NIST SP 800-63B RESTRICTED "
            "(vulnerable to SIM-swapping and SS7 interception)"
        )
        failures.append(("Mode 3 — Critical", label))
        fail_modes.add(3)
        print(f"  {RED}✗ FAIL: {label}{RESET}")
    elif NIST_RESTRICTED & second_factors:
        print(f"  {YELLOW}⚠ SMS OTP present alongside stronger factors — flag as observation{RESET}")
    else:
        if second_factors:
            print(f"  {GREEN}pass{RESET} — no NIST-restricted sole-factor scenario")

    print()

    # -----------------------------------------------------------------------
    # Mode 1 — Combination failures
    # -----------------------------------------------------------------------
    print(f"{BOLD} Mode 1 — Combination Failures{RESET}")
    print(f"  {DIM}Specific factor combinations that together create high-risk scenarios.{RESET}")
    print()

    # 1a: SMS + no strong factor (SMS as only MFA path, just not the only checked item)
    if NIST_RESTRICTED & second_factors and not strong_second:
        label = (
            "SMS OTP present with no strong second factor (TOTP/hardware key/push/biometric) — "
            "entire MFA posture rests on a NIST RESTRICTED channel"
        )
        failures.append(("Mode 1 — Combination", label))
        fail_modes.add(1)
        print(f"  {RED}✗ FAIL: {label}{RESET}")
    else:
        print(f"  {GREEN}pass{RESET} — SMS-only MFA posture check")

    # 1b: Backup codes as only second factor
    if second_factors and second_factors <= BACKUP_FACTORS:
        label = (
            "Backup/recovery codes are the only confirmed second factor — "
            "these are single-use emergency codes, not a real-time MFA mechanism"
        )
        failures.append(("Mode 1 — Combination", label))
        fail_modes.add(1)
        print(f"  {RED}✗ FAIL: {label}{RESET}")
    else:
        print(f"  {GREEN}pass{RESET} — backup codes not sole factor")

    # 1c: Security question (KBA) counted as a factor
    if KBA_FACTORS & factor_ids:
        label = (
            "Security questions (KBA) counted as a factor — KBA is not considered "
            "a valid authenticator under NIST SP 800-63B (see also ATHN-08)"
        )
        failures.append(("Mode 1 — Combination", label))
        fail_modes.add(1)
        print(f"  {RED}✗ FAIL: {label}{RESET}")
    else:
        print(f"  {GREEN}pass{RESET} — no KBA counted as MFA factor")

    # 1d: Same category both factors (SYK + SYK — no real second factor)
    categories = [f.get("category", "") for f in factors]
    cat_counts  = {}
    for c in categories:
        cat_counts[c] = cat_counts.get(c, 0) + 1
    if all(c == categories[0] for c in categories) and len(categories) >= 2:
        label = (
            f"Both confirmed factors are in the same category "
            f"('{categories[0]}') — true MFA requires factors from different categories"
        )
        failures.append(("Mode 1 — Combination", label))
        fail_modes.add(1)
        print(f"  {RED}✗ FAIL: {label}{RESET}")
    else:
        print(f"  {GREEN}pass{RESET} — factors span multiple categories")

    print()

    # -----------------------------------------------------------------------
    # Mode 2 — Cumulative (factor count)
    # -----------------------------------------------------------------------
    THRESHOLD = 2
    print(f"{BOLD} Mode 2 — Cumulative (factor count threshold: {THRESHOLD}){RESET}")
    print(f"  {DIM}Fewer than {THRESHOLD} confirmed second factors = Compromised.{RESET}")
    print()

    real_second = second_factors - KBA_FACTORS - BACKUP_FACTORS
    if len(real_second) < 1:
        label = (
            f"Fewer than 1 strong second factor confirmed "
            f"(strong factors: {sorted(real_second) or 'none'})"
        )
        failures.append(("Mode 2 — Cumulative", label))
        fail_modes.add(2)
        print(f"  {RED}✗ FAIL: {label}{RESET}")
    else:
        print(f"  {GREEN}pass{RESET} — {len(real_second)} strong second factor(s) confirmed: "
              f"{sorted(real_second)}")

    print()

    # -----------------------------------------------------------------------
    # Overall verdict
    # -----------------------------------------------------------------------
    print(f"{BOLD}{'─'*65}{RESET}")
    print(f"{BOLD} Overall Verdict{RESET}")
    print(f"{BOLD}{'─'*65}{RESET}")
    print()

    if failures:
        print(f"  {RED}{BOLD}This asset is COMPROMISED / FLAWED.{RESET}")
        print()
        print(f"  {RED}Failure modes: {', '.join(f'Mode {m}' for m in sorted(fail_modes))}{RESET}")
        print()
        print(f"  {RED}Specific failures:{RESET}")
        for mode_label, desc in failures:
            print(f"    {RED}[{mode_label}]{RESET}")
            print(f"      {desc}")
        print()
        print(f"  {RED}References:{RESET}")
        print(f"    OWASP WSTG-ATHN-11: https://owasp.org/www-project-web-security-testing-guide/"
              f"latest/4-Web_Application_Security_Testing/04-Authentication_Testing/"
              f"11-Testing_Multi-Factor_Authentication")
        print(f"    NIST SP 800-63B §5: https://pages.nist.gov/800-63-3/sp800-63b.html")
    else:
        print(f"  {GREEN}{BOLD}No failure modes triggered — MFA implementation appears adequate.{RESET}")
        print()
        print(f"  {GREEN}Confirmed strong second factors: {sorted(real_second)}{RESET}")
        print(f"  {DIM}Document as positive finding. Continue testing for bypass"
              f" (ATHN-11 sub-tests: OTP replay, fatigue attack, response manipulation).{RESET}")

    # Stored verdict comparison
    print()
    print(f"  Stored verdict (from questionnaire): {stored_verd}")
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description='ATHN-11: Three-mode MFA verdict from athn11_results.json'
    )
    p.add_argument(
        '-i', '--input',
        default='outputs/test_outputs/athn11_results.json',
        metavar='PATH',
        help='Path to athn11_results.json (default: outputs/test_outputs/athn11_results.json)'
    )
    return p.parse_args()


def main():
    args = parse_args()
    data = load_json(args.input)
    assess(data)


if __name__ == "__main__":
    main()
