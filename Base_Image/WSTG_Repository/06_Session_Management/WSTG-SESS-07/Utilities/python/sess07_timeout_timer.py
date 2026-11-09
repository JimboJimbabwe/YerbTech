#!/usr/bin/env python3
"""
WSTG-SESS-07 — Testing for Session Timeout
sess07_timeout_timer.py

Tests whether session management enforces an appropriate inactivity
timeout. The operator selects the application sensitivity tier, which
sets the expected timeout window. The script then runs an elapsed-time
display while the operator goes idle. On return, the operator confirms
whether their session was still active.

Flow:
  1. Parse login request from Burp XML — extract session cookie name/value
     and login timestamp from the response.
  2. Operator selects sensitivity tier:
       SENSITIVE     → 5–15 min expected timeout  (banking, healthcare, HR)
       NOT-SENSITIVE → 30–60 min expected timeout (general web, e-commerce)
  3. Elapsed-time display starts. Operator goes idle.
  4. Operator returns and presses Enter. Script shows elapsed time.
  5. Operator answers: was the session still active on return?
     → Still active PAST expected threshold → FAIL (timeout not enforced)
     → Session expired within window        → PASS
  6. Results and elapsed time written to report.

Inputs:
  WSTG-SESS-07/inputs/xml/<filename>.xml   (--xml, required)

Outputs:
  WSTG-SESS-07/outputs/test_outputs/sess07_report.md

Usage:
  python3 WSTG-SESS-07/utilities/python/sess07_timeout_timer.py \\
      --xml WSTG-SESS-07/inputs/xml/login_request.xml
"""

import argparse
import base64
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# ANSI
# ---------------------------------------------------------------------------
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
RESET  = "\033[0m"

# ---------------------------------------------------------------------------
# Sensitivity tiers — expected inactivity timeout thresholds
# ---------------------------------------------------------------------------
TIERS = {
    "1": {
        "label":       "SENSITIVE",
        "description": "Banking, healthcare, HR, admin panels, payment flows",
        "min_timeout": 5,    # minutes
        "max_timeout": 15,
        "nist_ref":    "NIST SP 800-63B §7.2.4 recommends ≤15 min for sensitive apps",
    },
    "2": {
        "label":       "NOT-SENSITIVE",
        "description": "General web apps, e-commerce, content platforms",
        "min_timeout": 30,
        "max_timeout": 60,
        "nist_ref":    "OWASP recommends ≤30 min for non-sensitive; 60 min is acceptable upper bound",
    },
}


# ---------------------------------------------------------------------------
# Burp XML decode
# ---------------------------------------------------------------------------

def decode_element(elem) -> str:
    if elem is None:
        return ""
    raw = elem.text or ""
    if elem.get("base64") == "true":
        try:
            return base64.b64decode(raw).decode("utf-8", errors="replace")
        except Exception:
            return raw
    return raw


def parse_login_item(path: str) -> dict:
    """
    Parses a Burp XML file expecting at least one item.
    Extracts from the first item with a Set-Cookie in the response:
      - url
      - session cookie name + value
      - response Date header (used as approximate login timestamp)

    Returns a dict with keys: url, cookie_name, cookie_value, login_time_str, login_dt
    """
    try:
        tree = ET.parse(path)
    except (ET.ParseError, FileNotFoundError) as e:
        print(f"{RED}[!] XML parse error: {e}{RESET}", file=sys.stderr)
        sys.exit(1)

    RE_SET_COOKIE = re.compile(r'^set-cookie\s*:', re.IGNORECASE)
    RE_DATE       = re.compile(r'^date\s*:', re.IGNORECASE)
    RE_PAIR       = re.compile(r'([^=;\s]+)=([^;]*)')

    for item in tree.getroot().findall("item"):
        url  = decode_element(item.find("url"))
        resp = decode_element(item.find("response"))
        head = resp.split("\r\n\r\n", 1)[0] if resp else ""

        cookie_name  = None
        cookie_value = None
        login_time_str = None
        login_dt       = None

        for line in head.splitlines():
            if RE_SET_COOKIE.match(line):
                val_part = line.split(":", 1)[1].strip()
                first    = val_part.split(";")[0].strip()
                m        = RE_PAIR.match(first)
                if m and not cookie_name:
                    cookie_name  = m.group(1).strip()
                    cookie_value = m.group(2).strip()

            elif RE_DATE.match(line):
                login_time_str = line.split(":", 1)[1].strip()
                try:
                    from email.utils import parsedate_to_datetime
                    login_dt = parsedate_to_datetime(login_time_str)
                except Exception:
                    login_dt = None

        if cookie_name:
            return {
                "url":            url,
                "cookie_name":    cookie_name,
                "cookie_value":   cookie_value,
                "login_time_str": login_time_str or "not found in response",
                "login_dt":       login_dt,
            }

    # Fallback — no Set-Cookie found
    return {
        "url":            "",
        "cookie_name":    "not found",
        "cookie_value":   "not found",
        "login_time_str": "not found",
        "login_dt":       None,
    }


# ---------------------------------------------------------------------------
# Tier selector
# ---------------------------------------------------------------------------

def select_tier() -> dict:
    print(f"\n{CYAN}{BOLD}── Application Sensitivity ──────────────────────────────{RESET}\n")
    print(f"  Select the sensitivity tier for this application.\n")
    for key, tier in TIERS.items():
        print(f"  [{key}] {BOLD}{tier['label']}{RESET} — {tier['description']}")
        print(f"       Expected timeout: {tier['min_timeout']}–{tier['max_timeout']} min")
        print(f"       {DIM}{tier['nist_ref']}{RESET}\n")

    while True:
        try:
            choice = input(f"  {BOLD}Select tier [1/2]: {RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{YELLOW}Interrupted.{RESET}")
            sys.exit(0)
        if choice in TIERS:
            return TIERS[choice]
        print(f"  {YELLOW}Enter 1 or 2.{RESET}")


# ---------------------------------------------------------------------------
# Elapsed-time display
# ---------------------------------------------------------------------------

def run_timer() -> float:
    """
    Shows elapsed time updating in-place.
    Returns when the operator presses Enter.
    Returns elapsed seconds.
    """
    print(f"\n{CYAN}{BOLD}── Timer ────────────────────────────────────────────────{RESET}\n")
    print(
        f"  {BOLD}Go idle now.{RESET}\n"
        f"  Stop interacting with the application and let the session sit.\n"
        f"  Return to this terminal and press ENTER when you are ready to check."
    )
    print(
        f"\n  {DIM}The timer below updates every second. "
        f"You do not need to watch it.{RESET}\n"
    )

    start = time.monotonic()

    try:
        # Show a live counter — update in place
        while True:
            elapsed = time.monotonic() - start
            mins    = int(elapsed) // 60
            secs    = int(elapsed) % 60
            display = f"  ⏱  {mins:02d}:{secs:02d} elapsed   (press ENTER to record session state)"
            print(f"\r{CYAN}{display}{RESET}", end="", flush=True)
            # Non-blocking check for Enter using select on stdin
            import select as _select
            r, _, _ = _select.select([sys.stdin], [], [], 1.0)
            if r:
                sys.stdin.readline()   # consume the Enter
                break
    except (KeyboardInterrupt, EOFError):
        pass

    elapsed_total = time.monotonic() - start
    print()
    return elapsed_total


# ---------------------------------------------------------------------------
# Post-timer check
# ---------------------------------------------------------------------------

def check_session_state(elapsed_secs: float, tier: dict, cookie_name: str) -> dict:
    elapsed_mins = elapsed_secs / 60.0

    print(f"\n{CYAN}{BOLD}── Session State Check ──────────────────────────────────{RESET}\n")
    print(
        f"  Elapsed idle time: {BOLD}{elapsed_mins:.1f} minutes{RESET} "
        f"({int(elapsed_secs)}s)\n"
        f"  Expected timeout window: {tier['min_timeout']}–{tier['max_timeout']} min\n"
    )
    print(
        f"  Now check whether the application session is still active.\n"
        f"  Try one of:\n"
        f"    • Navigate to an authenticated page and see if it loads\n"
        f"    • Replay an authenticated request in Burp with the cookie:\n"
        f"      {DIM}Cookie: {cookie_name}=<value from login>{RESET}\n"
        f"    • Refresh a protected page in the browser\n"
    )

    while True:
        try:
            val = input(
                f"  {BOLD}> Is the session still active after {elapsed_mins:.1f} min idle? [y/n]: {RESET}"
            ).strip().lower()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{YELLOW}Interrupted.{RESET}")
            sys.exit(0)
        if val in ("y", "yes"):
            session_active = True; break
        if val in ("n", "no"):
            session_active = False; break
        print(f"  {YELLOW}Enter y or n.{RESET}")

    # Derive verdict
    within_window = elapsed_mins <= tier["max_timeout"]

    if session_active and elapsed_mins > tier["max_timeout"]:
        verdict = "FAIL"
        verdict_detail = (
            f"Session was still active after {elapsed_mins:.1f} min, "
            f"which exceeds the {tier['max_timeout']} min maximum for a "
            f"{tier['label']} application. Timeout is not enforced."
        )
    elif session_active and elapsed_mins <= tier["min_timeout"]:
        verdict = "PASS_EARLY"
        verdict_detail = (
            f"Session still active at {elapsed_mins:.1f} min, "
            f"which is within the expected {tier['min_timeout']}–{tier['max_timeout']} min window. "
            f"Rerun after {tier['max_timeout']} min to confirm the upper bound is enforced."
        )
    elif session_active:
        verdict = "INCONCLUSIVE"
        verdict_detail = (
            f"Session still active at {elapsed_mins:.1f} min (within window). "
            f"Cannot confirm timeout enforcement without testing at or beyond {tier['max_timeout']} min."
        )
    else:
        verdict = "PASS"
        verdict_detail = (
            f"Session expired after {elapsed_mins:.1f} min idle. "
            f"Timeout is enforced within the expected window for a {tier['label']} application."
        )

    return {
        "session_active":   session_active,
        "elapsed_secs":     elapsed_secs,
        "elapsed_mins":     round(elapsed_mins, 2),
        "within_window":    within_window,
        "verdict":          verdict,
        "verdict_detail":   verdict_detail,
    }


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------

def get_notes() -> str:
    print(f"\n{CYAN}{BOLD}── Notes ────────────────────────────────────────────────{RESET}\n")
    print(f"  Optionally record observations (page loaded, error type, etc.).")
    try:
        notes = input(f"  {DIM}Notes (Enter to skip): {RESET}").strip()
    except (KeyboardInterrupt, EOFError):
        notes = ""
    return notes


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

VERDICT_TEXT = {
    "FAIL":         "🔴 **FAIL** — Session timeout NOT enforced",
    "PASS":         "✅ **PASS** — Session timeout enforced",
    "PASS_EARLY":   "✅ **PASS (early check)** — Session active within window; retest at upper bound",
    "INCONCLUSIVE": "⚠️ **INCONCLUSIVE** — Cannot confirm without longer idle period",
}


def build_report(
    xml_path:      str,
    login_info:    dict,
    tier:          dict,
    timer_result:  dict,
    notes:         str,
) -> str:
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines   = []

    lines.append("# WSTG-SESS-07 — Session Timeout Test Report")
    lines.append("")
    lines.append(f"**Generated:** {now_str}  ")
    lines.append(f"**XML source:** `{xml_path}`  ")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Verdict
    verdict = timer_result["verdict"]
    lines.append("## Verdict")
    lines.append("")
    lines.append(VERDICT_TEXT.get(verdict, f"❓ {verdict}"))
    lines.append("")
    lines.append(f"> {timer_result['verdict_detail']}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Test parameters
    lines.append("## Test Parameters")
    lines.append("")
    lines.append("| Parameter | Value |")
    lines.append("|-----------|-------|")
    lines.append(f"| Login endpoint | `{login_info['url'] or '—'}` |")
    lines.append(f"| Session cookie | `{login_info['cookie_name']}` |")
    lines.append(f"| Cookie value (truncated) | `{(login_info['cookie_value'] or '')[:30]}{'...' if len(login_info.get('cookie_value',''))>30 else ''}` |")
    lines.append(f"| Login timestamp (from XML) | `{login_info['login_time_str']}` |")
    lines.append(f"| Sensitivity tier | **{tier['label']}** — {tier['description']} |")
    lines.append(f"| Expected timeout window | {tier['min_timeout']}–{tier['max_timeout']} min |")
    lines.append(f"| NIST/OWASP reference | {tier['nist_ref']} |")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Timer results
    lines.append("## Timer Results")
    lines.append("")
    lines.append("| Measurement | Value |")
    lines.append("|-------------|-------|")
    lines.append(f"| Elapsed idle time | **{timer_result['elapsed_mins']} min** ({int(timer_result['elapsed_secs'])}s) |")
    lines.append(f"| Session active after idle? | {'Yes' if timer_result['session_active'] else 'No'} |")
    lines.append(f"| Within expected window? | {'Yes' if timer_result['within_window'] else 'No — exceeded maximum'} |")
    lines.append("")

    # Remediation if failed
    if verdict == "FAIL":
        lines.append("---")
        lines.append("")
        lines.append("## Remediation")
        lines.append("")
        lines.append(
            f"The application did not terminate the session after "
            f"{timer_result['elapsed_mins']} min of inactivity, exceeding the "
            f"{tier['max_timeout']} min maximum for a {tier['label']} application."
        )
        lines.append("")
        lines.append("**Recommended actions:**")
        lines.append("")
        lines.append(
            f"- Configure server-side session expiry to {tier['min_timeout']}–{tier['max_timeout']} min "
            f"of inactivity for this application tier."
        )
        lines.append("- Ensure timeout is enforced server-side, not only via client cookie expiry.")
        lines.append("- Do not rely on Max-Age/Expires alone — these are client hints, not server enforcement.")
        lines.append("- Verify all session types (web, API, mobile) enforce the same timeout.")
        lines.append("")

    # Notes
    if notes:
        lines.append("---")
        lines.append("")
        lines.append("## Operator Notes")
        lines.append("")
        lines.append(notes)
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## Reference")
    lines.append("")
    lines.append("| Item | Reference |")
    lines.append("|------|-----------|")
    lines.append("| OWASP WSTG-SESS-07 | https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/07-Testing_Session_Timeout |")
    lines.append("| NIST SP 800-63B §7.2 | https://pages.nist.gov/800-63-3/sp800-63b.html |")
    lines.append("| OWASP Session Management Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html |")
    lines.append("")
    lines.append("---")
    lines.append("*Generated by sess07_timeout_timer.py — WSTG-SESS-07*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def banner(title: str):
    width = 65
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD} {title}{RESET}")
    print(f"{BOLD}{'='*width}{RESET}\n")


def main():
    p = argparse.ArgumentParser(
        description="WSTG-SESS-07: Session timeout timer and verdict"
    )
    p.add_argument("--xml",
        required=True,
        metavar="PATH",
        help="Burp XML export containing the login request/response")
    p.add_argument("--out-dir",
        default=os.path.join("WSTG-SESS-07", "outputs", "test_outputs"),
        metavar="DIR")
    args = p.parse_args()

    banner("WSTG-SESS-07 — Session Timeout Test")
    print(
        f"  Tests whether the application enforces an appropriate inactivity\n"
        f"  timeout on authenticated sessions.\n\n"
        f"  {DIM}Reference: OWASP WSTG-SESS-07, NIST SP 800-63B §7.2{RESET}"
    )

    # Step 1 — parse XML
    print(f"\n{CYAN}{BOLD}── Step 1 — Parsing Login XML ───────────────────────────{RESET}\n")
    print(f"  Reading: {args.xml}")
    login_info = parse_login_item(args.xml)

    if login_info["cookie_name"] == "not found":
        print(f"  {YELLOW}⚠  No Set-Cookie found in XML responses.{RESET}")
        print(f"  {YELLOW}   Continuing — you will need to note the cookie manually.{RESET}")
    else:
        print(f"  {GREEN}✓  Cookie: {login_info['cookie_name']}={login_info['cookie_value'][:20]}...{RESET}")
        print(f"  {GREEN}✓  Login timestamp: {login_info['login_time_str']}{RESET}")
        print(f"  {GREEN}✓  Endpoint: {login_info['url']}{RESET}")

    # Step 2 — tier selection
    tier = select_tier()
    print(f"  {GREEN}✓  Tier selected: {tier['label']} "
          f"(expected timeout: {tier['min_timeout']}–{tier['max_timeout']} min){RESET}")

    # Step 3 — timer
    elapsed_secs = run_timer()

    # Step 4 — session state check
    timer_result = check_session_state(elapsed_secs, tier, login_info["cookie_name"])

    # Step 5 — notes
    notes = get_notes()

    # Step 6 — write report
    os.makedirs(args.out_dir, exist_ok=True)
    report_path = os.path.join(args.out_dir, "sess07_report.md")

    report = build_report(args.xml, login_info, tier, timer_result, notes)
    with open(report_path, "w") as f:
        f.write(report)

    # Final output
    verdict = timer_result["verdict"]
    print(f"\n{GREEN}[+] Report written: {report_path}{RESET}")
    if verdict == "FAIL":
        print(f"  {RED}{BOLD}⚠  VERDICT: TIMEOUT NOT ENFORCED{RESET}")
        print(f"  {RED}   Session still active after {timer_result['elapsed_mins']} min "
              f"(max: {tier['max_timeout']} min for {tier['label']}){RESET}")
    elif verdict == "PASS":
        print(f"  {GREEN}✓  VERDICT: PASS — session expired within window{RESET}")
    elif verdict == "PASS_EARLY":
        print(f"  {YELLOW}✓  VERDICT: PASS (early check) — retest at {tier['max_timeout']} min{RESET}")
    else:
        print(f"  {YELLOW}?  VERDICT: INCONCLUSIVE — idle time was {timer_result['elapsed_mins']} min{RESET}")
    print()


if __name__ == "__main__":
    main()
