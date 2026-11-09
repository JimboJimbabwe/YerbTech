#!/usr/bin/env python3
"""
WSTG-SESS-09 — Testing for Session Hijacking
Script: sess_09_checklist.py

Interactive checklist that walks the operator through the WSTG-SESS-09
session hijacking test procedure step by step. Each step must be confirmed
before the next is revealed. The operator records observations at key
decision points, and the script renders a final verdict and writes a
markdown report.

Usage:
  python3 WSTG-SESS-09/utilities/python/sess_09_checklist.py \\
      [--target https://app.example.com] \\
      [--out WSTG-SESS-09/outputs/test_outputs/sess09_report.md]
"""

import argparse
import os
import sys
from datetime import datetime


# ---------------------------------------------------------------------------
# ANSI
# ---------------------------------------------------------------------------
BOLD    = "\033[1m"
DIM     = "\033[2m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
RESET   = "\033[0m"

WIDTH = 65


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def hr(char="─"):
    print(f"  {char * (WIDTH - 2)}")


def header(title: str):
    print(f"\n{BOLD}{'=' * WIDTH}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'=' * WIDTH}{RESET}\n")


def step_header(n: int, total: int, title: str):
    print(f"\n  {CYAN}{BOLD}[ Step {n}/{total} ]{RESET}  {BOLD}{title}{RESET}")
    hr()


def info(text: str):
    for line in text.strip().splitlines():
        print(f"  {line}")


def note(text: str):
    for line in text.strip().splitlines():
        print(f"  {YELLOW}»{RESET} {line}")


def prompt_confirm(prompt: str = "Press ENTER when done") -> None:
    try:
        input(f"\n  {DIM}{prompt} ...{RESET} ")
    except (KeyboardInterrupt, EOFError):
        print(f"\n\n  {YELLOW}[!] Interrupted — exiting.{RESET}\n")
        sys.exit(0)


def prompt_yn(question: str) -> bool:
    while True:
        try:
            ans = input(f"\n  {BOLD}{question}{RESET}  {DIM}[y/n]{RESET} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print(f"\n\n  {YELLOW}[!] Interrupted — exiting.{RESET}\n")
            sys.exit(0)
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print(f"  {YELLOW}Please enter y or n.{RESET}")


def prompt_text(question: str, optional: bool = False) -> str:
    suffix = f"  {DIM}(optional, press ENTER to skip){RESET}" if optional else ""
    try:
        val = input(f"\n  {BOLD}{question}{RESET}{suffix}\n  > ").strip()
    except (KeyboardInterrupt, EOFError):
        print(f"\n\n  {YELLOW}[!] Interrupted — exiting.{RESET}\n")
        sys.exit(0)
    return val


# ---------------------------------------------------------------------------
# Checklist state
# ---------------------------------------------------------------------------

class State:
    def __init__(self, target: str):
        self.target          = target
        self.started_at      = datetime.now()
        self.secure_function = ""
        self.hsts_adoption   = ""   # none / partial / full
        self.cookies_noted   = []   # list of cookie names operator saved
        self.step4_success   = False
        self.step8_success   = False
        self.notes           = {}   # step_n -> operator note
        self.verdict         = ""


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------

TOTAL_STEPS = 10


def step_1(state: State):
    step_header(1, TOTAL_STEPS, "Login as victim & identify secure function")
    info("""
Login to the application as the victim user.
Navigate to any page that offers a secure function
requiring authentication (e.g. account settings, a
transfer page, admin action, profile update).
    """)
    note("Note the exact URL of the secure function — you will return to it multiple times.")
    state.secure_function = prompt_text("Enter the URL / description of the secure function")
    state.notes[1] = state.secure_function
    prompt_confirm("Press ENTER once you are logged in and have identified the function")


def step_2(state: State):
    step_header(2, TOTAL_STEPS, "Determine HSTS adoption")
    info("""
Check whether the application uses HTTP Strict Transport Security (HSTS).
This determines which cookies must be deleted in step 3.

  Check the response headers of any page:
    curl -sk -I https://TARGET | grep -i strict

  Three possible states:
    none     — No HSTS header present at all.
    partial  — HSTS present but subdomains not covered, or
               max-age is very short (< 30 days).
    full     — HSTS header present with includeSubDomains
               and a long max-age (≥ 180 days).
    """)
    while True:
        ans = prompt_text("HSTS adoption level? [none / partial / full]").lower()
        if ans in ("none", "partial", "full"):
            state.hsts_adoption = ans
            break
        print(f"  {YELLOW}Enter one of: none, partial, full{RESET}")
    state.notes[2] = f"HSTS adoption: {state.hsts_adoption}"


def step_3(state: State):
    step_header(3, TOTAL_STEPS, "Delete cookies from the cookie jar (victim session)")

    if state.hsts_adoption == "none":
        rule = "Delete ALL cookies that have the Secure attribute set."
    elif state.hsts_adoption == "partial":
        rule = ("Delete ALL cookies that have the Secure attribute set,\n"
                "OR that do not have the Domain attribute set.")
    else:
        rule = ("HSTS is fully adopted.\n"
                "No cookies need to be deleted for HSTS-based downgrade.\n"
                "Proceed without deleting any cookies.")

    info(f"\n  Rule for this target ({state.hsts_adoption} HSTS):\n")
    note(rule)
    info("""
In Burp Suite:
  Proxy → HTTP History → right-click a request → "Cookie jar"
  Or use the browser DevTools → Application → Cookies.

In curl / script:
  Maintain a cookie jar file; manually remove the matching lines.
    """)

    cookies_raw = prompt_text(
        "List the cookie names you deleted (comma-separated, or ENTER if none deleted)",
        optional=True
    )
    state.cookies_noted = [c.strip() for c in cookies_raw.split(",") if c.strip()]
    prompt_confirm("Press ENTER once you have saved a snapshot of the remaining cookie jar")
    state.notes[3] = f"Deleted cookies: {', '.join(state.cookies_noted) or 'none'}"


def step_4(state: State):
    step_header(4, TOTAL_STEPS, "Trigger the secure function (victim, reduced cookie jar)")
    info(f"""
With the reduced cookie jar (Secure-flagged cookies removed),
trigger the secure function identified in step 1:

  {state.secure_function}

Observe the HTTP response carefully.
    """)
    note("If the function completes successfully → the application is accepting the session\n"
         "  without Secure-flagged cookies, making it vulnerable.")
    state.step4_success = prompt_yn("Did the secure function complete successfully?")
    obs = prompt_text("Observation / notes (optional)", optional=True)
    state.notes[4] = f"Step 4 success: {state.step4_success}. {obs}".strip()


def step_5(state: State):
    step_header(5, TOTAL_STEPS, "Evaluate step-4 result")
    if state.step4_success:
        print(f"\n  {RED}{BOLD}[!] Attack vector confirmed at step 4.{RESET}")
        info("""
The application accepted the request without Secure-flagged cookies.
This means an attacker who can intercept traffic over HTTP can strip
those cookies and still authenticate as the victim.

Continue with steps 6–10 to confirm full cross-account hijacking.
        """)
    else:
        print(f"\n  {GREEN}[✓] Secure function failed without Secure cookies.{RESET}")
        info("""
The application correctly rejected the request.
This is the expected behaviour — the session is bound to the
Secure-flagged cookies that were removed.
Continue anyway to test the attacker-side replay in steps 6–10.
        """)
    prompt_confirm()


def step_6(state: State):
    step_header(6, TOTAL_STEPS, "Clear cookie jar — login as attacker")
    info("""
Completely clear the cookie jar (all cookies for this origin).
Log in with a separate attacker-controlled account.
Navigate to the same secure-function page identified in step 1.
    """)
    note("Use a different browser profile, private window, or a fresh Burp session\n"
         "to keep victim and attacker sessions cleanly separated.")
    prompt_confirm("Press ENTER once you are logged in as the attacker and on the target page")
    state.notes[6] = "Attacker logged in and on target page."


def step_7(state: State):
    step_header(7, TOTAL_STEPS, "Inject victim cookies into attacker session")
    if state.cookies_noted:
        info(f"Cookies saved from the victim session (step 3):\n")
        for c in state.cookies_noted:
            print(f"    {CYAN}•  {c}{RESET}")
    else:
        info("No specific cookies were recorded in step 3.\n"
             "Inject all cookies from the victim's snapshot.")

    info("""
Write these cookies into the attacker's cookie jar one by one.

In Burp Repeater:
  Add Cookie: <name>=<value> headers to the next request manually.

In the browser DevTools:
  Application → Cookies → add each name/value pair.

In curl:
  Add -b "name1=val1; name2=val2" to the request.
    """)
    note("Do NOT log out the attacker account — just overwrite the cookie values.")
    prompt_confirm("Press ENTER once all victim cookies are in the attacker's jar")
    state.notes[7] = "Victim cookies injected into attacker session."


def step_8(state: State):
    step_header(8, TOTAL_STEPS, "Trigger secure function again (attacker + victim cookies)")
    info(f"""
Trigger the secure function once more:

  {state.secure_function}

This time the request carries the attacker's session cookies
overlaid with the victim's Secure-stripped cookies.
Observe whether the action executes under the victim's account.
    """)
    state.step8_success = prompt_yn("Did the secure function complete successfully?")
    obs = prompt_text("Observation / notes (optional)", optional=True)
    state.notes[8] = f"Step 8 success: {state.step8_success}. {obs}".strip()


def step_9(state: State):
    step_header(9, TOTAL_STEPS, "Clear cookie jar — log back in as victim")
    info("""
Clear the cookie jar completely.
Log back in as the victim user.
Navigate to the same secure-function page.
    """)
    prompt_confirm("Press ENTER once you are logged in as the victim again")
    state.notes[9] = "Victim re-logged in to verify impact."


def step_10(state: State):
    step_header(10, TOTAL_STEPS, "Verify impact in victim account")
    info(f"""
Observe the victim's account state.

  Was the action triggered in step 8 reflected here?
  (e.g. changed email, completed transfer, modified data)

  Secure function: {state.secure_function}
    """)
    impact_visible = prompt_yn("Is the step-8 action visible / reflected in the victim's account?")
    obs = prompt_text("Describe the impact observed (optional)", optional=True)
    state.notes[10] = f"Impact visible: {impact_visible}. {obs}".strip()

    # ── Verdict ──────────────────────────────────────────────────────────────
    print()
    hr("═")
    if state.step8_success and impact_visible:
        state.verdict = "VULNERABLE"
        print(f"\n  {RED}{BOLD}  VERDICT: VULNERABLE — Session Hijacking Confirmed{RESET}")
        info("""
  The attacker successfully triggered an action in the victim's account
  by replaying session cookies that were not protected by the Secure flag.
  This constitutes a session hijacking vulnerability (WSTG-SESS-09).

  CWE-384 — Session Fixation
  CWE-614 — Sensitive Cookie Without 'Secure' Attribute
        """)
    elif state.step4_success and not state.step8_success:
        state.verdict = "PARTIAL"
        print(f"\n  {YELLOW}{BOLD}  VERDICT: PARTIAL FINDING{RESET}")
        info("""
  The application accepted requests without Secure cookies (step 4),
  but the cross-account replay (step 8) did not succeed or was not
  confirmed. Document the step-4 behaviour as a cookie configuration
  weakness and investigate further.
        """)
    else:
        state.verdict = "NOT VULNERABLE"
        print(f"\n  {GREEN}{BOLD}  VERDICT: NOT VULNERABLE{RESET}")
        info("""
  The site appears secure against this session hijacking vector.
  The secure function was not successfully triggered across accounts,
  and no impact was observed in the victim's account.
        """)
    hr("═")


# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------

def write_report(state: State, out_path: str):
    now_str  = state.started_at.strftime("%Y-%m-%d %H:%M:%S")
    fin_str  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sev_map  = {"VULNERABLE": "HIGH", "PARTIAL": "MEDIUM", "NOT VULNERABLE": "INFORMATIONAL"}
    severity = sev_map.get(state.verdict, "UNKNOWN")

    lines = []
    lines.append("# WSTG-SESS-09 — Session Hijacking Test Report")
    lines.append("")
    lines.append(f"**Started:**  {now_str}  ")
    lines.append(f"**Finished:** {fin_str}  ")
    if state.target:
        lines.append(f"**Target:**   `{state.target}`  ")
    lines.append(f"**Secure function:** `{state.secure_function}`  ")
    lines.append(f"**HSTS adoption:** {state.hsts_adoption}  ")
    lines.append(f"**Verdict:** **{state.verdict}**  ")
    lines.append(f"**Severity:** {severity}  ")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Step-by-Step Observations")
    lines.append("")

    step_titles = {
        1:  "Login as victim & identify secure function",
        2:  "Determine HSTS adoption",
        3:  "Delete cookies from the cookie jar",
        4:  "Trigger secure function (victim, reduced cookie jar)",
        5:  "Evaluate step-4 result",
        6:  "Clear cookie jar — login as attacker",
        7:  "Inject victim cookies into attacker session",
        8:  "Trigger secure function (attacker + victim cookies)",
        9:  "Clear cookie jar — log back in as victim",
        10: "Verify impact in victim account",
    }

    for n in range(1, TOTAL_STEPS + 1):
        title = step_titles.get(n, f"Step {n}")
        obs   = state.notes.get(n, "—")
        lines.append(f"### Step {n} — {title}")
        lines.append("")
        lines.append(f"{obs}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## Verdict Detail")
    lines.append("")

    if state.verdict == "VULNERABLE":
        lines.append("Session hijacking was confirmed. An attacker who can observe or")
        lines.append("intercept HTTP traffic (e.g. on a shared network, via a mixed-content")
        lines.append("leak, or through a MITM) can capture the victim's non-Secure cookies")
        lines.append("and replay them to perform actions in the victim's account.")
        lines.append("")
        lines.append("**References:**")
        lines.append("- CWE-384: Session Fixation")
        lines.append("- CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute")
        lines.append("- OWASP WSTG-SESS-09")
        lines.append("")
        lines.append("**Remediation:**")
        lines.append("- Set the `Secure` attribute on all session cookies.")
        lines.append("- Implement full HSTS with `includeSubDomains` and a long `max-age`.")
        lines.append("- Bind sessions to TLS channel fingerprints where possible.")
    elif state.verdict == "PARTIAL":
        lines.append("The application accepted requests without Secure-flagged cookies (step 4),")
        lines.append("indicating that some session tokens do not have the Secure attribute.")
        lines.append("Full cross-account hijacking was not confirmed in this run.")
        lines.append("")
        lines.append("**Remediation:**")
        lines.append("- Audit all session and auth cookies for the `Secure` attribute.")
        lines.append("- Repeat steps 6–10 with a more targeted cookie injection.")
    else:
        lines.append("No session hijacking vector was found via this test procedure.")
        lines.append("Consider also testing for session fixation (WSTG-SESS-03) and")
        lines.append("cookie attribute weaknesses (WSTG-SESS-02).")

    lines.append("")
    lines.append("---")
    lines.append("*Generated by sess_09_checklist.py — WSTG-SESS-09*")

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"\n  {GREEN}[+] Report → {out_path}{RESET}\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-SESS-09 interactive session hijacking checklist"
    )
    p.add_argument("--target", default="",
        metavar="URL",
        help="Base target URL (for report only)")
    p.add_argument("--out",
        default=os.path.join("WSTG-SESS-09", "outputs", "test_outputs", "sess09_report.md"),
        metavar="PATH",
        help="Output markdown report path")
    args = p.parse_args()

    header("WSTG-SESS-09 — Session Hijacking Checklist")

    if args.target:
        print(f"  Target : {args.target}\n")

    info("""
This checklist walks through the OWASP WSTG-SESS-09 test procedure
for session hijacking via cookie theft over non-TLS channels.

You will need:
  • Two browser sessions (or Burp Suite + manual cookie jar control)
  • A victim account and an attacker account on the target
  • Access to the cookie jar (DevTools or Burp Suite)

Work through each step and answer the prompts.
The script will record your observations and generate a report.
    """)

    prompt_confirm("Press ENTER to begin")

    state = State(target=args.target)

    step_1(state)
    step_2(state)
    step_3(state)
    step_4(state)
    step_5(state)
    step_6(state)
    step_7(state)
    step_8(state)
    step_9(state)
    step_10(state)

    write_report(state, args.out)


if __name__ == "__main__":
    main()
