#!/usr/bin/env python3
"""
WSTG-SESS-03 — Testing for Session Fixation
sess03_fixation_checklist.py

Interactive operator checklist for session fixation testing.
Walks the tester through each manual step, records answers,
and flags a session fixation vulnerability if the pre-auth
cookie is reused after login.

Steps:
  1. Identify the login endpoint
  2. Confirm browser cache / cookies cleared
  3. Visit the login endpoint (unauthenticated)
  4. Record the pre-authentication cookie value
  5. Authenticate as a valid user
  6. Check whether the server issued a NEW cookie post-login
     → Same cookie reused = session fixation vulnerability (HIGH)
     → New cookie issued   = pass

Outputs:
  WSTG-SESS-03/outputs/test_outputs/sess03_report.md

Usage:
  python3 WSTG-SESS-03/utilities/python/sess03_fixation_checklist.py
  python3 WSTG-SESS-03/utilities/python/sess03_fixation_checklist.py \\
      --out-dir WSTG-SESS-03/outputs/test_outputs
"""

import argparse
import os
import sys
from datetime import datetime


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
# Helpers
# ---------------------------------------------------------------------------

def banner(title: str):
    width = 65
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD} {title}{RESET}")
    print(f"{BOLD}{'='*width}{RESET}\n")


def section(title: str):
    print(f"\n{CYAN}{BOLD}── {title} {'─'*(55-len(title))}{RESET}\n")


def prompt_text(question: str, hint: str = "") -> str:
    if hint:
        print(f"  {DIM}{hint}{RESET}")
    try:
        val = input(f"  {BOLD}> {question}{RESET}  ").strip()
    except (KeyboardInterrupt, EOFError):
        print(f"\n{YELLOW}[!] Interrupted — exiting.{RESET}")
        sys.exit(0)
    return val


def prompt_yn(question: str, hint: str = "") -> bool:
    if hint:
        print(f"  {DIM}{hint}{RESET}")
    while True:
        try:
            val = input(f"  {BOLD}> {question} [y/n]: {RESET}").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{YELLOW}[!] Interrupted — exiting.{RESET}")
            sys.exit(0)
        if val in ("y", "yes"):
            return True
        if val in ("n", "no"):
            return False
        print(f"  {YELLOW}Please enter y or n.{RESET}")


def prompt_enter(instruction: str):
    print(f"\n  {YELLOW}{BOLD}ACTION REQUIRED:{RESET}  {instruction}")
    try:
        input(f"  {DIM}Press ENTER when done...{RESET}")
    except (KeyboardInterrupt, EOFError):
        print(f"\n{YELLOW}[!] Interrupted — exiting.{RESET}")
        sys.exit(0)


def ok(msg: str):
    print(f"  {GREEN}✓  {msg}{RESET}")


def warn(msg: str):
    print(f"  {YELLOW}⚠  {msg}{RESET}")


def alert(msg: str):
    print(f"  {RED}{BOLD}⚠  {msg}{RESET}")


# ---------------------------------------------------------------------------
# Checklist steps
# ---------------------------------------------------------------------------

def run_checklist() -> dict:
    """
    Walks through SESS-03 checklist steps.
    Returns a results dict with all recorded values and verdicts.
    """
    results = {
        "timestamp":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "login_endpoint":  "",
        "cache_cleared":   None,
        "pre_auth_cookie_name":  "",
        "pre_auth_cookie_value": "",
        "authenticated":   None,
        "new_cookie_issued": None,
        "post_auth_cookie_name":  "",
        "post_auth_cookie_value": "",
        "verdict":         "",
        "notes":           "",
        "steps":           [],
    }

    banner("WSTG-SESS-03 — Session Fixation Checklist")
    print(
        f"  This checklist walks through manual session fixation testing.\n"
        f"  A session fixation vulnerability exists when the server reuses\n"
        f"  the same session token before and after user authentication.\n\n"
        f"  {DIM}Reference: OWASP WSTG-SESS-03{RESET}"
    )

    # ── Step 1: Login endpoint ───────────────────────────────────────────────
    section("Step 1 — Identify Login Endpoint")
    print(
        f"  Identify the application's primary authentication endpoint.\n"
        f"  This is where credentials are submitted (POST /login, /auth, etc.)."
    )
    endpoint = prompt_text(
        "What is the login endpoint URL?",
        hint="e.g. https://target.com/login  or  /api/v1/auth/login"
    )
    results["login_endpoint"] = endpoint
    results["steps"].append({
        "step": 1,
        "description": "Login endpoint identified",
        "value": endpoint,
        "status": "recorded" if endpoint else "skipped",
    })
    if endpoint:
        ok(f"Login endpoint: {endpoint}")
    else:
        warn("No endpoint recorded — consider noting it.")

    # ── Step 2: Clear cache ──────────────────────────────────────────────────
    section("Step 2 — Clear Browser State")
    print(
        f"  Before visiting the login page, clear all cookies and cache\n"
        f"  for the target origin. This ensures you receive a fresh\n"
        f"  pre-authentication session token rather than a residual one.\n\n"
        f"  Browser DevTools → Application → Cookies → Clear all\n"
        f"  OR open a new private/incognito window."
    )
    cleared = prompt_yn(
        "Have you cleared cookies and cache (or used a fresh private window)?",
        hint="This step is critical — a stale cookie will produce a false result."
    )
    results["cache_cleared"] = cleared
    results["steps"].append({
        "step": 2,
        "description": "Cache and cookies cleared",
        "value": cleared,
        "status": "pass" if cleared else "warn",
    })
    if cleared:
        ok("Browser state cleared.")
    else:
        warn("Cache not confirmed cleared — result may be unreliable.")

    # ── Step 3: Visit login endpoint (unauthenticated) ───────────────────────
    section("Step 3 — Visit Login Endpoint (Do NOT Log In Yet)")
    print(
        f"  Navigate to the login endpoint in your browser or send a GET\n"
        f"  request to it via Burp. Do NOT submit credentials yet.\n"
        f"  The server may issue a session cookie at this point."
    )
    prompt_enter(
        f"Visit {endpoint or 'the login endpoint'} — do NOT log in yet."
    )
    results["steps"].append({
        "step": 3,
        "description": "Visited login endpoint unauthenticated",
        "value": "operator confirmed",
        "status": "done",
    })
    ok("Login endpoint visited (unauthenticated).")

    # ── Step 4: Record pre-auth cookie ───────────────────────────────────────
    section("Step 4 — Record Pre-Authentication Cookie")
    print(
        f"  Check the Set-Cookie header in the response, or inspect\n"
        f"  DevTools → Application → Cookies.\n"
        f"  Record the session cookie name and value."
    )
    pre_name = prompt_text(
        "Cookie name?",
        hint="e.g. PHPSESSID, sessionid, JSESSIONID, connect.sid"
    )
    pre_value = prompt_text(
        "Cookie value (pre-auth)?",
        hint="Paste the full value — it will be compared post-login."
    )
    results["pre_auth_cookie_name"]  = pre_name
    results["pre_auth_cookie_value"] = pre_value
    results["steps"].append({
        "step": 4,
        "description": "Pre-authentication cookie recorded",
        "value": f"{pre_name}={pre_value}",
        "status": "recorded" if pre_value else "warn",
    })
    if pre_value:
        ok(f"Pre-auth cookie recorded: {pre_name}={pre_value[:20]}{'...' if len(pre_value)>20 else ''}")
    else:
        warn("No pre-auth cookie value recorded — result will be inconclusive.")

    # ── Step 5: Authenticate ─────────────────────────────────────────────────
    section("Step 5 — Log In to the Application")
    print(
        f"  Submit valid credentials on the login page.\n"
        f"  Complete any MFA challenge if applicable.\n"
        f"  Do NOT navigate away from the post-login page yet."
    )
    prompt_enter("Log in with valid credentials now.")
    authenticated = prompt_yn("Did authentication succeed?")
    results["authenticated"] = authenticated
    results["steps"].append({
        "step": 5,
        "description": "Authentication attempted",
        "value": authenticated,
        "status": "pass" if authenticated else "blocked",
    })
    if not authenticated:
        warn("Authentication failed — cannot proceed with fixation check.")
        warn("Verify credentials and rerun, or note the issue and continue manually.")

    # ── Step 6: Check post-auth cookie ───────────────────────────────────────
    section("Step 6 — Inspect Post-Authentication Cookie")
    print(
        f"  After login, check the Set-Cookie header in the login response\n"
        f"  OR DevTools → Application → Cookies.\n"
        f"  Record the session cookie value NOW (post-login).\n\n"
        f"  KEY QUESTION: did the server issue a brand new session ID,\n"
        f"  or is the same pre-auth cookie value still in use?"
    )
    post_name  = prompt_text(
        "Cookie name (post-auth)?",
        hint=f"Usually the same name as before: {pre_name or 'e.g. PHPSESSID'}"
    )
    post_value = prompt_text(
        "Cookie value (post-auth)?",
        hint="Paste the full value."
    )
    results["post_auth_cookie_name"]  = post_name  or pre_name
    results["post_auth_cookie_value"] = post_value

    # Core verdict
    if not pre_value or not post_value:
        verdict      = "INCONCLUSIVE"
        new_issued   = None
    elif pre_value.strip() == post_value.strip():
        verdict    = "VULNERABLE"
        new_issued = False
    else:
        verdict    = "PASS"
        new_issued = True

    results["new_cookie_issued"] = new_issued
    results["verdict"]           = verdict

    results["steps"].append({
        "step": 6,
        "description": "Post-authentication cookie compared",
        "value": f"{post_name}={post_value}",
        "status": verdict.lower(),
    })

    # Print verdict
    print()
    if verdict == "VULNERABLE":
        alert("SESSION FIXATION VULNERABILITY DETECTED")
        alert(f"Pre-auth cookie:  {pre_name}={pre_value}")
        alert(f"Post-auth cookie: {post_name}={post_value}")
        alert("The server DID NOT rotate the session token on login.")
        alert(
            "An attacker who plants a known session token (via URL parameter,\n"
            "     meta-refresh, or XSS) can hijack the victim's authenticated session."
        )
    elif verdict == "PASS":
        ok("New session token issued after authentication.")
        ok(f"Pre-auth:  {pre_name}={pre_value[:20]}{'...' if len(pre_value)>20 else ''}")
        ok(f"Post-auth: {post_name}={post_value[:20]}{'...' if len(post_value)>20 else ''}")
        ok("Server correctly rotated the session ID on login.")
    else:
        warn("Result is inconclusive — one or both cookie values were not recorded.")

    # ── Notes ────────────────────────────────────────────────────────────────
    section("Additional Notes")
    print(
        f"  Optionally record any additional observations:\n"
        f"  (token format, MFA interaction, redirect behaviour, etc.)\n"
        f"  Leave blank to skip."
    )
    notes = prompt_text("Notes (optional):", hint="")
    results["notes"] = notes

    return results


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

VERDICT_BADGE = {
    "VULNERABLE":    "🔴 **VULNERABLE** — Session fixation confirmed",
    "PASS":          "✅ **PASS** — Session token rotated on login",
    "INCONCLUSIVE":  "⚠️ **INCONCLUSIVE** — Insufficient data collected",
}

STEP_STATUS_BADGE = {
    "pass":          "✅",
    "done":          "✅",
    "recorded":      "📝",
    "warn":          "⚠️",
    "blocked":       "🚫",
    "skipped":       "—",
    "inconclusive":  "❓",
    "vulnerable":    "🔴",
}


def build_report(results: dict) -> str:
    lines = []
    lines.append("# WSTG-SESS-03 — Session Fixation Checklist Report")
    lines.append("")
    lines.append(f"**Generated:** {results['timestamp']}  ")
    lines.append(f"**Login Endpoint:** `{results['login_endpoint'] or 'not recorded'}`  ")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Verdict block
    verdict = results["verdict"]
    lines.append("## Verdict")
    lines.append("")
    lines.append(VERDICT_BADGE.get(verdict, f"❓ {verdict}"))
    lines.append("")

    if verdict == "VULNERABLE":
        lines.append("> **Impact:** An attacker who can plant a known session token")
        lines.append("> (via URL parameter injection, meta-refresh, subdomain XSS,")
        lines.append("> or link sharing) can hijack the victim's authenticated session.")
        lines.append("> The server must rotate the session ID immediately after")
        lines.append("> successful authentication.")
        lines.append(">")
        lines.append("> **Remediation:** Issue a new session token on every successful")
        lines.append("> login and invalidate the pre-authentication token immediately.")
        lines.append("> Reference: OWASP WSTG-SESS-03, OWASP Session Management Cheat Sheet.")
    elif verdict == "PASS":
        lines.append("> Server issues a new session token on authentication.")
        lines.append("> Pre-authentication token is not accepted post-login.")

    lines.append("")
    lines.append("---")
    lines.append("")

    # Cookie comparison table
    lines.append("## Cookie Comparison")
    lines.append("")
    lines.append("| | Name | Value |")
    lines.append("|--|------|-------|")
    pre_name  = results["pre_auth_cookie_name"]  or "—"
    pre_val   = results["pre_auth_cookie_value"] or "—"
    post_name = results["post_auth_cookie_name"]  or "—"
    post_val  = results["post_auth_cookie_value"] or "—"
    lines.append(f"| Pre-login  | `{pre_name}`  | `{pre_val}` |")
    lines.append(f"| Post-login | `{post_name}` | `{post_val}` |")

    match_note = ""
    if pre_val != "—" and post_val != "—":
        if pre_val.strip() == post_val.strip():
            match_note = "🔴 **Values are identical — token NOT rotated**"
        else:
            match_note = "✅ Values differ — token rotated"
    lines.append("")
    if match_note:
        lines.append(match_note)
    lines.append("")
    lines.append("---")
    lines.append("")

    # Step-by-step checklist
    lines.append("## Checklist Steps")
    lines.append("")
    lines.append("| Step | Description | Value | Status |")
    lines.append("|------|-------------|-------|--------|")
    for step in results["steps"]:
        badge = STEP_STATUS_BADGE.get(step["status"], "—")
        val   = str(step["value"]) if step["value"] is not None else "—"
        # Truncate long values
        if len(val) > 60:
            val = val[:57] + "..."
        lines.append(
            f"| {step['step']} "
            f"| {step['description']} "
            f"| `{val}` "
            f"| {badge} {step['status']} |"
        )
    lines.append("")

    # Cache cleared note
    if results["cache_cleared"] is False:
        lines.append(
            "> ⚠️ **Note:** Operator did not confirm cache/cookies were cleared "
            "before testing. Result reliability may be reduced."
        )
        lines.append("")

    # Notes
    if results.get("notes"):
        lines.append("---")
        lines.append("")
        lines.append("## Operator Notes")
        lines.append("")
        lines.append(results["notes"])
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## Reference")
    lines.append("")
    lines.append("| Item | Reference |")
    lines.append("|------|-----------|")
    lines.append("| OWASP WSTG-SESS-03 | https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation |")
    lines.append("| OWASP Session Management Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html |")
    lines.append("")
    lines.append("---")
    lines.append("*Generated by sess03_fixation_checklist.py — WSTG-SESS-03*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-SESS-03: Session fixation interactive checklist"
    )
    p.add_argument("--out-dir",
        default=os.path.join("WSTG-SESS-03", "outputs", "test_outputs"),
        metavar="DIR")
    args = p.parse_args()

    results = run_checklist()

    os.makedirs(args.out_dir, exist_ok=True)
    report_path = os.path.join(args.out_dir, "sess03_report.md")

    report = build_report(results)
    with open(report_path, "w") as f:
        f.write(report)

    print(f"\n{GREEN}[+] Report written: {report_path}{RESET}")

    verdict = results["verdict"]
    if verdict == "VULNERABLE":
        print(f"  {RED}{BOLD}⚠  VERDICT: SESSION FIXATION VULNERABILITY{RESET}")
    elif verdict == "PASS":
        print(f"  {GREEN}✓  VERDICT: PASS — token rotated on login{RESET}")
    else:
        print(f"  {YELLOW}?  VERDICT: INCONCLUSIVE — rerun with complete values{RESET}")
    print()


if __name__ == "__main__":
    main()
