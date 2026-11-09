#!/usr/bin/env python3
"""
WSTG-SESS-06 — Testing for Logout Functionality
sess06_logout_checklist.py

Three-category checklist for secure session termination testing.

Category A — UI Logout Controls (operator attestation)
  A1. Is a logout control visible and accessible from all authenticated pages?
  A2. Does the logout action require a single, clear user gesture (no buried menus)?
  A3. Is the user redirected to a non-authenticated page after logout?

Category B — Session Timeout (XML scan + operator attestation)
  B1. [AUTO] Does any cookie in the XML have a Max-Age or Expires directive?
  B2. Does the application show an inactivity timeout warning before expiry?
  B3. Does the application enforce timeout consistently across all session types?

Category C — Server-Side Session Invalidation (operator attestation)
  C1. After logout, does replaying a captured authenticated request in Burp
      return a 401/403/redirect rather than a valid response?
  C2. After logout, is the session token rejected even if manually re-submitted
      in the Cookie header?
  C3. Does the server invalidate the token server-side (not just clear client cookie)?

Inputs:
  WSTG-SESS-06/inputs/xml/<filename>.xml   (--xml, optional — enhances B1)

Outputs:
  WSTG-SESS-06/outputs/test_outputs/sess06_report.md

Usage:
  python3 WSTG-SESS-06/utilities/python/sess06_logout_checklist.py \\
      --xml WSTG-SESS-06/inputs/xml/session_walk.xml
  python3 WSTG-SESS-06/utilities/python/sess06_logout_checklist.py
      (runs without XML — B1 will be marked for manual review)
"""

import argparse
import base64
import os
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime


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

REASONABLE_EXPIRY_SECONDS = 86400  # 24 hours


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def banner(title: str):
    width = 65
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD} {title}{RESET}")
    print(f"{BOLD}{'='*width}{RESET}\n")


def section(letter: str, title: str):
    print(f"\n{CYAN}{BOLD}── Category {letter}: {title} {'─'*(45-len(title))}{RESET}\n")


def prompt_yn_detail(question: str, hint: str = "") -> tuple[bool | None, str]:
    """Returns (bool_answer, optional_detail_note)."""
    if hint:
        print(f"  {DIM}{hint}{RESET}")
    while True:
        try:
            val = input(f"  {BOLD}> {question} [y/n/skip]: {RESET}").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{YELLOW}Interrupted.{RESET}")
            sys.exit(0)
        if val in ("y", "yes"):
            answer = True; break
        if val in ("n", "no"):
            answer = False; break
        if val in ("s", "skip", ""):
            answer = None; break
        print(f"  {YELLOW}Enter y, n, or skip.{RESET}")

    detail = ""
    if answer is not None:
        try:
            detail = input(f"  {DIM}  Optional note (Enter to skip): {RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            pass
    return answer, detail


def fmt_answer(answer) -> str:
    if answer is True:
        return "YES"
    if answer is False:
        return "NO"
    return "SKIPPED"


def status_from_answer(answer, expected_pass: bool = True) -> str:
    """Derive pass/fail/skipped status."""
    if answer is None:
        return "skipped"
    if answer == expected_pass:
        return "pass"
    return "fail"


# ---------------------------------------------------------------------------
# Burp XML decode + cookie expiry scan
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


def parse_set_cookies_from_xml(path: str) -> list[dict]:
    """
    Parses the XML and returns all Set-Cookie directives found.
    Each entry: {url, name, value, max_age, expires, seconds_until_expiry}
    """
    try:
        tree = ET.parse(path)
    except (ET.ParseError, FileNotFoundError) as e:
        print(f"{YELLOW}[!] Could not parse XML ({e}) — skipping auto-scan.{RESET}")
        return []

    results = []
    for item in tree.getroot().findall("item"):
        url  = decode_element(item.find("url"))
        resp = decode_element(item.find("response"))
        head = resp.split("\r\n\r\n", 1)[0] if resp else ""

        for line in head.splitlines():
            if line.strip().lower().startswith("set-cookie"):
                value_part = line.split(":", 1)[1].strip() if ":" in line else ""
                parts      = [p.strip() for p in value_part.split(";")]
                first      = parts[0]
                name, _, val = first.partition("=")
                directives = {}
                for part in parts[1:]:
                    if "=" in part:
                        dk, _, dv = part.partition("=")
                        directives[dk.strip().lower()] = dv.strip()
                    else:
                        key = part.strip().lower()
                        if key:
                            directives[key] = True

                max_age = directives.get("max-age", None)
                expires = directives.get("expires", None)

                secs = None
                if max_age is not None:
                    try:
                        secs = int(max_age)
                    except ValueError:
                        pass
                elif expires is not None:
                    try:
                        exp_dt = parsedate_to_datetime(expires)
                        secs   = int((exp_dt - datetime.now(timezone.utc)).total_seconds())
                    except Exception:
                        pass

                if max_age is not None or expires is not None:
                    results.append({
                        "url":                  url,
                        "name":                 name.strip(),
                        "value":                val.strip()[:30] + "..." if len(val.strip()) > 30 else val.strip(),
                        "max_age":              max_age,
                        "expires":              expires,
                        "seconds_until_expiry": secs,
                    })
    return results


# ---------------------------------------------------------------------------
# Checklist runner
# ---------------------------------------------------------------------------

def run_checklist(xml_path: str | None) -> dict:
    results = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "xml_scanned": xml_path or None,
        "categories": {
            "A": {"title": "UI Logout Controls",              "items": []},
            "B": {"title": "Session Timeout",                 "items": []},
            "C": {"title": "Server-Side Session Invalidation","items": []},
        },
    }

    banner("WSTG-SESS-06 — Logout Functionality Checklist")
    print(
        f"  Tests secure session termination across three categories:\n"
        f"  A) UI logout controls  B) Session timeout  C) Server-side invalidation\n\n"
        f"  {DIM}Reference: OWASP WSTG-SESS-06{RESET}"
    )

    # ════════════════════════════════════════════════════════════════════════
    # Category A — UI Logout Controls
    # ════════════════════════════════════════════════════════════════════════
    section("A", "UI Logout Controls")
    print(
        f"  Verify that the application provides accessible, clear logout\n"
        f"  controls on every authenticated page.\n"
    )

    a_items = []

    # A1
    print(f"  {BOLD}A1.{RESET} Logout control visibility")
    a1, a1_note = prompt_yn_detail(
        "Is a logout button/link visible and accessible from all authenticated pages?",
        hint="Check nav bar, header, user menu — it should not require digging."
    )
    a_items.append({
        "id": "A1", "question": "Logout control visible on all authenticated pages",
        "answer": fmt_answer(a1), "status": status_from_answer(a1),
        "note": a1_note,
    })
    print()

    # A2
    print(f"  {BOLD}A2.{RESET} Logout requires single user gesture")
    a2, a2_note = prompt_yn_detail(
        "Does logout complete in a single clear action (no multi-step confirmation maze)?",
        hint="One click or one confirmation is fine. Buried sub-sub-menus are not."
    )
    a_items.append({
        "id": "A2", "question": "Logout completes in a single clear user gesture",
        "answer": fmt_answer(a2), "status": status_from_answer(a2),
        "note": a2_note,
    })
    print()

    # A3
    print(f"  {BOLD}A3.{RESET} Post-logout redirect")
    a3, a3_note = prompt_yn_detail(
        "After logout, is the user redirected to a non-authenticated page (login page, home)?",
        hint="User should not remain on an authenticated page after logout."
    )
    a_items.append({
        "id": "A3", "question": "User redirected to unauthenticated page after logout",
        "answer": fmt_answer(a3), "status": status_from_answer(a3),
        "note": a3_note,
    })

    results["categories"]["A"]["items"] = a_items

    # ════════════════════════════════════════════════════════════════════════
    # Category B — Session Timeout
    # ════════════════════════════════════════════════════════════════════════
    section("B", "Session Timeout")

    b_items   = []
    xml_cookies = []

    # B1 — auto from XML if available
    print(f"  {BOLD}B1.{RESET} Cookie expiry directives (XML scan)")
    if xml_path:
        xml_cookies = parse_set_cookies_from_xml(xml_path)
        if xml_cookies:
            print(f"  {GREEN}[AUTO]{RESET} Found {len(xml_cookies)} cookie(s) with expiry directives:\n")
            long_lived = []
            for c in xml_cookies:
                secs = c["seconds_until_expiry"]
                if secs is None:
                    tag = f"{DIM}(parse error){RESET}"
                elif secs <= 0:
                    tag = f"{DIM}already expired / logout cookie{RESET}"
                elif secs > REASONABLE_EXPIRY_SECONDS:
                    hrs = secs // 3600
                    tag = f"{YELLOW}LONG-LIVED (~{hrs}h){RESET}"
                    long_lived.append(c)
                else:
                    mins = secs // 60
                    tag = f"{GREEN}short (~{mins}min){RESET}"
                print(f"    {CYAN}{c['name']}{RESET}  [{tag}]  ← {c['url']}")
            print()
            b1_auto_status = "warn" if long_lived else "pass"
            b1_auto_note   = (
                f"{len(long_lived)} long-lived cookie(s) found"
                if long_lived
                else "all expiry cookies within 24h threshold"
            )
        else:
            print(f"  {DIM}No cookies with Expires/Max-Age found in XML.{RESET}\n")
            b1_auto_status = "pass"
            b1_auto_note   = "No persistent-cookie expiry directives in XML"
    else:
        print(f"  {YELLOW}No XML provided — manual review required.{RESET}\n")
        b1_auto_status = "manual"
        b1_auto_note   = "No XML — cannot auto-scan"

    b_items.append({
        "id": "B1", "question": "Cookie expiry directives present in XML (auto-scan)",
        "answer": "AUTO", "status": b1_auto_status,
        "note": b1_auto_note,
        "xml_cookies": xml_cookies,
    })

    # B2
    print(f"  {BOLD}B2.{RESET} Inactivity timeout warning")
    b2, b2_note = prompt_yn_detail(
        "Does the application warn the user before their session expires due to inactivity?",
        hint="e.g. 'Your session will expire in 2 minutes' modal or banner."
    )
    b_items.append({
        "id": "B2", "question": "Application warns user before inactivity timeout",
        "answer": fmt_answer(b2), "status": status_from_answer(b2),
        "note": b2_note,
    })
    print()

    # B3
    print(f"  {BOLD}B3.{RESET} Consistent timeout enforcement")
    b3, b3_note = prompt_yn_detail(
        "Is the timeout enforced consistently across all session types (web, API, mobile, remember-me)?",
        hint="Check that a 'remember me' token or API key doesn't bypass the inactivity timeout."
    )
    b_items.append({
        "id": "B3", "question": "Timeout enforced consistently across all session types",
        "answer": fmt_answer(b3), "status": status_from_answer(b3),
        "note": b3_note,
    })

    results["categories"]["B"]["items"] = b_items

    # ════════════════════════════════════════════════════════════════════════
    # Category C — Server-Side Session Invalidation
    # ════════════════════════════════════════════════════════════════════════
    section("C", "Server-Side Session Invalidation")
    print(
        f"  These checks require Burp Suite Repeater.\n"
        f"  Capture an authenticated request BEFORE logging out,\n"
        f"  then replay it AFTER logout and observe the response.\n"
    )

    c_items = []

    # C1
    print(f"  {BOLD}C1.{RESET} Replay post-logout returns error (not valid response)")
    c1, c1_note = prompt_yn_detail(
        "After logout, does replaying a captured authenticated request in Burp\n"
        "       return 401 / 403 / redirect rather than a valid authenticated response?",
        hint="Send the captured request in Repeater after logging out. Server should reject it."
    )
    c_items.append({
        "id": "C1",
        "question": "Post-logout replay returns 401/403/redirect (Burp Repeater test)",
        "answer": fmt_answer(c1), "status": status_from_answer(c1),
        "note": c1_note,
    })
    print()

    # C2
    print(f"  {BOLD}C2.{RESET} Manual cookie re-submission rejected")
    c2, c2_note = prompt_yn_detail(
        "If you manually craft a request with the old session token in the Cookie header,\n"
        "       is it rejected by the server?",
        hint="In Burp Repeater, set Cookie: sessionid=<old_value> and confirm a 401/403."
    )
    c_items.append({
        "id": "C2",
        "question": "Old session token manually re-submitted is rejected",
        "answer": fmt_answer(c2), "status": status_from_answer(c2),
        "note": c2_note,
    })
    print()

    # C3
    print(f"  {BOLD}C3.{RESET} Server-side invalidation (not just client cookie clear)")
    c3, c3_note = prompt_yn_detail(
        "Does the server appear to invalidate the session server-side?\n"
        "       (i.e. rejection is not just because the browser cleared the cookie\n"
        "        but because the token itself is no longer valid on the server)",
        hint="If replaying in Burp with the old token fails, server-side invalidation is confirmed."
    )
    c_items.append({
        "id": "C3",
        "question": "Session invalidated server-side (not just client-side cookie clear)",
        "answer": fmt_answer(c3), "status": status_from_answer(c3),
        "note": c3_note,
    })

    results["categories"]["C"]["items"] = c_items

    return results


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

STATUS_EMOJI = {
    "pass":    "✅",
    "fail":    "🔴",
    "warn":    "⚠️",
    "skipped": "—",
    "manual":  "📋",
    "AUTO":    "🔍",
}


def build_report(results: dict) -> str:
    lines = []
    lines.append("# WSTG-SESS-06 — Logout Functionality Checklist Report")
    lines.append("")
    lines.append(f"**Generated:** {results['timestamp']}  ")
    if results["xml_scanned"]:
        lines.append(f"**XML scanned:** `{results['xml_scanned']}`  ")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Summary table
    lines.append("## Summary")
    lines.append("")
    lines.append("| Category | Title | Items | Failures |")
    lines.append("|----------|-------|-------|----------|")

    all_failures = []
    for letter, cat in results["categories"].items():
        fails = [i for i in cat["items"] if i["status"] == "fail"]
        all_failures.extend(fails)
        lines.append(
            f"| {letter} | {cat['title']} "
            f"| {len(cat['items'])} "
            f"| {'🔴 ' + str(len(fails)) if fails else '✅ 0'} |"
        )
    lines.append("")

    if all_failures:
        lines.append("### ⚠️ Items Requiring Remediation")
        lines.append("")
        for item in all_failures:
            lines.append(f"- **{item['id']}** — {item['question']}")
            if item.get("note"):
                lines.append(f"  - *{item['note']}*")
        lines.append("")

    lines.append("---")
    lines.append("")

    # Per-category detail
    for letter, cat in results["categories"].items():
        lines.append(f"## Category {letter} — {cat['title']}")
        lines.append("")
        lines.append("| ID | Question | Answer | Status | Note |")
        lines.append("|----|----------|--------|--------|------|")

        for item in cat["items"]:
            emoji  = STATUS_EMOJI.get(item["status"], "—")
            note   = item.get("note", "") or "—"
            answer = item["answer"]
            lines.append(
                f"| {item['id']} "
                f"| {item['question']} "
                f"| {answer} "
                f"| {emoji} {item['status']} "
                f"| {note} |"
            )
        lines.append("")

        # B1 cookie detail block
        if letter == "B":
            xml_cookies = next(
                (i.get("xml_cookies", []) for i in cat["items"] if i["id"] == "B1"),
                []
            )
            if xml_cookies:
                lines.append("### B1 — Cookies with Expiry Directives (from XML)")
                lines.append("")
                lines.append("| Cookie Name | Max-Age | Expires | ~Seconds | Assessment |")
                lines.append("|-------------|---------|---------|----------|------------|")
                for c in xml_cookies:
                    secs = c["seconds_until_expiry"]
                    if secs is None:
                        assess = "parse error"
                    elif secs <= 0:
                        assess = "already expired / logout"
                    elif secs > REASONABLE_EXPIRY_SECONDS:
                        assess = f"⚠️ long-lived (~{secs//3600}h)"
                    else:
                        assess = f"✅ short (~{secs//60}min)"
                    lines.append(
                        f"| `{c['name']}` "
                        f"| `{c['max_age'] or '—'}` "
                        f"| `{c['expires'] or '—'}` "
                        f"| {secs if secs is not None else '—'} "
                        f"| {assess} |"
                    )
                lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## Reference")
    lines.append("")
    lines.append("| Item | Reference |")
    lines.append("|------|-----------|")
    lines.append("| OWASP WSTG-SESS-06 | https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality |")
    lines.append("| OWASP Session Management Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html |")
    lines.append("| NIST SP 800-63B §7 | https://pages.nist.gov/800-63-3/sp800-63b.html |")
    lines.append("")
    lines.append("---")
    lines.append("*Generated by sess06_logout_checklist.py — WSTG-SESS-06*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-SESS-06: Logout functionality checklist"
    )
    p.add_argument("--xml",
        default=None,
        metavar="PATH",
        help="Burp XML export for B1 auto-scan (optional)")
    p.add_argument("--out-dir",
        default=os.path.join("WSTG-SESS-06", "outputs", "test_outputs"),
        metavar="DIR")
    args = p.parse_args()

    results = run_checklist(args.xml)

    os.makedirs(args.out_dir, exist_ok=True)
    report_path = os.path.join(args.out_dir, "sess06_report.md")

    report = build_report(results)
    with open(report_path, "w") as f:
        f.write(report)

    print(f"\n{GREEN}[+] Report written: {report_path}{RESET}")

    # Final tally
    failures = 0
    warns    = 0
    for cat in results["categories"].values():
        for item in cat["items"]:
            if item["status"] == "fail":
                failures += 1
            elif item["status"] == "warn":
                warns += 1

    if failures:
        print(f"  {RED}{BOLD}⚠  {failures} item(s) failed — review report{RESET}")
    elif warns:
        print(f"  {YELLOW}⚠  {warns} warning(s) — review report{RESET}")
    else:
        print(f"  {GREEN}✓  No failures recorded{RESET}")
    print()


if __name__ == "__main__":
    main()
