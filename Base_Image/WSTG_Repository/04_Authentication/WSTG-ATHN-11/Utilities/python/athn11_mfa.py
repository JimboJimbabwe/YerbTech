#!/usr/bin/env python3
"""
WSTG-ATHN-11 — Testing Multi-Factor Authentication
Questionnaire Script: athn11_mfa.py
COMMENT: STILL DO THIS — 10172026

Interactive MFA assessment with:
  • Y/N gating question (does MFA exist?)
  • Curses TUI factor checklist (check off confirmed factors)
  • Free-text entry for MFA technology/product name
  • Endpoint identification: --auth-ep CSV integers OR --xml path (TUI picker)
  • Verdict: Not Compromised if >=2 factors, Compromised if <2 or MFA absent

Reads:  inputs/data/athn11_questionnaire.json  (factor catalog + schema)
Writes: outputs/test_outputs/athn11_results.json

Usage:
  # No XML — manual endpoint entry
  python3 utilities/python/athn11_mfa.py

  # Known auth endpoint indices in the XML
  python3 utilities/python/athn11_mfa.py --xml captures/login.xml --auth-ep 1,3,7

  # TUI picker — browse and select auth endpoints from the XML
  python3 utilities/python/athn11_mfa.py --xml captures/login.xml

  # Full
  python3 utilities/python/athn11_mfa.py \\
      -q  inputs/data/athn11_questionnaire.json \\
      -o  outputs/test_outputs/athn11_results.json \\
      --xml captures/burp_export.xml \\
      --auth-ep 2,5
"""

import argparse
import base64
import curses
import json
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# ANSI (used outside curses)
# ---------------------------------------------------------------------------
BOLD   = "\033[1m"
DIM    = "\033[2m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
RESET  = "\033[0m"


# ---------------------------------------------------------------------------
# Burp XML parser (same decode_element pattern as all CONF/ATHN scripts)
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


def parse_burp_xml(path: str) -> list[dict]:
    """
    Parse a Burp Suite XML export and return a list of request dicts:
      {index, method, url, path, host, request_headers, request_body, response_status}
    """
    try:
        tree = ET.parse(path)
    except ET.ParseError as e:
        print(f"{RED}[!] XML parse error in {path}: {e}{RESET}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print(f"{RED}[!] XML file not found: {path}{RESET}", file=sys.stderr)
        sys.exit(1)

    items = []
    for i, item in enumerate(tree.getroot().findall("item"), start=1):
        url     = decode_element(item.find("url"))
        method  = decode_element(item.find("method"))
        host    = decode_element(item.find("host"))
        req     = decode_element(item.find("request"))
        resp    = decode_element(item.find("response"))

        parsed  = urlparse(url)
        path_s  = parsed.path or "/"

        # Extract response status line
        resp_status = ""
        if resp:
            first_line = resp.split("\n")[0].strip()
            resp_status = first_line[:80]

        # Extract first few request headers
        req_preview = ""
        if req:
            lines = req.split("\n")[:6]
            req_preview = " | ".join(l.strip() for l in lines if l.strip())[:120]

        items.append({
            "index":           i,
            "method":          method.strip().upper() or "?",
            "url":             url,
            "path":            path_s,
            "host":            host,
            "request_preview": req_preview,
            "response_status": resp_status,
        })

    return items


# ---------------------------------------------------------------------------
# Curses TUI — factor checklist
# ---------------------------------------------------------------------------

def tui_factor_checklist(factors: list[dict]) -> list[dict]:
    """
    Full-screen curses checklist. Returns the list of factor dicts with
    'checked': True/False and 'technology': str added.
    """
    state = [{"checked": False, "tech": ""} for _ in factors]

    def _draw(stdscr, cursor: int, in_tech_entry: bool, tech_buf: str):
        stdscr.clear()
        h, w = stdscr.getmaxyx()

        # Header
        title = " WSTG-ATHN-11 — MFA Factor Checklist "
        stdscr.addstr(0, max(0, (w - len(title)) // 2), title,
                      curses.A_BOLD | curses.A_REVERSE)
        stdscr.addstr(1, 2, "SPACE=toggle  T=enter technology  ENTER=confirm  Q=quit",
                      curses.A_DIM)
        stdscr.addstr(2, 2, "─" * min(w - 4, 70), curses.A_DIM)

        row = 3
        for i, factor in enumerate(factors):
            if row >= h - 4:
                break
            s = state[i]
            check = "[X]" if s["checked"] else "[ ]"
            tech  = f"  → {s['tech']}" if s["tech"] else ""
            line  = f"  {check} {factor['name']:<32} {factor['category']}"
            line  = line[:w - 2]

            attr = curses.A_REVERSE if i == cursor else curses.A_NORMAL
            if s["checked"]:
                attr |= curses.A_BOLD
            stdscr.addstr(row, 0, line, attr)
            row += 1

            if s["tech"]:
                tech_line = f"       Technology: {s['tech']}"[:w - 2]
                stdscr.addstr(row, 0, tech_line, curses.A_DIM)
                row += 1

            # Example hint
            example = factor.get("example", "")
            if example:
                hint = f"       {example}"[:w - 2]
                stdscr.addstr(row, 0, hint, curses.A_DIM)
                row += 1

            if row >= h - 4:
                break

        # Footer
        checked_count = sum(1 for s in state if s["checked"])
        status = f" Factors checked: {checked_count} "
        color  = curses.A_BOLD
        stdscr.addstr(h - 2, 2, status, color)

        if in_tech_entry:
            prompt = f" Technology for '{factors[cursor]['name']}': {tech_buf}_"
            stdscr.addstr(h - 1, 0, prompt[:w - 1], curses.A_BOLD)

        stdscr.refresh()

    def _inner(stdscr):
        curses.curs_set(0)
        cursor      = 0
        in_tech     = False
        tech_buf    = ""

        while True:
            _draw(stdscr, cursor, in_tech, tech_buf)
            key = stdscr.getch()

            if in_tech:
                if key in (curses.KEY_ENTER, 10, 13):
                    state[cursor]["tech"] = tech_buf.strip()
                    in_tech  = False
                    tech_buf = ""
                elif key in (curses.KEY_BACKSPACE, 127, 8):
                    tech_buf = tech_buf[:-1]
                elif 32 <= key <= 126:
                    tech_buf += chr(key)
            else:
                if key == curses.KEY_UP and cursor > 0:
                    cursor -= 1
                elif key == curses.KEY_DOWN and cursor < len(factors) - 1:
                    cursor += 1
                elif key == ord(' '):
                    state[cursor]["checked"] = not state[cursor]["checked"]
                elif key in (ord('t'), ord('T')):
                    in_tech  = True
                    tech_buf = state[cursor].get("tech", "")
                elif key in (ord('q'), ord('Q')):
                    break
                elif key in (curses.KEY_ENTER, 10, 13):
                    break

        return state

    final_state = curses.wrapper(_inner)

    result = []
    for i, factor in enumerate(factors):
        if final_state[i]["checked"]:
            result.append({
                "id":       factor["id"],
                "name":     factor["name"],
                "category": factor["category"],
                "example":  factor.get("example", ""),
                "technology": final_state[i]["tech"],
            })

    return result


# ---------------------------------------------------------------------------
# Curses TUI — XML endpoint picker
# ---------------------------------------------------------------------------

def tui_xml_endpoint_picker(requests: list[dict]) -> list[int]:
    """
    Full-screen curses list of Burp requests. SPACE toggles selection.
    Returns list of selected indices (1-based, matching Burp item order).
    """
    selected = set()

    def _draw(stdscr, cursor: int, offset: int):
        stdscr.clear()
        h, w = stdscr.getmaxyx()

        title = " ATHN-11: Select Authentication Endpoints "
        stdscr.addstr(0, max(0, (w - len(title)) // 2), title,
                      curses.A_BOLD | curses.A_REVERSE)
        stdscr.addstr(1, 2,
                      "↑↓=navigate  SPACE=toggle  ENTER=confirm  Q=abort  "
                      "PgUp/PgDn=scroll",
                      curses.A_DIM)
        stdscr.addstr(2, 2, "─" * min(w - 4, 76), curses.A_DIM)

        visible = h - 6
        for row_i in range(visible):
            req_i = offset + row_i
            if req_i >= len(requests):
                break
            req  = requests[req_i]
            mark = "[*]" if req["index"] in selected else "[ ]"
            line = (
                f"  {mark} #{req['index']:>4}  "
                f"{req['method']:<6} "
                f"{req['path'][:40]:<40}  "
                f"{req['response_status'][:20]}"
            )
            line = line[:w - 2]

            attr = curses.A_REVERSE if req_i == cursor else curses.A_NORMAL
            if req["index"] in selected:
                attr |= curses.A_BOLD
            stdscr.addstr(3 + row_i, 0, line, attr)

        # Detail panel for current item
        if 0 <= cursor < len(requests):
            req = requests[cursor]
            detail = f" {req['method']} {req['url'][:w - 4]} "
            stdscr.addstr(h - 3, 0, detail[:w - 1], curses.A_DIM)
            prev = req.get("request_preview", "")[:w - 2]
            stdscr.addstr(h - 2, 0, prev, curses.A_DIM)

        sel_str = f" Selected: {sorted(selected)} "
        stdscr.addstr(h - 1, 0, sel_str[:w - 1], curses.A_BOLD)
        stdscr.refresh()

    def _inner(stdscr):
        curses.curs_set(0)
        cursor = 0
        offset = 0
        h_ref  = [stdscr.getmaxyx()[0] - 6]

        while True:
            h_ref[0] = stdscr.getmaxyx()[0] - 6
            visible  = max(1, h_ref[0])
            _draw(stdscr, cursor, offset)
            key = stdscr.getch()

            if key == curses.KEY_UP:
                if cursor > 0:
                    cursor -= 1
                    if cursor < offset:
                        offset = cursor
            elif key == curses.KEY_DOWN:
                if cursor < len(requests) - 1:
                    cursor += 1
                    if cursor >= offset + visible:
                        offset = cursor - visible + 1
            elif key == curses.KEY_PPAGE:
                cursor = max(0, cursor - visible)
                offset = max(0, offset - visible)
            elif key == curses.KEY_NPAGE:
                cursor = min(len(requests) - 1, cursor + visible)
                offset = min(max(0, len(requests) - visible), offset + visible)
            elif key == ord(' '):
                idx = requests[cursor]["index"]
                if idx in selected:
                    selected.discard(idx)
                else:
                    selected.add(idx)
            elif key in (ord('q'), ord('Q')):
                return []
            elif key in (curses.KEY_ENTER, 10, 13):
                return sorted(selected)

        return sorted(selected)

    return curses.wrapper(_inner)


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_json(path: str, label: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"{RED}[!] {label} not found: {path}{RESET}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"{RED}[!] Invalid JSON in {label}: {e}{RESET}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Prompt helpers
# ---------------------------------------------------------------------------

def prompt_yn(prompt: str) -> bool:
    while True:
        raw = input(f"  {prompt} [Y/N]: ").strip().lower()
        if raw in ('y', 'yes'):
            return True
        if raw in ('n', 'no'):
            return False
        print(f"  {YELLOW}Please enter Y or N{RESET}")


def prompt_text(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    raw = input(f"  {prompt}{suffix}: ").strip()
    return raw or default


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------

def run(data: dict, args) -> dict:
    factor_catalog = data.get("factor_catalog", [])
    results        = data.setdefault("mfa_test_results", {}).setdefault("survey", {})

    print()
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"{BOLD} WSTG-ATHN-11 — Multi-Factor Authentication Assessment{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print()

    # -----------------------------------------------------------------------
    # Gate: does MFA exist?
    # -----------------------------------------------------------------------
    print(f"{CYAN}Q1: Does MFA exist on this application?{RESET}")
    print(f"  {DIM}Check login, sensitive actions, admin panel, API auth flows.{RESET}")
    mfa_exists = prompt_yn("MFA present?")
    print()

    if not mfa_exists:
        print(f"  {RED}MFA is absent — marking as Compromised immediately.{RESET}")
        results["findings"]       = "Compromised"
        results["factors"]        = []
        results["technology_mfa"] = ""
        results["endpoints"]      = []
        results["xml_file"]       = args.xml or ""
        results["mfa_exists"]     = False
        results["timestamp"]      = datetime.now(timezone.utc).isoformat()
        data["mfa_test_results"]["survey"] = results
        _print_summary(results)
        return data

    results["mfa_exists"] = True

    # -----------------------------------------------------------------------
    # Factor checklist — curses TUI
    # -----------------------------------------------------------------------
    print(f"  {DIM}Launching factor checklist TUI…{RESET}")
    print(f"  {DIM}SPACE=toggle  T=enter technology name  ENTER=confirm{RESET}")
    input(f"  {DIM}Press Enter to open the TUI…{RESET}")

    checked_factors = tui_factor_checklist(factor_catalog)

    print()
    if checked_factors:
        print(f"  {GREEN}Factors confirmed ({len(checked_factors)}):{RESET}")
        for f in checked_factors:
            tech = f"  [{f['technology']}]" if f["technology"] else ""
            print(f"    {GREEN}✓{RESET} {f['name']}{tech}")
    else:
        print(f"  {YELLOW}No factors checked — will be marked Compromised.{RESET}")
    print()

    # -----------------------------------------------------------------------
    # MFA technology free-text (overall product, if not entered per-factor)
    # -----------------------------------------------------------------------
    tech_names = [f["technology"] for f in checked_factors if f.get("technology")]
    if tech_names:
        default_tech = ", ".join(tech_names)
    else:
        default_tech = ""

    print(f"{CYAN}MFA Technology / Product:{RESET}")
    print(f"  {DIM}Overall MFA product/vendor (e.g. Duo Security, Okta, in-house TOTP).{RESET}")
    print(f"  {DIM}Leave blank to use per-factor entries above.{RESET}")
    tech_overall = prompt_text("Technology", default=default_tech)
    results["technology_mfa"] = tech_overall or default_tech
    print()

    # -----------------------------------------------------------------------
    # Endpoint identification
    # -----------------------------------------------------------------------
    endpoint_indices = []
    xml_path         = args.xml or ""

    if args.auth_ep:
        # CLI CSV integers
        try:
            endpoint_indices = [int(x.strip()) for x in args.auth_ep.split(",") if x.strip()]
            print(f"  {GREEN}Auth endpoints from --auth-ep: {endpoint_indices}{RESET}")
        except ValueError:
            print(f"  {YELLOW}[!] --auth-ep parse error — expected comma-separated integers{RESET}")

    elif xml_path:
        # TUI picker
        print(f"{CYAN}Loading XML: {xml_path}{RESET}")
        requests = parse_burp_xml(xml_path)
        print(f"  {len(requests)} request(s) parsed.")
        print(f"  {DIM}Launching endpoint picker TUI…{RESET}")
        input(f"  {DIM}Press Enter to open the TUI…{RESET}")
        endpoint_indices = tui_xml_endpoint_picker(requests)
        print()
        if endpoint_indices:
            print(f"  {GREEN}Selected auth endpoints: {endpoint_indices}{RESET}")
        else:
            print(f"  {YELLOW}No endpoints selected (or TUI aborted).{RESET}")

    else:
        # Manual entry
        print(f"{CYAN}Auth Endpoint Indices:{RESET}")
        print(f"  {DIM}Enter comma-separated request numbers from your Burp export,{RESET}")
        print(f"  {DIM}or leave blank if not using XML. (e.g. 1,3,7){RESET}")
        raw = input("  Indices: ").strip()
        if raw:
            try:
                endpoint_indices = [int(x.strip()) for x in raw.split(",") if x.strip()]
            except ValueError:
                print(f"  {YELLOW}[!] Could not parse — skipping endpoint indices{RESET}")

    results["endpoints"] = endpoint_indices
    results["xml_file"]  = xml_path
    print()

    # -----------------------------------------------------------------------
    # Verdict
    # -----------------------------------------------------------------------
    factor_count = len(checked_factors)
    if factor_count >= 2:
        verdict = "Not Compromised"
    else:
        verdict = "Compromised"

    results["findings"]   = verdict
    results["factors"]    = checked_factors
    results["timestamp"]  = datetime.now(timezone.utc).isoformat()
    data["mfa_test_results"]["survey"] = results

    _print_summary(results)
    return data


def _print_summary(results: dict):
    verdict      = results.get("findings", "Unknown")
    factors      = results.get("factors", [])
    tech         = results.get("technology_mfa", "")
    endpoints    = results.get("endpoints", [])
    mfa_exists   = results.get("mfa_exists", True)

    print(f"{BOLD}{'─'*65}{RESET}")
    print(f"{BOLD} Summary{RESET}")
    print(f"{BOLD}{'─'*65}{RESET}")
    color = GREEN if verdict == "Not Compromised" else RED
    print(f"  Verdict: {color}{BOLD}{verdict}{RESET}")

    if not mfa_exists:
        print(f"  {RED}MFA was absent — no factors assessed.{RESET}")
    else:
        print(f"  Factors confirmed: {len(factors)}")
        for f in factors:
            tech_note = f"  [{f['technology']}]" if f.get("technology") else ""
            print(f"    • {f['name']}{tech_note}")
        if tech:
            print(f"  Technology: {tech}")
        if endpoints:
            print(f"  Auth endpoints selected: {endpoints}")

    if verdict == "Compromised":
        factor_count = len(factors)
        if factor_count == 0 and mfa_exists:
            print(f"  {RED}Reason: MFA present but no factors confirmed in checklist.{RESET}")
        elif factor_count == 1:
            print(f"  {RED}Reason: Only 1 factor confirmed — SFA, not MFA.{RESET}")
        elif not mfa_exists:
            print(f"  {RED}Reason: MFA not present on application.{RESET}")
    else:
        print(f"  {GREEN}≥2 factors confirmed — MFA requirement met.{RESET}")
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description='ATHN-11: MFA assessment questionnaire with TUI factor checklist'
    )
    p.add_argument(
        '-q', '--questionnaire',
        default='inputs/data/athn11_questionnaire.json',
        metavar='PATH',
        help='Questionnaire/factor catalog JSON (default: inputs/data/athn11_questionnaire.json)'
    )
    p.add_argument(
        '-o', '--output',
        default='outputs/test_outputs/athn11_results.json',
        metavar='PATH',
        help='Output JSON (default: outputs/test_outputs/athn11_results.json)'
    )
    p.add_argument(
        '--xml',
        default=None,
        metavar='PATH',
        help='Burp XML export — launches TUI endpoint picker unless --auth-ep is given'
    )
    p.add_argument(
        '--auth-ep',
        default=None,
        metavar='N,N,N',
        help='Comma-separated auth endpoint indices from XML (skips TUI picker)'
    )
    return p.parse_args()


def main():
    args = parse_args()
    data = load_json(args.questionnaire, "questionnaire")
    data = run(data, args)

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"{GREEN}[+] Results written → {args.output}{RESET}")
    print(f"  Run verdict script:")
    print(f"  python3 utilities/python/verdict_ATHN11.py -i {args.output}")
    print()


if __name__ == "__main__":
    main()
