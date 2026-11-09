#!/usr/bin/env python3
"""
WSTG-ATHZ-02 — Bypassing Authorization Schema
Script 3: athz_reporting.py

Curses TUI that reads ATHZ_02.json and lets the operator:
  Left panel:  endpoint list, pre-checked, uncheck to omit
  Right panel: object type toggles, pre-checked per available wordlists

Generates: WSTG-ATHZ-02/outputs/test_outputs/athz02_report.md

Controls:
  ↑ / ↓        Navigate active panel
  Tab          Switch between panels
  Space        Toggle checkbox
  Enter        Generate report
  Q            Quit without generating

Usage:
  python3 WSTG-ATHZ-02/utilities/python/athz_reporting.py
  python3 WSTG-ATHZ-02/utilities/python/athz_reporting.py \\
      --json    WSTG-ATHZ-02/data/json/ATHZ_02.json \\
      --data    WSTG-ATHZ-02/data \\
      --output  WSTG-ATHZ-02/outputs/test_outputs/athz02_report.md
"""

import argparse
import curses
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# ANSI (for non-curses output)
# ---------------------------------------------------------------------------
BOLD  = "\033[1m"
GREEN = "\033[92m"
CYAN  = "\033[96m"
RESET = "\033[0m"

OBJECT_SUFFIXES = ["cookies", "JWTs", "UUIDs", "uniqueIDs", "headers"]
OBJECT_LABELS = {
    "cookies":   "cookies",
    "JWTs":      "JWT tokens",
    "UUIDs":     "UUIDs",
    "uniqueIDs": "unique URL IDs",
    "headers":   "differential headers",
}


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_json(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[!] JSON not found: {path} — run parse_athz02.py first", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)


def detect_available_objects(data_dir: str, usernames: list[str]) -> set[str]:
    """
    Returns set of object suffixes for which at least one user has a non-empty
    wordlist file in data_dir. Pre-populates the right panel checkboxes.
    """
    found = set()
    for username in usernames:
        for suffix in OBJECT_SUFFIXES:
            fpath = os.path.join(data_dir, f"{username}_{suffix}.txt")
            if os.path.exists(fpath) and os.path.getsize(fpath) > 0:
                found.add(suffix)
    return found


def collect_users(full_json: dict) -> tuple[list[str], list[str]]:
    """Returns (higher_users, lower_users) across all folders."""
    higher, lower = [], []
    for folder_data in full_json.get("folders", {}).values():
        for username, user_data in folder_data.items():
            role = user_data.get("role", "lower_priv")
            if role == "higher_priv" and username not in higher:
                higher.append(username)
            elif role != "higher_priv" and username not in lower:
                lower.append(username)
    return higher, lower


def collect_endpoints(full_json: dict) -> list[dict]:
    """
    Returns list of {ep_key, method, path, folder, users} dicts.
    Authorization-relevant: endpoints from higher_priv walks + diff-header endpoints.
    """
    seen = {}
    for folder_name, folder_data in full_json.get("folders", {}).items():
        for username, user_data in folder_data.items():
            role = user_data.get("role", "lower_priv")
            for ep_key, ep_data in user_data.get("endpoints", {}).items():
                is_auth = role == "higher_priv" or bool(ep_data.get("diff_headers"))
                if not is_auth:
                    continue
                if ep_key not in seen:
                    seen[ep_key] = {
                        "ep_key": ep_key,
                        "method": ep_data.get("method", ""),
                        "path":   ep_data.get("path", ""),
                        "folder": folder_name,
                        "users":  [],
                    }
                if username not in seen[ep_key]["users"]:
                    seen[ep_key]["users"].append(username)
    return sorted(seen.values(), key=lambda x: x["ep_key"])


# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------

def build_report(
    full_json:        dict,
    checked_eps:      list[dict],
    checked_objects:  list[str],
    higher_users:     list[str],
    lower_users:      list[str],
    data_dir:         str,
) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    obj_str = " / ".join(OBJECT_LABELS[s] for s in checked_objects) or "N/A"

    lines = [
        "# WSTG-ATHZ-02 — Authorization Schema Bypass Test Report",
        "",
        f"**Generated:** {ts}  ",
        f"**WSTG Reference:** [WSTG-ATHZ-02](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema)",
        "",
        "---",
        "",
        "## Users",
        "",
    ]

    for u in higher_users:
        lines.append(f"- **{u}** — `higher_priv`")
    for u in lower_users:
        lines.append(f"- **{u}** — `lower_priv`")
    lines.append("")

    lines += [
        "## Objects Tested",
        "",
    ]
    for s in checked_objects:
        lines.append(f"- {OBJECT_LABELS[s]}")
    lines.append("")

    lines += [
        "## Swap Test Instructions",
        "",
        "> For each user pair and endpoint below, perform the swap while the",
        "> source user is **logged out** to isolate the session state.",
        "",
    ]

    if higher_users and lower_users:
        for high in higher_users:
            for low in lower_users:
                lines += [
                    f"### Higher-priv user `{high}` — test with lower-priv tokens",
                    "",
                    f"Login as **{high}** and swap {obj_str} from lower user **{low}** "
                    f"(log {low} out first). Observe whether access is granted or denied.",
                    "",
                    f"### Lower-priv user `{low}` — attempt higher-priv access",
                    "",
                    f"Login as **{low}** and swap {obj_str} from higher user **{high}** "
                    f"(log {high} out first). Observe whether escalated access is granted.",
                    "",
                ]
    elif lower_users:
        for i, u1 in enumerate(lower_users):
            for u2 in lower_users[i+1:]:
                lines += [
                    f"### Peer swap: `{u1}` ↔ `{u2}`",
                    "",
                    f"Login as **{u1}**, swap {obj_str} from **{u2}** "
                    f"({u2} logged out). Then reverse.",
                    "",
                ]
    else:
        lines.append("_No user pairs identified._\n")

    lines += [
        "## Endpoints to Test",
        "",
        "| # | Method | Path | Folder | Relevant Users |",
        "|---|--------|------|--------|----------------|",
    ]
    for i, ep in enumerate(checked_eps, 1):
        users_str = ", ".join(ep["users"])
        lines.append(f"| {i} | `{ep['method']}` | `{ep['path']}` | {ep['folder']} | {users_str} |")
    lines.append("")

    lines += [
        "## Wordlist Files",
        "",
        "Feed these into Burp Intruder (Sniper mode, position on the token value):",
        "",
    ]

    all_usernames = higher_users + lower_users
    for username in all_usernames:
        user_dir = os.path.join(data_dir, username)
        files_found = []
        for suffix in checked_objects:
            fpath = os.path.join(user_dir, f"{suffix}.txt")
            if os.path.exists(fpath):
                files_found.append(f"`{fpath}`")
        if files_found:
            lines.append(f"**{username}**: " + ", ".join(files_found))
    lines.append("")

    lines += [
        "---",
        "",
        "## Findings",
        "",
        "_Record findings here after testing._",
        "",
        "| Endpoint | Object Swapped | Result | Notes |",
        "|----------|---------------|--------|-------|",
        "| | | | |",
        "",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Curses TUI
# ---------------------------------------------------------------------------

def tui(stdscr, endpoints: list[dict], available_objects: set[str]) -> tuple[list[dict], list[str]] | None:
    """
    Returns (checked_endpoints, checked_object_suffixes) or None if user quit.
    Both panels start fully checked.
    """
    curses.curs_set(0)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_CYAN,  -1)   # header
    curses.init_pair(2, curses.COLOR_GREEN, -1)   # checked
    curses.init_pair(3, curses.COLOR_YELLOW,-1)   # active row
    curses.init_pair(4, curses.COLOR_WHITE, -1)   # normal

    ep_checked  = [True] * len(endpoints)
    obj_list    = [s for s in OBJECT_SUFFIXES if s in available_objects]
    obj_checked = [True] * len(obj_list)

    # active_panel: 0 = left (endpoints), 1 = right (objects)
    active_panel = 0
    left_cursor  = 0
    right_cursor = 0
    left_scroll  = 0

    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()

        left_w  = w // 2 - 1
        right_w = w - left_w - 3

        # ── headers ──────────────────────────────────────────────────────
        title = " ATHZ-02 Report Builder "
        stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
        stdscr.addstr(0, max(0, (w - len(title)) // 2), title[:w])
        stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)

        controls = " Tab=switch panel  Space=toggle  Enter=generate  Q=quit "
        stdscr.attron(curses.A_DIM)
        stdscr.addstr(h - 1, max(0, (w - len(controls)) // 2), controls[:w])
        stdscr.attroff(curses.A_DIM)

        # ── left panel header ────────────────────────────────────────────
        left_title = "[ Endpoints ]" if active_panel != 0 else "[ Endpoints ] ◀"
        stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
        stdscr.addstr(1, 1, left_title[:left_w])
        stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)

        # ── right panel header ───────────────────────────────────────────
        right_x     = left_w + 3
        right_title = "[ Objects ]" if active_panel != 1 else "[ Objects ] ◀"
        stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
        stdscr.addstr(1, right_x, right_title[:right_w])
        stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)

        # ── divider ──────────────────────────────────────────────────────
        for row in range(2, h - 1):
            try:
                stdscr.addch(row, left_w + 2, curses.ACS_VLINE)
            except curses.error:
                pass

        # ── left panel: endpoints ────────────────────────────────────────
        visible_rows = h - 4
        if left_cursor < left_scroll:
            left_scroll = left_cursor
        if left_cursor >= left_scroll + visible_rows:
            left_scroll = left_cursor - visible_rows + 1

        for idx in range(visible_rows):
            ep_idx = idx + left_scroll
            if ep_idx >= len(endpoints):
                break
            ep      = endpoints[ep_idx]
            checked = ep_checked[ep_idx]
            box     = "[x]" if checked else "[ ]"
            label   = f"{box} {ep['method']:<7} {ep['path']}"
            label   = label[:left_w - 1]

            row = idx + 2
            if ep_idx == left_cursor and active_panel == 0:
                stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
                stdscr.addstr(row, 1, label.ljust(left_w - 1)[:left_w - 1])
                stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)
            elif checked:
                stdscr.attron(curses.color_pair(2))
                stdscr.addstr(row, 1, label[:left_w - 1])
                stdscr.attroff(curses.color_pair(2))
            else:
                stdscr.attron(curses.A_DIM)
                stdscr.addstr(row, 1, label[:left_w - 1])
                stdscr.attroff(curses.A_DIM)

        # scroll indicator
        if len(endpoints) > visible_rows:
            pct = int((left_scroll / max(1, len(endpoints) - visible_rows)) * 100)
            stdscr.addstr(h - 2, 1, f"  {left_scroll+1}-{min(left_scroll+visible_rows, len(endpoints))}/{len(endpoints)}"[:left_w])

        # ── right panel: objects ─────────────────────────────────────────
        for idx, suffix in enumerate(obj_list):
            checked = obj_checked[idx]
            box     = "[x]" if checked else "[ ]"
            label   = f"{box} {OBJECT_LABELS[suffix]}"
            row     = idx + 2

            if row >= h - 1:
                break

            if idx == right_cursor and active_panel == 1:
                stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
                stdscr.addstr(row, right_x, label.ljust(right_w)[:right_w])
                stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)
            elif checked:
                stdscr.attron(curses.color_pair(2))
                stdscr.addstr(row, right_x, label[:right_w])
                stdscr.attroff(curses.color_pair(2))
            else:
                stdscr.attron(curses.A_DIM)
                stdscr.addstr(row, right_x, label[:right_w])
                stdscr.attroff(curses.A_DIM)

        stdscr.refresh()

        key = stdscr.getch()

        if key in (ord('q'), ord('Q')):
            return None

        elif key == ord('\n'):  # Enter — generate
            checked_eps = [ep for i, ep in enumerate(endpoints) if ep_checked[i]]
            checked_obj = [obj_list[i] for i in range(len(obj_list)) if obj_checked[i]]
            return checked_eps, checked_obj

        elif key == ord('\t'):  # Tab — switch panels
            active_panel = 1 - active_panel

        elif key == ord(' '):  # Space — toggle
            if active_panel == 0 and endpoints:
                ep_checked[left_cursor] = not ep_checked[left_cursor]
            elif active_panel == 1 and obj_list:
                obj_checked[right_cursor] = not obj_checked[right_cursor]

        elif key == curses.KEY_UP:
            if active_panel == 0:
                left_cursor  = max(0, left_cursor - 1)
            else:
                right_cursor = max(0, right_cursor - 1)

        elif key == curses.KEY_DOWN:
            if active_panel == 0:
                left_cursor  = min(len(endpoints) - 1, left_cursor + 1)
            else:
                right_cursor = min(len(obj_list) - 1, right_cursor + 1)

        elif key == curses.KEY_PPAGE:  # PgUp
            if active_panel == 0:
                left_cursor = max(0, left_cursor - (h - 4))

        elif key == curses.KEY_NPAGE:  # PgDn
            if active_panel == 0:
                left_cursor = min(len(endpoints) - 1, left_cursor + (h - 4))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="ATHZ-02: Curses report builder from ATHZ_02.json"
    )
    p.add_argument(
        "--json",
        default=os.path.join("WSTG-ATHZ-02", "data", "json", "ATHZ_02.json"),
        metavar="PATH",
        help="Path to ATHZ_02.json"
    )
    p.add_argument(
        "--data",
        default=os.path.join("WSTG-ATHZ-02", "data"),
        metavar="DIR",
        help="Data directory (for wordlist file detection)"
    )
    p.add_argument(
        "--output",
        default=os.path.join("WSTG-ATHZ-02", "outputs", "test_outputs", "athz02_report.md"),
        metavar="PATH",
        help="Output report path"
    )
    return p.parse_args()


def main():
    args   = parse_args()
    data   = load_json(args.json)

    higher_users, lower_users = collect_users(data)
    all_usernames = higher_users + lower_users
    endpoints     = collect_endpoints(data)
    avail_objects = detect_available_objects(args.data, all_usernames)

    if not endpoints:
        print("[!] No authorization-relevant endpoints found. "
              "Ensure parse_athz02.py ran with --admin to mark higher-priv users.", file=sys.stderr)
        # Fall through — allow reporting on all endpoints anyway
        for folder_data in data.get("folders", {}).values():
            for user_data in folder_data.values():
                for ep_key, ep_data in user_data.get("endpoints", {}).items():
                    endpoints.append({
                        "ep_key": ep_key,
                        "method": ep_data.get("method", ""),
                        "path":   ep_data.get("path", ""),
                        "folder": "—",
                        "users":  [],
                    })
        # deduplicate
        seen_keys = set()
        dedup = []
        for ep in endpoints:
            if ep["ep_key"] not in seen_keys:
                seen_keys.add(ep["ep_key"])
                dedup.append(ep)
        endpoints = sorted(dedup, key=lambda x: x["ep_key"])

    if not avail_objects:
        print("[!] No object wordlist files found in data dir. "
              "Run parse_athz02.py and 2athz_tasks.py first.", file=sys.stderr)
        avail_objects = set(OBJECT_SUFFIXES)  # show all as unchecked stubs

    # Launch TUI
    result = curses.wrapper(tui, endpoints, avail_objects)

    if result is None:
        print("\n[!] Report generation cancelled.")
        return

    checked_eps, checked_objects = result

    if not checked_eps:
        print("[!] No endpoints selected — nothing to report.")
        return
    if not checked_objects:
        print("[!] No object types selected — nothing to report.")
        return

    report_md = build_report(
        full_json       = data,
        checked_eps     = checked_eps,
        checked_objects = checked_objects,
        higher_users    = higher_users,
        lower_users     = lower_users,
        data_dir        = args.data,
    )

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w") as f:
        f.write(report_md)

    print(f"\n{BOLD}[+] Report → {args.output}{RESET}")
    print(f"    {len(checked_eps)} endpoint(s) | {len(checked_objects)} object type(s)\n")


if __name__ == "__main__":
    main()
