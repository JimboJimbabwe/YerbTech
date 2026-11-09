#!/usr/bin/env python3
"""
WSTG-ATHZ-02 — Bypassing Authorization Schema
Script 2: 2athz_tasks.py

Reads WSTG-ATHZ-02/data/*.txt files (produced by parse_athz02.py).
For each user:
  - Builds per-object-type wordlists → WSTG-ATHZ-02/data/<username>/<OBJECT>.txt
  - Identifies higher/lower privilege users from the JSON
  - Prints swap test suggestions:
      "For higher_priv user X, login and swap [objects] from lower user Y..."
      "For lower_priv user Y, login and swap [objects] from higher user X..."
  - Lists authorization-relevant endpoints to test on

Usage:
  python3 WSTG-ATHZ-02/utilities/python/2athz_tasks.py
  python3 WSTG-ATHZ-02/utilities/python/2athz_tasks.py \\
      --data-dir WSTG-ATHZ-02/data \\
      --json     WSTG-ATHZ-02/data/json/ATHZ_02.json
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path


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

# Object suffixes as written by parse_athz02.py
OBJECT_SUFFIXES = ["cookies", "JWTs", "UUIDs", "uniqueIDs", "headers"]

# Human-readable label for each suffix used in suggestions
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
        print(f"{RED}[!] JSON not found: {path}  — run parse_athz02.py first{RESET}",
              file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"{RED}[!] Invalid JSON: {e}{RESET}", file=sys.stderr)
        sys.exit(1)


def load_txt(path: str) -> list[str]:
    """Returns non-empty lines from a TXT file, or [] if missing."""
    try:
        with open(path) as f:
            return [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return []


# ---------------------------------------------------------------------------
# Discover TXT files for a username in data_dir
# Returns {suffix: [values]}
# ---------------------------------------------------------------------------

def load_user_objects(data_dir: str, username: str) -> dict[str, list[str]]:
    result = {}
    for suffix in OBJECT_SUFFIXES:
        fpath = os.path.join(data_dir, f"{username}_{suffix}.txt")
        values = load_txt(fpath)
        result[suffix] = values
    return result


# ---------------------------------------------------------------------------
# Build per-user per-object wordlists in data/<username>/
# ---------------------------------------------------------------------------

def build_wordlists(data_dir: str, username: str, objects: dict[str, list[str]]) -> dict[str, str]:
    """
    Writes one wordlist per object type into data/<username>/<OBJECT>.txt
    Returns {suffix: filepath} for non-empty lists.
    """
    user_dir = os.path.join(data_dir, username)
    os.makedirs(user_dir, exist_ok=True)
    written = {}
    for suffix, values in objects.items():
        if not values:
            continue
        out_path = os.path.join(user_dir, f"{suffix}.txt")
        with open(out_path, "w") as f:
            f.write("\n".join(values) + "\n")
        written[suffix] = out_path
    return written


# ---------------------------------------------------------------------------
# Identify authorization-relevant endpoints from JSON
# These are endpoints that appear for higher-priv users that lower-priv
# users might attempt to reach — or vice versa for privilege escalation.
# ---------------------------------------------------------------------------

def find_auth_endpoints(full_json: dict) -> list[str]:
    """
    Returns deduplicated list of endpoint keys ("METHOD /path") that:
      - Appear in higher_priv user walks, OR
      - Have differential headers (suggesting role-specific access controls)
    These are the endpoints worth swapping tokens on.
    """
    higher_eps: set[str] = set()
    diff_header_eps: set[str] = set()

    for folder_name, folder_data in full_json.get("folders", {}).items():
        for username, user_data in folder_data.items():
            role = user_data.get("role", "lower_priv")
            for ep_key, ep_data in user_data.get("endpoints", {}).items():
                if role == "higher_priv":
                    higher_eps.add(ep_key)
                if ep_data.get("diff_headers"):
                    diff_header_eps.add(ep_key)

    # Union: any endpoint that is privilege-linked or shows differential headers
    return sorted(higher_eps | diff_header_eps)


# ---------------------------------------------------------------------------
# Print swap suggestions
# ---------------------------------------------------------------------------

def print_suggestions(
    higher_users: list[str],
    lower_users:  list[str],
    object_labels: list[str],
    auth_endpoints: list[str],
):
    obj_str = " / ".join(object_labels) if object_labels else "cookies/UUID/JWT/uniqueURLid"

    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"{BOLD} ATHZ-02 — Swap Test Suggestions{RESET}")
    print(f"{BOLD}{'='*65}{RESET}\n")

    if not higher_users:
        print(f"  {YELLOW}No higher_priv users identified. All users treated as lower_priv.")
        print(f"  Re-run parse_athz02.py with --admin <filename> to assign roles.{RESET}\n")

    for high in higher_users:
        for low in lower_users:
            print(f"  {CYAN}[HIGHER → LOWER swap]{RESET}")
            print(f"  For higher privilege user {BOLD}{high}{RESET}, login and swap "
                  f"{obj_str} from lower user {BOLD}{low}{RESET}, "
                  f"while {low} is logged out.")
            print()
            print(f"  {CYAN}[LOWER → HIGHER swap]{RESET}")
            print(f"  For lower privilege user {BOLD}{low}{RESET}, login and swap "
                  f"{obj_str} from higher user {BOLD}{high}{RESET}, "
                  f"while {high} is logged out.")
            print()

    if not higher_users and lower_users:
        for i, u1 in enumerate(lower_users):
            for u2 in lower_users[i+1:]:
                print(f"  {CYAN}[PEER swap — same role]{RESET}")
                print(f"  For user {BOLD}{u1}{RESET}, login and swap {obj_str} "
                      f"from user {BOLD}{u2}{RESET}, while {u2} is logged out.")
                print()

    if auth_endpoints:
        print(f"  {BOLD}Do this on the following authorization-relevant endpoints:{RESET}")
        for ep in auth_endpoints:
            print(f"    • {ep}")
    else:
        print(f"  {YELLOW}No authorization-relevant endpoints identified "
              f"(no higher_priv walks or differential headers found).{RESET}")
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="ATHZ-02: Build per-user wordlists and print swap test suggestions"
    )
    p.add_argument(
        "--data-dir",
        default=os.path.join("WSTG-ATHZ-02", "data"),
        metavar="DIR",
        help="Data directory containing username_*.txt files"
    )
    p.add_argument(
        "--json",
        default=os.path.join("WSTG-ATHZ-02", "data", "json", "ATHZ_02.json"),
        metavar="PATH",
        help="Path to ATHZ_02.json produced by parse_athz02.py"
    )
    return p.parse_args()


def main():
    args = parse_args()

    print()
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"{BOLD} WSTG-ATHZ-02 — Wordlist Builder & Task Suggester{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"  Data dir : {args.data_dir}")
    print(f"  JSON     : {args.json}")
    print()

    full_json    = load_json(args.json)
    auth_endpoints = find_auth_endpoints(full_json)

    higher_users: list[str] = []
    lower_users:  list[str] = []
    all_object_suffixes_used: set[str] = set()

    # Process each user across all folders
    for folder_name, folder_data in full_json.get("folders", {}).items():
        print(f"{CYAN}{BOLD}  Folder: {folder_name}{RESET}")
        for username, user_data in folder_data.items():
            role = user_data.get("role", "lower_priv")
            objects = load_user_objects(args.data_dir, username)

            # Track which object types have any values at all
            populated = {s: v for s, v in objects.items() if v}
            all_object_suffixes_used |= set(populated.keys())

            # Build per-user wordlist files
            written = build_wordlists(args.data_dir, username, populated)

            role_badge = f"{RED}higher_priv{RESET}" if role == "higher_priv" else f"{DIM}lower_priv{RESET}"
            print(f"    {BOLD}{username}{RESET} [{role_badge}]")
            for suffix, fpath in written.items():
                count = len(objects[suffix])
                print(f"      {GREEN}→ {fpath}{RESET}  ({count} entries)")

            if not written:
                print(f"      {DIM}(no objects extracted — check parse_athz02.py output){RESET}")

            if role == "higher_priv":
                if username not in higher_users:
                    higher_users.append(username)
            else:
                if username not in lower_users:
                    lower_users.append(username)
        print()

    # Build human-readable object labels for suggestion strings
    object_labels = [OBJECT_LABELS[s] for s in OBJECT_SUFFIXES if s in all_object_suffixes_used]

    print_suggestions(higher_users, lower_users, object_labels, auth_endpoints)

    print(f"  {GREEN}[+] Done. Next:{RESET}")
    print(f"  python3 WSTG-ATHZ-02/utilities/python/athz_reporting.py")
    print()


if __name__ == "__main__":
    main()
