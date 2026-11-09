#!/usr/bin/env python3
"""
WSTG-CONF-05 — Enumerate Infrastructure and Admin Interfaces
Script: conf_05_wordlist.py

Builds two focused wordlists for probing admin/management interfaces:

  1. config_actual.txt   — paths extracted from the service disseminator
                           bridge JSON (how_to_steps_bridge.json).
                           These come from real service documentation so they
                           reflect actual paths the platform may expose.
                           Pulled via the --paths flag (same trigger/extractor
                           logic as svc_dsr.py "paths" category).

  2. possible_defaults.txt — paths from svc_repo.json (DefaultEndpoints +
                             CommonEndpoints + UndesirableEndpoints across all
                             Ports → PotentialServices entries).
                             These are known default paths for the detected
                             service, and are higher-confidence guesses for
                             what an admin interface might live at.

After generating the lists, the script prints a manual testing note:
  "Test the below endpoints by fuzzing their URL path (OBJ1, OBJ2, etc.)
   with path traversal payloads derived from actual service documentation."

This test case does NOT have a verdict script — fuzz results are reviewed
manually or fed into conf_02_verdict.py if response classification is needed.

Usage:
  python3 WSTG-CONF-05/utilities/python/conf_05_wordlist.py \\
      [--bridge  how_to_steps_bridge.json] \\
      [--repo    WSTG-CONF-05/inputs/json/svc_repo.json] \\
      [--paths   WSTG-CONF-05/inputs/txt/dsr_triggers.txt]

  --bridge  Path to how_to_steps_bridge.json (svc_dsr source data).
            If absent, config_actual.txt is skipped with a warning.
  --repo    Path to svc_repo.json for default-path extraction.
            If absent, possible_defaults.txt is skipped with a warning.
  --paths   Optional trigger file for the disseminator pass.
            Uses the built-in admin/config trigger set if omitted.

Outputs:
  WSTG-CONF-05/inputs/wordlists/config_actual.txt
  WSTG-CONF-05/inputs/wordlists/possible_defaults.txt
  WSTG-CONF-05/inputs/json/conf_05_paths.json   (combined, categorised)
"""

import argparse
import json
import os
import re
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
RESET   = "\033[0m"


# ---------------------------------------------------------------------------
# Built-in admin/config trigger set
# Used when no --paths trigger file is provided.
# These are the terms that, when found in a how-to step, indicate the step
# is talking about an admin panel, config path, or management interface.
# ---------------------------------------------------------------------------

BUILTIN_TRIGGERS = [
    # Admin / management
    "admin",
    "administration",
    "administrator",
    "manage",
    "management",
    "manager",
    "console",
    "panel",
    "control panel",
    "dashboard",
    "cpanel",
    # Config / settings
    "config",
    "configuration",
    "configure",
    "settings",
    "setup",
    "preferences",
    "/conf/",
    "/config/",
    # Debug
    "debug",
    "diagnostics",
    "diagnostic",
    # Monitoring / metrics
    "monitoring",
    "monitor",
    "metrics",
    "health",
    "status",
    "actuator",
    # Specific well-known admin paths
    "/phpMyAdmin",
    "/phpmyadmin",
    "wp-admin",
    "wp-login",
    "/manager/html",
    "/host-manager",
    "/jmx-console",
    "/web-console",
    "/invoker",
    "/struts",
    "/axis2",
    "/axis",
    "webadmin",
    "sitemanager",
    "/ControlPanel",
    # Auth-adjacent (login pages to admin areas)
    "login",
    "sign in",
    "authenticate",
    # Default/backdoor
    "default credentials",
    "default password",
    "initial password",
    "factory default",
]

# ---------------------------------------------------------------------------
# Path extractor pattern — same as svc_dsr.py "paths" category
# ---------------------------------------------------------------------------

_PATH_EXTRACTOR = re.compile(
    '|'.join([
        r'\./[a-zA-Z0-9_.%/-]{2,}',                       # ./relative/path
        r'~/[a-zA-Z0-9_./-]+',                             # ~/home/relative
        r'/[a-zA-Z0-9_.~-]+(?:/[a-zA-Z0-9_.~%/-]+)+',    # /absolute/two/levels+
        r'%[0-9A-Fa-f]{2}(?:[a-zA-Z0-9_%/=.+-]*)',        # URL-encoded sequences
        # Single-segment paths that look like admin endpoints
        r'/(?:admin|manager|console|dashboard|panel|'
        r'config|configuration|settings|manage|management|'
        r'actuator|debug|diagnostics|monitoring|metrics|'
        r'health|status|phpMyAdmin|phpmyadmin|pma|'
        r'wp-admin|wp-login|jmx-console|web-console|'
        r'host-manager|struts|axis2|axis|webadmin|'
        r'cpanel|controlpanel|sitemanager|portal|'
        r'ControlPanel|AdminPanel|administrator)(?:/[^\s\'"<>]*)?',
    ]),
    re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Trigger builder — same logic as svc_dsr.py
# ---------------------------------------------------------------------------

def build_triggers_from_file(path: str):
    """Parse a trigger file → compiled regex. Same format as svc_dsr input.txt."""
    patterns = []
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            if line.lower().startswith('regex:'):
                patterns.append(line[6:])
            else:
                patterns.append(re.escape(line))
    if not patterns:
        raise ValueError(f"No trigger patterns in {path}")
    return re.compile('|'.join(patterns), re.IGNORECASE)


def build_triggers_from_list(terms: list[str]):
    """Build compiled regex from the built-in trigger list."""
    patterns = [re.escape(t) for t in terms]
    return re.compile('|'.join(patterns), re.IGNORECASE)


# ---------------------------------------------------------------------------
# Bridge reader — extracts paths from matching steps
# ---------------------------------------------------------------------------

def extract_paths_from_bridge(bridge_path: str, trigger_re) -> list[str]:
    """
    Walk how_to_steps_bridge.json, find steps that match trigger_re,
    extract path-like values with _PATH_EXTRACTOR.
    Returns deduplicated list preserving first-seen order.
    """
    try:
        with open(bridge_path, encoding="utf-8") as f:
            bridge = json.load(f)
    except FileNotFoundError:
        print(f"  {RED}[!] Bridge file not found: {bridge_path}{RESET}", file=sys.stderr)
        return []
    except json.JSONDecodeError as e:
        print(f"  {RED}[!] Bridge JSON parse error: {e}{RESET}", file=sys.stderr)
        return []

    paths = []
    seen  = set()
    matched_items = 0

    for svc in bridge.get('Services', {}).values():
        for ch in svc.get('Chapters', {}).values():
            for l2 in ch.get('Subchapters', {}).values():
                for item in l2.get('How_To_Inventory', []):
                    steps = item.get('Steps', [])
                    triggered = [s for s in steps if trigger_re.search(s)]
                    if not triggered:
                        continue
                    matched_items += 1
                    for step in triggered:
                        for m in _PATH_EXTRACTOR.finditer(step):
                            val = m.group(0).strip().rstrip('.,;:\'")')
                            if len(val) >= 2 and val not in seen:
                                seen.add(val)
                                paths.append(val)

    print(f"  {DIM}Bridge: {matched_items} matching items → {len(paths)} unique paths{RESET}")
    return paths


# ---------------------------------------------------------------------------
# svc_repo.json reader — same logic as BUSL-08 / CONF-02
# ---------------------------------------------------------------------------

def get_svc_repo_paths(repo_path: str) -> list[str]:
    """
    Reads svc_repo.json:
      Ports[] → PotentialServices[] →
        DefaultEndpoints + CommonEndpoints + UndesirableEndpoints
    Returns deduplicated list preserving order.
    """
    try:
        with open(repo_path, encoding="utf-8") as f:
            repo = json.load(f)
    except FileNotFoundError:
        print(f"  {YELLOW}[!] svc_repo.json not found at {repo_path} — skipping{RESET}")
        return []
    except json.JSONDecodeError as e:
        print(f"  {RED}[!] svc_repo.json parse error: {e} — skipping{RESET}")
        return []

    paths = []
    seen  = set()

    for port_entry in repo.get("Ports", []):
        for svc in port_entry.get("PotentialServices", []):
            for key in ("DefaultEndpoints", "CommonEndpoints", "UndesirableEndpoints"):
                for ep in svc.get(key, []):
                    ep = ep.strip()
                    if ep and ep not in seen:
                        seen.add(ep)
                        paths.append(ep)

    print(f"  {DIM}svc_repo.json: {len(paths)} paths loaded{RESET}")
    return paths


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-CONF-05 admin/config path wordlist generator"
    )
    p.add_argument("--bridge",
        default="how_to_steps_bridge.json",
        metavar="PATH",
        help="Path to how_to_steps_bridge.json  (default: how_to_steps_bridge.json)")
    p.add_argument("--repo",
        default=os.path.join("WSTG-CONF-05", "inputs", "json", "svc_repo.json"),
        metavar="PATH",
        help="Path to svc_repo.json")
    p.add_argument("--paths",
        default="",
        metavar="PATH",
        help="Optional trigger file (svc_dsr input.txt format). "
             "Uses built-in admin/config triggers if omitted.")
    p.add_argument("--wordlist-actual",
        default=os.path.join("WSTG-CONF-05", "inputs", "wordlists", "config_actual.txt"),
        metavar="PATH")
    p.add_argument("--wordlist-defaults",
        default=os.path.join("WSTG-CONF-05", "inputs", "wordlists", "possible_defaults.txt"),
        metavar="PATH")
    p.add_argument("--json-out",
        default=os.path.join("WSTG-CONF-05", "inputs", "json", "conf_05_paths.json"),
        metavar="PATH")
    args = p.parse_args()

    width = 65
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD}  WSTG-CONF-05 — Admin Interface Path Wordlist{RESET}")
    print(f"{BOLD}{'='*width}{RESET}\n")

    # ── Build trigger set ────────────────────────────────────────────────────
    if args.paths:
        print(f"  Trigger file : {args.paths}")
        try:
            trigger_re = build_triggers_from_file(args.paths)
        except (ValueError, OSError) as e:
            print(f"  {RED}[!] Could not load trigger file: {e}{RESET}", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"  Trigger file : {DIM}(using built-in admin/config trigger set){RESET}")
        trigger_re = build_triggers_from_list(BUILTIN_TRIGGERS)

    # ── Source 1: bridge → config_actual.txt ────────────────────────────────
    print(f"\n  {BOLD}[1] Service disseminator bridge{RESET}")
    print(f"      {args.bridge}")
    actual_paths = extract_paths_from_bridge(args.bridge, trigger_re)

    # ── Source 2: svc_repo.json → possible_defaults.txt ─────────────────────
    print(f"\n  {BOLD}[2] svc_repo.json default paths{RESET}")
    print(f"      {args.repo}")
    default_paths = get_svc_repo_paths(args.repo)

    # ── Write wordlists ──────────────────────────────────────────────────────
    os.makedirs(os.path.dirname(args.wordlist_actual),   exist_ok=True)
    os.makedirs(os.path.dirname(args.wordlist_defaults), exist_ok=True)
    os.makedirs(os.path.dirname(args.json_out),          exist_ok=True)

    with open(args.wordlist_actual, "w", encoding="utf-8") as f:
        f.write("\n".join(actual_paths) + ("\n" if actual_paths else ""))

    with open(args.wordlist_defaults, "w", encoding="utf-8") as f:
        f.write("\n".join(default_paths) + ("\n" if default_paths else ""))

    # Combined JSON
    all_paths = list(dict.fromkeys(actual_paths + default_paths))  # deduped, order preserved
    json_out = {
        "_meta": {
            "generated":        datetime.now().isoformat(),
            "bridge_source":    args.bridge,
            "repo_source":      args.repo,
            "trigger_file":     args.paths or "(built-in)",
            "actual_count":     len(actual_paths),
            "defaults_count":   len(default_paths),
            "combined_count":   len(all_paths),
        },
        "config_actual":     actual_paths,
        "possible_defaults": default_paths,
        "combined":          all_paths,
    }
    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(json_out, f, indent=2)

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n  {'─'*50}")
    print(f"  {GREEN}config_actual.txt{RESET}      {len(actual_paths):>5} paths  →  {args.wordlist_actual}")
    print(f"  {GREEN}possible_defaults.txt{RESET}  {len(default_paths):>5} paths  →  {args.wordlist_defaults}")
    print(f"  {GREEN}conf_05_paths.json{RESET}     {len(all_paths):>5} total  →  {args.json_out}")

    # ── Manual testing note ──────────────────────────────────────────────────
    print(f"""
  {'═'*width}
  {BOLD}MANUAL TESTING NOTE — WSTG-CONF-05{RESET}
  {'═'*width}

  Test the endpoints in both wordlists by fuzzing their URL path
  (OBJ1, OBJ2, etc.) with path traversal payloads derived from
  actual service documentation.

  Suggested workflow:

    1. Load config_actual.txt into Burp Intruder (Sniper).
       These paths come from real service docs — if the service is
       running, these are routes that genuinely exist or existed.
       Mark the path segment of interest as the §payload§ position.

    2. Load possible_defaults.txt as a second Intruder run.
       These are known default endpoints for the detected service
       type. An admin interface at a default path is a direct finding.

    3. For any 200/302 hit — attempt path traversal from that base:
         §base_path§/../../../etc/passwd
         §base_path§/%2F..%2F..%2Fetc%2Fpasswd
         §base_path§/..%5c..%5cetc%5cpasswd
       Payloads can be sourced from the CONF-02 dotslash wordlist:
         WSTG-CONF-02/inputs/wordlist/conf_02_paths.txt

    4. For any discovered admin panel — attempt default credentials
       before any further exploitation (cross-reference svc_dsr.py
       Default_Creds output for this service).

  {DIM}Note: classify responses with conf_02_verdict.py if needed.{RESET}
  {'═'*width}
""")


if __name__ == "__main__":
    main()
