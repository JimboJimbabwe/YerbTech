#!/usr/bin/env python3
"""
WSTG-SESS-04 — Testing for Exposed Session Variables
Script: svc_env_grab.py

Runs the service disseminator bridge logic for the "env_vars" category
against how_to_steps_bridge.json and writes the results as a flat
wordlist for use by sess_04_analyze.py.

Env-var triggers pull strings like:
  $APP_SECRET, SESSION_KEY, JWT_SECRET, DB_PASSWORD, AWS_ACCESS_KEY_ID,
  REDIS_URL, OAUTH_CLIENT_SECRET, API_KEY, AUTH_TOKEN, etc.

This is a minimal shim — it applies the same trigger/extractor pipeline
that svc_dsr.py uses for its env_vars category, standalone, with output
wired to WSTG-SESS-04 paths.

Usage:
  python3 WSTG-SESS-04/utilities/python/svc_env_grab.py \\
      [--bridge  how_to_steps_bridge.json]

Outputs:
  WSTG-SESS-04/inputs/data/wordlist.txt      (flat, one env var per line)
  WSTG-SESS-04/inputs/data/env_vars.json     (structured with metadata)
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
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
RESET  = "\033[0m"


# ---------------------------------------------------------------------------
# Trigger set — env_vars category (same as svc_dsr.py)
# ---------------------------------------------------------------------------

ENV_TRIGGERS = [
    # Generic env-var patterns
    "environment variable",
    "env var",
    "env variable",
    "export ",
    "set ",
    "$",
    # Common secret/config variable names
    "SECRET", "secret",
    "SESSION", "session",
    "JWT", "jwt",
    "TOKEN", "token",
    "API_KEY", "api_key", "api key",
    "AUTH", "auth",
    "PASSWORD", "password", "passwd",
    "PASSWD",
    "DATABASE_URL", "database url",
    "DB_PASSWORD", "DB_HOST", "DB_USER",
    "REDIS_URL", "redis url",
    "AWS_ACCESS_KEY", "AWS_SECRET_KEY", "AWS_SESSION_TOKEN",
    "OAUTH", "oauth",
    "CLIENT_SECRET", "client secret",
    "PRIVATE_KEY", "private key",
    "ENCRYPTION_KEY", "encryption key",
    "SIGNING_KEY", "signing key",
    "MASTER_KEY", "master key",
    "APP_KEY", "app key",
    "FLASK_SECRET", "DJANGO_SECRET",
    "RAILS_SECRET",
    "NODE_ENV",
    "DEBUG", "debug",
    # Generic variable assignment forms
    "=secret", "=password", "=token", "=key",
    ".env",
    "dotenv",
    "config.py", "settings.py",
    "application.yml", "application.properties",
]


# ---------------------------------------------------------------------------
# Extractor — pulls env-var-like strings from matched steps
# ---------------------------------------------------------------------------

_ENV_EXTRACTOR = re.compile(
    '|'.join([
        # $VAR or ${VAR} shell syntax
        r'\$\{?[A-Z][A-Z0-9_]{2,}\}?',
        # UPPER_SNAKE_CASE assignments  KEY=value or KEY="value"
        r'[A-Z][A-Z0-9_]{2,}(?==)',
        # export KEY or set KEY
        r'(?:export|set)\s+([A-Z][A-Z0-9_]{2,})',
        # Standalone common names (allow mixed case)
        r'(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|AUTH|'
        r'SESSION|JWT|OAUTH|PRIVATE_KEY|ENCRYPTION_KEY|'
        r'SIGNING_KEY|MASTER_KEY|CLIENT_SECRET|ACCESS_KEY|'
        r'DATABASE_URL|REDIS_URL|FLASK_SECRET|DJANGO_SECRET|'
        r'RAILS_SECRET|APP_KEY|APP_SECRET|NODE_ENV|'
        r'AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)'
        r'(?:_[A-Z0-9]+)*',
    ]),
    re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Bridge reader
# ---------------------------------------------------------------------------

def extract_env_vars(bridge_path: str) -> list[str]:
    try:
        with open(bridge_path, encoding="utf-8") as f:
            bridge = json.load(f)
    except FileNotFoundError:
        print(f"  {RED}[!] Bridge file not found: {bridge_path}{RESET}", file=sys.stderr)
        return []
    except json.JSONDecodeError as e:
        print(f"  {RED}[!] Bridge JSON parse error: {e}{RESET}", file=sys.stderr)
        return []

    trigger_re = re.compile(
        '|'.join(re.escape(t) for t in ENV_TRIGGERS),
        re.IGNORECASE
    )

    vars_found = []
    seen       = set()
    matched    = 0

    for svc in bridge.get('Services', {}).values():
        for ch in svc.get('Chapters', {}).values():
            for l2 in ch.get('Subchapters', {}).values():
                for item in l2.get('How_To_Inventory', []):
                    steps     = item.get('Steps', [])
                    triggered = [s for s in steps if trigger_re.search(s)]
                    if not triggered:
                        continue
                    matched += 1
                    for step in triggered:
                        for m in _ENV_EXTRACTOR.finditer(step):
                            raw = m.group(0).strip(" \t${}\"'")
                            if len(raw) >= 3 and raw not in seen:
                                seen.add(raw)
                                vars_found.append(raw)

    print(f"  {DIM}Bridge: {matched} matching items → {len(vars_found)} unique env vars{RESET}")
    return vars_found


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-SESS-04 env-var wordlist generator"
    )
    p.add_argument("--bridge",
        default="how_to_steps_bridge.json",
        metavar="PATH",
        help="Path to how_to_steps_bridge.json  (default: how_to_steps_bridge.json)")
    p.add_argument("--out-dir",
        default=os.path.join("WSTG-SESS-04", "inputs", "data"),
        metavar="DIR")
    args = p.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    wordlist_path = os.path.join(args.out_dir, "wordlist.txt")
    json_path     = os.path.join(args.out_dir, "env_vars.json")

    width = 65
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD}  WSTG-SESS-04 — Env Var Wordlist (svc_env_grab){RESET}")
    print(f"{BOLD}{'='*width}{RESET}\n")
    print(f"  Bridge : {args.bridge}\n")

    env_vars = extract_env_vars(args.bridge)

    with open(wordlist_path, "w", encoding="utf-8") as f:
        f.write("\n".join(env_vars) + ("\n" if env_vars else ""))

    out = {
        "_meta": {
            "generated":  datetime.now().isoformat(),
            "bridge":     args.bridge,
            "count":      len(env_vars),
            "category":   "env_vars",
            "consumer":   "sess_04_analyze.py",
        },
        "env_vars": env_vars,
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    print(f"  {'─'*50}")
    print(f"  {GREEN}wordlist.txt{RESET}  {len(env_vars):>5} entries  →  {wordlist_path}")
    print(f"  {GREEN}env_vars.json{RESET} {len(env_vars):>5} entries  →  {json_path}")
    print(f"\n  {DIM}Pass wordlist.txt to sess_04_analyze.py via --wordlist{RESET}\n")


if __name__ == "__main__":
    main()
