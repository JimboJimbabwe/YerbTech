#!/usr/bin/env python3
"""
WSTG-ATHN-02 — Default Credentials
Script: athn_02_wordlist.py

Runs the service disseminator against how_to_steps_bridge.json for two
categories and saves the results as wordlists:

  default_creds.txt   — usernames, passwords, and credential pairs extracted
                        from service documentation steps (svc_dsr
                        "default_creds" category logic).

  default_paths.txt   — paths associated with login/auth/admin interfaces
                        extracted from the same steps (svc_dsr "paths"
                        category logic, filtered to auth-adjacent terms).

After building the lists, prints a manual login-attempt note instructing
the operator to try the found credentials against the found paths.

Usage:
  python3 WSTG-ATHN-02/utilities/python/athn_02_wordlist.py \\
      [--bridge  how_to_steps_bridge.json]

Outputs:
  WSTG-ATHN-02/inputs/wordlists/default_creds.txt
  WSTG-ATHN-02/inputs/wordlists/default_paths.txt
  WSTG-ATHN-02/inputs/json/athn_02_creds.json     (structured, for reference)
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
# Trigger sets — same format as svc_dsr input.txt built-in lists
# ---------------------------------------------------------------------------

CRED_TRIGGERS = [
    "admin", "root", "guest", "default", "anonymous",
    "credentials", "credential", "password", "passwd",
    "secret", "username", "changeme", "letmein",
    "admin123", "password123", "P@ssword",
    "default password", "default user", "initial password",
    "factory default", "out of the box",
    "api key", "api_key", "access token", "access_token",
    "login with", "sign in with", "authenticate with",
]

PATH_TRIGGERS = [
    # Auth/login endpoints specifically
    "login", "sign in", "signin", "sign-in",
    "logout", "signout", "sign-out",
    "authenticate", "authentication",
    "register", "registration", "signup", "sign-up",
    "forgot password", "reset password",
    "admin", "administration", "administrator",
    "console", "panel", "dashboard", "management",
    "/auth", "/oauth", "/sso", "/saml",
    "default credentials", "default password",
]


# ---------------------------------------------------------------------------
# Extractors — same patterns as svc_dsr.py
# ---------------------------------------------------------------------------

_CRED_EXTRACTOR = re.compile(
    '|'.join([
        r'(?:username|user)\s*[:=]\s*["\']?([a-zA-Z0-9_@.-]{1,40})',
        r'(?:password|passwd|pass)\s*[:=]\s*["\']?([a-zA-Z0-9!@#$%^&*._-]{1,40})',
        r'(?:admin|root|guest|anonymous|default)(?:[:/ ][a-zA-Z0-9!@#$%_.-]{1,30})?',
        r'changeme|letmein|admin123|password123|root123|P@ssword|'
        r'default|anonymous|guest|admin|root',
        r'default\s+(?:credentials?|password|user(?:name)?)',
        r'(?:secret|token|api[-_]key)\s*[:=]\s*["\']?[a-zA-Z0-9._\-]{4,}',
    ]),
    re.IGNORECASE
)

_PATH_EXTRACTOR = re.compile(
    '|'.join([
        r'\./[a-zA-Z0-9_.%/-]{2,}',
        r'~/[a-zA-Z0-9_./-]+',
        r'/[a-zA-Z0-9_.~-]+(?:/[a-zA-Z0-9_.~%/-]+)+',
        r'%[0-9A-Fa-f]{2}(?:[a-zA-Z0-9_%/=.+-]*)',
        # Single-segment auth paths
        r'/(?:login|logout|signin|signout|signup|register|'
        r'admin|administrator|console|dashboard|panel|management|'
        r'auth|oauth|oauth2|sso|saml|authenticate|'
        r'forgot-password|reset-password|change-password)(?:/[^\s\'"<>]*)?',
    ]),
    re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Bridge reader
# ---------------------------------------------------------------------------

def extract_from_bridge(bridge_path: str,
                        trigger_terms: list[str],
                        extractor: re.Pattern,
                        label: str) -> list[str]:
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
        '|'.join(re.escape(t) for t in trigger_terms),
        re.IGNORECASE
    )

    values  = []
    seen    = set()
    matched = 0

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
                        for m in extractor.finditer(step):
                            val = m.group(0).strip().rstrip('.,;:\'")')
                            if len(val) >= 2 and val not in seen:
                                seen.add(val)
                                values.append(val)

    print(f"  {DIM}{label}: {matched} matching items → {len(values)} unique values{RESET}")
    return values


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-ATHN-02 default credentials wordlist generator"
    )
    p.add_argument("--bridge",
        default="how_to_steps_bridge.json",
        metavar="PATH",
        help="Path to how_to_steps_bridge.json  (default: how_to_steps_bridge.json)")
    p.add_argument("--out-dir",
        default=os.path.join("WSTG-ATHN-02", "inputs"),
        metavar="DIR")
    args = p.parse_args()

    wordlist_dir = os.path.join(args.out_dir, "wordlists")
    json_dir     = os.path.join(args.out_dir, "json")
    os.makedirs(wordlist_dir, exist_ok=True)
    os.makedirs(json_dir,     exist_ok=True)

    creds_txt  = os.path.join(wordlist_dir, "default_creds.txt")
    paths_txt  = os.path.join(wordlist_dir, "default_paths.txt")
    json_out   = os.path.join(json_dir,     "athn_02_creds.json")

    width = 65
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD}  WSTG-ATHN-02 — Default Credentials Wordlist{RESET}")
    print(f"{BOLD}{'='*width}{RESET}\n")
    print(f"  Bridge: {args.bridge}\n")

    # ── Extract credentials ──────────────────────────────────────────────────
    print(f"  {BOLD}[1] Extracting default credentials{RESET}")
    creds = extract_from_bridge(args.bridge, CRED_TRIGGERS, _CRED_EXTRACTOR, "creds")

    # ── Extract paths ────────────────────────────────────────────────────────
    print(f"\n  {BOLD}[2] Extracting auth/login paths{RESET}")
    paths = extract_from_bridge(args.bridge, PATH_TRIGGERS, _PATH_EXTRACTOR, "paths")

    # ── Write wordlists ──────────────────────────────────────────────────────
    with open(creds_txt, "w", encoding="utf-8") as f:
        f.write("\n".join(creds) + ("\n" if creds else ""))

    with open(paths_txt, "w", encoding="utf-8") as f:
        f.write("\n".join(paths) + ("\n" if paths else ""))

    out = {
        "_meta": {
            "generated":    datetime.now().isoformat(),
            "bridge":       args.bridge,
            "creds_count":  len(creds),
            "paths_count":  len(paths),
        },
        "default_creds": creds,
        "default_paths": paths,
    }
    with open(json_out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    print(f"\n  {'─'*50}")
    print(f"  {GREEN}default_creds.txt{RESET}  {len(creds):>5} entries  →  {creds_txt}")
    print(f"  {GREEN}default_paths.txt{RESET}  {len(paths):>5} entries  →  {paths_txt}")
    print(f"  {GREEN}athn_02_creds.json{RESET} {len(creds)+len(paths):>5} total   →  {json_out}")

    # ── Manual testing note ──────────────────────────────────────────────────
    print(f"""
  {'═'*width}
  {BOLD}OPERATOR DUTY — WSTG-ATHN-02{RESET}
  {'═'*width}

  The wordlists above have been generated from service documentation.
  Login attempts must be performed manually — form field names and
  submission methods vary per application and cannot be automated here.

  {BOLD}Step 1 — Identify login interfaces{RESET}
    Review default_paths.txt. For each path:
      curl -sk https://TARGET§PATH§ -o /dev/null -w '%{{http_code}}\\n'
    A 200 or 302 indicates a login form or auth endpoint is present.

  {BOLD}Step 2 — Try default credentials{RESET}
    For each discovered login page, try credential pairs from
    default_creds.txt. Common pairings to try first:
      admin   : admin
      admin   : password
      admin   : admin123
      admin   : changeme
      root    : root
      root    : toor
      guest   : guest
      admin   : (blank)
      (blank) : (blank)

    Use Burp Intruder (Pitchfork or Cluster Bomb mode) to automate
    combination testing. Mark both the username and password fields
    as payload positions.

  {BOLD}Step 3 — Record findings{RESET}
    For any successful login:
      - Note the credential pair
      - Note the path / endpoint
      - Note the privilege level obtained
      - Note whether default credentials were changed from a known default

  {BOLD}Step 4 — API keys / tokens{RESET}
    default_creds.txt may contain API key or token patterns in addition
    to username/password pairs. Test these against:
      - API endpoints (Authorization: Bearer §token§)
      - Query string (api_key=§token§, token=§token§)

  {DIM}Reference: athn_02_creds.json contains the full structured output.{RESET}
  {'═'*width}
""")


if __name__ == "__main__":
    main()
