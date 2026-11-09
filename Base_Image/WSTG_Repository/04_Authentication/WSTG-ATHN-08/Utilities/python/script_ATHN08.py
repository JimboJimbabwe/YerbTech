#!/usr/bin/env python3
"""
WSTG-ATHN-08 — Testing for Weak Security Questions / Answers
OSINT Dork Generator: script_ATHN08.py

Builds combinatorial Google dork strings by crossing:
  • Personal identifiers (name, email, username, URL, org, …) from optionals JSON
  • Security question keywords (pet name, mother's maiden name, …) from secq_keywords.txt
  • Infrastructure/site operators (site:pastebin.com, filetype:txt, …) from infra keywords

Output:
  dork_test.txt  — one dork string per line (ready to paste into Google)
  dork_test.json — flat payloads array + combinatorial_map showing how each was built

Usage:
  python3 utilities/python/script_ATHN08.py \\
    --security_questions inputs/data/secq_keywords.txt \\
    --optionals          inputs/data/optionals_keywords.json \\
    --infrastructure     inputs/data/infrastructure_keywords.txt \\
    --username           jsmith \\
    --output             inputs/wordlist/dork_test.txt \\
    --output_json        inputs/wordlist/dork_test.json

  # username is optional if already set in optionals_keywords.json
"""

import argparse
import itertools
import json
import os
import re
import sys
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_lines(path: str, label: str) -> list[str]:
    """Load non-empty, non-comment lines from a plain text file."""
    try:
        with open(path) as f:
            return [
                ln.strip() for ln in f
                if ln.strip() and not ln.strip().startswith('#')
            ]
    except FileNotFoundError:
        print(f"[!] {label} not found: {path}", file=sys.stderr)
        sys.exit(1)


def load_optionals(path: str) -> dict:
    """Load optional personal identifiers from JSON. Returns {field: value}."""
    try:
        with open(path) as f:
            raw = json.load(f)
    except FileNotFoundError:
        print(f"[!] Optionals file not found: {path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON in optionals file: {e}", file=sys.stderr)
        sys.exit(1)

    result = {}
    for key, entry in raw.items():
        if key.startswith('_'):
            continue
        val = entry.get("value", "") if isinstance(entry, dict) else str(entry)
        if val and val.strip():
            result[key] = val.strip()
    return result


# ---------------------------------------------------------------------------
# Dork building logic
# ---------------------------------------------------------------------------

def quote(s: str) -> str:
    """Wrap a plain string in double quotes for Google dork exact-match."""
    s = s.strip()
    # Already has site:, filetype:, inurl:, intitle:, etc. → no quotes
    if re.match(r'^(site:|filetype:|inurl:|intitle:|intext:|")', s):
        return s
    return f'"{s}"'


def build_personal_terms(optionals: dict, cli_username: str) -> dict:
    """
    Build a named map of personal dork terms from optionals + CLI username.
    Returns {label: dork_term} for use in combinations.
    """
    terms = {}

    def add(label: str, raw: str):
        if raw:
            terms[label] = quote(raw)

    add("first_name",   optionals.get("first_name", ""))
    add("last_name",    optionals.get("last_name", ""))
    add("email",        optionals.get("email", ""))
    add("email_prefix", optionals.get("email_prefix", ""))
    add("organisation", optionals.get("organisation", ""))
    add("location",     optionals.get("location", ""))
    add("phone",        optionals.get("phone", ""))

    # Full name composite
    fn = optionals.get("first_name", "")
    ln = optionals.get("last_name", "")
    if fn and ln:
        terms["full_name"] = quote(f"{fn} {ln}")

    # URL — use as site: operator
    url = optionals.get("url", "")
    if url:
        domain = re.sub(r'^https?://', '', url).split('/')[0]
        terms["url_site"] = f"site:{domain}"

    # Username — CLI arg takes precedence
    username = cli_username or optionals.get("username", "")
    if username:
        terms["username"] = quote(username)

    return terms


def generate_dorks(
    personal:  dict,      # {label: dork_term}
    secq:      list[str], # security question keywords (plain text)
    infra:     list[str], # infrastructure operators (may already have site:/filetype: etc.)
) -> tuple[list[str], list[dict]]:
    """
    Generate combinatorial dork strings and a combinatorial map.

    Combination strategy:
      Tier 1: personal_term + secq_keyword  (identity × question)
      Tier 2: personal_term + secq_keyword + infra_operator  (full dork)
      Tier 3: infra_operator + secq_keyword  (site/filetype × question, no personal)
      Tier 4: full_name (or username) + infra_operator  (identity × site, no question)

    Returns:
      payloads      — deduplicated list of dork strings
      combo_map     — list of {dork, components: {personal, secq, infra}} dicts
    """
    seen = set()
    payloads = []
    combo_map = []

    def add(dork: str, components: dict):
        d = dork.strip()
        if d and d not in seen:
            seen.add(d)
            payloads.append(d)
            combo_map.append({"dork": d, "components": components})

    secq_quoted = [quote(k) for k in secq]
    infra_terms = [i.strip() for i in infra]

    # -----------------------------------------------------------------------
    # Tier 1: personal + secq
    # -----------------------------------------------------------------------
    for p_label, p_term in personal.items():
        for sq in secq_quoted:
            add(f"{p_term} {sq}", {"personal": p_label, "secq": sq, "infra": None})

    # -----------------------------------------------------------------------
    # Tier 2: personal + secq + infra (full dork)
    # -----------------------------------------------------------------------
    for p_label, p_term in personal.items():
        for sq in secq_quoted:
            for inf in infra_terms:
                add(
                    f"{inf} {p_term} {sq}",
                    {"personal": p_label, "secq": sq, "infra": inf}
                )

    # -----------------------------------------------------------------------
    # Tier 3: infra + secq (site/filetype scoped, identity-agnostic)
    # -----------------------------------------------------------------------
    for inf in infra_terms:
        for sq in secq_quoted:
            add(f"{inf} {sq}", {"personal": None, "secq": sq, "infra": inf})

    # -----------------------------------------------------------------------
    # Tier 4: identity + infra (no secq — general OSINT sweeps)
    # For efficiency, only use high-value personal terms
    # -----------------------------------------------------------------------
    high_value = {k: v for k, v in personal.items()
                  if k in ("full_name", "email", "username")}
    for p_label, p_term in high_value.items():
        for inf in infra_terms:
            add(f"{inf} {p_term}", {"personal": p_label, "secq": None, "infra": inf})

    return payloads, combo_map


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------

def write_txt(path: str, payloads: list[str]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, 'w') as f:
        for d in payloads:
            f.write(d + "\n")


def write_json(path: str, payloads: list[str], combo_map: list[dict], meta: dict) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    out = {
        "wstg_id":            "WSTG-ATHN-08",
        "title":              "Security Question OSINT Dork Strings",
        "generated":          datetime.now(timezone.utc).isoformat(),
        "meta":               meta,
        "payloads":           payloads,
        "combinatorial_map":  combo_map,
    }
    with open(path, 'w') as f:
        json.dump(out, f, indent=2)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description='ATHN-08: Generate combinatorial Google dork strings for security question OSINT'
    )
    p.add_argument(
        '--security_questions',
        default='inputs/data/secq_keywords.txt',
        metavar='PATH',
        help='Security question keywords file (default: inputs/data/secq_keywords.txt)'
    )
    p.add_argument(
        '--optionals',
        default='inputs/data/optionals_keywords.json',
        metavar='PATH',
        help='Personal identifiers JSON (default: inputs/data/optionals_keywords.json)'
    )
    p.add_argument(
        '--infrastructure',
        default='inputs/data/infrastructure_keywords.txt',
        metavar='PATH',
        help='Infrastructure/site operator keywords (default: inputs/data/infrastructure_keywords.txt)'
    )
    p.add_argument(
        '--username',
        default='',
        metavar='USERNAME',
        help='Target username (overrides value in optionals JSON)'
    )
    p.add_argument(
        '--output',
        default='inputs/wordlist/dork_test.txt',
        metavar='PATH',
        help='Output plaintext dork list (default: inputs/wordlist/dork_test.txt)'
    )
    p.add_argument(
        '--output_json',
        default='inputs/wordlist/dork_test.json',
        metavar='PATH',
        help='Output JSON with payloads + combinatorial map (default: inputs/wordlist/dork_test.json)'
    )
    p.add_argument(
        '--tier', type=int, choices=[1, 2, 3, 4], default=None,
        help='Only generate dorks from specified tier (1–4). Default: all tiers.'
    )
    return p.parse_args()


def main():
    args = parse_args()

    print(f"[*] Loading security question keywords: {args.security_questions}")
    secq = load_lines(args.security_questions, "secq_keywords")

    print(f"[*] Loading optional personal identifiers: {args.optionals}")
    optionals = load_optionals(args.optionals)

    print(f"[*] Loading infrastructure keywords: {args.infrastructure}")
    infra = load_lines(args.infrastructure, "infrastructure_keywords")

    personal = build_personal_terms(optionals, args.username)

    if not personal:
        print("[!] No personal identifiers loaded — optionals JSON is empty and no --username given.")
        print("    Tier 3 dorks (site × secq) will still be generated.")

    print(f"[*] Personal terms loaded: {list(personal.keys()) or '(none)'}")
    print(f"[*] Security question keywords: {len(secq)}")
    print(f"[*] Infrastructure operators:   {len(infra)}")
    print(f"[*] Generating combinatorial dork strings…")

    payloads, combo_map = generate_dorks(personal, secq, infra)

    meta = {
        "username":     args.username or optionals.get("username", "(not set)"),
        "secq_count":   len(secq),
        "infra_count":  len(infra),
        "personal_terms": list(personal.keys()),
        "total_dorks":  len(payloads),
    }

    write_txt(args.output, payloads)
    write_json(args.output_json, payloads, combo_map, meta)

    print(f"[+] {len(payloads)} dork strings generated")
    print(f"[+] Plaintext → {args.output}")
    print(f"[+] JSON      → {args.output_json}")
    print()
    print("  To use: paste dork strings into Google one at a time,")
    print("  or pipe through a SERP API / dork runner.")
    print()


if __name__ == "__main__":
    main()
