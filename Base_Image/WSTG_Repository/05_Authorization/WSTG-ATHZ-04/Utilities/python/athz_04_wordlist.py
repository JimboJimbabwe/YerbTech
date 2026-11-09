#!/usr/bin/env python3
"""
WSTG-ATHZ-04 — Testing for Insecure Direct Object References (IDOR)
Script: athz_04_wordlist.py

Reads athz04_findings.json produced by athz_04_scan.py and generates
enumeration wordlists — one .txt file per unique finding, plus a combined
wordlist ready for Burp Intruder's "Sniper" mode.

Generator logic per pattern type:

  Sequential Integer      →  base ± range (default ±50), step 1
  Base64 Encoded ID       →  decode → int → enumerate → re-encode
  Hex Encoded Integer     →  int → enumerate → zero-padded hex
  MongoDB ObjectID        →  keep timestamp prefix, enumerate counter
                              (last 6 hex chars) ± range
  Unix Timestamp (s)      →  base ± 3600 s, step 60
  Unix Timestamp (ms)     →  base ± 3 600 000 ms, step 60 000 (= 60 s)
  UUIDv1                  →  note only — not enumerable by brute force;
                              prints extraction instructions
  UUIDv4                  →  skip (random, not enumerable)
  Compound ID             →  enumerate each numeric segment ± range,
                              keep non-numeric segments fixed

Usage:
  python3 WSTG-ATHZ-04/utilities/python/athz_04_wordlist.py \\
      [--findings  WSTG-ATHZ-04/outputs/test_outputs/athz04_findings.json] \\
      [--range     50] \\
      [--min-confidence  HIGH]

Outputs:
  WSTG-ATHZ-04/inputs/wordlists/<pattern_type>_<param>_<hash>.txt  (per finding)
  WSTG-ATHZ-04/inputs/wordlists/combined_wordlist.txt
"""

import argparse
import base64
import hashlib
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
MAGENTA = "\033[95m"
RESET   = "\033[0m"

WIDTH   = 65
CONF_COLOR = {"HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN}


# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------

def _safe_int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def gen_sequential_int(base: int, count: int) -> list[str]:
    low  = max(0, base - count)
    high = base + count
    return [str(i) for i in range(low, high + 1)]


def gen_base64_int(decoded_str: str, count: int) -> list[str]:
    """
    Decode → treat as integer → enumerate → re-encode.
    Works for both plain-digit and alphanumeric decoded values;
    for alphanumeric we increment the numeric suffix if present,
    otherwise fall back to treating the whole value as an integer.
    """
    results = []

    # Try pure integer path first
    stripped = str(decoded_str).strip()
    if stripped.isdigit():
        base = int(stripped)
        low  = max(0, base - count)
        high = base + count
        for i in range(low, high + 1):
            encoded = base64.b64encode(str(i).encode()).decode()
            results.append(encoded)
        return results

    # Alphanumeric: find trailing digit group and increment it
    m = re.search(r'^(.*?)(\d+)$', stripped)
    if m:
        prefix = m.group(1)
        num    = int(m.group(2))
        width  = len(m.group(2))  # preserve zero-padding
        low    = max(0, num - count)
        high   = num + count
        for i in range(low, high + 1):
            new_val  = f"{prefix}{str(i).zfill(width)}"
            encoded  = base64.b64encode(new_val.encode()).decode()
            results.append(encoded)
        return results

    # Can't enumerate — return the original so the file is not empty
    results.append(base64.b64encode(stripped.encode()).decode())
    return results


def gen_hex_int(base_int: int, count: int, original_hex: str) -> list[str]:
    """Enumerate around base_int, output zero-padded hex matching original length."""
    orig_clean  = original_hex.replace("0x", "").replace("0X", "")
    pad_width   = max(len(orig_clean), 2)
    has_prefix  = original_hex.lower().startswith("0x")

    low  = max(0, base_int - count)
    high = base_int + count
    results = []
    for i in range(low, high + 1):
        hex_str = hex(i)[2:].zfill(pad_width)
        results.append(("0x" + hex_str) if has_prefix else hex_str)
    return results


def gen_mongodb_objectid(ts_prefix: str, base_counter: int, count: int) -> list[str]:
    """
    Keep the 8-char timestamp prefix fixed, enumerate the last 6 hex chars
    of the counter segment (bytes 12-17, index 18-23 of the 24-char ID).
    The middle 10 chars (machine + process + padding) are kept from the
    original since we do not know them — we vary only the counter.
    """
    # A full ObjectID is:  tttttttt mmmmmm pppp cccccc
    #   t = timestamp (8 hex)
    #   m = machine id (6 hex)
    #   p = process id (4 hex)
    #   c = counter   (6 hex)
    # ts_prefix is only 8 chars here; fill the rest with zeros for the
    # wordlist (operator replaces middle section manually).
    low  = max(0, base_counter - count)
    high = base_counter + count
    results = []
    for i in range(low, high + 1):
        counter_hex = hex(i)[2:].zfill(6)
        oid = ts_prefix + "000000000000" + "0000" + counter_hex
        results.append(oid)
    return results


def gen_unix_timestamp_s(base_ts: int, window: int = 3600, step: int = 60) -> list[str]:
    low  = base_ts - window
    high = base_ts + window
    return [str(t) for t in range(low, high + 1, step)]


def gen_unix_timestamp_ms(base_ts: int,
                          window: int = 3_600_000,
                          step:   int =    60_000) -> list[str]:
    low  = base_ts - window
    high = base_ts + window
    return [str(t) for t in range(low, high + 1, step)]


def gen_compound_id(parts: list[str], sep: str,
                    numeric_indices: list,
                    count: int) -> list[str]:
    """
    Enumerate each numeric segment ± count while keeping the non-numeric
    segments fixed.  numeric_indices is a list of (index, original_value).
    Produces one wordlist entry per enumerated numeric value for the
    first numeric segment (to keep the list manageable).
    """
    if not numeric_indices:
        return [sep.join(parts)]

    # Enumerate the first numeric segment only (most common IDOR target)
    idx, orig_val = numeric_indices[0]
    base = int(orig_val)
    low  = max(0, base - count)
    high = base + count
    results = []
    for i in range(low, high + 1):
        new_parts      = list(parts)
        new_parts[idx] = str(i)
        results.append(sep.join(new_parts))
    return results


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def generate_wordlist(finding: dict, count: int) -> tuple[list[str], str]:
    """
    Returns (wordlist, note_string).
    note_string is a human-readable status / operator instruction.
    """
    gen_info = finding.get("generator")
    ptype    = finding.get("type", "")
    value    = finding.get("value", "")

    if not gen_info:
        # UUIDv4 or unknown
        if "UUIDv4" in ptype:
            return [], ("UUIDv4 is cryptographically random — not enumerable by brute force. "
                        "No wordlist generated. Confirm IDOR via access control testing in Burp Repeater.")
        return [], "No generator available for this finding."

    # gen_info was stored as a list (JSON round-trip from tuple)
    g = list(gen_info)
    gen_type = g[0]

    if gen_type == "sequential_int":
        base = _safe_int(g[1]) if len(g) > 1 else _safe_int(value)
        if base is None:
            return [], "Could not parse integer base."
        words = gen_sequential_int(base, count)
        note  = f"Sequential range {base - count} – {base + count} (step 1)"

    elif gen_type == "base64_int":
        decoded = g[1] if len(g) > 1 else value
        words   = gen_base64_int(str(decoded), count)
        note    = f"Base64-encoded integers around decoded value '{decoded}'"

    elif gen_type == "hex_int":
        base_int = _safe_int(g[1]) if len(g) > 1 else None
        if base_int is None:
            return [], "Could not parse hex integer base."
        words = gen_hex_int(base_int, count, value)
        note  = f"Hex integers around {base_int} (decimal), padded to match original"

    elif gen_type == "mongodb_objectid":
        ts_prefix   = g[1] if len(g) > 1 else value[:8]
        base_ctr    = _safe_int(g[2]) if len(g) > 2 else 0
        if base_ctr is None:
            base_ctr = 0
        words = gen_mongodb_objectid(ts_prefix, base_ctr, count)
        note  = (f"MongoDB ObjectIDs with timestamp prefix '{ts_prefix}', "
                 f"counter ± {count}\n"
                 f"  NOTE: The machine+process segment (chars 9–18) is zeroed in this "
                 f"wordlist.\n"
                 f"  Extract the real middle segment from the original request and "
                 f"  substitute it manually before testing in Burp Intruder.")

    elif gen_type == "unix_timestamp":
        base_ts = _safe_int(g[1]) if len(g) > 1 else _safe_int(value)
        if base_ts is None:
            return [], "Could not parse timestamp base."
        words = gen_unix_timestamp_s(base_ts)
        note  = f"Unix timestamps (s) within ±1 hour of {base_ts}, step 60 s"

    elif gen_type == "unix_timestamp_ms":
        base_ts = _safe_int(g[1]) if len(g) > 1 else _safe_int(value)
        if base_ts is None:
            return [], "Could not parse timestamp base."
        words = gen_unix_timestamp_ms(base_ts)
        note  = f"Unix timestamps (ms) within ±1 hour of {base_ts}, step 60 s"

    elif gen_type == "uuidv1":
        return [], ("UUIDv1 is time-based and partially predictable. "
                    "Wordlist brute force is impractical for full UUIDs. "
                    "Recommended approach: capture multiple UUIDs from the application, "
                    "extract the timestamp component (bits 60-63), compute the range, "
                    "and use a UUID-aware tool such as uuid-utils or a custom Burp extension.")

    elif gen_type == "compound_id":
        parts   = g[1] if len(g) > 1 else [value]
        sep     = g[2] if len(g) > 2 else "-"
        numeric = g[3] if len(g) > 3 else []
        # numeric was stored as list of [index, value] pairs
        numeric_pairs = [(item[0], item[1]) for item in numeric] if numeric else []
        words = gen_compound_id(parts, sep, numeric_pairs, count)
        note  = (f"Compound ID segments: {parts}, separator: '{sep}', "
                 f"numeric parts enumerated ± {count}")

    else:
        return [], f"Unknown generator type: {gen_type}"

    return words, note


# ---------------------------------------------------------------------------
# Filename helpers
# ---------------------------------------------------------------------------

def safe_name(s: str) -> str:
    """Sanitise a string for use in a filename."""
    return re.sub(r'[^a-zA-Z0-9_-]', '_', s)[:40].strip('_')


def finding_hash(finding: dict) -> str:
    key = f"{finding.get('type', '')}:{finding.get('param_name', '')}:{finding.get('value', '')}"
    return hashlib.md5(key.encode()).hexdigest()[:8]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-ATHZ-04 IDOR enumeration wordlist generator"
    )
    p.add_argument("--findings",
        default=os.path.join(
            "WSTG-ATHZ-04", "outputs", "test_outputs", "athz04_findings.json"),
        metavar="PATH",
        help="athz04_findings.json from athz_04_scan.py")
    p.add_argument("--out-dir",
        default=os.path.join("WSTG-ATHZ-04", "inputs", "wordlists"),
        metavar="DIR",
        help="Directory for output wordlist files")
    p.add_argument("--range",
        type=int, default=50,
        metavar="N",
        help="Enumeration count: values generated ±N around the observed value (default: 50)")
    p.add_argument("--min-confidence",
        default="HIGH",
        choices=["HIGH", "MEDIUM", "LOW"],
        metavar="LEVEL",
        help="Only generate wordlists for findings at or above this confidence (default: HIGH)")
    args = p.parse_args()

    print(f"\n{BOLD}{'='*WIDTH}{RESET}")
    print(f"{BOLD}  WSTG-ATHZ-04 — IDOR Wordlist Generator{RESET}")
    print(f"{BOLD}{'='*WIDTH}{RESET}\n")

    # ── Load findings ────────────────────────────────────────────────────────
    try:
        with open(args.findings, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"  {RED}[!] Findings JSON not found: {args.findings}{RESET}", file=sys.stderr)
        print(f"  {YELLOW}    Run athz_04_scan.py first.{RESET}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"  {RED}[!] JSON parse error: {e}{RESET}", file=sys.stderr)
        sys.exit(1)

    all_findings = data.get("findings", [])
    if not all_findings:
        print(f"  {YELLOW}[!] No findings in {args.findings}{RESET}")
        sys.exit(0)

    # Filter by confidence
    CONF_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    min_rank  = CONF_RANK.get(args.min_confidence.upper(), 0)
    findings  = [f for f in all_findings
                 if CONF_RANK.get(f.get("confidence", "LOW"), 9) <= min_rank]

    print(f"  Total findings : {len(all_findings)}")
    print(f"  Min confidence : {args.min_confidence} → {len(findings)} findings selected")
    print(f"  Range (±)      : {args.range}")
    print()

    os.makedirs(args.out_dir, exist_ok=True)

    combined: list[str] = []
    generated_files: list[str] = []
    skipped: list[str]         = []
    operator_notes: list[str]  = []

    # ── Per-finding wordlists ────────────────────────────────────────────────
    for idx, finding in enumerate(findings, start=1):
        ptype  = finding.get("type", "Unknown")
        param  = finding.get("param_name", "param")
        value  = finding.get("value", "")
        conf   = finding.get("confidence", "LOW")
        url    = finding.get("url", "")
        loc    = finding.get("location", "")
        col    = CONF_COLOR.get(conf, RESET)

        short_url = url[-50:] if len(url) > 50 else url
        print(f"  [{idx:02d}] {col}{conf:<8}{RESET}  {ptype}")
        print(f"        param: {param!r}  value: {value[:40]!r}")
        print(f"        url  : ...{short_url}")

        wordlist, note = generate_wordlist(finding, args.range)

        if not wordlist:
            print(f"        {YELLOW}↳ skipped — {note[:80]}{RESET}")
            skipped.append(f"[{idx:02d}] {ptype} ({param}): {note}")
            print()
            continue

        # Write per-finding file
        fname = (f"{safe_name(ptype)}_{safe_name(param)}_{finding_hash(finding)}.txt")
        fpath = os.path.join(args.out_dir, fname)
        with open(fpath, "w", encoding="utf-8") as wf:
            wf.write("\n".join(wordlist) + "\n")

        generated_files.append(fpath)
        combined.extend(wordlist)

        operator_notes.append({
            "index":    idx,
            "type":     ptype,
            "param":    param,
            "url":      url,
            "location": loc,
            "conf":     conf,
            "note":     note,
            "file":     fpath,
            "count":    len(wordlist),
        })

        print(f"        {GREEN}↳ {len(wordlist)} values  →  {fname}{RESET}")
        print()

    # ── Combined wordlist ────────────────────────────────────────────────────
    combined_deduped = list(dict.fromkeys(combined))  # preserve order, dedup
    combined_path    = os.path.join(args.out_dir, "combined_wordlist.txt")
    with open(combined_path, "w", encoding="utf-8") as cf:
        cf.write("\n".join(combined_deduped) + "\n")

    # ── Terminal summary ─────────────────────────────────────────────────────
    print(f"\n  {'─'*50}")
    print(f"  Findings processed : {len(findings)}")
    print(f"  {GREEN}Wordlists generated: {len(generated_files)}{RESET}")
    if skipped:
        print(f"  {YELLOW}Skipped            : {len(skipped)}{RESET}")
    print(f"  {GREEN}Combined wordlist  : {len(combined_deduped)} unique values{RESET}")
    print()

    # ── Operator instructions ─────────────────────────────────────────────────
    print(f"\n  {BOLD}{'─'*WIDTH}{RESET}")
    print(f"  {BOLD}OPERATOR INSTRUCTIONS — IDOR Enumeration{RESET}")
    print(f"  {BOLD}{'─'*WIDTH}{RESET}\n")

    if operator_notes:
        print("  For each finding below:")
        print("  1. Open Burp Suite > Proxy > HTTP History")
        print("  2. Find the request containing the flagged parameter")
        print("  3. Right-click → Send to Intruder")
        print("  4. In Intruder → Positions, highlight the parameter VALUE")
        print("  5. Attack type: Sniper")
        print("  6. Payloads → Simple List → Load the per-finding wordlist")
        print("  7. Configure Grep/Extract for identifiers unique to other users/records")
        print("  8. Launch attack; review responses for cross-user data leakage")
        print()
        print(f"  {YELLOW}NOTE: Do NOT use PUT via automation. If a PUT endpoint is identified,")
        print(f"  test it MANUALLY in Burp Repeater.{RESET}\n")

        print(f"  {'─'*50}")
        for n in operator_notes:
            col = CONF_COLOR.get(n["conf"], RESET)
            print()
            print(f"  {col}[{n['conf']}]{RESET} {n['type']} — param: {n['param']!r}")
            print(f"  Location : {n['location']}")
            print(f"  URL      : {n['url']}")
            print(f"  Wordlist : {n['file']}")
            print(f"  Values   : {n['count']}")
            print(f"  Note     : {n['note']}")

    if skipped:
        print(f"\n  {YELLOW}Skipped findings (no wordlist generated):{RESET}")
        for s in skipped:
            print(f"  {DIM}  {s}{RESET}")

    print(f"\n  {'─'*50}")
    print(f"  {GREEN}[+] Per-finding wordlists → {args.out_dir}/{RESET}")
    print(f"  {GREEN}[+] Combined wordlist     → {combined_path}{RESET}")
    print(f"\n  Load combined_wordlist.txt into Burp Intruder for a full sweep,")
    print(f"  or use per-finding files for targeted parameter enumeration.\n")


if __name__ == "__main__":
    main()
