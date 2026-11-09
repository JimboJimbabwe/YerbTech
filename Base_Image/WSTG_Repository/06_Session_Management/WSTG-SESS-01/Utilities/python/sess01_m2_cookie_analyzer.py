#!/usr/bin/env python3
"""
WSTG-SESS-01 — Testing for Session Management Schema
Module 2: sess01_m2_cookie_analyzer.py

Reads cookies_by_name.json (from Module 0) and performs sequential
pattern analysis on each cookie's ordered value history.

Algorithm:
  For each cookie name with ≥2 observed values (in observation order):
    For each window size W in {2, 3, 4, 5}:
      Slide window across the value string at each character position P:
        Extract substring[P : P+W] from every observed value.
        Attempt to parse each substring as a decimal integer.
        If ≥2 consecutive values parse successfully AND the numeric
        difference between them is constant (monotonically increasing
        or decreasing by a fixed step), flag that position as sequential.

  "Break" alert: if we find ≥2 sequential windows at the same position
  across consecutive cookies, log which observation indices triggered it.

  Why this matters:
    Sequential session tokens indicate server-side token generation with
    predictable state. An attacker who observes their own token value can
    compute adjacent tokens belonging to other active sessions.
    Reference: OWASP WSTG-SESS-01 §Token Analysis

Outputs:
  WSTG-SESS-01/outputs/m2_analysis.json
  WSTG-SESS-01/outputs/m2_alerts.txt

Usage:
  python3 WSTG-SESS-01/utilities/python/sess01_m2_cookie_analyzer.py \\
      --cookies WSTG-SESS-01/outputs/cookies_by_name.json
"""

import argparse
import json
import os
import sys
from collections import defaultdict


# ---------------------------------------------------------------------------
# ANSI
# ---------------------------------------------------------------------------
BOLD  = "\033[1m"
DIM   = "\033[2m"
GREEN = "\033[92m"
YELLOW= "\033[93m"
RED   = "\033[91m"
CYAN  = "\033[96m"
RESET = "\033[0m"

WINDOW_SIZES = [2, 3, 4, 5]
# Minimum number of consecutive cookies showing the same step to fire alert
MIN_CONSECUTIVE = 2


# ---------------------------------------------------------------------------
# Sequential pattern detector
# ---------------------------------------------------------------------------

def analyze_cookie(name: str, values: list[str]) -> list[dict]:
    """
    Returns list of alert dicts for sequential patterns found in this
    cookie's observed value history.

    Each alert: {
        cookie_name, position, window_size, step,
        direction, matching_indices, matching_substrings
    }
    """
    if len(values) < MIN_CONSECUTIVE + 1:
        return []

    alerts = []

    for W in WINDOW_SIZES:
        # Find the shortest value length to bound our positions
        min_len = min(len(v) for v in values)
        if min_len < W:
            continue

        for P in range(min_len - W + 1):
            # Extract substring at position P width W from every value
            substrings = [v[P:P+W] for v in values]

            # Attempt to parse as integers
            nums = []
            for sub in substrings:
                try:
                    nums.append((int(sub), sub))
                except ValueError:
                    nums.append((None, sub))

            # Collect runs of parseable consecutive values
            run_start = None
            run_nums  = []

            def flush_run():
                nonlocal run_start, run_nums
                if len(run_nums) >= MIN_CONSECUTIVE + 1:
                    # Check if step is constant
                    diffs = [run_nums[i+1][0] - run_nums[i][0]
                             for i in range(len(run_nums) - 1)]
                    if len(set(diffs)) == 1 and diffs[0] != 0:
                        step = diffs[0]
                        direction = "increasing" if step > 0 else "decreasing"
                        indices   = list(range(run_start, run_start + len(run_nums)))
                        alerts.append({
                            "cookie_name":         name,
                            "position":            P,
                            "window_size":         W,
                            "step":                step,
                            "direction":           direction,
                            "matching_indices":    indices,
                            "matching_substrings": [n[1] for n in run_nums],
                        })
                run_start = None
                run_nums  = []

            for i, (num, sub) in enumerate(nums):
                if num is None:
                    flush_run()
                else:
                    if run_start is None:
                        run_start = i
                    run_nums.append((num, sub))

            flush_run()

    # Deduplicate overlapping alerts (same position, different window — keep widest)
    seen_positions = {}
    for alert in sorted(alerts, key=lambda a: -a["window_size"]):
        pos = alert["position"]
        if pos not in seen_positions:
            seen_positions[pos] = alert

    return list(seen_positions.values())


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="SESS-01 M2: Sequential cookie value pattern detector"
    )
    p.add_argument("--cookies",
        default=os.path.join("WSTG-SESS-01", "outputs", "cookies_by_name.json"),
        metavar="PATH")
    p.add_argument("--out-dir",
        default=os.path.join("WSTG-SESS-01", "outputs"),
        metavar="DIR")
    args = p.parse_args()

    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"{BOLD} WSTG-SESS-01 M2 — Cookie Sequential Analyzer{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"  Input: {args.cookies}\n")

    try:
        with open(args.cookies) as f:
            cookies_by_name: dict[str, list[str]] = json.load(f)
    except FileNotFoundError:
        print(f"{RED}[!] {args.cookies} not found — run Module 0 first.{RESET}",
              file=sys.stderr)
        sys.exit(1)

    os.makedirs(args.out_dir, exist_ok=True)

    all_alerts   = []
    analysis_out = {}

    for name, values in cookies_by_name.items():
        print(f"  {CYAN}{name}{RESET} — {len(values)} observed value(s)", end="")
        if len(values) < 3:
            print(f"  {DIM}(too few to analyse){RESET}")
            analysis_out[name] = {"skipped": True, "reason": "fewer than 3 values"}
            continue

        alerts = analyze_cookie(name, values)
        analysis_out[name] = {
            "value_count": len(values),
            "alerts":      alerts,
        }

        if alerts:
            print(f"  {RED}⚠ {len(alerts)} sequential pattern(s) detected!{RESET}")
            for alert in alerts:
                print(f"    {RED}Position {alert['position']}, "
                      f"width {alert['window_size']}: "
                      f"{alert['direction']} by {alert['step']} "
                      f"at indices {alert['matching_indices']}{RESET}")
                print(f"    Values: {alert['matching_substrings']}")
            all_alerts.extend(alerts)
        else:
            print(f"  {GREEN}✓ No sequential pattern detected{RESET}")

    # Write JSON
    json_path = os.path.join(args.out_dir, "m2_analysis.json")
    with open(json_path, "w") as f:
        json.dump(analysis_out, f, indent=2)
    print(f"\n{GREEN}[+] {json_path}{RESET}")

    # Write human-readable alerts
    alert_lines = []
    alert_lines.append("WSTG-SESS-01 M2 — Sequential Pattern Alerts")
    alert_lines.append("=" * 65)
    alert_lines.append("")

    if not all_alerts:
        alert_lines.append("No sequential patterns detected.")
    else:
        alert_lines.append(f"ALERT: {len(all_alerts)} sequential pattern(s) found.")
        alert_lines.append("")
        alert_lines.append(
            "Sequential session tokens are PREDICTABLE. An attacker who\n"
            "observes their own token can compute adjacent tokens belonging\n"
            "to other active sessions.\n"
            "Reference: OWASP WSTG-SESS-01, NIST SP 800-63B §10.1\n"
        )
        for alert in all_alerts:
            alert_lines.append(f"Cookie      : {alert['cookie_name']}")
            alert_lines.append(f"Position    : char[{alert['position']}:"
                               f"{alert['position']+alert['window_size']}]")
            alert_lines.append(f"Window size : {alert['window_size']} chars")
            alert_lines.append(f"Direction   : {alert['direction']}")
            alert_lines.append(f"Step        : {alert['step']}")
            alert_lines.append(f"At indices  : {alert['matching_indices']}")
            alert_lines.append(f"Substrings  : {alert['matching_substrings']}")
            alert_lines.append("")

    alert_path = os.path.join(args.out_dir, "m2_alerts.txt")
    with open(alert_path, "w") as f:
        f.write("\n".join(alert_lines))
    print(f"{GREEN}[+] {alert_path}{RESET}")

    if all_alerts:
        print(f"\n  {RED}{BOLD}⚠ {len(all_alerts)} sequential pattern alert(s) — see {alert_path}{RESET}")
    else:
        print(f"\n  {GREEN}✓ No sequential token patterns found.{RESET}")

    print(f"\n  Next: sess01_m3_reverse_engineer.py")
    print()


if __name__ == "__main__":
    main()
