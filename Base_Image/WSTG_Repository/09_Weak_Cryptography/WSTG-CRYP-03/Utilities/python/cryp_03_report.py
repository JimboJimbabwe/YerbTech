#!/usr/bin/env python3
"""
WSTG-CRYP-03 — Report Reader
=============================
Reads cryp03_out.json produced by cryp_03.py and prints every
vulnerable index, endpoint, and the specific test case(s) that fired.

Usage:
    python cryp_03_report.py
    python cryp_03_report.py path/to/cryp03_out.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_IN = SCRIPT_DIR.parent.parent / "Outputs" / "test_outputs" / "cryp03_out.json"

DIV = "─" * 70


def main() -> None:
    in_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_IN

    if not in_path.exists():
        sys.exit(
            f"[!] Result file not found: {in_path}\n"
            f"    Run cryp_03.py first to generate it."
        )

    data    = json.loads(in_path.read_text())
    meta    = data.get("scan_metadata", {})
    results = data.get("results", {})

    # ── Header ────────────────────────────────────────────────────────────
    print(DIV)
    print("  WSTG-CRYP-03  |  Vulnerable Endpoint Report")
    print(f"  Scan time : {meta.get('scan_time', 'N/A')}")
    print(f"  Source    : {meta.get('source',    'N/A')}")
    print(DIV)

    # ── Filter to vulnerable hosts ────────────────────────────────────────
    vuln_entries = [
        (idx, host, hdata)
        for idx, (host, hdata) in enumerate(results.items())
        if hdata.get("overall_vulnerable")
    ]

    if not vuln_entries:
        print("\n  ✓  No vulnerable endpoints found.\n")
        print(DIV)
        return

    # ── Print each vulnerable host ────────────────────────────────────────
    for idx, host, hdata in vuln_entries:
        print(f"\n  [{idx}]  {host}")

        for tc in hdata.get("test_cases", []):
            if not tc.get("vulnerable"):
                continue

            tid  = tc.get("test_id",     "???")
            desc = tc.get("description", "")
            sc   = tc.get("status_code", "N/A")
            cmd  = tc.get("command",     "")

            print(f"\n         {tid}  ·  {desc}")
            print(f"         Command : {cmd}")
            print(f"         Status  : {sc}")

            # TC-02 — where did the redirect go (or not go)?
            if tid == "TC-02":
                loc = tc.get("location") or "(no Location header)"
                print(f"         Location: {loc}")

            # TC-03 — STS detail
            if tid == "TC-03":
                sts_raw = tc.get("sts_value") or "(header not present)"
                sane    = tc.get("sts_sane", False)
                print(f"         STS     : {sts_raw}")
                if tc.get("STS") and not sane:
                    print("         ⚑ max-age is below 1 year (31 536 000 s)")

            # TC-04 — insecure form actions
            if tid == "TC-04":
                for action in tc.get("http_form_actions", []):
                    print(f"         ⚑ Form action (HTTP): {action}")

            # TC-AUX — cookies missing Secure
            if tid == "TC-AUX":
                for ck in tc.get("insecure_cookies", []):
                    print(f"         ⚑ Set-Cookie (no Secure flag): {ck}")

    # ── Summary ───────────────────────────────────────────────────────────
    total = len(results)
    found = len(vuln_entries)
    print(f"\n  Summary: {found}/{total} host(s) flagged as vulnerable.")
    print(DIV)
    print()


if __name__ == "__main__":
    main()
