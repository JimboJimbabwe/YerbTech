#!/usr/bin/env python3
"""
WSTG-CRYP-01 — Testing for Weak Transport Layer Security
Script 1: cryp01_scan.py

Reads a list of target hosts from targets.txt and runs two tools
against each target sequentially:

  1. sslyze  — comprehensive TLS/SSL configuration audit
     Output:  outputs/test_outputs/<host>_sslyze.json

  2. nmap    — SSL cipher enumeration via ssl-enum-ciphers script
     Output:  outputs/test_outputs/<host>_nmap.xml

Strips http:// / https:// prefixes from targets automatically.
Handles port specification: host:port or bare host (defaults to 443).

Inputs:
  WSTG-CRYP-01/inputs/data/targets.txt

Outputs (per target):
  WSTG-CRYP-01/outputs/test_outputs/<host>_sslyze.json
  WSTG-CRYP-01/outputs/test_outputs/<host>_nmap.xml

Usage:
  python3 WSTG-CRYP-01/utilities/python/cryp01_scan.py
  python3 WSTG-CRYP-01/utilities/python/cryp01_scan.py \\
      --targets WSTG-CRYP-01/inputs/data/targets.txt \\
      --out-dir WSTG-CRYP-01/outputs/test_outputs \\
      --port 443
"""

import argparse
import os
import re
import subprocess
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
CYAN   = "\033[96m"
RESET  = "\033[0m"


# ---------------------------------------------------------------------------
# Target normalisation
# ---------------------------------------------------------------------------

RE_SCHEME = re.compile(r'^https?://', re.IGNORECASE)
RE_PATH   = re.compile(r'/.*$')


def normalise_target(raw: str) -> tuple[str, int]:
    """
    Strips scheme and path, returns (hostname, port).
    Handles:
      https://target.example.com        → (target.example.com, 443)
      http://target.example.com:8443/   → (target.example.com, 8443)
      target.example.com:443            → (target.example.com, 443)
      target.example.com                → (target.example.com, 443)
    """
    s = RE_SCHEME.sub("", raw.strip())
    s = RE_PATH.sub("", s)       # remove any trailing path
    if ":" in s:
        host, _, port_str = s.rpartition(":")
        try:
            port = int(port_str)
        except ValueError:
            host = s
            port = 443
    else:
        host = s
        port = 443
    return host, port


def safe_filename(host: str) -> str:
    """Makes host safe for use as a filename component."""
    return re.sub(r'[^\w\-.]', '_', host)


# ---------------------------------------------------------------------------
# Tool checks
# ---------------------------------------------------------------------------

def check_tool(name: str) -> bool:
    try:
        subprocess.run(
            [name, "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ---------------------------------------------------------------------------
# sslyze runner
# ---------------------------------------------------------------------------

def run_sslyze(host: str, port: int, out_path: str) -> tuple[bool, str]:
    """
    Runs sslyze against host:port and writes JSON output to out_path.
    Returns (success, message).
    """
    cmd = [
        "sslyze",
        f"{host}:{port}",
        "--json_out", out_path,
        "--regular",      # equivalent to --tlsv1 --tlsv1_1 --tlsv1_2 --tlsv1_3
                          # --sslv2 --sslv3 --certinfo --compression --reneg --resum
    ]

    print(f"  {DIM}CMD: {' '.join(cmd)}{RESET}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        # sslyze exits 0 even on TLS errors (scan completed with findings)
        # It exits non-zero if it couldn't connect at all
        if result.returncode not in (0, 1):
            return False, f"sslyze exited {result.returncode}: {result.stderr[:300]}"

        if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
            return True, f"sslyze output: {out_path}"
        else:
            # sslyze may print to stdout instead if path failed
            # Write stdout as fallback
            if result.stdout:
                with open(out_path.replace(".json", "_stdout.txt"), "w") as f:
                    f.write(result.stdout)
            return False, f"sslyze produced no JSON output. stderr: {result.stderr[:200]}"

    except subprocess.TimeoutExpired:
        return False, "sslyze timed out (120s)"
    except FileNotFoundError:
        return False, "sslyze not found — install with: pip install sslyze"


# ---------------------------------------------------------------------------
# nmap runner
# ---------------------------------------------------------------------------

def run_nmap(host: str, port: int, out_path: str) -> tuple[bool, str]:
    """
    Runs nmap ssl-enum-ciphers against host:port and writes XML to out_path.
    Returns (success, message).
    """
    cmd = [
        "nmap",
        "-Pn",
        "-vvv",
        "--script", "ssl-enum-ciphers",
        "-p", str(port),
        host,
        "-oX", out_path,
    ]

    print(f"  {DIM}CMD: {' '.join(cmd)}{RESET}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            return False, f"nmap exited {result.returncode}: {result.stderr[:300]}"

        if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
            return True, f"nmap output: {out_path}"
        else:
            return False, "nmap produced no XML output"

    except subprocess.TimeoutExpired:
        return False, "nmap timed out (120s)"
    except FileNotFoundError:
        return False, "nmap not found — install nmap and ensure it is in PATH"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-CRYP-01 Script 1: TLS scan runner (sslyze + nmap)"
    )
    p.add_argument("--targets",
        default=os.path.join("WSTG-CRYP-01", "inputs", "data", "targets.txt"),
        metavar="PATH",
        help="Path to targets.txt (one host per line)")
    p.add_argument("--out-dir",
        default=os.path.join("WSTG-CRYP-01", "outputs", "test_outputs"),
        metavar="DIR")
    p.add_argument("--port",
        type=int,
        default=None,
        metavar="PORT",
        help="Default port if not specified in targets.txt (default: 443)")
    p.add_argument("--skip-sslyze", action="store_true",
        help="Skip sslyze scan")
    p.add_argument("--skip-nmap", action="store_true",
        help="Skip nmap scan")
    args = p.parse_args()

    width = 65
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD} WSTG-CRYP-01 — TLS Scan Runner{RESET}")
    print(f"{BOLD}{'='*width}{RESET}")
    print(f"  Targets : {args.targets}")
    print(f"  Out dir : {args.out_dir}")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Check tools
    sslyze_ok = check_tool("sslyze") if not args.skip_sslyze else False
    nmap_ok   = check_tool("nmap")   if not args.skip_nmap   else False

    if not args.skip_sslyze:
        if sslyze_ok:
            print(f"  {GREEN}✓  sslyze found{RESET}")
        else:
            print(f"  {YELLOW}⚠  sslyze not found — sslyze scans will be skipped{RESET}")
            print(f"     Install: pip install sslyze")

    if not args.skip_nmap:
        if nmap_ok:
            print(f"  {GREEN}✓  nmap found{RESET}")
        else:
            print(f"  {YELLOW}⚠  nmap not found — nmap scans will be skipped{RESET}")
            print(f"     Install: https://nmap.org/download.html")

    if not sslyze_ok and not nmap_ok:
        print(f"\n{RED}[!] Neither tool is available. Install sslyze and/or nmap.{RESET}\n")
        sys.exit(1)

    # Read targets
    try:
        with open(args.targets) as f:
            raw_lines = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
    except FileNotFoundError:
        print(f"\n{RED}[!] targets.txt not found: {args.targets}{RESET}\n", file=sys.stderr)
        sys.exit(1)

    if not raw_lines:
        print(f"\n{YELLOW}[!] No targets found in {args.targets}{RESET}\n")
        sys.exit(0)

    targets = []
    for raw in raw_lines:
        host, port = normalise_target(raw)
        if args.port and port == 443:
            port = args.port
        targets.append((host, port, raw))

    print(f"\n  {len(targets)} target(s) loaded:\n")
    for host, port, raw in targets:
        print(f"    {CYAN}{host}:{port}{RESET}  {DIM}(from: {raw}){RESET}")

    os.makedirs(args.out_dir, exist_ok=True)

    # Per-target scan
    results_summary = []

    for idx, (host, port, raw) in enumerate(targets, 1):
        safe = safe_filename(host)
        print(f"\n{BOLD}{'─'*width}{RESET}")
        print(f"{BOLD}  [{idx}/{len(targets)}] {host}:{port}{RESET}")
        print(f"{BOLD}{'─'*width}{RESET}\n")

        row = {
            "host":          host,
            "port":          port,
            "sslyze_path":   None,
            "sslyze_ok":     False,
            "sslyze_msg":    "skipped",
            "nmap_path":     None,
            "nmap_ok":       False,
            "nmap_msg":      "skipped",
        }

        # sslyze
        if sslyze_ok:
            sslyze_out = os.path.join(args.out_dir, f"{safe}_sslyze.json")
            row["sslyze_path"] = sslyze_out
            print(f"  {CYAN}[sslyze]{RESET}")
            ok, msg = run_sslyze(host, port, sslyze_out)
            row["sslyze_ok"]  = ok
            row["sslyze_msg"] = msg
            if ok:
                print(f"  {GREEN}✓  {msg}{RESET}")
            else:
                print(f"  {YELLOW}⚠  {msg}{RESET}")
        else:
            print(f"  {DIM}[sslyze] skipped{RESET}")

        print()

        # nmap
        if nmap_ok:
            nmap_out = os.path.join(args.out_dir, f"{safe}_nmap.xml")
            row["nmap_path"] = nmap_out
            print(f"  {CYAN}[nmap]{RESET}")
            ok, msg = run_nmap(host, port, nmap_out)
            row["nmap_ok"]  = ok
            row["nmap_msg"] = msg
            if ok:
                print(f"  {GREEN}✓  {msg}{RESET}")
            else:
                print(f"  {YELLOW}⚠  {msg}{RESET}")
        else:
            print(f"  {DIM}[nmap] skipped{RESET}")

        results_summary.append(row)

    # Final summary
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD} Scan Summary{RESET}")
    print(f"{BOLD}{'='*width}{RESET}\n")
    print(f"  {'Host':<35} {'sslyze':<12} {'nmap':<12}")
    print(f"  {'─'*35} {'─'*12} {'─'*12}")
    for row in results_summary:
        s_tag = f"{GREEN}OK{RESET}"    if row["sslyze_ok"] else (f"{DIM}skip{RESET}" if row["sslyze_msg"] == "skipped" else f"{YELLOW}FAIL{RESET}")
        n_tag = f"{GREEN}OK{RESET}"    if row["nmap_ok"]   else (f"{DIM}skip{RESET}" if row["nmap_msg"]   == "skipped" else f"{YELLOW}FAIL{RESET}")
        print(f"  {row['host']:<35} {s_tag:<20} {n_tag:<20}")

    print(f"\n  Output directory: {args.out_dir}")
    print(f"  Next: cryp01_analyze.py --out-dir {args.out_dir}")
    print()


if __name__ == "__main__":
    main()
