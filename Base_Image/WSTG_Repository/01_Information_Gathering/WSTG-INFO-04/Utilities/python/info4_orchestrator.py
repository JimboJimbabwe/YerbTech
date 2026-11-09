#!/usr/bin/env python3
"""
info4_orchestrator.py — WSTG-INFO-04 DNS, Port & Virtual Host Enumeration Orchestrator
Location: WSTG_Repository/01_Information_Gathering/WSTG-INFO-04/Utilities/python/info4_orchestrator.py

Orchestrates the full WSTG-INFO-04 pipeline:
  1. DNS active enumeration (dig A/AAAA/MX/TXT/NS/CNAME/SOA/SRV per domain)
     → Outputs/test_outputs/DNS_MODULE/results.txt
  2. Wait 2 minutes
  3. naabu + nmap -Pn -vvv -sV  (service scan)
     → Outputs/data/uxp_scan.xml  +  Outputs/test_outputs/naabu_service/service_<ts>.md
  4. Wait 2 minutes
  5. naabu + nmap --script http-vhosts  (virtual host scan)
     → Outputs/data/vhost_scan.xml  +  Outputs/test_outputs/naabu_vhost/vhost_<ts>.md

Companion script: subdomain_seeker.py  (run separately, reads Burp XML)

Usage:
    python info4_orchestrator.py --domains <domains.txt> --ip <TARGET_IP>
                                 [--base <WSTG-INFO-04 root>]
                                 [--dns-sleep <seconds>]
                                 [--naabu-rate <rate>]
                                 [--no-wait]
                                 [--skip-dns] [--skip-portscan] [--skip-vhost]
"""

import argparse
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Output paths (relative to WSTG-INFO-04 root)
# ---------------------------------------------------------------------------
DNS_TXT_PATH    = "Outputs/test_outputs/DNS_MODULE/results.txt"
SERVICE_MD_DIR  = "Outputs/test_outputs/naabu_service"
VHOST_MD_DIR    = "Outputs/test_outputs/naabu_vhost"
SERVICE_XML     = "Outputs/data/uxp_scan.xml"
VHOST_XML       = "Outputs/data/vhost_scan.xml"

DEFAULT_BASE     = Path(__file__).resolve().parents[2]  # WSTG-INFO-04/
DEFAULT_DOMAINS  = "Inputs/Data/domains.txt"

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "SRV"]
DNS_SLEEP        = 2
WAIT_SECONDS     = 120

NAABU_DEFAULTS = {
    "rate":        2000,
    "concurrency": 50,
    "retries":     2,
    "warm_up":     1,
}


# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        prog="info4_orchestrator.py",
        description="WSTG-INFO-04 — DNS / Port / VHost Enumeration Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--domains", default=None,
        help=(
            f"Plaintext file — one domain per line (for DNS enum). "
            f"Defaults to <base>/{DEFAULT_DOMAINS}"
        ),
    )
    parser.add_argument(
        "--ip", required=True,
        help="Target IP address for naabu port scans."
    )
    parser.add_argument(
        "--base", default=None,
        help="WSTG-INFO-04 root directory. Defaults to two levels above this script."
    )
    parser.add_argument(
        "--dns-sleep", type=int, default=DNS_SLEEP,
        help=f"Seconds between DNS domain lookups (default: {DNS_SLEEP})."
    )
    parser.add_argument(
        "--naabu-rate", type=int, default=NAABU_DEFAULTS["rate"],
        help=f"naabu packet rate (default: {NAABU_DEFAULTS['rate']})."
    )
    parser.add_argument(
        "--no-wait", action="store_true",
        help="Skip the 2-minute waits between stages (useful for testing)."
    )
    parser.add_argument("--skip-dns",      action="store_true", help="Skip DNS enumeration.")
    parser.add_argument("--skip-portscan", action="store_true", help="Skip naabu service scan.")
    parser.add_argument("--skip-vhost",    action="store_true", help="Skip naabu vhost scan.")
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ts() -> str:
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def ensure(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def load_lines(path: Path) -> list[str]:
    if not path.is_file():
        sys.exit(f"[ERROR] File not found: {path}")
    lines = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                lines.append(line)
    return lines


def run(cmd: list[str], label: str, timeout: int = 300) -> tuple[str, str, int]:
    """Run a command, return (stdout, stderr, returncode)."""
    print(f"  [>] {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.stdout, proc.stderr, proc.returncode
    except FileNotFoundError:
        msg = f"[!] Not found on PATH: {cmd[0]}"
        print(msg)
        return "", msg, 127
    except subprocess.TimeoutExpired:
        msg = f"[!] Timed out: {' '.join(cmd)}"
        print(msg)
        return "", msg, 1


def countdown(seconds: int, label: str) -> None:
    """Visible countdown timer."""
    print(f"\n[*] {label} — waiting {seconds}s...")
    for remaining in range(seconds, 0, -10):
        print(f"  {remaining}s remaining...", end="\r")
        time.sleep(10)
    print(" " * 40)  # clear the line


def md_header(fh, title: str, meta: dict) -> None:
    fh.write(f"# {title}\n\n")
    for k, v in meta.items():
        fh.write(f"**{k}:** {v}  \n")
    fh.write("\n---\n\n")


def md_section(fh, heading: str, content: str, rc: int | None = None) -> None:
    fh.write(f"## {heading}\n\n")
    if rc is not None:
        status = "✅ OK" if rc == 0 else f"❌ rc={rc}"
        fh.write(f"**Status:** {status}  \n\n")
    fh.write("```\n")
    fh.write(content.strip() or "(no output)")
    fh.write("\n```\n\n---\n\n")


# ---------------------------------------------------------------------------
# Step 1 — DNS active enumeration → results.txt
# ---------------------------------------------------------------------------

def step_dns(domains: list[str], txt_path: Path, sleep_secs: int) -> Path:
    ensure(txt_path.parent)
    print(f"\n[DNS] Enumerating {len(domains)} domain(s) → {txt_path}")

    with txt_path.open("w", encoding="utf-8") as fh:
        fh.write("=" * 60 + "\n")
        fh.write("  WSTG-INFO-04 — DNS Active Enumeration\n")
        fh.write(f"  Generated : {datetime.utcnow().isoformat()}Z\n")
        fh.write(f"  Domains   : {len(domains)}\n")
        fh.write(f"  Records   : {', '.join(DNS_RECORD_TYPES)}\n")
        fh.write("=" * 60 + "\n\n")

        for i, domain in enumerate(domains, 1):
            print(f"  [{i}/{len(domains)}] {domain}")
            fh.write(f"=== {domain} ===\n\n")

            any_result = False
            for rtype in DNS_RECORD_TYPES:
                stdout, stderr, rc = run(
                    ["dig", domain, rtype, "+noall", "+answer"],
                    f"dig {domain} {rtype}",
                    timeout=30,
                )
                result = stdout.strip()
                if result:
                    any_result = True
                    fh.write(f"--- {rtype} ---\n{result}\n\n")
                    print(f"    [{rtype}] {result.splitlines()[0][:80]}")

            if not any_result:
                fh.write("(no records returned)\n\n")

            fh.write("\n")

            if i < len(domains):
                time.sleep(sleep_secs)

    print(f"  [+] DNS output → {txt_path}")
    return txt_path


# ---------------------------------------------------------------------------
# Step 3 — naabu + nmap -Pn -vvv -sV (service scan)
# ---------------------------------------------------------------------------

def step_service_scan(ip: str, xml_path: Path, md_dir: Path, rate: int) -> Path:
    ensure(xml_path.parent)
    ensure(md_dir)
    stamp   = ts()
    md_path = md_dir / f"service_{stamp}.md"

    nmap_cli = f"nmap -Pn -vvv -sV -oX {xml_path}"
    cmd = [
        "naabu",
        "-p", "-",
        "-rate",         str(rate),
        "-c",            str(NAABU_DEFAULTS["concurrency"]),
        "-retries",      str(NAABU_DEFAULTS["retries"]),
        "-warm-up-time", str(NAABU_DEFAULTS["warm_up"]),
        "-silent",
        "-host",         ip,
        "-nmap-cli",     nmap_cli,
    ]

    print(f"\n[*] Scanning for unexpected ports and services...")
    print(f"  Target : {ip}")
    stdout, stderr, rc = run(cmd, "naabu service scan", timeout=1800)

    with md_path.open("w", encoding="utf-8") as fh:
        md_header(fh, "WSTG-INFO-04 — Service Version Scan (naabu + nmap -Pn -vvv -sV)", {
            "Target":    ip,
            "nmap XML":  str(xml_path),
            "Generated": datetime.utcnow().isoformat() + "Z",
        })
        md_section(fh, "Command", " ".join(cmd))
        md_section(fh, "naabu stdout", stdout, rc)
        if stderr.strip():
            md_section(fh, "naabu stderr", stderr)
        if xml_path.is_file():
            fh.write(f"## nmap XML\n\nSaved to: `{xml_path}`\n\n---\n\n")

    print(f"  [+] Service scan output → {md_path}")
    return md_path


# ---------------------------------------------------------------------------
# Step 5 — naabu + nmap --script http-vhosts (virtual host scan)
# ---------------------------------------------------------------------------

def step_vhost_scan(ip: str, xml_path: Path, md_dir: Path, rate: int) -> Path:
    ensure(xml_path.parent)
    ensure(md_dir)
    stamp   = ts()
    md_path = md_dir / f"vhost_{stamp}.md"

    nmap_cli = f"nmap --script http-vhosts -oX {xml_path}"
    cmd = [
        "naabu",
        "-p", "-",
        "-rate",         str(rate),
        "-c",            str(NAABU_DEFAULTS["concurrency"]),
        "-retries",      str(NAABU_DEFAULTS["retries"]),
        "-warm-up-time", str(NAABU_DEFAULTS["warm_up"]),
        "-silent",
        "-host",         ip,
        "-nmap-cli",     nmap_cli,
    ]

    print(f"\n[*] Scanning for virtual hosts...")
    print(f"  Target : {ip}")
    stdout, stderr, rc = run(cmd, "naabu vhost scan", timeout=1800)

    with md_path.open("w", encoding="utf-8") as fh:
        md_header(fh, "WSTG-INFO-04 — Virtual Host Scan (naabu + nmap --script http-vhosts)", {
            "Target":    ip,
            "nmap XML":  str(xml_path),
            "Generated": datetime.utcnow().isoformat() + "Z",
        })
        md_section(fh, "Command", " ".join(cmd))
        md_section(fh, "naabu stdout", stdout, rc)
        if stderr.strip():
            md_section(fh, "naabu stderr", stderr)
        if xml_path.is_file():
            fh.write(f"## nmap XML\n\nSaved to: `{xml_path}`\n\n---\n\n")

    print(f"  [+] VHost scan output → {md_path}")
    return md_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args  = parse_args()
    base  = Path(args.base).resolve() if args.base else DEFAULT_BASE

    # Resolve domains file — default to Inputs/Data/domains.txt
    domains_path = (
        Path(args.domains).resolve()
        if args.domains
        else (base / DEFAULT_DOMAINS).resolve()
    )

    print(f"\n{'='*60}")
    print(f"  WSTG-INFO-04 Orchestrator")
    print(f"  Domains : {domains_path}")
    print(f"  IP      : {args.ip}")
    print(f"  Base    : {base}")
    print(f"{'='*60}")

    results = {}

    # ── Step 1: DNS ────────────────────────────────────────────────────────
    if not args.skip_dns:
        domains = load_lines(domains_path)
        if not domains:
            sys.exit("[ERROR] No domains loaded.")
        print(f"\n  Loaded {len(domains)} domain(s) from {domains_path}")
        results["dns"] = step_dns(
            domains,
            base / DNS_TXT_PATH,
            args.dns_sleep,
        )

    # ── Wait before port scans ─────────────────────────────────────────────
    if not args.skip_portscan or not args.skip_vhost:
        if args.no_wait:
            print("\n[*] Skipping 2-minute wait (--no-wait).")
        else:
            countdown(WAIT_SECONDS, "Waiting before port scans")

    # ── Step 3: Service scan ───────────────────────────────────────────────
    if not args.skip_portscan:
        results["service"] = step_service_scan(
            args.ip,
            base / SERVICE_XML,
            base / SERVICE_MD_DIR,
            args.naabu_rate,
        )

    # ── Wait before vhost scan ─────────────────────────────────────────────
    if not args.skip_vhost:
        if args.no_wait:
            print("\n[*] Skipping 2-minute wait (--no-wait).")
        else:
            countdown(WAIT_SECONDS, "Waiting before virtual host scan")

        results["vhost"] = step_vhost_scan(
            args.ip,
            base / VHOST_XML,
            base / VHOST_MD_DIR,
            args.naabu_rate,
        )

    # ── Summary ────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("  WSTG-INFO-04 Complete")
    for label, path in results.items():
        print(f"  {label:12s} → {path}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
