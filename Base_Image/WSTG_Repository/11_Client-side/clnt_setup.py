#!/usr/bin/env python3
"""
WSTG-CLNT — Client-Side Testing Setup
Script 1 of 4: clnt_setup.py

Interactive prompts to collect all variables needed for the client-side
test suite and writes them to clnt_config.json.

Variables collected:
  attacker_ip       Your IP address (where the test server will bind/listen)
  attacker_port     Port to serve the test pages on (default: 8888)
  attacker_path     Base path of your server root (default: /clnt_pages)
  target_domain     The target application's domain (e.g. https://target.example.com)
  target_path       A specific path or endpoint on the target (e.g. /app/dashboard)
  target_ports      Comma-separated list of target ports to test (e.g. 80,443,8080)
  xml_files         Comma-separated paths to Burp proxy XML exports to load
  templates         Which CLNT test templates to render (select from list)
  notes             Free-text engagement notes

Usage:
  python3 clnt_setup.py [--out clnt_config.json]
"""

import argparse
import ipaddress
import json
import os
import re
import socket
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
WIDTH   = 65

# ---------------------------------------------------------------------------
# Available templates
# ---------------------------------------------------------------------------
TEMPLATES = [
    ("clnt_01", "HTML Injection"),
    ("clnt_02", "Reflected XSS"),
    ("clnt_03", "DOM-Based XSS"),
    ("clnt_04", "CSS Injection Log Viewer"),
    ("clnt_05", "Client-Side Resource Manipulation"),
    ("clnt_06", "CORS Misconfiguration"),
    ("clnt_07", "XHR CORS Response Steal"),
    ("clnt_13", "Global Variable / JS Leak"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def detect_local_ip() -> str:
    """Best-effort local IP detection."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def prompt(question: str, default: str = "", required: bool = True) -> str:
    hint = f" [{default}]" if default else ""
    while True:
        raw = input(f"  {CYAN}{question}{hint}{RESET}\n  > ").strip()
        if not raw and default:
            return default
        if raw:
            return raw
        if not required:
            return ""
        print(f"  {YELLOW}  Required — please enter a value.{RESET}")


def prompt_port(question: str, default: int) -> int:
    while True:
        raw = prompt(question, str(default))
        try:
            port = int(raw)
            if 1 <= port <= 65535:
                return port
        except ValueError:
            pass
        print(f"  {YELLOW}  Enter a valid port number (1–65535).{RESET}")


def prompt_ports(question: str, default: str) -> list[int]:
    while True:
        raw = prompt(question, default)
        parts = [p.strip() for p in re.split(r"[,\s]+", raw) if p.strip()]
        ports = []
        valid = True
        for p in parts:
            try:
                n = int(p)
                if 1 <= n <= 65535:
                    ports.append(n)
                else:
                    valid = False
                    break
            except ValueError:
                valid = False
                break
        if valid and ports:
            return ports
        print(f"  {YELLOW}  Enter comma-separated port numbers.{RESET}")


def prompt_templates() -> list[str]:
    print(f"\n  {CYAN}Which CLNT templates do you want to render?{RESET}")
    for i, (key, name) in enumerate(TEMPLATES, start=1):
        print(f"    {i}. {key} — {name}")
    print(f"    a. All")
    while True:
        raw = input("  > ").strip().lower()
        if raw in ("a", "all", ""):
            return [t[0] for t in TEMPLATES]
        parts = [p.strip() for p in re.split(r"[,\s]+", raw) if p.strip()]
        selected = []
        valid    = True
        for part in parts:
            if part.isdigit():
                idx = int(part) - 1
                if 0 <= idx < len(TEMPLATES):
                    selected.append(TEMPLATES[idx][0])
                else:
                    valid = False
                    break
            elif part in [t[0] for t in TEMPLATES]:
                selected.append(part)
            else:
                valid = False
                break
        if valid and selected:
            return list(dict.fromkeys(selected))  # deduplicate, preserve order
        print(f"  {YELLOW}  Enter numbers (1-{len(TEMPLATES)}), template keys, or 'a' for all.{RESET}")


def prompt_xml_files() -> list[str]:
    print(f"\n  {CYAN}Paths to Burp proxy XML file(s) — comma-separated{RESET}")
    print(f"  {DIM}  Leave blank to skip XML-based endpoint rendering.{RESET}")
    raw = input("  > ").strip()
    if not raw:
        return []
    paths = [p.strip().strip('"').strip("'") for p in raw.split(",") if p.strip()]
    valid = []
    for p in paths:
        if os.path.isfile(p):
            valid.append(p)
        else:
            print(f"  {YELLOW}  Warning: file not found, still recorded: {p}{RESET}")
            valid.append(p)  # record anyway — might be set up later
    return valid


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-CLNT setup — collect config and write clnt_config.json"
    )
    p.add_argument("--out",
        default="clnt_config.json",
        metavar="PATH",
        help="Output config JSON path (default: clnt_config.json)")
    args = p.parse_args()

    print(f"\n{BOLD}{'='*WIDTH}{RESET}")
    print(f"{BOLD}  WSTG-CLNT — Client-Side Testing Setup{RESET}")
    print(f"{BOLD}{'='*WIDTH}{RESET}\n")
    print(f"  Fill in the values below. Press Enter to accept defaults.\n")

    detected_ip = detect_local_ip()

    # ── Collect values ───────────────────────────────────────────────────────
    attacker_ip   = prompt("Your IP address (attacker/server IP)", detected_ip)
    attacker_port = prompt_port("Your server port", 8888)
    attacker_path = prompt("Your server base path", "/clnt_pages")
    target_domain = prompt("Target domain (e.g. https://target.example.com)")
    target_path   = prompt("Target path or endpoint (e.g. /app/search)", "/")
    target_ports  = prompt_ports("Target port(s) — comma-separated", "80,443")
    xml_files     = prompt_xml_files()
    templates     = prompt_templates()
    notes         = prompt("Engagement notes (optional)", required=False)

    # Normalise target domain — strip trailing slash
    if target_domain.endswith("/"):
        target_domain = target_domain.rstrip("/")

    config = {
        "_meta": {
            "generated":  datetime.now().isoformat(),
            "tool":       "WSTG-CLNT setup",
        },
        "attacker_ip":   attacker_ip,
        "attacker_port": attacker_port,
        "attacker_path": attacker_path,
        "target_domain": target_domain,
        "target_path":   target_path,
        "target_ports":  target_ports,
        "xml_files":     xml_files,
        "templates":     templates,
        "notes":         notes,
        # Derived convenience values
        "attacker_base_url": f"http://{attacker_ip}:{attacker_port}{attacker_path}",
        "target_base_url":   f"{target_domain}{target_path}",
    }

    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

    print(f"\n  {'─'*50}")
    print(f"  {GREEN}[+] Config written → {args.out}{RESET}\n")
    print(f"  Attacker  : {attacker_ip}:{attacker_port}{attacker_path}")
    print(f"  Target    : {target_domain}{target_path}")
    print(f"  Ports     : {target_ports}")
    print(f"  Templates : {templates}")
    print(f"  XML files : {xml_files if xml_files else 'none'}")
    print(f"\n  {DIM}Next: source clnt_env.sh, then run clnt_render.py{RESET}\n")


if __name__ == "__main__":
    main()
