#!/usr/bin/env python3
"""
info2_orchestrator.py — WSTG-INFO-02 Web Server Fingerprinting Orchestrator
Location: WSTG_Repository/01_Information_Gathering/WSTG-INFO-02/Utilities/python/info2_orchestrator.py

Orchestrates the full WSTG-INFO-02 recon pipeline:
  1. Parse target URL(s) from a Burp XML export
  2. curl -I  (single domain)  OR  httpx  (multiple domains)
     → Utilities/Kali_Tools/curl/<timestamp>.md  or  .../httpx/<timestamp>.md
  3. Wait 2 minutes
  4. whatweb against each target
     → Utilities/Kali_Tools/whatweb/<timestamp>.md
  5. Run WebserverEnum.py (Burp XML version scanner)
     → Outputs/test_outputs/findings.md

Usage:
    python info2_orchestrator.py --file <burp_export.xml>
                                 [--webserverenum <path/to/WebserverEnum.py>]
                                 [--base <repo_base_path>]
                                 [--no-wait]
"""

import argparse
import json
import os
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Defaults — paths relative to WSTG-INFO-02 root
# ---------------------------------------------------------------------------

DEFAULT_BASE = Path(__file__).resolve().parents[2]  # WSTG-INFO-02/
CURL_OUT_DIR    = "Utilities/Kali_Tools/curl"
HTTPX_OUT_DIR   = "Utilities/Kali_Tools/httpx"
WHATWEB_OUT_DIR = "Utilities/Kali_Tools/whatweb"
FINDINGS_OUT    = "Outputs/test_outputs/findings.md"
WEBSERVERENUM   = "Utilities/python/WebserverEnum.py"

WAIT_SECONDS = 120


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        prog="info2_orchestrator.py",
        description="WSTG-INFO-02 Web Server Fingerprinting Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--file", "-f", required=True,
        help="Path to Burp Suite XML export file."
    )
    parser.add_argument(
        "--webserverenum", default=None,
        help=(
            "Path to WebserverEnum.py (version scanner). "
            f"Defaults to <base>/{WEBSERVERENUM}"
        ),
    )
    parser.add_argument(
        "--base", default=None,
        help=(
            "Base path of WSTG-INFO-02 directory. "
            "Defaults to two levels above this script."
        ),
    )
    parser.add_argument(
        "--no-wait", action="store_true",
        help="Skip the 2-minute wait between curl/httpx and whatweb (useful for testing)."
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------

def extract_urls_from_xml(xml_path: str) -> list[str]:
    """Return unique URLs found in a Burp Suite XML export."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    seen: set[str] = set()
    urls: list[str] = []
    for item in root.findall("item"):
        url_elem = item.find("url")
        if url_elem is not None and url_elem.text:
            u = url_elem.text.strip()
            if u and u not in seen:
                seen.add(u)
                urls.append(u)
    return urls


def unique_domains(urls: list[str]) -> list[str]:
    """Extract unique scheme+host combinations from a list of URLs."""
    seen: set[str] = set()
    domains: list[str] = []
    for u in urls:
        p = urlparse(u)
        base = f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else u
        if base not in seen:
            seen.add(base)
            domains.append(base)
    return domains


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def ts() -> str:
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def run_cmd(cmd: list[str], label: str) -> tuple[str, str, int]:
    """Run a shell command; return (stdout, stderr, returncode)."""
    print(f"  [>] {' '.join(cmd)}")
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60
        )
        return proc.stdout, proc.stderr, proc.returncode
    except FileNotFoundError:
        msg = f"[!] Command not found: {cmd[0]}"
        print(msg)
        return "", msg, 127
    except subprocess.TimeoutExpired:
        msg = f"[!] Timed out: {' '.join(cmd)}"
        print(msg)
        return "", msg, 1


def write_md(out_path: Path, title: str, sections: list[dict]) -> None:
    """
    Write a simple Markdown report.
    sections = [{"heading": str, "content": str}, ...]
    """
    with out_path.open("w", encoding="utf-8") as fh:
        fh.write(f"# {title}\n\n")
        fh.write(f"**Generated:** {datetime.utcnow().isoformat()}Z  \n\n")
        for sec in sections:
            fh.write(f"## {sec['heading']}\n\n")
            fh.write("```\n")
            fh.write(sec["content"].strip())
            fh.write("\n```\n\n")
    print(f"  [+] Written → {out_path}")


# ---------------------------------------------------------------------------
# Step 2 — curl -I / httpx
# ---------------------------------------------------------------------------

def step_curl(domain: str, out_dir: Path) -> str:
    """Single-domain header grab with curl -I."""
    ensure_dir(out_dir)
    out_file = out_dir / f"curl_{ts()}.md"

    stdout, stderr, rc = run_cmd(["curl", "-I", "-s", "-L", "--max-time", "15", domain], "curl")
    content = stdout if stdout else stderr

    write_md(
        out_file,
        title=f"curl -I: {domain}",
        sections=[{"heading": "Response Headers", "content": content}],
    )
    return str(out_file)


def step_httpx(domains: list[str], out_dir: Path) -> str:
    """Multi-domain header scan with httpx."""
    ensure_dir(out_dir)
    out_file = out_dir / f"httpx_{ts()}.md"

    # Build httpx command: probe all domains with tech-detect + headers
    cmd = [
        "httpx",
        "-silent",
        "-title",
        "-tech-detect",
        "-status-code",
        "-content-length",
        "-response-time",
        "-server",
        "-web-server",
    ] + domains

    stdout, stderr, rc = run_cmd(cmd, "httpx")
    content = stdout if stdout else stderr

    write_md(
        out_file,
        title="httpx Multi-Domain Probe",
        sections=[
            {"heading": f"Targets ({len(domains)})", "content": "\n".join(domains)},
            {"heading": "httpx Output", "content": content},
        ],
    )
    return str(out_file)


# ---------------------------------------------------------------------------
# Step 4 — whatweb
# ---------------------------------------------------------------------------

def step_whatweb(domains: list[str], out_dir: Path) -> str:
    """Run whatweb against all targets; write Markdown output."""
    ensure_dir(out_dir)
    out_file = out_dir / f"whatweb_{ts()}.md"

    sections = []
    for domain in domains:
        stdout, stderr, rc = run_cmd(
            ["whatweb", "--color=never", "-v", domain], "whatweb"
        )
        content = stdout if stdout else stderr
        sections.append({"heading": f"whatweb → {domain}", "content": content})

    write_md(out_file, title="WhatWeb Fingerprinting Results", sections=sections)
    return str(out_file)


# ---------------------------------------------------------------------------
# Step 5 — WebserverEnum.py (Burp XML version scanner)
# ---------------------------------------------------------------------------

def step_webserverenum(xml_path: str, script_path: Path, findings_path: Path) -> str:
    """
    Call WebserverEnum.py with the Burp XML and direct its JSON output,
    then convert to a Markdown findings report.
    """
    ensure_dir(findings_path.parent)

    # WebserverEnum.py writes JSON; we capture it then render as MD
    json_tmp = findings_path.parent / f"webserverenum_raw_{ts()}.json"

    stdout, stderr, rc = run_cmd(
        [sys.executable, str(script_path), "--file", xml_path, "--output", str(json_tmp)],
        "WebserverEnum.py",
    )

    if rc != 0:
        print(f"  [!] WebserverEnum.py exited {rc}: {stderr}")

    # Build Markdown findings from JSON output
    findings_sections = []

    if json_tmp.is_file():
        try:
            with json_tmp.open("r", encoding="utf-8") as fh:
                data = json.load(fh)

            for item_id, item in data.items():
                url = item.get("url", "unknown")
                products = item.get("detected_products", [])
                headers = item.get("headers", {})

                lines = [f"**URL:** `{url}`\n"]

                if headers:
                    lines.append("**Interesting Headers:**")
                    for h, v in headers.items():
                        lines.append(f"- `{h}`: `{v}`")

                if products:
                    lines.append("\n**Detected Products / Versions:**")
                    for p in products:
                        prod    = p.get("product", "unknown")
                        ver     = p.get("version", "unknown")
                        src_hdr = p.get("source_header", "")
                        full    = p.get("full_header_value", "")
                        lines.append(
                            f"- **{prod}** v{ver}  _(via `{src_hdr}`: `{full}`)_"
                        )

                findings_sections.append({
                    "heading": f"Item {item_id} — {url}",
                    "content": "\n".join(lines),
                })

        except (json.JSONDecodeError, Exception) as e:
            findings_sections.append({
                "heading": "Parse Error",
                "content": f"Could not parse WebserverEnum output: {e}\n\nRaw stdout:\n{stdout}",
            })
    else:
        findings_sections.append({
            "heading": "No Output",
            "content": f"WebserverEnum.py produced no output file.\n\nstdout:\n{stdout}\nstderr:\n{stderr}",
        })

    write_md(
        findings_path,
        title="WSTG-INFO-02 — Web Server Version Findings",
        sections=findings_sections,
    )
    return str(findings_path)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    base = Path(args.base).resolve() if args.base else DEFAULT_BASE
    xml_path = Path(args.file).resolve()

    if not xml_path.is_file():
        sys.exit(f"[ERROR] XML file not found: {xml_path}")

    webserverenum_path = (
        Path(args.webserverenum).resolve()
        if args.webserverenum
        else (base / WEBSERVERENUM).resolve()
    )

    print(f"\n{'='*60}")
    print(f"  WSTG-INFO-02 Orchestrator")
    print(f"  XML  : {xml_path}")
    print(f"  Base : {base}")
    print(f"{'='*60}\n")

    # ── Step 1: Extract targets ──────────────────────────────────────────
    print("[1/5] Extracting URLs from Burp XML...")
    urls = extract_urls_from_xml(str(xml_path))
    if not urls:
        sys.exit("[ERROR] No URLs found in the XML file.")
    domains = unique_domains(urls)
    print(f"  Found {len(urls)} URL(s) across {len(domains)} unique domain(s):")
    for d in domains:
        print(f"    {d}")

    # ── Step 2: curl -I or httpx ─────────────────────────────────────────
    print(f"\n[2/5] Header enumeration ({'curl -I' if len(domains) == 1 else 'httpx'})...")
    if len(domains) == 1:
        curl_out = step_curl(domains[0], base / CURL_OUT_DIR)
    else:
        curl_out = step_httpx(domains, base / HTTPX_OUT_DIR)

    # ── Step 3: Wait ─────────────────────────────────────────────────────
    if args.no_wait:
        print("\n[3/5] Skipping 2-minute wait (--no-wait flag set).")
    else:
        print(f"\n[3/5] Waiting {WAIT_SECONDS}s before whatweb run...")
        for remaining in range(WAIT_SECONDS, 0, -10):
            print(f"  {remaining}s remaining...", end="\r")
            time.sleep(10)
        print(" " * 30)  # clear the line

    # ── Step 4: whatweb ──────────────────────────────────────────────────
    print("\n[4/5] Running whatweb...")
    whatweb_out = step_whatweb(domains, base / WHATWEB_OUT_DIR)

    # ── Step 5: WebserverEnum.py ─────────────────────────────────────────
    print("\n[5/5] Running WebserverEnum.py (Burp XML version scanner)...")
    if not webserverenum_path.is_file():
        print(f"  [!] WebserverEnum.py not found at {webserverenum_path}")
        print(f"      Place WebserverEnum.py (the Burp XML header analyzer) at that path.")
        findings_out = "[skipped — script not found]"
    else:
        findings_out = step_webserverenum(
            str(xml_path),
            webserverenum_path,
            base / FINDINGS_OUT,
        )

    # ── Summary ──────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("  WSTG-INFO-02 Complete")
    print(f"  curl/httpx output : {curl_out}")
    print(f"  whatweb output    : {whatweb_out}")
    print(f"  findings (MD)     : {findings_out}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
