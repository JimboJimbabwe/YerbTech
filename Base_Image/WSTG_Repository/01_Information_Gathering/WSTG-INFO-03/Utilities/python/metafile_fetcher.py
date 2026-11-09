#!/usr/bin/env python3
"""
metafile_fetcher.py — WSTG-INFO-03 Web Server Metafile Retriever
Location: WSTG_Repository/01_Information_Gathering/WSTG-INFO-03/Utilities/python/metafile_fetcher.py

Fetches common server metafiles using both wget and curl, with and without
the /.well-known/ path prefix. Results are written as Markdown, one file
per tool, under Outputs/test_outputs/<TOOL_NAME>/.

Targets:
    security.txt, robots.txt, llms.txt, humans.txt, sitemap.xml

Usage:
    python metafile_fetcher.py --url https://example.com
                               [--output-base <path>]
                               [--timeout <seconds>]
"""

import argparse
import subprocess
import sys
import tempfile
import os
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Target definitions
# (filename, well-known variant exists?, direct path)
# ---------------------------------------------------------------------------

TARGETS = [
    # (filename,       well_known_prefix)
    ("security.txt",   True),
    ("robots.txt",     True),
    ("llms.txt",       True),
    ("humans.txt",     False),   # no official well-known path
    ("sitemap.xml",    False),
]

# Output subfolder names per tool
WGET_DIR  = "wget"
CURL_DIR  = "curl"

DEFAULT_OUTPUT_BASE = Path(__file__).resolve().parents[2] / "Outputs" / "test_outputs"
TIMEOUT = 15


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        prog="metafile_fetcher.py",
        description="WSTG-INFO-03 — Fetch server metafiles via wget and curl",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--url", "-u", required=True,
        help="Base URL of the target (e.g. https://example.com)"
    )
    parser.add_argument(
        "--output-base", "-o", default=None,
        help=(
            f"Base output directory. "
            f"Tool subfolders (wget/, curl/) are created here. "
            f"Defaults to Outputs/test_outputs/ relative to WSTG-INFO-03 root."
        )
    )
    parser.add_argument(
        "--timeout", "-t", type=int, default=TIMEOUT,
        help=f"Per-request timeout in seconds (default: {TIMEOUT})"
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# URL builders — with and without .well-known/
# ---------------------------------------------------------------------------

def build_urls(base: str, filename: str, well_known: bool) -> list[dict]:
    """
    Return a list of URL dicts to try for a given metafile.
    Always includes the direct path. Adds /.well-known/ variant when applicable.
    """
    base = base.rstrip("/")
    variants = []

    # Direct path (always)
    variants.append({
        "label":  f"direct — /{filename}",
        "url":    f"{base}/{filename}",
    })

    # .well-known/ variant
    if well_known:
        variants.append({
            "label":  f"well-known — /.well-known/{filename}",
            "url":    f"{base}/.well-known/{filename}",
        })

    return variants


# ---------------------------------------------------------------------------
# Runner helpers
# ---------------------------------------------------------------------------

def run_wget(url: str, timeout: int) -> tuple[str, int]:
    """Fetch URL with wget, return (body_or_error, returncode)."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".tmp") as tf:
        tmp_path = tf.name

    try:
        proc = subprocess.run(
            [
                "wget",
                "--no-verbose",
                "--timeout", str(timeout),
                "--tries", "1",
                "-O", tmp_path,
                url,
            ],
            capture_output=True, text=True, timeout=timeout + 5
        )
        try:
            with open(tmp_path, "r", encoding="utf-8", errors="replace") as fh:
                body = fh.read().strip()
        except Exception:
            body = ""
        output = body if body else (proc.stderr.strip() or "[empty response]")
        return output, proc.returncode
    except FileNotFoundError:
        return "[wget not found on PATH]", 127
    except subprocess.TimeoutExpired:
        return "[wget timed out]", 1
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def run_curl(url: str, timeout: int) -> tuple[str, int]:
    """Fetch URL with curl, return (body_or_error, returncode)."""
    try:
        proc = subprocess.run(
            [
                "curl",
                "-s",                     # silent (no progress)
                "-L",                     # follow redirects
                "--max-time", str(timeout),
                "--fail",                 # non-zero exit on HTTP errors
                url,
            ],
            capture_output=True, text=True, timeout=timeout + 5
        )
        output = proc.stdout.strip() if proc.stdout.strip() else (
            proc.stderr.strip() or "[empty response]"
        )
        return output, proc.returncode
    except FileNotFoundError:
        return "[curl not found on PATH]", 127
    except subprocess.TimeoutExpired:
        return "[curl timed out]", 1


# ---------------------------------------------------------------------------
# Markdown writer
# ---------------------------------------------------------------------------

def append_md_section(md_path: Path, heading: str, subheading: str,
                       url: str, returncode: int, content: str) -> None:
    """Append one result block to the Markdown file."""
    status = "✅ OK" if returncode == 0 else f"❌ Error (rc={returncode})"
    with md_path.open("a", encoding="utf-8") as fh:
        fh.write(f"## {heading}\n\n")
        fh.write(f"**Variant:** {subheading}  \n")
        fh.write(f"**URL:** `{url}`  \n")
        fh.write(f"**Status:** {status}  \n")
        fh.write(f"**Fetched:** {datetime.utcnow().isoformat()}Z  \n\n")
        fh.write("```\n")
        fh.write(content[:8000])   # cap at 8 KB per entry
        if len(content) > 8000:
            fh.write("\n... [truncated]")
        fh.write("\n```\n\n---\n\n")


def init_md(md_path: Path, tool: str, base_url: str) -> None:
    """Write the Markdown header (overwrites if exists)."""
    with md_path.open("w", encoding="utf-8") as fh:
        fh.write(f"# WSTG-INFO-03 Metafile Fetch — {tool.upper()}\n\n")
        fh.write(f"**Target:** `{base_url}`  \n")
        fh.write(f"**Generated:** {datetime.utcnow().isoformat()}Z  \n\n")
        fh.write("---\n\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    base_url = args.url.rstrip("/")
    parsed = urlparse(base_url)
    if not parsed.scheme or not parsed.netloc:
        sys.exit(f"[ERROR] Invalid URL: {base_url}")

    output_base = Path(args.output_base).resolve() if args.output_base else DEFAULT_OUTPUT_BASE

    wget_dir = output_base / WGET_DIR
    curl_dir = output_base / CURL_DIR
    wget_dir.mkdir(parents=True, exist_ok=True)
    curl_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    wget_md = wget_dir / f"metafiles_{timestamp}.md"
    curl_md = curl_dir / f"metafiles_{timestamp}.md"

    init_md(wget_md, "wget", base_url)
    init_md(curl_md, "curl", base_url)

    print(f"\n{'='*60}")
    print(f"  WSTG-INFO-03 Metafile Fetcher")
    print(f"  Target : {base_url}")
    print(f"  wget → {wget_md}")
    print(f"  curl → {curl_md}")
    print(f"{'='*60}\n")

    for filename, well_known in TARGETS:
        variants = build_urls(base_url, filename, well_known)

        for variant in variants:
            label = variant["label"]
            url   = variant["url"]
            heading = f"{filename} — {label}"

            # ── wget ──────────────────────────────────────────────────────
            print(f"[wget] {url}")
            w_content, w_rc = run_wget(url, args.timeout)
            append_md_section(wget_md, heading, label, url, w_rc, w_content)

            # ── curl ──────────────────────────────────────────────────────
            print(f"[curl] {url}")
            c_content, c_rc = run_curl(url, args.timeout)
            append_md_section(curl_md, heading, label, url, c_rc, c_content)

    print(f"\n[+] wget output : {wget_md}")
    print(f"[+] curl output : {curl_md}")
    print("[+] Done.\n")


if __name__ == "__main__":
    main()
