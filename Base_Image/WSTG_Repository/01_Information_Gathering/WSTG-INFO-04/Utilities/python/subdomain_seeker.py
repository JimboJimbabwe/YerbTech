#!/usr/bin/env python3
"""
subdomain_seeker.py — WSTG-INFO-04 Subdomain Discovery from Burp XML
Location: WSTG_Repository/01_Information_Gathering/WSTG-INFO-04/Utilities/python/subdomain_seeker.py

Reads a Burp Suite proxy XML export, scans the HTML body of every
response for strings matching SUBDOMAIN.TARGET.com, and outputs
a deduplicated list of discovered subdomains as Markdown.

Usage:
    python subdomain_seeker.py --input_xml <burp_export.xml>
                               --target_url <target.com>
                               [--output-base <path>]
                               [--include-requests]
"""

import argparse
import base64
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from collections import defaultdict


DEFAULT_BASE = Path(__file__).resolve().parents[2]  # WSTG-INFO-04/
TOOL_DIR     = "subdomain_seeker"


# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        prog="subdomain_seeker.py",
        description="WSTG-INFO-04 — Discover subdomains referenced in Burp XML responses",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--input_xml", "-x", required=True,
        help="Path to Burp Suite proxy XML export."
    )
    parser.add_argument(
        "--target_url", "-t", required=True,
        help="Root domain to search for (e.g. example.com). "
             "All SUBDOMAIN.example.com matches are captured."
    )
    parser.add_argument(
        "--output-base", "-o", default=None,
        help="Base output directory. Defaults to Outputs/test_outputs/ "
             "relative to WSTG-INFO-04 root."
    )
    parser.add_argument(
        "--include-requests", action="store_true",
        help="Also scan request bodies (not just responses) for subdomain references."
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# XML parsing
# ---------------------------------------------------------------------------

def decode_element(elem) -> str:
    """Decode a Burp XML element — handles base64 and plain text."""
    if elem is None:
        return ""
    text = elem.text or ""
    if elem.get("base64") == "true" and text:
        try:
            return base64.b64decode(text).decode("utf-8", errors="replace")
        except Exception:
            return ""
    return text


def parse_burp_xml(xml_path: str) -> list[dict]:
    """
    Parse Burp XML, return a list of item dicts:
      { index, url, request_text, response_text }
    """
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        sys.exit(f"[ERROR] Could not parse XML: {e}")

    root = tree.getroot()
    items = []

    for i, item in enumerate(root.findall("item"), 1):
        url_elem = item.find("url")
        url = url_elem.text.strip() if (url_elem is not None and url_elem.text) else "unknown"
        items.append({
            "index":         i,
            "url":           url,
            "request_text":  decode_element(item.find("request")),
            "response_text": decode_element(item.find("response")),
        })

    return items


# ---------------------------------------------------------------------------
# Subdomain extraction
# ---------------------------------------------------------------------------

def build_pattern(target: str) -> re.Pattern:
    """
    Build a regex that matches any SUBDOMAIN.target.com string.
    Captures the full subdomain string (including the root domain).

    Matches:
      - sub.target.com
      - sub.sub2.target.com
      - https://sub.target.com/path
      - "sub.target.com"
      - sub.target.com:8080

    Does NOT match:
      - target.com itself (requires at least one subdomain label)
    """
    escaped = re.escape(target.lstrip("www.").lstrip("*."))
    # Match one or more subdomain labels followed by .target.com
    pattern = rf'(?<![.\w])((?:[a-zA-Z0-9_-]+\.)+{escaped})(?:[:/\s"\'\<\>)]|$)'
    return re.compile(pattern, re.IGNORECASE)


def extract_subdomains(text: str, pattern: re.Pattern, target: str) -> set[str]:
    """Return all unique subdomain matches found in text."""
    found = set()
    for match in pattern.finditer(text):
        candidate = match.group(1).lower().rstrip(".")
        # Must have at least one label beyond the root domain
        root = target.lower().lstrip("www.").lstrip("*.")
        if candidate != root and candidate.endswith("." + root):
            found.add(candidate)
    return found


# ---------------------------------------------------------------------------
# Markdown output
# ---------------------------------------------------------------------------

def write_report(
    md_path: Path,
    target: str,
    xml_path: str,
    items_scanned: int,
    subdomain_map: dict[str, list[dict]],
    include_requests: bool,
) -> None:
    """
    subdomain_map: { subdomain: [ {index, url, found_in}, ... ] }
    """
    all_subdomains = sorted(subdomain_map.keys())
    total = len(all_subdomains)

    with md_path.open("w", encoding="utf-8") as fh:
        fh.write("# WSTG-INFO-04 — Subdomain Discovery (Burp XML)\n\n")
        fh.write(f"**Target domain:** `{target}`  \n")
        fh.write(f"**Input XML:** `{xml_path}`  \n")
        fh.write(f"**Items scanned:** {items_scanned}  \n")
        fh.write(f"**Scanned requests too:** {'Yes' if include_requests else 'No'}  \n")
        fh.write(f"**Unique subdomains found:** {total}  \n")
        fh.write(f"**Generated:** {datetime.utcnow().isoformat()}Z  \n\n")
        fh.write("---\n\n")

        # Summary table
        fh.write("## Discovered Subdomains\n\n")
        if not all_subdomains:
            fh.write(f"_No subdomains of `{target}` found in the scanned content._\n\n")
        else:
            fh.write("| # | Subdomain | First Seen In | Found In |\n")
            fh.write("|---|---|---|---|\n")
            for idx, sub in enumerate(all_subdomains, 1):
                hits = subdomain_map[sub]
                first_url = hits[0]["url"]
                sources   = ", ".join(sorted({h["found_in"] for h in hits}))
                fh.write(f"| {idx} | `{sub}` | `{first_url}` | {sources} |\n")
            fh.write("\n")

        # Detailed hits per subdomain
        fh.write("---\n\n## Detail — Hit Locations\n\n")
        for sub in all_subdomains:
            hits = subdomain_map[sub]
            fh.write(f"### `{sub}`\n\n")
            fh.write(f"**Occurrences:** {len(hits)}  \n\n")
            fh.write("| Item # | Source URL | Found In |\n")
            fh.write("|---|---|---|\n")
            for h in hits:
                fh.write(f"| {h['index']} | `{h['url']}` | {h['found_in']} |\n")
            fh.write("\n")

        fh.write("---\n\n_End of report._\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    # Normalise target — strip scheme/path if accidentally passed a full URL
    target = args.target_url
    parsed = urlparse(target)
    if parsed.netloc:
        target = parsed.netloc
    target = target.lstrip("www.").strip("/")

    xml_path = Path(args.input_xml).resolve()
    if not xml_path.is_file():
        sys.exit(f"[ERROR] XML file not found: {xml_path}")

    output_base = (
        Path(args.output_base).resolve()
        if args.output_base
        else DEFAULT_BASE / "Outputs" / "test_outputs"
    )
    tool_dir = output_base / TOOL_DIR
    tool_dir.mkdir(parents=True, exist_ok=True)

    stamp   = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    md_path = tool_dir / f"subdomains_{stamp}.md"

    print(f"\n{'='*60}")
    print(f"  WSTG-INFO-04 Subdomain Seeker")
    print(f"  Target  : {target}")
    print(f"  XML     : {xml_path}")
    print(f"  Output  : {md_path}")
    print(f"{'='*60}\n")

    items   = parse_burp_xml(str(xml_path))
    pattern = build_pattern(target)

    # subdomain → list of hit dicts
    subdomain_map: dict[str, list[dict]] = defaultdict(list)

    for item in items:
        # Always scan responses
        resp_subs = extract_subdomains(item["response_text"], pattern, target)
        for sub in resp_subs:
            subdomain_map[sub].append({
                "index":    item["index"],
                "url":      item["url"],
                "found_in": "response",
            })

        # Optionally scan requests
        if args.include_requests:
            req_subs = extract_subdomains(item["request_text"], pattern, target)
            for sub in req_subs:
                subdomain_map[sub].append({
                    "index":    item["index"],
                    "url":      item["url"],
                    "found_in": "request",
                })

    total = len(subdomain_map)
    print(f"[+] Scanned {len(items)} item(s)")
    print(f"[+] Found {total} unique subdomain(s)")
    if total:
        for sub in sorted(subdomain_map.keys()):
            print(f"    {sub}  ({len(subdomain_map[sub])} hit(s))")

    write_report(
        md_path,
        target,
        str(xml_path),
        len(items),
        subdomain_map,
        args.include_requests,
    )

    print(f"\n[+] Report written → {md_path}\n")


if __name__ == "__main__":
    main()
