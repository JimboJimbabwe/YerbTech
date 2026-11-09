#!/usr/bin/env python3
"""
WSTG-BUSL-08 — Upload of Unexpected File Types
Script 1: busl_08_wordlist.py

Generates a Burp Intruder wordlist of paths to probe for unexpected
upload endpoints. Combines:

  1. Paths extracted from the Burp XML proxy capture (file_input.xml)
  2. Service-catalogue paths from svc_repo.json (secondary service repo)
     — pulls CommonEndpoints + UndesirableEndpoints from every service
     entry across all ports after deduplication
  3. MISSING LOGIC stub for primary service repo (returns [])
  4. Upload-specific path expansions (common upload subdirectory variants)
  5. Extension-appended variants of all collected paths:
       Unexpected: .txt .csv .xml .html .svg .pdf .zip .tar.gz
       Malicious:  .php .asp .aspx .jsp .py .rb .sh
     (BUSL-08 focus = unexpected; extension list kept broad for discovery)
  6. Indexing / directory-traversal strings that may trigger directory
     listing or path disclosure

Outputs:
  WSTG-BUSL-08/inputs/wordlist/upload_paths.txt
  WSTG-BUSL-08/inputs/json/path_assessment.json

Usage:
  python3 WSTG-BUSL-08/utilities/python/busl_08_wordlist.py \\
      [--xml  WSTG-BUSL-08/inputs/xml/file_input.xml] \\
      [--repo WSTG-BUSL-08/inputs/json/svc_repo.json] \\
      [--out  WSTG-BUSL-08/inputs/wordlist/upload_paths.txt]
"""

import argparse
import base64
import json
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urlparse


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


# ---------------------------------------------------------------------------
# File extensions
# ---------------------------------------------------------------------------

# BUSL-08: unexpected (non-executable) file types
UNEXPECTED_EXTENSIONS = [
    ".txt", ".csv", ".xml", ".html", ".htm", ".svg", ".pdf",
    ".zip", ".tar.gz", ".tar", ".gz", ".bz2", ".rar", ".7z",
    ".docx", ".xlsx", ".pptx", ".doc", ".xls",
    ".json", ".yaml", ".yml", ".log", ".md",
    ".mp4", ".mp3", ".avi", ".mov",
    ".jpeg", ".jpg", ".png", ".gif", ".bmp", ".ico", ".webp",
    ".ttf", ".woff", ".woff2",
]

# Also include executable/script types for breadth — BUSL-09 separates these
# as "malicious", but discovering they 200 here is still a BUSL-08 finding
SCRIPT_EXTENSIONS = [
    ".php", ".php3", ".php4", ".php5", ".phtml",
    ".asp", ".aspx", ".ashx", ".asmx",
    ".jsp", ".jspx",
    ".py", ".rb", ".pl", ".sh", ".bash",
    ".cgi", ".cfm",
    ".exe", ".bat", ".bin", ".cmd",
    ".js",  ".ts",
    ".htaccess", ".htpasswd",
]

ALL_EXTENSIONS = UNEXPECTED_EXTENSIONS + SCRIPT_EXTENSIONS


# ---------------------------------------------------------------------------
# Indexing / traversal strings
# ---------------------------------------------------------------------------

INDEXING_STRINGS = [
    # Directory listing triggers
    "/",
    "/.",
    "/..",
    "/../",
    "./",
    "../",
    "*",
    "%2F",
    "%2F.",
    "%2F..",
    "%2F../",
    "%2F%2F",
    "%252F",
    # Null bytes and encodings that may bypass validation
    "%00",
    "%00.jpg",
    "%00.png",
    # Double-slash / path confusion
    "//",
    "///",
    # Windows UNC
    "\\",
    "\\\\",
    # Common index files that indicate directory is browsable
    "/index.php",
    "/index.html",
    "/index.htm",
    "/default.asp",
    "/default.aspx",
    # Apache mod_autoindex triggers
    "/?C=N;O=D",
    "/?C=M;O=A",
    "/?C=S;O=A",
    "/?C=D;O=A",
    # Tilde (Apache partial content / IIS short name)
    "/~",
    # Empty filename (some parsers accept)
    "",
]


# ---------------------------------------------------------------------------
# Hardcoded upload-specific path base list
# ---------------------------------------------------------------------------

UPLOAD_BASE_PATHS = [
    "/upload",
    "/uploads",
    "/upload/",
    "/uploads/",
    "/file",
    "/files",
    "/file/",
    "/files/",
    "/media",
    "/media/",
    "/images",
    "/images/",
    "/img",
    "/img/",
    "/attachments",
    "/attachments/",
    "/documents",
    "/documents/",
    "/docs",
    "/docs/",
    "/assets",
    "/assets/",
    "/static",
    "/static/",
    "/content",
    "/content/",
    "/data",
    "/data/",
    "/tmp",
    "/tmp/",
    "/temp",
    "/temp/",
    "/storage",
    "/storage/",
    "/public",
    "/public/",
    "/private",
    "/private/",
    "/user",
    "/users",
    "/user/",
    "/users/",
    "/profile",
    "/profile/",
    "/avatar",
    "/avatar/",
    "/photo",
    "/photos",
    "/photo/",
    "/photos/",
    "/download",
    "/downloads",
    "/download/",
    "/downloads/",
    "/export",
    "/exports",
    "/export/",
    "/exports/",
    "/import",
    "/imports",
    "/import/",
    "/imports/",
    "/backup",
    "/backups",
    "/backup/",
    "/backups/",
    "/log",
    "/logs",
    "/log/",
    "/logs/",
    "/report",
    "/reports",
    "/report/",
    "/reports/",
    "/share",
    "/shared",
    "/share/",
    "/shared/",
    "/resources",
    "/resources/",
    "/res",
    "/res/",
    # API upload variants
    "/api/upload",
    "/api/uploads",
    "/api/file",
    "/api/files",
    "/api/media",
    "/api/v1/upload",
    "/api/v1/uploads",
    "/api/v1/file",
    "/api/v1/files",
    "/api/v2/upload",
    "/api/v2/files",
    # Admin / CMS upload variants
    "/admin/upload",
    "/admin/uploads",
    "/admin/files",
    "/admin/media",
    "/wp-content/uploads",
    "/wp-content/uploads/",
    "/sites/default/files",
    "/sites/default/files/",
    "/wp-admin/upload.php",
]


# ---------------------------------------------------------------------------
# Primary service repo stub  ← MISSING LOGIC
# ---------------------------------------------------------------------------

def get_primary_repo_paths(xml_path: str) -> list[str]:
    """
    MISSING LOGIC — Primary service repository lookup.

    This function should query the primary service repository using the
    target application's URL / hostname extracted from xml_path to
    determine the service type, then return its known upload-relevant
    endpoint paths.

    Currently returns an empty list.
    """
    print(f"  {YELLOW}[!] Primary service repo: MISSING LOGIC — returning []{RESET}")
    return []


# ---------------------------------------------------------------------------
# Secondary service repo — svc_repo.json
# ---------------------------------------------------------------------------

def get_svc_repo_paths(repo_path: str) -> list[str]:
    """
    Reads svc_repo.json and returns all CommonEndpoints + UndesirableEndpoints
    across every service entry in every port, deduplicated.
    """
    if not os.path.isfile(repo_path):
        print(f"  {YELLOW}[!] svc_repo.json not found at {repo_path} — skipping{RESET}")
        return []

    try:
        with open(repo_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"  {RED}[!] svc_repo.json parse error: {e} — skipping{RESET}")
        return []

    paths = []
    ports = data.get("Ports", [])
    for port_entry in ports:
        for svc in port_entry.get("PotentialServices", []):
            paths.extend(svc.get("CommonEndpoints",      []))
            paths.extend(svc.get("UndesirableEndpoints", []))

    # Deduplicate preserving order
    seen  = set()
    deduped = []
    for p in paths:
        if p and p not in seen:
            seen.add(p)
            deduped.append(p)

    print(f"  {GREEN}[+] svc_repo.json → {len(deduped)} unique paths{RESET}")
    return deduped


# ---------------------------------------------------------------------------
# Burp XML helpers
# ---------------------------------------------------------------------------

def decode_element(elem) -> str:
    if elem is None:
        return ""
    raw = elem.text or ""
    if elem.get("base64") == "true":
        try:
            return base64.b64decode(raw).decode("utf-8", errors="replace")
        except Exception:
            return raw
    return raw


def extract_paths_from_xml(xml_path: str) -> list[str]:
    """Extracts unique URL paths from a Burp Suite XML proxy export."""
    if not os.path.isfile(xml_path):
        print(f"  {YELLOW}[!] XML not found at {xml_path} — skipping{RESET}")
        return []

    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        print(f"  {RED}[!] XML parse error: {e} — skipping{RESET}")
        return []

    paths = []
    for item in tree.getroot().findall("item"):
        url = decode_element(item.find("url"))
        if url:
            parsed = urlparse(url)
            p = parsed.path
            if p and p not in paths:
                paths.append(p)
            # Also add the path without its filename (parent dir)
            parent = p.rsplit("/", 1)[0]
            if parent and parent != p and parent not in paths:
                paths.append(parent + "/")

    print(f"  {GREEN}[+] XML → {len(paths)} unique paths{RESET}")
    return paths


# ---------------------------------------------------------------------------
# Wordlist assembly
# ---------------------------------------------------------------------------

def build_wordlist(
    xml_paths:      list[str],
    primary_paths:  list[str],
    svc_paths:      list[str],
    base_paths:     list[str],
) -> dict:
    """
    Returns a dict with sections:
      paths_raw         — all unique base paths (no extension)
      paths_extended    — each base path × every extension
      indexing_strings  — directory traversal / listing probes
    """

    # Merge all base paths, deduplicate
    all_base = []
    seen     = set()
    for src in (xml_paths, primary_paths, svc_paths, base_paths):
        for p in src:
            key = p.rstrip("/").lower()
            if key and key not in seen:
                seen.add(key)
                all_base.append(p)

    # Build extension variants
    extended = []
    ext_seen = set()
    for p in all_base:
        base = p.rstrip("/")
        for ext in ALL_EXTENSIONS:
            entry = base + ext
            if entry not in ext_seen:
                ext_seen.add(entry)
                extended.append(entry)

    return {
        "paths_raw":        all_base,
        "paths_extended":   extended,
        "indexing_strings": INDEXING_STRINGS,
    }


# ---------------------------------------------------------------------------
# Write wordlist file
# ---------------------------------------------------------------------------

def write_wordlist(sections: dict, out_path: str):
    lines = [
        "# WSTG-BUSL-08 Upload Path Wordlist",
        f"# Generated: {datetime.now().isoformat()}",
        "#",
        "# Sections:",
        "#   1. Raw paths (no extension) — discover exposed directories",
        "#   2. Extension variants — unexpected + script file types",
        "#   3. Indexing strings — trigger directory listing / path disclosure",
        "#",
        "# Load in Burp Intruder → Payloads → Simple List",
        "# Lines beginning with '#' are comments — Intruder skips them.",
        "#",
    ]

    lines.append("# ════ SECTION 1: Raw paths ════")
    for p in sections["paths_raw"]:
        lines.append(p)

    lines.append("")
    lines.append("# ════ SECTION 2: Extension variants (unexpected + script types) ════")
    for p in sections["paths_extended"]:
        lines.append(p)

    lines.append("")
    lines.append("# ════ SECTION 3: Indexing / traversal strings ════")
    for s in sections["indexing_strings"]:
        lines.append(s)

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-BUSL-08 Script 1: Upload path wordlist generator"
    )
    p.add_argument("--xml",
        default=os.path.join("WSTG-BUSL-08", "inputs", "xml", "file_input.xml"),
        metavar="PATH")
    p.add_argument("--repo",
        default=os.path.join("WSTG-BUSL-08", "inputs", "json", "svc_repo.json"),
        metavar="PATH",
        help="Path to svc_repo.json (secondary service catalogue)")
    p.add_argument("--out",
        default=os.path.join("WSTG-BUSL-08", "inputs", "wordlist", "upload_paths.txt"),
        metavar="PATH")
    p.add_argument("--json-out",
        default=os.path.join("WSTG-BUSL-08", "inputs", "json", "path_assessment.json"),
        metavar="PATH")
    args = p.parse_args()

    width = 65
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD}  WSTG-BUSL-08 — Upload Path Wordlist Generator{RESET}")
    print(f"{BOLD}{'='*width}{RESET}\n")

    # Collect from all sources
    print(f"  {BOLD}Sources:{RESET}")
    xml_paths     = extract_paths_from_xml(args.xml)
    primary_paths = get_primary_repo_paths(args.xml)
    svc_paths     = get_svc_repo_paths(args.repo)
    base_paths    = UPLOAD_BASE_PATHS
    print(f"  {DIM}hardcoded upload base paths: {len(base_paths)}{RESET}")

    sections = build_wordlist(xml_paths, primary_paths, svc_paths, base_paths)

    raw_count  = len(sections["paths_raw"])
    ext_count  = len(sections["paths_extended"])
    idx_count  = len(sections["indexing_strings"])
    total      = raw_count + ext_count + idx_count

    print(f"\n  {BOLD}Wordlist summary:{RESET}")
    print(f"    Raw paths           : {raw_count}")
    print(f"    Extension variants  : {ext_count}")
    print(f"    Indexing strings    : {idx_count}")
    print(f"    {'─'*30}")
    print(f"    Total entries       : {total}")

    write_wordlist(sections, args.out)
    print(f"\n{GREEN}[+] Wordlist → {args.out}{RESET}")

    # JSON assessment
    assessment = {
        "_meta": {
            "generated":    datetime.now().isoformat(),
            "source_xml":   args.xml,
            "svc_repo":     args.repo,
            "total_entries": total,
            "sections": {
                "paths_raw":       raw_count,
                "paths_extended":  ext_count,
                "indexing_strings": idx_count,
            },
            "extensions_tested": ALL_EXTENSIONS,
        },
        "paths_raw":        sections["paths_raw"],
        "paths_extended":   sections["paths_extended"][:500],   # cap for readability
        "indexing_strings": sections["indexing_strings"],
    }
    os.makedirs(os.path.dirname(args.json_out), exist_ok=True)
    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(assessment, f, indent=2, ensure_ascii=False)
    print(f"{GREEN}[+] Assessment JSON → {args.json_out}{RESET}")

    print(f"\n  {DIM}Next: load {args.out} into Burp Intruder, run scan,{RESET}")
    print(f"  {DIM}then: busl_08_verdict.py --intruder inputs/xml/intruder_test.xml{RESET}\n")


if __name__ == "__main__":
    main()
