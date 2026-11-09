#!/usr/bin/env python3
"""
WSTG-ATHZ-02 — Bypassing Authorization Schema
Script 1: parse_athz02.py

Walks WSTG-ATHZ-02/inputs/xml/ (flat or one-level subfolders).
Each XML is a Burp Suite proxy export for one user, named <username>_walk.xml.
Extracts per-user, per-endpoint:
  - Cookies
  - JWT tokens
  - UUIDs (standard + no-hyphen variants)
  - Unique alphanumeric path segments (≥8 chars, not username)
  - Headers that appear on an endpoint for some users but not all

Writes:
  WSTG-ATHZ-02/data/<username>_cookies.txt
  WSTG-ATHZ-02/data/<username>_JWTs.txt
  WSTG-ATHZ-02/data/<username>_UUIDs.txt
  WSTG-ATHZ-02/data/<username>_uniqueIDs.txt
  WSTG-ATHZ-02/data/<username>_headers.txt
  WSTG-ATHZ-02/data/json/ATHZ_02.json

Usage:
  python3 WSTG-ATHZ-02/utilities/python/parse_athz02.py
  python3 WSTG-ATHZ-02/utilities/python/parse_athz02.py \\
      --xml-dir  WSTG-ATHZ-02/inputs/xml \\
      --data-dir WSTG-ATHZ-02/data \\
      --admin    alice_walk.xml          # marks alice as higher_priv; all others → lower
"""

import argparse
import base64
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse


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
# Regex patterns
# ---------------------------------------------------------------------------

# Standard UUID: 8-4-4-4-12 hex
RE_UUID_STANDARD = re.compile(
    r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
)
# UUID without hyphens (32 hex chars)
RE_UUID_NOHYPHEN = re.compile(r'\b[0-9a-fA-F]{32}\b')

# JWT: three base64url segments separated by dots
RE_JWT = re.compile(
    r'\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b'
)

# Unique alphanumeric path segment:
# - At least 8 characters
# - Mix of letters and digits (not purely alphabetic — that's likely a word)
# - Not purely numeric
# Logic: ≥8 chars, contains at least one digit AND at least one letter
# This catches session tokens, object IDs, hashes embedded in URL paths
# but skips common words like "dashboard", "settings", "profile" etc.
RE_UNIQUE_ID_SEGMENT = re.compile(r'^(?=[a-zA-Z0-9_\-]{8,})(?=.*[a-zA-Z])(?=.*[0-9])[a-zA-Z0-9_\-]+$')

# Cookie header value parser
RE_COOKIE_PAIR = re.compile(r'([^=;\s]+)=([^;]*)')


# ---------------------------------------------------------------------------
# Burp XML decode (same pattern used across all scripts in this toolset)
# decode_element checks base64="true" attribute before attempting decode
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


# ---------------------------------------------------------------------------
# XML discovery: flat or one level of subfolders
# ---------------------------------------------------------------------------

def find_xml_files(xml_dir: str) -> dict[str, list[Path]]:
    """
    Returns {folder_name: [Path, ...]} where folder_name is either
    the xml_dir itself (for flat layout) or a subfolder name.
    Supports:
      xml_dir/alice_walk.xml          → folder key = xml_dir basename
      xml_dir/AppA/alice_walk.xml     → folder key = "AppA"
      xml_dir/AppB/bob_walk.xml       → folder key = "AppB"
    """
    root = Path(xml_dir)
    result: dict[str, list[Path]] = defaultdict(list)

    for item in sorted(root.iterdir()):
        if item.is_file() and item.suffix.lower() == ".xml":
            result[root.name].append(item)
        elif item.is_dir():
            for sub in sorted(item.glob("*.xml")):
                result[item.name].append(sub)

    return dict(result)


# ---------------------------------------------------------------------------
# Username extraction from filename
# Convention: <username>_walk.xml  →  username
# ---------------------------------------------------------------------------

def username_from_path(p: Path) -> str:
    stem = p.stem  # e.g. "alice_walk"
    if stem.endswith("_walk"):
        return stem[:-5]
    return stem


# ---------------------------------------------------------------------------
# Parse one Burp XML export → list of request dicts
# ---------------------------------------------------------------------------

def parse_burp_xml(path: Path) -> list[dict]:
    """
    Returns list of:
      {url, host, method, path, request_raw, response_raw,
       request_headers, request_body,
       response_headers, response_body, response_status}
    """
    try:
        tree = ET.parse(str(path))
    except ET.ParseError as e:
        print(f"  {RED}[!] XML parse error in {path.name}: {e}{RESET}", file=sys.stderr)
        return []

    items = []
    for item in tree.getroot().findall("item"):
        url_elem     = item.find("url")
        method_elem  = item.find("method")
        host_elem    = item.find("host")
        request_elem = item.find("request")
        response_elem= item.find("response")
        status_elem  = item.find("status")

        url    = decode_element(url_elem)
        method = decode_element(method_elem).upper()
        host   = decode_element(host_elem)
        req    = decode_element(request_elem)
        resp   = decode_element(response_elem)
        status = decode_element(status_elem)

        # Split request into headers + body
        req_parts = req.split("\r\n\r\n", 1)
        req_head  = req_parts[0] if req_parts else ""
        req_body  = req_parts[1] if len(req_parts) > 1 else ""

        resp_parts = resp.split("\r\n\r\n", 1)
        resp_head  = resp_parts[0] if resp_parts else ""
        resp_body  = resp_parts[1] if len(resp_parts) > 1 else ""

        # Parse path from URL
        try:
            parsed_path = urlparse(url).path
        except Exception:
            parsed_path = ""

        # Parse header dict from raw headers block
        req_headers = {}
        for line in req_head.splitlines()[1:]:  # skip request line
            if ":" in line:
                k, _, v = line.partition(":")
                req_headers[k.strip()] = v.strip()

        items.append({
            "url":             url,
            "host":            host,
            "method":          method,
            "path":            parsed_path,
            "request_raw":     req,
            "request_headers": req_headers,
            "request_body":    req_body,
            "response_headers":resp_head,
            "response_body":   resp_body,
            "response_status": status,
        })

    return items


# ---------------------------------------------------------------------------
# Extractors
# ---------------------------------------------------------------------------

def extract_cookies(req_headers: dict) -> dict[str, str]:
    """Returns {cookie_name: value} from Cookie header."""
    cookie_header = req_headers.get("Cookie", "")
    return {m.group(1): m.group(2) for m in RE_COOKIE_PAIR.finditer(cookie_header)}


def extract_jwts(text: str) -> list[str]:
    return list(set(RE_JWT.findall(text)))


def extract_uuids(text: str) -> list[str]:
    """
    Finds UUIDs in both standard (with-hyphen) and no-hyphen (32 hex) formats.
    No-hyphen UUIDs are checked to not be a subset of a longer hex string
    by requiring word boundaries — RE already handles this.
    De-duplicates and returns sorted list.
    """
    standard = RE_UUID_STANDARD.findall(text)
    # No-hyphen: exclude any 32-char hex that is actually part of a longer run
    nohyphen  = RE_UUID_NOHYPHEN.findall(text)
    # Normalise no-hyphen to lowercase and exclude ones that are substrings
    # of standard UUIDs (which when stripped of hyphens also match)
    standard_stripped = {u.replace("-", "").lower() for u in standard}
    nohyphen_unique   = [u for u in nohyphen if u.lower() not in standard_stripped]
    all_uuids = list({u.lower() for u in standard}) | set(u.lower() for u in nohyphen_unique)
    return sorted(all_uuids)


def extract_unique_path_ids(path: str, username: str) -> list[str]:
    """
    Splits URL path into segments and returns those that look like
    unique identifiers: ≥8 chars, mixed alpha+digit, not the username string.

    Design rationale (commented per spec request):
      - Minimum 8 chars: prevents common short path segments (/v2/, /api/)
        from triggering. Most meaningful object IDs are ≥8 chars.
      - Must contain at least one letter AND one digit: pure words like
        "dashboard" or "settings" are excluded. Pure numbers like "12345678"
        are also excluded — those are usually page IDs or timestamps, handled
        separately. We want the alphanumeric mixed pattern that signals a
        generated identifier.
      - Not the username: we already know the username; finding it in a path
        is expected and not interesting for authorization testing.
    """
    segments = [s for s in path.split("/") if s]
    results  = []
    uname_lower = username.lower()
    for seg in segments:
        # Strip common query string noise if path wasn't cleanly split
        seg = seg.split("?")[0]
        if RE_UNIQUE_ID_SEGMENT.match(seg) and seg.lower() != uname_lower:
            results.append(seg)
    return results


# ---------------------------------------------------------------------------
# Header differential analysis
# For each endpoint (method + path), find headers that exist for some
# users but not all — these may be authorization/session artefacts.
# ---------------------------------------------------------------------------

def find_differential_headers(
    all_users_data: dict[str, list[dict]]
) -> dict[str, dict[str, list[str]]]:
    """
    Returns {endpoint_key: {header_name: [usernames_that_have_it]}}
    where endpoint_key = "METHOD /path"
    Only headers present for SOME but not ALL users on that endpoint are returned.
    """
    # {endpoint: {username: set_of_header_names}}
    ep_user_headers: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))

    for username, requests in all_users_data.items():
        for req in requests:
            ep_key = f"{req['method']} {req['path']}"
            for hname in req["request_headers"]:
                ep_user_headers[ep_key][username].add(hname)

    result: dict[str, dict[str, list[str]]] = {}
    all_usernames = set(all_users_data.keys())

    for ep_key, user_hmap in ep_user_headers.items():
        # Collect all header names seen on this endpoint across any user
        all_headers_on_ep: set[str] = set()
        for hset in user_hmap.values():
            all_headers_on_ep |= hset

        differential = {}
        for hname in all_headers_on_ep:
            users_with = [u for u in all_usernames if hname in user_hmap.get(u, set())]
            # Only flag if at least one user has it but not all
            if 0 < len(users_with) < len(all_usernames):
                differential[hname] = sorted(users_with)

        if differential:
            result[ep_key] = differential

    return result


# ---------------------------------------------------------------------------
# Main extraction pipeline
# ---------------------------------------------------------------------------

def process_folder(
    folder_name: str,
    xml_files: list[Path],
    admin_files: set[str],
    data_dir: str,
) -> dict:
    """
    Processes all XML files for one folder (one application walk).
    Returns the JSON structure for this folder.
    """
    print(f"\n{BOLD}{CYAN}  Folder: {folder_name}{RESET}")

    # Step 1: parse all XMLs, assign roles
    all_users_requests: dict[str, list[dict]] = {}
    user_roles: dict[str, str] = {}

    for xml_path in xml_files:
        username = username_from_path(xml_path)
        requests = parse_burp_xml(xml_path)
        all_users_requests[username] = requests
        role = "higher_priv" if xml_path.name in admin_files else "lower_priv"
        user_roles[username] = role
        print(f"    {DIM}{username}{RESET} ({role}) — {len(requests)} requests")

    # Step 2: compute differential headers across all users in this folder
    diff_headers = find_differential_headers(all_users_requests)

    # Step 3: per-user extraction
    folder_json: dict = {}
    os.makedirs(data_dir, exist_ok=True)

    for username, requests in all_users_requests.items():
        print(f"\n    {BOLD}Processing {username}{RESET}")
        role = user_roles[username]

        cookies_all:    dict[str, str]  = {}
        jwts_all:       set             = set()
        uuids_all:      set             = set()
        unique_ids_all: set             = set()
        diff_hdrs_user: dict            = {}

        endpoints_json: dict = {}

        for req in requests:
            ep_key = f"{req['method']} {req['path']}"

            # Cookies
            cookies = extract_cookies(req["request_headers"])
            cookies_all.update(cookies)

            # JWTs — search full request text
            jwts = extract_jwts(req["request_raw"])
            jwts_all.update(jwts)

            # UUIDs — search full request text
            uuids = extract_uuids(req["request_raw"])
            uuids_all.update(uuids)

            # Unique path IDs
            path_ids = extract_unique_path_ids(req["path"], username)
            unique_ids_all.update(path_ids)

            # Endpoint entry in JSON
            if ep_key not in endpoints_json:
                endpoints_json[ep_key] = {
                    "method":     req["method"],
                    "path":       req["path"],
                    "url":        req["url"],
                    "cookies":    {},
                    "jwts":       [],
                    "uuids":      [],
                    "unique_ids": [],
                    "diff_headers": {},
                }
            endpoints_json[ep_key]["cookies"].update(cookies)
            endpoints_json[ep_key]["jwts"]       = list(set(endpoints_json[ep_key]["jwts"]) | set(jwts))
            endpoints_json[ep_key]["uuids"]      = list(set(endpoints_json[ep_key]["uuids"]) | set(uuids))
            endpoints_json[ep_key]["unique_ids"] = list(set(endpoints_json[ep_key]["unique_ids"]) | set(path_ids))

        # Attach differential headers per endpoint for this user
        for ep_key, hdr_map in diff_headers.items():
            if ep_key in endpoints_json:
                user_diff = {h: v for h, v in hdr_map.items() if username in v}
                if user_diff:
                    endpoints_json[ep_key]["diff_headers"] = user_diff

        # Build folder-level user JSON entry
        folder_json[username] = {
            "role":      role,
            "endpoints": endpoints_json,
        }

        # -----------------------------------------------------------------------
        # Write TXT files
        # -----------------------------------------------------------------------

        def write_txt(name_suffix: str, lines: list[str]):
            fname = os.path.join(data_dir, f"{username}_{name_suffix}.txt")
            with open(fname, "w") as f:
                f.write("\n".join(sorted(set(lines))) + "\n")
            print(f"      {GREEN}→ {fname}{RESET}  ({len(lines)} entries)")

        # Cookies: NAME=VALUE format
        write_txt("cookies",   [f"{k}={v}" for k, v in cookies_all.items()])
        write_txt("JWTs",      sorted(jwts_all))
        write_txt("UUIDs",     sorted(uuids_all))
        write_txt("uniqueIDs", sorted(unique_ids_all))

        # Differential headers: "endpoint | header_name (present for: users)"
        diff_lines = []
        for ep_key, hdr_map in diff_headers.items():
            for hname, users_with in hdr_map.items():
                if username in users_with:
                    diff_lines.append(f"{ep_key} | {hname} (present for: {', '.join(users_with)})")
        write_txt("headers", diff_lines)

    return folder_json


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="ATHZ-02: Parse Burp XML walks, extract auth artefacts, build JSON"
    )
    p.add_argument(
        "--xml-dir",
        default=os.path.join("WSTG-ATHZ-02", "inputs", "xml"),
        metavar="DIR",
        help="Root XML input directory (flat or one level of subfolders)"
    )
    p.add_argument(
        "--data-dir",
        default=os.path.join("WSTG-ATHZ-02", "data"),
        metavar="DIR",
        help="Output data directory for TXT files"
    )
    p.add_argument(
        "--admin",
        nargs="+",
        default=[],
        metavar="FILENAME",
        help="Filename(s) of higher-privilege XML (e.g. alice_walk.xml). "
             "All others become lower_priv. If omitted, all roles are lower_priv."
    )
    return p.parse_args()


def main():
    args = parse_args()
    admin_files = set(args.admin)

    print()
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"{BOLD} WSTG-ATHZ-02 — XML Parser / Auth Artefact Extractor{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"  XML dir  : {args.xml_dir}")
    print(f"  Data dir : {args.data_dir}")
    if admin_files:
        print(f"  Admin    : {', '.join(admin_files)}")
    else:
        print(f"  Admin    : {DIM}(none — all roles set to lower_priv){RESET}")
    print()

    folder_map = find_xml_files(args.xml_dir)
    if not folder_map:
        print(f"{RED}[!] No XML files found under {args.xml_dir}{RESET}", file=sys.stderr)
        sys.exit(1)

    full_json: dict = {
        "wstg_id":     "WSTG-ATHZ-02",
        "title":       "Bypassing Authorization Schema",
        "folders":     {},
    }

    for folder_name, xml_files in sorted(folder_map.items()):
        folder_data = process_folder(folder_name, xml_files, admin_files, args.data_dir)
        full_json["folders"][folder_name] = folder_data

    # Write master JSON
    json_dir  = os.path.join(args.data_dir, "json")
    json_path = os.path.join(json_dir, "ATHZ_02.json")
    os.makedirs(json_dir, exist_ok=True)
    with open(json_path, "w") as f:
        json.dump(full_json, f, indent=2)

    print(f"\n{GREEN}[+] Master JSON → {json_path}{RESET}")
    print(f"\n  Next: python3 WSTG-ATHZ-02/utilities/python/2athz_tasks.py")
    print()


if __name__ == "__main__":
    main()
