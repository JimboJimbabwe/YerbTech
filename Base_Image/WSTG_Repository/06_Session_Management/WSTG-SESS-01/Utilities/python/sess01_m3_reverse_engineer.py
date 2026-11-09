#!/usr/bin/env python3
"""
WSTG-SESS-01 — Testing for Session Management Schema
Module 3: sess01_m3_reverse_engineer.py

Black-box cookie reverse engineering.

Static items (supplied + auto-detected):
  --username, --password  (CLI flags)
  --ip                    (auto-detected from outbound interface; overridable)
  timestamp               (auto-generated at run time)
  user-agent              (picked from hardcoded list or --ua index)

Addition items (auto-extracted from XML):
  domain, request headers, body values, URL path segments, endpoint names

Saves to: WSTG-SESS-01/inputs/json/static_items.json
  (read back on subsequent runs — does NOT regenerate unless --reset)

Combinatorial generation:
  All non-empty subsets of the combined item pool are concatenated
  (with common separators: "", ":", ".", "-", "|") and each combo
  is encoded/hashed with every supported algorithm.

Encoding / hash types (going wide per spec):
  plain, hex, HEX (uppercase), base64, base64url,
  url_encoded, double_url_encoded, html_entity,
  unicode_escape, decimal_bytes, binary_bytes,
  md5, sha1, sha256, sha512,
  rot13, reverse,
  jwt_decode (attempt — if value looks like JWT, decode header+payload)

Overlap detection:
  Actual cookie values (from cookies_raw.txt) are compared against
  every generated encoded variant. A substring or exact match = overlap.
  Overlaps are written to: WSTG-SESS-01/outputs/m3_overlaps.txt

Outputs:
  WSTG-SESS-01/inputs/json/static_items.json   (persisted items)
  WSTG-SESS-01/outputs/m3_wordlist.txt         (all encoded combos)
  WSTG-SESS-01/outputs/m3_overlaps.txt         (overlap findings)
  WSTG-SESS-01/outputs/m3_combo_map.json       (variant → source combo)

Usage:
  # First run — supply credentials, auto-detects IP/timestamp/UA
  python3 WSTG-SESS-01/utilities/python/sess01_m3_reverse_engineer.py \\
      --xml      WSTG-SESS-01/inputs/xml/session_walk.xml \\
      --username jsmith \\
      --password hunter2

  # Subsequent runs — reads stored items, skip credential flags
  python3 WSTG-SESS-01/utilities/python/sess01_m3_reverse_engineer.py \\
      --xml WSTG-SESS-01/inputs/xml/session_walk.xml

  # Reset stored items and re-supply
  python3 WSTG-SESS-01/utilities/python/sess01_m3_reverse_engineer.py \\
      --xml WSTG-SESS-01/inputs/xml/session_walk.xml \\
      --username jsmith --password hunter2 --reset

  # Pick a specific user-agent (0–11) instead of all
  python3 ... --ua 3
"""

import argparse
import base64
import hashlib
import html
import itertools
import json
import os
import re
import socket
import sys
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.parse import urlparse


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


# ---------------------------------------------------------------------------
# Hardcoded user-agent list (12 visibly different types)
# ---------------------------------------------------------------------------
USER_AGENTS = [
    # 0  Desktop Chrome / Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # 1  Desktop Firefox / Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # 2  Desktop Safari / macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    # 3  Desktop Edge / Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # 4  Mobile Chrome / Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    # 5  Mobile Safari / iPhone
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    # 6  curl / CLI
    "curl/8.7.1",
    # 7  Python requests
    "python-requests/2.31.0",
    # 8  Googlebot
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    # 9  Burp Suite (default)
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; Burp)",
    # 10 Internet Explorer 11
    "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko",
    # 11 Wget
    "Wget/1.21.4",
]

# Separators to use when concatenating combo items
SEPARATORS = ["", ":", ".", "-", "|", "_", "/"]

# JWT detection pattern
RE_JWT = re.compile(r'^eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$')

# Regex for header value tokens worth extracting (skip common words/numbers)
RE_HEADER_TOKEN = re.compile(r'[A-Za-z0-9_\-\.@]{4,}')


# ---------------------------------------------------------------------------
# Auto-detect outbound IP
# ---------------------------------------------------------------------------

def detect_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ---------------------------------------------------------------------------
# Burp XML decode + parser
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


def parse_burp_xml(path: str) -> list[dict]:
    try:
        tree = ET.parse(path)
    except ET.ParseError as e:
        print(f"{RED}[!] XML parse error: {e}{RESET}", file=sys.stderr)
        sys.exit(1)

    items = []
    for idx, item in enumerate(tree.getroot().findall("item")):
        url    = decode_element(item.find("url"))
        req    = decode_element(item.find("request"))
        resp   = decode_element(item.find("response"))

        req_parts  = req.split("\r\n\r\n", 1)
        req_head   = req_parts[0]
        req_body   = req_parts[1] if len(req_parts) > 1 else ""

        items.append({
            "index":    idx,
            "url":      url,
            "req_head": req_head,
            "req_body": req_body,
            "resp":     resp,
        })
    return items


# ---------------------------------------------------------------------------
# Extract addition items from XML
# ---------------------------------------------------------------------------

def extract_additions(items: list[dict]) -> dict[str, list[str]]:
    """
    Returns {label: [values]} for:
      domain, request_headers, body_values, url_paths, endpoint_names
    """
    domains:     set[str] = set()
    header_vals: set[str] = set()
    body_vals:   set[str] = set()
    url_paths:   set[str] = set()
    endpoints:   set[str] = set()

    for item in items:
        parsed = urlparse(item["url"])

        # Domain (host without port)
        host = parsed.hostname or ""
        if host:
            domains.add(host)

        # URL path segments (non-numeric, ≥3 chars)
        for seg in parsed.path.split("/"):
            seg = seg.strip()
            if seg and len(seg) >= 3 and not seg.isdigit():
                url_paths.add(seg)

        # Endpoint = last meaningful path segment
        path_segs = [s for s in parsed.path.split("/") if s]
        if path_segs:
            endpoints.add(path_segs[-1])

        # Request headers — extract tokens from values, skip common headers
        SKIP_HEADERS = {"host", "connection", "accept", "accept-encoding",
                        "accept-language", "content-type", "content-length",
                        "cache-control", "pragma", "upgrade-insecure-requests"}
        for line in item["req_head"].splitlines()[1:]:
            if ":" not in line:
                continue
            k, _, v = line.partition(":")
            if k.strip().lower() in SKIP_HEADERS:
                continue
            for token in RE_HEADER_TOKEN.findall(v):
                if len(token) >= 4:
                    header_vals.add(token)

        # Request body — key=value pairs
        body = item["req_body"]
        if body:
            for pair in body.split("&"):
                if "=" in pair:
                    _, _, val = pair.partition("=")
                    val = urllib.parse.unquote_plus(val).strip()
                    if val and len(val) >= 3:
                        body_vals.add(val)
                else:
                    if len(pair.strip()) >= 3:
                        body_vals.add(pair.strip())

    return {
        "domain":         sorted(domains),
        "header_values":  sorted(header_vals)[:20],  # cap to keep combos sane
        "body_values":    sorted(body_vals)[:20],
        "url_paths":      sorted(url_paths)[:20],
        "endpoints":      sorted(endpoints)[:15],
    }


# ---------------------------------------------------------------------------
# Static items: load or build
# ---------------------------------------------------------------------------

def load_or_build_static(
    items_path: str,
    username:   str | None,
    password:   str | None,
    ip_override:str | None,
    ua_index:   int | None,
    reset:      bool,
) -> dict:
    """
    Loads static_items.json if it exists and --reset is not set.
    Otherwise builds and saves it.
    Returns the static items dict.
    """
    if not reset and os.path.exists(items_path):
        with open(items_path) as f:
            stored = json.load(f)
        print(f"  {GREEN}Loaded stored static items from {items_path}{RESET}")
        print(f"  {DIM}Use --reset to regenerate.{RESET}\n")
        return stored

    # Build fresh
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ip = ip_override or detect_local_ip()

    # User-agent: all 12 if no index given; else the one at index
    if ua_index is not None:
        uas = [USER_AGENTS[ua_index % len(USER_AGENTS)]]
    else:
        uas = USER_AGENTS

    static = {
        "username":    username or "",
        "password":    password or "",
        "ip":          ip,
        "timestamp":   ts,
        "user_agents": uas,
    }

    os.makedirs(os.path.dirname(os.path.abspath(items_path)), exist_ok=True)
    with open(items_path, "w") as f:
        json.dump(static, f, indent=2)
    print(f"  {GREEN}Saved static items → {items_path}{RESET}\n")
    return static


# ---------------------------------------------------------------------------
# Encoding / hashing engine (going wide)
# ---------------------------------------------------------------------------

def encode_all(s: str) -> dict[str, str]:
    """
    Applies every encoding/hash type to string s.
    Returns {encoding_name: encoded_value}.
    Silently skips any that error.
    """
    b = s.encode("utf-8", errors="replace")
    results = {}

    def safe(label: str, fn):
        try:
            results[label] = fn()
        except Exception:
            pass

    # Plain
    results["plain"] = s

    # Hex variants
    safe("hex_lower",    lambda: b.hex())
    safe("hex_upper",    lambda: b.hex().upper())
    safe("hex_spaced",   lambda: " ".join(f"{byte:02x}" for byte in b))

    # Base64 variants
    safe("base64",       lambda: base64.b64encode(b).decode())
    safe("base64_nopad", lambda: base64.b64encode(b).rstrip(b"=").decode())
    safe("base64url",    lambda: base64.urlsafe_b64encode(b).decode())
    safe("base64url_nopad", lambda: base64.urlsafe_b64encode(b).rstrip(b"=").decode())
    safe("base32",       lambda: base64.b32encode(b).decode())
    safe("base16",       lambda: base64.b16encode(b).decode())

    # URL encoding
    safe("url_encoded",        lambda: urllib.parse.quote(s, safe=""))
    safe("url_encoded_plus",   lambda: urllib.parse.quote_plus(s))
    safe("double_url_encoded", lambda: urllib.parse.quote(urllib.parse.quote(s, safe=""), safe=""))

    # HTML / Unicode
    safe("html_entity",       lambda: html.escape(s))
    safe("unicode_escape",    lambda: s.encode("unicode_escape").decode("ascii"))
    safe("unicode_code_pts",  lambda: " ".join(f"U+{ord(c):04X}" for c in s))

    # Byte representations
    safe("decimal_bytes",     lambda: " ".join(str(byte) for byte in b))
    safe("octal_bytes",       lambda: " ".join(f"\\{byte:03o}" for byte in b))
    safe("binary_bytes",      lambda: " ".join(f"{byte:08b}" for byte in b))

    # Hashes
    safe("md5",     lambda: hashlib.md5(b).hexdigest())
    safe("sha1",    lambda: hashlib.sha1(b).hexdigest())
    safe("sha224",  lambda: hashlib.sha224(b).hexdigest())
    safe("sha256",  lambda: hashlib.sha256(b).hexdigest())
    safe("sha384",  lambda: hashlib.sha384(b).hexdigest())
    safe("sha512",  lambda: hashlib.sha512(b).hexdigest())
    safe("sha3_256",lambda: hashlib.sha3_256(b).hexdigest())
    safe("sha3_512",lambda: hashlib.sha3_512(b).hexdigest())
    safe("blake2b", lambda: hashlib.blake2b(b).hexdigest())
    safe("blake2s", lambda: hashlib.blake2s(b).hexdigest())

    # Classic obfuscations
    safe("rot13",   lambda: s.translate(
        str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
        )
    ))
    safe("reverse",          lambda: s[::-1])
    safe("reverse_hex",      lambda: b[::-1].hex())
    safe("reverse_base64",   lambda: base64.b64encode(b[::-1]).decode())

    # JWT attempt: if value looks like JWT, decode header + payload (no verify)
    if RE_JWT.match(s):
        parts = s.split(".")
        for i, label in [(0, "jwt_header"), (1, "jwt_payload")]:
            try:
                padded = parts[i] + "=" * (-len(parts[i]) % 4)
                decoded = base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
                results[label] = decoded
            except Exception:
                pass

    return results


# ---------------------------------------------------------------------------
# Combinatorial generator
# ---------------------------------------------------------------------------

def build_item_pool(static: dict, additions: dict) -> dict[str, str]:
    """
    Returns flat {label: value} of all non-empty items to combine.
    Multiple user-agents become ua_0, ua_1, etc.
    Multiple addition values become domain_0, header_val_0, etc.
    """
    pool = {}

    if static.get("username"):
        pool["username"] = static["username"]
    if static.get("password"):
        pool["password"] = static["password"]
    if static.get("ip"):
        pool["ip"] = static["ip"]
    if static.get("timestamp"):
        pool["timestamp"] = static["timestamp"]
    for i, ua in enumerate(static.get("user_agents", [])):
        pool[f"ua_{i}"] = ua

    for cat, vals in additions.items():
        for i, val in enumerate(vals):
            if val:
                pool[f"{cat}_{i}"] = val

    return {k: v for k, v in pool.items() if v}


def generate_combos(pool: dict[str, str]) -> list[tuple[list[str], str]]:
    """
    For every non-empty subset of pool values (1 to len items),
    concatenate with each separator.
    Returns list of (labels_list, concatenated_string).
    Caps total at 5000 combos to prevent runaway file sizes.
    """
    labels = list(pool.keys())
    values = list(pool.values())
    results = []
    cap = 5000

    # Iterate subsets from size 1 upward
    for size in range(1, len(values) + 1):
        for idx_combo in itertools.combinations(range(len(values)), size):
            selected_labels = [labels[i] for i in idx_combo]
            selected_values = [values[i] for i in idx_combo]
            for sep in SEPARATORS:
                concat = sep.join(selected_values)
                if concat:
                    results.append((selected_labels, concat))
                if len(results) >= cap:
                    return results

    return results


# ---------------------------------------------------------------------------
# Overlap detection
# ---------------------------------------------------------------------------

def detect_overlaps(
    cookie_values: list[str],
    encoded_variants: list[tuple[str, str, str]],   # (combo_str, encoding, encoded_val)
) -> list[dict]:
    """
    Returns list of overlap findings:
    {cookie_value, combo_str, encoding, encoded_value, match_type}
    match_type: "exact" | "substring_in_cookie" | "cookie_in_encoded"
    """
    overlaps = []
    for cv in cookie_values:
        cv_lower = cv.lower()
        for combo_str, encoding, encoded_val in encoded_variants:
            ev_lower = encoded_val.lower()
            if not ev_lower or not cv_lower:
                continue
            if cv_lower == ev_lower:
                overlaps.append({
                    "cookie_value":  cv,
                    "combo_str":     combo_str,
                    "encoding":      encoding,
                    "encoded_value": encoded_val,
                    "match_type":    "exact",
                })
            elif len(ev_lower) >= 6 and ev_lower in cv_lower:
                overlaps.append({
                    "cookie_value":  cv,
                    "combo_str":     combo_str,
                    "encoding":      encoding,
                    "encoded_value": encoded_val,
                    "match_type":    "substring_in_cookie",
                })
            elif len(cv_lower) >= 6 and cv_lower in ev_lower:
                overlaps.append({
                    "cookie_value":  cv,
                    "combo_str":     combo_str,
                    "encoding":      encoding,
                    "encoded_value": encoded_val,
                    "match_type":    "cookie_in_encoded",
                })
    return overlaps


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="SESS-01 M3: Black-box cookie reverse engineering + overlap detection"
    )
    p.add_argument("--xml",
        default=os.path.join("WSTG-SESS-01", "inputs", "xml", "session_walk.xml"),
        metavar="PATH",
        help="Burp XML walk")
    p.add_argument("--username", default=None, metavar="STR")
    p.add_argument("--password", default=None, metavar="STR")
    p.add_argument("--ip", default=None, metavar="ADDR",
        help="Override auto-detected local IP")
    p.add_argument("--ua", type=int, default=None, metavar="0-11",
        help="Use single user-agent by index (0–11). Default: all 12.")
    p.add_argument("--reset", action="store_true",
        help="Regenerate static_items.json even if it exists")
    p.add_argument("--items-json",
        default=os.path.join("WSTG-SESS-01", "inputs", "json", "static_items.json"),
        metavar="PATH")
    p.add_argument("--cookies-raw",
        default=os.path.join("WSTG-SESS-01", "outputs", "cookies_raw.txt"),
        metavar="PATH",
        help="Output from Module 0")
    p.add_argument("--out-dir",
        default=os.path.join("WSTG-SESS-01", "outputs"),
        metavar="DIR")
    return p.parse_args()


def main():
    args = parse_args()

    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"{BOLD} WSTG-SESS-01 M3 — Black-Box Cookie Reverse Engineering{RESET}")
    print(f"{BOLD}{'='*65}{RESET}\n")

    # Load / build static items
    static = load_or_build_static(
        items_path  = args.items_json,
        username    = args.username,
        password    = args.password,
        ip_override = args.ip,
        ua_index    = args.ua,
        reset       = args.reset,
    )
    print(f"  Static items:")
    for k, v in static.items():
        if k == "user_agents":
            print(f"    user_agents : {len(v)} loaded")
        else:
            print(f"    {k:<12}: {str(v)[:60]}")
    print()

    # Parse XML for addition items
    print(f"  Parsing XML for addition items: {args.xml}")
    items     = parse_burp_xml(args.xml)
    additions = extract_additions(items)
    print(f"  Additions:")
    for cat, vals in additions.items():
        print(f"    {cat:<16}: {len(vals)} value(s)")
    print()

    # Build item pool
    pool = build_item_pool(static, additions)
    print(f"  Item pool: {len(pool)} items")
    print()

    # Generate combinatorial combos
    print(f"  Generating combinatorial combinations (cap 5000)...")
    combos = generate_combos(pool)
    print(f"  {len(combos)} combos generated")
    print()

    # Encode all combos
    print(f"  Encoding all combos (this may take a moment)...")
    os.makedirs(args.out_dir, exist_ok=True)

    wordlist_lines = []
    combo_map      = []
    all_variants   = []   # (combo_str, encoding, encoded_val) for overlap check

    for labels, combo_str in combos:
        encoded = encode_all(combo_str)
        for enc_name, enc_val in encoded.items():
            if enc_val:
                wordlist_lines.append(enc_val)
                all_variants.append((combo_str, enc_name, enc_val))
        combo_map.append({
            "labels":       labels,
            "combo_str":    combo_str,
            "encoding_count": len(encoded),
        })

    # Deduplicate wordlist
    seen = set()
    wordlist_deduped = []
    for line in wordlist_lines:
        if line not in seen:
            seen.add(line)
            wordlist_deduped.append(line)

    wordlist_path = os.path.join(args.out_dir, "m3_wordlist.txt")
    with open(wordlist_path, "w") as f:
        f.write("\n".join(wordlist_deduped) + "\n")
    print(f"{GREEN}[+] {wordlist_path}{RESET}  ({len(wordlist_deduped)} entries)")

    map_path = os.path.join(args.out_dir, "m3_combo_map.json")
    with open(map_path, "w") as f:
        json.dump(combo_map, f, indent=2)
    print(f"{GREEN}[+] {map_path}{RESET}")

    # Load actual cookie values from Module 0 output
    cookie_values = []
    if os.path.exists(args.cookies_raw):
        with open(args.cookies_raw) as f:
            for line in f:
                line = line.strip()
                if "=" in line:
                    # Only the value part after the first =
                    cookie_values.append(line.split("=", 1)[1])
                elif line:
                    cookie_values.append(line)
        print(f"\n  Loaded {len(cookie_values)} cookie values from {args.cookies_raw}")
    else:
        print(f"\n  {YELLOW}[!] cookies_raw.txt not found — run Module 0 first for overlap detection.{RESET}")

    # Overlap detection
    overlaps = []
    if cookie_values:
        print(f"  Running overlap detection...")
        overlaps = detect_overlaps(cookie_values, all_variants)

    overlap_lines = []
    overlap_lines.append("WSTG-SESS-01 M3 — Overlap Findings (Indicator of Cookie Composition)")
    overlap_lines.append("=" * 65)
    overlap_lines.append("")
    overlap_lines.append(
        "An overlap means an encoded representation of a known static or\n"
        "contextual value (username, IP, timestamp, etc.) was found as a\n"
        "substring or exact match within an actual observed cookie value.\n"
        "This indicates the cookie was composed from known plaintext data\n"
        "and may be reversible or predictable.\n"
    )

    if not overlaps:
        overlap_lines.append("No overlaps detected.")
        print(f"  {GREEN}✓ No overlaps detected.{RESET}")
    else:
        overlap_lines.append(f"ALERT: {len(overlaps)} overlap(s) found!\n")
        for ov in overlaps:
            overlap_lines.append(f"Match type   : {ov['match_type']}")
            overlap_lines.append(f"Cookie value : {ov['cookie_value'][:80]}")
            overlap_lines.append(f"Encoding     : {ov['encoding']}")
            overlap_lines.append(f"Source combo : {ov['combo_str'][:80]}")
            overlap_lines.append(f"Encoded val  : {ov['encoded_value'][:80]}")
            overlap_lines.append("")
        print(f"  {RED}{BOLD}⚠ {len(overlaps)} OVERLAP(S) DETECTED — cookie may be composed from known data!{RESET}")

    overlap_path = os.path.join(args.out_dir, "m3_overlaps.txt")
    with open(overlap_path, "w") as f:
        f.write("\n".join(overlap_lines))
    print(f"{GREEN}[+] {overlap_path}{RESET}")

    print(f"\n{BOLD} Encoding types applied per combo:{RESET}")
    sample_encs = list(encode_all("sample").keys())
    print(f"  {', '.join(sample_encs)}")
    print(f"  Total encoding types: {len(sample_encs)}")
    print()


if __name__ == "__main__":
    main()
