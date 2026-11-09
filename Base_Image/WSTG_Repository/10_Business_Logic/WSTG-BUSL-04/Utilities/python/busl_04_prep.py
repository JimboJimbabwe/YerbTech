#!/usr/bin/env python3
"""
WSTG-BUSL-04 — Process Timing / TOCTOU Prep
=============================================
Reads Burp Suite proxy history XML exports from Inputs/XML/, samples 3
endpoints per category file, parses each request into curl components,
and writes a structured JSON ready for the race-condition runner.

Same multi-file pattern as hpp_04 — drop authentication.xml and
authorization.xml (or any targeted exports) into Inputs/XML/.

Outputs
-------
    Outputs/test_outputs/<category>.json     — selected endpoints + curl data

Usage
-----
    python busl_04_prep.py                       # process all XMLs, pick 3 each
    python busl_04_prep.py -n 5                  # pick 5 per file
    python busl_04_prep.py --only authentication  # single category
    python busl_04_prep.py --seed 42             # reproducible sampling
"""

from __future__ import annotations

import argparse
import base64
import json
import random
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

# ── Paths ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR      = Path(__file__).resolve().parent        # Utilities/python/
TOOL_ROOT       = SCRIPT_DIR.parent.parent               # WSTG-BUSL-04/
DEFAULT_XML_DIR = TOOL_ROOT / "Inputs"  / "XML"
DEFAULT_OUT_DIR = TOOL_ROOT / "Outputs" / "test_outputs"

DEFAULT_PICK_N  = 3

# Headers curl handles itself or that break replay
_SKIP_HEADERS = {
    "content-length", "host", "connection",
    "accept-encoding", "transfer-encoding",
}


# ── Request decoding & parsing ─────────────────────────────────────────────────

def _decode_request(text: str, is_b64: bool) -> str:
    if is_b64:
        try:
            return base64.b64decode(text.strip()).decode("utf-8", errors="replace")
        except Exception:
            return text
    return text


def _parse_http_request(raw: str) -> dict:
    """
    Split a raw HTTP request into its component parts.

    Returns:
        {
          method, headers: [], cookies: [], body: str|None,
          content_type: str
        }
    """
    lines = raw.splitlines()
    if not lines:
        return {"method": "GET", "headers": [], "cookies": [],
                "body": None, "content_type": "text/plain"}

    # First line: METHOD /path HTTP/x.x
    parts  = lines[0].strip().split(" ", 2)
    method = parts[0].upper() if parts else "GET"

    headers: list[str] = []
    cookies: list[str] = []
    content_type       = "text/plain"
    body_lines: list[str] = []
    in_body = False

    for line in lines[1:]:
        if not in_body:
            if line.strip() == "":
                in_body = True
                continue

            if ":" not in line:
                continue

            name, _, value = line.partition(":")
            name  = name.strip()
            value = value.strip()
            lower = name.lower()

            if lower in _SKIP_HEADERS:
                continue

            if lower == "content-type":
                content_type = value
                headers.append(f"{name}: {value}")
            elif lower == "cookie":
                for ck in value.split(";"):
                    ck = ck.strip()
                    if ck:
                        cookies.append(ck)
            else:
                headers.append(f"{name}: {value}")
        else:
            body_lines.append(line)

    body = "\n".join(body_lines).strip() or None

    return {
        "method":       method,
        "headers":      headers,
        "cookies":      cookies,
        "body":         body,
        "content_type": content_type,
    }


# ── Curl builder ───────────────────────────────────────────────────────────────

def _build_curl_args(
    method: str,
    url: str,
    headers: list[str],
    cookies: list[str],
    body: str | None,
) -> list[str]:
    """
    Build a subprocess-ready curl args list.
    Output-capture flags are NOT included here — the runner appends them.
    """
    args: list[str] = ["curl", "-k", "-s"]

    if method.upper() != "GET":
        args.extend(["-X", method.upper()])

    for h in headers:
        args.extend(["-H", h])

    if cookies:
        args.extend(["-H", "Cookie: " + "; ".join(cookies)])

    if body:
        args.extend(["--data-raw", body])

    args.append(url)
    return args


def _curl_args_to_string(args: list[str]) -> str:
    """Human-readable curl command string from the args list."""
    parts: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-H", "-X", "--data-raw"):
            val = args[i + 1] if i + 1 < len(args) else ""
            parts.append(f'{a} \'{val}\'')
            i += 2
        elif i == len(args) - 1 and not a.startswith("-"):
            parts.append(f"'{a}'")
            i += 1
        else:
            parts.append(a)
            i += 1
    return " ".join(parts)


# ── Burp XML parsing ───────────────────────────────────────────────────────────

def parse_burp_xml(xml_path: Path) -> list[dict]:
    """
    Parse a Burp proxy history XML export.
    Returns only items whose request has a parseable body or URL params.
    """
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError as e:
        print(f"  [!] XML parse error in {xml_path.name}: {e}")
        return []
    except FileNotFoundError:
        print(f"  [!] File not found: {xml_path}")
        return []

    records: list[dict] = []

    for item in root.findall("item"):
        url    = (item.findtext("url")    or "").strip()
        path   = (item.findtext("path")   or "/").strip()
        host   = (item.findtext("host")   or "").strip()
        method = (item.findtext("method") or "GET").strip().upper()

        req_el = item.find("request")
        if req_el is None or not req_el.text:
            continue

        is_b64  = req_el.attrib.get("base64", "false").lower() == "true"
        raw     = _decode_request(req_el.text, is_b64)
        parsed  = _parse_http_request(raw)

        # Use method from parsed request; fall back to XML
        method = parsed["method"] or method

        # Must have URL + either a body or URL parameters to be worth racing
        has_qs   = bool(urlparse(url).query)
        has_body = bool(parsed["body"])
        if not (has_qs or has_body):
            continue

        curl_args = _build_curl_args(
            method, url,
            parsed["headers"], parsed["cookies"], parsed["body"],
        )

        records.append({
            "host":         host,
            "method":       method,
            "url":          url,
            "path":         path,
            "content_type": parsed["content_type"],
            "curl_args":    curl_args,
            "curl_command": _curl_args_to_string(curl_args),
            "components": {
                "url":          url,
                "method":       method,
                "headers":      parsed["headers"],
                "cookies":      parsed["cookies"],
                "data":         parsed["body"],
                "content_type": parsed["content_type"],
            },
        })

    return records


# ── Per-file processing ────────────────────────────────────────────────────────

def process_xml_file(
    xml_path: Path,
    pick_n:   int,
    out_dir:  Path,
    rng:      random.Random,
) -> None:
    category = xml_path.stem   # "authentication", "authorization", …

    print(f"\n  [{category}]  {xml_path.name}")

    candidates = parse_burp_xml(xml_path)
    if not candidates:
        print(f"    [!] No usable endpoints found — skipping.")
        return

    total = len(candidates)
    n     = min(pick_n, total)
    if n < pick_n:
        print(f"    [!] Requested {pick_n} but only {total} available — using {n}.")
    else:
        print(f"    Parameterised endpoints: {total}  |  Selecting: {n}")

    selected = rng.sample(candidates, n)

    # Stamp index onto each selected record
    for i, ep in enumerate(selected):
        ep["index"] = i
        print(
            f"    [{i}]  {ep['method']:<6} {ep['host']}{ep['path']}"
            f"  ({ep['content_type']})"
        )

    # Write JSON
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{category}.json"

    payload = {
        "scan_metadata": {
            "wstg_id":               "WSTG-BUSL-04",
            "title":                 "Testing for Process Timing (TOCTOU)",
            "category":              category,
            "source_xml":            xml_path.name,
            "scan_time":             datetime.now(timezone.utc).isoformat(),
            "total_in_xml":          total,
            "endpoints_selected":    n,
        },
        "endpoints": selected,
    }

    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"    Output → {out_path.relative_to(TOOL_ROOT)}")


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="WSTG-BUSL-04 Prep — extract & stage curl targets from Burp XML exports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Place authentication.xml / authorization.xml in Inputs/XML/.\n"
            "Each file becomes one staged JSON for the race-condition runner."
        ),
    )
    ap.add_argument(
        "--xml-dir", metavar="DIR", default=str(DEFAULT_XML_DIR),
        help=f"Folder containing Burp XML exports  [default: {DEFAULT_XML_DIR}]",
    )
    ap.add_argument(
        "--out-dir", metavar="DIR", default=str(DEFAULT_OUT_DIR),
        help=f"JSON output directory               [default: {DEFAULT_OUT_DIR}]",
    )
    ap.add_argument(
        "-n", "--pick-n", type=int, default=DEFAULT_PICK_N, metavar="N",
        help=f"Endpoints to sample per XML file    [default: {DEFAULT_PICK_N}]",
    )
    ap.add_argument(
        "--only", metavar="NAME[,NAME]",
        help="Process only these XML stems, comma-separated (e.g. authentication)",
    )
    ap.add_argument(
        "--seed", type=int, default=None, metavar="INT",
        help="RNG seed for reproducible sampling",
    )

    args    = ap.parse_args()
    xml_dir = Path(args.xml_dir)
    out_dir = Path(args.out_dir)
    rng     = random.Random(args.seed)

    if not xml_dir.is_dir():
        sys.exit(f"[!] XML directory not found: {xml_dir}")

    xml_files = sorted(xml_dir.glob("*.xml"))
    if not xml_files:
        sys.exit(f"[!] No *.xml files in {xml_dir}")

    if args.only:
        wanted    = {s.strip() for s in args.only.split(",")}
        xml_files = [f for f in xml_files if f.stem in wanted]
        if not xml_files:
            sys.exit(f"[!] --only '{args.only}' matched nothing.")

    print(f"\n[*] WSTG-BUSL-04 — Process Timing Prep")
    print(f"    XML dir : {xml_dir}")
    print(f"    Files   : {[f.name for f in xml_files]}")
    print(f"    Pick N  : {args.pick_n} per file")
    if args.seed is not None:
        print(f"    Seed    : {args.seed}")

    for xml_path in xml_files:
        process_xml_file(xml_path, args.pick_n, out_dir, rng)

    print(f"\n[+] Done — run busl_04_runner.py next.\n")


if __name__ == "__main__":
    main()
