#!/usr/bin/env python3
"""
WSTG-BUSL-04 — Process Timing / TOCTOU Race Runner
====================================================
Reads the staged endpoint JSON produced by busl_04_prep.py, fires each
curl command TWICE simultaneously (concurrent threads — the TOCTOU race),
records both status codes, and classifies the result.

Classification
--------------
    200        → FINDING     potential race condition / unrestricted access
    403        → INVESTIGATE access control present but worth probing further
    404 / 500  → NOT_FINDING endpoint not found / server error
    other      → INVESTIGATE review manually

Outputs
-------
    Outputs/test_outputs/<category>_results.json

Usage
-----
    python busl_04_runner.py                        # all staged JSONs
    python busl_04_runner.py --only authentication  # single category
    python busl_04_runner.py --race-count 3         # fire 3 concurrent requests
    python busl_04_runner.py --timeout 15           # per-request timeout (s)
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR      = Path(__file__).resolve().parent
TOOL_ROOT       = SCRIPT_DIR.parent.parent
DEFAULT_IN_DIR  = TOOL_ROOT / "Outputs" / "test_outputs"
DEFAULT_OUT_DIR = TOOL_ROOT / "Outputs" / "test_outputs"

DEFAULT_RACE_COUNT = 2
DEFAULT_TIMEOUT    = 10   # seconds per request


# ── Result classification ──────────────────────────────────────────────────────

def _classify(status_codes: list[int | None]) -> tuple[str, str]:
    """
    Return (result_label, note) based on the observed status codes.
    Evaluated across all concurrent requests for this endpoint.
    """
    codes = [c for c in status_codes if c is not None]

    if not codes:
        return "ERROR", "No status code received — connection failure or timeout"

    if 200 in codes:
        return "FINDING", "HTTP 200 OK received — potential TOCTOU / unrestricted access"

    if any(c == 403 for c in codes):
        return "INVESTIGATE", "HTTP 403 Forbidden — access control present, worth probing"

    if any(c == 404 for c in codes):
        return "NOT_FINDING", "HTTP 404 Not Found"

    if any(c == 500 for c in codes):
        return "NOT_FINDING", "HTTP 500 Server Error"

    # Anything else (301, 302, 429, etc.) — flag for manual review
    unique = sorted(set(codes))
    return "INVESTIGATE", f"HTTP {unique} — review manually"


# ── Race execution ─────────────────────────────────────────────────────────────

def _fire_single(curl_args: list[str], request_n: int, timeout: int) -> dict:
    """
    Run one curl call; return { request_n, status_code, elapsed_ms, error }.
    Appends output-capture flags to the stored curl_args list at run time.
    """
    # Add output flags: silent, discard body, print status code only
    cmd = curl_args + [
        "-o", "/dev/null" if sys.platform != "win32" else "NUL",
        "--write-out", "%{http_code}",
        "--max-time", str(timeout),
    ]

    start = time.monotonic()
    try:
        proc    = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=timeout + 5)
        elapsed = int((time.monotonic() - start) * 1000)

        raw_code = proc.stdout.strip()
        try:
            code = int(raw_code)
        except ValueError:
            code = None

        return {
            "request_n":   request_n,
            "status_code": code,
            "elapsed_ms":  elapsed,
            "error":       None,
        }

    except subprocess.TimeoutExpired:
        return {
            "request_n":   request_n,
            "status_code": None,
            "elapsed_ms":  -1,
            "error":       "timeout",
        }
    except FileNotFoundError:
        sys.exit("[!] curl not found on PATH — install curl and retry.")
    except Exception as exc:
        return {
            "request_n":   request_n,
            "status_code": None,
            "elapsed_ms":  -1,
            "error":       str(exc),
        }


def fire_race(curl_args: list[str], race_count: int, timeout: int) -> list[dict]:
    """
    Submit race_count curl calls simultaneously.
    Returns results sorted by request_n.
    """
    with ThreadPoolExecutor(max_workers=race_count) as pool:
        futures = {
            pool.submit(_fire_single, curl_args, n + 1, timeout): n
            for n in range(race_count)
        }
        results = [f.result() for f in as_completed(futures)]

    return sorted(results, key=lambda r: r["request_n"])


# ── Per-category processing ────────────────────────────────────────────────────

def process_category(
    json_path:  Path,
    out_dir:    Path,
    race_count: int,
    timeout:    int,
) -> None:
    category = json_path.stem   # "authentication", "authorization", …

    print(f"\n  [{category}]  {json_path.name}")

    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"    [!] Could not read JSON: {e}")
        return

    endpoints = data.get("endpoints", [])
    if not endpoints:
        print(f"    [!] No endpoints in JSON — run busl_04_prep.py first.")
        return

    print(f"    Endpoints to race: {len(endpoints)}  |  Concurrent requests each: {race_count}")

    result_endpoints: list[dict] = []
    summary = {"FINDING": 0, "INVESTIGATE": 0, "NOT_FINDING": 0, "ERROR": 0}

    for ep in endpoints:
        idx        = ep.get("index", "?")
        method     = ep.get("method", "?")
        url        = ep.get("url",    "?")
        path       = ep.get("path",   "?")
        host       = ep.get("host",   "?")
        curl_args  = ep.get("curl_args", [])

        if not curl_args:
            print(f"    [{idx}]  {method} {host}{path}  — no curl_args, skipping")
            continue

        print(f"    [{idx}]  {method} {host}{path}  — firing {race_count}x concurrently …", end="", flush=True)

        race_results = fire_race(curl_args, race_count, timeout)
        codes        = [r["status_code"] for r in race_results]
        result, note = _classify(codes)

        summary[result] = summary.get(result, 0) + 1

        # Status display
        codes_str = ", ".join(str(c) if c else "ERR" for c in codes)
        print(f"  [{codes_str}]  → {result}")

        result_endpoints.append({
            "index":        idx,
            "host":         host,
            "method":       method,
            "url":          url,
            "path":         path,
            "content_type": ep.get("content_type", ""),
            "race_results": race_results,
            "status_codes": codes,
            "result":       result,
            "result_note":  note,
        })

    # Summary line
    print(
        f"\n    Summary — "
        f"FINDING: {summary['FINDING']}  "
        f"INVESTIGATE: {summary['INVESTIGATE']}  "
        f"NOT_FINDING: {summary['NOT_FINDING']}  "
        f"ERROR: {summary.get('ERROR', 0)}"
    )

    # Write results JSON
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{category}_results.json"

    src_meta = data.get("scan_metadata", {})
    payload  = {
        "scan_metadata": {
            "wstg_id":               "WSTG-BUSL-04",
            "title":                 "Testing for Process Timing (TOCTOU)",
            "category":              category,
            "source_json":           json_path.name,
            "source_xml":            src_meta.get("source_xml", ""),
            "scan_time":             datetime.now(timezone.utc).isoformat(),
            "race_requests_per_ep":  race_count,
            "timeout_s":             timeout,
        },
        "summary":   summary,
        "endpoints": result_endpoints,
    }

    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"    Results → {out_path.relative_to(TOOL_ROOT)}")


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="WSTG-BUSL-04 Runner — concurrent race-condition tester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Reads <category>.json from Outputs/test_outputs/ (written by busl_04_prep.py).\n"
            "Fires each endpoint's curl command twice simultaneously and classifies responses."
        ),
    )
    ap.add_argument(
        "--in-dir", metavar="DIR", default=str(DEFAULT_IN_DIR),
        help=f"Directory containing prep JSONs  [default: {DEFAULT_IN_DIR}]",
    )
    ap.add_argument(
        "--out-dir", metavar="DIR", default=str(DEFAULT_OUT_DIR),
        help=f"Results output directory         [default: {DEFAULT_OUT_DIR}]",
    )
    ap.add_argument(
        "--race-count", type=int, default=DEFAULT_RACE_COUNT, metavar="N",
        help=f"Concurrent requests per endpoint [default: {DEFAULT_RACE_COUNT}]",
    )
    ap.add_argument(
        "--timeout", type=int, default=DEFAULT_TIMEOUT, metavar="S",
        help=f"Per-request timeout (seconds)    [default: {DEFAULT_TIMEOUT}]",
    )
    ap.add_argument(
        "--only", metavar="NAME[,NAME]",
        help="Process only these category stems, comma-separated",
    )

    args    = ap.parse_args()
    in_dir  = Path(args.in_dir)
    out_dir = Path(args.out_dir)

    if not in_dir.is_dir():
        sys.exit(f"[!] Input directory not found: {in_dir}")

    # Find staged JSONs — exclude anything already named *_results.json
    json_files = sorted(
        f for f in in_dir.glob("*.json")
        if not f.stem.endswith("_results")
    )
    if not json_files:
        sys.exit(
            f"[!] No staged JSONs found in {in_dir}\n"
            f"    Run busl_04_prep.py first."
        )

    if args.only:
        wanted     = {s.strip() for s in args.only.split(",")}
        json_files = [f for f in json_files if f.stem in wanted]
        if not json_files:
            sys.exit(f"[!] --only '{args.only}' matched nothing.")

    print(f"\n[*] WSTG-BUSL-04 — Process Timing Race Runner")
    print(f"    Input dir    : {in_dir}")
    print(f"    Categories   : {[f.stem for f in json_files]}")
    print(f"    Race count   : {args.race_count} concurrent requests per endpoint")
    print(f"    Timeout      : {args.timeout}s per request")

    for json_path in json_files:
        process_category(json_path, out_dir, args.race_count, args.timeout)

    print(f"\n[+] Done.\n")


if __name__ == "__main__":
    main()
