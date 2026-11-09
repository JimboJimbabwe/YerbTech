#!/usr/bin/env python3
"""
WSTG-BUSL-05 Prep — Function Limit Wordlist Generator
======================================================
Reads a Burp Suite proxy history XML export, presents a numbered selection
menu of captured requests, and writes one Burp Intruder wordlist per chosen
endpoint.

Each wordlist (EP_0.txt … EP_4.txt) contains a single extracted parameter
value repeated 50 times — ready to drop into Burp Intruder for
function-limit / rate-limit testing.

Workflow
--------
1.  Place your Burp proxy export at   Inputs/XML/function_limit.xml
2.  Run this script, select 5 endpoints from the menu
3.  Load EP_N.txt into Burp Intruder (Sniper / Battering Ram)
4.  Run the attack and export results to  Inputs/XML/intruder_test.xml
5.  Run busl_05_analyze.py to check for successive 200 OKs

Usage
-----
    python busl_05_prep.py                        # interactive menu
    python busl_05_prep.py --auto                 # auto-pick first 5
    python busl_05_prep.py --indices 0,2,4,7,12   # explicit selection
    python busl_05_prep.py -x /path/to/export.xml
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# ── Paths ──────────────────────────────────────────────────────────────────────
#   Place this file at  WSTG-BUSL-05/Utilities/python/busl_05_prep.py
SCRIPT_DIR  = Path(__file__).resolve().parent
TOOL_ROOT   = SCRIPT_DIR.parent.parent
DEFAULT_XML = TOOL_ROOT / "Inputs" / "XML"       / "function_limit.xml"
DEFAULT_OUT = TOOL_ROOT / "Inputs" / "Wordlists"

SELECT_COUNT   = 5     # number of endpoints to select
WORDLIST_LINES = 50    # repetitions per wordlist


# ── Request decoding & param extraction ───────────────────────────────────────

def _decode_request(text: str, is_b64: bool) -> str:
    """Decode a Burp request field (base64 or plain)."""
    if is_b64:
        try:
            return base64.b64decode(text.strip()).decode("utf-8", errors="replace")
        except Exception:
            return text
    return text


def _extract_first_param(request_text: str) -> tuple[str, str] | None:
    """
    Find the first parameter : value pair in an HTTP request.

    Search order (stops at the first hit):
      1. URL query string   (GET /path?foo=bar)
      2. URL-encoded body   (Content-Type: application/x-www-form-urlencoded)
      3. JSON body          (Content-Type: application/json)

    Returns (param_name, value) or None if nothing parseable is found.
    """
    lines = request_text.splitlines()
    if not lines:
        return None

    # ── 1. Query string ────────────────────────────────────────────────────
    first_line = lines[0]
    parts      = first_line.split(" ", 2)
    path_raw   = parts[1] if len(parts) >= 2 else ""

    qs = urlparse(path_raw).query
    if qs:
        params = parse_qs(qs, keep_blank_values=True)
        if params:
            k = next(iter(params))
            return k, params[k][0]

    # ── 2 & 3. Body (everything after the first blank line) ───────────────
    body = ""
    for i, line in enumerate(lines):
        if line.strip() == "":
            body = "\n".join(lines[i + 1:]).strip()
            break

    if not body:
        return None

    # URL-encoded body
    try:
        params = parse_qs(body, keep_blank_values=True)
        if params:
            k = next(iter(params))
            return k, params[k][0]
    except Exception:
        pass

    # JSON body
    try:
        data = json.loads(body)
        if isinstance(data, dict) and data:
            k = next(iter(data))
            return k, str(data[k])
    except Exception:
        pass

    return None


# ── XML loading ───────────────────────────────────────────────────────────────

def load_items(xml_path: Path) -> list[dict]:
    """
    Parse Burp proxy history XML.
    Returns a list of dicts, one per <item>, with index/method/path/param info.
    """
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError as e:
        sys.exit(f"[!] XML parse error in {xml_path}: {e}")
    except FileNotFoundError:
        sys.exit(f"[!] XML not found: {xml_path}")

    items: list[dict] = []

    for i, el in enumerate(root.findall("item")):
        method = (el.findtext("method") or "???").strip().upper()
        path   = (el.findtext("path")   or "/").strip()
        host   = (el.findtext("host")   or "").strip()

        # Decode request
        req_el  = el.find("request")
        req_raw = ""
        if req_el is not None and req_el.text:
            is_b64  = req_el.attrib.get("base64", "false").lower() == "true"
            req_raw = _decode_request(req_el.text, is_b64)

        pair = _extract_first_param(req_raw)
        param_name  = pair[0] if pair else "(none)"
        param_value = pair[1] if pair else ""

        items.append({
            "index":       i,
            "method":      method,
            "host":        host,
            "path":        path,
            "param_name":  param_name,
            "param_value": param_value,
        })

    if not items:
        sys.exit("[!] No <item> elements found in the XML.")

    print(f"[*] Loaded {len(items)} item(s) from {xml_path.name}")
    return items


# ── Selection helpers ─────────────────────────────────────────────────────────

def _print_menu(items: list[dict]) -> None:
    col = "{:>5}  {:<6}  {:<45}  {}"
    print()
    print(col.format("Index", "Method", "Path", "First Param : Value"))
    print(col.format("─────", "──────", "────", "────────────────────"))
    for it in items:
        path_trunc = it["path"][:45]
        if it["param_name"] != "(none)":
            pv = f"{it['param_name']} : {it['param_value']}"[:35]
        else:
            pv = "(no param found)"
        print(col.format(it["index"], it["method"], path_trunc, pv))
    print()


def select_interactive(items: list[dict], n: int) -> list[dict]:
    """Display menu and prompt the operator to choose n indices."""
    _print_menu(items)
    idx_map = {it["index"]: it for it in items}

    while True:
        raw = input(f"Select {n} indices (comma-separated, e.g. 0,1,3,5,9): ").strip()
        try:
            chosen = [int(x.strip()) for x in raw.split(",")]
        except ValueError:
            print("[!] Integers only, separated by commas.")
            continue

        if len(chosen) != n:
            print(f"[!] Need exactly {n} indices, got {len(chosen)}.")
            continue

        bad = [c for c in chosen if c not in idx_map]
        if bad:
            print(f"[!] These indices are out of range: {bad}")
            continue

        return [idx_map[c] for c in chosen]


def select_by_indices(items: list[dict], indices: list[int]) -> list[dict]:
    """Select items by explicit index list; exits on any invalid index."""
    idx_map = {it["index"]: it for it in items}
    result  = []
    for i in indices:
        if i not in idx_map:
            sys.exit(f"[!] Index {i} is out of range (XML has {len(items)} items, 0-based).")
        result.append(idx_map[i])
    return result


# ── Wordlist writer ───────────────────────────────────────────────────────────

def write_wordlists(selected: list[dict], out_dir: Path, repeat: int) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    for ep_idx, item in enumerate(selected):
        value = item["param_value"]

        # Warn if no value was extracted — write placeholder so file still exists
        if not value:
            print(
                f"  [!] EP_{ep_idx}: no parameter value found for "
                f"{item['method']} {item['path']} — wordlist will be empty strings."
            )

        out_file = out_dir / f"EP_{ep_idx}.txt"
        out_file.write_text("\n".join([value] * repeat) + "\n", encoding="utf-8")

        param_display = (
            f"{item['param_name']}={item['param_value']}"
            if item["param_name"] != "(none)"
            else "(no param)"
        )
        print(
            f"  [EP_{ep_idx}]  {item['method']:<6} {item['path']:<40}"
            f"  param: {param_display}"
            f"  →  {out_file.name}"
        )


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="WSTG-BUSL-05 Prep — generate Burp Intruder wordlists from Burp XML",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Output files: Inputs/Wordlists/EP_0.txt … EP_4.txt\n"
            "Each file contains the extracted parameter value repeated 50 times."
        ),
    )
    ap.add_argument(
        "-x", "--xml", metavar="FILE", default=str(DEFAULT_XML),
        help=f"Burp proxy XML export  [default: {DEFAULT_XML}]",
    )
    ap.add_argument(
        "-o", "--out-dir", metavar="DIR", default=str(DEFAULT_OUT),
        help=f"Wordlist output dir    [default: {DEFAULT_OUT}]",
    )

    sel = ap.add_mutually_exclusive_group()
    sel.add_argument(
        "--indices", metavar="N,N,...",
        help=f"Comma-separated XML item indices to select (must be exactly {SELECT_COUNT})",
    )
    sel.add_argument(
        "--auto", action="store_true",
        help=f"Auto-select first {SELECT_COUNT} items from the XML (no menu)",
    )

    ap.add_argument(
        "--count", type=int, default=WORDLIST_LINES,
        help=f"Number of lines (repetitions) per wordlist  [default: {WORDLIST_LINES}]",
    )
    ap.add_argument(
        "--select-count", type=int, default=SELECT_COUNT, dest="select_count",
        help=f"Number of endpoints to select  [default: {SELECT_COUNT}]",
    )

    args  = ap.parse_args()
    items = load_items(Path(args.xml))
    n     = args.select_count

    # ── Resolve selection ─────────────────────────────────────────────────
    if args.indices:
        try:
            idx_list = [int(x.strip()) for x in args.indices.split(",")]
        except ValueError:
            sys.exit("[!] --indices must be comma-separated integers.")
        if len(idx_list) != n:
            sys.exit(f"[!] --indices needs exactly {n} values, got {len(idx_list)}.")
        selected = select_by_indices(items, idx_list)

    elif args.auto:
        if len(items) < n:
            print(f"[!] XML has only {len(items)} item(s); selecting all.")
            n = len(items)
        selected = items[:n]
        print(f"[*] Auto-selected first {len(selected)} item(s).")

    else:
        if len(items) < n:
            print(f"[!] XML has only {len(items)} item(s) — selecting all.")
            n = len(items)
        selected = select_interactive(items, n)

    # ── Write wordlists ───────────────────────────────────────────────────
    out_dir = Path(args.out_dir)
    print(f"\n[*] Writing {len(selected)} wordlist(s) ({args.count} lines each) to {out_dir} …\n")
    write_wordlists(selected, out_dir, args.count)
    print(f"\n[+] Done — EP_0.txt … EP_{len(selected) - 1}.txt ready for Burp Intruder.")


if __name__ == "__main__":
    main()
