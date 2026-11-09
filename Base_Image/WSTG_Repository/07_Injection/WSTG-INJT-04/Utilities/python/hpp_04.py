#!/usr/bin/env python3
"""
WSTG-INJT-04 — HTTP Parameter Pollution Payload Generator
==========================================================
Reads Burp Suite proxy history XML exports from Inputs/XML/, samples N
endpoints per file, generates HPP variations using the core HPPGenerator
logic, and writes per-category wordlists and endpoint JSON reports.

Designed for impact-focused scoping: drop only authentication.xml and
authorization.xml (or any other targeted exports) into Inputs/XML/ —
outputs are named after each file automatically.

Outputs
-------
    Inputs/Wordlists/<xml_name>.txt          — aggregated HPP payload list
    Outputs/test_outputs/<xml_name>.json     — selected endpoint metadata

Usage
-----
    python hpp_04.py                         # process all XMLs, pick 5 each
    python hpp_04.py -n 10                   # pick 10 endpoints per file
    python hpp_04.py --xml-dir /path/to/xml  # alternate XML folder
    python hpp_04.py --only authentication   # single file (no .xml extension)
    python hpp_04.py --seed 42               # reproducible random sampling
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
from urllib.parse import parse_qs, urlparse

# ── Paths ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR       = Path(__file__).resolve().parent        # Utilities/python/
TOOL_ROOT        = SCRIPT_DIR.parent.parent               # WSTG-INJT-04/
DEFAULT_XML_DIR  = TOOL_ROOT / "Inputs"  / "XML"
DEFAULT_WL_DIR   = TOOL_ROOT / "Inputs"  / "Wordlists"
DEFAULT_OUT_DIR  = TOOL_ROOT / "Outputs" / "test_outputs"

DEFAULT_PICK_N   = 5


# ══════════════════════════════════════════════════════════════════════════════
# HPP Generator — core logic preserved from original tool
# ══════════════════════════════════════════════════════════════════════════════

class HPPGenerator:
    def __init__(self, query_string: str):
        self.query_string = query_string
        self.params       = self._parse_params(query_string)

    def _parse_params(self, qs: str) -> dict[str, str]:
        params = {}
        if not qs:
            return params
        qs = qs.lstrip("?")
        for pair in qs.split("&"):
            if "=" in pair:
                k, _, v = pair.partition("=")
                k = k.strip()
                if k:
                    params[k] = v
        return params

    def generate_single_param_variations(self, param_name: str, param_value: str) -> list[str]:
        v = [(f"{param_name}={param_value}")]   # handy alias

        variations = [
            # Duplicated
            f"{param_name}={param_value}&{param_name}={param_value}",
            f"{param_name}={param_value}&{param_name}=modified",
            f"{param_name}=modified&{param_name}={param_value}",
            f"{param_name}={param_value}&{param_name}={param_value}&{param_name}=third",
            # Empty / null
            f"{param_name}=",
            f"{param_name}=&{param_name}={param_value}",
            f"{param_name}={param_value}&{param_name}=",
            f"{param_name}",
            f"{param_name}=null",
            f"{param_name}=NULL",
            f"{param_name}=%00",
            f"{param_name}=%20",
            # Special / injection
            f"{param_name}={param_value}%00&{param_name}=injected",
            f"{param_name}={param_value}%26{param_name}=injected",
            f"{param_name}={param_value}%23{param_name}=injected",
            f"{param_name}={param_value};{param_name}=injected",
            f"{param_name}[]={param_value}",
            f"{param_name}[0]={param_value}",
            f"{param_name}[]=value1&{param_name}[]=value2",
            f"{param_name}={param_value}&{param_name}=<script>alert(1)</script>",
            f"{param_name}={param_value}&{param_name}='OR'1'='1",
            f"{param_name}={param_value}%0a{param_name}=injected",
            f"{param_name}={param_value}%0d%0a{param_name}=injected",
        ]
        return variations

    def generate_multi_param_variations(self) -> list[str]:
        if len(self.params) < 2:
            return []

        variations  = []
        param_list  = list(self.params.items())

        # Duplicate first param in various positions
        fk, fv = param_list[0]
        rest   = "&".join(f"{k}={v}" for k, v in param_list[1:])
        variations += [
            f"{fk}={fv}&{fk}=injected&{rest}",
            f"{fk}={fv}&{rest}&{fk}=injected",
            f"{fk}=injected&{fk}={fv}&{rest}",
        ]

        # Duplicate last param in various positions
        lk, lv   = param_list[-1]
        beginning = "&".join(f"{k}={v}" for k, v in param_list[:-1])
        variations += [
            f"{lk}=injected&{beginning}&{lk}={lv}",
            f"{beginning}&{lk}={lv}&{lk}=injected",
            f"{beginning}&{lk}=injected&{lk}={lv}",
        ]

        # Duplicate middle param (3+ params only)
        if len(param_list) >= 3:
            mid       = len(param_list) // 2
            mk, mv    = param_list[mid]
            before    = "&".join(f"{k}={v}" for k, v in param_list[:mid])
            after     = "&".join(f"{k}={v}" for k, v in param_list[mid + 1:])
            variations += [
                f"{before}&{mk}={mv}&{mk}=injected&{after}",
                f"{mk}=injected&{before}&{mk}={mv}&{after}",
            ]

        # Inject new param between existing ones
        head = f"{param_list[0][0]}={param_list[0][1]}"
        tail = "&".join(f"{k}={v}" for k, v in param_list[1:])
        tail_prefix = "&".join(f"{k}={v}" for k, v in param_list[:-1])
        tail_last   = f"{param_list[-1][0]}={param_list[-1][1]}"
        variations += [
            f"{head}&injected=malicious&{tail}",
            f"{tail_prefix}&injected=malicious&{tail_last}",
        ]

        # Null-byte separator injections
        original = "&".join(f"{k}={v}" for k, v in param_list)
        variations += [
            original.replace("&", "%00&", 1),
            original.replace("&", "&%00", 1),
            original.replace("&", "%26",  1),
        ]

        # All params duplicated
        variations.append("&".join(f"{k}={v}&{k}={v}" for k, v in param_list))

        # Reversed param order
        variations.append("&".join(f"{k}={v}" for k, v in reversed(param_list)))

        return variations

    def generate_all(self) -> list[str]:
        all_variations: list[str] = []

        for name, value in self.params.items():
            all_variations.extend(self.generate_single_param_variations(name, value))

        if len(self.params) > 1:
            all_variations.extend(self.generate_multi_param_variations())

        # Deduplicate, preserve order
        seen: set[str] = set()
        unique: list[str] = []
        for var in all_variations:
            if var not in seen:
                seen.add(var)
                unique.append(var)
        return unique


# ══════════════════════════════════════════════════════════════════════════════
# Burp XML parsing & param extraction
# ══════════════════════════════════════════════════════════════════════════════

def _decode_request(text: str, is_b64: bool) -> str:
    if is_b64:
        try:
            return base64.b64decode(text.strip()).decode("utf-8", errors="replace")
        except Exception:
            return text
    return text


def _extract_query_string(request_raw: str) -> str | None:
    """
    Pull a  key=value&key2=value2  string out of a raw HTTP request.
    Search order: URL query string → URL-encoded body → JSON body.
    Returns None if no parseable parameters are found.
    """
    lines = request_raw.splitlines()
    if not lines:
        return None

    # First line:  METHOD /path?qs HTTP/x.x
    parts    = lines[0].strip().split(" ", 2)
    path_raw = parts[1] if len(parts) >= 2 else ""
    qs       = urlparse(path_raw).query
    if qs:
        return qs

    # Body — everything after the first blank line
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
            return body
    except Exception:
        pass

    # JSON body → convert to flat query-string format
    try:
        data = json.loads(body)
        if isinstance(data, dict) and data:
            parts = []
            for k, v in data.items():
                if isinstance(v, (str, int, float, bool)):
                    parts.append(f"{k}={v}")
                elif isinstance(v, list):
                    for item in v:
                        parts.append(f"{k}={item}")
            if parts:
                return "&".join(parts)
    except Exception:
        pass

    return None


def parse_burp_xml(xml_path: Path) -> list[dict]:
    """
    Parse a Burp Suite proxy history XML export.
    Returns only items that have at least one extractable parameter.

    Each record:
        { method, host, path, query_string }
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
        method = (item.findtext("method") or "GET").strip().upper()
        path   = (item.findtext("path")   or "/").strip()
        host   = (item.findtext("host")   or "").strip()

        req_el = item.find("request")
        if req_el is None or not req_el.text:
            continue

        is_b64  = req_el.attrib.get("base64", "false").lower() == "true"
        req_raw = _decode_request(req_el.text, is_b64)
        qs      = _extract_query_string(req_raw)

        if not qs:
            continue   # no params — nothing for HPP to work with

        records.append({"method": method, "host": host, "path": path, "query_string": qs})

    return records


# ══════════════════════════════════════════════════════════════════════════════
# Per-file processing
# ══════════════════════════════════════════════════════════════════════════════

def process_xml_file(
    xml_path:  Path,
    pick_n:    int,
    wl_dir:    Path,
    out_dir:   Path,
    rng:       random.Random,
) -> None:
    category = xml_path.stem    # "authentication", "authorization", …

    print(f"\n  [{category}]  {xml_path.name}")

    # ── Parse ──────────────────────────────────────────────────────────────
    candidates = parse_burp_xml(xml_path)
    if not candidates:
        print(f"    [!] No parameterised endpoints found — skipping.")
        return

    total = len(candidates)
    print(f"    Endpoints with params: {total}")

    # ── Sample ─────────────────────────────────────────────────────────────
    n = min(pick_n, total)
    if n < pick_n:
        print(f"    [!] Requested {pick_n} but only {total} available — using all {n}.")
    selected = rng.sample(candidates, n)
    print(f"    Selected: {n}")

    # ── Generate HPP variations ────────────────────────────────────────────
    all_variations:  list[str]  = []
    endpoint_meta:   list[dict] = []

    for ep_idx, ep in enumerate(selected):
        gen        = HPPGenerator(ep["query_string"])
        variations = gen.generate_all()
        all_variations.extend(variations)

        endpoint_meta.append({
            "index":                   ep_idx,
            "host":                    ep["host"],
            "method":                  ep["method"],
            "path":                    ep["path"],
            "query_string_used":       ep["query_string"],
            "params":                  gen.params,
            "hpp_variations_generated": len(variations),
        })

        print(
            f"    [{ep_idx}]  {ep['method']:<6} {ep['host']}{ep['path']}"
            f"  —  {len(gen.params)} param(s)  →  {len(variations)} variation(s)"
        )

    # Deduplicate across all selected endpoints
    seen: set[str] = set()
    unique: list[str] = []
    for var in all_variations:
        if var not in seen:
            seen.add(var)
            unique.append(var)

    print(f"    Total unique HPP variations: {len(unique)}")

    # ── Write wordlist ─────────────────────────────────────────────────────
    wl_dir.mkdir(parents=True, exist_ok=True)
    wl_path = wl_dir / f"{category}.txt"
    wl_path.write_text("\n".join(unique) + "\n", encoding="utf-8")
    print(f"    Wordlist  →  {wl_path.relative_to(wl_dir.parent.parent)}")

    # ── Write JSON report ──────────────────────────────────────────────────
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"{category}.json"

    payload = {
        "scan_metadata": {
            "wstg_id":                  "WSTG-INJT-04",
            "title":                    "HTTP Parameter Pollution",
            "category":                 category,
            "source_xml":               xml_path.name,
            "scan_time":                datetime.now(timezone.utc).isoformat(),
            "total_endpoints_in_xml":   total,
            "endpoints_selected":       n,
            "total_hpp_variations":     len(unique),
        },
        "endpoints": endpoint_meta,
    }

    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"    Report    →  {json_path.relative_to(wl_dir.parent.parent)}")


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    ap = argparse.ArgumentParser(
        description="WSTG-INJT-04 — HPP payload generator from Burp XML exports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Place authentication.xml / authorization.xml (or any targeted exports)\n"
            "in Inputs/XML/ — each file becomes its own wordlist and JSON report."
        ),
    )
    ap.add_argument(
        "--xml-dir", metavar="DIR", default=str(DEFAULT_XML_DIR),
        help=f"Folder containing Burp XML exports  [default: {DEFAULT_XML_DIR}]",
    )
    ap.add_argument(
        "--wl-dir", metavar="DIR", default=str(DEFAULT_WL_DIR),
        help=f"Wordlist output directory           [default: {DEFAULT_WL_DIR}]",
    )
    ap.add_argument(
        "--out-dir", metavar="DIR", default=str(DEFAULT_OUT_DIR),
        help=f"JSON report output directory        [default: {DEFAULT_OUT_DIR}]",
    )
    ap.add_argument(
        "-n", "--pick-n", type=int, default=DEFAULT_PICK_N, metavar="N",
        help=f"Endpoints to randomly sample per XML file  [default: {DEFAULT_PICK_N}]",
    )
    ap.add_argument(
        "--only", metavar="NAME[,NAME]",
        help="Process only these XML file stems, comma-separated (e.g. authentication)",
    )
    ap.add_argument(
        "--seed", type=int, default=None, metavar="INT",
        help="RNG seed for reproducible endpoint sampling",
    )

    args    = ap.parse_args()
    xml_dir = Path(args.xml_dir)
    wl_dir  = Path(args.wl_dir)
    out_dir = Path(args.out_dir)
    rng     = random.Random(args.seed)

    if not xml_dir.is_dir():
        sys.exit(f"[!] XML directory not found: {xml_dir}")

    # Discover XML files
    xml_files = sorted(xml_dir.glob("*.xml"))
    if not xml_files:
        sys.exit(f"[!] No *.xml files found in {xml_dir}")

    # Apply --only filter
    if args.only:
        wanted = {s.strip() for s in args.only.split(",")}
        xml_files = [f for f in xml_files if f.stem in wanted]
        if not xml_files:
            sys.exit(f"[!] --only filter '{args.only}' matched nothing in {xml_dir}")

    print(f"\n[*] WSTG-INJT-04 — HTTP Parameter Pollution")
    print(f"    XML dir  : {xml_dir}")
    print(f"    Files    : {[f.name for f in xml_files]}")
    print(f"    Pick N   : {args.pick_n} endpoints per file")
    if args.seed is not None:
        print(f"    RNG seed : {args.seed}")

    for xml_path in xml_files:
        process_xml_file(xml_path, args.pick_n, wl_dir, out_dir, rng)

    print(f"\n[+] Done.\n")


if __name__ == "__main__":
    main()
