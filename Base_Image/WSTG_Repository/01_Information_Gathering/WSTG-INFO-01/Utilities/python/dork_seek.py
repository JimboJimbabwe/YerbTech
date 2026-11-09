#!/usr/bin/env python3
"""
dork_seek.py — WSTG-INFO-01 Google Dork Reconnaissance Tool
Location: WSTG_Repository/01_Information_Gathering/WSTG-INFO-01/Utilities/python/dork_seek.py

Usage:
    python dork_seek.py --input_file <path> --input_keyword <keyword>
                        [--filetype <ext> [<ext> ...]] --output <path>

Example:
    python dork_seek.py --input_file Inputs/Data/terms.txt
                        --input_keyword "Trusted Ascent"
                        --filetype pdf xlsx
                        --output Outputs/test_outputs/dork_results.txt
"""

import argparse
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
import json
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        prog="dork_seek.py",
        description="Google dork reconnaissance — WSTG-INFO-01",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--input_file", required=True,
        help="Path to plaintext file containing one search term per line."
    )
    parser.add_argument(
        "--input_keyword", required=True,
        help='Static keyword always included in every dork (e.g. "Trusted Ascent").'
    )
    parser.add_argument(
        "--filetype", nargs="+", default=None, metavar="EXT",
        help="One or more filetypes to restrict results (e.g. pdf xlsx docx). "
             "Each is searched as a separate dork loop."
    )
    parser.add_argument(
        "--output", required=True,
        help="Output file path (txt or json). Extension determines format."
    )
    parser.add_argument(
        "--delay", type=float, default=2.0,
        help="Seconds to wait between requests to avoid rate-limiting (default: 2)."
    )
    parser.add_argument(
        "--num_results", type=int, default=10,
        help="Number of results to request per dork query (default: 10, max: 10 for free CSE)."
    )
    parser.add_argument(
        "--api_key", default=None,
        help="Google Custom Search API key. If omitted, dorks are built and printed "
             "only (dry-run / manual mode)."
    )
    parser.add_argument(
        "--cse_id", default=None,
        help="Google Custom Search Engine ID (cx). Required when --api_key is provided."
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def load_terms(path: str) -> list[str]:
    """Read non-empty, non-comment lines from the terms file."""
    p = Path(path)
    if not p.is_file():
        sys.exit(f"[ERROR] Input file not found: {path}")
    terms = []
    with p.open("r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if line and not line.startswith("#"):
                terms.append(line)
    if not terms:
        sys.exit(f"[ERROR] No usable terms found in: {path}")
    print(f"[+] Loaded {len(terms)} term(s) from {path}")
    return terms


def build_dork(keyword: str, term: str, filetype: str | None = None) -> str:
    """
    Construct a Google dork string.
    Format:  "<keyword>" "<term>" [filetype:<ext>]
    """
    dork = f'"{keyword}" "{term}"'
    if filetype:
        dork += f" filetype:{filetype}"
    return dork


def google_cse_search(dork: str, api_key: str, cse_id: str,
                      num: int = 10) -> list[dict]:
    """
    Call Google Custom Search JSON API and return a list of result dicts.
    Each dict has: title, link, snippet.
    """
    base = "https://www.googleapis.com/customsearch/v1"
    params = urllib.parse.urlencode({
        "key": api_key,
        "cx": cse_id,
        "q": dork,
        "num": min(num, 10),
    })
    url = f"{base}?{params}"
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"  [!] HTTP {e.code} for dork: {dork[:60]}...")
        return []
    except urllib.error.URLError as e:
        print(f"  [!] URL error ({e.reason}) for dork: {dork[:60]}...")
        return []

    items = data.get("items", [])
    return [
        {
            "title":   item.get("title", ""),
            "link":    item.get("link", ""),
            "snippet": item.get("snippet", "").replace("\n", " "),
        }
        for item in items
    ]


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

def write_txt(path: Path, records: list[dict], meta: dict) -> None:
    with path.open("w", encoding="utf-8") as fh:
        fh.write("=" * 72 + "\n")
        fh.write("  dork_seek.py — WSTG-INFO-01 Google Dork Reconnaissance\n")
        fh.write(f"  Generated : {meta['timestamp']}\n")
        fh.write(f"  Keyword   : {meta['keyword']}\n")
        fh.write(f"  Terms file: {meta['input_file']}\n")
        fh.write(f"  Filetypes : {', '.join(meta['filetypes']) if meta['filetypes'] else 'none'}\n")
        fh.write(f"  Total hits: {meta['total_hits']}\n")
        fh.write("=" * 72 + "\n\n")

        for rec in records:
            fh.write(f"DORK     : {rec['dork']}\n")
            if rec.get("dry_run"):
                fh.write("  [DRY-RUN — no API key supplied]\n")
                fh.write(f"  Manual URL: https://www.google.com/search?q={urllib.parse.quote(rec['dork'])}\n")
            elif not rec["results"]:
                fh.write("  [no results]\n")
            else:
                for i, r in enumerate(rec["results"], 1):
                    fh.write(f"  [{i}] {r['title']}\n")
                    fh.write(f"      {r['link']}\n")
                    fh.write(f"      {r['snippet']}\n")
            fh.write("\n")


def write_json(path: Path, records: list[dict], meta: dict) -> None:
    payload = {"meta": meta, "results": records}
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    # Validate API/CSE pairing
    if args.api_key and not args.cse_id:
        sys.exit("[ERROR] --cse_id is required when --api_key is provided.")
    dry_run = args.api_key is None

    if dry_run:
        print("[!] No --api_key supplied — running in DRY-RUN mode.")
        print("    Dorks will be built and written but NOT executed.\n")

    # Ensure output directory exists
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    terms = load_terms(args.input_file)
    filetypes = args.filetype or [None]   # None = no filetype restriction

    records = []
    total_hits = 0

    for ft in filetypes:
        ft_label = ft if ft else "(none)"
        print(f"\n[*] Filetype: {ft_label}")
        for term in terms:
            dork = build_dork(args.input_keyword, term, ft)
            print(f"  Dork: {dork}")

            if dry_run:
                records.append({"dork": dork, "filetype": ft_label,
                                 "term": term, "dry_run": True, "results": []})
            else:
                results = google_cse_search(
                    dork, args.api_key, args.cse_id, args.num_results
                )
                hit_count = len(results)
                total_hits += hit_count
                print(f"    → {hit_count} result(s)")
                records.append({
                    "dork": dork, "filetype": ft_label,
                    "term": term, "dry_run": False,
                    "results": results,
                })
                time.sleep(args.delay)

    meta = {
        "timestamp":  datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "keyword":    args.input_keyword,
        "input_file": args.input_file,
        "filetypes":  [f for f in (args.filetype or []) if f],
        "total_hits": total_hits,
        "dry_run":    dry_run,
    }

    # Write output
    suffix = out_path.suffix.lower()
    if suffix == ".json":
        write_json(out_path, records, meta)
    else:
        write_txt(out_path, records, meta)

    print(f"\n[+] Output written to: {out_path}")
    print(f"[+] Total results recorded: {total_hits}")
    if dry_run:
        print("[+] Re-run with --api_key and --cse_id to execute live searches.")


if __name__ == "__main__":
    main()
