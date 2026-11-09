#!/usr/bin/env python3
"""
WSTG-CONF-02 — Application Platform Configuration
Script: conf_02_verdict.py

Reads a Burp Suite Intruder or proxy XML export and classifies each
response using the standard alert threshold logic. Every finding is
additionally tagged with the payload category it came from
(debug / dotslash / config / default / svc_repo / backup_variants / unknown).

Category attribution works by loading the conf_02_paths.json produced by
conf_02_wordlist.py and doing a reverse lookup from payload → category.
If the JSON is absent, all payloads fall under "unknown".

Alert thresholds (standard):
  200                       → HIGH
  302 / 202 / 301           → MEDIUM
  403 / 500 ≥ --min-bytes   → LOW  (verbose error, interesting)
  403 / 500 < --min-bytes   → SKIP (bare error, noise)
  404                       → SKIP
  other                     → SKIP

Body content checks (additional signals on any non-skip):
  - Indexing keywords (Index of, Parent Directory, mod_autoindex, etc.)
    → upgrades or confirms finding with INDEXING label
  - Config-file content keywords (DB_HOST, password=, API_KEY, secret=, etc.)
    → notes SENSITIVE_CONTENT

Inputs:
  WSTG-CONF-02/inputs/xml/intruder_conf02.xml   (Burp XML export)
  WSTG-CONF-02/inputs/json/conf_02_paths.json   (category map, optional)

Outputs:
  WSTG-CONF-02/outputs/test_outputs/sitrep.md   (appended)
  WSTG-CONF-02/inputs/json/intruder_alerts.json

Usage:
  python3 WSTG-CONF-02/utilities/python/conf_02_verdict.py \\
      --intruder WSTG-CONF-02/inputs/xml/intruder_conf02.xml \\
      [--paths-json WSTG-CONF-02/inputs/json/conf_02_paths.json] \\
      [--min-bytes 500] \\
      [--target https://app.example.com]
"""

import argparse
import base64
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime


# ---------------------------------------------------------------------------
# ANSI
# ---------------------------------------------------------------------------
BOLD    = "\033[1m"
DIM     = "\033[2m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
RESET   = "\033[0m"

SEV_COLOR = {"HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN}

CAT_COLOR = {
    "debug":           MAGENTA,
    "dotslash":        YELLOW,
    "config":          CYAN,
    "default":         DIM,
    "svc_repo":        GREEN,
    "backup_variants": YELLOW,
    "unknown":         DIM,
}


# ---------------------------------------------------------------------------
# Body content signals
# ---------------------------------------------------------------------------

INDEXING_PATTERN = re.compile(
    r'Index of|Parent Directory|Directory listing|mod_autoindex|'
    r'<title>\s*Index of|autoindex|DirectoryIndex|\[DIR\]|"sort by"',
    re.IGNORECASE
)

SENSITIVE_CONTENT_PATTERN = re.compile(
    r'(?:DB_HOST|DB_PASSWORD|DATABASE_URL|API_KEY|SECRET_KEY|'
    r'ACCESS_TOKEN|PRIVATE_KEY|AWS_ACCESS|AWS_SECRET|'
    r'password\s*=|passwd\s*=|secret\s*=|credentials|'
    r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----|'
    r'stack trace|Exception in thread|Traceback \(most recent call|'
    r'syntax error|parse error|Fatal error)',
    re.IGNORECASE
)

CONFIG_LEAK_PATTERN = re.compile(
    r'(?:application\.yml|application\.properties|web\.config|'
    r'nginx\.conf|httpd\.conf|docker-compose|Dockerfile|'
    r'\.env|settings\.py|database\.yml|secrets\.yml)',
    re.IGNORECASE
)


# ---------------------------------------------------------------------------
# XML parsing
# ---------------------------------------------------------------------------

def decode_element(el) -> str:
    if el is None:
        return ""
    if el.get("base64") == "true":
        try:
            return base64.b64decode(el.text or "").decode("utf-8", errors="replace")
        except Exception:
            return ""
    return (el.text or "").strip()


def parse_burp_xml(xml_path: str) -> list[dict]:
    """Parse Burp Intruder/proxy XML export → list of item dicts."""
    try:
        tree = ET.parse(xml_path)
    except (FileNotFoundError, ET.ParseError) as e:
        print(f"{RED}[!] Cannot parse XML: {e}{RESET}", file=sys.stderr)
        sys.exit(1)

    root = tree.getroot()
    # Handle both <items> root (proxy) and bare <item> list (intruder)
    items_el = root if root.tag == "items" else root.findall(".//items")
    if root.tag == "items":
        item_list = root.findall("item")
    else:
        item_list = root.findall(".//item")

    results = []
    for item in item_list:
        url_el      = item.find("url")
        status_el   = item.find("status")
        length_el   = item.find("responselength")
        response_el = item.find("response")

        url      = decode_element(url_el)
        status   = int(status_el.text.strip()) if status_el is not None and status_el.text else 0
        length   = int(length_el.text.strip()) if length_el is not None and length_el.text else 0
        response = decode_element(response_el)

        # Extract body from response (everything after \r\n\r\n or \n\n)
        body = ""
        if response:
            sep = response.find("\r\n\r\n")
            if sep == -1:
                sep = response.find("\n\n")
            body = response[sep + 4:] if sep != -1 else response

        # Extract payload from URL (last path segment or query)
        payload = url.split("?")[0].rstrip("/") if url else ""
        # Try to isolate the path portion
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            payload = parsed.path or url
        except Exception:
            pass

        results.append({
            "url":     url,
            "payload": payload,
            "status":  status,
            "length":  length,
            "body":    body,
        })

    return results


# ---------------------------------------------------------------------------
# Category map loader
# ---------------------------------------------------------------------------

def build_category_map(paths_json: str) -> dict[str, str]:
    """
    Loads conf_02_paths.json → { path: category }.
    If absent, returns empty dict (all unknowns).
    """
    if not paths_json or not os.path.exists(paths_json):
        return {}
    try:
        with open(paths_json, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}

    cat_map: dict[str, str] = {}
    for cat, paths in data.get("categories", {}).items():
        for path in paths:
            # Don't overwrite — first category wins (order: debug, dotslash, config, default, svc_repo, backup)
            if path not in cat_map:
                cat_map[path] = cat
    return cat_map


def get_category(payload: str, cat_map: dict[str, str]) -> str:
    if not cat_map:
        return "unknown"
    # Exact match first
    if payload in cat_map:
        return cat_map[payload]
    # Try with/without trailing slash
    alt = payload.rstrip("/") if payload.endswith("/") else payload + "/"
    if alt in cat_map:
        return cat_map[alt]
    return "unknown"


# ---------------------------------------------------------------------------
# Alert classification
# ---------------------------------------------------------------------------

def classify_response(status: int, body_bytes: int, min_bytes: int) -> tuple:
    """Returns (severity_or_None, reason_str)."""
    if status == 404:
        return None, "404 Not Found — skip"
    if status in (403, 500):
        if body_bytes < min_bytes:
            return None, f"{status} <{min_bytes}B — bare error, skip"
        return "LOW", f"{status} verbose error ({body_bytes}B)"
    if status == 200:
        return "HIGH", "200 OK — request accepted"
    if status in (302, 202, 301):
        return "MEDIUM", f"{status} — redirect/queued"
    if 200 <= status < 400:
        return "LOW", f"{status} unexpected 2xx/3xx"
    return None, f"{status} — skip"


def body_signals(body: str) -> list[str]:
    signals = []
    if INDEXING_PATTERN.search(body):
        signals.append("INDEXING — directory listing detected")
    if SENSITIVE_CONTENT_PATTERN.search(body):
        signals.append("SENSITIVE_CONTENT — credentials/stack trace/config keywords in body")
    if CONFIG_LEAK_PATTERN.search(body):
        signals.append("CONFIG_FILE — config filename referenced in body")
    return signals


# ---------------------------------------------------------------------------
# Report append
# ---------------------------------------------------------------------------

def append_sitrep(sitrep_path: str, alerts: list[dict], target: str):
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines   = []
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## WSTG-CONF-02 — Verdict Results")
    lines.append("")
    lines.append(f"**Generated:** {now_str}  ")
    if target:
        lines.append(f"**Target:** `{target}`  ")
    lines.append(f"**Total alerts:** {len(alerts)}  ")
    lines.append("")

    if not alerts:
        lines.append("No alerts above threshold.")
    else:
        # Group by severity
        for sev in ("HIGH", "MEDIUM", "LOW"):
            group = [a for a in alerts if a["severity"] == sev]
            if not group:
                continue
            lines.append(f"### {sev} ({len(group)})")
            lines.append("")
            for a in group:
                lines.append(f"#### `{a['payload']}` [{a['category']}]")
                lines.append("")
                lines.append(f"- **Status:** {a['status']}")
                lines.append(f"- **Length:** {a['length']}B")
                lines.append(f"- **Reason:** {a['reason']}")
                lines.append(f"- **Category:** `{a['category']}`")
                if a["body_signals"]:
                    for sig in a["body_signals"]:
                        lines.append(f"- **Signal:** {sig}")
                if target:
                    full_url = target.rstrip("/") + a["payload"]
                    lines.append(f"- **Probe:**")
                    lines.append(f"  ```")
                    lines.append(f"  curl -sk '{full_url}' -o /dev/null -w '%{{http_code}} %{{size_download}}\\n'")
                    lines.append(f"  ```")
                lines.append("")

    lines.append("---")
    lines.append("*Generated by conf_02_verdict.py — WSTG-CONF-02*")

    os.makedirs(os.path.dirname(sitrep_path), exist_ok=True)
    mode = "a" if os.path.exists(sitrep_path) else "w"
    with open(sitrep_path, mode, encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-CONF-02 Burp Intruder verdict classifier"
    )
    p.add_argument("--intruder",
        default=os.path.join("WSTG-CONF-02", "inputs", "xml", "intruder_conf02.xml"),
        metavar="PATH",
        help="Burp Intruder/proxy XML export")
    p.add_argument("--paths-json",
        default=os.path.join("WSTG-CONF-02", "inputs", "json", "conf_02_paths.json"),
        metavar="PATH",
        help="conf_02_paths.json for category attribution (optional)")
    p.add_argument("--sitrep",
        default=os.path.join("WSTG-CONF-02", "outputs", "test_outputs", "sitrep.md"),
        metavar="PATH")
    p.add_argument("--json-out",
        default=os.path.join("WSTG-CONF-02", "inputs", "json", "intruder_alerts.json"),
        metavar="PATH")
    p.add_argument("--min-bytes", type=int, default=500,
        metavar="N",
        help="Minimum body bytes to count a 403/500 as LOW (default: 500)")
    p.add_argument("--target", default="",
        metavar="URL",
        help="Base target URL for curl commands in sitrep (e.g. https://app.example.com)")
    args = p.parse_args()

    width = 65
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD}  WSTG-CONF-02 — Verdict{RESET}")
    print(f"{BOLD}{'='*width}{RESET}")
    print(f"  XML    : {args.intruder}")
    print(f"  Target : {args.target or '(not set)'}\n")

    items   = parse_burp_xml(args.intruder)
    cat_map = build_category_map(args.paths_json)

    if not cat_map:
        print(f"  {YELLOW}[!] No paths JSON found — all categories will be 'unknown'{RESET}")

    alerts = []
    skipped = 0

    for item in items:
        sev, reason = classify_response(item["status"], item["length"], args.min_bytes)
        if sev is None:
            skipped += 1
            continue

        category    = get_category(item["payload"], cat_map)
        signals     = body_signals(item["body"])

        # Body signals can upgrade severity
        if sev == "LOW" and signals:
            sev = "MEDIUM"

        alerts.append({
            "severity":     sev,
            "payload":      item["payload"],
            "url":          item["url"],
            "status":       item["status"],
            "length":       item["length"],
            "reason":       reason,
            "category":     category,
            "body_signals": signals,
        })

    # Sort: HIGH → MEDIUM → LOW, then by category, then by payload
    sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    alerts.sort(key=lambda x: (sev_order.get(x["severity"], 9), x["category"], x["payload"]))

    # ── Terminal summary ─────────────────────────────────────────────────────
    sev_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    cat_counts: dict = {}
    for a in alerts:
        sev_counts[a["severity"]] = sev_counts.get(a["severity"], 0) + 1
        cat_counts[a["category"]] = cat_counts.get(a["category"], 0) + 1

    print(f"  Processed : {len(items)} items")
    print(f"  Skipped   : {skipped}")
    print(f"  Alerts    : {len(alerts)}")
    print()

    for sev in ("HIGH", "MEDIUM", "LOW"):
        c = sev_counts.get(sev, 0)
        if c:
            color = SEV_COLOR.get(sev, RESET)
            print(f"  {color}{sev:<10}{RESET}  {c}")

    if cat_counts:
        print()
        print(f"  {'Category':<22} {'Alerts':>6}")
        print(f"  {'─'*30}")
        for cat in ("debug", "dotslash", "config", "default", "svc_repo", "backup_variants", "unknown"):
            c = cat_counts.get(cat, 0)
            if c:
                col = CAT_COLOR.get(cat, DIM)
                print(f"  {col}{cat:<22}{RESET} {c:>6}")

    # ── Print HIGH/MEDIUM details to terminal ────────────────────────────────
    notable = [a for a in alerts if a["severity"] in ("HIGH", "MEDIUM")]
    if notable:
        print(f"\n  {'─'*50}")
        for a in notable:
            col = SEV_COLOR.get(a["severity"], RESET)
            cat_col = CAT_COLOR.get(a["category"], DIM)
            print(f"  {col}{a['severity']:<8}{RESET}  "
                  f"{a['status']}  "
                  f"{cat_col}[{a['category']}]{RESET}  "
                  f"{a['payload']}")
            for sig in a["body_signals"]:
                print(f"           {YELLOW}↳ {sig}{RESET}")

    # ── Write outputs ────────────────────────────────────────────────────────
    append_sitrep(args.sitrep, alerts, args.target)
    print(f"\n{GREEN}[+] Sitrep     → {args.sitrep}{RESET}")

    os.makedirs(os.path.dirname(args.json_out), exist_ok=True)
    output = {
        "_meta": {
            "source_xml":   args.intruder,
            "generated":    datetime.now().isoformat(),
            "target":       args.target,
            "total_items":  len(items),
            "skipped":      skipped,
            "total_alerts": len(alerts),
            "severity_counts": sev_counts,
            "category_counts": cat_counts,
        },
        "alerts": alerts,
    }
    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    print(f"{GREEN}[+] Alerts     → {args.json_out}{RESET}\n")


if __name__ == "__main__":
    main()
