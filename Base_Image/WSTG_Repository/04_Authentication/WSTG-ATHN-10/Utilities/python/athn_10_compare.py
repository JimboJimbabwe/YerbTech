#!/usr/bin/env python3
"""
WSTG-ATHN-10 — Testing for Weaker Authentication in Alternative Channel
Script: athn_10_compare.py

Reads a folder of Burp proxy/spider XML exports — one per walk condition —
and a baseline XML.  For every walk file it computes:

  LACKS    — endpoints in baseline that are ABSENT from this walk
  EXCLUSIVE — endpoints ONLY in this walk (not in baseline)

The EXCLUSIVE list is the primary finding: an endpoint reachable only under
a weakened condition (no cookies, mobile UA, no TLS, etc.) is a potential
weaker-authentication channel.

A second pass flags EXCLUSIVE endpoints using indicator-of-compromise (IoC)
heuristics:
  • Authentication bypass keywords in path (login, auth, token, session, …)
  • Sensitive resource keywords (admin, config, backup, internal, api, …)
  • Unauthenticated parameter exposure (password, secret, key, token in params)
  • HTTP (not HTTPS) endpoints when walk = weak_tls or no_tls
  • Methods other than GET (POST/PUT/DELETE on exclusive paths)

Walk categories are derived from the XML filename.  Supported names:

  baseline.xml
  no_cookies.xml
  no_javascript.xml
  no_java_plugins.xml
  no_tls.xml
  weak_tls.xml
  ua_iphone.xml
  ua_mobile.xml
  ua_android.xml
  ua_blackberry.xml

Any other filename is accepted as a custom walk label.

Usage:
  python3 WSTG-ATHN-10/utilities/python/athn_10_compare.py \\
      --walks-dir  WSTG-ATHN-10/inputs/xml/ \\
      --baseline   baseline.xml \\
      [--min-ioc   LOW]

Outputs:
  WSTG-ATHN-10/outputs/test_outputs/athn10_findings.json
  WSTG-ATHN-10/outputs/test_outputs/athn10_report.md
"""

import argparse
import base64
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote


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
WIDTH   = 70


# ---------------------------------------------------------------------------
# Walk-category labels
# ---------------------------------------------------------------------------
WALK_LABELS = {
    "baseline":        "Baseline (full browser)",
    "no_cookies":      "No cookies",
    "no_javascript":   "No JavaScript",
    "no_java_plugins": "No Java plugins",
    "no_tls":          "No TLS (plain HTTP)",
    "weak_tls":        "Weak TLS (TLS 1.0/1.1 / RC4 / export ciphers)",
    "ua_iphone":       "User-Agent: iPhone",
    "ua_mobile":       "User-Agent: Generic mobile",
    "ua_android":      "User-Agent: Android",
    "ua_blackberry":   "User-Agent: BlackBerry",
}

UA_WALKS = {"ua_iphone", "ua_mobile", "ua_android", "ua_blackberry"}
TLS_WALKS = {"no_tls", "weak_tls"}


def label(walk_key: str) -> str:
    return WALK_LABELS.get(walk_key, walk_key.replace("_", " ").title())


# ---------------------------------------------------------------------------
# XML helpers
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


def split_headers_body(raw: str) -> tuple[str, str]:
    for sep, width in (("\r\n\r\n", 4), ("\n\n", 2)):
        idx = raw.find(sep)
        if idx != -1:
            return raw[:idx], raw[idx + width:]
    return raw, ""


def parse_request_line(raw: str) -> tuple[str, str]:
    """Return (method, raw_path_with_query) from first line of raw request."""
    first = raw.splitlines()[0] if raw else ""
    parts = first.split()
    if len(parts) >= 2:
        return parts[0].upper(), parts[1]
    return "GET", "/"


def parse_url_params(url_str: str) -> list[tuple[str, str]]:
    try:
        q = urlparse(url_str).query
        return [(k, v[0]) for k, v in parse_qs(q, keep_blank_values=False).items() if v]
    except Exception:
        return []


def parse_body_params(body: str) -> list[tuple[str, str]]:
    if not body or "=" not in body:
        return []
    try:
        return [(k, v[0]) for k, v in parse_qs(body.strip(), keep_blank_values=False).items() if v]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Endpoint representation
# ---------------------------------------------------------------------------

class Endpoint:
    """
    Normalised representation of one HTTP transaction.
    Identity key = (method, path_no_query) — ignores param values so that
    the same path with different values counts once.
    """
    __slots__ = ("method", "path", "url", "params", "status", "response_snippet")

    def __init__(self, method, path, url, params, status, response_snippet=""):
        self.method           = method
        self.path             = path
        self.url              = url
        self.params           = params          # list of (name, value)
        self.status           = status
        self.response_snippet = response_snippet

    @property
    def key(self) -> str:
        return f"{self.method}:{self.path}"

    def to_dict(self) -> dict:
        return {
            "method":           self.method,
            "path":             self.path,
            "url":              self.url,
            "params":           [{"name": k, "value": v} for k, v in self.params],
            "status":           self.status,
            "response_snippet": self.response_snippet,
        }


def load_xml(xml_path: str) -> list[Endpoint]:
    try:
        tree = ET.parse(xml_path)
    except FileNotFoundError:
        print(f"  {RED}[!] XML not found: {xml_path}{RESET}", file=sys.stderr)
        return []
    except ET.ParseError as e:
        print(f"  {RED}[!] XML parse error in {xml_path}: {e}{RESET}", file=sys.stderr)
        return []

    root  = tree.getroot()
    items = root.findall("item") if root.tag == "items" else root.findall(".//item")

    endpoints = []
    seen_keys: set[str] = set()

    for item in items:
        url          = decode_element(item.find("url"))
        req_raw      = decode_element(item.find("request"))
        resp_raw     = decode_element(item.find("response"))
        status_el    = item.find("status")
        status       = int(status_el.text or 0) if status_el is not None and status_el.text else 0

        method, raw_path = parse_request_line(req_raw)
        parsed_url       = urlparse(url)
        path             = parsed_url.path or raw_path.split("?")[0]

        # Normalise path: strip trailing slash (except root)
        if len(path) > 1:
            path = path.rstrip("/")

        key = f"{method}:{path}"
        if key in seen_keys:
            continue
        seen_keys.add(key)

        _, req_body   = split_headers_body(req_raw)
        _, resp_body  = split_headers_body(resp_raw)
        params        = parse_url_params(url) + parse_body_params(req_body)
        snippet       = resp_body[:200].replace("\n", " ").strip()

        endpoints.append(Endpoint(method, path, url, params, status, snippet))

    return endpoints


def endpoints_by_key(eps: list[Endpoint]) -> dict[str, Endpoint]:
    return {ep.key: ep for ep in eps}


# ---------------------------------------------------------------------------
# IoC heuristics
# ---------------------------------------------------------------------------

_AUTH_BYPASS_PATHS = re.compile(
    r'(?:login|logout|signin|signout|authenticate?|auth|session|token|'
    r'oauth|sso|saml|jwt|password|passwd|reset|forgot|recover|verify|'
    r'activate|register|signup|enroll)',
    re.IGNORECASE,
)

_SENSITIVE_PATHS = re.compile(
    r'(?:admin|administrator|manage|management|config|configuration|'
    r'backup|dump|export|import|internal|private|secret|debug|test|'
    r'staging|dev|development|console|dashboard|panel|api|graphql|'
    r'swagger|openapi|actuator|metrics|health|info|env|properties)',
    re.IGNORECASE,
)

_SENSITIVE_PARAMS = re.compile(
    r'(?:password|passwd|pass|secret|token|apikey|api_key|access_key|'
    r'auth|session|sid|jwt|credential|private)',
    re.IGNORECASE,
)

_NON_GET_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def ioc_check(ep: Endpoint, walk_key: str) -> list[dict]:
    """Return list of IoC dicts for a given endpoint in the given walk context."""
    iocs = []
    path_lower = ep.path.lower()

    if _AUTH_BYPASS_PATHS.search(ep.path):
        iocs.append({
            "severity": "HIGH",
            "type":     "Auth-related path reachable under weakened condition",
            "detail":   f"Path '{ep.path}' matches authentication keyword pattern",
        })

    if _SENSITIVE_PATHS.search(ep.path):
        iocs.append({
            "severity": "HIGH",
            "type":     "Sensitive/admin path reachable under weakened condition",
            "detail":   f"Path '{ep.path}' matches sensitive resource keyword pattern",
        })

    sensitive_param_names = [
        p["name"] if isinstance(p, dict) else p[0]
        for p in (ep.params if ep.params else [])
        if _SENSITIVE_PARAMS.search(p["name"] if isinstance(p, dict) else p[0])
    ]
    if sensitive_param_names:
        iocs.append({
            "severity": "HIGH",
            "type":     "Sensitive parameter exposed in request",
            "detail":   f"Parameter(s) matching sensitive keyword: {sensitive_param_names}",
        })

    if ep.method in _NON_GET_METHODS:
        iocs.append({
            "severity": "MEDIUM",
            "type":     f"{ep.method} method available on exclusive path",
            "detail":   f"State-changing method '{ep.method}' reachable only in this walk",
        })

    if walk_key in TLS_WALKS and ep.url.startswith("http://"):
        iocs.append({
            "severity": "HIGH",
            "type":     "Unencrypted HTTP endpoint",
            "detail":   f"Endpoint served over plain HTTP in '{label(walk_key)}' walk",
        })

    if walk_key in UA_WALKS:
        # Mobile UA giving exclusive access suggests a mobile-specific channel
        iocs.append({
            "severity": "MEDIUM",
            "type":     "Path only reachable via mobile User-Agent",
            "detail":   f"Endpoint appears exclusively on '{label(walk_key)}' walk — "
                        f"possible mobile-specific code path with weaker auth",
        })

    return iocs


SEV_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def max_severity(iocs: list[dict]) -> str:
    if not iocs:
        return "LOW"
    return min(iocs, key=lambda i: SEV_RANK.get(i["severity"], 9))["severity"]


# ---------------------------------------------------------------------------
# Compare
# ---------------------------------------------------------------------------

def compare_walks(
    baseline_eps: dict[str, Endpoint],
    walk_eps:     dict[str, Endpoint],
    walk_key:     str,
) -> dict:
    baseline_keys = set(baseline_eps.keys())
    walk_keys     = set(walk_eps.keys())

    lacks_keys     = baseline_keys - walk_keys      # in baseline, absent from walk
    exclusive_keys = walk_keys - baseline_keys       # only in walk

    lacks = [baseline_eps[k].to_dict() for k in sorted(lacks_keys)]

    exclusive = []
    for k in sorted(exclusive_keys):
        ep   = walk_eps[k]
        iocs = ioc_check(ep, walk_key)
        entry = ep.to_dict()
        entry["iocs"]         = iocs
        entry["max_severity"] = max_severity(iocs)
        exclusive.append(entry)

    # Sort exclusive by severity then path
    sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "": 3}
    exclusive.sort(key=lambda e: (sev_order.get(e["max_severity"], 9), e["path"]))

    return {
        "walk_key":   walk_key,
        "walk_label": label(walk_key),
        "lacks":      lacks,
        "exclusive":  exclusive,
        "stats": {
            "baseline_count":  len(baseline_keys),
            "walk_count":      len(walk_keys),
            "lacks_count":     len(lacks),
            "exclusive_count": len(exclusive_keys),
            "ioc_high":   sum(1 for e in exclusive if e["max_severity"] == "HIGH"),
            "ioc_medium": sum(1 for e in exclusive if e["max_severity"] == "MEDIUM"),
            "ioc_none":   sum(1 for e in exclusive if not e["iocs"]),
        },
    }


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

def write_markdown(results: list[dict], meta: dict, path: str) -> None:
    md = []
    md.append("# WSTG-ATHN-10 — Weaker Authentication in Alternative Channel")
    md.append("")
    md.append(f"**Generated:** {meta['generated']}  ")
    md.append(f"**Baseline:** `{meta['baseline_file']}`  ")
    md.append(f"**Walks compared:** {meta['walk_count']}  ")
    md.append("")
    md.append(
        "An **EXCLUSIVE** endpoint is one found *only* under a weakened condition "
        "(no cookies, mobile UA, no TLS, etc.) and absent from the baseline walk. "
        "These are the primary ATHN-10 candidates."
    )
    md.append("")
    md.append("---")
    md.append("")

    # Summary table
    md.append("## Summary")
    md.append("")
    md.append("| Walk | Baseline paths | Walk paths | Lacks | Exclusive | HIGH IoC | MEDIUM IoC |")
    md.append("|------|---------------|------------|-------|-----------|----------|------------|")
    for r in results:
        s = r["stats"]
        h = f"**{s['ioc_high']}**" if s["ioc_high"] else str(s["ioc_high"])
        m_str = str(s["ioc_medium"])
        md.append(
            f"| {r['walk_label']} "
            f"| {s['baseline_count']} "
            f"| {s['walk_count']} "
            f"| {s['lacks_count']} "
            f"| {s['exclusive_count']} "
            f"| {h} "
            f"| {m_str} |"
        )
    md.append("")
    md.append("---")
    md.append("")

    # Per-walk detail
    for r in results:
        md.append(f"## Walk: {r['walk_label']}")
        md.append("")

        excl = r["exclusive"]
        lacks = r["lacks"]

        # --- Exclusive ---
        md.append(f"### Exclusive Endpoints ({len(excl)})")
        md.append("")
        md.append(
            "These paths were **not** present in the baseline walk — "
            "they are only reachable under this weakened condition."
        )
        md.append("")

        if not excl:
            md.append("*None.*")
            md.append("")
        else:
            high   = [e for e in excl if e["max_severity"] == "HIGH"]
            medium = [e for e in excl if e["max_severity"] == "MEDIUM"]
            low    = [e for e in excl if e["max_severity"] not in ("HIGH", "MEDIUM") or not e["iocs"]]

            for group_label, group in [("⚠ HIGH", high), ("MEDIUM", medium), ("LOW / No IoC", low)]:
                if not group:
                    continue
                md.append(f"#### {group_label}")
                md.append("")
                for ep in group:
                    md.append(f"- **`{ep['method']} {ep['path']}`**  (HTTP {ep['status']})")
                    md.append(f"  URL: `{ep['url']}`")
                    if ep["params"]:
                        param_str = ", ".join(
                            f"`{p['name']}={p['value']}`" for p in ep["params"][:5]
                        )
                        md.append(f"  Parameters: {param_str}")
                    if ep["iocs"]:
                        for ioc in ep["iocs"]:
                            md.append(f"  - **[{ioc['severity']}]** {ioc['type']}: {ioc['detail']}")
                    md.append("")

        # --- Lacks ---
        md.append(f"### Lacks (Baseline Endpoints Absent from This Walk) ({len(lacks)})")
        md.append("")
        if not lacks:
            md.append("*This walk reached all baseline endpoints.*")
            md.append("")
        else:
            md.append(
                "These paths were found in the baseline but are **absent** in this walk. "
                "They may be hidden or protected when the walk condition is applied, "
                "or the walk simply did not traverse them."
            )
            md.append("")
            md.append("| Method | Path | Baseline Status |")
            md.append("|--------|------|-----------------|")
            for ep in lacks[:50]:
                md.append(f"| `{ep['method']}` | `{ep['path']}` | {ep['status']} |")
            if len(lacks) > 50:
                md.append(f"| … | *{len(lacks) - 50} more — see JSON* | — |")
            md.append("")

        md.append("---")
        md.append("")

    md.append("## Investigation Guidance")
    md.append("")
    md.append(
        "For every **EXCLUSIVE** endpoint with a HIGH or MEDIUM IoC rating:"
    )
    md.append("")
    md.append("1. Open Burp Suite > Proxy > HTTP History")
    md.append("2. Locate the request in the relevant walk XML")
    md.append("3. Send to Repeater")
    md.append("4. Replay the request using your standard (baseline) session — "
              "does the server accept it?")
    md.append("5. If accepted: confirm whether authentication is weaker or absent "
              "compared to the baseline path")
    md.append("6. Document the delta in your report as a WSTG-ATHN-10 finding")
    md.append("")
    md.append("**Priority order:** Auth-related paths > Admin/sensitive paths > "
              "Sensitive parameters > Non-GET methods > Mobile-UA-only paths")
    md.append("")
    md.append("---")
    md.append("*Generated by athn_10_compare.py — WSTG-ATHN-10*")

    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")


# ---------------------------------------------------------------------------
# Terminal printer
# ---------------------------------------------------------------------------

def print_summary(results: list[dict]) -> None:
    print(f"\n  {'Walk':<35} {'Lacks':>6} {'Excl':>6} {'HIGH':>6} {'MED':>6}")
    print(f"  {'─'*60}")
    for r in results:
        s   = r["stats"]
        h   = f"{RED}{s['ioc_high']}{RESET}"   if s["ioc_high"]   else str(s["ioc_high"])
        m   = f"{YELLOW}{s['ioc_medium']}{RESET}" if s["ioc_medium"] else str(s["ioc_medium"])
        print(f"  {r['walk_label']:<35} {s['lacks_count']:>6} {s['exclusive_count']:>6} "
              f"  {h:>6}   {m:>6}")
    print()

    # Print HIGH IoC findings inline
    high_findings = []
    for r in results:
        for ep in r["exclusive"]:
            if ep["max_severity"] == "HIGH":
                high_findings.append((r["walk_label"], ep))

    if high_findings:
        print(f"  {RED}{BOLD}HIGH IoC Exclusive Endpoints:{RESET}")
        print(f"  {'─'*60}")
        for wl, ep in high_findings[:30]:
            print(f"  {RED}[HIGH]{RESET}  {wl[:25]:<25}  {ep['method']:<6}  {ep['path'][:40]}")
        if len(high_findings) > 30:
            print(f"  {DIM}  … {len(high_findings)-30} more in output files{RESET}")
        print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-ATHN-10 alternative-channel walk comparator"
    )
    p.add_argument("--walks-dir",
        default=os.path.join("WSTG-ATHN-10", "inputs", "xml"),
        metavar="DIR",
        help="Folder containing all walk XML files including baseline.xml")
    p.add_argument("--baseline",
        default="baseline.xml",
        metavar="FILE",
        help="Filename of the baseline XML within --walks-dir (default: baseline.xml)")
    p.add_argument("--json-out",
        default=os.path.join(
            "WSTG-ATHN-10", "outputs", "test_outputs", "athn10_findings.json"),
        metavar="PATH")
    p.add_argument("--md-out",
        default=os.path.join(
            "WSTG-ATHN-10", "outputs", "test_outputs", "athn10_report.md"),
        metavar="PATH")
    args = p.parse_args()

    print(f"\n{BOLD}{'='*WIDTH}{RESET}")
    print(f"{BOLD}  WSTG-ATHN-10 — Weaker Authentication in Alternative Channel{RESET}")
    print(f"{BOLD}{'='*WIDTH}{RESET}\n")
    print(f"  Walks directory : {args.walks_dir}")
    print(f"  Baseline file   : {args.baseline}\n")

    # ── Find XMLs ────────────────────────────────────────────────────────────
    if not os.path.isdir(args.walks_dir):
        print(f"  {RED}[!] Directory not found: {args.walks_dir}{RESET}", file=sys.stderr)
        sys.exit(1)

    all_xml = sorted(
        f for f in os.listdir(args.walks_dir) if f.lower().endswith(".xml")
    )
    if not all_xml:
        print(f"  {RED}[!] No XML files found in {args.walks_dir}{RESET}", file=sys.stderr)
        sys.exit(1)

    baseline_filename = args.baseline
    if baseline_filename not in all_xml:
        # Case-insensitive fallback
        matches = [f for f in all_xml if f.lower() == baseline_filename.lower()]
        if matches:
            baseline_filename = matches[0]
        else:
            print(f"  {RED}[!] Baseline '{args.baseline}' not found in {args.walks_dir}{RESET}",
                  file=sys.stderr)
            print(f"  {YELLOW}    Available: {', '.join(all_xml)}{RESET}", file=sys.stderr)
            sys.exit(1)

    walk_files = [f for f in all_xml if f != baseline_filename]

    print(f"  Baseline        : {baseline_filename}")
    print(f"  Walk files      : {len(walk_files)}")
    for wf in walk_files:
        print(f"    • {wf}")
    print()

    # ── Load baseline ────────────────────────────────────────────────────────
    baseline_path = os.path.join(args.walks_dir, baseline_filename)
    print(f"  Loading baseline...", end=" ", flush=True)
    baseline_list = load_xml(baseline_path)
    baseline_eps  = endpoints_by_key(baseline_list)
    print(f"{len(baseline_eps)} unique endpoints")

    # ── Load + compare each walk ─────────────────────────────────────────────
    results = []
    for wf in walk_files:
        walk_key  = os.path.splitext(wf)[0].lower()
        walk_path = os.path.join(args.walks_dir, wf)
        print(f"  Comparing {wf:<30}", end=" ", flush=True)
        walk_list = load_xml(walk_path)
        walk_eps  = endpoints_by_key(walk_list)
        result    = compare_walks(baseline_eps, walk_eps, walk_key)
        results.append(result)
        s = result["stats"]
        print(f"→ lacks {s['lacks_count']:3d}  exclusive {s['exclusive_count']:3d}"
              f"  HIGH ioc {s['ioc_high']:2d}")

    # ── Print summary ────────────────────────────────────────────────────────
    print()
    print_summary(results)

    # ── Write JSON ───────────────────────────────────────────────────────────
    meta = {
        "generated":     datetime.now().isoformat(),
        "walks_dir":     args.walks_dir,
        "baseline_file": baseline_filename,
        "walk_count":    len(walk_files),
        "walk_files":    walk_files,
    }
    out_json = {"_meta": meta, "results": results}
    os.makedirs(os.path.dirname(args.json_out) if os.path.dirname(args.json_out) else ".",
                exist_ok=True)
    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(out_json, f, indent=2)

    # ── Write Markdown ───────────────────────────────────────────────────────
    write_markdown(results, meta, args.md_out)

    print(f"  {GREEN}[+] Findings JSON  → {args.json_out}{RESET}")
    print(f"  {GREEN}[+] Report MD      → {args.md_out}{RESET}\n")


if __name__ == "__main__":
    main()
