#!/usr/bin/env python3
"""
WSTG-BUSL-09 — Upload of Malicious Files
Script 2: busl_09_verdict.py

Reads a Burp Intruder XML export of malicious file upload probe results.
Adapted from busl_08_verdict.py with one critical distinction:

  BUSL-08 — unexpected file types (non-executable: .txt, .pdf, .zip …)
  BUSL-09 — malicious file types  (executable/script: .exe, .bat, .bin,
             .py, .php, .asp, .jsp, .sh, .rb, .pl …)

Alert categories (BUSL-09 specific):

  RCE RISK     — server-side script extension (.php, .asp, .jsp, .py, .rb,
                 .pl, .sh, .cgi, .cfm) returned 200 or 302.
                 ⚠ Attempt to GET the upload URL and look for execution.
  EXEC RISK    — client-executable extension (.exe, .bat, .bin, .cmd)
                 returned 200.
                 File is downloadable — social-engineering / client-side risk.
  UNEXPECTED   — extension from the unexpected (non-executable) set returned
                 200/302 — BUSL-08 finding surfacing in BUSL-09 run.
  EXPOSED PATH — path with no extension returned 200/302.
  INDEXING     — indexing/traversal payload produced listing response.

Status logic (same thresholds as all other BUSL scripts):
  200                     → HIGH for RCE/EXEC, MEDIUM for raw/unexpected
  302 / 301               → MEDIUM
  403 / 500 ≥ min_bytes  → LOW (verbose error)
  404 / bare 403/500      → SKIP

Appends findings to WSTG-BUSL-09/outputs/test_outputs/sitrep.md.

Inputs:
  WSTG-BUSL-09/inputs/xml/intruder_test.xml

Outputs:
  WSTG-BUSL-09/outputs/test_outputs/sitrep.md  (appended)
  WSTG-BUSL-09/inputs/json/intruder_alerts.json

Usage:
  python3 WSTG-BUSL-09/utilities/python/busl_09_verdict.py \\
      [--intruder WSTG-BUSL-09/inputs/xml/intruder_test.xml] \\
      [--target   https://app.example.com] \\
      [--min-bytes 500]
"""

import argparse
import base64
import json
import os
import re
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
MAGENTA = "\033[95m"
RESET   = "\033[0m"

SEVERITY_COLOR = {
    "HIGH":   RED,
    "MEDIUM": YELLOW,
    "LOW":    CYAN,
}


# ---------------------------------------------------------------------------
# Extension sets
# ---------------------------------------------------------------------------

# Server-side script execution risk — RCE if file is served/executed
RCE_EXTENSIONS = {
    ".php", ".php3", ".php4", ".php5", ".phtml", ".phar",
    ".asp", ".aspx", ".ashx", ".asmx",
    ".jsp", ".jspx",
    ".py", ".rb", ".pl",
    ".sh", ".bash",
    ".cgi", ".cfm",
    ".htaccess",    # can configure execution handlers
}

# Client-side executable — no server execution, but social-engineering / delivery risk
EXEC_EXTENSIONS = {
    ".exe", ".bat", ".bin", ".cmd",
    ".msi", ".dll", ".vbs", ".ps1", ".psm1",
    ".jar", ".apk", ".ipa",
    ".scr", ".com", ".pif",
}

# Script that COULD be RCE depending on server config — lower confidence
SCRIPT_EXTENSIONS = {
    ".js", ".ts",       # unlikely but check if Node/Deno serves them
    ".htpasswd",        # config risk, not execution
}

# Unexpected (non-malicious) — BUSL-08 territory surfacing here
UNEXPECTED_EXTENSIONS = {
    ".txt", ".csv", ".xml", ".html", ".htm", ".svg", ".pdf",
    ".zip", ".tar", ".tar.gz", ".gz", ".bz2", ".rar", ".7z",
    ".docx", ".xlsx", ".pptx", ".doc", ".xls",
    ".json", ".yaml", ".yml", ".log", ".md",
    ".mp4", ".mp3", ".avi", ".mov",
    ".jpeg", ".jpg", ".png", ".gif", ".bmp", ".ico", ".webp",
    ".ttf", ".woff", ".woff2",
}

# All malicious for quick lookup
ALL_MALICIOUS = RCE_EXTENSIONS | EXEC_EXTENSIONS | SCRIPT_EXTENSIONS

# Indexing triggers
INDEXING_STRINGS = {
    "/", "/.", "/..", "/../", "./", "../", "*", "%2F", "%2F.", "%2F..",
    "%2F../", "%2F%2F", "%252F", "%00", "//", "///", "\\", "\\\\",
    "/?C=N;O=D", "/?C=M;O=A", "/?C=S;O=A", "/?C=D;O=A", "/~", "",
    "%00.jpg", "%00.png",
}
INDEXING_BODY_PATTERNS = re.compile(
    r'Index of|Parent Directory|Directory listing|mod_autoindex|'
    r'<title>\s*Index of|autoindex|DirectoryIndex|\[DIR\]|"sort by"',
    re.IGNORECASE
)


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


def _parse_status_from_response(resp: str) -> int:
    if not resp:
        return 0
    first_line = resp.split("\n", 1)[0].strip()
    m = re.match(r'HTTP/[\d.]+\s+(\d+)', first_line)
    return int(m.group(1)) if m else 0


def parse_intruder_xml(path: str) -> list[dict]:
    try:
        tree = ET.parse(path)
    except (ET.ParseError, FileNotFoundError) as e:
        print(f"{RED}[!] XML error: {e}{RESET}", file=sys.stderr)
        sys.exit(1)

    items = []
    for idx, item in enumerate(tree.getroot().findall("item")):
        url    = decode_element(item.find("url"))
        method = decode_element(item.find("method")).upper()
        req    = decode_element(item.find("request"))
        resp   = decode_element(item.find("response"))

        status_elem = item.find("status")
        if status_elem is not None and status_elem.text:
            try:
                status = int(status_elem.text.strip())
            except ValueError:
                status = _parse_status_from_response(resp)
        else:
            status = _parse_status_from_response(resp)

        resp_parts = resp.split("\r\n\r\n", 1) if resp else ["", ""]
        resp_body  = resp_parts[1] if len(resp_parts) > 1 else ""

        parsed_url = urlparse(url)
        path_str   = parsed_url.path or url
        payload    = _extract_payload(req, path_str)

        items.append({
            "index":     idx,
            "url":       url,
            "method":    method,
            "path":      path_str,
            "status":    status,
            "resp_body": resp_body,
            "payload":   payload,
        })
    return items


def _extract_payload(req: str, fallback_path: str) -> str:
    if "§" in req:
        m = re.search(r'§([^§]*)§', req)
        if m:
            return m.group(1)
    return fallback_path


# ---------------------------------------------------------------------------
# Path / extension classification
# ---------------------------------------------------------------------------

def get_extension(path: str) -> str:
    base = path.rstrip("/")
    for dbl in (".tar.gz", ".tar.bz2"):
        if base.lower().endswith(dbl):
            return dbl
    _, ext = os.path.splitext(base)
    return ext.lower()


def is_indexing_payload(payload: str) -> bool:
    return payload.strip("/") in {s.strip("/") for s in INDEXING_STRINGS} or payload in INDEXING_STRINGS


def has_indexing_body(body: str) -> bool:
    return bool(INDEXING_BODY_PATTERNS.search(body))


def classify_path_type(payload: str, resp_body: str) -> tuple[str, str]:
    """
    Returns (category, ext).
    Category: 'indexing', 'rce', 'exec', 'script', 'unexpected', 'raw_path'
    """
    if is_indexing_payload(payload) or has_indexing_body(resp_body):
        return "indexing", ""
    ext = get_extension(payload)
    if ext in RCE_EXTENSIONS:
        return "rce", ext
    if ext in EXEC_EXTENSIONS:
        return "exec", ext
    if ext in SCRIPT_EXTENSIONS:
        return "script", ext
    if ext in UNEXPECTED_EXTENSIONS:
        return "unexpected", ext
    return "raw_path", ext


# ---------------------------------------------------------------------------
# Alert classification
# ---------------------------------------------------------------------------

def classify_response(
    status:     int,
    body_bytes: int,
    category:   str,
    min_bytes:  int,
) -> tuple:
    if status == 404:
        return None, "404 — skip"
    if status in (403, 500):
        if body_bytes < min_bytes:
            return None, f"{status} <{min_bytes}B — bare error, skip"
        return "LOW", f"{status} verbose error ({body_bytes}B) — may leak info"
    if status == 200:
        if category in ("rce", "exec"):
            return "HIGH",   f"200 — {category.upper()} extension accepted"
        if category == "script":
            return "HIGH",   "200 — script extension accepted (check server config)"
        if category == "indexing":
            return "HIGH",   "200 — possible directory listing / indexing"
        if category == "unexpected":
            return "MEDIUM", "200 — unexpected (non-malicious) extension accepted"
        return "MEDIUM",     "200 — raw path exists, investigate"
    if status in (302, 301):
        if category in ("rce", "exec", "script"):
            return "HIGH",   f"{status} redirect on malicious extension — follow chain"
        return "MEDIUM",     f"{status} redirect — investigate"
    if status == 202:
        return "MEDIUM",     "202 Accepted — queued, may execute server-side"
    if 200 <= status < 400:
        return "LOW",        f"{status} unexpected 2xx/3xx"
    return None, f"{status} — skip"


# ---------------------------------------------------------------------------
# Curl + GET verification helpers
# ---------------------------------------------------------------------------

def curl_cmd(base_url: str, payload: str, method: str) -> str:
    target = (base_url.rstrip("/") + payload) if base_url else payload
    flag   = f"-X {method}" if method not in ("GET", "") else ""
    return f"curl -sv {flag} '{target}'"


def curl_get_verify(base_url: str, payload: str) -> str:
    target = (base_url.rstrip("/") + payload) if base_url else payload
    return f"curl -sv '{target}'"


# ---------------------------------------------------------------------------
# Sitrep append
# ---------------------------------------------------------------------------

def append_to_sitrep(alerts: list[dict], sitrep_path: str, source_xml: str, min_bytes: int):
    now_str    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sev_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in alerts:
        sev_counts[a["severity"]] += 1

    lines = []
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## WSTG-BUSL-09 Intruder Verdict")
    lines.append("")
    lines.append(f"**Verdict run:** {now_str}  ")
    lines.append(f"**Source XML:** `{source_xml}`  ")
    lines.append(f"**Alerts:** HIGH={sev_counts['HIGH']}  MEDIUM={sev_counts['MEDIUM']}  LOW={sev_counts['LOW']}  ")
    lines.append(f"**Min bytes threshold:** {min_bytes}  ")
    lines.append("")

    # ── RCE Risk alerts ──────────────────────────────────────────────────────
    rce_alerts = [a for a in alerts if a["category"] in ("rce", "script") and a["severity"] == "HIGH"]
    if rce_alerts:
        lines.append("### 🔴 RCE Risk — Server-Side Script Extensions Accepted")
        lines.append("")
        lines.append(
            "The following server-side script extensions were accepted (200/302).  \n"
            "**Attempt to GET the upload URL** — if the server executes the file, this is a critical RCE."
        )
        lines.append("")
        for a in rce_alerts:
            lines.append(f"- **{a['severity']}** `{a['payload']}` ({a['extension']}) — HTTP {a['status_code']} ({a['body_bytes']}B)")
            lines.append(f"  - Upload verify: `{a['curl_cmd']}`")
            lines.append(f"  - GET verify:    `{a['curl_get']}`")
            lines.append(f"  - {a['reason']}")
        lines.append("")

    # ── Exec Risk alerts ─────────────────────────────────────────────────────
    exec_alerts = [a for a in alerts if a["category"] == "exec" and a["severity"] == "HIGH"]
    if exec_alerts:
        lines.append("### 🟠 Executable File Risk — Client-Executable Extensions Accepted")
        lines.append("")
        lines.append(
            "The following client-executable extensions were accepted (200/302).  \n"
            "No server-side execution, but files are downloadable — social-engineering / malware delivery risk."
        )
        lines.append("")
        for a in exec_alerts:
            lines.append(f"- **{a['severity']}** `{a['payload']}` ({a['extension']}) — HTTP {a['status_code']} ({a['body_bytes']}B)")
            lines.append(f"  - Verify: `{a['curl_cmd']}`")
            lines.append(f"  - Check endpoint LOCATION: `{a['url']}`")
            lines.append(f"  - {a['reason']}")
        lines.append("")

    # ── Redirect on malicious extension ──────────────────────────────────────
    redir_mal = [a for a in alerts if a["category"] in ("rce", "exec", "script") and a["status_code"] in (301, 302)]
    if redir_mal:
        lines.append("### 🟡 Redirect on Malicious Extension — Follow Chain")
        lines.append("")
        for a in redir_mal:
            lines.append(f"- **{a['severity']}** `{a['payload']}` ({a['extension']}) — HTTP {a['status_code']}")
            lines.append(f"  - Verify (follow redirects): `{a['curl_cmd'].replace('-sv', '-svL')}`")
        lines.append("")

    # ── Indexing alerts ──────────────────────────────────────────────────────
    indexing = [a for a in alerts if a["category"] == "indexing"]
    if indexing:
        lines.append("### ⚠️ Indexing Alerts")
        lines.append("")
        for a in indexing:
            lines.append(f"- **{a['severity']}** `{a['payload']}` — HTTP {a['status_code']} ({a['body_bytes']}B)")
            lines.append(f"  - Verify: `{a['curl_cmd']}`")
        lines.append("")

    # ── Exposed paths ────────────────────────────────────────────────────────
    exposed = [a for a in alerts if a["category"] == "raw_path"]
    if exposed:
        lines.append("### 📂 Exposed Paths")
        lines.append("")
        for a in exposed:
            lines.append(f"- **{a['severity']}** `{a['path']}` — HTTP {a['status_code']} ({a['body_bytes']}B)")
            lines.append(f"  - Verify: `{a['curl_cmd']}`")
        lines.append("")

    # ── BUSL-08 cross-surface findings ────────────────────────────────────────
    unexpected = [a for a in alerts if a["category"] == "unexpected"]
    if unexpected:
        lines.append("### ℹ️ Unexpected (Non-Malicious) Extensions — BUSL-08 Overlap")
        lines.append("")
        for a in unexpected:
            lines.append(f"- **{a['severity']}** `{a['payload']}` ({a['extension']}) — HTTP {a['status_code']}")
        lines.append("")

    # ── LOW verbose errors ────────────────────────────────────────────────────
    low_errs = [a for a in alerts if a["severity"] == "LOW"]
    if low_errs:
        lines.append("### ℹ️ Verbose Error Responses (LOW)")
        lines.append("")
        for a in low_errs:
            lines.append(f"- `{a['path']}` — HTTP {a['status_code']} ({a['body_bytes']}B)  {a['reason']}")
        lines.append("")

    if not alerts:
        lines.append("*No alerts generated — all responses were 404 or bare errors.*")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by busl_09_verdict.py — WSTG-BUSL-09*")

    os.makedirs(os.path.dirname(sitrep_path), exist_ok=True)
    mode = "a" if os.path.isfile(sitrep_path) else "w"
    if mode == "w":
        header = (
            "# WSTG-BUSL-09 — Upload of Malicious Files — Sitrep\n\n"
            f"**Generated:** {now_str}  \n"
            "*(Questionnaire not run — run busl_09_questionnaire.py for full pre-test context)*\n"
        )
        lines.insert(0, header)

    with open(sitrep_path, mode, encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-BUSL-09 Script 2: Malicious upload intruder verdict"
    )
    p.add_argument("--intruder",
        default=os.path.join("WSTG-BUSL-09", "inputs", "xml", "intruder_test.xml"),
        metavar="PATH")
    p.add_argument("--target",
        default="",
        metavar="URL",
        help="Target base URL for curl commands (e.g. https://app.example.com)")
    p.add_argument("--sitrep",
        default=os.path.join("WSTG-BUSL-09", "outputs", "test_outputs", "sitrep.md"),
        metavar="PATH")
    p.add_argument("--json-out",
        default=os.path.join("WSTG-BUSL-09", "inputs", "json", "intruder_alerts.json"),
        metavar="PATH")
    p.add_argument("--min-bytes", type=int, default=500, metavar="N",
        help="Min body bytes for 403/500 LOW threshold (default: 500)")
    args = p.parse_args()

    width = 65
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD}  WSTG-BUSL-09 — Malicious Upload Verdict{RESET}")
    print(f"{BOLD}{'='*width}{RESET}")
    print(f"  Intruder XML : {args.intruder}")
    print(f"  Min bytes    : {args.min_bytes}\n")

    items = parse_intruder_xml(args.intruder)
    print(f"  Parsed {len(items)} result(s)\n")

    alerts  = []
    skipped = 0

    for item in items:
        idx       = item["index"]
        url       = item["url"]
        status    = item["status"]
        payload   = item["payload"]
        resp_body = item["resp_body"]
        method    = item["method"]
        path      = item["path"]
        body_len  = len(resp_body.encode("utf-8", errors="replace"))

        category, ext            = classify_path_type(payload, resp_body)
        severity, reason         = classify_response(status, body_len, category, args.min_bytes)

        if severity is None:
            skipped += 1
            print(f"  [{idx:3d}] {DIM}{status}  {reason[:55]}{RESET}")
            continue

        # Display label
        cat_color = {
            "rce":        RED,
            "exec":       MAGENTA,
            "script":     YELLOW,
            "unexpected": CYAN,
            "indexing":   MAGENTA,
            "raw_path":   CYAN,
        }.get(category, DIM)
        sev_color = SEVERITY_COLOR.get(severity, RESET)

        print(
            f"  [{idx:3d}] {sev_color}{severity:<6}{RESET}  "
            f"HTTP {status}  {cat_color}{category.upper():<12}{RESET}  "
            f"{ext:<8}  {path[:35]}{'...' if len(path)>35 else ''}"
        )

        # Derive base URL for curl
        base_url = args.target
        if not base_url:
            parsed   = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

        alert = {
            "alert_index":    len(alerts),
            "endpoint_index": idx,
            "url":            url,
            "method":         method,
            "path":           path,
            "payload":        payload,
            "extension":      ext,
            "status_code":    status,
            "severity":       severity,
            "reason":         reason,
            "category":       category,
            "body_bytes":     body_len,
            "curl_cmd":       curl_cmd(base_url, payload, method),
            "curl_get":       curl_get_verify(base_url, payload),
        }
        alerts.append(alert)

    # Summary
    sev_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    cat_counts: dict = {}
    for a in alerts:
        sev_counts[a["severity"]] += 1
        cat_counts[a["category"]] = cat_counts.get(a["category"], 0) + 1

    print(f"\n  {'─'*50}")
    print(f"  Total:   {len(items)}")
    print(f"  Alerts:  {len(alerts)}  (HIGH={sev_counts['HIGH']}  MEDIUM={sev_counts['MEDIUM']}  LOW={sev_counts['LOW']})")
    print(f"  Skipped: {skipped}")
    if cat_counts:
        for cat, cnt in sorted(cat_counts.items()):
            print(f"    {cat:<24} {cnt}")

    append_to_sitrep(alerts, args.sitrep, args.intruder, args.min_bytes)
    print(f"\n{GREEN}[+] Sitrep appended → {args.sitrep}{RESET}")

    os.makedirs(os.path.dirname(args.json_out), exist_ok=True)
    output = {
        "_meta": {
            "source_xml":      args.intruder,
            "generated":       datetime.now().isoformat(),
            "total_items":     len(items),
            "alerts":          len(alerts),
            "skipped":         skipped,
            "min_bytes":       args.min_bytes,
            "severity_counts": sev_counts,
            "category_counts": cat_counts,
        },
        "alerts": alerts,
        "findings_metadata": {
            "by_category": {
                cat: [a for a in alerts if a["category"] == cat]
                for cat in cat_counts
            }
        },
    }
    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"{GREEN}[+] Alerts JSON    → {args.json_out}{RESET}\n")


if __name__ == "__main__":
    main()
