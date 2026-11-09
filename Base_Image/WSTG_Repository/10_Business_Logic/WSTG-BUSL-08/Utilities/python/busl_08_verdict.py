#!/usr/bin/env python3
"""
WSTG-BUSL-08 — Upload of Unexpected File Types
Script 2: busl_08_verdict.py

Reads a Burp Intruder XML export of upload-path probe results and
classifies each response into one of three alert categories:

  INDEXING      — payload was an indexing/traversal string AND response
                  was 200 or contained directory-listing indicators
                  (e.g. "Index of", "Parent Directory", autoindex)
  EXPOSED PATH  — a path with NO extension returned 200/302 (directory
                  or resource exists — unexpected)
  EXT 200/302   — a path WITH a file extension returned 200 or 302
                  (check immediately — file may be accessible / writable)

Status logic (identical threshold to other BUSL scripts):
  200                     → alert (HIGH for ext, MEDIUM for raw path)
  302 / 301               → alert (MEDIUM)
  403 / 500 ≥ min_bytes  → LOW (verbose error)
  404 / 403 < min_bytes  → SKIP

For each alert the operator is given:
  - The probed path
  - Status code + body size
  - Category
  - curl verification command

Appends findings to WSTG-BUSL-08/outputs/test_outputs/sitrep.md
(creating the file if questionnaire has not been run yet).

Inputs:
  WSTG-BUSL-08/inputs/xml/intruder_test.xml

Outputs:
  WSTG-BUSL-08/outputs/test_outputs/sitrep.md  (appended)
  WSTG-BUSL-08/inputs/json/intruder_alerts.json

Usage:
  python3 WSTG-BUSL-08/utilities/python/busl_08_verdict.py \\
      [--intruder WSTG-BUSL-08/inputs/xml/intruder_test.xml] \\
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
# Indexing indicators
# ---------------------------------------------------------------------------

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

# Executable / script extension set (BUSL-09 "malicious" category)
MALICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".bin", ".cmd", ".py", ".rb", ".pl", ".sh", ".bash",
    ".php", ".php3", ".php4", ".php5", ".phtml",
    ".asp", ".aspx", ".ashx", ".asmx",
    ".jsp", ".jspx", ".cgi", ".cfm", ".js", ".ts",
    ".htaccess", ".htpasswd",
}

# Unexpected (non-executable) extension set — BUSL-08 primary focus
UNEXPECTED_EXTENSIONS = {
    ".txt", ".csv", ".xml", ".html", ".htm", ".svg", ".pdf",
    ".zip", ".tar", ".tar.gz", ".gz", ".bz2", ".rar", ".7z",
    ".docx", ".xlsx", ".pptx", ".doc", ".xls",
    ".json", ".yaml", ".yml", ".log", ".md",
    ".mp4", ".mp3", ".avi", ".mov",
    ".jpeg", ".jpg", ".png", ".gif", ".bmp", ".ico", ".webp",
    ".ttf", ".woff", ".woff2",
}


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

        # Extract the probed path from the URL
        parsed_url = urlparse(url)
        path_str   = parsed_url.path or url

        # Extract payload (Intruder § markers preferred)
        payload = _extract_payload(req, path_str)

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
# Path classification helpers
# ---------------------------------------------------------------------------

def get_extension(path: str) -> str:
    """Returns the lowercase file extension including dot, or '' if none."""
    base = path.rstrip("/")
    # Handle double extensions like .tar.gz
    for dbl in (".tar.gz", ".tar.bz2"):
        if base.lower().endswith(dbl):
            return dbl
    _, ext = os.path.splitext(base)
    return ext.lower()


def is_indexing_payload(payload: str) -> bool:
    return payload.strip("/") in {s.strip("/") for s in INDEXING_STRINGS} or payload in INDEXING_STRINGS


def has_indexing_body(body: str) -> bool:
    return bool(INDEXING_BODY_PATTERNS.search(body))


def classify_path_type(payload: str, resp_body: str) -> str:
    """
    Returns one of: 'indexing', 'extension_malicious',
                    'extension_unexpected', 'raw_path'
    """
    if is_indexing_payload(payload) or has_indexing_body(resp_body):
        return "indexing"
    ext = get_extension(payload)
    if ext in MALICIOUS_EXTENSIONS:
        return "extension_malicious"
    if ext in UNEXPECTED_EXTENSIONS:
        return "extension_unexpected"
    return "raw_path"


# ---------------------------------------------------------------------------
# Alert classification
# ---------------------------------------------------------------------------

def classify_response(
    status: int,
    body_bytes: int,
    path_type: str,
    min_bytes: int,
) -> tuple:
    """Returns (severity | None, reason)."""
    if status == 404:
        return None, "404 — skip"
    if status in (403, 500):
        if body_bytes < min_bytes:
            return None, f"{status} <{min_bytes}B — bare error, skip"
        return "LOW", f"{status} verbose error ({body_bytes}B) — may leak info"
    if status == 200:
        if path_type == "indexing":
            return "HIGH",   "200 — possible directory listing / indexing"
        if path_type in ("extension_malicious", "extension_unexpected"):
            return "HIGH",   f"200 — file accessible: {path_type}"
        return "MEDIUM",     "200 — raw path exists, investigate"
    if status in (302, 301):
        return "MEDIUM",     f"{status} redirect — follow chain, check destination"
    if status == 202:
        return "MEDIUM",     "202 Accepted — possible queued upload"
    if 200 <= status < 400:
        return "LOW",        f"{status} — unexpected 2xx/3xx"
    return None, f"{status} — not interesting, skip"


# ---------------------------------------------------------------------------
# Curl verification command builder
# ---------------------------------------------------------------------------

def curl_cmd(url: str, method: str, payload: str) -> str:
    target = url
    # Replace payload marker if present
    if payload and payload in url:
        pass
    elif payload:
        parsed = urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}"
        target = base + payload
    flag = "-X PUT" if method == "PUT" else f"-X {method}" if method not in ("GET", "") else ""
    return f"curl -sv {flag} '{target}'"


# ---------------------------------------------------------------------------
# Sitrep append
# ---------------------------------------------------------------------------

def append_to_sitrep(alerts: list[dict], sitrep_path: str, source_xml: str, min_bytes: int):
    now_str  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sev_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in alerts:
        sev_counts[a["severity"]] += 1

    lines = []
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## WSTG-BUSL-08 Intruder Verdict")
    lines.append("")
    lines.append(f"**Verdict run:** {now_str}  ")
    lines.append(f"**Source XML:** `{source_xml}`  ")
    lines.append(f"**Alerts:** HIGH={sev_counts['HIGH']}  MEDIUM={sev_counts['MEDIUM']}  LOW={sev_counts['LOW']}  ")
    lines.append(f"**Min bytes threshold:** {min_bytes}  ")
    lines.append("")

    # ── Indexing alerts ──────────────────────────────────────────────────────
    indexing = [a for a in alerts if a["category"] == "indexing"]
    if indexing:
        lines.append("### ⚠️ Indexing Alerts")
        lines.append("")
        lines.append(
            "The following endpoints responded to indexing / traversal strings with "
            "a non-error status or a body matching directory listing patterns."
        )
        lines.append("")
        for a in indexing:
            lines.append(f"- **{a['severity']}** `{a['path']}` — HTTP {a['status']} ({a['body_bytes']}B)")
            lines.append(f"  - Payload: `{a['payload']}`")
            lines.append(f"  - {a['reason']}")
            lines.append(f"  - Verify: `{a['curl_cmd']}`")
        lines.append("")

    # ── Exposed path alerts ──────────────────────────────────────────────────
    exposed = [a for a in alerts if a["category"] == "raw_path"]
    if exposed:
        lines.append("### 📂 Exposed Path Alerts")
        lines.append("")
        lines.append(
            "The following paths (no file extension) returned 200 or redirect — "
            "directories or resources that should not be publicly accessible."
        )
        lines.append("")
        for a in exposed:
            lines.append(f"- **{a['severity']}** `{a['path']}` — HTTP {a['status']} ({a['body_bytes']}B)")
            lines.append(f"  - {a['reason']}")
            lines.append(f"  - Verify: `{a['curl_cmd']}`")
        lines.append("")

    # ── Extension alerts ─────────────────────────────────────────────────────
    ext_unexp = [a for a in alerts if a["category"] == "extension_unexpected"]
    ext_mal   = [a for a in alerts if a["category"] == "extension_malicious"]

    if ext_unexp or ext_mal:
        lines.append("### 📎 Extension Paths — 200 OK / 302 Redirect — Check Now")
        lines.append("")
        lines.append(
            "The following file-extension paths returned 200 or redirect.  \n"
            "**Verify manually with curl immediately** — a successful upload "
            "of a non-image / non-document type may indicate bypass."
        )
        lines.append("")
        for a in (ext_unexp + ext_mal):
            tag = "🔴 MALICIOUS EXT" if a["category"] == "extension_malicious" else "🟡 UNEXPECTED EXT"
            lines.append(f"- **{a['severity']}** {tag} `{a['path']}` — HTTP {a['status']} ({a['body_bytes']}B)")
            lines.append(f"  - {a['reason']}")
            lines.append(f"  - Verify: `{a['curl_cmd']}`")
        lines.append("")

    # ── LOW verbose errors ────────────────────────────────────────────────────
    low_errs = [a for a in alerts if a["severity"] == "LOW" and a["category"] not in ("indexing", "raw_path", "extension_unexpected", "extension_malicious")]
    if low_errs:
        lines.append("### ℹ️ Verbose Error Responses (LOW)")
        lines.append("")
        for a in low_errs:
            lines.append(f"- `{a['path']}` — HTTP {a['status']} ({a['body_bytes']}B)")
            lines.append(f"  - {a['reason']}")
        lines.append("")

    if not alerts:
        lines.append("*No alerts generated — all responses were 404 or bare errors.*")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by busl_08_verdict.py — WSTG-BUSL-08*")

    os.makedirs(os.path.dirname(sitrep_path), exist_ok=True)
    mode = "a" if os.path.isfile(sitrep_path) else "w"
    if mode == "w":
        # Create minimal header if questionnaire wasn't run
        header = (
            "# WSTG-BUSL-08 — Upload of Unexpected File Types — Sitrep\n\n"
            f"**Generated:** {now_str}  \n"
            "*(Questionnaire not run — create manually or run busl_08_questionnaire.py)*\n"
        )
        lines.insert(0, header)

    with open(sitrep_path, mode, encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-BUSL-08 Script 2: Intruder upload-path verdict"
    )
    p.add_argument("--intruder",
        default=os.path.join("WSTG-BUSL-08", "inputs", "xml", "intruder_test.xml"),
        metavar="PATH")
    p.add_argument("--target",
        default="",
        metavar="URL",
        help="Target base URL (e.g. https://app.example.com) for curl commands")
    p.add_argument("--sitrep",
        default=os.path.join("WSTG-BUSL-08", "outputs", "test_outputs", "sitrep.md"),
        metavar="PATH")
    p.add_argument("--json-out",
        default=os.path.join("WSTG-BUSL-08", "inputs", "json", "intruder_alerts.json"),
        metavar="PATH")
    p.add_argument("--min-bytes", type=int, default=500, metavar="N",
        help="Min body bytes for 403/500 to count as LOW (default: 500)")
    args = p.parse_args()

    width = 65
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD}  WSTG-BUSL-08 — Intruder Upload-Path Verdict{RESET}")
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

        path_type         = classify_path_type(payload, resp_body)
        severity, reason  = classify_response(status, body_len, path_type, args.min_bytes)

        if severity is None:
            skipped += 1
            print(f"  [{idx:3d}] {DIM}{status}  {reason[:55]}{RESET}")
            continue

        color = SEVERITY_COLOR.get(severity, RESET)

        # Category label for display
        cat_label = {
            "indexing":             f"{MAGENTA}INDEXING{RESET}",
            "raw_path":             f"{CYAN}EXPOSED PATH{RESET}",
            "extension_unexpected": f"{YELLOW}EXT UNEXPECTED{RESET}",
            "extension_malicious":  f"{RED}EXT MALICIOUS{RESET}",
        }.get(path_type, path_type)

        print(
            f"  [{idx:3d}] {color}{severity:<6}{RESET}  "
            f"HTTP {status}  {cat_label}  "
            f"{path[:40]}{'...' if len(path)>40 else ''}"
        )

        # Derive target URL for curl
        base_url = args.target
        if not base_url:
            parsed  = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

        alert = {
            "alert_index":  len(alerts),
            "endpoint_index": idx,
            "url":          url,
            "method":       method,
            "path":         path,
            "payload":      payload,
            "status_code":  status,
            "severity":     severity,
            "reason":       reason,
            "category":     path_type,
            "body_bytes":   body_len,
            "curl_cmd":     curl_cmd(base_url + payload if base_url else url, method, payload),
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

    # Append to sitrep
    append_to_sitrep(alerts, args.sitrep, args.intruder, args.min_bytes)
    print(f"\n{GREEN}[+] Sitrep appended → {args.sitrep}{RESET}")

    # Write alerts JSON
    os.makedirs(os.path.dirname(args.json_out), exist_ok=True)
    output = {
        "_meta": {
            "source_xml":    args.intruder,
            "generated":     datetime.now().isoformat(),
            "total_items":   len(items),
            "alerts":        len(alerts),
            "skipped":       skipped,
            "min_bytes":     args.min_bytes,
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
