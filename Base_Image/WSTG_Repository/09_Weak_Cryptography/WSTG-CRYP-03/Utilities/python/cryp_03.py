#!/usr/bin/env python3
"""
WSTG-CRYP-03 — Sensitive Information Sent via Unencrypted Channels
===================================================================
Curl-based tester.  Accepts a single domain, a domain list file,
or reads endpoints from a Burp Suite proxy history XML export.

Test Cases
----------
TC-01  Does the host respond on plain HTTP (2xx)?
TC-02  Does plain HTTP redirect to HTTPS on the login path?
TC-03  Is Strict-Transport-Security present and sane (max-age ≥ 1 yr)?
TC-04  Do login form actions post to an http:// URL?
TC-AUX Are any Set-Cookie headers missing the Secure flag?

Output
------
Writes JSON to Outputs/test_outputs/cryp03_out.json by default.

Usage
-----
    python cryp_03.py                          # reads Inputs/XML/cryp03.xml
    python cryp_03.py -d example.com
    python cryp_03.py -f hosts.txt
    python cryp_03.py -x /path/to/export.xml -o /path/to/out.json
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

# ── Directory layout (relative to this script) ────────────────────────────────
#   Place this file at:  WSTG-CRYP-03/Utilities/python/cryp_03.py
SCRIPT_DIR  = Path(__file__).resolve().parent       # …/Utilities/python/
TOOL_ROOT   = SCRIPT_DIR.parent.parent               # …/WSTG-CRYP-03/
DEFAULT_XML = TOOL_ROOT / "Inputs"  / "XML"  / "cryp03.xml"
DEFAULT_OUT = TOOL_ROOT / "Outputs" / "test_outputs" / "cryp03_out.json"

# Path fragments treated as login / auth endpoints when parsing Burp XML
LOGIN_KEYWORDS = ("login", "signin", "sign-in", "auth", "session", "account", "logon")

CURL_TIMEOUT = 10  # seconds per curl call


# ── Curl helpers ──────────────────────────────────────────────────────────────

def _run_curl(url: str, flags: list[str] | None = None) -> tuple[str, str, int]:
    """
    Execute ``curl -kis [flags] <url>`` and return (stdout, stderr, returncode).
    -k  ignore TLS cert errors
    -i  include response headers in output
    -s  silent (no progress bar)
    """
    cmd = ["curl", "-kis", "--max-time", str(CURL_TIMEOUT)]
    if flags:
        cmd.extend(flags)
    cmd.append(url)

    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=CURL_TIMEOUT + 5)
        return p.stdout, p.stderr, p.returncode
    except subprocess.TimeoutExpired:
        return "", "[timeout]", 1
    except FileNotFoundError:
        sys.exit("[!] curl not found on PATH — install curl and try again.")


def _status(raw: str) -> int | None:
    """Return the *last* HTTP status code in curl -i output (skips 100-Continue)."""
    hits = re.findall(r"HTTP/[\d.]+ (\d{3})", raw)
    return int(hits[-1]) if hits else None


def _header(raw: str, name: str) -> str | None:
    """Return the value of the first occurrence of *name* header, or None."""
    m = re.search(rf"(?im)^{re.escape(name)}:\s*(.+)$", raw)
    return m.group(1).strip() if m else None


def _headers_all(raw: str, name: str) -> list[str]:
    """Return values of every occurrence of *name* (e.g. multiple Set-Cookie)."""
    return [m.group(1).strip()
            for m in re.finditer(rf"(?im)^{re.escape(name)}:\s*(.+)$", raw)]


def _ts() -> str:
    """ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


# ── Test cases ────────────────────────────────────────────────────────────────

def tc01_http_response(host: str) -> dict:
    """
    TC-01 — Does the host respond on plain HTTP?
    Vulnerable when the server returns a 2xx (serves content without redirecting).
    A 3xx is caught separately by TC-02.
    """
    url = f"http://{host}/"
    cmd = f"curl -kis http://{host}/"
    ts  = _ts()

    stdout, _, _ = _run_curl(url)

    # head -20 equivalent — first 20 lines of the response
    excerpt = "\n".join(stdout.splitlines()[:20])
    code    = _status(stdout)

    vulnerable = code is not None and 200 <= code < 300

    return {
        "test_id":       "TC-01",
        "description":   "HTTP plain-text response (does HTTP serve content?)",
        "command":       cmd,
        "time_launched": ts,
        "status_code":   code,
        "vulnerable":    vulnerable,
        "raw_excerpt":   excerpt,
    }


def tc02_http_redirect(host: str, login_path: str) -> dict:
    """
    TC-02 — Does plain HTTP redirect to HTTPS on the login path?
    Vulnerable when there is no redirect, or the redirect stays on HTTP.
    """
    url = f"http://{host}{login_path}"
    cmd = f"curl -kis http://{host}{login_path}"
    ts  = _ts()

    stdout, _, _ = _run_curl(url)

    code     = _status(stdout)
    location = _header(stdout, "Location")

    to_https   = bool(location and location.lower().startswith("https://"))
    vulnerable = not to_https

    return {
        "test_id":           "TC-02",
        "description":       f"HTTP → HTTPS redirect on login path ({login_path})",
        "command":           cmd,
        "time_launched":     ts,
        "status_code":       code,
        "location":          location,
        "redirect_to_https": to_https,
        "vulnerable":        vulnerable,
    }


def tc03_hsts(host: str) -> dict:
    """
    TC-03 — Is Strict-Transport-Security present and sane?
    'Sane' = max-age is at least 31 536 000 seconds (one year).
    Adds key 'STS' (bool) per spec — False means vulnerable.
    """
    url = f"https://{host}/"
    cmd = f"curl -kis https://{host}/"
    ts  = _ts()

    stdout, _, _ = _run_curl(url)

    code      = _status(stdout)
    sts_value = _header(stdout, "Strict-Transport-Security")
    sts_present = sts_value is not None

    sts_sane = False
    if sts_present:
        m = re.search(r"max-age\s*=\s*(\d+)", sts_value, re.IGNORECASE)
        if m and int(m.group(1)) >= 31_536_000:
            sts_sane = True

    vulnerable = not sts_present or not sts_sane

    return {
        "test_id":       "TC-03",
        "description":   "HSTS header presence and sanity (max-age ≥ 1 year)",
        "command":       cmd,
        "time_launched": ts,
        "status_code":   code,
        "STS":           sts_present,   # per spec: False → vulnerable
        "sts_value":     sts_value,
        "sts_sane":      sts_sane,
        "vulnerable":    vulnerable,
    }


def tc04_form_action(host: str, login_path: str) -> dict:
    """
    TC-04 — Audit the login form's action attribute.
    Vulnerable when any <form> submits to an http:// URL.
    """
    url = f"https://{host}{login_path}"
    cmd = f"curl -kis https://{host}{login_path}"
    ts  = _ts()

    stdout, _, _ = _run_curl(url)

    code      = _status(stdout)
    form_tags = re.findall(r"<form[^>]*>", stdout, re.IGNORECASE)

    http_actions: list[str] = []
    for tag in form_tags:
        m = re.search(r'action=["\']([^"\']*)["\']', tag, re.IGNORECASE)
        if m and m.group(1).lower().startswith("http://"):
            http_actions.append(m.group(1))

    vulnerable = bool(http_actions)

    return {
        "test_id":           "TC-04",
        "description":       f"Login form action attribute ({login_path})",
        "command":           cmd,
        "time_launched":     ts,
        "status_code":       code,
        "forms_found":       form_tags,
        "http_form_actions": http_actions,
        "vulnerable":        vulnerable,
    }


def tc_aux_cookie_secure(host: str) -> dict:
    """
    TC-AUX — Set-Cookie headers anywhere without the Secure flag.
    Checks HTTPS root; extend to additional paths as needed.
    """
    url = f"https://{host}/"
    cmd = f"curl -kis https://{host}/"
    ts  = _ts()

    stdout, _, _ = _run_curl(url)

    code             = _status(stdout)
    all_cookies      = _headers_all(stdout, "Set-Cookie")
    insecure_cookies = [c for c in all_cookies if "secure" not in c.lower()]
    vulnerable       = bool(insecure_cookies)

    return {
        "test_id":          "TC-AUX",
        "description":      "Set-Cookie without Secure flag",
        "command":          cmd,
        "time_launched":    ts,
        "status_code":      code,
        "vulnerable":       vulnerable,
        "insecure_cookies": insecure_cookies,
    }


# ── Burp XML parsing ──────────────────────────────────────────────────────────

def _is_login_path(path: str) -> bool:
    return any(kw in path.lower() for kw in LOGIN_KEYWORDS)


def parse_burp_xml(xml_path: Path) -> dict[str, dict]:
    """
    Parse a Burp Suite proxy history XML export.

    Returns:
        {
          "example.com": {
              "all_paths":   ["/", "/login", "/api/session"],
              "login_paths": ["/login"],     # auto-detected; falls back to ["/login"]
          },
          …
        }
    """
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError as exc:
        sys.exit(f"[!] XML parse error in {xml_path}: {exc}")
    except FileNotFoundError:
        sys.exit(f"[!] XML file not found: {xml_path}")

    hosts: dict[str, dict] = {}

    for item in root.findall("item"):
        host_el = item.find("host")
        if host_el is None or not (host_el.text or "").strip():
            continue

        host = host_el.text.strip()
        path = (item.findtext("path") or "/").strip() or "/"

        if host not in hosts:
            hosts[host] = {"all_paths": set(), "login_paths": set()}

        hosts[host]["all_paths"].add(path)
        if _is_login_path(path):
            hosts[host]["login_paths"].add(path)

    if not hosts:
        sys.exit(
            "[!] No <item> entries parsed from the XML.\n"
            "    Is this a Burp Suite proxy history export?"
        )

    # Freeze sets → sorted lists; fall back to /login if none detected.
    for h in hosts:
        hosts[h]["all_paths"]   = sorted(hosts[h]["all_paths"])
        hosts[h]["login_paths"] = sorted(hosts[h]["login_paths"]) or ["/login"]

    print(f"[*] Parsed {len(hosts)} unique host(s) from XML.")
    return hosts


# ── Per-host scanner ──────────────────────────────────────────────────────────

def scan_host(host: str, login_path: str) -> dict:
    steps = [
        ("TC-01", tc01_http_response,   (host,)),
        ("TC-02", tc02_http_redirect,   (host, login_path)),
        ("TC-03", tc03_hsts,            (host,)),
        ("TC-04", tc04_form_action,     (host, login_path)),
        ("AUX  ", tc_aux_cookie_secure, (host,)),
    ]

    test_cases: list[dict] = []
    for label, fn, fn_args in steps:
        # First line of docstring as a short progress label
        brief = (fn.__doc__ or "").strip().splitlines()[0]
        print(f"    [{label}] {brief} …")
        test_cases.append(fn(*fn_args))

    return {
        "test_cases":        test_cases,
        "overall_vulnerable": any(tc["vulnerable"] for tc in test_cases),
    }


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="WSTG-CRYP-03 — curl-based unencrypted channel tester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Input priority:  -d/--domain  >  -f/--file  >  -x/--xml (default)\n"
            "                 XML defaults to Inputs/XML/cryp03.xml"
        ),
    )
    src = ap.add_mutually_exclusive_group()
    src.add_argument(
        "-d", "--domain", metavar="HOST",
        help="Single target hostname  (e.g. example.com)",
    )
    src.add_argument(
        "-f", "--file", metavar="FILE",
        help="Plain-text file with one hostname per line",
    )
    ap.add_argument(
        "-x", "--xml", metavar="FILE", default=str(DEFAULT_XML),
        help=f"Burp Suite XML export  [default: {DEFAULT_XML}]",
    )
    ap.add_argument(
        "-o", "--output", metavar="FILE", default=str(DEFAULT_OUT),
        help=f"JSON output path       [default: {DEFAULT_OUT}]",
    )

    args = ap.parse_args()
    hosts: dict[str, dict] = {}

    # ── Build target list ─────────────────────────────────────────────────
    if args.domain:
        h = args.domain.strip()
        hosts[h] = {"login_paths": ["/login"], "all_paths": ["/"]}

    elif args.file:
        fp = Path(args.file)
        if not fp.exists():
            sys.exit(f"[!] Domain list not found: {fp}")
        lines = [ln.strip() for ln in fp.read_text().splitlines() if ln.strip()]
        for ln in lines:
            hosts[ln] = {"login_paths": ["/login"], "all_paths": ["/"]}
        print(f"[*] Loaded {len(hosts)} host(s) from {fp.name}")

    else:
        xml_path = Path(args.xml)
        if not xml_path.exists():
            sys.exit(
                f"[!] No --domain / --file given and XML not found:\n"
                f"    {xml_path}\n"
                f"    Specify a different path with --xml."
            )
        hosts = parse_burp_xml(xml_path)

    # ── Run scans ─────────────────────────────────────────────────────────
    payload: dict = {
        "scan_metadata": {
            "wstg_id":   "WSTG-CRYP-03",
            "title":     "Sensitive Information Sent via Unencrypted Channels",
            "scan_time": _ts(),
            "source":    args.domain or args.file or args.xml,
        },
        "results": {},
    }

    for host, info in hosts.items():
        print(f"\n[*] Scanning {host} …")
        login_path = (info.get("login_paths") or ["/login"])[0]
        payload["results"][host] = scan_host(host, login_path)

    # ── Write output ──────────────────────────────────────────────────────
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2))

    vuln_count = sum(
        1 for h in payload["results"].values() if h["overall_vulnerable"]
    )
    print(f"\n[+] Done — {vuln_count}/{len(hosts)} host(s) flagged  →  {out_path}")


if __name__ == "__main__":
    main()
