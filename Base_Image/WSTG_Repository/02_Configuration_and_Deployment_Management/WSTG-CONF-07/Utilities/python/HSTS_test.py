#!/usr/bin/env python3
"""
WSTG-CONF-07 — HTTP Strict Transport Security (HSTS) Tester

Runs three checks per domain:

  1. HSTS header check
     curl -s -D- https://<domain> | grep -i strict-transport-security
     → parses max-age, includeSubDomains, preload directives

  2. HSTS preload status
     curl -s "https://hstspreload.org/api/v2/status?domain=<domain>"
     → checks if domain is listed, eligible, has preload directive

  3. HTTP → HTTPS redirect check
     curl -s -D- http://<domain> | head -n 5
     → confirms whether plain HTTP redirects to HTTPS

Results written to:
  -o / --output  (default: outputs/test_outputs/report.txt)

Usage:
  python3 HSTS_test.py -d example.com
  python3 HSTS_test.py -d example.com sub.example.com -o outputs/test_outputs/report.txt
  python3 HSTS_test.py --domains-file inputs/domains.txt
"""

import argparse
import subprocess
import sys
import os
import json
import re
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# curl helpers
# ---------------------------------------------------------------------------

CURL_TIMEOUT = 15


def curl_headers(url: str) -> tuple[int | None, dict, str]:
    """
    Run: curl -s -o /dev/null -D- --max-time <T> <url>
    Returns (status_code, headers_dict, raw_header_text)
    """
    try:
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-D", "-",
             "--max-time", str(CURL_TIMEOUT),
             "-A", "Mozilla/5.0",
             "-L",           # follow redirects to capture final headers
             "--max-redirs", "5",
             url],
            capture_output=True,
            text=True,
            timeout=CURL_TIMEOUT + 5,
        )
        raw = result.stdout
        lines = raw.replace('\r\n', '\n').split('\n')
        status_code = None
        headers = {}
        # When -L follows redirects, there may be multiple header blocks
        # We want the LAST status line and its following headers
        blocks = []
        current_block = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("HTTP/"):
                if current_block:
                    blocks.append(current_block)
                current_block = [stripped]
            else:
                current_block.append(stripped)
        if current_block:
            blocks.append(current_block)

        if blocks:
            last_block = blocks[-1]
            for i, line in enumerate(last_block):
                if i == 0 and line.startswith("HTTP/"):
                    m = re.search(r'\s(\d{3})\s', line)
                    if m:
                        status_code = int(m.group(1))
                elif ':' in line:
                    name, _, value = line.partition(':')
                    headers[name.strip().lower()] = value.strip()

        return status_code, headers, raw
    except subprocess.TimeoutExpired:
        return None, {}, "TIMEOUT"
    except FileNotFoundError:
        print("[!] curl not found on PATH. Install curl and retry.")
        sys.exit(1)
    except Exception as e:
        return None, {}, str(e)


def curl_redirect_check(domain: str) -> tuple[int | None, str | None, str]:
    """
    Check what http://<domain> returns — specifically whether it
    redirects to https://. Returns (status_code, location_header, raw_first5).
    Does NOT follow redirects so we see the raw Location header.
    """
    url = f"http://{domain}"
    try:
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-D", "-",
             "--max-time", str(CURL_TIMEOUT),
             "-A", "Mozilla/5.0",
             url],                            # no -L intentionally
            capture_output=True,
            text=True,
            timeout=CURL_TIMEOUT + 5,
        )
        raw = result.stdout
        lines = raw.replace('\r\n', '\n').split('\n')
        status_code = None
        location = None
        for line in lines[:20]:              # only care about first block
            stripped = line.strip()
            if stripped.startswith("HTTP/"):
                m = re.search(r'\s(\d{3})\s', stripped)
                if m:
                    status_code = int(m.group(1))
            elif stripped.lower().startswith("location:"):
                location = stripped.split(':', 1)[1].strip()
        return status_code, location, '\n'.join(lines[:5])
    except subprocess.TimeoutExpired:
        return None, None, "TIMEOUT"
    except Exception as e:
        return None, None, str(e)


def curl_preload_api(domain: str) -> dict:
    """
    curl -s "https://hstspreload.org/api/v2/status?domain=<domain>"
    Returns the parsed JSON dict or an error dict.
    """
    url = f"https://hstspreload.org/api/v2/status?domain={domain}"
    try:
        result = subprocess.run(
            ["curl", "-s", "--max-time", str(CURL_TIMEOUT), url],
            capture_output=True,
            text=True,
            timeout=CURL_TIMEOUT + 5,
        )
        text = result.stdout.strip()
        if not text:
            return {"error": "empty response"}
        return json.loads(text)
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}
    except json.JSONDecodeError as e:
        return {"error": f"JSON parse error: {e}", "raw": result.stdout[:200]}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# HSTS header parser
# ---------------------------------------------------------------------------

def parse_hsts_header(value: str) -> dict:
    """
    Parse 'max-age=31536000; includeSubDomains; preload'
    into {max_age, include_subdomains, preload, raw}
    """
    result = {
        "raw": value,
        "max_age": None,
        "include_subdomains": False,
        "preload": False,
        "valid": False,
        "issues": [],
    }

    if not value:
        result["issues"].append("Header absent")
        return result

    # max-age
    m = re.search(r'max-age\s*=\s*(\d+)', value, re.IGNORECASE)
    if m:
        result["max_age"] = int(m.group(1))
    else:
        result["issues"].append("max-age directive missing")

    result["include_subdomains"] = bool(
        re.search(r'includeSubDomains', value, re.IGNORECASE)
    )
    result["preload"] = bool(
        re.search(r'\bpreload\b', value, re.IGNORECASE)
    )

    # Validation checks
    if result["max_age"] is not None:
        if result["max_age"] < 10886400:   # 18 weeks — preload minimum
            result["issues"].append(
                f"max-age={result['max_age']} is below the 18-week (10886400s) preload minimum"
            )
        if result["max_age"] < 31536000:   # 1 year — recommended
            result["issues"].append(
                f"max-age={result['max_age']} is below the recommended 1-year (31536000s) value"
            )

    if result["preload"] and not result["include_subdomains"]:
        result["issues"].append(
            "preload directive present but includeSubDomains is missing — "
            "preload requires includeSubDomains"
        )

    if not result["issues"] and result["max_age"] is not None:
        result["valid"] = True

    return result


# ---------------------------------------------------------------------------
# Preload status analyser
# ---------------------------------------------------------------------------

def analyse_preload(preload_data: dict, hsts: dict) -> dict:
    """
    Interpret hstspreload.org API response alongside the live HSTS header.
    Returns {status, in_progress, issues, notes}
    """
    result = {
        "status": preload_data.get("status", "unknown"),
        "in_progress": False,
        "issues": [],
        "notes": [],
    }

    if "error" in preload_data:
        result["issues"].append(f"Could not reach hstspreload.org: {preload_data['error']}")
        return result

    status = preload_data.get("status", "")

    # hstspreload.org statuses: preloaded, pending, eligible, unknown
    if status == "preloaded":
        result["notes"].append("Domain is listed in the HSTS preload list.")
    elif status == "pending":
        result["in_progress"] = True
        result["notes"].append(
            "Domain has a pending preload submission — submission in progress."
        )
        # Confirm the live header actually has preload directive
        if not hsts.get("preload"):
            result["issues"].append(
                "Pending preload submission but live HSTS header lacks 'preload' directive — "
                "submission may be stale or the header was recently changed."
            )
    elif status == "eligible":
        result["notes"].append("Domain is eligible for preloading but not yet submitted.")
        if hsts.get("preload"):
            result["notes"].append(
                "preload directive is present in the live header — "
                "consider submitting to hstspreload.org."
            )
    else:
        # unknown / not submitted
        if hsts.get("preload"):
            result["issues"].append(
                "preload directive is present in the HSTS header but the domain is NOT in the "
                "preload list and has no pending submission. "
                "This is a stale or no-op directive — either remove 'preload' or submit the domain."
            )

    return result


# ---------------------------------------------------------------------------
# Per-domain check
# ---------------------------------------------------------------------------

def check_domain(domain: str) -> dict:
    domain = domain.strip().lstrip("https://").lstrip("http://").rstrip("/")
    print(f"\n[*] Checking: {domain}")

    record = {
        "domain": domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hsts_header": {},
        "redirect": {},
        "preload": {},
        "preload_analysis": {},
        "raw": {},
    }

    # 1. HSTS header
    print(f"    [1/3] HSTS header (HTTPS)...")
    https_url = f"https://{domain}"
    status, headers, raw = curl_headers(https_url)
    record["raw"]["hsts_request"] = raw
    record["raw"]["https_status"] = status
    hsts_value = headers.get("strict-transport-security", "")
    record["hsts_header"] = parse_hsts_header(hsts_value)
    record["hsts_header"]["https_status"] = status
    print(f"    → HTTPS {status} | HSTS: {'present' if hsts_value else 'ABSENT'}")
    if hsts_value:
        print(f"    → {hsts_value}")

    # 2. Preload API
    print(f"    [2/3] Preload status (hstspreload.org)...")
    preload_data = curl_preload_api(domain)
    record["preload"] = preload_data
    record["preload_analysis"] = analyse_preload(preload_data, record["hsts_header"])
    print(f"    → Preload status: {preload_data.get('status', 'error/unknown')}")

    # 3. HTTP redirect
    print(f"    [3/3] HTTP → HTTPS redirect check...")
    redir_status, redir_location, redir_raw = curl_redirect_check(domain)
    record["raw"]["redirect_raw"] = redir_raw
    redirects_to_https = (
        redir_status in (301, 302, 307, 308)
        and redir_location is not None
        and redir_location.lower().startswith("https://")
    )
    record["redirect"] = {
        "status_code": redir_status,
        "location": redir_location,
        "redirects_to_https": redirects_to_https,
    }
    print(f"    → HTTP {redir_status} | Location: {redir_location or 'none'} | "
          f"Redirects to HTTPS: {redirects_to_https}")

    return record


# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------

def write_report(output_path: str, results: list):
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    lines = []
    lines.append("# CONF-07 HSTS Test Report")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(f"Domains checked: {len(results)}")
    lines.append("")
    lines.append("=" * 60)
    lines.append("")

    for r in results:
        domain = r["domain"]
        hsts = r["hsts_header"]
        redir = r["redirect"]
        preload = r["preload"]
        pa = r["preload_analysis"]

        lines.append(f"DOMAIN: {domain}")
        lines.append("-" * 40)

        # Check 1: HSTS header
        lines.append("[CHECK 1] HSTS Header (HTTPS)")
        hsts_raw = hsts.get("raw", "")
        if hsts_raw:
            lines.append(f"  Header present: YES")
            lines.append(f"  Raw value:      Strict-Transport-Security: {hsts_raw}")
            lines.append(f"  max-age:        {hsts.get('max_age', 'not set')}")
            lines.append(f"  includeSubDomains: {hsts.get('include_subdomains', False)}")
            lines.append(f"  preload:        {hsts.get('preload', False)}")
            if hsts.get("issues"):
                for issue in hsts["issues"]:
                    lines.append(f"  ISSUE: {issue}")
        else:
            lines.append(f"  Header present: NO")
            lines.append(f"  HTTPS status:   {hsts.get('https_status', 'unknown')}")
            lines.append(f"  ISSUE: Strict-Transport-Security header is absent")
        lines.append("")

        # Check 2: Preload
        lines.append("[CHECK 2] HSTS Preload Status (hstspreload.org)")
        if "error" in preload:
            lines.append(f"  Status: ERROR — {preload['error']}")
        else:
            lines.append(f"  API status:    {preload.get('status', 'unknown')}")
            lines.append(f"  In progress:   {pa.get('in_progress', False)}")
        for note in pa.get("notes", []):
            lines.append(f"  NOTE: {note}")
        for issue in pa.get("issues", []):
            lines.append(f"  ISSUE: {issue}")
        lines.append("")

        # Check 3: Redirect
        lines.append("[CHECK 3] HTTP → HTTPS Redirect")
        lines.append(f"  HTTP status:   {redir.get('status_code', 'unknown')}")
        lines.append(f"  Location:      {redir.get('location', 'none')}")
        lines.append(f"  Redirects to HTTPS: {redir.get('redirects_to_https', False)}")
        if not redir.get("redirects_to_https"):
            lines.append(f"  ISSUE: HTTP does not redirect to HTTPS")
        lines.append("")
        lines.append("=" * 60)
        lines.append("")

    with open(output_path, 'w') as f:
        f.write('\n'.join(lines))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description='CONF-07: HSTS header, preload status, and HTTP redirect check'
    )
    p.add_argument(
        '-d', '--domains', nargs='+',
        help='One or more domains to check (e.g. example.com sub.example.com)'
    )
    p.add_argument(
        '--domains-file',
        help='File with one domain per line'
    )
    p.add_argument(
        '-o', '--output',
        default='outputs/test_outputs/report.txt',
        help='Output report file (default: outputs/test_outputs/report.txt)'
    )
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    domains = []
    if args.domains:
        domains.extend(args.domains)
    if args.domains_file:
        try:
            with open(args.domains_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        domains.append(line)
        except FileNotFoundError:
            print(f"[!] Domains file not found: {args.domains_file}")
            sys.exit(1)

    if not domains:
        print("[!] No domains specified. Use -d example.com or --domains-file file.txt")
        sys.exit(1)

    # Deduplicate preserving order
    seen = set()
    unique_domains = []
    for d in domains:
        if d not in seen:
            seen.add(d)
            unique_domains.append(d)

    print("=" * 60)
    print("CONF-07 — HSTS Tester")
    print("=" * 60)
    print(f"[*] Domains to check: {len(unique_domains)}")

    results = []
    for domain in unique_domains:
        results.append(check_domain(domain))

    write_report(args.output, results)
    print(f"\n[+] Report written → {args.output}")
    print(f"\nNext: run HSTS_findings_report.py -i {args.output}")


if __name__ == "__main__":
    main()
