#!/usr/bin/env python3
"""
WSTG-CONF-12 — Content Security Policy (CSP) Scanner
Path: utilities/CSP_Scanner.py

Reads a Burp Suite XML export and for each HTTP item:

  1. Checks response headers for Content-Security-Policy (CSP)
  2. Flags Content-Security-Policy-Report-Only as a finding
  3. Falls back to HTML <meta http-equiv="Content-Security-Policy"> tags
     if no CSP header is present
  4. Analyses any found CSP policy for:
       - High-risk directives: unsafe-inline, unsafe-eval, unsafe-hashes, data:, blob:
       - Wildcard sources: *, https:, http: in script-src / default-src
       - Missing critical directives: default-src, object-src, base-uri, script-src,
         form-action, frame-ancestors
  5. Tags endpoints as AUTH or INPUT-BEARING based on path keywords
  6. Reports severity-rated findings per endpoint

Reads CSP directive definitions + reasoning from CSP_Strings.json.

Usage:
  python3 utilities/CSP_Scanner.py \\
      --xml  inputs/XML/subfolder/export.xml \\
      --csp-strings inputs/Data/CSP_Strings.json \\
      -o outputs/test_output/test_findings.txt

Flags:
  -x / --xml          Burp XML export (required)
  -c / --csp-strings  CSP_Strings.json (default: inputs/Data/CSP_Strings.json)
  -o / --output       Output report (default: outputs/test_output/test_findings.txt)
  --auth-only         Only report endpoints matching auth path keywords
  --input-only        Only report endpoints matching input-bearing keywords
"""

import argparse
import base64
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Burp XML helpers
# ---------------------------------------------------------------------------

def decode_element(elem) -> str:
    """Decode a Burp XML element, handling base64='true' attribute."""
    if elem is None:
        return ""
    raw = elem.text or ""
    if elem.attrib.get("base64", "false").lower() == "true":
        try:
            return base64.b64decode(raw).decode("utf-8", errors="replace")
        except Exception:
            return raw
    return raw


def parse_request_line(request_text: str) -> tuple:
    first = request_text.split('\n', 1)[0].strip()
    parts = first.split(' ')
    if len(parts) >= 2:
        return parts[0], parts[1]
    return "UNKNOWN", "/"


def split_headers_body(text: str) -> tuple:
    normalized = text.replace('\r\n', '\n')
    if '\n\n' in normalized:
        headers_part, body = normalized.split('\n\n', 1)
    else:
        headers_part = normalized
        body = ""
    return headers_part, body


def parse_response_headers(headers_text: str) -> dict:
    """Parse response headers into {name_lower: value} dict."""
    headers = {}
    lines = headers_text.split('\n')
    for line in lines[1:]:   # skip status line
        if ':' in line:
            name, _, value = line.partition(':')
            key = name.strip().lower()
            # Keep first occurrence only (CSP can appear once; if duped that's another issue)
            if key not in headers:
                headers[key] = value.strip()
    return headers


def get_response_status(headers_text: str) -> tuple:
    """Extract HTTP version and status code from the first response line."""
    first = headers_text.split('\n', 1)[0].strip()
    m = re.search(r'\s(\d{3})\s', first)
    if m:
        return int(m.group(1)), first
    return None, first


# ---------------------------------------------------------------------------
# Meta tag extraction
# ---------------------------------------------------------------------------

_META_CSP_RE = re.compile(
    r'<\s*meta\s[^>]*http-equiv\s*=\s*["\']?\s*Content-Security-Policy\s*["\']?[^>]*content\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE | re.DOTALL,
)
_META_CSP_RE2 = re.compile(
    r'<\s*meta\s[^>]*content\s*=\s*["\']([^"\']+)["\'][^>]*http-equiv\s*=\s*["\']?\s*Content-Security-Policy\s*["\']?',
    re.IGNORECASE | re.DOTALL,
)


def extract_csp_from_meta(html: str) -> str | None:
    """Return the CSP value from a <meta http-equiv='Content-Security-Policy'> tag, or None."""
    m = _META_CSP_RE.search(html) or _META_CSP_RE2.search(html)
    if m:
        return m.group(1).strip()
    return None


# ---------------------------------------------------------------------------
# CSP policy analysis
# ---------------------------------------------------------------------------

def parse_csp_directives(policy: str) -> dict:
    """
    Parse a CSP string into a dict of {directive_name: [sources]}.
    e.g. "default-src 'self'; script-src 'unsafe-inline' cdn.example.com"
    → {'default-src': ["'self'"], 'script-src': ["'unsafe-inline'", "cdn.example.com"]}
    """
    directives = {}
    for part in policy.split(';'):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directive = tokens[0].lower()
            sources = tokens[1:]
            directives[directive] = sources
    return directives


def analyse_csp(policy: str, csp_strings: dict) -> list:
    """
    Analyse a CSP policy string and return a list of finding dicts:
      {severity, finding_type, directive, matched_value, reasoning}
    """
    findings = []
    directives = parse_csp_directives(policy)
    policy_lower = policy.lower()

    # 1. Check high-risk directives anywhere in the policy
    for entry in csp_strings.get('high_risk_directives', []):
        val = entry['value'].lower()
        if val in policy_lower:
            # Find which directive it appears in
            for dname, sources in directives.items():
                src_lower = [s.lower() for s in sources]
                if val in src_lower or any(val in s for s in src_lower):
                    findings.append({
                        'severity':     entry['severity'],
                        'finding_type': 'HIGH_RISK_DIRECTIVE',
                        'directive':    dname,
                        'matched_value': entry['value'],
                        'reasoning':    entry['reasoning'],
                    })
                    break
            else:
                # Appeared in policy text but couldn't pin to a directive
                findings.append({
                    'severity':     entry['severity'],
                    'finding_type': 'HIGH_RISK_DIRECTIVE',
                    'directive':    '(policy-level)',
                    'matched_value': entry['value'],
                    'reasoning':    entry['reasoning'],
                })

    # 2. Wildcard patterns — only meaningful in script-src / default-src / connect-src
    risky_directives_for_wildcards = {
        'script-src', 'default-src', 'connect-src', 'style-src', 'img-src',
        'font-src', 'media-src', 'frame-src', 'child-src', 'worker-src',
    }
    for entry in csp_strings.get('wildcard_patterns', []):
        val = entry['value'].lower()
        for dname, sources in directives.items():
            if dname not in risky_directives_for_wildcards:
                continue
            src_lower = [s.strip("'\"").lower() for s in sources]
            if val in src_lower:
                findings.append({
                    'severity':     entry['severity'],
                    'finding_type': 'WILDCARD_SOURCE',
                    'directive':    dname,
                    'matched_value': entry['value'],
                    'reasoning':    entry.get('reasoning', ''),
                })

    # 3. Missing critical directives
    for entry in csp_strings.get('missing_directives', []):
        dname = entry['directive'].lower()
        if dname not in directives:
            # If default-src is present, some missing directives are covered —
            # but base-uri, form-action, frame-ancestors are NEVER covered by default-src
            never_covered = {'base-uri', 'form-action', 'frame-ancestors'}
            if dname in never_covered or 'default-src' not in directives:
                findings.append({
                    'severity':     entry['severity'],
                    'finding_type': 'MISSING_DIRECTIVE',
                    'directive':    dname,
                    'matched_value': f"(absent)",
                    'reasoning':    entry['reasoning'],
                })

    # 4. Nonce / hash info notes (INFO level)
    for entry in csp_strings.get('nonce_and_hash_notes', []):
        val = entry['value'].lower()
        for dname, sources in directives.items():
            if any(val in s.lower() for s in sources):
                findings.append({
                    'severity':     entry['severity'],
                    'finding_type': 'NONCE_HASH_NOTE',
                    'directive':    dname,
                    'matched_value': entry['value'],
                    'reasoning':    entry['reasoning'],
                })
                break

    # Deduplicate
    seen = set()
    unique = []
    for f in findings:
        key = (f['finding_type'], f['directive'], f['matched_value'])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Sort: CRITICAL → HIGH → MEDIUM → LOW → INFO
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    unique.sort(key=lambda x: sev_order.get(x['severity'], 99))
    return unique


# ---------------------------------------------------------------------------
# Path classification
# ---------------------------------------------------------------------------

def build_path_re(keywords: list) -> re.Pattern:
    return re.compile(
        '|'.join(re.escape(kw) for kw in keywords),
        re.IGNORECASE,
    )


def classify_path(path: str, auth_re: re.Pattern, input_re: re.Pattern) -> set:
    tags = set()
    if auth_re.search(path):
        tags.add('AUTH')
    if input_re.search(path):
        tags.add('INPUT')
    return tags


# ---------------------------------------------------------------------------
# Per-item processing
# ---------------------------------------------------------------------------

def process_item(index: int, item, csp_strings: dict,
                 auth_re: re.Pattern, input_re: re.Pattern) -> dict | None:
    """
    Process one Burp item. Returns a result dict or None if nothing to report.
    """
    # Extract URL
    url_elem = item.find('./url')
    url = url_elem.text.strip() if url_elem is not None and url_elem.text else ""

    # Extract request
    request_text = decode_element(item.find('./request'))
    req_method, req_path = parse_request_line(request_text)

    # Fallback URL
    if not url:
        host_elem = item.find('./host')
        host = host_elem.text.strip() if host_elem is not None and host_elem.text else "unknown"
        proto_elem = item.find('./protocol')
        proto = proto_elem.text.strip() if proto_elem is not None and proto_elem.text else "https"
        url = f"{proto}://{host}{req_path}"

    try:
        parsed = urlparse(url)
        path = parsed.path or req_path
    except Exception:
        path = req_path

    # Path classification
    path_tags = classify_path(path, auth_re, input_re)

    # Extract response
    response_text = decode_element(item.find('./response'))
    resp_headers_text, resp_body = split_headers_body(response_text)
    resp_headers = parse_response_headers(resp_headers_text)
    status_code, status_line = get_response_status(resp_headers_text)

    # --- CSP detection ---
    csp_value = None
    csp_source = None
    report_only = False

    # Check for Report-Only first (always a finding regardless of policy quality)
    ro_value = resp_headers.get('content-security-policy-report-only', '')
    if ro_value:
        report_only = True
        csp_value = ro_value
        csp_source = 'header:report-only'

    # Check for enforcing CSP
    enforcing_value = resp_headers.get('content-security-policy', '')
    if enforcing_value:
        if not csp_value:
            csp_value = enforcing_value
            csp_source = 'header:enforcing'
        # If both exist, track that too
        if report_only:
            csp_source = 'header:both-present'

    # If no CSP header, check <meta> tags
    if not csp_value and resp_body:
        meta_csp = extract_csp_from_meta(resp_body)
        if meta_csp:
            csp_value = meta_csp
            csp_source = 'meta-tag'

    # --- Findings ---
    findings = []
    csp_absent = (csp_value is None)

    # Report-Only finding
    if report_only:
        ro_entry = csp_strings.get('report_only_indicator', {})
        findings.append({
            'severity':     ro_entry.get('severity', 'MEDIUM'),
            'finding_type': 'REPORT_ONLY',
            'directive':    'Content-Security-Policy-Report-Only',
            'matched_value': '(header present)',
            'reasoning':    ro_entry.get('reasoning', ''),
        })

    # CSP absent
    if csp_absent:
        sev = 'HIGH' if ('AUTH' in path_tags or 'INPUT' in path_tags) else 'MEDIUM'
        findings.append({
            'severity':     sev,
            'finding_type': 'CSP_ABSENT',
            'directive':    'Content-Security-Policy',
            'matched_value': '(header and meta tag both absent)',
            'reasoning':    (
                'No Content-Security-Policy header or <meta> tag was found in this response. '
                'Without a CSP, the browser applies no restrictions on script execution sources, '
                'making the page fully vulnerable to XSS without browser-level mitigation.'
            ),
        })
    else:
        # Analyse the policy
        policy_findings = analyse_csp(csp_value, csp_strings)
        findings.extend(policy_findings)

    # Only return result if there's something to report
    if not findings:
        return None

    return {
        'index':        index,
        'method':       req_method,
        'url':          url,
        'path':         path,
        'status_code':  status_code,
        'path_tags':    path_tags,
        'csp_value':    csp_value,
        'csp_source':   csp_source,
        'csp_absent':   csp_absent,
        'report_only':  report_only,
        'findings':     findings,
    }


# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------

SEVERITY_BADGE = {
    'CRITICAL': '[CRITICAL]',
    'HIGH':     '[HIGH]    ',
    'MEDIUM':   '[MEDIUM]  ',
    'LOW':      '[LOW]     ',
    'INFO':     '[INFO]    ',
}

FINDING_TYPE_LABEL = {
    'CSP_ABSENT':          'CSP Absent',
    'REPORT_ONLY':         'Report-Only Mode (No Enforcement)',
    'HIGH_RISK_DIRECTIVE': 'High-Risk Directive',
    'WILDCARD_SOURCE':     'Wildcard Source',
    'MISSING_DIRECTIVE':   'Missing Directive',
    'NONCE_HASH_NOTE':     'Nonce/Hash Note',
}

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def max_severity(findings: list) -> str:
    if not findings:
        return 'INFO'
    return min(findings, key=lambda f: SEV_ORDER.get(f['severity'], 99))['severity']


def write_report(output_path: str, results: list, xml_filename: str,
                 total_items: int, meta: dict):
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    # Aggregate counts
    sev_counts = defaultdict(int)
    for r in results:
        for f in r['findings']:
            sev_counts[f['severity']] += 1

    csp_absent_count  = sum(1 for r in results if r['csp_absent'])
    report_only_count = sum(1 for r in results if r['report_only'])
    auth_hit_count    = sum(1 for r in results if 'AUTH' in r['path_tags'])
    input_hit_count   = sum(1 for r in results if 'INPUT' in r['path_tags'])

    lines = []
    lines.append("=" * 72)
    lines.append("CONF-12 — Content Security Policy (CSP) Scanner")
    lines.append("WSTG-CONF-12 | Test for Content Security Policy")
    lines.append("=" * 72)
    lines.append(f"Generated   : {meta['generated']}")
    lines.append(f"XML File    : {xml_filename}")
    lines.append(f"CSP Strings : {meta['csp_strings_path']}")
    lines.append(f"Items scanned          : {total_items}")
    lines.append(f"Endpoints with findings: {len(results)}")
    lines.append(f"  CSP absent           : {csp_absent_count}")
    lines.append(f"  Report-Only only     : {report_only_count}")
    lines.append(f"  Auth pathway hits    : {auth_hit_count}")
    lines.append(f"  Input-bearing hits   : {input_hit_count}")
    lines.append("")
    lines.append("Severity Breakdown:")
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        if sev_counts[sev]:
            lines.append(f"  {sev:<10} {sev_counts[sev]:>4} finding(s)")
    lines.append("")
    lines.append("=" * 72)
    lines.append("")

    if not results:
        lines.append("No CSP issues found. All scanned responses appear to have CSP configured.")
    else:
        for r in results:
            idx        = r['index']
            method     = r['method']
            url        = r['url']
            path       = r['path']
            status     = r['status_code'] or 'N/A'
            path_tags  = r['path_tags']
            csp_val    = r['csp_value']
            csp_src    = r['csp_source']
            findings   = r['findings']
            top_sev    = max_severity(findings)

            tags_str = ''
            if path_tags:
                tags_str = '  [' + ' | '.join(sorted(path_tags)) + ']'

            lines.append(
                f"ENDPOINT {idx:>4} | {method:<7} | {path}{tags_str}"
            )
            lines.append(f"  URL    : {url}")
            lines.append(f"  Status : {status}  |  File: {xml_filename}")
            lines.append(f"  Top Severity: {top_sev}  |  Findings: {len(findings)}")

            if csp_val:
                src_label = {
                    'header:enforcing':   'Response Header (Enforcing)',
                    'header:report-only': 'Response Header (Report-Only)',
                    'header:both-present':'Response Headers (Both Present)',
                    'meta-tag':           '<meta> Tag (fallback)',
                }.get(csp_src, csp_src)
                lines.append(f"  CSP Source: {src_label}")
                lines.append(f"  CSP Value : {csp_val}")
            else:
                lines.append(f"  CSP Source: ABSENT")
            lines.append("")

            for f in findings:
                badge = SEVERITY_BADGE.get(f['severity'], f['severity'])
                ftype = FINDING_TYPE_LABEL.get(f['finding_type'], f['finding_type'])
                lines.append(f"  {badge} {ftype}")
                if f['directive'] and f['matched_value']:
                    lines.append(f"    Directive : {f['directive']}")
                    lines.append(f"    Match     : {f['matched_value']}")
                if f['reasoning']:
                    # Word-wrap reasoning at ~68 chars
                    words = f['reasoning'].split()
                    line_buf = "    Reasoning: "
                    for word in words:
                        if len(line_buf) + len(word) + 1 > 72:
                            lines.append(line_buf)
                            line_buf = "               " + word
                        else:
                            line_buf = (line_buf + " " + word).lstrip()
                            if line_buf.startswith("Reasoning"):
                                line_buf = "    Reasoning: " + word
                    if line_buf.strip():
                        lines.append(line_buf)
                lines.append("")

            lines.append("-" * 72)
            lines.append("")

    # Remediation guidance
    lines.append("")
    lines.append("=" * 72)
    lines.append("REMEDIATION GUIDANCE")
    lines.append("=" * 72)
    lines.append("")
    lines.append("Minimal recommended CSP for a standard web application:")
    lines.append("")
    lines.append("  Content-Security-Policy:")
    lines.append("    default-src 'self';")
    lines.append("    script-src 'self' 'nonce-{RANDOM}';")
    lines.append("    object-src 'none';")
    lines.append("    base-uri 'self';")
    lines.append("    form-action 'self';")
    lines.append("    frame-ancestors 'none';")
    lines.append("    upgrade-insecure-requests;")
    lines.append("")
    lines.append("Replace 'unsafe-inline' / 'unsafe-eval' with:")
    lines.append("  - Nonces (preferred):  script-src 'nonce-<base64-random>'")
    lines.append("  - Hashes (for static): script-src 'sha256-<hash>'")
    lines.append("")
    lines.append("References:")
    lines.append("  https://content-security-policy.com/")
    lines.append("  https://csp-evaluator.withgoogle.com/")
    lines.append("  https://owasp.org/www-project-secure-headers/")
    lines.append("")

    with open(output_path, 'w') as f:
        f.write('\n'.join(lines))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description='CONF-12: Scan Burp XML for CSP header presence and policy weaknesses'
    )
    p.add_argument(
        '-x', '--xml', required=True,
        help='Burp Suite XML export file'
    )
    p.add_argument(
        '-c', '--csp-strings',
        default='inputs/Data/CSP_Strings.json',
        help='CSP strings JSON (default: inputs/Data/CSP_Strings.json)'
    )
    p.add_argument(
        '-o', '--output',
        default='outputs/test_output/test_findings.txt',
        help='Output report (default: outputs/test_output/test_findings.txt)'
    )
    p.add_argument(
        '--auth-only', action='store_true',
        help='Only report endpoints matching auth path keywords'
    )
    p.add_argument(
        '--input-only', action='store_true',
        help='Only report endpoints matching input-bearing keywords'
    )
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    print("=" * 60)
    print("CONF-12 — CSP Scanner")
    print("=" * 60)

    # Load CSP strings
    try:
        with open(args.csp_strings) as f:
            csp_strings = json.load(f)
    except FileNotFoundError:
        print(f"[!] CSP strings file not found: {args.csp_strings}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON in {args.csp_strings}: {e}")
        sys.exit(1)

    auth_keywords  = csp_strings.get('auth_path_keywords', [])
    input_keywords = csp_strings.get('input_bearing_keywords', [])
    auth_re  = build_path_re(auth_keywords)
    input_re = build_path_re(input_keywords)

    print(f"[*] Loaded CSP strings from {args.csp_strings}")
    print(f"[*] Auth keywords: {len(auth_keywords)}  |  Input keywords: {len(input_keywords)}")

    # Parse XML
    try:
        tree = ET.parse(args.xml)
    except FileNotFoundError:
        print(f"[!] XML not found: {args.xml}")
        sys.exit(1)
    except ET.ParseError as e:
        print(f"[!] XML parse error: {e}")
        sys.exit(1)

    items = tree.getroot().findall('.//item')
    if not items:
        print("[!] No <item> elements found in XML.")
        sys.exit(1)

    xml_filename = os.path.basename(args.xml)
    print(f"[*] XML: {xml_filename} — {len(items)} items")

    # Process
    results = []
    for i, item in enumerate(items, start=1):
        result = process_item(i, item, csp_strings, auth_re, input_re)
        if result is None:
            continue

        # Filters
        if args.auth_only and 'AUTH' not in result['path_tags']:
            continue
        if args.input_only and 'INPUT' not in result['path_tags']:
            continue

        results.append(result)

    print(f"[*] Endpoints with findings: {len(results)} / {len(items)}")

    sev_counts = defaultdict(int)
    for r in results:
        for f in r['findings']:
            sev_counts[f['severity']] += 1
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if sev_counts[sev]:
            print(f"    {sev}: {sev_counts[sev]}")

    meta = {
        'generated':        datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
        'csp_strings_path': args.csp_strings,
    }

    write_report(args.output, results, xml_filename, len(items), meta)
    print(f"\n[+] Report written → {args.output}")

    print(f"\n{'=' * 60}")
    print("CONF-12 SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Items scanned       : {len(items)}")
    print(f"  Endpoints flagged   : {len(results)}")
    print(f"  CSP absent          : {sum(1 for r in results if r['csp_absent'])}")
    print(f"  Report-Only present : {sum(1 for r in results if r['report_only'])}")
    print(f"  Output              : {args.output}")

    if not (args.auth_only or args.input_only):
        print(f"\n  Tip: rerun with --auth-only or --input-only to focus on sensitive endpoints.")


if __name__ == "__main__":
    main()
