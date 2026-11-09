#!/usr/bin/env python3
"""
WSTG-CONF-10 — Subdomain Takeover Analysis

Step 4 of the CONF-10 pipeline (after subfinder → dnsx → subzy).

For each subdomain in the input list this script:
  1. Runs `dig CNAME <subdomain>` and extracts the CNAME target
  2. Matches the CNAME target against known provider fingerprints
  3. Runs `curl -i https://<subdomain>` and checks the response for
     known "unclaimed" / "dangling" fingerprint strings
  4. Flags subdomains where CNAME points at a claimable provider
     AND the HTTP response suggests the resource is unclaimed
  5. Reads existing subzy output (if present) and merges its results
  6. Writes a consolidated findings report to outputs/test_outputs/findings.md
     and prints a terminal summary

Usage:
  python3 conf10_takeover.py \\
      -d example.com \\
      --subdomains /kali-tools/subfinder/subdomains.txt \\
      --dnsx       /kali-tools/dnsx/dnsx_resolved.txt \\
      --subzy      /kali-tools/subzy/subzy_out.txt \\
      --dig-out    /kali-tools/dig/dig_cname.txt \\
      -o outputs/test_outputs/findings.md

Flags:
  -d / --domain       Target domain (e.g. example.com) — used for labelling
  --subdomains        subfinder output: one subdomain per line (required)
  --dnsx              dnsx -cname -resp output (optional, merged into report)
  --subzy             subzy output file (optional, merged into report)
  --dig-out           Where to write combined dig CNAME output
                      (default: /kali-tools/dig/dig_cname.txt)
  -o / --output       Findings markdown output
                      (default: outputs/test_outputs/findings.md)
  --timeout           curl timeout in seconds (default: 10)
  --concurrency       Parallel probes (default: 10)
  --http-also         Also probe http:// if https:// fails or times out
"""

import argparse
import concurrent.futures
import os
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Provider fingerprint database
# Maps a regex matched against the CNAME target → provider metadata
# ---------------------------------------------------------------------------

PROVIDER_FINGERPRINTS = [
    # AWS
    {
        "provider":   "AWS S3",
        "cname_re":   re.compile(r's3(?:-website)?(?:\.[a-z0-9-]+)?\.amazonaws\.com', re.I),
        "http_signs": ["NoSuchBucket", "The specified bucket does not exist",
                       "NoSuchKey", "403 Forbidden"],
        "takeover":   True,
        "notes":      "S3 bucket named after subdomain may be claimable if bucket does not exist."
    },
    {
        "provider":   "AWS CloudFront",
        "cname_re":   re.compile(r'cloudfront\.net', re.I),
        "http_signs": ["Bad request", "ERROR: The request could not be satisfied"],
        "takeover":   False,
        "notes":      "CloudFront distributions are not directly claimable but may expose misconfig."
    },
    {
        "provider":   "AWS Elastic Beanstalk",
        "cname_re":   re.compile(r'elasticbeanstalk\.com', re.I),
        "http_signs": ["404 Not Found", "NoSuchBucket"],
        "takeover":   True,
        "notes":      "EB environment may be deleted; environment name could be re-registered."
    },
    {
        "provider":   "AWS API Gateway",
        "cname_re":   re.compile(r'execute-api\.[a-z0-9-]+\.amazonaws\.com', re.I),
        "http_signs": ["{"message":"Forbidden"}", "{"message":"Not Found"}"],
        "takeover":   False,
        "notes":      "API Gateway endpoint — not typically claimable but worth noting."
    },
    # Azure
    {
        "provider":   "Azure App Service / Web Apps",
        "cname_re":   re.compile(r'azurewebsites\.net', re.I),
        "http_signs": ["404 Web Site not found", "does not exist",
                       "You do not have permission", "Web App - Unavailable"],
        "takeover":   True,
        "notes":      "Azure Web App name may be available for registration if subdomain 404s."
    },
    {
        "provider":   "Azure CDN",
        "cname_re":   re.compile(r'azureedge\.net', re.I),
        "http_signs": ["404", "The resource you are looking for has been removed"],
        "takeover":   True,
        "notes":      "Azure CDN endpoint may be claimable if the backing app/storage is gone."
    },
    {
        "provider":   "Azure Traffic Manager",
        "cname_re":   re.compile(r'trafficmanager\.net', re.I),
        "http_signs": ["404"],
        "takeover":   True,
        "notes":      "Traffic Manager profile may be deleted but DNS still points to it."
    },
    {
        "provider":   "Azure Blob Storage (Static Website)",
        "cname_re":   re.compile(r'z\d+\.web\.core\.windows\.net|blob\.core\.windows\.net', re.I),
        "http_signs": ["BlobNotFound", "404", "ResourceNotFound", "PublicAccessNotPermitted"],
        "takeover":   True,
        "notes":      "Azure static web hosting container may be unclaimed."
    },
    # GitHub
    {
        "provider":   "GitHub Pages",
        "cname_re":   re.compile(r'github\.io', re.I),
        "http_signs": ["There isn't a GitHub Pages site here",
                       "404 There is no GitHub Pages site here.",
                       "For root URLs (like http://example.com/) you must provide an index.html"],
        "takeover":   True,
        "notes":      "GitHub Pages repo may be deleted; username/org + repo name could be claimed."
    },
    # Heroku
    {
        "provider":   "Heroku",
        "cname_re":   re.compile(r'herokuapp\.com|herokussl\.com|herokudns\.com', re.I),
        "http_signs": ["No such app", "heroku | no such app", "application not found"],
        "takeover":   True,
        "notes":      "Heroku app may have been deleted; app name could be re-registered."
    },
    # Netlify
    {
        "provider":   "Netlify",
        "cname_re":   re.compile(r'netlify\.(?:app|com)', re.I),
        "http_signs": ["Not Found - Request ID", "404 - Not Found"],
        "takeover":   True,
        "notes":      "Netlify site may be deleted; site name could be re-registered."
    },
    # Vercel
    {
        "provider":   "Vercel",
        "cname_re":   re.compile(r'vercel\.app|now\.sh', re.I),
        "http_signs": ["The deployment could not be found", "404: NOT_FOUND"],
        "takeover":   True,
        "notes":      "Vercel deployment may be removed; project/deployment name may be claimable."
    },
    # Shopify
    {
        "provider":   "Shopify",
        "cname_re":   re.compile(r'myshopify\.com|shops\.myshopify\.com', re.I),
        "http_signs": ["Sorry, this shop is currently unavailable",
                       "Only one step away!", "Sorry, this store is unavailable."],
        "takeover":   True,
        "notes":      "Shopify store may be inactive or deprovisioned."
    },
    # WordPress
    {
        "provider":   "WordPress.com",
        "cname_re":   re.compile(r'wordpress\.com', re.I),
        "http_signs": ["Do you want to register", "doesn't exist"],
        "takeover":   True,
        "notes":      "WordPress.com subdomain/site may be available for registration."
    },
    # Tumblr
    {
        "provider":   "Tumblr",
        "cname_re":   re.compile(r'tumblr\.com', re.I),
        "http_signs": ["There's nothing here.", "Whatever you were looking for doesn't live here"],
        "takeover":   True,
        "notes":      "Tumblr blog may have been deleted."
    },
    # Ghost
    {
        "provider":   "Ghost (Pro)",
        "cname_re":   re.compile(r'ghost\.io', re.I),
        "http_signs": ["The thing you were looking for is no longer here",
                       "404 Not found", "Domain Not Found"],
        "takeover":   True,
        "notes":      "Ghost Pro site may be deprovisioned."
    },
    # Zendesk
    {
        "provider":   "Zendesk",
        "cname_re":   re.compile(r'zendesk\.com', re.I),
        "http_signs": ["Help Center Closed", "Oops, this help center no longer exists"],
        "takeover":   True,
        "notes":      "Zendesk help center may have been closed."
    },
    # Fastly
    {
        "provider":   "Fastly",
        "cname_re":   re.compile(r'fastly\.net', re.I),
        "http_signs": ["Fastly error: unknown domain", "Please check that this domain has been added"],
        "takeover":   True,
        "notes":      "Fastly service may be removed but DNS still points to Fastly."
    },
    # Pantheon
    {
        "provider":   "Pantheon",
        "cname_re":   re.compile(r'pantheonsite\.io|getpantheon\.com', re.I),
        "http_signs": ["404 error unknown site!", "The gods are wise"],
        "takeover":   True,
        "notes":      "Pantheon site may be deleted."
    },
    # Squarespace
    {
        "provider":   "Squarespace",
        "cname_re":   re.compile(r'squarespace\.com|sqsp\.net', re.I),
        "http_signs": ["You need to assign this domain in Squarespace",
                       "No Such Account", "Website Expired"],
        "takeover":   True,
        "notes":      "Squarespace site may be expired or removed."
    },
    # HubSpot
    {
        "provider":   "HubSpot",
        "cname_re":   re.compile(r'hubspot\.net|hs-sites\.com', re.I),
        "http_signs": ["This page isn't available", "does not exist in our system",
                       "hs-sites.com"],
        "takeover":   True,
        "notes":      "HubSpot landing page may have been removed."
    },
    # Webflow
    {
        "provider":   "Webflow",
        "cname_re":   re.compile(r'webflow\.io', re.I),
        "http_signs": ["The page you are looking for doesn't exist",
                       "SSL Handshake Failed", "Not found"],
        "takeover":   True,
        "notes":      "Webflow site may be deleted; subdomain may be claimable."
    },
    # Cargo
    {
        "provider":   "Cargo Collective",
        "cname_re":   re.compile(r'cargocollective\.com', re.I),
        "http_signs": ["404 Not Found"],
        "takeover":   True,
        "notes":      "Cargo Collective site may be inactive."
    },
    # Surge.sh
    {
        "provider":   "Surge.sh",
        "cname_re":   re.compile(r'surge\.sh', re.I),
        "http_signs": ["project not found", "Surge - 404"],
        "takeover":   True,
        "notes":      "Surge.sh project may be unpublished; subdomain claimable."
    },
    # Intercom
    {
        "provider":   "Intercom",
        "cname_re":   re.compile(r'custom\.intercom\.help', re.I),
        "http_signs": ["This page is reserved for artistic dogs",
                       "Uh oh. That page doesn't exist."],
        "takeover":   True,
        "notes":      "Intercom help center may have been deprovisioned."
    },
    # Fly.io
    {
        "provider":   "Fly.io",
        "cname_re":   re.compile(r'fly\.dev|flycast\.dev', re.I),
        "http_signs": ["404 Not Found", "fly.io - Not Found"],
        "takeover":   True,
        "notes":      "Fly.io app may be deleted; app name could be re-registered."
    },
    # Render
    {
        "provider":   "Render",
        "cname_re":   re.compile(r'onrender\.com', re.I),
        "http_signs": ["Service Not Found", "404"],
        "takeover":   True,
        "notes":      "Render service may have been deleted."
    },
    # Generic dangling / catch-all
    {
        "provider":   "Unknown / Unresolved",
        "cname_re":   re.compile(r'.*'),          # matches anything not caught above
        "http_signs": [],
        "takeover":   False,
        "notes":      "CNAME target did not match a known provider. Manual review recommended."
    },
]


# ---------------------------------------------------------------------------
# NXDOMAIN / dangling DNS signals
# ---------------------------------------------------------------------------

NXDOMAIN_SIGNALS = [
    "NXDOMAIN", "Non-existent domain", "no answer",
    "SERVFAIL", "can't find", "Host not found",
]


# ---------------------------------------------------------------------------
# Dig helper
# ---------------------------------------------------------------------------

def dig_cname(subdomain: str) -> tuple:
    """
    Run `dig CNAME <subdomain> +short` and return (cname_target, raw_output).
    cname_target is None if no CNAME record found.
    """
    try:
        result = subprocess.run(
            ["dig", "CNAME", subdomain, "+short"],
            capture_output=True, text=True, timeout=15,
        )
        raw = result.stdout.strip()
        stderr = result.stderr.strip()
        if not raw:
            # Try without +short to check for NXDOMAIN
            result2 = subprocess.run(
                ["dig", "CNAME", subdomain],
                capture_output=True, text=True, timeout=15,
            )
            full_raw = result2.stdout
            nx = any(sig in full_raw for sig in NXDOMAIN_SIGNALS)
            return None, full_raw if nx else raw
        # +short gives us the CNAME target directly (trailing dot possible)
        cname = raw.rstrip('.')
        return cname, raw
    except subprocess.TimeoutExpired:
        return None, "TIMEOUT"
    except FileNotFoundError:
        return None, "dig not found"
    except Exception as e:
        return None, str(e)


# ---------------------------------------------------------------------------
# Provider matching
# ---------------------------------------------------------------------------

def match_provider(cname_target: str):
    """Match a CNAME target against the known provider fingerprints."""
    if not cname_target:
        return None
    for fp in PROVIDER_FINGERPRINTS[:-1]:   # skip the generic catch-all
        if fp['cname_re'].search(cname_target):
            return fp
    return PROVIDER_FINGERPRINTS[-1]         # generic


# ---------------------------------------------------------------------------
# HTTP probe
# ---------------------------------------------------------------------------

def curl_probe(url: str, timeout: int = 10) -> tuple:
    """
    curl -si <url> — returns (status_code, headers_dict, body_snippet, raw_headers).
    """
    try:
        result = subprocess.run(
            ["curl", "-si", "--max-time", str(timeout),
             "-A", "Mozilla/5.0",
             "--max-redirs", "5", "-L",
             url],
            capture_output=True, text=True, timeout=timeout + 5,
        )
        raw = result.stdout
        # Split headers from body (first blank line)
        # With -L there may be multiple response blocks; take the last
        blocks = re.split(r'(?m)^HTTP/', raw)
        if len(blocks) > 1:
            last_block = "HTTP/" + blocks[-1]
        else:
            last_block = raw

        header_part = last_block.split('\r\n\r\n', 1)[0] if '\r\n\r\n' in last_block else \
                      last_block.split('\n\n', 1)[0]
        body_part   = last_block[len(header_part):].strip()

        # Status code
        m = re.search(r'HTTP/[\d.]+ (\d+)', header_part)
        status = int(m.group(1)) if m else None

        # Headers
        headers = {}
        for line in header_part.split('\n')[1:]:
            if ':' in line:
                k, _, v = line.partition(':')
                headers[k.strip().lower()] = v.strip()

        # Body snippet (first 2000 chars)
        body_snippet = body_part[:2000]

        return status, headers, body_snippet, header_part

    except subprocess.TimeoutExpired:
        return None, {}, "", "TIMEOUT"
    except FileNotFoundError:
        return None, {}, "", "curl not found"
    except Exception as e:
        return None, {}, "", str(e)


def check_http_signs(body: str, headers_raw: str, signs: list) -> list:
    """Return list of matched fingerprint strings from body or headers."""
    combined = (body + " " + headers_raw).lower()
    return [s for s in signs if s.lower() in combined]


# ---------------------------------------------------------------------------
# Per-subdomain analysis
# ---------------------------------------------------------------------------

CONFIDENCE_MAP = {
    # (cname_matched_provider, http_signs_matched, status_is_4xx)
    (True,  True,  True):  ("HIGH",   "CNAME → known provider + HTTP fingerprint matched + 4xx response"),
    (True,  True,  False): ("MEDIUM", "CNAME → known provider + HTTP fingerprint matched (non-4xx)"),
    (True,  False, True):  ("MEDIUM", "CNAME → known provider + 4xx response (no fingerprint match)"),
    (True,  False, False): ("LOW",    "CNAME → known provider (no HTTP confirmation)"),
    (False, False, True):  ("LOW",    "NXDOMAIN or no CNAME + 4xx — possible dangling DNS"),
    (False, False, False): ("INFO",   "No CNAME match and no HTTP confirmation"),
}


def analyse_subdomain(subdomain: str, timeout: int, http_also: bool) -> dict:
    """Full CONF-10 analysis for one subdomain."""
    subdomain = subdomain.strip()
    result = {
        "subdomain":     subdomain,
        "cname_target":  None,
        "cname_raw":     "",
        "provider":      None,
        "provider_name": "N/A",
        "http_status":   None,
        "http_signs_matched": [],
        "verdict":       None,   # TAKEOVER_CANDIDATE / INVESTIGATE / CLEAN
        "confidence":    None,
        "confidence_reason": "",
        "notes":         "",
        "curl_raw_headers": "",
    }

    # Step 1: dig CNAME
    cname, cname_raw = dig_cname(subdomain)
    result["cname_target"] = cname
    result["cname_raw"]    = cname_raw

    # Step 2: match provider
    provider = match_provider(cname) if cname else None
    result["provider"]      = provider
    result["provider_name"] = provider["provider"] if provider else "No CNAME / NXDOMAIN"

    # Step 3: curl
    https_url = f"https://{subdomain}"
    status, headers, body, raw_headers = curl_probe(https_url, timeout)
    result["http_status"]       = status
    result["curl_raw_headers"]  = raw_headers

    if http_also and status is None:
        http_url = f"http://{subdomain}"
        status, headers, body, raw_headers = curl_probe(http_url, timeout)
        result["http_status"]      = status
        result["curl_raw_headers"] = raw_headers

    # Step 4: check HTTP fingerprints
    signs = provider["http_signs"] if provider else []
    matched = check_http_signs(body, raw_headers, signs)
    result["http_signs_matched"] = matched

    # Step 5: determine verdict
    cname_known    = provider is not None and provider["takeover"]
    signs_matched  = len(matched) > 0
    is_4xx         = status is not None and 400 <= status < 500

    conf_key = (cname_known, signs_matched, is_4xx)
    confidence, reason = CONFIDENCE_MAP.get(conf_key, ("INFO", "Insufficient data"))
    result["confidence"]        = confidence
    result["confidence_reason"] = reason

    if provider and provider["takeover"]:
        if signs_matched or is_4xx:
            result["verdict"] = "TAKEOVER_CANDIDATE"
            result["notes"]   = provider["notes"]
        else:
            result["verdict"] = "INVESTIGATE"
            result["notes"]   = provider["notes"] + " — HTTP response does not confirm unclaimed state; manual check required."
    elif is_4xx:
        result["verdict"] = "INVESTIGATE"
        result["notes"]   = "4xx response without CNAME match — possible dangling DNS or misconfiguration."
    else:
        result["verdict"] = "CLEAN"
        result["notes"]   = "No takeover indicators found."

    return result


# ---------------------------------------------------------------------------
# Subzy output parser
# ---------------------------------------------------------------------------

def parse_subzy_output(path: str) -> dict:
    """
    Parse subzy output (txt or md). Returns {subdomain: subzy_verdict} dict.
    Subzy typically outputs lines like:
      [VULNERABLE] sub.example.com - Service: GitHub Pages
      [NOT VULNERABLE] sub2.example.com
    """
    subzy_results = {}
    if not path or not os.path.exists(path):
        return subzy_results
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                m = re.match(r'\[(VULNERABLE|NOT VULNERABLE|INFO)\]\s+(\S+)', line, re.I)
                if m:
                    status = m.group(1).upper()
                    sub    = m.group(2).rstrip(',')
                    subzy_results[sub] = {"status": status, "raw": line}
    except Exception as e:
        print(f"[!] Could not parse subzy output {path}: {e}")
    return subzy_results


# ---------------------------------------------------------------------------
# dnsx output parser
# ---------------------------------------------------------------------------

def parse_dnsx_output(path: str) -> dict:
    """
    Parse dnsx -cname -resp output. Returns {subdomain: cname_from_dnsx} dict.
    dnsx output example:
      sub.example.com [1.2.3.4] [CNAME: something.github.io.]
    """
    dnsx_results = {}
    if not path or not os.path.exists(path):
        return dnsx_results
    try:
        with open(path) as f:
            for line in f:
                m_sub = re.match(r'(\S+)', line)
                m_cname = re.search(r'\[CNAME:\s*([^\]]+)\]', line, re.I)
                if m_sub:
                    sub = m_sub.group(1)
                    cname = m_cname.group(1).rstrip('.') if m_cname else None
                    dnsx_results[sub] = cname
    except Exception as e:
        print(f"[!] Could not parse dnsx output {path}: {e}")
    return dnsx_results


# ---------------------------------------------------------------------------
# Terminal summary printer
# ---------------------------------------------------------------------------

VERDICT_COLOURS = {
    "TAKEOVER_CANDIDATE": "\033[91m",  # red
    "INVESTIGATE":        "\033[93m",  # yellow
    "CLEAN":              "\033[92m",  # green
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def print_terminal_summary(results: list, domain: str):
    candidates = [r for r in results if r["verdict"] == "TAKEOVER_CANDIDATE"]
    investigate = [r for r in results if r["verdict"] == "INVESTIGATE"]
    clean       = [r for r in results if r["verdict"] == "CLEAN"]

    print(f"\n{'='*70}")
    print(f"{BOLD}CONF-10 — Subdomain Takeover Analysis — {domain}{RESET}")
    print(f"{'='*70}")
    print(f"  Subdomains analysed : {len(results)}")
    print(f"  {VERDICT_COLOURS['TAKEOVER_CANDIDATE']}TAKEOVER_CANDIDATE  : {len(candidates)}{RESET}")
    print(f"  {VERDICT_COLOURS['INVESTIGATE']}INVESTIGATE         : {len(investigate)}{RESET}")
    print(f"  {VERDICT_COLOURS['CLEAN']}CLEAN               : {len(clean)}{RESET}")
    print()

    if candidates:
        print(f"{BOLD}{'─'*70}")
        print(f"  TAKEOVER CANDIDATES")
        print(f"{'─'*70}{RESET}")
        for r in candidates:
            colour = VERDICT_COLOURS["TAKEOVER_CANDIDATE"]
            print(f"  {colour}[{r['confidence']}]{RESET} {r['subdomain']}")
            print(f"        CNAME  → {r['cname_target'] or 'N/A'}")
            print(f"        Provider: {r['provider_name']}")
            print(f"        HTTP {r['http_status'] or 'N/A'}  |  Fingerprints: {r['http_signs_matched'] or 'none'}")
            print(f"        {r['confidence_reason']}")
            print()

    if investigate:
        print(f"{BOLD}{'─'*70}")
        print(f"  INVESTIGATE (manual review needed)")
        print(f"{'─'*70}{RESET}")
        for r in investigate:
            colour = VERDICT_COLOURS["INVESTIGATE"]
            print(f"  {colour}[{r['confidence']}]{RESET} {r['subdomain']}")
            print(f"        CNAME  → {r['cname_target'] or 'N/A'}")
            print(f"        Provider: {r['provider_name']}")
            print(f"        HTTP {r['http_status'] or 'N/A'}")
            print()


# ---------------------------------------------------------------------------
# Markdown report writer
# ---------------------------------------------------------------------------

VERDICT_EMOJI = {
    "TAKEOVER_CANDIDATE": "🔴",
    "INVESTIGATE":        "🟡",
    "CLEAN":              "🟢",
}
CONFIDENCE_BADGE = {
    "HIGH":   "**HIGH**",
    "MEDIUM": "**MEDIUM**",
    "LOW":    "LOW",
    "INFO":   "INFO",
}


def write_findings_md(output_path: str, results: list, domain: str,
                      subzy_results: dict, dnsx_results: dict,
                      meta: dict):
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    candidates = [r for r in results if r["verdict"] == "TAKEOVER_CANDIDATE"]
    investigate = [r for r in results if r["verdict"] == "INVESTIGATE"]
    clean_count = sum(1 for r in results if r["verdict"] == "CLEAN")

    lines = []
    lines.append("# CONF-10 — Subdomain Takeover Analysis")
    lines.append("")
    lines.append(f"**Target domain:** `{domain}`  ")
    lines.append(f"**Generated:** {meta['generated']}  ")
    lines.append(f"**Subdomains analysed:** {len(results)}  ")
    lines.append("")

    # Summary table
    lines.append("## Summary")
    lines.append("")
    lines.append("| Verdict | Count |")
    lines.append("|---------|-------|")
    lines.append(f"| 🔴 TAKEOVER_CANDIDATE | {len(candidates)} |")
    lines.append(f"| 🟡 INVESTIGATE | {len(investigate)} |")
    lines.append(f"| 🟢 CLEAN | {clean_count} |")
    lines.append("")

    # Takeover candidates
    if candidates:
        lines.append("---")
        lines.append("")
        lines.append("## 🔴 Takeover Candidates")
        lines.append("")
        lines.append("> These subdomains show strong indicators of subdomain takeover risk.")
        lines.append("> Confirm manually before reporting — DNS propagation and transient errors")
        lines.append("> can produce false positives.")
        lines.append("")

        for r in candidates:
            lines.append(f"### `{r['subdomain']}`")
            lines.append("")
            lines.append(f"| Field | Value |")
            lines.append(f"|-------|-------|")
            lines.append(f"| Confidence | {CONFIDENCE_BADGE.get(r['confidence'], r['confidence'])} |")
            lines.append(f"| Provider | {r['provider_name']} |")
            lines.append(f"| CNAME Target | `{r['cname_target'] or 'N/A'}` |")
            lines.append(f"| HTTP Status | `{r['http_status'] or 'N/A'}` |")
            if r['http_signs_matched']:
                lines.append(f"| HTTP Fingerprints Matched | {', '.join(f'`{s}`' for s in r['http_signs_matched'])} |")
            # Subzy correlation
            sz = subzy_results.get(r['subdomain'])
            if sz:
                lines.append(f"| Subzy | `{sz['status']}` — {sz['raw']} |")
            # dnsx correlation
            dx = dnsx_results.get(r['subdomain'])
            if dx:
                lines.append(f"| dnsx CNAME | `{dx}` |")
            lines.append("")
            lines.append(f"**Assessment:** {r['confidence_reason']}")
            lines.append("")
            if r['notes']:
                lines.append(f"**Notes:** {r['notes']}")
                lines.append("")
            lines.append("**CNAME raw output:**")
            lines.append("```")
            lines.append(r['cname_raw'] or "(no output)")
            lines.append("```")
            lines.append("")
            if r['curl_raw_headers']:
                lines.append("**HTTP response headers:**")
                lines.append("```")
                lines.append(r['curl_raw_headers'][:1500])
                lines.append("```")
                lines.append("")
            lines.append("**Manual verification steps:**")
            lines.append("")
            lines.append(f"1. Confirm CNAME is still live:")
            lines.append(f"   ```")
            lines.append(f"   dig CNAME {r['subdomain']}")
            lines.append(f"   ```")
            lines.append(f"2. Attempt to register/claim the resource at `{r['cname_target'] or '<provider>'}` using the provider's UI.")
            lines.append(f"3. If claimed, serve a benign proof-of-concept page (your pentest firm domain) — confirm it resolves via `{r['subdomain']}`.")
            lines.append(f"4. Document and report before reverting or releasing the claim.")
            lines.append("")
            lines.append("---")
            lines.append("")

    # Investigate section
    if investigate:
        lines.append("## 🟡 Investigate (Manual Review Required)")
        lines.append("")
        for r in investigate:
            lines.append(f"### `{r['subdomain']}`")
            lines.append("")
            lines.append(f"| Field | Value |")
            lines.append(f"|-------|-------|")
            lines.append(f"| Confidence | {CONFIDENCE_BADGE.get(r['confidence'], r['confidence'])} |")
            lines.append(f"| Provider | {r['provider_name']} |")
            lines.append(f"| CNAME Target | `{r['cname_target'] or 'N/A'}` |")
            lines.append(f"| HTTP Status | `{r['http_status'] or 'N/A'}` |")
            sz = subzy_results.get(r['subdomain'])
            if sz:
                lines.append(f"| Subzy | `{sz['status']}` — {sz['raw']} |")
            lines.append("")
            lines.append(f"**Assessment:** {r['confidence_reason']}")
            if r['notes']:
                lines.append(f"  \n**Notes:** {r['notes']}")
            lines.append("")
            lines.append("---")
            lines.append("")

    # Tool outputs reference
    lines.append("## Tool Outputs Reference")
    lines.append("")
    for label, path in [
        ("subfinder", meta.get('subdomains_file', 'N/A')),
        ("dnsx",      meta.get('dnsx_file', 'N/A')),
        ("subzy",     meta.get('subzy_file', 'N/A')),
        ("dig CNAME", meta.get('dig_out', 'N/A')),
    ]:
        lines.append(f"- **{label}:** `{path}`")
    lines.append("")

    # Subzy summary if available
    if subzy_results:
        lines.append("### Subzy Results")
        lines.append("")
        vuln = [k for k, v in subzy_results.items() if v['status'] == 'VULNERABLE']
        lines.append(f"Subzy flagged **{len(vuln)}** subdomain(s) as VULNERABLE:")
        for sub in vuln:
            lines.append(f"- `{sub}` — {subzy_results[sub]['raw']}")
        lines.append("")

    with open(output_path, 'w') as f:
        f.write('\n'.join(lines))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description='CONF-10 Step 4: CNAME analysis, HTTP probe, and findings report'
    )
    p.add_argument(
        '-d', '--domain', required=True,
        help='Target domain (e.g. example.com) — used for labelling'
    )
    p.add_argument(
        '--subdomains', required=True,
        help='subfinder output file — one subdomain per line'
    )
    p.add_argument(
        '--dnsx',
        help='dnsx -cname -resp output file (optional)'
    )
    p.add_argument(
        '--subzy',
        help='subzy output file (optional, merged into report)'
    )
    p.add_argument(
        '--dig-out',
        default='/kali-tools/dig/dig_cname.txt',
        help='Path to write combined dig CNAME output (default: /kali-tools/dig/dig_cname.txt)'
    )
    p.add_argument(
        '-o', '--output',
        default='outputs/test_outputs/findings.md',
        help='Findings markdown (default: outputs/test_outputs/findings.md)'
    )
    p.add_argument(
        '--timeout', type=int, default=10,
        help='curl timeout per probe in seconds (default: 10)'
    )
    p.add_argument(
        '--concurrency', type=int, default=10,
        help='Parallel subdomain probes (default: 10)'
    )
    p.add_argument(
        '--http-also', action='store_true',
        help='Also probe http:// if https:// fails or times out'
    )
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    print("=" * 70)
    print(f"CONF-10 — Subdomain Takeover Analysis — {args.domain}")
    print("=" * 70)

    # Load subdomains
    try:
        with open(args.subdomains) as f:
            subdomains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"[!] Subdomains file not found: {args.subdomains}")
        sys.exit(1)

    if not subdomains:
        print("[!] No subdomains found in input file.")
        sys.exit(1)

    print(f"[*] Subdomains to analyse: {len(subdomains)}")

    # Load optional tool outputs
    subzy_results = parse_subzy_output(args.subzy)
    dnsx_results  = parse_dnsx_output(args.dnsx)
    if subzy_results:
        print(f"[*] subzy results loaded: {len(subzy_results)} entries")
    if dnsx_results:
        print(f"[*] dnsx results loaded: {len(dnsx_results)} entries")

    # Prepare dig output directory
    if args.dig_out:
        os.makedirs(os.path.dirname(os.path.abspath(args.dig_out)), exist_ok=True)

    print(f"[*] Running dig + curl with concurrency={args.concurrency} timeout={args.timeout}s")
    print()

    # Run analysis in parallel
    results = []
    dig_lines = []

    def probe(subdomain):
        r = analyse_subdomain(subdomain, args.timeout, args.http_also)
        # Accumulate dig output
        dig_lines.append(f"; {subdomain}")
        dig_lines.append(r['cname_raw'] or "(no output)")
        dig_lines.append("")
        return r

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futures = {ex.submit(probe, sub): sub for sub in subdomains}
        for future in concurrent.futures.as_completed(futures):
            r = future.result()
            results.append(r)
            v = r['verdict']
            colour = VERDICT_COLOURS.get(v, "")
            print(f"  {colour}[{v}]{RESET} {r['subdomain']} "
                  f"| CNAME: {r['cname_target'] or 'none'} "
                  f"| HTTP {r['http_status'] or 'N/A'} "
                  f"| {r['provider_name']}")

    # Sort: candidates first
    verdict_order = {"TAKEOVER_CANDIDATE": 0, "INVESTIGATE": 1, "CLEAN": 2}
    results.sort(key=lambda r: (verdict_order.get(r['verdict'], 9), r['subdomain']))

    # Write dig output
    if args.dig_out:
        with open(args.dig_out, 'w') as f:
            f.write('\n'.join(dig_lines))
        print(f"\n[*] dig CNAME output → {args.dig_out}")

    # Print terminal summary
    print_terminal_summary(results, args.domain)

    # Write findings MD
    meta = {
        'generated':      datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
        'subdomains_file': args.subdomains,
        'dnsx_file':      args.dnsx or 'N/A',
        'subzy_file':     args.subzy or 'N/A',
        'dig_out':        args.dig_out,
    }
    write_findings_md(args.output, results, args.domain,
                      subzy_results, dnsx_results, meta)
    print(f"\n[+] Findings written → {args.output}")

    # Final counts
    candidates = sum(1 for r in results if r['verdict'] == 'TAKEOVER_CANDIDATE')
    investigate = sum(1 for r in results if r['verdict'] == 'INVESTIGATE')
    print(f"\n{'='*70}")
    print("CONF-10 SUMMARY")
    print(f"{'='*70}")
    print(f"  Subdomains analysed    : {len(results)}")
    print(f"  Takeover candidates    : {candidates}")
    print(f"  Investigate            : {investigate}")
    print(f"  Findings report        : {args.output}")


if __name__ == "__main__":
    main()
