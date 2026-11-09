#!/usr/bin/env python3
"""
info8_orchestrator.py — WSTG-INFO-08 Web Application Framework Fingerprinting
Location: WSTG_Repository/01_Information_Gathering/WSTG-INFO-08/Utilities/python/info8_orchestrator.py

Pipeline:
  1. Parse Burp XML → extract unique domains + subdomain regex sweep
  2. Merge with optional domains file → deduplicated target list
  3. version_detection  — scan response headers/body for version/tech fingerprints
                          → Outputs/test_outputs/version_detection.md
  4. comment_extract    — pull HTML/JS/CSS/etc. comments from responses
                          → Outputs/test_outputs/comment_extract.md
  5. whatweb            — run `whatweb --color=never -v` against each target
                          → Outputs/test_outputs/whatweb.md
  6. nc banner grab     — raw HEAD probe on user-specified ports (--nc-ports)
                          → Outputs/test_outputs/nc.md

Usage:
    python info8_orchestrator.py --input <burp_export.xml>
                                 [--domains <extra_domains.txt>]
                                 [--target-domain <root> for subdomain regex]
                                 [--nc-ports 80,443,8080,8443]
                                 [--base <WSTG-INFO-08 root>]
                                 [--skip-version] [--skip-comments]
                                 [--skip-whatweb] [--skip-nc]
"""

import argparse
import base64
import re
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

# ---------------------------------------------------------------------------
# Repo paths
# ---------------------------------------------------------------------------
OUTPUT_DIR   = "Outputs/test_outputs"
DEFAULT_BASE = Path(__file__).resolve().parents[2]   # WSTG-INFO-08/

NC_PROBE        = b"HEAD / HTTP/1.0\r\n\r\n"
NC_TIMEOUT      = 5      # seconds per nc connection
WHATWEB_TIMEOUT = 60     # seconds per whatweb call


# ===========================================================================
#  SHARED BURP XML PARSER
# ===========================================================================

def decode_element(elem) -> str:
    """Return text from a Burp XML element, base64-decoding when flagged."""
    if elem is None:
        return ""
    raw = elem.text or ""
    if elem.attrib.get("base64", "false").lower() == "true":
        try:
            return base64.b64decode(raw).decode("utf-8", errors="replace")
        except Exception:
            return raw
    return raw


def _parse_http_block(raw: str) -> tuple[dict, str]:
    """Split raw HTTP message into (headers_dict, body_str)."""
    if not raw:
        return {}, ""
    sep = "\r\n\r\n" if "\r\n\r\n" in raw else "\n\n"
    parts = raw.split(sep, 1)
    header_block = parts[0]
    body = parts[1] if len(parts) > 1 else ""
    headers: dict[str, str] = {}
    for line in header_block.splitlines()[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()
    return headers, body


def parse_burp_xml(xml_path: Path) -> list[dict]:
    """
    Parse Burp Suite proxy export XML.
    Each item: url, method, request_headers, request_body,
                response_headers, response_body, domain
    """
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        sys.exit(f"[ERROR] Could not parse XML: {exc}")

    items = []
    for idx, item in enumerate(root.findall("item")):
        url    = (item.findtext("url") or "").strip()
        req    = decode_element(item.find("request"))
        resp   = decode_element(item.find("response"))

        # extract method from request first line
        method = "UNKNOWN"
        if req:
            first = req.splitlines()[0] if req.splitlines() else ""
            method = first.split(" ")[0] if " " in first else "UNKNOWN"

        rq_headers, rq_body = _parse_http_block(req)
        rs_headers, rs_body = _parse_http_block(resp)

        items.append({
            "index":            idx,
            "url":              url,
            "method":           method,
            "domain":           urlparse(url).netloc if url else "",
            "request_headers":  rq_headers,
            "request_body":     rq_body,
            "response_headers": rs_headers,
            "response_body":    rs_body,
        })
    return items


# ===========================================================================
#  TARGET EXTRACTION — domains + subdomain sweep from Burp XML
#  (subdomain_seeker logic from INFO-04, adapted)
# ===========================================================================

def _build_subdomain_pattern(root_domain: str):
    escaped = re.escape(root_domain)
    return re.compile(
        r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + escaped,
        re.IGNORECASE,
    )


def extract_targets(items: list[dict], root_domain: str | None,
                    extra_domains_path: Path | None) -> list[str]:
    """
    Build deduplicated target list:
      - base domains from Burp XML URLs
      - subdomains found by regex in response bodies (when --target-domain set)
      - domains from extra file
    Returns sorted list of unique hostnames (no scheme, no path).
    """
    targets: set[str] = set()

    # 1. base domains from item URLs
    for item in items:
        d = item["domain"]
        if d:
            # strip port if present
            targets.add(d.split(":")[0])

    # 2. subdomain sweep across response bodies
    if root_domain:
        pattern = _build_subdomain_pattern(root_domain)
        for item in items:
            for text in (item["response_body"], item["request_body"]):
                for m in pattern.finditer(text or ""):
                    host = m.group(0).lower()
                    targets.add(host)

    # 3. extra domains file
    if extra_domains_path and extra_domains_path.is_file():
        with extra_domains_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.add(line.lower())

    return sorted(targets)


# ===========================================================================
#  MODULE 1 — VERSION / TECH DETECTOR
#  (same extraction as INFO-05 — exact same logic)
# ===========================================================================

VERSION_PATTERNS = [
    r'[vV]ersion["\': ]+(\d+\.\d+(?:\.\d+)?)',
    r'[vV]er["\': ]+(\d+\.\d+(?:\.\d+)?)',
    r'[vV](\d+\.\d+(?:\.\d+)?)',
    r'(?:^|[^a-zA-Z0-9.])(\d+\.\d+\.\d+)(?:[^a-zA-Z0-9]|$)',
    r'(?:^|[^a-zA-Z0-9.])(\d+\.\d+)(?:[^a-zA-Z0-9]|$)',
    r'[bB]uild["\': ]+([0-9a-zA-Z._-]+)',
    r'[rR]elease["\': ]+([0-9a-zA-Z._-]+)',
]

SERVER_INFO_HEADERS = {
    "server", "x-powered-by", "x-aspnet-version", "x-runtime",
    "x-version", "x-generator", "x-ua-compatible",
}

TECH_FINGERPRINT_PATTERNS = [
    r'(?i)<script[^>]*src=["\'][^"\']*(?:jquery|react|angular|vue|backbone|ember|bootstrap)[^"\']*\.js["\']',
    r'(?i)<script[^>]*src=["\'][^"\']*cloudflare[^"\']*\.js["\']',
    r'(?i)<script[^>]*src=["\'][^"\']*akamai[^"\']*\.js["\']',
    r'(?i)<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
    r'(?i)<meta[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']generator["\']',
    r'(?i)wp-content', r'(?i)wp-includes', r'(?i)Drupal\.settings', r'(?i)Joomla!',
    r'(?i)<!--[^>]*wordpress[^>]*-->', r'(?i)<!--[^>]*drupal[^>]*-->',
    r'(?i)<!--[^>]*joomla[^>]*-->', r'(?i)<!--[^>]*sitecore[^>]*-->',
    r'(?i)\.asp(?:x)?', r'(?i)\.jsp', r'(?i)\.php', r'(?i)\.cgi',
    r'(?i)Laravel', r'(?i)Django', r'(?i)Rails', r'(?i)Express', r'(?i)Symfony',
]

KNOWN_VULNERABILITIES = {
    "Apache":        {"2.4.49": ["CVE-2021-41773", "Path Traversal"],
                      "2.4.50": ["CVE-2021-42013", "Path Traversal"]},
    "Nginx":         {"1.20.0": ["CVE-2021-23017", "Heap Buffer Overflow"]},
    "PHP":           {"7.4.11": ["CVE-2020-7069", "Type Confusion"]},
    "WordPress":     {"5.7.0":  ["CVE-2021-29447", "XXE Vulnerability"]},
    "Drupal":        {"8.9.0":  ["CVE-2020-13666", "CSRF Vulnerability"]},
    "OpenSSL":       {"1.0.1":  ["CVE-2014-0160", "Heartbleed"],
                      "1.0.2":  ["CVE-2016-0800", "DROWN"]},
    "Apache Struts": {"2.5.12": ["CVE-2017-5638", "RCE"]},
}

TECH_PATTERN_MAP = {
    "jquery": "jQuery", "react": "React", "angular": "Angular",
    "vue": "Vue.js", "bootstrap": "Bootstrap",
    "wordpress": "WordPress", "wp-": "WordPress",
    "drupal": "Drupal", "joomla": "Joomla",
    "asp": "ASP.NET", "jsp": "JSP", "php": "PHP",
    "cloudflare": "Cloudflare", "akamai": "Akamai",
    "laravel": "Laravel", "django": "Django",
    "rails": "Ruby on Rails", "express": "Express.js",
    "symfony": "Symfony",
}

COMMON_TECHS = [
    "Apache", "Nginx", "IIS", "Tomcat", "PHP", "MySQL", "MariaDB",
    "WordPress", "Drupal", "Joomla", "jQuery", "React", "Angular",
    "Vue", "Bootstrap", "Laravel", "Symfony", "Django", "Flask",
    "Express", "Node.js", "ASP.NET", "Ruby", "Rails", "Python",
]


def _get_context(text: str, match_text: str, size: int = 50) -> str:
    pos = text.find(match_text)
    if pos == -1:
        return ""
    return text[max(0, pos - size): pos + len(match_text) + size]


def _is_version_vulnerable(detected: str, vuln: str) -> bool:
    try:
        dp = [int(p) for p in detected.split(".")]
        vp = [int(p) for p in vuln.split(".")]
        while len(dp) < len(vp): dp.append(0)
        while len(vp) < len(dp): vp.append(0)
        for d, v in zip(dp, vp):
            if d < v: return False
            if d > v: return True
        return True
    except Exception:
        return False


def _check_vulnerabilities(technologies: dict) -> list[dict]:
    vulns = []
    for _cat, techs in technologies.items():
        for tech in techs:
            if not isinstance(tech, dict):
                continue
            name    = tech.get("name", "")
            version = tech.get("version", "")
            if not (name and version) or name not in KNOWN_VULNERABILITIES:
                continue
            for vuln_ver, info in KNOWN_VULNERABILITIES[name].items():
                if version == vuln_ver:
                    vulns.append({"technology": name, "version": version,
                                  "cve_id": info[0], "description": info[1],
                                  "confidence": "high"})
                elif _is_version_vulnerable(version, vuln_ver):
                    vulns.append({"technology": name, "version": version,
                                  "vulnerable_version": vuln_ver,
                                  "cve_id": info[0], "description": info[1],
                                  "confidence": "medium"})
    return vulns


def analyze_version_item(item: dict) -> dict | None:
    """Run version/tech detection on one Burp item. Returns result or None."""
    rs_headers = item["response_headers"]
    rs_body    = item["response_body"]

    technologies: dict[str, list] = {}
    version_findings: list[dict]  = []
    seen: set[tuple] = set()

    def add_finding(category, pattern, match, location):
        key = (match, location)
        if key in seen: return
        seen.add(key)
        version_findings.append({"category": category, "pattern": pattern,
                                  "match": match, "location": location})

    def add_tech(bucket, name, extra: dict | None = None):
        if bucket not in technologies:
            technologies[bucket] = []
        entry = {"name": name}
        if extra: entry.update(extra)
        for existing in technologies[bucket]:
            if isinstance(existing, dict) and existing.get("name") == name:
                if extra and "version" in extra and "version" not in existing:
                    existing["version"] = extra["version"]
                return
        technologies[bucket].append(entry)

    # headers
    for hname, hval in rs_headers.items():
        hl = hname.lower()
        if hl in SERVER_INFO_HEADERS or hl.startswith("x-"):
            add_finding("server_info", hname, hval, f"header:{hname}")
            if hl == "server":
                parts = hval.split()
                add_tech("server", parts[0].rstrip("/").split("/")[0] if parts else hval)
            elif hl == "x-powered-by":
                parts = hval.split()
                add_tech("platform", parts[0] if parts else hval)
        for pat in VERSION_PATTERNS:
            for m in re.findall(pat, hval):
                add_finding("version", pat, m, f"header:{hname}")
                add_tech("server" if hl == "server" else "detected",
                         hname, {"version": m})

    # body
    if rs_body:
        for pat in VERSION_PATTERNS:
            for m in re.findall(pat, rs_body):
                add_finding("version", pat, m, "body")
                ctx = _get_context(rs_body, m)
                for tech in COMMON_TECHS:
                    if tech.lower() in ctx.lower():
                        add_tech("detected", tech, {"version": m, "confidence": "medium"})

        for pat in TECH_FINGERPRINT_PATTERNS:
            matches = re.findall(pat, rs_body)
            if matches:
                raw = matches[0] if isinstance(matches[0], str) else (matches[0][0] if matches[0] else "")
                if not raw:
                    mo = re.search(pat, rs_body)
                    raw = mo.group(0) if mo else ""
                add_finding("technology", pat, raw, "body")
                pat_l = pat.lower()
                for key, tech_name in TECH_PATTERN_MAP.items():
                    if key in pat_l:
                        ver_m = re.search(r'(\d+\.\d+(?:\.\d+)?)', raw)
                        add_tech("fingerprinted", tech_name,
                                 {"version": ver_m.group(1)} if ver_m else None)
                        break

    if not version_findings and not technologies:
        return None

    return {
        "url":                      item["url"],
        "technologies":             technologies,
        "version_findings":         version_findings,
        "potential_vulnerabilities": _check_vulnerabilities(technologies),
    }


def run_version_detection(items: list[dict], out_path: Path) -> None:
    print(f"\n[VERSION DETECTION] Scanning {len(items)} item(s)...")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    results = []
    for item in items:
        r = analyze_version_item(item)
        if r:
            results.append(r)

    with out_path.open("w", encoding="utf-8") as fh:
        fh.write(f"# WSTG-INFO-08 — Version & Technology Detection\n\n")
        fh.write(f"**Generated:** {datetime.now(timezone.utc).isoformat()}  \n")
        fh.write(f"**Items scanned:** {len(items)}  \n")
        fh.write(f"**Items with findings:** {len(results)}  \n\n---\n\n")

        if not results:
            fh.write("_No version/technology findings._\n")
        else:
            for r in results:
                fh.write(f"## {r['url']}\n\n")

                # technologies table
                if r["technologies"]:
                    fh.write("### Technologies\n\n")
                    fh.write("| Bucket | Name | Version |\n|---|---|---|\n")
                    for bucket, techs in r["technologies"].items():
                        for t in techs:
                            name = t.get("name", str(t)) if isinstance(t, dict) else str(t)
                            ver  = t.get("version", "—")  if isinstance(t, dict) else "—"
                            fh.write(f"| {bucket} | {name} | {ver} |\n")
                    fh.write("\n")

                # version findings
                if r["version_findings"]:
                    fh.write("### Version Findings\n\n")
                    fh.write("| Category | Match | Location |\n|---|---|---|\n")
                    for f in r["version_findings"]:
                        fh.write(f"| {f['category']} | `{f['match']}` | {f['location']} |\n")
                    fh.write("\n")

                # CVEs
                if r["potential_vulnerabilities"]:
                    fh.write("### ⚠️ Potential Vulnerabilities\n\n")
                    fh.write("| Technology | Version | CVE | Description | Confidence |\n|---|---|---|---|---|\n")
                    for v in r["potential_vulnerabilities"]:
                        fh.write(f"| {v['technology']} | {v['version']} | {v['cve_id']} "
                                 f"| {v['description']} | {v['confidence']} |\n")
                    fh.write("\n")

                fh.write("---\n\n")

    print(f"  [+] → {out_path}")


# ===========================================================================
#  MODULE 2 — COMMENT EXTRACTOR
#  (CommentExtractor class + analyze_comments logic, same extraction as given)
# ===========================================================================

class CommentExtractor:
    PATTERNS = {
        "html": [
            (r'<!--(.*?)-->', "HTML Comment"),
            (r'<!--(.*?)--!>', "HTML Comment (variant)"),
        ],
        "javascript": [
            (r'//([^\n\r]*)', "JS Single-line"),
            (r'/\*(.*?)\*/', "JS Multi-line"),
        ],
        "css": [
            (r'/\*(.*?)\*/', "CSS Comment"),
        ],
        "jsp": [
            (r'<%--.*?--%>', "JSP Comment"),
        ],
        "asp": [
            (r"<%'[^\n\r]*%>",   "ASP Comment (VB)"),
            (r'<%//[^\n\r]*%>',  "ASP Comment (C#)"),
            (r'<%/\*.*?\*/%>',   "ASP Multi-line"),
        ],
        "php": [
            (r'<\?php\s*//[^\n\r]*\?>', "PHP Single-line"),
            (r'<\?php\s*/\*.*?\*/\s*\?>', "PHP Multi-line"),
            (r'#[^\n\r]*', "PHP/Shell Comment"),
        ],
        "xml": [
            (r'<!--(.*?)-->', "XML Comment"),
        ],
        "sql": [
            (r'--[^\n\r]*', "SQL Comment"),
            (r'/\*(.*?)\*/', "SQL Multi-line"),
        ],
        "python": [
            (r'#[^\n\r]*', "Python Comment"),
            (r'""".*?"""', "Python Docstring"),
            (r"'''.*?'''", "Python Docstring (single)"),
        ],
    }

    INTERESTING_CATEGORIES = {"Potential Sensitive", "TODO/FIXME", "Debug/Test", "Hack/Workaround"}

    def __init__(self):
        self.compiled: dict[str, list[tuple]] = {}
        for lang, patterns in self.PATTERNS.items():
            self.compiled[lang] = [
                (re.compile(pat, re.DOTALL | re.IGNORECASE), ctype)
                for pat, ctype in patterns
            ]

    def extract(self, text: str) -> dict[str, list[str]]:
        found: dict[str, list[str]] = defaultdict(list)
        for lang, patterns in self.compiled.items():
            for compiled, ctype in patterns:
                for m in compiled.findall(text):
                    cleaned = (m if isinstance(m, str) else str(m)).strip()
                    if cleaned:
                        found[ctype].append(cleaned)
        return found

    @staticmethod
    def categorize(comment: str) -> str:
        cl = comment.lower()
        if "todo" in cl or "fixme" in cl:              return "TODO/FIXME"
        if "debug" in cl or "test" in cl:              return "Debug/Test"
        if "deprecated" in cl or "obsolete" in cl:    return "Deprecated"
        if "warning" in cl or "caution" in cl:        return "Warning"
        if "note" in cl or "nb:" in cl:               return "Note"
        if "hack" in cl or "workaround" in cl:        return "Hack/Workaround"
        if "copyright" in cl or "license" in cl:      return "Copyright/License"
        if "author" in cl or "created" in cl:         return "Metadata"
        if re.search(r'v\d+\.\d+', cl) or "version" in cl: return "Version Info"
        if re.search(r'\b(api|key|token|secret|password)\b', cl): return "Potential Sensitive"
        if re.search(r'\b(url|http|endpoint|path)\b', cl):        return "URL/Endpoint"
        return "General"


def run_comment_extraction(items: list[dict], out_path: Path) -> None:
    print(f"\n[COMMENT EXTRACTION] Scanning {len(items)} item(s)...")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    extractor = CommentExtractor()
    all_details:  list[dict]       = []
    interesting:  list[dict]       = []
    by_category:  dict[str, list]  = defaultdict(list)
    by_type:      dict[str, list]  = defaultdict(list)
    unique:       set[str]         = set()
    responses_with = 0

    for item in items:
        comments = extractor.extract(item["response_body"])
        if not comments:
            continue
        responses_with += 1
        for ctype, clist in comments.items():
            for raw in clist:
                cleaned = " ".join(raw.split())[:500]
                if not cleaned:
                    continue
                category = extractor.categorize(cleaned)
                unique.add(cleaned)
                by_type[ctype].append(cleaned)
                by_category[category].append(cleaned)
                detail = {
                    "index":    item["index"],
                    "url":      item["url"],
                    "method":   item["method"],
                    "domain":   item["domain"],
                    "type":     ctype,
                    "category": category,
                    "comment":  cleaned,
                }
                all_details.append(detail)
                if category in extractor.INTERESTING_CATEGORIES:
                    interesting.append(detail)

    with out_path.open("w", encoding="utf-8") as fh:
        fh.write(f"# WSTG-INFO-08 — Comment Extraction\n\n")
        fh.write(f"**Generated:** {datetime.now(timezone.utc).isoformat()}  \n")
        fh.write(f"**Items scanned:** {len(items)}  \n")
        fh.write(f"**Responses with comments:** {responses_with}  \n")
        fh.write(f"**Total comments:** {len(all_details)}  \n")
        fh.write(f"**Unique comments:** {len(unique)}  \n\n---\n\n")

        # Interesting findings first
        if interesting:
            fh.write(f"## ⚠️ Interesting Findings ({len(interesting)})\n\n")
            fh.write("| Category | Type | URL | Comment (truncated) |\n|---|---|---|---|\n")
            for f in interesting:
                snippet = f["comment"][:120].replace("|", "\\|")
                fh.write(f"| {f['category']} | {f['type']} | {f['url']} | `{snippet}` |\n")
            fh.write("\n---\n\n")

        # By category
        fh.write("## Comments by Category\n\n")
        for cat in sorted(by_category):
            items_in_cat = by_category[cat]
            unique_in_cat = list(dict.fromkeys(items_in_cat))  # preserve order, dedup
            fh.write(f"### {cat} ({len(items_in_cat)} total, {len(unique_in_cat)} unique)\n\n")
            for i, c in enumerate(unique_in_cat[:10], 1):
                fh.write(f"{i}. `{c[:200]}`\n")
            if len(unique_in_cat) > 10:
                fh.write(f"_… and {len(unique_in_cat) - 10} more_\n")
            fh.write("\n")

        fh.write("---\n\n")

        # Detailed list (all)
        fh.write(f"## Detailed Comment List\n\n")
        fh.write("| # | URL | Type | Category | Comment |\n|---|---|---|---|---|\n")
        for i, d in enumerate(all_details, 1):
            snippet = d["comment"][:150].replace("|", "\\|")
            fh.write(f"| {i} | {d['url']} | {d['type']} | {d['category']} | `{snippet}` |\n")

    print(f"  [+] → {out_path}")


# ===========================================================================
#  MODULE 3 — WHATWEB
# ===========================================================================

def run_whatweb(targets: list[str], out_path: Path) -> None:
    print(f"\n[WHATWEB] Running against {len(targets)} target(s)...")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", encoding="utf-8") as fh:
        fh.write(f"# WSTG-INFO-08 — WhatWeb Fingerprinting\n\n")
        fh.write(f"**Generated:** {datetime.now(timezone.utc).isoformat()}  \n")
        fh.write(f"**Targets:** {len(targets)}  \n\n---\n\n")

        for target in targets:
            url = target if target.startswith(("http://", "https://")) else f"http://{target}"
            cmd = ["whatweb", "--color=never", "-v", url]
            print(f"  [>] whatweb {url}")

            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=WHATWEB_TIMEOUT
                )
                stdout = proc.stdout
                stderr = proc.stderr
                rc     = proc.returncode
            except FileNotFoundError:
                stdout, stderr, rc = "", "[!] whatweb not found on PATH", 127
            except subprocess.TimeoutExpired:
                stdout, stderr, rc = "", f"[!] Timed out after {WHATWEB_TIMEOUT}s", 1

            status = "✅ OK" if rc == 0 else f"❌ rc={rc}"
            fh.write(f"## {target}\n\n")
            fh.write(f"**Command:** `{' '.join(cmd)}`  \n")
            fh.write(f"**Status:** {status}  \n\n")
            fh.write("```\n")
            fh.write((stdout.strip() or "(no output)") + "\n")
            fh.write("```\n\n")
            if stderr.strip():
                fh.write(f"**stderr:**\n```\n{stderr.strip()}\n```\n\n")
            fh.write("---\n\n")

    print(f"  [+] → {out_path}")


# ===========================================================================
#  MODULE 4 — NC BANNER GRAB
# ===========================================================================

def _nc_banner(host: str, port: int) -> tuple[str, int]:
    """
    Send HEAD probe via nc subprocess, return (output, returncode).
    Uses `nc -w <timeout> <host> <port>` with stdin piped.
    """
    cmd = ["nc", "-w", str(NC_TIMEOUT), host, str(port)]
    try:
        proc = subprocess.run(
            cmd,
            input=NC_PROBE,
            capture_output=True,
            timeout=NC_TIMEOUT + 2,
        )
        output = proc.stdout.decode("utf-8", errors="replace")
        if not output:
            output = proc.stderr.decode("utf-8", errors="replace")
        return output, proc.returncode
    except FileNotFoundError:
        return "[!] nc not found on PATH", 127
    except subprocess.TimeoutExpired:
        return f"[!] Timed out after {NC_TIMEOUT}s", 1
    except Exception as exc:
        return f"[!] Error: {exc}", 1


def run_nc(targets: list[str], ports: list[int], out_path: Path) -> None:
    print(f"\n[NC BANNER GRAB] {len(targets)} target(s) × {len(ports)} port(s)...")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", encoding="utf-8") as fh:
        fh.write(f"# WSTG-INFO-08 — nc Banner Grab\n\n")
        fh.write(f"**Generated:** {datetime.now(timezone.utc).isoformat()}  \n")
        fh.write(f"**Targets:** {len(targets)}  \n")
        fh.write(f"**Ports:** {', '.join(str(p) for p in ports)}  \n")
        fh.write(f"**Probe:** `HEAD / HTTP/1.0\\r\\n\\r\\n`  \n\n---\n\n")

        for target in targets:
            # strip scheme if user included it
            host = target.replace("https://", "").replace("http://", "").split("/")[0]
            fh.write(f"## {host}\n\n")

            for port in ports:
                print(f"  [>] nc -w {NC_TIMEOUT} {host} {port}")
                banner, rc = _nc_banner(host, port)
                status = "✅" if rc == 0 else "❌"

                fh.write(f"### Port {port}  {status}\n\n")
                fh.write("```\n")
                fh.write((banner.strip() or "(no response)") + "\n")
                fh.write("```\n\n")

            fh.write("---\n\n")

    print(f"  [+] → {out_path}")


# ===========================================================================
#  CLI
# ===========================================================================

def parse_args():
    p = argparse.ArgumentParser(
        prog="info8_orchestrator.py",
        description="WSTG-INFO-08 — Web Application Framework Fingerprinting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--input", "-i", required=True,
                   help="Burp Suite proxy export XML.")
    p.add_argument("--domains",
                   help="Extra domains file to merge with XML-extracted targets (one per line).")
    p.add_argument("--target-domain",
                   help="Root domain for subdomain regex sweep across Burp responses "
                        "(e.g. example.com). Enables subdomain discovery.")
    p.add_argument("--nc-ports", default="",
                   help="CSV list of ports for nc banner grab (e.g. 80,443,8080,8443). "
                        "Omit or leave empty to skip nc.")
    p.add_argument("--base", default=None,
                   help="WSTG-INFO-08 root directory. Defaults to two levels above this script.")
    p.add_argument("--skip-version",  action="store_true", help="Skip version detection.")
    p.add_argument("--skip-comments", action="store_true", help="Skip comment extraction.")
    p.add_argument("--skip-whatweb",  action="store_true", help="Skip whatweb.")
    p.add_argument("--skip-nc",       action="store_true", help="Skip nc banner grab.")
    return p.parse_args()


def ts() -> str:
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def main():
    args     = parse_args()
    base     = Path(args.base).resolve() if args.base else DEFAULT_BASE
    out_base = base / OUTPUT_DIR
    xml_path = Path(args.input).resolve()

    if not xml_path.is_file():
        sys.exit(f"[ERROR] Input not found: {xml_path}")

    print(f"\n{'='*60}")
    print(f"  WSTG-INFO-08 — Framework Fingerprinting Orchestrator")
    print(f"  Input : {xml_path}")
    print(f"  Base  : {base}")
    print(f"{'='*60}")

    # ── Parse XML ─────────────────────────────────────────────────────────
    print("\n[*] Parsing Burp XML...")
    items = parse_burp_xml(xml_path)
    if not items:
        sys.exit("[ERROR] No items found in XML.")
    print(f"  [+] {len(items)} item(s) loaded.")

    # ── Extract targets ────────────────────────────────────────────────────
    extra_domains = Path(args.domains).resolve() if args.domains else None
    targets = extract_targets(items, args.target_domain, extra_domains)
    print(f"  [+] {len(targets)} unique target(s): {', '.join(targets[:5])}"
          + (" …" if len(targets) > 5 else ""))

    # ── Parse nc ports ────────────────────────────────────────────────────
    nc_ports: list[int] = []
    if args.nc_ports:
        for p in args.nc_ports.split(","):
            p = p.strip()
            if p.isdigit():
                nc_ports.append(int(p))
            else:
                print(f"  [!] Ignoring invalid port: {p!r}")

    # ── Run pipeline ──────────────────────────────────────────────────────
    stamp = ts()

    if not args.skip_version:
        run_version_detection(items, out_base / "version_detection.md")

    if not args.skip_comments:
        run_comment_extraction(items, out_base / "comment_extract.md")

    if not args.skip_whatweb:
        if targets:
            run_whatweb(targets, out_base / "whatweb.md")
        else:
            print("\n[WHATWEB] No targets found — skipping.")

    if not args.skip_nc:
        if nc_ports and targets:
            run_nc(targets, nc_ports, out_base / "nc.md")
        elif not nc_ports:
            print("\n[NC] No --nc-ports specified — skipping.")
        else:
            print("\n[NC] No targets found — skipping.")

    print(f"\n{'='*60}")
    print("  WSTG-INFO-08 Complete")
    print(f"  Outputs → {out_base}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
