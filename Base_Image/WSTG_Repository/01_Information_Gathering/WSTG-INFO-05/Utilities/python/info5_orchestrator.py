#!/usr/bin/env python3
"""
info5_orchestrator.py — WSTG-INFO-05 Web Page Content Information Leakage
Location: WSTG_Repository/01_Information_Gathering/WSTG-INFO-05/Utilities/python/info5_orchestrator.py

Reads a Burp Suite proxy export XML and runs three analysis passes over every
request/response item:

  1. VERSION INFO   — version strings, server tech, CVE correlation
                      (logic from version_detector module)
  2. SENSITIVE INFO — API keys, tokens, passwords, PII, credit cards
                      (logic from sensitive_info module)
  3. PATHS          — interesting file paths, directories, extensions
                      (logic from path_finder module)

Output:
    Outputs/test_outputs/info5_leakage/leakage_<ts>.json

Usage:
    python info5_orchestrator.py --input <burp_export.xml>
                                 [--base <WSTG-INFO-05 root>]
                                 [--output <explicit output path>]
"""

import argparse
import base64
import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urljoin

# ---------------------------------------------------------------------------
# Repo paths
# ---------------------------------------------------------------------------
OUTPUT_SUBDIR  = "Outputs/test_outputs/info5_leakage"
DEFAULT_BASE   = Path(__file__).resolve().parents[2]   # WSTG-INFO-05/


# ===========================================================================
#  BURP XML PARSING
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
    """
    Split a raw HTTP message (request or response) into
    (headers_dict, body_str).
    """
    if not raw:
        return {}, ""
    parts = raw.split("\r\n\r\n", 1) if "\r\n\r\n" in raw else raw.split("\n\n", 1)
    header_block = parts[0]
    body = parts[1] if len(parts) > 1 else ""
    headers: dict[str, str] = {}
    for line in header_block.splitlines()[1:]:   # skip request/status line
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()
    return headers, body


def parse_burp_xml(xml_path: Path) -> list[dict]:
    """
    Parse a Burp Suite proxy XML export.
    Returns a list of items, each with:
        url, request_headers, request_body, response_headers, response_body
    """
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        sys.exit(f"[ERROR] Could not parse XML: {exc}")

    items = []
    for item in root.findall("item"):
        url   = (item.findtext("url") or "").strip()
        req   = decode_element(item.find("request"))
        resp  = decode_element(item.find("response"))

        req_headers,  req_body  = _parse_http_block(req)
        resp_headers, resp_body = _parse_http_block(resp)

        items.append({
            "url":              url,
            "request_headers":  req_headers,
            "request_body":     req_body,
            "response_headers": resp_headers,
            "response_body":    resp_body,
        })
    return items


# ===========================================================================
#  MODULE 1 — VERSION / TECHNOLOGY DETECTOR
#  Extracted from version_detector module (version.py)
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
    r'(?i)wp-content',
    r'(?i)wp-includes',
    r'(?i)Drupal\.settings',
    r'(?i)Joomla!',
    r'(?i)<!--[^>]*wordpress[^>]*-->',
    r'(?i)<!--[^>]*drupal[^>]*-->',
    r'(?i)<!--[^>]*joomla[^>]*-->',
    r'(?i)<!--[^>]*sitecore[^>]*-->',
    r'(?i)\.asp(?:x)?',
    r'(?i)\.jsp',
    r'(?i)\.php',
    r'(?i)\.cgi',
    r'(?i)Laravel',
    r'(?i)Django',
    r'(?i)Rails',
    r'(?i)Express',
    r'(?i)Symfony',
]

KNOWN_VULNERABILITIES = {
    "Apache": {
        "2.4.49": ["CVE-2021-41773", "Path Traversal Vulnerability"],
        "2.4.50": ["CVE-2021-42013", "Path Traversal Vulnerability"],
    },
    "Nginx": {
        "1.20.0": ["CVE-2021-23017", "Heap Buffer Overflow"],
    },
    "PHP": {
        "7.4.11": ["CVE-2020-7069", "Type Confusion Vulnerability"],
    },
    "WordPress": {
        "5.7.0": ["CVE-2021-29447", "XXE Vulnerability"],
    },
    "Drupal": {
        "8.9.0": ["CVE-2020-13666", "CSRF Vulnerability"],
    },
    "OpenSSL": {
        "1.0.1": ["CVE-2014-0160", "Heartbleed Vulnerability"],
        "1.0.2": ["CVE-2016-0800", "DROWN Vulnerability"],
    },
    "Apache Struts": {
        "2.5.12": ["CVE-2017-5638", "Remote Code Execution"],
    },
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
            if not (name and version):
                continue
            if name in KNOWN_VULNERABILITIES:
                for vuln_ver, info in KNOWN_VULNERABILITIES[name].items():
                    if version == vuln_ver:
                        vulns.append({
                            "technology":  name,
                            "version":     version,
                            "cve_id":      info[0],
                            "description": info[1],
                            "confidence":  "high",
                        })
                    elif _is_version_vulnerable(version, vuln_ver):
                        vulns.append({
                            "technology":        name,
                            "version":           version,
                            "vulnerable_version": vuln_ver,
                            "cve_id":            info[0],
                            "description":       info[1],
                            "confidence":        "medium",
                        })
    return vulns


def analyze_version(url: str, resp_headers: dict, resp_body: str) -> dict:
    result = {
        "technologies":           {},
        "version_findings":       [],
        "potential_vulnerabilities": [],
    }
    seen: set[tuple] = set()

    def add_finding(category, pattern, match, location):
        key = (match, location)
        if key in seen:
            return
        seen.add(key)
        result["version_findings"].append({
            "category": category, "pattern": pattern,
            "match": match, "location": location,
        })

    def add_tech(bucket, name, extra: dict | None = None):
        if bucket not in result["technologies"]:
            result["technologies"][bucket] = []
        entry = {"name": name}
        if extra:
            entry.update(extra)
        for existing in result["technologies"][bucket]:
            if isinstance(existing, dict) and existing.get("name") == name:
                if extra and "version" in extra and "version" not in existing:
                    existing["version"] = extra["version"]
                return
        result["technologies"][bucket].append(entry)

    # ── headers ──────────────────────────────────────────────────────────────
    for hname, hval in resp_headers.items():
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

    # ── body ─────────────────────────────────────────────────────────────────
    if resp_body:
        for pat in VERSION_PATTERNS:
            for m in re.findall(pat, resp_body):
                add_finding("version", pat, m, "body")
                ctx = _get_context(resp_body, m)
                for tech in COMMON_TECHS:
                    if tech.lower() in ctx.lower():
                        add_tech("detected", tech, {"version": m, "confidence": "medium"})

        for pat in TECH_FINGERPRINT_PATTERNS:
            matches = re.findall(pat, resp_body)
            if matches:
                raw = matches[0] if isinstance(matches[0], str) else (matches[0][0] if matches[0] else "")
                if not raw:
                    m = re.search(pat, resp_body)
                    raw = m.group(0) if m else ""
                add_finding("technology", pat, raw, "body")
                pat_l = pat.lower()
                for key, tech_name in TECH_PATTERN_MAP.items():
                    if key in pat_l:
                        ver_m = re.search(r'(\d+\.\d+(?:\.\d+)?)', raw)
                        add_tech("fingerprinted", tech_name,
                                 {"version": ver_m.group(1)} if ver_m else None)
                        break

    result["potential_vulnerabilities"] = _check_vulnerabilities(result["technologies"])
    return result


# ===========================================================================
#  MODULE 2 — SENSITIVE INFORMATION DETECTOR
#  Extracted from sensitive_info module (sensitive_infoV2.py)
# ===========================================================================

SENSITIVE_PATTERNS: dict[str, list[str]] = {
    "api_keys": [
        r'(?i)(api[_-]?key|apikey|api[_-]?token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{16,})["\'&]?',
        r'(?i)AKIA[0-9A-Z]{16}',
        r'(?i)sk_live_[0-9a-zA-Z]{24}',
        r'(?i)AIza[0-9A-Za-z-_]{35}',
    ],
    "tokens": [
        r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
        r'(?i)(access_token|auth_token|token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{10,})["\'&]?',
        r'(?i)(sessionid|session[_-]?id)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{10,})["\'&]?',
    ],
    "passwords": [
        r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^"\'\s&]{3,})["\'&]?',
        r'(?i)(secret|private_key)["\']?\s*[:=]\s*["\']?([^"\'\s&]{3,})["\'&]?',
    ],
    "personal_info": [
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        r'\b\d{3}[-]?\d{2}[-]?\d{4}\b',
    ],
    "credit_cards": [
        r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}'
        r'|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b',
    ],
}


def _mask(text: str) -> str:
    if len(text) > 10:
        return text[:4] + "****" + text[-4:]
    return "****"


def analyze_sensitive(url: str, item_index: int,
                      req_headers: dict, req_body: str,
                      resp_headers: dict, resp_body: str) -> list[dict]:
    findings = []
    seen: set[tuple] = set()

    def scan(text: str, source: str, location: str):
        for category, patterns in SENSITIVE_PATTERNS.items():
            for pat in patterns:
                for m in re.finditer(pat, text):
                    raw = m.group(0)
                    key = (raw, location)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append({
                        "url":          url,
                        "item_index":   item_index,
                        "category":     category,
                        "source":       source,
                        "location":     location,
                        "match_masked": _mask(raw),
                        "start":        m.start(),
                        "end":          m.end(),
                    })

    # request
    for hname, hval in req_headers.items():
        scan(hval, "request", f"header:{hname}")
    if req_body:
        scan(req_body, "request", "body")

    # response
    for hname, hval in resp_headers.items():
        scan(hval, "response", f"header:{hname}")
    if resp_body:
        scan(resp_body, "response", "body")

    return findings


# ===========================================================================
#  MODULE 3 — PATH / DIRECTORY FINDER
#  Extracted from path_finder module (path_finderV2.py)
#  Only interesting paths are kept.
# ===========================================================================

INTERESTING_EXTENSIONS = {
    "php", "asp", "aspx", "jsp", "jspx", "do", "action", "json", "xml",
    "conf", "config", "cfg", "ini", "env", "log", "bak", "backup", "old",
    "txt", "sql", "db", "mdb", "sqlite", "csv", "xls", "xlsx", "doc", "docx",
    "pdf", "zip", "tar", "gz", "7z", "rar", "war", "jar", "pem", "key", "cert",
}

INTERESTING_DIRECTORIES = {
    "admin", "administrator", "backup", "backups", "bak", "beta", "conf", "config",
    "configs", "configuration", "data", "database", "db", "deploy", "dev",
    "development", "includes", "internal", "log", "logs", "private", "prod",
    "production", "secret", "secrets", "secure", "security", "server", "servers",
    "staging", "test", "tests", "tmp", "temp", "upload", "uploads", "api",
    "v1", "v2", "v3", "svn", "git", "cvs", "jenkins", "jira", "confluence",
    "wp-admin", "wp-content", "wp-includes",
}

SENSITIVE_FILES = [
    ".git/HEAD", ".git/config", ".svn/entries", ".env", ".htaccess", "web.config",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
    "phpinfo.php", "info.php", "server-status", "server-info", "elmah.axd",
    "trace.axd", "webpack.config.js", "package.json", "config.json", "settings.json",
    "wp-config.php", "wp-config.bak", "config.php.bak", ".bash_history", ".zsh_history",
    "id_rsa", "id_dsa", "authorized_keys", "known_hosts",
]

COMMON_SKIP_EXTENSIONS = {
    "js", "css", "html", "htm", "png", "jpg", "jpeg", "gif", "svg", "webp",
    "ico", "woff", "woff2", "ttf", "eot", "mp4", "webm", "mp3", "wav",
}

PATH_PATTERNS = [
    r'(?:^|[^\w/-])(\/(?:[a-zA-Z0-9_-]+\/)*[a-zA-Z0-9_.-]+)(?:[^\w/]|$)',
    r'(?:^|[^\w:\\-])([A-Z]:\\(?:[a-zA-Z0-9_-]+\\)*[a-zA-Z0-9_.-]+)(?:[^\w\\]|$)',
    r'(?:^|[^\w/-])((?:\.\.\/|\.\/)?(?:[a-zA-Z0-9_-]+\/)+[a-zA-Z0-9_.-]+)(?:[^\w/]|$)',
    r'(?:https?://[a-zA-Z0-9.-]+)(/(?:[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+)',
    r'(?:src|href|action|data|url|path|include|require)["\']?\s*[:=]\s*["\']?([^"\'<>\s\)]+)["\']?',
]
HTML_ATTR_PATTERN = r'\s(?:href|src|action|data-url|data-src)=["\']([^"\'<>\s]+)["\']'


def _extract_paths_from_text(text: str, source: str) -> list[dict]:
    """Return interesting path findings from arbitrary text."""
    findings = []
    seen: set[str] = set()

    def record(path: str, find_source: str, find_type: str, extension: str = "", dirname: str = ""):
        if path in seen:
            return
        seen.add(path)
        entry = {"path": path, "source": find_source, "type": find_type}
        if extension:
            entry["extension"] = extension
        if dirname:
            entry["directory"] = dirname
        findings.append(entry)

    def process_path(path: str, src: str):
        path = path.strip()
        if not path or path in ("/", ".", "*"):
            return
        parts = [p for p in path.replace("\\", "/").split("/") if p]
        current = ""
        for part in parts:
            if "." in part and not part.startswith("."):
                ext = part.split(".")[-1].lower()
                if ext not in COMMON_SKIP_EXTENSIONS and ext in INTERESTING_EXTENSIONS:
                    fpath = (current + "/" + part) if current else ("/" + part)
                    record(fpath, src, "interesting_file", extension=ext)
            else:
                current = (current + "/" + part) if current else ("/" + part)
                if part.lower() in INTERESTING_DIRECTORIES:
                    record(current, src, "interesting_directory", dirname=part.lower())

    # regex patterns
    for pat in PATH_PATTERNS:
        for m in re.finditer(pat, text):
            try:
                raw = m.group(1).strip()
            except IndexError:
                continue
            if raw.startswith(("http://", "https://")):
                parsed = urlparse(raw)
                process_path(parsed.path, f"{source}:url")
            elif raw.startswith(("/", "\\", "C:", "D:")):
                process_path(raw, f"{source}:absolute")
            else:
                process_path(raw, f"{source}:relative")

    # html attributes
    for m in re.finditer(HTML_ATTR_PATTERN, text):
        val = m.group(1).strip()
        if not val or val.startswith(("javascript:", "data:", "#", "mailto:")):
            continue
        if val.startswith(("http://", "https://")):
            parsed = urlparse(val)
            process_path(parsed.path, f"{source}:html_attr")
        else:
            process_path(val, f"{source}:html_attr")

    return findings


def analyze_paths(url: str, item_index: int,
                  req_headers: dict, req_body: str,
                  resp_headers: dict, resp_body: str) -> dict:
    findings: list[dict] = []

    # response headers
    for hname, hval in resp_headers.items():
        findings.extend(_extract_paths_from_text(hval, f"response:header:{hname}"))

    # response body
    if resp_body:
        findings.extend(_extract_paths_from_text(resp_body, "response:body"))

    # request body (POST data can leak paths)
    if req_body:
        findings.extend(_extract_paths_from_text(req_body, "request:body"))

    # tag each finding with url + item_index
    for f in findings:
        f["url"] = url
        f["item_index"] = item_index

    # potential sensitive files (not confirmed — just flagged for manual check)
    base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}" if url else ""
    sensitive_flags = [
        {"path": sf, "check_url": urljoin(base_url, sf) if base_url else sf, "confirmed": False}
        for sf in SENSITIVE_FILES
    ]

    return {"item_findings": findings, "potential_sensitive_files": sensitive_flags}


# ===========================================================================
#  AGGREGATION
# ===========================================================================

def aggregate(items: list[dict]) -> dict:
    """
    Run all three analyzers across every Burp item and collate into
    the unified output structure.
    """
    version_by_url:   dict[str, dict] = {}
    sensitive_all:    list[dict]      = []
    sensitive_by_cat: dict[str, dict] = {}
    path_findings:    list[dict]      = []
    # Dedup sensitive files across items (one set per base URL)
    sensitive_files_seen: set[str]    = set()
    sensitive_files_list: list[dict]  = []

    for idx, item in enumerate(items, 1):
        url   = item["url"]
        rqh   = item["request_headers"]
        rqb   = item["request_body"]
        rsh   = item["response_headers"]
        rsb   = item["response_body"]

        # ── version ──────────────────────────────────────────────────────────
        vr = analyze_version(url, rsh, rsb)
        if vr["version_findings"] or vr["technologies"]:
            version_by_url[url] = {
                "technologies":            vr["technologies"],
                "version_findings":        vr["version_findings"],
                "potential_vulnerabilities": vr["potential_vulnerabilities"],
            }

        # ── sensitive ────────────────────────────────────────────────────────
        si = analyze_sensitive(url, idx, rqh, rqb, rsh, rsb)
        for f in si:
            sensitive_all.append(f)
            cat = f["category"]
            if cat not in sensitive_by_cat:
                sensitive_by_cat[cat] = {"count": 0, "urls": []}
            sensitive_by_cat[cat]["count"] += 1
            if url not in sensitive_by_cat[cat]["urls"]:
                sensitive_by_cat[cat]["urls"].append(url)

        # ── paths ─────────────────────────────────────────────────────────────
        pr = analyze_paths(url, idx, rqh, rqb, rsh, rsb)
        path_findings.extend(pr["item_findings"])

        # merge sensitive-file suggestions (dedup by path)
        for sf in pr["potential_sensitive_files"]:
            if sf["path"] not in sensitive_files_seen:
                sensitive_files_seen.add(sf["path"])
                sensitive_files_list.append(sf)

    return {
        "meta": {
            "generated":          datetime.now(timezone.utc).isoformat(),
            "total_items_scanned": len(items),
        },
        "version_info": {
            "total_urls_with_findings": len(version_by_url),
            "by_url": version_by_url,
        },
        "sensitive_info": {
            "total_findings":      len(sensitive_all),
            "items_with_findings": len({f["item_index"] for f in sensitive_all}),
            "by_category":         sensitive_by_cat,
            "findings":            sensitive_all,
        },
        "paths": {
            "total_interesting_findings": len(path_findings),
            "findings":                   path_findings,
            "potential_sensitive_files":  sensitive_files_list,
        },
    }


# ===========================================================================
#  CLI
# ===========================================================================

def parse_args():
    p = argparse.ArgumentParser(
        prog="info5_orchestrator.py",
        description="WSTG-INFO-05 — Web Page Content Information Leakage Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--input", "-i", required=True,
        help="Path to Burp Suite proxy export XML.",
    )
    p.add_argument(
        "--base", default=None,
        help="WSTG-INFO-05 root directory. Defaults to two levels above this script.",
    )
    p.add_argument(
        "--output", "-o", default=None,
        help="Explicit output JSON path (overrides default).",
    )
    return p.parse_args()


def ts() -> str:
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def main():
    args  = parse_args()
    base  = Path(args.base).resolve() if args.base else DEFAULT_BASE
    xml_path = Path(args.input).resolve()

    if not xml_path.is_file():
        sys.exit(f"[ERROR] Input file not found: {xml_path}")

    if args.output:
        out_path = Path(args.output).resolve()
    else:
        out_dir  = base / OUTPUT_SUBDIR
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"leakage_{ts()}.json"

    out_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"  WSTG-INFO-05 — Information Leakage Analyzer")
    print(f"  Input   : {xml_path}")
    print(f"  Output  : {out_path}")
    print(f"{'='*60}\n")

    print("[*] Parsing Burp XML...")
    items = parse_burp_xml(xml_path)
    if not items:
        sys.exit("[ERROR] No items found in XML.")
    print(f"  [+] Loaded {len(items)} item(s).")

    print("[*] Running analysis (version / sensitive / paths)...")
    result = aggregate(items)
    result["meta"]["source_xml"] = str(xml_path)

    print(f"  [+] Version URLs with findings : {result['version_info']['total_urls_with_findings']}")
    print(f"  [+] Sensitive findings         : {result['sensitive_info']['total_findings']}")
    print(f"  [+] Interesting path findings  : {result['paths']['total_interesting_findings']}")

    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    print(f"\n[+] Output written → {out_path}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
