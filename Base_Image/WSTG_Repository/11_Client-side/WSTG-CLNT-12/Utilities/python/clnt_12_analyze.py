#!/usr/bin/env python3
"""
WSTG-CLNT-12 — Testing Browser Storage
Script: clnt_12_analyze.py

Reads the JSON dump produced by the storage_dump JS snippet
(storage_dump.json, with a Pulled_Objects wrapper) and performs
a structured security analysis across every storage mechanism:

  Local_Storage   → key + value pattern scan
  Session_Storage → key + value pattern scan
  Cookies         → key + value pattern scan + HttpOnly/Secure note
  IndexedDB       → per-store value scan + CryptoKey serialization check
  Cache_Storage   → URL pattern scan on cached request URLs

For each mechanism findings are tagged with:
  storage, key, value_truncated, severity, pattern_type, description

Key names are also scanned — a key named "private_key" with any
value is itself a finding regardless of the value.

Additional checks:
  - Empty-object {} entries in IndexedDB (possible CryptoKey that
    failed JSON serialization — extractability cannot be confirmed)
  - Presence of tokens that survive across storage mechanisms
    (same token value in both localStorage AND sessionStorage = persistence risk)

Appends a manual checklist to the report covering:
  - Post-logout diff (run dump again after logout, compare)
  - window.* global scope inspection
  - Code review of storage write points

Outputs:
  WSTG-CLNT-12/outputs/test_outputs/clnt12_report.md
  WSTG-CLNT-12/inputs/json/clnt12_findings.json

Usage:
  python3 WSTG-CLNT-12/utilities/python/clnt_12_analyze.py \\
      [--dump WSTG-CLNT-12/inputs/json/storage_dump.json] \\
      [--pre  WSTG-CLNT-12/inputs/json/storage_dump_pre_logout.json] \\
      [--post WSTG-CLNT-12/inputs/json/storage_dump_post_logout.json]

  The --pre / --post flags enable optional post-logout diff mode:
  supply both to get a diff of what tokens survived after logout.
"""

import argparse
import json
import os
import re
import sys
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

SEV_COLOR = {
    "CRITICAL": RED,
    "HIGH":     RED,
    "MEDIUM":   YELLOW,
    "LOW":      CYAN,
    "INFO":     DIM,
}


# ---------------------------------------------------------------------------
# Pattern library — scans both keys and values
# Values: regex applied to the string representation of the value
# Keys:   regex applied to the key name (separate, lighter patterns)
# ---------------------------------------------------------------------------

VALUE_PATTERNS = [
    # ── Authentication tokens ────────────────────────────────────────────────
    {
        "id":          "jwt",
        "severity":    "CRITICAL",
        "description": "JWT token — readable by JavaScript, theft via XSS is trivial",
        "regex":       re.compile(
            r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'
        ),
        "cwe":  "CWE-312",
        "note": "JWTs in localStorage/sessionStorage are accessible to any JS on the page. "
                "Should be in HttpOnly cookies.",
    },
    {
        "id":          "bearer_token",
        "severity":    "CRITICAL",
        "description": "Bearer token",
        "regex":       re.compile(
            r'bearer\s+[a-zA-Z0-9\-._~+\/]+=*', re.IGNORECASE
        ),
        "cwe": "CWE-312",
        "note": "",
    },
    {
        "id":          "access_token",
        "severity":    "CRITICAL",
        "description": "Access token",
        "regex":       re.compile(
            r'(?:access[_-]?token|accesstoken)[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-\.]{20,})',
            re.IGNORECASE
        ),
        "cwe": "CWE-312",
        "note": "",
    },
    {
        "id":          "refresh_token",
        "severity":    "CRITICAL",
        "description": "Refresh token",
        "regex":       re.compile(
            r'(?:refresh[_-]?token|refreshtoken)[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-\.]{20,})',
            re.IGNORECASE
        ),
        "cwe": "CWE-312",
        "note": "Refresh tokens in client storage allow persistent session hijack.",
    },
    {
        "id":          "session_id",
        "severity":    "HIGH",
        "description": "Session identifier",
        "regex":       re.compile(
            r'(?:session[_-]?id|sessionid|sess(?:ion)?)[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{16,})',
            re.IGNORECASE
        ),
        "cwe": "CWE-312",
        "note": "Session IDs should live in HttpOnly cookies, not readable storage.",
    },
    # ── API / cloud credentials ───────────────────────────────────────────────
    {
        "id":          "api_key",
        "severity":    "CRITICAL",
        "description": "API key",
        "regex":       re.compile(
            r'(?:api[_-]?key|apikey|api_key)[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{16,})',
            re.IGNORECASE
        ),
        "cwe": "CWE-312",
        "note": "",
    },
    {
        "id":          "aws_access_key",
        "severity":    "CRITICAL",
        "description": "AWS Access Key ID",
        "regex":       re.compile(r'AKIA[0-9A-Z]{16}'),
        "cwe": "CWE-312",
        "note": "",
    },
    {
        "id":          "aws_secret_key",
        "severity":    "CRITICAL",
        "description": "AWS Secret Access Key",
        "regex":       re.compile(
            r'aws[_-]?secret[_-]?access[_-]?key[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9\/+=]{40})',
            re.IGNORECASE
        ),
        "cwe": "CWE-312",
        "note": "",
    },
    {
        "id":          "google_api_key",
        "severity":    "CRITICAL",
        "description": "Google API Key",
        "regex":       re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        "cwe": "CWE-312",
        "note": "",
    },
    {
        "id":          "slack_token",
        "severity":    "CRITICAL",
        "description": "Slack token",
        "regex":       re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'),
        "cwe": "CWE-312",
        "note": "",
    },
    {
        "id":          "github_token",
        "severity":    "CRITICAL",
        "description": "GitHub token",
        "regex":       re.compile(r'gh[pousr]_[0-9a-zA-Z]{36}'),
        "cwe": "CWE-312",
        "note": "",
    },
    # ── Private key material ─────────────────────────────────────────────────
    {
        "id":          "private_key_pem",
        "severity":    "CRITICAL",
        "description": "PEM private key block",
        "regex":       re.compile(
            r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'
        ),
        "cwe": "CWE-312",
        "note": "Private key material in browser storage is directly exfiltrable via XSS.",
    },
    # ── Database connection strings ──────────────────────────────────────────
    {
        "id":          "db_connection_string",
        "severity":    "HIGH",
        "description": "Database connection string",
        "regex":       re.compile(
            r'(?:mongodb|mysql|postgresql|postgres|redis)://[^\s\'"]{8,}',
            re.IGNORECASE
        ),
        "cwe": "CWE-312",
        "note": "",
    },
    # ── PII ──────────────────────────────────────────────────────────────────
    {
        "id":          "email",
        "severity":    "MEDIUM",
        "description": "Email address",
        "regex":       re.compile(
            r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        ),
        "cwe": "CWE-359",
        "note": "PII in client storage — confirm business necessity.",
    },
    {
        "id":          "ssn",
        "severity":    "HIGH",
        "description": "US Social Security Number pattern",
        "regex":       re.compile(r'\b\d{3}[-]\d{2}[-]\d{4}\b'),
        "cwe": "CWE-359",
        "note": "",
    },
    {
        "id":          "cc_visa",
        "severity":    "CRITICAL",
        "description": "Visa card number",
        "regex":       re.compile(r'\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
        "cwe": "CWE-312",
        "note": "",
    },
    {
        "id":          "cc_mastercard",
        "severity":    "CRITICAL",
        "description": "Mastercard number",
        "regex":       re.compile(
            r'\b(?:5[1-5]\d{2}|222[1-9]|22[3-9]\d|2[3-6]\d{2}|27[01]\d|2720)[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
        ),
        "cwe": "CWE-312",
        "note": "",
    },
    {
        "id":          "cc_amex",
        "severity":    "CRITICAL",
        "description": "American Express card number",
        "regex":       re.compile(r'\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b'),
        "cwe": "CWE-312",
        "note": "",
    },
    # ── Passwords in storage ──────────────────────────────────────────────────
    {
        "id":          "password_in_value",
        "severity":    "CRITICAL",
        "description": "Password stored in value",
        "regex":       re.compile(
            r'(?:password|passwd|pwd|secret)[\'"]?\s*[:=]\s*[\'"]?([^\s\'"&,}{]{6,})',
            re.IGNORECASE
        ),
        "cwe": "CWE-256",
        "note": "Plaintext password / secret in client-accessible storage.",
    },
]

# Key name patterns — applied to the key string only
KEY_PATTERNS = [
    {
        "id":          "key_auth_token",
        "severity":    "HIGH",
        "description": "Key name suggests authentication token",
        "regex":       re.compile(
            r'\b(?:token|jwt|auth|access[_-]?token|refresh[_-]?token|id[_-]?token|bearer)\b',
            re.IGNORECASE
        ),
        "cwe": "CWE-312",
        "note": "Key name indicates an auth token — inspect the value.",
    },
    {
        "id":          "key_credential",
        "severity":    "HIGH",
        "description": "Key name suggests credential storage",
        "regex":       re.compile(
            r'\b(?:password|passwd|pwd|secret|private[_-]?key|api[_-]?key|credentials?)\b',
            re.IGNORECASE
        ),
        "cwe": "CWE-312",
        "note": "Key name suggests sensitive credential — inspect the value immediately.",
    },
    {
        "id":          "key_session",
        "severity":    "MEDIUM",
        "description": "Key name suggests session data",
        "regex":       re.compile(
            r'\b(?:sess(?:ion)?(?:[_-]?id)?|sid|user[_-]?id|user[_-]?data|profile)\b',
            re.IGNORECASE
        ),
        "cwe": "CWE-312",
        "note": "Session/user data in client storage — confirm it clears on logout.",
    },
    {
        "id":          "key_pii",
        "severity":    "MEDIUM",
        "description": "Key name suggests PII",
        "regex":       re.compile(
            r'\b(?:email|phone|address|dob|birth|ssn|national[_-]?id|passport)\b',
            re.IGNORECASE
        ),
        "cwe": "CWE-359",
        "note": "PII key in client storage — confirm business necessity and data minimisation.",
    },
    {
        "id":          "key_payment",
        "severity":    "CRITICAL",
        "description": "Key name suggests payment data",
        "regex":       re.compile(
            r'\b(?:cc[_-]?num|card[_-]?num|cvv|cvc|pan|credit[_-]?card|payment)\b',
            re.IGNORECASE
        ),
        "cwe": "CWE-312",
        "note": "Payment data key in client storage — likely PCI-DSS violation.",
    },
]


# ---------------------------------------------------------------------------
# JSON dump ingestion
# ---------------------------------------------------------------------------

def load_dump(path: str) -> dict:
    """
    Loads storage_dump.json. Handles:
      { "Pulled_Objects": { "Local_Storage": {}, ... } }   ← JS dumper format
      { "Local_Storage": {}, ... }                          ← bare format
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"{RED}[!] Cannot load dump: {e}{RESET}", file=sys.stderr)
        sys.exit(1)

    if "Pulled_Objects" in data:
        return data["Pulled_Objects"]
    return data


# ---------------------------------------------------------------------------
# Value scanning
# ---------------------------------------------------------------------------

def _str_value(v) -> str:
    """Coerce any value to a string for regex scanning."""
    if isinstance(v, str):
        return v
    return json.dumps(v)


def scan_value(storage: str, key: str, raw_value, source_note: str = "") -> list[dict]:
    """Scan a single key+value pair. Returns list of finding dicts."""
    findings = []
    val_str  = _str_value(raw_value)

    # Key name scan
    for pat in KEY_PATTERNS:
        if pat["regex"].search(key):
            findings.append(_finding(storage, key, val_str, pat, "key_name", source_note))

    # Value scan
    for pat in VALUE_PATTERNS:
        for m in pat["regex"].finditer(val_str):
            findings.append(_finding(storage, key, val_str, pat, "value", source_note,
                                     match_snippet=m.group(0)))

    return findings


def _finding(storage, key, val_str, pat, scan_type, source_note, match_snippet=None) -> dict:
    trunc = val_str[:120] + ("…" if len(val_str) > 120 else "")
    return {
        "storage":       storage,
        "key":           key,
        "value_preview": trunc,
        "severity":      pat["severity"],
        "pattern_id":    pat["id"],
        "description":   pat["description"],
        "cwe":           pat.get("cwe", ""),
        "note":          pat.get("note", ""),
        "scan_type":     scan_type,          # "key_name" | "value"
        "match":         (match_snippet or "")[:100],
        "source_note":   source_note,
    }


# ---------------------------------------------------------------------------
# Storage section analyzers
# ---------------------------------------------------------------------------

def analyze_flat(storage_name: str, obj: dict) -> list[dict]:
    """LocalStorage, SessionStorage, Cookies — flat key→value maps."""
    findings = []
    if not isinstance(obj, dict):
        return findings
    for key, value in obj.items():
        findings.extend(scan_value(storage_name, key, value))
    return findings


def analyze_cookies(obj: dict) -> list[dict]:
    """
    Same as flat, but add an INFO note for any cookie that looks like
    an auth token — cookies should have HttpOnly flag, which the JS
    dumper can access (meaning HttpOnly is NOT set if it appears here).
    """
    findings = analyze_flat("Cookies", obj)
    for key in obj:
        # If the key matches auth-token pattern and it showed up in JS-accessible
        # dump at all → HttpOnly is absent
        if re.search(
            r'\b(?:token|jwt|session|sess|auth|sid)\b', key, re.IGNORECASE
        ):
            findings.append({
                "storage":       "Cookies",
                "key":           key,
                "value_preview": str(obj[key])[:120],
                "severity":      "HIGH",
                "pattern_id":    "cookie_missing_httponly",
                "description":   "Auth-related cookie readable by JavaScript — HttpOnly flag absent",
                "cwe":           "CWE-1004",
                "note":          "This cookie was accessible via document.cookie (the JS dumper). "
                                 "An HttpOnly cookie would not appear here. "
                                 "Auth cookies without HttpOnly are trivially stolen via XSS.",
                "scan_type":     "cookie_flag",
                "match":         "",
                "source_note":   "",
            })
    return findings


def analyze_indexed_db(obj: dict) -> list[dict]:
    """
    IndexedDB — { dbName: { storeName: [records] } }.
    Also detects empty-object records that may be unserialised CryptoKeys.
    """
    findings = []
    if not isinstance(obj, dict):
        return findings

    if "_error" in obj:
        findings.append({
            "storage":       "IndexedDB",
            "key":           "_error",
            "value_preview": str(obj["_error"])[:120],
            "severity":      "INFO",
            "pattern_id":    "indexeddb_error",
            "description":   "IndexedDB enumeration error during dump",
            "cwe":           "",
            "note":          "May indicate a cross-origin or permissions issue.",
            "scan_type":     "meta",
            "match":         "",
            "source_note":   "",
        })
        return findings

    for db_name, stores in obj.items():
        if not isinstance(stores, dict):
            continue
        for store_name, records in stores.items():
            if not isinstance(records, list):
                continue
            for i, record in enumerate(records):
                source = f"IndexedDB/{db_name}/{store_name}[{i}]"

                # Empty object — possible CryptoKey serialisation failure
                if record == {} or record == []:
                    findings.append({
                        "storage":       "IndexedDB",
                        "key":           f"{db_name}/{store_name}[{i}]",
                        "value_preview": "{}",
                        "severity":      "MEDIUM",
                        "pattern_id":    "indexeddb_possible_cryptokey",
                        "description":   "Empty object in IndexedDB — possible CryptoKey (not JSON-serialisable)",
                        "cwe":           "CWE-321",
                        "note":          "CryptoKey objects silently become {} when JSON.stringify is called. "
                                         "WSTG-CLNT-12 requires checking whether stored keys have "
                                         "extractable: true. Verify manually: open DevTools → Application → "
                                         f"IndexedDB → {db_name} → {store_name} and inspect the record. "
                                         "If it is a CryptoKey, confirm extractable is false.",
                        "scan_type":     "cryptokey_check",
                        "match":         "",
                        "source_note":   source,
                    })
                    continue

                # Scan record fields
                rec_str = _str_value(record)
                for key_name, val in (record.items() if isinstance(record, dict) else {}.items()):
                    findings.extend(
                        scan_value("IndexedDB", key_name, val, source_note=source)
                    )
                # Also full-string scan the serialised record
                for pat in VALUE_PATTERNS:
                    for m in pat["regex"].finditer(rec_str):
                        findings.append(
                            _finding("IndexedDB", f"{db_name}/{store_name}[{i}]",
                                     rec_str, pat, "value", source, match_snippet=m.group(0))
                        )

    return findings


def analyze_cache_storage(obj: dict) -> list[dict]:
    """
    CacheStorage — { cacheName: [url, url, ...] }.
    Scans URLs for sensitive path patterns.
    """
    findings = []
    if not isinstance(obj, dict):
        return findings
    if "_error" in obj:
        return findings

    SENSITIVE_URL_PATTERNS = [
        (re.compile(r'/api/(?:v\d+/)?(?:token|auth|login|session)', re.I),
         "HIGH", "Cached API auth endpoint URL", "CWE-312"),
        (re.compile(r'[?&](?:token|jwt|access_token|api_key)=', re.I),
         "CRITICAL", "Cached URL with credential in query string", "CWE-312"),
        (re.compile(r'[?&](?:password|passwd|pwd|secret)=', re.I),
         "CRITICAL", "Cached URL with password in query string", "CWE-256"),
        (re.compile(r'/admin|/dashboard|/internal|/private', re.I),
         "MEDIUM", "Cached URL for privileged path", "CWE-312"),
    ]

    for cache_name, urls in obj.items():
        if not isinstance(urls, list):
            continue
        for url in urls:
            if not isinstance(url, str):
                continue
            for pat, sev, desc, cwe in SENSITIVE_URL_PATTERNS:
                if pat.search(url):
                    findings.append({
                        "storage":       "Cache_Storage",
                        "key":           cache_name,
                        "value_preview": url[:120],
                        "severity":      sev,
                        "pattern_id":    "cache_url",
                        "description":   desc,
                        "cwe":           cwe,
                        "note":          "URL cached in CacheStorage — response body may contain sensitive data. "
                                         "Verify with DevTools → Application → Cache Storage.",
                        "scan_type":     "url",
                        "match":         url[:100],
                        "source_note":   cache_name,
                    })
    return findings


# ---------------------------------------------------------------------------
# Cross-storage persistence check
# ---------------------------------------------------------------------------

def check_cross_storage_persistence(pulled: dict) -> list[dict]:
    """
    Finds identical values (that look like tokens) present in BOTH
    Local_Storage and Session_Storage. Session storage should not
    outlive the tab, but if the same token is also in localStorage
    it persists indefinitely.
    """
    findings = []

    ls = pulled.get("Local_Storage", {})
    ss = pulled.get("Session_Storage", {})
    if not isinstance(ls, dict) or not isinstance(ss, dict):
        return findings

    ls_vals = {v: k for k, v in ls.items() if isinstance(v, str) and len(v) > 20}
    for ss_key, ss_val in ss.items():
        if not isinstance(ss_val, str) or len(ss_val) < 20:
            continue
        if ss_val in ls_vals:
            ls_key = ls_vals[ss_val]
            findings.append({
                "storage":       "Cross-Storage",
                "key":           f"localStorage[{ls_key}] = sessionStorage[{ss_key}]",
                "value_preview": ss_val[:80] + ("…" if len(ss_val) > 80 else ""),
                "severity":      "HIGH",
                "pattern_id":    "cross_storage_persistence",
                "description":   "Same value in both localStorage and sessionStorage",
                "cwe":           "CWE-312",
                "note":          "sessionStorage values should die with the tab. "
                                 "If the same token is in localStorage it persists indefinitely "
                                 "and survives logout unless explicitly cleared.",
                "scan_type":     "cross_storage",
                "match":         "",
                "source_note":   "",
            })
    return findings


# ---------------------------------------------------------------------------
# Post-logout diff
# ---------------------------------------------------------------------------

def diff_dumps(pre: dict, post: dict) -> list[dict]:
    """
    Compares two Pulled_Objects dicts (pre-logout vs post-logout).
    Returns findings for values that survived logout.
    """
    findings = []
    FLAT_STORES = ["Local_Storage", "Session_Storage", "Cookies"]

    for store in FLAT_STORES:
        pre_store  = pre.get(store, {})
        post_store = post.get(store, {})
        if not isinstance(pre_store, dict) or not isinstance(post_store, dict):
            continue
        for key, val in pre_store.items():
            if key in post_store and post_store[key] == val:
                findings.append({
                    "storage":       store,
                    "key":           key,
                    "value_preview": str(val)[:80],
                    "severity":      "HIGH",
                    "pattern_id":    "survived_logout",
                    "description":   f"Value persisted after logout in {store}",
                    "cwe":           "CWE-613",
                    "note":          "WSTG-CLNT-12 requires tokens and session data to clear after logout. "
                                     "This entry was present both before and after logout with the same value.",
                    "scan_type":     "logout_diff",
                    "match":         "",
                    "source_note":   "post-logout diff",
                })

    return findings


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def deduplicate(findings: list[dict]) -> list[dict]:
    """Remove exact duplicates (same storage+key+pattern_id+match)."""
    seen = set()
    out  = []
    for f in findings:
        sig = (f["storage"], f["key"], f["pattern_id"], f["match"][:40])
        if sig not in seen:
            seen.add(sig)
            out.append(f)
    return out


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

def build_report(
    findings:   list[dict],
    dump_path:  str,
    has_diff:   bool,
    diff_findings: list[dict],
) -> str:
    now_str    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    lines = []
    lines.append("# WSTG-CLNT-12 — Browser Storage Security Analysis")
    lines.append("")
    lines.append(f"**Generated:** {now_str}  ")
    lines.append(f"**Source dump:** `{dump_path}`  ")
    lines.append(f"**Total findings:** {len(findings)}  ")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        lines.append(f"| {sev} | {sev_counts.get(sev, 0)} |")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Group by storage
    storage_order = [
        "Local_Storage", "Session_Storage", "Cookies",
        "IndexedDB", "Cache_Storage", "Cross-Storage",
    ]
    by_storage: dict = {}
    for f in sorted(findings, key=lambda x: SEV_ORDER.get(x["severity"], 9)):
        s = f["storage"]
        by_storage.setdefault(s, []).append(f)

    for storage in storage_order + [s for s in by_storage if s not in storage_order]:
        group = by_storage.get(storage, [])
        if not group:
            continue

        lines.append(f"## {storage.replace('_', ' ')}")
        lines.append("")

        # Summarise by severity
        g_sev: dict = {}
        for f in group:
            g_sev.setdefault(f["severity"], []).append(f)

        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            sev_group = g_sev.get(sev, [])
            if not sev_group:
                continue
            lines.append(f"### {sev} ({len(sev_group)})")
            lines.append("")
            for f in sev_group:
                lines.append(f"#### `{f['key']}`")
                lines.append("")
                lines.append(f"- **Pattern:** {f['description']}")
                if f["cwe"]:
                    lines.append(f"- **CWE:** [{f['cwe']}](https://cwe.mitre.org/data/definitions/{f['cwe'].split('-')[1]}.html)")
                lines.append(f"- **Scan type:** {f['scan_type']}")
                if f["match"]:
                    lines.append(f"- **Match:** `{f['match']}`")
                lines.append(f"- **Value preview:** `{f['value_preview']}`")
                if f["note"]:
                    lines.append(f"- **Note:** {f['note']}")
                if f["source_note"]:
                    lines.append(f"- **Source:** {f['source_note']}")
                lines.append("")
        lines.append("---")
        lines.append("")

    # Post-logout diff section
    if has_diff:
        lines.append("## Post-Logout Diff Results")
        lines.append("")
        if diff_findings:
            lines.append(f"**{len(diff_findings)} value(s) survived logout:**")
            lines.append("")
            for f in diff_findings:
                lines.append(f"- **{f['severity']}** `{f['storage']}[{f['key']}]` — {f['description']}")
                lines.append(f"  - `{f['value_preview']}`")
                lines.append(f"  - {f['note']}")
        else:
            lines.append("✅ No values from the pre-logout dump were present in the post-logout dump.  ")
            lines.append("Tokens and session data appear to be correctly cleared on logout.")
        lines.append("")
        lines.append("---")
        lines.append("")

    # Manual checklist
    lines.append("## Manual Verification Checklist")
    lines.append("")
    lines.append(
        "The automated scan covers data present in the dump. The following "
        "items **require manual steps** and cannot be checked programmatically:"
    )
    lines.append("")

    checklist = [
        (
            "Post-logout persistence (if not already done with --pre/--post)",
            "1. Log in to the application.\n"
            "2. Run the storage dumper JS snippet and save as `storage_dump_pre_logout.json`.\n"
            "3. Log out.\n"
            "4. Run the dumper again and save as `storage_dump_post_logout.json`.\n"
            "5. Re-run this script with `--pre storage_dump_pre_logout.json --post storage_dump_post_logout.json`.\n"
            "   Any matching values = CWE-613 Insufficient Session Expiration."
        ),
        (
            "`window.*` global scope inspection",
            "The JS dumper does not capture custom properties on the `window` object.  \n"
            "In the browser console, run:  \n"
            "```javascript\n"
            "Object.keys(window).filter(k => !['__proto__','constructor'].includes(k))\n"
            "  .map(k => ({ key: k, val: typeof window[k] === 'string' ? window[k].slice(0,80) : typeof window[k] }))\n"
            "  .filter(e => typeof e.val === 'string')\n"
            "```\n"
            "Look for token/auth/key names in the result."
        ),
        (
            "IndexedDB CryptoKey extractability",
            "For each `{}` (empty object) finding in IndexedDB above:  \n"
            "1. Open DevTools → Application → IndexedDB.  \n"
            "2. Navigate to the flagged database and object store.  \n"
            "3. Click the record — if it is a CryptoKey, the panel shows `type`, `algorithm`, **`extractable`**.  \n"
            "4. `extractable: true` = CRITICAL finding (key material can be exported with `crypto.subtle.exportKey`).  \n"
            "5. `extractable: false` = PASS."
        ),
        (
            "Cookie HttpOnly / Secure / SameSite flags",
            "In DevTools → Application → Cookies, check each auth/session cookie:  \n"
            "- `HttpOnly` should be **checked** (prevents JS access).  \n"
            "- `Secure` should be **checked** (HTTPS only).  \n"
            "- `SameSite` should be `Strict` or `Lax` (CSRF protection).  \n"
            "Any auth cookie already present in the dump has **no HttpOnly flag** (cookies with HttpOnly "
            "are invisible to `document.cookie` and would not appear in the JS dumper output)."
        ),
        (
            "Storage code review — injection risk",
            "WSTG-CLNT-12 requires reviewing the code that writes to storage.  \n"
            "Search the application JS for:  \n"
            "```\n"
            "localStorage.setItem    sessionStorage.setItem\n"
            "document.cookie =       indexedDB.open\n"
            "```\n"
            "For each write: confirm the value is not constructed from unvalidated URL parameters "
            "or untrusted DOM properties (DOM-based XSS via storage write)."
        ),
        (
            "Session expiry on tab/browser close",
            "`sessionStorage` is supposed to clear when the tab closes.  \n"
            "1. Log in. Note auth token in sessionStorage.  \n"
            "2. Close ALL tabs for the origin and reopen.  \n"
            "3. Run the dumper again — `Session_Storage` should be empty.  \n"
            "If it persists, the app may be copying sessionStorage → localStorage on page load."
        ),
    ]

    for i, (title, steps) in enumerate(checklist, 1):
        lines.append(f"### {i}. {title}")
        lines.append("")
        lines.append(steps)
        lines.append("")

    lines.append("---")
    lines.append("*Generated by clnt_12_analyze.py — WSTG-CLNT-12*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-CLNT-12 browser storage security analyzer"
    )
    p.add_argument("--dump",
        default=os.path.join("WSTG-CLNT-12", "inputs", "json", "storage_dump.json"),
        metavar="PATH",
        help="storage_dump.json from the JS dumper snippet")
    p.add_argument("--pre",
        default="",
        metavar="PATH",
        help="Pre-logout dump (optional — enables post-logout diff)")
    p.add_argument("--post",
        default="",
        metavar="PATH",
        help="Post-logout dump (optional — enables post-logout diff)")
    p.add_argument("--report",
        default=os.path.join("WSTG-CLNT-12", "outputs", "test_outputs", "clnt12_report.md"),
        metavar="PATH")
    p.add_argument("--json-out",
        default=os.path.join("WSTG-CLNT-12", "inputs", "json", "clnt12_findings.json"),
        metavar="PATH")
    args = p.parse_args()

    width = 65
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD}  WSTG-CLNT-12 — Browser Storage Analyzer{RESET}")
    print(f"{BOLD}{'='*width}{RESET}")
    print(f"  Dump : {args.dump}\n")

    pulled = load_dump(args.dump)

    findings: list[dict] = []

    # ── Scan each storage section ────────────────────────────────────────────
    for section_name, analyzer in [
        ("Local_Storage",   lambda: analyze_flat("Local_Storage",   pulled.get("Local_Storage",   {}))),
        ("Session_Storage", lambda: analyze_flat("Session_Storage", pulled.get("Session_Storage", {}))),
        ("Cookies",         lambda: analyze_cookies(pulled.get("Cookies", {}))),
        ("IndexedDB",       lambda: analyze_indexed_db(pulled.get("IndexedDB", {}))),
        ("Cache_Storage",   lambda: analyze_cache_storage(pulled.get("Cache_Storage", {}))),
    ]:
        section_findings = analyzer()
        print(
            f"  {section_name:<20} "
            f"{len(section_findings):3d} finding(s)"
        )
        findings.extend(section_findings)

    # ── Cross-storage persistence ────────────────────────────────────────────
    cross = check_cross_storage_persistence(pulled)
    if cross:
        print(f"  {'Cross-Storage':<20} {len(cross):3d} finding(s)")
    findings.extend(cross)

    findings = deduplicate(findings)

    # ── Post-logout diff ─────────────────────────────────────────────────────
    has_diff      = bool(args.pre and args.post)
    diff_findings = []
    if has_diff:
        print(f"\n  Diff mode: {args.pre} → {args.post}")
        pre_dump  = load_dump(args.pre)
        post_dump = load_dump(args.post)
        diff_findings = diff_dumps(pre_dump, post_dump)
        findings.extend(diff_findings)
        findings = deduplicate(findings)

    # ── Summary ──────────────────────────────────────────────────────────────
    sev_counts: dict = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    print(f"\n  {'─'*50}")
    print(f"  Total findings: {len(findings)}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        c = sev_counts.get(sev, 0)
        if c:
            color = SEV_COLOR.get(sev, RESET)
            print(f"    {color}{sev:<10}{RESET}  {c}")

    # ── Output ───────────────────────────────────────────────────────────────
    report = build_report(findings, args.dump, has_diff, diff_findings)
    os.makedirs(os.path.dirname(args.report),   exist_ok=True)
    os.makedirs(os.path.dirname(args.json_out), exist_ok=True)

    with open(args.report, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"\n{GREEN}[+] Report     → {args.report}{RESET}")

    output = {
        "_meta": {
            "source_dump":    args.dump,
            "generated":      datetime.now().isoformat(),
            "total_findings": len(findings),
            "severity_counts": sev_counts,
            "has_logout_diff": has_diff,
        },
        "findings": sorted(findings, key=lambda x: SEV_ORDER.get(x["severity"], 9)),
    }
    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"{GREEN}[+] Findings   → {args.json_out}{RESET}")

    print(f"\n  {DIM}For post-logout diff:{RESET}")
    print(f"  {DIM}  python3 clnt_12_analyze.py --pre pre.json --post post.json{RESET}\n")


if __name__ == "__main__":
    main()
