#!/usr/bin/env python3
"""
WSTG-CRYP-04 — Testing for Weak Encryption
Script 2: cryp04_analyze.py

Reads objects_gathered.json (from cryp04_gather.py) and performs two
independent analyses on every collected parameter value:

═══════════════════════════════════════════════════════════════
Part A — Decoding / Block-Size Analysis  (CWE-326, 327, 261)
═══════════════════════════════════════════════════════════════
For each value, attempts five decoding schemes and evaluates the
resulting byte lengths against known symmetric cipher block sizes:

  8 bytes  (1 × 8-byte DES block)          → VULN   (DES/3DES, deprecated)
  16 bytes (1 × 16-byte AES block)          → INFO   (AES-128, acceptable)
  24 bytes (3 × 8-byte DES or 1.5 × 16)    → VULN   (DES/3DES key material)
  32 bytes (2 × 16-byte AES or 4 × 8-byte) → PASS   (AES-256 — best practice)
  64 bytes (4 × 16)                         → PASS   (AES-256 with IV)
  Other multiples of 8                      → INFO   (unusual, worth noting)
  Other multiples of 16                     → INFO   (AES-128 CBC data?)
  Anything else                             → no cipher match

Key rule: 256-bit (32-byte) key material = PASS — it is the current
best practice (AES-256-GCM) and must NOT be flagged as vulnerable.

CWE references:
  CWE-326 — Inadequate Encryption Strength
  CWE-327 — Use of a Broken or Risky Cryptographic Algorithm
  CWE-261 — Weak Encoding for Password (hash/encoding misuse)

═══════════════════════════════════════════════════════════════
Part B — Shannon Entropy / Randomness Analysis  (NIST SP 800-22)
═══════════════════════════════════════════════════════════════
Groups parameter values by name across all endpoints (a corpus).
Computes per-character Shannon entropy for each corpus.

Academic basis:
  Shannon, C.E. (1948). "A Mathematical Theory of Communication."
  Bell System Technical Journal, 27(3), 379–423.
  — H(X) = -Σ p(x) log₂ p(x)

  NIST SP 800-22 Rev 1a (2010). "A Statistical Test Suite for
  Random and Pseudorandom Number Generators for Cryptographic
  Applications." — defines 15 statistical tests for randomness;
  the frequency/monobit test and approximate entropy test are
  the most actionable for token corpora.

Expected entropy by character set:
  Base64 (64 chars):    log₂(64)  = 6.00 bits/char (theoretical max)
  Hex (16 chars):       log₂(16)  = 4.00 bits/char
  Alphanumeric (62):    log₂(62)  ≈ 5.95 bits/char
  Observed thresholds (practical, after NIST SP 800-22 guidance):
    < 3.5 bits/char     → SUSPICIOUS — low entropy, possible pattern
    3.5–4.5 bits/char   → LOW        — below expected for crypto tokens
    4.5–5.5 bits/char   → MEDIUM     → acceptable for most token types
    > 5.5 bits/char     → HIGH       → strong randomness

  Note on corpus size: entropy estimates are unreliable with fewer than
  100 samples (per NIST SP 800-22 §2.1). Results on small corpora are
  flagged with a confidence warning.

Outputs:
  objects_gathered.json — enriched in place (decode + entropy fields filled)
  WSTG-CRYP-04/outputs/test_outputs/cryp04_report.md

Usage:
  python3 WSTG-CRYP-04/utilities/python/cryp04_analyze.py \\
      --gathered WSTG-CRYP-04/outputs/test_outputs/objects_gathered.json
"""

import argparse
import base64
import json
import math
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from urllib.parse import unquote_plus


# ---------------------------------------------------------------------------
# ANSI
# ---------------------------------------------------------------------------
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
MAGENTA = "\033[95m"
RESET  = "\033[0m"


# ---------------------------------------------------------------------------
# Part A — Decoding
# ---------------------------------------------------------------------------

ENCODING_NAMES = [
    "base64",
    "base64_urldec",
    "base64url",
    "hex",
    "url_then_base64",
]


def try_all_decodings(raw: str) -> list[dict]:
    """
    Attempts all 5 encoding schemes.
    Returns list of dicts, one per successful decode.
    """
    results = []
    raw_stripped = raw.strip()
    url_decoded  = unquote_plus(raw_stripped)

    def _add(name, data: bytes):
        results.append({"encoding": name, "bytes": data, "byte_count": len(data)})

    # 1. Standard Base64
    for name, candidate in [("base64", raw_stripped), ("base64_urldec", url_decoded)]:
        padded = candidate + "=" * (-len(candidate) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True)
            if decoded:
                _add(name, decoded)
        except Exception:
            pass

    # 2. URL-safe Base64
    padded = raw_stripped + "=" * (-len(raw_stripped) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded)
        if decoded and not any(r["bytes"] == decoded for r in results):
            _add("base64url", decoded)
    except Exception:
        pass

    # 3. Hex
    hex_clean = re.sub(r'[^0-9a-fA-F]', '', raw_stripped)
    if len(hex_clean) % 2 == 0 and len(hex_clean) >= 2:
        try:
            decoded = bytes.fromhex(hex_clean)
            if decoded:
                _add("hex", decoded)
        except Exception:
            pass

    # 4. URL-decoded → Base64
    if url_decoded != raw_stripped:
        padded = url_decoded + "=" * (-len(url_decoded) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True)
            if decoded and not any(r["bytes"] == decoded for r in results):
                _add("url_then_base64", decoded)
        except Exception:
            pass

    return results


# Block-size classification
# Key: byte_count → (label, verdict, possible_types, note)
# "PASS"   = best practice, should NOT be reported as vulnerable
# "INFO"   = acceptable but worth noting
# "VULN"   = weak / deprecated

def classify_byte_count(n: int) -> dict:
    """Returns classification dict for a decoded byte count."""
    # Exact-match best-practice sizes first
    if n == 32:
        return {
            "verdict":        "PASS",
            "expected_types": ["AES-256 key material (256-bit)", "SHA-256 hash"],
            "note":           "32 bytes = 256-bit — current best practice (AES-256-GCM/CBC). NOT flagged as vulnerable.",
        }
    if n == 64:
        return {
            "verdict":        "PASS",
            "expected_types": ["AES-256-CBC ciphertext with IV (256+128 bits)", "SHA-512 hash"],
            "note":           "64 bytes = 512-bit — strong. NOT flagged as vulnerable.",
        }
    if n == 48:
        return {
            "verdict":        "INFO",
            "expected_types": ["AES-256 key + 128-bit IV", "AES-192 key material"],
            "note":           "48 bytes — likely AES-256 key with IV, or AES-192. Acceptable if AES-256-GCM.",
        }
    # AES-128 acceptable
    if n == 16:
        return {
            "verdict":        "INFO",
            "expected_types": ["AES-128 key (128-bit)", "AES block (one block)"],
            "note":           "16 bytes = 128-bit — AES-128 is acceptable but AES-256 is preferred.",
        }
    # DES/3DES — weak
    if n == 8:
        return {
            "verdict":        "VULN",
            "expected_types": ["DES key (56-bit effective)", "DES block", "3DES single block"],
            "note":           "8 bytes = 64-bit — DES is broken. CWE-327.",
            "cwe":            "CWE-327",
        }
    if n == 24:
        return {
            "verdict":        "VULN",
            "expected_types": ["3DES/Triple-DES key (168-bit nominal, 112-bit effective)"],
            "note":           "24 bytes = 3DES key material. 3DES is deprecated (NIST SP 800-67 Rev 2). CWE-326.",
            "cwe":            "CWE-326",
        }
    # Other multiples of 16
    if n % 16 == 0 and n > 16:
        blocks = n // 16
        return {
            "verdict":        "INFO",
            "expected_types": [f"AES CBC ciphertext ({blocks} × 16-byte blocks)", "AES key schedule material"],
            "note":           f"{n} bytes — {blocks} AES blocks. Strength depends on key size (need key to confirm 128 vs 256).",
        }
    # Other multiples of 8
    if n % 8 == 0 and n > 8:
        blocks = n // 8
        return {
            "verdict":        "INFO",
            "expected_types": [f"Possible block cipher data ({blocks} × 8-byte blocks)", "DES-family ciphertext"],
            "note":           f"{n} bytes — multiple of 8. Could be DES/3DES CBC ciphertext. Investigate further.",
        }
    # No match
    return {
        "verdict":        "UNKNOWN",
        "expected_types": [],
        "note":           f"{n} bytes — not a standard cipher block size multiple. May be hash, token, or non-encrypted data.",
    }


def analyze_decode(value: str) -> dict:
    """Runs full decode + classification for a single value."""
    if len(value) < 8:
        return {
            "attempted": False,
            "reason":    "Value too short (<8 chars) — skipped",
            "results":   [],
        }

    raw_results = try_all_decodings(value)
    if not raw_results:
        return {
            "attempted": True,
            "decoded":   False,
            "results":   [],
        }

    classified = []
    for r in raw_results:
        cls = classify_byte_count(r["byte_count"])
        classified.append({
            "encoding":           r["encoding"],
            "byte_count":         r["byte_count"],
            "expected_types":     cls["expected_types"],
            "verdict":            cls["verdict"],
            "note":               cls["note"],
            "cwe":                cls.get("cwe"),
        })

    return {
        "attempted":    True,
        "decoded":      True,
        "decode_count": len(classified),
        "results":      classified,
        "top_result":   classified[0],  # first successful decode
    }


# ---------------------------------------------------------------------------
# Part B — Shannon Entropy
# ---------------------------------------------------------------------------

def shannon_entropy(s: str) -> float:
    """Computes per-character Shannon entropy in bits."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def entropy_verdict(h: float, n_samples: int) -> tuple[str, str]:
    """
    Returns (verdict, note) for an entropy value h.
    """
    low_conf = n_samples < 100
    suffix   = f" (LOW CONFIDENCE: only {n_samples} sample{'s' if n_samples != 1 else ''} — need ≥100 for reliable estimate per NIST SP 800-22)" if low_conf else ""

    if h < 3.5:
        return "SUSPICIOUS", f"< 3.5 bits/char — very low entropy. Pattern or hardcoded value likely.{suffix}"
    elif h < 4.5:
        return "LOW",        f"3.5–4.5 bits/char — below expected for cryptographic tokens.{suffix}"
    elif h < 5.5:
        return "MEDIUM",     f"4.5–5.5 bits/char — acceptable for most token types.{suffix}"
    else:
        return "HIGH",       f"> 5.5 bits/char — strong apparent randomness.{suffix}"


def analyze_entropy_corpus(name: str, values: list[str]) -> dict:
    """Analyses entropy across a corpus of same-named parameter values."""
    # Concatenate all values for aggregate entropy
    combined = "".join(values)
    per_value = [shannon_entropy(v) for v in values if v]
    agg_entropy = shannon_entropy(combined)

    avg_per_value = sum(per_value) / len(per_value) if per_value else 0.0
    min_h = min(per_value) if per_value else 0.0
    max_h = max(per_value) if per_value else 0.0

    verdict, note = entropy_verdict(agg_entropy, len(values))

    # Detect sequential/predictable pattern in values
    sequential_flag = False
    seq_note = ""
    if len(values) >= 3:
        # Look for common prefix with incrementing suffix
        try:
            # If values look like base-10 incrementing numbers
            nums = [int(v) for v in values if v.isdigit()]
            if len(nums) >= 3:
                diffs = [nums[i+1] - nums[i] for i in range(len(nums)-1)]
                if len(set(diffs)) == 1:  # constant diff
                    sequential_flag = True
                    seq_note = f"Values appear to increment by {diffs[0]} — enumerable."
        except Exception:
            pass

        if not sequential_flag:
            # Check if all values share a long common prefix (>50% of length)
            prefix = os.path.commonprefix(values)
            avg_len = sum(len(v) for v in values) / len(values)
            if len(prefix) > avg_len * 0.5 and len(prefix) > 4:
                sequential_flag = True
                seq_note = (
                    f"Values share a long common prefix ('{prefix[:20]}...') — "
                    f"possibly sequential or predictably generated."
                )

    return {
        "parameter_name":        name,
        "sample_count":          len(values),
        "aggregate_entropy_bpc": round(agg_entropy, 4),
        "avg_per_value_bpc":     round(avg_per_value, 4),
        "min_bpc":               round(min_h, 4),
        "max_bpc":               round(max_h, 4),
        "verdict":               verdict,
        "note":                  note,
        "sequential_pattern":    sequential_flag,
        "sequential_note":       seq_note,
        "reference":             (
            "Shannon (1948) — bits/char entropy. "
            "NIST SP 800-22 Rev 1a — statistical randomness tests. "
            "Threshold 3.5 bpc derived from NIST SP 800-22 §2.1 frequency test guidance."
        ),
    }


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"VULN": 0, "SUSPICIOUS": 1, "LOW": 2, "INFO": 3, "MEDIUM": 4, "PASS": 5, "HIGH": 6, "UNKNOWN": 7}


def sev_color(v: str) -> str:
    return {
        "VULN":       RED,
        "SUSPICIOUS": RED,
        "LOW":        YELLOW,
        "INFO":       CYAN,
        "MEDIUM":     YELLOW,
        "PASS":       GREEN,
        "HIGH":       GREEN,
        "UNKNOWN":    DIM,
    }.get(v, RESET)


def build_report(gathered: dict, entropy_corpora: dict[str, dict]) -> str:
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines   = []

    lines.append("# WSTG-CRYP-04 — Weak Encryption Analysis Report")
    lines.append("")
    lines.append(f"**Generated:** {now_str}  ")
    lines.append(f"**Source XML:** {gathered['_meta']['source_xml']}  ")
    lines.append(f"**Total values analysed:** {gathered['_meta']['total_values']}  ")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ── Part A: Decoding Findings ─────────────────────────────────────────
    lines.append("## Part A — Decoding / Block-Size Analysis (CWE-326, 327, 261)")
    lines.append("")
    lines.append(
        "Each collected parameter value was decoded using up to 5 encoding "
        "schemes. Decoded byte lengths were classified against known cipher "
        "block and key sizes. **32-byte (AES-256) and 64-byte values are "
        "considered best practice and are NOT flagged as vulnerable.**"
    )
    lines.append("")

    vuln_entries   = []
    info_entries   = []
    pass_entries   = []
    unknown_entries = []

    for category in ("url_params", "body_params", "cookies", "headers"):
        for entry in gathered.get(category, []):
            da = entry.get("decode_analysis")
            if not da or not da.get("decoded"):
                continue
            for res in da.get("results", []):
                v = res.get("verdict", "UNKNOWN")
                row = {
                    "category": category,
                    "endpoint": entry["endpoint_index"],
                    "url":      entry["url"],
                    "name":     entry["name"],
                    "encoding": res["encoding"],
                    "bytes":    res["byte_count"],
                    "verdict":  v,
                    "types":    res["expected_types"],
                    "note":     res["note"],
                    "cwe":      res.get("cwe"),
                }
                if v == "VULN":
                    vuln_entries.append(row)
                elif v == "INFO":
                    info_entries.append(row)
                elif v == "PASS":
                    pass_entries.append(row)
                else:
                    unknown_entries.append(row)

    def _render_rows(rows: list[dict], label: str, show: bool = True):
        if not rows:
            lines.append(f"### {label}\n\n_None identified._\n")
            return
        lines.append(f"### {label} ({len(rows)})\n")
        lines.append("| Ep | Category | Parameter | Bytes | Encoding | Possible Types | Note |")
        lines.append("|----|----------|-----------|-------|----------|----------------|------|")
        for r in rows:
            types_str = ", ".join(r["types"][:2]) if r["types"] else "—"
            cwe_str   = f" `{r['cwe']}`" if r.get("cwe") else ""
            lines.append(
                f"| {r['endpoint']} | {r['category']} | `{r['name']}` "
                f"| {r['bytes']} | `{r['encoding']}` "
                f"| {types_str}{cwe_str} | {r['note'][:80]}... |"
                if len(r['note']) > 80
                else
                f"| {r['endpoint']} | {r['category']} | `{r['name']}` "
                f"| {r['bytes']} | `{r['encoding']}` "
                f"| {types_str}{cwe_str} | {r['note']} |"
            )
        lines.append("")

    _render_rows(vuln_entries,  "⚠️  VULNERABLE — Weak Cipher / Key Size")
    _render_rows(info_entries,  "ℹ️  INFO — Acceptable but Notable")
    _render_rows(pass_entries,  "✅ PASS — Best Practice Sizes")

    lines.append("---")
    lines.append("")

    # ── Part B: Entropy Findings ──────────────────────────────────────────
    lines.append("## Part B — Token Entropy / Randomness Analysis (NIST SP 800-22)")
    lines.append("")
    lines.append(
        "Parameter values are grouped by name across all endpoints. "
        "Per-character Shannon entropy is computed on the combined corpus. "
        "Values below 3.5 bits/char are suspicious; cryptographic tokens "
        "should exceed 5.5 bits/char (base64 theoretical max = 6.0 bpc).\n\n"
        "**Academic basis:** Shannon (1948); NIST SP 800-22 Rev 1a §2.1–2.15.  \n"
        "**Confidence note:** estimates with <100 samples are low-confidence."
    )
    lines.append("")

    if not entropy_corpora:
        lines.append("_No parameter corpora available._\n")
    else:
        lines.append("| Parameter | Samples | Entropy (bpc) | Avg/Value (bpc) | Verdict | Sequential? |")
        lines.append("|-----------|---------|---------------|-----------------|---------|-------------|")

        sorted_corpora = sorted(
            entropy_corpora.values(),
            key=lambda x: SEVERITY_ORDER.get(x["verdict"], 99)
        )

        for c in sorted_corpora:
            seq_flag = "⚠️ YES" if c["sequential_pattern"] else "No"
            lines.append(
                f"| `{c['parameter_name']}` "
                f"| {c['sample_count']} "
                f"| {c['aggregate_entropy_bpc']} "
                f"| {c['avg_per_value_bpc']} "
                f"| {c['verdict']} "
                f"| {seq_flag} |"
            )
        lines.append("")

        # Detail for suspicious/low
        problem_corpora = [c for c in sorted_corpora if c["verdict"] in ("SUSPICIOUS", "LOW")]
        if problem_corpora:
            lines.append("### Low Entropy Details\n")
            for c in problem_corpora:
                lines.append(f"**`{c['parameter_name']}`** — {c['verdict']}")
                lines.append(f"> {c['note']}")
                if c["sequential_pattern"]:
                    lines.append(f"> ⚠️ Sequential pattern: {c['sequential_note']}")
                lines.append("")

    lines.append("---")
    lines.append("")

    # ── Remediation ───────────────────────────────────────────────────────
    lines.append("## Remediation")
    lines.append("")
    lines.append(
        "**Weak cipher / key size (CWE-326, CWE-327):**\n"
        "- Replace DES, 3DES, RC4, and any 64-bit block cipher with AES-256-GCM (AEAD).\n"
        "- Key sizes below 128 bits are considered inadequate per NIST SP 800-57.\n"
        "- 3DES is deprecated as of NIST SP 800-67 Rev 2 (effective 2023).\n\n"
        "**Low entropy / weak randomness (CWE-338, CWE-330):**\n"
        "- Generate session tokens and cryptographic nonces using a "
        "CSPRNG (e.g. `os.urandom()`, `secrets` module in Python, "
        "`SecureRandom` in Java, `crypto.randomBytes()` in Node.js).\n"
        "- Token length should provide ≥128 bits of entropy "
        "(e.g. 22 base64url chars ≈ 132 bits).\n"
        "- Reference: OWASP Session Management Cheat Sheet; NIST SP 800-63B §5.1."
    )
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## References")
    lines.append("")
    lines.append("| Reference | Link |")
    lines.append("|-----------|------|")
    lines.append("| OWASP WSTG-CRYP-04 | https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/04-Testing_for_Weak_Encryption |")
    lines.append("| CWE-326 Inadequate Encryption Strength | https://cwe.mitre.org/data/definitions/326.html |")
    lines.append("| CWE-327 Broken Cryptographic Algorithm | https://cwe.mitre.org/data/definitions/327.html |")
    lines.append("| CWE-261 Weak Encoding for Password | https://cwe.mitre.org/data/definitions/261.html |")
    lines.append("| NIST SP 800-22 Statistical Tests | https://csrc.nist.gov/publications/detail/sp/800-22/rev-1a/final |")
    lines.append("| NIST SP 800-57 Key Management | https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final |")
    lines.append("| Shannon (1948) Entropy | https://doi.org/10.1002/j.1538-7305.1948.tb01338.x |")
    lines.append("")
    lines.append("---")
    lines.append("*Generated by cryp04_analyze.py — WSTG-CRYP-04*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-CRYP-04 Script 2: Decode + entropy analysis"
    )
    p.add_argument("--gathered",
        default=os.path.join("WSTG-CRYP-04", "outputs", "test_outputs", "objects_gathered.json"),
        metavar="PATH",
        help="Path to objects_gathered.json from cryp04_gather.py")
    p.add_argument("--out-dir",
        default=os.path.join("WSTG-CRYP-04", "outputs", "test_outputs"),
        metavar="DIR")
    p.add_argument("--entropy-threshold",
        type=float,
        default=3.5,
        metavar="FLOAT",
        help="Bits-per-char threshold below which verdict is SUSPICIOUS (default: 3.5)")
    args = p.parse_args()

    width = 65
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD} WSTG-CRYP-04 — Decode + Entropy Analyzer{RESET}")
    print(f"{BOLD}{'='*width}{RESET}")
    print(f"  Gathered : {args.gathered}")
    print(f"  Out dir  : {args.out_dir}\n")

    try:
        with open(args.gathered) as f:
            gathered: dict = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"{RED}[!] Cannot read gathered JSON: {e}{RESET}", file=sys.stderr)
        sys.exit(1)

    os.makedirs(args.out_dir, exist_ok=True)

    # ── Part A: Decode analysis ───────────────────────────────────────────
    print(f"\n{CYAN}{BOLD}Part A — Decode / Block-Size Analysis{RESET}\n")

    categories = ("url_params", "body_params", "cookies", "headers")
    vuln_count = 0
    info_count = 0
    pass_count = 0

    for category in categories:
        entries = gathered.get(category, [])
        cat_label = category.replace("_", " ").title()
        for entry in entries:
            val = entry.get("value", "")
            da  = analyze_decode(val)
            entry["decode_analysis"] = da

            if da.get("decoded"):
                for res in da["results"]:
                    v = res.get("verdict")
                    col = sev_color(v)
                    print(
                        f"  [{entry['endpoint_index']:3d}] {cat_label:<14} "
                        f"`{entry['name']:<20}` "
                        f"{res['byte_count']:3d}B  "
                        f"{col}{v:<10}{RESET}  "
                        f"{DIM}{res['encoding']}{RESET}"
                    )
                    if v == "VULN":
                        vuln_count += 1
                    elif v == "INFO":
                        info_count += 1
                    elif v == "PASS":
                        pass_count += 1

    print(f"\n  Summary: {RED}{vuln_count} VULN{RESET}  {CYAN}{info_count} INFO{RESET}  {GREEN}{pass_count} PASS{RESET}")

    # ── Part B: Entropy analysis ──────────────────────────────────────────
    print(f"\n{CYAN}{BOLD}Part B — Shannon Entropy Analysis{RESET}\n")
    print(f"  {DIM}Academic basis: Shannon (1948); NIST SP 800-22 Rev 1a{RESET}\n")

    # Group values by parameter name across all categories
    corpus: dict[str, list[str]] = defaultdict(list)
    for category in categories:
        for entry in gathered.get(category, []):
            val = entry.get("value", "")
            if val:
                corpus[entry["name"]].append(val)

    entropy_corpora: dict[str, dict] = {}
    for name, values in corpus.items():
        result = analyze_entropy_corpus(name, values)
        entropy_corpora[name] = result

        col = sev_color(result["verdict"])
        seq = f"  {YELLOW}⚠ sequential{RESET}" if result["sequential_pattern"] else ""
        print(
            f"  `{name:<25}` "
            f"n={result['sample_count']:<4} "
            f"entropy={result['aggregate_entropy_bpc']:.3f} bpc  "
            f"{col}{result['verdict']:<12}{RESET}"
            f"{seq}"
        )

    # Write entropy results back to entries (match by name)
    for category in categories:
        for entry in gathered.get(category, []):
            name = entry.get("name")
            if name in entropy_corpora:
                entry["entropy_analysis"] = entropy_corpora[name]

    # Persist enriched gathered JSON
    with open(args.gathered, "w") as f:
        json.dump(gathered, f, indent=2)
    print(f"\n{GREEN}[+] objects_gathered.json enriched: {args.gathered}{RESET}")

    # Build and write report
    report = build_report(gathered, entropy_corpora)
    report_path = os.path.join(args.out_dir, "cryp04_report.md")
    with open(report_path, "w") as f:
        f.write(report)
    print(f"{GREEN}[+] Report: {report_path}{RESET}")

    # Final verdict line
    print()
    problem_entropy = [c for c in entropy_corpora.values() if c["verdict"] in ("SUSPICIOUS", "LOW")]
    if vuln_count or problem_entropy:
        print(f"  {RED}{BOLD}⚠  Findings: {vuln_count} weak cipher/key value(s), {len(problem_entropy)} low-entropy parameter(s).{RESET}")
    else:
        print(f"  {GREEN}✓  No weak cipher values or low-entropy tokens identified.{RESET}")
    print()


if __name__ == "__main__":
    main()
