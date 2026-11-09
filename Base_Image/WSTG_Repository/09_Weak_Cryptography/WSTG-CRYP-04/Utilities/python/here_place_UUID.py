#!/usr/bin/env python3
"""
WSTG-CRYP-04 — Testing for Weak Encryption
Script 4: here_place_UUID.py

Reads UUIDs.txt (produced by case2_cryp04.py) and performs deep
analysis on each UUID to identify version, decode embedded data,
and assess predictability/security risk.

Per-UUID analysis:
  v1 (time-based):
    • Extract 60-bit timestamp → convert to UTC datetime (UUID epoch = 1582-10-15)
    • Extract 48-bit node (MAC address) → check random vs real MAC (RFC 4122 bit 40)
    • Extract 14-bit clock_seq → check for sequential increment across corpus
    • Risk: HIGH — timestamp + MAC leaks machine identity and enables enumeration

  v2 (DCE Security):
    • Similar to v1 + POSIX UID/GID embedded in time_low
    • Risk: HIGH — extremely rare in web apps; flag immediately

  v3 (MD5 hash-based):
    • Deterministic: same namespace+name → same UUID, always
    • MD5 is broken (collision attacks, CWE-327)
    • Risk: MEDIUM — predictable if namespace/name guessable

  v4 (random):
    • Validate that variant bits are set correctly (RFC 4122 §4.4)
    • Corpus analysis: check if any bit positions across multiple v4 UUIDs
      show suspiciously low entropy (constant or near-constant bits suggest
      a broken/seeded PRNG)
    • Risk: LOW if generated with CSPRNG; MEDIUM if weak PRNG detected

  v5 (SHA-1 hash-based):
    • Same determinism risk as v3 but with SHA-1 instead of MD5
    • SHA-1 is deprecated for cryptographic use (CWE-327)
    • Risk: MEDIUM

  v6/v7 (new standards, RFC 9562):
    • v6: reordered v1 (time-sortable, still leaks timestamp)
    • v7: Unix-ms timestamp + random — time-ordered but random suffix
    • Risk: INFO for v7 (modern, acceptable); MEDIUM for v6 (leaks time)

  Unknown version:
    • Could be a nil UUID (all zeros), max UUID (all ones), or non-standard
    • Flag for manual review

Corpus-level checks (require ≥2 UUIDs of the same version):
  - v1: Are timestamps sequential within a window? (enumerable)
  - v1: Do all UUIDs share the same node (same machine)?
  - v4: Bit-position entropy check (weak PRNG detection)
  - Mixed versions: flag as inconsistent implementation

Outputs:
  WSTG-CRYP-04/outputs/test_outputs/uuid_report.md
  WSTG-CRYP-04/outputs/test_outputs/uuid_analysis.json

Usage:
  python3 WSTG-CRYP-04/utilities/python/here_place_UUID.py \\
      --uuids WSTG-CRYP-04/inputs/data/UUIDs.txt
"""

import argparse
import json
import math
import os
import re
import sys
import uuid as uuid_mod
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta


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
# UUID epoch offset
# UUID timestamps are 100-nanosecond intervals since 1582-10-15 00:00:00 UTC
# Python datetime epoch is 1970-01-01 00:00:00 UTC
# Offset in 100-ns intervals:
# ---------------------------------------------------------------------------
UUID_EPOCH_OFFSET_100NS = 0x01b21dd213814000  # ~122192928000000000


def uuid_timestamp_to_datetime(uuid_time: int) -> datetime:
    """Converts UUID v1 60-bit timestamp to UTC datetime."""
    unix_100ns = uuid_time - UUID_EPOCH_OFFSET_100NS
    unix_seconds = unix_100ns / 1e7
    return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=unix_seconds)


# ---------------------------------------------------------------------------
# MAC address analysis
# ---------------------------------------------------------------------------

def analyze_node(node: int) -> dict:
    """Analyses the 48-bit node field of a v1 UUID."""
    mac_hex = f"{node:012x}"
    mac_str = ":".join(mac_hex[i:i+2] for i in range(0, 12, 2))

    # RFC 4122 §4.5: if bit 40 of the node is 1, the node was randomly generated
    # Bit 40 is the LSB of the first octet (multicast bit in Ethernet)
    first_octet = (node >> 40) & 0xFF
    is_random_node = bool(first_octet & 0x01)

    # Check for known reserved/special ranges
    is_broadcast = (node == 0xFFFFFFFFFFFF)
    is_nil       = (node == 0x000000000000)

    return {
        "mac_hex":         mac_str,
        "raw_node":        hex(node),
        "is_random_node":  is_random_node,
        "is_broadcast":    is_broadcast,
        "is_nil_node":     is_nil,
        "note": (
            "Node was randomly generated per RFC 4122 §4.5 (bit 40 set) — MAC not leaked."
            if is_random_node else
            "Node appears to be a real MAC address — machine identity may be disclosed."
        ),
    }


# ---------------------------------------------------------------------------
# Per-UUID analysis
# ---------------------------------------------------------------------------

def analyze_single(uuid_str: str) -> dict:
    uuid_str = uuid_str.strip().lower()

    result = {
        "uuid":             uuid_str,
        "is_valid":         False,
        "version":          None,
        "variant":          None,
        "risk":             "UNKNOWN",
        "risk_reason":      "",
        "details":          {},
        "cwe":              [],
        "recommendations":  [],
    }

    # Validate
    try:
        u = uuid_mod.UUID(uuid_str)
    except ValueError as e:
        result["risk_reason"] = f"Invalid UUID: {e}"
        return result

    result["is_valid"] = True

    # Nil / Max UUIDs
    if str(u) == "00000000-0000-0000-0000-000000000000":
        result["version"]     = "nil"
        result["risk"]        = "INFO"
        result["risk_reason"] = "Nil UUID (all zeros) — placeholder or uninitialized value."
        return result

    if str(u) == "ffffffff-ffff-ffff-ffff-ffffffffffff":
        result["version"]     = "max"
        result["risk"]        = "INFO"
        result["risk_reason"] = "Max UUID (all ones) — placeholder value."
        return result

    version = u.version
    result["version"] = version

    # Variant field
    try:
        variant_bits = (u.int >> 62) & 0b11
        result["variant"] = f"RFC 4122 (Leach-Salz)" if variant_bits >= 2 else f"Other (bits={variant_bits:02b})"
    except Exception:
        pass

    # ── Version-specific analysis ──────────────────────────────────────
    if version == 1:
        ts_dt = uuid_timestamp_to_datetime(u.time)
        node_info = analyze_node(u.node)
        clock_seq = u.clock_seq

        result["risk"] = "HIGH"
        result["risk_reason"] = (
            "v1 UUID embeds a 60-bit timestamp (precise to 100ns) and a 48-bit "
            "node (typically MAC address). Sequential generation enables enumeration. "
            "Timestamp reveals when the token was issued."
        )
        result["cwe"] = ["CWE-330 (Use of Insufficiently Random Values)"]
        result["details"] = {
            "timestamp_raw":    u.time,
            "timestamp_utc":    ts_dt.isoformat(),
            "clock_seq":        clock_seq,
            "node":             node_info,
            "concerns": [
                f"Timestamp: {ts_dt.strftime('%Y-%m-%d %H:%M:%S.%f')} UTC",
                f"Node (MAC): {node_info['mac_hex']} — {'random (safe)' if node_info['is_random_node'] else 'REAL MAC — machine identity disclosed'}",
                f"Clock sequence: {clock_seq} — if sequential across observations, enumerable",
                "Sequential nature allows an attacker to predict past and future UUIDs",
            ],
        }
        result["recommendations"] = [
            "Replace v1 with v4 (random) or v7 (time-ordered random) UUIDs.",
            "If time-sortability is required, use UUIDv7 (RFC 9562) — random suffix, no MAC.",
        ]

    elif version == 2:
        result["risk"] = "HIGH"
        result["risk_reason"] = (
            "v2 (DCE Security) UUID embeds timestamp, MAC, and POSIX UID/GID. "
            "Extremely rare in web applications — presence is unusual and warrants investigation."
        )
        result["cwe"] = ["CWE-330", "CWE-200 (Exposure of Sensitive Information)"]
        result["details"] = {
            "concerns": [
                "Contains timestamp (predictable/enumerable)",
                "Contains MAC address (machine identity)",
                "Contains POSIX UID/GID (system user information leaked)",
                "Rarely used in web apps — investigate why this version is present",
            ]
        }
        result["recommendations"] = [
            "Replace with v4 or v7. Investigate why v2 is present in this context.",
        ]

    elif version == 3:
        result["risk"] = "MEDIUM"
        result["risk_reason"] = (
            "v3 uses MD5 hashing. Deterministic: identical namespace+name always "
            "produces the same UUID. If the input (namespace, name) is guessable, "
            "the UUID is predictable. MD5 is cryptographically broken."
        )
        result["cwe"] = ["CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)", "CWE-330"]
        result["details"] = {
            "hash_algorithm": "MD5",
            "concerns": [
                "MD5 is broken — collision and preimage attacks exist",
                "Deterministic: attacker who knows the namespace can predict UUIDs for known names",
                "Common namespaces (DNS=6ba7b810-..., URL=6ba7b811-...) are public",
            ]
        }
        result["recommendations"] = [
            "Use v4 for random tokens.",
            "If namespace-based UUIDs are required for idempotency, use v5 (SHA-1) at minimum, "
            "but prefer a keyed hash (HMAC-SHA256) with a secret namespace.",
        ]

    elif version == 4:
        # Validate structure: version nibble = 4, variant bits = 10xx
        version_nibble = (u.int >> 76) & 0xF
        variant_nibble = (u.int >> 62) & 0x3

        structural_ok = (version_nibble == 4) and (variant_nibble >= 2)

        result["risk"] = "LOW"
        result["risk_reason"] = (
            "v4 is randomly generated. Risk is LOW if produced by a CSPRNG. "
            "RFC 4122 structural bits are " +
            ("correct." if structural_ok else "MALFORMED — possible non-standard generator.")
        )
        result["cwe"] = [] if structural_ok else ["CWE-330"]
        result["details"] = {
            "structural_valid": structural_ok,
            "version_nibble":   hex(version_nibble),
            "variant_nibble":   f"{variant_nibble:02b}",
            "concerns": (
                [] if structural_ok else
                ["Version or variant bits are not RFC 4122 compliant — non-standard UUID generator?"]
            ),
            "note": (
                "Corpus-level weak PRNG detection requires multiple v4 UUIDs — "
                "see corpus analysis section."
            ),
        }
        result["recommendations"] = [
            "Ensure UUIDs are generated with os.urandom() / secrets.token_bytes() (Python), "
            "SecureRandom (Java), or crypto.randomUUID() (Node.js/browser).",
            "Avoid seeded PRNGs (Random(), Math.random()) for UUID generation.",
        ]

    elif version == 5:
        result["risk"] = "MEDIUM"
        result["risk_reason"] = (
            "v5 uses SHA-1 hashing. Deterministic: identical namespace+name always "
            "produces the same UUID. SHA-1 is deprecated for cryptographic use. "
            "If input is guessable, UUID is predictable."
        )
        result["cwe"] = ["CWE-327", "CWE-330"]
        result["details"] = {
            "hash_algorithm": "SHA-1",
            "concerns": [
                "SHA-1 is deprecated for cryptographic use (NIST 2011)",
                "Deterministic — same input always yields same UUID",
                "Attacker with known namespace can enumerate UUIDs for guessable names",
            ]
        }
        result["recommendations"] = [
            "Use v4 for random tokens, or a keyed HMAC-SHA256 with a secret key for deterministic IDs.",
        ]

    elif version == 6:
        # RFC 9562 — reordered v1
        result["risk"] = "MEDIUM"
        result["risk_reason"] = (
            "v6 (RFC 9562) is a time-sortable reordering of v1. Still embeds a "
            "timestamp — token issuance time is recoverable. No MAC (uses random node)."
        )
        result["cwe"] = ["CWE-330"]
        result["details"] = {
            "concerns": [
                "Timestamp embedded — issuance time disclosed",
                "Time-ordered: sequential tokens are predictable within the same process",
                "Newer than v1/v4 — indicates modern implementation awareness",
            ]
        }
        result["recommendations"] = [
            "Prefer v7 over v6 — v7 uses a Unix millisecond timestamp + random suffix, "
            "which is sortable without leaking sub-millisecond precision.",
        ]

    elif version == 7:
        # RFC 9562 — Unix-ms timestamp + random
        result["risk"] = "INFO"
        result["risk_reason"] = (
            "v7 (RFC 9562) — modern time-ordered UUID with random suffix. "
            "Embeds Unix millisecond timestamp only (not MAC, not 100ns precision). "
            "Considered acceptable for most web application use cases."
        )
        result["cwe"] = []
        result["details"] = {
            "note": (
                "UUIDv7 is the current recommended standard for database-friendly "
                "time-ordered identifiers. Random suffix (62 bits) provides good entropy."
            ),
            "concerns": [
                "Millisecond timestamp embedded — token creation time is approximate but knowable",
            ]
        }
        result["recommendations"] = [
            "v7 is acceptable. Ensure the random suffix is generated by a CSPRNG.",
        ]

    else:
        result["risk"] = "UNKNOWN"
        result["risk_reason"] = f"UUID version {version} is not defined in RFC 4122 or RFC 9562. Manual review required."
        result["details"] = {"raw_int": str(u.int)}

    return result


# ---------------------------------------------------------------------------
# Corpus-level analysis
# ---------------------------------------------------------------------------

def analyze_corpus(analyses: list[dict]) -> dict:
    """Performs cross-UUID corpus checks."""
    corpus_result = {
        "total":           len(analyses),
        "version_counts":  {},
        "mixed_versions":  False,
        "v1_checks":       None,
        "v4_checks":       None,
        "flags":           [],
    }

    # Version distribution
    version_counts: dict[int | str, int] = Counter(
        a.get("version") for a in analyses if a.get("is_valid")
    )
    corpus_result["version_counts"] = {str(k): v for k, v in version_counts.items()}

    valid_versions = [v for v in version_counts.keys() if isinstance(v, int)]
    if len(valid_versions) > 1:
        corpus_result["mixed_versions"] = True
        corpus_result["flags"].append(
            f"Mixed UUID versions detected {dict(version_counts)} — "
            f"inconsistent implementation. Different generators may be in use."
        )

    # ── v1 corpus checks ──────────────────────────────────────────────────
    v1_uuids = [a for a in analyses if a.get("version") == 1 and a.get("is_valid")]
    if len(v1_uuids) >= 2:
        v1_checks = {}

        # Timestamp sequentiality
        timestamps = []
        for a in v1_uuids:
            ts = a.get("details", {}).get("timestamp_raw")
            if ts is not None:
                timestamps.append(ts)

        if len(timestamps) >= 2:
            timestamps_sorted = sorted(timestamps)
            diffs = [timestamps_sorted[i+1] - timestamps_sorted[i]
                     for i in range(len(timestamps_sorted)-1)]
            avg_diff = sum(diffs) / len(diffs)
            # 10_000_000 = 1 second in 100-ns units
            all_within_1s = all(d < 10_000_000 for d in diffs)
            v1_checks["timestamp_diffs_100ns"] = diffs[:10]  # first 10
            v1_checks["avg_diff_seconds"]       = round(avg_diff / 1e7, 4)
            v1_checks["sequential_within_1s"]   = all_within_1s
            if all_within_1s:
                corpus_result["flags"].append(
                    "v1 UUIDs: all timestamps within 1-second windows — likely sequential "
                    "generation from the same process. Enumerable."
                )

        # Shared node (same machine)
        nodes = [a.get("details", {}).get("node", {}).get("raw_node") for a in v1_uuids]
        nodes = [n for n in nodes if n]
        if nodes and len(set(nodes)) == 1:
            v1_checks["shared_node"] = nodes[0]
            corpus_result["flags"].append(
                f"v1 UUIDs: all share node {nodes[0]} — all generated on the same machine."
            )

        # Clock sequence spread
        clock_seqs = [a.get("details", {}).get("clock_seq") for a in v1_uuids]
        clock_seqs = [c for c in clock_seqs if c is not None]
        if len(clock_seqs) >= 2:
            cs_diffs = [abs(clock_seqs[i+1] - clock_seqs[i]) for i in range(len(clock_seqs)-1)]
            if all(d <= 1 for d in cs_diffs):
                v1_checks["clock_seq_sequential"] = True
                corpus_result["flags"].append(
                    "v1 UUIDs: clock_seq increments by ≤1 between samples — strictly sequential."
                )

        corpus_result["v1_checks"] = v1_checks

    # ── v4 corpus checks (weak PRNG detection) ────────────────────────────
    v4_uuids = [a for a in analyses if a.get("version") == 4 and a.get("is_valid")]
    if len(v4_uuids) >= 5:
        v4_checks = {}

        # Collect the 128-bit int representations
        int_vals = []
        for a in v4_uuids:
            try:
                u = uuid_mod.UUID(a["uuid"])
                int_vals.append(u.int)
            except Exception:
                pass

        if len(int_vals) >= 5:
            # Check per-bit entropy: for each of the 128 bit positions,
            # compute the fraction of 1s. A truly random source should be ~0.5.
            # Bits fixed by spec (version=0100 at bits 76-79, variant=10 at bits 62-63)
            # are expected to be constant — exclude them.
            SPEC_BITS = set(range(62, 64)) | set(range(76, 80))  # variant + version

            suspicious_bits = []
            for bit_pos in range(128):
                if bit_pos in SPEC_BITS:
                    continue
                bit_vals = [(v >> bit_pos) & 1 for v in int_vals]
                fraction_ones = sum(bit_vals) / len(bit_vals)
                # Flag if fraction is outside 0.05–0.95 (very skewed for n≥5)
                if fraction_ones < 0.05 or fraction_ones > 0.95:
                    suspicious_bits.append({
                        "bit_position": bit_pos,
                        "fraction_ones": round(fraction_ones, 3),
                    })

            v4_checks["bits_analysed"]   = 128 - len(SPEC_BITS)
            v4_checks["suspicious_bits"] = suspicious_bits
            v4_checks["sample_count"]    = len(int_vals)

            if suspicious_bits:
                corpus_result["flags"].append(
                    f"v4 UUIDs: {len(suspicious_bits)} bit position(s) show near-constant values "
                    f"across {len(int_vals)} samples — possible weak or seeded PRNG. "
                    f"Suspicious positions: {[b['bit_position'] for b in suspicious_bits[:5]]}"
                )
            else:
                v4_checks["prng_assessment"] = (
                    f"No strongly biased bit positions detected across {len(int_vals)} samples. "
                    f"Apparent PRNG quality: GOOD (note: ≥100 samples needed for high confidence)."
                )

        corpus_result["v4_checks"] = v4_checks

    return corpus_result


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3, "UNKNOWN": 4}

RISK_COLOR = {
    "HIGH":    RED,
    "MEDIUM":  YELLOW,
    "LOW":     CYAN,
    "INFO":    DIM,
    "UNKNOWN": DIM,
}


def build_report(analyses: list[dict], corpus: dict) -> str:
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines   = []

    lines.append("# WSTG-CRYP-04 — UUID Analysis Report")
    lines.append("")
    lines.append(f"**Generated:** {now_str}  ")
    lines.append(f"**UUIDs analysed:** {len(analyses)}  ")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ── Corpus summary ────────────────────────────────────────────────────
    lines.append("## Corpus Summary")
    lines.append("")
    lines.append(f"| Version | Count | Risk Level |")
    lines.append(f"|---------|-------|------------|")

    ver_risk = {
        1: "HIGH", 2: "HIGH", 3: "MEDIUM", 4: "LOW",
        5: "MEDIUM", 6: "MEDIUM", 7: "INFO",
        "nil": "INFO", "max": "INFO", "UNKNOWN": "UNKNOWN",
    }

    for ver, count in sorted(corpus["version_counts"].items()):
        try:
            ver_int = int(ver)
        except (ValueError, TypeError):
            ver_int = ver
        risk = ver_risk.get(ver_int, "UNKNOWN")
        lines.append(f"| v{ver} | {count} | {risk} |")

    lines.append("")

    if corpus["flags"]:
        lines.append("### ⚠️ Corpus-Level Flags\n")
        for flag in corpus["flags"]:
            lines.append(f"- {flag}")
        lines.append("")

    # v1 corpus detail
    if corpus.get("v1_checks"):
        c = corpus["v1_checks"]
        lines.append("### v1 Corpus Detail\n")
        if c.get("sequential_within_1s"):
            lines.append("⚠️ **Timestamps are sequential within 1-second windows** — generation is enumerable.\n")
        if c.get("shared_node"):
            lines.append(f"⚠️ **All UUIDs share node `{c['shared_node']}`** — same machine.\n")
        if c.get("clock_seq_sequential"):
            lines.append("⚠️ **clock_seq increments by ≤1** — strictly sequential generation.\n")
        if c.get("avg_diff_seconds") is not None:
            lines.append(f"Average time between sequential UUIDs: **{c['avg_diff_seconds']}s**\n")

    # v4 corpus detail
    if corpus.get("v4_checks"):
        c = corpus["v4_checks"]
        lines.append("### v4 Corpus Detail (PRNG Quality)\n")
        lines.append(
            f"Analysed {c.get('bits_analysed', '?')} random bit positions "
            f"across {c.get('sample_count', '?')} UUIDs.\n"
        )
        suspicious = c.get("suspicious_bits", [])
        if suspicious:
            lines.append(f"⚠️ **{len(suspicious)} suspicious bit position(s) detected:**\n")
            for b in suspicious:
                lines.append(f"  - Bit {b['bit_position']}: {b['fraction_ones']*100:.1f}% ones (expected ~50%)")
            lines.append("")
        else:
            lines.append(c.get("prng_assessment", "") + "\n")

    lines.append("---")
    lines.append("")

    # ── Per-UUID detail ───────────────────────────────────────────────────
    lines.append("## Per-UUID Analysis\n")

    sorted_analyses = sorted(
        analyses,
        key=lambda a: (RISK_ORDER.get(a.get("risk", "UNKNOWN"), 99), a["uuid"])
    )

    for a in sorted_analyses:
        risk_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "ℹ️", "UNKNOWN": "❓"}.get(a.get("risk"), "❓")
        lines.append(f"### {risk_icon} `{a['uuid']}`")
        lines.append("")

        if not a["is_valid"]:
            lines.append(f"❌ **Invalid UUID** — {a.get('risk_reason', '')}\n")
            lines.append("---\n")
            continue

        lines.append(f"**Version:** {a.get('version', '?')}  ")
        lines.append(f"**Risk:** {a.get('risk', '?')}  ")
        lines.append(f"**Assessment:** {a.get('risk_reason', '')}  ")

        if a.get("cwe"):
            lines.append(f"**CWE:** {', '.join(a['cwe'])}  ")

        details = a.get("details", {})

        if a.get("version") == 1:
            lines.append("")
            lines.append("**Decoded v1 fields:**")
            lines.append("")
            lines.append(f"| Field | Value |")
            lines.append(f"|-------|-------|")
            lines.append(f"| Timestamp (UTC) | `{details.get('timestamp_utc', '?')}` |")
            lines.append(f"| Clock sequence | `{details.get('clock_seq', '?')}` |")
            node = details.get("node", {})
            lines.append(f"| Node (MAC) | `{node.get('mac_hex', '?')}` |")
            lines.append(f"| Node type | {'Random (safe, RFC 4122 §4.5)' if node.get('is_random_node') else '⚠️ Real MAC address — machine identity disclosed'} |")
            lines.append("")

        if details.get("concerns"):
            lines.append("**Concerns:**")
            lines.append("")
            for concern in details["concerns"]:
                lines.append(f"- {concern}")
            lines.append("")

        if a.get("recommendations"):
            lines.append("**Recommendations:**")
            lines.append("")
            for rec in a["recommendations"]:
                lines.append(f"- {rec}")
            lines.append("")

        lines.append("---")
        lines.append("")

    # ── Remediation ───────────────────────────────────────────────────────
    lines.append("## Remediation Summary\n")
    lines.append(
        "| Finding | Recommended Fix |\n"
        "|---------|----------------|\n"
        "| v1/v2 UUIDs (MAC + timestamp) | Replace with v4 or v7 |\n"
        "| v3 UUIDs (MD5-based) | Replace with v4; use HMAC-SHA256 for deterministic IDs |\n"
        "| v5 UUIDs (SHA-1-based) | Replace with v4; use HMAC-SHA256 for deterministic IDs |\n"
        "| v4 with biased bits (weak PRNG) | Use CSPRNG: `os.urandom()`, `crypto.randomUUID()`, `SecureRandom` |\n"
        "| v6 (time-sortable v1) | Prefer v7 — same sortability, no sub-ms timestamp leak |\n"
        "| v7 | Acceptable — verify CSPRNG is used for random suffix |\n"
    )
    lines.append("")
    lines.append("**References:**")
    lines.append("")
    lines.append("- RFC 4122 — UUID specification: https://datatracker.ietf.org/doc/html/rfc4122")
    lines.append("- RFC 9562 — New UUID formats (v6, v7, v8): https://datatracker.ietf.org/doc/html/rfc9562")
    lines.append("- CWE-330 — Use of Insufficiently Random Values: https://cwe.mitre.org/data/definitions/330.html")
    lines.append("- CWE-327 — Broken/Risky Cryptographic Algorithm: https://cwe.mitre.org/data/definitions/327.html")
    lines.append("- OWASP Testing for Weak Cryptography (WSTG-CRYP-04): https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/04-Testing_for_Weak_Encryption")
    lines.append("")
    lines.append("---")
    lines.append("*Generated by here_place_UUID.py — WSTG-CRYP-04*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-CRYP-04 Script 4: UUID deep analysis"
    )
    p.add_argument("--uuids",
        default=os.path.join("WSTG-CRYP-04", "inputs", "data", "UUIDs.txt"),
        metavar="PATH",
        help="Path to UUIDs.txt from case2_cryp04.py")
    p.add_argument("--out-dir",
        default=os.path.join("WSTG-CRYP-04", "outputs", "test_outputs"),
        metavar="DIR")
    args = p.parse_args()

    width = 65
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD} WSTG-CRYP-04 — UUID Deep Analysis{RESET}")
    print(f"{BOLD}{'='*width}{RESET}")
    print(f"  UUIDs : {args.uuids}\n")

    try:
        with open(args.uuids) as f:
            raw_lines = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
    except FileNotFoundError:
        print(f"{RED}[!] UUIDs.txt not found: {args.uuids}{RESET}", file=sys.stderr)
        sys.exit(1)

    if not raw_lines:
        print(f"{YELLOW}[!] No UUIDs in file.{RESET}\n")
        sys.exit(0)

    print(f"  {len(raw_lines)} UUID(s) to analyse\n")

    analyses = []
    for raw in raw_lines:
        result = analyze_single(raw)
        analyses.append(result)

        risk = result.get("risk", "UNKNOWN")
        col  = RISK_COLOR.get(risk, DIM)
        ver  = result.get("version", "?")
        print(
            f"  {col}{risk:<8}{RESET}  "
            f"v{ver:<3}  "
            f"{CYAN}{result['uuid']}{RESET}"
        )

        # Print v1 decoded timestamp inline
        if result.get("version") == 1 and result.get("details", {}).get("timestamp_utc"):
            ts = result["details"]["timestamp_utc"]
            node = result["details"].get("node", {})
            print(
                f"           {DIM}ts={ts}  "
                f"node={'random' if node.get('is_random_node') else node.get('mac_hex','?')}{RESET}"
            )

    # Corpus analysis
    print(f"\n{CYAN}{BOLD}Corpus Analysis{RESET}\n")
    corpus = analyze_corpus(analyses)

    if corpus["flags"]:
        for flag in corpus["flags"]:
            print(f"  {YELLOW}⚠  {flag}{RESET}")
    else:
        print(f"  {GREEN}✓  No corpus-level anomalies detected.{RESET}")

    os.makedirs(args.out_dir, exist_ok=True)

    # Write JSON
    json_path = os.path.join(args.out_dir, "uuid_analysis.json")
    with open(json_path, "w") as f:
        json.dump({"analyses": analyses, "corpus": corpus}, f, indent=2, default=str)
    print(f"\n{GREEN}[+] uuid_analysis.json → {json_path}{RESET}")

    # Write report
    report = build_report(analyses, corpus)
    report_path = os.path.join(args.out_dir, "uuid_report.md")
    with open(report_path, "w") as f:
        f.write(report)
    print(f"{GREEN}[+] uuid_report.md     → {report_path}{RESET}")

    # Final verdict
    high_risk = [a for a in analyses if a.get("risk") == "HIGH"]
    medium_risk = [a for a in analyses if a.get("risk") == "MEDIUM"]
    print()
    if high_risk or corpus["flags"]:
        print(
            f"  {RED}{BOLD}⚠  {len(high_risk)} HIGH-risk UUID(s), "
            f"{len(corpus['flags'])} corpus flag(s).{RESET}"
        )
    elif medium_risk:
        print(f"  {YELLOW}⚠  {len(medium_risk)} MEDIUM-risk UUID(s).{RESET}")
    else:
        print(f"  {GREEN}✓  No high-risk UUIDs detected.{RESET}")
    print()


if __name__ == "__main__":
    main()
