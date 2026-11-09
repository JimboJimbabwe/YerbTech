#!/usr/bin/env python3
"""
WSTG-CRYP-02 — Testing for Padding Oracle
Script 2: padding_verdict.py

Reads padding_oracle_scan.json (from padding_scan.py), confirms
which entries are block-size candidates (decoded byte length is a
multiple of 8 or 16 AND has ≥2 blocks), generates 256-payload
Burp Intruder probe wordlists, and writes a findings report.

Probe generation logic:
  For each candidate:
    1. Decode the raw value using its detected encoding.
    2. Split into blocks of block_size bytes.
    3. Identify the penultimate block (blocks[-2]).
    4. Target the LAST BYTE of the penultimate block.
    5. XOR that byte with each value 0x00–0xFF (256 variants).
    6. Re-assemble the full ciphertext with the modified block.
    7. Re-encode to the original encoding (base64/hex/etc.).
    8. Write all 256 encoded strings to a wordlist file.

  These 256 payloads are sent to the endpoint in Burp Intruder
  (Sniper mode, payload position = the parameter value).
  A padding oracle is confirmed when one or more payloads produce
  a distinct response (different status, body length, or error message)
  from the majority.

Outputs:
  WSTG-CRYP-02/outputs/test_outputs/<param>_ep<idx>_probes.txt  (per candidate)
  WSTG-CRYP-02/outputs/test_outputs/padding_oracle_report.md

Usage:
  python3 WSTG-CRYP-02/utilities/python/padding_verdict.py \\
      --scan WSTG-CRYP-02/outputs/test_outputs/padding_oracle_scan.json
"""

import argparse
import base64
import json
import os
import re
import sys
from datetime import datetime
from urllib.parse import quote_plus


# ---------------------------------------------------------------------------
# ANSI
# ---------------------------------------------------------------------------
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
RESET  = "\033[0m"


# ---------------------------------------------------------------------------
# Decoding (mirrors padding_scan.py, needed to reconstruct bytes)
# ---------------------------------------------------------------------------

def decode_value(raw: str, encoding: str) -> bytes | None:
    """
    Decodes raw string back to bytes using the named encoding.
    Returns None if decoding fails.
    """
    from urllib.parse import unquote_plus
    raw_stripped = raw.strip()
    url_decoded  = unquote_plus(raw_stripped)

    try:
        if encoding in ("base64", "base64_urldec"):
            candidate = url_decoded if encoding == "base64_urldec" else raw_stripped
            padded    = candidate + "=" * (-len(candidate) % 4)
            return base64.b64decode(padded, validate=True)

        elif encoding in ("base64url", "base64url_urldec"):
            candidate = url_decoded if encoding == "base64url_urldec" else raw_stripped
            padded    = candidate + "=" * (-len(candidate) % 4)
            return base64.urlsafe_b64decode(padded)

        elif encoding == "hex":
            hex_clean = re.sub(r'[^0-9a-fA-F]', '', raw_stripped)
            return bytes.fromhex(hex_clean)

        elif encoding == "url_then_base64":
            padded = url_decoded + "=" * (-len(url_decoded) % 4)
            return base64.b64decode(padded, validate=True)

    except Exception:
        return None

    return None


# ---------------------------------------------------------------------------
# Re-encoding
# ---------------------------------------------------------------------------

def reencode(data: bytes, encoding: str, original_raw: str) -> str:
    """
    Re-encodes modified bytes back to the original encoding format.
    Tries to preserve formatting (padding, URL-encoding, case).
    """
    # Determine if original was URL-encoded (had %xx characters)
    was_url_encoded = "%" in original_raw or "+" in original_raw

    if encoding in ("base64", "base64_urldec"):
        encoded = base64.b64encode(data).decode("ascii")
        # Preserve padding style of original
        if "=" not in original_raw:
            encoded = encoded.rstrip("=")
        if was_url_encoded:
            encoded = quote_plus(encoded)
        return encoded

    elif encoding in ("base64url", "base64url_urldec"):
        encoded = base64.urlsafe_b64encode(data).decode("ascii")
        if "=" not in original_raw:
            encoded = encoded.rstrip("=")
        if was_url_encoded:
            encoded = quote_plus(encoded)
        return encoded

    elif encoding == "hex":
        # Match original case
        if original_raw == original_raw.upper():
            return data.hex().upper()
        return data.hex().lower()

    elif encoding == "url_then_base64":
        from urllib.parse import unquote_plus
        # Re-encode as base64 then URL-encode
        b64 = base64.b64encode(data).decode("ascii")
        return quote_plus(b64)

    # Fallback — base64
    return base64.b64encode(data).decode("ascii")


# ---------------------------------------------------------------------------
# Probe generator
# ---------------------------------------------------------------------------

def generate_probes(
    raw_value:  str,
    encoding:   str,
    block_size: int,
) -> list[str] | None:
    """
    Generates 256 probe payloads by flipping the last byte of the
    penultimate block through all values 0x00–0xFF.

    Returns list of 256 re-encoded strings, or None on error.
    """
    ct = decode_value(raw_value, encoding)
    if ct is None:
        return None

    n_blocks = len(ct) // block_size
    if n_blocks < 2:
        return None  # Need at least 2 blocks

    # Split into blocks
    blocks = [
        bytearray(ct[i * block_size : (i + 1) * block_size])
        for i in range(n_blocks)
    ]

    # Penultimate block index and target byte position
    penultimate_idx  = n_blocks - 2
    target_byte_pos  = block_size - 1   # last byte of penultimate block

    probes = []
    for byte_val in range(256):
        modified_blocks = [bytearray(b) for b in blocks]
        modified_blocks[penultimate_idx][target_byte_pos] = byte_val
        modified_ct = b"".join(bytes(b) for b in modified_blocks)
        probes.append(reencode(modified_ct, encoding, raw_value))

    return probes


# ---------------------------------------------------------------------------
# Safe filename helper
# ---------------------------------------------------------------------------

def safe_fname(s: str) -> str:
    return re.sub(r'[^\w\-]', '_', s)[:40]


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

def build_report(candidates: list[dict], non_candidates: list[dict], out_dir: str) -> str:
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines   = []

    lines.append("# WSTG-CRYP-02 — Padding Oracle Findings Report")
    lines.append("")
    lines.append(f"**Generated:** {now_str}  ")
    lines.append(f"**Candidates:** {len(candidates)}  ")
    lines.append(f"**Non-candidates evaluated:** {len(non_candidates)}  ")
    lines.append("")
    lines.append("---")
    lines.append("")

    if not candidates:
        lines.append(
            "## Result\n\n"
            "✅ No padding oracle candidates identified.\n\n"
            "No parameter values decoded to a block-aligned byte length "
            "(multiple of 8 or 16) with ≥2 blocks across the XML walk."
        )
        lines.append("")
        lines.append("---")
        lines.append("*Generated by padding_verdict.py — WSTG-CRYP-02*")
        return "\n".join(lines)

    # Summary
    lines.append("## ⚠️ Candidates Identified")
    lines.append("")
    lines.append(
        "The following parameters decoded to block-aligned ciphertext lengths "
        "and are candidates for padding oracle testing. Send the corresponding "
        "probe wordlist to Burp Intruder (Sniper mode) against the target endpoint. "
        "A **padding oracle** is confirmed when one or more probe responses differ "
        "from the majority in status code, body length, or error content."
    )
    lines.append("")
    lines.append("| # | Endpoint | Source | Parameter | Bytes | Blocks | Block Size | Encoding | Wordlist |")
    lines.append("|---|----------|--------|-----------|-------|--------|------------|----------|----------|")

    for c in candidates:
        n_blocks  = c["decoded_bytes_size"] // c["block_size"]
        wordlist  = c.get("wordlist_file", "—")
        wl_name   = os.path.basename(wordlist) if wordlist and wordlist != "—" else "—"
        lines.append(
            f"| {c['endpoint_index']} "
            f"| `{c['url'][:50]}{'...' if len(c['url'])>50 else ''}` "
            f"| {c['source']} "
            f"| `{c['parameter']}` "
            f"| {c['decoded_bytes_size']} "
            f"| {n_blocks} "
            f"| {c['block_size']} ({'AES' if c['block_size']==16 else 'DES/3DES'}) "
            f"| `{c['encoding']}` "
            f"| `{wl_name}` |"
        )
    lines.append("")
    lines.append("---")
    lines.append("")

    # Per-candidate detail
    lines.append("## Per-Candidate Detail")
    lines.append("")

    for c in candidates:
        n_blocks = c["decoded_bytes_size"] // c["block_size"]
        lines.append(f"### Endpoint {c['endpoint_index']} — `{c['parameter']}` ({c['source']})")
        lines.append("")
        lines.append(f"**URL:** `{c['url']}`  ")
        lines.append(f"**Method:** `{c['method']}`  ")
        lines.append(f"**Parameter source:** {c['source']}  ")
        lines.append(f"**Parameter name:** `{c['parameter']}`  ")
        lines.append(f"**Raw value (truncated):** `{c['raw_value'][:80]}{'...' if len(c['raw_value'])>80 else ''}`  ")
        lines.append(f"**Detected encoding:** `{c['encoding']}`  ")
        lines.append(f"**Decoded byte length:** {c['decoded_bytes_size']} bytes  ")
        lines.append(f"**Block analysis:** {n_blocks} × {c['block_size']}-byte blocks ({'AES' if c['block_size']==16 else 'DES/3DES'})  ")
        lines.append(f"**Decoded hex:** `{c['decoded_bytes']}`  ")
        lines.append("")

        # Block breakdown
        lines.append("**Block layout:**")
        lines.append("")
        lines.append("```")
        decoded_hex = c["decoded_bytes"]
        decoded_b   = bytes.fromhex(decoded_hex)
        bs          = c["block_size"]
        for i in range(n_blocks):
            block = decoded_b[i * bs : (i + 1) * bs]
            label = ""
            if i == 0 and n_blocks > 2:
                label = "  ← IV (likely)"
            elif i == n_blocks - 2:
                label = "  ← PENULTIMATE BLOCK — target byte position [-1] modified in probes"
            elif i == n_blocks - 1:
                label = "  ← last block"
            lines.append(f"  Block {i:2d}: {block.hex()}  {label}")
        lines.append("```")
        lines.append("")

        # Probe wordlist info
        wordlist = c.get("wordlist_file", None)
        if wordlist:
            lines.append(f"**Probe wordlist:** `{wordlist}`  ")
            lines.append(f"**Payloads:** 256 (byte values 0x00–0xFF at position [{bs-1}] of block [{n_blocks-2}])  ")
            lines.append("")
            lines.append("**Burp Intruder instructions:**")
            lines.append("")
            lines.append(
                f"1. In Burp Proxy history, find the request to `{c['url'][:60]}`.\n"
                f"2. Send it to Intruder.\n"
                f"3. In Positions tab, set the payload position to the value of parameter `{c['parameter']}`.\n"
                f"   Mark the entire value as the payload position (§value§).\n"
                f"4. In Payloads tab, set type to **Simple List** and load `{os.path.basename(wordlist)}`.\n"
                f"5. Start attack. Sort results by **Response length** or **Status code**.\n"
                f"6. A padding oracle is present if any response(s) differ from the majority\n"
                f"   (e.g. 200 instead of 500, or different body length indicating valid padding accepted)."
            )
        else:
            lines.append(f"⚠️ Wordlist generation failed for this candidate.")
        lines.append("")
        lines.append("---")
        lines.append("")

    # Remediation
    lines.append("## Remediation")
    lines.append("")
    lines.append(
        "A confirmed padding oracle allows an attacker to decrypt ciphertext "
        "byte-by-byte without the key, and in some configurations forge arbitrary "
        "ciphertexts (e.g. privilege escalation via forged session tokens).\n\n"
        "**Recommended fixes:**\n\n"
        "- Replace CBC mode encryption with **Authenticated Encryption with Associated Data (AEAD)**,\n"
        "  such as AES-GCM or ChaCha20-Poly1305. AEAD verifies authenticity before decrypting,\n"
        "  eliminating the padding check entirely.\n"
        "- If CBC must be used, apply **Encrypt-then-MAC**: compute an HMAC over the ciphertext\n"
        "  and verify it before any decryption attempt. Reject on MAC failure without attempting\n"
        "  decryption or padding validation.\n"
        "- **Never return different errors** for 'bad padding' vs. 'bad MAC/decryption'. All\n"
        "  failure paths must return identical responses in identical time.\n"
        "- Reference: OWASP WSTG-CRYP-02, RFC 5116 (AEAD), CVE-2014-3566 (POODLE)."
    )
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Reference")
    lines.append("")
    lines.append("| Item | Reference |")
    lines.append("|------|-----------|")
    lines.append("| OWASP WSTG-CRYP-02 | https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle |")
    lines.append("| Padding Oracle Attack | https://en.wikipedia.org/wiki/Padding_oracle_attack |")
    lines.append("| NIST SP 800-38A (CBC mode) | https://doi.org/10.6028/NIST.SP.800-38A |")
    lines.append("| RFC 5116 (AEAD) | https://datatracker.ietf.org/doc/html/rfc5116 |")
    lines.append("")
    lines.append("---")
    lines.append("*Generated by padding_verdict.py — WSTG-CRYP-02*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-CRYP-02 Script 2: Padding oracle verdict + probe wordlist generator"
    )
    p.add_argument("--scan",
        default=os.path.join("WSTG-CRYP-02", "outputs", "test_outputs", "padding_oracle_scan.json"),
        metavar="PATH",
        help="Path to padding_oracle_scan.json from padding_scan.py")
    p.add_argument("--out-dir",
        default=os.path.join("WSTG-CRYP-02", "outputs", "test_outputs"),
        metavar="DIR")
    args = p.parse_args()

    width = 65
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD} WSTG-CRYP-02 — Padding Oracle Verdict{RESET}")
    print(f"{BOLD}{'='*width}{RESET}")
    print(f"  Scan: {args.scan}\n")

    try:
        with open(args.scan) as f:
            scan_results: list[dict] = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"{RED}[!] Cannot read scan JSON: {e}{RESET}", file=sys.stderr)
        sys.exit(1)

    print(f"  {len(scan_results)} entry/entries in scan file\n")

    os.makedirs(args.out_dir, exist_ok=True)

    candidates     = []
    non_candidates = []

    for entry in scan_results:
        # Re-evaluate candidate status from decoded_bytes_size
        size     = entry.get("decoded_bytes_size")
        encoding = entry.get("encoding")
        raw      = entry.get("raw_value", "")

        is_candidate = False
        block_size   = entry.get("block_size")

        if size and block_size:
            n_blocks = size // block_size
            if size % block_size == 0 and n_blocks >= 2:
                is_candidate = True

        # Update candidate flag in entry
        entry["candidate"] = is_candidate

        if not is_candidate:
            non_candidates.append(entry)
            print(f"  {DIM}[{entry['endpoint_index']}] {entry['source']}.{entry['parameter']}  "
                  f"size={size}  → not a candidate{RESET}")
            continue

        # Generate probe wordlist
        print(
            f"  {RED}{BOLD}[{entry['endpoint_index']}] {entry['source']}.{entry['parameter']}{RESET}  "
            f"size={size}  blocks={size//block_size}  bs={block_size}  enc={encoding}"
        )

        probes = generate_probes(raw, encoding, block_size)

        wordlist_file = None
        if probes:
            wl_name = (
                f"{safe_fname(entry['parameter'])}"
                f"_ep{entry['endpoint_index']}"
                f"_probes.txt"
            )
            wordlist_file = os.path.join(args.out_dir, wl_name)
            with open(wordlist_file, "w") as f:
                f.write("\n".join(probes) + "\n")
            print(f"  {GREEN}  → {len(probes)} probes → {wordlist_file}{RESET}")

            # Print first 3 and last 1 as preview
            print(f"  {DIM}  Preview (first 3 / last 1):{RESET}")
            for line in probes[:3]:
                print(f"  {DIM}    {line}{RESET}")
            print(f"  {DIM}    ...{RESET}")
            print(f"  {DIM}    {probes[-1]}{RESET}")
        else:
            print(f"  {YELLOW}  ⚠  Probe generation failed (decode error){RESET}")

        entry["wordlist_file"] = wordlist_file
        candidates.append(entry)

    # Update candidate flags in scan JSON and write back
    updated_path = os.path.join(args.out_dir, "padding_oracle_scan.json")
    with open(updated_path, "w") as f:
        json.dump(scan_results, f, indent=2)
    print(f"\n{GREEN}[+] Updated scan JSON: {updated_path}{RESET}")

    # Build and write report
    report = build_report(candidates, non_candidates, args.out_dir)
    report_path = os.path.join(args.out_dir, "padding_oracle_report.md")
    with open(report_path, "w") as f:
        f.write(report)
    print(f"{GREEN}[+] Report: {report_path}{RESET}")

    # Final verdict
    print()
    if candidates:
        print(
            f"  {RED}{BOLD}⚠  {len(candidates)} padding oracle candidate(s) identified.{RESET}\n"
            f"  {RED}   Send probe wordlists to Burp Intruder and observe response variation.{RESET}"
        )
    else:
        print(f"  {GREEN}✓  No padding oracle candidates identified.{RESET}")
    print()


if __name__ == "__main__":
    main()
