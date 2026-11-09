#!/usr/bin/env python3
"""
WSTG-CRYP-01 — Testing for Weak Transport Layer Security
Script 2: cryp01_analyze.py

Reads sslyze JSON and nmap XML outputs from the scan directory,
detects weak protocols and ciphers, then runs targeted
openssl s_client verification commands for each confirmed issue.

Detection signatures:

  Weak protocols:
    SSLv2, SSLv3, TLSv1.0, TLSv1.1
    → openssl s_client -connect host:port -<protocol_flag>

  Weak ciphers (per IANA / OWASP / NIST SP 800-52r2):
    RC4_*, *_NULL_*, *EXPORT*, *_DES_*, *_3DES_*, *ANON*,
    *_RC2_*, *_IDEA_*, *_SEED_*, *_MD5* (non-HMAC uses),
    ADH-*, AECDH-*
    → openssl s_client -connect host:port -cipher '<cipher_name>'

  Certificate issues (from sslyze):
    Expired, self-signed, hostname mismatch, weak key, SHA1 signature

Outputs:
  WSTG-CRYP-01/outputs/test_outputs/cryp01_report.md
  WSTG-CRYP-01/outputs/test_outputs/<host>_openssl_<tag>.txt  (raw openssl output per test)

Usage:
  python3 WSTG-CRYP-01/utilities/python/cryp01_analyze.py \\
      --scan-dir WSTG-CRYP-01/outputs/test_outputs \\
      --out-dir  WSTG-CRYP-01/outputs/test_outputs
"""

import argparse
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime


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
# Weak protocol definitions
# ---------------------------------------------------------------------------

# Maps detected protocol name → openssl flag
WEAK_PROTOCOLS = {
    "SSLv2":  "-ssl2",
    "SSLv3":  "-ssl3",
    "TLSv1":  "-tls1",
    "TLSv1.0": "-tls1",
    "TLSv1_0": "-tls1",
    "TLSv1.1": "-tls1_1",
    "TLSv1_1": "-tls1_1",
}

WEAK_PROTOCOL_SEVERITY = {
    "SSLv2":   "CRITICAL",
    "SSLv3":   "CRITICAL",
    "TLSv1":   "HIGH",
    "TLSv1.0": "HIGH",
    "TLSv1_0": "HIGH",
    "TLSv1.1": "HIGH",
    "TLSv1_1": "HIGH",
}

# ---------------------------------------------------------------------------
# Weak cipher patterns (regex matched against cipher suite names)
# ---------------------------------------------------------------------------

WEAK_CIPHER_PATTERNS = [
    # RC4
    (re.compile(r'RC4',          re.IGNORECASE), "CRITICAL", "RC4 stream cipher — broken, predictable keystream"),
    # NULL encryption
    (re.compile(r'_NULL_|WITH_NULL', re.IGNORECASE), "CRITICAL", "NULL cipher — no encryption at all"),
    # EXPORT-grade (40/56-bit)
    (re.compile(r'EXPORT',       re.IGNORECASE), "CRITICAL", "EXPORT-grade cipher — trivially brute-forceable (FREAK/LOGJAM)"),
    # Single DES
    (re.compile(r'_DES_(?!3)',   re.IGNORECASE), "CRITICAL", "Single DES — 56-bit key, broken"),
    # 3DES / SWEET32
    (re.compile(r'3DES|DES_EDE', re.IGNORECASE), "HIGH",     "3DES — SWEET32 birthday attack (64-bit block cipher)"),
    # Anonymous DH/ECDH (no auth)
    (re.compile(r'^ADH-|^AECDH-|_anon_', re.IGNORECASE), "CRITICAL", "Anonymous DH — no server authentication, trivial MitM"),
    # RC2
    (re.compile(r'_RC2_',        re.IGNORECASE), "HIGH",     "RC2 — weak legacy cipher"),
    # IDEA
    (re.compile(r'_IDEA_',       re.IGNORECASE), "MEDIUM",   "IDEA — legacy cipher, not recommended"),
    # SEED
    (re.compile(r'_SEED_',       re.IGNORECASE), "MEDIUM",   "SEED — regional legacy cipher, not recommended"),
    # MD5-based HMAC in cipher suites
    (re.compile(r'_MD5$',        re.IGNORECASE), "MEDIUM",   "MD5 HMAC — collision-prone, prefer SHA-256+"),
]

# ---------------------------------------------------------------------------
# openssl protocol flags (for version negotiation tests)
# ---------------------------------------------------------------------------

OPENSSL_PROTO_FLAGS = {
    "SSLv2":   "-ssl2",
    "SSLv3":   "-ssl3",
    "TLSv1":   "-tls1",
    "TLSv1.0": "-tls1",
    "TLSv1_0": "-tls1",
    "TLSv1.1": "-tls1_1",
    "TLSv1_1": "-tls1_1",
}


# ---------------------------------------------------------------------------
# sslyze JSON parser
# ---------------------------------------------------------------------------

def parse_sslyze(path: str) -> dict:
    """
    Parses sslyze JSON output.
    Returns {
        host, port,
        accepted_protocols: [str],
        cipher_suites: {protocol: [cipher_name]},
        cert_issues: [str],
        compression: bool,
        renegotiation: bool,
    }
    """
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        return {"error": str(e), "source": path}

    result = {
        "source":             path,
        "accepted_protocols": [],
        "cipher_suites":      {},
        "cert_issues":        [],
        "compression":        False,
        "renegotiation":      False,
        "host":               "",
        "port":               443,
    }

    # sslyze JSON schema varies by version; handle both v5+ and older
    # Try v5+ schema first: data["server_scan_results"][0]
    scan_results = data.get("server_scan_results", [])
    if not scan_results:
        # Some versions use "accepted_targets"
        scan_results = data.get("accepted_targets", [])

    if not scan_results:
        result["error"] = "No scan results in JSON"
        return result

    scan = scan_results[0]

    # Host info
    server_info = scan.get("server_location", scan.get("server_info", {}))
    result["host"] = server_info.get("hostname", "")
    result["port"] = server_info.get("port", 443)

    # Scan commands result block
    commands = scan.get("scan_result", scan.get("scan_commands_results", {}))

    # Protocol support — sslyze reports per-protocol
    protocol_map = {
        "ssl_2_0_cipher_suites": "SSLv2",
        "ssl_3_0_cipher_suites": "SSLv3",
        "tls_1_0_cipher_suites": "TLSv1.0",
        "tls_1_1_cipher_suites": "TLSv1.1",
        "tls_1_2_cipher_suites": "TLSv1.2",
        "tls_1_3_cipher_suites": "TLSv1.3",
    }

    for key, proto_name in protocol_map.items():
        proto_data = commands.get(key, {})
        if not proto_data:
            continue
        # v5+: result.accepted_cipher_suites
        # older: accepted_cipher_suites directly
        accepted = (
            proto_data.get("result", {}).get("accepted_cipher_suites", [])
            or proto_data.get("accepted_cipher_suites", [])
        )
        if accepted:
            result["accepted_protocols"].append(proto_name)
            ciphers = []
            for cs in accepted:
                name = (
                    cs.get("cipher_suite", {}).get("name", "")
                    or cs.get("name", "")
                )
                if name:
                    ciphers.append(name)
            result["cipher_suites"][proto_name] = ciphers

    # Certificate issues
    cert_data = commands.get("certificate_info", {})
    if cert_data:
        deployments = (
            cert_data.get("result", {}).get("certificate_deployments", [])
            or cert_data.get("certificate_deployments", [])
        )
        for dep in deployments:
            chain = dep.get("verified_chain_has_sha1_signature", False)
            if chain:
                result["cert_issues"].append("SHA1 signature in certificate chain")

            leaf = (
                dep.get("received_chain_contains_legacy_symantec_anchor", False)
            )
            if leaf:
                result["cert_issues"].append("Legacy Symantec anchor in chain")

            # Key size
            chain_list = dep.get("received_certificate_chain", [])
            for cert in chain_list[:1]:  # leaf only
                pk = cert.get("public_key", {})
                pk_type = pk.get("algorithm", "")
                pk_size = pk.get("key_size", 0)
                if pk_type == "RSA" and pk_size and pk_size < 2048:
                    result["cert_issues"].append(
                        f"Weak RSA key: {pk_size} bits (minimum 2048)"
                    )
                elif pk_type == "EC" and pk_size and pk_size < 256:
                    result["cert_issues"].append(
                        f"Weak EC key: {pk_size} bits (minimum 256)"
                    )

            # Hostname mismatch
            match = dep.get("leaf_certificate_subject_matches_hostname", True)
            if match is False:
                result["cert_issues"].append("Certificate hostname mismatch")

            # Expiry
            not_after = (
                dep.get("leaf_certificate_not_after", None)
                or (dep.get("received_certificate_chain", [{}])[0]
                    .get("not_after", None))
            )
            if not_after:
                try:
                    exp = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                    if exp < datetime.now(exp.tzinfo):
                        result["cert_issues"].append(f"Certificate expired: {not_after}")
                except Exception:
                    pass

    # Compression (CRIME)
    comp = commands.get("tls_compression", {})
    if comp:
        supports = (
            comp.get("result", {}).get("supports_compression", False)
            or comp.get("supports_compression", False)
        )
        result["compression"] = bool(supports)
        if supports:
            result["cert_issues"].append("TLS compression enabled (CRIME vulnerability)")

    # Insecure renegotiation
    reneg = commands.get("session_renegotiation", {})
    if reneg:
        insecure = (
            reneg.get("result", {}).get("supports_insecure_renegotiation", False)
            or reneg.get("supports_insecure_renegotiation", False)
        )
        result["renegotiation"] = bool(insecure)
        if insecure:
            result["cert_issues"].append("Insecure TLS renegotiation supported (CVE-2009-3555)")

    return result


# ---------------------------------------------------------------------------
# nmap XML parser
# ---------------------------------------------------------------------------

def parse_nmap(path: str) -> dict:
    """
    Parses nmap XML (ssl-enum-ciphers script output).
    Returns {
        host, port,
        accepted_protocols: [str],
        cipher_suites: {protocol: [cipher_name]},
        weak_grade_ciphers: {protocol: [cipher_name]},   # nmap grades F/D/C
    }
    """
    result = {
        "source":             path,
        "host":               "",
        "port":               443,
        "accepted_protocols": [],
        "cipher_suites":      {},
        "weak_grade_ciphers": {},
    }

    try:
        tree = ET.parse(path)
    except (ET.ParseError, FileNotFoundError) as e:
        result["error"] = str(e)
        return result

    root = tree.getroot()

    for host_elem in root.findall("host"):
        # Address
        addr_elem = host_elem.find("address")
        if addr_elem is not None:
            result["host"] = addr_elem.get("addr", "")

        for port_elem in host_elem.findall(".//port"):
            portid = int(port_elem.get("portid", 443))
            result["port"] = portid

            # ssl-enum-ciphers script output
            for script in port_elem.findall("script"):
                if script.get("id") != "ssl-enum-ciphers":
                    continue

                for tbl in script.findall("table"):
                    proto = tbl.get("key", "")
                    if not proto:
                        continue

                    # Normalise protocol name
                    proto_norm = proto.upper().replace("TLSV", "TLSv").replace("SSLV", "SSLv")
                    if proto_norm not in result["accepted_protocols"]:
                        result["accepted_protocols"].append(proto_norm)

                    ciphers      = []
                    weak_ciphers = []

                    for cipher_tbl in tbl.findall("table"):
                        cipher_name = ""
                        grade       = ""
                        for elem in cipher_tbl.findall("elem"):
                            key = elem.get("key", "")
                            if key == "name":
                                cipher_name = elem.text or ""
                            elif key == "strength":
                                grade = (elem.text or "").upper()

                        if cipher_name:
                            ciphers.append(cipher_name)
                            # nmap grades: A > B > C > D > F
                            if grade in ("F", "D", "C"):
                                weak_ciphers.append(cipher_name)

                    result["cipher_suites"][proto_norm]      = ciphers
                    result["weak_grade_ciphers"][proto_norm] = weak_ciphers

    return result


# ---------------------------------------------------------------------------
# Issue detection
# ---------------------------------------------------------------------------

def detect_weak_protocols(proto_list: list[str]) -> list[dict]:
    """Returns finding dicts for any weak/deprecated protocol accepted."""
    findings = []
    for proto in proto_list:
        if proto in WEAK_PROTOCOLS or proto in WEAK_PROTOCOL_SEVERITY:
            findings.append({
                "type":       "weak_protocol",
                "protocol":   proto,
                "severity":   WEAK_PROTOCOL_SEVERITY.get(proto, "HIGH"),
                "openssl_flag": OPENSSL_PROTO_FLAGS.get(proto, ""),
                "detail":     f"{proto} is accepted — deprecated protocol vulnerable to known attacks",
            })
    return findings


def detect_weak_ciphers(cipher_suites: dict) -> list[dict]:
    """
    cipher_suites: {protocol: [cipher_name]}
    Returns finding dicts per weak cipher per protocol.
    """
    findings = []
    seen = set()  # deduplicate same cipher across protocols

    for proto, ciphers in cipher_suites.items():
        for cipher in ciphers:
            for pattern, severity, reason in WEAK_CIPHER_PATTERNS:
                if pattern.search(cipher):
                    key = (cipher, pattern.pattern)
                    if key not in seen:
                        seen.add(key)
                        findings.append({
                            "type":         "weak_cipher",
                            "cipher":       cipher,
                            "protocol":     proto,
                            "severity":     severity,
                            "reason":       reason,
                        })
                    break  # first matching pattern wins per cipher

    return findings


# ---------------------------------------------------------------------------
# openssl verifier
# ---------------------------------------------------------------------------

def run_openssl_proto(host: str, port: int, proto_flag: str, out_path: str) -> tuple[bool, str]:
    """
    Runs: openssl s_client -connect host:port <proto_flag> </dev/null
    Captures output to out_path.
    Returns (connected, raw_output_snippet).
    """
    cmd = [
        "openssl", "s_client",
        "-connect", f"{host}:{port}",
        proto_flag,
    ]
    print(f"  {DIM}CMD: {' '.join(cmd)}{RESET}")

    try:
        result = subprocess.run(
            cmd,
            input="",
            capture_output=True,
            text=True,
            timeout=15,
        )
        output = result.stdout + result.stderr
        # Write raw output
        with open(out_path, "w") as f:
            f.write(f"Command: {' '.join(cmd)}\n")
            f.write(f"Exit code: {result.returncode}\n")
            f.write(f"{'='*60}\n")
            f.write(output)

        # Determine if connection succeeded
        connected = (
            "CONNECTED" in output and
            "handshake failure" not in output.lower() and
            "ssl handshake" not in output.lower() and
            "unknown protocol" not in output.lower()
        )
        return connected, output[:300]

    except subprocess.TimeoutExpired:
        with open(out_path, "w") as f:
            f.write(f"Command: {' '.join(cmd)}\nTimeout after 15s\n")
        return False, "timeout"
    except FileNotFoundError:
        return False, "openssl not found"


def run_openssl_cipher(host: str, port: int, cipher: str, out_path: str) -> tuple[bool, str]:
    """
    Runs: openssl s_client -connect host:port -cipher '<cipher>'
    Returns (cipher_accepted, raw_output_snippet).
    """
    cmd = [
        "openssl", "s_client",
        "-connect", f"{host}:{port}",
        "-cipher", cipher,
    ]
    print(f"  {DIM}CMD: {' '.join(cmd)}{RESET}")

    try:
        result = subprocess.run(
            cmd,
            input="",
            capture_output=True,
            text=True,
            timeout=15,
        )
        output = result.stdout + result.stderr
        with open(out_path, "w") as f:
            f.write(f"Command: {' '.join(cmd)}\n")
            f.write(f"Exit code: {result.returncode}\n")
            f.write(f"{'='*60}\n")
            f.write(output)

        accepted = (
            "CONNECTED" in output and
            "no cipher can be selected" not in output.lower() and
            "handshake failure" not in output.lower()
        )
        return accepted, output[:300]

    except subprocess.TimeoutExpired:
        with open(out_path, "w") as f:
            f.write(f"Command: {' '.join(cmd)}\nTimeout after 15s\n")
        return False, "timeout"
    except FileNotFoundError:
        return False, "openssl not found"


def safe_filename(s: str) -> str:
    return re.sub(r'[^\w\-.]', '_', s)


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "ℹ️",
    "PASS":     "✅",
}


def build_report(all_host_results: list[dict]) -> str:
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines   = []

    lines.append("# WSTG-CRYP-01 — Weak Transport Layer Security Report")
    lines.append("")
    lines.append(f"**Generated:** {now_str}  ")
    lines.append(f"**Hosts scanned:** {len(all_host_results)}  ")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Executive summary
    all_issues = []
    for hr in all_host_results:
        all_issues.extend(hr.get("issues", []))

    crits  = sum(1 for i in all_issues if i.get("severity") == "CRITICAL")
    highs  = sum(1 for i in all_issues if i.get("severity") == "HIGH")
    meds   = sum(1 for i in all_issues if i.get("severity") == "MEDIUM")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    lines.append(f"| 🔴 CRITICAL | {crits} |")
    lines.append(f"| 🟠 HIGH     | {highs} |")
    lines.append(f"| 🟡 MEDIUM   | {meds} |")
    lines.append("")

    # Quick-reference table — all critical/high
    top_issues = [i for i in all_issues if i.get("severity") in ("CRITICAL", "HIGH")]
    if top_issues:
        lines.append("### Issues Requiring Immediate Action")
        lines.append("")
        lines.append("| Severity | Host | Type | Detail |")
        lines.append("|----------|------|------|--------|")
        for issue in sorted(top_issues, key=lambda x: SEVERITY_ORDER.get(x.get("severity","INFO"), 4)):
            emoji = SEVERITY_EMOJI.get(issue.get("severity","INFO"), "")
            host  = issue.get("host", "—")
            itype = issue.get("type", "—")
            detail = (issue.get("detail") or issue.get("reason") or issue.get("cipher") or "").replace("|","\\|")
            lines.append(f"| {emoji} {issue.get('severity')} | `{host}` | {itype} | {detail} |")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## Per-Host Findings")
    lines.append("")

    for hr in all_host_results:
        host   = hr["host"]
        port   = hr["port"]
        issues = hr.get("issues", [])

        lines.append(f"### `{host}:{port}`")
        lines.append("")

        if not issues and not hr.get("cert_issues"):
            lines.append("✅ No weak protocols, ciphers, or certificate issues detected.")
            lines.append("")
            continue

        # Protocols
        proto_issues = [i for i in issues if i["type"] == "weak_protocol"]
        if proto_issues:
            lines.append("#### Weak / Deprecated Protocols")
            lines.append("")
            lines.append("| Protocol | Severity | OpenSSL Verified | Detail |")
            lines.append("|----------|----------|------------------|--------|")
            for i in proto_issues:
                emoji    = SEVERITY_EMOJI.get(i["severity"], "")
                verified = i.get("openssl_verified")
                if verified is True:
                    v_cell = "✅ confirmed accepted"
                elif verified is False:
                    v_cell = "✅ rejected (server refused)"
                else:
                    v_cell = "—"
                raw_file = i.get("openssl_raw_file", "")
                if raw_file:
                    v_cell += f" · `{os.path.basename(raw_file)}`"
                lines.append(
                    f"| `{i['protocol']}` "
                    f"| {emoji} {i['severity']} "
                    f"| {v_cell} "
                    f"| {i.get('detail','').replace('|','\\|')} |"
                )
            lines.append("")

        # Ciphers
        cipher_issues = [i for i in issues if i["type"] == "weak_cipher"]
        if cipher_issues:
            lines.append("#### Weak Cipher Suites")
            lines.append("")
            lines.append("| Cipher | Protocol | Severity | Verified | Reason |")
            lines.append("|--------|----------|----------|----------|--------|")
            for i in cipher_issues:
                emoji    = SEVERITY_EMOJI.get(i["severity"], "")
                verified = i.get("openssl_verified")
                if verified is True:
                    v_cell = "✅ confirmed accepted"
                elif verified is False:
                    v_cell = "✅ rejected by server"
                else:
                    v_cell = "—"
                raw_file = i.get("openssl_raw_file", "")
                if raw_file:
                    v_cell += f" · `{os.path.basename(raw_file)}`"
                lines.append(
                    f"| `{i['cipher']}` "
                    f"| `{i.get('protocol','—')}` "
                    f"| {emoji} {i['severity']} "
                    f"| {v_cell} "
                    f"| {i.get('reason','').replace('|','\\|')} |"
                )
            lines.append("")

        # Cert / misc issues
        cert_issues = hr.get("cert_issues", [])
        if cert_issues:
            lines.append("#### Certificate / Configuration Issues")
            lines.append("")
            for ci in cert_issues:
                lines.append(f"- ⚠️  {ci}")
            lines.append("")

    # Reference
    lines.append("---")
    lines.append("")
    lines.append("## Reference")
    lines.append("")
    lines.append("| Item | Reference |")
    lines.append("|------|-----------|")
    lines.append("| OWASP WSTG-CRYP-01 | https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security |")
    lines.append("| NIST SP 800-52r2 | https://doi.org/10.6028/NIST.SP.800-52r2 |")
    lines.append("| Mozilla TLS Config Generator | https://ssl-config.mozilla.org/ |")
    lines.append("| BSI TR-02102-2 | https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr02102/tr02102_node.html |")
    lines.append("")
    lines.append("---")
    lines.append("*Generated by cryp01_analyze.py — WSTG-CRYP-01*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-CRYP-01 Script 2: TLS weakness analyzer and openssl verifier"
    )
    p.add_argument("--scan-dir",
        default=os.path.join("WSTG-CRYP-01", "outputs", "test_outputs"),
        metavar="DIR",
        help="Directory containing *_sslyze.json and *_nmap.xml files")
    p.add_argument("--out-dir",
        default=os.path.join("WSTG-CRYP-01", "outputs", "test_outputs"),
        metavar="DIR")
    p.add_argument("--skip-openssl", action="store_true",
        help="Skip openssl verification (parse and report only)")
    args = p.parse_args()

    width = 65
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD} WSTG-CRYP-01 — TLS Analyzer{RESET}")
    print(f"{BOLD}{'='*width}{RESET}")
    print(f"  Scan dir: {args.scan_dir}")
    print(f"  Out dir : {args.out_dir}\n")

    # Discover scan files
    try:
        all_files = os.listdir(args.scan_dir)
    except FileNotFoundError:
        print(f"{RED}[!] Scan directory not found: {args.scan_dir}{RESET}", file=sys.stderr)
        sys.exit(1)

    sslyze_files = sorted(f for f in all_files if f.endswith("_sslyze.json"))
    nmap_files   = sorted(f for f in all_files if f.endswith("_nmap.xml"))

    if not sslyze_files and not nmap_files:
        print(f"{YELLOW}[!] No *_sslyze.json or *_nmap.xml files found in {args.scan_dir}{RESET}")
        print(f"    Run cryp01_scan.py first.")
        sys.exit(1)

    print(f"  Found {len(sslyze_files)} sslyze file(s), {len(nmap_files)} nmap file(s)\n")

    # Build host → files map
    host_files: dict[str, dict] = defaultdict(lambda: {"sslyze": None, "nmap": None})

    for fname in sslyze_files:
        stem = fname[:-len("_sslyze.json")]
        host_files[stem]["sslyze"] = os.path.join(args.scan_dir, fname)

    for fname in nmap_files:
        stem = fname[:-len("_nmap.xml")]
        host_files[stem]["nmap"] = os.path.join(args.scan_dir, fname)

    os.makedirs(args.out_dir, exist_ok=True)
    all_host_results = []

    for stem, paths in sorted(host_files.items()):
        print(f"{BOLD}{'─'*width}{RESET}")
        print(f"{BOLD}  {stem}{RESET}\n")

        # Parse available sources
        sslyze_data = parse_sslyze(paths["sslyze"]) if paths["sslyze"] else {}
        nmap_data   = parse_nmap(paths["nmap"])     if paths["nmap"]   else {}

        # Merge host/port
        host = (
            sslyze_data.get("host") or
            nmap_data.get("host") or
            stem.replace("_", ".")
        )
        port = sslyze_data.get("port") or nmap_data.get("port") or 443

        # Merge accepted protocols and ciphers across sources
        all_protocols: list[str] = list({
            *sslyze_data.get("accepted_protocols", []),
            *nmap_data.get("accepted_protocols", []),
        })
        all_ciphers: dict[str, list[str]] = {}
        for proto in set(
            list(sslyze_data.get("cipher_suites", {}).keys()) +
            list(nmap_data.get("cipher_suites", {}).keys())
        ):
            combined = list({
                *sslyze_data.get("cipher_suites", {}).get(proto, []),
                *nmap_data.get("cipher_suites", {}).get(proto, []),
            })
            all_ciphers[proto] = combined

        # Detect issues
        proto_findings  = detect_weak_protocols(all_protocols)
        cipher_findings = detect_weak_ciphers(all_ciphers)
        cert_issues     = sslyze_data.get("cert_issues", [])

        # Attach host to each finding
        for f in proto_findings + cipher_findings:
            f["host"] = host

        all_issues = proto_findings + cipher_findings

        if not all_issues and not cert_issues:
            print(f"  {GREEN}✓  No weak protocols or ciphers detected.{RESET}\n")
        else:
            if proto_findings:
                print(f"  {RED}[PROTOCOLS]{RESET}")
                for f in proto_findings:
                    color = RED if f["severity"] == "CRITICAL" else YELLOW
                    print(f"    {color}[{f['severity']}]{RESET} {f['protocol']}")
            if cipher_findings:
                print(f"  {RED}[CIPHERS]{RESET}")
                for f in cipher_findings:
                    color = RED if f["severity"] == "CRITICAL" else YELLOW
                    print(f"    {color}[{f['severity']}]{RESET} {f['cipher']}  — {f['reason']}")
            if cert_issues:
                print(f"  {YELLOW}[CERT/CONFIG]{RESET}")
                for ci in cert_issues:
                    print(f"    {YELLOW}⚠  {ci}{RESET}")

        # openssl verification
        if not args.skip_openssl and all_issues:
            print(f"\n  {CYAN}Running openssl verification...{RESET}\n")

            for issue in all_issues:
                if issue["type"] == "weak_protocol":
                    flag = issue.get("openssl_flag", "")
                    if not flag:
                        continue
                    tag      = issue["protocol"].replace(".", "_").replace("/", "_")
                    raw_file = os.path.join(
                        args.out_dir,
                        f"{safe_filename(host)}_openssl_{tag}.txt"
                    )
                    connected, snippet = run_openssl_proto(host, port, flag, raw_file)
                    issue["openssl_verified"]  = connected
                    issue["openssl_raw_file"]  = raw_file
                    if connected:
                        print(f"  {RED}✓  {issue['protocol']} ACCEPTED by server → {os.path.basename(raw_file)}{RESET}")
                    else:
                        print(f"  {GREEN}✓  {issue['protocol']} rejected by server → {os.path.basename(raw_file)}{RESET}")

                elif issue["type"] == "weak_cipher":
                    cipher   = issue["cipher"]
                    tag      = re.sub(r'[^\w]', '_', cipher)[:30]
                    raw_file = os.path.join(
                        args.out_dir,
                        f"{safe_filename(host)}_openssl_{tag}.txt"
                    )
                    accepted, snippet = run_openssl_cipher(host, port, cipher, raw_file)
                    issue["openssl_verified"] = accepted
                    issue["openssl_raw_file"] = raw_file
                    if accepted:
                        print(f"  {RED}✓  Cipher '{cipher}' ACCEPTED → {os.path.basename(raw_file)}{RESET}")
                    else:
                        print(f"  {GREEN}✓  Cipher '{cipher}' rejected → {os.path.basename(raw_file)}{RESET}")

        all_host_results.append({
            "host":        host,
            "port":        port,
            "issues":      all_issues,
            "cert_issues": cert_issues,
        })

    # Write report
    report = build_report(all_host_results)
    report_path = os.path.join(args.out_dir, "cryp01_report.md")
    with open(report_path, "w") as f:
        f.write(report)

    print(f"\n{GREEN}[+] Report: {report_path}{RESET}")

    # Final tally
    total_issues = sum(len(hr["issues"]) for hr in all_host_results)
    crits = sum(1 for hr in all_host_results for i in hr["issues"] if i.get("severity") == "CRITICAL")
    highs = sum(1 for hr in all_host_results for i in hr["issues"] if i.get("severity") == "HIGH")

    if crits:
        print(f"  {RED}{BOLD}⚠  {crits} CRITICAL · {highs} HIGH — immediate action required{RESET}")
    elif highs:
        print(f"  {YELLOW}⚠  {highs} HIGH findings{RESET}")
    elif total_issues:
        print(f"  {YELLOW}  {total_issues} finding(s) — review report{RESET}")
    else:
        print(f"  {GREEN}✓  No critical issues detected across all hosts{RESET}")
    print()


if __name__ == "__main__":
    main()
