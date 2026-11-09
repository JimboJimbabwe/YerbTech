#!/usr/bin/env python3
"""
WSTG-BUSL-09 — Upload of Malicious Files
Questionnaire Script: busl_09_questionnaire.py

Interactive pre-test operator questionnaire. Run BEFORE the intruder
scan. Captures operator context specifically around malicious file upload
testing — executable types (.exe, .bat, .bin, .py, .php, etc.) that could
lead to remote code execution or server-side execution if accepted.

The line between BUSL-08 (unexpected) and BUSL-09 (malicious):
  BUSL-08 → unexpected types (.txt, .xml, .svg, .pdf, .zip …)
  BUSL-09 → malicious types  (.exe, .bat, .bin, .py, .php, .asp, .sh …)
  Overlap is intentional — a path that accepts .php is both unexpected AND
  potentially malicious.

Outputs:
  WSTG-BUSL-09/outputs/test_outputs/sitrep.md  (created/overwritten)

Usage:
  python3 WSTG-BUSL-09/utilities/python/busl_09_questionnaire.py
"""

import os
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


# ---------------------------------------------------------------------------
# Prompt helpers
# ---------------------------------------------------------------------------

def ask(prompt: str, allow_empty: bool = False) -> str:
    while True:
        try:
            val = input(f"  {CYAN}>{RESET} {prompt} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{YELLOW}[!] Interrupted — exiting.{RESET}")
            sys.exit(0)
        if val or allow_empty:
            return val
        print(f"  {DIM}(required — please enter a value){RESET}")


def ask_yn(prompt: str, default: str = "n") -> bool:
    hint = "[Y/n]" if default == "y" else "[y/N]"
    while True:
        try:
            raw = input(f"  {CYAN}>{RESET} {prompt} {DIM}{hint}{RESET} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{YELLOW}[!] Interrupted — exiting.{RESET}")
            sys.exit(0)
        if not raw:
            raw = default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print(f"  {DIM}Please enter y or n.{RESET}")


def ask_list(prompt: str, example: str = "") -> list[str]:
    print(f"  {CYAN}>{RESET} {prompt}")
    if example:
        print(f"    {DIM}(e.g. {example} — one per line, blank line to finish){RESET}")
    else:
        print(f"    {DIM}(one per line, blank line to finish){RESET}")
    items = []
    while True:
        try:
            line = input("    ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            break
        items.append(line)
    return items


def ask_choice(prompt: str, choices: list[str]) -> str:
    print(f"  {CYAN}>{RESET} {prompt}")
    for i, c in enumerate(choices, 1):
        print(f"    {DIM}[{i}]{RESET} {c}")
    while True:
        try:
            raw = input(f"    Choice (1-{len(choices)}): ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{YELLOW}[!] Interrupted — exiting.{RESET}")
            sys.exit(0)
        if raw.isdigit() and 1 <= int(raw) <= len(choices):
            return choices[int(raw) - 1]
        print(f"  {DIM}Enter a number between 1 and {len(choices)}.{RESET}")


def section(title: str):
    width = 60
    print(f"\n{BOLD}{'─'*width}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'─'*width}{RESET}")


# ---------------------------------------------------------------------------
# Main questionnaire
# ---------------------------------------------------------------------------

def run_questionnaire() -> dict:
    width = 65
    print(f"\n{BOLD}{'='*width}{RESET}")
    print(f"{BOLD}  WSTG-BUSL-09 — Upload of Malicious Files{RESET}")
    print(f"{BOLD}  Pre-Test Operator Questionnaire{RESET}")
    print(f"{BOLD}{'='*width}{RESET}")
    print(f"\n  {DIM}Focus: can the application be made to accept executable or{RESET}")
    print(f"  {DIM}server-side script files (.exe .bat .bin .py .php .asp .sh …)?{RESET}")
    print(f"  {DIM}Blank line = done for list entries.{RESET}\n")

    data = {}

    # ── Section 1: Service overview ─────────────────────────────────────────
    section("1 · Service Overview")
    data["target_url"]    = ask("Target base URL (e.g. https://app.example.com):")
    data["service_desc"]  = ask("Briefly describe the service / application:")
    data["tech_stack"]    = ask("Known server-side tech (e.g. PHP/Apache, Python/Django, Java/Tomcat):", allow_empty=True)
    data["authenticated"] = ask_yn("Are you testing as an authenticated user?", default="y")
    if data["authenticated"]:
        data["auth_role"] = ask("Role / privilege level (e.g. standard user, admin, anonymous):")
    else:
        data["auth_role"] = "unauthenticated"

    # ── Section 2: Upload functionality ─────────────────────────────────────
    section("2 · Upload Functionality")
    data["upload_exists"] = ask_yn("Does a file upload feature exist on the site?", default="y")
    if data["upload_exists"]:
        data["upload_locations"] = ask_list(
            "Known upload endpoints:",
            example="/api/v1/files, /admin/import, /profile/avatar"
        )
        data["upload_types_allowed"] = ask(
            "What file types does the application claim to accept?",
            allow_empty=True
        )
        data["server_side_processing"] = ask_yn(
            "Does the server appear to process/execute uploaded files (e.g. image resize, script runner)?",
            default="n"
        )
        data["storage_location"] = ask(
            "Where are uploaded files stored, if known? (e.g. /var/www/uploads/, S3, CDN, unknown):",
            allow_empty=True
        )
        data["stored_accessible"] = ask_yn(
            "Are uploaded files accessible via a public URL after upload?", default="y"
        )
    else:
        data["upload_locations"]       = []
        data["upload_types_allowed"]   = ""
        data["server_side_processing"] = False
        data["storage_location"]       = ""
        data["stored_accessible"]      = False

    # ── Section 3: Validation bypass recon ──────────────────────────────────
    section("3 · Validation & Bypass Recon")
    data["client_side_validation"] = ask_yn(
        "Does the site appear to use client-side file type validation (JS/HTML accept=)?",
        default="n"
    )
    data["content_type_checked"] = ask_yn(
        "Do you know if the server validates Content-Type (or only the file extension)?",
        default="n"
    )
    data["magic_bytes_checked"] = ask_yn(
        "Do you know if the server validates file magic bytes / signatures?",
        default="n"
    )
    data["double_ext_tried"] = ask_yn(
        "Have you tried double extensions (e.g. shell.php.jpg, shell.jpg.php)?",
        default="n"
    )
    if data["double_ext_tried"]:
        data["double_ext_result"] = ask("What happened?:", allow_empty=True)
    else:
        data["double_ext_result"] = ""

    data["null_byte_tried"] = ask_yn(
        "Have you tried null-byte injection (e.g. shell.php%00.jpg)?",
        default="n"
    )
    data["mime_type_tried"] = ask_yn(
        "Have you tried spoofing the MIME type in the Content-Type header?",
        default="n"
    )

    # ── Section 4: Execution context ────────────────────────────────────────
    section("4 · Execution Context")
    data["webshell_rce_concern"] = ask_yn(
        "Is webshell / RCE via uploaded .php/.asp/.jsp the primary concern?",
        default="y"
    )
    data["polyglot_concern"] = ask_yn(
        "Are you considering polyglot files (e.g. valid image that is also valid PHP)?",
        default="n"
    )
    data["archive_concern"] = ask_yn(
        "Are there archive upload endpoints (zip/tar) that might be extracted server-side (zip-slip)?",
        default="n"
    )
    data["upload_rename"] = ask_yn(
        "Does the server appear to rename uploaded files (randomise filename)?",
        default="n"
    )

    # ── Section 5: Prior manual findings ────────────────────────────────────
    section("5 · Prior Manual Findings")
    data["busl08_run"] = ask_yn(
        "Have you already run the BUSL-08 unexpected file type scan?",
        default="n"
    )
    if data["busl08_run"]:
        data["busl08_findings"] = ask(
            "Any BUSL-08 findings relevant to malicious upload testing?",
            allow_empty=True
        )
    else:
        data["busl08_findings"] = ""
    data["manual_findings"] = ask(
        "Any manual findings or additional context? (optional):",
        allow_empty=True
    )

    return data


# ---------------------------------------------------------------------------
# Sitrep writer
# ---------------------------------------------------------------------------

def write_sitrep(data: dict, out_path: str):
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines   = []

    lines.append("# WSTG-BUSL-09 — Upload of Malicious Files — Sitrep")
    lines.append("")
    lines.append(f"**Generated:** {now_str}  ")
    lines.append(f"**Test case:** WSTG-BUSL-09  ")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ── Operator context ────────────────────────────────────────────────────
    lines.append("## Operator Pre-Test Context")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    lines.append(f"| Target URL | `{data['target_url']}` |")
    lines.append(f"| Service | {data['service_desc']} |")
    lines.append(f"| Server-side tech | {data['tech_stack'] or 'unknown'} |")
    lines.append(f"| Authenticated | {'Yes — ' + data['auth_role'] if data['authenticated'] else 'No'} |")
    if data["upload_exists"]:
        lines.append(f"| Accepted file types | {data['upload_types_allowed'] or 'unknown'} |")
        lines.append(f"| Storage location | {data['storage_location'] or 'unknown'} |")
        lines.append(f"| Stored files publicly accessible | {'Yes' if data['stored_accessible'] else 'No / Unknown'} |")
        lines.append(f"| Server-side file processing | {'Yes' if data['server_side_processing'] else 'No / Unknown'} |")
    lines.append("")

    # ── Upload endpoints ─────────────────────────────────────────────────────
    if data["upload_exists"] and data["upload_locations"]:
        lines.append("## Known Upload Endpoints")
        lines.append("")
        for loc in data["upload_locations"]:
            lines.append(f"- `{loc}`")
        lines.append("")

    # ── Validation recon ─────────────────────────────────────────────────────
    lines.append("## Validation Recon")
    lines.append("")
    lines.append(f"- Client-side validation observed: {'Yes — may be bypassable via Burp intercept' if data['client_side_validation'] else 'No'}")
    lines.append(f"- Server validates Content-Type: {'Known' if data['content_type_checked'] else 'Unknown'}")
    lines.append(f"- Server validates magic bytes: {'Known' if data['magic_bytes_checked'] else 'Unknown'}")
    if data["double_ext_tried"]:
        lines.append(f"- Double extension tested: Yes — result: {data['double_ext_result'] or 'not recorded'}")
    else:
        lines.append("- Double extension tested: No")
    lines.append(f"- Null-byte injection tried: {'Yes' if data['null_byte_tried'] else 'No'}")
    lines.append(f"- MIME type spoofing tried: {'Yes' if data['mime_type_tried'] else 'No'}")
    lines.append("")

    # ── Execution concerns ───────────────────────────────────────────────────
    lines.append("## Execution Concerns")
    lines.append("")
    concerns = []
    if data["webshell_rce_concern"]:
        concerns.append("Webshell / RCE via .php/.asp/.jsp upload")
    if data["polyglot_concern"]:
        concerns.append("Polyglot file bypass (valid image + valid script)")
    if data["archive_concern"]:
        concerns.append("Archive extraction / zip-slip path traversal")
    if data["upload_rename"]:
        concerns.append("Server renames files — harvesting renamed path required after upload")
    if concerns:
        for c in concerns:
            lines.append(f"- {c}")
    else:
        lines.append("- None flagged in pre-test recon")
    lines.append("")

    # ── BUSL-08 cross-reference ───────────────────────────────────────────────
    if data["busl08_run"]:
        lines.append("## BUSL-08 Cross-Reference")
        lines.append("")
        lines.append("BUSL-08 unexpected file scan was run prior to this test.")
        if data["busl08_findings"]:
            lines.append(f"Relevant findings: {data['busl08_findings']}")
        lines.append("")

    if data["manual_findings"]:
        lines.append("## Additional Notes")
        lines.append("")
        lines.append(data["manual_findings"])
        lines.append("")

    lines.append("---")
    lines.append("")

    # ── Next steps ───────────────────────────────────────────────────────────
    lines.append("## Next Steps")
    lines.append("")
    lines.append(
        "1. For each upload endpoint above, send the upload request to **Burp Intruder** (Sniper mode).\n"
        "2. Mark the `filename` parameter (in Content-Disposition or query string) as the payload position.\n"
        "3. Load the BUSL-08 wordlist (`upload_paths.txt`) — the extension section covers malicious types.\n"
        "   Alternatively, use a targeted list: `.php .php5 .phtml .asp .aspx .jsp .py .sh .exe .bat .bin`\n"
        "4. If client-side validation is present, intercept in Burp and modify the filename directly.\n"
        "5. Start the attack. Export results as XML.\n"
        "6. Run `busl_09_verdict.py --intruder inputs/xml/intruder_test.xml` to classify results.\n"
        "7. For any 200 OK on a script extension, attempt to GET the uploaded file URL and observe response."
    )
    lines.append("")
    lines.append("---")
    lines.append("*Generated by busl_09_questionnaire.py — WSTG-BUSL-09*")

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    import argparse
    p = argparse.ArgumentParser(
        description="WSTG-BUSL-09 pre-test operator questionnaire"
    )
    p.add_argument("--out",
        default=os.path.join("WSTG-BUSL-09", "outputs", "test_outputs", "sitrep.md"),
        metavar="PATH")
    args = p.parse_args()

    data = run_questionnaire()

    write_sitrep(data, args.out)

    print(f"\n{GREEN}[+] Sitrep written → {args.out}{RESET}")
    print(f"\n  {DIM}Next: send upload requests to Burp Intruder with malicious extension payloads,{RESET}")
    print(f"  {DIM}then run busl_09_verdict.py to classify results.{RESET}\n")


if __name__ == "__main__":
    main()
