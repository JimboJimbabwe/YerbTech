#!/usr/bin/env python3
"""
WSTG-BUSL-08 — Upload of Unexpected File Types
Questionnaire Script: busl_08_questionnaire.py

Interactive pre-test operator questionnaire. Run BEFORE Script 1
(busl_08_wordlist.py). Captures operator context and reconnaissance
findings, then writes them to the sitrep.

Outputs:
  WSTG-BUSL-08/outputs/test_outputs/sitrep.md  (created/overwritten)

Usage:
  python3 WSTG-BUSL-08/utilities/python/busl_08_questionnaire.py
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
    print(f"{BOLD}  WSTG-BUSL-08 — Upload of Unexpected File Types{RESET}")
    print(f"{BOLD}  Pre-Test Operator Questionnaire{RESET}")
    print(f"{BOLD}{'='*width}{RESET}")
    print(f"\n  {DIM}Answer each question before running the wordlist generator.{RESET}")
    print(f"  {DIM}Blank line = done for list entries.{RESET}\n")

    data = {}

    # ── Section 1: Service overview ─────────────────────────────────────────
    section("1 · Service Overview")
    data["target_url"]     = ask("Target base URL (e.g. https://app.example.com):")
    data["service_desc"]   = ask("Briefly describe the service / application:")
    data["tech_stack"]     = ask("Known tech stack (e.g. Nginx + Laravel, Apache + PHP, unknown):", allow_empty=True)
    data["authenticated"]  = ask_yn("Are you testing as an authenticated user?", default="y")
    if data["authenticated"]:
        data["auth_role"]  = ask("What role / privilege level? (e.g. standard user, admin, guest):")
    else:
        data["auth_role"]  = "unauthenticated"

    # ── Section 2: Upload functionality ─────────────────────────────────────
    section("2 · Upload Functionality")
    data["upload_exists"]  = ask_yn("Does a file upload feature exist on the site (by design)?", default="y")
    if data["upload_exists"]:
        data["upload_locations"] = ask_list(
            "List all known upload endpoints / pages:",
            example="/profile/avatar, /documents/upload, /api/v1/files"
        )
        data["upload_types_allowed"] = ask(
            "What file types does the application claim to accept? (e.g. .jpg .png .pdf, or 'any'):",
            allow_empty=True
        )
    else:
        data["upload_locations"]     = []
        data["upload_types_allowed"] = ""

    data["upload_size_limit"] = ask("Is there a stated file size limit? (e.g. 5MB, unknown):", allow_empty=True)

    # ── Section 3: Exposed / unexpected paths ───────────────────────────────
    section("3 · Exposed & Unexpected Paths")
    data["unexpected_paths_found"] = ask_yn(
        "Have you already found any unexpected or unintended file paths?", default="n"
    )
    if data["unexpected_paths_found"]:
        data["unexpected_paths"] = ask_list(
            "List the unexpected paths you found:",
            example="/backup/, /uploads/debug/, /temp/"
        )
        data["manual_upload_tested"] = ask_yn(
            "Have you manually tried to upload a file to any of those paths?", default="n"
        )
        if data["manual_upload_tested"]:
            data["manual_upload_result"] = ask(
                "What happened? (e.g. 200 accepted .txt, 403 on .exe, directory listing shown):"
            )
        else:
            data["manual_upload_result"] = ""
    else:
        data["unexpected_paths"]     = []
        data["manual_upload_tested"] = False
        data["manual_upload_result"] = ""

    # ── Section 4: Recon notes ───────────────────────────────────────────────
    section("4 · Recon Notes")
    data["robots_sitemap_checked"] = ask_yn(
        "Have you reviewed robots.txt / sitemap.xml for path hints?", default="n"
    )
    data["js_paths_reviewed"] = ask_yn(
        "Have you reviewed page source / JS files for hidden upload endpoints?", default="n"
    )
    data["burp_sitemap_notes"] = ask(
        "Any notes from the Burp Suite sitemap / proxy history relevant to uploads?",
        allow_empty=True
    )
    data["additional_notes"] = ask(
        "Anything else the wordlist generator should know? (optional):",
        allow_empty=True
    )

    return data


# ---------------------------------------------------------------------------
# Sitrep writer
# ---------------------------------------------------------------------------

def write_sitrep(data: dict, out_path: str):
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines   = []

    lines.append("# WSTG-BUSL-08 — Upload of Unexpected File Types — Sitrep")
    lines.append("")
    lines.append(f"**Generated:** {now_str}  ")
    lines.append(f"**Test case:** WSTG-BUSL-08  ")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ── Operator context ────────────────────────────────────────────────────
    lines.append("## Operator Pre-Test Context")
    lines.append("")
    lines.append(f"| Field | Value |")
    lines.append(f"|-------|-------|")
    lines.append(f"| Target URL | `{data['target_url']}` |")
    lines.append(f"| Service description | {data['service_desc']} |")
    lines.append(f"| Tech stack | {data['tech_stack'] or 'unknown'} |")
    lines.append(f"| Authenticated | {'Yes — ' + data['auth_role'] if data['authenticated'] else 'No'} |")
    lines.append(f"| File size limit | {data['upload_size_limit'] or 'unknown'} |")
    lines.append("")

    # ── Upload functionality ─────────────────────────────────────────────────
    lines.append("## Upload Functionality")
    lines.append("")
    if data["upload_exists"]:
        lines.append("Upload functionality **exists** on the site by design.")
        lines.append("")
        if data["upload_locations"]:
            lines.append("**Known upload endpoints:**")
            for loc in data["upload_locations"]:
                lines.append(f"- `{loc}`")
        else:
            lines.append("No upload endpoints listed by operator.")
        lines.append("")
        if data["upload_types_allowed"]:
            lines.append(f"**Claimed accepted types:** `{data['upload_types_allowed']}`")
            lines.append("")
    else:
        lines.append("Upload functionality is **not present** by design — testing for unintended upload paths.")
        lines.append("")

    # ── Unexpected paths ────────────────────────────────────────────────────
    lines.append("## Unexpected / Exposed Paths")
    lines.append("")
    if data["unexpected_paths_found"] and data["unexpected_paths"]:
        lines.append("⚠️ **Operator identified unexpected paths prior to Intruder scan:**")
        lines.append("")
        for p in data["unexpected_paths"]:
            lines.append(f"- `{p}`")
        lines.append("")
        if data["manual_upload_tested"]:
            lines.append(f"**Manual upload attempted:** Yes  ")
            lines.append(f"**Result:** {data['manual_upload_result']}")
        else:
            lines.append("**Manual upload attempted:** No — not yet tested.")
        lines.append("")
    else:
        lines.append("No unexpected paths identified in pre-test recon.")
        lines.append("")

    # ── Recon notes ─────────────────────────────────────────────────────────
    lines.append("## Recon Notes")
    lines.append("")
    lines.append(f"- robots.txt / sitemap.xml reviewed: {'Yes' if data['robots_sitemap_checked'] else 'No'}")
    lines.append(f"- JS / page source reviewed for hidden endpoints: {'Yes' if data['js_paths_reviewed'] else 'No'}")
    if data["burp_sitemap_notes"]:
        lines.append(f"- Burp proxy notes: {data['burp_sitemap_notes']}")
    if data["additional_notes"]:
        lines.append(f"- Additional notes: {data['additional_notes']}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ── Next steps ──────────────────────────────────────────────────────────
    lines.append("## Next Steps")
    lines.append("")
    lines.append(
        "1. Run `busl_08_wordlist.py` to generate the upload path + extension wordlist.\n"
        "2. Send the target upload request to **Burp Intruder** (Sniper mode).\n"
        "3. Mark the file path / filename parameter as the payload position.\n"
        "4. Load the generated wordlist as a **Simple List** payload.\n"
        "5. Start the attack. Export results as XML.\n"
        "6. Run `busl_08_verdict.py --intruder inputs/xml/intruder_test.xml` to classify results.\n"
        "7. Verify any 200 OK / 302 findings manually with `curl` as directed in the verdict report."
    )
    lines.append("")
    lines.append("---")
    lines.append("*Generated by busl_08_questionnaire.py — WSTG-BUSL-08*")

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    import argparse
    p = argparse.ArgumentParser(
        description="WSTG-BUSL-08 pre-test operator questionnaire"
    )
    p.add_argument("--out",
        default=os.path.join("WSTG-BUSL-08", "outputs", "test_outputs", "sitrep.md"),
        metavar="PATH")
    args = p.parse_args()

    data = run_questionnaire()

    write_sitrep(data, args.out)

    print(f"\n{GREEN}[+] Sitrep written → {args.out}{RESET}")
    print(f"\n  {DIM}Next: run busl_08_wordlist.py to generate the Intruder wordlist.{RESET}\n")


if __name__ == "__main__":
    main()
