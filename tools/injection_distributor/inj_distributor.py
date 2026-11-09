#!/usr/bin/env python3
"""
07_Injection — Master Wordlist & Data Distributor
==================================================
Single script that seeds every active WSTG-INJT-XX subfolder with:

    Inputs/Wordlists/wordlist.txt       — type-specific payload placeholders
    Inputs/Data/<type>_injection.md     — what/why methodology notes

Folders marked  skip=True  are left untouched — those injection types
have (or will have) their own dedicated tooling.

Place this script at:  07_Injection/inj_distributor.py

------------------------------------------------------------------------------
2026-11-08 correction - READ THIS IF YOU ARE COMPARING AGAINST AN OLDER COPY
------------------------------------------------------------------------------
Every WSTG-INJT-XX key in CATALOG below has been re-checked against this
project's own wstg_reporting.json (the file that actually drives the GUI's
checklist and is the single source of truth for WSTG IDs in this project -
see the README's "Insecure Deserialization" and "Prototype Pollution"
sections for the same correction applied earlier to two individual items).

The previous version of this file had roughly half its IDs wrong against
that source: several entries were shifted by a few numbers (its "01" was
really SQL Injection, properly WSTG-INJT-05; its "05" was really LDAP
Injection, properly WSTG-INJT-06; and so on down the list), WSTG-INJT-15 and
-16 were swapped (Request Smuggling and Response Splitting), real items
WSTG-INJT-01 (Reflected XSS), -02 (Stored XSS) and -14 (Incubated
Vulnerability) were missing from the catalog entirely, and two entries -
"Blind SQL Injection" at old-"02" and "ORM / GraphQL Injection" at old-"23" -
aren't their own WSTG-INJT IDs in this project's numbering at all (GraphQL
has its own real ID, WSTG-APIT-99, in a different category; blind SQLi is a
technique within WSTG-INJT-05, not a separate item), so they've been removed
as standalone catalog entries - two of blind SQLi's placeholder payloads were
folded into WSTG-INJT-05's own payload list instead of being discarded.

Worst of all: the old WSTG-INJT-21/22/23 entries were themselves wrong in a
way that actively mattered - they were labelled Insecure Deserialization,
NoSQL Injection and ORM/GraphQL Injection respectively, skip=False for the
latter two, meaning a plain `python inj_distributor.py` run would have
written a placeholder wordlist.txt and a wrong-topic methodology .md
straight into the Prototype Pollution (WSTG-INJT-22) and Insecure
Deserialization (WSTG-INJT-23) item folders - the two items that now have
real, purpose-built tools (tools/protopollution/, tools/deser/) sitting in
those exact folders. Both are now correctly marked skip=True here, same as
WSTG-INJT-04 (HTTP Parameter Pollution, hpp_04.py) already was.

WSTG-INJT-15, -16, -18, -19, -20 keep their skip=True status from the
previous version (just corrected to their right IDs/content) - that was
recorded earlier in this project as "by design per the user's own
statement", i.e. confirmed deliberately, not discovered by this script, and
this correction pass had no independent reason to second-guess it. If any of
those five is not actually handled elsewhere, flip its skip to False (or run
with --only) rather than relying on the distributor to catch that.

Usage
-----
    python inj_distributor.py                               # write all active folders
    python inj_distributor.py --dry-run                     # preview without writing
    python inj_distributor.py --only WSTG-INJT-01,WSTG-INJT-11
    python inj_distributor.py --list-json                    # print CATALOG as JSON, exit
                                                               # (used by the GUI wrapper so it
                                                               # never carries its own separate
                                                               # copy of this list to drift out
                                                               # of sync with the one below)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Windows consoles often default to a legacy code page (cp1252) that can't encode the
# arrow/dash characters used in this script's own status output below (print() calls in
# distribute(), not the file writes - those already pass encoding="utf-8" explicitly).
# Reconfigure stdout/stderr to UTF-8 so printing never crashes, regardless of the host's
# console codepage or whether stdout is a real console or a pipe (e.g. run from the GUI).
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

SCRIPT_DIR = Path(__file__).resolve().parent   # 07_Injection/


# ── Injection catalog ─────────────────────────────────────────────────────────
# One entry per WSTG-INJT-XX folder, IDs matched against this project's own
# wstg_reporting.json - see the correction note above before editing this.
#
#   label    — human-readable injection type name (matches wstg_reporting.json)
#   md_name  — filename written to Inputs/Data/
#   skip     — True → leave folder alone (dedicated tool exists / out-of-scope)
#   what     — brief answer for "What are we testing?"
#   why      — brief answer for "Why are we testing for this?"
#   payloads — placeholder list; operator fills with live strings before use

CATALOG: dict[str, dict] = {

    # ── Reflected XSS ─────────────────────────────────────────────────────────
    "WSTG-INJT-01": dict(
        label    = "Reflected Cross Site Scripting",
        md_name  = "reflected_xss_injection.md",
        skip     = False,
        what     = (
            "Identify input that is reflected back in the response and test whether it is "
            "accepted without proper output encoding, allowing script execution in the "
            "victim's browser."
        ),
        why      = (
            "Reflected XSS can be used to steal sessions, perform actions as the victim, or "
            "deliver malicious content through a crafted link - no stored state required."
        ),
        payloads = [
            "PLACEHOLDER_XSS_REFLECTED_SCRIPT_01",
            "PLACEHOLDER_XSS_REFLECTED_EVENT_01",
            "PLACEHOLDER_XSS_REFLECTED_ENCODED_01",
        ],
    ),

    # ── Stored XSS ────────────────────────────────────────────────────────────
    "WSTG-INJT-02": dict(
        label    = "Stored Cross Site Scripting",
        md_name  = "stored_xss_injection.md",
        skip     = False,
        what     = (
            "Find stored user input that is later rendered to other users and test whether "
            "it is properly encoded wherever it is redisplayed."
        ),
        why      = (
            "Stored XSS executes automatically for every viewer, so it can compromise many "
            "users - including administrators - without any interaction beyond visiting the page."
        ),
        payloads = [
            "PLACEHOLDER_XSS_STORED_SCRIPT_01",
            "PLACEHOLDER_XSS_STORED_ATTR_01",
        ],
    ),

    # ── HTTP Verb Tampering ───────────────────────────────────────────────────
    "WSTG-INJT-03": dict(
        label    = "HTTP Verb Tampering",
        md_name  = "http_verb_tampering_injection.md",
        skip     = False,
        what     = (
            "Test whether the application correctly validates and restricts HTTP "
            "methods, and whether switching verbs (GET → POST → PUT → HEAD → TRACE) "
            "bypasses access controls or triggers unintended behaviour."
        ),
        why      = (
            "Security controls in web frameworks are sometimes scoped to specific "
            "methods only. An unexpected verb can expose privileged functionality, "
            "bypass CSRF protections, or evade WAF rules written for POST."
        ),
        payloads = [
            "PLACEHOLDER_VERB_01",
            "PLACEHOLDER_VERB_02",
        ],
    ),

    # ── HTTP Parameter Pollution — SKIP (own dedicated tool: hpp_04.py) ───────
    "WSTG-INJT-04": dict(
        label    = "HTTP Parameter Pollution",
        md_name  = "http_parameter_pollution_injection.md",
        skip     = True,    # dedicated HPP tool - hpp_04.py, confirmed present in this folder
        what     = "N/A — handled by dedicated HPP tool.",
        why      = "N/A",
        payloads = [],
    ),

    # ── SQL ───────────────────────────────────────────────────────────────────
    "WSTG-INJT-05": dict(
        label    = "SQL Injection",
        md_name  = "sql_injection.md",
        skip     = False,
        what     = (
            "Determine whether user-supplied input incorporated into SQL queries "
            "is sanitised or parameterised before execution against the database - "
            "both where errors/data are returned directly, and blind (boolean- or "
            "time-based inference when the application suppresses direct output)."
        ),
        why      = (
            "Successful exploitation lets an attacker read sensitive data, modify "
            "or delete database content, bypass authentication, and — depending on "
            "the DB engine's configuration — execute OS-level commands. Blind SQLi "
            "bypasses mitigations that merely hide error output and is routinely "
            "automated with tools such as sqlmap."
        ),
        payloads = [
            "PLACEHOLDER_SQL_01",
            "PLACEHOLDER_SQL_02",
            "PLACEHOLDER_SQL_03",
            "PLACEHOLDER_BLIND_SQL_BOOL_01",
            "PLACEHOLDER_BLIND_SQL_TIME_01",
        ],
    ),

    # ── LDAP ─────────────────────────────────────────────────────────────────
    "WSTG-INJT-06": dict(
        label    = "LDAP Injection",
        md_name  = "ldap_injection.md",
        skip     = False,
        what     = (
            "Test whether user input passed into LDAP filter strings is correctly "
            "escaped, enabling manipulation of filter logic."
        ),
        why      = (
            "LDAP injection can allow an attacker to bypass authentication, enumerate "
            "directory objects (users, groups, OUs, attributes), and in some "
            "configurations modify directory entries."
        ),
        payloads = [
            "PLACEHOLDER_LDAP_01",
            "PLACEHOLDER_LDAP_02",
        ],
    ),

    # ── XML ───────────────────────────────────────────────────────────────────
    "WSTG-INJT-07": dict(
        label    = "XML Injection",
        md_name  = "xml_injection.md",
        skip     = False,
        what     = (
            "Test whether the application's XML parser processes external entities "
            "(XXE) or allows injection of malicious XML nodes that alter application "
            "logic or data handling."
        ),
        why      = (
            "XXE allows reading arbitrary local files, server-side request forgery, "
            "and denial-of-service via entity expansion (billion-laughs). XML "
            "injection can corrupt data logic and bypass input validation."
        ),
        payloads = [
            "PLACEHOLDER_XXE_FILE_READ_01",
            "PLACEHOLDER_XXE_SSRF_01",
            "PLACEHOLDER_XML_INJECT_01",
        ],
    ),

    # ── SSI ──────────────────────────────────────────────────────────────────
    "WSTG-INJT-08": dict(
        label    = "SSI Injection",
        md_name  = "ssi_injection.md",
        skip     = False,
        what     = (
            "Test whether user input is reflected into HTML pages parsed for SSI "
            "directives, allowing injection of directives that the web server executes."
        ),
        why      = (
            "SSI injection can expose server-side files and environment variables. "
            "In permissive configurations, #exec directives allow arbitrary command "
            "execution on the web server."
        ),
        payloads = [
            "PLACEHOLDER_SSI_01",
            "PLACEHOLDER_SSI_02",
        ],
    ),

    # ── XPath ────────────────────────────────────────────────────────────────
    "WSTG-INJT-09": dict(
        label    = "XPath Injection",
        md_name  = "xpath_injection.md",
        skip     = False,
        what     = (
            "Test whether user-supplied data passed into XPath expressions is "
            "sanitised, allowing manipulation of the query to return unintended nodes."
        ),
        why      = (
            "XPath injection can bypass XML-backed authentication, expose the full "
            "document structure, and leak data stored in XML datastores without "
            "requiring SQL knowledge."
        ),
        payloads = [
            "PLACEHOLDER_XPATH_01",
            "PLACEHOLDER_XPATH_02",
        ],
    ),

    # ── IMAP / SMTP ───────────────────────────────────────────────────────────
    "WSTG-INJT-10": dict(
        label    = "IMAP SMTP Injection",
        md_name  = "imap_smtp_injection.md",
        skip     = False,
        what     = (
            "Test whether user input passed to IMAP or SMTP backend commands is "
            "sanitised, allowing injection of additional protocol-level commands."
        ),
        why      = (
            "IMAP/SMTP injection can allow an attacker to read other users' mail, "
            "relay outbound spam, enumerate mailbox contents, or exfiltrate data "
            "through crafted protocol sequences."
        ),
        payloads = [
            "PLACEHOLDER_IMAP_01",
            "PLACEHOLDER_SMTP_01",
        ],
    ),

    # ── Code Injection ────────────────────────────────────────────────────────
    "WSTG-INJT-11": dict(
        label    = "Code Injection",
        md_name  = "code_injection.md",
        skip     = False,
        what     = (
            "Test whether user-controlled data is evaluated as executable code "
            "server-side — e.g. through eval(), exec(), dynamic requires/includes, "
            "or interpreted string expansion."
        ),
        why      = (
            "Code injection leads directly to remote code execution, granting full "
            "server compromise, data exfiltration, persistence, and the ability to "
            "pivot into internal networks from the web server."
        ),
        payloads = [
            "PLACEHOLDER_CODE_PHP_01",
            "PLACEHOLDER_CODE_JS_01",
            "PLACEHOLDER_CODE_GENERIC_01",
        ],
    ),

    # ── Command Injection ─────────────────────────────────────────────────────
    "WSTG-INJT-12": dict(
        label    = "Command Injection",
        md_name  = "command_injection.md",
        skip     = False,
        what     = (
            "Test whether user-supplied input is passed unsanitised to OS shell "
            "calls (system(), exec(), popen(), subprocess, etc.), allowing injection "
            "of arbitrary shell instructions."
        ),
        why      = (
            "Command injection gives the attacker a shell on the web server with "
            "the process's effective privileges — enabling full filesystem access, "
            "credential harvesting, and lateral movement."
        ),
        payloads = [
            "PLACEHOLDER_CMD_UNIX_01",
            "PLACEHOLDER_CMD_WIN_01",
            "PLACEHOLDER_CMD_SEPARATOR_01",
        ],
    ),

    # ── Format String ─────────────────────────────────────────────────────────
    "WSTG-INJT-13": dict(
        label    = "Format String Injection",
        md_name  = "format_string_injection.md",
        skip     = False,
        what     = (
            "Test whether user input is placed directly into printf-family format "
            "functions (or equivalent constructs) without a fixed format specifier, "
            "exposing format string processing to attacker control."
        ),
        why      = (
            "Format string bugs allow arbitrary memory reads (leaking stack, heap, "
            "canaries, and return addresses) and — via %n — arbitrary memory writes "
            "that can redirect control flow and achieve code execution."
        ),
        payloads = [
            "PLACEHOLDER_FMT_01",
            "PLACEHOLDER_FMT_02",
        ],
    ),

    # ── Incubated Vulnerability ───────────────────────────────────────────────
    "WSTG-INJT-14": dict(
        label    = "Incubated Vulnerability",
        md_name  = "incubated_vulnerability_injection.md",
        skip     = False,
        what     = (
            "Find injections that are stored and only trigger later when another process "
            "or user recalls the stored data, and set up listeners/triggers for that recall "
            "(e.g. a payload in a filename, log line, or export that fires when an admin "
            "tool or batch job later processes it)."
        ),
        why      = (
            "These delayed attacks are easy to miss during normal testing, since nothing "
            "happens at submission time, but can affect other users or back-end systems "
            "once the stored data is eventually reprocessed."
        ),
        payloads = [
            "PLACEHOLDER_INCUBATED_FILENAME_01",
            "PLACEHOLDER_INCUBATED_LOGLINE_01",
        ],
    ),

    # ── HTTP Response Splitting — SKIP ─────────────────────────────────────────
    "WSTG-INJT-15": dict(
        label    = "HTTP Response Splitting",
        md_name  = "http_response_splitting_injection.md",
        skip     = True,    # grouped with HTTP splitting/smuggling tool - see 2026-11-08 note above
        what     = "N/A — handled by dedicated HTTP splitting tool.",
        why      = "N/A",
        payloads = [],
    ),

    # ── HTTP Request Smuggling — SKIP ─────────────────────────────────────────
    "WSTG-INJT-16": dict(
        label    = "HTTP Request Smuggling",
        md_name  = "http_request_smuggling_injection.md",
        skip     = True,    # dedicated tool - see 2026-11-08 note above
        what     = "N/A — handled by dedicated HTTP smuggling tool.",
        why      = "N/A",
        payloads = [],
    ),

    # ── Host Header Injection ─────────────────────────────────────────────────
    "WSTG-INJT-17": dict(
        label    = "Host Header Injection",
        md_name  = "host_header_injection.md",
        skip     = False,
        what     = (
            "Test whether the application uses the HTTP Host header value without "
            "validation in link generation, redirects, cache keys, or downstream "
            "requests, making it susceptible to poisoning attacks."
        ),
        why      = (
            "Host header injection can poison web caches with malicious responses, "
            "redirect password-reset links to attacker-controlled domains, or trigger "
            "internal SSRF if the header value is forwarded as a URL."
        ),
        payloads = [
            "PLACEHOLDER_HOST_01",
            "PLACEHOLDER_HOST_02",
        ],
    ),

    # ── SSTI — SKIP ───────────────────────────────────────────────────────────
    "WSTG-INJT-18": dict(
        label    = "Server-side Template Injection",
        md_name  = "ssti_injection.md",
        skip     = True,    # own dedicated tool - see 2026-11-08 note above
        what     = "N/A — handled by dedicated SSTI tool.",
        why      = "N/A",
        payloads = [],
    ),

    # ── SSRF — SKIP ───────────────────────────────────────────────────────────
    "WSTG-INJT-19": dict(
        label    = "Server-Side Request Forgery",
        md_name  = "ssrf_injection.md",
        skip     = True,    # own dedicated tool - see 2026-11-08 note above
        what     = "N/A — handled by dedicated SSRF tool.",
        why      = "N/A",
        payloads = [],
    ),

    # ── Mass Assignment — SKIP ────────────────────────────────────────────────
    "WSTG-INJT-20": dict(
        label    = "Mass Assignment",
        md_name  = "mass_assignment_injection.md",
        skip     = True,    # own dedicated tool - see 2026-11-08 note above
        what     = "N/A — handled by dedicated mass assignment tool.",
        why      = "N/A",
        payloads = [],
    ),

    # ── CSV Injection ─────────────────────────────────────────────────────────
    # NOTE: this is the correct topic for WSTG-INJT-21. The previous version of
    # this file had Insecure Deserialization here (wrong - that's WSTG-INJT-23,
    # see below) - see the 2026-11-08 correction note at the top of this file.
    "WSTG-INJT-21": dict(
        label    = "CSV Injection",
        md_name  = "csv_injection.md",
        skip     = False,
        what     = (
            "Test spreadsheet/CSV export features to see whether untrusted values are "
            "interpreted as formulas when opened in spreadsheet software, and whether "
            "mitigations (leading-character escaping/quoting) hold."
        ),
        why      = (
            "Malicious formulas can exfiltrate data or run commands on the machine of "
            "whoever opens the export, such as an administrator."
        ),
        payloads = [
            "PLACEHOLDER_CSV_FORMULA_EQUALS_01",
            "PLACEHOLDER_CSV_FORMULA_PLUS_01",
            "PLACEHOLDER_CSV_FORMULA_AT_01",
        ],
    ),

    # ── Prototype Pollution — SKIP ────────────────────────────────────────────
    # NOTE: this is the correct topic for WSTG-INJT-22. The previous version of
    # this file had "NoSQL Injection" here (wrong, and not a real distinct
    # WSTG-INJT ID in this project's numbering at all) - see the 2026-11-08
    # correction note at the top of this file. Own dedicated tool now lives
    # here: tools/protopollution/ (protopoll_wordlists.py + hash_fragment_opener.py).
    "WSTG-INJT-22": dict(
        label    = "Prototype Pollution",
        md_name  = "prototype_pollution_injection.md",
        skip     = True,    # own dedicated tool - tools/protopollution/
        what     = "N/A — handled by the dedicated Prototype Pollution tool.",
        why      = "N/A",
        payloads = [],
    ),

    # ── Insecure Deserialization — SKIP ───────────────────────────────────────
    # NOTE: this is the correct topic for WSTG-INJT-23. The previous version of
    # this file had "ORM / GraphQL Injection" here (wrong, and not a real
    # distinct WSTG-INJT ID in this project's numbering - GraphQL has its own
    # real WSTG ID, WSTG-APIT-99, in a different category) - see the
    # 2026-11-08 correction note at the top of this file. Own dedicated tool
    # now lives here: tools/deser/deser_wordlist.py (ysoserial / phpggc wrapper).
    "WSTG-INJT-23": dict(
        label    = "Insecure Deserialization",
        md_name  = "insecure_deserialization_injection.md",
        skip     = True,    # own dedicated tool - tools/deser/
        what     = "N/A — handled by the dedicated Insecure Deserialization tool.",
        why      = "N/A",
        payloads = [],
    ),
}


# ── Markdown template ─────────────────────────────────────────────────────────

def _render_md(folder_id: str, entry: dict) -> str:
    return f"""# {folder_id} — {entry['label']}

## What Are We Testing?

{entry['what']}

## Why Are We Testing For This?

{entry['why']}

---
*{folder_id} | 07 — Injection Testing*
*Auto-generated by `inj_distributor.py` — extend with engagement-specific notes below.*

## Engagement Notes

<!-- Scope, target observations, confirmed findings, tool output references. -->
"""


# ── Distributor ───────────────────────────────────────────────────────────────

def distribute(
    root: Path,
    catalog: dict[str, dict],
    dry_run: bool,
    only: set[str] | None,
) -> None:
    folders = sorted(root.glob("WSTG-INJT-*"))
    if not folders:
        sys.exit(f"[!] No WSTG-INJT-* folders found under {root}")

    tag = "[DRY RUN]" if dry_run else "[WRITE]  "
    print(f"\n{tag}  Root : {root}\n")

    written = skipped = filtered = unknown = 0

    for folder in folders:
        fid   = folder.name
        entry = catalog.get(fid)

        # --only filter
        if only and fid not in only:
            filtered += 1
            continue

        # Not in catalog at all
        if entry is None:
            print(f"  [?]  {fid:<18}  — not in catalog (add an entry if needed)")
            unknown += 1
            continue

        # Explicitly skipped
        if entry.get("skip"):
            print(f"  [─]  {fid:<18}  {entry['label']}  — own tool, skipped")
            skipped += 1
            continue

        # ── Active folder ────────────────────────────────────────────────
        wl_dir  = folder / "Inputs" / "Wordlists"
        dat_dir = folder / "Inputs" / "Data"
        wl_path = wl_dir  / "wordlist.txt"
        md_path = dat_dir / entry["md_name"]

        wl_content = "\n".join(entry["payloads"]) + "\n"
        md_content = _render_md(fid, entry)

        n_payloads = len(entry["payloads"])
        print(f"  [+]  {fid:<18}  {entry['label']}")
        print(f"         wordlist  →  {wl_path.relative_to(root)}  ({n_payloads} placeholder(s))")
        print(f"         data      →  {md_path.relative_to(root)}")

        if not dry_run:
            wl_dir.mkdir(parents=True, exist_ok=True)
            dat_dir.mkdir(parents=True, exist_ok=True)
            wl_path.write_text(wl_content, encoding="utf-8")
            md_path.write_text(md_content, encoding="utf-8")

        written += 1

    # ── Summary ───────────────────────────────────────────────────────────
    print(f"\n{tag}  Summary")
    print(f"  Active   : {written}")
    print(f"  Skipped  : {skipped}  (own tools)")
    if only:
        print(f"  Filtered : {filtered}  (--only)")
    if unknown:
        print(f"  Unknown  : {unknown}  (add to CATALOG dict)")
    if dry_run:
        print(f"\n  Nothing written.  Re-run without --dry-run to apply.\n")
    else:
        print(f"\n  Done.\n")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="WSTG 07_Injection — master wordlist & methodology distributor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Wordlists contain placeholder strings — replace with live payloads.\n"
            "MD files contain what/why notes — extend with engagement observations."
        ),
    )
    ap.add_argument(
        "--dry-run", action="store_true",
        help="Preview what would be written without touching the filesystem",
    )
    ap.add_argument(
        "--only", metavar="WSTG-INJT-XX,…",
        help="Process only these comma-separated folder names",
    )
    ap.add_argument(
        "--root", metavar="DIR", default=str(SCRIPT_DIR),
        help=f"Injection folder root  [default: {SCRIPT_DIR}]",
    )
    ap.add_argument(
        "--list-json", action="store_true",
        help="Print CATALOG (id, label, skip) as JSON to stdout and exit - nothing is written. "
             "Used by the GUI wrapper so it reads this file's own catalog live instead of "
             "carrying a separate copy that could drift out of sync with it.",
    )

    args     = ap.parse_args()

    if args.list_json:
        print(json.dumps(
            [{"id": k, "label": v["label"], "skip": bool(v.get("skip"))} for k, v in CATALOG.items()],
            indent=2,
        ))
        return

    root     = Path(args.root)
    only_set = {x.strip() for x in args.only.split(",")} if args.only else None

    if not root.is_dir():
        sys.exit(f"[!] Root directory not found: {root}")

    distribute(root, CATALOG, dry_run=args.dry_run, only=only_set)


if __name__ == "__main__":
    main()
