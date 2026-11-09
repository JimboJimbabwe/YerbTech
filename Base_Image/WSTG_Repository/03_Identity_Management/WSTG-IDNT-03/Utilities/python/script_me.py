#!/usr/bin/env python3
"""
WSTG-IDNT-03 — Account Provisioning Process
Report Generator: script_me.py

Reads four inputs:
  1. how_to_bridge.json  — maps how-to guide IDs to full descriptions / steps
  2. q_base.json         — IDNT-03 questions with applicable_how_tos stubs
  3. how_to_query.txt    — plain-text query strings used to match svc_json services
  4. svc_json            — services JSON (Ports → PotentialServices → CommonEndpoints)
                           [optional: if not supplied, service section is omitted]

Outputs:
  report.md — markdown report with:
    - Per-question checklist (question + applicable how-tos with resolved descriptions)
    - Matched services section (services relevant to provisioning found in svc_json)
    - How-to guide reference table

Usage:
  python3 script_me.py \
    -How_To_bridge /inputs/data/how_to_bridge.json \
    -questionnaire  /inputs/data/q_base.json \
    -input_strings  /inputs/data/how_to_query.txt \
    [-svc_json      /inputs/data/svc.json] \
    [-o             outputs/test_outputs/report.md]
"""

import argparse
import json
import os
import re
import sys
import textwrap
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_json(path: str, label: str) -> dict | list:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[!] {label} not found: {path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] {label} is not valid JSON: {e}", file=sys.stderr)
        sys.exit(1)


def load_query_strings(path: str) -> list[str]:
    try:
        with open(path) as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"[!] how_to_query.txt not found: {path}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Service matching (same 3-strategy approach used across CONF scripts)
# ---------------------------------------------------------------------------

def match_services(svc_json: list, query_strings: list[str]) -> list[dict]:
    """
    Return a deduplicated list of PotentialService entries whose Service name
    matches any query string. Three-pass strategy:
      1. Direct substring (case-insensitive)
      2. Keyword tokenisation
      3. Reverse keyword (query token in service name)
    """
    matched = {}  # key: service_name → entry dict

    def _add(service_name: str, service_entry: dict, port: str, protocol: str):
        if service_name not in matched:
            matched[service_name] = {
                "service":           service_name,
                "port":              port,
                "protocol":          protocol,
                "common_endpoints":  service_entry.get("CommonEndpoints", []),
                "undesirable_endpoints": service_entry.get("UndesirableEndpoints", []),
            }

    ports_list = svc_json if isinstance(svc_json, list) else svc_json.get("Ports", [])

    for port_entry in ports_list:
        port     = str(port_entry.get("Port", "?"))
        protocol = port_entry.get("Protocol", "")
        for svc in port_entry.get("PotentialServices", []):
            svc_name = svc.get("Service", "")
            svc_lower = svc_name.lower()

            for q in query_strings:
                q_lower = q.lower()

                # Strategy 1: direct substring
                if q_lower in svc_lower or svc_lower in q_lower:
                    _add(svc_name, svc, port, protocol)
                    break

                # Strategy 2: keyword tokenise the query
                tokens = re.split(r'[\s\-_/]+', q_lower)
                if all(t in svc_lower for t in tokens if t):
                    _add(svc_name, svc, port, protocol)
                    break

                # Strategy 3: reverse — service tokens in query
                svc_tokens = re.split(r'[\s\-_/]+', svc_lower)
                if any(t and t in q_lower for t in svc_tokens):
                    _add(svc_name, svc, port, protocol)
                    break

    return list(matched.values())


# ---------------------------------------------------------------------------
# How-to bridge resolution
# ---------------------------------------------------------------------------

def resolve_how_to(ht_id: str, bridge: dict) -> dict:
    """
    Look up a how-to guide in the bridge JSON.
    Bridge format expected:
      { "HT-IDNT03-AUTH-GATE": { "name": "...", "description": "...", "steps": [...] }, ... }
    OR a list:
      [ { "id": "...", "name": "...", "description": "...", "steps": [...] }, ... ]
    Falls back gracefully if not found.
    """
    if isinstance(bridge, dict):
        entry = bridge.get(ht_id)
        if entry:
            return {
                "id":          ht_id,
                "name":        entry.get("name", ht_id),
                "description": entry.get("description", ""),
                "steps":       entry.get("steps", []),
                "url":         entry.get("url", ""),
            }
    elif isinstance(bridge, list):
        for entry in bridge:
            if entry.get("id") == ht_id:
                return {
                    "id":          ht_id,
                    "name":        entry.get("name", ht_id),
                    "description": entry.get("description", ""),
                    "steps":       entry.get("steps", []),
                    "url":         entry.get("url", ""),
                }
    # Not found — return stub
    return {
        "id":          ht_id,
        "name":        ht_id,
        "description": "(no description in how_to_bridge.json)",
        "steps":       [],
        "url":         "",
    }


# ---------------------------------------------------------------------------
# Markdown report builder
# ---------------------------------------------------------------------------

def wrap(text: str, width: int = 100, indent: str = "") -> str:
    return textwrap.fill(text, width=width, initial_indent=indent, subsequent_indent=indent)


def build_report(
    q_base:       dict,
    bridge:       dict | list,
    query_strings: list[str],
    matched_svcs:  list[dict],
    args,
) -> str:
    lines = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # -----------------------------------------------------------------------
    # Header
    # -----------------------------------------------------------------------
    lines.append(f"# WSTG-IDNT-03 — Account Provisioning Process")
    lines.append(f"")
    lines.append(f"> **Generated:** {now}")
    if args.target:
        lines.append(f">")
        lines.append(f"> **Target:** {args.target}")
    if args.tester:
        lines.append(f">")
        lines.append(f"> **Tester:** {args.tester}")
    lines.append(f"")
    lines.append(
        wrap(
            q_base.get("description",
                "This report documents the assessment of the account provisioning process. "
                "Each question below maps to specific test techniques from the how-to bridge.")
        )
    )
    lines.append("")

    # -----------------------------------------------------------------------
    # Matched services
    # -----------------------------------------------------------------------
    lines.append("---")
    lines.append("")
    lines.append("## Relevant Services (from svc_json)")
    lines.append("")
    if not matched_svcs:
        if args.svc_json:
            lines.append(
                "_No services matched the provisioning query strings. "
                "Manual review of the service inventory may be needed._"
            )
        else:
            lines.append("_No svc_json supplied — service matching skipped._")
    else:
        lines.append(
            f"The following {len(matched_svcs)} service(s) matched provisioning-related "
            f"query terms and should be included in scope for this test:"
        )
        lines.append("")
        for svc in matched_svcs:
            lines.append(f"### {svc['service']} (:{svc['port']} / {svc['protocol']})")
            lines.append("")
            ce = svc.get("common_endpoints", [])
            ue = svc.get("undesirable_endpoints", [])
            if ce:
                lines.append("**Common endpoints:**")
                for ep in ce:
                    lines.append(f"- `{ep}`")
                lines.append("")
            if ue:
                lines.append("**Undesirable endpoints (flag if exposed):**")
                for ep in ue:
                    lines.append(f"- `{ep}`")
                lines.append("")

    lines.append("---")
    lines.append("")

    # -----------------------------------------------------------------------
    # Query strings used
    # -----------------------------------------------------------------------
    lines.append("## Query Strings Used (how_to_query.txt)")
    lines.append("")
    lines.append("The following terms were used to match services in svc_json:")
    lines.append("")
    for qs in query_strings:
        lines.append(f"- `{qs}`")
    lines.append("")
    lines.append("---")
    lines.append("")

    # -----------------------------------------------------------------------
    # Per-question checklist
    # -----------------------------------------------------------------------
    lines.append("## Assessment Checklist")
    lines.append("")
    lines.append(
        "Work through each question. For each how-to guide listed, follow the steps "
        "in the **How-To Guide Reference** section at the bottom of this report."
    )
    lines.append("")

    questions = q_base.get("questions", [])
    # Collect all how-tos for the reference table
    all_how_tos = {}

    for i, q in enumerate(questions, start=1):
        lines.append(f"### Q{i}: {q['text']}")
        lines.append("")
        lines.append("- [ ] Tested")
        lines.append("")

        how_tos = q.get("applicable_how_tos", [])
        if how_tos:
            lines.append("**Applicable how-to guides:**")
            lines.append("")
            for ht_stub in how_tos:
                ht_id   = ht_stub.get("id", "")
                ht_name = ht_stub.get("name", ht_id)
                ht_url  = ht_stub.get("url", "")

                resolved = resolve_how_to(ht_id, bridge)
                all_how_tos[ht_id] = resolved

                # Override name from stub if bridge has nothing better
                display_name = resolved["name"] if resolved["name"] != ht_id else ht_name

                if ht_url:
                    lines.append(f"- [{display_name}]({ht_url}) — `{ht_id}`")
                elif resolved.get("url"):
                    lines.append(f"- [{display_name}]({resolved['url']}) — `{ht_id}`")
                else:
                    lines.append(f"- {display_name} — `{ht_id}`")

            lines.append("")

        lines.append("**Notes:**")
        lines.append("")
        lines.append("> _Record observations, evidence, or test results here._")
        lines.append("")

    lines.append("---")
    lines.append("")

    # -----------------------------------------------------------------------
    # How-to guide reference
    # -----------------------------------------------------------------------
    lines.append("## How-To Guide Reference")
    lines.append("")
    lines.append(
        "Full descriptions and steps for each how-to guide referenced above. "
        "Entries are drawn from `how_to_bridge.json`."
    )
    lines.append("")

    for ht_id, ht in all_how_tos.items():
        lines.append(f"### {ht['name']}")
        lines.append(f"**ID:** `{ht_id}`")
        if ht.get("url"):
            lines.append(f"**Reference:** {ht['url']}")
        lines.append("")
        if ht.get("description"):
            lines.append(wrap(ht["description"]))
            lines.append("")
        steps = ht.get("steps", [])
        if steps:
            lines.append("**Steps:**")
            lines.append("")
            for j, step in enumerate(steps, start=1):
                if isinstance(step, str):
                    lines.append(f"{j}. {step}")
                elif isinstance(step, dict):
                    title = step.get("title", step.get("name", f"Step {j}"))
                    detail = step.get("detail", step.get("description", ""))
                    lines.append(f"{j}. **{title}**")
                    if detail:
                        lines.append(f"   {detail}")
            lines.append("")
        else:
            lines.append(
                "_No steps defined in how_to_bridge.json for this guide. "
                "Populate the bridge file to add step-by-step instructions._"
            )
            lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## Vulnerability Assessment")
    lines.append("")
    lines.append("After completing the checklist, record the overall verdict here.")
    lines.append("")
    lines.append("**Flawed / Vulnerable:** ☐ Yes &nbsp; ☐ No")
    lines.append("")
    lines.append("**Why (if yes):**")
    lines.append("")
    lines.append("> _Enter reasoning here._")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(f"*Generated by script_me.py — WSTG-IDNT-03*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description=(
            'IDNT-03 Report Generator: '
            'reads how_to_bridge.json + q_base.json + how_to_query.txt '
            '[+ svc_json] → outputs report.md'
        )
    )
    p.add_argument(
        '-How_To_bridge', '--How_To_bridge',
        required=True,
        metavar='PATH',
        help='Path to how_to_bridge.json'
    )
    p.add_argument(
        '-questionnaire', '--questionnaire',
        required=True,
        metavar='PATH',
        help='Path to q_base.json'
    )
    p.add_argument(
        '-input_strings', '--input_strings',
        required=True,
        metavar='PATH',
        help='Path to how_to_query.txt (plain text, one query string per line)'
    )
    p.add_argument(
        '-svc_json', '--svc_json',
        default=None,
        metavar='PATH',
        help='Path to svc_json (optional; enables service matching)'
    )
    p.add_argument(
        '-o', '--output',
        default='outputs/test_outputs/report.md',
        help='Output markdown report (default: outputs/test_outputs/report.md)'
    )
    p.add_argument('--target', default='', help='Target application name/version')
    p.add_argument('--tester', default='', help='Tester name / handle')
    return p.parse_args()


def main():
    args = parse_args()

    bridge       = load_json(args.How_To_bridge, "how_to_bridge.json")
    q_base       = load_json(args.questionnaire, "q_base.json")
    query_strings = load_query_strings(args.input_strings)

    matched_svcs = []
    if args.svc_json:
        svc_data = load_json(args.svc_json, "svc_json")
        matched_svcs = match_services(svc_data, query_strings)
        print(f"[*] svc_json: {len(matched_svcs)} service(s) matched provisioning query strings")
    else:
        print("[*] No svc_json supplied — service matching skipped")

    report = build_report(q_base, bridge, query_strings, matched_svcs, args)

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, 'w') as f:
        f.write(report)

    print(f"[+] Report written → {args.output}")


if __name__ == "__main__":
    main()
