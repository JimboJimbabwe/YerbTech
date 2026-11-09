#!/usr/bin/env python3
"""
WSTG-BUSL-06 — Circumvention of Workflows
Script: curl_tester.py

Reads workflows_groups.json produced by busl_06_gui.py, executes the
Curl_to_launch command for every workflow group, and records whether
the endpoint was reachable (HTTP 200).

A 200 OK means the final workflow step was accessible directly —
without completing the preceding steps — which is the vulnerability.

Note on §SESSION§:
  The curl commands contain a §SESSION§ placeholder for cookies and
  auth headers. Before running this script, edit workflows_groups.json
  and replace §SESSION§ with a real (or empty) session value, OR pass
  --session-token to have this script substitute it automatically.

Usage:
  python3 WSTG-BUSL-06/utilities/python/curl_tester.py \\
      [--groups   WSTG-BUSL-06/inputs/json/workflows_groups.json] \\
      [--session-token "sessionid=abc123"] \\
      [--timeout  15]

Outputs:
  WSTG-BUSL-06/outputs/test_outputs/workflow_findings.json
  WSTG-BUSL-06/outputs/test_outputs/workflow_findings.md
"""

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
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

WIDTH  = 65


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SESSION_PLACEHOLDER = "§SESSION§"


def substitute_session(curl_cmd: str, token: str) -> str:
    """Replace §SESSION§ with a real token value."""
    return curl_cmd.replace(SESSION_PLACEHOLDER, token)


def run_curl(curl_cmd: str, timeout: int) -> tuple[int, str, str]:
    """
    Execute a curl command, return (http_status_code, stdout, stderr).
    Appends -o /dev/null -w '%{http_code}' -s to capture only the status.
    """
    # Strip any existing -o / -w flags we might duplicate, add ours
    cmd_with_status = curl_cmd + " -o /dev/null -w '%{http_code}'"
    try:
        result = subprocess.run(
            cmd_with_status,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        # Last token of stdout should be the status code from %{http_code}
        status_str = stdout.split()[-1] if stdout else "0"
        try:
            status = int(status_str)
        except ValueError:
            status = 0
        return status, stdout, stderr
    except subprocess.TimeoutExpired:
        return 0, "", f"Timeout after {timeout}s"
    except Exception as e:
        return 0, "", str(e)


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-BUSL-06 workflow curl tester"
    )
    p.add_argument("--groups",
        default=os.path.join("WSTG-BUSL-06", "inputs", "json", "workflows_groups.json"),
        metavar="PATH",
        help="workflows_groups.json from busl_06_gui.py")
    p.add_argument("--json-out",
        default=os.path.join("WSTG-BUSL-06", "outputs", "test_outputs", "workflow_findings.json"),
        metavar="PATH")
    p.add_argument("--md-out",
        default=os.path.join("WSTG-BUSL-06", "outputs", "test_outputs", "workflow_findings.md"),
        metavar="PATH")
    p.add_argument("--session-token",
        default="",
        metavar="TOKEN",
        help="Replace §SESSION§ with this value in all curl commands "
             "(e.g. 'sessionid=abc123; csrf=xyz')")
    p.add_argument("--timeout",
        type=int, default=15,
        metavar="N",
        help="Per-request timeout in seconds (default: 15)")
    args = p.parse_args()

    print(f"\n{BOLD}{'='*WIDTH}{RESET}")
    print(f"{BOLD}  WSTG-BUSL-06 — Workflow Curl Tester{RESET}")
    print(f"{BOLD}{'='*WIDTH}{RESET}\n")

    # ── Load groups ──────────────────────────────────────────────────────────
    try:
        with open(args.groups, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"  {RED}[!] groups JSON not found: {args.groups}{RESET}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"  {RED}[!] JSON parse error: {e}{RESET}", file=sys.stderr)
        sys.exit(1)

    workflows = data.get("Workflows", {})
    if not workflows:
        print(f"  {YELLOW}[!] No workflow groups found in {args.groups}{RESET}")
        sys.exit(0)

    # ── Warn about placeholder ───────────────────────────────────────────────
    unresolved = any(
        SESSION_PLACEHOLDER in g.get("Curl_to_launch", "")
        for g in workflows.values()
    )
    if unresolved and not args.session_token:
        print(f"  {YELLOW}[!] §SESSION§ placeholder detected in curl commands.{RESET}")
        print(f"  {YELLOW}    Pass --session-token or edit workflows_groups.json{RESET}")
        print(f"  {YELLOW}    to substitute a real session token before running.{RESET}\n")

    # ── Run curls ────────────────────────────────────────────────────────────
    findings = {"Workflows": {}}
    vulnerable_count = 0
    total = len(workflows)

    print(f"  Groups to test : {total}")
    print(f"  Timeout        : {args.timeout}s\n")
    print(f"  {'─'*50}")

    for gname, group in workflows.items():
        curl_raw = group.get("Curl_to_launch", "")
        target   = group.get("Target_endpoint", "?")
        t_index  = group.get("Target_index", "?")
        paths    = group.get("Paths", [])

        # Substitute session token if provided
        curl_cmd = substitute_session(curl_raw, args.session_token) if args.session_token else curl_raw

        still_has_placeholder = SESSION_PLACEHOLDER in curl_cmd

        print(f"\n  {BOLD}{gname}{RESET}  →  {target}  [index {t_index}]")

        if still_has_placeholder:
            print(f"  {YELLOW}  ⚠ §SESSION§ not substituted — curl may fail or test unauth path{RESET}")

        status, stdout, stderr = run_curl(curl_cmd, args.timeout)

        vulnerable = (status == 200)
        if vulnerable:
            vulnerable_count += 1
            flag = f"{RED}[VULNERABLE]{RESET}"
        elif status == 0:
            flag = f"{YELLOW}[ERROR / TIMEOUT]{RESET}"
        else:
            flag = f"{GREEN}[NOT VULNERABLE]{RESET}  ({status})"

        print(f"  {flag}  HTTP {status}")
        if stderr:
            print(f"  {DIM}  stderr: {stderr[:80]}{RESET}")

        findings["Workflows"][gname] = {
            "Vulnerable":      vulnerable,
            "Target_paths":    paths,
            "Target_endpoint": target,
            "Target_index":    t_index,
            "Curl_launched":   curl_cmd,
            "Http_status":     status,
            "Error":           stderr if not vulnerable else "",
        }

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n  {'─'*50}")
    print(f"  Tested      : {total}")
    print(f"  {RED}Vulnerable  : {vulnerable_count}{RESET}")
    print(f"  {GREEN}Secure      : {total - vulnerable_count}{RESET}")

    # ── Write JSON ───────────────────────────────────────────────────────────
    os.makedirs(os.path.dirname(args.json_out), exist_ok=True)
    findings["_meta"] = {
        "generated":         datetime.now().isoformat(),
        "groups_source":     args.groups,
        "total_groups":      total,
        "vulnerable_count":  vulnerable_count,
    }
    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    # ── Write markdown ───────────────────────────────────────────────────────
    os.makedirs(os.path.dirname(args.md_out), exist_ok=True)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    md = []
    md.append("# WSTG-BUSL-06 — Workflow Findings")
    md.append("")
    md.append(f"**Generated:** {now_str}  ")
    md.append(f"**Groups tested:** {total}  ")
    md.append(f"**Vulnerable:** {vulnerable_count}  ")
    md.append("")
    md.append("---")
    md.append("")

    for gname, result in findings["Workflows"].items():
        vuln     = result["Vulnerable"]
        endpoint = result["Target_endpoint"]
        t_idx    = result["Target_index"]
        curl_out = result["Curl_launched"]
        http_s   = result["Http_status"]

        md.append(f"## {gname}")
        md.append("")

        if vuln:
            md.append(f"**Verdict: ⚠ VULNERABLE**  ")
            md.append("")
            md.append(
                f"The endpoint or workflow `{endpoint}` (index `{t_idx}`) was accessible "
                f"directly without completing the preceding workflow steps. "
                f"A `200 OK` was returned when the final request was issued in isolation."
            )
            md.append("")
            md.append(
                f"Confirm this as a true positive by replaying the request in "
                f"**Burp Repeater** and verifying the response represents a meaningful "
                f"state change or privileged action completion."
            )
        else:
            md.append(f"**Verdict: ✓ Not Vulnerable** (HTTP {http_s})  ")
            md.append("")
            md.append(
                f"The endpoint `{endpoint}` (index `{t_idx}`) did not return HTTP 200 "
                f"when the final workflow request was issued in isolation."
            )
            if result.get("Error"):
                md.append("")
                md.append(f"*Error:* `{result['Error']}`")

        md.append("")
        md.append(f"**Target endpoint:** `{endpoint}`  ")
        md.append(f"**Target index:** `{t_idx}`  ")
        md.append(f"**HTTP status:** `{http_s}`  ")
        md.append("")
        md.append("**Curl launched:**")
        md.append("")
        md.append("```bash")
        md.append(curl_out)
        md.append("```")
        md.append("")

    md.append("---")
    md.append("*Generated by curl_tester.py — WSTG-BUSL-06*")

    with open(args.md_out, "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")

    print(f"\n  {GREEN}[+] Findings JSON  → {args.json_out}{RESET}")
    print(f"  {GREEN}[+] Findings MD    → {args.md_out}{RESET}\n")

    if vulnerable_count:
        print(f"  {RED}{BOLD}[!] {vulnerable_count} group(s) returned 200 — verify in Burp Repeater.{RESET}\n")


if __name__ == "__main__":
    main()
