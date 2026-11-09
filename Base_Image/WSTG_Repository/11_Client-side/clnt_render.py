#!/usr/bin/env python3
"""
WSTG-CLNT — Client-Side Testing Setup
Script 3 of 4: clnt_render.py

Reads clnt_config.json + template HTML files + Burp proxy XML exports, and
produces one rendered HTML file per (template × endpoint) combination.

Output structure:
  clnt_pages/
    clnt_01__GET__search__q_foo__0001.html
    clnt_01__POST__login__username__0002.html
    clnt_02__GET__search__q_foo__0001.html
    ...
    index.html     ← master index linking all pages

Placeholders replaced in every template:
  {{TARGET_URL}}          Full target URL for this endpoint
  {{TARGET_DOMAIN}}       Target domain (no path)
  {{ATTACKER_IP}}         Your IP
  {{ATTACKER_PORT}}       Your port
  {{ATTACKER_PATH}}       Your base path
  {{ATTACKER_BASE_URL}}   http://<ip>:<port><path>
  {{ENDPOINT_PATH}}       Path of this endpoint
  {{ENDPOINT_LABEL}}      Safe short label for filenames / titles
  {{METHOD}}              HTTP method
  {{PARAMS}}              Comma-separated param names from the request
  {{PARAM_TABLE}}         HTML table of param name=value pairs

Usage:
  python3 clnt_render.py \\
      [--config     clnt_config.json] \\
      [--templates  templates/] \\
      [--out-dir    clnt_pages/]
"""

import argparse
import base64
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote


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
WIDTH   = 65


# ---------------------------------------------------------------------------
# XML helpers (same pattern as the rest of the toolset)
# ---------------------------------------------------------------------------

def decode_element(el) -> str:
    if el is None:
        return ""
    if el.get("base64") == "true":
        try:
            return base64.b64decode(el.text or "").decode("utf-8", errors="replace")
        except Exception:
            return ""
    return (el.text or "").strip()


def split_headers_body(raw: str) -> tuple[str, str]:
    for sep, w in (("\r\n\r\n", 4), ("\n\n", 2)):
        idx = raw.find(sep)
        if idx != -1:
            return raw[:idx], raw[idx + w:]
    return raw, ""


def parse_request_line(raw: str) -> tuple[str, str]:
    first = raw.splitlines()[0] if raw else ""
    parts = first.split()
    if len(parts) >= 2:
        return parts[0].upper(), parts[1]
    return "GET", "/"


def parse_url_params(url: str) -> list[tuple[str, str]]:
    try:
        q = urlparse(url).query
        return [(k, v[0]) for k, v in parse_qs(q, keep_blank_values=False).items() if v]
    except Exception:
        return []


def parse_body_params(body: str) -> list[tuple[str, str]]:
    if not body or "=" not in body:
        return []
    try:
        return [(k, v[0]) for k, v in parse_qs(body.strip(), keep_blank_values=False).items() if v]
    except Exception:
        return []


def load_xml_endpoints(xml_path: str) -> list[dict]:
    """Return list of {url, method, path, params} dicts."""
    try:
        tree = ET.parse(xml_path)
    except FileNotFoundError:
        print(f"  {YELLOW}[!] XML not found: {xml_path} — skipping{RESET}", file=sys.stderr)
        return []
    except ET.ParseError as e:
        print(f"  {YELLOW}[!] XML parse error in {xml_path}: {e} — skipping{RESET}", file=sys.stderr)
        return []

    root  = tree.getroot()
    items = root.findall("item") if root.tag == "items" else root.findall(".//item")

    endpoints = []
    seen: set[str] = set()

    for item in items:
        url     = decode_element(item.find("url"))
        req_raw = decode_element(item.find("request"))
        method, _ = parse_request_line(req_raw)
        _, req_body = split_headers_body(req_raw)

        parsed = urlparse(url)
        path   = parsed.path.rstrip("/") or "/"
        params = parse_url_params(url) + parse_body_params(req_body)

        key = f"{method}:{path}"
        if key in seen:
            continue
        seen.add(key)

        endpoints.append({
            "url":    url,
            "method": method,
            "path":   path,
            "params": params,
        })

    return endpoints


# ---------------------------------------------------------------------------
# Fallback synthetic endpoint (when no XML provided)
# ---------------------------------------------------------------------------

def synthetic_endpoint(config: dict) -> list[dict]:
    """One endpoint derived from config's target_path."""
    return [{
        "url":    config["target_base_url"],
        "method": "GET",
        "path":   config.get("target_path", "/"),
        "params": [],
    }]


# ---------------------------------------------------------------------------
# Filename / label helpers
# ---------------------------------------------------------------------------

def safe_label(s: str, maxlen: int = 30) -> str:
    return re.sub(r'[^a-zA-Z0-9_-]', '_', s)[:maxlen].strip('_')


def endpoint_label(ep: dict) -> str:
    path_part  = safe_label(ep["path"].lstrip("/") or "root", 20)
    param_part = safe_label(ep["params"][0][0], 10) if ep["params"] else "noparam"
    return f"{ep['method']}_{path_part}_{param_part}"


def param_table_html(params: list[tuple[str, str]]) -> str:
    if not params:
        return "<em>none detected</em>"
    rows = "".join(
        f"<tr><td style='color:#6cf'>{n}</td><td style='color:#ccc'>{v[:60]}</td></tr>"
        for n, v in params
    )
    return (
        "<table style='border-collapse:collapse;font-size:0.9em'>"
        "<tr><th style='text-align:left;color:#f90;padding-right:2rem'>Name</th>"
        "<th style='text-align:left;color:#f90'>Value</th></tr>"
        + rows + "</table>"
    )


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------

def render(template_html: str, config: dict, ep: dict) -> str:
    """Substitute all {{PLACEHOLDER}} values in a template."""
    params_str  = ", ".join(p[0] for p in ep["params"]) if ep["params"] else "none"
    ep_label    = endpoint_label(ep)
    target_url  = ep["url"] or (config["target_domain"] + ep["path"])

    subs = {
        "TARGET_URL":        target_url,
        "TARGET_DOMAIN":     config.get("target_domain", ""),
        "ATTACKER_IP":       config.get("attacker_ip", ""),
        "ATTACKER_PORT":     str(config.get("attacker_port", "")),
        "ATTACKER_PATH":     config.get("attacker_path", ""),
        "ATTACKER_BASE_URL": config.get("attacker_base_url", ""),
        "ENDPOINT_PATH":     ep["path"],
        "ENDPOINT_LABEL":    ep_label,
        "METHOD":            ep["method"],
        "PARAMS":            params_str,
        "PARAM_TABLE":       param_table_html(ep["params"]),
    }

    out = template_html
    for key, val in subs.items():
        out = out.replace("{{" + key + "}}", val)
    return out


# ---------------------------------------------------------------------------
# Index page
# ---------------------------------------------------------------------------

TEMPLATE_NAMES = {
    "clnt_01": "HTML Injection",
    "clnt_02": "Reflected XSS",
    "clnt_03": "DOM-Based XSS",
    "clnt_04": "CSS Injection Log Viewer",
    "clnt_05": "Client-Side Resource Manipulation",
    "clnt_06": "CORS Misconfiguration",
    "clnt_07": "XHR CORS Response Steal",
    "clnt_13": "Global Variable / JS Leak",
}

TEMPLATE_COLORS = {
    "clnt_01": "#f90",
    "clnt_02": "#f00",
    "clnt_03": "#f60",
    "clnt_04": "#c6f",
    "clnt_05": "#0cf",
    "clnt_06": "#f90",
    "clnt_07": "#f33",
    "clnt_13": "#0cf",
}


def write_index(pages: list[dict], config: dict, out_dir: str) -> str:
    """
    Write index.html as a two-level navigator:
      Level 1 — WSTG test (clnt_01 … clnt_13) as section headers
      Level 2 — endpoint cards inside each section (test_case_1 … test_case_N)

    Each endpoint card is a clickable link that opens the rendered page.
    """
    # Group pages by template key, preserve insertion order
    from collections import defaultdict as _dd
    by_template: dict[str, list[dict]] = _dd(list)
    for pg in pages:
        by_template[pg["template"]].append(pg)

    # Build sections HTML
    sections_html = ""
    for tkey, tpages in by_template.items():
        tname  = TEMPLATE_NAMES.get(tkey, tkey)
        tcolor = TEMPLATE_COLORS.get(tkey, "#f90")

        cards_html = ""
        for case_n, pg in enumerate(tpages, start=1):
            fname    = os.path.basename(pg["path"])
            method   = pg["method"]
            ep_path  = pg["endpoint_path"]
            params   = pg["params"] or "—"
            cards_html += f"""
        <a class="card" href="{fname}">
          <div class="case-label" style="color:{tcolor}">test_case_{case_n}</div>
          <div class="case-method">{method}</div>
          <div class="case-path">{ep_path}</div>
          <div class="case-params">params: {params}</div>
          <div class="case-file">{fname}</div>
        </a>"""

        sections_html += f"""
    <section>
      <h2 style="color:{tcolor}">{tkey.upper()} — {tname}
        <span class="count">{len(tpages)} test case{"s" if len(tpages) != 1 else ""}</span>
      </h2>
      <div class="cards">{cards_html}
      </div>
    </section>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>WSTG-CLNT Test Pages</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body   {{ font-family: monospace; background: #0d0d0d; color: #ccc;
             padding: 2rem; max-width: 1400px; }}
    h1     {{ color: #f90; margin-bottom: 0.25rem; font-size: 1.4rem; }}
    .bar   {{ color: #555; font-size: 0.8em; margin-bottom: 2rem; }}
    .bar b {{ color: #f90; }}
    section  {{ margin-bottom: 2.5rem; }}
    h2       {{ font-size: 1rem; margin-bottom: 0.75rem; border-bottom: 1px solid #222;
                padding-bottom: 0.4rem; }}
    .count   {{ color: #444; font-size: 0.75em; font-weight: normal; margin-left: 0.5rem; }}
    .cards   {{ display: flex; flex-wrap: wrap; gap: 0.75rem; }}
    .card    {{ display: block; text-decoration: none; background: #161616;
                border: 1px solid #2a2a2a; padding: 0.75rem 1rem;
                width: 240px; transition: border-color 0.15s; }}
    .card:hover {{ border-color: #555; background: #1e1e1e; }}
    .case-label  {{ font-size: 0.75em; font-weight: bold; margin-bottom: 0.25rem; }}
    .case-method {{ color: #fc0; font-size: 0.9em; }}
    .case-path   {{ color: #ccc; font-size: 0.82em; word-break: break-all;
                    margin: 0.2rem 0; }}
    .case-params {{ color: #666; font-size: 0.75em; word-break: break-all; }}
    .case-file   {{ color: #333; font-size: 0.7em; margin-top: 0.4rem;
                    word-break: break-all; }}
    .footer {{ color: #333; font-size: 0.75em; margin-top: 2rem; }}
  </style>
</head>
<body>
  <h1>WSTG-CLNT — Client-Side Test Pages</h1>
  <p class="bar">
    Generated: <b>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</b> &nbsp;·&nbsp;
    Attacker: <b>{config.get("attacker_base_url", "")}</b> &nbsp;·&nbsp;
    Target: <b>{config.get("target_base_url", "")}</b> &nbsp;·&nbsp;
    <b>{len(pages)}</b> total pages across <b>{len(by_template)}</b> test(s)
  </p>
  {sections_html}
  <p class="footer">Served by clnt_serve.py — WSTG-CLNT</p>
</body>
</html>"""

    index_path = os.path.join(out_dir, "index.html")
    with open(index_path, "w", encoding="utf-8") as f:
        f.write(html)
    return index_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-CLNT template renderer"
    )
    p.add_argument("--config",
        default="clnt_config.json",
        metavar="PATH",
        help="clnt_config.json from clnt_setup.py (default: clnt_config.json)")
    p.add_argument("--templates",
        default="templates",
        metavar="DIR",
        help="Directory containing clnt_0N.html template files (default: templates/)")
    p.add_argument("--out-dir",
        default="clnt_pages",
        metavar="DIR",
        help="Output directory for rendered pages (default: clnt_pages/)")
    args = p.parse_args()

    print(f"\n{BOLD}{'='*WIDTH}{RESET}")
    print(f"{BOLD}  WSTG-CLNT — Template Renderer{RESET}")
    print(f"{BOLD}{'='*WIDTH}{RESET}\n")

    # ── Load config ──────────────────────────────────────────────────────────
    try:
        with open(args.config, encoding="utf-8") as f:
            config = json.load(f)
    except FileNotFoundError:
        print(f"  {RED}[!] Config not found: {args.config}{RESET}", file=sys.stderr)
        print(f"  {YELLOW}    Run clnt_setup.py first.{RESET}", file=sys.stderr)
        sys.exit(1)

    selected_templates = config.get("templates", [])
    xml_files          = config.get("xml_files", [])

    print(f"  Config        : {args.config}")
    print(f"  Templates dir : {args.templates}")
    print(f"  Output dir    : {args.out_dir}")
    print(f"  Templates     : {selected_templates}")
    print(f"  XML files     : {xml_files if xml_files else 'none (synthetic endpoint used)'}\n")

    # ── Load templates ───────────────────────────────────────────────────────
    template_html: dict[str, str] = {}
    for tkey in selected_templates:
        tpath = os.path.join(args.templates, f"{tkey}.html")
        if not os.path.isfile(tpath):
            print(f"  {YELLOW}[!] Template not found: {tpath} — skipping {tkey}{RESET}")
            continue
        with open(tpath, encoding="utf-8") as f:
            template_html[tkey] = f.read()

    if not template_html:
        print(f"  {RED}[!] No templates loaded — check --templates path{RESET}", file=sys.stderr)
        sys.exit(1)

    print(f"  Loaded {len(template_html)} template(s): {list(template_html.keys())}\n")

    # ── Load endpoints ───────────────────────────────────────────────────────
    all_endpoints: list[dict] = []
    if xml_files:
        for xf in xml_files:
            eps = load_xml_endpoints(xf)
            print(f"  XML: {xf}  →  {len(eps)} endpoint(s)")
            all_endpoints.extend(eps)
    else:
        all_endpoints = synthetic_endpoint(config)
        print(f"  No XML files — using synthetic endpoint: {all_endpoints[0]['url']}")

    # Deduplicate by method+path
    seen: set[str] = set()
    unique_eps: list[dict] = []
    for ep in all_endpoints:
        k = f"{ep['method']}:{ep['path']}"
        if k not in seen:
            seen.add(k)
            unique_eps.append(ep)

    print(f"\n  {len(unique_eps)} unique endpoint(s) × {len(template_html)} template(s) "
          f"= {len(unique_eps) * len(template_html)} page(s)\n")

    os.makedirs(args.out_dir, exist_ok=True)

    # ── Render ───────────────────────────────────────────────────────────────
    pages    = []
    counter  = 0
    for tkey, html in template_html.items():
        for ep in unique_eps:
            counter += 1
            ep_label = endpoint_label(ep)
            fname    = f"{tkey}__{ep_label}__{counter:04d}.html"
            fpath    = os.path.join(args.out_dir, fname)
            rendered = render(html, config, ep)
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(rendered)

            params_str = ", ".join(p[0] for p in ep["params"]) if ep["params"] else "none"
            pages.append({
                "path":          fpath,
                "template":      tkey,
                "method":        ep["method"],
                "endpoint_path": ep["path"],
                "params":        params_str,
            })
            print(f"  {GREEN}[+]{RESET}  {fname}")

    # ── Write index ──────────────────────────────────────────────────────────
    index_path = write_index(pages, config, args.out_dir)

    print(f"\n  {'─'*50}")
    print(f"  {GREEN}[+] {len(pages)} page(s) rendered → {args.out_dir}/{RESET}")
    print(f"  {GREEN}[+] Index             → {index_path}{RESET}")
    print(f"\n  {DIM}Run clnt_serve.py --pages-dir {args.out_dir} to serve and open in browser.{RESET}\n")


if __name__ == "__main__":
    main()
