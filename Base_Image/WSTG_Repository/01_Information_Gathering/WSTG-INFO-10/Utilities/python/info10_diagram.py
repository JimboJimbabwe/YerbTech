#!/usr/bin/env python3
"""
WSTG-INFO-10 — Application Architecture Diagram Generator
Script 2 of 2: info10_diagram.py

Reads arch_data.json produced by info10_collect.py and generates a
self-contained SVG + HTML architecture diagram showing all 10 objects:

  1  Server          — hostname, IP, OS
  2  Services        — open ports / service versions
  3  Cloud Providers — detected cloud/CDN providers
  4  Subdomains      — subdomain map with verdicts
  5  Auth Endpoints  — login/oauth/token paths + provider
  6  Authed Functions— authenticated user capabilities
  7  Main App        — core application endpoints
  8  Databases       — detected database services
  9  Third Parties   — (stub) external services
  10 Config/Mgmt     — (stub) configuration surface

Output: WSTG-INFO-10/outputs/diagram/arch_diagram.html
        WSTG-INFO-10/outputs/diagram/arch_diagram.svg

Usage:
  python3 info10_diagram.py [--data <arch_data.json>]
                             [--out  <output_dir>]
                             [--base <repo_root>]
                             [--title <app name>]
"""

import argparse
import json
import os
import sys
from datetime import datetime

# ---------------------------------------------------------------------------
# ANSI
# ---------------------------------------------------------------------------
BOLD   = "\033[1m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
WIDTH  = 65

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_DATA = "WSTG-INFO-10/inputs/data/arch_data.json"
DEFAULT_OUT  = "WSTG-INFO-10/outputs/diagram"

# ---------------------------------------------------------------------------
# Colour palette (dark terminal aesthetic)
# ---------------------------------------------------------------------------
BG          = "#0d0d0d"
BG_CARD     = "#111"
BG_CARD2    = "#151515"
BORDER      = "#2a2a2a"
TEXT_MAIN   = "#cccccc"
TEXT_DIM    = "#555555"
TEXT_BRIGHT = "#eeeeee"
ACCENT_RED  = "#ff4444"
ACCENT_ORG  = "#ff9900"
ACCENT_YEL  = "#ffcc00"
ACCENT_GRN  = "#00ff88"
ACCENT_CYN  = "#00ccff"
ACCENT_BLU  = "#4488ff"
ACCENT_PRP  = "#cc66ff"
ACCENT_PNK  = "#ff6699"

# Per-object accent colours
OBJ_COLORS = {
    "server":          ACCENT_CYN,
    "services":        ACCENT_BLU,
    "cloud":           ACCENT_ORG,
    "subdomains":      ACCENT_YEL,
    "auth":            ACCENT_RED,
    "authed":          ACCENT_PRP,
    "main_app":        ACCENT_GRN,
    "databases":       ACCENT_PNK,
    "third_parties":   TEXT_DIM,
    "config_mgmt":     TEXT_DIM,
}

OBJ_LABELS = {
    "server":        "① SERVER",
    "services":      "② SERVICES",
    "cloud":         "③ CLOUD PROVIDERS",
    "subdomains":    "④ SUBDOMAINS",
    "auth":          "⑤ AUTH ENDPOINTS",
    "authed":        "⑥ AUTHED FUNCTIONS",
    "main_app":      "⑦ MAIN APP",
    "databases":     "⑧ DATABASES",
    "third_parties": "⑨ THIRD PARTIES",
    "config_mgmt":   "⑩ CONFIG / MGMT",
}

# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------

def load_json(path: str) -> dict:
    if not os.path.isfile(path):
        print(f"  {YELLOW}[!] arch_data.json not found: {path}{RESET}")
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def txt_lines(path: str, limit: int = 200) -> list:
    """Read a .txt wordlist, skip comment lines, cap at limit."""
    if not os.path.isfile(path):
        return []
    lines = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                lines.append(line)
                if len(lines) >= limit:
                    break
    return lines


def esc(s: str) -> str:
    """XML/SVG-safe escaping."""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


# ---------------------------------------------------------------------------
# Extract display data from arch_data.json
# ---------------------------------------------------------------------------

def build_display(data: dict, data_dir: str) -> dict:
    """
    Pull the most useful lines from each section for display in the diagram.
    Returns a dict keyed by object name with list-of-strings content.
    """
    d = {}

    # 1 — Server
    server_lines = txt_lines(os.path.join(data_dir, "server.txt"), 12)
    d["server"] = server_lines or ["(no data — run info10_collect.py first)"]

    # 2 — Services
    svc_lines = txt_lines(os.path.join(data_dir, "services.txt"), 20)
    d["services"] = svc_lines or ["(no open ports detected)"]

    # 3 — Cloud
    cloud_lines = txt_lines(os.path.join(data_dir, "cloud_providers.txt"), 10)
    d["cloud"] = cloud_lines or ["(no cloud indicators detected)"]

    # 4 — Subdomains
    sub_lines = txt_lines(os.path.join(data_dir, "subdomains.txt"), 20)
    d["subdomains"] = sub_lines or ["(no subdomains detected)"]

    # 5 — Auth endpoints
    auth_lines = txt_lines(os.path.join(data_dir, "auth_endpoints.txt"), 20)
    d["auth"] = auth_lines or ["(no auth endpoints detected)"]

    # 6 — Authed functions
    authed_lines = txt_lines(os.path.join(data_dir, "authed_endpoints.txt"), 20)
    d["authed"] = authed_lines or ["(no authed endpoints detected)"]

    # 7 — Main app
    main_lines = txt_lines(os.path.join(data_dir, "main_app_endpoints.txt"), 20)
    d["main_app"] = main_lines or ["(no main app endpoints detected)"]

    # 8 — Databases
    db_lines = txt_lines(os.path.join(data_dir, "databases.txt"), 10)
    d["databases"] = db_lines or ["(no databases detected)"]

    # 9 — Third parties (stub)
    tp_lines = txt_lines(os.path.join(data_dir, "third_parties.txt"), 10)
    d["third_parties"] = tp_lines or ["(stub — not yet collected)"]

    # 10 — Config/mgmt (stub)
    cfg_lines = txt_lines(os.path.join(data_dir, "config_mgmt.txt"), 10)
    d["config_mgmt"] = cfg_lines or ["(stub — not yet collected)"]

    return d


# ---------------------------------------------------------------------------
# SVG layout constants
# ---------------------------------------------------------------------------

CARD_W    = 340
CARD_PAD  = 14
COLS      = 3
COL_GAP   = 20
ROW_GAP   = 20
SVG_PAD   = 30
HEADER_H  = 80
LINE_H    = 16
TITLE_H   = 32
BADGE_H   = 22

ORDER = [
    "server", "services", "databases",
    "cloud",  "subdomains", "third_parties",
    "auth",   "authed",     "main_app",
    # config_mgmt gets a full-width footer row
]
FOOTER_OBJ = "config_mgmt"


def card_height(lines: list) -> int:
    """Compute card height from number of content lines."""
    content_lines = min(len(lines), 20)
    return TITLE_H + BADGE_H + CARD_PAD + content_lines * LINE_H + CARD_PAD


# ---------------------------------------------------------------------------
# SVG builder
# ---------------------------------------------------------------------------

def build_svg(display: dict, title: str, generated: str) -> str:
    """Produce the full SVG as a string."""

    # Pre-compute card heights per object
    heights = {k: card_height(display[k]) for k in display}

    # Grid: 3 columns, rows of 3 objects each
    rows = []
    for i in range(0, len(ORDER), COLS):
        row_objs = ORDER[i:i + COLS]
        row_h    = max(heights[o] for o in row_objs)
        rows.append((row_objs, row_h))

    footer_h = card_height(display[FOOTER_OBJ])

    total_w = SVG_PAD * 2 + COLS * CARD_W + (COLS - 1) * COL_GAP
    total_h = (SVG_PAD + HEADER_H + ROW_GAP
               + sum(rh + ROW_GAP for _, rh in rows)
               + footer_h + SVG_PAD)

    lines = []
    W = lambda s: lines.append(s)

    W(f'<svg xmlns="http://www.w3.org/2000/svg" '
      f'width="{total_w}" height="{total_h}" '
      f'viewBox="0 0 {total_w} {total_h}">')

    # Defs
    W('<defs>')
    W(f'  <style>')
    W(f'    text {{ font-family: "Courier New", Courier, monospace; fill: {TEXT_MAIN}; }}')
    W(f'    .title-main {{ font-size: 22px; font-weight: bold; fill: {TEXT_BRIGHT}; }}')
    W(f'    .title-sub  {{ font-size: 11px; fill: {TEXT_DIM}; }}')
    W(f'    .card-title {{ font-size: 11px; font-weight: bold; letter-spacing: 1px; }}')
    W(f'    .badge      {{ font-size: 10px; }}')
    W(f'    .item       {{ font-size: 10px; fill: {TEXT_MAIN}; }}')
    W(f'    .item-dim   {{ font-size: 10px; fill: {TEXT_DIM}; }}')
    W(f'    .more       {{ font-size: 9px;  fill: {TEXT_DIM}; font-style: italic; }}')
    W(f'  </style>')
    # Arrow marker
    W(f'  <marker id="arr" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">')
    W(f'    <path d="M0,0 L0,6 L8,3 z" fill="{TEXT_DIM}"/>')
    W(f'  </marker>')
    W('</defs>')

    # Background
    W(f'<rect width="{total_w}" height="{total_h}" fill="{BG}"/>')

    # ── Header ───────────────────────────────────────────────────────────────
    hx = SVG_PAD
    hy = SVG_PAD
    W(f'<text x="{hx}" y="{hy + 26}" class="title-main">'
      f'WSTG-INFO-10 — Application Architecture</text>')
    W(f'<text x="{hx}" y="{hy + 44}" class="title-sub">'
      f'{esc(title)}</text>')
    W(f'<text x="{hx}" y="{hy + 60}" class="title-sub">'
      f'Generated: {esc(generated)}</text>')
    # Horizontal rule
    W(f'<line x1="{SVG_PAD}" y1="{SVG_PAD + HEADER_H - 8}" '
      f'x2="{total_w - SVG_PAD}" y2="{SVG_PAD + HEADER_H - 8}" '
      f'stroke="{BORDER}" stroke-width="1"/>')

    # ── Grid cards ───────────────────────────────────────────────────────────
    cy = SVG_PAD + HEADER_H + ROW_GAP

    for row_objs, row_h in rows:
        for col_i, obj_key in enumerate(row_objs):
            cx  = SVG_PAD + col_i * (CARD_W + COL_GAP)
            col = OBJ_COLORS.get(obj_key, TEXT_DIM)
            lbl = OBJ_LABELS.get(obj_key, obj_key.upper())
            items = display[obj_key]

            _draw_card(lines, cx, cy, CARD_W, row_h, col, lbl, items)

        cy += row_h + ROW_GAP

    # ── Footer (config_mgmt full-width) ──────────────────────────────────────
    footer_w = total_w - SVG_PAD * 2
    col  = OBJ_COLORS["config_mgmt"]
    lbl  = OBJ_LABELS["config_mgmt"]
    items = display["config_mgmt"]
    _draw_card(lines, SVG_PAD, cy, footer_w, footer_h, col, lbl, items)

    # ── Connection arrows (logical flow) ─────────────────────────────────────
    # Draw subtle arrows between related cards:
    # Internet → Server, Server → Services, Services → Auth, Auth → Authed, Authed → MainApp
    # We'll add these as optional visual connectors using the grid positions
    # (skipped for stub nodes; kept subtle)

    W('</svg>')
    return "\n".join(lines)


def _draw_card(lines, x, y, w, h, accent, label, items):
    """Append SVG elements for one architecture card."""
    W = lambda s: lines.append(s)
    max_items = 18

    # Card background
    W(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" '
      f'fill="{BG_CARD}" rx="4" '
      f'stroke="{accent}" stroke-width="1" stroke-opacity="0.4"/>')

    # Top accent bar
    W(f'<rect x="{x}" y="{y}" width="{w}" height="3" '
      f'fill="{accent}" rx="2"/>')

    # Title
    tx = x + CARD_PAD
    ty = y + TITLE_H - 10
    W(f'<text x="{tx}" y="{ty}" class="card-title" fill="{accent}">'
      f'{esc(label)}</text>')

    # Separator
    W(f'<line x1="{x + CARD_PAD}" y1="{y + TITLE_H + 2}" '
      f'x2="{x + w - CARD_PAD}" y2="{y + TITLE_H + 2}" '
      f'stroke="{BORDER}" stroke-width="1"/>')

    # Count badge
    count = len(items)
    badge_txt = f"{count} item{'s' if count != 1 else ''}"
    W(f'<text x="{x + w - CARD_PAD}" y="{ty}" '
      f'class="badge" fill="{accent}" '
      f'text-anchor="end" opacity="0.6">{esc(badge_txt)}</text>')

    # Items
    iy = y + TITLE_H + BADGE_H
    for i, item in enumerate(items[:max_items]):
        is_dim  = item.startswith("(") or item.startswith("#")
        cls     = "item-dim" if is_dim else "item"
        # Truncate long lines
        display_item = item if len(item) <= 52 else item[:49] + "…"
        W(f'<text x="{tx}" y="{iy}" class="{cls}">'
          f'{esc(display_item)}</text>')
        iy += LINE_H

    if count > max_items:
        W(f'<text x="{tx}" y="{iy}" class="more">'
          f'… and {count - max_items} more</text>')


# ---------------------------------------------------------------------------
# HTML wrapper
# ---------------------------------------------------------------------------

def build_html(svg_content: str, title: str, generated: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WSTG-INFO-10 — {esc(title)}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: {BG};
      color: {TEXT_MAIN};
      font-family: "Courier New", Courier, monospace;
      min-height: 100vh;
      padding: 0;
    }}
    header {{
      background: #111;
      border-bottom: 1px solid {BORDER};
      padding: 0.75rem 1.5rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}
    header .logo  {{ color: {ACCENT_CYN}; font-weight: bold; font-size: 0.9em; }}
    header .meta  {{ color: {TEXT_DIM};  font-size: 0.75em; }}
    .toolbar {{
      background: #111;
      border-bottom: 1px solid {BORDER};
      padding: 0.5rem 1.5rem;
      display: flex;
      gap: 1rem;
      align-items: center;
    }}
    .toolbar button {{
      background: #1a1a1a;
      border: 1px solid {BORDER};
      color: {TEXT_MAIN};
      padding: 0.3rem 0.8rem;
      font-family: inherit;
      font-size: 0.8em;
      cursor: pointer;
      border-radius: 3px;
    }}
    .toolbar button:hover {{ border-color: {ACCENT_CYN}; color: {ACCENT_CYN}; }}
    .toolbar .zoom-label  {{ color: {TEXT_DIM}; font-size: 0.8em; }}
    #canvas {{
      overflow: auto;
      padding: 1.5rem;
      cursor: grab;
    }}
    #canvas:active {{ cursor: grabbing; }}
    #svg-wrap {{
      display: inline-block;
      transform-origin: top left;
      transition: transform 0.15s ease;
    }}
    footer {{
      border-top: 1px solid {BORDER};
      padding: 0.5rem 1.5rem;
      font-size: 0.72em;
      color: {TEXT_DIM};
    }}
  </style>
</head>
<body>
  <header>
    <span class="logo">WSTG-INFO-10 — Application Architecture Diagram</span>
    <span class="meta">Generated: {esc(generated)} · {esc(title)}</span>
  </header>
  <div class="toolbar">
    <button onclick="zoom(0.1)">＋ Zoom In</button>
    <button onclick="zoom(-0.1)">－ Zoom Out</button>
    <button onclick="resetZoom()">⊙ Reset</button>
    <span class="zoom-label" id="zoom-pct">100%</span>
    <button onclick="exportSvg()" style="margin-left:auto">⬇ Export SVG</button>
  </div>
  <div id="canvas">
    <div id="svg-wrap">
{svg_content}
    </div>
  </div>
  <footer>
    WSTG-INFO-10 · info10_diagram.py · Trusted Ascent
  </footer>
  <script>
    let scale = 1.0;
    const wrap = document.getElementById("svg-wrap");
    const pct  = document.getElementById("zoom-pct");

    function zoom(delta) {{
      scale = Math.max(0.2, Math.min(3.0, scale + delta));
      wrap.style.transform = "scale(" + scale + ")";
      pct.textContent = Math.round(scale * 100) + "%";
    }}
    function resetZoom() {{
      scale = 1.0;
      wrap.style.transform = "scale(1)";
      pct.textContent = "100%";
    }}

    // Drag-to-pan
    const canvas = document.getElementById("canvas");
    let dragging = false, sx = 0, sy = 0, sl = 0, st = 0;
    canvas.addEventListener("mousedown", e => {{
      dragging = true; sx = e.clientX; sy = e.clientY;
      sl = canvas.scrollLeft; st = canvas.scrollTop;
    }});
    document.addEventListener("mouseup",   () => dragging = false);
    document.addEventListener("mousemove", e => {{
      if (!dragging) return;
      canvas.scrollLeft = sl - (e.clientX - sx);
      canvas.scrollTop  = st - (e.clientY - sy);
    }});

    // Mouse-wheel zoom
    canvas.addEventListener("wheel", e => {{
      if (e.ctrlKey || e.metaKey) {{
        e.preventDefault();
        zoom(e.deltaY < 0 ? 0.1 : -0.1);
      }}
    }}, {{ passive: false }});

    // Export SVG
    function exportSvg() {{
      const svg  = wrap.querySelector("svg");
      const blob = new Blob([svg.outerHTML], {{type: "image/svg+xml"}});
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href     = url;
      a.download = "arch_diagram.svg";
      a.click();
      URL.revokeObjectURL(url);
    }}
  </script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="WSTG-INFO-10: Generate architecture diagram from arch_data.json"
    )
    p.add_argument("--base",  default=".",
                   help="Repository root (default: .)")
    p.add_argument("--data",  default=None,
                   help=f"arch_data.json path (default: <base>/{DEFAULT_DATA})")
    p.add_argument("--out",   default=None,
                   help=f"Output directory (default: <base>/{DEFAULT_OUT})")
    p.add_argument("--title", default="Target Application",
                   help="Application name shown in diagram header")
    return p.parse_args()


def main():
    args      = parse_args()
    base      = os.path.abspath(args.base)
    data_path = args.data or os.path.join(base, DEFAULT_DATA)
    out_dir   = args.out  or os.path.join(base, DEFAULT_OUT)
    title     = args.title
    generated = datetime.now().strftime("%Y-%m-%d %H:%M")

    print(f"\n{BOLD}{'='*WIDTH}{RESET}")
    print(f"{BOLD}  WSTG-INFO-10 — Architecture Diagram Generator{RESET}")
    print(f"{BOLD}{'='*WIDTH}{RESET}\n")

    # Data dir is same folder as arch_data.json
    data_dir = os.path.dirname(data_path)

    data = load_json(data_path)
    if not data:
        print(f"  {YELLOW}[!] No arch_data.json found — diagram will show empty cards.{RESET}")
        print(f"      Run info10_collect.py first to populate the data.\n")
        # Continue anyway — diagram with empty cards is still useful as a template

    print(f"  {CYAN}Building display data from wordlists in:{RESET}")
    print(f"    {data_dir}\n")

    display = build_display(data, data_dir)

    # Print summary
    for key in list(ORDER) + [FOOTER_OBJ]:
        count = len(display[key])
        label = OBJ_LABELS[key]
        color = GREEN if count > 1 else YELLOW
        print(f"  {color}[{'~' if count <= 1 else '+'}]{RESET}  {label:25s} {count} line(s)")

    print()

    # Build SVG
    print(f"  {CYAN}Generating SVG…{RESET}")
    svg_content = build_svg(display, title, generated)

    # Build HTML
    html_content = build_html(svg_content, title, generated)

    # Write outputs
    os.makedirs(out_dir, exist_ok=True)

    svg_path  = os.path.join(out_dir, "arch_diagram.svg")
    html_path = os.path.join(out_dir, "arch_diagram.html")

    with open(svg_path,  "w", encoding="utf-8") as f:
        f.write(svg_content)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"\n  {GREEN}[+]{RESET} SVG  → {svg_path}")
    print(f"  {GREEN}[+]{RESET} HTML → {html_path}")
    print(f"\n  Open {os.path.basename(html_path)} in a browser.")
    print(f"  Ctrl+scroll to zoom · drag to pan · '⬇ Export SVG' to save\n")


if __name__ == "__main__":
    main()
