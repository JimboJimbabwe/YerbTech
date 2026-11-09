#!/usr/bin/env python3
"""
WSTG-BUSL-06 — Circumvention of Workflows
Script: busl_06_gui.py

Tkinter GUI for grouping Burp proxy history requests into workflow groups
and generating the curl commands needed to test each workflow's final step
in isolation.

Workflow:
  1. Load proxy history XML from WSTG-BUSL-06/inputs/xml/file_here.xml
  2. Browse all requests in the left panel (index, method, path, status)
  3. Select N requests with click / Shift-click / Ctrl-click
  4. Name the group and press "Push to Group"
  5. Review groups in the right panel; remove individual requests or whole groups
  6. "Save & Report" writes:
       - WSTG-BUSL-06/inputs/json/workflows_groups.json
       - WSTG-BUSL-06/outputs/test_outputs/sitrep.md    (appended)
     and prints per-group operator instructions to the terminal.

XML → curl:
  Reconstructs a curl command from the captured Burp request.
  Cookie and Authorization header values are replaced with §SESSION§
  so the operator can substitute their own session before running.

Usage:
  python3 WSTG-BUSL-06/utilities/python/busl_06_gui.py \\
      [--xml  WSTG-BUSL-06/inputs/xml/file_here.xml]
"""

import argparse
import base64
import json
import os
import shlex
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import xml.etree.ElementTree as ET
from datetime import datetime

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
DEFAULT_XML       = os.path.join("WSTG-BUSL-06", "inputs",  "xml",          "file_here.xml")
DEFAULT_JSON_OUT  = os.path.join("WSTG-BUSL-06", "inputs",  "json",         "workflows_groups.json")
DEFAULT_SITREP    = os.path.join("WSTG-BUSL-06", "outputs", "test_outputs", "sitrep.md")


# ---------------------------------------------------------------------------
# XML → request parsing
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


def parse_request_line(raw: str) -> tuple[str, str]:
    """Return (METHOD, path) from first line of raw HTTP request."""
    first = raw.splitlines()[0] if raw else ""
    parts = first.split()
    method = parts[0] if parts else "GET"
    path   = parts[1] if len(parts) > 1 else "/"
    return method, path


def parse_headers(raw: str) -> dict[str, str]:
    """Parse HTTP headers from raw request string (skip request line)."""
    headers = {}
    lines   = raw.splitlines()
    for line in lines[1:]:
        if not line.strip():
            break
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()
    return headers


def parse_body(raw: str) -> str:
    """Extract body (after blank line) from raw HTTP request."""
    sep = raw.find("\r\n\r\n")
    if sep == -1:
        sep = raw.find("\n\n")
        if sep == -1:
            return ""
        return raw[sep + 2:]
    return raw[sep + 4:]


AUTH_HEADERS = {"authorization", "cookie", "x-auth-token", "x-api-key",
                "x-access-token", "x-session-token"}

def build_curl(url: str, raw_request: str) -> str:
    """
    Build a curl command from a captured Burp request.
    Cookie and Authorization header values → §SESSION§ placeholder.
    """
    method, path = parse_request_line(raw_request)
    headers      = parse_headers(raw_request)
    body         = parse_body(raw_request)

    # Build full URL if we have it; otherwise compose from Host header + path
    if url and url.startswith("http"):
        full_url = url
    else:
        host    = headers.get("Host", "TARGET")
        scheme  = "https" if "443" in host or not host.endswith(":80") else "http"
        full_url = f"{scheme}://{host}{path}"

    parts = ["curl", "-sk"]

    if method.upper() != "GET":
        parts += ["-X", method.upper()]

    for k, v in headers.items():
        if k.lower() in ("host", "content-length"):
            continue
        if k.lower() in AUTH_HEADERS:
            v = "§SESSION§"
        parts += ["-H", f"{k}: {v}"]

    if body.strip():
        parts += ["--data-raw", body.strip()]

    parts.append(full_url)

    return " ".join(shlex.quote(p) if " " in p or any(c in p for c in '"\'\\;|&<>') else p
                   for p in parts)


# ---------------------------------------------------------------------------
# XML loader
# ---------------------------------------------------------------------------

def load_xml(xml_path: str) -> list[dict]:
    """
    Parse Burp proxy history XML.
    Returns list of request dicts ordered by Burp index (preserving file order).
    """
    try:
        tree = ET.parse(xml_path)
    except (FileNotFoundError, ET.ParseError) as e:
        messagebox.showerror("XML Error", str(e))
        return []

    root     = tree.getroot()
    item_els = root.findall("item") if root.tag == "items" else root.findall(".//item")

    requests = []
    for i, item in enumerate(item_els):
        url         = decode_element(item.find("url"))
        status_el   = item.find("status")
        method_el   = item.find("method")
        request_raw = decode_element(item.find("request"))

        status = int(status_el.text.strip()) if status_el is not None and status_el.text else 0
        method, path = parse_request_line(request_raw)
        if method_el is not None and method_el.text:
            method = method_el.text.strip()

        curl_cmd = build_curl(url, request_raw)

        requests.append({
            "index":       i,           # 0-based, display as 1-based
            "burp_index":  i + 1,
            "url":         url,
            "path":        path,
            "method":      method,
            "status":      status,
            "request_raw": request_raw,
            "curl":        curl_cmd,
        })

    return requests


# ---------------------------------------------------------------------------
# GUI Application
# ---------------------------------------------------------------------------

class WorkflowGrouper(tk.Tk):
    def __init__(self, xml_path: str, json_out: str, sitrep_path: str):
        super().__init__()

        self.xml_path    = xml_path
        self.json_out    = json_out
        self.sitrep_path = sitrep_path

        self.requests: list[dict] = []
        self.groups:   dict[str, list[int]] = {}   # group_name → [burp_indexes]

        self.title("WSTG-BUSL-06 — Workflow Grouper")
        self.geometry("1200x700")
        self.configure(bg="#1e1e1e")

        self._build_ui()
        self._load(xml_path)

    # ── UI construction ──────────────────────────────────────────────────────

    def _build_ui(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview",
            background="#252526", foreground="#d4d4d4",
            fieldbackground="#252526", rowheight=22,
            font=("Consolas", 10))
        style.configure("Treeview.Heading",
            background="#3c3c3c", foreground="#cccccc",
            font=("Consolas", 10, "bold"))
        style.map("Treeview", background=[("selected", "#264f78")])

        # ── Top bar ──────────────────────────────────────────────────────────
        top = tk.Frame(self, bg="#2d2d2d", pady=6)
        top.pack(fill=tk.X, padx=6, pady=(6, 0))

        tk.Label(top, text="XML:", bg="#2d2d2d", fg="#cccccc",
                 font=("Consolas", 10)).pack(side=tk.LEFT, padx=(4, 2))
        self.xml_var = tk.StringVar(value=self.xml_path)
        tk.Entry(top, textvariable=self.xml_var, width=55,
                 bg="#3c3c3c", fg="#d4d4d4", insertbackground="#d4d4d4",
                 font=("Consolas", 10), relief=tk.FLAT).pack(side=tk.LEFT, padx=2)
        tk.Button(top, text="Browse", command=self._browse_xml,
                  bg="#3c3c3c", fg="#cccccc", relief=tk.FLAT,
                  font=("Consolas", 10), cursor="hand2").pack(side=tk.LEFT, padx=4)
        tk.Button(top, text="Load", command=self._on_load,
                  bg="#0e639c", fg="#ffffff", relief=tk.FLAT,
                  font=("Consolas", 10, "bold"), cursor="hand2").pack(side=tk.LEFT, padx=4)

        # ── Main pane ────────────────────────────────────────────────────────
        pane = tk.PanedWindow(self, orient=tk.HORIZONTAL,
                              bg="#1e1e1e", sashwidth=5, sashrelief=tk.FLAT)
        pane.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # Left: request list
        left = tk.Frame(pane, bg="#1e1e1e")
        pane.add(left, width=540)

        tk.Label(left, text="Requests  (click to select, Shift/Ctrl for multi-select)",
                 bg="#1e1e1e", fg="#858585",
                 font=("Consolas", 9)).pack(anchor=tk.W, padx=4)

        cols = ("#", "Method", "Status", "Path")
        self.req_tree = ttk.Treeview(left, columns=cols, show="headings",
                                     selectmode="extended")
        for c, w in zip(cols, (50, 65, 55, 340)):
            self.req_tree.heading(c, text=c)
            self.req_tree.column(c, width=w, anchor=tk.W)
        self.req_tree.pack(fill=tk.BOTH, expand=True, padx=4)

        sb1 = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self.req_tree.yview)
        self.req_tree.configure(yscrollcommand=sb1.set)
        sb1.pack(side=tk.RIGHT, fill=tk.Y)

        self.req_tree.bind("<<TreeviewSelect>>", self._on_select)

        # Left bottom: request preview + group controls
        lbot = tk.Frame(left, bg="#1e1e1e")
        lbot.pack(fill=tk.X, padx=4, pady=4)

        tk.Label(lbot, text="Group name:", bg="#1e1e1e", fg="#cccccc",
                 font=("Consolas", 10)).pack(side=tk.LEFT)
        self.group_name_var = tk.StringVar(value="Group_1")
        self.group_entry = tk.Entry(lbot, textvariable=self.group_name_var, width=18,
                                    bg="#3c3c3c", fg="#d4d4d4",
                                    insertbackground="#d4d4d4",
                                    font=("Consolas", 10), relief=tk.FLAT)
        self.group_entry.pack(side=tk.LEFT, padx=6)
        tk.Button(lbot, text="⊕ Push to Group", command=self._push_to_group,
                  bg="#16825d", fg="#ffffff", relief=tk.FLAT,
                  font=("Consolas", 10, "bold"), cursor="hand2").pack(side=tk.LEFT)

        # Right: groups panel
        right = tk.Frame(pane, bg="#1e1e1e")
        pane.add(right, width=620)

        tk.Label(right, text="Workflow Groups",
                 bg="#1e1e1e", fg="#858585",
                 font=("Consolas", 9)).pack(anchor=tk.W, padx=4)

        gcols = ("Group", "#", "Method", "Status", "Path")
        self.grp_tree = ttk.Treeview(right, columns=gcols, show="headings",
                                     selectmode="browse")
        for c, w in zip(gcols, (90, 50, 65, 55, 320)):
            self.grp_tree.heading(c, text=c)
            self.grp_tree.column(c, width=w, anchor=tk.W)
        self.grp_tree.pack(fill=tk.BOTH, expand=True, padx=4)

        sb2 = ttk.Scrollbar(right, orient=tk.VERTICAL, command=self.grp_tree.yview)
        self.grp_tree.configure(yscrollcommand=sb2.set)
        sb2.pack(side=tk.RIGHT, fill=tk.Y)

        # Right bottom: group action buttons
        rbot = tk.Frame(right, bg="#1e1e1e")
        rbot.pack(fill=tk.X, padx=4, pady=4)

        tk.Button(rbot, text="✕ Remove Selected", command=self._remove_selected,
                  bg="#6b2727", fg="#ffffff", relief=tk.FLAT,
                  font=("Consolas", 10), cursor="hand2").pack(side=tk.LEFT, padx=(0, 6))
        tk.Button(rbot, text="✕ Delete Group", command=self._delete_group,
                  bg="#5a2020", fg="#ffffff", relief=tk.FLAT,
                  font=("Consolas", 10), cursor="hand2").pack(side=tk.LEFT)
        tk.Button(rbot, text="💾  Save & Report", command=self._save_and_report,
                  bg="#0e639c", fg="#ffffff", relief=tk.FLAT,
                  font=("Consolas", 10, "bold"), cursor="hand2").pack(side=tk.RIGHT)

        # Bottom: request detail pane
        bot = tk.Frame(self, bg="#1e1e1e")
        bot.pack(fill=tk.X, padx=6, pady=(0, 6))

        tk.Label(bot, text="Request preview",
                 bg="#1e1e1e", fg="#858585",
                 font=("Consolas", 9)).pack(anchor=tk.W)
        self.preview = tk.Text(bot, height=8, bg="#1e1e1e", fg="#9cdcfe",
                               insertbackground="#d4d4d4",
                               font=("Consolas", 10), relief=tk.FLAT,
                               state=tk.DISABLED, wrap=tk.NONE)
        self.preview.pack(fill=tk.X)

    # ── Data loading ─────────────────────────────────────────────────────────

    def _browse_xml(self):
        path = filedialog.askopenfilename(
            title="Select Burp proxy XML",
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")]
        )
        if path:
            self.xml_var.set(path)

    def _on_load(self):
        self._load(self.xml_var.get())

    def _load(self, xml_path: str):
        if not xml_path or not os.path.exists(xml_path):
            return
        self.xml_path = xml_path
        self.requests = load_xml(xml_path)
        self.groups   = {}
        self._refresh_req_tree()
        self._refresh_grp_tree()
        self._auto_name_next_group()

    def _refresh_req_tree(self):
        self.req_tree.delete(*self.req_tree.get_children())
        for r in self.requests:
            tag = "even" if r["burp_index"] % 2 == 0 else "odd"
            self.req_tree.insert("", tk.END, iid=str(r["index"]),
                                 values=(r["burp_index"], r["method"],
                                         r["status"], r["path"]),
                                 tags=(tag,))
        self.req_tree.tag_configure("odd",  background="#252526")
        self.req_tree.tag_configure("even", background="#2d2d2d")

    def _refresh_grp_tree(self):
        self.grp_tree.delete(*self.grp_tree.get_children())
        for gname, indexes in self.groups.items():
            # Parent row
            self.grp_tree.insert("", tk.END, iid=f"g:{gname}",
                                 values=(gname, "", "", "", ""),
                                 tags=("group",))
            self.grp_tree.tag_configure("group", background="#1a3a4a")
            # Child rows — sorted by burp_index
            sorted_idxs = sorted(indexes)
            for bi in sorted_idxs:
                r = self.requests[bi - 1]
                marker = "◀ FINAL" if bi == sorted_idxs[-1] else ""
                self.grp_tree.insert(f"g:{gname}", tk.END,
                                     iid=f"gi:{gname}:{bi}",
                                     values=(marker, r["burp_index"],
                                             r["method"], r["status"],
                                             r["path"]))
            self.grp_tree.item(f"g:{gname}", open=True)

    def _auto_name_next_group(self):
        n = len(self.groups) + 1
        self.group_name_var.set(f"Group_{n}")

    # ── Request preview ───────────────────────────────────────────────────────

    def _on_select(self, _event=None):
        sel = self.req_tree.selection()
        if not sel:
            return
        r = self.requests[int(sel[-1])]
        lines = [
            f"# {r['burp_index']}  {r['method']}  {r['path']}  [{r['status']}]",
            f"URL: {r['url']}",
            "",
            "--- curl ---",
            r["curl"],
            "",
            "--- raw (first 20 lines) ---",
        ] + r["request_raw"].splitlines()[:20]
        self.preview.configure(state=tk.NORMAL)
        self.preview.delete("1.0", tk.END)
        self.preview.insert(tk.END, "\n".join(lines))
        self.preview.configure(state=tk.DISABLED)

    # ── Group management ──────────────────────────────────────────────────────

    def _push_to_group(self):
        sel = self.req_tree.selection()
        if not sel:
            messagebox.showwarning("No selection", "Select at least one request first.")
            return
        gname = self.group_name_var.get().strip()
        if not gname:
            messagebox.showwarning("No name", "Enter a group name.")
            return

        burp_idxs = [self.requests[int(s)]["burp_index"] for s in sel]

        if gname not in self.groups:
            self.groups[gname] = []
        existing = set(self.groups[gname])
        for bi in burp_idxs:
            if bi not in existing:
                self.groups[gname].append(bi)
                existing.add(bi)
        self.groups[gname].sort()

        self._refresh_grp_tree()
        self._auto_name_next_group()

    def _remove_selected(self):
        sel = self.grp_tree.selection()
        if not sel:
            return
        iid = sel[0]
        if iid.startswith("gi:"):
            _, gname, bi_str = iid.split(":", 2)
            bi = int(bi_str)
            if gname in self.groups:
                self.groups[gname] = [x for x in self.groups[gname] if x != bi]
                if not self.groups[gname]:
                    del self.groups[gname]
        self._refresh_grp_tree()

    def _delete_group(self):
        sel = self.grp_tree.selection()
        if not sel:
            return
        iid = sel[0]
        gname = None
        if iid.startswith("g:"):
            gname = iid[2:]
        elif iid.startswith("gi:"):
            gname = iid.split(":")[1]
        if gname and gname in self.groups:
            del self.groups[gname]
        self._refresh_grp_tree()

    # ── Save & Report ─────────────────────────────────────────────────────────

    def _save_and_report(self):
        if not self.groups:
            messagebox.showwarning("No groups", "No workflow groups defined yet.")
            return

        json_data  = {"Workflows": {}}
        sitrep_lines = []
        print_lines  = []

        for gname, indexes in self.groups.items():
            sorted_idxs = sorted(indexes)
            final_bi    = sorted_idxs[-1]
            final_req   = self.requests[final_bi - 1]

            paths = [self.requests[bi - 1]["path"] for bi in sorted_idxs]
            curl  = final_req["curl"]

            json_data["Workflows"][gname] = {
                "Indexes":        sorted_idxs,
                "Paths":          paths,
                "Target_endpoint": final_req["path"],
                "Target_index":    final_bi,
                "Curl_to_launch":  curl,
            }

            # Terminal output
            print_lines.append(f"\n{'='*65}")
            print_lines.append(f"  {gname}  ({len(sorted_idxs)} requests)")
            print_lines.append(f"{'='*65}")
            print_lines.append(f"  Flow  : {' → '.join(paths)}")
            print_lines.append(f"  Final : [{final_bi}] {final_req['method']} {final_req['path']}")
            print_lines.append(f"\n  This endpoint represents the successful completion of the")
            print_lines.append(f"  workflow. To test whether it can be reached without")
            print_lines.append(f"  completing the prior steps:")
            print_lines.append(f"\n    1. Log out of the application.")
            print_lines.append(f"    2. Replace §SESSION§ in the curl command with your")
            print_lines.append(f"       session token (or omit auth to test unauthenticated).")
            print_lines.append(f"    3. Run:")
            print_lines.append(f"\n       {curl}\n")

            # Sitrep lines
            sitrep_lines.append(f"### {gname}")
            sitrep_lines.append(f"")
            sitrep_lines.append(f"**Requests in flow ({len(sorted_idxs)}):** "
                                 + ", ".join(f"`[{bi}]`" for bi in sorted_idxs))
            sitrep_lines.append(f"")
            sitrep_lines.append(f"**Flow path:** `{'` → `'.join(paths)}`")
            sitrep_lines.append(f"")
            sitrep_lines.append(f"**Final request:** `[{final_bi}]` "
                                 f"`{final_req['method']} {final_req['path']}`  ")
            sitrep_lines.append(f"")
            sitrep_lines.append(f"The final request in this group represents a successful "
                                 f"transaction completion. Test whether this step can be "
                                 f"triggered without going through the preceding steps:")
            sitrep_lines.append(f"")
            sitrep_lines.append(f"1. Log out of the application.")
            sitrep_lines.append(f"2. Replace `§SESSION§` with a valid (or no) session token.")
            sitrep_lines.append(f"3. Run the curl command below:")
            sitrep_lines.append(f"")
            sitrep_lines.append(f"```bash")
            sitrep_lines.append(curl)
            sitrep_lines.append(f"```")
            sitrep_lines.append(f"")

        # Write JSON
        os.makedirs(os.path.dirname(self.json_out), exist_ok=True)
        with open(self.json_out, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2)

        # Write sitrep
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        os.makedirs(os.path.dirname(self.sitrep_path), exist_ok=True)
        mode = "a" if os.path.exists(self.sitrep_path) else "w"
        with open(self.sitrep_path, mode, encoding="utf-8") as f:
            f.write(f"\n---\n\n## WSTG-BUSL-06 — Workflow Groups\n\n")
            f.write(f"**Generated:** {now_str}  \n")
            f.write(f"**Groups:** {len(self.groups)}  \n\n")
            f.write("\n".join(sitrep_lines) + "\n")
            f.write("\n---\n*Generated by busl_06_gui.py — WSTG-BUSL-06*\n")

        # Terminal print
        for line in print_lines:
            print(line)
        print(f"\n  JSON  → {self.json_out}")
        print(f"  Sitrep → {self.sitrep_path}\n")

        messagebox.showinfo(
            "Saved",
            f"Groups saved.\n\nJSON  → {self.json_out}\nSitrep → {self.sitrep_path}"
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="WSTG-BUSL-06 workflow grouper GUI"
    )
    p.add_argument("--xml",
        default=DEFAULT_XML,
        metavar="PATH",
        help=f"Burp proxy history XML (default: {DEFAULT_XML})")
    p.add_argument("--json-out",
        default=DEFAULT_JSON_OUT,
        metavar="PATH")
    p.add_argument("--sitrep",
        default=DEFAULT_SITREP,
        metavar="PATH")
    args = p.parse_args()

    app = WorkflowGrouper(
        xml_path    = args.xml,
        json_out    = args.json_out,
        sitrep_path = args.sitrep,
    )
    app.mainloop()


if __name__ == "__main__":
    main()
