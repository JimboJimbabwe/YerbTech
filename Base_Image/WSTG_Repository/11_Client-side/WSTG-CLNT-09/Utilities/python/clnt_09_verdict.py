#!/usr/bin/env python3
"""
WSTG-CLNT-09 — Clickjacking Verdict Recorder (GUI)
====================================================
Reads the scan_results.json produced by clnt_09_scan.py, lists all
unprotected endpoints, lets the operator open each test HTML in Firefox,
record a verdict (Vulnerable / Not Vulnerable) with reasoning, and push
the entry to JSON.

Verdicts are saved to both:
    Inputs/JSON/verdict.json
    Outputs/test_outputs/verdict.json

Usage
-----
    python clnt_09_verdict.py
    python clnt_09_verdict.py --scan-json /path/to/scan_results.json
    python clnt_09_verdict.py --firefox "C:\\Program Files\\Mozilla Firefox\\firefox.exe"
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk

# ── Paths ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR         = Path(__file__).resolve().parent
TOOL_ROOT          = SCRIPT_DIR.parent.parent
DEFAULT_SCAN_JSON  = TOOL_ROOT / "Outputs" / "test_outputs" / "scan_results.json"
VERDICT_JSON_OUT   = TOOL_ROOT / "Outputs" / "test_outputs" / "verdict.json"
VERDICT_JSON_IN    = TOOL_ROOT / "Inputs"  / "JSON"         / "verdict.json"


# ── Firefox detection ──────────────────────────────────────────────────────────

def _find_firefox() -> str | None:
    if sys.platform == "win32":
        for candidate in (
            r"C:\Program Files\Mozilla Firefox\firefox.exe",
            r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
        ):
            if Path(candidate).exists():
                return candidate
        return None
    elif sys.platform == "darwin":
        mac = "/Applications/Firefox.app/Contents/MacOS/firefox"
        return mac if Path(mac).exists() else None
    else:
        return "firefox"   # assume in PATH on Linux


# ── Verdict JSON helpers ───────────────────────────────────────────────────────

def _load_verdicts(path: Path) -> dict:
    """Load existing verdict JSON or return a fresh structure."""
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {
        "scan_metadata": {
            "wstg_id": "WSTG-CLNT-09",
            "title":   "Testing for Clickjacking — Verdicts",
        },
        "verdicts": [],
    }


def _save_verdicts(data: dict, paths: list[Path]) -> None:
    text = json.dumps(data, indent=2)
    for p in paths:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


# ── GUI ────────────────────────────────────────────────────────────────────────

class VerdictGUI:

    # Listbox item colours
    _COL_DEFAULT  = ("#ffffff", "#1c1c1c")   # (bg, fg) — unreviewed
    _COL_VULN     = ("#2d1515", "#e06c75")   # red — vulnerable
    _COL_SAFE     = "#98c379"                # green — not vulnerable

    def __init__(self, root: tk.Tk, endpoints: list[dict],
                 firefox_path: str | None, json_paths: list[Path]) -> None:
        self.root         = root
        self.endpoints    = endpoints      # unprotected endpoints only
        self.firefox      = firefox_path
        self.json_paths   = json_paths

        # url → verdict dict (in-memory working set)
        self.verdicts: dict[str, dict] = {}

        # Load any existing verdicts from the primary output file
        existing = _load_verdicts(json_paths[0])
        for v in existing.get("verdicts", []):
            self.verdicts[v["url"]] = v

        root.title("WSTG-CLNT-09 — Clickjacking Verdict Recorder")
        root.geometry("960x680")
        root.minsize(720, 520)
        root.configure(bg="#1c1c1c")

        self._build_ui()
        self._populate_list()
        self._refresh_status()

    # ── UI construction ────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        # ── Endpoint list (top half) ─────────────────────────────────────────
        list_outer = tk.Frame(self.root, bg="#1c1c1c")
        list_outer.pack(fill=tk.BOTH, expand=True, padx=12, pady=(12, 4))

        list_label = tk.Label(
            list_outer, text="Unprotected Endpoints",
            bg="#1c1c1c", fg="#abb2bf", font=("TkDefaultFont", 10, "bold"),
        )
        list_label.pack(anchor=tk.W, pady=(0, 4))

        list_frame = tk.Frame(list_outer, bg="#282c34", bd=1, relief=tk.SUNKEN)
        list_frame.pack(fill=tk.BOTH, expand=True)

        sb = tk.Scrollbar(list_frame, bg="#3e4452")
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        self.listbox = tk.Listbox(
            list_frame,
            yscrollcommand=sb.set,
            font=("Courier", 10),
            selectmode=tk.SINGLE,
            bg="#282c34", fg="#abb2bf",
            selectbackground="#3e4452",
            selectforeground="#ffffff",
            activestyle="none",
            bd=0, highlightthickness=0,
        )
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.config(command=self.listbox.yview)
        self.listbox.bind("<<ListboxSelect>>", self._on_select)

        # ── Verdict panel (bottom half) ──────────────────────────────────────
        verdict_outer = tk.Frame(self.root, bg="#1c1c1c")
        verdict_outer.pack(fill=tk.X, padx=12, pady=(4, 12))

        verdict_label = tk.Label(
            verdict_outer, text="Verdict",
            bg="#1c1c1c", fg="#abb2bf", font=("TkDefaultFont", 10, "bold"),
        )
        verdict_label.pack(anchor=tk.W, pady=(0, 4))

        panel = tk.Frame(verdict_outer, bg="#282c34", bd=1, relief=tk.SUNKEN,
                         padx=12, pady=10)
        panel.pack(fill=tk.X)

        # URL display row
        url_row = tk.Frame(panel, bg="#282c34")
        url_row.pack(fill=tk.X, pady=(0, 6))
        tk.Label(url_row, text="URL:", bg="#282c34",
                 fg="#56b6c2", font=("TkDefaultFont", 9, "bold")).pack(side=tk.LEFT)
        self.url_label = tk.Label(
            url_row, text="(select an endpoint above)",
            bg="#282c34", fg="#5c6370",
            font=("Courier", 9), wraplength=760, justify=tk.LEFT,
        )
        self.url_label.pack(side=tk.LEFT, padx=(6, 0))

        # Firefox + radio row
        action_row = tk.Frame(panel, bg="#282c34")
        action_row.pack(fill=tk.X, pady=(0, 8))

        self.firefox_btn = tk.Button(
            action_row, text="⚙  Open in Firefox",
            bg="#3e4452", fg="#abb2bf",
            activebackground="#4b5263", activeforeground="#ffffff",
            relief=tk.FLAT, padx=10, pady=4,
            command=self._open_firefox,
            state=tk.DISABLED,
        )
        self.firefox_btn.pack(side=tk.LEFT)

        separator = tk.Frame(action_row, width=30, bg="#282c34")
        separator.pack(side=tk.LEFT)

        tk.Label(action_row, text="Verdict:",
                 bg="#282c34", fg="#abb2bf").pack(side=tk.LEFT)

        self.vuln_var = tk.StringVar(value="")

        self.radio_vuln = tk.Radiobutton(
            action_row, text="Vulnerable",
            variable=self.vuln_var, value="vulnerable",
            bg="#282c34", fg="#e06c75",
            selectcolor="#282c34", activebackground="#282c34",
            state=tk.DISABLED,
        )
        self.radio_vuln.pack(side=tk.LEFT, padx=(10, 4))

        self.radio_safe = tk.Radiobutton(
            action_row, text="Not Vulnerable",
            variable=self.vuln_var, value="not_vulnerable",
            bg="#282c34", fg="#98c379",
            selectcolor="#282c34", activebackground="#282c34",
            state=tk.DISABLED,
        )
        self.radio_safe.pack(side=tk.LEFT)

        # Reasoning text box
        tk.Label(panel, text="Reasoning:", bg="#282c34",
                 fg="#abb2bf").pack(anchor=tk.W)

        self.reasoning = scrolledtext.ScrolledText(
            panel, height=4,
            bg="#21252b", fg="#abb2bf", insertbackground="#528bff",
            font=("TkDefaultFont", 10), relief=tk.FLAT,
            state=tk.DISABLED,
        )
        self.reasoning.pack(fill=tk.X, pady=(3, 10))

        # Push button + status
        bottom_row = tk.Frame(panel, bg="#282c34")
        bottom_row.pack(fill=tk.X)

        self.push_btn = tk.Button(
            bottom_row, text="Push Entry to JSON",
            bg="#528bff", fg="#ffffff",
            activebackground="#3a6fd8", activeforeground="#ffffff",
            relief=tk.FLAT, padx=12, pady=5,
            font=("TkDefaultFont", 10, "bold"),
            command=self._push_verdict,
            state=tk.DISABLED,
        )
        self.push_btn.pack(side=tk.LEFT)

        self.status_label = tk.Label(
            bottom_row, text="",
            bg="#282c34", fg="#5c6370",
            font=("TkDefaultFont", 9),
        )
        self.status_label.pack(side=tk.LEFT, padx=(14, 0))

    # ── Listbox population ─────────────────────────────────────────────────────

    def _populate_list(self) -> None:
        self.listbox.delete(0, tk.END)
        for ep in self.endpoints:
            idx    = ep["index"]
            url    = ep["url"]
            label  = f"  [{idx:>3}]  {url}"
            self.listbox.insert(tk.END, label)
            self._apply_list_colour(self.listbox.size() - 1, url)

    def _apply_list_colour(self, pos: int, url: str) -> None:
        v = self.verdicts.get(url)
        if v is None:
            self.listbox.itemconfig(pos, fg="#abb2bf", bg="#282c34")
        elif v.get("vulnerable"):
            self.listbox.itemconfig(pos, fg="#e06c75", bg="#2d1515")
        else:
            self.listbox.itemconfig(pos, fg="#98c379", bg="#1a2a1a")

    # ── Event handlers ─────────────────────────────────────────────────────────

    def _on_select(self, _event: tk.Event | None = None) -> None:
        sel = self.listbox.curselection()
        if not sel:
            return

        ep            = self.endpoints[sel[0]]
        self._current = ep

        # Update URL label
        self.url_label.config(text=ep["url"], fg="#61afef")

        # Enable controls
        self.firefox_btn.config(state=tk.NORMAL)
        self.radio_vuln.config(state=tk.NORMAL)
        self.radio_safe.config(state=tk.NORMAL)
        self.push_btn.config(state=tk.NORMAL)
        self.reasoning.config(state=tk.NORMAL)

        # Restore any previously saved verdict for this endpoint
        v = self.verdicts.get(ep["url"])
        if v:
            self.vuln_var.set("vulnerable" if v.get("vulnerable") else "not_vulnerable")
            self.reasoning.delete("1.0", tk.END)
            self.reasoning.insert("1.0", v.get("reasoning", ""))
        else:
            self.vuln_var.set("")
            self.reasoning.delete("1.0", tk.END)

    def _open_firefox(self) -> None:
        if not hasattr(self, "_current"):
            return

        ep        = self._current
        test_file = ep.get("test_file")

        if not test_file or not Path(test_file).exists():
            messagebox.showwarning(
                "Test file not found",
                f"HTML test file not found:\n{test_file}\n\nRe-run clnt_09_scan.py to regenerate it.",
            )
            return

        browser = self.firefox or _find_firefox()
        if not browser:
            messagebox.showerror(
                "Firefox not found",
                "Could not locate Firefox automatically.\n"
                "Launch with --firefox <path> to specify it manually.",
            )
            return

        file_url = Path(test_file).as_uri()
        try:
            subprocess.Popen([browser, file_url])
        except FileNotFoundError:
            messagebox.showerror(
                "Firefox not found",
                f"Could not launch Firefox at:\n{browser}",
            )
        except Exception as e:
            messagebox.showerror("Error", f"Could not open Firefox:\n{e}")

    def _push_verdict(self) -> None:
        if not hasattr(self, "_current"):
            return

        ep         = self._current
        url        = ep["url"]
        vuln_val   = self.vuln_var.get()
        reasoning  = self.reasoning.get("1.0", tk.END).strip()

        if not vuln_val:
            messagebox.showwarning(
                "No verdict selected",
                "Please select Vulnerable or Not Vulnerable before pushing.",
            )
            return

        verdict = {
            "index":        ep["index"],
            "url":          url,
            "scan_result":  ep.get("scan_result", "NO_PROTECTION"),
            "test_file":    ep.get("test_file"),
            "vulnerable":   vuln_val == "vulnerable",
            "reasoning":    reasoning,
            "verdict_time": datetime.now(timezone.utc).isoformat(),
        }

        self.verdicts[url] = verdict

        # Build JSON payload, preserving existing non-clickjacking metadata
        existing = _load_verdicts(self.json_paths[0])
        existing["scan_metadata"].update({
            "wstg_id":      "WSTG-CLNT-09",
            "title":        "Testing for Clickjacking — Verdicts",
            "last_updated": datetime.now(timezone.utc).isoformat(),
        })

        # Merge: replace by url, preserve order, add new
        existing_by_url = {v["url"]: v for v in existing.get("verdicts", [])}
        existing_by_url[url] = verdict
        existing["verdicts"] = list(existing_by_url.values())

        _save_verdicts(existing, self.json_paths)

        # Refresh listbox colour for this entry
        sel = self.listbox.curselection()
        if sel:
            self._apply_list_colour(sel[0], url)

        # Status feedback
        result_str = "FINDING" if verdict["vulnerable"] else "NOT FINDING"
        self.status_label.config(
            text=f"✓  Pushed — [{result_str}] saved to both JSON outputs.",
            fg="#98c379",
        )
        self._refresh_status()

    # ── Status bar ─────────────────────────────────────────────────────────────

    def _refresh_status(self) -> None:
        total    = len(self.endpoints)
        reviewed = len(self.verdicts)
        vuln     = sum(1 for v in self.verdicts.values() if v.get("vulnerable"))

        self.root.title(
            f"WSTG-CLNT-09 — Clickjacking Verdict Recorder  "
            f"({reviewed}/{total} reviewed  |  {vuln} finding(s))"
        )


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="WSTG-CLNT-09 — Clickjacking Verdict Recorder GUI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Run clnt_09_scan.py first to generate scan_results.json and test HTML files."
        ),
    )
    ap.add_argument(
        "--scan-json", metavar="FILE", default=str(DEFAULT_SCAN_JSON),
        help=f"Scan results JSON from clnt_09_scan.py  [default: {DEFAULT_SCAN_JSON}]",
    )
    ap.add_argument(
        "--firefox", metavar="PATH", default=None,
        help="Path to Firefox executable (auto-detected if omitted)",
    )

    args      = ap.parse_args()
    scan_path = Path(args.scan_json)

    if not scan_path.exists():
        sys.exit(
            f"[!] Scan results not found: {scan_path}\n"
            f"    Run clnt_09_scan.py first."
        )

    scan_data = json.loads(scan_path.read_text(encoding="utf-8"))
    endpoints = [
        ep for ep in scan_data.get("endpoints", [])
        if ep.get("scan_result") == "NO_PROTECTION"
    ]

    if not endpoints:
        print("[!] No unprotected endpoints in scan results — nothing to review.")
        sys.exit(0)

    firefox_path = args.firefox or _find_firefox()
    if not firefox_path:
        print("[!] Warning: Firefox not found automatically. Use --firefox to specify the path.")

    json_paths = [VERDICT_JSON_OUT, VERDICT_JSON_IN]

    print(f"[*] Loading {len(endpoints)} unprotected endpoint(s) …")
    print(f"    Verdicts → {VERDICT_JSON_OUT.relative_to(TOOL_ROOT)}")
    print(f"             → {VERDICT_JSON_IN.relative_to(TOOL_ROOT)}")

    root = tk.Tk()
    VerdictGUI(root, endpoints, firefox_path, json_paths)
    root.mainloop()


if __name__ == "__main__":
    main()
