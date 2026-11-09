#!/usr/bin/env python3
"""
Reporting tool (live) - the webgui-integrated version of mouse_reporter_demo.py.

Same interaction model as the demo - middle-click category/item picker,
Space-toggled capture rectangle, Shift+scroll resize, F9 capture+describe,
Esc un-prime - all via *globally observed* pynput listeners, never a local Tk
mouse/keyboard binding and never any attempt to suppress an OS default.
Two things are different from the demo:

  1. Categories and items come from the project's own wstg_reporting.json
     (--reporting-file), not a hardcoded sample list.
  2. F9 takes a REAL screenshot (scrot, falling back to PIL.ImageGrab) of the
     capture rectangle's current screen position/size. The image is saved
     under that WSTG item's own Reporting/ folder, found the same
     scan-for-WSTG-ID way as the rest of this project (find_wstg_folder,
     imported from tools/param_mapper/threat_rank.py - never a hardcoded
     category -> folder map) and created lazily, same as lib/findings.js
     does for Outputs/test_outputs. The JSON index of every step lives at
     <project-root>/Reporting/reporting_index.json, also created lazily, so
     there is one place that lists everything captured across the project.

This is meant to be spawned by the Node server (lib/reportingProc.js), which
supplies --project-root and --reporting-file from the project and server
config it already knows about - nothing here hardcodes a path.

Usage
-----
    pip install pynput
    python3 reporting_overlay.py --project-root <dir> --reporting-file <path/to/wstg_reporting.json>
"""
import argparse
import json
import os
import re
import signal
import subprocess
import sys
import tkinter as tk
from pathlib import Path

from pynput import keyboard, mouse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'param_mapper'))
from threat_rank import find_wstg_folder  # noqa: E402  (local module, path inserted above)

try:
    from PIL import ImageGrab
except ImportError:
    ImageGrab = None

ID_RE = re.compile(r'^WSTG-[A-Z]{4}-\d{2}$')

DIAMETER = 90
GAP = 14
MARGIN_TOP = 12
ALPHA = 0.82
KEY_COLOR = "#010203"          # becomes see-through on Windows

COL_IDLE = "#2b2f3a"
COL_IDLE_OUT = "#6b7280"
COL_ACTIVE = "#3b82f6"
COL_ACTIVE_OUT = "#ffffff"
COL_LOCKED = "#16a34a"
COL_TEXT = "#f3f4f6"

RECT_STEP = 20                 # pixels per scroll notch
RECT_MIN = 20
RECT_ALPHA = 0.40
COL_RECT = "#f59e0b"

MASTER_INDEX_NAME = "reporting_index.json"
HIDE_BEFORE_CAPTURE_MS = 150   # let the WM actually unmap the overlay windows first


def atomic_write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    tmp.replace(path)


def load_categories(reporting_file: Path):
    """wstg_reporting.json -> (category_order, {category: [(wstg_id, name), ...]}).
    Mirrors lib/data.js's getReporting() parsing exactly, so a file that's valid for the
    Node app is valid here too. Categories with no valid WSTG test IDs are dropped rather
    than shown as an empty, unusable circle."""
    with open(reporting_file, "r", encoding="utf-8") as f:
        raw = json.load(f)
    cats_raw = raw.get("categories") if isinstance(raw, dict) else None
    if not isinstance(cats_raw, dict):
        raise SystemExit(f'{reporting_file}: no "categories" object.')
    order = []
    items_by_cat = {}
    for cat_name, cat in cats_raw.items():
        tests = cat.get("tests") if isinstance(cat, dict) else None
        pairs = []
        for t in (tests or []):
            if not isinstance(t, dict):
                continue
            tid = str(t.get("id", "")).strip()
            if not ID_RE.match(tid):
                continue
            pairs.append((tid, str(t.get("name") or tid)))
        if pairs:
            order.append(cat_name)
            items_by_cat[cat_name] = pairs
    if not order:
        raise SystemExit(f'{reporting_file}: no categories with valid WSTG test IDs.')
    return order, items_by_cat


class ReportingOverlay:
    def __init__(self, project_root: Path, categories, items_by_category):
        self.project_root = project_root
        self.categories = categories
        self.items_by_category = items_by_category
        self.master_index_path = project_root / "Reporting" / MASTER_INDEX_NAME

        # picking state: None | "category" | "item"
        self.mode = None
        self.index = 0
        self.locked_category = None
        self.locked_item = None        # (wstg_id, name)
        self.primed = False

        # rectangle state (this rectangle IS the capture frame - F9 refuses without it)
        self.rect_on = False
        self.rect_w, self.rect_h = 240, 140
        self.resize_axis = None        # None | "length" | "height"
        self.rect_win = None
        self.rect_canvas = None
        self.mx = self.my = 0

        self.pressed = set()           # swallow key auto-repeat
        self.quit_requested = False
        self.describe_win = None
        self.capture_in_progress = False
        self.step_counts = {}          # (category, wstg_id) -> last step number

        self.root = tk.Tk()
        self.root.title("reporting-overlay")
        self.root.overrideredirect(True)
        self.root.attributes("-topmost", True)
        self._setup_transparency()

        self.w = max(1, len(self.categories)) * DIAMETER + (len(self.categories) + 1) * GAP
        self.h = DIAMETER + MARGIN_TOP + GAP
        sw = self.root.winfo_screenwidth()
        self.x0 = max(0, (sw - self.w) // 2)
        self.y0 = 0
        self.root.geometry(f"{self.w}x{self.h}+{self.x0}+{self.y0}")

        self.canvas = tk.Canvas(self.root, width=self.w, height=self.h,
                                 bg=self._bg, highlightthickness=0)
        self.canvas.pack()

        self.status_win = tk.Toplevel(self.root)
        self.status_win.overrideredirect(True)
        self.status_win.attributes("-topmost", True)
        try:
            self.status_win.attributes("-alpha", ALPHA)
        except tk.TclError:
            pass
        self.status_label = tk.Label(self.status_win, text="", fg="#f3f4f6",
                                      bg="#111318", font=("Helvetica", 10),
                                      padx=10, pady=4, justify="left", anchor="w")
        self.status_label.pack(fill="both", expand=True)
        self.status_win.geometry(f"520x28+{self.x0}+{self.y0 + self.h + 6}")

        self.draw()
        self._refresh_status()
        self.root.protocol("WM_DELETE_WINDOW", self.shutdown)
        self.root.after(200, self._poll)

    # ---- transparency ---------------------------------------------------
    def _setup_transparency(self):
        self._bg = "black"
        try:
            if sys.platform.startswith("win"):
                self._bg = KEY_COLOR
                self.root.attributes("-transparentcolor", KEY_COLOR)
                self.root.attributes("-alpha", ALPHA)
            elif sys.platform == "darwin":
                self.root.attributes("-transparent", True)
                self.root.config(bg="systemTransparent")
                self._bg = "systemTransparent"
                self.root.attributes("-alpha", ALPHA)
            else:
                self.root.attributes("-alpha", ALPHA)
        except tk.TclError:
            pass

    # ---- drawing: category/item HUD -------------------------------------
    def _labels(self):
        if self.mode == "category":
            idx = self.categories.index(self.locked_category) if self.locked_category in self.categories else None
            return self.categories, idx
        if self.mode == "item":
            items = self.items_by_category[self.locked_category]
            return [f"{wid}\n{name}" for wid, name in items], None
        if self.primed and self.locked_category:
            items = self.items_by_category[self.locked_category]
            idx = next((i for i, it in enumerate(items) if it == self.locked_item), None)
            return [f"{wid}\n{name}" for wid, name in items], idx
        return self.categories, None

    def circle_center(self, i, n):
        cx = GAP + DIAMETER / 2 + i * (DIAMETER + GAP)
        cy = MARGIN_TOP + DIAMETER / 2
        return cx, cy

    def draw(self):
        c = self.canvas
        c.delete("all")
        labels, locked_idx = self._labels()
        n = max(1, len(labels))
        r = DIAMETER / 2
        picking = self.mode in ("category", "item")
        for i, label in enumerate(labels):
            cx, cy = self.circle_center(i, n)
            if picking and i == self.index:
                fill, outline, width = COL_ACTIVE, COL_ACTIVE_OUT, 3
            elif locked_idx is not None and i == locked_idx:
                fill, outline, width = COL_LOCKED, COL_IDLE_OUT, 2
            else:
                fill, outline, width = COL_IDLE, COL_IDLE_OUT, 2
            c.create_oval(cx - r, cy - r, cx + r, cy + r,
                          fill=fill, outline=outline, width=width)
            c.create_text(cx, cy, text=label, fill=COL_TEXT,
                          width=DIAMETER - 14, font=("Helvetica", 9, "bold"),
                          justify="center")

    def _refresh_status(self):
        if self.mode == "category":
            msg = "Pick category - scroll/hover to move, middle-click to confirm"
        elif self.mode == "item":
            msg = f"[{self.locked_category}] pick item - scroll/hover, middle-click to confirm"
        elif self.primed:
            wid, _name = self.locked_item
            msg = f"PRIMED: {self.locked_category} / {wid}  (Space=rect, F9=capture, Esc=unprime)"
        else:
            msg = "Idle - middle-click to pick a category"
        self.status_label.config(text=msg)

    # ---- category/item picking state machine -----------------------------
    def on_middle_click(self):
        if self.describe_win is not None or self.capture_in_progress:
            return
        if self.mode is None:
            if self.rect_win:
                self.rect_win.destroy()
                self.rect_win = None
            self.rect_on = False
            self.resize_axis = None
            self.mode = "category"
            self.index = (self.categories.index(self.locked_category)
                          if self.locked_category in self.categories else 0)
        elif self.mode == "category":
            self.locked_category = self.categories[self.index]
            self.mode = "item"
            self.index = 0
        elif self.mode == "item":
            items = self.items_by_category[self.locked_category]
            self.locked_item = items[self.index]
            self.mode = None
            self.primed = True
        self.draw()
        self._refresh_status()

    def move_highlight(self, delta):
        if self.mode not in ("category", "item"):
            return
        n = len(self.categories) if self.mode == "category" else len(self.items_by_category[self.locked_category])
        if n == 0:
            return
        self.index = (self.index + delta) % n
        self.draw()

    def hover(self, x, y):
        self.mx, self.my = int(x), int(y)
        if self.rect_on:
            self.update_rect()
        if self.mode not in ("category", "item"):
            return
        lx, ly = x - self.x0, y - self.y0
        if not (0 <= ly <= self.h):
            return
        labels, _ = self._labels()
        n = max(1, len(labels))
        for i in range(n):
            cx, cy = self.circle_center(i, n)
            if (lx - cx) ** 2 + (ly - cy) ** 2 <= (DIAMETER / 2) ** 2:
                if i != self.index:
                    self.index = i
                    self.draw()
                return

    def scroll(self, dy):
        if dy == 0:
            return
        if self.mode in ("category", "item"):
            self.move_highlight(1 if dy < 0 else -1)
            return
        if self.rect_on and self.resize_axis:
            self.resize_rect(dy)

    # ---- capture rectangle ------------------------------------------------
    def toggle_rect(self):
        if not self.primed or self.mode is not None or self.describe_win is not None or self.capture_in_progress:
            return
        if self.rect_on:
            self.rect_on = False
            self.resize_axis = None
            if self.rect_win:
                self.rect_win.destroy()
                self.rect_win = None
            return
        self.rect_on = True
        w = tk.Toplevel(self.root)
        w.overrideredirect(True)
        w.attributes("-topmost", True)
        try:
            w.attributes("-alpha", RECT_ALPHA)
        except tk.TclError:
            pass
        self.rect_canvas = tk.Canvas(w, bg=COL_RECT, highlightthickness=3,
                                      highlightbackground="#ffffff")
        self.rect_canvas.pack(fill="both", expand=True)
        self.rect_win = w
        self.update_rect()

    def set_resize_axis(self, axis):
        if not (self.primed and self.rect_on) or self.mode is not None:
            return
        self.resize_axis = None if self.resize_axis == axis else axis
        self.update_rect()

    def update_rect(self):
        if not (self.rect_on and self.rect_win):
            return
        self.rect_win.geometry(f"{self.rect_w}x{self.rect_h}+{self.mx}+{self.my}")
        label = {"length": "LENGTH <-> (scroll)",
                 "height": "HEIGHT ^v (scroll)"}.get(self.resize_axis, "")
        c = self.rect_canvas
        c.delete("all")
        c.create_text(self.rect_w / 2, self.rect_h / 2,
                      text=f"{label}\n{self.rect_w} x {self.rect_h}".strip(),
                      fill="black", font=("Helvetica", 11, "bold"), justify="center")

    def resize_rect(self, dy):
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        d = RECT_STEP if dy > 0 else -RECT_STEP
        if self.resize_axis == "length":
            self.rect_w = max(RECT_MIN, min(sw, self.rect_w + d))
        else:
            self.rect_h = max(RECT_MIN, min(sh, self.rect_h + d))
        self.update_rect()

    # ---- real capture + description ----------------------------------------
    def capture(self):
        if not self.primed or self.mode is not None or self.describe_win is not None or self.capture_in_progress:
            return
        if not (self.rect_on and self.rect_win):
            print("[capture] no capture rectangle is shown - press Space first.", flush=True)
            return
        self.capture_in_progress = True
        x, y, w, h = self.mx, self.my, self.rect_w, self.rect_h
        wstg_id = self.locked_item[0]
        key = (self.locked_category, wstg_id)
        step_no = self.step_counts.get(key, 0) + 1

        test_dir = find_wstg_folder(str(self.project_root), wstg_id)
        image_path = None
        shot_dir = None
        if test_dir:
            shot_dir = Path(test_dir) / "Reporting"
            image_path = shot_dir / f"step_{step_no}.png"
        else:
            print(f"[capture] no WSTG folder found for {wstg_id} under {self.project_root} - "
                  f"saving the step without an image.", flush=True)

        # Hide the overlay (HUD, status, rectangle) before grabbing, same as the reference
        # tooling does, so the overlay never captures itself; a short delay lets the window
        # manager actually unmap them first.
        self.root.withdraw()
        self.status_win.withdraw()
        if self.rect_win:
            self.rect_win.withdraw()
        self.root.after(HIDE_BEFORE_CAPTURE_MS, lambda: self._do_capture(x, y, w, h, shot_dir, image_path, step_no))

    def _do_capture(self, x, y, w, h, shot_dir, image_path, step_no):
        saved = False
        if image_path is not None:
            shot_dir.mkdir(parents=True, exist_ok=True)
            saved = self._take_screenshot(x, y, w, h, str(image_path))
            if not saved:
                image_path = None

        self.root.deiconify()
        self.status_win.deiconify()
        if self.rect_win:
            self.rect_win.deiconify()
        self.capture_in_progress = False
        self._open_describe_window(step_no, image_path)

    def _take_screenshot(self, x, y, w, h, filepath):
        try:
            subprocess.run(["scrot", "-a", f"{x},{y},{w},{h}", filepath],
                            check=True, capture_output=True, timeout=10)
            print(f"[captured] {filepath} (scrot)", flush=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
            if ImageGrab is None:
                print(f"[capture] scrot unavailable ({e}) and Pillow is not installed - "
                      f"no image saved. Install scrot or run: pip install pillow", flush=True)
                return False
            try:
                im = ImageGrab.grab(bbox=(x, y, x + w, y + h))
                im.save(filepath)
                print(f"[captured] {filepath} (PIL.ImageGrab fallback)", flush=True)
                return True
            except Exception as e2:
                print(f"[capture] screenshot failed: {e2}", flush=True)
                return False

    def _open_describe_window(self, step_no, image_path):
        win = tk.Toplevel(self.root)
        win.title(f"Describe step {step_no}")
        win.attributes("-topmost", True)
        win.geometry(f"420x220+{self.x0}+{self.y0 + 80}")
        shot_note = f" - {image_path}" if image_path else " - no image saved"
        tk.Label(win, text=f"{self.locked_category} / {self.locked_item[0]} - step {step_no}{shot_note}",
                font=("Helvetica", 10, "bold"), wraplength=400, justify="left").pack(anchor="w", padx=8, pady=(8, 2))
        text = tk.Text(win, height=6, wrap="word")
        text.pack(fill="both", expand=True, padx=8, pady=4)
        text.focus_set()

        def save(_event=None):
            desc = text.get("1.0", "end").strip()
            self._save_step(step_no, desc, image_path)
            close()

        def close(_event=None):
            self.describe_win = None
            win.destroy()
            self.draw()
            self._refresh_status()

        btns = tk.Frame(win)
        btns.pack(fill="x", padx=8, pady=(0, 8))
        tk.Button(btns, text="Save step (Ctrl+Enter)", command=save).pack(side="left")
        tk.Button(btns, text="Cancel (Esc)", command=close).pack(side="left", padx=(8, 0))
        win.bind("<Control-Return>", save)
        win.bind("<Escape>", close)
        win.protocol("WM_DELETE_WINDOW", close)
        self.describe_win = win

    def _save_step(self, step_no, description, image_path):
        data = {}
        if self.master_index_path.exists():
            try:
                data = json.loads(self.master_index_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                data = {}
        cat = data.setdefault(self.locked_category, {})
        wid, name = self.locked_item
        entry = cat.setdefault(wid, {"name": name, "steps": []})
        rel_image = None
        if image_path is not None:
            try:
                rel_image = os.path.relpath(str(image_path), str(self.project_root))
            except ValueError:
                rel_image = str(image_path)  # different drive on Windows, say - fall back to absolute
        entry["steps"].append({"step": step_no, "description": description, "image_path": rel_image})
        self.step_counts[(self.locked_category, wid)] = step_no
        atomic_write_json(self.master_index_path, data)
        print(f"[saved] {self.master_index_path} <- {self.locked_category}/{wid} step {step_no}", flush=True)

    # ---- un-prime / quit ----------------------------------------------------
    def unprime(self):
        if self.capture_in_progress:
            return
        if self.describe_win is not None:
            self.describe_win.destroy()
            self.describe_win = None
        self.mode = None
        self.primed = False
        self.locked_category = None
        self.locked_item = None
        if self.rect_win:
            self.rect_win.destroy()
            self.rect_win = None
        self.rect_on = False
        self.resize_axis = None
        self.draw()
        self._refresh_status()

    def request_quit(self, *_):
        self.quit_requested = True   # safe to call from signal/listener threads

    def _poll(self):
        if self.quit_requested:
            self.shutdown()
        else:
            self.root.after(200, self._poll)

    def shutdown(self):
        if getattr(self, "_closing", False):
            return
        self._closing = True
        for l in (getattr(self, "mouse_listener", None), getattr(self, "kb_listener", None)):
            try:
                if l:
                    l.stop()
            except Exception:
                pass
        try:
            if self.rect_win:
                self.rect_win.destroy()
            if self.describe_win:
                self.describe_win.destroy()
            self.status_win.destroy()
            self.root.quit()
            self.root.destroy()
        except tk.TclError:
            pass

    # ---- global listeners (run in their own threads) -----------------------
    def start_listeners(self):
        def on_click(x, y, button, pressed):
            if button == mouse.Button.middle and pressed:
                self.root.after(0, self.on_middle_click)

        def on_scroll(x, y, dx, dy):
            self.root.after(0, self.scroll, dy)

        def on_move(x, y):
            self.root.after(0, self.hover, x, y)

        self.mouse_listener = mouse.Listener(on_click=on_click,
                                              on_scroll=on_scroll,
                                              on_move=on_move)
        self.mouse_listener.start()

        def on_press(key):
            if key in self.pressed:
                return                      # ignore auto-repeat
            self.pressed.add(key)
            if key == keyboard.Key.space:
                self.root.after(0, self.toggle_rect)
            elif key == keyboard.Key.shift_l:
                self.root.after(0, self.set_resize_axis, "length")
            elif key == keyboard.Key.shift_r:
                self.root.after(0, self.set_resize_axis, "height")
            elif key == keyboard.Key.f9:
                self.root.after(0, self.capture)
            elif key == keyboard.Key.esc:
                self.root.after(0, self.unprime)
            elif (key == keyboard.KeyCode.from_char("q") and
                  (keyboard.Key.ctrl_l in self.pressed or keyboard.Key.ctrl in self.pressed) and
                  (keyboard.Key.alt_l in self.pressed or keyboard.Key.alt in self.pressed)):
                self.request_quit()         # Ctrl+Alt+Q

        def on_release(key):
            self.pressed.discard(key)

        self.kb_listener = keyboard.Listener(on_press=on_press, on_release=on_release)
        self.kb_listener.start()

    def run(self):
        signal.signal(signal.SIGINT, self.request_quit)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, self.request_quit)
        self.start_listeners()
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project-root", required=True, help="Project directory (same one the GUI has open).")
    ap.add_argument("--reporting-file", required=True, help="Path to the server's wstg_reporting.json.")
    args = ap.parse_args()

    project_root = Path(args.project_root).resolve()
    if not project_root.is_dir():
        raise SystemExit(f"--project-root is not a directory: {project_root}")
    reporting_file = Path(args.reporting_file)
    if not reporting_file.is_file():
        raise SystemExit(f"--reporting-file not found: {reporting_file}")

    order, items_by_cat = load_categories(reporting_file)
    overlay = ReportingOverlay(project_root, order, items_by_cat)
    overlay.run()


if __name__ == "__main__":
    main()
