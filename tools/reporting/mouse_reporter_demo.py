#!/usr/bin/env python3
"""
Reporting tool - standalone input/overlay demo (no real screenshot capture yet).

Demonstrates, with a hardcoded sample WSTG category/item list, the full
category -> item -> capture-rectangle -> description -> save flow using only
*globally observed* input (pynput mouse + keyboard listeners). Nothing here
is a local Tk mouse/keyboard binding, and nothing attempts to suppress any OS
default (there is no OS default to suppress for any of these - middle-click,
scroll and the chosen keys have no competing system menu).

Flow
----
Idle            -> middle-click                      -> picking category
Picking cat     -> scroll / hover moves the highlight
                   middle-click confirms              -> picking item (same category)
Picking item    -> scroll / hover moves the highlight
                   middle-click confirms              -> PRIMED (category+item locked)
Primed          -> Space toggles the capture rectangle (it follows the cursor)
                   Shift_L / Shift_R pick the resize axis (length / height)
                   scroll resizes the rectangle along that axis
                   F9                                  -> stub screenshot + description window
                   middle-click                         -> re-opens the category picker (re-prime)
                   Esc                                  -> un-prime, hide the rectangle
Description win -> type text, "Save step" (or Ctrl+Enter) writes it out
                   "Cancel" (or Esc) closes without saving
Anywhere        -> Ctrl+Alt+Q quits

Output
------
Appends to <output-dir>/reporting_demo.json (default: ./demo_output), shaped as:
  { category: { wstg_id: { "name": ..., "steps": [
        {"step": n, "description": ..., "image_path": ...}, ... ] } } }

Usage
-----
    pip install pynput
    python3 mouse_reporter_demo.py [--output-dir DIR]
"""
import argparse
import json
import signal
import sys as _sys
import tkinter as tk
from pathlib import Path

from pynput import keyboard, mouse

# ---------------------------------------------------------------------------
# Sample data - standalone demo only, no project dependency.
SAMPLE_WSTG = {
    "Information Gathering": [
        ("WSTG-INFO-01", "Conduct Search Engine Discovery"),
        ("WSTG-INFO-02", "Fingerprint Web Server"),
    ],
    "Configuration Management": [
        ("WSTG-CONF-06", "Test HTTP Methods"),
        ("WSTG-CONF-07", "Test HSTS"),
    ],
    "Authentication": [
        ("WSTG-ATHN-03", "Test for Weak Lock Out Mechanism"),
        ("WSTG-ATHN-07", "Test for Weak Password Policy"),
    ],
}
CATEGORIES = list(SAMPLE_WSTG.keys())

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

DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent / "demo_output"
OUTPUT_FILENAME = "reporting_demo.json"


def atomic_write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    tmp.replace(path)


class ReportingOverlay:
    def __init__(self, output_dir: Path):
        self.output_path = output_dir / OUTPUT_FILENAME

        # picking state: None | "category" | "item"
        self.mode = None
        self.index = 0
        self.locked_category = None
        self.locked_item = None        # (wstg_id, name)
        self.primed = False

        # rectangle state
        self.rect_on = False
        self.rect_w, self.rect_h = 240, 140
        self.resize_axis = None        # None | "length" | "height"
        self.rect_win = None
        self.rect_canvas = None
        self.mx = self.my = 0

        self.pressed = set()           # swallow key auto-repeat
        self.quit_requested = False
        self.describe_win = None
        self.step_counts = {}          # (category, wstg_id) -> last step number

        self.root = tk.Tk()
        self.root.title("reporting-overlay-demo")
        self.root.overrideredirect(True)
        self.root.attributes("-topmost", True)
        self._setup_transparency()

        self.w = max(1, len(CATEGORIES)) * DIAMETER + (len(CATEGORIES) + 1) * GAP
        self.h = DIAMETER + MARGIN_TOP + GAP
        sw = self.root.winfo_screenwidth()
        self.x0 = max(0, (sw - self.w) // 2)
        self.y0 = 0
        self.root.geometry(f"{self.w}x{self.h}+{self.x0}+{self.y0}")

        self.canvas = tk.Canvas(self.root, width=self.w, height=self.h,
                                 bg=self._bg, highlightthickness=0)
        self.canvas.pack()

        # Small always-on-top status readout, separate window so it never
        # fights the HUD's own overrideredirect geometry.
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
        self.status_win.geometry(f"460x28+{self.x0}+{self.y0 + self.h + 6}")

        self.draw()
        self._refresh_status()
        self.root.protocol("WM_DELETE_WINDOW", self.shutdown)
        self.root.after(200, self._poll)

    # ---- transparency ---------------------------------------------------
    def _setup_transparency(self):
        self._bg = "black"
        try:
            if _sys.platform.startswith("win"):
                self._bg = KEY_COLOR
                self.root.attributes("-transparentcolor", KEY_COLOR)
                self.root.attributes("-alpha", ALPHA)
            elif _sys.platform == "darwin":
                self.root.attributes("-transparent", True)
                self.root.config(bg="systemTransparent")
                self._bg = "systemTransparent"
                self.root.attributes("-alpha", ALPHA)
            else:
                # X11: needs a compositor for real alpha; stays an opaque bar
                # otherwise, which is fine for this demo.
                self.root.attributes("-alpha", ALPHA)
        except tk.TclError:
            pass

    # ---- drawing: category/item HUD -------------------------------------
    def _labels(self):
        """Returns (labels, locked_index_or_None) for whatever row is on screen."""
        if self.mode == "category":
            idx = CATEGORIES.index(self.locked_category) if self.locked_category in CATEGORIES else None
            return CATEGORIES, idx
        if self.mode == "item":
            items = SAMPLE_WSTG[self.locked_category]
            return [f"{wid}\n{name}" for wid, name in items], None
        if self.primed and self.locked_category:
            items = SAMPLE_WSTG[self.locked_category]
            idx = next((i for i, it in enumerate(items) if it == self.locked_item), None)
            return [f"{wid}\n{name}" for wid, name in items], idx
        return CATEGORIES, None

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
        if self.describe_win is not None:
            return  # ignore while typing a description
        if self.mode is None:
            # Starting (or re-starting) a pick. Category picking always
            # takes priority over any rectangle currently shown.
            if self.rect_win:
                self.rect_win.destroy()
                self.rect_win = None
            self.rect_on = False
            self.resize_axis = None
            self.mode = "category"
            self.index = (CATEGORIES.index(self.locked_category)
                          if self.locked_category in CATEGORIES else 0)
        elif self.mode == "category":
            self.locked_category = CATEGORIES[self.index]
            self.mode = "item"
            self.index = 0
        elif self.mode == "item":
            items = SAMPLE_WSTG[self.locked_category]
            self.locked_item = items[self.index]
            self.mode = None
            self.primed = True
        self.draw()
        self._refresh_status()

    def move_highlight(self, delta):
        if self.mode not in ("category", "item"):
            return
        n = len(CATEGORIES) if self.mode == "category" else len(SAMPLE_WSTG[self.locked_category])
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
        if not self.primed or self.mode is not None or self.describe_win is not None:
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
        # top-left corner tracks the cursor, same as the reference HUD.
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

    # ---- capture + description --------------------------------------------
    def capture(self):
        if not self.primed or self.mode is not None or self.describe_win is not None:
            return
        geom = (self.mx, self.my, self.rect_w, self.rect_h) if self.rect_on else None
        key = (self.locked_category, self.locked_item[0])
        step_no = self.step_counts.get(key, 0) + 1
        print(f"[stub-screenshot] would capture rect={geom} for {key} step={step_no}", flush=True)
        self._open_describe_window(step_no, geom)

    def _open_describe_window(self, step_no, geom):
        win = tk.Toplevel(self.root)
        win.title(f"Describe step {step_no}")
        win.attributes("-topmost", True)
        win.geometry(f"420x220+{self.x0}+{self.y0 + 80}")
        tk.Label(win, text=f"{self.locked_category} / {self.locked_item[0]} - step {step_no}",
                font=("Helvetica", 10, "bold")).pack(anchor="w", padx=8, pady=(8, 2))
        text = tk.Text(win, height=6, wrap="word")
        text.pack(fill="both", expand=True, padx=8, pady=4)
        text.focus_set()

        def save(_event=None):
            desc = text.get("1.0", "end").strip()
            self._save_step(step_no, desc, geom)
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

    def _save_step(self, step_no, description, geom):
        data = {}
        if self.output_path.exists():
            try:
                data = json.loads(self.output_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                data = {}
        cat = data.setdefault(self.locked_category, {})
        wid, name = self.locked_item
        entry = cat.setdefault(wid, {"name": name, "steps": []})
        image_path = None
        if geom is not None:
            image_dir = self.output_path.parent / self.locked_category / wid
            image_path = str(image_dir / f"step_{step_no}.png")
        entry["steps"].append({"step": step_no, "description": description, "image_path": image_path})
        self.step_counts[(self.locked_category, wid)] = step_no
        atomic_write_json(self.output_path, data)
        print(f"[saved] {self.output_path} <- {self.locked_category}/{wid} step {step_no}", flush=True)

    # ---- un-prime / quit ----------------------------------------------------
    def unprime(self):
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
    ap.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR),
                    help="Directory to write reporting_demo.json into (default: ./demo_output)")
    args = ap.parse_args()
    overlay = ReportingOverlay(Path(args.output_dir))
    overlay.run()


if __name__ == "__main__":
    main()
