#!/usr/bin/env python3
"""
clipboard_interceptor.py  (renamed from clipboard_listener.py)

Clipboard JSON recorder with global hotkeys, plus Burp-XML association.

Two modes:

  CONFIG MODE (--config / --project-root): paths come from the project's own
  Settings/Configurations/Mouse_Tool/mouse_tool.json, keyed by WSTG ID. Nothing
  about a folder is typed on the command line - --category/--input_json/
  --output_json/--xml/--master are not used in this mode.
    - The "active" WSTG item lives in Mouse_Tool/active_target.json, polled on
      a timer (about every 0.5s). The web page writes it; F6/F7 cycle through
      the items locally and write it too, so the page and the hotkeys always
      agree on which item is active.
    - Each item keeps its own turn counter and input/output state. Switching
      to another item and back does not disturb its numbering; the counter
      is seeded from the highest synchronizer.turn already on disk the first
      time an item is visited in this run.
    - A clipboard JSON that names a mouse_target.wstg_id different from the
      active item is rejected (ALERT, nothing saved) - a stale copy of the
      listener script pasted into the wrong tab can never save under the
      wrong item. A clipboard JSON with no mouse_target at all (or {}) is
      accepted, since not every capture tool is expected to tag it.
    - Mode resets to INPUT every time the active item changes.
    - F9 association writes <WSTG-ID>_association.json into the item's own
      Master_Folder (Outputs/test_outputs), using the one Burp XML file found
      in its XML_Path - zero or more than one XML there stops the association
      with a clear message, nothing is guessed.
    - Every saved file's "recording" block also carries the WSTG ID.

  LEGACY MODE (no --config): unchanged from clipboard_listener.py - the
  original --category / --input_json / --output_json / --xml / --master
  flags, one turn counter for the whole run, no active-item polling, no WSTG
  stamping. Kept so nothing already built on the old flags breaks.

Workflow (same hotkeys in both modes)
  1. Tap LEFT SHIFT     Copies the JS file to the clipboard. In config mode,
                        the placeholder __WSTG_ID__ inside it is replaced with
                        the active item before copying.
  2. Press I or O       Chooses whether the next save is an INPUT or an OUTPUT.
  3. MIDDLE MOUSE click Reads the clipboard. If it is JSON (config mode: any
                        JSON object; legacy mode: the Path_Config structure),
                        it is saved as <input|output>_Req_N.json. Anything else
                        is rejected with an ALERT on screen and in log.txt.
  4. Press F8           "Output not found" for the current turn.
  5. Press F9           PUSH TO ASSOCIATE.
  6. Press F6 / F7      Config mode only: cycle the active WSTG item back/forward.

Every saved file gets:
    "recording":    {"type": "input" | "output"}                  (legacy)
    "recording":    {"type": "input" | "output", "wstg_id": "..."} (config mode)
    "synchronizer": {"turn": N}

File numbering: N is the highest existing <input|output>_Req_N.json in the
target folder plus 1 (or 1 if none exist). Existing files are never overwritten.

--max: no limit by default in either mode (was 10 in the original legacy
script). Pass --max to cap the number of saves in a run.

Requires:  pip install pynput pyperclip
  - Windows: works as is.
  - macOS:   grant your terminal Accessibility / Input Monitoring permission.
  - Linux:   needs an X11 session (global hotkeys do not work under Wayland);
             pyperclip also needs xclip, xsel or wl-clipboard.

Usage:
  Config mode:
    python clipboard_interceptor.py --config /path/to/Project/Settings/Configurations/Mouse_Tool/mouse_tool.json \
        --project-root /path/to/Project --js /path/to/listener.js [--wstg WSTG-INJT-08]

  Legacy mode (unchanged):
    python clipboard_interceptor.py --category category_2 --js C:/tools/grab.js
    python clipboard_interceptor.py --js C:/tools/grab.js ^
        --xml C:/wstg/cat1/a01/input/xml/burp.xml ^
        --input_json C:/wstg/cat1/a01/input/json ^
        --output_json C:/wstg/cat1/a01/output/json
    python clipboard_interceptor.py --associate-only --xml ... --input_json ... --output_json ...
"""

import argparse
import json
import os
import queue
import re
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from itertools import zip_longest
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pyperclip

SCRIPT_DIR = Path(__file__).resolve().parent
LOG_FILE = SCRIPT_DIR / "log.txt"

# ---- Hotkeys: edit here to change them ---------------------------------------
KEY_INPUT = "i"               # character key: switch to INPUT mode
KEY_OUTPUT = "o"              # character key: switch to OUTPUT mode
KEY_NOT_FOUND = "f8"          # name of a pynput Key: "output not found" for this turn
KEY_ASSOCIATE = "f9"          # name of a pynput Key: push to associate
KEY_PREV_ITEM = "f6"          # config mode only: previous WSTG item
KEY_NEXT_ITEM = "f7"          # config mode only: next WSTG item
MIDDLE_CLICK_DEBOUNCE = 0.5   # seconds; ignores an accidental double middle-click
ACTIVE_POLL_SECONDS = 0.5     # how often active_target.json's mtime is checked
# Left Shift (a tap) copies the JS file. Middle mouse button saves.
# -------------------------------------------------------------------------------

FILENAME_TEMPLATE = "{io}_Req_{n}.json"
XML_INDEX_BASE = 1            # first <item> in the XML is index 1 (use 0 for zero-based)
MASTER_SUFFIX = "_association.json"
ID_RE = re.compile(r"^WSTG-[A-Z]{3,5}-\d{2}$")
WSTG_PLACEHOLDER = "__WSTG_ID__"

_log_lock = threading.Lock()


# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------
def log(level, message):
    """Print a line and append it to log.txt (safe to call from any thread)."""
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{stamp}] {level}: {message}"
    with _log_lock:
        print(line, flush=True)
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError as e:
            print(f"[warn] could not write to {LOG_FILE}: {e}", flush=True)


def preview(text, limit=80):
    one_line = " ".join(text.split())
    return one_line if len(one_line) <= limit else one_line[:limit] + "..."


# --------------------------------------------------------------------------
# Argument helpers
# --------------------------------------------------------------------------
def parse_category(value):
    """Accept category_1..category_4 (or just 1..4); return 'Category_N'. Legacy mode only."""
    m = re.fullmatch(r"(?:category_)?([1-4])", value.strip(), re.IGNORECASE)
    if not m:
        raise argparse.ArgumentTypeError(
            "must be category_1, category_2, category_3 or category_4 (or just 1-4)")
    return f"Category_{m.group(1)}"


def parse_io(value):
    v = value.strip().lower()
    if v not in ("input", "output"):
        raise argparse.ArgumentTypeError("must be 'input' or 'output'")
    return v


def positive_int(value):
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a whole number")
    if n < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return n


def parse_path(value):
    """A user-supplied path: ~ expanded and made absolute."""
    return Path(value).expanduser().resolve()


def resolve_js_file(path):
    """--js may be a .js file, or a folder holding one (newest .js file wins)."""
    p = Path(path).expanduser()
    if p.is_file():
        return p
    if p.is_dir():
        files = sorted(p.glob("*.js"), key=lambda f: f.stat().st_mtime, reverse=True)
        if not files:
            raise ValueError(f"no .js file found in folder {p}")
        return files[0]
    raise ValueError(f"path not found: {p}")


# --------------------------------------------------------------------------
# mouse_tool.json resolution (config mode) - same relative-path safety rule
# as the Node side (lib/mouse.js) and the orchestrator.
# --------------------------------------------------------------------------
class MouseConfigError(Exception):
    """A problem reading or resolving mouse_tool.json."""


def inside_repo(repo_dir: Path, rel: str, label: str) -> Path:
    if not isinstance(rel, str) or not rel.strip():
        raise MouseConfigError(f"{label} is empty in mouse_tool.json")
    if rel.startswith("/") or rel.startswith("\\") or (len(rel) > 1 and rel[1] == ":"):
        raise MouseConfigError(f"{label} must be a relative path, got: {rel}")
    abs_path = (repo_dir / rel).resolve()
    try:
        abs_path.relative_to(repo_dir.resolve())
    except ValueError:
        raise MouseConfigError(f"{label} points outside the project: {rel}")
    return abs_path


_mouse_cfg_cache = {}  # path -> (mtime_ns, size, dict)


def load_mouse_config(path: Path) -> dict:
    try:
        st = path.stat()
    except OSError as e:
        raise MouseConfigError(f"cannot read mouse_tool.json ({path}): {e}")
    stamp = (st.st_mtime_ns, st.st_size)
    cached = _mouse_cfg_cache.get(str(path))
    if cached and cached[0] == stamp:
        return cached[1]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise MouseConfigError(f"mouse_tool.json is not valid JSON: {e}")
    targets = data.get("Targets")
    if not isinstance(targets, dict) or not targets:
        raise MouseConfigError('mouse_tool.json needs a non-empty "Targets" object')
    _mouse_cfg_cache[str(path)] = (stamp, targets)
    return targets


def resolve_item(project_root: Path, targets: dict, wstg_id: str) -> dict:
    t = targets.get(wstg_id)
    if t is None:
        raise MouseConfigError(f"{wstg_id} is not in mouse_tool.json")
    repo = project_root / "WSTG_Repository"
    master_folder = inside_repo(repo, t.get("Master_Folder", ""), f"{wstg_id}.Master_Folder")
    return {
        "wstg_id": wstg_id,
        "input_folder": inside_repo(repo, t.get("Input_Folder", ""), f"{wstg_id}.Input_Folder"),
        "output_folder": inside_repo(repo, t.get("Output_Folder", ""), f"{wstg_id}.Output_Folder"),
        "xml_path": inside_repo(repo, t.get("XML_Path", ""), f"{wstg_id}.XML_Path"),
        "master_folder": master_folder,
        "master_file": master_folder / f"{wstg_id}{MASTER_SUFFIX}",
    }


def find_single_xml(xml_dir: Path):
    """Returns (Path, None) or (None, reason) - never guesses when there's more than one."""
    if not xml_dir.is_dir():
        return None, f"XML folder does not exist yet: {xml_dir}"
    names = sorted(p.name for p in xml_dir.iterdir() if p.is_file() and p.suffix.lower() == ".xml")
    if not names:
        return None, f"No Burp XML found in {xml_dir}"
    if len(names) > 1:
        return None, f"More than one XML in {xml_dir} ({', '.join(names)}); leave exactly one"
    return xml_dir / names[0], None


def active_target_path(settings_root: Path) -> Path:
    return settings_root / "Configurations" / "Mouse_Tool" / "active_target.json"


def read_active(path: Path):
    """Returns wstg_id string, or None if the file is missing/unreadable/malformed."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    wstg_id = data.get("wstg_id") if isinstance(data, dict) else None
    return wstg_id if isinstance(wstg_id, str) else None


def write_active(path: Path, wstg_id: str):
    """Atomic write: temp file, then rename. The one file in Settings this script writes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps({"wstg_id": wstg_id}, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def seed_turn(input_folder: Path) -> int:
    """Highest synchronizer.turn already saved in this item's input folder, plus 1 (or 1)."""
    if not input_folder.is_dir():
        return 1
    best = 0
    for p in input_folder.glob("input_Req_*.json"):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            turn = data.get("synchronizer", {}).get("turn")
            if isinstance(turn, int):
                best = max(best, turn)
        except (OSError, ValueError, AttributeError):
            continue
    return best + 1


# --------------------------------------------------------------------------
# JSON structure handling (legacy mode's Path_Config lookup)
# --------------------------------------------------------------------------
def get_key(d, wanted):
    """Case-insensitive key lookup; returns the real key or None."""
    for k in d:
        if isinstance(k, str) and k.lower() == wanted.lower():
            return k
    return None


def looks_like_path(s):
    """True for text that is plausibly a folder path (has a slash, drive letter or ~)."""
    s = s.strip()
    return bool(re.search(r"[\\/]", s) or re.match(r"[A-Za-z]:", s) or s.startswith("~"))


def check_structure(data):
    """Confirm the JSON is an object holding Path_Config. Legacy mode only.

    Returns (path_config_dict, None) or (None, reason).
    """
    if not isinstance(data, dict):
        return None, "top level is not a JSON object (expected one containing Path_Config)"
    pc_key = get_key(data, "Path_Config")
    if pc_key is None or not isinstance(data[pc_key], dict):
        return None, "no 'Path_Config' object found"
    return data[pc_key], None


def extract_folder(data, category, io):
    """Find the target folder inside the parsed JSON. Legacy mode only.

    Returns (Path, None) on success or (None, reason) on failure.
    """
    path_config, reason = check_structure(data)
    if path_config is None:
        return None, reason

    cat_key = get_key(path_config, category)
    if cat_key is None or not isinstance(path_config[cat_key], dict):
        return None, f"Path_Config has no '{category}' section"
    cat = path_config[cat_key]

    folder_name = f"{io.capitalize()}_Folder"
    folder_key = get_key(cat, folder_name)
    if folder_key is None:
        return None, f"{category} has no '{folder_name}' entry"
    entry = cat[folder_key]

    if isinstance(entry, dict):
        path_key = get_key(entry, "path")
        raw = entry[path_key] if path_key else None
        if raw is None:
            desc_key = get_key(entry, "description")
            desc = entry[desc_key] if desc_key else None
            if isinstance(desc, str) and looks_like_path(desc):
                raw = desc
    else:
        raw = entry
    if not isinstance(raw, str) or not raw.strip():
        return None, (f"{category}.{folder_key} has no folder path set "
                      "(use a path string, or an object with a 'path' field, "
                      "or a path in 'description')")

    folder = Path(raw.strip()).expanduser()
    if not folder.is_absolute():
        base_key = get_key(path_config, "Base_Path")
        base_val = path_config[base_key] if base_key else ""
        if isinstance(base_val, str) and base_val.strip():
            base = Path(base_val.strip()).expanduser()
            if not base.is_absolute():
                base = SCRIPT_DIR / base
        else:
            base = SCRIPT_DIR
        folder = base / folder
    return folder, None


def check_mouse_target(data, active_wstg_id):
    """Config mode: if the clipboard JSON names a mouse_target.wstg_id, it must match the
    active item. No mouse_target at all is accepted (not every capture is expected to tag it).
    Returns None (ok) or a reason string (reject).
    """
    if not isinstance(data, dict):
        return None
    mt_key = get_key(data, "mouse_target")
    if mt_key is None:
        return None
    mt = data[mt_key]
    tagged = mt.get("wstg_id") if isinstance(mt, dict) else None
    if not isinstance(tagged, str) or not tagged.strip() or tagged == WSTG_PLACEHOLDER:
        return None  # unset/placeholder: no claim being made, nothing to contradict
    if tagged != active_wstg_id:
        return (f"clipboard JSON is tagged for {tagged}, but the active item is "
                f"{active_wstg_id} - rejected so it isn't saved under the wrong item")
    return None


# --------------------------------------------------------------------------
# Saving
# --------------------------------------------------------------------------
def req_pattern(io):
    """Matches <io>_Req_N.json in any capitalisation; group 1 is N."""
    return re.compile(rf"{re.escape(io)}_req_(\d+)\.json", re.IGNORECASE)


def next_number(folder, io):
    """Highest existing <io>_Req_N.json number in the folder, plus 1 (or 1)."""
    pattern = req_pattern(io)
    nums = []
    for p in folder.iterdir():
        m = pattern.fullmatch(p.name)
        if m:
            nums.append(int(m.group(1)))
    return max(nums, default=0) + 1


def save_json(text, folder, io):
    """Write text to <folder>/<io>_Req_N.json without overwriting anything."""
    folder.mkdir(parents=True, exist_ok=True)
    n = next_number(folder, io)
    while True:
        path = folder / FILENAME_TEMPLATE.format(io=io, n=n)
        try:
            # "x" = fail if the file exists, so an existing file is never overwritten.
            with open(path, "x", encoding="utf-8", newline="") as f:
                f.write(text)
            return path
        except FileExistsError:
            n += 1


def handle_clip(text, folder, io, turn, *, wstg_id=None):
    """Validate clipboard text and save it with the appended blocks.

    `folder` is the resolved destination (config mode: the active item's input/output folder;
    legacy mode: --input_json/--output_json override, or the folder named inside the JSON).
    Returns the saved Path, or None if the text was rejected.
    """
    if not text.strip():
        log("ALERT", "Clipboard is empty or not text. Nothing saved.")
        return None

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        log("ALERT", f"Clipboard is not valid JSON ({e.msg}, line {e.lineno} col {e.colno}). "
                     f"Not saved. Starts with: {preview(text)}")
        return None

    if not isinstance(data, dict):
        log("ALERT", "Valid JSON but not an object. Not saved.")
        return None

    if wstg_id is not None:
        reason = check_mouse_target(data, wstg_id)
        if reason:
            log("ALERT", reason + ". Not saved.")
            return None

    data["recording"] = {"type": io} if wstg_id is None else {"type": io, "wstg_id": wstg_id}
    data["synchronizer"] = {"turn": turn}
    out_text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"

    try:
        path = save_json(out_text, folder, io)
    except OSError as e:
        log("ALERT", f"Could not save to {folder}: {e}")
        return None

    log("SAVED", f"{path}  ({io}, turn {turn}{f', {wstg_id}' if wstg_id else ''})")
    return path


# --------------------------------------------------------------------------
# Association: tie the saved input/output JSONs to Burp XML endpoints
# --------------------------------------------------------------------------
class AssociationError(Exception):
    """A problem that stops an association run (missing path, unreadable XML...)."""


def norm_path(p):
    """Normalise a URL path for comparing: no query/fragment, decoded, no trailing slash."""
    path = unquote(urlsplit(str(p).strip()).path)
    if len(path) > 1:
        path = path.rstrip("/") or "/"
    return path or "/"


_xml_cache = {}   # xml path -> ((mtime_ns, size), items)


def load_burp_xml(xml_path):
    """Parse a Burp 'Save items' export into a list of endpoint dicts.

    ElementTree is fine for your own Burp exports; do not point this at XML from an
    untrusted source.
    """
    try:
        st = xml_path.stat()
    except OSError as e:
        raise AssociationError(f"cannot read XML file {xml_path}: {e}")
    stamp = (st.st_mtime_ns, st.st_size)
    cached = _xml_cache.get(str(xml_path))
    if cached and cached[0] == stamp:
        return cached[1]

    items = []
    root = None
    try:
        for event, elem in ET.iterparse(str(xml_path), events=("start", "end")):
            if event == "start":
                if root is None:
                    root = elem
                continue
            if elem.tag != "item":
                continue
            url = (elem.findtext("url") or "").strip()
            raw_path = (elem.findtext("path") or "").strip()
            split = urlsplit(url or raw_path)
            items.append({
                "index": len(items) + XML_INDEX_BASE,
                "method": (elem.findtext("method") or "").strip(),
                "url": url,
                "status": (elem.findtext("status") or "").strip(),
                "host": (split.hostname or (elem.findtext("host") or "").strip()).lower(),
                "path": norm_path(split.path or raw_path),
                "query": split.query,
            })
            root.clear()
    except ET.ParseError as e:
        raise AssociationError(f"the XML file is not well-formed: {e}")
    except OSError as e:
        raise AssociationError(f"cannot read XML file {xml_path}: {e}")

    if not items:
        raise AssociationError("no <item> entries found in the XML "
                               "(is it a Burp 'Save items' export?)")
    _xml_cache[str(xml_path)] = (stamp, items)
    return items


def find_xml_item(by_path, url, path):
    """Best XML item for a page. Returns (item, match_kind, all_same_path_items)."""
    cands = by_path.get(norm_path(path), [])
    if not cands:
        return None, None, []
    host = query = ""
    if url:
        split = urlsplit(url)
        host, query = (split.hostname or "").lower(), split.query
    if host:
        exact = [c for c in cands if c["host"] == host and c["query"] == query]
        if exact:
            return exact[0], "exact_url", cands
        same_host = [c for c in cands if c["host"] == host]
        if same_host:
            return same_host[0], "host_and_path", cands
    return cands[0], "path_only", cands


def scan_folder(folder, io):
    """{N: Path} for every <io>_Req_N.json in the folder."""
    pattern = req_pattern(io)
    found = {}
    if not folder.is_dir():
        return found
    for p in sorted(folder.iterdir()):
        m = pattern.fullmatch(p.name)
        if m and p.is_file():
            found[int(m.group(1))] = p
    return found


def load_record(n, path):
    """Read one saved JSON and pull out what association needs."""
    rec = {"n": n, "file": str(path), "turn": None, "url": None, "path": None, "error": None}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        rec["error"] = f"{path.name} could not be read as JSON ({e})"
        return rec
    if not isinstance(data, dict):
        rec["error"] = f"{path.name} is not a JSON object"
        return rec

    sync = data.get("synchronizer")
    if isinstance(sync, dict) and isinstance(sync.get("turn"), int):
        rec["turn"] = sync["turn"]

    endpoint = data.get("page_endpoint")
    if isinstance(endpoint, dict):
        if isinstance(endpoint.get("url"), str):
            rec["url"] = endpoint["url"]
        if isinstance(endpoint.get("path"), str) and endpoint["path"].strip():
            rec["path"] = endpoint["path"]
        elif rec["url"]:
            rec["path"] = urlsplit(rec["url"]).path or None
    if not rec["path"]:
        rec["error"] = (f"{path.name} has no page_endpoint.path "
                        "(captured before page_endpoint was added?)")
    return rec


def pair_up(inputs, outputs, pair_by):
    """Group input and output records into (key, input_or_None, output_or_None) pairs."""
    groups = {}
    for io, recs in (("input", inputs), ("output", outputs)):
        for rec in sorted(recs, key=lambda r: r["n"]):
            key = (0, rec["turn"]) if (pair_by == "turn" and rec["turn"] is not None) \
                else (1, rec["n"])
            groups.setdefault(key, {"input": [], "output": []})[io].append(rec)
    pairs = []
    for key in sorted(groups):
        for inp, out in zip_longest(groups[key]["input"], groups[key]["output"]):
            pairs.append((key, inp, out))
    return pairs


def file_block(rec, io):
    if rec is None:
        return None
    return {io.capitalize(): rec["n"], "File": rec["file"]}


def associate_pairs(items, pairs):
    """Match each pair to an XML item. Returns (associations, unmatched)."""
    by_path = {}
    for it in items:
        by_path.setdefault(it["path"], []).append(it)

    associations, unmatched = [], []
    for _key, inp, out in pairs:
        notes = []
        for label, rec in (("input", inp), ("output", out)):
            if rec is None:
                notes.append("No input was recorded for this pair." if label == "input"
                             else "No output was recorded (output not found).")
            elif rec["error"]:
                notes.append(f"The {label} is unusable: {rec['error']}.")
        inp_ok = inp is not None and not inp["error"]
        out_ok = out is not None and not out["error"]
        anchor = inp if inp_ok else out if out_ok else None
        turn = next((r["turn"] for r in (inp, out) if r and r["turn"] is not None), None)

        base = {"Turn": turn, "Input": file_block(inp, "input"), "Output": file_block(out, "output")}
        if anchor is None:
            unmatched.append({"Reason": " ".join(notes), "Path": None, **base})
            continue

        item, kind, cands = find_xml_item(by_path, anchor["url"], anchor["path"])
        if item is None:
            notes.insert(0, f"Path {norm_path(anchor['path'])} was not found in the XML "
                            f"({len(items)} items).")
            unmatched.append({"Reason": " ".join(notes), "Path": anchor["path"], **base})
            continue

        if inp_ok and out_ok and norm_path(inp["path"]) != norm_path(out["path"]):
            out_item, _, _ = find_xml_item(by_path, out["url"], out["path"])
            where = f"XML #{out_item['index']}" if out_item else "not in the XML"
            notes.append(f"Input was captured on {norm_path(inp['path'])} (XML #{item['index']}) "
                         f"but the output on {norm_path(out['path'])} ({where}).")

        entry = {
            "Xml_index": item["index"],
            "Path": norm_path(anchor["path"]),
            "Turn": turn,
            "Input": base["Input"],
            "Output": base["Output"],
            "Bridge": " ".join(notes) or None,
            "Xml_match": kind,
            "Xml_item": {"Method": item["method"], "Url": item["url"], "Status": item["status"]},
        }
        if len(cands) > 1:
            entry["Xml_candidates"] = [c["index"] for c in cands[:10]]
        associations.append(entry)

    associations.sort(key=lambda e: (e["Xml_index"], e["Turn"] if e["Turn"] is not None else 10**9))
    return associations, unmatched


def write_master(master, path):
    """Write the master file atomically (temp file, then replace)."""
    tmp = path.with_name(path.name + ".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp, "w", encoding="utf-8", newline="") as f:
            json.dump(master, f, indent=2, ensure_ascii=False)
            f.write("\n")
        os.replace(tmp, path)
    except OSError as e:
        raise AssociationError(f"could not write the master file {path}: {e}")


def default_master_path(xml_path):
    return xml_path.with_name(xml_path.stem + MASTER_SUFFIX)


def run_association(xml_path, input_dir, output_dir, pair_by="turn", master_path=None, *, wstg_id=None):
    """Scan both folders, match against the XML, write the master file.

    Returns (master_dict, master_path). Raises AssociationError for fatal problems.
    """
    if not xml_path.is_file():
        raise AssociationError(f"XML file not found: {xml_path}")
    for label, folder in (("input folder", input_dir), ("output folder", output_dir)):
        if not folder.is_dir():
            raise AssociationError(f"{label} not found: {folder}")

    items = load_burp_xml(xml_path)
    try:
        inputs = [load_record(n, p) for n, p in scan_folder(input_dir, "input").items()]
        outputs = [load_record(n, p) for n, p in scan_folder(output_dir, "output").items()]
    except OSError as e:
        raise AssociationError(f"cannot read the JSON folders: {e}")
    if not inputs and not outputs:
        raise AssociationError("no input_Req_N.json or output_Req_N.json files found yet")

    pairs = pair_up(inputs, outputs, pair_by)
    associations, unmatched = associate_pairs(items, pairs)
    master = {
        "Generated": datetime.now().isoformat(timespec="seconds"),
        "Wstg_Id": wstg_id,
        "Xml_File": str(xml_path),
        "Input_Folder": str(input_dir),
        "Output_Folder": str(output_dir),
        "Pair_By": pair_by,
        "Xml_index_base": XML_INDEX_BASE,
        "Summary": {
            "xml_items": len(items),
            "input_files": len(inputs),
            "output_files": len(outputs),
            "pairs": len(pairs),
            "matched": len(associations),
            "bridged": sum(1 for a in associations if a["Bridge"]),
            "unmatched": len(unmatched),
        },
        "Associations": associations,
        "Unmatched": unmatched,
    }
    master_path = master_path or default_master_path(xml_path)
    write_master(master, master_path)
    return master, master_path


def pair_label(entry):
    if entry["Turn"] is not None:
        return f"turn {entry['Turn']}"
    files = [Path(b["File"]).name for b in (entry["Input"], entry["Output"]) if b]
    return " + ".join(files) or "unknown pair"


def log_association(master, master_path):
    s = master["Summary"]
    log("ASSOC", f"{s['pairs']} pair(s) from {s['input_files']} input / {s['output_files']} output "
                 f"file(s): {s['matched']} matched to the XML ({s['bridged']} with a bridge note), "
                 f"{s['unmatched']} unmatched -> {master_path}")
    for a in [a for a in master["Associations"] if a["Bridge"]][:5]:
        log("BRIDGE", f"XML #{a['Xml_index']} {pair_label(a)}: {a['Bridge']}")
    for u in master["Unmatched"][:5]:
        log("UNMATCHED", f"{pair_label(u)}: {u['Reason']}")
    hidden = max(0, s["unmatched"] - 5)
    if hidden:
        log("UNMATCHED", f"...and {hidden} more (see the master file).")


# --------------------------------------------------------------------------
# Recording session (state + actions)
# --------------------------------------------------------------------------
class Session:
    """Holds the recording state.

    Hotkey callbacks only queue actions; one worker thread runs them in order.
    That keeps the callbacks instant and means the state never needs locking.
    """

    def __init__(self, mode, max_saves, js_path, *,
                 # legacy mode
                 category=None, turn=1, xml_path=None, input_dir=None, output_dir=None,
                 pair_by="turn", master_path=None,
                 # config mode
                 config_mode=False, project_root=None, mouse_cfg_path=None,
                 settings_root=None, active_wstg_id=None):
        self.mode = mode
        self.saved = 0
        self.max_saves = max_saves  # None = no limit
        self.js_path = js_path
        self.pair_by = pair_by
        self.actions = queue.Queue()
        self.stop = threading.Event()

        self.config_mode = config_mode
        if config_mode:
            self.project_root = project_root
            self.mouse_cfg_path = mouse_cfg_path
            self.settings_root = settings_root
            self.active_target_file = active_target_path(settings_root)
            self._active_mtime = None
            self.active_wstg_id = None
            self.items_state = {}  # wstg_id -> {"turn": int, "input_done": bool}
            self.set_active(active_wstg_id, write=active_wstg_id is not None)
        else:
            self.category = category
            self.turn = turn
            self.input_done = False
            self.xml_path = xml_path
            self.input_dir = input_dir
            self.output_dir = output_dir
            self.master_path = master_path

    # -- config mode: active item -------------------------------------------
    def wstg_ids(self):
        return list(load_mouse_config(self.mouse_cfg_path).keys())

    def resolved(self, wstg_id=None):
        targets = load_mouse_config(self.mouse_cfg_path)
        return resolve_item(self.project_root, targets, wstg_id or self.active_wstg_id)

    def set_active(self, wstg_id, write=True):
        ids = self.wstg_ids()
        if not ids:
            raise MouseConfigError("mouse_tool.json has no Targets")
        if wstg_id is None or wstg_id not in ids:
            wstg_id = ids[0]
        self.active_wstg_id = wstg_id
        self.mode = "input"
        if wstg_id not in self.items_state:
            try:
                r = self.resolved(wstg_id)
                self.items_state[wstg_id] = {"turn": seed_turn(r["input_folder"]), "input_done": False}
            except MouseConfigError as e:
                log("ALERT", f"Could not resolve {wstg_id}: {e}")
                self.items_state[wstg_id] = {"turn": 1, "input_done": False}
        if write:
            try:
                write_active(self.active_target_file, wstg_id)
            except OSError as e:
                log("ALERT", f"Could not write {self.active_target_file}: {e}")
        self._active_mtime = self._stat_active()
        log("INFO", f"Active item: {wstg_id}  [{self.status()}]")

    def _stat_active(self):
        try:
            return self.active_target_file.stat().st_mtime_ns
        except OSError:
            return None

    def poll_active(self):
        """Called often from the worker loop; switches if the file changed on disk."""
        if not self.config_mode:
            return
        m = self._stat_active()
        if m != self._active_mtime:
            new_id = read_active(self.active_target_file)
            if new_id and new_id != self.active_wstg_id and new_id in self.wstg_ids():
                self.set_active(new_id, write=False)
            else:
                self._active_mtime = m  # file touched but nothing usable changed

    def cycle_active(self, step):
        ids = self.wstg_ids()
        if not ids:
            return
        i = ids.index(self.active_wstg_id) if self.active_wstg_id in ids else 0
        self.set_active(ids[(i + step) % len(ids)])

    # -- plumbing -------------------------------------------------------------
    def status(self):
        if self.config_mode:
            turn = self.items_state.get(self.active_wstg_id, {}).get("turn", "?")
            return f"item={self.active_wstg_id} mode={self.mode.upper()} turn={turn}"
        return f"mode={self.mode.upper()} turn={self.turn}"

    def dispatch(self, fn, *args):
        self.actions.put((fn, args))

    def run_worker(self):
        last_poll = 0.0
        while not self.stop.is_set():
            if self.config_mode and time.monotonic() - last_poll >= ACTIVE_POLL_SECONDS:
                self.poll_active()
                last_poll = time.monotonic()
            try:
                fn, args = self.actions.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                fn(*args)
            except Exception as e:
                log("ALERT", f"Unexpected error: {e!r}")
            finally:
                self.actions.task_done()

    # -- actions ------------------------------------------------------------
    def set_mode(self, mode):
        self.mode = mode
        log("INFO", f"Mode: {mode.upper()}  [{self.status()}]")

    def copy_js(self):
        if self.js_path is None:
            log("WARN", "Left Shift pressed but no --js path was given. Nothing copied.")
            return
        try:
            js_file = resolve_js_file(self.js_path)
            text = js_file.read_text(encoding="utf-8")
        except (OSError, ValueError, UnicodeDecodeError) as e:
            log("ALERT", f"Could not read the JS file: {e}")
            return
        if self.config_mode:
            text = text.replace(WSTG_PLACEHOLDER, self.active_wstg_id)
        try:
            pyperclip.copy(text)
        except pyperclip.PyperclipException as e:
            log("ALERT", f"Could not write to the clipboard: {e}")
            return
        tag = f" tagged for {self.active_wstg_id}" if self.config_mode else ""
        log("INFO", f"JS copied to clipboard ({len(text)} chars from {js_file.name}{tag}). "
                    "It is not saved; middle-click only saves valid JSON.")

    def _config_save(self):
        r = self.resolved()
        folder = r["input_folder"] if self.mode == "input" else r["output_folder"]
        state = self.items_state[self.active_wstg_id]
        try:
            text = pyperclip.paste()
        except pyperclip.PyperclipException as e:
            log("ALERT", f"Could not read the clipboard: {e}")
            return
        path = handle_clip(text, folder, self.mode, state["turn"], wstg_id=self.active_wstg_id)
        if path is None:
            return
        self.saved += 1
        if self.mode == "input":
            if state["input_done"]:
                log("WARN", f"Another input saved for turn {state['turn']} (one was already recorded).")
            state["input_done"] = True
        else:
            if state["input_done"]:
                done = state["turn"]
                state["turn"] += 1
                state["input_done"] = False
                log("INFO", f"Turn {done} complete. Next turn: {state['turn']}")
            else:
                log("WARN", f"Output saved but no input was recorded for turn {state['turn']}. "
                            "Turn not advanced.")
        log("INFO", f"{self.saved}/{self.max_saves or '\u221e'} saves used  [{self.status()}]")
        if self.max_saves and self.saved >= self.max_saves:
            log("INFO", f"Reached the limit of {self.max_saves} saves. Stopping.")
            self.stop.set()

    def _legacy_save(self):
        try:
            text = pyperclip.paste()
        except pyperclip.PyperclipException as e:
            log("ALERT", f"Could not read the clipboard: {e}")
            return
        mode, turn = self.mode, self.turn
        override = self.input_dir if mode == "input" else self.output_dir
        if override is not None:
            data = None
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                pass
            folder = override if isinstance(data, dict) else None
            if folder is None:
                log("ALERT", "Clipboard is not a JSON object. Not saved.")
                return
            path = handle_clip(text, folder, mode, turn)
        else:
            path, reason = None, None
            try:
                data = json.loads(text)
            except json.JSONDecodeError as e:
                log("ALERT", f"Clipboard is not valid JSON ({e.msg}). Not saved.")
                return
            folder, reason = extract_folder(data, self.category, mode)
            if folder is None:
                log("ALERT", f"Valid JSON but not the expected structure: {reason}. Not saved.")
                return
            path = handle_clip(text, folder, mode, turn)
        if path is None:
            return
        self.saved += 1
        if mode == "input":
            if self.input_done:
                log("WARN", f"Another input saved for turn {turn} (one was already recorded).")
            self.input_done = True
        else:
            if self.input_done:
                self.turn += 1
                self.input_done = False
                log("INFO", f"Turn {turn} complete. Next turn: {self.turn}")
            else:
                log("WARN", f"Output saved but no input was recorded for turn {turn}. "
                            "Turn not advanced.")
        log("INFO", f"{self.saved}/{self.max_saves or '\u221e'} saves used  [{self.status()}]")
        if self.max_saves and self.saved >= self.max_saves:
            log("INFO", f"Reached the limit of {self.max_saves} saves. Stopping.")
            self.stop.set()

    def save_from_clipboard(self):
        if self.config_mode:
            self._config_save()
        else:
            self._legacy_save()

    def mark_not_found(self):
        if self.config_mode:
            state = self.items_state[self.active_wstg_id]
            if not state["input_done"]:
                log("WARN", f"No input recorded for turn {state['turn']}, nothing to mark 'not found'.")
                return
            done = state["turn"]
            state["turn"] += 1
            state["input_done"] = False
            log("INFO", f"Turn {done}: output NOT FOUND (verified). Next turn: {state['turn']}  "
                        f"[{self.status()}]")
            return
        if not self.input_done:
            log("WARN", f"No input recorded for turn {self.turn}, so there is nothing to mark "
                        "as 'output not found'. Ignored.")
            return
        done = self.turn
        self.turn += 1
        self.input_done = False
        log("INFO", f"Turn {done}: output NOT FOUND (verified). Next turn: {self.turn}  "
                    f"[{self.status()}]")

    def associate(self):
        if self.config_mode:
            r = self.resolved()
            xml_path, reason = find_single_xml(r["xml_path"])
            if xml_path is None:
                log("ALERT", f"Push to associate: {reason}.")
                return
            log("INFO", f"Push to associate ({self.active_wstg_id}): scanning the folders...")
            try:
                master, path = run_association(xml_path, r["input_folder"], r["output_folder"],
                                               self.pair_by, r["master_file"], wstg_id=self.active_wstg_id)
            except AssociationError as e:
                log("ALERT", f"Association failed: {e}")
                return
            log_association(master, path)
            return
        if None in (self.xml_path, self.input_dir, self.output_dir):
            log("WARN", f"{KEY_ASSOCIATE.upper()} pressed but association is not set up. "
                        "Start the script with --xml, --input_json and --output_json.")
            return
        log("INFO", "Push to associate: scanning the folders...")
        try:
            master, path = run_association(self.xml_path, self.input_dir, self.output_dir,
                                           self.pair_by, self.master_path)
        except AssociationError as e:
            log("ALERT", f"Association failed: {e}")
            return
        log_association(master, path)

    def cycle(self, step):
        if not self.config_mode:
            log("WARN", "F6/F7 only do something in config mode (--config).")
            return
        self.cycle_active(step)


# --------------------------------------------------------------------------
# Hotkey routing
# --------------------------------------------------------------------------
class KeyRouter:
    """Turns raw pynput keyboard/mouse events into Session actions."""

    def __init__(self, session, Key, Button):
        self.s = session
        self.Button = Button
        self.left_shift = {getattr(Key, n) for n in ("shift", "shift_l") if hasattr(Key, n)}
        blockers = ("ctrl", "ctrl_l", "ctrl_r", "alt", "alt_l", "alt_r", "alt_gr",
                    "cmd", "cmd_l", "cmd_r")
        self.blockers = {getattr(Key, n) for n in blockers if hasattr(Key, n)}
        self.not_found_key = getattr(Key, KEY_NOT_FOUND)
        self.associate_key = getattr(Key, KEY_ASSOCIATE)
        self.prev_key = getattr(Key, KEY_PREV_ITEM, None)
        self.next_key = getattr(Key, KEY_NEXT_ITEM, None)
        self.down = set()
        self.shift_tap = False
        self._last_middle = 0.0

    def on_press(self, key):
        try:
            if key in self.down:
                return
            self.down.add(key)

            if key in self.left_shift:
                self.shift_tap = True
                return
            self.shift_tap = False

            if key == self.not_found_key:
                self.s.dispatch(self.s.mark_not_found)
                return
            if key == self.associate_key:
                self.s.dispatch(self.s.associate)
                return
            if self.prev_key is not None and key == self.prev_key:
                self.s.dispatch(self.s.cycle, -1)
                return
            if self.next_key is not None and key == self.next_key:
                self.s.dispatch(self.s.cycle, 1)
                return
            if self.blockers & self.down:
                return
            ch = getattr(key, "char", None)
            if ch:
                ch = ch.lower()
                if ch == KEY_INPUT:
                    self.s.dispatch(self.s.set_mode, "input")
                elif ch == KEY_OUTPUT:
                    self.s.dispatch(self.s.set_mode, "output")
        except Exception as e:
            log("ALERT", f"Hotkey error: {e!r}")

    def on_release(self, key):
        try:
            self.down.discard(key)
            if key in self.left_shift and self.shift_tap:
                self.shift_tap = False
                self.s.dispatch(self.s.copy_js)
        except Exception as e:
            log("ALERT", f"Hotkey error: {e!r}")

    def on_click(self, x, y, button, pressed):
        try:
            if not pressed:
                return
            self.shift_tap = False
            if button == self.Button.middle:
                now = time.monotonic()
                if now - self._last_middle < MIDDLE_CLICK_DEBOUNCE:
                    log("INFO", "Middle click ignored (debounce: too soon after the last one).")
                    return
                self._last_middle = now
                log("INFO", f"Middle click received - reading clipboard  [{self.s.status()}]")
                self.s.dispatch(self.s.save_from_clipboard)
        except Exception as e:
            log("ALERT", f"Mouse error: {e!r}")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Hotkey-driven clipboard JSON recorder with Burp-XML association. "
                    "Config mode (--config/--project-root) resolves paths from mouse_tool.json "
                    "and polls active_target.json; without --config, the original flags apply.")
    parser.add_argument("--config", type=parse_path, default=None,
                        help="Path to the project's mouse_tool.json. Turns on config mode.")
    parser.add_argument("--project-root", type=parse_path, default=None, dest="project_root",
                        help="Project folder (holds WSTG_Repository, Settings, ...). Required with --config.")
    parser.add_argument("--wstg", default=None,
                        help="Config mode: starting WSTG item (default: whatever active_target.json "
                             "already has, else the first item in mouse_tool.json).")
    parser.add_argument("--category", type=parse_category, default=None,
                        help="Legacy mode: category_1 to category_4 (or just 1-4).")
    parser.add_argument("--js", "--js-path", dest="js", default=None,
                        help="Path to the JS file (or a folder containing it) that Left Shift copies")
    parser.add_argument("--input_output", "--io", dest="io", type=parse_io, default="input",
                        help="Starting mode, 'input' or 'output' (default: input)")
    parser.add_argument("--start-turn", type=positive_int, default=1,
                        help="Legacy mode: turn number to start from (default: 1)")
    parser.add_argument("--max", type=positive_int, default=None, dest="max_saves",
                        help="Maximum number of files to save per run (default: no limit)")
    parser.add_argument("--xml", type=parse_path, default=None,
                        help="Legacy mode: Burp XML export to associate against")
    parser.add_argument("--input_json", "--input-json", dest="input_json", type=parse_path, default=None,
                        help="Legacy mode: folder holding input_Req_N.json")
    parser.add_argument("--output_json", "--output-json", dest="output_json", type=parse_path, default=None,
                        help="Legacy mode: folder holding output_Req_N.json")
    parser.add_argument("--pair-by", choices=("turn", "number"), default="turn", dest="pair_by",
                        help="How to pair inputs with outputs (default: turn)")
    parser.add_argument("--master", type=parse_path, default=None,
                        help="Legacy mode: where to write the master association file")
    parser.add_argument("--associate-only", action="store_true", dest="associate_only",
                        help="Run the association once and exit (no hotkeys, no clipboard)")
    args = parser.parse_args()

    config_mode = args.config is not None
    if config_mode and args.project_root is None:
        parser.error("--config also needs --project-root")

    if config_mode:
        settings_root = args.config.parent.parent  # .../Settings/Configurations/Mouse_Tool/mouse_tool.json -> Settings
        try:
            targets = load_mouse_config(args.config)
        except MouseConfigError as e:
            parser.error(str(e))
        if args.wstg and args.wstg not in targets:
            parser.error(f"--wstg {args.wstg} is not in mouse_tool.json")
        start_id = args.wstg or read_active(active_target_path(settings_root))

        if args.associate_only:
            wstg_id = start_id or next(iter(targets))
            try:
                r = resolve_item(args.project_root, targets, wstg_id)
            except MouseConfigError as e:
                print(f"[FATAL] {e}", flush=True)
                return 1
            xml_path, reason = find_single_xml(r["xml_path"])
            if xml_path is None:
                print(f"[FATAL] {reason}", flush=True)
                return 1
            try:
                master, path = run_association(xml_path, r["input_folder"], r["output_folder"],
                                               args.pair_by, r["master_file"], wstg_id=wstg_id)
            except AssociationError as e:
                log("ALERT", f"Association failed: {e}")
                return 1
            log_association(master, path)
            return 0

        js_file = None
        if args.js:
            try:
                js_file = resolve_js_file(args.js)
            except ValueError as e:
                parser.error(f"--js: {e}")

        try:
            from pynput import keyboard, mouse
        except Exception as e:
            print(f"Could not load pynput: {e}\nInstall it with:  pip install pynput", flush=True)
            return 1

        session = Session(args.io, args.max_saves, args.js, pair_by=args.pair_by,
                          config_mode=True, project_root=args.project_root, mouse_cfg_path=args.config,
                          settings_root=settings_root, active_wstg_id=start_id)
        router = KeyRouter(session, keyboard.Key, mouse.Button)

        threading.Thread(target=session.run_worker, daemon=True).start()
        kb = keyboard.Listener(on_press=router.on_press, on_release=router.on_release)
        ms = mouse.Listener(on_click=router.on_click)
        kb.start()
        ms.start()

        log("INFO", f"Config mode. {len(targets)} item(s) in mouse_tool.json. [{session.status()}]")
        log("INFO", f"Hotkeys: Left Shift tap = copy JS (tagged for the active item) | "
                    f"{KEY_INPUT.upper()} = input | {KEY_OUTPUT.upper()} = output | "
                    f"{KEY_NOT_FOUND.upper()} = output not found | {KEY_ASSOCIATE.upper()} = push to associate | "
                    f"{KEY_PREV_ITEM.upper()}/{KEY_NEXT_ITEM.upper()} = prev/next item | "
                    "Middle mouse = save | Ctrl+C in this window = quit")
        if js_file:
            log("INFO", f"JS file: {js_file}")
        else:
            log("WARN", "No --js given: Left Shift will not copy anything.")

        try:
            while not session.stop.is_set():
                session.stop.wait(0.5)
        except KeyboardInterrupt:
            log("INFO", "Stopped by user.")
        finally:
            kb.stop()
            ms.stop()
        return 0

    # -------------------- legacy mode (original behavior) --------------------
    have_all_assoc = None not in (args.xml, args.input_json, args.output_json)
    if args.associate_only and not have_all_assoc:
        parser.error("--associate-only needs --xml, --input_json and --output_json")
    if args.xml and not have_all_assoc:
        parser.error("--xml also needs --input_json and --output_json, so the script knows "
                     "which folders to scan")
    if args.xml and not args.xml.is_file():
        parser.error(f"--xml: file not found: {args.xml}")
    if not args.category and not (args.input_json and args.output_json):
        parser.error("--category is required unless both --input_json and --output_json are given "
                     "(or use --config for the project's mouse_tool.json)")
    master_path = args.master or (default_master_path(args.xml) if args.xml else None)

    if args.associate_only:
        try:
            master, path = run_association(args.xml, args.input_json, args.output_json,
                                           args.pair_by, master_path)
        except AssociationError as e:
            log("ALERT", f"Association failed: {e}")
            return 1
        log_association(master, path)
        return 0

    js_file = None
    if args.js:
        try:
            js_file = resolve_js_file(args.js)
        except ValueError as e:
            parser.error(f"--js: {e}")

    try:
        from pynput import keyboard, mouse
    except Exception as e:
        print(f"Could not load pynput: {e}\n"
              "Install it with:  pip install pynput\n"
              "macOS: allow your terminal under Accessibility / Input Monitoring.\n"
              "Linux: an X11 session is required (Wayland is not supported).")
        return 1

    session = Session(args.io, args.max_saves, args.js, category=args.category,
                      turn=args.start_turn, xml_path=args.xml, input_dir=args.input_json,
                      output_dir=args.output_json, pair_by=args.pair_by, master_path=master_path)
    router = KeyRouter(session, keyboard.Key, mouse.Button)

    threading.Thread(target=session.run_worker, daemon=True).start()
    kb = keyboard.Listener(on_press=router.on_press, on_release=router.on_release)
    ms = mouse.Listener(on_click=router.on_click)
    kb.start()
    ms.start()

    log("INFO", f"Category: {args.category or '(not used)'} | {session.status()} | "
                f"max saves: {args.max_saves or 'unlimited'}")
    log("INFO", f"Hotkeys: Left Shift tap = copy JS | {KEY_INPUT.upper()} = input | "
                f"{KEY_OUTPUT.upper()} = output | {KEY_NOT_FOUND.upper()} = output not found | "
                f"{KEY_ASSOCIATE.upper()} = push to associate | Middle mouse = save | "
                "Ctrl+C in this window = quit")
    if js_file:
        log("INFO", f"JS file: {js_file}")
    else:
        log("WARN", "No --js given: Left Shift will not copy anything.")
    for label, folder in (("Input", args.input_json), ("Output", args.output_json)):
        log("INFO", f"{label} JSON saved to: "
                    f"{folder if folder else 'the folder named inside the copied JSON'}")
    if have_all_assoc:
        log("INFO", f"Association ready ({args.pair_by}-based pairing): XML {args.xml} | "
                    f"master file {master_path}")
    else:
        log("INFO", f"Association is off (no --xml): {KEY_ASSOCIATE.upper()} will do nothing.")

    try:
        while not session.stop.is_set():
            session.stop.wait(0.5)
    except KeyboardInterrupt:
        log("INFO", "Stopped by user.")
    finally:
        kb.stop()
        ms.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
