#!/usr/bin/env python3
"""
mac_threat_rank.py — the AI ranking stage, run standalone on a machine that has Ollama but
NOT the project folder (the Mac, when the VM running the rest of this tool has no network
path to it and you don't want to open one just for this).

This is threat_rank.py split in two. threat_rank.py normally does both things in one pass:
calls Ollama for each association in param_map.json, AND finds each WSTG item's own folder
in the project to write Threat_Model.json/.md into. That second half needs the project tree.
This script does ONLY the first half - it has no --project-root, doesn't walk the project,
and doesn't know what a WSTG folder even is. It reads param_mapper.py's already-bulk
param_map.json (categories -> wstg_id -> every association, the whole project in one file -
param_mapper.py already produces this; nothing upstream needed to change), ranks every
association in it against a local Ollama, and writes ONE merged file,
MASTER_THREAT_MODEL_OUTPUT.json, with the exact same per-item shape threat_rank.py would
normally write directly to disk per item - just all of it in one JSON instead of scattered
across the project tree.

That file is the hand-off back the other way (shared drive, USB, whatever you're already
using to move param_map.json over) - import_threat_model.py (run back where the project
tree lives) splits it back into the normal per-item Threat_Model.json/.md files, and the GUI
reads those exactly as it always has. This script and that one are the only two new pieces;
everything else in the pipeline (param_mapper.py, the server, the viewer) is unchanged.

Ranking logic itself (the system prompt, the JSON schema, the Ollama call, the
drop-hallucinated-parameters check) is imported from threat_rank.py, not duplicated - one
place owns what gets sent to the model and what's trusted back from it.

Usage:
    python3 mac_threat_rank.py --input param_map.json --output MASTER_THREAT_MODEL_OUTPUT.json \
        [--ollama-url http://localhost:11434] [--model qwen2.5:7b-instruct]

    # Or, with no --input/--output: on macOS this opens the native file-choose/save dialogs
    # (via osascript) instead of erroring, since this is meant to be handed to someone who
    # just wants to point at a file and go, not remember flags.
    python3 mac_threat_rank.py
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from threat_rank import rank_entry  # noqa: E402  (local module, path inserted above)


def choose_file_mac(prompt, kind):
    """Native macOS "choose file" (kind='open') or "choose file name" (kind='save') dialog via
    osascript - no extra Python packages, nothing to pip install, works on a stock macOS Python.
    Returns the chosen POSIX path, or None if the dialog was cancelled."""
    if kind == "open":
        script = f'POSIX path of (choose file with prompt "{prompt}" of type {{"json", "public.json"}})'
    else:
        script = (
            f'set f to choose file name with prompt "{prompt}" default name "MASTER_THREAT_MODEL_OUTPUT.json"\n'
            f"POSIX path of f"
        )
    try:
        result = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        return None  # not on macOS, or osascript genuinely missing - caller falls back to erroring
    if result.returncode != 0:
        return None  # user clicked Cancel, or something went wrong - either way, nothing chosen
    path = result.stdout.strip()
    return path or None


def resolve_input_path(given):
    if given:
        return given
    if sys.platform != "darwin":
        sys.exit("[!] --input is required (no file dialog available outside macOS).")
    chosen = choose_file_mac("Select param_map.json (from param_mapper.py)", "open")
    if not chosen:
        sys.exit("[!] No file selected.")
    return chosen


def resolve_output_path(given, input_path):
    if given:
        return given
    if sys.platform != "darwin":
        default = os.path.join(os.path.dirname(os.path.abspath(input_path)), "MASTER_THREAT_MODEL_OUTPUT.json")
        print(f"[*] --output not given; writing to {default}", file=sys.stderr)
        return default
    chosen = choose_file_mac("Save the ranked output as", "save")
    if not chosen:
        sys.exit("[!] No output location chosen.")
    return chosen


def load_param_map(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        sys.exit(f"[!] Input file not found: {path}")
    except json.JSONDecodeError as e:
        sys.exit(f"[!] Input file is not valid JSON: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Rank every association in a param_map.json against a local Ollama, in one pass, "
                    "with no project folder required. Run this on the machine that has Ollama."
    )
    parser.add_argument("--input", "-i", default=None, help="Path to param_map.json (param_mapper.py's output). "
                                                              "Omit on macOS to pick it with a file dialog.")
    parser.add_argument("--output", "-o", default=None, help="Where to write MASTER_THREAT_MODEL_OUTPUT.json. "
                                                               "Omit on macOS to pick it with a save dialog.")
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    parser.add_argument("--model", default="qwen2.5:7b-instruct")
    args = parser.parse_args()

    input_path = resolve_input_path(args.input)
    param_map = load_param_map(input_path)

    categories_in = param_map.get("categories", {})
    total = sum(len(entries) for wstg_items in categories_in.values() for entries in wstg_items.values())
    if total == 0:
        sys.exit("[!] Nothing to rank - param_map.json has no associations under \"categories\".")

    output_path = resolve_output_path(args.output, input_path)

    categories_out = {}
    skipped_items = []
    done = 0

    for category, wstg_items in categories_in.items():
        for wstg_id, entries in wstg_items.items():
            ranked_items, item_skipped = [], []
            for entry in entries:
                done += 1
                print(f"[{done}/{total}] {wstg_id} xml_index {entry.get('xml_index')} ... ", end="", file=sys.stderr, flush=True)
                result, reason = rank_entry(args.ollama_url, args.model, entry)
                if reason:
                    print(f"skipped ({reason})", file=sys.stderr)
                    item_skipped.append({"xml_index": entry["xml_index"], "reason": reason})
                    continue
                print(f"best match: {result.get('best_match') or 'none'}", file=sys.stderr)
                ranked_items.append({
                    "endpoint": {"method": entry["method"], "path": entry["path"],
                                 "xml_index": entry["xml_index"], "burp_index": entry["burp_index"]},
                    "xml_file": entry["_source"]["xml_file"],
                    **result,
                })

            if not ranked_items:
                skipped_items.append({"wstg_id": wstg_id, "category": category,
                                       "reason": "No association could be ranked.", "associations": item_skipped})
                continue

            entry_out = {"items": ranked_items}
            if item_skipped:
                entry_out["skipped_associations"] = item_skipped
            categories_out.setdefault(category, {})[wstg_id] = entry_out

    full = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": args.model,
        "source_input": os.path.basename(input_path),
        "categories": categories_out,
    }
    if skipped_items:
        full["skipped_items"] = skipped_items

    with open(f"{output_path}.tmp", "w", encoding="utf-8") as fh:
        json.dump(full, fh, indent=2)
    os.replace(f"{output_path}.tmp", output_path)

    ranked_count = sum(len(v["items"]) for wstg_items in categories_out.values() for v in wstg_items.values())
    print(f"\n[*] Ranked {ranked_count} association(s), skipped {len(skipped_items)} item(s) entirely. "
          f"Written to: {output_path}", file=sys.stderr)
    print(f"[*] Hand {output_path} back to the project side and run import_threat_model.py against it.", file=sys.stderr)


if __name__ == "__main__":
    main()
