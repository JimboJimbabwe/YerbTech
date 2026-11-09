#!/usr/bin/env python3
"""
import_threat_model.py — the other half of the mac_threat_rank.py split: takes the one merged
MASTER_THREAT_MODEL_OUTPUT.json it wrote (on the Mac, or wherever Ollama is) and fans it back
out into the normal per-item Threat_Model.json/.md files, same as threat_rank.py would have
written directly if it had been run against the project tree itself with a live Ollama next to
it.

No AI here, no network call - this is pure file-shuffling, same as param_mapper.py's own job.
Run it wherever the project tree actually lives (the Kali VM, in the usual setup). The GUI's
Threat-Model button never knows or cares that the ranking happened somewhere else - it just
reads Threat_Model.json the same way it always has.

Folder resolution is scan-by-name (find_wstg_folder, imported from threat_rank.py - same
function, same rule every other tool in this project follows: never a hardcoded category map),
not anything path-based in the master file itself.

Usage:
    python3 import_threat_model.py --master MASTER_THREAT_MODEL_OUTPUT.json --project-root /path/to/project
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from threat_rank import find_wstg_folder, render_markdown  # noqa: E402  (local module, path inserted above)


def load_master(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        sys.exit(f"[!] Master file not found: {path}")
    except json.JSONDecodeError as e:
        sys.exit(f"[!] Master file is not valid JSON: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Split a MASTER_THREAT_MODEL_OUTPUT.json (from mac_threat_rank.py) back into "
                    "each WSTG item's own Threat_Model.json/.md."
    )
    parser.add_argument("--master", "-m", required=True, help="Path to MASTER_THREAT_MODEL_OUTPUT.json")
    parser.add_argument("--project-root", required=True, help="Project root to scan for WSTG item folders")
    args = parser.parse_args()

    master = load_master(args.master)
    model = master.get("model", "unknown")
    categories = master.get("categories", {})

    written, skipped = [], []

    for category, wstg_items in categories.items():
        for wstg_id, payload in wstg_items.items():
            items = payload.get("items") or []
            if not items:
                skipped.append({"wstg_id": wstg_id, "category": category, "reason": "No ranked items under this WSTG ID in the master file."})
                continue

            folder = find_wstg_folder(args.project_root, wstg_id)
            if not folder:
                skipped.append({"wstg_id": wstg_id, "category": category, "reason": f"No {wstg_id} folder found in this project."})
                continue

            out_dir = os.path.join(folder, "Outputs", "test_outputs")
            os.makedirs(out_dir, exist_ok=True)
            json_file = os.path.join(out_dir, "Threat_Model.json")
            md_file = os.path.join(out_dir, "Threat_Model.md")

            full = {
                "wstg_id": wstg_id,
                "category": category,
                "generated_at": master.get("generated_at"),
                "model": model,
                "items": items,
            }
            if payload.get("skipped_associations"):
                full["skipped_associations"] = payload["skipped_associations"]

            with open(f"{json_file}.tmp", "w", encoding="utf-8") as fh:
                json.dump(full, fh, indent=2)
            os.replace(f"{json_file}.tmp", json_file)
            with open(f"{md_file}.tmp", "w", encoding="utf-8") as fh:
                fh.write(render_markdown(wstg_id, items))
            os.replace(f"{md_file}.tmp", md_file)

            written.append({"wstg_id": wstg_id, "ranked": len(items), "json": json_file})

    for item in master.get("skipped_items", []):
        skipped.append({**item, "reason": f"(skipped during ranking, before import) {item.get('reason', '')}"})

    print(json.dumps({"written": written, "skipped": skipped}, indent=2))


if __name__ == "__main__":
    main()
