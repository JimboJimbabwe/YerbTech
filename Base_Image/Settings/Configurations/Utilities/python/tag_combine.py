#!/usr/bin/env python3
"""
tag_combine.py  (script 3 of the shuttle_gen / rebuild_tag / tag_combine pipeline)

Takes shuttle_gen's wordlist (one payload per line) and rebuild_tag's tag-split JSON
({"index", "tag_start", "tag_end"}), and writes one combined line per surviving payload:

    tagged_line = tag_start + payload + tag_end

# TODO(pairing): the orchestrator is responsible for only ever pairing an Input wordlist
# with the Input tag-split of the SAME source file (never crossed with an Output side, and
# never across two different association entries). This script itself does no matching by
# name - it just combines whatever two files it is given - so that rule lives in the caller.
# Revisit together once script 1/2 wiring in the orchestrator is settled.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load_wordlist(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    return [line for line in text.splitlines() if line.strip()]


def load_tagsplit(path: Path) -> tuple[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if "tag_start" not in data or "tag_end" not in data:
        raise ValueError(f"{path} is missing tag_start/tag_end (not a rebuild_tag --output file?)")
    return data["tag_start"], data["tag_end"]


def combine(payloads: list[str], tag_start: str, tag_end: str) -> list[str]:
    return [f"{tag_start}{p}{tag_end}" for p in payloads]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Combine a shuttle_gen wordlist with a rebuild_tag tag-split.")
    ap.add_argument("--wordlist", required=True, help="Path to shuttle_gen's output .txt (one payload per line).")
    ap.add_argument("--tagsplit", required=True, help="Path to rebuild_tag's --output .json (tag_start/tag_end).")
    ap.add_argument("--output", required=True, help="Where to write the combined .txt.")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    wordlist_path = Path(args.wordlist)
    tagsplit_path = Path(args.tagsplit)
    out_path = Path(args.output)

    if not wordlist_path.exists():
        print(f"[!] wordlist not found: {wordlist_path}", file=sys.stderr)
        return 1
    if not tagsplit_path.exists():
        print(f"[!] tag-split file not found: {tagsplit_path}", file=sys.stderr)
        return 1

    try:
        payloads = load_wordlist(wordlist_path)
    except OSError as e:
        print(f"[!] could not read {wordlist_path}: {e}", file=sys.stderr)
        return 1
    try:
        tag_start, tag_end = load_tagsplit(tagsplit_path)
    except (OSError, json.JSONDecodeError, ValueError) as e:
        print(f"[!] could not read {tagsplit_path}: {e}", file=sys.stderr)
        return 1

    if not payloads:
        print(f"[!] {wordlist_path} has no payload lines", file=sys.stderr)
        return 1

    tagged = combine(payloads, tag_start, tag_end)

    if args.dry_run:
        print(f"[dry] would write {len(tagged)} line(s) -> {out_path}")
        for line in tagged[:3]:
            print(f"    {line}")
        return 0

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(tagged) + "\n", encoding="utf-8")
    print(f"[✓] wrote {len(tagged)} tagged payload(s) -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
