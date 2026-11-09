#!/usr/bin/env python3
"""
param_mapper.py — the data-prep stage for the surface-ranking idea.

Does nothing more than correlate three things that already exist in a project,
per WSTG item:

  1. injection_router.json   — which WSTG items are in scope (Client_Side / Server_Side)
  2. master_associations.json — which XML request index pairs with which hover-trace
                                  (rebuilt-tag) JSON file for that item (the operator's
                                  own XSSMouse-style tool already produces this)
  3. The actual Burp XML and hover-trace JSON those two point to.

For each in-scope item it:
  - finds the item's own folder by scanning for a directory literally named like the
    WSTG ID (never a hardcoded category map — same rule every other tool in this
    project follows),
  - finds a file named exactly "master_associations.json" somewhere under that folder
    (again: scan, not a hardcoded subpath — the operator's tool may write it anywhere),
  - processes EVERY entry in that file's "Associations" array (not just the first -
    an item can have more than one traced request/tag pair, and the GUI's Threat-Model
    list needs all of them to have more than one row to show),
  - for each one, runs param_inventory's extractors against the XML request at that
    index to get its URL/body/JSON parameters,
  - runs rebuild_tag against the hover-trace JSON that association points to, to get the
    reconstructed HTML tag and its attributes,
  - writes one nested list: category -> wstg_id -> [ one merged result per association ].
    One association failing (missing tag file, bad index, etc.) is recorded per-entry
    and does not block the others for the same item.

This script does NOT rank, score, or decide which parameter is "the" surface. That is
the next stage (a separate script, deliberately not built yet). This one only produces
the JSON the next stage would read.

Usage:
    python3 param_mapper.py --router injection_router.json --project-root /path/to/project \
        [--output param_map.json]
"""

import argparse
import base64
import json
import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import param_inventory  # noqa: E402  (local module, path inserted above)
import rebuild_tag      # noqa: E402


# ---------------------------------------------------------------------------
# WSTG folder resolution — scan, never a hardcoded category map.
# Mirrors resources.locateTest / resources.indexTestDirs in the Node app.
# ---------------------------------------------------------------------------

_WSTG_DIR_RE = re.compile(r"^(WSTG-[A-Z]+-\d+)(?:_.*)?$")


def load_router(path):
    """Same clean-failure shape as orchestrator.py's load_json: a one-line message and a
    non-zero exit, never a raw traceback over a missing or malformed --router path."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        sys.exit(f"[!] injection_router.json not found: {path}")
    except json.JSONDecodeError as e:
        sys.exit(f"[!] injection_router.json is not valid JSON: {e}")


def find_wstg_folder(project_root, wstg_id):
    """Scan project_root for a directory literally named WSTG-XXXX-NN (optionally
    with a _description suffix). Returns the absolute path, or None."""
    for dirpath, dirnames, _filenames in os.walk(project_root):
        for d in list(dirnames):
            m = _WSTG_DIR_RE.match(d)
            if m and m.group(1) == wstg_id:
                return os.path.join(dirpath, d)
    return None


def find_master_associations(wstg_folder):
    """Scan a WSTG item's own folder for a file named exactly master_associations.json."""
    for dirpath, _dirnames, filenames in os.walk(wstg_folder):
        if "master_associations.json" in filenames:
            return os.path.join(dirpath, "master_associations.json")
    return None


# ---------------------------------------------------------------------------
# Per-item processing
# ---------------------------------------------------------------------------

def resolve_path(search_root, maybe_path):
    """master_associations.json's own paths are written by a different machine
    (the operator's own box, often Windows paths, often a different folder layout
    entirely - XSSMouse's input_folder/output_folder are not this project's
    Inputs/XML, Inputs/JSON). If the path doesn't exist as written, fall back to
    a scan for that exact filename anywhere under the WSTG item's own folder -
    the common case once a project has been moved onto this machine."""
    if maybe_path and os.path.isfile(maybe_path):
        return maybe_path
    name = re.split(r"[\\/]", maybe_path or "")[-1] if maybe_path else None
    if name:
        for dirpath, _dirnames, filenames in os.walk(search_root):
            if name in filenames:
                return os.path.join(dirpath, name)
    return maybe_path


def extract_traced_sources(tag_file, candidates):
    """Pull the hover-trace file's own "dataSources" entries where the traced tool
    already found the tag's shown/connected value tracing back to a URL query
    param or browser storage key - evidence that's a lot stronger than attribute
    name/id matching, when it's present. Not every hover-trace file will have
    this (it's the operator's own tool's output, shape may vary), so this always
    returns a list, possibly empty, never raises.

    Each kept entry also gets "likely_parameter" filled in when the source is a
    URL query string and its key (the "?name" in "where") matches one of this
    request's actual candidate parameters - lets the ranking stage anchor on it
    directly instead of re-deriving it from a "?query" string itself."""
    try:
        with open(tag_file, "r", encoding="utf-8") as fh:
            tag_data = json.load(fh)
    except Exception:
        return []

    keep_kinds = {"URL", "storage"}
    out = []
    for s in tag_data.get("dataSources") or []:
        kind = s.get("sourceKind")
        if kind not in keep_kinds:
            continue
        where = s.get("where") or []
        likely_parameter = None
        if kind == "URL":
            for w in where:
                key = w.lstrip("?") if isinstance(w, str) else None
                if key and key in candidates:
                    likely_parameter = key
                    break
        out.append({
            "source_kind": kind,
            "source": s.get("source"),
            "where": where,
            "value": s.get("value") or s.get("sourceValue"),
            "controllable": s.get("controllable"),
            "change": (s.get("change") or {}).get("detail"),
            "likely_parameter": likely_parameter,
        })
    return out


def process_association(assoc, assoc_data, folder, xml_cache, name, side):
    """One Associations[] entry -> (entry_dict_or_None, skip_reason_or_None)."""
    xml_index_base = assoc_data.get("Xml_index_base", 1)
    xml_index = assoc.get("Xml_index")

    xml_file = resolve_path(folder, assoc_data.get("Xml_File"))
    if not xml_file or not os.path.isfile(xml_file):
        return None, f"xml_index {xml_index}: the XML file this association points to ({assoc_data.get('Xml_File')}) could not be found."

    tag_file = resolve_path(folder, (assoc.get("Input") or {}).get("File"))
    if not tag_file or not os.path.isfile(tag_file):
        return None, f"xml_index {xml_index}: the hover-trace JSON this association points to ({(assoc.get('Input') or {}).get('File')}) could not be found."

    # --- parameter inventory, scoped to this one request index ---
    # The same Xml_File is usually shared by every association in the file - parse
    # it once per file, not once per association.
    if xml_file not in xml_cache:
        xml_cache[xml_file] = param_inventory.parse_xml_file(xml_file)
    items = xml_cache[xml_file]
    target = None
    for it in items:
        if it["index"] + xml_index_base == xml_index:
            target = it
            break
    if target is None:
        return None, f"xml_index {xml_index} (base {xml_index_base}) does not exist in {os.path.basename(xml_file)} ({len(items)} request(s) found)."

    inv = param_inventory.build_inventory([target])["inventory"][0]

    url_param_names = [p["name"] for p in inv["parameters"] if p["source"] == "url_query"]
    body_param_names = [p["name"] for p in inv["parameters"] if p["source"].startswith("body_")]
    all_candidates = url_param_names + body_param_names

    # --- rebuilt tag ---
    try:
        html_tag, dom_attributes = rebuild_tag.process_file(tag_file)
    except Exception as e:
        return None, f"xml_index {xml_index}: rebuild_tag failed on {os.path.basename(tag_file)}: {e}"

    traced_sources = extract_traced_sources(tag_file, all_candidates)

    entry = {
        "name": name,
        "side": side,
        "xml_index": xml_index,
        "burp_index": target["index"],  # 0-based, exactly what lib/burp.js's getRequest expects
        "path": inv["url"],
        "method": inv["method"],
        "attributes": {
            "body_data": bool(inv["attributes"]["has_body_params"] or inv["attributes"]["has_json_params"]),
            "data_type": inv["attributes"]["body_data_type"],
            "url_param": bool(inv["attributes"]["has_url_params"]),
            "body_param": bool(inv["attributes"]["has_body_params"] or inv["attributes"]["has_json_params"]),
        },
        "attribute_names": {
            "url_param": url_param_names,
            "body_param": body_param_names,
        },
        "rebuilt_tag": {
            "html": html_tag,
            "dom_attributes": dom_attributes,
            "traced_sources": traced_sources,
        },
        "_source": {
            "xml_file": xml_file,
            "tag_file": tag_file,
        },
    }
    raw_body = target.get("body") or ""
    entry["body_data_b64"] = (
        base64.b64encode(raw_body.encode("utf-8")).decode("ascii") if raw_body.strip() else None
    )
    return entry, None


def process_item(category, wstg_id, name, side, project_root):
    """Returns (entries_list_or_None, item_skip_reason_or_None, per_association_skips)."""
    folder = find_wstg_folder(project_root, wstg_id)
    if not folder:
        return None, f"No {wstg_id} folder found in this project.", []

    assoc_path = find_master_associations(folder)
    if not assoc_path:
        return None, f"No master_associations.json found under {wstg_id}'s folder yet.", []

    try:
        with open(assoc_path, "r", encoding="utf-8") as fh:
            assoc_data = json.load(fh)
    except Exception as e:
        return None, f"Could not read master_associations.json: {e}", []

    associations = assoc_data.get("Associations") or []
    if not associations:
        return None, "master_associations.json has no entries in its Associations array.", []

    xml_cache = {}
    entries, sub_skipped = [], []
    for assoc in associations:
        entry, reason = process_association(assoc, assoc_data, folder, xml_cache, name, side)
        if reason:
            sub_skipped.append({"xml_index": assoc.get("Xml_index"), "reason": reason})
        else:
            entry["_source"]["master_associations"] = assoc_path
            entries.append(entry)

    if not entries:
        return None, "None of this item's associations could be processed.", sub_skipped
    return entries, None, sub_skipped


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Correlate parameter inventory + rebuilt tag per in-scope WSTG item.")
    parser.add_argument("--router", required=True, help="Path to injection_router.json")
    parser.add_argument("--project-root", required=True, help="Project root to scan for WSTG item folders")
    parser.add_argument("--output", "-o", default=None, help="Where to write the result JSON (default: stdout)")
    args = parser.parse_args()

    router = load_router(args.router)

    categories = {}
    skipped = []

    for side_key, side_label in (("Client_Side", "client"), ("Server_Side", "server")):
        for item in router.get(side_key, []):
            missing = [k for k in ("category", "wstg_id", "name") if k not in item]
            if missing:
                skipped.append({
                    "wstg_id": item.get("wstg_id", "?"), "category": item.get("category"),
                    "reason": f"router entry is missing {', '.join(missing)} - orchestrator.py would accept this (it only needs wstg_id), but param_mapper.py needs all three.",
                })
                continue
            category, wstg_id, name = item["category"], item["wstg_id"], item["name"]

            entries, reason, sub_skipped = process_item(category, wstg_id, name, side_label, args.project_root)
            if reason:
                skipped.append({"wstg_id": wstg_id, "category": category, "reason": reason})
                continue

            categories.setdefault(category, {})[wstg_id] = entries
            if sub_skipped:
                skipped.append({"wstg_id": wstg_id, "category": category, "partial": True, "associations": sub_skipped})

    result = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "router_source": os.path.abspath(args.router),
        "project_root": os.path.abspath(args.project_root),
        "categories": categories,
        "skipped": skipped,
    }

    output = json.dumps(result, indent=2)
    total_associations = sum(len(v) for items in categories.values() for v in items.values())
    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"[*] Mapped {total_associations} association(s) across {sum(len(v) for v in categories.values())} item(s), skipped {len(skipped)}. Written to: {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
