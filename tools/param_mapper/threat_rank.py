#!/usr/bin/env python3
"""
threat_rank.py — the AI ranking stage, reading param_mapper.py's output.

For each WSTG item in param_map.json that has candidate parameters, asks a local
LLM (via Ollama's HTTP API - http://localhost:11434 by default) which candidate
parameter most likely corresponds to the traced HTML tag for that endpoint, and
writes the ranking into that item's own Outputs/test_outputs/ folder.

Deliberately narrow task for the model: NAME-MATCHING, not vulnerability judgment.
It is given (A) the parameter names found on the request and (B) the traced tag's
attributes, and is told (C, the fixed system prompt below) to rank candidates by
how well their name corresponds to the tag - nothing about exploitability, payload
selection, or security impact. See SYSTEM_PROMPT below; don't loosen it without
good reason - it's what keeps this a correlation tool instead of a "find a vuln"
tool.

Output is forced JSON (a JSON Schema passed to Ollama's "format" field, supported
by Ollama >= 0.5). Every parameter name the model returns is checked against the
actual candidate list - a model that invents a parameter that doesn't exist on the
request gets that entry silently dropped, never trusted blind.

Usage:
    python3 threat_rank.py --map param_map.json --project-root /path/to/project \
        [--ollama-url http://localhost:11434] [--model qwen2.5:7b-instruct]
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

_WSTG_DIR_RE = re.compile(r"^(WSTG-[A-Z]+-\d+)(?:_.*)?$")

# ---------------------------------------------------------------------------
# The fixed "C" context - a narrow, name-matching-only instruction. This is the
# whole safety boundary for this feature: it is a string-similarity judge, not
# a vulnerability finder.
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = (
    "You are a narrow string-matching assistant for a web security audit tool. "
    "You are given: (1) a list of parameter names found on one HTTP request, (2) "
    "the name/id/type attributes of one HTML input tag that was traced on the page "
    "for this same endpoint, and (3) optionally, a list of traced data sources - "
    "cases where a separate tool already found that this tag's shown or connected "
    "value traces back to a specific URL query parameter or browser storage key. "
    "Your only job is to decide which parameter name, if any, most closely "
    "corresponds to that tag. Prefer (3) over (2) when it is present and its "
    "'likely_parameter' field is filled in - a traced data source showing the "
    "tag's value is identical to a URL parameter's value is stronger evidence than "
    "attribute name/id similarity, and should usually outrank a same-tag guess "
    "based on name alone. Fall back to (2) - name/id similarity and structural "
    "correspondence (for example, a tag with name=\"email\" matching a parameter "
    "named email or user_email) - only when (3) is empty or doesn't point at an "
    "actual candidate. Rank every candidate parameter from most to least likely to "
    "be the one driven by this tag, and give a one-sentence reason for each ranking "
    "that cites the actual evidence used (the traced source or the name/id "
    "comparison). Do not evaluate security impact, suggest payloads, or discuss "
    "exploitation - that is out of scope for you. If no candidate parameter has any "
    "plausible relationship to the tag from either source, rank them all low/none "
    "rather than guessing a favorite."
)

RANKING_SCHEMA = {
    "type": "object",
    "properties": {
        "best_match": {"type": ["string", "null"]},
        "ranked_parameters": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "parameter": {"type": "string"},
                    "rank": {"type": "integer"},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low", "none"]},
                    "reason": {"type": "string"},
                },
                "required": ["parameter", "rank", "confidence", "reason"],
            },
        },
    },
    "required": ["ranked_parameters"],
}


def find_wstg_folder(project_root, wstg_id):
    for dirpath, dirnames, _filenames in os.walk(project_root):
        for d in list(dirnames):
            m = _WSTG_DIR_RE.match(d)
            if m and m.group(1) == wstg_id:
                return os.path.join(dirpath, d)
    return None


def build_messages(entry):
    candidates = entry["attribute_names"]["url_param"] + entry["attribute_names"]["body_param"]
    tag_attrs = entry["rebuilt_tag"]["dom_attributes"]
    traced_sources = entry["rebuilt_tag"].get("traced_sources") or []

    sources_block = (
        f"Traced data sources for this tag (independently found - treat as the "
        f"stronger signal when 'likely_parameter' is filled in):\n"
        f"{json.dumps(traced_sources, indent=2)}\n\n"
        if traced_sources else
        "Traced data sources for this tag: none recorded - use the tag attributes below.\n\n"
    )

    user_content = (
        f"Endpoint: {entry['method']} {entry['path']}\n\n"
        f"Candidate parameter names found on this request:\n"
        f"{json.dumps(candidates, indent=2)}\n\n"
        f"{sources_block}"
        f"Traced HTML tag for this endpoint:\n"
        f"{entry['rebuilt_tag']['html']}\n\n"
        f"Tag attributes:\n"
        f"{json.dumps(tag_attrs, indent=2)}\n\n"
        f"Rank every candidate parameter above by how well it corresponds to this tag."
    )
    return candidates, [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]


def call_ollama(base_url, model, messages, timeout=120):
    body = json.dumps({
        "model": model,
        "messages": messages,
        "format": RANKING_SCHEMA,
        "stream": False,
        "options": {"temperature": 0},
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/api/chat", data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    return payload["message"]["content"]


def rank_entry(base_url, model, entry):
    """Returns (result_dict_or_None, reason_if_skipped)."""
    candidates, messages = build_messages(entry)
    if not candidates:
        return None, "No candidate parameters for this endpoint (nothing to rank)."

    try:
        raw = call_ollama(base_url, model, messages)
    except urllib.error.URLError as e:
        return None, f"Could not reach the local model server at {base_url}: {e}"
    except Exception as e:
        return None, f"Local model call failed: {e}"

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None, "The model's response was not valid JSON (even with a forced schema)."

    ranked = parsed.get("ranked_parameters") or []
    # Trust nothing: drop any "parameter" the model invented that isn't an actual
    # candidate, then re-number ranks so there are no gaps left by the drop.
    valid = [r for r in ranked if r.get("parameter") in candidates]
    dropped = [r.get("parameter") for r in ranked if r.get("parameter") not in candidates]
    valid.sort(key=lambda r: r.get("rank", 999))
    for i, r in enumerate(valid, start=1):
        r["rank"] = i

    best_match = parsed.get("best_match")
    if best_match not in candidates:
        best_match = valid[0]["parameter"] if valid else None

    result = {
        "best_match": best_match,
        "ranked_parameters": valid,
    }
    if dropped:
        result["_dropped_hallucinated"] = dropped
    return result, None


def render_markdown(wstg_id, items):
    lines = [f"# {wstg_id} — Threat Model (parameter ranking)", "", f"**Generated:** {datetime.now(timezone.utc).isoformat()}  ", ""]
    for it in items:
        ep = it["endpoint"]
        lines.append(f"## xml_index {ep['xml_index']} — `{ep['method']} {ep['path']}`")
        lines.append(f"**Best match:** `{it['best_match']}`" if it["best_match"] else "**Best match:** none")
        lines.append("")
        lines.append("| Rank | Parameter | Confidence | Reason |")
        lines.append("|------|-----------|------------|--------|")
        for r in it["ranked_parameters"]:
            lines.append(f"| {r['rank']} | `{r['parameter']}` | {r['confidence']} | {r['reason']} |")
        if it.get("_dropped_hallucinated"):
            lines.append("")
            lines.append(f"_Dropped (not an actual candidate on this request): {', '.join(it['_dropped_hallucinated'])}_")
        lines.append("")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Rank candidate parameters per WSTG item using a local LLM.")
    parser.add_argument("--map", required=True, help="Path to param_map.json (param_mapper.py's output)")
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    parser.add_argument("--model", default="qwen2.5:7b-instruct")
    args = parser.parse_args()

    with open(args.map, "r", encoding="utf-8") as fh:
        param_map = json.load(fh)

    written, skipped = [], []

    for category, wstg_items in param_map.get("categories", {}).items():
        for wstg_id, entries in wstg_items.items():
            folder = find_wstg_folder(args.project_root, wstg_id)
            if not folder:
                skipped.append({"wstg_id": wstg_id, "reason": "No WSTG folder found to write Threat_Model.json into."})
                continue

            ranked_items, item_skipped = [], []
            for entry in entries:
                result, reason = rank_entry(args.ollama_url, args.model, entry)
                if reason:
                    item_skipped.append({"xml_index": entry["xml_index"], "reason": reason})
                    continue
                ranked_items.append({
                    "endpoint": {"method": entry["method"], "path": entry["path"],
                                 "xml_index": entry["xml_index"], "burp_index": entry["burp_index"]},
                    "xml_file": entry["_source"]["xml_file"],
                    **result,
                })

            if not ranked_items:
                skipped.append({"wstg_id": wstg_id, "reason": "No association could be ranked.", "associations": item_skipped})
                continue

            out_dir = os.path.join(folder, "Outputs", "test_outputs")
            os.makedirs(out_dir, exist_ok=True)
            json_file = os.path.join(out_dir, "Threat_Model.json")
            md_file = os.path.join(out_dir, "Threat_Model.md")

            full = {
                "wstg_id": wstg_id,
                "category": category,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "model": args.model,
                "items": ranked_items,
            }
            if item_skipped:
                full["skipped_associations"] = item_skipped
            with open(f"{json_file}.tmp", "w", encoding="utf-8") as fh:
                json.dump(full, fh, indent=2)
            os.replace(f"{json_file}.tmp", json_file)
            with open(f"{md_file}.tmp", "w", encoding="utf-8") as fh:
                fh.write(render_markdown(wstg_id, ranked_items))
            os.replace(f"{md_file}.tmp", md_file)

            written.append({"wstg_id": wstg_id, "ranked": len(ranked_items), "skipped": len(item_skipped), "json": json_file})

    print(json.dumps({"written": written, "skipped": skipped}, indent=2))


if __name__ == "__main__":
    main()
