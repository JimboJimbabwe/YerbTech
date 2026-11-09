#!/usr/bin/env python3
"""
server_side_orchestrator.py  (renamed/reworked from wstg_wordlist.py)

Generates WAF-smuggling payload wordlists for the project's server-side WSTG items.
A single, self-contained script - unlike the client-side pipeline (shuttle_gen /
rebuild_tag / tag_combine), there's only one stage here: base commands in x waf
character insertion = a wordlist, one file per WSTG item.

Three data files, all read-only (this script never writes any of them):

  injection_router.json      Which WSTG items are "Server_Side", and - this is the piece
                              the original script got wrong by hardcoding a single
                              "07_Injection" folder for everything - each item's own
                              category folder, since not every server-side item actually
                              lives under 07_Injection (WSTG-INPV-19/SSRF does not).
  server_side_inj.json       Base commands per WSTG ID (the "config"). Hand-written,
                              not generated here.
  waf_items.json             WAF-smuggling character/string libraries by category.
  server_side_waf_map.json   The routing key this script added: which waf_items.json
                              category each WSTG ID's commands get smuggled with.

A WSTG item only gets a wordlist if it appears in ALL of: the router's Server_Side list,
server_side_inj.json (by the same ID), and server_side_waf_map.json (by the same ID).
A mismatch between any two files' spelling of an ID is reported as a skipped item with a
clear reason, not a crash - fix the spelling in whichever file is wrong and it starts
working. (2026-11-08: fixed one such mismatch - server_side_inj.json had spelled the SSRF
item WSTG-INPV-19 where the router and the waf map both use WSTG-INJT-19 - and added
WSTG-INJT-07/11/13 entries, which previously existed in neither file. WSTG-ERRH-01/02
still intentionally have no entries here: Error Handling is "provoke a verbose error",
not "inject a command past a WAF", so it doesn't fit this script's model - left skipping
with its current clear reason pending a decision on how those two should be generated.)

Output: <project>/WSTG_Repository/<category>/<wstg_id>/Outputs/test_outputs/<wstg_id>_WL.txt

Usage:
  python server_side_orchestrator.py --project-root /path/to/Projects/MyProject

Test mode (bypasses project routing, dumps into CWD):
  python server_side_orchestrator.py --test-full-run --server-side-cfg server_side_inj.json \
      --waf-chars waf_items.json --waf-map server_side_waf_map.json
"""

import argparse
import json
import random
import sys
from pathlib import Path


DEFAULT_MAX_LINES    = 800
DEFAULT_MAX_POS_PAIRS = 3
DEFAULT_WAF_PER_CAT   = 3
MIN_GAP               = 4  # positions must be >=4 chars apart


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def load_json(path: Path, label: str) -> dict:
    if not path.is_file():
        sys.exit(f"[FATAL] {label} not found: {path}")
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        sys.exit(f"[FATAL] {label} is not valid JSON ({path}): {exc}")


def flatten_config_payloads(block) -> list:
    """Flatten a config block into a list of plain strings."""
    out = []

    def add(v):
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, list):
            for item in v:
                add(item)
        elif isinstance(v, dict):
            for k, val in v.items():
                out.append(f"{k}={val}")
        else:
            out.append(str(v))

    if "typologies" in block:
        for typ in block["typologies"].values():
            if "commands" in typ:
                for entry in typ["commands"]:
                    add(entry.get("command"))
            elif "command" in typ:
                add(typ["command"])
    elif "commands" in block:
        for entry in block["commands"]:
            add(entry.get("command"))
    elif "command" in block:
        add(block["command"])
    return out


def valid_position_pairs(payload: str) -> list:
    """All (pos_a, pos_b) with pos_b - pos_a >= MIN_GAP, both inside payload."""
    n = len(payload)
    pairs = []
    for a in range(n):
        for b in range(a + MIN_GAP, n):
            pairs.append((a, b))
    return pairs


def pick_waf_strings(waf_chars: dict, waf_key: str, waf_per_cat: int) -> list:
    """All items from the one WAF category this WSTG ID is routed to."""
    items = waf_chars.get(waf_key) or []
    if not items:
        return []
    take = min(waf_per_cat, len(items))
    return random.sample(items, take)


def build_variant(payload: str, pos_a: int, pos_b: int, waf: str) -> str:
    """Insert the SAME waf string at both positions."""
    return payload[:pos_a] + waf + payload[pos_a:pos_b] + waf + payload[pos_b:]


def generate_variants(base_payloads: list, waf_strings: list, max_pos_pairs: int) -> list:
    """For each payload x WAF string, generate up to max_pos_pairs variants."""
    variants = []
    for payload in base_payloads:
        pairs = valid_position_pairs(payload)
        if not pairs:
            continue
        for waf in waf_strings:
            sample = random.sample(pairs, min(max_pos_pairs, len(pairs)))
            for (a, b) in sample:
                variants.append(build_variant(payload, a, b, waf))
    return variants


def dedup_preserve(seq: list) -> list:
    seen = set()
    out = []
    for s in seq:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


# ---------------------------------------------------------------------------
# Routing: join the router's Server_Side list against the waf map and the cfg
# ---------------------------------------------------------------------------
def planned_items(router: dict, waf_map: dict, cfg: dict, wanted_ids=None):
    """Returns (plan, skipped). plan: list of (wstg_id, category, name, waf_key).
    skipped: list of (wstg_id, reason) for anything in the router that didn't make it.
    """
    entries = router.get("Server_Side") or []
    plan, skipped = [], []
    seen_ids = set()
    for e in entries:
        wstg_id = e.get("wstg_id")
        if not wstg_id:
            continue
        seen_ids.add(wstg_id)
        if wanted_ids and wstg_id not in wanted_ids:
            continue
        waf_key = waf_map.get(wstg_id)
        if waf_key is None:
            skipped.append((wstg_id, f"not in server_side_waf_map.json (routing key missing)"))
            continue
        if wstg_id not in cfg:
            skipped.append((wstg_id, f"not in server_side_inj.json (checked for the ID '{wstg_id}' "
                                      f"exactly as injection_router.json spells it - if server_side_inj.json "
                                      f"uses a different ID for this item, that's a mismatch between the two "
                                      f"files to fix, not something this script should guess around)"))
            continue
        plan.append((wstg_id, e.get("category"), e.get("name", wstg_id), waf_key))
    if wanted_ids:
        for wstg_id in wanted_ids:
            if wstg_id not in seen_ids:
                skipped.append((wstg_id, "not in injection_router.json's Server_Side list"))
    return plan, skipped


# ---------------------------------------------------------------------------
# Pre-flight orientation
# ---------------------------------------------------------------------------
def preflight(project_root: Path, plan: list, waf: dict, create_wordlists: bool = True) -> list:
    if not project_root.is_dir():
        sys.exit(f"[FATAL] --project-root does not exist: {project_root}")
    repo = project_root / "WSTG_Repository"
    if not repo.is_dir():
        sys.exit(f"[FATAL] WSTG_Repository not found under --project-root: {repo}")

    results = []
    for wstg_id, category, name, waf_key in plan:
        id_dir = repo / category / wstg_id
        wl_dir = id_dir / "Outputs" / "test_outputs"
        wl_file = wl_dir / f"{wstg_id}_WL.txt"

        status = []
        if not id_dir.is_dir():
            results.append((wstg_id, category, name, waf_key, None,
                            f"folder missing: {id_dir} (check the category in injection_router.json)"))
            continue
        status.append("ID_DIR=OK")

        if not wl_dir.is_dir():
            if create_wordlists:
                wl_dir.mkdir(parents=True, exist_ok=True)
                status.append("OUTPUTS=CREATED")
            else:
                results.append((wstg_id, category, name, waf_key, None, f"Outputs/test_outputs missing: {wl_dir}"))
                continue
        else:
            status.append("OUTPUTS=OK")

        if waf_key not in waf:
            results.append((wstg_id, category, name, waf_key, None,
                            f"waf_items.json has no '{waf_key}' category"))
            continue
        status.append("WAF=OK")

        results.append((wstg_id, category, name, waf_key, wl_file, ",".join(status)))
    return results


# ---------------------------------------------------------------------------
# Test full run: one file per attack type, uncapped, into CWD (or given dir)
# ---------------------------------------------------------------------------
def run_test_full(plan: list, cfg: dict, waf: dict, out_dir: Path, dry_run: bool,
                  cap: int, max_pos_pairs: int, waf_per_cat: int) -> list:
    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    print(f"\n=== Test Full Run ({'uncapped' if cap == 0 else f'cap={cap}'}) ===")
    for wstg_id, category, name, waf_key in plan:
        base = flatten_config_payloads(cfg[wstg_id])
        waf_strings = pick_waf_strings(waf, waf_key, waf_per_cat)

        variants = []
        for payload in base:
            pairs = valid_position_pairs(payload)
            for waf_s in waf_strings:
                for (a, b) in pairs:
                    variants.append(build_variant(payload, a, b, waf_s))

        truncated = False
        if cap and len(base) + len(variants) > cap:
            budget = max(0, cap - len(base))
            random.shuffle(variants)
            variants = variants[:budget]
            truncated = True

        final = dedup_preserve(base + variants)
        if cap and len(final) > cap:
            final = final[:cap]
            truncated = True

        content = "\n".join(final) + "\n"
        n_bytes = len(content.encode("utf-8"))

        out_file = out_dir / f"{wstg_id}.txt"
        if not dry_run:
            out_file.write_text(content, encoding="utf-8")

        summary.append({"wstg_id": wstg_id, "base": len(base), "waf_strings": len(waf_strings),
                        "variants": len(variants), "final": len(final), "bytes": n_bytes,
                        "truncated": truncated, "path": str(out_file)})
        print(f"  {wstg_id:<16} base={len(base):<3} waf={len(waf_strings):<3} "
              f"variants={len(variants):<6} final={len(final):<6} bytes={n_bytes:<8} "
              f"{'TRUNCATED' if truncated else ''} -> {out_file}")
    return summary


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Generate WSTG WAF-smuggling wordlists for server-side items.")
    ap.add_argument("--project-root", type=Path, default=None,
                    help="Required unless --test-full-run.")
    ap.add_argument("--router", type=Path, default=None,
                    help="injection_router.json (default: <project-root>/Settings/Configurations/Utilities/JSON/injection_router.json)")
    ap.add_argument("--server-side-cfg", type=Path, default=None, dest="cfg_path",
                    help="server_side_inj.json (default: alongside --router)")
    ap.add_argument("--waf-chars", type=Path, default=None, dest="waf_path",
                    help="waf_items.json (default: alongside --router)")
    ap.add_argument("--waf-map", type=Path, default=None, dest="waf_map_path",
                    help="server_side_waf_map.json (default: alongside --router)")
    ap.add_argument("--wstg", nargs="+", default=None,
                    help="One or more WSTG IDs (default: every item the router/map/cfg all agree on).")
    ap.add_argument("--max-lines", type=int, default=DEFAULT_MAX_LINES, dest="max_lines")
    ap.add_argument("--max-pos-pairs", type=int, default=DEFAULT_MAX_POS_PAIRS, dest="max_pos_pairs")
    ap.add_argument("--waf-per-cat", type=int, default=DEFAULT_WAF_PER_CAT, dest="waf_per_cat")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-create", action="store_true",
                    help="Fail instead of creating a missing Outputs/test_outputs folder.")
    ap.add_argument("--test-full-run", action="store_true", dest="test_full_run",
                    help="Bypass project routing; dump one uncapped file per WSTG ID into the working directory.")
    ap.add_argument("--test-full-run-dir", type=Path, default=Path.cwd(), dest="test_full_run_dir")
    ap.add_argument("--test-cap", type=int, default=0, dest="test_cap")
    args = ap.parse_args()

    if args.test_full_run:
        if not (args.cfg_path and args.waf_path and args.waf_map_path and args.router):
            ap.error("--test-full-run needs --router, --server-side-cfg, --waf-chars and --waf-map")
        router = load_json(args.router, "injection_router.json")
        cfg = load_json(args.cfg_path, "server_side_inj.json")
        waf = load_json(args.waf_path, "waf_items.json")
        waf_map = load_json(args.waf_map_path, "server_side_waf_map.json")
        waf_map = {k: v for k, v in waf_map.items() if not k.startswith("_")}
        plan, skipped = planned_items(router, waf_map, cfg, set(args.wstg) if args.wstg else None)
        for wstg_id, reason in skipped:
            print(f"[-] {wstg_id}: skipped ({reason})")
        if not plan:
            sys.exit("[FATAL] nothing to do: no WSTG ID is in the router, the waf map and the cfg all at once")
        run_test_full(plan, cfg, waf, args.test_full_run_dir, args.dry_run, args.test_cap,
                      args.max_pos_pairs, args.waf_per_cat)
        if args.dry_run:
            print("\n[DRY-RUN] No files written.")
        return 0

    if not args.project_root:
        ap.error("--project-root is required unless --test-full-run is set.")
    settings_json = args.project_root / "Settings" / "Configurations" / "Utilities" / "JSON"
    router_path = args.router or settings_json / "injection_router.json"
    cfg_path = args.cfg_path or settings_json / "server_side_inj.json"
    waf_path = args.waf_path or settings_json / "waf_items.json"
    waf_map_path = args.waf_map_path or settings_json / "server_side_waf_map.json"

    router = load_json(router_path, "injection_router.json")
    cfg = load_json(cfg_path, "server_side_inj.json")
    waf = load_json(waf_path, "waf_items.json")
    waf_map = load_json(waf_map_path, "server_side_waf_map.json")
    waf_map = {k: v for k, v in waf_map.items() if not k.startswith("_")}

    plan, skipped = planned_items(router, waf_map, cfg, set(args.wstg) if args.wstg else None)
    for wstg_id, reason in skipped:
        print(f"[-] {wstg_id}: skipped ({reason})")
    if not plan:
        print("[FATAL] nothing to do: no WSTG ID is in the router, the waf map and the cfg all at once", file=sys.stderr)
        return 1

    orient = preflight(args.project_root, plan, waf, create_wordlists=not args.no_create)

    print("\n=== Pre-flight ===")
    ok_rows = []
    for wstg_id, category, name, waf_key, wl_file, status in orient:
        print(f"  {wstg_id:<16} {category:<20} {status}")
        if wl_file is None:
            print(f"        SKIPPED")
        else:
            print(f"        -> {wl_file}")
            ok_rows.append((wstg_id, category, name, waf_key, wl_file))

    print("\n=== Generation ===")
    summary = []
    for wstg_id, category, name, waf_key, wl_file in ok_rows:
        base = flatten_config_payloads(cfg[wstg_id])
        waf_strings = pick_waf_strings(waf, waf_key, args.waf_per_cat)
        variants = generate_variants(base, waf_strings, args.max_pos_pairs)

        budget = args.max_lines - len(base)
        truncated = False
        if len(variants) > budget:
            random.shuffle(variants)
            variants = variants[:max(0, budget)]
            truncated = True

        final = dedup_preserve(base + variants)
        if len(final) > args.max_lines:
            final = final[:args.max_lines]
            truncated = True

        content = "\n".join(final) + "\n"
        n_bytes = len(content.encode("utf-8"))

        if not args.dry_run:
            wl_file.write_text(content, encoding="utf-8")

        summary.append({"wstg_id": wstg_id, "category": category, "base": len(base),
                        "waf_strings": len(waf_strings), "variants": len(variants),
                        "final": len(final), "bytes": n_bytes, "truncated": truncated, "path": str(wl_file)})

        print(f"  {wstg_id:<16} {category:<20} base={len(base):<3} waf={len(waf_strings):<3} "
              f"variants={len(variants):<4} final={len(final):<4} bytes={n_bytes:<6} "
              f"{'TRUNCATED' if truncated else ''}")
        print(f"        -> {wl_file}")

    if args.dry_run:
        print("\n[DRY-RUN] No files written.")
    else:
        print(f"\nWrote {len(summary)} wordlist(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
