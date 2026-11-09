#!/usr/bin/env python3
"""
orchestrator.py

Drives shuttle_gen.py (script 1), rebuild_tag.py (script 2) and tag_combine.py (script 3)
across every WSTG item on one side ("Client_Side" by default) of injection_router.json,
using the paths already resolved in mouse_tool.json. Nothing here invents a path rule;
both JSON files are read as data and only their fields are trusted.

Flow, three full passes (not interleaved per item - this matches how the operator wants
to watch it run):

  Phase 1: for every WSTG item, for every Associations[] entry, for Input and Output (when
           present and the source file exists), run shuttle_gen.py --single-file -> a
           deduped, capped wordlist.
  Phase 2: same iteration, run rebuild_tag.py on the same source file with the one --split
           string reused everywhere -> a tag_start/tag_end split.
  Phase 3: for every (Input|Output) job where BOTH phase 1 and phase 2 succeeded, run
           tag_combine.py to pair that wordlist with that tag-split - never crossing Input
           with Output, never crossing two different association entries (see the TODO in
           tag_combine.py; that pairing rule is enforced here, by construction, since each
           job only ever carries its own wordlist and its own tag-split path).

File names (all written into the association's own Master_Folder, i.e. the item's
Outputs/test_outputs folder):

  {xml_index}_wordlist_SFCi{N}.txt / SFCo{N}.txt    (phase 1, shuttle_gen's own naming)
  {xml_index}_tagsplit_SFCi{N}.json / SFCo{N}.json  (phase 2)
  {xml_index}_tagged_SFCi{N}.txt / SFCo{N}.txt       (phase 3, the final deliverable)

Nothing is run through a shell; every subprocess call is an explicit argument list.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ID_RE_FRAGMENT = r"WSTG-[A-Z]{3,5}-\d{2}"
DEFAULT_CAP_PERCENT = 10


# ----------------------------------------------------------------------
# mouse_tool.json resolution (same safety rule as the Node side: lib/mouse.js)
# ----------------------------------------------------------------------

def load_json(path: Path, label: str) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"[!] {label} not found: {path}")
    except json.JSONDecodeError as e:
        raise SystemExit(f"[!] {label} is not valid JSON: {e}")


def inside(repo_dir: Path, rel: str, label: str) -> Path:
    """Join a relative path from mouse_tool.json onto the repo, refusing anything that escapes it."""
    if not isinstance(rel, str) or not rel.strip():
        raise SystemExit(f"[!] {label} is empty in mouse_tool.json")
    if rel.startswith("/") or rel.startswith("\\") or (len(rel) > 1 and rel[1] == ":"):
        raise SystemExit(f"[!] {label} must be a relative path, got: {rel}")
    abs_path = (repo_dir / rel).resolve()
    try:
        abs_path.relative_to(repo_dir.resolve())
    except ValueError:
        raise SystemExit(f"[!] {label} points outside the project: {rel}")
    return abs_path


@dataclass
class Target:
    wstg_id: str
    input_folder: Path
    output_folder: Path
    xml_path: Path
    master_folder: Path
    master_file: Path


def resolve_targets(project_root: Path, mouse_config: dict, wstg_ids: list[str]) -> dict[str, Target]:
    repo = project_root / "WSTG_Repository"
    targets = mouse_config.get("Targets")
    if not isinstance(targets, dict):
        raise SystemExit('[!] mouse_tool.json needs a "Targets" object')
    out = {}
    for wstg_id in wstg_ids:
        t = targets.get(wstg_id)
        if t is None:
            print(f"[-] {wstg_id} is in the router but not in mouse_tool.json - skipped")
            continue
        master_folder = inside(repo, t.get("Master_Folder", ""), f"{wstg_id}.Master_Folder")
        out[wstg_id] = Target(
            wstg_id=wstg_id,
            input_folder=inside(repo, t.get("Input_Folder", ""), f"{wstg_id}.Input_Folder"),
            output_folder=inside(repo, t.get("Output_Folder", ""), f"{wstg_id}.Output_Folder"),
            xml_path=inside(repo, t.get("XML_Path", ""), f"{wstg_id}.XML_Path"),
            master_folder=master_folder,
            master_file=master_folder / f"{wstg_id}_association.json",
        )
    return out


def router_wstg_ids(router: dict, side: str) -> list[str]:
    entries = router.get(side) or []
    return [e["wstg_id"] for e in entries if isinstance(e, dict) and e.get("wstg_id")]


# ----------------------------------------------------------------------
# Jobs: one per (association entry, Input|Output) pair with a real source file
# ----------------------------------------------------------------------

@dataclass
class Job:
    wstg_id: str
    xml_index: object
    side_key: str       # "Input" or "Output"
    prefix: str          # "SFCi" or "SFCo"
    num: object
    source_file: Path
    folder: Path         # Master_Folder - where phase outputs land
    wordlist_path: Path = field(init=False)
    tagsplit_path: Path = field(init=False)
    tagged_path: Path = field(init=False)
    wordlist_ok: bool = False
    tagsplit_ok: bool = False
    tagged_ok: bool = False

    def __post_init__(self):
        self.wordlist_path = self.folder / f"{self.xml_index}_wordlist_{self.prefix}{self.num}.txt"
        self.tagsplit_path = self.folder / f"{self.xml_index}_tagsplit_{self.prefix}{self.num}.json"
        self.tagged_path = self.folder / f"{self.xml_index}_tagged_{self.prefix}{self.num}.txt"


def build_jobs(targets: dict[str, Target]) -> list[Job]:
    jobs = []
    for wstg_id, t in targets.items():
        if not t.master_file.is_file():
            print(f"[-] {wstg_id}: no association file yet ({t.master_file.name}) - skipped")
            continue
        assoc_doc = load_json(t.master_file, f"{wstg_id} master association file")
        associations = assoc_doc.get("Associations") or []
        if not associations:
            print(f"[-] {wstg_id}: association file has no Associations - skipped")
            continue
        for assoc in associations:
            xml_index = assoc.get("Xml_index")
            if xml_index is None:
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
                    print(f"[!] {wstg_id} xml#{xml_index} {side_key}: file missing, skipped: {src}")
                    continue
                jobs.append(Job(wstg_id, xml_index, side_key, prefix, num, src, t.master_folder))
    return jobs


# ----------------------------------------------------------------------
# Subprocess helper - argument list only, never a shell
# ----------------------------------------------------------------------

def run(python: str, script: Path, args: list[str], label: str) -> bool:
    cmd = [python, str(script), *args]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout).strip().splitlines()
        reason = tail[-1] if tail else f"exit code {proc.returncode}"
        print(f"    [!] {label} failed: {reason}")
        return False
    return True


# ----------------------------------------------------------------------
# Phases
# ----------------------------------------------------------------------

def phase1_shuttle_gen(jobs: list[Job], python: str, scripts_dir: Path, cap_percent: float, dry_run: bool):
    print(f"\n=== Phase 1: shuttle_gen ({len(jobs)} job(s)) ===")
    script = scripts_dir / "shuttle_gen.py"
    for j in jobs:
        label = f"{j.wstg_id} xml#{j.xml_index} {j.side_key}"
        if dry_run:
            print(f"    [dry] shuttle_gen <- {j.source_file} -> {j.wordlist_path.name}")
            j.wordlist_ok = True
            continue
        ok = run(python, script, [
            "--single-file", str(j.source_file),
            "--out", str(j.wordlist_path),
            "--cap-percent", str(cap_percent),
        ], f"{label} shuttle_gen")
        j.wordlist_ok = ok
        print(f"    {'[✓]' if ok else '[ ]'} {label}: {j.wordlist_path.name}")


def phase2_rebuild_tag(jobs: list[Job], python: str, scripts_dir: Path, split_value: str, dry_run: bool):
    print(f"\n=== Phase 2: rebuild_tag ({len(jobs)} job(s)) ===")
    script = scripts_dir / "rebuild_tag.py"
    for j in jobs:
        label = f"{j.wstg_id} xml#{j.xml_index} {j.side_key}"
        if dry_run:
            print(f"    [dry] rebuild_tag <- {j.source_file} --split {split_value!r} -> {j.tagsplit_path.name}")
            j.tagsplit_ok = True
            continue
        ok = run(python, script, [
            str(j.source_file),
            "--split", split_value,
            "--index", str(j.xml_index),
            "--output", str(j.tagsplit_path),
        ], f"{label} rebuild_tag")
        j.tagsplit_ok = ok
        print(f"    {'[✓]' if ok else '[ ]'} {label}: {j.tagsplit_path.name}")


def phase3_tag_combine(jobs: list[Job], python: str, scripts_dir: Path, dry_run: bool):
    ready = [j for j in jobs if j.wordlist_ok and j.tagsplit_ok]
    print(f"\n=== Phase 3: tag_combine ({len(ready)} of {len(jobs)} job(s) ready) ===")
    script = scripts_dir / "tag_combine.py"
    for j in ready:
        label = f"{j.wstg_id} xml#{j.xml_index} {j.side_key}"
        # Every job pairs its own wordlist with its own tag-split - same source file, same
        # Input-or-Output side - never another job's. See the TODO in tag_combine.py.
        if dry_run:
            print(f"    [dry] tag_combine {j.wordlist_path.name} + {j.tagsplit_path.name} -> {j.tagged_path.name}")
            j.tagged_ok = True
            continue
        ok = run(python, script, [
            "--wordlist", str(j.wordlist_path),
            "--tagsplit", str(j.tagsplit_path),
            "--output", str(j.tagged_path),
        ], f"{label} tag_combine")
        j.tagged_ok = ok
        print(f"    {'[✓]' if ok else '[ ]'} {label}: {j.tagged_path.name}")


def summarize(jobs: list[Job]):
    print("\n=== Summary ===")
    by_wstg: dict[str, list[Job]] = {}
    for j in jobs:
        by_wstg.setdefault(j.wstg_id, []).append(j)
    for wstg_id, js in by_wstg.items():
        tagged = sum(1 for j in js if j.tagged_ok)
        print(f"  {wstg_id}: {len(js)} job(s), {tagged} tagged file(s) written")
    total = len(jobs)
    tagged_total = sum(1 for j in jobs if j.tagged_ok)
    print(f"  TOTAL: {total} job(s), {tagged_total} tagged file(s) written")


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Drive shuttle_gen / rebuild_tag / tag_combine across a project's WSTG items.")
    ap.add_argument("--project-root", required=True, help="Absolute path to the project folder (holds WSTG_Repository, Settings, ...).")
    ap.add_argument("--router", default=None, help="Path to injection_router.json (default: <project-root>/Settings/Configurations/Utilities/JSON/injection_router.json).")
    ap.add_argument("--mouse-config", default=None, help="Path to mouse_tool.json (default: <project-root>/Settings/Configurations/Mouse_Tool/mouse_tool.json).")
    ap.add_argument("--scripts-dir", default=None, help="Folder holding shuttle_gen.py / rebuild_tag.py / tag_combine.py (default: <project-root>/Settings/Configurations/Utilities/python).")
    ap.add_argument("--side", default="Client_Side", choices=["Client_Side", "Server_Side"])
    ap.add_argument("--split", required=True, help="The one string to split every tag on; reused for every item and every file in this run.")
    ap.add_argument("--cap-percent", type=float, default=DEFAULT_CAP_PERCENT, dest="cap_percent")
    ap.add_argument("--python", default=sys.executable, help="Interpreter to run the three scripts with (default: this interpreter).")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    project_root = Path(args.project_root).resolve()
    if not project_root.is_dir():
        print(f"[!] --project-root is not a folder: {project_root}", file=sys.stderr)
        return 1
    settings_cfg = project_root / "Settings" / "Configurations"
    router_path = Path(args.router) if args.router else settings_cfg / "Utilities" / "JSON" / "injection_router.json"
    mouse_path = Path(args.mouse_config) if args.mouse_config else settings_cfg / "Mouse_Tool" / "mouse_tool.json"
    scripts_dir = Path(args.scripts_dir) if args.scripts_dir else settings_cfg / "Utilities" / "python"

    router = load_json(router_path, "injection_router.json")
    mouse_config = load_json(mouse_path, "mouse_tool.json")

    wstg_ids = router_wstg_ids(router, args.side)
    if not wstg_ids:
        print(f"[!] injection_router.json has no entries for side={args.side}", file=sys.stderr)
        return 1

    targets = resolve_targets(project_root, mouse_config, wstg_ids)
    if not targets:
        print("[!] none of the router's WSTG items were found in mouse_tool.json", file=sys.stderr)
        return 1

    print(f"[*] project:  {project_root}")
    print(f"[*] side:     {args.side}  ({len(targets)} of {len(wstg_ids)} item(s) resolved)")
    print(f"[*] split:    {args.split!r}  (reused for every item)")
    print(f"[*] cap:      {args.cap_percent}%")

    jobs = build_jobs(targets)
    if not jobs:
        print("[!] nothing to do: no association files with usable Input/Output entries were found", file=sys.stderr)
        return 1

    phase1_shuttle_gen(jobs, args.python, scripts_dir, args.cap_percent, args.dry_run)
    phase2_rebuild_tag(jobs, args.python, scripts_dir, args.split, args.dry_run)
    phase3_tag_combine(jobs, args.python, scripts_dir, args.dry_run)
    summarize(jobs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
