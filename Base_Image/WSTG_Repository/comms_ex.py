#!/usr/bin/env python3
"""
spider_docstrings.py

Recursively walks a folder tree, finds all Python files, extracts their
module-level triple-quoted docstrings, and prints the results to the terminal
and writes them to a .txt file.

Usage:
    python spider_docstrings.py /path/to/folder
    python spider_docstrings.py /path/to/folder --output my_report.txt
"""

import argparse
import ast
import os
import re
import sys
from collections import defaultdict
from pathlib import Path


def extract_module_docstring(filepath: Path) -> str | None:
    """
    Extract the module-level triple-quoted docstring from a Python file.
    Tries AST parsing first; falls back to regex for files with syntax errors.
    """
    try:
        source = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return f"[Error reading file: {e}]"

    # --- AST approach (reliable for valid Python) ---
    try:
        tree = ast.parse(source)
        docstring = ast.get_docstring(tree)
        if docstring is not None:
            return docstring
    except SyntaxError:
        pass

    # --- Regex fallback for files that don't parse cleanly ---
    pattern = r'^\s*(?:"""(.*?)"""|\'\'\'(.*?)\'\'\')'
    match = re.search(pattern, source, re.DOTALL)
    if match:
        raw = match.group(1) if match.group(1) is not None else match.group(2)
        return raw.strip()

    return None


def spider_folder(root: Path) -> dict[str, list[tuple[str, str | None]]]:
    """
    Walk the entire folder tree under *root*.

    Returns a dict keyed by the subfolder path relative to *root*
    (e.g. "ml/classification"), each value being an ordered list of
    (filename, docstring_or_None) tuples for every .py file found there.
    """
    results: dict[str, list[tuple[str, str | None]]] = defaultdict(list)

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()  # alphabetical, consistent order
        py_files = sorted(f for f in filenames if f.endswith(".py"))
        if not py_files:
            continue

        current = Path(dirpath)
        rel = current.relative_to(root)
        key = str(rel)  # "." for the root itself, otherwise e.g. "sub/deep"

        for name in py_files:
            docstring = extract_module_docstring(current / name)
            results[key].append((name, docstring))

    return dict(sorted(results.items()))


def build_output(results: dict, root: Path) -> str:
    """Format the collected data into the desired report layout."""
    sections: list[str] = []

    for subfolder, files in results.items():
        # Human-readable folder label (relative path, uppercased)
        if subfolder == ".":
            label = root.name + " (root)"
        else:
            label = subfolder

        block_lines = [label.upper(), ""]

        for i, (filename, docstring) in enumerate(files):
            block_lines.append(f"Title of python file: {filename}")
            if docstring:
                # Indent continuation lines so multi-line docstrings look tidy
                indented = docstring.replace("\n", "\n    ")
                block_lines.append(f"Commentary: {indented}")
            else:
                block_lines.append("Commentary: [No triple-quoted docstring found]")

            # Blank line between files, but not after the last one
            if i < len(files) - 1:
                block_lines.append("")

        sections.append("\n".join(block_lines))

    # Sections separated by a blank line
    return "\n\n".join(sections)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Spider a folder tree, extract Python module docstrings, "
            "and write a summary to the terminal and a .txt file."
        )
    )
    parser.add_argument(
        "folder",
        help="Root folder to spider (required)",
    )
    parser.add_argument(
        "-o", "--output",
        default="docstring_report.txt",
        metavar="FILE",
        help="Output .txt file path (default: docstring_report.txt)",
    )
    args = parser.parse_args()

    root = Path(args.folder).resolve()
    if not root.is_dir():
        print(f"Error: '{args.folder}' is not a valid directory.", file=sys.stderr)
        sys.exit(1)

    print(f"Spidering: {root}\n{'─' * 60}")

    results = spider_folder(root)

    if not results:
        print("No Python files found under the specified folder.")
        sys.exit(0)

    output = build_output(results, root)

    # ── Terminal ──────────────────────────────────────────────────────────────
    print(output)
    print(f"\n{'─' * 60}")

    # ── File ──────────────────────────────────────────────────────────────────
    out_path = Path(args.output)
    out_path.write_text(output, encoding="utf-8")
    print(f"Report written to: {out_path.resolve()}")


if __name__ == "__main__":
    main()