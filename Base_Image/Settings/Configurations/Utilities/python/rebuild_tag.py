"""
rebuild_tag.py
Reads a hover-trace JSON file and reconstructs the HTML tag
from the `element` selector and `domAttributes` fields.
"""

import json
import re
import sys
from pathlib import Path


def extract_tag_name(element_selector: str) -> str:
    """
    Take the last segment of a CSS selector like:
        div#search-suggestions > div > div > div:nth-of-type(2) > a:nth-of-type(1)
    and return only the bare tag name, e.g. "a".
    Strips  :pseudo-class,  #id,  .class  suffixes.
    """
    last_segment = element_selector.strip().split(">")[-1].strip()
    # Split on any of  :  #  .  and take the first piece
    tag = re.split(r"[:#.]", last_segment)[0].strip()
    return tag or "div"   # fallback to div if parsing yields nothing


def build_html_tag(tag: str, dom_attributes: list[dict]) -> str:
    """
    Given a tag name and a list of {name, value, prop} dicts,
    return a reconstructed HTML element string.
    Attributes whose value is None are rendered as bare boolean attrs.
    """
    attr_parts = []
    for attr in dom_attributes:
        name  = attr.get("name", "")
        value = attr.get("value")
        if not name:
            continue
        if value is None:
            attr_parts.append(name)          # e.g.  disabled
        else:
            escaped = value.replace('"', "&quot;")
            attr_parts.append(f'{name}="{escaped}"')

    attrs_str = (" " + " ".join(attr_parts)) if attr_parts else ""
    return f"<{tag}{attrs_str}></{tag}>"



def split_at_value(html_tag: str, dom_attributes: list[dict], search_str: str) -> tuple[str, str]:
    """
    Find the first attribute whose value contains search_str.
    Split the tag at the position where search_str starts inside that value.
    Returns (before, from_match).
    Raises ValueError if search_str is not found in any attribute value.
    """
    # Two passes: exact value match first, then partial match fallback
    for exact in (True, False):
        for attr in dom_attributes:
            raw_value = attr.get("value")
            if raw_value is None:
                continue
            if exact:
                if raw_value != search_str:
                    continue
            else:
                if search_str not in raw_value:
                    continue

            # Search for  name="value"  so we anchor to the right attribute
            escaped_value = raw_value.replace('"', "&quot;")
            attr_name     = attr.get("name", "")
            anchor        = f'{attr_name}="{escaped_value}"'
            anchor_start  = html_tag.find(anchor)
            if anchor_start == -1:
                continue
            # value starts right after  name="
            val_start  = anchor_start + len(attr_name) + 2   # len('name="') = name + ='
            str_offset = escaped_value.find(search_str)
            split_idx  = val_start + str_offset
            return html_tag[:split_idx], html_tag[split_idx:]

    raise ValueError(f"String {search_str!r} not found in any attribute value.")


def process_file(json_path: str) -> tuple[str, list[dict]]:
    """Returns (html_tag, dom_attributes)."""
    path = Path(json_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {json_path}")

    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)

    element        = data.get("element", "")
    dom_attributes = data.get("domAttributes", [])

    if not element:
        raise ValueError("JSON has no 'element' field.")

    tag      = extract_tag_name(element)
    html_tag = build_html_tag(tag, dom_attributes)
    return html_tag, dom_attributes


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Rebuild an HTML tag from a hover-trace JSON file."
    )
    parser.add_argument("json_file", help="Path to the input JSON file.")
    parser.add_argument(
        "--split",
        metavar="STRING",
        default=None,
        help="Split the tag at the start of STRING inside its attribute value.",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Write split result to this JSON file.",
    )
    parser.add_argument(
        "--index",
        type=int,
        default=1,
        help="Index number to include in the output JSON (default: 1).",
    )
    args = parser.parse_args()

    # Orchestrator-driven runs check the exit code, so a bad --split value (not found anywhere
    # in this element's attributes) is reported as a clean failure, not a raw traceback.
    try:
        html_tag, dom_attributes = process_file(args.json_file)
    except (FileNotFoundError, ValueError, json.JSONDecodeError, OSError) as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1

    if args.split is not None:
        try:
            before, after = split_at_value(html_tag, dom_attributes, args.split)
        except ValueError as e:
            print(f"[!] {e}", file=sys.stderr)
            return 1

        if args.output:
            result = {
                "index": args.index,
                "tag_start": before,
                "tag_end": after,
            }
            out_path = Path(args.output)
            with out_path.open("w", encoding="utf-8") as fh:
                json.dump(result, fh, indent=2)
            print(f"Written to {out_path}")
        else:
            print(before)
            print()
            print(after)
    else:
        print(html_tag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
