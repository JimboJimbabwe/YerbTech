"""
Parameter Inventory Scanner

Combines URL parameter, body parameter, and JSON parameter detection logic
into a single pass over a Burp-suite-style XML file. Outputs a structured
inventory JSON where each request index lists its detected parameters.

Usage:
    python param_inventory.py <xml_file> [--output results.json] [--format json|txt]
"""

import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.parse
import xml.etree.ElementTree as ET
from urllib.parse import urljoin

# ---------------------------------------------------------------------------
# Configuration (mirrors the defaults from each original module)
# ---------------------------------------------------------------------------

url_config = {
    "min_param_name_length": 1,
    "min_param_value_length": 0,
    "include_values": True,
    "max_value_preview_length": 30,
    "include_hash_parameters": True,
}

body_config = {
    "min_param_name_length": 1,
    "min_param_value_length": 0,
    "include_values": True,
    "max_value_preview_length": 30,
    "check_form_urlencoded": True,
    "check_multipart_form": True,
    "check_xml_attributes": True,
    "check_plain_key_value": True,
}

json_config = {
    "include_arrays": True,
    "include_values": True,
    "include_nested": True,
    "min_key_length": 1,
    "max_depth": 10,
    "max_value_preview_length": 30,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _val_preview(value, max_len):
    if not value:
        return ""
    s = str(value)
    return s[:max_len] + "..." if len(s) > max_len else s


def decode_base64_safe(text):
    try:
        return base64.b64decode(text).decode("utf-8", errors="replace")
    except Exception:
        return text

# ---------------------------------------------------------------------------
# URL parameter extraction  (from url_parameter_detectorV2)
# ---------------------------------------------------------------------------

def extract_url_parameters(url):
    parameters = []
    max_len = url_config["max_value_preview_length"]
    min_name = url_config["min_param_name_length"]
    min_val = url_config["min_param_value_length"]

    try:
        parsed = urllib.parse.urlparse(url)

        if parsed.query:
            for name, values in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items():
                if len(name) < min_name:
                    continue
                for value in values:
                    if len(value) < min_val:
                        continue
                    entry = {"name": name, "source": "url_query"}
                    if url_config["include_values"]:
                        entry["value"] = _val_preview(value, max_len)
                    parameters.append(entry)

        if url_config["include_hash_parameters"] and parsed.fragment and "=" in parsed.fragment:
            try:
                for name, values in urllib.parse.parse_qs(parsed.fragment, keep_blank_values=True).items():
                    if len(name) < min_name:
                        continue
                    for value in values:
                        if len(value) < min_val:
                            continue
                        entry = {"name": name, "source": "url_fragment"}
                        if url_config["include_values"]:
                            entry["value"] = _val_preview(value, max_len)
                        parameters.append(entry)
            except Exception:
                pass

    except Exception:
        pass

    return parameters

# ---------------------------------------------------------------------------
# Body parameter extraction  (from body_parameter_detectorV2)
# ---------------------------------------------------------------------------

def _extract_urlencoded_params(body):
    params = []
    max_len = body_config["max_value_preview_length"]
    min_name = body_config["min_param_name_length"]
    min_val = body_config["min_param_value_length"]
    try:
        for name, values in urllib.parse.parse_qs(body, keep_blank_values=True).items():
            if len(name) < min_name:
                continue
            for value in values:
                if len(value) < min_val:
                    continue
                entry = {"name": name, "source": "body_form"}
                if body_config["include_values"]:
                    entry["value"] = _val_preview(value, max_len)
                params.append(entry)
    except Exception:
        pass
    return params


def _extract_multipart_params(body, boundary):
    params = []
    max_len = body_config["max_value_preview_length"]
    min_name = body_config["min_param_name_length"]
    min_val = body_config["min_param_value_length"]

    parts = re.split(r"--" + re.escape(boundary), body)
    for part in parts:
        if not part.strip():
            continue
        name_match = re.search(r'Content-Disposition:[^\n]*name="([^"]+)"', part, re.IGNORECASE)
        if not name_match:
            name_match = re.search(r"Content-Disposition:[^\n]*name=([^\s;]+)", part, re.IGNORECASE)
        if not name_match:
            continue
        name = name_match.group(1)
        if len(name) < min_name:
            continue
        val_match = re.search(r"\r?\n\r?\n(.*)", part, re.DOTALL)
        value = val_match.group(1).strip() if val_match else ""
        if len(value) < min_val:
            continue
        entry = {"name": name, "source": "body_multipart"}
        if body_config["include_values"]:
            entry["value"] = _val_preview(value, max_len)
        params.append(entry)
    return params


def _extract_xml_attributes(body):
    params = []
    max_len = body_config["max_value_preview_length"]
    min_name = body_config["min_param_name_length"]
    min_val = body_config["min_param_value_length"]

    for name, value in re.findall(r'<[^>]+\s+([a-zA-Z0-9_:-]+)="([^"]*)"', body):
        if len(name) < min_name or len(value) < min_val:
            continue
        entry = {"name": name, "source": "body_xml_attr"}
        if body_config["include_values"]:
            entry["value"] = _val_preview(value, max_len)
        params.append(entry)
    return params


def _extract_key_value_pairs(body):
    """
    Extract plain key=value pairs, excluding things that look like HTML/XML tags.
    Per the spec: skip anything that is body data but NOT a real key=value param.
    """
    params = []
    max_len = body_config["max_value_preview_length"]
    min_name = body_config["min_param_name_length"]
    min_val = body_config["min_param_value_length"]

    pattern = r"(?<![<\w])([a-zA-Z0-9_-]+)=([^\s&;]+|\"[^\"]*\"|'[^']*')"
    for name, value in re.findall(pattern, body):
        if len(name) < min_name:
            continue
        # strip surrounding quotes
        if (value.startswith('"') and value.endswith('"')) or \
           (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
        if len(value) < min_val:
            continue
        entry = {"name": name, "source": "body_kv"}
        if body_config["include_values"]:
            entry["value"] = _val_preview(value, max_len)
        params.append(entry)
    return params


def extract_body_parameters(body, content_type, method):
    """
    Route the body to the appropriate extractor(s) based on content-type.
    Returns (list_of_params, body_data_type_str).
    Returns ([], None) when the body exists but contains no recognisable params.
    """
    if not body or not body.strip():
        return [], None

    ct_lower = content_type.lower() if content_type else ""
    params = []
    body_data_type = "unknown"

    # --- URL-encoded form ---
    if body_config["check_form_urlencoded"] and (
        "application/x-www-form-urlencoded" in ct_lower
        or (method == "POST" and not content_type)
    ):
        found = _extract_urlencoded_params(body)
        if found:
            params.extend(found)
            body_data_type = "form-urlencoded"

    # --- Multipart ---
    if body_config["check_multipart_form"] and "multipart/form-data" in ct_lower:
        boundary_match = re.search(r"boundary=([^;]+)", content_type or "")
        if boundary_match:
            boundary = boundary_match.group(1).strip()
            found = _extract_multipart_params(body, boundary)
            if found:
                params.extend(found)
                body_data_type = "multipart"

    # --- XML attributes ---
    if body_config["check_xml_attributes"] and (
        "xml" in ct_lower or body.strip().startswith("<?xml")
    ):
        found = _extract_xml_attributes(body)
        if found:
            params.extend(found)
            body_data_type = "xml"

    # --- Plain key-value (only when no structured type was matched) ---
    # We deliberately skip this when JSON, so JSON requests are handled by
    # the JSON extractor only, not double-counted as plain kv.
    if body_config["check_plain_key_value"] and "json" not in ct_lower and not params:
        found = _extract_key_value_pairs(body)
        if found:
            params.extend(found)
            body_data_type = "plain-kv"

    return params, body_data_type if params else None

# ---------------------------------------------------------------------------
# JSON parameter extraction  (from json_parameter_detectorV2)
# ---------------------------------------------------------------------------

def _json_type_name(value):
    if value is None:        return "null"
    if isinstance(value, bool):   return "boolean"
    if isinstance(value, int):    return "integer"
    if isinstance(value, float):  return "float"
    if isinstance(value, str):    return "string"
    if isinstance(value, list):   return "array"
    if isinstance(value, dict):   return "object"
    return type(value).__name__


def _json_val_preview(value):
    max_len = json_config["max_value_preview_length"]
    if value is None:              return "null"
    if isinstance(value, bool):    return str(value)
    if isinstance(value, (int, float)): return str(value)
    if isinstance(value, str):
        return value[:max_len] + "..." if len(value) > max_len else value
    if isinstance(value, list):    return f"Array[{len(value)}]"
    if isinstance(value, dict):    return f"Object({len(value)} keys)"
    return str(type(value).__name__)


def _extract_json_params_recursive(json_data, prefix="", depth=0):
    if depth > json_config["max_depth"]:
        return []
    params = []

    if isinstance(json_data, dict):
        for key, value in json_data.items():
            if len(key) < json_config["min_key_length"]:
                continue
            full_key = f"{prefix}.{key}" if prefix else key
            entry = {
                "name": full_key,
                "source": "body_json",
                "json_type": _json_type_name(value),
            }
            if json_config["include_values"]:
                entry["value"] = _json_val_preview(value)
            params.append(entry)

            if json_config["include_nested"]:
                if isinstance(value, dict):
                    params.extend(_extract_json_params_recursive(value, full_key, depth + 1))
                elif isinstance(value, list) and json_config["include_arrays"]:
                    for i, item in enumerate(value):
                        if isinstance(item, (dict, list)):
                            params.extend(
                                _extract_json_params_recursive(item, f"{full_key}[{i}]", depth + 1)
                            )

    elif isinstance(json_data, list) and json_config["include_arrays"]:
        for i, item in enumerate(json_data):
            if isinstance(item, (dict, list)):
                params.extend(
                    _extract_json_params_recursive(item, f"{prefix}[{i}]", depth + 1)
                )

    return params


def extract_json_parameters(body, content_type):
    ct_lower = (content_type or "").lower()
    if "json" not in ct_lower and "+json" not in ct_lower:
        return []
    if not body or not body.strip():
        return []
    try:
        json_data = json.loads(body)
        return _extract_json_params_recursive(json_data)
    except (json.JSONDecodeError, Exception):
        return []

# ---------------------------------------------------------------------------
# XML file parser  (shared across all three original modules)
# ---------------------------------------------------------------------------

def parse_xml_file(file_path):
    """
    Parse a Burp-suite-style XML export.

    Returns a list of dicts:
        {index, url, method, content_type, body}
    """
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except Exception as e:
        print(f"[ERROR] Could not parse XML: {e}", file=sys.stderr)
        sys.exit(1)

    items = []
    for idx, item in enumerate(root.findall("./item")):
        url_elem = item.find("url")
        url = url_elem.text.strip() if url_elem is not None and url_elem.text else ""

        # --- parse the raw request block ---
        method = "GET"
        content_type = ""
        body = ""

        request_elem = item.find("request")
        if request_elem is not None:
            raw = request_elem.text or ""
            if request_elem.get("base64") == "true":
                raw = decode_base64_safe(raw)

            # split headers / body on first blank line
            header_body_split = re.split(r"\r?\n\r?\n", raw, maxsplit=1)
            header_block = header_body_split[0]
            body = header_body_split[1] if len(header_body_split) > 1 else ""

            # method from first line
            first_line = header_block.splitlines()[0] if header_block else ""
            method = first_line.split(" ", 1)[0] if first_line else "GET"

            # content-type from headers
            ct_match = re.search(r"^Content-Type:\s*(.+)$", header_block, re.IGNORECASE | re.MULTILINE)
            if ct_match:
                content_type = ct_match.group(1).strip()

        items.append({
            "index": idx,          # 0-based; displayed as 1-based below
            "url": url,
            "method": method,
            "content_type": content_type,
            "body": body,
        })

    return items

# ---------------------------------------------------------------------------
# Core inventory builder
# ---------------------------------------------------------------------------

def build_inventory(items):
    inventory = []

    for item in items:
        display_index = item["index"] + 1
        url = item["url"]
        method = item["method"]
        content_type = item["content_type"]
        body = item["body"]

        # Run all three detectors
        url_params = extract_url_parameters(url)

        body_params, body_data_type = extract_body_parameters(body, content_type, method)

        json_params = extract_json_parameters(body, content_type)

        # Merge — JSON params win over plain-kv for json bodies
        # (body extractor already skips json content, so no duplication)
        all_params = url_params + body_params + json_params

        # Attributes summary
        attributes = {
            "has_url_params":    bool(url_params),
            "has_body_params":   bool(body_params),
            "has_json_params":   bool(json_params),
            "body_data_type":    body_data_type,   # None when no body params
            "content_type":      content_type or None,
        }

        entry = {
            "index":      display_index,
            "url":        url,
            "method":     method,
            "attributes": attributes,
            "parameters": all_params,   # only real key=value params, per spec
        }

        inventory.append(entry)

    return {"inventory": inventory}

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def format_as_text(result):
    lines = []
    lines.append("PARAMETER INVENTORY")
    lines.append("=" * 60)
    for entry in result["inventory"]:
        lines.append(f"\nIndex #{entry['index']}  {entry['method']}  {entry['url']}")
        lines.append("-" * 60)
        attrs = entry["attributes"]
        lines.append(f"  URL params    : {attrs['has_url_params']}")
        lines.append(f"  Body params   : {attrs['has_body_params']}")
        lines.append(f"  JSON params   : {attrs['has_json_params']}")
        if attrs["body_data_type"]:
            lines.append(f"  Body data type: {attrs['body_data_type']}")
        if attrs["content_type"]:
            lines.append(f"  Content-Type  : {attrs['content_type']}")

        if entry["parameters"]:
            lines.append("  Parameters:")
            for p in entry["parameters"]:
                val_part = f" = {p['value']}" if "value" in p else ""
                jtype = f" [{p['json_type']}]" if "json_type" in p else ""
                lines.append(f"    [{p['source']}] {p['name']}{jtype}{val_part}")
        else:
            lines.append("  Parameters: (none)")

    return "\n".join(lines)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Scan a Burp XML export and inventory all URL / body / JSON parameters."
    )
    parser.add_argument("xml_file", help="Path to the Burp XML file")
    parser.add_argument("--output", "-o", help="Output file path (default: stdout)")
    parser.add_argument(
        "--format", "-f", choices=["json", "txt"], default="json",
        help="Output format (default: json)"
    )
    args = parser.parse_args()

    if not os.path.isfile(args.xml_file):
        print(f"[ERROR] File not found: {args.xml_file}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Parsing: {args.xml_file}", file=sys.stderr)
    items = parse_xml_file(args.xml_file)
    print(f"[*] Found {len(items)} request(s)", file=sys.stderr)

    result = build_inventory(items)

    total_params = sum(len(e["parameters"]) for e in result["inventory"])
    print(f"[*] Total parameters inventoried: {total_params}", file=sys.stderr)

    if args.format == "json":
        output = json.dumps(result, indent=2)
    else:
        output = format_as_text(result)

    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w") as f:
            f.write(output)
        print(f"[*] Results written to: {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()