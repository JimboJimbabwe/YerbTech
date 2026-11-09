#!/usr/bin/env python3
"""
metatag_scraper.py — WSTG-INFO-03 HTML Meta Tag Extractor
Location: WSTG_Repository/01_Information_Gathering/WSTG-INFO-03/Utilities/python/metatag_scraper.py

Reads a plaintext file of URLs (one per line), fetches each page,
and extracts all HTML <meta> tags. Results are written as Markdown
under Outputs/test_outputs/metatag_scraper/.

Usage:
    python metatag_scraper.py --input <urls.txt>
                              [--output-base <path>]
                              [--timeout <seconds>]
                              [--delay <seconds>]
"""

import argparse
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path


DEFAULT_OUTPUT_BASE = Path(__file__).resolve().parents[2] / "Outputs" / "test_outputs"
TOOL_DIR = "metatag_scraper"
TIMEOUT  = 15
DELAY    = 1.0


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        prog="metatag_scraper.py",
        description="WSTG-INFO-03 — Extract HTML meta tags from a list of URLs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--input", "-i", required=True,
        help="Path to plaintext file with one URL per line."
    )
    parser.add_argument(
        "--output-base", "-o", default=None,
        help=(
            "Base output directory. "
            "metatag_scraper/ subfolder is created here. "
            "Defaults to Outputs/test_outputs/ relative to WSTG-INFO-03 root."
        )
    )
    parser.add_argument(
        "--timeout", "-t", type=int, default=TIMEOUT,
        help=f"Per-request timeout in seconds (default: {TIMEOUT})"
    )
    parser.add_argument(
        "--delay", "-d", type=float, default=DELAY,
        help=f"Delay in seconds between requests (default: {DELAY})"
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# URL loader
# ---------------------------------------------------------------------------

def load_urls(path: str) -> list[str]:
    p = Path(path)
    if not p.is_file():
        sys.exit(f"[ERROR] Input file not found: {path}")
    urls = []
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    if not urls:
        sys.exit(f"[ERROR] No URLs found in: {path}")
    print(f"[+] Loaded {len(urls)} URL(s) from {path}")
    return urls


# ---------------------------------------------------------------------------
# Meta tag parser
# ---------------------------------------------------------------------------

class MetaTagParser(HTMLParser):
    """Extract all <meta> tags and the <title> from an HTML document."""

    def __init__(self):
        super().__init__()
        self.meta_tags: list[dict] = []
        self.title: str = ""
        self._in_title = False
        self._title_buf: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple]):
        if tag.lower() == "meta":
            attr_dict = {k.lower(): v for k, v in attrs if v is not None}
            if attr_dict:
                self.meta_tags.append(attr_dict)
        elif tag.lower() == "title":
            self._in_title = True

    def handle_endtag(self, tag: str):
        if tag.lower() == "title":
            self._in_title = False
            self.title = "".join(self._title_buf).strip()

    def handle_data(self, data: str):
        if self._in_title:
            self._title_buf.append(data)


def fetch_and_parse(url: str, timeout: int) -> tuple[str, list[dict], str | None]:
    """
    Fetch URL and extract meta tags.
    Returns (page_title, [meta_tag_dicts], error_string_or_None).
    """
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (WSTG-INFO-03/metatag_scraper)"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content_type = resp.headers.get("Content-Type", "")
            charset = "utf-8"
            if "charset=" in content_type:
                charset = content_type.split("charset=")[-1].split(";")[0].strip()
            raw = resp.read()
            try:
                html = raw.decode(charset, errors="replace")
            except (LookupError, UnicodeDecodeError):
                html = raw.decode("utf-8", errors="replace")

        parser = MetaTagParser()
        parser.feed(html)
        return parser.title, parser.meta_tags, None

    except urllib.error.HTTPError as e:
        return "", [], f"HTTP {e.code} {e.reason}"
    except urllib.error.URLError as e:
        return "", [], f"URL error: {e.reason}"
    except Exception as e:
        return "", [], f"Unexpected error: {e}"


# ---------------------------------------------------------------------------
# Markdown helpers
# ---------------------------------------------------------------------------

def meta_tag_to_md_row(tag: dict) -> str:
    """Render a single <meta> tag as a Markdown table row."""
    name    = tag.get("name", tag.get("property", tag.get("http-equiv", "—")))
    content = tag.get("content", "—").replace("|", "\\|").replace("\n", " ")
    charset = tag.get("charset", "")
    extras  = {k: v for k, v in tag.items() if k not in ("name", "property",
                                                           "http-equiv", "content",
                                                           "charset")}
    extra_str = ", ".join(f"`{k}={v}`" for k, v in extras.items()) if extras else ""
    if charset:
        return f"| `charset` | `{charset}` | {extra_str} |"
    return f"| `{name}` | {content} | {extra_str} |"


def write_url_section(fh, url: str, title: str,
                       tags: list[dict], error: str | None) -> None:
    """Write one URL block into the open Markdown file handle."""
    fh.write(f"## `{url}`\n\n")
    fh.write(f"**Fetched:** {datetime.utcnow().isoformat()}Z  \n")

    if error:
        fh.write(f"**Error:** {error}  \n\n---\n\n")
        return

    fh.write(f"**Page title:** {title or '_(none)_'}  \n")
    fh.write(f"**Meta tags found:** {len(tags)}  \n\n")

    if not tags:
        fh.write("_No `<meta>` tags detected._\n\n---\n\n")
        return

    fh.write("| Name / Property | Content | Extra Attrs |\n")
    fh.write("|---|---|---|\n")
    for tag in tags:
        fh.write(meta_tag_to_md_row(tag) + "\n")

    fh.write("\n")

    # Security-relevant tags highlighted separately
    sec_tags = [t for t in tags if t.get("http-equiv", "").lower() in (
        "content-security-policy", "x-frame-options", "x-content-type-options",
        "referrer-policy", "permissions-policy"
    ) or t.get("name", "").lower() in ("robots", "googlebot", "generator")]

    if sec_tags:
        fh.write("### ⚠️ Security / Recon Relevant Tags\n\n")
        fh.write("| Name / Property | Content |\n")
        fh.write("|---|---|\n")
        for tag in sec_tags:
            name    = tag.get("name", tag.get("http-equiv", "—"))
            content = tag.get("content", "—").replace("|", "\\|").replace("\n", " ")
            fh.write(f"| `{name}` | {content} |\n")
        fh.write("\n")

    fh.write("---\n\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    urls = load_urls(args.input)

    output_base = Path(args.output_base).resolve() if args.output_base else DEFAULT_OUTPUT_BASE
    tool_dir = output_base / TOOL_DIR
    tool_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    md_path = tool_dir / f"metatags_{timestamp}.md"

    print(f"\n{'='*60}")
    print(f"  WSTG-INFO-03 Meta Tag Scraper")
    print(f"  URLs    : {len(urls)}")
    print(f"  Output  : {md_path}")
    print(f"{'='*60}\n")

    with md_path.open("w", encoding="utf-8") as fh:
        fh.write("# WSTG-INFO-03 — HTML Meta Tag Extraction\n\n")
        fh.write(f"**Input file:** `{args.input}`  \n")
        fh.write(f"**URLs processed:** {len(urls)}  \n")
        fh.write(f"**Generated:** {datetime.utcnow().isoformat()}Z  \n\n")
        fh.write("---\n\n")

        for i, url in enumerate(urls, 1):
            print(f"[{i}/{len(urls)}] {url}")
            page_title, tags, error = fetch_and_parse(url, args.timeout)

            if error:
                print(f"  [!] {error}")
            else:
                print(f"  → {len(tags)} meta tag(s) | title: {page_title[:60] or '(none)'}")

            write_url_section(fh, url, page_title, tags, error)

            if i < len(urls):
                time.sleep(args.delay)

    print(f"\n[+] Output written to: {md_path}")
    print("[+] Done.\n")


if __name__ == "__main__":
    main()
