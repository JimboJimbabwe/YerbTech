#!/usr/bin/env python3
"""
WSTG-INJT-17 (Host Header Injection) - wordlist builder that reuses whatever
WSTG-INFO-04 (DNS / Port / VHost Enumeration) has already produced for this
project, instead of asking the operator to re-type IPs and subdomains by hand.

Every upstream source below is OPTIONAL and reused only if present - a fresh
project with none of WSTG-INFO-04's outputs yet still gets a wordlist, just a
smaller one (the target URL, scope file if any, the literal `*`/empty-Host
entries, and the cloud-metadata/region entries). Nothing here ever fails the
run because an upstream file is missing; it is reported and skipped.

Reused from WSTG-INFO-04, by default (--no-reuse-recon turns this off):

  - subdomain_seeker.py's own report
    (Outputs/test_outputs/subdomain_seeker/subdomains_*.md, newest by name) -
    the "Discovered Subdomains" table's Subdomain column.
  - the orchestrator's DNS step
    (Outputs/test_outputs/DNS_MODULE/results.txt) - dig A/AAAA answers per
    domain, used first for "what's this subdomain's IP" before this script
    does its own lookup.
  - the orchestrator's two nmap XML outputs
    (Outputs/data/uxp_scan.xml, Outputs/data/vhost_scan.xml) - every
    <address addrtype="ipv4|ipv6"> in them, i.e. "other IPs in scope" as
    already scanned.

For any subdomain found by subdomain_seeker.py that ISN'T already resolved in
WSTG-INFO-04's own DNS results, this script does its own DNS lookup (plain
socket.gethostbyname_ex - no extra tooling) unless --no-resolve is given.
This is a live DNS query against discovered hostnames; disable it if even
that should be avoided for this engagement.

What goes into the wordlist, besides the above:

  - --target-url (required) and every entry in --scope-file (defaults to
    WSTG-INFO-04's own Inputs/Data/domains.txt, the file its DNS step already
    treats as "domains in scope", if that file exists) - scheme/path stripped
    down to a bare host[:port], since that's what actually goes in a Host
    header.
  - the broadcast address of every IPv4 found above, assuming a /24
    (override with --cidr) - nmap/dig don't report the real subnet mask, so
    this is a stated assumption, not a measurement.
  - `*` and an empty string (a literal blank line in the wordlist - Burp's
    Simple List payload type sends blank lines as an empty Host value;
    that's deliberate here, not a formatting accident).
  - cloud metadata: 169.254.169.254 (the link-local IMDS address shared by
    AWS, Azure and GCP alike - there's no separate well-known IP for Azure or
    GCP) and metadata.google.internal (GCP's own metadata hostname; AWS and
    Azure have no equivalent hostname of their own, only the shared IP).
  - --no-region-guess turns off the one speculative category here: common
    AWS/Azure/GCP region tokens (us-east-1, eastus, us-central1, ...) tried
    both bare and as a subdomain of the target (region.target.tld), to see
    if a region string in the Host header changes routing/caching anywhere.
    This is a guess with no evidence behind it for any given target - unlike
    everything else above, which comes from data this project already
    collected - so it's flagged here and in the README, and is easy to turn
    off.

Finally, every host value collected is also emitted in encoded form (unless
--no-encode) to Host_Values_Encoded.txt: URL-encoded, double URL-encoded for
all values, and - for anything that's a plain IPv4 address - the same
address again in decimal and hex notation, both of which are long-standing
Host-header/SSRF IP-obfuscation bypasses and don't apply to a domain name the
way percent-encoding does.

Usage
-----
    python3 hostheader_wordlist.py --project-root /path/to/Projects/MyProject \
        --target-url https://example.com
    python3 hostheader_wordlist.py --project-root ... --target-url https://example.com \
        --scope-file /path/to/extra_scope.txt --cidr 16
    python3 hostheader_wordlist.py --project-root ... --target-url https://example.com \
        --no-reuse-recon --no-region-guess
"""
import argparse
import glob
import ipaddress
import os
import re
import socket
import sys
from urllib.parse import quote, urlparse

SELF_ID = "WSTG-INJT-17"
RECON_ID = "WSTG-INFO-04"

CLOUD_METADATA_IPS = ["169.254.169.254"]
CLOUD_METADATA_HOSTS = ["metadata.google.internal"]

# Small, clearly-labelled guess list - see --no-region-guess in the module
# docstring. Not exhaustive; meant as a cheap probe, not full coverage.
DEFAULT_REGION_TOKENS = [
    "us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1",   # AWS-style
    "eastus", "westeurope", "westus2",                                         # Azure-style
    "us-central1", "europe-west1", "asia-southeast1",                         # GCP-style
]
CLOUD_PROVIDER_TOKENS = ["aws", "azure", "gcp"]

SUBDOMAIN_TABLE_ROW_RE = re.compile(r"^\|\s*\d+\s*\|\s*`([^`]+)`\s*\|", re.MULTILINE)
DIG_A_RE = re.compile(r"\bIN\s+A\s+(\d{1,3}(?:\.\d{1,3}){3})\b")
DIG_AAAA_RE = re.compile(r"\bIN\s+AAAA\s+([0-9a-fA-F:]+)\b")


def find_item_folder(project_root, wstg_id):
    """Scan the project tree for the one folder named after wstg_id - never a
    hardcoded category path, since category folder names/numbers do drift
    (and have, elsewhere in this project) while the WSTG ID itself doesn't."""
    wstg_id = wstg_id.strip().upper()
    for root, dirs, _files in os.walk(project_root):
        for d in dirs:
            if d.strip().upper() == wstg_id:
                return os.path.join(root, d)
    return None


def atomic_write_text(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def host_only(value):
    """Strip a URL (or bare host) down to host[:port], the shape a Host
    header actually takes. Returns None for empty/unusable input."""
    value = (value or "").strip()
    if not value:
        return None
    parsed = urlparse(value if "//" in value else f"//{value}")
    host = parsed.netloc or parsed.path
    host = host.strip().strip("/")
    return host or None


def load_lines(path):
    if not path or not os.path.isfile(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out


# ------------------------- WSTG-INFO-04 reuse -------------------------

def read_subdomain_seeker_md(recon_dir):
    """Newest subdomains_*.md by filename (the stamp sorts lexically), or
    None if subdomain_seeker.py has never been run for this project."""
    pattern = os.path.join(recon_dir, "Outputs", "test_outputs", "subdomain_seeker", "subdomains_*.md")
    files = sorted(glob.glob(pattern))
    if not files:
        return None, []
    path = files[-1]
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    subs = sorted(set(m.group(1).strip().lower() for m in SUBDOMAIN_TABLE_ROW_RE.finditer(text)))
    return path, subs


def read_dns_results(recon_dir):
    """Outputs/test_outputs/DNS_MODULE/results.txt -> {domain: [ips]}, keyed
    by the '=== domain ===' header the orchestrator wrote (the domain it was
    actually asked to look up), not by whatever name a dig answer line
    echoes back (which can be a CNAME target instead)."""
    path = os.path.join(recon_dir, "Outputs", "test_outputs", "DNS_MODULE", "results.txt")
    if not os.path.isfile(path):
        return None, {}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    result = {}
    current = None
    for line in text.splitlines():
        header = re.match(r"^===\s*(.+?)\s*===$", line.strip())
        if header:
            current = header.group(1).strip().lower()
            result.setdefault(current, [])
            continue
        if current is None:
            continue
        for m in DIG_A_RE.finditer(line):
            result[current].append(m.group(1))
        for m in DIG_AAAA_RE.finditer(line):
            result[current].append(m.group(1))
    return path, {k: sorted(set(v)) for k, v in result.items() if v}


def read_nmap_ips(recon_dir):
    """Every <address addrtype="ipv4"|"ipv6"> across both nmap XML outputs
    the orchestrator produces. Returns (sources_checked, ips) where
    sources_checked lists (path, found_bool) for the report."""
    import xml.etree.ElementTree as ET

    candidates = [
        os.path.join(recon_dir, "Outputs", "data", "uxp_scan.xml"),
        os.path.join(recon_dir, "Outputs", "data", "vhost_scan.xml"),
    ]
    ips = set()
    sources = []
    for path in candidates:
        if not os.path.isfile(path):
            sources.append((path, False))
            continue
        try:
            tree = ET.parse(path)
        except ET.ParseError:
            sources.append((path, False))
            continue
        for host_elem in tree.getroot().findall(".//host"):
            for addr in host_elem.findall("./address"):
                if addr.get("addrtype") in ("ipv4", "ipv6"):
                    a = addr.get("addr", "").strip()
                    if a:
                        ips.add(a)
        sources.append((path, True))
    return sources, sorted(ips)


def resolve_host(host):
    try:
        _name, _aliases, addrs = socket.gethostbyname_ex(host)
        return sorted(set(addrs))
    except (socket.gaierror, socket.herror, UnicodeError, OSError):
        return []


# ------------------------- IP helpers -------------------------

def is_ipv4(value):
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def broadcast_of(ip, cidr):
    try:
        net = ipaddress.ip_network(f"{ip}/{cidr}", strict=False)
        return str(net.broadcast_address)
    except ValueError:
        return None


def ip_to_decimal(ip):
    return str(int(ipaddress.IPv4Address(ip)))


def ip_to_hex(ip):
    return "0x%08x" % int(ipaddress.IPv4Address(ip))


# ------------------------- main build -------------------------

def build(args):
    project_root = os.path.abspath(args.project_root)
    self_dir = find_item_folder(project_root, SELF_ID)
    if not self_dir:
        print(f"[error] no folder found for {SELF_ID} under {project_root}", file=sys.stderr)
        sys.exit(1)

    report_lines = []
    report_lines.append(f"# {SELF_ID} - Host Header Injection wordlist\n")
    report_lines.append(f"**Target URL:** `{args.target_url}`  ")
    report_lines.append(f"**Broadcast CIDR assumption:** /{args.cidr}  ")
    report_lines.append(f"**Live DNS resolution:** {'enabled' if args.resolve else 'disabled (--no-resolve)'}  ")
    report_lines.append(f"**Cloud metadata entries:** {'included' if not args.no_cloud else 'excluded (--no-cloud)'}  ")
    report_lines.append(f"**Region/provider-token guesses:** {'included' if not args.no_region_guess else 'excluded (--no-region-guess)'}  \n")

    hosts = set()          # final Host_Values.txt contents (strings, already host-only)
    ipv4s = set()          # tracked separately so the encoded-IP step only touches real IPv4s

    def add_host(value, label):
        h = host_only(value)
        if h:
            hosts.add(h)
        return h

    # --- target URL + scope file (own URLs in scope) ---
    target_host = add_host(args.target_url, "target")
    report_lines.append(f"## Normal URL / scope\n\n- Target: `{target_host}`")

    scope_file = args.scope_file
    scope_source = "explicit --scope-file"
    if not scope_file and not args.no_reuse_recon:
        recon_dir_probe = find_item_folder(project_root, RECON_ID)
        if recon_dir_probe:
            candidate = os.path.join(recon_dir_probe, "Inputs", "Data", "domains.txt")
            if os.path.isfile(candidate):
                scope_file = candidate
                scope_source = f"{RECON_ID}'s own Inputs/Data/domains.txt (default domains-in-scope file)"
    scope_entries = load_lines(scope_file)
    for entry in scope_entries:
        add_host(entry, "scope")
    if scope_file:
        report_lines.append(f"- Scope file: `{scope_file}` ({scope_source}) - {len(scope_entries)} entries")
    else:
        report_lines.append("- Scope file: none given, and none found to default to.")

    # --- WSTG-INFO-04 reuse ---
    recon_dir = None if args.no_reuse_recon else find_item_folder(project_root, RECON_ID)
    subdomains = []
    dns_map = {}
    nmap_ips = []

    report_lines.append(f"\n## Reused from {RECON_ID}\n")
    if args.no_reuse_recon:
        report_lines.append("- Skipped entirely (--no-reuse-recon).")
    elif not recon_dir:
        report_lines.append(f"- {RECON_ID}'s folder was not found in this project - nothing to reuse.")
    else:
        md_path, subdomains = read_subdomain_seeker_md(recon_dir)
        if md_path:
            report_lines.append(f"- Subdomains: `{md_path}` -> {len(subdomains)} subdomain(s)")
        else:
            report_lines.append("- Subdomains: subdomain_seeker.py has not been run for this project yet - skipped.")

        dns_path, dns_map = read_dns_results(recon_dir)
        if dns_path:
            total_ips = sum(len(v) for v in dns_map.values())
            report_lines.append(f"- DNS results: `{dns_path}` -> {len(dns_map)} domain(s), {total_ips} IP(s)")
        else:
            report_lines.append("- DNS results: no DNS_MODULE/results.txt yet - skipped.")

        nmap_sources, nmap_ips = read_nmap_ips(recon_dir)
        for path, found in nmap_sources:
            report_lines.append(f"- nmap XML: `{path}` -> {'found' if found else 'not found'}")
        report_lines.append(f"  Total IP(s) from nmap XML: {len(nmap_ips)}")

    for sub in subdomains:
        add_host(sub, "subdomain")

    # subdomain -> IP: WSTG-INFO-04's own DNS results first, then (if enabled) a live lookup
    resolved_count = 0
    live_resolved_count = 0
    for sub in subdomains:
        ips = dns_map.get(sub, [])
        if not ips and args.resolve:
            ips = resolve_host(sub)
            if ips:
                live_resolved_count += 1
        if ips:
            resolved_count += 1
        for ip in ips:
            hosts.add(ip)
            if is_ipv4(ip):
                ipv4s.add(ip)
    report_lines.append(
        f"\nSubdomain IPs: {resolved_count}/{len(subdomains)} resolved "
        f"({live_resolved_count} via this script's own DNS lookup)."
    )

    # other in-scope IPs from DNS results + nmap XML
    for ip_list in dns_map.values():
        for ip in ip_list:
            hosts.add(ip)
            if is_ipv4(ip):
                ipv4s.add(ip)
    for ip in nmap_ips:
        hosts.add(ip)
        if is_ipv4(ip):
            ipv4s.add(ip)

    # broadcast addresses
    broadcasts = set()
    for ip in ipv4s:
        b = broadcast_of(ip, args.cidr)
        if b:
            broadcasts.add(b)
    hosts |= broadcasts
    report_lines.append(f"Broadcast addresses added (assuming /{args.cidr}): {len(broadcasts)}")

    # wildcard + null
    hosts.add("*")
    hosts.add("")  # literal empty Host value - see module docstring

    # cloud metadata
    if not args.no_cloud:
        for v in CLOUD_METADATA_IPS + CLOUD_METADATA_HOSTS:
            hosts.add(v)
            if is_ipv4(v):
                ipv4s.add(v)
        report_lines.append(f"\nCloud metadata entries added: {len(CLOUD_METADATA_IPS) + len(CLOUD_METADATA_HOSTS)}")

    # region/provider token guesses (speculative - see module docstring)
    region_tokens = load_lines(args.region_list) if args.region_list else DEFAULT_REGION_TOKENS
    if not args.no_region_guess and target_host:
        base_host = target_host.split(":")[0]
        added = 0
        for token in region_tokens + CLOUD_PROVIDER_TOKENS:
            for candidate in (token, f"{token}.{base_host}"):
                if candidate not in hosts:
                    hosts.add(candidate)
                    added += 1
        report_lines.append(f"Region/provider-token guesses added: {added} (speculative - see README)")

    # --- write Host_Values.txt ---
    wl_dir = os.path.join(self_dir, "Inputs", "Wordlists")
    host_values_path = os.path.join(wl_dir, "Host_Values.txt")
    ordered = sorted(h for h in hosts if h != "")
    # keep the literal empty-Host entry, placed last and on its own, so it
    # doesn't read as a stray blank line at the top of the file
    lines_out = ordered + [""]
    atomic_write_text(host_values_path, "\n".join(lines_out) + "\n")
    print(f"[+] {host_values_path} <- {len(ordered)} host value(s) + 1 empty-Host line", flush=True)

    # --- write Host_Values_Encoded.txt ---
    encoded_path = None
    if not args.no_encode:
        encoded = []
        for h in ordered:
            if h in ("*",):
                continue  # percent-encoding '*' isn't a meaningful bypass variant
            single = quote(h, safe="")
            double = quote(single, safe="")
            encoded.append(single)
            encoded.append(double)
            if is_ipv4(h):
                encoded.append(ip_to_decimal(h))
                encoded.append(ip_to_hex(h))
        encoded = sorted(set(encoded))
        encoded_path = os.path.join(wl_dir, "Host_Values_Encoded.txt")
        atomic_write_text(encoded_path, "\n".join(encoded) + "\n")
        print(f"[+] {encoded_path} <- {len(encoded)} encoded variant(s)", flush=True)

    # --- provenance report ---
    report_lines.append(f"\n## Output\n\n- `{host_values_path}` - {len(ordered)} host value(s) + 1 empty-Host line")
    if encoded_path:
        report_lines.append(f"- `{encoded_path}` - {len(encoded)} encoded variant(s)")
    else:
        report_lines.append("- Encoded variants: skipped (--no-encode)")

    report_dir = os.path.join(self_dir, "Outputs", "test_outputs")
    import datetime
    stamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    report_path = os.path.join(report_dir, f"hostheader_report_{stamp}.md")
    atomic_write_text(report_path, "\n".join(report_lines) + "\n")
    print(f"[+] {report_path}", flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project-root", required=True, help="Project directory.")
    ap.add_argument("--target-url", required=True, help="The engagement's normal target URL.")
    ap.add_argument("--scope-file", default=None,
                     help="Extra in-scope hosts/URLs, one per line. Defaults to "
                          f"{RECON_ID}'s Inputs/Data/domains.txt if that file exists.")
    ap.add_argument("--no-reuse-recon", action="store_true",
                     help=f"Don't read anything from {RECON_ID} (subdomains, DNS results, nmap XML).")
    ap.add_argument("--resolve", dest="resolve", action="store_true", default=True,
                     help="Live DNS lookup for subdomains with no IP in WSTG-INFO-04's own DNS results (default: on).")
    ap.add_argument("--no-resolve", dest="resolve", action="store_false",
                     help="Disable the live DNS lookup fallback above.")
    ap.add_argument("--cidr", type=int, default=24, help="Assumed subnet size for broadcast-address calculation (default 24).")
    ap.add_argument("--no-cloud", action="store_true", help="Skip the static AWS/Azure/GCP metadata entries.")
    ap.add_argument("--no-region-guess", action="store_true", help="Skip the speculative region/provider-token Host variants.")
    ap.add_argument("--region-list", default=None, help="Override file of region tokens, one per line, replacing the small built-in list.")
    ap.add_argument("--no-encode", action="store_true", help="Skip writing Host_Values_Encoded.txt.")
    args = ap.parse_args()

    if not os.path.isdir(args.project_root):
        print(f"[error] --project-root is not a directory: {args.project_root}", file=sys.stderr)
        sys.exit(1)

    build(args)


if __name__ == "__main__":
    main()
