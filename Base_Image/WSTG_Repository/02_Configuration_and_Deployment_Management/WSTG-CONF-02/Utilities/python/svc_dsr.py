#!/usr/bin/env python3
"""
svc_dsr.py — Service Disseminator
Searches how-to Steps for trigger patterns and extracts isolated values.

Usage:
  python3 svc_dsr.py --init                  # create SVC_DSR/ folder structure
  python3 svc_dsr.py --type env_vars         # run one category
  python3 svc_dsr.py --all                   # run all five categories

Options:
  --bridge   path to how_to_steps_bridge.json          (default: how_to_steps_bridge.json)
  --main     path to conceptual_mapping_v4_complete.json (default: conceptual_mapping_v4_complete.json)
  --type     env_vars | paths | headers | default_creds | commands
  --init     create SVC_DSR/ folder tree + default input.txt files
  --all      run all categories sequentially (also runs --init first)

input.txt format:
  - One trigger per line (plain string → substring match, case-insensitive)
  - Lines starting with  regex:  are used as raw regex patterns
  - Lines starting with  #  are comments; blank lines ignored

Output (per category, inside SVC_DSR/<Folder>/):
  output.json   — structured: { query_type, matched_items, LIST, References }
  wordlist.txt  — flat newline-separated list of extracted values (Burp-ready)

  output.txt is still written for backward compatibility (same content as output.json).
"""

import argparse, json, os, re, sys
from pathlib import Path

# ── Folder mapping ────────────────────────────────────────────────────────────
ROOT = 'SVC_DSR'
FOLDERS = {
    'env_vars':      'ENV_VARS',
    'paths':         'Paths',
    'headers':       'Headers',
    'default_creds': 'Default_Creds',
    'commands':      'commands',
}

# ── Per-type extractors ───────────────────────────────────────────────────────
# These pull the *specific interesting value* out of a matching step.
# Multiple patterns per type are joined with | and tried together.
_EXTRACTOR_PATTERNS = {

    'env_vars': '|'.join([
        r'[A-Z][A-Z0-9_]{2,}=[^\s,;\'\")\]]*',    # VARNAME=value (with value)
        r'[A-Z][A-Z0-9_]{2,}(?==)',                 # VARNAME= (just the name=)
        r'\$\{?[A-Z][A-Z0-9_]{2,}\}?',             # $VAR or ${VAR} references
        r'export\s+[A-Z][A-Z0-9_]{2,}',            # export VARNAME
    ]),

    'paths': '|'.join([
        r'\./[a-zA-Z0-9_.%/-]{2,}',                 # ./relative/path
        r'~/[a-zA-Z0-9_./-]+',                      # ~/home/relative
        r'/[a-zA-Z0-9_.~-]+(?:/[a-zA-Z0-9_.~%/-]+)+',  # /absolute/two/levels+
        r'%[0-9A-Fa-f]{2}(?:[a-zA-Z0-9_%/=.+-]*)', # URL-encoded sequences
    ]),

    'headers': '|'.join([
        r'[Xx]-[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)+',   # X-Custom-Header (2+ segments)
        r'Authorization:\s*\S+',                     # Authorization: Bearer xxx
        r'Content-Type:\s*[^\s,;]+',                 # Content-Type: application/json
        r'Accept:\s*[^\s,;]+',                       # Accept: */*
        r'Bearer\s+[a-zA-Z0-9._\-]{4,}',           # Bearer token
        r'Basic\s+[a-zA-Z0-9+/=]{4,}',             # Basic b64
        r'(?:api[-_]key|x-api-key):\s*\S+',        # api-key header
    ]),

    'default_creds': '|'.join([
        r'(?:username|user)\s*[:=]\s*["\']?([a-zA-Z0-9_@.-]{1,40})',
        r'(?:password|passwd|pass)\s*[:=]\s*["\']?([a-zA-Z0-9!@#$%^&*._-]{1,40})',
        r'(?:admin|root|guest|anonymous|default)(?:[:/ ][a-zA-Z0-9!@#$%_.-]{1,30})?',
        r'changeme|letmein|admin123|password123|root123',
        r'default\s+(?:credentials?|password|user(?:name)?)',
        r'(?:secret|token|api[-_]key)\s*[:=]\s*["\']?[a-zA-Z0-9._\-]{4,}',
    ]),

    'commands': '|'.join([
        r'/(?:bin|sbin|usr/bin|usr/sbin|usr/local/bin)/[a-zA-Z0-9_-]+',   # /bin/cmd
        r'\.(?:bin)/[a-zA-Z0-9_-]+',                                        # .bin/cmd
        r'\b(?:bin/bash|bin/sh|/sh|/bash)\b',                               # shell refs
        r'\b(?:aws|gcloud|gsutil|kubectl|eksctl|az|terraform|cdk|pulumi|vault|nomad|helm)\s+[a-zA-Z][a-zA-Z0-9_:-]*',  # cloud CLIs
        r'\b(?:sudo|curl|wget|bash|sh|python3?|pip3?|npm|yarn|npx|apt(?:-get)?|yum|dnf|brew|make|gcc|go run|java -jar|mvn|gradle)\s+[^\s]{1,60}',  # linux tools + arg
        r'\b(?:chmod|chown|chgrp)\s+[0-9]{3,4}\b',                         # permission cmds
        r'\b(?:eval|exec)\s+[^\s]',                                          # eval/exec
        r'\$\([^)]{4,60}\)',                                                  # command substitution $(...)
        r'`[^`]{4,60}`',                                                      # backtick substitution
    ]),
}

EXTRACTORS = {k: re.compile(v, re.IGNORECASE) for k, v in _EXTRACTOR_PATTERNS.items()}

# ── Default input.txt content per type ───────────────────────────────────────
DEFAULT_INPUTS = {
    'env_vars': """\
# ENV_VARS input triggers
# Lines with  regex:  prefix are used as raw regex patterns.
# Plain lines are matched as case-insensitive substrings.
#
regex:[A-Z][A-Z0-9_]{2,}=
export
API_KEY
SECRET_KEY
ACCESS_KEY
ACCESS_TOKEN
DATABASE_URL
DB_HOST
DB_NAME
DB_USER
DB_PASSWORD
REDIS_URL
KAFKA_
MONGO_URI
ES_HOST
ELASTIC_
AWS_ACCESS
AWS_SECRET
AWS_REGION
AWS_BUCKET
GCP_PROJECT
GCP_KEY
AZURE_
PRIVATE_KEY
PUBLIC_KEY
CERTIFICATE
SSL_CERT
TLS_
HOST=
PORT=
USERNAME=
PASSWORD=
TOKEN=
SECRET=
BASE_URL=
ENDPOINT=
AUTH_
FLASK_
DJANGO_
RAILS_
NODE_ENV
LOG_LEVEL
""",

    'paths': """\
# Paths input triggers
#
/etc/
/var/
/usr/
/opt/
/home/
/tmp/
/proc/
/sys/
/run/
/lib/
/bin/
/sbin/
/dev/
./
~/
regex:%[0-9A-Fa-f]{2}
/config
/conf
/certs
/ssl
/tls
/keys
/secrets
/logs
/data
/init.d
/systemd
/nginx
/apache
/httpd
/nginx.conf
/application.yml
/application.properties
/settings.py
/.env
/.ssh
/authorized_keys
/known_hosts
/passwd
/shadow
/hosts
/resolv.conf
/sudoers
/crontab
""",

    'headers': """\
# Headers input triggers
#
X-
x-
Authorization
Bearer
Basic
Content-Type:
Accept:
api-key
API-Key
x-api-key
X-Api-Key
X-Auth
X-Token
X-Request
X-Forwarded
X-Real-IP
X-Correlation
X-Trace
X-Session
X-User
X-Client
X-Source
X-B3
x-amz-
x-goog-
x-ms-
""",

    'default_creds': """\
# Default credentials input triggers
#
admin
root
guest
default
anonymous
credentials
credential
password
passwd
secret
username
changeme
letmein
admin123
password123
P@ssword
default password
default user
initial password
factory default
out of the box
api key
api_key
access token
access_token
login with
sign in with
authenticate with
""",

    'commands': """\
# Command injection / shell command triggers
#
/bin/
/sbin/
.bin/
bin/bash
bin/sh
/bin/sh
/bin/bash
sudo
curl
wget
bash
sh
aws
gcloud
kubectl
terraform
docker
helm
eksctl
az
gsutil
vault
nomad
cdk
pulumi
python3
pip install
pip3
npm install
npm run
npx
yarn
apt-get
apt install
yum install
dnf install
brew install
chmod
chown
chgrp
grep
sed
awk
xargs
eval
exec
$(
`
make
gcc
go build
java -jar
mvn
gradle
""",
}

# ── Helpers ───────────────────────────────────────────────────────────────────
def l2_id_from_item_id(item_id: str) -> str:
    """SVC_001_C1_L2_001_HT_001 → SVC_001_C1_L2_001"""
    idx = item_id.rfind('_HT_')
    return item_id[:idx] if idx != -1 else item_id


def build_url_map(main_path: str) -> dict:
    """Build {l2_id: url} from the conceptual mapping JSON."""
    with open(main_path) as f:
        cm = json.load(f)
    url_map = {}
    for svc in cm['Services'].values():
        for ch in svc['Chapters'].values():
            for l2_id, l2 in ch['Subchapters'].items():
                url = l2.get('URL', '').strip()
                if url:
                    url_map[l2_id] = url
    return url_map


def build_triggers(input_path: str):
    """
    Parse input.txt → compiled regex that matches any trigger.
    Plain lines → escaped substring.  regex:PATTERN lines → raw pattern.
    """
    patterns = []
    with open(input_path) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            if line.lower().startswith('regex:'):
                patterns.append(line[6:])
            else:
                patterns.append(re.escape(line))
    if not patterns:
        raise ValueError(f"No trigger patterns found in {input_path}")
    return re.compile('|'.join(patterns), re.IGNORECASE)


# ── Core run ──────────────────────────────────────────────────────────────────
def run(type_key: str, bridge_path: str, main_path: str):
    folder       = FOLDERS[type_key]
    in_path      = os.path.join(ROOT, folder, 'input.txt')
    out_txt_path = os.path.join(ROOT, folder, 'output.txt')
    out_json_path = os.path.join(ROOT, folder, 'output.json')
    wordlist_path = os.path.join(ROOT, folder, 'wordlist.txt')

    if not os.path.exists(in_path):
        print(f"[{type_key}] ERROR: {in_path} not found — run --init first", file=sys.stderr)
        return

    print(f"[{type_key}] Loading data…")
    trigger_re = build_triggers(in_path)
    extractor  = EXTRACTORS[type_key]
    url_map    = build_url_map(main_path)

    with open(bridge_path) as f:
        bridge = json.load(f)

    extracted_values: set = set()
    reference_urls:   set = set()
    matched_items = 0

    for svc in bridge['Services'].values():
        for ch in svc['Chapters'].values():
            for l2 in ch['Subchapters'].values():
                for item in l2['How_To_Inventory']:
                    steps = item.get('Steps', [])
                    triggered = [s for s in steps if trigger_re.search(s)]
                    if not triggered:
                        continue

                    matched_items += 1

                    # Extract specific values from triggered steps
                    for step in triggered:
                        for m in extractor.finditer(step):
                            val = m.group(0).strip().rstrip('.,;:')
                            if len(val) >= 2:
                                extracted_values.add(val)

                    # Look up URL via L2 id
                    l2_id = l2_id_from_item_id(item['ID'])
                    url   = url_map.get(l2_id, '')
                    if url:
                        reference_urls.add(url)

    sorted_values = sorted(extracted_values, key=str.lower)
    sorted_refs   = sorted(reference_urls)

    output = {
        'query_type':    type_key,
        'matched_items': matched_items,
        'LIST':          sorted_values,
        'References':    sorted_refs,
    }

    # output.txt — backward-compatible (JSON content)
    with open(out_txt_path, 'w') as f:
        json.dump(output, f, indent=2)

    # output.json — structured JSON (same content, proper extension)
    with open(out_json_path, 'w') as f:
        json.dump(output, f, indent=2)

    # wordlist.txt — flat newline-separated list, Burp-ready
    with open(wordlist_path, 'w') as f:
        f.write('\n'.join(sorted_values))
        if sorted_values:
            f.write('\n')

    print(f"[{type_key}] {matched_items} items matched | "
          f"{len(extracted_values)} unique values | "
          f"{len(reference_urls)} URLs")
    print(f"[{type_key}] → {out_json_path}")
    print(f"[{type_key}] → {wordlist_path}  (wordlist)")


# ── Init ──────────────────────────────────────────────────────────────────────
def init_structure(overwrite=False):
    """Create SVC_DSR/ folder tree with default input.txt files."""
    os.makedirs(ROOT, exist_ok=True)
    for type_key, folder in FOLDERS.items():
        dir_path = os.path.join(ROOT, folder)
        os.makedirs(dir_path, exist_ok=True)

        in_path       = os.path.join(dir_path, 'input.txt')
        out_txt_path  = os.path.join(dir_path, 'output.txt')
        out_json_path = os.path.join(dir_path, 'output.json')
        wordlist_path = os.path.join(dir_path, 'wordlist.txt')

        if not os.path.exists(in_path) or overwrite:
            with open(in_path, 'w') as f:
                f.write(DEFAULT_INPUTS[type_key])
            print(f"  wrote {in_path}")
        else:
            print(f"  kept  {in_path}  (already exists; use --overwrite to reset)")

        for p in (out_txt_path, out_json_path, wordlist_path):
            if not os.path.exists(p):
                Path(p).touch()

    print(f"\nSVC_DSR/ ready. Edit the input.txt files to customize triggers, then run:")
    for type_key, folder in FOLDERS.items():
        print(f"  python3 svc_dsr.py --type {type_key}")
    print(f"  python3 svc_dsr.py --all   (runs all five)")
    print(f"\nOutputs per category:")
    print(f"  output.json   — structured JSON (query_type, matched_items, LIST, References)")
    print(f"  wordlist.txt  — flat list, load directly into Burp Intruder")
    print(f"  output.txt    — backward-compatible copy of output.json")


# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    p = argparse.ArgumentParser(
        description='Service Disseminator — extract security-relevant values from how-to steps',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument('--type', choices=list(FOLDERS.keys()),
                   help='Category to run')
    p.add_argument('--bridge', default='how_to_steps_bridge.json',
                   help='Path to how_to_steps_bridge.json  (default: %(default)s)')
    p.add_argument('--main',   default='conceptual_mapping_v4_complete.json',
                   help='Path to conceptual_mapping_v4_complete.json  (default: %(default)s)')
    p.add_argument('--init',   action='store_true',
                   help='Create SVC_DSR/ folder structure with default input.txt files')
    p.add_argument('--overwrite', action='store_true',
                   help='With --init: overwrite existing input.txt files with defaults')
    p.add_argument('--all',   action='store_true',
                   help='Run all five categories (also runs --init first)')
    args = p.parse_args()

    if args.init or args.all:
        init_structure(overwrite=args.overwrite)

    if args.all:
        print()
        for type_key in FOLDERS:
            run(type_key, args.bridge, args.main)
            print()
    elif args.type:
        run(args.type, args.bridge, args.main)
    elif not args.init:
        p.print_help()
