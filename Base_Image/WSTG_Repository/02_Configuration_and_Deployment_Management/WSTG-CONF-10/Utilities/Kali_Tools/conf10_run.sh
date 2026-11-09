#!/usr/bin/env bash
# =============================================================================
# WSTG-CONF-10 — Subdomain Takeover Pipeline Orchestrator
#
# Runs the full CONF-10 pipeline in sequence:
#   Step 1: subfinder  → enumerate subdomains
#   Step 2: dnsx       → resolve CNAMEs
#   Step 3: subzy      → fast takeover fingerprint scan
#   Step 4: Python     → CNAME analysis + HTTP probing + findings report
#
# Usage:
#   ./conf10_run.sh -d example.com
#   ./conf10_run.sh -d example.com --skip-subzy --http-also
#
# Flags:
#   -d / --domain     Target domain (required)
#   --skip-subzy      Skip subzy step (if not installed)
#   --skip-dnsx       Skip dnsx step (if not installed)
#   --http-also       Also probe http:// if https:// fails (passed to Python)
#   --concurrency N   Parallel probes in Python step (default: 10)
#   --timeout N       curl timeout per probe in Python step (default: 10)
#   --python          Path to python3 (default: python3)
#   --script          Path to conf10_takeover.py (default: same dir as this script)
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DOMAIN=""
SKIP_SUBZY=false
SKIP_DNSX=false
HTTP_ALSO=false
CONCURRENCY=10
TIMEOUT=10
PYTHON="python3"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAKEOVER_SCRIPT="${SCRIPT_DIR}/conf10_takeover.py"

# ---------------------------------------------------------------------------
# Output paths (match the paths in your CONF-10 notes)
# ---------------------------------------------------------------------------
SUBFINDER_OUT="/kali-tools/subfinder/subdomains.txt"
DNSX_OUT="/kali-tools/dnsx/dnsx_resolved.txt"
SUBZY_OUT="/kali-tools/subzy/subzy_out.txt"
DIG_OUT="/kali-tools/dig/dig_cname.txt"
FINDINGS_MD="outputs/test_outputs/findings.md"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--domain)
            DOMAIN="$2"; shift 2 ;;
        --skip-subzy)
            SKIP_SUBZY=true; shift ;;
        --skip-dnsx)
            SKIP_DNSX=true; shift ;;
        --http-also)
            HTTP_ALSO=true; shift ;;
        --concurrency)
            CONCURRENCY="$2"; shift 2 ;;
        --timeout)
            TIMEOUT="$2"; shift 2 ;;
        --python)
            PYTHON="$2"; shift 2 ;;
        --script)
            TAKEOVER_SCRIPT="$2"; shift 2 ;;
        --subfinder-out)
            SUBFINDER_OUT="$2"; shift 2 ;;
        --dnsx-out)
            DNSX_OUT="$2"; shift 2 ;;
        --subzy-out)
            SUBZY_OUT="$2"; shift 2 ;;
        --dig-out)
            DIG_OUT="$2"; shift 2 ;;
        --output)
            FINDINGS_MD="$2"; shift 2 ;;
        -h|--help)
            sed -n '3,30p' "$0" | sed 's/^# //'
            exit 0 ;;
        *)
            echo "[!] Unknown argument: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$DOMAIN" ]]; then
    echo "[!] Domain is required: -d example.com"
    exit 1
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
BOLD="\033[1m"
RESET="\033[0m"
GREEN="\033[92m"
YELLOW="\033[93m"
RED="\033[91m"

info()    { echo -e "  ${GREEN}[*]${RESET} $*"; }
warn()    { echo -e "  ${YELLOW}[!]${RESET} $*"; }
section() { echo -e "\n${BOLD}${GREEN}=== $* ===${RESET}"; }
die()     { echo -e "  ${RED}[!]${RESET} $*" >&2; exit 1; }

require_tool() {
    command -v "$1" &>/dev/null || die "$1 is not on PATH. Install it or use --skip-$1."
}

mkdir_for() { mkdir -p "$(dirname "$1")"; }

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}============================================================${RESET}"
echo -e "${BOLD} WSTG-CONF-10 — Subdomain Takeover Pipeline${RESET}"
echo -e "${BOLD} Target: ${DOMAIN}${RESET}"
echo -e "${BOLD}============================================================${RESET}"
echo ""
info "Output paths:"
info "  subfinder → ${SUBFINDER_OUT}"
info "  dnsx      → ${DNSX_OUT}"
info "  subzy     → ${SUBZY_OUT}"
info "  dig CNAME → ${DIG_OUT}"
info "  findings  → ${FINDINGS_MD}"
echo ""

# ---------------------------------------------------------------------------
# Step 1: subfinder
# ---------------------------------------------------------------------------
section "STEP 1: subfinder — enumerate subdomains"
require_tool subfinder
mkdir_for "${SUBFINDER_OUT}"

info "Running: subfinder -d ${DOMAIN} -o ${SUBFINDER_OUT}"
if subfinder -d "${DOMAIN}" -o "${SUBFINDER_OUT}"; then
    COUNT=$(wc -l < "${SUBFINDER_OUT}" | tr -d ' ')
    info "subfinder complete — ${COUNT} subdomains written to ${SUBFINDER_OUT}"
else
    die "subfinder failed (exit $?)"
fi

# ---------------------------------------------------------------------------
# Step 2: dnsx
# ---------------------------------------------------------------------------
section "STEP 2: dnsx — resolve CNAMEs"
if $SKIP_DNSX; then
    warn "Skipping dnsx (--skip-dnsx)"
    DNSX_OUT=""
else
    require_tool dnsx
    mkdir_for "${DNSX_OUT}"
    info "Running: dnsx -l ${SUBFINDER_OUT} -cname -resp -o ${DNSX_OUT}"
    if dnsx -l "${SUBFINDER_OUT}" -cname -resp -o "${DNSX_OUT}"; then
        COUNT=$(wc -l < "${DNSX_OUT}" | tr -d ' ')
        info "dnsx complete — ${COUNT} lines written to ${DNSX_OUT}"
    else
        warn "dnsx exited non-zero (some failures are normal — continuing)"
    fi
fi

# ---------------------------------------------------------------------------
# Step 3: subzy
# ---------------------------------------------------------------------------
section "STEP 3: subzy — fast takeover fingerprint scan"
if $SKIP_SUBZY; then
    warn "Skipping subzy (--skip-subzy)"
    SUBZY_OUT=""
else
    if ! command -v subzy &>/dev/null; then
        warn "subzy not found on PATH — skipping. Install with: go install github.com/PentestPad/subzy@latest"
        SUBZY_OUT=""
    else
        mkdir_for "${SUBZY_OUT}"
        info "Running: subzy run --targets ${SUBFINDER_OUT} --output ${SUBZY_OUT}"
        # subzy writes its own output; some versions use --output, some use -output
        if subzy run --targets "${SUBFINDER_OUT}" --output "${SUBZY_OUT}" 2>/dev/null || \
           subzy run --targets "${SUBFINDER_OUT}" -output "${SUBZY_OUT}" 2>/dev/null; then
            info "subzy complete — results in ${SUBZY_OUT}"
        else
            warn "subzy failed or unsupported flag — skipping output file"
            SUBZY_OUT=""
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Step 4: Python analysis
# ---------------------------------------------------------------------------
section "STEP 4: Python — CNAME analysis + HTTP probing + findings report"
require_tool dig
require_tool curl

if [[ ! -f "${TAKEOVER_SCRIPT}" ]]; then
    die "conf10_takeover.py not found at ${TAKEOVER_SCRIPT}. Use --script to set path."
fi

mkdir_for "${DIG_OUT}"
mkdir_for "${FINDINGS_MD}"

CMD=(
    "${PYTHON}" "${TAKEOVER_SCRIPT}"
    --domain "${DOMAIN}"
    --subdomains "${SUBFINDER_OUT}"
    --dig-out "${DIG_OUT}"
    --output "${FINDINGS_MD}"
    --concurrency "${CONCURRENCY}"
    --timeout "${TIMEOUT}"
)

if [[ -n "${DNSX_OUT}" && -f "${DNSX_OUT}" ]]; then
    CMD+=(--dnsx "${DNSX_OUT}")
fi
if [[ -n "${SUBZY_OUT}" && -f "${SUBZY_OUT}" ]]; then
    CMD+=(--subzy "${SUBZY_OUT}")
fi
if $HTTP_ALSO; then
    CMD+=(--http-also)
fi

info "Running: ${CMD[*]}"
echo ""
"${CMD[@]}"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}============================================================${RESET}"
echo -e "${BOLD} CONF-10 PIPELINE COMPLETE${RESET}"
echo -e "${BOLD}============================================================${RESET}"
echo ""
info "All tool outputs:"
info "  subfinder : ${SUBFINDER_OUT}"
[[ -n "${DNSX_OUT}" ]]  && info "  dnsx      : ${DNSX_OUT}"
[[ -n "${SUBZY_OUT}" ]] && info "  subzy     : ${SUBZY_OUT}"
info "  dig CNAME : ${DIG_OUT}"
info "  findings  : ${FINDINGS_MD}"
echo ""
echo -e "  ${BOLD}Open the findings report:${RESET}"
echo -e "  cat ${FINDINGS_MD}"
echo ""
