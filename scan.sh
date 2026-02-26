#!/bin/bash
# ==========================================
#  Vulnerability Scanner Automation v3.0
#  Features: Resume, Auto-pause, Detachable
#  Requires: recon.sh to have been run first
#  Usage: ./scan.sh <domain> [options]
#  Managed by: scan_manager.sh
# ==========================================

# ==========================================
# COLORS & FORMATTING
# ==========================================
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
RESET='\033[0m'

# ==========================================
# BANNER
# ==========================================
print_banner() {
    echo -e "${RED}${BOLD}"
    echo "  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗"
    echo "  ██║   ██║██║   ██║██║     ████╗  ██║"
    echo "  ██║   ██║██║   ██║██║     ██╔██╗ ██║"
    echo "  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║"
    echo "   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║"
    echo "    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝  Scanner v3.0"
    echo -e "${RESET}"
}

# ==========================================
# HELPERS
# ==========================================
log_info()    { echo -e "[$(date '+%H:%M:%S')] ${BLUE}[*]${RESET} $1"; }
log_success() { echo -e "[$(date '+%H:%M:%S')] ${GREEN}[+]${RESET} $1"; }
log_warn()    { echo -e "[$(date '+%H:%M:%S')] ${YELLOW}[!]${RESET} $1"; }
log_error()   { echo -e "[$(date '+%H:%M:%S')] ${RED}[✗]${RESET} $1"; }
log_phase()   {
    echo -e "\n${RED}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${RED}${BOLD}  $1${RESET}"
    echo -e "${RED}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}
log_finding() {
    local severity="$1"
    local msg="$2"
    case "$severity" in
        CRITICAL) echo -e "[$(date '+%H:%M:%S')] ${RED}${BOLD}  [CRITICAL]${RESET} $msg" ;;
        HIGH)     echo -e "[$(date '+%H:%M:%S')] ${RED}  [HIGH]${RESET} $msg" ;;
        MEDIUM)   echo -e "[$(date '+%H:%M:%S')] ${YELLOW}  [MEDIUM]${RESET} $msg" ;;
        LOW)      echo -e "[$(date '+%H:%M:%S')] ${BLUE}  [LOW]${RESET} $msg" ;;
        INFO)     echo -e "[$(date '+%H:%M:%S')] ${CYAN}  [INFO]${RESET} $msg" ;;
    esac
}

count_lines() {
    [ -f "$1" ] && wc -l < "$1" || echo 0
}

safe_touch() {
    for f in "$@"; do [ -f "$f" ] || touch "$f"; done
}

require_tool() {
    if ! command -v "$1" &>/dev/null; then
        log_warn "Tool not found: ${BOLD}$1${RESET} — skipping related step."
        return 1
    fi
    return 0
}

require_file() {
    if [ ! -f "$1" ] || [ ! -s "$1" ]; then
        log_warn "Required file missing or empty: ${BOLD}$1${RESET} — skipping step."
        return 1
    fi
    return 0
}

report_finding() {
    local section="$1"
    local severity="$2"
    local tool="$3"
    local detail="$4"
    echo "| $section | $severity | $tool | $detail |" >> "$REPORT_MD"
}

# ==========================================
# RESUME / STEP STATE TRACKING
# ==========================================
# Each completed step name is written to STEP_STATE_FILE.
# On re-run, completed steps are skipped automatically.

step_done() {
    grep -qxF "$1" "$STEP_STATE_FILE" 2>/dev/null
}

mark_step_done() {
    echo "$1" >> "$STEP_STATE_FILE"
    log_info "Step '${BOLD}$1${RESET}' marked complete."
}

# ==========================================
# NETWORK WATCHDOG
# ==========================================
# Spawns a background loop that monitors connectivity.
# On 3 consecutive ping failures → creates PAUSE_FILE.
# When connectivity restored → removes PAUSE_FILE.
# All steps call wait_if_paused() before executing.

PAUSE_FILE=""   # set after OUT_DIR is known
WATCHDOG_PID=""

start_network_watchdog() {
    (
        local fail_count=0
        local check_host="8.8.8.8"
        local paused=false

        while true; do
            if ping -c 1 -W 3 "$check_host" &>/dev/null 2>&1; then
                fail_count=0
                if $paused; then
                    rm -f "$PAUSE_FILE"
                    paused=false
                    echo "[$(date '+%H:%M:%S')] [WATCHDOG] Network restored — scan will resume." \
                        >> "${PAUSE_FILE%/*}/watchdog.log"
                fi
            else
                ((fail_count++))
                echo "[$(date '+%H:%M:%S')] [WATCHDOG] Ping failed ($fail_count/3)" \
                    >> "${PAUSE_FILE%/*}/watchdog.log"
                if [ "$fail_count" -ge 3 ] && ! $paused; then
                    touch "$PAUSE_FILE"
                    paused=true
                    echo "[$(date '+%H:%M:%S')] [WATCHDOG] Network lost — scan paused." \
                        >> "${PAUSE_FILE%/*}/watchdog.log"
                fi
            fi
            sleep 10
        done
    ) &
    WATCHDOG_PID=$!
    echo "$WATCHDOG_PID" > "$OUT_DIR/.watchdog_pid"
    log_info "Network watchdog started (PID: $WATCHDOG_PID)"
}

stop_network_watchdog() {
    if [ -n "$WATCHDOG_PID" ] && kill -0 "$WATCHDOG_PID" 2>/dev/null; then
        kill "$WATCHDOG_PID" 2>/dev/null
        rm -f "$OUT_DIR/.watchdog_pid"
    fi
}

wait_if_paused() {
    if [ ! -f "$PAUSE_FILE" ]; then return 0; fi

    log_warn "Scan PAUSED (network/manual pause). Waiting to resume..."
    log_warn "To manually resume: rm '$PAUSE_FILE'"

    while [ -f "$PAUSE_FILE" ]; do
        sleep 15
    done

    log_success "Scan RESUMED — continuing from last checkpoint."
}

# ==========================================
# GRACEFUL SHUTDOWN HANDLER
# ==========================================
cleanup_on_exit() {
    local exit_code=$?
    stop_network_watchdog
    rm -f "$OUT_DIR/.scan_pid"

    if [ "$exit_code" -eq 0 ]; then
        echo "done" > "$OUT_DIR/.scan_status"
        log_success "Scan finished cleanly."
    else
        echo "interrupted" > "$OUT_DIR/.scan_status"
        log_warn "Scan interrupted (exit $exit_code). Re-run to resume from last checkpoint."
    fi
}

trap cleanup_on_exit EXIT
trap 'log_warn "Received SIGTERM — stopping scan."; exit 130' TERM
trap 'log_warn "Received SIGINT — stopping scan."; exit 130' INT

# ==========================================
# USAGE
# ==========================================
usage() {
    echo -e "${BOLD}Usage:${RESET} $0 <target-domain> [options]"
    echo ""
    echo -e "${BOLD}Options:${RESET}"
    echo "  --invasive              Enable active/invasive scans (XSS, SQLi fuzz)"
    echo "  --threads <n>           Thread count (default: 50)"
    echo "  --rate <n>              Rate limit for ffuf/nuclei (default: 50)"
    echo "  --severity <s>          Nuclei severity filter (default: low,medium,high,critical)"
    echo "  --nuclei-templates <p>  Path to nuclei templates (default: ~/nuclei-templates)"
    echo "  --skip-nuclei           Skip nuclei scan"
    echo "  --skip-js               Skip JS analysis"
    echo "  --skip-ffuf             Skip directory fuzzing"
    echo "  --skip-gf               Skip GF pattern filtering"
    echo "  --fresh                 Ignore saved state and restart from scratch"
    echo ""
    echo -e "${BOLD}Resume:${RESET}"
    echo "  Simply re-run the same command — completed steps are skipped automatically."
    echo "  Use --fresh to force a full restart."
    echo ""
    echo -e "${BOLD}Examples:${RESET}"
    echo "  $0 example.com"
    echo "  $0 example.com --invasive --threads 100"
    echo "  $0 example.com --fresh"
    exit 1
}

# ==========================================
# ARG PARSING
# ==========================================
if [ "$#" -lt 1 ]; then
    print_banner
    usage
fi

target="$1"
shift

INVASIVE=false
THREADS=50
RATE=50
SEVERITY="low,medium,high,critical"
NUCLEI_TEMPLATES="$HOME/nuclei-templates"
SKIP_NUCLEI=false
SKIP_JS=false
SKIP_FFUF=false
SKIP_GF=false
FRESH_START=false
FFUF_WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --invasive)           INVASIVE=true; shift ;;
        --threads)            THREADS="$2"; shift 2 ;;
        --rate)               RATE="$2"; shift 2 ;;
        --severity)           SEVERITY="$2"; shift 2 ;;
        --nuclei-templates)   NUCLEI_TEMPLATES="$2"; shift 2 ;;
        --skip-nuclei)        SKIP_NUCLEI=true; shift ;;
        --skip-js)            SKIP_JS=true; shift ;;
        --skip-ffuf)          SKIP_FFUF=true; shift ;;
        --skip-gf)            SKIP_GF=true; shift ;;
        --fresh)              FRESH_START=true; shift ;;
        -h|--help)            usage ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
done

# ==========================================
# SETUP
# ==========================================
OUT_DIR="$HOME/bb/${target}"
VULN_DIR="$OUT_DIR/vulns"
REPORT_DIR="$OUT_DIR/report"
LOG_FILE="$OUT_DIR/vuln_scan.log"
STEP_STATE_FILE="$OUT_DIR/.scan_steps"
PAUSE_FILE="$OUT_DIR/.paused"

mkdir -p "$VULN_DIR" "$REPORT_DIR"

# Write PID so manager can track/kill us
echo $$ > "$OUT_DIR/.scan_pid"
echo "running" > "$OUT_DIR/.scan_status"

# Redirect all output to log file AND stdout (so manager can tail -f)
exec > >(tee -a "$LOG_FILE") 2>&1

# ==========================================
# RESUME / FRESH START LOGIC
# ==========================================
if [ "$FRESH_START" = "true" ]; then
    log_warn "Fresh start requested — clearing previous scan state."
    rm -f "$STEP_STATE_FILE"
    rm -f "$VULN_DIR"/*.txt "$VULN_DIR"/*.json "$VULN_DIR"/*.html 2>/dev/null
fi

IS_RESUME=false
if [ -f "$STEP_STATE_FILE" ] && [ -s "$STEP_STATE_FILE" ]; then
    IS_RESUME=true
    COMPLETED=$(wc -l < "$STEP_STATE_FILE")
    log_warn "Resuming scan — ${BOLD}$COMPLETED${RESET} steps already completed."
fi

# ==========================================
# VERIFY RECON OUTPUT EXISTS
# ==========================================
if [ ! -d "$OUT_DIR" ]; then
    log_error "Recon output directory not found: $OUT_DIR"
    log_error "Please run recon.sh first: ./recon.sh $target"
    exit 1
fi

# ==========================================
# INIT REPORT (only on fresh start)
# ==========================================
REPORT_MD="$REPORT_DIR/report.md"
REPORT_HTML="$REPORT_DIR/report.html"
SCAN_DATE=$(date '+%Y-%m-%d %H:%M:%S')
START_TIME=$(date +%s)

init_report() {
    # Don't overwrite if resuming
    if [ -f "$REPORT_MD" ] && [ "$IS_RESUME" = "true" ]; then
        log_info "Keeping existing report (resume mode)."
        return
    fi
    cat > "$REPORT_MD" <<EOF
# Vulnerability Scan Report
**Target:** \`$target\`
**Date:** $SCAN_DATE
**Mode:** $([ "$INVASIVE" = "true" ] && echo "Invasive (Active)" || echo "Passive")

---

## Summary

| Category | Count |
|----------|-------|
| Nuclei Findings | - |
| JS Secrets | - |
| Potential SSRF | - |
| Potential SQLi | - |
| Potential LFI | - |
| Potential RCE | - |
| Open Redirects | - |
| XSS (Dalfox) | - |
| FFUF Findings | - |

---

## Findings

| Category | Severity | Tool | Detail |
|----------|----------|------|--------|
EOF
}

# ==========================================
# START
# ==========================================
print_banner

echo -e "${BOLD}Target    :${RESET} $target"
echo -e "${BOLD}Output    :${RESET} $OUT_DIR"
echo -e "${BOLD}Vuln Dir  :${RESET} $VULN_DIR"
echo -e "${BOLD}Report    :${RESET} $REPORT_DIR"
echo -e "${BOLD}Invasive  :${RESET} $INVASIVE"
echo -e "${BOLD}Threads   :${RESET} $THREADS"
echo -e "${BOLD}Rate      :${RESET} $RATE"
echo -e "${BOLD}Severity  :${RESET} $SEVERITY"
echo -e "${BOLD}Resume    :${RESET} $IS_RESUME"
echo -e "${BOLD}PID       :${RESET} $$"
echo ""

init_report
start_network_watchdog

# ==========================================
# STEP 1: Nuclei - Full Vulnerability Scan
# ==========================================
STEP_NAME="nuclei_main"
if [ "$SKIP_NUCLEI" = true ]; then
    log_phase "Step 1: Nuclei Scan (Skipped via --skip-nuclei)"
elif step_done "$STEP_NAME"; then
    log_phase "Step 1: Nuclei Vulnerability Scan [ALREADY DONE — SKIPPED]"
else
    log_phase "Step 1: Nuclei Vulnerability Scan"
    wait_if_paused

    if require_tool nuclei && require_file "$OUT_DIR/web_alive.txt"; then
        awk '{print $1}' "$OUT_DIR/web_alive.txt" > "$VULN_DIR/nuclei_targets.txt"

        log_info "Updating Nuclei templates..."
        nuclei -update-templates -silent 2>/dev/null

        log_info "Running Nuclei (CVE + Tech + OSINT)..."
        nuclei -l "$VULN_DIR/nuclei_targets.txt" \
               -tags cve,osint,tech,exposure,misconfig,default-login \
               -et dos,fuzzing,headless \
               -severity "$SEVERITY" \
               -rate-limit "$RATE" \
               -silent \
               -o "$VULN_DIR/nuclei_vulns.txt" \
               -t "$NUCLEI_TEMPLATES/" 2>/dev/null

        wait_if_paused
        log_info "Running Nuclei exposure scan..."
        nuclei -l "$VULN_DIR/nuclei_targets.txt" \
               -tags exposure,token,secret,api-key \
               -silent \
               -rate-limit "$RATE" \
               -o "$VULN_DIR/nuclei_exposures.txt" \
               -t "$NUCLEI_TEMPLATES/" 2>/dev/null

        wait_if_paused
        if require_file "$OUT_DIR/final_subdomains.txt"; then
            log_info "Checking for subdomain takeovers..."
            nuclei -l "$OUT_DIR/final_subdomains.txt" \
                   -tags takeover \
                   -silent \
                   -rate-limit "$RATE" \
                   -o "$VULN_DIR/nuclei_takeovers.txt" \
                   -t "$NUCLEI_TEMPLATES/" 2>/dev/null
            TAKEOVER_COUNT=$(count_lines "$VULN_DIR/nuclei_takeovers.txt")
            [ "$TAKEOVER_COUNT" -gt 0 ] && log_finding "CRITICAL" "Potential subdomain takeovers: $TAKEOVER_COUNT"
        fi

        NUCLEI_COUNT=$(count_lines "$VULN_DIR/nuclei_vulns.txt")
        EXPOSURE_COUNT=$(count_lines "$VULN_DIR/nuclei_exposures.txt")
        log_success "Nuclei: ${BOLD}$NUCLEI_COUNT${RESET} vulnerabilities, ${BOLD}$EXPOSURE_COUNT${RESET} exposures"

        if grep -qiE "critical|high" "$VULN_DIR/nuclei_vulns.txt" 2>/dev/null; then
            log_finding "HIGH" "High/Critical Nuclei findings detected — review $VULN_DIR/nuclei_vulns.txt"
            report_finding "Nuclei" "HIGH" "nuclei" "High/Critical findings: $NUCLEI_COUNT total"
        fi
    fi
    mark_step_done "$STEP_NAME"
fi

# ==========================================
# STEP 2: JavaScript Analysis
# ==========================================
STEP_NAME="js_analysis"
if [ "$SKIP_JS" = true ]; then
    log_phase "Step 2: JavaScript Analysis (Skipped via --skip-js)"
elif step_done "$STEP_NAME"; then
    log_phase "Step 2: JavaScript Analysis [ALREADY DONE — SKIPPED]"
else
    log_phase "Step 2: JavaScript Analysis"
    wait_if_paused

    if require_file "$OUT_DIR/clean_urls.txt"; then
        grep -iE "\.js(\?|$)" "$OUT_DIR/clean_urls.txt" | sort -u > "$VULN_DIR/js_files.txt"
        JS_COUNT=$(count_lines "$VULN_DIR/js_files.txt")

        if [ "$JS_COUNT" -eq 0 ]; then
            log_warn "No JS files found in clean_urls.txt"
        else
            log_info "Found ${BOLD}$JS_COUNT${RESET} JS files to analyze"

            if require_tool nuclei; then
                log_info "Scanning JS for secrets/tokens with Nuclei..."
                nuclei -l "$VULN_DIR/js_files.txt" \
                       -t "$NUCLEI_TEMPLATES/http/exposures/" \
                       -tags token,secret,api-key,exposure \
                       -silent \
                       -o "$VULN_DIR/js_secrets.txt" 2>/dev/null
                JS_SECRET_COUNT=$(count_lines "$VULN_DIR/js_secrets.txt")
                [ "$JS_SECRET_COUNT" -gt 0 ] && log_finding "HIGH" "JS Secrets found: $JS_SECRET_COUNT"
                log_success "JS Secrets: ${BOLD}$JS_SECRET_COUNT${RESET} findings"
            fi

            wait_if_paused

            if require_tool mantra; then
                log_info "Mining JS for hidden endpoints with Mantra..."
                cat "$VULN_DIR/js_files.txt" | mantra 2>/dev/null | sort -u > "$VULN_DIR/js_endpoints.txt"
                JS_EP_COUNT=$(count_lines "$VULN_DIR/js_endpoints.txt")
                log_success "JS Hidden Endpoints: ${BOLD}$JS_EP_COUNT${RESET}"
                [ "$JS_EP_COUNT" -gt 0 ] && report_finding "JS Analysis" "MEDIUM" "mantra" "Hidden endpoints in JS: $JS_EP_COUNT"
            fi

            log_info "Extracting API paths from JS..."
            while IFS= read -r jsurl; do
                curl -sk --max-time 10 "$jsurl" 2>/dev/null \
                    | grep -oP '(?:"|'"'"')(/[a-zA-Z0-9_/.-]{3,}(?:\?[^"'"'"']*)?|https?://[^"'"'"']+)(?:"|'"'"')' \
                    | tr -d '"'"'" \
                    | sort -u
            done < "$VULN_DIR/js_files.txt" | sort -u > "$VULN_DIR/js_api_paths.txt"
            JS_API_COUNT=$(count_lines "$VULN_DIR/js_api_paths.txt")
            log_success "JS API Paths Extracted: ${BOLD}$JS_API_COUNT${RESET}"

            wait_if_paused

            if require_tool trufflehog; then
                log_info "Running TruffleHog on JS files..."
                while IFS= read -r jsurl; do
                    trufflehog --regex --entropy=False "$jsurl" 2>/dev/null
                done < "$VULN_DIR/js_files.txt" | sort -u > "$VULN_DIR/trufflehog_secrets.txt"
                TH_COUNT=$(count_lines "$VULN_DIR/trufflehog_secrets.txt")
                [ "$TH_COUNT" -gt 0 ] && log_finding "CRITICAL" "TruffleHog secrets: $TH_COUNT"
                log_success "TruffleHog: ${BOLD}$TH_COUNT${RESET} secrets"
            fi
        fi
    fi
    mark_step_done "$STEP_NAME"
fi

# ==========================================
# STEP 3: Directory & File Fuzzing (FFUF)
# ==========================================
STEP_NAME="ffuf_fuzz"
if [ "$SKIP_FFUF" = true ]; then
    log_phase "Step 3: Directory & File Fuzzing (Skipped via --skip-ffuf)"
elif step_done "$STEP_NAME"; then
    log_phase "Step 3: Directory & File Fuzzing [ALREADY DONE — SKIPPED]"
else
    log_phase "Step 3: Directory & File Fuzzing (FFUF)"
    wait_if_paused

    if require_tool ffuf && require_file "$OUT_DIR/alive_urls_only.txt"; then
        if [ ! -f "$FFUF_WORDLIST" ]; then
            log_error "Wordlist not found: $FFUF_WORDLIST — skipping FFUF."
        else
            grep -iE "admin|dev|stage|test|api|corp|internal|portal|dashboard|manage|backend|uat" \
                "$OUT_DIR/alive_urls_only.txt" \
                | sort -u > "$VULN_DIR/ffuf_interesting.txt"

            INTERESTING_COUNT=$(count_lines "$VULN_DIR/ffuf_interesting.txt")

            if [ "$INTERESTING_COUNT" -gt 0 ]; then
                log_info "Fuzzing ${BOLD}$INTERESTING_COUNT${RESET} interesting targets..."
                ffuf -w "$FFUF_WORDLIST:FUZZ" \
                     -w "$VULN_DIR/ffuf_interesting.txt:URL" \
                     -u "URL/FUZZ" \
                     -mc 200,201,204,301,302,403,405 \
                     -fc 404,429 \
                     -ac \
                     -s \
                     -t "$THREADS" \
                     -rate "$RATE" \
                     -timeout 10 \
                     -o "$VULN_DIR/ffuf_interesting_results.json" \
                     -of json 2>/dev/null
                log_success "FFUF interesting targets done"
            fi

            wait_if_paused

            log_info "Scanning for backup & sensitive files..."
            BACKUP_WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-small-files.txt"
            if [ -f "$BACKUP_WORDLIST" ]; then
                ffuf -w "$BACKUP_WORDLIST:FUZZ" \
                     -w "$OUT_DIR/alive_urls_only.txt:URL" \
                     -u "URL/FUZZ" \
                     -mc 200,403 \
                     -fc 404,429 \
                     -ac \
                     -s \
                     -t "$THREADS" \
                     -rate "$RATE" \
                     -timeout 10 \
                     -o "$VULN_DIR/ffuf_backup_files.json" \
                     -of json 2>/dev/null
                log_success "FFUF backup file scan done"
            fi

            for json_file in "$VULN_DIR"/ffuf_*.json; do
                if [ -f "$json_file" ]; then
                    txt_file="${json_file%.json}.txt"
                    python3 -c "
import json, sys
try:
    with open('$json_file') as f:
        data = json.load(f)
    results = data.get('results', [])
    for r in results:
        print(f\"{r.get('status','?')} {r.get('length','?')} {r.get('url','?')}\")
except:
    pass
" > "$txt_file" 2>/dev/null
                fi
            done

            FFUF_COUNT=$(cat "$VULN_DIR"/ffuf_*.txt 2>/dev/null | wc -l)
            log_success "FFUF Total Findings: ${BOLD}$FFUF_COUNT${RESET}"
            [ "$FFUF_COUNT" -gt 0 ] && report_finding "FFUF" "MEDIUM" "ffuf" "Directory/file findings: $FFUF_COUNT"
        fi
    fi
    mark_step_done "$STEP_NAME"
fi

# ==========================================
# STEP 4: GF Pattern Filtering
# ==========================================
STEP_NAME="gf_patterns"
if [ "$SKIP_GF" = true ]; then
    log_phase "Step 4: GF Pattern Filtering (Skipped via --skip-gf)"
elif step_done "$STEP_NAME"; then
    log_phase "Step 4: GF Pattern Filtering [ALREADY DONE — SKIPPED]"
else
    log_phase "Step 4: GF Pattern Filtering"
    wait_if_paused

    if require_tool gf && require_file "$OUT_DIR/final_params.txt"; then
        PARAM_COUNT=$(count_lines "$OUT_DIR/final_params.txt")
        log_info "Running GF patterns on ${BOLD}$PARAM_COUNT${RESET} URLs..."

        declare -A GF_PATTERNS=(
            ["ssrf"]="potential_ssrf.txt"
            ["sqli"]="potential_sqli.txt"
            ["lfi"]="potential_lfi.txt"
            ["redirect"]="potential_redirect.txt"
            ["rce"]="potential_rce.txt"
            ["ssti"]="potential_ssti.txt"
            ["idor"]="potential_idor.txt"
            ["xss"]="potential_xss.txt"
            ["xxe"]="potential_xxe.txt"
            ["debug_logic"]="potential_debug.txt"
        )

        for pattern in "${!GF_PATTERNS[@]}"; do
            outfile="$VULN_DIR/${GF_PATTERNS[$pattern]}"
            gf "$pattern" "$OUT_DIR/final_params.txt" 2>/dev/null | sort -u > "$outfile"
            cnt=$(count_lines "$outfile")
            if [ "$cnt" -gt 0 ]; then
                log_finding "MEDIUM" "GF [$pattern]: $cnt potential URLs"
                report_finding "GF Pattern" "MEDIUM" "gf" "$pattern: $cnt potential URLs"
            fi
        done

        log_success "GF filtering complete — check $VULN_DIR/potential_*.txt"
    fi
    mark_step_done "$STEP_NAME"
fi

# ==========================================
# STEP 5: CORS Misconfiguration
# ==========================================
STEP_NAME="cors_check"
if step_done "$STEP_NAME"; then
    log_phase "Step 5: CORS Misconfiguration [ALREADY DONE — SKIPPED]"
else
    log_phase "Step 5: CORS Misconfiguration Check"
    wait_if_paused

    if require_file "$OUT_DIR/alive_urls_only.txt"; then
        if require_tool corsy; then
            log_info "Running Corsy..."
            corsy -i "$OUT_DIR/alive_urls_only.txt" \
                  -t "$THREADS" \
                  --headers "User-Agent: Mozilla/5.0" \
                  > "$VULN_DIR/cors_findings.txt" 2>/dev/null
            CORS_COUNT=$(grep -c "CORS" "$VULN_DIR/cors_findings.txt" 2>/dev/null || echo 0)
        elif require_tool nuclei; then
            log_info "Checking CORS with Nuclei..."
            nuclei -l "$OUT_DIR/alive_urls_only.txt" \
                   -tags cors \
                   -silent \
                   -o "$VULN_DIR/cors_findings.txt" \
                   -t "$NUCLEI_TEMPLATES/" 2>/dev/null
            CORS_COUNT=$(count_lines "$VULN_DIR/cors_findings.txt")
        fi

        [ "${CORS_COUNT:-0}" -gt 0 ] && \
            log_finding "HIGH" "CORS misconfigurations: $CORS_COUNT" && \
            report_finding "CORS" "HIGH" "corsy/nuclei" "Misconfigurations: $CORS_COUNT"
        log_success "CORS: ${BOLD}${CORS_COUNT:-0}${RESET} findings"
    fi
    mark_step_done "$STEP_NAME"
fi

# ==========================================
# STEP 6: HTTP Headers & SSL/TLS Check
# ==========================================
STEP_NAME="headers_ssl"
if step_done "$STEP_NAME"; then
    log_phase "Step 6: HTTP Security Headers & SSL/TLS [ALREADY DONE — SKIPPED]"
else
    log_phase "Step 6: HTTP Security Headers & SSL/TLS"
    wait_if_paused

    if require_file "$OUT_DIR/alive_urls_only.txt"; then
        if require_tool nuclei; then
            log_info "Checking missing security headers..."
            nuclei -l "$OUT_DIR/alive_urls_only.txt" \
                   -tags headers,ssl,tls,misconfiguration \
                   -silent \
                   -rate-limit "$RATE" \
                   -o "$VULN_DIR/headers_ssl_findings.txt" \
                   -t "$NUCLEI_TEMPLATES/" 2>/dev/null
            HEADER_COUNT=$(count_lines "$VULN_DIR/headers_ssl_findings.txt")
            [ "$HEADER_COUNT" -gt 0 ] && log_finding "LOW" "Security header/SSL issues: $HEADER_COUNT"
            log_success "Headers/SSL: ${BOLD}$HEADER_COUNT${RESET} findings"
        fi

        if require_tool testssl.sh; then
            log_info "Running testssl.sh on apex domain..."
            testssl.sh --quiet --jsonfile "$VULN_DIR/testssl.json" "$target" 2>/dev/null
            log_success "testssl.sh complete — $VULN_DIR/testssl.json"
        fi
    fi
    mark_step_done "$STEP_NAME"
fi

# ==========================================
# STEP 7: Open Redirect Check
# ==========================================
STEP_NAME="open_redirect"
if step_done "$STEP_NAME"; then
    log_phase "Step 7: Open Redirect Check [ALREADY DONE — SKIPPED]"
else
    log_phase "Step 7: Open Redirect Check"
    wait_if_paused

    if require_file "$VULN_DIR/potential_redirect.txt"; then
        REDIRECT_COUNT=$(count_lines "$VULN_DIR/potential_redirect.txt")
        log_info "Testing ${BOLD}$REDIRECT_COUNT${RESET} potential open redirect URLs..."

        if require_tool nuclei && [ "$REDIRECT_COUNT" -gt 0 ]; then
            nuclei -l "$VULN_DIR/potential_redirect.txt" \
                   -tags redirect \
                   -silent \
                   -o "$VULN_DIR/confirmed_redirects.txt" \
                   -t "$NUCLEI_TEMPLATES/" 2>/dev/null
            CONFIRMED=$(count_lines "$VULN_DIR/confirmed_redirects.txt")
            [ "$CONFIRMED" -gt 0 ] && log_finding "MEDIUM" "Confirmed open redirects: $CONFIRMED" && \
                report_finding "Open Redirect" "MEDIUM" "nuclei" "Confirmed: $CONFIRMED"
            log_success "Open Redirects Confirmed: ${BOLD}$CONFIRMED${RESET}"
        fi
    else
        safe_touch "$VULN_DIR/potential_redirect.txt"
        log_warn "No redirect candidates — run GF step first or check final_params.txt"
    fi
    mark_step_done "$STEP_NAME"
fi

# ==========================================
# STEP 8: SQLi Testing (sqlmap) — Invasive
# ==========================================
STEP_NAME="sqli_sqlmap"
if [ "$INVASIVE" = "true" ]; then
    if step_done "$STEP_NAME"; then
        log_phase "Step 8: SQLi Testing [ALREADY DONE — SKIPPED]"
    else
        log_phase "Step 8: SQLi Testing (sqlmap) [INVASIVE]"
        wait_if_paused

        if require_tool sqlmap && require_file "$VULN_DIR/potential_sqli.txt"; then
            SQLI_COUNT=$(count_lines "$VULN_DIR/potential_sqli.txt")
            log_info "Testing ${BOLD}$SQLI_COUNT${RESET} potential SQLi targets with sqlmap..."

            sqlmap -m "$VULN_DIR/potential_sqli.txt" \
                   --batch \
                   --level=2 \
                   --risk=2 \
                   --threads="$THREADS" \
                   --output-dir="$VULN_DIR/sqlmap/" \
                   --forms \
                   --crawl=2 \
                   --random-agent \
                   --timeout=10 \
                   --retries=2 \
                   -q 2>/dev/null

            SQLI_FINDINGS=$(find "$VULN_DIR/sqlmap/" -name "*.csv" 2>/dev/null | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}')
            log_success "SQLmap done — check $VULN_DIR/sqlmap/"
            [ -n "$SQLI_FINDINGS" ] && report_finding "SQLi" "CRITICAL" "sqlmap" "Potential injections found"
        else
            log_warn "SQLi: potential_sqli.txt missing or sqlmap not found. Run GF step first."
        fi
        mark_step_done "$STEP_NAME"
    fi
else
    log_phase "Step 8: SQLi Testing (Skipped — use --invasive to enable)"
fi

# ==========================================
# STEP 9: XSS Testing (Dalfox) — Invasive
# ==========================================
STEP_NAME="xss_dalfox"
if [ "$INVASIVE" = "true" ]; then
    if step_done "$STEP_NAME"; then
        log_phase "Step 9: XSS Testing (Dalfox) [ALREADY DONE — SKIPPED]"
    else
        log_phase "Step 9: XSS Testing (Dalfox) [INVASIVE]"
        wait_if_paused

        if require_tool dalfox; then
            if [ -s "$VULN_DIR/potential_xss.txt" ]; then
                XSS_INPUT="$VULN_DIR/potential_xss.txt"
            elif [ -f "$OUT_DIR/final_params.txt" ]; then
                XSS_INPUT="$OUT_DIR/final_params.txt"
            else
                XSS_INPUT=""
            fi

            if [ -n "$XSS_INPUT" ]; then
                XSS_COUNT=$(count_lines "$XSS_INPUT")
                log_info "Testing ${BOLD}$XSS_COUNT${RESET} URLs for XSS with Dalfox..."

                dalfox file "$XSS_INPUT" \
                       --skip-bav \
                       --silence \
                       --no-color \
                       --worker "$THREADS" \
                       --timeout 10 \
                       --output "$VULN_DIR/dalfox_xss.txt" 2>/dev/null

                XSS_FOUND=$(count_lines "$VULN_DIR/dalfox_xss.txt")
                [ "$XSS_FOUND" -gt 0 ] && log_finding "HIGH" "XSS confirmed: $XSS_FOUND" && \
                    report_finding "XSS" "HIGH" "dalfox" "Confirmed XSS: $XSS_FOUND"
                log_success "Dalfox: ${BOLD}$XSS_FOUND${RESET} XSS confirmed"
            else
                log_warn "No XSS input file available."
            fi
        fi
        mark_step_done "$STEP_NAME"
    fi
else
    log_phase "Step 9: XSS Testing (Skipped — use --invasive to enable)"
fi

# ==========================================
# STEP 10: SSRF Testing
# ==========================================
STEP_NAME="ssrf_test"
if step_done "$STEP_NAME"; then
    log_phase "Step 10: SSRF Testing [ALREADY DONE — SKIPPED]"
else
    log_phase "Step 10: SSRF Testing"
    wait_if_paused

    if require_file "$VULN_DIR/potential_ssrf.txt"; then
        SSRF_COUNT=$(count_lines "$VULN_DIR/potential_ssrf.txt")
        log_info "Testing ${BOLD}$SSRF_COUNT${RESET} potential SSRF URLs..."

        if require_tool nuclei; then
            nuclei -l "$VULN_DIR/potential_ssrf.txt" \
                   -tags ssrf \
                   -silent \
                   -o "$VULN_DIR/confirmed_ssrf.txt" \
                   -t "$NUCLEI_TEMPLATES/" 2>/dev/null
            SSRF_CONFIRMED=$(count_lines "$VULN_DIR/confirmed_ssrf.txt")
            [ "$SSRF_CONFIRMED" -gt 0 ] && log_finding "HIGH" "SSRF confirmed: $SSRF_CONFIRMED" && \
                report_finding "SSRF" "HIGH" "nuclei" "Confirmed: $SSRF_CONFIRMED"
            log_success "SSRF: ${BOLD}$SSRF_CONFIRMED${RESET} confirmed"
        fi
    else
        safe_touch "$VULN_DIR/potential_ssrf.txt"
        log_warn "No SSRF candidates — run GF step first."
    fi
    mark_step_done "$STEP_NAME"
fi

# ==========================================
# STEP 11: LFI Testing
# ==========================================
STEP_NAME="lfi_test"
if step_done "$STEP_NAME"; then
    log_phase "Step 11: LFI Testing [ALREADY DONE — SKIPPED]"
else
    log_phase "Step 11: LFI Testing"
    wait_if_paused

    if require_file "$VULN_DIR/potential_lfi.txt"; then
        LFI_COUNT=$(count_lines "$VULN_DIR/potential_lfi.txt")
        log_info "Testing ${BOLD}$LFI_COUNT${RESET} potential LFI URLs..."

        if require_tool nuclei; then
            nuclei -l "$VULN_DIR/potential_lfi.txt" \
                   -tags lfi,traversal \
                   -silent \
                   -c "$THREADS" \
                   -o "$VULN_DIR/confirmed_lfi.txt" \
                   -t "$NUCLEI_TEMPLATES/" 2>/dev/null
            LFI_CONFIRMED=$(count_lines "$VULN_DIR/confirmed_lfi.txt")
            [ "$LFI_CONFIRMED" -gt 0 ] && log_finding "HIGH" "LFI confirmed: $LFI_CONFIRMED" && \
                report_finding "LFI" "HIGH" "nuclei" "Confirmed: $LFI_CONFIRMED"
            log_success "LFI: ${BOLD}$LFI_CONFIRMED${RESET} confirmed"
        fi
    else
        safe_touch "$VULN_DIR/potential_lfi.txt"
        log_warn "No LFI candidates — run GF step first."
    fi
    mark_step_done "$STEP_NAME"
fi

# ==========================================
# STEP 12: 403 Bypass Attempts
# ==========================================
STEP_NAME="403_bypass"
if step_done "$STEP_NAME"; then
    log_phase "Step 12: 403 Bypass [ALREADY DONE — SKIPPED]"
else
    log_phase "Step 12: 403 Bypass"
    wait_if_paused

    if require_tool nuclei && require_file "$OUT_DIR/alive_urls_only.txt"; then
        log_info "Testing 403 responses for bypass opportunities..."
        grep " 403 " "$OUT_DIR/web_alive.txt" 2>/dev/null | awk '{print $1}' > "$VULN_DIR/403_pages.txt"
        BYPASS_TARGETS=$(count_lines "$VULN_DIR/403_pages.txt")

        if [ "$BYPASS_TARGETS" -gt 0 ]; then
            nuclei -l "$VULN_DIR/403_pages.txt" \
                   -tags bypass,403 \
                   -silent \
                   -o "$VULN_DIR/403_bypass.txt" \
                   -t "$NUCLEI_TEMPLATES/" 2>/dev/null
            BYPASS_COUNT=$(count_lines "$VULN_DIR/403_bypass.txt")
            [ "$BYPASS_COUNT" -gt 0 ] && log_finding "MEDIUM" "403 bypasses found: $BYPASS_COUNT" && \
                report_finding "403 Bypass" "MEDIUM" "nuclei" "Bypasses: $BYPASS_COUNT"
            log_success "403 Bypass: ${BOLD}$BYPASS_COUNT${RESET} findings on $BYPASS_TARGETS targets"
        else
            log_warn "No 403 pages found to test."
        fi
    fi
    mark_step_done "$STEP_NAME"
fi

# ==========================================
# FINAL: Generate HTML Report
# ==========================================
log_phase "Generating Report"

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
ELAPSED_FMT=$(printf "%02d:%02d:%02d" $((ELAPSED/3600)) $((ELAPSED%3600/60)) $((ELAPSED%60)))

# Update summary counts in markdown
sed -i "s/| Nuclei Findings | - |/| Nuclei Findings | $(count_lines "$VULN_DIR/nuclei_vulns.txt") |/" "$REPORT_MD"
sed -i "s/| JS Secrets | - |/| JS Secrets | $(count_lines "$VULN_DIR/js_secrets.txt") |/" "$REPORT_MD"
sed -i "s/| Potential SSRF | - |/| Potential SSRF | $(count_lines "$VULN_DIR/potential_ssrf.txt") |/" "$REPORT_MD"
sed -i "s/| Potential SQLi | - |/| Potential SQLi | $(count_lines "$VULN_DIR/potential_sqli.txt") |/" "$REPORT_MD"
sed -i "s/| Potential LFI | - |/| Potential LFI | $(count_lines "$VULN_DIR/potential_lfi.txt") |/" "$REPORT_MD"
sed -i "s/| Potential RCE | - |/| Potential RCE | $(count_lines "$VULN_DIR/potential_rce.txt") |/" "$REPORT_MD"
sed -i "s/| Open Redirects | - |/| Open Redirects | $(count_lines "$VULN_DIR/confirmed_redirects.txt") |/" "$REPORT_MD"
sed -i "s/| XSS (Dalfox) | - |/| XSS (Dalfox) | $(count_lines "$VULN_DIR/dalfox_xss.txt") |/" "$REPORT_MD"
sed -i "s/| FFUF Findings | - |/| FFUF Findings | $(cat "$VULN_DIR"/ffuf_*.txt 2>/dev/null | wc -l) |/" "$REPORT_MD"

if [ -s "$VULN_DIR/nuclei_vulns.txt" ]; then
    echo -e "\n---\n\n## Nuclei Findings\n\n\`\`\`" >> "$REPORT_MD"
    cat "$VULN_DIR/nuclei_vulns.txt" >> "$REPORT_MD"
    echo '```' >> "$REPORT_MD"
fi

if require_tool pandoc; then
    pandoc "$REPORT_MD" \
           -o "$REPORT_HTML" \
           --standalone \
           --metadata title="Vuln Scan: $target" \
           --css "https://cdnjs.cloudflare.com/ajax/libs/github-markdown-css/5.2.0/github-markdown.min.css" \
           2>/dev/null
    log_success "HTML report generated: $REPORT_HTML"
else
    cat > "$REPORT_HTML" <<HTMLEOF
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Vuln Scan: $target</title>
<style>
body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 2em; max-width: 1200px; margin: auto; }
h1,h2,h3 { color: #ff6b6b; }
h2 { border-bottom: 1px solid #30363d; padding-bottom: 0.3em; }
table { border-collapse: collapse; width: 100%; margin: 1em 0; }
th { background: #21262d; color: #ff6b6b; padding: 8px 12px; text-align: left; }
td { padding: 6px 12px; border-bottom: 1px solid #21262d; }
tr:hover td { background: #161b22; }
code, pre { background: #161b22; padding: 2px 6px; border-radius: 4px; color: #79c0ff; }
pre { padding: 1em; overflow-x: auto; white-space: pre-wrap; }
</style>
</head>
<body>
<h1>🔴 Vulnerability Scan Report</h1>
<p><strong>Target:</strong> <code>$target</code> &nbsp;|&nbsp;
   <strong>Date:</strong> $SCAN_DATE &nbsp;|&nbsp;
   <strong>Duration:</strong> $ELAPSED_FMT &nbsp;|&nbsp;
   <strong>Mode:</strong> $([ "$INVASIVE" = "true" ] && echo "Invasive" || echo "Passive")</p>
<hr>
<h2>📊 Summary</h2>
<table>
<tr><th>Category</th><th>Count</th></tr>
<tr><td>Nuclei Vulnerabilities</td><td>$(count_lines "$VULN_DIR/nuclei_vulns.txt")</td></tr>
<tr><td>Nuclei Exposures</td><td>$(count_lines "$VULN_DIR/nuclei_exposures.txt")</td></tr>
<tr><td>Subdomain Takeovers</td><td>$(count_lines "$VULN_DIR/nuclei_takeovers.txt")</td></tr>
<tr><td>JS Secrets</td><td>$(count_lines "$VULN_DIR/js_secrets.txt")</td></tr>
<tr><td>JS Endpoints</td><td>$(count_lines "$VULN_DIR/js_endpoints.txt")</td></tr>
<tr><td>CORS Issues</td><td>$(count_lines "$VULN_DIR/cors_findings.txt")</td></tr>
<tr><td>Header/SSL Issues</td><td>$(count_lines "$VULN_DIR/headers_ssl_findings.txt")</td></tr>
<tr><td>Open Redirects</td><td>$(count_lines "$VULN_DIR/confirmed_redirects.txt")</td></tr>
<tr><td>SSRF Confirmed</td><td>$(count_lines "$VULN_DIR/confirmed_ssrf.txt")</td></tr>
<tr><td>LFI Confirmed</td><td>$(count_lines "$VULN_DIR/confirmed_lfi.txt")</td></tr>
<tr><td>XSS (Dalfox)</td><td>$(count_lines "$VULN_DIR/dalfox_xss.txt")</td></tr>
<tr><td>403 Bypasses</td><td>$(count_lines "$VULN_DIR/403_bypass.txt")</td></tr>
</table>
<h2>🚨 Nuclei Vulnerabilities</h2>
<pre>$(cat "$VULN_DIR/nuclei_vulns.txt" 2>/dev/null || echo "No findings")</pre>
<h2>🔑 JS Secrets</h2>
<pre>$(cat "$VULN_DIR/js_secrets.txt" 2>/dev/null || echo "No findings")</pre>
<h2>🌐 CORS Findings</h2>
<pre>$(cat "$VULN_DIR/cors_findings.txt" 2>/dev/null || echo "No findings")</pre>
<h2>💉 XSS (Dalfox)</h2>
<pre>$(cat "$VULN_DIR/dalfox_xss.txt" 2>/dev/null || echo "No findings / invasive mode disabled")</pre>
<h2>📝 Output Files</h2>
<table><tr><th>File</th><th>Lines</th></tr>
HTMLEOF

    for f in "$VULN_DIR"/*.txt; do
        [ -f "$f" ] && echo "<tr><td><code>$(basename "$f")</code></td><td>$(wc -l < "$f")</td></tr>" >> "$REPORT_HTML"
    done

    cat >> "$REPORT_HTML" <<HTMLEOF
</table>
<p style="color:#8b949e;margin-top:3em;font-size:0.85em">Generated by scan.sh v3.0 | Duration: $ELAPSED_FMT</p>
</body></html>
HTMLEOF
    log_success "HTML report generated: $REPORT_HTML"
fi

# ==========================================
# TERMINAL SUMMARY
# ==========================================
echo ""
echo -e "${RED}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${RED}${BOLD}  SCAN SUMMARY — $target${RESET}"
echo -e "${RED}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  ${BOLD}Nuclei Vulns       :${RESET} $(count_lines "$VULN_DIR/nuclei_vulns.txt")"
echo -e "  ${BOLD}Nuclei Exposures   :${RESET} $(count_lines "$VULN_DIR/nuclei_exposures.txt")"
echo -e "  ${BOLD}Subdomain Takeover :${RESET} $(count_lines "$VULN_DIR/nuclei_takeovers.txt")"
echo -e "  ${BOLD}JS Secrets         :${RESET} $(count_lines "$VULN_DIR/js_secrets.txt")"
echo -e "  ${BOLD}CORS Issues        :${RESET} $(count_lines "$VULN_DIR/cors_findings.txt")"
echo -e "  ${BOLD}Open Redirects     :${RESET} $(count_lines "$VULN_DIR/confirmed_redirects.txt")"
echo -e "  ${BOLD}SSRF Confirmed     :${RESET} $(count_lines "$VULN_DIR/confirmed_ssrf.txt")"
echo -e "  ${BOLD}LFI Confirmed      :${RESET} $(count_lines "$VULN_DIR/confirmed_lfi.txt")"
echo -e "  ${BOLD}XSS (Dalfox)       :${RESET} $(count_lines "$VULN_DIR/dalfox_xss.txt")"
echo -e "  ${BOLD}403 Bypasses       :${RESET} $(count_lines "$VULN_DIR/403_bypass.txt")"
echo -e "${RED}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  ${BOLD}Output Directory   :${RESET} $VULN_DIR"
echo -e "  ${BOLD}Report (MD)        :${RESET} $REPORT_MD"
echo -e "  ${BOLD}Report (HTML)      :${RESET} $REPORT_HTML"
echo -e "  ${BOLD}Log File           :${RESET} $LOG_FILE"
echo -e "  ${BOLD}Step State         :${RESET} $STEP_STATE_FILE"
echo -e "  ${BOLD}Time Elapsed       :${RESET} $ELAPSED_FMT"
echo -e "${RED}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
log_success "Scan complete!"
