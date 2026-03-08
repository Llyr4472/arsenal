#!/bin/bash
# ══════════════════════════════════════════════════════════════
#  scan.sh v4.0 — Vulnerability Scanner | Resume | bbq-managed
#
#  All tool output goes to per-tool log files under $OUT_DIR/logs/
#  Main scan.log gets timestamped step progress + counts only.
#  Use --redo <step> to re-run specific steps without --fresh.
#
#  Requires: recon.sh to have been run first
#  Usage: ./scan.sh <domain> [options]
# ══════════════════════════════════════════════════════════════

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
BLUE='\033[0;34m';  CYAN='\033[0;36m';   MAGENTA='\033[0;35m'
BOLD='\033[1m';     DIM='\033[2m';       RESET='\033[0m'

# ── Logging ───────────────────────────────────────────────────
TS()          { date '+%Y-%m-%d %H:%M:%S'; }
log_info()    { echo -e "[$(TS)] ${BLUE}[*]${RESET} $1";  echo "[$(TS)] [INFO]  $1" >> "$LOG_FILE"; }
log_ok()      { echo -e "[$(TS)] ${GREEN}[+]${RESET} $1"; echo "[$(TS)] [OK]    $1" >> "$LOG_FILE"; }
log_warn()    { echo -e "[$(TS)] ${YELLOW}[!]${RESET} $1"; echo "[$(TS)] [WARN]  $1" >> "$LOG_FILE"; }
log_error()   { echo -e "[$(TS)] ${RED}[x]${RESET} $1";  echo "[$(TS)] [ERROR] $1" >> "$LOG_FILE"; }
log_finding() {
    local sev="$1" msg="$2"
    case "$sev" in
        CRITICAL) echo -e "[$(TS)] ${RED}${BOLD}[CRITICAL]${RESET} $msg" ;;
        HIGH)     echo -e "[$(TS)] ${RED}[HIGH]${RESET} $msg" ;;
        MEDIUM)   echo -e "[$(TS)] ${YELLOW}[MEDIUM]${RESET} $msg" ;;
        LOW)      echo -e "[$(TS)] ${BLUE}[LOW]${RESET} $msg" ;;
        INFO)     echo -e "[$(TS)] ${CYAN}[INFO]${RESET} $msg" ;;
    esac
    echo "[$(TS)] [FINDING/$sev] $msg" >> "$LOG_FILE"
}
log_phase() {
    local msg="$1"
    echo -e "\n${RED}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${RED}${BOLD}  $msg${RESET}"
    echo -e "${RED}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo "[$(TS)] [PHASE] === $msg ===" >> "$LOG_FILE"
}

# Run a tool, capturing ALL stdout+stderr to a dedicated log file.
# Writes start/end markers so you can see exactly what happened.
# Usage: run_tool <logname> <description> <cmd> [args...]
run_tool() {
    local logname="$1" desc="$2"
    shift 2
    local toollog="$LOGS_DIR/${logname}.log"
    echo "[$(TS)] [START] $desc" >> "$LOG_FILE"
    echo "[$(TS)] [CMD]   $*"    >> "$LOG_FILE"
    echo "[$(TS)] [LOG]   $toollog" >> "$LOG_FILE"
    {
        echo "=== START: $desc ==="
        echo "=== CMD:   $*"
        echo "=== TIME:  $(TS)"
        echo ""
        "$@"
        local ec=$?
        echo ""
        echo "=== END: exit=$ec time=$(TS) ==="
        return $ec
    } >> "$toollog" 2>&1
    local ec=$?
    echo "[$(TS)] [DONE]  $desc (exit=$ec)" >> "$LOG_FILE"
    return $ec
}

count_lines()  { [ -f "$1" ] && wc -l < "$1" || echo 0; }
safe_touch()   { for f in "$@"; do [ -f "$f" ] || touch "$f"; done; }

require_tool() {
    command -v "$1" &>/dev/null && return 0
    log_warn "Tool not found: ${BOLD}$1${RESET} — skipping."
    return 1
}

require_file() {
    [ -f "$1" ] && [ -s "$1" ] && return 0
    log_warn "Missing/empty: ${BOLD}$1${RESET} — skipping."
    return 1
}

step_done()      { grep -qxF "$1" "$STEP_STATE_FILE" 2>/dev/null; }
mark_step_done() {
    echo "$1" >> "$STEP_STATE_FILE"
    log_ok "Step '${BOLD}$1${RESET}' marked complete."
}

force_redo_step() {
    local step="$1"
    if grep -qxF "$step" "$STEP_STATE_FILE" 2>/dev/null; then
        grep -v "^${step}$" "$STEP_STATE_FILE" > "${STEP_STATE_FILE}.tmp" \
            && mv "${STEP_STATE_FILE}.tmp" "$STEP_STATE_FILE"
        log_warn "Cleared checkpoint for step: $step — will re-run"
    fi
}

# ── Pause ─────────────────────────────────────────────────────
wait_if_paused() {
    [ ! -f "$PAUSE_FILE" ] && return 0
    log_warn "Scan PAUSED — waiting to resume..."
    while [ -f "$PAUSE_FILE" ]; do sleep 15; done
    log_ok "Scan RESUMED."
}

# ── Cleanup ───────────────────────────────────────────────────
cleanup_on_exit() {
    local code=$?
    rm -f "$OUT_DIR/.scan_pid" "$OUT_DIR/.scan_pgid"
    if [ "$code" -eq 0 ]; then
        echo "done"        > "$OUT_DIR/.scan_status"
        log_ok "Scan finished cleanly."
    else
        echo "interrupted" > "$OUT_DIR/.scan_status"
        log_warn "Scan interrupted (exit $code) — re-run to resume from checkpoint."
    fi
}
trap cleanup_on_exit EXIT
trap 'exit 130' TERM INT

# ── Usage ─────────────────────────────────────────────────────
usage() {
    echo -e "${BOLD}Usage:${RESET} $0 <target-domain> [options]"
    echo ""
    echo "  --invasive              Enable active scans (XSS, SQLi)"
    echo "  --threads <n>           Thread count (default: 50)"
    echo "  --rate <n>              Rate limit for nuclei/ffuf (default: 50)"
    echo "  --severity <s>          Nuclei severity (default: low,medium,high,critical)"
    echo "  --nuclei-templates <p>  Path to nuclei templates (default: ~/nuclei-templates)"
    echo "  --nuclei-timeout <n>    Per-host nuclei timeout seconds (default: 30)"
    echo "  --fresh                 Wipe ALL scan state and restart"
    echo "  --redo <step>           Re-run one step, keep all others"
    echo "                          Steps: nuclei  js  ffuf  gf  cors"
    echo "                                 headers  redirect  ssrf  lfi  bypass"
    echo "                                 sqli  xss  (sqli/xss require --invasive)"
    echo "  --skip-nuclei           Skip nuclei scan"
    echo "  --skip-js               Skip JS analysis"
    echo "  --skip-ffuf             Skip directory fuzzing"
    echo "  --skip-gf               Skip GF pattern filtering"
    echo ""
    echo "Resume: just re-run — completed steps are skipped automatically."
    exit 1
}

# ── Arg Parsing ───────────────────────────────────────────────
[ "$#" -lt 1 ] && { usage; }
TARGET="$1"; shift

INVASIVE=false
THREADS=50
RATE=50
SEVERITY="low,medium,high,critical"
NUCLEI_TEMPLATES="$HOME/nuclei-templates"
NUCLEI_TIMEOUT=30
SKIP_NUCLEI=false
SKIP_JS=false
SKIP_FFUF=false
SKIP_GF=false
FRESH_START=false
REDO_STEPS=()
FFUF_WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --invasive)           INVASIVE=true;            shift   ;;
        --threads)            THREADS="$2";             shift 2 ;;
        --rate)               RATE="$2";                shift 2 ;;
        --severity)           SEVERITY="$2";            shift 2 ;;
        --nuclei-templates)   NUCLEI_TEMPLATES="$2";    shift 2 ;;
        --nuclei-timeout)     NUCLEI_TIMEOUT="$2";      shift 2 ;;
        --skip-nuclei)        SKIP_NUCLEI=true;         shift   ;;
        --skip-js)            SKIP_JS=true;             shift   ;;
        --skip-ffuf)          SKIP_FFUF=true;           shift   ;;
        --skip-gf)            SKIP_GF=true;             shift   ;;
        --fresh)              FRESH_START=true;         shift   ;;
        --redo)               REDO_STEPS+=("$2");       shift 2 ;;
        -h|--help)            usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

# ── Setup (must happen before any logging) ────────────────────
OUT_DIR="$HOME/bb/$TARGET"
VULN_DIR="$OUT_DIR/vulns"
REPORT_DIR="$OUT_DIR/report"
LOGS_DIR="$OUT_DIR/logs"
LOG_FILE="$LOGS_DIR/scan.log"
STEP_STATE_FILE="$OUT_DIR/.scan_steps"
PAUSE_FILE="$OUT_DIR/.paused"

[ ! -d "$OUT_DIR" ] && {
    echo "[ERROR] Recon output not found: $OUT_DIR"
    echo "[ERROR] Run recon.sh first: ./recon.sh $TARGET"
    exit 1
}

mkdir -p "$VULN_DIR" "$REPORT_DIR" "$LOGS_DIR"

# Write PID and PGID for bbq tracking
echo $$       > "$OUT_DIR/.scan_pid"
ps -o pgid= -p $$ | tr -d ' ' > "$OUT_DIR/.scan_pgid"
echo "running" > "$OUT_DIR/.scan_status"

# Fresh log on fresh start, append on resume
if [ "$FRESH_START" = "true" ]; then
    > "$LOG_FILE"
fi

# Log header
echo "" >> "$LOG_FILE"
echo "[$(TS)] ============================================" >> "$LOG_FILE"
echo "[$(TS)] [START] scan.sh $TARGET  pid=$$" >> "$LOG_FILE"
echo "[$(TS)] [ARGS]  threads=$THREADS rate=$RATE severity=$SEVERITY invasive=$INVASIVE fresh=$FRESH_START" >> "$LOG_FILE"
echo "[$(TS)] ============================================" >> "$LOG_FILE"

# ── Fresh Start / Resume ──────────────────────────────────────
if [ "$FRESH_START" = "true" ]; then
    log_warn "Fresh start — clearing previous scan state."
    rm -f "$STEP_STATE_FILE"
    rm -f "$VULN_DIR"/*.txt "$VULN_DIR"/*.json "$VULN_DIR"/*.html 2>/dev/null
    rm -f "$LOGS_DIR"/*.log 2>/dev/null
fi

# ── Redo specific steps ───────────────────────────────────────
for step in "${REDO_STEPS[@]}"; do
    case "$step" in
        nuclei)   force_redo_step "nuclei_main" ;;
        js)       force_redo_step "js_analysis" ;;
        ffuf)     force_redo_step "ffuf_fuzz" ;;
        gf)       force_redo_step "gf_patterns" ;;
        cors)     force_redo_step "cors_check" ;;
        headers)  force_redo_step "headers_ssl" ;;
        redirect) force_redo_step "open_redirect" ;;
        ssrf)     force_redo_step "ssrf_test" ;;
        lfi)      force_redo_step "lfi_test" ;;
        bypass)   force_redo_step "403_bypass" ;;
        sqli)     force_redo_step "sqli_sqlmap" ;;
        xss)      force_redo_step "xss_dalfox" ;;
        *) log_warn "Unknown step name for --redo: $step" ;;
    esac
done

IS_RESUME=false
if [ -f "$STEP_STATE_FILE" ] && [ -s "$STEP_STATE_FILE" ]; then
    IS_RESUME=true
    log_warn "Resuming — $(wc -l < "$STEP_STATE_FILE") steps already done."
fi

START_TIME=$(date +%s)

echo ""
echo -e "  ${BOLD}Target       :${RESET} $TARGET"
echo -e "  ${BOLD}Output       :${RESET} $OUT_DIR"
echo -e "  ${BOLD}Logs dir     :${RESET} $LOGS_DIR"
echo -e "  ${BOLD}PID/PGID     :${RESET} $$ / $(cat "$OUT_DIR/.scan_pgid")"
echo -e "  ${BOLD}Invasive     :${RESET} $INVASIVE"
echo -e "  ${BOLD}Threads/Rate :${RESET} $THREADS / $RATE"
echo -e "  ${BOLD}Severity     :${RESET} $SEVERITY"
echo -e "  ${BOLD}Resume       :${RESET} $IS_RESUME"
echo ""

# ══ STEP 1: Nuclei ════════════════════════════════════════════
STEP="nuclei_main"
if [ "$SKIP_NUCLEI" = "true" ]; then
    log_phase "Step 1: Nuclei Scan [SKIPPED via --skip-nuclei]"
elif step_done "$STEP"; then
    log_phase "Step 1: Nuclei Scan [DONE — SKIPPED]"
else
    log_phase "Step 1: Nuclei Vulnerability Scan"
    wait_if_paused

    if require_tool nuclei && require_file "$OUT_DIR/web_alive.txt"; then
        awk '{print $1}' "$OUT_DIR/web_alive.txt" > "$VULN_DIR/nuclei_targets.txt"
        log_info "Nuclei targets: $(count_lines "$VULN_DIR/nuclei_targets.txt")"

        log_info "Running Nuclei — CVE/misconfig/exposure scan..."
        run_tool "nuclei_vulns" "nuclei CVE+misconfig scan for $TARGET" \
            nuclei -l "$VULN_DIR/nuclei_targets.txt" \
                   -tags cve,osint,tech,exposure,misconfig,default-login \
                   -et dos,fuzzing,headless \
                   -severity "$SEVERITY" \
                   -rate-limit "$RATE" \
                   -timeout "$NUCLEI_TIMEOUT" \
                   -silent \
                   -o "$VULN_DIR/nuclei_vulns.txt" \
                   -t "$NUCLEI_TEMPLATES/"
        wait_if_paused

        log_info "Running Nuclei — exposure/secrets scan..."
        run_tool "nuclei_exposures" "nuclei exposures+secrets scan for $TARGET" \
            nuclei -l "$VULN_DIR/nuclei_targets.txt" \
                   -tags exposure,token,secret,api-key \
                   -rate-limit "$RATE" \
                   -timeout "$NUCLEI_TIMEOUT" \
                   -silent \
                   -o "$VULN_DIR/nuclei_exposures.txt" \
                   -t "$NUCLEI_TEMPLATES/"
        wait_if_paused

        if require_file "$OUT_DIR/final_subdomains.txt"; then
            log_info "Running Nuclei — subdomain takeover check..."
            run_tool "nuclei_takeovers" "nuclei takeover scan for $TARGET" \
                nuclei -l "$OUT_DIR/final_subdomains.txt" \
                       -tags takeover \
                       -rate-limit "$RATE" \
                       -timeout "$NUCLEI_TIMEOUT" \
                       -silent \
                       -o "$VULN_DIR/nuclei_takeovers.txt" \
                       -t "$NUCLEI_TEMPLATES/"
            local_n=$(count_lines "$VULN_DIR/nuclei_takeovers.txt")
            [ "$local_n" -gt 0 ] && log_finding "CRITICAL" "Subdomain takeovers: $local_n — see $VULN_DIR/nuclei_takeovers.txt"
        fi

        NUCLEI_COUNT=$(count_lines "$VULN_DIR/nuclei_vulns.txt")
        EXPOSURE_COUNT=$(count_lines "$VULN_DIR/nuclei_exposures.txt")
        log_ok "Nuclei: ${BOLD}$NUCLEI_COUNT${RESET} vulns, ${BOLD}$EXPOSURE_COUNT${RESET} exposures"
        grep -qiE "critical|high" "$VULN_DIR/nuclei_vulns.txt" 2>/dev/null \
            && log_finding "HIGH" "High/Critical Nuclei findings — review $VULN_DIR/nuclei_vulns.txt"
    fi
    mark_step_done "$STEP"
fi

# ══ STEP 2: JavaScript Analysis ═══════════════════════════════
STEP="js_analysis"
if [ "$SKIP_JS" = "true" ]; then
    log_phase "Step 2: JavaScript Analysis [SKIPPED via --skip-js]"
elif step_done "$STEP"; then
    log_phase "Step 2: JavaScript Analysis [DONE — SKIPPED]"
else
    log_phase "Step 2: JavaScript Analysis"
    wait_if_paused

    if require_file "$OUT_DIR/clean_urls.txt"; then
        grep -iE "\.js(\?|$)" "$OUT_DIR/clean_urls.txt" | sort -u > "$VULN_DIR/js_files.txt"
        JS_COUNT=$(count_lines "$VULN_DIR/js_files.txt")

        if [ "$JS_COUNT" -eq 0 ]; then
            log_warn "No JS files found in clean_urls.txt."
        else
            log_info "Found $JS_COUNT JS files to analyze"

            if require_tool nuclei; then
                log_info "Scanning JS for secrets with Nuclei..."
                run_tool "js_secrets_nuclei" "nuclei JS secrets scan for $TARGET" \
                    nuclei -l "$VULN_DIR/js_files.txt" \
                           -t "$NUCLEI_TEMPLATES/http/exposures/" \
                           -tags token,secret,api-key,exposure \
                           -rate-limit "$RATE" \
                           -timeout "$NUCLEI_TIMEOUT" \
                           -silent \
                           -o "$VULN_DIR/js_secrets.txt"
                local_n=$(count_lines "$VULN_DIR/js_secrets.txt")
                [ "$local_n" -gt 0 ] && log_finding "HIGH" "JS secrets: $local_n"
                log_ok "JS secrets: $local_n"
            fi
            wait_if_paused

            if require_tool mantra; then
                log_info "Mantra — mining JS for hidden endpoints (timeout: 5m)..."
                run_tool "mantra" "mantra JS endpoint mining for $TARGET" \
                    bash -c "timeout 300 bash -c \
                        \"cat '${VULN_DIR}/js_files.txt' | mantra | sort -u > '${VULN_DIR}/js_endpoints.txt'\" \
                        || echo 'mantra: timed out after 5m'"
                local_n=$(count_lines "$VULN_DIR/js_endpoints.txt")
                log_ok "JS endpoints: $local_n"
                [ "$local_n" -gt 0 ] && log_finding "INFO" "JS hidden endpoints: $local_n — see $VULN_DIR/js_endpoints.txt"
            fi
            wait_if_paused

            log_info "Extracting API paths from JS files..."
            safe_touch "$VULN_DIR/js_api_paths.txt"
            while IFS= read -r jsurl; do
                curl -sk --max-time 10 "$jsurl" 2>>"$LOGS_DIR/js_api_curl.log" \
                    | grep -oP '(?:"|'"'"')(/[a-zA-Z0-9_/.-]{3,}(?:\?[^"'"'"']*)?|https?://[^"'"'"']+)(?:"|'"'"')' \
                    | tr -d '"'"'"
            done < "$VULN_DIR/js_files.txt" | sort -u > "$VULN_DIR/js_api_paths.txt"
            log_ok "JS API paths: $(count_lines "$VULN_DIR/js_api_paths.txt")"
        fi
    fi
    mark_step_done "$STEP"
fi

# ══ STEP 3: Directory Fuzzing (FFUF) ══════════════════════════
STEP="ffuf_fuzz"
if [ "$SKIP_FFUF" = "true" ]; then
    log_phase "Step 3: FFUF [SKIPPED via --skip-ffuf]"
elif step_done "$STEP"; then
    log_phase "Step 3: FFUF [DONE — SKIPPED]"
else
    log_phase "Step 3: Directory & File Fuzzing (FFUF)"
    wait_if_paused

    if require_tool ffuf && require_file "$OUT_DIR/alive_urls_only.txt"; then
        if [ ! -f "$FFUF_WORDLIST" ]; then
            log_error "Wordlist not found: $FFUF_WORDLIST — skipping FFUF."
        else
            # Fuzz interesting-looking admin/api targets
            grep -iE "admin|dev|stage|test|api|corp|internal|portal|dashboard|manage|backend|uat" \
                "$OUT_DIR/alive_urls_only.txt" \
                | sort -u > "$VULN_DIR/ffuf_interesting.txt"
            INTERESTING_COUNT=$(count_lines "$VULN_DIR/ffuf_interesting.txt")

            if [ "$INTERESTING_COUNT" -gt 0 ]; then
                log_info "Fuzzing $INTERESTING_COUNT interesting targets with raft-small-words..."
                run_tool "ffuf_interesting" "ffuf interesting targets for $TARGET" \
                    ffuf -w "${FFUF_WORDLIST}:FUZZ" \
                         -w "${VULN_DIR}/ffuf_interesting.txt:URL" \
                         -u "URL/FUZZ" \
                         -mc 200,201,204,301,302,403,405 \
                         -fc 404,429 \
                         -ac -s \
                         -t "$THREADS" -rate "$RATE" -timeout 10 \
                         -o "$VULN_DIR/ffuf_interesting_results.json" -of json
            else
                log_warn "No interesting admin/api targets found in alive_urls_only.txt"
            fi
            wait_if_paused

            BACKUP_WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-small-files.txt"
            if [ -f "$BACKUP_WORDLIST" ]; then
                log_info "Scanning for backup & sensitive files..."
                run_tool "ffuf_backup" "ffuf backup file scan for $TARGET" \
                    ffuf -w "${BACKUP_WORDLIST}:FUZZ" \
                         -w "${OUT_DIR}/alive_urls_only.txt:URL" \
                         -u "URL/FUZZ" \
                         -mc 200,403 -fc 404,429 \
                         -ac -s \
                         -t "$THREADS" -rate "$RATE" -timeout 10 \
                         -o "$VULN_DIR/ffuf_backup_files.json" -of json
            fi

            # Parse all JSON results to human-readable txt
            for json_file in "$VULN_DIR"/ffuf_*.json; do
                [ -f "$json_file" ] || continue
                local_out="${json_file%.json}.txt"
                python3 -c "
import json, sys
try:
    with open('${json_file}') as f:
        data = json.load(f)
    for r in data.get('results', []):
        print(r.get('status','?'), r.get('length','?'), r.get('url','?'))
except Exception as e:
    print('parse error:', e)
" > "$local_out" 2>>"$LOGS_DIR/ffuf_parse.log"
            done

            FFUF_COUNT=$(cat "$VULN_DIR"/ffuf_*.txt 2>/dev/null | wc -l)
            log_ok "FFUF total findings: $FFUF_COUNT"
        fi
    fi
    mark_step_done "$STEP"
fi

# ══ STEP 4: GF Pattern Filtering ══════════════════════════════
STEP="gf_patterns"
if [ "$SKIP_GF" = "true" ]; then
    log_phase "Step 4: GF Patterns [SKIPPED via --skip-gf]"
elif step_done "$STEP"; then
    log_phase "Step 4: GF Patterns [DONE — SKIPPED]"
else
    log_phase "Step 4: GF Pattern Filtering"
    wait_if_paused

    if require_tool gf && require_file "$OUT_DIR/final_params.txt"; then
        PARAM_COUNT=$(count_lines "$OUT_DIR/final_params.txt")
        log_info "GF patterns on $PARAM_COUNT URLs..."

        GF_PATTERNS=(ssrf sqli lfi redirect rce ssti idor xss xxe debug_logic)

        for pattern in "${GF_PATTERNS[@]}"; do
            local_out="$VULN_DIR/potential_${pattern}.txt"
            run_tool "gf_${pattern}" "gf $pattern pattern filter for $TARGET" \
                bash -c "gf '$pattern' '$OUT_DIR/final_params.txt' 2>/dev/null \
                    | sort -u > '$local_out'"
            local_cnt
            local_cnt=$(count_lines "$local_out")
            if [ "$local_cnt" -gt 0 ]; then
                log_finding "MEDIUM" "GF [$pattern]: $local_cnt potential URLs"
            fi
            log_info "  gf[$pattern]: $local_cnt URLs"
        done
        log_ok "GF filtering complete — results in $VULN_DIR/potential_*.txt"
    fi
    mark_step_done "$STEP"
fi

# ══ STEP 5: CORS ══════════════════════════════════════════════
STEP="cors_check"
if step_done "$STEP"; then
    log_phase "Step 5: CORS Check [DONE — SKIPPED]"
else
    log_phase "Step 5: CORS Misconfiguration Check"
    wait_if_paused

    if require_file "$OUT_DIR/alive_urls_only.txt"; then
        safe_touch "$VULN_DIR/cors_findings.txt"
        if require_tool corsy; then
            log_info "Running Corsy..."
            run_tool "corsy" "corsy CORS check for $TARGET" \
                corsy -i "$OUT_DIR/alive_urls_only.txt" -t "$THREADS" \
                      --headers "User-Agent: Mozilla/5.0"
            # corsy writes to stdout so we need to capture differently
            run_tool "corsy_out" "corsy CORS check output for $TARGET" \
                bash -c "corsy -i '$OUT_DIR/alive_urls_only.txt' -t '$THREADS' \
                    --headers 'User-Agent: Mozilla/5.0' > '$VULN_DIR/cors_findings.txt' 2>&1"
            CORS_COUNT=$(grep -c "CORS" "$VULN_DIR/cors_findings.txt" 2>/dev/null) || CORS_COUNT=0
        elif require_tool nuclei; then
            log_info "Checking CORS with Nuclei..."
            run_tool "nuclei_cors" "nuclei CORS check for $TARGET" \
                nuclei -l "$OUT_DIR/alive_urls_only.txt" \
                       -tags cors -silent \
                       -rate-limit "$RATE" -timeout "$NUCLEI_TIMEOUT" \
                       -o "$VULN_DIR/cors_findings.txt" \
                       -t "$NUCLEI_TEMPLATES/"
            CORS_COUNT=$(count_lines "$VULN_DIR/cors_findings.txt")
        else
            CORS_COUNT=0
        fi
        [ "$CORS_COUNT" -gt 0 ] && log_finding "HIGH" "CORS misconfigurations: $CORS_COUNT"
        log_ok "CORS: $CORS_COUNT findings"
    fi
    mark_step_done "$STEP"
fi

# ══ STEP 6: Headers & SSL ═════════════════════════════════════
STEP="headers_ssl"
if step_done "$STEP"; then
    log_phase "Step 6: Headers & SSL [DONE — SKIPPED]"
else
    log_phase "Step 6: HTTP Security Headers & SSL/TLS"
    wait_if_paused

    if require_file "$OUT_DIR/alive_urls_only.txt" && require_tool nuclei; then
        log_info "Checking security headers and SSL..."
        run_tool "nuclei_headers_ssl" "nuclei headers+SSL check for $TARGET" \
            nuclei -l "$OUT_DIR/alive_urls_only.txt" \
                   -tags headers,ssl,tls,misconfiguration \
                   -rate-limit "$RATE" -timeout "$NUCLEI_TIMEOUT" \
                   -silent \
                   -o "$VULN_DIR/headers_ssl_findings.txt" \
                   -t "$NUCLEI_TEMPLATES/"
        local_n=$(count_lines "$VULN_DIR/headers_ssl_findings.txt")
        [ "$local_n" -gt 0 ] && log_finding "LOW" "Header/SSL issues: $local_n"
        log_ok "Headers/SSL: $local_n findings"
    fi

    if require_tool testssl.sh; then
        log_info "testssl.sh on apex domain..."
        run_tool "testssl" "testssl.sh for $TARGET" \
            testssl.sh --quiet --jsonfile "$VULN_DIR/testssl.json" "$TARGET"
        log_ok "testssl.sh complete"
    fi
    mark_step_done "$STEP"
fi

# ══ STEP 7: Open Redirects ════════════════════════════════════
STEP="open_redirect"
if step_done "$STEP"; then
    log_phase "Step 7: Open Redirect Check [DONE — SKIPPED]"
else
    log_phase "Step 7: Open Redirect Check"
    wait_if_paused
    safe_touch "$VULN_DIR/potential_redirect.txt"

    REDIRECT_COUNT=$(count_lines "$VULN_DIR/potential_redirect.txt")
    if [ "$REDIRECT_COUNT" -gt 0 ] && require_tool nuclei; then
        log_info "Testing $REDIRECT_COUNT redirect candidates..."
        run_tool "nuclei_redirect" "nuclei open redirect check for $TARGET" \
            nuclei -l "$VULN_DIR/potential_redirect.txt" \
                   -tags redirect -silent \
                   -rate-limit "$RATE" -timeout "$NUCLEI_TIMEOUT" \
                   -o "$VULN_DIR/confirmed_redirects.txt" \
                   -t "$NUCLEI_TEMPLATES/"
        local_n=$(count_lines "$VULN_DIR/confirmed_redirects.txt")
        [ "$local_n" -gt 0 ] && log_finding "MEDIUM" "Confirmed open redirects: $local_n"
        log_ok "Open redirects confirmed: $local_n"
    else
        [ "$REDIRECT_COUNT" -eq 0 ] && log_warn "No redirect candidates — run GF step first (bbq retry $TARGET --redo gf)"
    fi
    mark_step_done "$STEP"
fi

# ══ STEP 8: SQLi — Invasive Only ══════════════════════════════
STEP="sqli_sqlmap"
if [ "$INVASIVE" = "true" ]; then
    if step_done "$STEP"; then
        log_phase "Step 8: SQLi Testing [DONE — SKIPPED]"
    else
        log_phase "Step 8: SQLi Testing (sqlmap) [INVASIVE]"
        wait_if_paused

        if require_tool sqlmap && require_file "$VULN_DIR/potential_sqli.txt"; then
            SQLI_COUNT=$(count_lines "$VULN_DIR/potential_sqli.txt")
            log_info "Testing $SQLI_COUNT SQLi candidates..."
            run_tool "sqlmap" "sqlmap SQLi test for $TARGET" \
                sqlmap -m "$VULN_DIR/potential_sqli.txt" \
                       --batch --level=2 --risk=2 \
                       --threads="$THREADS" \
                       --output-dir="$VULN_DIR/sqlmap/" \
                       --forms --crawl=2 --random-agent \
                       --timeout=10 --retries=2
            log_ok "sqlmap done — results in $VULN_DIR/sqlmap/"
        else
            log_warn "No SQLi candidates or sqlmap not found — run: bbq retry $TARGET --redo gf"
        fi
        mark_step_done "$STEP"
    fi
else
    log_phase "Step 8: SQLi Testing [SKIPPED — use --invasive to enable]"
fi

# ══ STEP 9: XSS (Dalfox) — Invasive Only ══════════════════════
STEP="xss_dalfox"
if [ "$INVASIVE" = "true" ]; then
    if step_done "$STEP"; then
        log_phase "Step 9: XSS Testing [DONE — SKIPPED]"
    else
        log_phase "Step 9: XSS Testing (Dalfox) [INVASIVE]"
        wait_if_paused

        if require_tool dalfox; then
            XSS_INPUT=""
            [ -s "$VULN_DIR/potential_xss.txt" ]     && XSS_INPUT="$VULN_DIR/potential_xss.txt"
            [ -z "$XSS_INPUT" ] && [ -f "$OUT_DIR/final_params.txt" ] && XSS_INPUT="$OUT_DIR/final_params.txt"

            if [ -n "$XSS_INPUT" ]; then
                log_info "Dalfox on $(count_lines "$XSS_INPUT") URLs..."
                run_tool "dalfox" "dalfox XSS scan for $TARGET" \
                    dalfox file "$XSS_INPUT" \
                           --skip-bav --silence --no-color \
                           --worker "$THREADS" --timeout 10 \
                           --output "$VULN_DIR/dalfox_xss.txt"
                local_n=$(count_lines "$VULN_DIR/dalfox_xss.txt")
                [ "$local_n" -gt 0 ] && log_finding "HIGH" "XSS confirmed: $local_n"
                log_ok "Dalfox: $local_n XSS confirmed"
            else
                log_warn "No XSS input — run: bbq retry $TARGET --redo gf"
            fi
        fi
        mark_step_done "$STEP"
    fi
else
    log_phase "Step 9: XSS Testing [SKIPPED — use --invasive to enable]"
fi

# ══ STEP 10: SSRF ═════════════════════════════════════════════
STEP="ssrf_test"
if step_done "$STEP"; then
    log_phase "Step 10: SSRF Testing [DONE — SKIPPED]"
else
    log_phase "Step 10: SSRF Testing"
    wait_if_paused
    safe_touch "$VULN_DIR/potential_ssrf.txt"

    SSRF_COUNT=$(count_lines "$VULN_DIR/potential_ssrf.txt")
    if [ "$SSRF_COUNT" -gt 0 ] && require_tool nuclei; then
        log_info "Testing $SSRF_COUNT SSRF candidates..."
        run_tool "nuclei_ssrf" "nuclei SSRF test for $TARGET" \
            nuclei -l "$VULN_DIR/potential_ssrf.txt" \
                   -tags ssrf -silent \
                   -rate-limit "$RATE" -timeout "$NUCLEI_TIMEOUT" \
                   -o "$VULN_DIR/confirmed_ssrf.txt" \
                   -t "$NUCLEI_TEMPLATES/"
        local_n=$(count_lines "$VULN_DIR/confirmed_ssrf.txt")
        [ "$local_n" -gt 0 ] && log_finding "HIGH" "SSRF confirmed: $local_n"
        log_ok "SSRF confirmed: $local_n"
    else
        [ "$SSRF_COUNT" -eq 0 ] && log_warn "No SSRF candidates — run: bbq retry $TARGET --redo gf"
    fi
    mark_step_done "$STEP"
fi

# ══ STEP 11: LFI ══════════════════════════════════════════════
STEP="lfi_test"
if step_done "$STEP"; then
    log_phase "Step 11: LFI Testing [DONE — SKIPPED]"
else
    log_phase "Step 11: LFI Testing"
    wait_if_paused
    safe_touch "$VULN_DIR/potential_lfi.txt"

    LFI_COUNT=$(count_lines "$VULN_DIR/potential_lfi.txt")
    if [ "$LFI_COUNT" -gt 0 ] && require_tool nuclei; then
        log_info "Testing $LFI_COUNT LFI candidates..."
        run_tool "nuclei_lfi" "nuclei LFI test for $TARGET" \
            nuclei -l "$VULN_DIR/potential_lfi.txt" \
                   -tags lfi,traversal -silent \
                   -c "$THREADS" \
                   -rate-limit "$RATE" -timeout "$NUCLEI_TIMEOUT" \
                   -o "$VULN_DIR/confirmed_lfi.txt" \
                   -t "$NUCLEI_TEMPLATES/"
        local_n=$(count_lines "$VULN_DIR/confirmed_lfi.txt")
        [ "$local_n" -gt 0 ] && log_finding "HIGH" "LFI confirmed: $local_n"
        log_ok "LFI confirmed: $local_n"
    else
        [ "$LFI_COUNT" -eq 0 ] && log_warn "No LFI candidates — run: bbq retry $TARGET --redo gf"
    fi
    mark_step_done "$STEP"
fi

# ══ STEP 12: 403 Bypass ═══════════════════════════════════════
STEP="403_bypass"
if step_done "$STEP"; then
    log_phase "Step 12: 403 Bypass [DONE — SKIPPED]"
else
    log_phase "Step 12: 403 Bypass"
    wait_if_paused

    if require_tool nuclei && require_file "$OUT_DIR/web_alive.txt"; then
        grep " 403 " "$OUT_DIR/web_alive.txt" 2>/dev/null \
            | awk '{print $1}' > "$VULN_DIR/403_pages.txt"
        BYPASS_TARGETS=$(count_lines "$VULN_DIR/403_pages.txt")

        if [ "$BYPASS_TARGETS" -gt 0 ]; then
            log_info "Testing $BYPASS_TARGETS 403 pages for bypass..."
            run_tool "nuclei_403bypass" "nuclei 403 bypass for $TARGET" \
                nuclei -l "$VULN_DIR/403_pages.txt" \
                       -tags bypass,403 -silent \
                       -rate-limit "$RATE" -timeout "$NUCLEI_TIMEOUT" \
                       -o "$VULN_DIR/403_bypass.txt" \
                       -t "$NUCLEI_TEMPLATES/"
            local_n=$(count_lines "$VULN_DIR/403_bypass.txt")
            [ "$local_n" -gt 0 ] && log_finding "MEDIUM" "403 bypasses: $local_n"
            log_ok "403 bypass: $local_n findings"
        else
            log_warn "No 403 pages found in web_alive.txt."
        fi
    fi
    mark_step_done "$STEP"
fi

# ── Generate HTML Report ──────────────────────────────────────
log_phase "Generating Report"

SCAN_DATE=$(date '+%Y-%m-%d %H:%M:%S')
END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
ELAPSED_FMT=$(printf "%02d:%02d:%02d" $(( ELAPSED/3600 )) $(( ELAPSED%3600/60 )) $(( ELAPSED%60 )))

REPORT_HTML="$REPORT_DIR/report.html"

{
    echo '<!DOCTYPE html><html>'
    echo '<head><meta charset="UTF-8">'
    printf '<title>Scan: %s</title>\n' "$TARGET"
    cat << 'CSS'
<style>
body{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:2em;max-width:1200px;margin:auto}
h1,h2,h3{color:#ff6b6b}
h2{border-bottom:1px solid #30363d;padding-bottom:.3em}
table{border-collapse:collapse;width:100%;margin:1em 0}
th{background:#21262d;color:#ff6b6b;padding:8px 12px;text-align:left}
td{padding:6px 12px;border-bottom:1px solid #21262d}
tr:hover td{background:#161b22}
code,pre{background:#161b22;padding:2px 6px;border-radius:4px;color:#79c0ff}
pre{padding:1em;overflow-x:auto;white-space:pre-wrap}
.crit{color:#ff4444;font-weight:bold}
.high{color:#ff6b6b}
.med{color:#f0a500}
.low{color:#58a6ff}
</style></head><body>
CSS
    printf '<h1>&#x1F534; Scan Report — %s</h1>\n' "$TARGET"
    printf '<p><strong>Date:</strong> %s &nbsp;|&nbsp; <strong>Duration:</strong> %s &nbsp;|&nbsp; <strong>Mode:</strong> %s</p>\n' \
        "$SCAN_DATE" "$ELAPSED_FMT" "$([ "$INVASIVE" = "true" ] && echo "Invasive" || echo "Passive")"

    echo '<h2>Summary</h2><table>'
    echo '<tr><th>Category</th><th>Count</th><th>Severity</th></tr>'

    _row() { printf '<tr><td>%s</td><td>%s</td><td class="%s">%s</td></tr>\n' \
        "$1" "$(count_lines "$2")" "$3" "$4"; }

    _row "Nuclei Vulns"        "$VULN_DIR/nuclei_vulns.txt"        "high"  "HIGH"
    _row "Nuclei Exposures"    "$VULN_DIR/nuclei_exposures.txt"    "med"   "MEDIUM"
    _row "Subdomain Takeovers" "$VULN_DIR/nuclei_takeovers.txt"    "crit"  "CRITICAL"
    _row "JS Secrets"          "$VULN_DIR/js_secrets.txt"          "high"  "HIGH"
    _row "JS Endpoints"        "$VULN_DIR/js_endpoints.txt"        "low"   "INFO"
    _row "CORS Issues"         "$VULN_DIR/cors_findings.txt"       "high"  "HIGH"
    _row "Header/SSL Issues"   "$VULN_DIR/headers_ssl_findings.txt" "low"  "LOW"
    _row "Open Redirects"      "$VULN_DIR/confirmed_redirects.txt" "med"   "MEDIUM"
    _row "SSRF Confirmed"      "$VULN_DIR/confirmed_ssrf.txt"      "high"  "HIGH"
    _row "LFI Confirmed"       "$VULN_DIR/confirmed_lfi.txt"       "high"  "HIGH"
    _row "XSS (Dalfox)"        "$VULN_DIR/dalfox_xss.txt"         "high"  "HIGH"
    _row "403 Bypasses"        "$VULN_DIR/403_bypass.txt"          "med"   "MEDIUM"

    echo '</table>'

    _section() {
        local title="$1" file="$2"
        local n
        n=$(count_lines "$file")
        [ "$n" -eq 0 ] && return
        printf '<h2>%s (%s)</h2><pre>' "$title" "$n"
        # Escape HTML entities to prevent XSS in our own report
        sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' "$file"
        echo '</pre>'
    }

    _section "Nuclei Vulns"         "$VULN_DIR/nuclei_vulns.txt"
    _section "Nuclei Exposures"     "$VULN_DIR/nuclei_exposures.txt"
    _section "Subdomain Takeovers"  "$VULN_DIR/nuclei_takeovers.txt"
    _section "JS Secrets"           "$VULN_DIR/js_secrets.txt"
    _section "CORS Findings"        "$VULN_DIR/cors_findings.txt"
    _section "SSRF Confirmed"       "$VULN_DIR/confirmed_ssrf.txt"
    _section "LFI Confirmed"        "$VULN_DIR/confirmed_lfi.txt"
    _section "XSS Confirmed"        "$VULN_DIR/dalfox_xss.txt"
    _section "403 Bypasses"         "$VULN_DIR/403_bypass.txt"

    echo '<h2>Output Files</h2><table>'
    echo '<tr><th>File</th><th>Lines</th></tr>'
    for f in "$VULN_DIR"/*.txt; do
        [ -f "$f" ] && printf '<tr><td><code>%s</code></td><td>%s</td></tr>\n' \
            "$(basename "$f")" "$(wc -l < "$f")"
    done
    echo '</table>'
    echo '<h2>Tool Logs</h2><table>'
    echo '<tr><th>Log</th><th>Size</th></tr>'
    for f in "$LOGS_DIR"/*.log; do
        [ -f "$f" ] && printf '<tr><td><code>%s</code></td><td>%s</td></tr>\n' \
            "$(basename "$f")" "$(wc -l < "$f") lines"
    done
    echo '</table>'
    printf '<p style="color:#8b949e;margin-top:3em;font-size:.85em">scan.sh v4.0 | %s | %s</p>' \
        "$ELAPSED_FMT" "$SCAN_DATE"
    echo '</body></html>'
} > "$REPORT_HTML"

log_ok "HTML report: $REPORT_HTML"

# ── Log Summary ───────────────────────────────────────────────
echo "[$(TS)] ============================================" >> "$LOG_FILE"
echo "[$(TS)] [SUMMARY] $TARGET" >> "$LOG_FILE"
echo "[$(TS)] [SUMMARY] Nuclei vulns:      $(count_lines "$VULN_DIR/nuclei_vulns.txt")" >> "$LOG_FILE"
echo "[$(TS)] [SUMMARY] Nuclei exposures:  $(count_lines "$VULN_DIR/nuclei_exposures.txt")" >> "$LOG_FILE"
echo "[$(TS)] [SUMMARY] Takeovers:         $(count_lines "$VULN_DIR/nuclei_takeovers.txt")" >> "$LOG_FILE"
echo "[$(TS)] [SUMMARY] JS secrets:        $(count_lines "$VULN_DIR/js_secrets.txt")" >> "$LOG_FILE"
echo "[$(TS)] [SUMMARY] CORS issues:       $(count_lines "$VULN_DIR/cors_findings.txt")" >> "$LOG_FILE"
echo "[$(TS)] [SUMMARY] Open redirects:    $(count_lines "$VULN_DIR/confirmed_redirects.txt")" >> "$LOG_FILE"
echo "[$(TS)] [SUMMARY] SSRF confirmed:    $(count_lines "$VULN_DIR/confirmed_ssrf.txt")" >> "$LOG_FILE"
echo "[$(TS)] [SUMMARY] LFI confirmed:     $(count_lines "$VULN_DIR/confirmed_lfi.txt")" >> "$LOG_FILE"
echo "[$(TS)] [SUMMARY] XSS (Dalfox):      $(count_lines "$VULN_DIR/dalfox_xss.txt")" >> "$LOG_FILE"
echo "[$(TS)] [SUMMARY] 403 bypasses:      $(count_lines "$VULN_DIR/403_bypass.txt")" >> "$LOG_FILE"
echo "[$(TS)] [SUMMARY] Elapsed:           $ELAPSED_FMT" >> "$LOG_FILE"
echo "[$(TS)] ============================================" >> "$LOG_FILE"

# ── Terminal Summary ──────────────────────────────────────────
echo ""
echo -e "${RED}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${RED}${BOLD}  SCAN SUMMARY — $TARGET${RESET}"
echo -e "${RED}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
printf "  %-24s %s\n" "Nuclei vulns:"      "$(count_lines "$VULN_DIR/nuclei_vulns.txt")"
printf "  %-24s %s\n" "Nuclei exposures:"  "$(count_lines "$VULN_DIR/nuclei_exposures.txt")"
printf "  %-24s %s\n" "Takeovers:"         "$(count_lines "$VULN_DIR/nuclei_takeovers.txt")"
printf "  %-24s %s\n" "JS secrets:"        "$(count_lines "$VULN_DIR/js_secrets.txt")"
printf "  %-24s %s\n" "CORS issues:"       "$(count_lines "$VULN_DIR/cors_findings.txt")"
printf "  %-24s %s\n" "Open redirects:"    "$(count_lines "$VULN_DIR/confirmed_redirects.txt")"
printf "  %-24s %s\n" "SSRF confirmed:"    "$(count_lines "$VULN_DIR/confirmed_ssrf.txt")"
printf "  %-24s %s\n" "LFI confirmed:"     "$(count_lines "$VULN_DIR/confirmed_lfi.txt")"
printf "  %-24s %s\n" "XSS (Dalfox):"      "$(count_lines "$VULN_DIR/dalfox_xss.txt")"
printf "  %-24s %s\n" "403 bypasses:"      "$(count_lines "$VULN_DIR/403_bypass.txt")"
echo -e "${RED}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  ${BOLD}Vulns dir :${RESET} $VULN_DIR"
echo -e "  ${BOLD}Logs dir  :${RESET} $LOGS_DIR"
echo -e "  ${BOLD}Report    :${RESET} $REPORT_HTML"
echo -e "  ${BOLD}Log       :${RESET} $LOG_FILE"
echo -e "  ${BOLD}Elapsed   :${RESET} $ELAPSED_FMT"
echo -e "${RED}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
log_ok "Scan complete!"