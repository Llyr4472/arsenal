#!/bin/bash
# ══════════════════════════════════════════════════════════════
#  recon.sh v4.0 — Smart Recon | Resume | bbq-managed
#
#  All tool output goes to per-tool log files under $OUT_DIR/logs/
#  Main recon.log gets timestamped phase progress + counts only.
#  Use --skip-step <name> to re-run specific phases without --fresh.
#
#  Usage: ./recon.sh <domain> [options]
# ══════════════════════════════════════════════════════════════

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
BLUE='\033[0;34m';  CYAN='\033[0;36m';   BOLD='\033[1m'; RESET='\033[0m'

# ── Logging ───────────────────────────────────────────────────
TS()         { date '+%Y-%m-%d %H:%M:%S'; }
log_info()   { echo -e "[$(TS)] ${BLUE}[*]${RESET} $1";  echo "[$(TS)] [INFO]  $1" >> "$LOG_FILE"; }
log_ok()     { echo -e "[$(TS)] ${GREEN}[+]${RESET} $1"; echo "[$(TS)] [OK]    $1" >> "$LOG_FILE"; }
log_warn()   { echo -e "[$(TS)] ${YELLOW}[!]${RESET} $1"; echo "[$(TS)] [WARN]  $1" >> "$LOG_FILE"; }
log_error()  { echo -e "[$(TS)] ${RED}[x]${RESET} $1";  echo "[$(TS)] [ERROR] $1" >> "$LOG_FILE"; }
log_phase()  {
    local msg="$1"
    echo -e "\n${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${CYAN}${BOLD}  $msg${RESET}"
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo "[$(TS)] [PHASE] === $msg ===" >> "$LOG_FILE"
}

# Run a tool and log ALL its output (stdout+stderr) to a dedicated log file.
# Also writes a one-liner summary to the main log on completion.
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

count_lines() { [ -f "$1" ] && wc -l < "$1" || echo 0; }
safe_touch()  { for f in "$@"; do [ -f "$f" ] || touch "$f"; done; }

require_tool() {
    command -v "$1" &>/dev/null && return 0
    log_warn "Tool not found: ${BOLD}$1${RESET} — skipping."
    return 1
}

step_done()      { grep -qxF "$1" "$STEP_STATE_FILE" 2>/dev/null; }
mark_step_done() {
    echo "$1" >> "$STEP_STATE_FILE"
    log_ok "Phase '${BOLD}$1${RESET}' complete."
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
    log_warn "Recon PAUSED — waiting to resume..."
    while [ -f "$PAUSE_FILE" ]; do sleep 15; done
    log_ok "Recon RESUMED."
}

# ── Cleanup ───────────────────────────────────────────────────
cleanup_on_exit() {
    local code=$?
    rm -f "$OUT_DIR/.scan_pid" "$OUT_DIR/.scan_pgid"
    if [ "$code" -eq 0 ]; then
        echo "done"        > "$OUT_DIR/.scan_status"
        log_ok "Recon finished cleanly."
    else
        echo "interrupted" > "$OUT_DIR/.scan_status"
        log_warn "Recon interrupted (exit $code) — re-run to resume from checkpoint."
    fi
}
trap cleanup_on_exit EXIT
trap 'exit 130' TERM INT

# ── Usage ─────────────────────────────────────────────────────
usage() {
    echo -e "${BOLD}Usage:${RESET} $0 <target-domain> [options]"
    echo ""
    echo "  --threads <n>          Thread count (default: 50)"
    echo "  --rate-limit <n>       DNS rate limit (default: 3000)"
    echo "  --wordlist <path>      Subdomain wordlist"
    echo "  --fresh                Wipe ALL state and restart"
    echo "  --redo <step>          Re-run one specific step (keeps all others)"
    echo "                         Steps: passive  bruteforce  resolve"
    echo "                                permutations  probing  crawling  params"
    echo "  --skip-brute           Skip DNS bruteforce"
    echo "  --skip-perms           Skip permutation generation"
    echo "  --skip-crawl           Skip URL crawling"
    echo ""
    echo "Resume: just re-run — completed phases are skipped automatically."
    exit 1
}

# ── Arg Parsing ───────────────────────────────────────────────
[ "$#" -lt 1 ] && { usage; }
TARGET="$1"; shift

THREADS=50
RATE_LIMIT=3000
FRESH_START=false
DNS_BRUTE=false
DNS_PERMS=false
SKIP_CRAWL=false
REDO_STEPS=()
WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
RESOLVERS="$HOME/resolvers.txt"

# load secrets
source "$HOME/.config/secrets.env"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --threads)     THREADS="$2";             shift 2 ;;
        --wordlist)    WORDLIST="$2";            shift 2 ;;
        --rate-limit)  RATE_LIMIT="$2";          shift 2 ;;
        --fresh)       FRESH_START=true;         shift   ;;
        --redo)        REDO_STEPS+=("$2");       shift 2 ;;
        --dns-brute)   DNS_BRUTE=true;          shift   ;;
        --dns-perms)   DNS_PERMS=true;          shift   ;;
        --skip-crawl)  SKIP_CRAWL=true;          shift   ;;
        -h|--help)     usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

# ── Setup (must happen before any logging) ────────────────────
OUT_DIR="$HOME/bb/$TARGET"
LOGS_DIR="$OUT_DIR/logs"
STEP_STATE_FILE="$OUT_DIR/.recon_steps"
PAUSE_FILE="$OUT_DIR/.paused"
LOG_FILE="$LOGS_DIR/recon.log"

mkdir -p "$OUT_DIR" "$LOGS_DIR"

# Write PID and PGID for bbq tracking
echo $$       > "$OUT_DIR/.scan_pid"
ps -o pgid= -p $$ | tr -d ' ' > "$OUT_DIR/.scan_pgid"
echo "running" > "$OUT_DIR/.scan_status"

# Fresh start wipes log too
if [ "$FRESH_START" = "true" ]; then
    > "$LOG_FILE"
fi

# Log header
echo "" >> "$LOG_FILE"
echo "[$(TS)] ============================================" >> "$LOG_FILE"
echo "[$(TS)] [START] recon.sh $TARGET  pid=$$" >> "$LOG_FILE"
echo "[$(TS)] [ARGS]  threads=$THREADS rate=$RATE_LIMIT fresh=$FRESH_START" >> "$LOG_FILE"
echo "[$(TS)] ============================================" >> "$LOG_FILE"

# ── Fresh Start ───────────────────────────────────────────────
if [ "$FRESH_START" = "true" ]; then
    log_warn "Fresh start — clearing previous recon state."
    rm -f "$STEP_STATE_FILE"
    rm -f "$OUT_DIR"/*.txt 2>/dev/null
    rm -f "$LOGS_DIR"/*.log 2>/dev/null
fi

# ── Redo specific steps ───────────────────────────────────────
for step in "${REDO_STEPS[@]}"; do
    force_redo_step "phase_1_passive"     # map friendly names
    case "$step" in
        passive)       force_redo_step "phase_1_passive" ;;
        bruteforce)    force_redo_step "phase_2_bruteforce" ;;
        resolve)       force_redo_step "phase_3_resolve" ;;
        permutations)  force_redo_step "phase_4_permutations" ;;
        probing)       force_redo_step "phase_5_probing" ;;
        crawling)      force_redo_step "phase_6_crawling" ;;
        params)        force_redo_step "phase_7_params" ;;
        *) log_warn "Unknown step name for --redo: $step" ;;
    esac
done

IS_RESUME=false
if [ -f "$STEP_STATE_FILE" ] && [ -s "$STEP_STATE_FILE" ]; then
    IS_RESUME=true
    log_warn "Resuming — $(wc -l < "$STEP_STATE_FILE") phases already done."
fi

# ── Resolver Refresh ──────────────────────────────────────────
refresh_resolvers() {
    local stale=false
    [ ! -f "$RESOLVERS" ] && stale=true
    [ -n "$(find "$RESOLVERS" -mtime +7 2>/dev/null)" ] && stale=true
    if $stale; then
        log_info "Refreshing resolver list..."
        if curl -s --max-time 30 \
            "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
            -o "$RESOLVERS" 2>>"$LOGS_DIR/resolver_refresh.log"; then
            log_ok "Resolvers: $(count_lines "$RESOLVERS") entries"
        else
            log_warn "Resolver refresh failed — using existing or proceeding without."
        fi
    fi
}

run_dnsx() {
    local input="$1" output="$2" label="${3:-Resolving}"
    log_info "dnsx: $label ($(count_lines "$input") inputs)..."
    run_tool "dnsx_${label// /_}" "dnsx $label" \
        dnsx -l "$input" -silent -o "$output" \
             -r "$RESOLVERS" -t "$THREADS" -rl "$RATE_LIMIT"
}

# ── Start ─────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}Target   :${RESET} $TARGET"
echo -e "  ${BOLD}Output   :${RESET} $OUT_DIR"
echo -e "  ${BOLD}Logs dir :${RESET} $LOGS_DIR"
echo -e "  ${BOLD}PID/PGID :${RESET} $$ / $(cat "$OUT_DIR/.scan_pgid")"
echo -e "  ${BOLD}Threads  :${RESET} $THREADS   ${BOLD}Rate:${RESET} $RATE_LIMIT   ${BOLD}Resume:${RESET} $IS_RESUME"
echo ""

refresh_resolvers
START_TIME=$(date +%s)

# ══ PHASE 1: Passive Enumeration ══════════════════════════════
STEP="phase_1_passive"
if step_done "$STEP"; then
    log_phase "Phase 1: Passive Enumeration [DONE — SKIPPED]"
else
    log_phase "Phase 1: Passive Enumeration"
    wait_if_paused

    safe_touch "$OUT_DIR/subfinder.txt" "$OUT_DIR/assetfinder.txt" \
               "$OUT_DIR/github_subs.txt" "$OUT_DIR/crtsh.txt" "$OUT_DIR/otx.txt"

    if require_tool subfinder; then
        log_info "Running subfinder..."
        run_tool "subfinder" "subfinder -d $TARGET" \
            subfinder -d "$TARGET" -o "$OUT_DIR/subfinder.txt" -silent -t "$THREADS"
        log_ok "Subfinder: $(count_lines "$OUT_DIR/subfinder.txt") subs"
    fi
    wait_if_paused

    if require_tool assetfinder; then
        log_info "Running assetfinder..."
        run_tool "assetfinder" "assetfinder $TARGET" \
            bash -c "assetfinder --subs-only '$TARGET' > '$OUT_DIR/assetfinder.txt'"
        log_ok "Assetfinder: $(count_lines "$OUT_DIR/assetfinder.txt") subs"
    fi
    wait_if_paused

    log_info "Querying crt.sh..."
    run_tool "crtsh" "crt.sh query for $TARGET" \
        bash -c "curl -s --max-time 30 'https://crt.sh/?q=%25.$TARGET&output=json' \
            | grep -oP '\"name_value\":\"\K[^\"]+' | sed 's/\*\.//g' \
            | sort -u > '$OUT_DIR/crtsh.txt'"
    log_ok "crt.sh: $(count_lines "$OUT_DIR/crtsh.txt") subs"

    log_info "Querying AlienVault OTX..."
    run_tool "otx" "AlienVault OTX passive DNS for $TARGET" \
        bash -c "curl -s --max-time 30 \
            'https://otx.alienvault.com/api/v1/indicators/domain/${TARGET}/passive_dns' \
            | grep -oP '\"hostname\":\"\K[^\"]+' | grep -F '.$TARGET' \
            | sort -u > '$OUT_DIR/otx.txt'"
    log_ok "OTX: $(count_lines "$OUT_DIR/otx.txt") subs"
    wait_if_paused

    if require_tool github-subdomains; then
        log_info "Running github-subdomains..."
        run_tool "github_subs" "github-subdomains $TARGET" \
            github-subdomains -d "$TARGET" -o "$OUT_DIR/github_subs.txt"
        log_ok "Github: $(count_lines "$OUT_DIR/github_subs.txt") subs"
    fi

    cat "$OUT_DIR/subfinder.txt" "$OUT_DIR/assetfinder.txt" \
        "$OUT_DIR/github_subs.txt" "$OUT_DIR/crtsh.txt" "$OUT_DIR/otx.txt" \
        2>/dev/null | sort -u > "$OUT_DIR/passive_raw.txt"
    log_ok "Total passive: ${BOLD}$(count_lines "$OUT_DIR/passive_raw.txt")${RESET} subs"
    mark_step_done "$STEP"
fi

# ══ PHASE 2: DNS Bruteforce ════════════════════════════════════
STEP="phase_2_bruteforce"
if [ "$DNS_BRUTE" = "false" ]; then
    log_phase "Phase 2: DNS Bruteforce [SKIPPED without --dns-brute]"
    safe_touch "$OUT_DIR/brute_subs.txt"
elif step_done "$STEP"; then
    log_phase "Phase 2: DNS Bruteforce [DONE — SKIPPED]"
else
    log_phase "Phase 2: DNS Bruteforce"
    wait_if_paused
    safe_touch "$OUT_DIR/brute_subs.txt"

    if [ ! -f "$WORDLIST" ]; then
        log_error "Wordlist not found: $WORDLIST — skipping bruteforce."
    elif require_tool dnsx; then
        log_info "Bruteforcing $(count_lines "$WORDLIST") words against $TARGET..."
        run_tool "brute_dnsx" "DNS bruteforce for $TARGET" \
            bash -c "awk -v d='$TARGET' '{print \$1\".\"d}' '$WORDLIST' \
                | dnsx -silent -o '$OUT_DIR/brute_subs.txt' \
                       -r '$RESOLVERS' -t '$THREADS' -rl '$RATE_LIMIT'"
        log_ok "Bruteforce: ${BOLD}$(count_lines "$OUT_DIR/brute_subs.txt")${RESET} subs"
    fi
    mark_step_done "$STEP"
fi

# ══ PHASE 3: Resolve ══════════════════════════════════════════
STEP="phase_3_resolve"
if step_done "$STEP"; then
    log_phase "Phase 3: Resolve [DONE — SKIPPED]"
else
    log_phase "Phase 3: Resolve"
    wait_if_paused

    cat "$OUT_DIR/passive_raw.txt" "$OUT_DIR/brute_subs.txt" 2>/dev/null \
        | sort -u > "$OUT_DIR/all_raw.txt"
    local_total=$(count_lines "$OUT_DIR/all_raw.txt")

    if [ "$local_total" -eq 0 ]; then
        log_warn "Nothing to resolve."
        safe_touch "$OUT_DIR/base_resolved.txt"
    else
        run_dnsx "$OUT_DIR/all_raw.txt" "$OUT_DIR/base_resolved.txt" "Resolve"
        log_ok "Alive: ${BOLD}$(count_lines "$OUT_DIR/base_resolved.txt")${RESET} / $local_total"
    fi
    mark_step_done "$STEP"
fi

ALIVE_BASE_COUNT=$(count_lines "$OUT_DIR/base_resolved.txt")

# ══ PHASE 4: Permutations ═════════════════════════════════════
STEP="phase_4_permutations"
if [ "$DNS_PERMS" = "false" ]; then
    log_phase "Phase 4: Permutations [SKIPPED without --dns-perms]"
    safe_touch "$OUT_DIR/permutations_resolved.txt"
elif step_done "$STEP"; then
    log_phase "Phase 4: Permutations [DONE — SKIPPED]"
else
    log_phase "Phase 4: Smart Permutations"
    wait_if_paused
    safe_touch "$OUT_DIR/permutations_resolved.txt"

    if [ "$ALIVE_BASE_COUNT" -eq 0 ]; then
        log_warn "No alive domains — skipping permutations."
    elif require_tool dnsgen; then
        log_info "Generating permutations from $ALIVE_BASE_COUNT domains..."
        dnsgen "$OUT_DIR/base_resolved.txt" \
    |       dnsx -silent -o "$OUT_DIR/permutations_resolved.txt" \
                 -r "$RESOLVERS" -t "$THREADS" -rl "$RATE_LIMIT" \
            >> "$LOGS_DIR/permutations_dnsx.log" 2>&1
        log_ok "Permutations: ${BOLD}$(count_lines "$OUT_DIR/permutations_resolved.txt")${RESET} new subs"
    fi
    mark_step_done "$STEP"
fi

# ══ PHASE 5: Port Scan & HTTP Probe ═══════════════════════════
STEP="phase_5_probing"
if step_done "$STEP"; then
    log_phase "Phase 5: Port Scan & HTTP Probing [DONE — SKIPPED]"
else
    log_phase "Phase 5: Port Scan & HTTP Probing"
    wait_if_paused

    cat "$OUT_DIR/base_resolved.txt" "$OUT_DIR/permutations_resolved.txt" 2>/dev/null \
        | sort -u > "$OUT_DIR/final_subdomains.txt"
    local_total=$(count_lines "$OUT_DIR/final_subdomains.txt")

    if [ "$local_total" -eq 0 ]; then
        log_warn "No subdomains to probe."
        safe_touch "$OUT_DIR/alive.txt" "$OUT_DIR/web_alive.txt" "$OUT_DIR/alive_urls_only.txt"
    else
        # Always start with base subdomains (for default HTTP/HTTPS ports)
        cp "$OUT_DIR/final_subdomains.txt" "$OUT_DIR/alive.txt"
        
        if require_tool naabu; then
            log_info "Port scanning $local_total subdomains (top-1000)..."
            run_tool "naabu" "naabu port scan for $TARGET" \
                naabu -list "$OUT_DIR/final_subdomains.txt" \
                      -top-ports 1000 -silent -o "$OUT_DIR/.naabu_temp.txt"
            
            # Append naabu results (hosts with non-standard ports) to alive.txt
            if [ -s "$OUT_DIR/.naabu_temp.txt" ]; then
                cut -d: -f1 "$OUT_DIR/.naabu_temp.txt" | sort -u >> "$OUT_DIR/alive.txt"
                sort -u "$OUT_DIR/alive.txt" -o "$OUT_DIR/alive.txt"
                sync
            fi
            
            log_ok "Open ports: ${BOLD}$(count_lines "$OUT_DIR/.naabu_temp.txt")${RESET}"
            rm -f "$OUT_DIR/.naabu_temp.txt"
        fi
        
        # Delay to avoid rate limiting after port scan
        log_info "Waiting 5s before HTTP probe to avoid rate limiting..."
        sleep 5
        
        wait_if_paused

        if require_tool httpx; then
            log_info "HTTP probing $(count_lines "$OUT_DIR/alive.txt") hosts..."
            run_tool "httpx" "httpx HTTP probe for $TARGET" \
                httpx -l "$OUT_DIR/alive.txt" \
                      -title -tech-detect -status-code -ip -cdn \
                      -follow-redirects -threads "$THREADS" \
                      -retries 2 \
                      -timeout 10 \
                      -o "$OUT_DIR/web_alive.txt"
            awk '{print $1}' "$OUT_DIR/web_alive.txt" > "$OUT_DIR/alive_urls_only.txt"
            log_ok "Live web servers: ${BOLD}$(count_lines "$OUT_DIR/web_alive.txt")${RESET}"
        else
            safe_touch "$OUT_DIR/web_alive.txt" "$OUT_DIR/alive_urls_only.txt"
        fi
    fi
    mark_step_done "$STEP"
fi

# ══ PHASE 6: URL Discovery & Crawling ═════════════════════════
STEP="phase_6_crawling"
HTTP_COUNT=$(count_lines "$OUT_DIR/web_alive.txt")

if [ "$SKIP_CRAWL" = "true" ]; then
    log_phase "Phase 6: URL Discovery & Crawling [SKIPPED via --skip-crawl]"
    safe_touch "$OUT_DIR/clean_urls.txt"
elif step_done "$STEP"; then
    log_phase "Phase 6: URL Discovery & Crawling [DONE — SKIPPED]"
else
    log_phase "Phase 6: URL Discovery & Crawling"
    wait_if_paused
    safe_touch "$OUT_DIR/waymore_urls.txt" "$OUT_DIR/katana.txt" "$OUT_DIR/gau_urls.txt"

    if [ "$HTTP_COUNT" -eq 0 ]; then
        log_warn "No live web servers — skipping crawl."
        safe_touch "$OUT_DIR/clean_urls.txt"
    else
        if require_tool waymore; then
            log_info "Running waymore..."
            run_tool "waymore" "waymore URL discovery for $TARGET" \
                waymore -i "$TARGET" -mode U -oU "$OUT_DIR/waymore_urls.txt"
            log_ok "Waymore: $(count_lines "$OUT_DIR/waymore_urls.txt") URLs"
        fi
        wait_if_paused

        if require_tool gau; then
            log_info "Running gau..."
            run_tool "gau" "gau URL discovery for $TARGET" \
                bash -c "gau --threads '$THREADS' --subs '$TARGET' \
                    2>/dev/null | sort -u > '$OUT_DIR/gau_urls.txt'"
            log_ok "GAU: $(count_lines "$OUT_DIR/gau_urls.txt") URLs"
        fi
        wait_if_paused

        if require_tool katana; then
            log_info "Katana crawl on $HTTP_COUNT endpoints..."
            run_tool "katana" "katana crawl for $TARGET" \
                katana -list "$OUT_DIR/alive_urls_only.txt" \
                       -jc -jsl -kf all -d 3 -rl 10 -timeout 10 \
                       -concurrency "$THREADS" -silent \
                       -o "$OUT_DIR/katana.txt"
            log_ok "Katana: $(count_lines "$OUT_DIR/katana.txt") URLs"
        fi
        wait_if_paused

        log_info "Deduplicating URLs..."
        if require_tool uro; then
            cat "$OUT_DIR/waymore_urls.txt" "$OUT_DIR/gau_urls.txt" "$OUT_DIR/katana.txt" \
                2>/dev/null | uro | sort -u > "$OUT_DIR/clean_urls.txt"
        else
            cat "$OUT_DIR/waymore_urls.txt" "$OUT_DIR/gau_urls.txt" "$OUT_DIR/katana.txt" \
                2>/dev/null | sort -u > "$OUT_DIR/clean_urls.txt"
        fi
        log_ok "Unique URLs: ${BOLD}$(count_lines "$OUT_DIR/clean_urls.txt")${RESET}"
    fi
    mark_step_done "$STEP"
fi

# ══ PHASE 7: Parameter Extraction ═════════════════════════════
STEP="phase_7_params"
if step_done "$STEP"; then
    log_phase "Phase 7: Parameter Extraction [DONE — SKIPPED]"
else
    log_phase "Phase 7: Parameter Extraction"
    wait_if_paused
    safe_touch "$OUT_DIR/paramspider.txt" "$OUT_DIR/crawled_params.txt"

    if require_tool paramspider; then
        log_info "Running paramspider..."
        run_tool "paramspider" "paramspider for $TARGET" \
            bash -c "paramspider -d '$TARGET' --quiet 2>/dev/null; \
                [ -f 'results/$TARGET.txt' ] && mv 'results/$TARGET.txt' '$OUT_DIR/paramspider.txt'; \
                rmdir results 2>/dev/null; true"
        log_ok "Paramspider: $(count_lines "$OUT_DIR/paramspider.txt") URLs"
    fi

    grep "?" "$OUT_DIR/clean_urls.txt" 2>/dev/null | sort -u > "$OUT_DIR/crawled_params.txt"
    log_ok "Crawled params: $(count_lines "$OUT_DIR/crawled_params.txt") URLs"

    if require_tool uro; then
        cat "$OUT_DIR/paramspider.txt" "$OUT_DIR/crawled_params.txt" \
            2>/dev/null | uro | sort -u > "$OUT_DIR/final_params.txt"
    else
        cat "$OUT_DIR/paramspider.txt" "$OUT_DIR/crawled_params.txt" \
            2>/dev/null | sort -u > "$OUT_DIR/final_params.txt"
    fi
    log_ok "Unique param URLs: ${BOLD}$(count_lines "$OUT_DIR/final_params.txt")${RESET}"
    mark_step_done "$STEP"
fi

# ── Summary ───────────────────────────────────────────────────
END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
ELAPSED_FMT=$(printf "%02d:%02d:%02d" $(( ELAPSED/3600 )) $(( ELAPSED%3600/60 )) $(( ELAPSED%60 )))

SUMMARY="
[$(TS)] ============================================
[$(TS)] [SUMMARY] $TARGET
[$(TS)] [SUMMARY] Passive subs:    $(count_lines "$OUT_DIR/passive_raw.txt")
[$(TS)] [SUMMARY] Bruteforce hits: $(count_lines "$OUT_DIR/brute_subs.txt")
[$(TS)] [SUMMARY] Resolved alive:  $(count_lines "$OUT_DIR/base_resolved.txt")
[$(TS)] [SUMMARY] Permutations:    $(count_lines "$OUT_DIR/permutations_resolved.txt")
[$(TS)] [SUMMARY] Final subs:      $(count_lines "$OUT_DIR/final_subdomains.txt")
[$(TS)] [SUMMARY] Live web:        $(count_lines "$OUT_DIR/web_alive.txt")
[$(TS)] [SUMMARY] Unique URLs:     $(count_lines "$OUT_DIR/clean_urls.txt")
[$(TS)] [SUMMARY] Param URLs:      $(count_lines "$OUT_DIR/final_params.txt")
[$(TS)] [SUMMARY] Elapsed:         $ELAPSED_FMT
[$(TS)] ============================================"
echo "$SUMMARY" >> "$LOG_FILE"

echo ""
echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${CYAN}${BOLD}  RECON SUMMARY — $TARGET${RESET}"
echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
printf "  %-24s %s\n" "Passive subs:"    "$(count_lines "$OUT_DIR/passive_raw.txt")"
printf "  %-24s %s\n" "Bruteforce hits:" "$(count_lines "$OUT_DIR/brute_subs.txt")"
printf "  %-24s %s\n" "Resolved alive:"  "$(count_lines "$OUT_DIR/base_resolved.txt")"
printf "  %-24s %s\n" "Permutations:"    "$(count_lines "$OUT_DIR/permutations_resolved.txt")"
printf "  %-24s %s\n" "Final subdomains:""$(count_lines "$OUT_DIR/final_subdomains.txt")"
printf "  %-24s %s\n" "Live web servers:""$(count_lines "$OUT_DIR/web_alive.txt")"
printf "  %-24s %s\n" "Unique URLs:"     "$(count_lines "$OUT_DIR/clean_urls.txt")"
printf "  %-24s %s\n" "URLs w/ params:"  "$(count_lines "$OUT_DIR/final_params.txt")"
echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  ${BOLD}Output :${RESET} $OUT_DIR"
echo -e "  ${BOLD}Log    :${RESET} $LOG_FILE"
echo -e "  ${BOLD}ToolLog:${RESET} $LOGS_DIR/*.log"
echo -e "  ${BOLD}Elapsed:${RESET} $ELAPSED_FMT"
echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
log_ok "Recon complete!"