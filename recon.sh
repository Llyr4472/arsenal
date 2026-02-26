#!/bin/bash
# Smart Recon Script v3.0 — Resume, Auto-pause, Detachable | Managed by: bbq

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
BLUE='\033[0;34m';  CYAN='\033[0;36m';   BOLD='\033[1m'; RESET='\033[0m'

print_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗"
    echo "  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║"
    echo "  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║"
    echo "  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║"
    echo "  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║"
    echo "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝  v3.0"
    echo -e "${RESET}"
}

log_info()    { echo -e "[$(date '+%H:%M:%S')] ${BLUE}[*]${RESET} $1"; }
log_success() { echo -e "[$(date '+%H:%M:%S')] ${GREEN}[+]${RESET} $1"; }
log_warn()    { echo -e "[$(date '+%H:%M:%S')] ${YELLOW}[!]${RESET} $1"; }
log_error()   { echo -e "[$(date '+%H:%M:%S')] ${RED}[✗]${RESET} $1"; }
log_phase()   {
    echo -e "\n${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${CYAN}${BOLD}  $1${RESET}"
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

count_lines() { [ -f "$1" ] && wc -l < "$1" || echo 0; }
safe_touch()  { for f in "$@"; do [ -f "$f" ] || touch "$f"; done; }
require_tool() {
    command -v "$1" &>/dev/null && return 0
    log_warn "Tool not found: ${BOLD}$1${RESET} — skipping."
    return 1
}

step_done()      { grep -qxF "$1" "$STEP_STATE_FILE" 2>/dev/null; }
mark_step_done() { echo "$1" >> "$STEP_STATE_FILE"; log_info "Phase '${BOLD}$1${RESET}' complete."; }

PAUSE_FILE=""; WATCHDOG_PID=""

start_network_watchdog() {
    (
        local fails=0 paused=false wlog="${OUT_DIR}/watchdog.log"
        while true; do
            if ping -c 1 -W 3 8.8.8.8 &>/dev/null 2>&1; then
                fails=0
                if $paused; then
                    rm -f "$PAUSE_FILE"; paused=false
                    echo "[$(date '+%H:%M:%S')] [WATCHDOG] Network restored." >> "$wlog"
                fi
            else
                ((fails++))
                if [ "$fails" -ge 3 ] && ! $paused; then
                    touch "$PAUSE_FILE"; paused=true
                    echo "[$(date '+%H:%M:%S')] [WATCHDOG] Network lost — paused." >> "$wlog"
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
    [ -n "$WATCHDOG_PID" ] && kill "$WATCHDOG_PID" 2>/dev/null
    rm -f "$OUT_DIR/.watchdog_pid"
}

wait_if_paused() {
    [ ! -f "$PAUSE_FILE" ] && return 0
    log_warn "Recon PAUSED. Waiting to resume... (rm '$PAUSE_FILE' to force resume)"
    while [ -f "$PAUSE_FILE" ]; do sleep 15; done
    log_success "Recon RESUMED."
}

cleanup_on_exit() {
    local code=$?
    stop_network_watchdog; rm -f "$OUT_DIR/.scan_pid"
    [ "$code" -eq 0 ] && echo "done" > "$OUT_DIR/.scan_status" \
                      || echo "interrupted" > "$OUT_DIR/.scan_status"
}
trap cleanup_on_exit EXIT
trap 'exit 130' TERM INT

usage() {
    echo -e "${BOLD}Usage:${RESET} $0 <target-domain> [options]"
    echo "  --threads <n>   --wordlist <p>  --rate-limit <n>  --no-pv"
    echo "  --fresh         --skip-brute    --skip-perms       --skip-crawl"
    echo ""
    echo "Resume: just re-run — completed phases auto-skipped. Use --fresh to restart."
    exit 1
}

[ "$#" -lt 1 ] && { print_banner; usage; }
target="$1"; shift

THREADS=50; RATE_LIMIT=3000; USE_PV=true; FRESH_START=false
SKIP_BRUTE=false; SKIP_PERMS=false; SKIP_CRAWL=false
WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
RESOLVERS="$HOME/resolvers.txt"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --threads)     THREADS="$2";     shift 2 ;;
        --wordlist)    WORDLIST="$2";    shift 2 ;;
        --rate-limit)  RATE_LIMIT="$2";  shift 2 ;;
        --no-pv)       USE_PV=false;     shift   ;;
        --fresh)       FRESH_START=true; shift   ;;
        --skip-brute)  SKIP_BRUTE=true;  shift   ;;
        --skip-perms)  SKIP_PERMS=true;  shift   ;;
        --skip-crawl)  SKIP_CRAWL=true;  shift   ;;
        -h|--help) usage ;;
        *) log_error "Unknown: $1"; usage ;;
    esac
done

OUT_DIR="$HOME/bb/${target}"
STEP_STATE_FILE="$OUT_DIR/.recon_steps"
PAUSE_FILE="$OUT_DIR/.paused"
LOG_FILE="$OUT_DIR/recon.log"

mkdir -p "$OUT_DIR"
echo $$ > "$OUT_DIR/.scan_pid"
echo "running" > "$OUT_DIR/.scan_status"
exec > >(tee -a "$LOG_FILE") 2>&1

HAS_PV=false
$USE_PV && command -v pv &>/dev/null && HAS_PV=true

if [ "$FRESH_START" = "true" ]; then
    log_warn "Fresh start — clearing previous recon state."
    rm -f "$STEP_STATE_FILE" "$OUT_DIR"/*.txt 2>/dev/null
fi

IS_RESUME=false
if [ -f "$STEP_STATE_FILE" ] && [ -s "$STEP_STATE_FILE" ]; then
    IS_RESUME=true
    log_warn "Resuming — $(wc -l < "$STEP_STATE_FILE") phases already done."
fi

refresh_resolvers() {
    local stale=false
    [ ! -f "$RESOLVERS" ] && stale=true
    [ "$(find "$RESOLVERS" -mtime +7 2>/dev/null)" ] && stale=true
    if $stale; then
        log_info "Refreshing resolvers..."
        command -v wget &>/dev/null && wget -q "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" -O "$RESOLVERS" \
            || curl -s "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" -o "$RESOLVERS" 2>/dev/null
        [ -f "$RESOLVERS" ] && log_success "Resolvers: $(count_lines "$RESOLVERS") entries"
    fi
}

run_dnsx_resolve() {
    local input="$1" output="$2" label="${3:-Resolving}"
    if $HAS_PV; then
        pv -N "$label" -l "$input" | dnsx -silent -o "$output" -r "$RESOLVERS" -t "$THREADS" -rl "$RATE_LIMIT"
    else
        dnsx -l "$input" -silent -o "$output" -r "$RESOLVERS" -t "$THREADS" -rl "$RATE_LIMIT"
    fi
}

print_banner
echo -e "${BOLD}Target:${RESET} $target  ${BOLD}Output:${RESET} $OUT_DIR  ${BOLD}PID:${RESET} $$"
echo -e "${BOLD}Threads:${RESET} $THREADS  ${BOLD}Rate:${RESET} $RATE_LIMIT  ${BOLD}Resume:${RESET} $IS_RESUME"
echo ""
refresh_resolvers
start_network_watchdog
START_TIME=$(date +%s)

# ══ PHASE 1: Passive Enumeration ══════════
STEP="phase_1_passive"
if step_done "$STEP"; then
    log_phase "Phase 1: Passive Enumeration [DONE — SKIPPED]"
else
    log_phase "Phase 1: Passive Enumeration"
    wait_if_paused
    safe_touch "$OUT_DIR/subfinder.txt" "$OUT_DIR/assetfinder.txt" \
               "$OUT_DIR/amass.txt"     "$OUT_DIR/github_subs.txt" \
               "$OUT_DIR/crtsh.txt"     "$OUT_DIR/otx.txt"

    require_tool subfinder && {
        log_info "Running Subfinder..."
        subfinder -d "$target" -o "$OUT_DIR/subfinder.txt" -silent -t "$THREADS" 2>/dev/null
        log_success "Subfinder: $(count_lines "$OUT_DIR/subfinder.txt") subs"
    }
    wait_if_paused

    require_tool assetfinder && {
        log_info "Running Assetfinder..."
        assetfinder --subs-only "$target" > "$OUT_DIR/assetfinder.txt" 2>/dev/null
        log_success "Assetfinder: $(count_lines "$OUT_DIR/assetfinder.txt") subs"
    }
    wait_if_paused

    if command -v curl &>/dev/null; then
        log_info "Querying crt.sh..."
        curl -s "https://crt.sh/?q=%25.$target&output=json" 2>/dev/null \
            | grep -oP '"name_value":"\K[^"]+' | sed 's/\*\.//g' \
            | sort -u > "$OUT_DIR/crtsh.txt"
        log_success "crt.sh: $(count_lines "$OUT_DIR/crtsh.txt") subs"

        log_info "Querying AlienVault OTX..."
        curl -s "https://otx.alienvault.com/api/v1/indicators/domain/${target}/passive_dns" 2>/dev/null \
            | grep -oP '"hostname":"\K[^"]+' | grep -F ".$target" \
            | sort -u > "$OUT_DIR/otx.txt"
        log_success "OTX: $(count_lines "$OUT_DIR/otx.txt") subs"
    fi
    wait_if_paused

    if require_tool github-subdomains; then
        if [ -n "$gh_token" ]; then
            log_info "Running Github Subdomains..."
            github-subdomains -d "$target" -t "$gh_token" -o "$OUT_DIR/github_subs.txt" 2>/dev/null
            log_success "Github: $(count_lines "$OUT_DIR/github_subs.txt") subs"
        else
            log_warn "gh_token not set — skipping github-subdomains. Set: export gh_token=TOKEN"
        fi
    fi

    cat "$OUT_DIR/subfinder.txt" "$OUT_DIR/assetfinder.txt" "$OUT_DIR/amass.txt" \
        "$OUT_DIR/github_subs.txt" "$OUT_DIR/crtsh.txt" "$OUT_DIR/otx.txt" \
        2>/dev/null | sort -u > "$OUT_DIR/passive_raw.txt"
    log_success "Total Passive: ${BOLD}$(count_lines "$OUT_DIR/passive_raw.txt")${RESET} subs"
    mark_step_done "$STEP"
fi

# ══ PHASE 2: Active Bruteforce ════════════
STEP="phase_2_bruteforce"
if [ "$SKIP_BRUTE" = "true" ]; then
    log_phase "Phase 2: Active Bruteforce [SKIPPED]"
    safe_touch "$OUT_DIR/brute_subs.txt"
elif step_done "$STEP"; then
    log_phase "Phase 2: Active Bruteforce [DONE — SKIPPED]"
else
    log_phase "Phase 2: Active Bruteforce"
    wait_if_paused
    safe_touch "$OUT_DIR/brute_subs.txt"

    if [ ! -f "$WORDLIST" ]; then
        log_error "Wordlist not found: $WORDLIST"
    elif require_tool dnsx; then
        log_info "Bruteforcing $(count_lines "$WORDLIST") words..."
        if $HAS_PV; then
            awk -v d="$target" '{print $1"."d}' "$WORDLIST" | pv -N "Brute" -l \
                | dnsx -silent -o "$OUT_DIR/brute_subs.txt" -r "$RESOLVERS" -t "$THREADS" -rl "$RATE_LIMIT"
        else
            awk -v d="$target" '{print $1"."d}' "$WORDLIST" \
                | dnsx -silent -o "$OUT_DIR/brute_subs.txt" -r "$RESOLVERS" -t "$THREADS" -rl "$RATE_LIMIT"
        fi
        log_success "Bruteforce: ${BOLD}$(count_lines "$OUT_DIR/brute_subs.txt")${RESET} subs"
    fi
    mark_step_done "$STEP"
fi

# ══ PHASE 3: Resolve Base List ════════════
STEP="phase_3_resolve"
if step_done "$STEP"; then
    log_phase "Phase 3: Resolve Base List [DONE — SKIPPED]"
    ALIVE_BASE_COUNT=$(count_lines "$OUT_DIR/base_resolved.txt")
else
    log_phase "Phase 3: Resolve Base List"
    wait_if_paused

    cat "$OUT_DIR/passive_raw.txt" "$OUT_DIR/brute_subs.txt" 2>/dev/null \
        | sort -u > "$OUT_DIR/all_raw.txt"
    TOTAL=$(count_lines "$OUT_DIR/all_raw.txt")

    if [ "$TOTAL" -eq 0 ]; then
        log_warn "Nothing to resolve."
        safe_touch "$OUT_DIR/base_resolved.txt"; ALIVE_BASE_COUNT=0
    else
        log_info "Resolving ${BOLD}$TOTAL${RESET} domains..."
        run_dnsx_resolve "$OUT_DIR/all_raw.txt" "$OUT_DIR/base_resolved.txt" "Resolve"
        ALIVE_BASE_COUNT=$(count_lines "$OUT_DIR/base_resolved.txt")
        log_success "Alive: ${BOLD}$ALIVE_BASE_COUNT${RESET} / $TOTAL"
    fi
    mark_step_done "$STEP"
fi

# ══ PHASE 4: Smart Permutations ═══════════
STEP="phase_4_permutations"
if [ "$SKIP_PERMS" = "true" ]; then
    log_phase "Phase 4: Smart Permutations [SKIPPED]"
    safe_touch "$OUT_DIR/permutations_resolved.txt"
elif step_done "$STEP"; then
    log_phase "Phase 4: Smart Permutations [DONE — SKIPPED]"
else
    log_phase "Phase 4: Smart Permutations"
    wait_if_paused
    safe_touch "$OUT_DIR/permutations_resolved.txt"

    if [ "$ALIVE_BASE_COUNT" -eq 0 ]; then
        log_warn "No alive domains — skipping permutations."
    elif require_tool dnsgen; then
        log_info "Generating permutations from $ALIVE_BASE_COUNT domains..."
        if $HAS_PV; then
            dnsgen "$OUT_DIR/base_resolved.txt" | pv -N "Perms" -l \
                | dnsx -silent -o "$OUT_DIR/permutations_resolved.txt" \
                       -r "$RESOLVERS" -t "$THREADS" -rl "$RATE_LIMIT"
        else
            dnsgen "$OUT_DIR/base_resolved.txt" \
                | dnsx -silent -o "$OUT_DIR/permutations_resolved.txt" \
                       -r "$RESOLVERS" -t "$THREADS" -rl "$RATE_LIMIT"
        fi
        log_success "Permutations: ${BOLD}$(count_lines "$OUT_DIR/permutations_resolved.txt")${RESET} new subs"
    fi
    mark_step_done "$STEP"
fi

# ══ PHASE 5: Port Scan & HTTP Probing ════
STEP="phase_5_probing"
if step_done "$STEP"; then
    log_phase "Phase 5: Port Scan & HTTP Probing [DONE — SKIPPED]"
    HTTP_COUNT=$(count_lines "$OUT_DIR/web_alive.txt")
else
    log_phase "Phase 5: Port Scan & HTTP Probing"
    wait_if_paused

    cat "$OUT_DIR/base_resolved.txt" "$OUT_DIR/permutations_resolved.txt" 2>/dev/null \
        | sort -u > "$OUT_DIR/final_subdomains.txt"
    TOTAL=$(count_lines "$OUT_DIR/final_subdomains.txt")

    if [ "$TOTAL" -eq 0 ]; then
        log_warn "No subdomains to probe."
        safe_touch "$OUT_DIR/alive.txt" "$OUT_DIR/web_alive.txt" "$OUT_DIR/alive_urls_only.txt"
        HTTP_COUNT=0
    else
        if require_tool naabu; then
            log_info "Port scanning ${BOLD}$TOTAL${RESET} subdomains..."
            naabu -list "$OUT_DIR/final_subdomains.txt" -top-ports 1000 \
                  -silent -o "$OUT_DIR/alive.txt" 2>/dev/null
        else
            cp "$OUT_DIR/final_subdomains.txt" "$OUT_DIR/alive.txt"
        fi
        log_success "Open ports: ${BOLD}$(count_lines "$OUT_DIR/alive.txt")${RESET}"
        wait_if_paused

        if require_tool httpx; then
            log_info "HTTP probing $(count_lines "$OUT_DIR/alive.txt") hosts..."
            httpx -l "$OUT_DIR/alive.txt" \
                  -title -tech-detect -status-code -ip -cdn \
                  -follow-redirects -threads "$THREADS" -silent \
                  -o "$OUT_DIR/web_alive.txt" 2>/dev/null
            HTTP_COUNT=$(count_lines "$OUT_DIR/web_alive.txt")
            awk '{print $1}' "$OUT_DIR/web_alive.txt" > "$OUT_DIR/alive_urls_only.txt"
            log_success "Live web servers: ${BOLD}$HTTP_COUNT${RESET}"
        else
            safe_touch "$OUT_DIR/web_alive.txt" "$OUT_DIR/alive_urls_only.txt"
            HTTP_COUNT=0
        fi
    fi
    mark_step_done "$STEP"
fi

# ══ PHASE 6: URL Discovery & Crawling ════
STEP="phase_6_crawling"
if [ "$SKIP_CRAWL" = "true" ]; then
    log_phase "Phase 6: URL Discovery & Crawling [SKIPPED]"
    safe_touch "$OUT_DIR/clean_urls.txt"
    URL_COUNT=$(count_lines "$OUT_DIR/clean_urls.txt")
elif step_done "$STEP"; then
    log_phase "Phase 6: URL Discovery & Crawling [DONE — SKIPPED]"
    URL_COUNT=$(count_lines "$OUT_DIR/clean_urls.txt")
else
    log_phase "Phase 6: URL Discovery & Crawling"
    wait_if_paused
    safe_touch "$OUT_DIR/waymore_urls.txt" "$OUT_DIR/katana.txt" "$OUT_DIR/gau_urls.txt"

    if [ "$HTTP_COUNT" -eq 0 ]; then
        log_warn "No live web servers — skipping crawl."
        safe_touch "$OUT_DIR/clean_urls.txt"; URL_COUNT=0
    else
        require_tool waymore && {
            log_info "Running Waymore..."
            waymore -i "$target" -mode U -oU "$OUT_DIR/waymore_urls.txt" 2>/dev/null
            log_success "Waymore: $(count_lines "$OUT_DIR/waymore_urls.txt") URLs"
        }
        wait_if_paused

        require_tool gau && {
            log_info "Running GAU..."
            gau --threads "$THREADS" --subs "$target" 2>/dev/null \
                | sort -u > "$OUT_DIR/gau_urls.txt"
            log_success "GAU: $(count_lines "$OUT_DIR/gau_urls.txt") URLs"
        }
        wait_if_paused

        require_tool katana && {
            log_info "Crawling ${BOLD}$HTTP_COUNT${RESET} endpoints with Katana..."
            if $HAS_PV; then
                pv -N "Katana" -l "$OUT_DIR/alive_urls_only.txt" \
                    | katana -jc -jsl -kf all -d 3 -rl 10 -timeout 10 \
                             -concurrency "$THREADS" -silent \
                             -o "$OUT_DIR/katana.txt" 2>/dev/null
            else
                katana -list "$OUT_DIR/alive_urls_only.txt" \
                       -jc -jsl -kf all -d 3 -rl 10 -timeout 10 \
                       -concurrency "$THREADS" -silent \
                       -o "$OUT_DIR/katana.txt" 2>/dev/null
            fi
            log_success "Katana: $(count_lines "$OUT_DIR/katana.txt") URLs"
        }
        wait_if_paused

        log_info "Deduplicating URLs..."
        if require_tool uro; then
            cat "$OUT_DIR/waymore_urls.txt" "$OUT_DIR/gau_urls.txt" "$OUT_DIR/katana.txt" \
                | uro | sort -u > "$OUT_DIR/clean_urls.txt"
        else
            cat "$OUT_DIR/waymore_urls.txt" "$OUT_DIR/gau_urls.txt" "$OUT_DIR/katana.txt" \
                | sort -u > "$OUT_DIR/clean_urls.txt"
        fi
        URL_COUNT=$(count_lines "$OUT_DIR/clean_urls.txt")
        log_success "Unique URLs: ${BOLD}$URL_COUNT${RESET}"
    fi
    mark_step_done "$STEP"
fi

# ══ PHASE 7: Parameter Extraction ════════
STEP="phase_7_params"
if step_done "$STEP"; then
    log_phase "Phase 7: Parameter Extraction [DONE — SKIPPED]"
    PARAM_COUNT=$(count_lines "$OUT_DIR/final_params.txt")
else
    log_phase "Phase 7: Parameter Extraction"
    wait_if_paused
    safe_touch "$OUT_DIR/paramspider.txt" "$OUT_DIR/crawled_params.txt"

    require_tool paramspider && {
        log_info "Running Paramspider..."
        paramspider -d "$target" --quiet 2>/dev/null
        [ -f "results/$target.txt" ] && mv "results/$target.txt" "$OUT_DIR/paramspider.txt" && rmdir results 2>/dev/null
        log_success "Paramspider: $(count_lines "$OUT_DIR/paramspider.txt") URLs"
    }

    grep "?" "$OUT_DIR/clean_urls.txt" 2>/dev/null | sort -u > "$OUT_DIR/crawled_params.txt"
    log_success "Crawled params: $(count_lines "$OUT_DIR/crawled_params.txt") URLs"

    if require_tool uro; then
        cat "$OUT_DIR/paramspider.txt" "$OUT_DIR/crawled_params.txt" \
            | uro | sort -u > "$OUT_DIR/final_params.txt"
    else
        cat "$OUT_DIR/paramspider.txt" "$OUT_DIR/crawled_params.txt" \
            | sort -u > "$OUT_DIR/final_params.txt"
    fi
    PARAM_COUNT=$(count_lines "$OUT_DIR/final_params.txt")
    log_success "Unique Parameters: ${BOLD}$PARAM_COUNT${RESET}"
    mark_step_done "$STEP"
fi

# ── SUMMARY ───────────────────────────────
END_TIME=$(date +%s); ELAPSED=$((END_TIME - START_TIME))
ELAPSED_FMT=$(printf "%02d:%02d:%02d" $((ELAPSED/3600)) $((ELAPSED%3600/60)) $((ELAPSED%60)))

echo ""
echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${CYAN}${BOLD}  RECON SUMMARY — $target${RESET}"
echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  ${BOLD}Passive Subdomains :${RESET} $(count_lines "$OUT_DIR/passive_raw.txt")"
echo -e "  ${BOLD}Bruteforce Hits    :${RESET} $(count_lines "$OUT_DIR/brute_subs.txt")"
echo -e "  ${BOLD}Resolved (alive)   :${RESET} $(count_lines "$OUT_DIR/base_resolved.txt")"
echo -e "  ${BOLD}Permutations       :${RESET} $(count_lines "$OUT_DIR/permutations_resolved.txt")"
echo -e "  ${BOLD}Final Subdomains   :${RESET} $(count_lines "$OUT_DIR/final_subdomains.txt")"
echo -e "  ${BOLD}Live Web Servers   :${RESET} $(count_lines "$OUT_DIR/web_alive.txt")"
echo -e "  ${BOLD}Unique URLs        :${RESET} $(count_lines "$OUT_DIR/clean_urls.txt")"
echo -e "  ${BOLD}URLs w/ Params     :${RESET} $(count_lines "$OUT_DIR/final_params.txt")"
echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  ${BOLD}Output Dir  :${RESET} $OUT_DIR"
echo -e "  ${BOLD}Step State  :${RESET} $STEP_STATE_FILE"
echo -e "  ${BOLD}Log File    :${RESET} $LOG_FILE"
echo -e "  ${BOLD}Elapsed     :${RESET} $ELAPSED_FMT"
echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
log_success "Recon complete!"
