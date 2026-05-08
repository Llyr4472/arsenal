#!/bin/bash
# ══════════════════════════════════════════════════════════════
#  recon.sh v5.0 — Smart Recon | Resume | bbq-managed
#
#  Phase 1 : Passive enum (subfinder, assetfinder, crt.sh, OTX,
#             github-subdomains, amass v4 opt-in)
#  Phase 2 : DNS bruteforce (--dns-brute)
#  Phase 3 : Resolve → base_resolved.txt
#  Phase 4 : Permutations (--dns-perms)
#  Phase 5 : HTTP probe pass 1 (httpx on all resolved)
#  Phase 6 : URL discovery (waymore, gau) + JS collection
#             + katana (--crawl)
#  Phase 7 : Parameter extraction
#  Phase 8 : Port scan (naabu, excl default HTTP ports)
#             + HTTP probe pass 2 (httpx on host:port findings)
#             → merged all_web_alive.txt
#
#  Usage: ./recon.sh <domain> [options]
# ══════════════════════════════════════════════════════════════

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
BLUE='\033[0;34m';  CYAN='\033[0;36m';   BOLD='\033[1m'; RESET='\033[0m'

# ── Logging ───────────────────────────────────────────────────
TS()        { date '+%Y-%m-%d %H:%M:%S'; }
log_info()  { echo -e "[$(TS)] ${BLUE}[*]${RESET} $1";   echo "[$(TS)] [INFO]  $1" >> "$LOG_FILE"; }
log_ok()    { echo -e "[$(TS)] ${GREEN}[+]${RESET} $1";  echo "[$(TS)] [OK]    $1" >> "$LOG_FILE"; }
log_warn()  { echo -e "[$(TS)] ${YELLOW}[!]${RESET} $1"; echo "[$(TS)] [WARN]  $1" >> "$LOG_FILE"; }
log_error() { echo -e "[$(TS)] ${RED}[x]${RESET} $1";   echo "[$(TS)] [ERROR] $1" >> "$LOG_FILE"; }
log_phase() {
    local msg="$1"
    echo -e "\n${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${CYAN}${BOLD}  $msg${RESET}"
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo "[$(TS)] [PHASE] === $msg ===" >> "$LOG_FILE"
}

# Runs a command, logs all output to a dedicated per-tool log file.
# Writes one-liner status to main log on completion.
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

# ── Pause/Resume ──────────────────────────────────────────────
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
    echo -e "  ${BOLD}--threads <n>${RESET}          Thread count (default: 50)"
    echo -e "  ${BOLD}--rate-limit <n>${RESET}       DNS rate limit for dnsx (default: 3000)"
    echo -e "  ${BOLD}--wordlist <path>${RESET}      Subdomain wordlist for bruteforce"
    echo -e "  ${BOLD}--fresh${RESET}                Wipe ALL state and restart from scratch"
    echo -e "  ${BOLD}--redo <step>${RESET}          Re-run one specific step (keeps all others)"
    echo ""
    echo "    Steps: passive  bruteforce  resolve  permutations"
    echo "           probing  crawling    params   ports"
    echo ""
    echo -e "  ${BOLD}--amass${RESET}                Enable amass v4 passive enum (slow, use with API keys)"
    echo -e "  ${BOLD}--dns-brute${RESET}            Enable DNS bruteforce"
    echo -e "  ${BOLD}--dns-perms${RESET}            Enable subdomain permutation generation"
    echo -e "  ${BOLD}--crawl${RESET}                Enable katana active crawling (intrusive)"
    echo -e "  ${BOLD}--skip-urls${RESET}            Skip all URL discovery (waymore/gau/katana)"
    echo ""
    echo "  Resume: just re-run — completed phases are skipped automatically."
    exit 1
}

# ── Arg Parsing ───────────────────────────────────────────────
[ "$#" -lt 1 ] && usage
TARGET="$1"; shift

THREADS=50
RATE_LIMIT=3000
FRESH_START=false
DNS_BRUTE=false
DNS_PERMS=false
SKIP_URLS=false
ENABLE_AMASS=false
ENABLE_KATANA=false
REDO_STEPS=()
WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
RESOLVERS="$HOME/resolvers.txt"

# Ports excluded from naabu — already covered by httpx pass 1
NAABU_EXCLUDE="80,443,8080,8443,8000,8001,8008,8888,3000,3001"

# Load secrets (API keys etc) — non-fatal if missing
source "$HOME/.config/secrets.env" 2>/dev/null || true

while [[ $# -gt 0 ]]; do
    case "$1" in
        --threads)     THREADS="$2";        shift 2 ;;
        --wordlist)    WORDLIST="$2";        shift 2 ;;
        --rate-limit)  RATE_LIMIT="$2";      shift 2 ;;
        --fresh)       FRESH_START=true;     shift   ;;
        --redo)        REDO_STEPS+=("$2");   shift 2 ;;
        --amass)       ENABLE_AMASS=true;    shift   ;;
        --dns-brute)   DNS_BRUTE=true;       shift   ;;
        --dns-perms)   DNS_PERMS=true;       shift   ;;
        --crawl)       ENABLE_KATANA=true;   shift   ;;
        --skip-urls)   SKIP_URLS=true;       shift   ;;
        -h|--help)     usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

# ── Setup ─────────────────────────────────────────────────────
OUT_DIR="$HOME/bb/$TARGET"
LOGS_DIR="$OUT_DIR/logs"
STEP_STATE_FILE="$OUT_DIR/.recon_steps"
PAUSE_FILE="$OUT_DIR/.paused"
LOG_FILE="$LOGS_DIR/recon.log"

mkdir -p "$OUT_DIR" "$LOGS_DIR"

echo $$    > "$OUT_DIR/.scan_pid"
ps -o pgid= -p $$ | tr -d ' ' > "$OUT_DIR/.scan_pgid"
echo "running" > "$OUT_DIR/.scan_status"

if [ "$FRESH_START" = "true" ]; then
    > "$LOG_FILE"
fi

echo ""                                                              >> "$LOG_FILE"
echo "[$(TS)] ============================================"          >> "$LOG_FILE"
echo "[$(TS)] [START] recon.sh $TARGET  pid=$$"                     >> "$LOG_FILE"
echo "[$(TS)] [ARGS]  threads=$THREADS rate=$RATE_LIMIT"            >> "$LOG_FILE"
echo "[$(TS)] [FLAGS] fresh=$FRESH_START amass=$ENABLE_AMASS"       >> "$LOG_FILE"
echo "[$(TS)] [FLAGS] brute=$DNS_BRUTE perms=$DNS_PERMS crawl=$ENABLE_KATANA" >> "$LOG_FILE"
echo "[$(TS)] ============================================"          >> "$LOG_FILE"

if [ "$FRESH_START" = "true" ]; then
    log_warn "Fresh start — clearing previous recon state."
    rm -f "$STEP_STATE_FILE"
    rm -f "$OUT_DIR"/*.txt 2>/dev/null
    rm -f "$LOGS_DIR"/*.log 2>/dev/null
fi

# ── Redo specific steps (bug fix: was always force-redoing phase_1_passive) ──
for step in "${REDO_STEPS[@]}"; do
    case "$step" in
        passive)      force_redo_step "phase_1_passive" ;;
        bruteforce)   force_redo_step "phase_2_bruteforce" ;;
        resolve)      force_redo_step "phase_3_resolve" ;;
        permutations) force_redo_step "phase_4_permutations" ;;
        probing)      force_redo_step "phase_5_probing" ;;
        crawling)     force_redo_step "phase_6_crawling" ;;
        params)       force_redo_step "phase_7_params" ;;
        ports)        force_redo_step "phase_8_ports" ;;
        *) log_warn "Unknown step for --redo: $step" ;;
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

    if [ -f "$RESOLVERS" ] && [ "$(count_lines "$RESOLVERS")" -lt 100 ]; then
        log_warn "Resolver file too small ($(count_lines "$RESOLVERS") entries) — refreshing."
        stale=true
    fi

    if $stale; then
        log_info "Refreshing resolver list..."
        local tmp_resolvers
        tmp_resolvers="$(mktemp)"

        local sources=(
            "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
            "https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt"
            "https://raw.githubusercontent.com/proabiral/fresh-resolvers/master/resolvers.txt"
        )

        local fetched=false
        for url in "${sources[@]}"; do
            if curl -s --max-time 30 "$url" -o "$tmp_resolvers" 2>>"$LOGS_DIR/resolver_refresh.log"; then
                local count
                count=$(count_lines "$tmp_resolvers")
                if [ "$count" -ge 100 ]; then
                    mv "$tmp_resolvers" "$RESOLVERS"
                    fetched=true
                    log_ok "Resolvers: $count entries from $url"
                    break
                else
                    log_warn "Source returned only $count resolvers, trying next..."
                fi
            fi
        done

        if ! $fetched; then
            rm -f "$tmp_resolvers"
            log_warn "All resolver sources failed — using fallback resolvers."
            printf '8.8.8.8\n8.8.4.4\n1.1.1.1\n1.0.0.1\n9.9.9.9\n208.67.222.222\n' > "$RESOLVERS"
        fi
    else
        log_info "Resolvers up to date: $(count_lines "$RESOLVERS") entries"
    fi

    log_info "Validating resolvers..."
    local sample_resolvers test_domain working=0
    sample_resolvers="$(mktemp)"
    test_domain="$(mktemp)"
    echo "google.com" > "$test_domain"

    for attempt in 1 2 3; do
        local sample_size=$(( attempt * 100 ))
        shuf -n "$sample_size" "$RESOLVERS" > "$sample_resolvers"
        working=$(dnsx -silent -r "$sample_resolvers" -l "$test_domain" \
            -rl 100 -timeout 10 2>/dev/null | grep -c 'google.com')
        [ "$working" -gt 0 ] && break
        log_warn "Resolver validation attempt $attempt failed, retrying with larger sample..."
        sleep 2
    done

    rm -f "$sample_resolvers" "$test_domain"

    if [ "$working" -eq 0 ]; then
        log_warn "Resolver validation failed — falling back to trusted resolvers."
        local fallback="$OUT_DIR/resolvers_fallback.txt"
        printf '8.8.8.8\n8.8.4.4\n1.1.1.1\n1.0.0.1\n9.9.9.9\n208.67.222.222\n' > "$fallback"
        RESOLVERS="$fallback"
    else
        log_ok "Resolvers validated OK ($(count_lines "$RESOLVERS") available)"
    fi
}

run_dnsx() {
    local input="$1" output="$2" label="${3:-Resolving}"
    log_info "dnsx: $label ($(count_lines "$input") inputs)..."
    run_tool "dnsx_${label// /_}" "dnsx $label" \
        dnsx -l "$input" -silent -o "$output" \
             -r "$RESOLVERS" -t "$THREADS" -rl "$RATE_LIMIT"
}

# ── Start Banner ──────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}Target   :${RESET} $TARGET"
echo -e "  ${BOLD}Output   :${RESET} $OUT_DIR"
echo -e "  ${BOLD}Logs     :${RESET} $LOGS_DIR"
echo -e "  ${BOLD}PID/PGID :${RESET} $$ / $(cat "$OUT_DIR/.scan_pgid")"
echo -e "  ${BOLD}Threads  :${RESET} $THREADS   ${BOLD}Rate:${RESET} $RATE_LIMIT   ${BOLD}Resume:${RESET} $IS_RESUME"
echo -e "  ${BOLD}Flags    :${RESET} amass=$ENABLE_AMASS brute=$DNS_BRUTE perms=$DNS_PERMS crawl=$ENABLE_KATANA"
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

    safe_touch "$OUT_DIR/subfinder.txt"   "$OUT_DIR/assetfinder.txt" \
               "$OUT_DIR/github_subs.txt" "$OUT_DIR/crtsh.txt" \
               "$OUT_DIR/otx.txt"         "$OUT_DIR/amass.txt"

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
    run_tool "crtsh" "crt.sh query $TARGET" \
        bash -c "curl -s --max-time 30 'https://crt.sh/?q=%25.$TARGET&output=json' \
            | grep -oP '\"name_value\":\"\K[^\"]+' \
            | sed 's/\*\.//g' \
            | sort -u > '$OUT_DIR/crtsh.txt'"
    log_ok "crt.sh: $(count_lines "$OUT_DIR/crtsh.txt") subs"

    log_info "Querying AlienVault OTX..."
    run_tool "otx" "AlienVault OTX $TARGET" \
        bash -c "curl -s --max-time 30 \
            'https://otx.alienvault.com/api/v1/indicators/domain/${TARGET}/passive_dns' \
            | grep -oP '\"hostname\":\"\K[^\"]+' \
            | grep -F '.$TARGET' \
            | sort -u > '$OUT_DIR/otx.txt'"
    log_ok "OTX: $(count_lines "$OUT_DIR/otx.txt") subs"
    wait_if_paused

    if require_tool github-subdomains; then
        log_info "Running github-subdomains..."
        run_tool "github_subs" "github-subdomains $TARGET" \
            github-subdomains -d "$TARGET" -o "$OUT_DIR/github_subs.txt"
        log_ok "Github: $(count_lines "$OUT_DIR/github_subs.txt") subs"
    fi
    wait_if_paused

    # amass v4 — opt-in, passive only, hard timeout
    if [ "$ENABLE_AMASS" = "true" ]; then
        if require_tool amass; then
            log_info "Running amass v4 passive (timeout 10min)..."
            run_tool "amass" "amass enum passive $TARGET" \
                timeout 600 amass enum -passive -d "$TARGET" -o "$OUT_DIR/amass.txt"
            local ec=$?
            [ $ec -eq 124 ] && log_warn "Amass timed out after 10min — partial results kept."
            log_ok "Amass: $(count_lines "$OUT_DIR/amass.txt") subs"
        fi
    else
        log_info "Amass skipped — use --amass to enable (recommended with API keys)"
    fi

    cat "$OUT_DIR/subfinder.txt"   "$OUT_DIR/assetfinder.txt" \
        "$OUT_DIR/github_subs.txt" "$OUT_DIR/crtsh.txt" \
        "$OUT_DIR/otx.txt"         "$OUT_DIR/amass.txt" \
        2>/dev/null | sort -u > "$OUT_DIR/passive_raw.txt"
    log_ok "Total passive: ${BOLD}$(count_lines "$OUT_DIR/passive_raw.txt")${RESET} subs"
    mark_step_done "$STEP"
fi

# ══ PHASE 2: DNS Bruteforce ════════════════════════════════════
STEP="phase_2_bruteforce"
if [ "$DNS_BRUTE" = "false" ]; then
    log_phase "Phase 2: DNS Bruteforce [SKIPPED — use --dns-brute]"
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
        run_tool "brute_dnsx" "DNS bruteforce $TARGET" \
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
        log_ok "DNS alive: ${BOLD}$(count_lines "$OUT_DIR/base_resolved.txt")${RESET} / $local_total"
    fi
    mark_step_done "$STEP"
fi

ALIVE_BASE_COUNT=$(count_lines "$OUT_DIR/base_resolved.txt")

# ══ PHASE 4: Permutations ═════════════════════════════════════
STEP="phase_4_permutations"
if [ "$DNS_PERMS" = "false" ]; then
    log_phase "Phase 4: Permutations [SKIPPED — use --dns-perms]"
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
            | dnsx -silent -o "$OUT_DIR/permutations_resolved.txt" \
                   -r "$RESOLVERS" -t "$THREADS" -rl "$RATE_LIMIT" \
            >> "$LOGS_DIR/permutations_dnsx.log" 2>&1
        log_ok "Permutations: ${BOLD}$(count_lines "$OUT_DIR/permutations_resolved.txt")${RESET} new subs"
    fi
    mark_step_done "$STEP"
fi

# Build final subdomain list (used by probing + port scan)
cat "$OUT_DIR/base_resolved.txt" "$OUT_DIR/permutations_resolved.txt" 2>/dev/null \
    | sort -u > "$OUT_DIR/final_subdomains.txt"

# ══ PHASE 5: HTTP Probe Pass 1 ════════════════════════════════
# httpx on all DNS-alive hosts, standard HTTP/HTTPS ports
STEP="phase_5_probing"
if step_done "$STEP"; then
    log_phase "Phase 5: HTTP Probe Pass 1 [DONE — SKIPPED]"
else
    log_phase "Phase 5: HTTP Probe Pass 1 (standard ports)"
    wait_if_paused

    local_total=$(count_lines "$OUT_DIR/final_subdomains.txt")

    if [ "$local_total" -eq 0 ]; then
        log_warn "No subdomains to probe."
        safe_touch "$OUT_DIR/web_alive.txt" "$OUT_DIR/alive_urls_only.txt"
    elif require_tool httpx; then
        log_info "HTTP probing $local_total hosts..."
        run_tool "httpx_pass1" "httpx pass 1 — standard ports" \
            httpx -l "$OUT_DIR/final_subdomains.txt" \
                  -title -tech-detect -status-code -ip -cdn \
                  -follow-redirects \
                  -threads "$THREADS" \
                  -retries 2 \
                  -timeout 10 \
                  -o "$OUT_DIR/web_alive.txt"
        awk '{print $1}' "$OUT_DIR/web_alive.txt" > "$OUT_DIR/alive_urls_only.txt"
        log_ok "Live web (pass 1): ${BOLD}$(count_lines "$OUT_DIR/web_alive.txt")${RESET}"
    else
        safe_touch "$OUT_DIR/web_alive.txt" "$OUT_DIR/alive_urls_only.txt"
    fi
    mark_step_done "$STEP"
fi

# ══ PHASE 6: URL Discovery + JS Collection ════════════════════
STEP="phase_6_crawling"
HTTP_COUNT=$(count_lines "$OUT_DIR/alive_urls_only.txt")

if [ "$SKIP_URLS" = "true" ]; then
    log_phase "Phase 6: URL Discovery [SKIPPED via --skip-urls]"
    safe_touch "$OUT_DIR/clean_urls.txt" "$OUT_DIR/js_urls.txt"
elif step_done "$STEP"; then
    log_phase "Phase 6: URL Discovery + JS Collection [DONE — SKIPPED]"
else
    log_phase "Phase 6: URL Discovery + JS Collection"
    wait_if_paused

    safe_touch "$OUT_DIR/waymore_urls.txt" "$OUT_DIR/gau_urls.txt" \
               "$OUT_DIR/katana.txt"       "$OUT_DIR/js_urls.txt"

    if [ "$HTTP_COUNT" -eq 0 ]; then
        log_warn "No live web servers — skipping URL discovery."
        safe_touch "$OUT_DIR/clean_urls.txt"
    else
        # waymore
        if require_tool waymore; then
            log_info "Running waymore (timeout 5min)..."
            run_tool "waymore" "waymore $TARGET" \
                timeout 300 waymore -i "$TARGET" -mode U -oU "$OUT_DIR/waymore_urls.txt"
            local ec=$?
            [ $ec -eq 124 ] && log_warn "Waymore timed out — partial results kept."
            log_ok "Waymore: $(count_lines "$OUT_DIR/waymore_urls.txt") URLs"
        fi
        wait_if_paused

        # gau
        if require_tool gau; then
            log_info "Running gau..."
            run_tool "gau" "gau $TARGET" \
                bash -c "gau --threads '$THREADS' --subs '$TARGET' \
                    2>/dev/null | sort -u > '$OUT_DIR/gau_urls.txt'"
            log_ok "GAU: $(count_lines "$OUT_DIR/gau_urls.txt") URLs"
        fi
        wait_if_paused

        # katana — opt-in only (intrusive)
        if [ "$ENABLE_KATANA" = "true" ]; then
            if require_tool katana; then
                log_info "Katana active crawl on $HTTP_COUNT endpoints..."
                run_tool "katana" "katana $TARGET" \
                    katana -list "$OUT_DIR/alive_urls_only.txt" \
                           -jc -jsl -kf all \
                           -d 3 -rl 10 -timeout 10 \
                           -concurrency "$THREADS" \
                           -silent \
                           -o "$OUT_DIR/katana.txt"
                log_ok "Katana: $(count_lines "$OUT_DIR/katana.txt") URLs"
            fi
        else
            log_info "Katana skipped — use --crawl to enable (intrusive)"
        fi
        wait_if_paused

        # Deduplicate all discovered URLs
        log_info "Deduplicating URLs..."
        if require_tool uro; then
            cat "$OUT_DIR/waymore_urls.txt" "$OUT_DIR/gau_urls.txt" \
                "$OUT_DIR/katana.txt" 2>/dev/null \
                | uro | sort -u > "$OUT_DIR/clean_urls.txt"
        else
            cat "$OUT_DIR/waymore_urls.txt" "$OUT_DIR/gau_urls.txt" \
                "$OUT_DIR/katana.txt" 2>/dev/null \
                | sort -u > "$OUT_DIR/clean_urls.txt"
        fi
        log_ok "Unique URLs: ${BOLD}$(count_lines "$OUT_DIR/clean_urls.txt")${RESET}"

        # JS collection — aggregate from all URL sources
        log_info "Collecting JS file URLs..."
        safe_touch "$OUT_DIR/js_from_subjs.txt"

        # subjs on live hosts
        if require_tool subjs; then
            run_tool "subjs" "subjs JS discovery" \
                bash -c "subjs -i '$OUT_DIR/alive_urls_only.txt' 2>/dev/null \
                    | sort -u > '$OUT_DIR/js_from_subjs.txt'"
            log_ok "subjs: $(count_lines "$OUT_DIR/js_from_subjs.txt") JS files"
        fi

        # grep .js from all discovered URLs
        grep -iE '\.js(\?.*)?$' "$OUT_DIR/clean_urls.txt" 2>/dev/null \
            | sort -u > "$OUT_DIR/js_from_urls.txt"

        cat "$OUT_DIR/js_from_subjs.txt" "$OUT_DIR/js_from_urls.txt" \
            2>/dev/null | sort -u > "$OUT_DIR/js_urls.txt"
        log_ok "Total JS files: ${BOLD}$(count_lines "$OUT_DIR/js_urls.txt")${RESET}"
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
        run_tool "paramspider" "paramspider $TARGET" \
            bash -c "paramspider -d '$TARGET' --quiet 2>/dev/null; \
                [ -f 'results/$TARGET.txt' ] \
                    && mv 'results/$TARGET.txt' '$OUT_DIR/paramspider.txt'; \
                rmdir results 2>/dev/null; true"
        log_ok "Paramspider: $(count_lines "$OUT_DIR/paramspider.txt") URLs"
    fi

    grep "?" "$OUT_DIR/clean_urls.txt" 2>/dev/null \
        | sort -u > "$OUT_DIR/crawled_params.txt"
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

# ══ PHASE 8: Port Scan + HTTP Probe Pass 2 ════════════════════
# naabu on ALL DNS-alive hosts (not just httpx-alive),
# skipping ports already covered by pass 1.
# httpx pass 2 on naabu host:port findings.
# Merge both httpx outputs → all_web_alive.txt
STEP="phase_8_ports"
if step_done "$STEP"; then
    log_phase "Phase 8: Port Scan + HTTP Probe Pass 2 [DONE — SKIPPED]"
else
    log_phase "Phase 8: Port Scan + HTTP Probe Pass 2"
    wait_if_paused

    safe_touch "$OUT_DIR/naabu_ports.txt" \
               "$OUT_DIR/web_alive_ports.txt" \
               "$OUT_DIR/all_web_alive.txt"

    FINAL_COUNT=$(count_lines "$OUT_DIR/final_subdomains.txt")

    if [ "$FINAL_COUNT" -eq 0 ]; then
        log_warn "No subdomains for port scan."
    elif require_tool naabu; then
        log_info "Port scanning $FINAL_COUNT hosts (top-1000, excl $NAABU_EXCLUDE)..."
        run_tool "naabu" "naabu port scan $TARGET" \
            naabu -list "$OUT_DIR/final_subdomains.txt" \
                  -top-ports 1000 \
                  -exclude-ports "$NAABU_EXCLUDE" \
                  -silent \
                  -o "$OUT_DIR/naabu_ports.txt"
        log_ok "Open non-HTTP ports: ${BOLD}$(count_lines "$OUT_DIR/naabu_ports.txt")${RESET}"

        if [ -s "$OUT_DIR/naabu_ports.txt" ] && require_tool httpx; then
            log_info "HTTP probing $(count_lines "$OUT_DIR/naabu_ports.txt") host:port pairs..."
            run_tool "httpx_pass2" "httpx pass 2 — port findings" \
                httpx -l "$OUT_DIR/naabu_ports.txt" \
                      -title -tech-detect -status-code -ip -cdn \
                      -follow-redirects \
                      -threads "$THREADS" \
                      -retries 2 \
                      -timeout 10 \
                      -o "$OUT_DIR/web_alive_ports.txt"
            log_ok "Live web (port findings): ${BOLD}$(count_lines "$OUT_DIR/web_alive_ports.txt")${RESET}"
        else
            [ ! -s "$OUT_DIR/naabu_ports.txt" ] && log_info "No open non-HTTP ports found — skipping httpx pass 2."
        fi
    fi

    # Merge both httpx outputs into one final live targets file
    cat "$OUT_DIR/web_alive.txt" "$OUT_DIR/web_alive_ports.txt" 2>/dev/null \
        | sort -u > "$OUT_DIR/all_web_alive.txt"
    log_ok "All live web (merged): ${BOLD}$(count_lines "$OUT_DIR/all_web_alive.txt")${RESET}"

    mark_step_done "$STEP"
fi

# ── Summary ───────────────────────────────────────────────────
END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
ELAPSED_FMT=$(printf "%02d:%02d:%02d" \
    $(( ELAPSED/3600 )) $(( ELAPSED%3600/60 )) $(( ELAPSED%60 )))

SUMMARY="
[$(TS)] ============================================
[$(TS)] [SUMMARY] $TARGET
[$(TS)] [SUMMARY] Passive subs:        $(count_lines "$OUT_DIR/passive_raw.txt")
[$(TS)] [SUMMARY] Bruteforce hits:     $(count_lines "$OUT_DIR/brute_subs.txt")
[$(TS)] [SUMMARY] DNS alive:           $(count_lines "$OUT_DIR/base_resolved.txt")
[$(TS)] [SUMMARY] Permutations:        $(count_lines "$OUT_DIR/permutations_resolved.txt")
[$(TS)] [SUMMARY] Final subdomains:    $(count_lines "$OUT_DIR/final_subdomains.txt")
[$(TS)] [SUMMARY] Live web (pass 1):   $(count_lines "$OUT_DIR/web_alive.txt")
[$(TS)] [SUMMARY] Open ports found:    $(count_lines "$OUT_DIR/naabu_ports.txt")
[$(TS)] [SUMMARY] Live web (ports):    $(count_lines "$OUT_DIR/web_alive_ports.txt")
[$(TS)] [SUMMARY] All live web:        $(count_lines "$OUT_DIR/all_web_alive.txt")
[$(TS)] [SUMMARY] Unique URLs:         $(count_lines "$OUT_DIR/clean_urls.txt")
[$(TS)] [SUMMARY] JS files:            $(count_lines "$OUT_DIR/js_urls.txt")
[$(TS)] [SUMMARY] Param URLs:          $(count_lines "$OUT_DIR/final_params.txt")
[$(TS)] [SUMMARY] Elapsed:             $ELAPSED_FMT
[$(TS)] ============================================"
echo "$SUMMARY" >> "$LOG_FILE"

echo ""
echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${CYAN}${BOLD}  RECON SUMMARY — $TARGET${RESET}"
echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
printf "  %-28s %s\n" "Passive subs:"       "$(count_lines "$OUT_DIR/passive_raw.txt")"
printf "  %-28s %s\n" "Bruteforce hits:"    "$(count_lines "$OUT_DIR/brute_subs.txt")"
printf "  %-28s %s\n" "DNS alive:"          "$(count_lines "$OUT_DIR/base_resolved.txt")"
printf "  %-28s %s\n" "Permutations:"       "$(count_lines "$OUT_DIR/permutations_resolved.txt")"
printf "  %-28s %s\n" "Final subdomains:"   "$(count_lines "$OUT_DIR/final_subdomains.txt")"
printf "  %-28s %s\n" "Live web (pass 1):"  "$(count_lines "$OUT_DIR/web_alive.txt")"
printf "  %-28s %s\n" "Open non-HTTP ports:""$(count_lines "$OUT_DIR/naabu_ports.txt")"
printf "  %-28s %s\n" "Live web (ports):"   "$(count_lines "$OUT_DIR/web_alive_ports.txt")"
printf "  %-28s %s\n" "All live web:"       "$(count_lines "$OUT_DIR/all_web_alive.txt")"
printf "  %-28s %s\n" "Unique URLs:"        "$(count_lines "$OUT_DIR/clean_urls.txt")"
printf "  %-28s %s\n" "JS files:"           "$(count_lines "$OUT_DIR/js_urls.txt")"
printf "  %-28s %s\n" "URLs w/ params:"     "$(count_lines "$OUT_DIR/final_params.txt")"
echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  ${BOLD}Output :${RESET} $OUT_DIR"
echo -e "  ${BOLD}Log    :${RESET} $LOG_FILE"
echo -e "  ${BOLD}ToolLog:${RESET} $LOGS_DIR/*.log"
echo -e "  ${BOLD}Elapsed:${RESET} $ELAPSED_FMT"
echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
log_ok "Recon complete!"
