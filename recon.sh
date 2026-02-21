#!/bin/bash
# ==========================================
#  Smart Recon Script v2.0
#  Author: Llyr4472
#  Usage: ./recon.sh <domain> [--resume <phase>]
# ==========================================

# ==========================================
# COLORS & FORMATTING
# ==========================================
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ==========================================
# BANNER
# ==========================================
print_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗"
    echo "  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║"
    echo "  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║"
    echo "  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║"
    echo "  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║"
    echo "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝  v2.0"
    echo -e "${RESET}"
}

# ==========================================
# HELPERS
# ==========================================
log_info()    { echo -e "${BLUE}[*]${RESET} $1"; }
log_success() { echo -e "${GREEN}[+]${RESET} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
log_error()   { echo -e "${RED}[✗]${RESET} $1"; }
log_phase()   { echo -e "\n${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; echo -e "${CYAN}${BOLD}  $1${RESET}"; echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; }

count_lines() {
    local file="$1"
    if [ -f "$file" ]; then
        wc -l < "$file"
    else
        echo 0
    fi
}

safe_touch() {
    for f in "$@"; do
        [ -f "$f" ] || touch "$f"
    done
}

# Check if a tool exists
require_tool() {
    if ! command -v "$1" &> /dev/null; then
        log_warn "Tool not found: ${BOLD}$1${RESET} — skipping related step."
        return 1
    fi
    return 0
}

# ==========================================
# USAGE
# ==========================================
usage() {
    echo -e "${BOLD}Usage:${RESET} $0 <target-domain> [--resume <phase>] [--threads <n>] [--wordlist <path>] [--rate-limit <n>]"
    echo ""
    echo -e "${BOLD}Phases:${RESET}"
    echo "  1 = Passive Enumeration"
    echo "  2 = Active Bruteforce"
    echo "  3 = Resolve Base List"
    echo "  4 = Smart Permutations"
    echo "  5 = HTTP Probing & Port Scan"
    echo "  6 = URL Discovery & Crawling"
    echo "  7 = Parameter Extraction"
    echo ""
    echo -e "${BOLD}Options:${RESET}"
    echo "  --resume     <phase>   Resume from a specific phase (1-7)"
    echo "  --threads    <n>       Number of threads (default: 50)"
    echo "  --wordlist   <path>    Custom wordlist path"
    echo "  --rate-limit <n>       DNS rate limit (default: 3000)"
    echo "  --no-pv                Disable pv progress bars even if installed"
    echo ""
    echo -e "${BOLD}Examples:${RESET}"
    echo "  $0 example.com"
    echo "  $0 example.com --resume 3"
    echo "  $0 example.com --threads 100 --rate-limit 5000"
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

START_PHASE=1
THREADS=50
RATE_LIMIT=3000
USE_PV=true
WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
RESOLVERS="$HOME/resolvers.txt"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --resume)      START_PHASE="$2"; shift 2 ;;
        --threads)     THREADS="$2"; shift 2 ;;
        --wordlist)    WORDLIST="$2"; shift 2 ;;
        --rate-limit)  RATE_LIMIT="$2"; shift 2 ;;
        --no-pv)       USE_PV=false; shift ;;
        -h|--help)     usage ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
done

# Validate phase
if ! [[ "$START_PHASE" =~ ^[1-7]$ ]]; then
    log_error "Invalid phase number. Must be between 1-7."
    exit 1
fi

# ==========================================
# SETUP
# ==========================================
OUT_DIR="$HOME/bb/${target}"
mkdir -p "$OUT_DIR"
LOG_FILE="$OUT_DIR/recon.log"

# Redirect all output also to log file
exec > >(tee -a "$LOG_FILE") 2>&1

# Check pv availability
HAS_PV=false
if $USE_PV && command -v pv &> /dev/null; then
    HAS_PV=true
fi

# Auto-download resolvers if missing or older than 7 days
refresh_resolvers() {
    local needs_refresh=false
    if [ ! -f "$RESOLVERS" ]; then
        needs_refresh=true
    elif [ "$(find "$RESOLVERS" -mtime +7 2>/dev/null)" ]; then
        needs_refresh=true
    fi

    if $needs_refresh; then
        log_info "Downloading fresh resolver list from trickest..."
        if command -v wget &> /dev/null; then
            wget -q "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" -O "$RESOLVERS"
        elif command -v curl &> /dev/null; then
            curl -s "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" -o "$RESOLVERS"
        else
            log_warn "wget/curl not found. Cannot auto-refresh resolvers."
        fi
        if [ -f "$RESOLVERS" ]; then
            log_success "Resolvers updated: $(count_lines "$RESOLVERS") entries"
        fi
    fi
}

# dnsx wrapper: resolves a list and writes valid results to output file
# Usage: run_dnsx_resolve <input_file> <output_file> [label]
run_dnsx_resolve() {
    local input="$1"
    local output="$2"
    local label="${3:-Resolving}"

    if $HAS_PV; then
        pv -N "$label" -l "$input" | dnsx -silent -o "$output" -r "$RESOLVERS" -t "$THREADS" -rl "$RATE_LIMIT"
    else
        dnsx -l "$input" -silent -o "$output" -r "$RESOLVERS" -t "$THREADS" -rl "$RATE_LIMIT"
    fi
}

# ==========================================
# START
# ==========================================
print_banner
echo -e "${BOLD}Target   :${RESET} $target"
echo -e "${BOLD}Output   :${RESET} $OUT_DIR"
echo -e "${BOLD}Threads  :${RESET} $THREADS"
echo -e "${BOLD}RateLimit:${RESET} $RATE_LIMIT"
echo -e "${BOLD}Wordlist :${RESET} $WORDLIST"
echo -e "${BOLD}Phase    :${RESET} Starting from phase $START_PHASE"
echo -e "${BOLD}Log      :${RESET} $LOG_FILE"
echo ""

START_TIME=$(date +%s)
refresh_resolvers

# ==========================================
# PHASE 1: Passive Enumeration
# ==========================================
if [ "$START_PHASE" -le 1 ]; then
    log_phase "Phase 1: Passive Enumeration"

    safe_touch "$OUT_DIR/subfinder.txt" "$OUT_DIR/assetfinder.txt" \
               "$OUT_DIR/amass.txt" "$OUT_DIR/github_subs.txt" \
               "$OUT_DIR/crtsh.txt"

    # Subfinder
    if require_tool subfinder; then
        log_info "Running Subfinder..."
        subfinder -d "$target" -o "$OUT_DIR/subfinder.txt" -silent -t "$THREADS" 2>/dev/null
        log_success "Subfinder: $(count_lines "$OUT_DIR/subfinder.txt") subdomains"
    fi

    # Assetfinder
    if require_tool assetfinder; then
        log_info "Running Assetfinder..."
        assetfinder --subs-only "$target" > "$OUT_DIR/assetfinder.txt" 2>/dev/null
        log_success "Assetfinder: $(count_lines "$OUT_DIR/assetfinder.txt") subdomains"
    fi

    # crt.sh (no tool needed, just curl)
    if command -v curl &> /dev/null; then
        log_info "Querying crt.sh..."
        curl -s "https://crt.sh/?q=%25.$target&output=json" 2>/dev/null \
            | grep -oP '"name_value":"\K[^"]+' \
            | sed 's/\*\.//g' \
            | sort -u > "$OUT_DIR/crtsh.txt"
        log_success "crt.sh: $(count_lines "$OUT_DIR/crtsh.txt") subdomains"
    fi

    # GitHub Subdomains
    if require_tool github-subdomains; then
        if [ -n "$gh_token" ]; then
            log_info "Running Github Subdomains..."
            github-subdomains -d "$target" -t "$gh_token" -o "$OUT_DIR/github_subs.txt" 2>/dev/null
            log_success "Github: $(count_lines "$OUT_DIR/github_subs.txt") subdomains"
        else
            log_warn "gh_token not set — skipping github-subdomains. Export it with: export gh_token=YOUR_TOKEN"
        fi
    fi

    # Amass (optional, commented — uncomment if you use it)
    # if require_tool amass; then
    #     log_info "Running Amass (passive)..."
    #     amass enum -passive -norecursive -d "$target" -o "$OUT_DIR/amass.txt" -silent 2>/dev/null
    #     log_success "Amass: $(count_lines "$OUT_DIR/amass.txt") subdomains"
    # fi

    # Merge all passive sources
    cat "$OUT_DIR/subfinder.txt" \
        "$OUT_DIR/assetfinder.txt" \
        "$OUT_DIR/amass.txt" \
        "$OUT_DIR/github_subs.txt" \
        "$OUT_DIR/crtsh.txt" \
        2>/dev/null | sort -u > "$OUT_DIR/passive_raw.txt"

    PASSIVE_COUNT=$(count_lines "$OUT_DIR/passive_raw.txt")
    log_success "Total Passive Subdomains: ${BOLD}$PASSIVE_COUNT${RESET}"
else
    log_phase "Phase 1: Passive Enumeration (Skipped)"
    safe_touch "$OUT_DIR/passive_raw.txt"
fi

# ==========================================
# PHASE 2: Active Bruteforce (dnsx)
# ==========================================
if [ "$START_PHASE" -le 2 ]; then
    log_phase "Phase 2: Active Bruteforce"

    safe_touch "$OUT_DIR/brute_subs.txt"

    if [ ! -f "$WORDLIST" ]; then
        log_error "Wordlist not found: $WORDLIST — skipping bruteforce."
    elif ! require_tool dnsx; then
        log_error "dnsx not found — skipping bruteforce."
    else
        log_info "Bruteforcing with wordlist: $WORDLIST ($(count_lines "$WORDLIST") words)"

        # Generate subdomain candidates then resolve
        if $HAS_PV; then
            awk -v domain="$target" '{print $1"."domain}' "$WORDLIST" \
                | pv -N "Bruteforcing" -l \
                | dnsx -silent -o "$OUT_DIR/brute_subs.txt" -r "$RESOLVERS" -t "$THREADS" -rl "$RATE_LIMIT"
        else
            awk -v domain="$target" '{print $1"."domain}' "$WORDLIST" \
                | dnsx -silent -o "$OUT_DIR/brute_subs.txt" -r "$RESOLVERS" -t "$THREADS" -rl "$RATE_LIMIT"
        fi

        BRUTE_COUNT=$(count_lines "$OUT_DIR/brute_subs.txt")
        log_success "Bruteforce Found: ${BOLD}$BRUTE_COUNT${RESET} subdomains"
    fi
else
    log_phase "Phase 2: Active Bruteforce (Skipped)"
    safe_touch "$OUT_DIR/brute_subs.txt"
fi

# ==========================================
# PHASE 3: Resolve Base List (dnsx)
# ==========================================
if [ "$START_PHASE" -le 3 ]; then
    log_phase "Phase 3: Resolving Base List"

    cat "$OUT_DIR/passive_raw.txt" "$OUT_DIR/brute_subs.txt" 2>/dev/null \
        | sort -u > "$OUT_DIR/all_raw.txt"

    TOTAL_TO_RESOLVE=$(count_lines "$OUT_DIR/all_raw.txt")

    if [ "$TOTAL_TO_RESOLVE" -eq 0 ]; then
        log_warn "No domains to resolve. Did previous phases produce output?"
        safe_touch "$OUT_DIR/base_resolved.txt"
        ALIVE_BASE_COUNT=0
    else
        log_info "Resolving ${BOLD}$TOTAL_TO_RESOLVE${RESET} domains..."
        run_dnsx_resolve "$OUT_DIR/all_raw.txt" "$OUT_DIR/base_resolved.txt" "Resolving"

        ALIVE_BASE_COUNT=$(count_lines "$OUT_DIR/base_resolved.txt")
        log_success "Alive Subdomains: ${BOLD}$ALIVE_BASE_COUNT${RESET} / $TOTAL_TO_RESOLVE"
    fi
else
    log_phase "Phase 3: Resolving Base List (Skipped)"
    safe_touch "$OUT_DIR/base_resolved.txt"
    ALIVE_BASE_COUNT=$(count_lines "$OUT_DIR/base_resolved.txt")
fi

# ==========================================
# PHASE 4: Smart Permutations (dnsgen + dnsx)
# ==========================================
if [ "$START_PHASE" -le 4 ]; then
    log_phase "Phase 4: Smart Permutations"

    safe_touch "$OUT_DIR/permutations_resolved.txt"

    if [ "$ALIVE_BASE_COUNT" -eq 0 ]; then
        log_warn "No alive domains from Phase 3 — skipping permutations."
    elif ! require_tool dnsgen; then
        log_warn "dnsgen not found — skipping permutations."
    else
        log_info "Generating permutations from $ALIVE_BASE_COUNT domains..."

        if $HAS_PV; then
            dnsgen "$OUT_DIR/base_resolved.txt" \
                | pv -N "Permutations" -l \
                | dnsx -silent -o "$OUT_DIR/permutations_resolved.txt" \
                       -r "$RESOLVERS" -t "$THREADS" -rl "$RATE_LIMIT"
        else
            dnsgen "$OUT_DIR/base_resolved.txt" \
                | dnsx -silent -o "$OUT_DIR/permutations_resolved.txt" \
                       -r "$RESOLVERS" -t "$THREADS" -rl "$RATE_LIMIT"
        fi

        PERM_COUNT=$(count_lines "$OUT_DIR/permutations_resolved.txt")
        log_success "Permutations Found: ${BOLD}$PERM_COUNT${RESET} new subdomains"
    fi
else
    log_phase "Phase 4: Smart Permutations (Skipped)"
    safe_touch "$OUT_DIR/permutations_resolved.txt"
fi

# ==========================================
# PHASE 5: Port Scan & HTTP Probing
# ==========================================
if [ "$START_PHASE" -le 5 ]; then
    log_phase "Phase 5: Port Scan & HTTP Probing"

    # Final merge of all discovered & resolved subdomains
    cat "$OUT_DIR/base_resolved.txt" "$OUT_DIR/permutations_resolved.txt" 2>/dev/null \
        | sort -u > "$OUT_DIR/final_subdomains.txt"

    TOTAL_TO_PROBE=$(count_lines "$OUT_DIR/final_subdomains.txt")

    if [ "$TOTAL_TO_PROBE" -eq 0 ]; then
        log_warn "No subdomains to probe. Skipping."
        safe_touch "$OUT_DIR/alive.txt" "$OUT_DIR/web_alive.txt"
        HTTP_COUNT=0
    else
        log_info "Port scanning ${BOLD}$TOTAL_TO_PROBE${RESET} subdomains..."

        if require_tool naabu; then
            naabu -list "$OUT_DIR/final_subdomains.txt" \
                  -top-ports 1000 \
                  -silent \
                  -o "$OUT_DIR/alive.txt" 2>/dev/null
        else
            # Fallback: just use subdomains as-is for httpx
            cp "$OUT_DIR/final_subdomains.txt" "$OUT_DIR/alive.txt"
        fi

        ALIVE_COUNT=$(count_lines "$OUT_DIR/alive.txt")
        log_success "Open Ports Found: ${BOLD}$ALIVE_COUNT${RESET}"

        if require_tool httpx; then
            log_info "HTTP probing ${BOLD}$ALIVE_COUNT${RESET} hosts..."
            httpx -l "$OUT_DIR/alive.txt" \
                  -title \
                  -tech-detect \
                  -status-code \
                  -ip \
                  -cdn \
                  -follow-redirects \
                  -threads "$THREADS" \
                  -silent \
                  -o "$OUT_DIR/web_alive.txt" 2>/dev/null

            HTTP_COUNT=$(count_lines "$OUT_DIR/web_alive.txt")
            log_success "Live Web Servers: ${BOLD}$HTTP_COUNT${RESET} / $ALIVE_COUNT"

            # Extract just the URLs for downstream use
            awk '{print $1}' "$OUT_DIR/web_alive.txt" > "$OUT_DIR/alive_urls_only.txt"
        else
            safe_touch "$OUT_DIR/web_alive.txt" "$OUT_DIR/alive_urls_only.txt"
            HTTP_COUNT=0
        fi
    fi
else
    log_phase "Phase 5: Port Scan & HTTP Probing (Skipped)"
    safe_touch "$OUT_DIR/web_alive.txt" "$OUT_DIR/alive_urls_only.txt"
    HTTP_COUNT=$(count_lines "$OUT_DIR/web_alive.txt")
fi

# ==========================================
# PHASE 6: URL Discovery & Crawling
# ==========================================
if [ "$START_PHASE" -le 6 ]; then
    log_phase "Phase 6: URL Discovery & Crawling"

    safe_touch "$OUT_DIR/waymore_urls.txt" "$OUT_DIR/katana.txt" "$OUT_DIR/gau_urls.txt"

    if [ "$HTTP_COUNT" -eq 0 ]; then
        log_warn "No live web servers found — skipping crawling."
        safe_touch "$OUT_DIR/clean_urls.txt"
        URL_COUNT=0
    else
        # Waymore
        if require_tool waymore; then
            log_info "Running Waymore..."
            waymore -i "$target" -mode U -oU "$OUT_DIR/waymore_urls.txt" 2>/dev/null
            log_success "Waymore: $(count_lines "$OUT_DIR/waymore_urls.txt") URLs"
        fi

        # GAU (alternative passive URL source)
        if require_tool gau; then
            log_info "Running GAU..."
            gau --threads "$THREADS" --subs "$target" 2>/dev/null | sort -u > "$OUT_DIR/gau_urls.txt"
            log_success "GAU: $(count_lines "$OUT_DIR/gau_urls.txt") URLs"
        fi

        # Katana
        if require_tool katana; then
            log_info "Crawling ${BOLD}$HTTP_COUNT${RESET} endpoints with Katana..."
            if $HAS_PV; then
                pv -N "Crawling" -l "$OUT_DIR/alive_urls_only.txt" \
                    | katana -jc -jsl -kf all -d 3 -rl 10 -timeout 10 -concurrency "$THREADS" -silent \
                    -o "$OUT_DIR/katana.txt" 2>/dev/null
            else
                katana -list "$OUT_DIR/alive_urls_only.txt" \
                       -jc -jsl -kf all -d 3 -rl 10 -timeout 10 -concurrency "$THREADS" -silent \
                       -o "$OUT_DIR/katana.txt" 2>/dev/null
            fi
            log_success "Katana: $(count_lines "$OUT_DIR/katana.txt") URLs"
        fi

        # Merge & deduplicate with uro
        log_info "Deduplicating and cleaning URLs..."
        if require_tool uro; then
            if $HAS_PV; then
                cat "$OUT_DIR/waymore_urls.txt" \
                    "$OUT_DIR/gau_urls.txt" \
                    "$OUT_DIR/katana.txt" \
                    | pv -N "Deduplicating" -l \
                    | uro | sort -u > "$OUT_DIR/clean_urls.txt"
            else
                cat "$OUT_DIR/waymore_urls.txt" \
                    "$OUT_DIR/gau_urls.txt" \
                    "$OUT_DIR/katana.txt" \
                    | uro | sort -u > "$OUT_DIR/clean_urls.txt"
            fi
        else
            cat "$OUT_DIR/waymore_urls.txt" \
                "$OUT_DIR/gau_urls.txt" \
                "$OUT_DIR/katana.txt" \
                | sort -u > "$OUT_DIR/clean_urls.txt"
        fi

        URL_COUNT=$(count_lines "$OUT_DIR/clean_urls.txt")
        log_success "Unique URLs Found: ${BOLD}$URL_COUNT${RESET}"
    fi
else
    log_phase "Phase 6: URL Discovery & Crawling (Skipped)"
    safe_touch "$OUT_DIR/clean_urls.txt"
    URL_COUNT=$(count_lines "$OUT_DIR/clean_urls.txt")
fi

# ==========================================
# PHASE 7: Parameter Extraction
# ==========================================
if [ "$START_PHASE" -le 7 ]; then
    log_phase "Phase 7: Parameter Extraction"

    safe_touch "$OUT_DIR/paramspider.txt" "$OUT_DIR/crawled_params.txt"

    # Paramspider
    if require_tool paramspider; then
        log_info "Running Paramspider..."
        paramspider -d "$target" --quiet 2>/dev/null
        if [ -f "results/$target.txt" ]; then
            mv "results/$target.txt" "$OUT_DIR/paramspider.txt"
            # Cleanup empty results dir
            rmdir results 2>/dev/null
        fi
        log_success "Paramspider: $(count_lines "$OUT_DIR/paramspider.txt") URLs"
    fi

    # Extract URLs with parameters from crawled results
    grep "?" "$OUT_DIR/clean_urls.txt" 2>/dev/null | sort -u > "$OUT_DIR/crawled_params.txt"
    log_success "Crawled Params: $(count_lines "$OUT_DIR/crawled_params.txt") URLs"

    # Merge & deduplicate
    if require_tool uro; then
        cat "$OUT_DIR/paramspider.txt" "$OUT_DIR/crawled_params.txt" \
            | uro | sort -u > "$OUT_DIR/final_params.txt"
    else
        cat "$OUT_DIR/paramspider.txt" "$OUT_DIR/crawled_params.txt" \
            | sort -u > "$OUT_DIR/final_params.txt"
    fi

    PARAM_COUNT=$(count_lines "$OUT_DIR/final_params.txt")
    log_success "Unique Parameters Found: ${BOLD}$PARAM_COUNT${RESET}"
else
    log_phase "Phase 7: Parameter Extraction (Skipped)"
    PARAM_COUNT=$(count_lines "$OUT_DIR/final_params.txt")
fi

# ==========================================
# SUMMARY
# ==========================================
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
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
echo -e "  ${BOLD}Output Directory   :${RESET} $OUT_DIR"
echo -e "  ${BOLD}Log File           :${RESET} $LOG_FILE"
echo -e "  ${BOLD}Time Elapsed       :${RESET} $ELAPSED_FMT"
echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
log_success "Recon complete!"