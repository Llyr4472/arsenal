#!/bin/bash
# ==========================================
#  Smart Recon Script (Storage Optimized & Robust)
#  Usage: ./recon.sh domain.com
# ==========================================

# 1. Input Check
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <target-domain> [--resume <phase>]"
    echo ""
    echo "Phases:"
    echo "  1 = Passive Enumeration"
    echo "  2 = Active Bruteforce"
    echo "  3 = Resolving Base List"
    echo "  4 = Smart Permutations"
    echo "  5 = HTTP Probing"
    echo "  6 = URL Discovery & Crawling"
    echo "  7 = Parameter Extraction"
    echo ""
    echo "Examples:"
    echo "  $0 example.com"
    echo "  $0 example.com --resume 5"
    exit 1
fi

target=$1
START_PHASE=1

# Check for resume flag
if [ "$#" -ge 3 ] && [ "$2" == "--resume" ]; then
    START_PHASE=$3
    if ! [[ "$START_PHASE" =~ ^[1-7]$ ]]; then
        echo -e "${RED}[!] Invalid phase number. Must be between 1-7.${RESET}"
        exit 1
    fi
    echo -e "${YELLOW}[+] Resuming from Phase $START_PHASE...${RESET}"
fi

# Progress bar function with current/total
show_progress() {
    local current=$1
    local total=$2
    local width=25
    local percent=$((current * 100 / total))
    local filled=$((percent * width / 100))

    printf "  ["
    printf "%${filled}s" | tr ' ' '█'
    printf "%$((width - filled))s" | tr ' ' '░'
    printf "] ${percent}% (${current}/${total})\r"
}

target=$1
# Use $HOME to be safe with paths
OUT_DIR="$HOME/${target}"
mkdir -p "$OUT_DIR"

# 2. Colors & Vars
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
RESET='\033[0m'
WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

# Check for resume flag
if [ "$#" -ge 3 ] && [ "$2" == "--resume" ]; then
    START_PHASE=$3
    if ! [[ "$START_PHASE" =~ ^[1-7]$ ]]; then
        echo -e "${RED}[!] Invalid phase number. Must be between 1-7.${RESET}"
        exit 1
    fi
    echo -e "${YELLOW}[+] Resuming from Phase $START_PHASE...${RESET}"
else
    START_PHASE=1
fi

echo -e "\n${GREEN}[+] Saving output to: $OUT_DIR${RESET}\n"

# ==========================================
# PHASE 1: Passive Enumeration
# ==========================================
if [ "$START_PHASE" -le 1 ]; then
    echo -e "${YELLOW}[+] Phase 1: Passive Enumeration...${RESET}"
    echo "    -> Running Subfinder..."
    subfinder -d $target -o $OUT_DIR/subfinder.txt -silent > /dev/null 2>&1
    echo -e "${GREEN}[+] Enumerated [$(wc -l < $OUT_DIR/subfinder.txt)] subdomains.${RESET}"

    echo "    -> Running Assetfinder..."
    assetfinder --subs-only $target > $OUT_DIR/assetfinder.txt
    echo -e "${GREEN}[+] Enumerated [$(wc -l < $OUT_DIR/assetfinder.txt)] subdomains.${RESET}"

    echo "    -> Running Amass (Passive)..."
    # Amass often times out or fails, we allow it but don't depend on it
    # amass enum -passive -norecursive -d $target -o $OUT_DIR/amass.txt -silent
    echo -e "${GREEN}[+] Enumerated [$(wc -l < $OUT_DIR/amass.txt)] subdomains.${RESET}"
else
    echo -e "${YELLOW}[+] Phase 1: Passive Enumeration (Skipped)${RESET}"
fi

if [ "$START_PHASE" -le 1 ]; then
    echo "    -> Running Github Subdomains..."
    touch $OUT_DIR/github_subs.txt
    if [ ! -z "$gh_token" ]; then
        github-subdomains -d $target -t "$gh_token" -o $OUT_DIR/github_subs.txt
        echo -e "${GREEN}[+] Enumerated [$(wc -l < $OUT_DIR/github_subs.txt)] subdomains.${RESET}"
    fi

    # Merge all passive sources
    # 2>/dev/null suppresses "No such file" errors if a tool failed
    cat $OUT_DIR/subfinder.txt $OUT_DIR/assetfinder.txt $OUT_DIR/amass.txt $OUT_DIR/github_subs.txt | sort -u > $OUT_DIR/passive_raw.txt

    PASSIVE_COUNT=$(wc -l < $OUT_DIR/passive_raw.txt)
    echo -e "${GREEN}[+] Passive Subdomains Found: $PASSIVE_COUNT${RESET}"

fi

#==========================================
# PHASE 2: Active Bruteforce (Puredns)
# ==========================================
if [ "$START_PHASE" -le 2 ]; then
    echo -e "${YELLOW}[+] Phase 2: Active Bruteforce...${RESET}"

    if [ -f "$WORDLIST" ]; then
        # Using Puredns instead of dnsx
        puredns bruteforce "$WORDLIST" "$target" -w "$OUT_DIR/brute_subs.txt"  -r ~/resolvers.txt --quiet > /dev/null 2>&1

        if [ -f "$OUT_DIR/brute_subs.txt" ]; then
            BRUTE_COUNT=$(wc -l < $OUT_DIR/brute_subs.txt)
        else
            BRUTE_COUNT=0
        fi
        echo -e "${GREEN}[+] Bruteforce Found: $BRUTE_COUNT${RESET}"
    else
        echo -e "${RED}[!] Wordlist not found at $WORDLIST. Skipping bruteforce.${RESET}"
        touch $OUT_DIR/brute_subs.txt
    fi
else
    echo -e "${YELLOW}[+] Phase 2: Active Bruteforce (Skipped)${RESET}"
fi

# ==========================================
# PHASE 3: First Resolution (Puredns)
# ==========================================
if [ "$START_PHASE" -le 3 ]; then
    echo -e "${YELLOW}[+] Phase 3: Resolving Base List...${RESET}"

    cat $OUT_DIR/passive_raw.txt $OUT_DIR/brute_subs.txt | sort -u > $OUT_DIR/all_raw.txt
    TOTAL_TO_RESOLVE=$(wc -l < $OUT_DIR/all_raw.txt)
    echo "    Resolving $TOTAL_TO_RESOLVE domains..."

    # Using Puredns to resolve with progress tracking
    if command -v pv &> /dev/null; then
        pv -N "Resolving" -l $OUT_DIR/all_raw.txt | puredns resolve -w "$OUT_DIR/base_resolved.txt" -r ~/resolvers.txt --quiet > /dev/null 2>&1
    else
        puredns resolve "$OUT_DIR/all_raw.txt" -w "$OUT_DIR/base_resolved.txt" -r ~/resolvers.txt --quiet > /dev/null 2>&1
    fi

    if [ -f "$OUT_DIR/base_resolved.txt" ]; then
        ALIVE_BASE_COUNT=$(wc -l < $OUT_DIR/base_resolved.txt)
    else
        ALIVE_BASE_COUNT=0
    fi
    echo -e "${GREEN}[+] Valid (Alive) Base Subdomains: $ALIVE_BASE_COUNT / $TOTAL_TO_RESOLVE${RESET}"
else
    echo -e "${YELLOW}[+] Phase 3: Resolving Base List (Skipped)${RESET}"
    # Load existing count for subsequent phases
    if [ -f "$OUT_DIR/base_resolved.txt" ]; then
        ALIVE_BASE_COUNT=$(wc -l < $OUT_DIR/base_resolved.txt)
    else
        ALIVE_BASE_COUNT=0
    fi
fi

# ==========================================
# PHASE 4: Smart Permutations
# ==========================================
if [ "$START_PHASE" -le 4 ] && [ "$ALIVE_BASE_COUNT" -gt 0 ] ; then
    echo -e "${YELLOW}[+] Phase 4: Smart Permutations (on $ALIVE_BASE_COUNT domains)...${RESET}"

    # Pipeline: dnsgen -> puredns resolve with progress
    echo "    Generating and resolving permutations..."
    if command -v pv &> /dev/null; then
        dnsgen $OUT_DIR/base_resolved.txt | pv -N "Permutations" -l | puredns resolve -w "$OUT_DIR/permutations_resolved.txt" --quiet --rate-limit 500 -r ~/resolvers.txt > /dev/null 2>&1
    else
        dnsgen $OUT_DIR/base_resolved.txt | puredns resolve -w "$OUT_DIR/permutations_resolved.txt" --quiet --rate-limit 100 -r ~/resolvers.txt > /dev/null 2>&1
    fi

    if [ -f "$OUT_DIR/permutations_resolved.txt" ]; then
        PERM_COUNT=$(wc -l < $OUT_DIR/permutations_resolved.txt)
    else
        PERM_COUNT=0
    fi
    echo -e "${GREEN}[+] New Permutation Subdomains: $PERM_COUNT${RESET}"
else
    if [ "$START_PHASE" -le 4 ]; then
        echo -e "${YELLOW}[!] Phase 4: Smart Permutations (Skipped - No alive domains)${RESET}"
    else
        echo -e "${YELLOW}[+] Phase 4: Smart Permutations (Skipped)${RESET}"
    fi
    touch $OUT_DIR/permutations_resolved.txt
fi

# ==========================================
# PHASE 5: Final Merge & HTTP Probing
# ==========================================
if [ "$START_PHASE" -le 5 ]; then
    echo -e "${YELLOW}[+] Phase 5: Final HTTP Probing...${RESET}"

    # Merge Base Alive + Permutations Alive
    cat $OUT_DIR/base_resolved.txt $OUT_DIR/permutations_resolved.txt  | sort -u > $OUT_DIR/final_subdomains.txt
    TOTAL_TO_PROBE=$(wc -l < $OUT_DIR/final_subdomains.txt)
    echo "    Probing $TOTAL_TO_PROBE subdomains for HTTP/HTTPS..."

    # Port scan all subdomains to find open ports (Silent)
    naabu -list $OUT_DIR/final_subdomains.txt -tp 1000 -silent -o $OUT_DIR/alive.txt

    if [ -f "$OUT_DIR/alive.txt" ]; then
        ALIVE_COUNT=$(wc -l < $OUT_DIR/alive.txt)
    else
        ALIVE_COUNT=0
    fi

    # Check for HTTP/HTTPS with progress
    httpx -l $OUT_DIR/alive.txt \
        -title -tech-detect -status-code -ip -silent \
        -o $OUT_DIR/web_alive.txt

    if [ -f "$OUT_DIR/web_alive.txt" ]; then
        HTTP_COUNT=$(wc -l < $OUT_DIR/web_alive.txt)
    else
        HTTP_COUNT=0
    fi
    echo -e "${GREEN}[+] Alive Web Servers Found: $HTTP_COUNT / $ALIVE_COUNT${RESET}"
else
    echo -e "${YELLOW}[+] Phase 5: Final HTTP Probing (Skipped)${RESET}"
    # Load existing count for subsequent phases
    if [ -f "$OUT_DIR/alive.txt" ]; then
        HTTP_COUNT=$(wc -l < $OUT_DIR/alive.txt)
    else
        HTTP_COUNT=0
    fi
fi

# ==========================================
# PHASE 6: Crawling & URL Discovery
# ==========================================
if [ "$START_PHASE" -le 6 ] && [ "$HTTP_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}[+] Phase 6: URL Discovery...${RESET}"

    # Create a simple list of URLs (http://sub.domain.com) for crawlers
    awk '{print $1}' $OUT_DIR/web_alive.txt > $OUT_DIR/alive_urls_only.txt

    # Waymore (Silent)
    echo "    -> Running Waymore..."
    waymore -i $target -mode U -oU $OUT_DIR/waymore_urls.txt > /dev/null 2>&1

    # Katana (Silent) with progress
    echo "    -> Running Katana (crawling $HTTP_COUNT endpoints)..."
    if command -v pv &> /dev/null; then
        pv -N "Crawling" -l $OUT_DIR/alive_urls_only.txt | katana -jc -d 2 -rl 5 -timeout 10 -silent -o $OUT_DIR/katana.txt > /dev/null 2>&1
    else
        katana -list $OUT_DIR/alive_urls_only.txt -jc -jsl -kf all -rl 5 -timeout 10 -silent -o $OUT_DIR/katana.txt > /dev/null 2>&1
    fi

    # Merge & Clean with URO
    echo "    -> Cleaning URLs..."
    if command -v pv &> /dev/null; then
        cat $OUT_DIR/waymore_urls.txt $OUT_DIR/katana.txt | pv -N "Deduplicating" -l | uro | sort -u > $OUT_DIR/clean_urls.txt
    else
        cat $OUT_DIR/waymore_urls.txt $OUT_DIR/katana.txt  | uro | sort -u > $OUT_DIR/clean_urls.txt
    fi

    if [ -f "$OUT_DIR/clean_urls.txt" ]; then
        URL_COUNT=$(wc -l < $OUT_DIR/clean_urls.txt)
    else
        URL_COUNT=0
    fi
    echo -e "${GREEN}[+] Unique URLs Found: $URL_COUNT${RESET}"
else
    if [ "$START_PHASE" -le 6 ]; then
        echo -e "${RED}[!] Phase 6: URL Discovery (Skipped - No alive web servers)${RESET}"
    else
        echo -e "${YELLOW}[+] Phase 6: URL Discovery (Skipped)${RESET}"
    fi
    touch $OUT_DIR/clean_urls.txt
fi

# ==========================================
# PHASE 7: Parameter Extraction
# ==========================================
if [ "$START_PHASE" -le 7 ]; then
    echo -e "${YELLOW}[+] Phase 7: Parameter Extraction...${RESET}"

    # Paramspider
    paramspider -d $target --quiet > /dev/null 2>&1
    # Move paramspider results if they exist
    if [ -f "results/$target.txt" ]; then
        mv "results/$target.txt" "$OUT_DIR/paramspider.txt"
    else
        touch $OUT_DIR/paramspider.txt
    fi

    # Grep from Crawled URLs
    grep "?" $OUT_DIR/clean_urls.txt > $OUT_DIR/crawled_params.txt

    # Merge
    cat $OUT_DIR/paramspider.txt $OUT_DIR/crawled_params.txt  | uro | sort -u > $OUT_DIR/final_params.txt

    if [ -f "$OUT_DIR/final_params.txt" ]; then
        PARAM_COUNT=$(wc -l < $OUT_DIR/final_params.txt)
    else
        PARAM_COUNT=0
    fi
    echo -e "${GREEN}[+] Unique Parameters Found: $PARAM_COUNT${RESET}"
else
    echo -e "${YELLOW}[+] Phase 7: Parameter Extraction (Skipped)${RESET}"
fi

echo -e "\n${GREEN}[DONE] Recon complete! Output saved to: $OUT_DIR${RESET}"
