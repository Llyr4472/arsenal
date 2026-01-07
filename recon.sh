#!/bin/bash
# ==========================================
#  Subdomain Enumeration and Recon Script
#  Usage: ./recon.sh domain.com
# ==========================================

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target-domain>"
    exit 1
fi

target=$1
# Fix: Use $HOME instead of ~ inside quotes
OUT_DIR="$HOME/${target}"
mkdir -p "$OUT_DIR"

# Colors for status output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RESET='\033[0m'

echo -e "\n${GREEN}[+] Saving output to: $OUT_DIR${RESET}\n"

# 1. Passive Enumeration
echo -e "${YELLOW}[+] Starting Passive Enum...${RESET}"

# Amass: -silent suppresses logs, > /dev/null hides the domain flood, -o saves the data
echo "    -> Running Amass..."
amass enum -passive -norecursive -d $target -o $OUT_DIR/amass.txt -silent > /dev/null 2>&1

# Subfinder: -silent hides the flood
echo "    -> Running Subfinder..."
subfinder -all -recursive -d $target -o $OUT_DIR/subfinder.txt -silent

# Assetfinder: already silent via redirection
echo "    -> Running Assetfinder..."
assetfinder --subs-only $target > $OUT_DIR/assetfinder.txt

# Github dorking
echo "    -> Running Github Subdomains..."
touch $OUT_DIR/github_subs.txt
# Redirecting to /dev/null so tokens/errors don't leak to screen
github-subdomains -d $target -t "$gh_token" -o $OUT_DIR/github_subs.txt > /dev/null 2>&1

# Merge Passive
cat $OUT_DIR/amass.txt $OUT_DIR/subfinder.txt $OUT_DIR/assetfinder.txt $OUT_DIR/github_subs.txt 2>/dev/null | sort -u > $OUT_DIR/passive_subs.txt
echo -e "${GREEN}[+] Passive complete. Unique subdomains found: $(wc -l < $OUT_DIR/passive_subs.txt)${RESET}"

# 2. Active Bruteforce
echo -e "${YELLOW}[+] Starting Bruteforce...${RESET}"
WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

if [ -f "$WORDLIST" ]; then
    # dnsx -silent ensures clean output
    dnsx -d $target -w $WORDLIST -silent -o $OUT_DIR/brute_subs.txt
    echo -e "${GREEN}[+] Bruteforce complete. Found: $(wc -l < $OUT_DIR/brute_subs.txt)${RESET}"
else
    echo "[-] Wordlist not found. Skipping bruteforce."
    touch $OUT_DIR/brute_subs.txt
fi

# 3. Permutations 
echo -e "${YELLOW}[+] Generating Permutations...${RESET}"
cat $OUT_DIR/passive_subs.txt $OUT_DIR/brute_subs.txt | sort -u > $OUT_DIR/all_subs_so_far.txt

if [ -s "$OUT_DIR/all_subs_so_far.txt" ]; then
    # Redirect dnsgen stderr to null to hide "generating..." logs if any
    dnsgen $OUT_DIR/all_subs_so_far.txt 2>/dev/null | dnsx -silent -o $OUT_DIR/permutations.txt
    echo -e "${GREEN}[+] Permutations complete. Found: $(wc -l < $OUT_DIR/permutations.txt)${RESET}"
else
    touch $OUT_DIR/permutations.txt
fi

# 4. Final DNS Resolution & Merging
cat $OUT_DIR/passive_subs.txt $OUT_DIR/brute_subs.txt $OUT_DIR/permutations.txt | sort -u | dnsx -silent > $OUT_DIR/final_resolvable_subdomains.txt
echo -e "${GREEN}[+] Final Resolvable Subdomains: $(wc -l < $OUT_DIR/final_resolvable_subdomains.txt)${RESET}"

echo -e "${YELLOW}[+] Probing HTTP/S on standard and non-standard ports...${RESET}"

# Option A: Fast (80, 443, 8000, 8080, 8443)
httpx -l $OUT_DIR/final_resolvable_subdomains.txt -ports 80,443,8000,8080,8443 -title -tech-detect -status-code -ip -silent -o $OUT_DIR/alive.txt
echo -e "${GREEN}[+] Alive Web Servers: $(wc -l < $OUT_DIR/alive.txt)${RESET}"

# --- Step 3: Endpoint Discovery ---

# Clean the list to just URLs for the tools
awk '{print $1}' $OUT_DIR/alive.txt > $OUT_DIR/alive_urls_only.txt

echo -e "${YELLOW}[+] Mining Archives (Waymore)...${RESET}"
# Redirecting Waymore output to /dev/null because it's very chatty
waymore -i $target -mode U -oU $OUT_DIR/waymore_urls.txt > /dev/null 2>&1
echo -e "${GREEN}[+] Waymore URLs found: $(wc -l < $OUT_DIR/waymore_urls.txt)${RESET}"

echo -e "${YELLOW}[+] Crawling (Katana)...${RESET}"
katana -list $OUT_DIR/alive_urls_only.txt -jc -d 2 -rl 5 -timeout 10 -silent -o $OUT_DIR/katana.txt
echo -e "${GREEN}[+] Katana URLs found: $(wc -l < $OUT_DIR/katana.txt)${RESET}"

echo "[+] Merging & Cleaning..."
# Fix: Handle cases where files might be empty
cat $OUT_DIR/waymore_urls.txt $OUT_DIR/katana.txt 2>/dev/null | uro | sort -u > $OUT_DIR/clean_urls.txt
echo -e "${GREEN}[+] Total Unique URLs: $(wc -l < $OUT_DIR/clean_urls.txt)${RESET}"


# --- Step 4: Parameter Discovery ---

echo -e "${YELLOW}[+] Extracting Params...${RESET}"

# 1. From Archives
# Added --quiet and redirect just in case
paramspider -d $target --quiet > /dev/null 2>&1

# Paramspider usually saves to results/domain.txt. Let's move it if -o fails
if [ -f "results/$target.txt" ]; then
    mv "results/$target.txt" "$OUT_DIR/paramspider.txt"
fi

# 2. Extract from crawled URLs
grep "?" $OUT_DIR/clean_urls.txt > $OUT_DIR/crawled_params.txt

# 3. Merge
cat $OUT_DIR/paramspider.txt $OUT_DIR/crawled_params.txt 2>/dev/null | uro | sort -u > $OUT_DIR/final_params.txt

echo -e "${GREEN}[+] Recon Complete. Parameters found: $(wc -l < $OUT_DIR/final_params.txt)${RESET}"
echo -e "${GREEN}[+] All data saved in $OUT_DIR${RESET}"