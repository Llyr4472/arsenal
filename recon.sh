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

echo -e "\n[+] Saving output to: $OUT_DIR\n"

# 1. Passive Enumeration
echo "[+] Starting Passive Enum..."
amass enum -passive -norecursive -d $target -o $OUT_DIR/amass.txt
subfinder -all -recursive -d $target -o $OUT_DIR/subfinder.txt
assetfinder --subs-only $target > $OUT_DIR/assetfinder.txt

# Github dorking
touch $OUT_DIR/github_subs.txt
github-subdomains -d $target -t $gh_token -o $OUT_DIR/github_subs.txt
# Merge Passive
cat $OUT_DIR/amass.txt $OUT_DIR/subfinder.txt $OUT_DIR/assetfinder.txt $OUT_DIR/github_subs.txt 2>/dev/null | sort -u > $OUT_DIR/passive_subs.txt

# 2. Active Bruteforce
echo "[+] Starting Bruteforce..."
# Ensure the wordlist exists, or default to a smaller one/skip
WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
if [ -f "$WORDLIST" ]; then
    dnsx -d $target -w $WORDLIST -silent -o $OUT_DIR/brute_subs.txt
else
    echo "[-] Wordlist not found at $WORDLIST. Skipping bruteforce."
    touch $OUT_DIR/brute_subs.txt
fi

# 3. Permutations 
echo "[+] Generating Permutations..."
cat $OUT_DIR/passive_subs.txt $OUT_DIR/brute_subs.txt | sort -u > $OUT_DIR/all_subs_so_far.txt

if [ -s "$OUT_DIR/all_subs_so_far.txt" ]; then
    dnsgen $OUT_DIR/all_subs_so_far.txt | dnsx -silent -o $OUT_DIR/permutations.txt
else
    touch $OUT_DIR/permutations.txt
fi

# 4. Final DNS Resolution & Merging
cat $OUT_DIR/passive_subs.txt $OUT_DIR/brute_subs.txt $OUT_DIR/permutations.txt | sort -u | dnsx -silent > $OUT_DIR/final_resolvable_subdomains.txt

echo "[+] Probing HTTP/S on standard and non-standard ports..."

# Option A: Fast (80, 443, 8000, 8080, 8443)
httpx -l $OUT_DIR/final_resolvable_subdomains.txt -ports 80,443,8000,8080,8443 -title -tech-detect -status-code -ip -silent -o $OUT_DIR/alive.txt

# --- Step 3: Endpoint Discovery ---

# Clean the list to just URLs for the tools
awk '{print $1}' $OUT_DIR/alive.txt > $OUT_DIR/alive_urls_only.txt

echo "[+] Mining Archives..."
# Note: Waymore requires config setup usually, ensure it's working
waymore -i $target -mode U -oU $OUT_DIR/waymore_urls.txt

echo "[+] Crawling..."
katana -list $OUT_DIR/alive_urls_only.txt -jc -d 2 -rl 5 -timeout 10 -silent -o $OUT_DIR/katana.txt

echo "[+] Merging & Cleaning..."
# Fix: Handle cases where files might be empty
cat $OUT_DIR/waymore_urls.txt $OUT_DIR/katana.txt 2>/dev/null | uro | sort -u > $OUT_DIR/clean_urls.txt


# --- Step 4: Parameter Discovery ---

echo "[+] Extracting Params..."

# 1. From Archives
# Paramspider sometimes saves to ./results/, let's force output or move it
paramspider -d $target --quiet 
# Paramspider usually saves to results/domain.txt. Let's move it if -o fails
if [ -f "results/$target.txt" ]; then
    mv "results/$target.txt" "$OUT_DIR/paramspider.txt"
fi

# 2. Extract from crawled URLs
grep "?" $OUT_DIR/clean_urls.txt > $OUT_DIR/crawled_params.txt

# 3. Merge
cat $OUT_DIR/paramspider.txt $OUT_DIR/crawled_params.txt 2>/dev/null | uro | sort -u > $OUT_DIR/final_params.txt

echo "[+] Recon Complete. All data saved in $OUT_DIR"