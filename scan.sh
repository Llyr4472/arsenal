#!/bin/bash

# ==========================================
#  Vulnerability Scanner Automation
#  Input: Expects recon.sh to have run first
# ==========================================

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target-domain>"
    exit 1
fi
target=$1

# --- Configuration ---
FFUF_WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
invasive=false  # Set to true to enable XSS scanning

# --- Output Setup ---
# Fix: Use $HOME instead of ~
OUT_DIR="$HOME/bb/${target}"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RESET='\033[0m'

echo -e "${GREEN}[+] Starting Vulnerability Scan for: $target${RESET}"
echo -e "${GREEN}[+] Reading files from: $OUT_DIR${RESET}"

# ==========================================
# 1. Nuclei - General Vulnerability Scan
# ==========================================
if [ -f "$OUT_DIR/alive.txt" ]; then
    echo -e "${YELLOW}[*] Running Nuclei on alive domains...${RESET}"
    
    nuclei -l "$OUT_DIR/alive.txt" \
        -tags cve,osint,tech \
        -et dos,fuzzing \
        -severity low,medium,high,critical \
        -o "$OUT_DIR/nuclei_vulns.txt" -t ~/nuclei-templates/
        
    echo -e "${GREEN}[+] Nuclei scan complete. Results: $OUT_DIR/nuclei_vulns.txt${RESET}"
else
    echo -e "${RED}[!] $OUT_DIR/alive.txt not found. Skipping Nuclei.${RESET}"
fi

# ==========================================
# 2. JavaScript Analysis
# ==========================================
if [ -f "$OUT_DIR/clean_urls.txt" ]; then
    echo -e "${YELLOW}[*] Extracting and Analyzing JavaScript files...${RESET}"
    
    grep "\.js$" "$OUT_DIR/clean_urls.txt" | sort -u > "$OUT_DIR/js_files_url.txt"
    
    if [ -s "$OUT_DIR/js_files_url.txt" ]; then
        echo -e "${YELLOW}    -> Scanning JS for secrets...${RESET}"
        nuclei -l "$OUT_DIR/js_files_url.txt" -t http/exposures -o "$OUT_DIR/js_secrets.txt"
        
        echo -e "${YELLOW}    -> Mining JS for hidden endpoints...${RESET}"
        cat "$OUT_DIR/js_files_url.txt" | mantra > "$OUT_DIR/js_hidden_endpoints.txt"
    else
        echo -e "${RED}[!] No JS files found in clean_urls.txt.${RESET}"
    fi
else
    echo -e "${RED}[!] $OUT_DIR/clean_urls.txt not found. Skipping JS Analysis.${RESET}"
fi

# ==========================================
# 3. Targeted Directory Brute-Forcing (Ffuf)
# ==========================================
if [ -f "$OUT_DIR/alive.txt" ]; then
    echo -e "${YELLOW}[*] Starting Targeted Fuzzing...${RESET}"
    
    grep -E "admin|dev|stage|test|api|corp|internal" "$OUT_DIR/alive.txt" > "$OUT_DIR/ffuf_targets.txt"
    
    if [ -s "$OUT_DIR/ffuf_targets.txt" ]; then
        echo -e "${YELLOW}    -> Fuzzing $(wc -l < "$OUT_DIR/ffuf_targets.txt") targets...${RESET}"
        
        # Check if wordlist exists
        if [ ! -f "$FFUF_WORDLIST" ]; then
             echo -e "${RED}[!] Wordlist $FFUF_WORDLIST not found! Skipping FFUF.${RESET}"
        else
            # Fix: Added backslash \ for line continuation
            ffuf -w "$FFUF_WORDLIST:FUZZ" \
                 -w "$OUT_DIR/ffuf_targets.txt:URL" \
                 -u "URL/FUZZ" \
                 -mc 200,403 \
                 -fc 404 \
                 -ac \
                 -s \
                 -o "$OUT_DIR/ffuf_sensitive_files.txt" \
                 -or \
                 -rate 4
                 
            echo -e "${GREEN}[+] Ffuf complete. Check $OUT_DIR/ffuf_sensitive_files.txt${RESET}"
        fi
    else
        echo -e "${RED}[!] No 'interesting' subdomains found for fuzzing.${RESET}"
    fi
fi

# ==========================================
# 4. XSS Automation (Dalfox)
# ==========================================
# Fix: Proper boolean check
if [ "$invasive" = "true" ]; then
    echo -e "${YELLOW}[*] Invasive mode enabled. Proceeding with XSS scanning...${RESET}"
    if [ -f "$OUT_DIR/final_params.txt" ]; then
        echo -e "${YELLOW}[*] Scanning for XSS with Dalfox...${RESET}"
        
        dalfox file "$OUT_DIR/final_params.txt" \
            --skip-bav \
            --silence \
            --output "$OUT_DIR/dalfox_xss.txt"
            
        echo -e "${GREEN}[+] XSS Scan complete. Results: $OUT_DIR/dalfox_xss.txt${RESET}"
    else
        echo -e "${RED}[!] final_params.txt not found. Skipping XSS scan.${RESET}"
    fi
else
    echo -e "${YELLOW}[*] Invasive mode disabled (invasive=false). Skipping XSS scan.${RESET}"
fi

# ==========================================
# 5. Pattern Filtering (GF)
# ==========================================
if [ -f "$OUT_DIR/final_params.txt" ]; then
    echo -e "${YELLOW}[*] Filtering parameters for manual testing (GF)...${RESET}"
    
    # We pipe into specific files
    cat "$OUT_DIR/final_params.txt" | gf ssrf > "$OUT_DIR/potential_ssrf.txt"
    cat "$OUT_DIR/final_params.txt" | gf sqli > "$OUT_DIR/potential_sqli.txt"
    cat "$OUT_DIR/final_params.txt" | gf lfi > "$OUT_DIR/potential_lfi.txt"
    cat "$OUT_DIR/final_params.txt" | gf redirect > "$OUT_DIR/potential_redirect.txt"
    cat "$OUT_DIR/final_params.txt" | gf rce > "$OUT_DIR/potential_rce.txt"
    
    echo -e "${GREEN}[+] GF Filtering complete. Check text files in $OUT_DIR/${RESET}"
fi

echo -e "${GREEN}[Done] All scans finished for $target.${RESET}"
