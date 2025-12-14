#!/bin/bash

# Usage: ./geturls.sh target.com [-n]

DOMAIN=$1
OPTION=$2

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 target.com [-n]"
    echo "  -n  Disable subdomains (main domain only)"
    exit 1
fi

OUTPUT="urls_${DOMAIN}.txt"

# Default settings (Subdomains ON)
GAU_FLAGS="--subs --threads 5"
WB_FLAGS=""

# Check if subdomains should be disabled
if [ "$OPTION" == "-n" ]; then
    echo "Fetching URLs for $DOMAIN (Main domain only)..."
    GAU_FLAGS="--threads 5"
    WB_FLAGS="-no-subs"
else
    echo "Fetching URLs for $DOMAIN (Including subdomains)..."
fi

# Run gau in background
gau $GAU_FLAGS "$DOMAIN" > temp_gau.txt 2>/dev/null &
PID_GAU=$!

# Run waybackurls in background
echo "$DOMAIN" | waybackurls $WB_FLAGS > temp_wb.txt 2>/dev/null &
PID_WB=$!

# Wait for both to finish
wait $PID_GAU
wait $PID_WB

# Merge and sort
cat temp_gau.txt temp_wb.txt | sort -u > "$OUTPUT"

# Cleanup
rm temp_gau.txt temp_wb.txt

echo "Done! Saved $(wc -l < "$OUTPUT") URLs to $OUTPUT"
