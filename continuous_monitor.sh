#!/bin/bash
# continuous_monitor.sh
programs=("example1.com" "example2.com" "example3.com")
while true; do
    for domain in "${programs[@]}"; do
        echo "[*] Scanning $domain at $(date)"
        
        # Run reconnaissance
        ./recon.sh $domain
        
        # Compare with previous results
        if [ -f "previous_results/${domain}_urls.txt" ]; then
            # Find new URLs
            comm -13 <(sort previous_results/${domain}_urls.txt) <(sort recon_${domain}_*/all_urls.txt) > new_urls_${domain}.txt
            
            if [ -s new_urls_${domain}.txt ]; then
                echo "[!] Found $(wc -l < new_urls_${domain}.txt) new URLs for $domain"
                # Scan only new URLs
                nuclei -l new_urls_${domain}.txt -severity critical,high -o new_findings_${domain}.txt
            fi
        fi
        
        # Update previous results
        mkdir -p previous_results
        cp recon_${domain}_*/all_urls.txt previous_results/${domain}_urls.txt
    done
    
    # Sleep for 24 hours
    echo "[*] Sleeping for 24 hours..."
    sleep 86400
done
