#!/bin/bash
domain=$1
# Run multiple tools in parallel
subfinder -d $domain -silent | tee -a all_subs.txt &
amass enum -passive -d $domain -o amass.txt &
assetfinder --subs-only $domain | tee -a all_subs.txt &
# Wait for all to complete
wait
# Merge and deduplicate
cat all_subs.txt amass.txt | sort -u > unique_subs.txt
# Generate subdomain permutations
cat unique_subs.txt | dnsgen - | massdns -r resolvers.txt -t A -o J --flush -w massdns_out.json
