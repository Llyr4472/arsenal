#!/usr/bin/env bash

if [ -z "$1" ]; then
  echo "Usage: live <domain>"
  exit 1
fi

DOMAIN="$1"

subfinder -all -d "$DOMAIN" -silent \
  | httpx -sc -title -ip \
  > "subdomains_${DOMAIN}.txt"
