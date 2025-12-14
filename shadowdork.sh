#!/bin/bash

# ==========================================
# SHADOWDORK
# Automated Google Dorking Generator
# ==========================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RESET='\033[0m'

DOMAIN=$1

if [ -z "$DOMAIN" ]; then
    echo -e "${RED}Usage: $0 target.com${RESET}"
    exit 1
fi

# Extract keyword (e.g., "tesla" from "tesla.com") for SaaS searches
KEYWORD=$(echo "$DOMAIN" | cut -d. -f1)

echo -e "${BLUE}_________________________________________________${RESET}"
echo -e "${YELLOW}           S H A D O W  D O R K              ${RESET}"
echo -e "${BLUE}_________________________________________________${RESET}"
echo -e "Target  : ${GREEN}$DOMAIN${RESET}"
echo -e "Keyword : ${GREEN}$KEYWORD${RESET}"
echo -e "${RED}Tip: Open links slowly to avoid Captchas.${RESET}"
echo ""

# Function: Search strictly within the target domain
dork_direct() {
    TITLE=$1
    QUERY=$2
    LINK="https://www.google.com/search?q=site:$DOMAIN+$QUERY"
    echo -e "${YELLOW}[+] $TITLE${RESET}"
    echo "$LINK"
    echo ""
}

# Function: Search 3rd party sites for the Company Name or Domain
dork_saas() {
    TITLE=$1
    SITE=$2
    LINK="https://www.google.com/search?q=site:$SITE+\"$KEYWORD\"+OR+\"$DOMAIN\""
    echo -e "${BLUE}[+] $TITLE (External/SaaS)${RESET}"
    echo "$LINK"
    echo ""
}

# ==========================================
# 1. FORGOTTEN FILES (Zips, Docs, Excel)
# ==========================================
echo -e "${GREEN}=== FILES & ARCHIVES ===${RESET}"

dork_direct "Backup Archives (Source Code / Dumps)" \
"ext:zip+OR+ext:rar+OR+ext:7z+OR+ext:tar+OR+ext:gz+OR+ext:tgz+OR+ext:bak+OR+ext:war"

dork_direct "Spreadsheets (PII / Financials)" \
"ext:xlsx+OR+ext:xls+OR+ext:csv+OR+ext:ods+OR+ext:tsv"

dork_direct "Confidential Documents" \
"ext:pdf+OR+ext:docx+OR+ext:doc+intext:confidential+OR+intext:internal+OR+intext:private"

dork_direct "Mobile App & Packages" \
"ext:apk+OR+ext:ipa+OR+ext:jar"

# ==========================================
# 2. CONFIGS & SECRETS
# ==========================================
echo -e "${GREEN}=== SECRETS & LOGS ===${RESET}"

dork_direct "Configuration Secrets (.env, .yml)" \
"ext:env+OR+ext:yml+OR+ext:yaml+OR+ext:config+OR+ext:conf+OR+ext:ini+OR+ext:properties"

dork_direct "Database Exports" \
"ext:sql+OR+ext:db+OR+ext:dbf+OR+ext:mdb+OR+ext:dump"

dork_direct "Log Files" \
"ext:log+OR+ext:txt+inurl:log+OR+ext:out"

dork_direct "SSH & Private Keys" \
"ext:pem+OR+ext:key+OR+ext:pub+OR+ext:p12+OR+ext:asc"

# ==========================================
# 3. SHADOW IT (Cloud & SaaS)
# ==========================================
echo -e "${GREEN}=== SHADOW IT (3rd Party) ===${RESET}"

dork_saas "Trello Boards" "trello.com"
dork_saas "Jira / Atlassian" "atlassian.net"
dork_saas "Notion Pages" "notion.site"
dork_saas "Loom Videos" "loom.com/share"
dork_saas "Pastebin" "pastebin.com"
dork_saas "Google Drive/Docs" "docs.google.com"
dork_saas "Airtable Bases" "airtable.com"
dork_saas "S3 Buckets" "s3.amazonaws.com"
dork_saas "Azure Blobs" "blob.core.windows.net"

# ==========================================
# 4. INFRASTRUCTURE & PORTALS
# ==========================================
echo -e "${GREEN}=== INFRASTRUCTURE ===${RESET}"

dork_direct "API Docs (Swagger/WSDL)" \
"inurl:swagger+OR+inurl:api-docs+OR+inurl:wsdl+OR+filetype:wsdl"

dork_direct "Directory Listing (Index Of)" \
"intitle:\"index+of\""

dork_direct "Admin/Login Portals" \
"inurl:admin+OR+inurl:dashboard+OR+intitle:\"admin panel\"+OR+inurl:login"

echo -e "${YELLOW}Done.${RESET}"
