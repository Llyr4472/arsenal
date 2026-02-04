#!/bin/bash

WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"

if [[ "$2" == "-raft" ]]; then
    WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
    ffuf -ac -recursion -w "$WORDLIST" -rate 2 -u $1FUZZ "${@:3}"
else
    ffuf -ac -recursion -w "$WORDLIST" -rate 2 -u $1FUZZ "${@:2}"
fi 
