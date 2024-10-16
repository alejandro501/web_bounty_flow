#!/bin/bash

FINGERPRINT_RESULTS_DIR="fingerprint_results"

RED='\033[0;31m'
GREEN='\033[0;32m'
PURPLE='\033[0;35m'
NC='\033[0m' 

fingerprint_with_grapw00f() {
    local url="$1"
    echo -e "${PURPLE}Fingerprinting $url with graphw00f...${NC}"

    local sanitized_url=$(echo "$url" | sed -E 's|https?://||; s|/.*||')
    local output_file="$FINGERPRINT_RESULTS_DIR/${sanitized_url}.csv"

    mkdir -p "$FINGERPRINT_RESULTS_DIR"

    python3 graphw00f/main.py -f -d -t "$url" -o "$output_file"

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Fingerprinting and detection successful for $url${NC}"
    else
        echo -e "${RED}Fingerprinting failed for $url${NC}"
    fi
}

main() {
    INPUT_FILE="${1:-graphql.txt}"

    while read -r endpoint; do
        if [ -n "$endpoint" ]; then
            fingerprint_with_grapw00f "$endpoint"
        fi
    done < "$INPUT_FILE"
}

main "$@"
