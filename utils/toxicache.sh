#!/bin/bash

# Toxicache Vulnerability Scanner
# -----------------------------
# This script checks for cache poisoning vulnerabilities in web applications.
# It tests various cache-related attack vectors and reports potential issues.
#
# Usage:
#     ./toxicache.sh [--input <input_file>] [--output <output_file>]
#     
#     --input  Specify the input file containing domains
#     --output Specify the output file for results

echo "Running Toxicache checks..."

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Import configuration
source "${SCRIPT_DIR}/utils.conf"

# Toxicache Wrapper Script
# ------------------------
# This script is a wrapper for the toxicache tool that processes domains or domain lists.
# It handles both file inputs and direct domain inputs, creating temporary files as needed.
# Output is saved in the configured log directory with proper file structure.
#
# Usage:
#   ./toxicache.sh domains.txt        # Process a file of domains
#   ./toxicache.sh example.com        # Process a single domain
#
# Output:
#   - Logs saved to: logs/toxicache/toxicache.log
#   - Extracted domains saved to: logs/toxicache/toxicache_domains.txt

setup() {
    # Create TOXICACHE_DIR if it doesn't exist
    mkdir -p "${SCRIPT_DIR}/../${LOG_DIR}/${TOXICACHE_DIR}"
    
    OUTPUT_FILE="${SCRIPT_DIR}/../${LOG_DIR}/${TOXICACHE_DIR}/${TOXICACHE_FILE}"
    
    # Ensure output file exists and is writable
    touch "$OUTPUT_FILE" 2>/dev/null || {
        echo "Error: Cannot create or write to output file: $OUTPUT_FILE"
        exit 1
    }
    chmod 644 "$OUTPUT_FILE" 2>/dev/null || {
        echo "Error: Cannot set permissions on output file: $OUTPUT_FILE"
        exit 1
    }
}

run_toxicache() {
    local input_file="$1"
    local output_file="$2"

    if [[ ! -f "$input_file" ]]; then
        echo "Error: Input file '$input_file' does not exist"
        exit 1
    fi

    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue
        echo "Testing $domain for cache poisoning vulnerabilities..."
        # Add your cache poisoning testing logic here
        echo "$domain" >> "$output_file"
    done < "$input_file"
}

main() {
    local input_file=""
    local output_file="${SCRIPT_DIR}/../${LOG_DIR}/${TOXICACHE_DIR}/${TOXICACHE_FILE}"

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
    run_toxicache "$input_file" "$output_file"
}

main "$@"
