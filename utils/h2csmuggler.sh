#!/bin/bash

echo "Running H2C Smuggling checks..."

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Import configuration
source "${SCRIPT_DIR}/utils.conf"

setup() {
    # Create H2C_SMUGGLER_DIR if it doesn't exist
    mkdir -p "${SCRIPT_DIR}/../${LOG_DIR}/${H2C_SMUGGLER_DIR}"
    
    OUTPUT_FILE="${SCRIPT_DIR}/../${LOG_DIR}/${H2C_SMUGGLER_DIR}/${H2C_SMUGGLER_FILE}"
    
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

run_h2c_smuggler() {
    local input_file="$1"
    local output_file="$2"

    if [[ ! -f "$input_file" ]]; then
        echo "Error: Input file '$input_file' does not exist"
        exit 1
    fi

    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue
        echo "Testing $domain for H2C smuggling vulnerabilities..."
        # Add your H2C smuggling testing logic here
        echo "$domain" >> "$output_file"
    done < "$input_file"
}

main() {
    local input_file=""
    local output_file="${SCRIPT_DIR}/../${LOG_DIR}/${H2C_SMUGGLER_DIR}/${H2C_SMUGGLER_FILE}"

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
    run_h2c_smuggler "$input_file" "$output_file"
}

main "$@"
