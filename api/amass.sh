#!/bin/bash

# Global Variables
TARGET_ORGANIZATION=''
ORGANIZATION_LIST=''
AMASS_OUTPUT_DIR='amass_output'  # Define the output directory
WORDLIST_FILE='wordlist.txt'      # Define the wordlist file (update as necessary)

# Usage function
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "
    Input Feed:
    -L,   --list <filename>           Specify a file containing a list of organizations (one per line).
    -D,   --domain <domain>           Specify a single domain.

    Help:
    -H,   --help                      Display this help message.
    "
}

# Get parameters from command line arguments
get_params() {
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            -L|--list) ORGANIZATION_LIST="$2"; shift ;;
            -D|--domain) TARGET_ORGANIZATION="$2"; shift ;;
            -H|--help) usage; exit 0 ;;
            *) echo "Unknown parameter: $1"; exit 1 ;;
        esac
        shift
    done
}

# Amass operations function
amass_operations() {
    mkdir -p "$AMASS_OUTPUT_DIR"  # Create output directory if it doesn't exist

    if [[ -n "$TARGET_ORGANIZATION" ]]; then
        # Call with -d if domain is specified
        amass enum -passive -d "$TARGET_ORGANIZATION" -dir "$AMASS_OUTPUT_DIR"  # Passive enumeration
        amass enum -active -d "$TARGET_ORGANIZATION" -dir "$AMASS_OUTPUT_DIR"  # Active enumeration
        amass intel -d "$TARGET_ORGANIZATION" -whois -dir "$AMASS_OUTPUT_DIR"  # WHOIS lookup
        amass enum -active -brute -w "$WORDLIST_FILE" -d "$TARGET_ORGANIZATION" -dir "$AMASS_OUTPUT_DIR"  # Brute force enumeration
        amass viz -enum -d3 -d "$TARGET_ORGANIZATION" -dir "$AMASS_OUTPUT_DIR"  # Visualization
    fi

    if [[ -n "$ORGANIZATION_LIST" ]]; then
        while IFS= read -r org; do
            # Call with -df for each organization in the list file
            amass enum -passive -df "$ORGANIZATION_LIST" -dir "$AMASS_OUTPUT_DIR"  # Passive enumeration
            amass enum -active -df "$ORGANIZATION_LIST" -dir "$AMASS_OUTPUT_DIR"  # Active enumeration
            amass intel -df "$ORGANIZATION_LIST" -whois -dir "$AMASS_OUTPUT_DIR"  # WHOIS lookup
            amass enum -active -brute -w "$WORDLIST_FILE" -df "$ORGANIZATION_LIST" -dir "$AMASS_OUTPUT_DIR"  # Brute force enumeration
            amass viz -enum -d3 -df "$ORGANIZATION_LIST" -dir "$AMASS_OUTPUT_DIR"  # Visualization
        done < "$ORGANIZATION_LIST"
    fi
}

main() {
    get_params "$@"
    
    # Check if at least one of the parameters is provided
    if [[ -z "$TARGET_ORGANIZATION" && -z "$ORGANIZATION_LIST" ]]; then
        usage
        exit 1
    fi

    # Execute Amass operations
    amass_operations
}

# Allow standalone execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
