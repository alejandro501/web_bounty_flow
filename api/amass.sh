#!/bin/bash

# Global Variables
TARGET_ORGANIZATION=''
ORGANIZATION_LIST=''
AMASS_OUTPUT_DIR='amass'
WORDLIST_FILE='wordlist.txt' # not used, later todo
SUBDOMAIN_FILE="$AMASS_OUTPUT_DIR/subdomains"
VISUALIZATION_FILE="$AMASS_OUTPUT_DIR/visualization.html"
USE_TOR=false

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "
    Input Feed:
    -L,   --list <filename>           Specify a file containing a list of organizations (one per line).
    -D,   --domain <domain>           Specify a single domain.

    Optional:
    -T,   --tor                       Use Tor for network requests.

    Help:
    -H,   --help                      Display this help message.
    "
}

get_params() {
    while [[ "$#" -gt 0 ]]; do
        case $1 in
        -L | --list)
            ORGANIZATION_LIST="$2"
            shift
            ;;
        -D | --domain)
            TARGET_ORGANIZATION="$2"
            shift
            ;;
        -T | --tor) USE_TOR=true ;;
        -H | --help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown parameter: $1"
            exit 1
            ;;
        esac
        shift
    done
}

amass_operations() {
    mkdir -p "$AMASS_OUTPUT_DIR"
    >"$SUBDOMAIN_FILE" # Clear previous subdomain file contents

    # Prefix with "torsocks" if Tor is enabled
    AMASS_CMD_PREFIX=""
    if $USE_TOR; then
        AMASS_CMD_PREFIX="torsocks"
    fi

    run_amass() {
        local mode=$1
        local domain_flag=$2
        local domain_value=$3

        # Capture output, extract only the domain part, and append API-related subdomains to the subdomain file
        $AMASS_CMD_PREFIX amass enum "$mode" "$domain_flag" "$domain_value" -dir "$AMASS_OUTPUT_DIR" -o amass_tmp |
            awk '{print $1}' | grep -i 'api' | anew "$SUBDOMAIN_FILE"
    }

    if [[ -n "$TARGET_ORGANIZATION" ]]; then
        # Run Amass commands for a single domain
        run_amass "-passive" "-d" "$TARGET_ORGANIZATION"
        run_amass "-active" "-d" "$TARGET_ORGANIZATION" -p 80,443
        $AMASS_CMD_PREFIX amass intel -d "$TARGET_ORGANIZATION" -whois -dir "$AMASS_OUTPUT_DIR" |
            awk '{print $1}' | grep -i 'api' >>"$SUBDOMAIN_FILE"
        run_amass "-active -brute -w $WORDLIST_FILE" "-d" "$TARGET_ORGANIZATION"

        # Generate visualization output
        $AMASS_CMD_PREFIX amass viz -enum -d3 -d "$TARGET_ORGANIZATION" -dir "$AMASS_OUTPUT_DIR" -o "$VISUALIZATION_FILE"
    fi

    if [[ -n "$ORGANIZATION_LIST" ]]; then
        # Run Amass commands for a list of domains
        while IFS= read -r org; do
            run_amass "-passive" "-df" "$ORGANIZATION_LIST"
            run_amass "-active" "-df" "$ORGANIZATION_LIST" -p 80,443
            $AMASS_CMD_PREFIX amass intel -df "$ORGANIZATION_LIST" -whois -dir "$AMASS_OUTPUT_DIR" |
                awk '{print $1}' | grep -i 'api' >>"$SUBDOMAIN_FILE"
            run_amass "-active -brute -w $WORDLIST_FILE" "-df" "$ORGANIZATION_LIST"

            # Generate visualization output for each domain list
            $AMASS_CMD_PREFIX amass viz -enum -d3 -df "$ORGANIZATION_LIST" -dir "$AMASS_OUTPUT_DIR" -o "$VISUALIZATION_FILE"
        done <"$ORGANIZATION_LIST"

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
