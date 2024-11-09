#!/bin/bash

<<<<<<< HEAD
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
=======
target_organization=''
organization_list=''
amass_dir='amass'
wordlist_file='wordlist.txt'
subdomain_file="$amass_dir/subdomains"
visualization_file="$amass_dir/visualization.html"
use_tor=false

usage() {
    echo "Usage: $0 [options]"
    echo "
    Input Feed:
    -ad,  --amass-dir <filename>      Specify a name for the amass output directory (default: amass).
    -l,   --list <filename>           Specify a file containing a list of organizations (one per line).
    -d,   --domain <domain>           Specify a single domain.

    Optional:
    -t,   --tor                       Use Tor for network requests.

    Help:
    -h,   --help                      Display this help message.
>>>>>>> 9628b04 (new flow.sh, recon stuff)
    "
}

get_params() {
    while [[ "$#" -gt 0 ]]; do
        case $1 in
<<<<<<< HEAD
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
=======
        -ad | --amass-dir)
            amass_dir="$2"
            shift
            ;;
        -l | --list)
            organization_list="$2"
            shift
            ;;
        -d | --domain)
            target_organization="$2"
            shift
            ;;
        -t | --tor) use_tor=true ;;
        -h | --help)
>>>>>>> 9628b04 (new flow.sh, recon stuff)
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
    mkdir -p "$amass_dir"
    >"$subdomain_file"

    amass_cmd_prefix=""
    if $use_tor; then
        amass_cmd_prefix="torsocks"
    fi

    run_amass() {
        local mode=$1
        local domain_flag=$2
        local domain_value=$3

        $amass_cmd_prefix amass enum "$mode" "$domain_flag" "$domain_value" -dir "$amass_dir" -o amass_tmp |
            awk '{print $1}' | grep -i 'api' | anew "$subdomain_file"
    }

    if [[ -n "$target_organization" ]]; then
        run_amass "-passive" "-d" "$target_organization"
        run_amass "-active" "-d" "$target_organization" -p 80,443
        $amass_cmd_prefix amass intel -d "$target_organization" -whois -dir "$amass_dir" |
            awk '{print $1}' | grep -i 'api' >>"$subdomain_file"
        run_amass "-active -brute -w $wordlist_file" "-d" "$target_organization"

        $amass_cmd_prefix amass viz -enum -d3 -d "$target_organization" -dir "$amass_dir" -o "$visualization_file"
    fi

    if [[ -n "$organization_list" ]]; then
        while IFS= read -r org; do
            run_amass "-passive" "-df" "$organization_list"
            run_amass "-active" "-df" "$organization_list" -p 80,443
            $amass_cmd_prefix amass intel -df "$organization_list" -whois -dir "$amass_dir" |
                awk '{print $1}' | grep -i 'api' >>"$subdomain_file"
            run_amass "-active -brute -w $wordlist_file" "-df" "$organization_list"

            $amass_cmd_prefix amass viz -enum -d3 -df "$organization_list" -dir "$amass_dir" -o "$visualization_file"
        done <"$organization_list"
    fi
}

main() {
    get_params "$@"

<<<<<<< HEAD
    # Check if at least one of the parameters is provided
    if [[ -z "$TARGET_ORGANIZATION" && -z "$ORGANIZATION_LIST" ]]; then
=======
    if [[ -z "$target_organization" && -z "$organization_list" ]]; then
>>>>>>> 9628b04 (new flow.sh, recon stuff)
        usage
        exit 1
    fi

<<<<<<< HEAD
    # Execute Amass operations
    amass_operations
}

# Allow standalone execution
=======
    amass_operations
}

>>>>>>> 9628b04 (new flow.sh, recon stuff)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
