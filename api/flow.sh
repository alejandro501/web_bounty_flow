#!/bin/bash

# global variables
ORGANIZATION=''
ORGANIZATION_LIST=''

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "
    Input Feed:
    -oR,  --organization <org>       Specify a single organization.
    -oL,  --org-list <filename>      Specify a file containing a list of organizations (one per line).

    Help:
    -H,   --help                     Display this help message.
    "
}

get_params() {
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            -oR|--org) ORGANIZATION="$2"; shift ;;
            -oL|--org-list) ORGANIZATION_LIST="$2"; shift ;;
            -H|--help) usage; exit 0 ;;
            *) echo "Unknown parameter: $1"; exit 1 ;;
        esac
        shift
    done
}

# generate dork links - google github shodan
passive_recon() {
    if [[ -n "$ORGANIZATION" ]]; then
        generate_dork_links -oR "$ORGANIZATION" --api
        ./amass.sh -oR "$ORGANIZATION" 
    elif [[ -n "$ORGANIZATION_LIST" ]]; then
        generate_dork_links -L "$ORGANIZATION_LIST" --api
        ./amass.sh -L "$ORGANIZATION_LIST" 
    fi
}

main() {
    get_params "$@"
    passive_recon
}

main "$@"
