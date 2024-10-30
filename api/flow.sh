#!/bin/bash

# global variables
TARGET_ORGANIZATION=''
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
            -oR|--org) TARGET_ORGANIZATION="$2"; shift ;;
            -oL|--org-list) ORGANIZATION_LIST="$2"; shift ;;
            -H|--help) usage; exit 0 ;;
            *) echo "Unknown parameter: $1"; exit 1 ;;
        esac
        shift
    done
}

# generate dork links - google github shodan
dorking() {
    if [[ -n "$TARGET_ORGANIZATION" ]]; then
        generate_dork_links -oR "$TARGET_ORGANIZATION" --api
    elif [[ -n "$ORGANIZATION_LIST" ]]; then
        generate_dork_links -L "$TARGET_ORGANIZATION_LIST" --api
    fi
}

main() {
    get_params "$@"
    dorking
}

main "$@"
