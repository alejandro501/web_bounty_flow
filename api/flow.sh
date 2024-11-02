#!/bin/bash

# directories
ROBOTS_DIR='robots'
NMAP_DIR='nmap'
FUZZING_DIR='fuzzing'

# arguments
ORGANIZATION=''
ORGANIZATION_LIST=''
SUBDOMAIN_OUTPUT='apidomains'
### after amass finishes
# [ ] put together subfinder and amass api hits
# [ ] feed them to the amass scan
USE_TOR=false

# wordlists
GOBUSTER_WORDLIST='wordlist.txt' # temporary individual

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "
    Input Feed:
    -oR,  --organization <org>       Specify a single organization.
    -oL,  --org-list <filename>      Specify a file containing a list of organizations (one per line).

    Optional:
    -T,   --tor                      Use Tor for network requests.

    Help:
    -H,   --help                     Display this help message.
    "
}

get_params() {
    while [[ "$#" -gt 0 ]]; do
        case $1 in
        -oR | --organization)
            ORGANIZATION="$2"
            shift
            ;;
        -oL | --org-list)
            ORGANIZATION_LIST="$2"
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

check_setup_tor() {
    if $USE_TOR; then
        setup_tor
        TOR_FLAG="--tor"
    else
        TOR_FLAG=""
    fi
}

robots() {
    local orgs="$1"

    mkdir -p "$ROBOTS_DIR"
    { cat "$SUBDOMAIN_OUTPUT" "$orgs"; } | sort -u | while IFS= read -r org; do
        clean_org=$(echo "$org" | sed -e 's|http[s]*://||' -e 's|www\.||')
        curl -s -o "$ROBOTS_DIR/$clean_org.robots.txt" "$org/robots.txt"

        # Extract urls to processed file
        if [[ -f "$ROBOTS_DIR/$clean_org.robots.txt" ]]; then
            cat "$ROBOTS_DIR/$clean_org.robots.txt" | grep -E '^(Disallow|Allow): ' | sed -E "s|^(Disallow|Allow): (.*)|https://$org\2|g" >"$ROBOTS_DIR/$clean_org.robots.urls.txt"
        else
            echo "No robots.txt found for $org"
        fi
    done
}

passive_recon() {
    if [[ -n "$ORGANIZATION" ]]; then
        generate_dork_links -oR "$ORGANIZATION" --api
        subfinder -d "$ORGANIZATION" | grep api | httprobe --prefer-https | anew "$SUBDOMAIN_OUTPUT"
        ./amass.sh -oR "$ORGANIZATION" --tor

        # nmap service, version, and port enumeration
        nmap -sC -sV "$ORGANIZATION" -oA nmap.scsv.log
        nmap -p- "$ORGANIZATION" -oA nmap.allports.log
        robots "$ORGANIZATION"

    elif [[ -n "$ORGANIZATION_LIST" ]]; then
        generate_dork_links -L "$ORGANIZATION_LIST" --api
        subfinder -dL "$ORGANIZATION_LIST" | grep api | httprobe --prefer-https | anew "$SUBDOMAIN_OUTPUT"
        ./amass.sh -L "$ORGANIZATION_LIST" --tor

        # nmap service, version, and port enumeration
        mkdir -p "$NMAP_DIR"
        while IFS= read -r org; do
            nmap -sC -sV "$org" -oA "$NMAP_DIR/${org}.scsv"
            nmap -p- "$org" -oA "$NMAP_DIR/${org}_allports"
        done <"$SUBDOMAIN_OUTPUT"
        robots "$ORGANIZATION_LIST"
    fi
}

fuzzing() {
    mkdir -p "$FUZZING_DIR"
    mkdir -p "${FUZZING_DIR}/gobuster"
    mkdir -p "${FUZZING_DIR}/kiterunner"
    while IFS= read -r url; do
        echo "Running Gobuster for $url"
        gobuster dir -u "$url" -w "$GOBUSTER_WORDLIST" -x 200,201,202,301 -b 302 -o "$FUZZING_DIR/gobuster/$(basename "$url").gobuster.txt"
        kr scan "$url" -A apiroutes-240528 -o text | anew "$FUZZING_DIR/kiterunner/$(basename "$url").kiterunner.txt" # tryy
    done <"$SUBDOMAIN_OUTPUT"
}

main() {
    get_params "$@"
    check_setup_tor
    passive_recon
    fuzzing
}

main "$@"
