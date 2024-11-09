#!/bin/bash

# directories
<<<<<<< HEAD
=======
AMASS_DIR='amass'
>>>>>>> 9628b04 (new flow.sh, recon stuff)
ROBOTS_DIR='robots'
NMAP_DIR='nmap'
FUZZING_DIR='fuzzing'

# arguments
ORGANIZATION=''
<<<<<<< HEAD
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
=======
ORGANIZATION_LIST='wildcards'
SUBDOMAIN_OUTPUT='apidomains'
USE_TOR=false

# wordlists
501_APIWILD='~/hack/resources/wordlists/501-api-wild.txt'
SECLIST_API_LONGEST='~/hack/resources/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints-res.txt'
CUSTOM_PROJECT_SPECIFIC='custom-apifuzz.txt' # add individually crafted here if present
APIDOCS='~/hack/resources/wordlists/api_docs_path'

usage() {
    echo "Usage: $0 [options]"
    echo "
    Input Feed:
    -org,  --organization <org>       Specify a single organization.
    -ol,  --org-list <filename>      Specify a file containing a list of organizations (one per line).

    Optional:
    -t,   --tor                      Use Tor for network requests.

    Help:
    -h,   --help                     Display this help message.

    Example Call:
    $0 -or example.com -ol wildcards -t
>>>>>>> 9628b04 (new flow.sh, recon stuff)
    "
}

get_params() {
    while [[ "$#" -gt 0 ]]; do
        case $1 in
<<<<<<< HEAD
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
=======
        -org | --organization)
            ORGANIZATION="$2"
            shift
            ;;
        -ol | --org-list)
            ORGANIZATION_LIST="$2"
            shift
            ;;
        -t | --tor) USE_TOR=true ;;
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

check_setup_tor() {
    if $USE_TOR; then
        setup_tor
        TOR_FLAG="--tor"
    else
        TOR_FLAG=""
    fi
}

<<<<<<< HEAD
robots() {
    local orgs="$1"

=======
scan_network() {
    local orgs="$1"

    mkdir -p "$NMAP_DIR"

    while IFS= read -r org; do
        echo "Scanning $org with nmap"
        clean_org=$(echo "$org" | sed -e 's|http[s]*://||' -e 's|www\.||')
        touch "$NMAP_DIR/${clean_org}.scsv.log"
        touch "$NMAP_DIR/${clean_org}.allports.log"
        nmap -sC -sV "$org" -oA "$NMAP_DIR/${clean_org}.scsv.log"
        nmap -p- "$org" -oA "$NMAP_DIR/${clean_org}.allports.log"
    done <"$orgs"
}

robots() {
    local orgs="$1"
>>>>>>> 9628b04 (new flow.sh, recon stuff)
    mkdir -p "$ROBOTS_DIR"
    { cat "$SUBDOMAIN_OUTPUT" "$orgs"; } | sort -u | while IFS= read -r org; do
        clean_org=$(echo "$org" | sed -e 's|http[s]*://||' -e 's|www\.||')
        curl -s -o "$ROBOTS_DIR/$clean_org.robots.txt" "$org/robots.txt"

<<<<<<< HEAD
        # Extract urls to processed file
        if [[ -f "$ROBOTS_DIR/$clean_org.robots.txt" ]]; then
            cat "$ROBOTS_DIR/$clean_org.robots.txt" | grep -E '^(Disallow|Allow): ' | sed -E "s|^(Disallow|Allow): (.*)|https://$org\2|g" >"$ROBOTS_DIR/$clean_org.robots.urls.txt"
=======
        if [[ -f "$ROBOTS_DIR/$clean_org.robots.txt" ]]; then
            cat "$ROBOTS_DIR/$clean_org.robots.txt" | grep -E '^(Disallow|Allow): ' | sed -E "s|^(Disallow|Allow): (.*)|https://$org\2|g" >"$ROBOTS_DIR/$clean_org.robots.urls"
>>>>>>> 9628b04 (new flow.sh, recon stuff)
        else
            echo "No robots.txt found for $org"
        fi
    done
}

passive_recon() {
<<<<<<< HEAD
    if [[ -n "$ORGANIZATION" ]]; then
        generate_dork_links -oR "$ORGANIZATION" --api
        subfinder -d "$ORGANIZATION" | grep api | httprobe --prefer-https | anew "$SUBDOMAIN_OUTPUT"
        ./amass.sh -oR "$ORGANIZATION" --tor

        # nmap service, version, and port enumeration
        nmap -sC -sV "$ORGANIZATION" -oA nmap.scsv.log
        nmap -p- "$ORGANIZATION" -oA nmap.allports.log
=======
    mkdir -p "$NMAP_DIR"

    if [[ -n "$ORGANIZATION" ]]; then
        generate_dork_links -oR "$ORGANIZATION" --api
        subfinder -d "$ORGANIZATION" | grep api | httprobe --prefer-https | anew "$SUBDOMAIN_OUTPUT"
        ./amass.sh -oR "$ORGANIZATION" "$TOR_FLAG"
        cat "$AMASS_DIR/subdomains" | anew "$SUBDOMAIN_OUTPUT"
        scan_network <(echo "$ORGANIZATION")
>>>>>>> 9628b04 (new flow.sh, recon stuff)
        robots "$ORGANIZATION"

    elif [[ -n "$ORGANIZATION_LIST" ]]; then
        generate_dork_links -L "$ORGANIZATION_LIST" --api
        subfinder -dL "$ORGANIZATION_LIST" | grep api | httprobe --prefer-https | anew "$SUBDOMAIN_OUTPUT"
<<<<<<< HEAD
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
=======
        ./amass.sh -L "$ORGANIZATION_LIST" "$TOR_FLAG"
        scan_network "$ORGANIZATION_LIST"
        scan_network "$SUBDOMAIN_OUTPUT"
        robots "$ORGANIZATION_LIST"
        robots "$SUBDOMAIN_OUTPUT"
    fi
}

fuzz_directories() {
    mkdir -p "$FUZZING_DIR"
    mkdir -p "${FUZZING_DIR}/ffuf"
    mkdir -p "${FUZZING_DIR}/kiterunner"

    # combined wordlist
    cat "$501_APIWILD" "$SECLIST_API_LONGEST" "$CUSTOM_PROJECT_SPECIFIC" | anew >"$FUZZING_DIR/fuzzme"

    (cat "$SUBDOMAIN_OUTPUT" "$ORGANIZATION_LIST") | while IFS= read -r url; do
        echo "Fuzzing for $url"

        output_file="${FUZZING_DIR}/ffuf/$(basename "$url").csv"
        ffuf -u "${url}/FUZZ" -w "$FUZZING_DIR/fuzzme" -mc 200,301 -p 0.2 -o "$output_file" -of csv

        # Extract the actual URLs from the CSV if any hits are found
        if grep -q "^[^,]\+," "$output_file"; then
            awk -F',' 'NR>1 {print $2}' "$output_file" >>"$FUZZING_DIR/endpoint_hits"
        fi
    done
}

fuzz_documentation() {
    mkdir -p "${FUZZING_DIR}/documentation"
    local targets=()

    [[ -n "$ORGANIZATION" ]] && targets+=("$ORGANIZATION")
    [[ -n "$ORGANIZATION_LIST" ]] && targets+=($(<"$ORGANIZATION_LIST"))
    [[ -f "$SUBDOMAIN_OUTPUT" ]] && targets+=($(<"$SUBDOMAIN_OUTPUT"))

    for url in "${targets[@]}"; do
        clean_url=$(echo "$url" | sed -e 's|http[s]*://||' -e 's|www\.||' -e 's|/||g')
        ffuf -u "${url}/FUZZ" -w "$APIDOCS" -mc 200,301 -o "${FUZZING_DIR}/documentation/${clean_url}.csv" -of csv

        # Extract the actual URLs from the CSV if any hits are found
        if grep -q "^[^,]\+," "$output_file"; then
            awk -F',' 'NR>1 {print $2}' "$output_file" >>"${FUZZING_DIR}/doc_hits"
        fi
    done
>>>>>>> 9628b04 (new flow.sh, recon stuff)
}

main() {
    get_params "$@"
    check_setup_tor
    passive_recon
<<<<<<< HEAD
    fuzzing
=======
    fuzz_directories
    fuzz_documentation
    # requires manual interaction, reverse engineer api using postman, extract collection, feed postman extract script
    # postman_extract_url -i postman_extract.json -o postman_extracted_api_urls --keyword api
>>>>>>> 9628b04 (new flow.sh, recon stuff)
}

main "$@"
