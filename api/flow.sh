#!/bin/bash

# directories
AMASS_DIR='amass'
ROBOTS_DIR='robots'
NMAP_DIR='nmap'
FUZZING_DIR='fuzzing'

# arguments
ORGANIZATION=''
ORGANIZATIONS='organizations'
IPS='ips'
WILDCARDS='wildcards'
DOMAINS='domains'
APIDOMAINS='apidomains'
USE_TOR=false

# wordlists
API_WILD_501="${HOME}/hack/resources/wordlists/api-wild-501.txt"
SECLIST_API_LONGEST="${HOME}/hack/resources/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints-res.txt"
CUSTOM_PROJECT_SPECIFIC='project-apifuzz.txt'
APIDOCS="${HOME}/hack/resources/wordlists/api_docs_path"

usage() {
    echo "Usage: $0 [options]"
    echo "
    Input Feed:
    -org,  --organization <org>       specify a single organization.
    -ol,  --org-list <filename>      specify a file containing a list of organizations (one per line).

    Optional:
    -t,   --tor                      use tor for network requests.

    Help:
    -h,   --help                     display this help message.

    Example Call:
    $0 -or example.com -ol wildcards -t
    "
}

get_params() {
    while [[ "$#" -gt 0 ]]; do
        case $1 in
        -org | --organization)
            ORGANIZATION="$2"
            shift
            ;;
        -ol | --org-list)
            WILDCARDS="$2"
            shift
            ;;
        -t | --tor) USE_TOR=true ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "unknown parameter: $1"
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

scan_network() {
    local orgs="$1"

    mkdir -p "$NMAP_DIR"

    while IFS= read -r org; do
        [[ -z "$org" ]] && continue
        echo "Scanning $org with nmap"

        clean_org=$(echo "$org" | sed -e 's#http[s]*://##' -e 's#www\.##')
        clean_org=$(echo "$clean_org" | tr -d '/:')

        touch "$NMAP_DIR/${clean_org}.scsv.log"
        touch "$NMAP_DIR/${clean_org}.allports.log"

        nmap -sC -sV "$clean_org" -oA "$NMAP_DIR/${clean_org}.scsv.log"
        nmap -p- "$clean_org" -oA "$NMAP_DIR/${clean_org}.allports.log"
    done <"$orgs"
}

robots() {
    local orgs="$1"
    echo "fetching robots.txt for $orgs..."

    mkdir -p "$ROBOTS_DIR"

    { cat "$APIDOMAINS" "$orgs"; } | sort -u | while IFS= read -r org; do
        [[ -z "$org" ]] && continue
        clean_org=$(echo "$org" | sed -e 's#http[s]*://##' -e 's#www\.##')
        curl -s -o "$ROBOTS_DIR/$clean_org.robots.txt" "$org/robots.txt"

        if [[ -f "$ROBOTS_DIR/$clean_org.robots.txt" ]]; then
            grep -E '^(Disallow|Allow): ' "$ROBOTS_DIR/$clean_org.robots.txt" | sed -E "s#^(Disallow|Allow): (.*)#https://$org\2#g" >"$ROBOTS_DIR/$clean_org.robots.urls"
            echo "robots.txt found for $org"
        fi
    done
}

passive_recon() {
    # Handle ORGANIZATION if provided
    if [[ -n "$ORGANIZATION" ]]; then
        generate_dork_links -oR "$ORGANIZATION" --api
        grep -h 'http' ./dorking/* | while IFS= read -r url; do xdg-open "$url"; done # opens everything in the dorking dir
        robots "$DOMAINS"
        scan_network "$DOMAINS"
    fi

    # Handle WILDCARDS if provided
    if [[ -n "$WILDCARDS" && -s "$WILDCARDS" ]]; then
        generate_dork_links -L "$WILDCARDS" --api
        grep -h 'http' ./dorking/* | while IFS= read -r url; do xdg-open "$url"; done # opens everything in the dorking dir
        robots "$WILDCARDS"
        robots "$APIDOMAINS"
        subfinder -dL "$WILDCARDS" | grep api | httprobe --prefer-https | anew "$APIDOMAINS"
        ./amass.sh -L "$WILDCARDS" "$TOR_FLAG"
        scan_network "$APIDOMAINS"
    fi

    # Handle DOMAINS independently if no WILDCARDS or others
    if [[ -n "$DOMAINS" && -s "$DOMAINS" ]]; then
        robots "$DOMAINS"
        scan_network "$DOMAINS"
    else
        echo "DOMAINS is either missing or empty. Skipping domain-based operations."
    fi

    # Handle APIDOMAINS independently if available
    if [[ -n "$APIDOMAINS" && -s "$APIDOMAINS" ]]; then
        scan_network "$APIDOMAINS"
    else
        echo "APIDOMAINS is either missing or empty. Skipping API domain-based operations."
    fi
}

fuzz_directories() {
    mkdir -p "$FUZZING_DIR"
    mkdir -p "${FUZZING_DIR}/ffuf"

    cat "$API_WILD_501" "$SECLIST_API_LONGEST" "$CUSTOM_PROJECT_SPECIFIC" | anew >"$FUZZING_DIR/fuzzme"

    if [[ -s "$APIDOMAINS" || (-s "$WILDCARDS") ]]; then
        (cat "$APIDOMAINS" "$WILDCARDS") | while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            echo "fuzzing for $url"

            output_file="${FUZZING_DIR}/ffuf/$(basename "$url").csv"
            ffuf -u "${url}/FUZZ" -w "$FUZZING_DIR/fuzzme" -mc 200,301 -p 0.2 -o "$output_file" -of csv

            if grep -q "^[^,]\+," "$output_file"; then
                awk -F',' 'NR>1 {print $2}' "$output_file" >>"$FUZZING_DIR/endpoint_hits"
            fi
        done
    else
        echo "skipping fuzzing as the apidomain output or wildcards file is empty."
    fi
}

fuzz_documentation() {
    mkdir -p "${FUZZING_DIR}/documentation"
    local targets=()

    # Add entries from ORGANIZATIONS (if the file is not empty)
    if [[ -s "$ORGANIZATIONS" ]]; then
        while IFS= read -r org_line; do
            [[ -n "$org_line" ]] && targets+=("$org_line")
        done < "$ORGANIZATIONS"
    fi

    # Add entries from WILDCARDS if it exists
    if [[ -s "$WILDCARDS" ]]; then
        targets+=($(<"$WILDCARDS"))
    fi

    # Add entries from APIDOMAINS if it exists
    if [[ -f "$APIDOMAINS" && -s "$APIDOMAINS" ]]; then
        targets+=($(<"$APIDOMAINS"))
    fi

    # Perform fuzzing if there are valid targets
    if [[ ${#targets[@]} -gt 0 ]]; then
        for url in "${targets[@]}"; do
            [[ -z "$url" ]] && continue
            clean_url=$(echo "$url" | sed -e 's#http[s]*://##' -e 's#www\.##' -e 's#/##g')
            ffuf -u "${url}/FUZZ" -w "$APIDOCS" -mc 200,301 -o "${FUZZING_DIR}/documentation/${clean_url}.csv" -of csv

            output_file="${FUZZING_DIR}/documentation/${clean_url}.csv"
            if grep -q "^[^,]\+," "$output_file"; then
                awk -F',' 'NR>1 {print $2}' "$output_file" >>"${FUZZING_DIR}/doc_hits"
            fi
        done
    else
        echo "skipping documentation fuzzing as there are no valid targets."
    fi
}

main() {
    #get_params "$@"
    #check_setup_tor
    passive_recon
    #fuzz_documentation
    #fuzz_directories
    # manual: check shodan dork hits and add valid ip's to $IPS
    
}

main "$@"
