#!/bin/bash

# Load configuration
if [[ -f "flow.conf" ]]; then
    source "flow.conf"
else
    echo "Error: flow.conf not found. Please create the configuration file."
    exit 1
fi

# Display usage instructions
usage() {
    echo "Usage: $0 [options]"
    echo "
    Options:
    -org,  --organization <org>       specify a single organization.
    -ol,  --org-list <filename>      specify a file containing a list of organizations.
    -h,   --help                     display this help message.

    Example:
    $0 -org example.com -ol wildcards
    "
}

# Parse command-line arguments
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
        -h | --help)
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

# Perform network scanning with nmap
scan_network() {
    local orgs="$1"
    mkdir -p "$NMAP_DIR"
    while IFS= read -r org; do
        [[ -z "$org" ]] && continue
        clean_org=$(echo "$org" | sed -e 's#http[s]*://##' -e 's#www\.##' | tr -d '/:')
        nmap -sC -sV "$clean_org" -oA "$NMAP_DIR/${clean_org}.scsv.log"
        nmap -p- "$clean_org" -oA "$NMAP_DIR/${clean_org}.allports.log"
    done <"$orgs"
}

# Process .gnmap files for useful data
process_gnmap() {
    [[ "$ENABLE_NMAP_SUMMARY" != true ]] && return
    mkdir -p "$NMAP_DIR"
    >"$SUMMARY_FILE"
    >"$POINTERS_FILE"
    >"$SERVICES_FILE"
    >"$SEARCHSPLOIT_RESULTS"
    for gnmap_file in "$NMAP_DIR"/*.gnmap; do
        [[ ! -f "$gnmap_file" ]] && continue
        target_domain=$(grep -oP 'Nmap .* scan initiated .* as: nmap .* \K[^ ]+' "$gnmap_file")
        host=$(grep -oP 'Host: \K[^ ]+' "$gnmap_file")
        open_ports=$(grep -oP '\d+/open' "$gnmap_file" | cut -d'/' -f1 | tr '\n' ',')
        services=$(grep -oP '\d+/open/[^/]+//[^/]+//[^/]+' "$gnmap_file" | sed 's#//# #g')
        echo "Target: $target_domain\nHost: $host\nOpen ports: $open_ports\nServices:\n$services" >>"$SUMMARY_FILE"
        while IFS= read -r service_line; do
            port=$(echo "$service_line" | awk '{print $1}' | cut -d'/' -f1)
            service=$(echo "$service_line" | awk '{print $2}')
            [[ " ${INTERESTING_SERVICES[*]} " =~ " ${service} " || " ${INTERESTING_PORTS[*]} " =~ " ${port} " ]] && echo "$service_line" >>"$POINTERS_FILE"
        done <<<"$services"
        grep -oP '\d+/open/[^/]+//[^/]+//[^/]+' "$gnmap_file" | awk -F'//' '{print $2, $3}' >>"$SERVICES_FILE"
    done
    sort -u "$SERVICES_FILE" -o "$SERVICES_FILE"
    [[ -s "$SERVICES_FILE" ]] && while IFS= read -r service; do
        searchsploit "$service" >>"$SEARCHSPLOIT_RESULTS"
    done <"$SERVICES_FILE"
}

# Fetch robots.txt from target domains
robots() {
    local orgs="$1"
    mkdir -p "$ROBOTS_DIR"
    { cat "$APIDOMAINS" "$orgs"; } | sort -u | while IFS= read -r org; do
        [[ -z "$org" ]] && continue
        clean_org=$(echo "$org" | sed -e 's#http[s]*://##' -e 's#www\.##')
        curl -s -m 10 -o "$ROBOTS_DIR/$clean_org.robots.txt" "$org/robots.txt"
        [[ -f "$ROBOTS_DIR/$clean_org.robots.txt" ]] && grep -E '^(Disallow|Allow): ' "$ROBOTS_DIR/$clean_org.robots.txt" | sed -E "s#^(Disallow|Allow): (.*)#https://$org\2#g" >"$ROBOTS_DIR/$clean_org.robots.urls"
    done
}

# Perform passive reconnaissance
passive_recon() {
    [[ -n "$ORGANIZATION" ]] && generate_dork_links -oR "$ORGANIZATION" --api && robots "$DOMAINS"
    [[ -n "$WILDCARDS" && -s "$WILDCARDS" ]] && generate_dork_links -L "$WILDCARDS" --api && robots "$WILDCARDS" "$APIDOMAINS"
    [[ -n "$DOMAINS" && -s "$DOMAINS" ]] && robots "$DOMAINS"
}

# Fuzz API endpoints
fuzz_directories() {
    mkdir -p "$FUZZING_DIR/ffuf"
    cat "$API_WILD_501" "$SECLIST_API_LONGEST" "$CUSTOM_PROJECT_SPECIFIC" | anew >"$FUZZING_DIR/fuzzme"
}

# Main function
main() {
    get_params "$@"
    passive_recon
    fuzz_directories
    [[ -n "$DOMAINS" && -s "$DOMAINS" ]] && scan_network "$DOMAINS"
    [[ -n "$APIDOMAINS" && -s "$APIDOMAINS" ]] && scan_network "$APIDOMAINS"
    process_gnmap
}

main "$@"
