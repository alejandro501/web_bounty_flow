#!/bin/bash

# Source the configuration file
if [[ -f "flow.conf" ]]; then
    source "flow.conf"
else
    echo "Error: flow.conf not found. Please create the configuration file."
    exit 1
fi

usage() {
    echo "Usage: $0 [options]"
    echo "
    Input Feed:
    -org,  --organization <org>       specify a single organization.
    -ol,  --org-list <filename>      specify a file containing a list of organizations (one per line).

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

process_gnmap() {
    if [[ "$ENABLE_NMAP_SUMMARY" != true ]]; then
        echo "[++] Nmap summary processing is disabled. Skipping."
        return
    fi

    echo "[+] Processing .gnmap files in $NMAP_DIR..."

    # Ensure the NMAP_DIR exists
    mkdir -p "$NMAP_DIR"

    # Create empty output files
    >"$SUMMARY_FILE"
    >"$POINTERS_FILE"
    >"$SERVICES_FILE"
    >"$SEARCHSPLOIT_RESULTS"

    # Process each .gnmap file in the NMAP_DIR
    for gnmap_file in "$NMAP_DIR"/*.gnmap; do
        [[ ! -f "$gnmap_file" ]] && continue
        echo "[++] Processing $gnmap_file..."

        # Extract target domain and host
        target_domain=$(grep -oP 'Nmap .* scan initiated .* as: nmap .* \K[^ ]+' "$gnmap_file")
        host=$(grep -oP 'Host: \K[^ ]+' "$gnmap_file")
        echo "-------
Target: $target_domain
Host: $host" >>"$SUMMARY_FILE"

        # Extract open ports and services
        open_ports=$(grep -oP '\d+/open' "$gnmap_file" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$/\n/')
        services=$(grep -oP '\d+/open/[^/]+//[^/]+//[^/]+' "$gnmap_file" | sed 's#//# #g')

        # Write open ports and services to the summary file
        echo "Open ports: $open_ports" >>"$SUMMARY_FILE"
        echo "Services:" >>"$SUMMARY_FILE"
        echo "$services" >>"$SUMMARY_FILE"

        # Check for interesting services/ports
        interesting_found=false
        while IFS= read -r service_line; do
            port=$(echo "$service_line" | awk '{print $1}' | cut -d'/' -f1)
            service=$(echo "$service_line" | awk '{print $2}')
            version=$(echo "$service_line" | awk '{print $3}')

            if [[ " ${INTERESTING_SERVICES[*]} " =~ " ${service} " ]] || [[ " ${INTERESTING_PORTS[*]} " =~ " ${port} " ]]; then
                if [[ "$interesting_found" == false ]]; then
                    echo "Interesting services found on $host ($target_domain):" >>"$POINTERS_FILE"
                    interesting_found=true
                fi
                echo "$service_line" >>"$POINTERS_FILE"
            fi
        done <<<"$services"

        # Extract services for searchsploit
        grep -oP '\d+/open/[^/]+//[^/]+//[^/]+' "$gnmap_file" | awk -F'//' '{print $2, $3}' >>"$SERVICES_FILE"
    done

    # Sort and deduplicate services
    sort -u "$SERVICES_FILE" -o "$SERVICES_FILE"

    # Run searchsploit on discovered services
    if [[ -s "$SERVICES_FILE" ]]; then
        echo "[++] Running searchsploit on services..."
        while IFS= read -r service; do
            echo "Searching for exploits for: $service" >>"$SEARCHSPLOIT_RESULTS"
            searchsploit "$service" >>"$SEARCHSPLOIT_RESULTS"
            echo "-----------------------------" >>"$SEARCHSPLOIT_RESULTS"
        done <"$SERVICES_FILE"
    else
        echo "[++] No services found for searchsploit."
    fi

    echo "[+] Nmap summary processing complete. Results saved to:"
    echo "- $SUMMARY_FILE"
    echo "- $POINTERS_FILE"
    echo "- $SERVICES_FILE"
    echo "- $SEARCHSPLOIT_RESULTS"
}

robots() {
    local orgs="$1"
    echo "fetching robots.txt for $orgs..."

    mkdir -p "$ROBOTS_DIR"

    { cat "$APIDOMAINS" "$orgs"; } | sort -u | while IFS= read -r org; do
        [[ -z "$org" ]] && continue
        clean_org=$(echo "$org" | sed -e 's#http[s]*://##' -e 's#www\.##')
        curl -s -m 10 -o "$ROBOTS_DIR/$clean_org.robots.txt" "$org/robots.txt"

        if [[ -f "$ROBOTS_DIR/$clean_org.robots.txt" ]]; then
            grep -E '^(Disallow): ' "$ROBOTS_DIR/$clean_org.robots.txt" | sed -E "s#^(Disallow|Allow): (.*)#https://$org\2#g" >"$ROBOTS_DIR/$clean_org.robots.urls"
            echo "robots.txt found for $org"
        fi
    done
}

passive_recon() {
    # Handle ORGANIZATION if provided
    if [[ -n "$ORGANIZATION" ]]; then
        generate_dork_links -oR "$ORGANIZATION" --api
        robots "$DOMAINS"
    fi

    # Handle WILDCARDS if provided
    if [[ -n "$WILDCARDS" && -s "$WILDCARDS" ]]; then
        generate_dork_links -L "$WILDCARDS" --api
        robots "$WILDCARDS"
        robots "$APIDOMAINS"
        subfinder -dL "$WILDCARDS" | grep api | httprobe --prefer-https | anew "$APIDOMAINS"
        ./amass.sh -L "$WILDCARDS"
    fi

    # Handle DOMAINS independently if no WILDCARDS or others
    if [[ -n "$DOMAINS" && -s "$DOMAINS" ]]; then
        robots "$DOMAINS"
    else
        echo "DOMAINS is either missing or empty. Skipping domain-based operations."
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
        done <"$ORGANIZATIONS"
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
    get_params "$@"
    passive_recon
    fuzz_documentation
    fuzz_directories
    # manual: check shodan dork hits and add valid ip's to $IPS

    # Perform network scan as the final step
    if [[ -n "$DOMAINS" && -s "$DOMAINS" ]]; then
        scan_network "$DOMAINS"
    elif [[ -n "$APIDOMAINS" && -s "$APIDOMAINS" ]]; then
        scan_network "$APIDOMAINS"
    elif [[ -n "$WILDCARDS" && -s "$WILDCARDS" ]]; then
        scan_network "$WILDCARDS"
    else
        echo "No valid targets found for network scanning."
    fi

    # Process Nmap results
    process_gnmap
}

main "$@"
