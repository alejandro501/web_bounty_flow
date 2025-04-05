#!/bin/bash

if [[ -f "flow.conf" ]]; then
    source "flow.conf"
else
    echo "Error: flow.conf not found!"
    exit 1
fi

# Displays usage information and examples for the script
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

# Fetches robots.txt files and extracts disallowed paths/sitemaps
robots() {
    local orgs="$1"
    echo "fetching robots.txt for $orgs..."

    mkdir -p "$ROBOTS_DIR/$ROBOTS_HITS_DIR"
    mkdir -p "$ROBOTS_DIR/$ROBOTS_NO_HITS_DIR"

    { cat "$APIDOMAINS" "$orgs"; } | sort -u | while IFS= read -r org; do
        [[ -z "$org" ]] && continue
        clean_org=$(echo "$org" | sed -e 's#http[s]*://##' -e 's#www\.##')
        robots_url="$org/robots.txt"
        robots_file="$ROBOTS_DIR/$clean_org.robots.txt"
        robots_urls_file="$ROBOTS_DIR/$clean_org.robots.urls"

        robots_content=$(curl -s -m 10 "$robots_url")
        echo -e "$robots_url\n----------------------------------------------------------\n$robots_content" >"$robots_file"

        if [[ -f "$robots_file" ]]; then
            grep -E '^(Disallow): ' "$robots_file" | sed -E "s#^(Disallow): (.*)#https://$org\2#g" >"$robots_urls_file"

            if [[ -s "$robots_urls_file" ]]; then
                mv "$robots_file" "$ROBOTS_DIR/$ROBOTS_HITS_DIR/"
                mv "$robots_urls_file" "$ROBOTS_DIR/$ROBOTS_HITS_DIR/"
                cat "$ROBOTS_DIR/$ROBOTS_HITS_DIR/$clean_org.robots.urls" >>"$ROBOTS_DIR/_hits.txt"
                echo "robots.txt found for $org (URLs found, moved to hits folder)"

                if [[ -f "$ROBOTS_DIR/_hits.txt" ]]; then
                    echo "source $ROBOTS_DIR/_hits.txt" >>"$ROBOTS_DIR/flow.conf"
                fi

                sitemap_url=$(grep -i '^Sitemap:' "$ROBOTS_DIR/$ROBOTS_HITS_DIR/$clean_org.robots.txt" | sed -E 's#^Sitemap:[[:space:]]*(.*)#\1#')
                if [[ -n "$sitemap_url" ]]; then
                    echo "$sitemap_url" >>"${ROBOTS_DIR}/${SITEMAPS_FILE}"
                    echo "Sitemap found for $org: $sitemap_url"
                fi
            else
                mv "$robots_file" "$ROBOTS_DIR/$ROBOTS_NO_HITS_DIR/"
                mv "$robots_urls_file" "$ROBOTS_DIR/$ROBOTS_NO_HITS_DIR/"
                echo "robots.txt found for $org (No URLs found, moved to no_hits folder)"
            fi
        fi
    done
}

#!/bin/bash

# Scans the network using targets from a given file
scan_network() {
    local input_file="$1"
    mkdir -p "$NMAP_DIR"

    if [[ ! -f "$input_file" || ! -r "$input_file" ]]; then
        echo "Error: Input file '$input_file' not found or not readable!"
        return 1
    fi

    echo "Reading targets from: $input_file"

    while IFS= read -r target || [[ -n "$target" ]]; do
        target=$(echo "$target" | sed -e 's/#.*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
        [[ -z "$target" ]] && continue

        echo "Scanning target: $target"

        clean_target=$(echo "$target" | sed -e 's#http[s]*://##' -e 's#www\.##' | tr -d '/:')

        # Basic scan is currently disabled, you can choose to use it instead of verbose, or you can use both
        # echo "Running basic scan..."
        # nmap -sC -sV "$clean_target" -oA "$NMAP_DIR/${clean_target}.scsv"

        echo "Running full port scan..."
        nmap -p- "$clean_target" -oA "$NMAP_DIR/${clean_target}.allports"
    done <"$input_file" # THIS IS THE CRUCIAL FIX - reads file content
}

process_gnmap() {
    if [[ "$ENABLE_NMAP_SUMMARY" != true ]]; then
        echo "[++] Nmap summary processing is disabled. Skipping."
        return
    fi

    echo "[+] Processing .gnmap files in $NMAP_DIR..."

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

# Main scanning function
nmap_scan() {
    # Domain scanning
    if [[ -n "$DOMAINS" && -s "$DOMAINS" ]]; then
        echo "=== Starting Domain Scans ==="
        scan_network "$DOMAINS"
    else
        echo "DOMAINS not specified or file empty. Skipping domain scans."
    fi

    # API Domain scanning
    if [[ -n "$APIDOMAINS" && -s "$APIDOMAINS" ]]; then
        echo "=== Starting API Domain Scans ==="
        scan_network "$APIDOMAINS"
    else
        echo "APIDOMAINS not specified or file empty. Skipping API scans."
    fi

    process_gnmap
}

passive_recon() {
    # if organization file is filled
    if [[ -n "$ORGANIZATIONS" && -s "$ORGANIZATIONS" ]]; then
        generate_dork_links -oR "$ORGANIZATIONS" --api
    fi

    if [[ -n "$WILDCARDS" && -s "$WILDCARDS" ]]; then
        subfinder -dL "$WILDCARDS" | anew $DOMAINS

        # after subfinder remove domains that are present in the out-of-scope file
        sed -i -f <(sed 's/.*/\/&\/d/' "$OUT_OF_SCOPE_DOMAINS") "$DOMAINS"

        cat $DOMAINS | grep api | httprobe --prefer-https | anew "$APIDOMAINS"

        generate_dork_links -L "$WILDCARDS" --api
        generate_dork_links -L "$DOMAINS" --api
        generate_dork_links -L "$APIDOMAINS" --api

        # distribute dork links into corresponding folders
        mkdir -p $DORKING_DIR/shodan && find . -maxdepth 1 -type f -name "*shodan*" -exec mv {} $DORKING_DIR/shodan/ \;
        mkdir -p $DORKING_DIR/github && find . -maxdepth 1 -type f -name "*github*" -exec mv {} $DORKING_DIR/github/ \;
        mkdir -p $DORKING_DIR/google && find . -maxdepth 1 -type f -name "*google*" -exec mv {} $DORKING_DIR/google/ \;
        mkdir -p $DORKING_DIR/wayback && find . -maxdepth 1 -type f -name "*wayback*" -exec mv {} $DORKING_DIR/wayback/ \;

        robots "$WILDCARDS"
        robots "$DOMAINS"
        robots "$APIDOMAINS"
    fi

    if [[ -n "$DOMAINS" && -s "$DOMAINS" ]]; then
        robots "$DOMAINS"
    else
        echo "DOMAINS is either missing or empty. Skipping domain-based operations."
    fi

    if [[ -n "$APIDOMAINS" && -s "$APIDOMAINS" ]]; then
        echo "APIDOMAINS is available for further processing."
    else
        echo "APIDOMAINS is either missing or empty. Skipping API domain-based operations."
    fi
}

# Fuzzes directories on target URLs using ffuf
fuzz_directories() {
    mkdir -p "$FUZZING_DIR"
    mkdir -p "${FUZZING_DIR}/${FFUF_DIR}"
    mkdir -p "${FUZZING_DIR}/${FFUF_DIR}/${FUZZING_ENDPOINT_HITS_DIR}"
    mkdir -p "${FUZZING_DIR}/${FFUF_DIR}/${FUZZING_ENDPOINT_NO_HITS_DIR}"

    cat "$API_WILD_501" "$SECLIST_API_LONGEST" "$CUSTOM_PROJECT_SPECIFIC" | anew >"$FUZZING_DIR/fuzzme"

    if [[ -s "$APIDOMAINS" || -s "$WILDCARDS" ]]; then
        (cat "$APIDOMAINS" "$WILDCARDS") | while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            echo "Fuzzing for $url"

            output_file="${FUZZING_DIR}/${FFUF_DIR}/$(basename "$url").csv"

            ffuf -u "${url}/FUZZ" -w "$FUZZING_DIR/fuzzme" -mc 200,301 -p 0.2 -o "$output_file" -of csv

            if grep -q "^[^,]\+," "$output_file"; then
                awk -F',' 'NR>1 {print $2 > ("'"${FUZZING_DIR}/${FFUF_DIR}/${FUZZING_ENDPOINT_HITS_DIR}/"'" $1 ".txt")}' "$output_file"
                awk -F',' 'NR>1 {print $2}' "$output_file" >>"${FUZZING_DIR}/${FFUF_DIR}/${FUZZING_ENDPOINT_HITS_DIR}/${ALL_HITS_FILE}"
            else
                mv "$output_file" "${FUZZING_DIR}/${FFUF_DIR}/${FUZZING_ENDPOINT_NO_HITS_DIR}/"
            fi
        done
    else
        echo "Skipping fuzzing as the apidomain output or wildcards file is empty."
    fi
}

# Fuzzes documentation endpoints on target URLs using ffuf
fuzz_documentation() {
    mkdir -p "${FUZZING_DIR}/documentation"
    local targets=()

    if [[ -s "$ORGANIZATIONS" ]]; then
        while IFS= read -r org_line; do
            [[ -n "$org_line" ]] && targets+=("$org_line")
        done <"$ORGANIZATIONS"
    fi

    if [[ -s "$WILDCARDS" ]]; then
        targets+=($(<"$WILDCARDS"))
    fi

    if [[ -f "$APIDOMAINS" && -s "$APIDOMAINS" ]]; then
        targets+=($(<"$APIDOMAINS"))
    fi

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
    passive_recon # dorking, robots
    fuzz_documentation # fuzzing for documentation with ffuf
    fuzz_directories
    nmap_scan # scan domains and apidomans
    # scan_network $IPS # scan manually added ip's after shodan recon
    # process_gnmap # run manually after new ip scans, it's also in default nmap_scan function
}

main "$@"
