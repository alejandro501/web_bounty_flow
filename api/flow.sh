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

# Scans the network for the provided list of organizations using nmap
scan_network() {
    local orgs_file="$1"
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
    done <"$orgs_file"
}

nmap() {
    if [[ -n "$DOMAINS" && -s "$DOMAINS" ]]; then
        echo "Scanning DOMAINS: $DOMAINS"
        scan_network "$DOMAINS"
    else
        echo "DOMAINS is either missing or empty. Skipping domain-based scanning."
    fi

    if [[ -n "$APIDOMAINS" && -s "$APIDOMAINS" ]]; then
        echo "Scanning APIDOMAINS: $APIDOMAINS"
        scan_network "$APIDOMAINS"
    else
        echo "APIDOMAINS is either missing or empty. Skipping API domain-based scanning."
    fi
}

passive_recon() {
    if [[ -n "$ORGANIZATION" ]]; then
        generate_dork_links -oR "$ORGANIZATION" --api
        robots "$DOMAINS"
    fi

    if [[ -n "$WILDCARDS" && -s "$WILDCARDS" ]]; then
        subfinder -dL "$WILDCARDS" | anew $DOMAINS | grep api | httprobe --prefer-https | anew "$APIDOMAINS"
        generate_dork_links -L "$WILDCARDS" --api
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
    nmap
}

main "$@"
