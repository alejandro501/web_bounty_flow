#!/bin/bash

# Parse command-line arguments
USE_TOR=false

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --tor) USE_TOR=true ;;
        *) echo "Usage: $0 [--tor]"; exit 1 ;;
    esac
    shift
done

source ./setup_tor.sh
setup_tor "$USE_TOR"

enumerate_subdomains() {
    if ! command -v subfinder &>/dev/null; then
        echo "Subfinder is not installed. Please install it first."
        exit 1
    fi

    if ! command -v httprobe &>/dev/null; then
        echo "httprobe is not installed. Please install it first."
        exit 1
    fi

    if [ ! -f wildcards.txt ]; then
        echo "The wildcards.txt file does not exist."
        exit 1
    fi

    echo "Starting subdomain enumeration..."
    echo -n >subdomains.txt

    while read -r domain; do
        echo "Finding subdomains for: $domain"
        subfinder -d "$domain" -all -o temp_subdomains.txt

        if [[ -s temp_subdomains.txt ]]; then
            echo "Subdomains found for $domain:"
            cat temp_subdomains.txt
            cat temp_subdomains.txt >>subdomains.txt
        else
            echo "No subdomains found for $domain."
        fi
    done <wildcards.txt

    echo "Probing live subdomains..."
    cat subdomains.txt | httprobe -c 50 --prefer-https | anew live_subdomains.txt | sort

    echo "Subdomain enumeration completed."
    echo "Results saved in live_subdomains.txt."

    # Cleanup
    rm temp_subdomains.txt
}

# Call the function
enumerate_subdomains
