#!/bin/bash

# Define the input and output files
INPUT_FILE="live_subdomains.txt"
OUTPUT_FILE="toxicache.log"
DOMAINS_FILE="toxicache_domains.txt"

# Parse command-line arguments
USE_TOR=false

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --tor)
            USE_TOR=true ;;
        *)
            echo "Usage: $0 [--tor]"; exit 1 ;;
    esac
    shift
done

# Source the setup_tor.sh script
source ./setup_tor.sh

# Setup Tor if the flag is set
setup_tor "$USE_TOR"

# Function to run the toxicache tool
run_toxicache() {
    # Check if the input file exists
    if [[ ! -f $INPUT_FILE ]]; then
        echo "Input file $INPUT_FILE does not exist."
        exit 1
    fi

    # Run the toxicache program with specified input and output
    toxicache -i "$INPUT_FILE" -o "$OUTPUT_FILE"

    # Extract domains from the output file and save them to toxicache_domains.txt
    grep -oP '(?<=@ )http[s]?://[^ ]+' "$OUTPUT_FILE" | sort -u > "$DOMAINS_FILE"

    # Notify the user that the domains have been extracted
    echo "Domains have been extracted to $DOMAINS_FILE."
}

# Call the run_toxicache function
run_toxicache
