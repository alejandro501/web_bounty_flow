#!/bin/bash

# Define the input and output files
INPUT_FILE="live_subdomains.txt"
OUTPUT_FILE="toxicache.log"
DOMAINS_FILE="toxicache_domains.txt"

# Check if the input file exists
if [[ ! -f $INPUT_FILE ]]; then
    echo "Input file $INPUT_FILE does not exist."
    exit 1
fi

# Run the toxicache program with specified input and output
toxicache -i "$INPUT_FILE" -o "$OUTPUT_FILE"

# Extract domains from the output file and save them to toxicache.domains
grep -oP '(?<=@ )http[s]?://[^ ]+' "$OUTPUT_FILE" | sort -u > "$DOMAINS_FILE"

# Optional: Notify the user that the domains have been extracted
echo "Domains have been extracted to $DOMAINS_FILE."
