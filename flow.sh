#!/bin/bash

# Parse command-line arguments
USE_TOR=false

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --tor) USE_TOR=true ;;
    esac
    shift
done

source ./setup_tor.sh
setup_tor "$USE_TOR"

# Check if necessary tools are installed
check_tool() {
    if ! command -v "$1" &>/dev/null; then
        echo "$1 is not installed. Please install it first."
        exit 1
    fi
}

check_tool "subfinder"
check_tool "httprobe"
check_tool "anew"

# Ensure necessary file exists
if [ ! -f wildcards.txt ]; then
    echo "The wildcards.txt file does not exist."
    exit 1
fi

echo "Starting subdomain enumeration..."
./enumerate_subdomains.sh

echo "Sorting subdomains by status code..."
python sort_subdomains.py

echo "Running hop-by-hop checker..."
python hop_by_hop_checker.py

echo "Running toxicache..."
./toxicache.sh

echo "Checking for request smuggling..."
python request_smuggling.py

echo "Checking h2c smuggling..."
./h2csmuggler.sh

echo "Running SSI/ESI injection tests..."
python ssi_esi.py

echo "Reminder: Run cloudflare.py manually due to prompt interaction."
