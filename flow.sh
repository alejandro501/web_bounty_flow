#!/bin/bash

# Parse command-line arguments
USE_TOR=false

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --tor) USE_TOR=true ;;
    esac
    shift
done

setup_tor

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

check_tool "enumerate_subdomains"
check_tool "sort_http"

# Starting subdomain enumeration...
enumerate_subdomains -I wildcards

echo "Sorting subdomains by status code..."
sort_http -I subdomains

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
