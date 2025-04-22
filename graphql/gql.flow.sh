#!/bin/bash

GRAPHQL_FILE="graphql.txt"

if [ ! -d "graphw00f" ]; then
    echo "Cloning graphw00f repository..."
    git clone https://github.com/dolevf/graphw00f.git
    if [ $? -ne 0 ]; then
        echo "Error cloning graphw00f. Exiting."
        exit 1
    fi
fi

mkdir -p "introspection_results"
mkdir -p "fingerprint_results"

main() {
    INPUT_FILE="${1:-$GRAPHQL_FILE}"

    echo "Starting fingerprinting..."
    ./fingerprint.sh "$INPUT_FILE"

    echo "Starting introspection..."
    ./introspect.sh "$INPUT_FILE"
}

main "$@"
