#!/bin/bash
# This script retrieves robots.txt files from a list of domains and saves the content to an output file.

usage() {
    echo "Usage: $0 --input <input_file> --output <output_file>"
    echo "Usage: $0 -I <input_file> -O <output_file>"
    exit 1
}

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --input|-I) input_file="$2"; shift ;;
        --output|-O) output_file="$2"; shift ;;
        *) usage ;;
    esac
    shift
done

if [[ -z "$input_file" || -z "$output_file" ]]; then
    usage
fi

> "$output_file"

while IFS= read -r domain; do
    if [[ -n "$domain" ]]; then
        echo "# $domain" >> "$output_file"
        curl -s "$domain/robots.txt" >> "$output_file"
        echo -e "\n" >> "$output_file"
    fi
done < "$input_file"

echo "Robots.txt content saved to $output_file"
