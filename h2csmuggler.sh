#!/bin/bash

DEFAULT_INPUT="live_subdomains.txt"
DEFAULT_OUTPUT="h2csmuggler.log"

usage() {
    echo "Usage: $0 [--input <input_file>] [--output <output_file>] [--tor]"
    echo "  --input  Specify the input file (default: $DEFAULT_INPUT)"
    echo "  --output Specify the output file (default: $DEFAULT_OUTPUT)"
    echo "  --tor    Run through Tor"
    exit 1
}

USE_TOR=false

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --input)
            INPUT="$2"
            shift ;;
        --output)
            OUTPUT="$2"
            shift ;;
        --tor)
            USE_TOR=true ;;
        *)
            usage ;;
    esac
    shift
done

INPUT="${INPUT:-$DEFAULT_INPUT}"
OUTPUT="${OUTPUT:-$DEFAULT_OUTPUT}"

source ./setup_tor.sh
setup_tor "$USE_TOR"

if [[ ! -f "$INPUT" ]]; then
    echo "Error: Input file '$INPUT' does not exist."
    exit 1
fi

# Check if h2csmuggler is installed
if ! command -v h2csmuggler > /dev/null 2>&1; then
    echo "Error: h2csmuggler is not installed or not in the PATH."
    exit 1
fi

echo "Running h2csmuggler with input: $INPUT and output: $OUTPUT"

# Run h2csmuggler with specified input and output
echo "Executing h2csmuggler command..."
RESULT=$(h2csmuggler smuggle $(cat "$INPUT") 2>&1)

if [[ $? -ne 0 ]]; then
    echo "Error: h2csmuggler failed with the following output:"
    echo "$RESULT"
    exit 1
else
    echo "$RESULT" > "$OUTPUT"
fi

echo "Output written to $OUTPUT"
