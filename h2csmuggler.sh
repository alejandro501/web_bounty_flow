#!/bin/bash

# Default input and output files
DEFAULT_INPUT="live_subdomains.txt"
DEFAULT_OUTPUT="h2csmuggler.log"

# Function to display usage
usage() {
    echo "Usage: $0 [--input <input_file>] [--output <output_file>] [--tor]"
    echo "  --input  Specify the input file (default: $DEFAULT_INPUT)"
    echo "  --output Specify the output file (default: $DEFAULT_OUTPUT)"
    echo "  --tor    Run through Tor"
    exit 1
}

# Parse command-line arguments
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

# Set input and output to defaults if not specified
INPUT="${INPUT:-$DEFAULT_INPUT}"
OUTPUT="${OUTPUT:-$DEFAULT_OUTPUT}"

source ./setup_tor.sh
setup_tor "$USE_TOR"

# Check if the input file exists
if [[ ! -f "$INPUT" ]]; then
    echo "Error: Input file '$INPUT' does not exist."
    exit 1
fi

# Check if h2csmuggler is installed
if ! command -v h2csmuggler > /dev/null 2>&1; then
    echo "Error: h2csmuggler is not installed or not in the PATH."
    exit 1
fi

# Inform about the input and output being used
echo "Running h2csmuggler with input: $INPUT and output: $OUTPUT"

# Run h2csmuggler with specified input and output
echo "Executing h2csmuggler command..."
RESULT=$(h2csmuggler smuggle $(cat "$INPUT") 2>&1)

# Check if the command was successful
if [[ $? -ne 0 ]]; then
    echo "Error: h2csmuggler failed with the following output:"
    echo "$RESULT"
    exit 1
else
    echo "$RESULT" > "$OUTPUT"
fi

# Notify user of completion
echo "Output written to $OUTPUT"
