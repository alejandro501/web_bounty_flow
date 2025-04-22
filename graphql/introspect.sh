#!/bin/bash

INTROSPECTION_RESULTS_DIR="introspection_results"

# color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
PURPLE='\033[0;35m' # no Color

# universal introspection query
INTROSPECTION_QUERY='{"query":"{__schema{types{name,fields{name,args{name,description,type{name,kind,ofType{name,kind}}}}}}}"}'

perform_introspection() {
    local url="$1"
    echo -e "${PURPLE}Trying introspection on $url${NC}"
    
    response=$(curl -s -X POST -H "Content-Type: application/json" --data "$INTROSPECTION_QUERY" "$url")
    
    if [[ $response == *"__schema"* ]]; then
        echo -e "${GREEN}Introspection successful for $url${NC}"
        echo "$response" > "$INTROSPECTION_RESULTS_DIR/introspection_$(echo $url | sed 's/[^a-zA-Z0-9]/_/g').txt"
    else
        echo -e "${RED}Introspection failed or disabled for $url${NC}"
    fi
}

main() {
    INPUT_FILE="${1:-graphql.txt}"

    while read -r endpoint; do
        if [ -n "$endpoint" ]; then
            perform_introspection "$endpoint"
        fi
    done < "$INPUT_FILE"
}

main "$@"
