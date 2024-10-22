#!/bin/bash

# Function to set up Tor if required
setup_tor() {
    if [[ "$1" == true ]]; then
        export https_proxy=socks5://127.0.0.1:9050
        export http_proxy=socks5://127.0.0.1:9050
        echo "Running everything through Tor..."
    fi
}
