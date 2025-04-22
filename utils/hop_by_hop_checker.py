#!/usr/bin/env python3

"""
Hop-by-Hop Header Vulnerability Checker
-------------------------------------
This script tests web servers for potential vulnerabilities related to hop-by-hop headers.
It works by:
1. Sending a baseline request without special headers
2. Sending a request with various hop-by-hop headers
3. Comparing responses to detect differences that might indicate vulnerabilities

The script can test either a single domain or a list of domains, and can run checks in parallel.
Results are logged to separate files for vulnerable domains, differing status codes, and all status codes.

Usage:
    python hop_by_hop_checker.py -d example.com
    python hop_by_hop_checker.py -l domains.txt
"""

import sys
import os
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import logging

# Suppress only the InsecureRequestWarning from urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Get the directory where the script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

headers_to_test = {
    'Connection': 'close',
    'X-Forwarded-For': '127.0.0.1',
    'Proxy-Connection': 'close'
}

# More advanced headers for test
additional_headers = {
    'Proxy-Authenticate': 'Basic realm="Secure Area"',
    'Proxy-Authorization': 'Basic QWxhZGRpbjpPcGVuU2VzYW1l',
    'TE': 'trailers',
    'Transfer-Encoding': 'chunked',
    'Upgrade': 'HTTP/2.0, SHTTP/1.3, IRC/6.9, websocket',
    'X-Http-Method-Override': 'PUT',
    'X-Requested-With': 'XMLHttpRequest',
    'X-Forwarded-Host': 'example.com',
    'X-Forwarded-Server': 'example.com',
    'X-Forwarded-Port': '443',
    'X-Forwarded-Proto': 'https'
}

def setup_logging():
    """Set up logging configuration"""
    log_dir = os.path.join(os.path.dirname(SCRIPT_DIR), "logs")
    os.makedirs(log_dir, exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(log_dir, "hop_by_hop.log")),
            logging.StreamHandler()
        ]
    )

def format_url(url):
    """Format URL to ensure it has a scheme"""
    if not url.startswith(('http://', 'https://')):
        return f'https://{url}'
    return url

def check_hop_by_hop_vulnerability(subdomain, proxies=None, verify=False, output_file=None, differing_status_file=None, statuses_file=None, no_log=False):
    try:
        url = format_url(subdomain)
        # 1. Send baseline request (without hop-by-hop headers)
        baseline_response = requests.get(url, timeout=5, proxies=proxies, verify=verify)

        # 2. Send request with hop-by-hop headers
        manipulated_response = requests.get(url, headers=headers_to_test, timeout=5, proxies=proxies, verify=verify)

        # 3. Check if responses differ in ways that indicate vulnerabilities
        if baseline_response.status_code != manipulated_response.status_code:
            logging.warning(f"Potential vulnerability detected on {url} (status codes differ: {baseline_response.status_code} vs {manipulated_response.status_code})")
            if not no_log:
                log_vulnerability(url, baseline_response.status_code, manipulated_response.status_code, output_file)
                log_differing_status(url, baseline_response.status_code, manipulated_response.status_code, differing_status_file)
                log_status(url, baseline_response.status_code, manipulated_response.status_code, statuses_file)
        elif baseline_response.text != manipulated_response.text:
            logging.warning(f"Potential vulnerability detected on {url} (response content differs)")
            if not no_log:
                log_vulnerability(url, baseline_response.status_code, manipulated_response.status_code, output_file)
                log_status(url, baseline_response.status_code, manipulated_response.status_code, statuses_file)
        else:
            logging.info(f"No vulnerability detected on {url}")

    except requests.RequestException as e:
        logging.error(f"Error with {url}: {e}")

def load_subdomains(file_path):
    with open(file_path, 'r') as file:
        return file.read().splitlines()

def log_vulnerability(subdomain, original_status, hopped_status, output_file):
    with open(output_file, 'a') as log_file:
        log_file.write(f"{subdomain}\n")

def log_differing_status(subdomain, original_status, hopped_status, differing_status_file):
    with open(differing_status_file, 'a') as status_file:
        status_file.write(f"{subdomain} | {original_status} | {hopped_status}\n")

def log_status(subdomain, original_status, hopped_status, statuses_file):
    with open(statuses_file, 'a') as log_file:
        log_file.write(f"{subdomain} | {original_status} | {hopped_status}\n")

def run_checks_in_threads(subdomains, proxies=None, verify=False, max_workers=5, output_file='hop_by_hop.txt', differing_status_file='hop_by_hop_differing_status.txt', statuses_file='hop_by_hop_statuses.txt', no_log=False):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_subdomain = {
            executor.submit(check_hop_by_hop_vulnerability, subdomain, proxies, verify, output_file, differing_status_file, statuses_file, no_log): subdomain
            for subdomain in subdomains
        }

        for future in as_completed(future_to_subdomain):
            subdomain = future_to_subdomain[future]
            try:
                future.result()
            except Exception as exc:
                logging.error(f"Error occurred for {subdomain}: {exc}")

def main():
    parser = argparse.ArgumentParser(description="Check hop-by-hop header vulnerabilities.")
    parser.add_argument('--domain', '-d', type=str, help='Single domain to check')
    parser.add_argument('--list', '-l', type=str, help='Input file with list of domains')
    parser.add_argument('--output', '-o', type=str, default='hop_by_hop.txt', help='Output file for vulnerabilities')
    parser.add_argument('--differing-status-output', '-ds', type=str, default='hop_by_hop_differing_status.txt', help='File for subdomains with differing status codes')
    parser.add_argument('--statuses-output', '-so', type=str, default='hop_by_hop_statuses.txt', help='File for vulnerable subdomains and their status codes')
    parser.add_argument('--port', '-p', type=int, help='Specify a proxy port (optional)', default=None)
    parser.add_argument('--threads', '-t', type=int, default=5, help='Number of threads to use (default: 5)')
    parser.add_argument('--ca', '-c', type=str, help='Path to the custom CA certificate (optional)', default=None)
    parser.add_argument('--no-log', '-q', action='store_true', help='Disable output logging to files')

    args = parser.parse_args()

    if not args.domain and not args.list:
        parser.error("Either --domain or --list must be specified")

    # Set up logging
    setup_logging()
    logging.info("Starting Hop-by-Hop header scan")

    # Set up output files
    output_dir = os.path.join(os.path.dirname(SCRIPT_DIR), "logs", "hop_by_hop")
    os.makedirs(output_dir, exist_ok=True)

    output_file = os.path.join(output_dir, args.output)
    differing_status_file = os.path.join(output_dir, args.differing_status_output)
    statuses_file = os.path.join(output_dir, args.statuses_output)

    proxies = None
    if args.port:
        proxies = {
            'http': f'http://localhost:{args.port}',
            'https': f'http://localhost:{args.port}',
        }
        logging.info(f"Using proxy on port {args.port} for forwarding requests...")

    if args.domain:
        subdomains = [args.domain]
    else:
        subdomains = load_subdomains(args.list)

    run_checks_in_threads(subdomains, proxies, verify=args.ca is not None, max_workers=args.threads, 
                         output_file=output_file, differing_status_file=differing_status_file, 
                         statuses_file=statuses_file, no_log=args.no_log)

if __name__ == "__main__":
    main()
