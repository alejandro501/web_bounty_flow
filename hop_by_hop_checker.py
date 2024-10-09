import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse

# Suppress only the InsecureRequestWarning from urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

# Function to check vulnerability for each subdomain
def check_hop_by_hop_vulnerability(subdomain, proxies=None, verify=False, output_file=None, differing_status_file=None, statuses_file=None, no_log=False):
    try:
        # 1. Send baseline request (without hop-by-hop headers)
        baseline_response = requests.get(subdomain, timeout=5, proxies=proxies, verify=verify)

        # 2. Send request with hop-by-hop headers
        manipulated_response = requests.get(subdomain, headers=headers_to_test, timeout=5, proxies=proxies, verify=verify)

        # 3. Check if responses differ in ways that indicate vulnerabilities
        if baseline_response.status_code != manipulated_response.status_code:
            print(f"[!] Potential vulnerability detected on {subdomain} (status codes differ: {baseline_response.status_code} vs {manipulated_response.status_code})")
            if not no_log:
                log_vulnerability(subdomain, baseline_response.status_code, manipulated_response.status_code, output_file)  # Log to vulnerable file
                log_differing_status(subdomain, baseline_response.status_code, manipulated_response.status_code, differing_status_file)  # Log differing status
                log_status(subdomain, baseline_response.status_code, manipulated_response.status_code, statuses_file)  # Log statuses
        elif baseline_response.text != manipulated_response.text:
            print(f"[!] Potential vulnerability detected on {subdomain} (response content differs)")
            if not no_log:
                log_vulnerability(subdomain, baseline_response.status_code, manipulated_response.status_code, output_file)
                log_status(subdomain, baseline_response.status_code, manipulated_response.status_code, statuses_file)
        else:
            print(f"[-] No vulnerability detected on {subdomain}")

    except requests.RequestException as e:
        print(f"[-] Error with {subdomain}: {e}")

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
                print(f"[!] Error occurred for {subdomain}: {exc}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check hop-by-hop header vulnerabilities.")
    parser.add_argument('--file', type=str, default='live_subdomains.txt', help='Input file with subdomains')
    parser.add_argument('--output', type=str, default='hop_by_hop.txt', help='Output file for vulnerabilities')
    parser.add_argument('--differing-status-output', type=str, default='hop_by_hop_differing_status.txt', help='File for subdomains with differing status codes')
    parser.add_argument('--statuses-output', type=str, default='hop_by_hop_statuses.txt', help='File for vulnerable subdomains and their status codes')
    parser.add_argument('--port', type=int, help='Specify a proxy port (optional)', default=None)
    parser.add_argument('--threads', type=int, default=5, help='Number of threads to use (default: 5)')
    parser.add_argument('--ca', type=str, help='Path to the custom CA certificate (optional)', default=None)
    parser.add_argument('--no-log', action='store_true', help='Disable output logging to files')

    args = parser.parse_args()

    proxies = None
    if args.port:
        proxies = {
            'http': f'http://localhost:{args.port}',
            'https': f'http://localhost:{args.port}',
        }
        print(f"Using proxy on port {args.port} for forwarding requests...")

    subdomains = load_subdomains(args.file)

    run_checks_in_threads(subdomains, proxies, verify=args.ca is not None, max_workers=args.threads, output_file=args.output, differing_status_file=args.differing_status_output, statuses_file=args.statuses_output, no_log=args.no_log)
