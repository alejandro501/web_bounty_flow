import requests
import argparse
import setup_tor
import time

def main(input_file, output_file, log_file, use_tor):
    if use_tor and not setup_tor.check_tor():
        print("Exiting due to Tor not being accessible.")
        return

    proxies = {
        'http': 'socks5h://localhost:9050',
        'https': 'socks5h://localhost:9050',
    } if use_tor else {}

    # Timeout for unresponsive calls
    timeout = 25

    with open(input_file, 'r') as f:
        domains = f.read().splitlines()

    with open(log_file, 'w') as log:
        with open(output_file, 'a') as out:  # Open output file in append mode
            for domain in domains:
                try:
                    print(f"Probing {domain} ...")
                    # Normal request
                    start_time = time.time()
                    response_normal = requests.get(domain, proxies=proxies, timeout=timeout)
                    orig_response = response_normal.text
                    orig_content_type = response_normal.headers.get('Content-Type', '')
                    elapsed_time = time.time() - start_time

                    if elapsed_time > timeout:
                        log.write(f"Timeout exceeded for normal request to {domain}: {elapsed_time:.2f} seconds\n")
                        log.flush()

                    # Request with X-Forwarded-For header
                    start_time = time.time()
                    headers = {'X-Forwarded-For': '127.0.0.1'}
                    response_modified = requests.get(domain, headers=headers, proxies=proxies, timeout=timeout)
                    modified_response = response_modified.text
                    modified_content_type = response_modified.headers.get('Content-Type', '')
                    elapsed_time = time.time() - start_time

                    if elapsed_time > timeout:
                        log.write(f"Timeout exceeded for modified request to {domain}: {elapsed_time:.2f} seconds\n")
                        log.flush()

                    # Compare responses
                    if orig_response != modified_response:
                        # Log HTML responses differently
                        orig_log_response = 'html...' if 'text/html' in orig_content_type else orig_response
                        modified_log_response = 'html...' if 'text/html' in modified_content_type else modified_response
                        
                        out.write(domain + '\n')  # Write to output file in real time
                        out.flush()  # Flush the output buffer immediately
                        log.write(f"## {domain}\n### original:\n```sh\n{orig_log_response}\n```\n### modified:\n```sh\n{modified_log_response}\n```\n\n")
                        log.flush()  # Ensure the log is updated immediately

                except requests.RequestException as e:
                    print(f"Error accessing {domain}: {e}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Compare HTTP responses with and without X-Forwarded-For header.')
    parser.add_argument('--input', '-I', default='domains.txt', help='Input file with domain names')
    parser.add_argument('--output', '-O', default='x_forwarded_for.txt', help='Output file for different URLs')
    parser.add_argument('--log', '-L', default='x_forwarded_diff.md', help='Log file for response differences')
    parser.add_argument('--tor', action='store_true', help='Use Tor proxy for requests')
    args = parser.parse_args()

    main(args.input, args.output, args.log, args.tor)
