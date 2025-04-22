import os
import re
import requests
import time
import socket
import shutil
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote_plus

# Configuration
GITHUB_TOKEN_FILE = "_github_token.txt"
HITS_MINIMAL = "_hits.txt"
HITS_VERBOSE = "_hits_verbose.txt"
PROCESSED_FOLDER = "processed"
MAX_RETRIES = 3
BASE_DELAY = 2  # seconds
NETWORK_ERROR_DELAY = 30  # Longer delay for network issues

# ANSI color codes
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'

def setup_environment():
    """Create necessary folders and files."""
    if not os.path.exists(PROCESSED_FOLDER):
        os.makedirs(PROCESSED_FOLDER)
    # Clear output files at start
    open(HITS_MINIMAL, "w").close()
    open(HITS_VERBOSE, "w").close()

def get_github_tokens():
    """Read all GitHub tokens from token file."""
    if not os.path.exists(GITHUB_TOKEN_FILE):
        print(f"{RED}[!] Token file {GITHUB_TOKEN_FILE} not found{RESET}")
        exit(1)
    
    with open(GITHUB_TOKEN_FILE, "r") as f:
        tokens = [line.strip() for line in f if line.strip()]
    return tokens

GITHUB_TOKENS = get_github_tokens()
current_token_index = 0

def get_current_token():
    global current_token_index
    return GITHUB_TOKENS[current_token_index]

def rotate_token():
    global current_token_index
    current_token_index = (current_token_index + 1) % len(GITHUB_TOKENS)
    print(f"{RED}[!] Rotating to token {current_token_index + 1}/{len(GITHUB_TOKENS)}{RESET}")
    return get_current_token()

def get_headers():
    return {
        "Authorization": f"Bearer {get_current_token()}",
        "Accept": "application/vnd.github.v3+json",
    }

def get_search_files():
    """Get all .txt files containing search URLs, except the token file."""
    return [f for f in os.listdir(".") 
            if f.endswith(".txt") 
            and f != GITHUB_TOKEN_FILE
            and f != HITS_MINIMAL
            and f != HITS_VERBOSE]

def get_urls_from_file(filename):
    """Get all search URLs from a single file."""
    urls = set()
    with open(filename, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("https://github.com/search?q="):
                urls.add(line)
    return sorted(urls)

def extract_github_search_query(url):
    """Extract and clean the search query from a GitHub URL."""
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    raw_query = query_params.get("q", [""])[0]
    decoded_query = unquote_plus(raw_query)
    decoded_query = re.sub(r'in:url"?([^\s"]+)"?', r'in:url:\1', decoded_query)
    return decoded_query

def log_hit_verbose(query, total_count, results):
    """Log detailed results to verbose file."""
    with open(HITS_VERBOSE, "a") as f:
        f.write(f"\n=== HIT ===\nQuery: {query}\nResults: {total_count}\n")
        for item in results:
            f.write(f"- {item['html_url']}\n")
        f.write(f"Time: {datetime.now()}\n")

def log_hit_minimal(url):
    """Log only the original search URL to minimal file."""
    with open(HITS_MINIMAL, "a") as f:
        f.write(f"{url}\n")

def check_rate_limit():
    """Check remaining rate limit and reset time."""
    try:
        resp = requests.get("https://api.github.com/rate_limit", 
                          headers=get_headers(), 
                          timeout=10)
        if resp.status_code == 401:
            rotate_token()
            return check_rate_limit()
        resp.raise_for_status()
        data = resp.json()
        search = data["resources"]["search"]
        return search["remaining"], search["reset"]
    except requests.exceptions.Timeout:
        print(f"{RED}[!] Timeout while checking rate limit{RESET}")
        return 0, time.time() + 60
    except requests.exceptions.ConnectionError:
        print(f"{RED}[!] Connection error while checking rate limit{RESET}")
        return 0, time.time() + 60
    except Exception as e:
        print(f"{RED}[!] Rate limit check failed: {e}{RESET}")
        return 0, time.time() + 60

def is_network_error(e):
    """Check if the exception is a network-related error."""
    network_errors = (
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
        socket.gaierror,
    )
    return isinstance(e, network_errors)

def github_search(url, retry=0):
    """Execute GitHub search using the exact URL query."""
    if retry >= MAX_RETRIES:
        print(f"{RED}[!] Max retries reached for: {url}{RESET}")
        return None

    try:
        query = extract_github_search_query(url)
        if not query:
            return None

        api_url = "https://api.github.com/search/code"
        response = requests.get(api_url, 
                              headers=get_headers(), 
                              params={"q": query}, 
                              timeout=10)
        
        if response.status_code == 401:
            rotate_token()
            return github_search(url, retry + 1)
        
        if response.status_code == 403:
            sleep_time = int(response.headers.get('Retry-After', 60))
            print(f"{RED}[!] Rate limit triggered. Sleeping {sleep_time}s...{RESET}")
            time.sleep(sleep_time)
            return github_search(url, retry + 1)
        
        response.raise_for_status()
        return response.json()
    
    except requests.exceptions.RequestException as e:
        if is_network_error(e):
            print(f"{RED}[!] Network error searching '{url}': {e}{RESET}")
            sleep_time = NETWORK_ERROR_DELAY * (retry + 1)
            print(f"{YELLOW}[!] Waiting {sleep_time}s before retry...{RESET}")
            time.sleep(sleep_time)
        else:
            print(f"{RED}[!] Error searching '{url}': {e}{RESET}")
            time.sleep(BASE_DELAY * (retry + 1))
        return github_search(url, retry + 1)
    except Exception as e:
        print(f"{RED}[!] Unexpected error searching '{url}': {e}{RESET}")
        time.sleep(BASE_DELAY * (retry + 1))
        return github_search(url, retry + 1)

def process_file(filename):
    """Process all URLs in a single file."""
    print(f"\n{YELLOW}[*] Processing file: {filename}{RESET}")
    urls = get_urls_from_file(filename)
    print(f"[*] Found {len(urls)} search URLs in this file.")
    
    for url in urls:
        try:
            remaining, reset_time = check_rate_limit()
            
            if remaining <= 1:
                sleep_time = max(reset_time - time.time(), 0) + 5
                print(f"{YELLOW}[!] Approaching rate limit. Sleeping {sleep_time:.1f}s...{RESET}")
                time.sleep(sleep_time)

            query = extract_github_search_query(url)
            print(f"[>] Executing: {query}")
            result = github_search(url)
            
            if result and "total_count" in result and result["total_count"] > 0:
                print(f"{GREEN}[+] Found {result['total_count']} results!{RESET}")
                log_hit_verbose(query, result["total_count"], result["items"])
                log_hit_minimal(url)
            else:
                print(f"[-] No results.")
            
            time.sleep(BASE_DELAY)
        
        except KeyboardInterrupt:
            print(f"\n{YELLOW}[!] Processing interrupted by user{RESET}")
            return False  # Signal that processing wasn't completed
        except Exception as e:
            print(f"{RED}[!] Error processing URL {url}: {e}{RESET}")
            continue
    
    return True  # Signal that processing completed successfully

def move_to_processed(filename):
    """Move a completed file to the processed folder."""
    try:
        dest = os.path.join(PROCESSED_FOLDER, filename)
        shutil.move(filename, dest)
        print(f"{YELLOW}[*] Moved {filename} to {PROCESSED_FOLDER}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error moving file {filename}: {e}{RESET}")

if __name__ == "__main__":
    setup_environment()
    
    if not GITHUB_TOKENS:
        print(f"{RED}[!] No valid tokens found in {GITHUB_TOKEN_FILE}{RESET}")
        exit(1)
        
    print(f"[*] Starting scan with {len(GITHUB_TOKENS)} tokens available")
    
    search_files = get_search_files()
    print(f"[*] Found {len(search_files)} files to process")
    
    for filename in search_files:
        completed = process_file(filename)
        if completed:
            move_to_processed(filename)
        else:
            print(f"{YELLOW}[!] Stopping processing (user interrupt){RESET}")
            break

    print("[*] Scan complete.")
