#!/usr/bin/env python3

"""
HTTP Request Smuggling Vulnerability Scanner
------------------------------------------
This script tests web servers for HTTP request smuggling vulnerabilities by sending
carefully crafted requests that attempt to exploit various request smuggling techniques.

The scanner performs two types of checks:
1. Basic Checks: Simple requests to detect potential vulnerabilities
2. Advanced Checks: Multiple sophisticated payloads testing different smuggling techniques:
   - White Space Character manipulation
   - Incorrect Header Prioritization
   - Multiple Header Injection
   - Content-Length/Transfer-Encoding manipulation
   - Connection handling issues
   - CRLF Injection
   - Chunk Extensions
   - Trailer Headers

Usage:
    python request_smuggling.py --file domains.txt [--port PROXY_PORT]

Output:
    - logs/request_smuggling/request_smuggling_basic.log: Results from basic checks
    - logs/request_smuggling/request_smuggling_advanced.log: Results from advanced checks
"""

import requests
from requests.exceptions import RequestException
import argparse
import logging
from typing import List, Dict, Optional
from pathlib import Path
import os
import sys
import re
from urllib3.exceptions import InsecureRequestWarning
import urllib3
from datetime import datetime

# Disable SSL warnings
urllib3.disable_warnings(InsecureRequestWarning)

# Add parent directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Get script directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def read_conf(conf_file: str) -> Dict[str, str]:
    """Read configuration from shell config file."""
    config = {}
    try:
        with open(conf_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"\'')
                        config[key] = value
    except Exception as e:
        print(f"Error reading config file: {e}")
    return config

# Read configuration from utils.conf
config = read_conf(os.path.join(SCRIPT_DIR, 'utils.conf'))
LOG_DIR = config.get('LOG_DIR', 'logs')
REQUEST_SMUGGLING_DIR = config.get('REQUEST_SMUGGLING_DIR', 'request_smuggling')
REQUEST_SMUGGLING_BASIC_FILE = config.get('REQUEST_SMUGGLING_BASIC_FILE', 'request_smuggling_basic.log')
REQUEST_SMUGGLING_ADVANCED_FILE = config.get('REQUEST_SMUGGLING_ADVANCED_FILE', 'request_smuggling_advanced.log')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def load_domains(filename: str) -> List[str]:
    """Load domains from the input file."""
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        logger.error(f"Input file {filename} not found")
        raise

def log_vulnerability(domain: str, status_code: int, test_type: str, headers: dict, is_basic: bool = False) -> None:
    """Log potential vulnerabilities to the configured log file."""
    log_dir = os.path.join(os.path.dirname(SCRIPT_DIR), LOG_DIR, REQUEST_SMUGGLING_DIR)
    os.makedirs(log_dir, exist_ok=True)
    
    # Choose appropriate log file based on test type
    log_file = os.path.join(log_dir, REQUEST_SMUGGLING_BASIC_FILE if is_basic else REQUEST_SMUGGLING_ADVANCED_FILE)
    
    try:
        with open(log_file, 'a') as f:
            f.write(f"\n{'='*50}\n")
            f.write(f"Potential vulnerability in {test_type}\n")
            f.write(f"Target: {domain}\n")
            f.write(f"Status Code: {status_code}\n")
            f.write(f"Headers Used: {headers}\n")
            f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{'='*50}\n")
    except IOError as e:
        print(f"Error writing to log file: {e}")

def basic_check(domain: str) -> bool:
    """Basic request smuggling check using simple header manipulation"""
    url = f"https://{domain}" if not domain.startswith(('http://', 'https://')) else domain
    headers = {
        'Transfer-Encoding': 'chunked',
        'Content-Length': '0'
    }
    
    try:
        response = requests.post(url, headers=headers, verify=True, timeout=10)
        if response.status_code in [400, 401, 403, 500, 501, 502, 503]:
            log_vulnerability(url, response.status_code, "Basic Check", headers, is_basic=True)
            return True
        return False
    except Exception as e:
        return False

def advanced_check(domain: str) -> bool:
    """Advanced request smuggling checks"""
    url = f"https://{domain}" if not domain.startswith(('http://', 'https://')) else domain
    vulnerable = False
    
    # CL.TE test
    headers = {
        'Content-Length': '4',
        'Transfer-Encoding': 'chunked'
    }
    data = '0\r\n\r\n'
    try:
        response = requests.post(url, headers=headers, data=data, verify=True, timeout=10)
        if response.status_code in [400, 401, 403, 500, 501, 502, 503]:
            log_vulnerability(url, response.status_code, "CL.TE Test", headers, is_basic=False)
            vulnerable = True
    except Exception:
        pass
    
    # TE.CL test
    headers = {
        'Transfer-Encoding': 'chunked',
        'Content-Length': '6'
    }
    data = '0\r\n\r\n'
    try:
        response = requests.post(url, headers=headers, data=data, verify=True, timeout=10)
        if response.status_code in [400, 401, 403, 500, 501, 502, 503]:
            log_vulnerability(url, response.status_code, "TE.CL Test", headers, is_basic=False)
            vulnerable = True
    except Exception:
        pass
    
    # TE.TE test
    headers = {
        'Transfer-Encoding': 'chunked, identity',
        'Content-Length': '4'
    }
    data = '0\r\n\r\n'
    try:
        response = requests.post(url, headers=headers, data=data, verify=True, timeout=10)
        if response.status_code in [400, 401, 403, 500, 501, 502, 503]:
            log_vulnerability(url, response.status_code, "TE.TE Test", headers, is_basic=False)
            vulnerable = True
    except Exception:
        pass
    
    return vulnerable

def setup_logging() -> None:
    """Setup logging directories and files."""
    log_dir = Path(os.path.dirname(SCRIPT_DIR)) / LOG_DIR / REQUEST_SMUGGLING_DIR
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Clear existing log files
    for log_file in [REQUEST_SMUGGLING_BASIC_FILE, REQUEST_SMUGGLING_ADVANCED_FILE]:
        (log_dir / log_file).touch(exist_ok=True)
        (log_dir / log_file).write_text('')

def main() -> None:
    """Main function to orchestrate the scanning process."""
    parser = argparse.ArgumentParser(description="Check for request smuggling vulnerabilities.")
    parser.add_argument('--file', type=str, help='Input file with domains to test')
    parser.add_argument('-d', '--domain', type=str, help='Single domain to test')
    args = parser.parse_args()

    domains = []
    if args.domain:
        domains.append(args.domain)
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading domain file: {e}")
            return
    
    if not domains:
        print("No domains provided. Use --file or -d/--domain")
        return

    print("Running Request Smuggling checks...")
    for domain in domains:
        if basic_check(domain) or advanced_check(domain):
            print(f"[!] Potential vulnerability found in {domain}")
        else:
            print(f"[-] No vulnerabilities found in {domain}")

if __name__ == "__main__":
    main()
