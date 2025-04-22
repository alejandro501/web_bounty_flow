#!/usr/bin/env python3

"""
Cloudflare Detection Script
--------------------------
This script uses CloakQuest3r to detect Cloudflare-protected domains and potential bypasses.
It can process either a single domain or a list of domains from a file.

Usage:
    python cloudflare.py domain.com          # Check a single domain
    python cloudflare.py                     # Check all domains in wildcards.txt

Output:
    - logs/cloudflare/cloudflare.log: General execution logs
    - logs/cloudflare/cloudflare_domains.txt: List of detected Cloudflare domains
"""

import os
import sys
import requests
import logging
from datetime import datetime

# Add parent directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Get the directory where this script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def read_conf():
    """Read configuration from utils.conf"""
    config = {}
    try:
        with open(os.path.join(SCRIPT_DIR, 'utils.conf'), 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if '=' in line:
                        key, value = line.replace('export', '').split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"\'')
                        config[key] = value
    except Exception as e:
        print(f"Error reading config file: {e}")
    return config

# Read configuration
config = read_conf()
LOG_DIR = config.get('LOG_DIR', 'logs')
CLOUDFLARE_DIR = config.get('CLOUDFLARE_DIR', 'cloudflare')
CLOUDFLARE_FILE = config.get('CLOUDFLARE_FILE', 'cloudflare.log')

def setup():
    """Setup logging and directories"""
    # Create log directory
    log_dir = os.path.join(LOG_DIR, CLOUDFLARE_DIR)
    os.makedirs(log_dir, exist_ok=True)
    
    # Setup logging
    log_file = os.path.join(log_dir, CLOUDFLARE_FILE)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

def run_cloudscan(domain):
    """Run the cloakquest3r.py script with the given domain."""
    try:
        process = subprocess.Popen(
            ['python', 'cloakquest3r.py', domain],
            text=True,
            cwd='CloakQuest3r',
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        stdout, stderr = process.communicate()
        
        # Log the results
        with open(f"{LOG_DIR}/{CLOUDFLARE_DIR}/{CLOUDFLARE_FILE}", 'a') as log:
            log.write(f"Scanning domain: {domain}\n")
            log.write(f"Output: {stdout}\n")
            if stderr:
                log.write(f"Errors: {stderr}\n")
            log.write("-" * 40 + "\n")
        
        # If Cloudflare is detected, add to domains file
        if "Cloudflare detected" in stdout:
            with open(f"{LOG_DIR}/{CLOUDFLARE_DIR}/{CLOUDFLARE_DOMAINS_FILE}", 'a') as domains:
                domains.write(f"{domain}\n")
            
        logger.info(f"Completed scan for {domain}")
        
    except Exception as e:
        logger.error(f"Error scanning {domain}: {e}")

def check_cloudflare_bypass(domain: str) -> None:
    """Check for Cloudflare bypass vulnerabilities"""
    url = f"https://{domain}" if not domain.startswith(('http://', 'https://')) else domain
    
    # Headers to test
    headers = {
        'CF-Connecting-IP': '127.0.0.1',
        'X-Forwarded-For': '127.0.0.1',
        'X-Forwarded-Proto': 'https',
        'X-Real-IP': '127.0.0.1'
    }
    
    try:
        # Make request with bypass headers
        response = requests.get(url, headers=headers, verify=True, timeout=10)
        
        # Check if bypass might be successful
        if response.status_code == 200:
            logging.warning(f"Potential Cloudflare bypass vulnerability in {domain}")
            logging.info(f"Headers used: {headers}")
            logging.info(f"Response status: {response.status_code}")
    except Exception as e:
        logging.error(f"Error checking {domain}: {str(e)}")

def main():
    """Main function"""
    import argparse
    parser = argparse.ArgumentParser(description="Check for Cloudflare bypass vulnerabilities")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', '--domain', help='Single domain to test')
    group.add_argument('-f', '--file', help='File containing list of domains')
    args = parser.parse_args()
    
    setup()
    print("Running Cloudflare bypass checks...")
    
    if args.domain:
        check_cloudflare_bypass(args.domain)
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
            for domain in domains:
                check_cloudflare_bypass(domain)
        except Exception as e:
            logging.error(f"Error reading domain file: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
