# README for Recon Automation Script

## Overview
This Bash script automates reconnaissance tasks for penetration testing and security assessments, including passive reconnaissance, network scanning, `robots.txt` fetching, directory fuzzing, and API endpoint exploration.

---

## Features
- **Passive Reconnaissance**: Scans organizations/domains, generates dork links, and extracts endpoints.
- **Robots.txt Analysis**: Fetches and processes `robots.txt` files for potential disallowed paths.
- **Network Scanning**: Performs detailed scans using Nmap.
- **Directory and API Fuzzing**: Uses `ffuf` to identify hidden directories and API endpoints.
- **Documentation Fuzzing**: Targets API documentation paths.

---

## Usage
### Basic Syntax
```bash
./flow.sh [options]
```

### Options
- **Input Feed**:
  - `-org, --organization <org>`: Specify a single organization to target.
  - `-ol, --org-list <filename>`: Specify a file containing a list of organizations.
- **Optional**:
  - `-t, --tor`: Enable Tor for anonymous network requests.
- **Help**:
  - `-h, --help`: Display the help message.

### Example
```bash
./flow.sh -org example.com -ol wildcards.txt -t
```

---

## Functionality
1. **Passive Reconnaissance**:
   - Generates Google dork links.
   - Fetches `robots.txt` and performs Nmap scans for domains.
2. **Network Scanning**:
   - Scans domains using Nmap (`-sC -sV` for default and `-p-` for all ports).
3. **Fuzzing**:
   - Directory fuzzing using multiple wordlists.
   - Documentation fuzzing to identify API documentation paths.

---

## Output
The script generates outputs in structured directories:
- **Nmap scans**: Results saved in the `nmap` directory.
- **Robots.txt files**: Stored in `robots`.
- **Fuzzing results**: Saved in `fuzzing/ffuf`.

---
