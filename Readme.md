# README for Recon Automation Script

## Overview
This Bash script automates reconnaissance tasks for penetration testing and security assessments, including passive reconnaissance, network scanning, `robots.txt` fetching, directory fuzzing, and API endpoint exploration.

---

## Configuration
The tool uses `flow.conf` for configuration settings. Key files:
- `domains`: Target domains
- `scope`: In-scope targets
- `out-of-scope`: Excluded targets
- `wildcards`: Wildcard domains
- `organizations`: Target organizations

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
  - `-org, --organization <org>`: Target a single organization
  - `-ol, --org-list <filename>`: Process multiple organizations from a file
- **Help**:
  - `-h, --help`: Display help message

### Example
```bash
./flow.sh -org example.com -ol wildcards
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

## Output Structure
- **Dorking Results**: Organized by platform in `dorking/`
- **Fuzzing Results**: Stored in `fuzzing/ffuf/`
- **Robots Analysis**: Parsed results in `robots/`
  - `_hits.txt`: Valid findings
  - Separate directories for hits/no-hits

## Features in Detail

### Passive Reconnaissance
1. **Domain Enumeration**
   - Subdomain discovery via subfinder
   - API endpoint detection
   - Out-of-scope domain filtering

2. **Dorking**
   - Automated dork generation for multiple platforms
   - Results categorized by platform
   - API-specific dork queries

### Active Scanning
1. **Network Analysis**
   - Full port scans (-p-)
   - Service version detection
   - Automated reporting

2. **Vulnerability Assessment**
   - Integration with searchsploit
   - Service-based vulnerability mapping
   - Summary reports generation

## Security Notes
- Sensitive files (tokens, credentials) are automatically excluded via `.gitignore`
- Ensure proper scope definition before running scans
- Review and comply with target's security policies

## Requirements
- Nmap
- subfinder
- ffuf
- curl
- searchsploit

---
