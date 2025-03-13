import requests

# File paths
urls_file = 'ping_urls.txt'  # Your list of URLs
wordlist_file = 'ping_wordlist.txt'  # The wordlist
output_file = 'ping_results.txt'  # Output file for results

# Read URLs and wordlist
with open(urls_file, 'r') as f:
    urls = [line.strip() for line in f.readlines()]

with open(wordlist_file, 'r') as f:
    wordlist = [line.strip() for line in f.readlines()]

# Test each URL with the wordlist
with open(output_file, 'w') as outfile:
    for url in urls:
        for payload in wordlist:
            test_url = f"{url}{payload}"
            try:
                response = requests.get(test_url, timeout=5)
                outfile.write(f"URL: {test_url}\n")
                outfile.write(f"Status Code: {response.status_code}\n")
                outfile.write(f"Response: {response.text[:200]}\n")  # First 200 chars
                outfile.write("-" * 50 + "\n")
            except requests.RequestException as e:
                outfile.write(f"URL: {test_url}\n")
                outfile.write(f"Error: {str(e)}\n")
                outfile.write("-" * 50 + "\n")

print(f"Testing complete. Results saved to {output_file}")
