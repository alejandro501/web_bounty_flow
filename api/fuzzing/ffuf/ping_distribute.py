import re

# Input and output file paths
input_file = 'ping_results.txt'  # Your results file
output_dir = 'status_codes'  # Directory to store organized files

# Create the output directory if it doesn't exist
import os
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Read the input file
with open(input_file, 'r') as infile:
    content = infile.read()

# Split the content into individual test cases
test_cases = content.split('-' * 50 + '\n')

# Process each test case
for test_case in test_cases:
    if not test_case.strip():  # Skip empty lines
        continue

    # Extract the URL, status code, and response
    url_match = re.search(r'URL: (.+)', test_case)
    status_match = re.search(r'Status Code: (\d+)', test_case)
    response_match = re.search(r'Response: (.+)', test_case)

    if url_match and status_match and response_match:
        url = url_match.group(1)
        status_code = status_match.group(1)
        response = response_match.group(1)

        # Write to the appropriate file
        output_file = os.path.join(output_dir, f'ping_{status_code}.txt')
        with open(output_file, 'a') as outfile:
            outfile.write(f"URL: {url}\n")
            outfile.write(f"Status Code: {status_code}\n")
            outfile.write(f"Response: {response}\n")
            outfile.write('-' * 50 + '\n')

print(f"Results organized into files in the '{output_dir}' directory.")