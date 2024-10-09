import requests

def check_subdomain_status(subdomain):
    try:
        response = requests.get(subdomain, timeout=5)
        print(f"Checked {subdomain}: Status Code {response.status_code}")
        return response.status_code
    except requests.exceptions.RequestException as e:
        print(f"Error with {subdomain}: {e}")
        return None  # Return None for any request errors

def sort_subdomains(input_file):
    status_dict = {}

    # Read the subdomains from the input file
    try:
        with open(input_file, 'r') as file:
            subdomains = file.readlines()
    except FileNotFoundError:
        print(f"Error: The file {input_file} was not found.")
        return

    print(f"Loaded {len(subdomains)} subdomains from {input_file}.")

    # Check the status of each subdomain
    for subdomain in subdomains:
        subdomain = subdomain.strip()  # Remove any whitespace/newlines
        if not subdomain:
            continue

        status_code = check_subdomain_status(subdomain)
        if status_code:
            if status_code not in status_dict:
                status_dict[status_code] = []
            status_dict[status_code].append(subdomain)

    # Write the sorted subdomains into files based on their status codes
    for status_code, subdomains in status_dict.items():
        filename = f"{status_code}.txt"
        with open(filename, 'w') as output_file:
            for subdomain in subdomains:
                output_file.write(subdomain + '\n')
        print(f"Wrote {len(subdomains)} subdomains with status {status_code} to {filename}")

    if not status_dict:
        print("No subdomains returned valid HTTP status codes.")

if __name__ == "__main__":
    # Modify this path to your actual file location
    sort_subdomains("live_subdomains.txt")
