import os
import sys
import subprocess

def run_cloudscan(domain):
    """Run the cloakquest3r.py script with the given domain."""
    # Run the cloakquest3r.py script for the specified domain
    process = subprocess.Popen(
        ['python', 'cloakquest3r.py', domain],
        text=True,
        cwd='CloakQuest3r'  # Set the working directory to CloakQuest3r
    )
    
    process.wait()  # Wait for the process to complete

def main():
    # Set the path to wildcards.txt in the outer directory
    wildcards_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wildcards.txt')

    # Check if an argument was provided
    if len(sys.argv) > 1:
        # Take domain from command-line argument
        domain = sys.argv[1]
        run_cloudscan(domain)
    else:
        # Read domains from wildcards.txt
        try:
            with open(wildcards_path, 'r') as file:
                domains = file.read().splitlines()
                if not domains:
                    print("wildcards.txt is empty. Please add domains to analyze.")
                    return
                for domain in domains:
                    run_cloudscan(domain)
        except FileNotFoundError:
            print(f"{wildcards_path} not found. Please make sure it exists in the outer directory.")

if __name__ == '__main__':
    main()
